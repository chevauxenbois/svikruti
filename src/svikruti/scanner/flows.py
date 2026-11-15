"""Processor data flows: which personal data is handed to which third party.

A third-party SDK in a file tells you a processor exists. It does not tell you
what it receives. This detector follows the SDK from its import to the calls
made on it and reports the personal-data categories in those calls' arguments:

    const mixpanel = require("mixpanel").init(token);
    mixpanel.track("refund_requested", { email, pincode });   ->  Contact, Location -> Mixpanel

Wrappers are followed across files. If ``notify.py`` defines

    def send_sms(phone, text): requests.post(MSG91_URL, json={"mobiles": phone, ...})

then ``send_sms(user.phone_number, msg)`` in another file that imports it is
reported as Contact -> MSG91, up to three levels of wrapping.

Scope and honesty: a handle is an identifier bound to the SDK by an
import/require, by construction from such an identifier, or a constant holding
the vendor's URL. Arguments are followed one assignment back (``payload =
{...}`` then ``sdk.send(payload)``). A wrapper is a function that passes one of
its own parameters to a vendor call; a call to it counts only where the caller
imports the wrapper's module (or shares its package). Dependency injection,
dynamic dispatch, queues and event buses between caller and vendor are not
followed.
"""

from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from svikruti.models import Evidence
from svikruti.scanner.code import _code_outside_strings, _drop_record_identifiers, _file_context, _is_fixture_file, _language_for, iter_source_files
from svikruti.scanner.patterns import AI_PROVIDERS, CATEGORY_SEVERITY, THIRD_PARTY_PATTERNS, normalize_text
from svikruti.scanner.semantic import _categories_for_text

_FLOW_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".rb", ".go", ".java", ".kt", ".php", ".html", ".htm"}
_MAX_STATEMENT_LINES = 25
_ASSIGN_LOOKBACK = 40

_IDENT = r"[A-Za-z_$][\w$]*"
_BINDING_RES = (
    re.compile(rf"\b(?:const|let|var|val|final)\s+(?:{_IDENT}\s+)?({_IDENT})\s*(?::[^=]+)?="),   # const x = / val x: T =
    re.compile(rf"\b(?:const|let|var)\s+\{{([^}}]*)\}}\s*="),                                   # const { a, b } =
    re.compile(rf"^\s*import\s+({_IDENT})\b(?!\s*\.)"),                                         # import x / import x from
    re.compile(rf"^\s*import\s+\{{([^}}]*)\}}"),                                                # import { a, b } from
    re.compile(rf"^\s*import\s+\*\s+as\s+({_IDENT})"),                                          # import * as x from
    re.compile(rf"^\s*from\s+\S+\s+import\s+(.+)$"),                                            # from x import a, b
    re.compile(rf"^\s*import\s+\S+\s+as\s+({_IDENT})"),                                         # import x.y as z
    re.compile(rf"^\s*(?:self\.|this\.|@|\$)?({_IDENT})\s*(?::[^=]+)?=(?!=)"),                  # x = / self.x = / $x =
    re.compile(rf"^\s*({_IDENT})\s*:="),                                                        # x := (Go)
    re.compile(r"^\s*import\s+(?:static\s+)?[\w.]+\.([A-Z]\w*)\s*;"),                             # import com.vendor.Client; (Java/Kotlin)
    re.compile(r"^\s*use\s+[\w\\]+\\(\w+)\s*;"),                                                # use Vendor\Api\Client; (PHP)
    re.compile(rf"^\s*import\s+({_IDENT})\s+\""),                                                # import alias "pkg" (Go)
)
_KEY_RE = re.compile(r"""["']([A-Za-z_][\w-]*)["']\s*(?::|=>)""")
_IMPORT_LINE_RE = re.compile(r"^\s*(?:import\b|from\s+\S+\s+import\b|use\s|require_once|require\s*\(|#include)|\brequire\s*\(", re.IGNORECASE)
_ASSIGN_RE = re.compile(rf"^\s*(?:const|let|var|val|final)?\s*(?:self\.|this\.|\$)?({_IDENT})\s*(?::[^=]+)?(?::=|=)(?!=)\s*(.+)$")
_SKIP_HANDLES = {"const", "let", "var", "import", "from", "require", "new", "await", "return", "this", "self", "default", "as", "type"}


def _split_names(group: str) -> List[str]:
    names = []
    for part in group.split(","):
        part = part.strip()
        if not part:
            continue
        # `a as b` (JS/Python) and `a: b` (JS destructuring) bind the right-hand name.
        part = re.split(r"\s+as\s+|:", part)[-1].strip()
        if re.fullmatch(_IDENT, part) and part not in _SKIP_HANDLES:
            names.append(part)
    return names


def _bound_names(line: str) -> List[str]:
    names: List[str] = []
    for pattern in _BINDING_RES:
        match = pattern.search(line)
        if match:
            names.extend(_split_names(match.group(1)))
    return names


def _needle_handles(needles: List[str]) -> Set[str]:
    """Vendor names that are themselves call targets: mixpanel.track, gtag(...), fbq(...)."""
    out = set()
    for needle in needles:
        candidate = needle.rstrip("(").strip()
        if re.fullmatch(r"[A-Za-z_]\w{2,}", candidate):
            out.add(candidate.lower())
    return out


def _statement(lines: List[str], start: int) -> str:
    """The statement starting at ``start``, extended until brackets balance."""
    depth = 0
    collected: List[str] = []
    for offset in range(start, min(start + _MAX_STATEMENT_LINES, len(lines))):
        text = lines[offset]
        collected.append(text)
        depth += sum(text.count(ch) for ch in "([{") - sum(text.count(ch) for ch in ")]}")
        if depth <= 0:
            break
    return "\n".join(collected)


# `address: "auto"`, `"mode": "payment"`, `email_enabled=True`: a key set to a
# constant is configuration, not a person's data.
_CONSTANT_PAIR_RE = re.compile(
    r"""["']?[A-Za-z_$][\w$-]*["']?\s*(?::|=>|=)\s*(?:"[^"\n]*"|'[^'\n]*'|`[^`$\n]*`|true|false|True|False|null|None|nil|undefined|-?\d[\d_.]*)\s*(?=[,)}\]\n]|$)"""
)
_CALL_RESULT_RE = re.compile(r"^\s*(?:await\s+|yield\s+)?(?:new\s+)?[\w$.:\\>-]+\s*\(")
_AGGREGATE_BUILDERS = ("dict(", "Object.assign(", "JSON.stringify(", "json.dumps(", "array(", "map[", "Map.of(", "mapOf(", "hashMapOf(")


def _argument_text(statement: str) -> str:
    """Identifiers, interpolations and object/dict keys in a statement; message prose and constants dropped."""
    statement = _CONSTANT_PAIR_RE.sub(" ", statement)
    # Passing `customer_id` or `intent.id` hands over a record reference, not the record's data.
    statement = _drop_record_identifiers(statement)
    return _code_outside_strings(statement) + " " + " ".join(_KEY_RE.findall(statement))


def _carries_its_inputs(value: str) -> bool:
    """Is a variable assigned from ``value`` still the data that went in?

    `payload = {"email": user.email}` is. `customer = create_customer(email)` is
    the callee's answer (an id, a status), so it is not followed.
    """
    stripped = value.strip()
    if stripped.startswith(_AGGREGATE_BUILDERS):
        return True
    return not _CALL_RESULT_RE.match(stripped)


def _call_arguments(statement: str) -> str:
    """What is passed, not what is called or assigned to.

    `payment_method = stripe.PaymentMethod.retrieve(pm_id)` hands Stripe an id.
    The words "payment method" in the callee and the target are not arguments.
    """
    opened = statement.find("(")
    return _argument_text(statement[opened:] if opened >= 0 else "")


_CONSTRUCTION_RE_TEMPLATE = r"(?:\bnew\s+(?:{h})\b|(?<![\w$.])(?:{h})\s*(?:\.|::)\s*(?:[A-Z]\w*(?:\s*(?:\.|::)\s*\w+)?|init|client|create_client|configure|setup|getInstance|instance)\s*\(|(?<![\w$.])(?:{h})\s*\(|\\?(?:{h})(?:\\\w+)+::\w+\s*\()"
_STRING_RE = re.compile(r"""["'`]([^"'`]*)["'`]""")


def _handles_for(lines: List[str], needles: List[str]) -> Set[str]:
    """Identifiers bound to the vendor SDK or to the vendor's endpoint.

    The result of a call *on* the SDK (``order = razorpay.orders.create(...)``)
    is the vendor's response, not a handle, and is deliberately not followed.
    """
    lowered_needles = [needle.lower().rstrip("(") for needle in needles]
    handles: Set[str] = set()
    for line in lines:
        lowered = line.lower()
        if not any(needle in lowered for needle in lowered_needles):
            continue
        if _IMPORT_LINE_RE.search(line):
            handles.update(_bound_names(line))
            continue
        # VENDOR_URL = "https://api.vendor.com/..." : a constant holding the endpoint.
        for literal in _STRING_RE.findall(line):
            lowered_literal = literal.lower()
            if not any(needle in lowered_literal for needle in lowered_needles):
                continue
            before_literal = line.split(literal)[0]
            # A constant holding the endpoint, or a client built for the service by name:
            # bedrock = boto3.client("bedrock-runtime")
            if "/" in literal or "." in literal or ("=" in before_literal and "(" in before_literal.split("=", 1)[1]):
                handles.update(_bound_names(before_literal))
    handles |= _typed_as(lines, handles | _needle_handles(needles))
    seeds = handles | _needle_handles(needles)
    # Construction: client = razorpay.Client(...), const rzp = new Razorpay({...}), mp = Mixpanel(token)
    for _ in range(2):
        if not seeds:
            break
        pattern = re.compile(_CONSTRUCTION_RE_TEMPLATE.format(h="|".join(re.escape(seed) for seed in sorted(seeds, key=len, reverse=True))), re.IGNORECASE)
        before = len(handles)
        for line in lines:
            if "=" not in line or _IMPORT_LINE_RE.search(line):
                continue
            left, right = line.split("=", 1)
            if pattern.search(right) and not re.search(r"\.\s*[a-z_]\w*\s*\.\s*[a-z_]\w*\s*\(", right):
                handles.update(_bound_names(left + "="))
            # LangChain-style composition: chain = prompt | llm | parser
            elif "|" in right and "||" not in right and seeds & set(re.findall(_IDENT, right.split("#")[0])):
                handles.update(_bound_names(left + "="))
        seeds = handles | _needle_handles(needles)
        if len(handles) == before:
            break
    return {handle for handle in handles if handle not in _SKIP_HANDLES and len(handle) > 1}


def _typed_as(lines: List[str], types: Set[str]) -> Set[str]:
    """Names declared with a vendor type: injected clients, fields and parameters.

        constructor(private readonly stripe: Stripe)     TypeScript / Kotlin
        def track(mp: Mixpanel, user)                    Python annotations
        private final RazorpayClient razorpayClient;     Java
        rzp *razorpay.Client                             Go struct field or parameter
    """
    # Only client-like types. `StripeObject`, `PaymentIntent` and `Event` are the
    # vendor's data, and a variable holding one is a response, not a client.
    client_like = re.compile(r"(?:Client|Api|API|Sdk|SDK|Service|Gateway|Instance|Connection)$")
    types = {name for name in types if len(name) > 2 and (client_like.search(name) or not re.search(r"[a-z][A-Z]", name))}
    if not types:
        return set()
    alternation = "|".join(re.escape(name) for name in sorted(types, key=len, reverse=True))
    patterns = (
        re.compile(rf"({_IDENT})\s*\??\s*:\s*(?:Optional\[|\"|')?(?:[\w$]+\.)*(?:{alternation})\b(?!\s*[.(])"),   # name: Type
        re.compile(rf"\b(?:{alternation})(?:<[^>]*>)?\s+({_IDENT})\s*(?=[;,)=])"),                              # Type name
        re.compile(rf"({_IDENT})\s+\*?(?:{alternation})\.[A-Z]\w*\b(?!\s*\()"),                               # name *pkg.Type
    )
    names: Set[str] = set()
    for line in lines:
        if _IMPORT_LINE_RE.search(line):
            continue
        for pattern in patterns:
            for match in pattern.finditer(line):
                name = match.group(1)
                if name not in _SKIP_HANDLES and name not in {"return", "new", "case", "throw", "else", "public", "private", "protected", "static", "final", "readonly"}:
                    names.add(name)
    return names


def _statement_starts(lines: List[str]) -> List[int]:
    """For each line, the index of the line where its enclosing bracketed statement opens."""
    starts: List[int] = []
    depth, current = 0, 0
    for index, text in enumerate(lines):
        if depth <= 0:
            current, depth = index, 0
        starts.append(current)
        depth += sum(text.count(ch) for ch in "([") - sum(text.count(ch) for ch in ")]")
    return starts


_MAX_WRAPPERS = 300
_WRAPPER_ROUNDS = 2  # wrapper of a wrapper of a wrapper is the deepest chain followed
_GENERIC_MODULE_STEMS = {"index", "__init__", "main", "mod", "lib", "utils", "util", "helpers", "helper", "common"}
_IMPLICIT_PACKAGE_SUFFIXES = {".go", ".java", ".kt", ".rb", ".php"}
_NOT_FUNCTIONS = {"if", "for", "while", "switch", "catch", "return", "function", "else", "elif", "with", "try", "do", "new", "typeof", "await", "sizeof", "foreach", "match", "when", "super", "constructor", "__init__"}
_SELF_PARAMS = {"self", "cls", "this"}

_PY_DEF_RE = re.compile(r"^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
_RB_DEF_RE = re.compile(r"^(\s*)def\s+(?:self\.)?([A-Za-z_]\w*[?!]?)\s*(?:\((.*?)\))?\s*$")
_BRACE_DEF_RES = (
    re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),                                                      # JS/PHP function f(
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\s*\*?\s*)?\("),  # const f = (..) => / = function(
    re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),                                                  # Go func (r T) f(
    re.compile(r"\bfun\s+(?:[\w.<>]+\.)?([A-Za-z_]\w*)\s*\("),                                                      # Kotlin fun f(
    re.compile(r"^\s*(?:(?:public|private|protected|internal|static|final|async|override|export|default|abstract|synchronized)\s+)*(?:[\w<>\[\],.?]+\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*$"),  # method f(..) {
)


@dataclass
class _Function:
    name: str
    params: List[str]
    start: int  # line index of the signature
    end: int    # last line index of the body (inclusive)


@dataclass
class _Wrapper:
    name: str
    rel: str
    processor: str
    start: int
    end: int
    depth: int

    @property
    def stem(self) -> str:
        path = Path(self.rel)
        return (path.parent.name if path.stem.lower() in _GENERIC_MODULE_STEMS else path.stem).lower()


@dataclass
class _SourceFile:
    rel: str
    path: Path
    lines: List[str]
    lowered: str
    file_context: str
    _assignments: Optional[List[Tuple[int, str, str]]] = None
    _functions: Optional[List[_Function]] = None
    _starts: Optional[List[int]] = None

    @property
    def assignments(self) -> List[Tuple[int, str, str]]:
        if self._assignments is None:
            self._assignments = _assignments(self.lines)
        return self._assignments

    @property
    def functions(self) -> List[_Function]:
        if self._functions is None:
            self._functions = _functions(self.lines, self.path.suffix.lower())
        return self._functions

    @property
    def starts(self) -> List[int]:
        if self._starts is None:
            self._starts = _statement_starts(self.lines)
        return self._starts

    def enclosing(self, index: int) -> Optional[_Function]:
        best: Optional[_Function] = None
        for function in self.functions:
            if function.start <= index <= function.end and (best is None or function.start >= best.start):
                best = function
        return best


def _param_names(signature: str, suffix: str) -> List[str]:
    """Parameter identifiers from the text between a signature's parentheses."""
    depth, start, inner = 0, None, None
    for position, char in enumerate(signature):
        if char == "(":
            if depth == 0:
                start = position + 1
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and start is not None:
                inner = signature[start:position]
                break
    if inner is None:
        inner = signature[start:] if start is not None else ""
    names: List[str] = []
    for raw in re.split(r",(?![^<\[{(]*[>\]})])", inner):
        part = raw.strip()
        if not part:
            continue
        if suffix == ".php":
            found = re.findall(r"\$([A-Za-z_]\w*)", part)
            names.extend(found[:1])
            continue
        part = part.split("=")[0].strip().lstrip("*&.")
        if part.startswith(("{", "[")):  # JS destructuring: ({ email, phone })
            names.extend(re.findall(r"[A-Za-z_$][\w$]*", part.split(":")[0] if "}" not in part else part[: part.index("}")]))
            continue
        if suffix in {".java"}:
            idents = re.findall(r"[A-Za-z_]\w*", part)
            names.extend(idents[-1:])
        else:  # Python, JS/TS, Kotlin (name: Type), Go (name Type)
            match = re.match(r"(?:@\w+\s+)*(?:(?:public|private|protected|readonly|final|val|var)\s+)*([A-Za-z_$][\w$]*)", part)
            if match:
                names.append(match.group(1))
    return [name for name in names if name not in _SELF_PARAMS]


def _functions(lines: List[str], suffix: str) -> List[_Function]:
    functions: List[_Function] = []
    total = len(lines)
    if suffix == ".py":
        for index, line in enumerate(lines):
            match = _PY_DEF_RE.match(line)
            if not match:
                continue
            indent = len(match.group(1))
            signature = _statement(lines, index)
            end = index
            for offset in range(index + 1 + signature.count("\n"), total):
                text = lines[offset]
                if text.strip() and len(text) - len(text.lstrip()) <= indent:
                    break
                end = offset
            functions.append(_Function(match.group(2), _param_names(signature, suffix), index, end))
        return functions
    if suffix == ".rb":
        for index, line in enumerate(lines):
            match = _RB_DEF_RE.match(line)
            if not match:
                continue
            indent = match.group(1)
            end = next((offset for offset in range(index + 1, total) if lines[offset].rstrip() == f"{indent}end"), index)
            functions.append(_Function(match.group(2).rstrip("?!"), _param_names(f"({match.group(3) or ''})", suffix), index, end))
        return functions
    for index, line in enumerate(lines):
        if "(" not in line:
            continue
        stripped = line.lstrip()
        if stripped.startswith(("//", "*", "/*", "#")):
            continue
        name = None
        for pattern in _BRACE_DEF_RES:
            match = pattern.search(line)
            if match and match.group(1) not in _NOT_FUNCTIONS:
                name = match.group(1)
                signature_at = match.start(1)
                break
        if name is None:
            continue
        # Find the body's opening brace after the parameter list closes.
        depth_paren, brace_line, seen_paren = 0, None, False
        for offset in range(index, min(index + 12, total)):
            text = lines[offset][signature_at:] if offset == index else lines[offset]
            for char in text:
                if char == "(":
                    depth_paren += 1
                    seen_paren = True
                elif char == ")":
                    depth_paren -= 1
                elif char == "{" and seen_paren and depth_paren == 0:
                    brace_line = offset
                    break
                elif char == ";" and seen_paren and depth_paren == 0:
                    break
            else:
                continue
            break
        signature = "\n".join(lines[index : (brace_line if brace_line is not None else index) + 1])[signature_at:]
        if brace_line is None:
            if "=>" not in signature:
                continue  # a call or a declaration without a body, not a definition
            end = index + _statement(lines, index).count("\n")
        else:
            depth, end, opened = 0, brace_line, False
            for offset in range(brace_line, min(brace_line + 400, total)):
                text = lines[offset][signature_at:] if offset == index else lines[offset]
                if offset == brace_line and brace_line == index:
                    text = text[text.index("{", _body_brace(text)) :] if "{" in text else text
                depth += text.count("{") - text.count("}")
                opened = opened or "{" in text
                end = offset
                if opened and depth <= 0:
                    break
        functions.append(_Function(name, _param_names(signature[len(name) :], suffix), index, end))
    return functions


def _body_brace(text: str) -> int:
    """Index from which to look for the body's `{` on a one-line signature (after the params close)."""
    depth = 0
    for position, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return position
    return 0


def _load(root: Path) -> List[_SourceFile]:
    files: List[_SourceFile] = []
    for path in iter_source_files(root):
        if path.suffix.lower() not in _FLOW_SUFFIXES:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _is_fixture_file(root, rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_context = _file_context(rel, text)
        if file_context in {"reference", "test"}:
            continue  # documentation and test suites do not send production data anywhere
        files.append(_SourceFile(rel=rel, path=path, lines=text.splitlines(), lowered=text.lower(), file_context=file_context))
    return files


def scan_processor_flows(repo_path: str) -> List[Evidence]:
    root = Path(repo_path).resolve()
    files = _load(root)
    evidence: List[Evidence] = []
    wrappers: List[_Wrapper] = []
    reported: Set[Tuple[str, int, str, str]] = set()

    # Pass 1: direct calls on a vendor SDK, and the functions that wrap them.
    for source in files:
        present = {name: needles for name, needles in THIRD_PARTY_PATTERNS.items() if any(needle.lower() in source.lowered for needle in needles)}
        for name, needles in present.items():
            handles = _handles_for(source.lines, needles)
            call_targets = handles | _needle_handles(needles)
            for index in _call_sites(source, handles, call_targets):
                evidence.extend(_site_evidence(source, index, name, call_targets, reported))
                _note_wrapper(source, index, name, 1, wrappers)

    # Pass 2: calls to those wrappers, anywhere in the repository.
    current = wrappers[:_MAX_WRAPPERS]
    for _ in range(_WRAPPER_ROUNDS):
        if not current:
            break
        discovered: List[_Wrapper] = []
        for source in files:
            for wrapper in current:
                if wrapper.name.lower() not in source.lowered or not _linked(source, wrapper):
                    continue
                for index in _wrapper_call_sites(source, wrapper):
                    evidence.extend(_site_evidence(source, index, wrapper.processor, {wrapper.name}, reported, via=wrapper))
                    _note_wrapper(source, index, wrapper.processor, wrapper.depth + 1, discovered)
        known = {(w.rel, w.name, w.processor) for w in wrappers}
        current = [w for w in discovered if (w.rel, w.name, w.processor) not in known][:_MAX_WRAPPERS]
        wrappers.extend(current)
    return evidence


def _note_wrapper(source: _SourceFile, index: int, processor: str, depth: int, into: List[_Wrapper]) -> None:
    """Record the enclosing function as a wrapper if one of its parameters reaches the call."""
    function = source.enclosing(index)
    if function is None or not function.params or len(function.name) < 3:
        return
    statement = _statement(source.lines, index)
    tokens = set(re.findall(_IDENT, _code_outside_strings(statement)))
    for assigned_at, variable, value in source.assignments:
        if variable in tokens and function.start < assigned_at < index and _carries_its_inputs(value):
            tokens.update(re.findall(_IDENT, _code_outside_strings(value)))
    if not {token.lstrip("$") for token in tokens} & set(function.params):
        return
    if not any(w.rel == source.rel and w.name == function.name and w.processor == processor for w in into):
        into.append(_Wrapper(function.name, source.rel, processor, function.start, function.end, depth))


def _linked(source: _SourceFile, wrapper: _Wrapper) -> bool:
    """Does this file plausibly call *that* function, not another one with the same name?"""
    if source.rel == wrapper.rel:
        return True
    name, stem = wrapper.name.lower(), wrapper.stem
    for line in source.lines[:400]:
        if _IMPORT_LINE_RE.search(line):
            lowered = line.lower()
            if re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", lowered) or (len(stem) > 2 and re.search(rf"(?<![\w$]){re.escape(stem)}(?![\w$])", lowered)):
                return True
    # Languages where siblings share a package without importing each other.
    suffix = source.path.suffix.lower()
    if suffix in _IMPLICIT_PACKAGE_SUFFIXES and suffix == Path(wrapper.rel).suffix.lower():
        return str(Path(source.rel).parent) == str(Path(wrapper.rel).parent)
    return False


def _wrapper_call_sites(source: _SourceFile, wrapper: _Wrapper) -> List[int]:
    call_re = re.compile(rf"(?<![\w$]){re.escape(wrapper.name)}\s*\(")
    definition_re = re.compile(rf"\b(?:def|function|func|fun)\s+(?:\([^)]*\)\s*)?(?:self\.)?{re.escape(wrapper.name)}\b|\b(?:const|let|var)\s+{re.escape(wrapper.name)}\s*=")
    sites: List[int] = []
    for index, line in enumerate(source.lines):
        if not call_re.search(line) or definition_re.search(line) or _IMPORT_LINE_RE.search(line):
            continue
        if line.lstrip().startswith(("//", "#", "*", "/*")):
            continue
        if source.rel == wrapper.rel and wrapper.start <= index <= wrapper.end:
            continue  # the wrapper's own signature or a recursive call
        if any(function.start == index and function.name == wrapper.name for function in source.functions):
            continue  # another definition with the same name (method on a class, overload)
        if index not in sites:
            sites.append(index)
    return sites


def _assignments(lines: List[str]) -> List[Tuple[int, str, str]]:
    """(line index, variable, right-hand statement text) for simple assignments."""
    found = []
    for index, line in enumerate(lines):
        match = _ASSIGN_RE.match(line)
        if match and match.group(1) not in _SKIP_HANDLES:
            found.append((index, match.group(1), _statement(lines, index).split("=", 1)[-1]))
    return found


def _call_sites(source: _SourceFile, handles: Set[str], call_targets: Set[str]) -> List[int]:
    """Statement start indices of calls made on (or with) a vendor handle."""
    if not call_targets:
        return []
    lines = source.lines
    alternation = "|".join(re.escape(handle) for handle in sorted(call_targets, key=len, reverse=True))
    # handle.method(  /  handle(  /  new Handle(  /  Handle::method(  /  handle->method(
    # An SDK held on the instance counts too: self.client.x(  this.stripe.x(  $this->api->x(  s.rzp.X(
    target_re = re.compile(
        rf"(?:(?<![\w.>])|(?<=\bself\.)|(?<=\bthis\.)|(?<=\$this->)|(?<=@)|(?<=(?<![\w.])[a-z]\.))(?:{alternation})\s*(?:\.|\(|::|->)",
        re.IGNORECASE,
    )
    # A handle passed as an argument: requests.post(VENDOR_URL, json=...), fetch(vendorUrl, {{...}})
    argument_re = (
        re.compile(rf"(?:[(,]\s*|^\s*)(?:{'|'.join(re.escape(h) for h in sorted(handles, key=len, reverse=True))})\s*(?:[,)]|$)")
        if handles
        else None
    )
    starts = source.starts
    sites: List[int] = []
    for line_index, line in enumerate(lines):
        if _IMPORT_LINE_RE.search(line) or line.lstrip().startswith(("//", "#", "*", "/*")):
            continue
        if target_re.search(line):
            index = line_index
        elif argument_re and argument_re.search(line) and starts[line_index] != line_index:
            index = starts[line_index]
        elif argument_re and argument_re.search(line) and "(" in line.split("=", 1)[-1]:
            index = line_index
        else:
            continue
        if "(" in _statement(lines, index) and index not in sites:
            sites.append(index)
    return sites


def _site_evidence(
    source: _SourceFile,
    index: int,
    name: str,
    call_targets: Iterable[str],
    reported: Set[Tuple[str, int, str, str]],
    via: Optional[_Wrapper] = None,
) -> List[Evidence]:
    lines = source.lines
    statement = _statement(lines, index)
    opened = statement.find("(")
    arguments = statement[opened:] if opened >= 0 else ""
    direct = set(_categories_for_text(_call_arguments(statement)))
    hop: Set[str] = set()
    tokens = set(re.findall(_IDENT, _code_outside_strings(arguments)))
    targets = set(call_targets)
    for assigned_at, variable, value in source.assignments:
        if variable in tokens and variable not in targets and 0 < index - assigned_at <= _ASSIGN_LOOKBACK and _carries_its_inputs(value):
            hop.update(_categories_for_text(_argument_text(value)))
    out: List[Evidence] = []
    for category in sorted(direct | hop):
        key = (source.rel, index, category, name)
        if key in reported:
            continue
        reported.add(key)
        via_variable = category not in direct
        detector_id = f"flow.processor.{normalize_text(name)}.{normalize_text(category)}"
        if via is not None:
            detail = f"{category} data is passed to `{via.name}()` ({via.rel}:{via.start + 1}), which sends its arguments to {name}."
            flow = "wrapper"
        elif via_variable:
            detail = f"A variable built from {category} data is passed to a {name} call."
            flow = "one_hop"
        else:
            detail = f"{category} data is passed as an argument to a {name} call."
            flow = "direct"
        metadata = {
            "detector_id": detector_id,
            "confidence": "medium",
            "evidence_ref": f"{source.rel}:{index + 1}:{detector_id}",
            "file_context": source.file_context,
            "language": _language_for(source.path),
            "data_category": category,
            "third_party": name,
            "flow": flow,
            "semantic_role": "processor_sink",
            "ai_provider": name in AI_PROVIDERS,
        }
        if via is not None:
            metadata["via"] = f"{via.rel}:{via.start + 1}:{via.name}"
            metadata["wrapper_depth"] = via.depth
        if name in AI_PROVIDERS:
            detail = detail.replace(f"a {name} call", f"a {name} model call (prompt or request payload)")
        out.append(
            Evidence(
                kind="processor_data_flow",
                label=f"{category} data sent to {name}",
                severity=CATEGORY_SEVERITY.get(category, "MEDIUM"),
                source="data-flow",
                file=source.rel,
                line=index + 1,
                detail=detail,
                recommendation=f"Confirm {name} needs {category} data for the stated purpose, record it on the processor, and cover it in the contract and the notice.",
                category="Third-party processors",
                metadata=metadata,
            )
        )
    return out
