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
imports the wrapper's module (or shares its package), or names the interface
or base class the wrapper's class implements (dependency injection: the caller
holds a `NotificationService`, the container supplies `SmsNotificationService`).

Queues, task runners and event buses are followed too (see ``channels``): data
a producer publishes is attributed to every vendor its consumer reaches.
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

_FLOW_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".rb", ".go", ".java", ".kt", ".cs", ".php", ".html", ".htm"}
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
_ACCESSED_KEY_RE = re.compile(
    r"""(?:(?<=[\w\])])\[\s*["']([A-Za-z_][\w-]*)["']\s*\]|(?:->|\.)\s*(?:input|get|getParameter|getString|param|params|query|post|json|value|getHeader|getAttribute|getValue)\s*\(\s*["']([A-Za-z_][\w-]*)["'])"""
)
_KEY_RE = re.compile(r"""["']([A-Za-z_][\w-]*)["']\s*(?::|=>)""")
_IMPORT_LINE_RE = re.compile(r"^\s*(?:import\b|from\s+\S+\s+import\b|use\s|require_once|require\s*\(|#include)|\brequire\s*\(", re.IGNORECASE)
_ASSIGN_RE = re.compile(rf"^\s*(?:const|let|var|val|final)?\s*(?:self\.|this\.|\$)?({_IDENT})\s*(?::[^=]+)?(?::=|=)(?!=)\s*(.+)$")
_SDK_SETUP_RE = re.compile(r"^[.:>-]*\s*(?:init|initialize|configure|config|setup|set_up|setOptions|set_options|load|use)\s*\(", re.IGNORECASE)
_ASSIGNMENT_RE = re.compile(r"^\s*(?:const|let|var|val|final)?\s*[\w$.\[\]\"']+\s*(?::[^=]+)?(?::=|=)(?!=)")
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
    # String values sent to a vendor API are options ("expand": ["default_payment_method"]),
    # not field names; keys are kept separately below.
    # Field names read out of a request or a mapping are the data itself:
    # $request->input('email'), request.POST["phone"], data.get("pan"), params.require(:user)
    accessed = " ".join(part for pair in _ACCESSED_KEY_RE.findall(statement) for part in pair if part)
    return _code_outside_strings(statement, keep_identifier_literals=False) + " " + " ".join(_KEY_RE.findall(statement)) + " " + accessed


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
        # $mc = new \MailchimpMarketing\ApiClient();  var client = new Twilio.Clients.TwilioRestClient(sid, token);
        namespaced = re.match(r"^\s*(?:(?:var|val|const|let|final|auto)\s+|[\w<>\[\]]+\s+)?(\$?[A-Za-z_]\w*)\s*=\s*new\s+\\?([\w\\.]+)\s*\(", line)
        if namespaced and any(needle in namespaced.group(2).lower() for needle in lowered_needles):
            handles.add(namespaced.group(1).lstrip("$"))
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
        if suffix in {".java", ".cs"}:
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

    sinks: Dict[str, List[Tuple[int, str]]] = {}  # file -> (line index, processor) of every vendor or wrapper call

    # Pass 1: direct calls on a vendor SDK, and the functions that wrap them.
    for source in files:
        present = {name: needles for name, needles in THIRD_PARTY_PATTERNS.items() if any(needle.lower() in source.lowered for needle in needles)}
        for name, needles in present.items():
            handles = _handles_for(source.lines, needles)
            call_targets = handles | _needle_handles(needles)
            for index in _call_sites(source, handles, call_targets):
                sinks.setdefault(source.rel, []).append((index, name))
                evidence.extend(_site_evidence(source, index, name, call_targets, reported))
                _note_wrapper(source, index, name, 1, wrappers)

    # Pass 2: calls to those wrappers, anywhere in the repository.
    _follow_wrappers(files, wrappers, wrappers[:_MAX_WRAPPERS], evidence, reported, sinks)

    # Pass 3: queues, task runners and event buses. A producer's payload reaches
    # every vendor its consumer's code calls.
    if sinks:
        from svikruti.scanner.channels import constants_of, find_consumers, find_producers

        constants = constants_of(files)
        reach: Dict[str, List[Tuple[object, str]]] = {}
        consumers = find_consumers(files, constants)
        # A task queue can run any plain function handed to it: q.enqueue(text_borrower, phone) (RQ, Huey, arq).
        from svikruti.scanner.channels import Consumer

        for source in files:
            for function in source.functions:
                if any(function.start <= index <= function.end for index, _ in sinks.get(source.rel, [])):
                    consumers.append(Consumer(f"callable:{function.name.lower()}", source.rel, function.name, function.start, function.end))
        for consumer in consumers:
            for index, processor in sinks.get(consumer.rel, []):
                if consumer.start <= index <= consumer.end and not any(p == processor and c.rel == consumer.rel and c.start == consumer.start for c, p in reach.get(consumer.channel, [])):
                    reach.setdefault(consumer.channel, []).append((consumer, processor))
        produced: List[_Wrapper] = []
        if reach:
            for source in files:
                for producer in find_producers(source, constants):
                    for consumer, processor in reach.get(producer.channel, []):
                        if consumer.rel == source.rel and consumer.start <= producer.index <= consumer.end:
                            continue  # the consumer re-publishing to its own channel
                        hop = _Wrapper(consumer.name, consumer.rel, processor, consumer.start, consumer.end, 1)
                        evidence.extend(_site_evidence(source, producer.index, processor, set(), reported, via=hop, channel=producer.channel))
                        sinks.setdefault(source.rel, []).append((producer.index, processor))
                        _note_wrapper(source, producer.index, processor, 2, produced)
        known = {(w.rel, w.name, w.processor) for w in wrappers}
        fresh = [w for w in produced if (w.rel, w.name, w.processor) not in known][:_MAX_WRAPPERS]
        wrappers.extend(fresh)
        _follow_wrappers(files, wrappers, fresh, evidence, reported, sinks, rounds=1)
    return evidence


def _follow_wrappers(
    files: List[_SourceFile],
    wrappers: List[_Wrapper],
    current: List[_Wrapper],
    evidence: List[Evidence],
    reported: Set[Tuple[str, int, str, str]],
    sinks: Dict[str, List[Tuple[int, str]]],
    rounds: int = _WRAPPER_ROUNDS,
) -> None:
    for _ in range(rounds):
        if not current:
            break
        discovered: List[_Wrapper] = []
        for source in files:
            for wrapper in current:
                if wrapper.name.lower() not in source.lowered or not _linked(source, wrapper, files):
                    continue
                for index in _wrapper_call_sites(source, wrapper):
                    sinks.setdefault(source.rel, []).append((index, wrapper.processor))
                    evidence.extend(_site_evidence(source, index, wrapper.processor, {wrapper.name}, reported, via=wrapper))
                    _note_wrapper(source, index, wrapper.processor, wrapper.depth + 1, discovered)
        known = {(w.rel, w.name, w.processor) for w in wrappers}
        current = [w for w in discovered if (w.rel, w.name, w.processor) not in known][:_MAX_WRAPPERS]
        wrappers.extend(current)


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


def _linked(source: _SourceFile, wrapper: _Wrapper, files: Optional[List[_SourceFile]] = None) -> bool:
    """Does this file plausibly call *that* function, not another one with the same name?"""
    if source.rel == wrapper.rel:
        return True
    name, stem = wrapper.name.lower(), wrapper.stem
    for line in source.lines[:400]:
        if _IMPORT_LINE_RE.search(line):
            lowered = line.lower()
            if re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", lowered) or (len(stem) > 2 and re.search(rf"(?<![\w$]){re.escape(stem)}(?![\w$])", lowered)):
                return True
    # Dependency injection: the caller holds the interface or base class, the container
    # supplies the implementation that wraps the vendor.
    owner = next((item for item in files or [] if item.rel == wrapper.rel), None)
    if owner is not None:
        for contract in _contracts(owner, wrapper.start):
            if re.search(rf"(?<![\w$]){re.escape(contract)}(?![\w$])", source.lowered):
                return True
    # Languages where siblings share a package without importing each other.
    suffix = source.path.suffix.lower()
    if suffix in _IMPLICIT_PACKAGE_SUFFIXES and suffix == Path(wrapper.rel).suffix.lower():
        return str(Path(source.rel).parent) == str(Path(wrapper.rel).parent)
    return False


_CLASS_DECL_RE = re.compile(r"^(\s*)(?:export\s+)?(?:default\s+)?(?:(?:public|private|internal|final|abstract|sealed|open|data|partial|static)\s+)*class\s+([A-Za-z_]\w*)(.*)$")
_GENERIC_CONTRACTS = {"object", "base", "model", "service", "basemodel", "exception", "abc", "generic", "component", "controller", "interface", "protocol", "handler", "client", "provider", "module"}


def _contracts(source: _SourceFile, line: int) -> List[str]:
    """Interfaces and base classes of the class that encloses ``line`` (lowercased), for DI linking."""
    for index in range(min(line, len(source.lines) - 1), -1, -1):
        match = _CLASS_DECL_RE.match(source.lines[index])
        if not match:
            continue
        if len(match.group(1)) > len(source.lines[line]) - len(source.lines[line].lstrip()):
            continue
        header = " ".join(source.lines[index : index + 3])
        header = header.split("{", 1)[0]
        names: List[str] = []
        py = re.search(r"class\s+\w+\s*\(([^)]*)\)", header)
        if py and source.path.suffix.lower() == ".py":
            names = re.findall(r"([A-Za-z_]\w*)\s*(?:,|$)", py.group(1))
        else:
            tail = re.search(r"(?:\bextends|\bimplements|:)\s+(.+)$", header.split("class", 1)[-1])
            if tail:
                names = re.findall(r"([A-Z]\w+)", re.sub(r"<[^>]*>", "", tail.group(1)))
        return [name.lower() for name in names if len(name) >= 6 and name.lower() not in _GENERIC_CONTRACTS]
    return []


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
        if re.search(rf"(?:^|[{{;])\s*(?:(?:public|private|protected|internal|static|abstract|default|final|synchronized|override|virtual|async)\s+)*[\w<>\[\],.?]+\s+{re.escape(wrapper.name)}\s*\([^)]*\)\s*(?:throws\s+[\w., ]+)?\s*;", line) and not re.match(r"^\s*(?:return|await|yield|throw|new|else)\b", line):
            continue  # an interface or abstract method declaration: `void notifyUser(String phone);`
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
        target = target_re.search(line)
        if target and _SDK_SETUP_RE.search(line[target.end() - 1 :]):
            continue  # sentry_sdk.init(...), mixpanel.init(token): configuration, not data
        if target and target.group(0).rstrip().endswith("(") and starts[line_index] != line_index and re.search(r"[:,(=]\s*$", line[: target.start()]):
            # The vendor client is a value inside a larger call, as in the Vercel AI SDK:
            # generateText({ model: openai("gpt-4o"), prompt: `... ${user.email}` })
            index = starts[line_index]
        elif target:
            index = line_index
        elif argument_re and argument_re.search(line) and starts[line_index] != line_index:
            index = starts[line_index]
        elif argument_re and argument_re.search(line) and "(" in (line.split("=", 1)[-1] if _ASSIGNMENT_RE.match(line) else line):
            # requests.post(VENDOR_URL, json={...}): only an assignment's left side is skipped,
            # never a keyword argument's.
            index = line_index
        else:
            continue
        if re.search(r"(?:\.|::|->)\s*(?:init|initialize|configure|setup|set_up|setOptions)\s*\(", lines[index], re.IGNORECASE):
            continue  # the enclosing statement configures an SDK (sentry_sdk.init(integrations=[...]))
        if "(" in _statement(lines, index) and index not in sites:
            sites.append(index)
    return sites


FREE_TEXT = "Free text"
_REQUEST_SOURCE_RE = re.compile(
    r"(?:\b(?:req|request|ctx\.request|event|evt)\s*\.\s*(?:body|json|data|form|POST|GET|args|values|query|query_params|params|get_json|input|stream|text)\b"
    r"|\$request\s*->\s*(?:input|get|all|post|json|string)\b|\$_(?:POST|GET|REQUEST)\b|(?<![\w.])params\s*\[|\bparams\.(?:require|permit|fetch)\b"
    r"|\bformData\.get\s*\(|\b(?:ShouldBindJSON|ShouldBind|BindJSON|BodyParser|PostForm)\s*\(|\bc\.(?:Bind|Query|Param)\s*\("
    r"|\bupdate\.message\.text\b|\bevent\s*\[\s*[\"']body[\"']\s*\]|\bst\.(?:chat_input|text_input|text_area)\s*\(|\binput\s*\(\s*[\"'])"
)
_FREE_FIELD = r"(?:prompt|question|query|message|messages|content|text|input|user_input|userinput|user_message|usermessage|chat_input|comment|feedback|transcript|conversation|history|description|notes?|body|utterance|instruction|instructions)"
_HOLDER_PARAMS = {"req", "request", "body", "payload", "dto", "form", "data", "params", "input", "chat", "command", "cmd", "args"}
_FIELD_OF_HOLDER_RE = re.compile(rf"(?<![\w$])({'|'.join(sorted(_HOLDER_PARAMS))})\s*(?:\.\s*(?:get_?)?{_FREE_FIELD}\b|\[\s*[\"']{_FREE_FIELD}[\"']\s*\]|\.get\s*\(\s*[\"']{_FREE_FIELD}[\"'])", re.IGNORECASE)
_ROUTE_SIGNATURE_RE = re.compile(r"@(?:RequestBody|RequestParam|PathVariable|Body|Query|Param)\b|\bBody\s*\(|\bForm\s*\(|@(?:app|router|api|bp|blueprint)\.(?:post|put|patch|route|get|websocket)\b|@(?:Post|Put|Patch|Get)Mapping\b|@(?:Post|Put|Get|Patch)\s*\(|\b(?:req|request)\s*[:,)]", re.IGNORECASE)
_DESTRUCTURE_RE = re.compile(r"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$")
_REDACTION_RE = re.compile(
    r"\b(?:redact\w*|scrub\w*|anonymi[sz]e\w*|pseudonymi[sz]e\w*|deidentify\w*|de_identify\w*|mask_?pii\w*|maskPII|strip_?pii\w*|remove_?pii\w*|sanitize_?pii\w*|sanitizePII|filter_?pii\w*|filterPII|pii_?(?:filter|scrub|redact|mask)\w*)\s*\("
    r"|\b(?:AnalyzerEngine|AnonymizerEngine|BatchAnonymizerEngine|DeidentifyContent|deidentify_content|detect_pii_entities|DetectPiiEntities|scrubadub|presidio_\w+)\b"
    r"|\bAnonymize\s*\(|\bllm_guard\b|\bscan_prompt\s*\(",
)


def _free_text_source(source: _SourceFile, index: int, statement: str, tokens: Set[str]) -> Optional[str]:
    """Where user-typed text in an AI call comes from, or None. Redacted text counts as None."""
    function = source.enclosing(index)
    start = function.start if function is not None else max(0, index - _ASSIGN_LOOKBACK)
    region = source.lines[start : index + 1]
    reached = [statement]
    names = {token.lstrip("$") for token in tokens} | set(_KEY_RE.findall(statement))
    for _ in range(3):
        grew = False
        for assigned_at, variable, value in source.assignments:
            if start <= assigned_at < index and variable in names and value not in reached:
                if not (_carries_its_inputs(value) or _REQUEST_SOURCE_RE.search(value) or _REDACTION_RE.search(value)):
                    continue  # `response = await client.create(...)` is the vendor's answer, not the user's text
                reached.append(value)
                names.update(re.findall(_IDENT, _code_outside_strings(value)))
                grew = True
        for offset, line in enumerate(region):
            match = _DESTRUCTURE_RE.match(line)
            if match and {part.split(":")[0].strip() for part in match.group(1).split(",")} & names and match.group(2) not in reached:
                reached.append(match.group(2))
                names.update(re.findall(_IDENT, _code_outside_strings(match.group(2))))
                grew = True
        if not grew:
            break
    text = "\n".join(reached)
    found = _REQUEST_SOURCE_RE.search(text)
    label = None
    if found:
        label = f"`{found.group(0).strip()}`"
    else:
        field_of = _FIELD_OF_HOLDER_RE.search(text)
        params = set(function.params) if function is not None else set()
        signature = "\n".join(source.lines[max(0, start - 3) : start + 3])
        if field_of and field_of.group(1) in params and _ROUTE_SIGNATURE_RE.search(signature):
            label = f"`{field_of.group(0).strip()}`"
        elif function is not None and _ROUTE_SIGNATURE_RE.search(signature):
            typed = [param for param in function.params if re.fullmatch(_FREE_FIELD, param, re.IGNORECASE) and param in names]
            if typed:
                label = f"request parameter `{typed[0]}`"
    if label is None:
        return None
    if _REDACTION_RE.search("\n".join(region)) or _REDACTION_RE.search(text):
        return None
    return label


def _site_evidence(
    source: _SourceFile,
    index: int,
    name: str,
    call_targets: Iterable[str],
    reported: Set[Tuple[str, int, str, str]],
    via: Optional[_Wrapper] = None,
    channel: Optional[str] = None,
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
    free_text = _free_text_source(source, index, statement, tokens) if name in AI_PROVIDERS else None
    if free_text:
        direct.add(FREE_TEXT)
    out: List[Evidence] = []
    for category in sorted(direct | hop):
        key = (source.rel, index, category, name)
        if key in reported:
            continue
        reported.add(key)
        via_variable = category not in direct
        detector_id = f"flow.processor.{normalize_text(name)}.{normalize_text(category)}"
        if channel is not None and via is not None:
            from svikruti.scanner.channels import describe

            handler = f"`{via.name}()`" if not via.name.startswith("<") else "a consumer"
            detail = f"{category} data is published to {describe(channel)}; {handler} ({via.rel}:{via.start + 1}) consumes it and calls {name}."
            flow = "queue"
        elif via is not None:
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
        if channel is not None:
            metadata["channel"] = channel
        if name in AI_PROVIDERS:
            detail = detail.replace(f"a {name} call", f"a {name} model call (prompt or request payload)")
        severity = CATEGORY_SEVERITY.get(category, "MEDIUM")
        if category == FREE_TEXT:
            severity = "HIGH"
            metadata["free_text_source"] = free_text
            reach = f"`{via.name}()`, which calls {name}" if via is not None else name
            detail = (
                f"Text a user typed ({free_text}) is sent to {reach} without redaction. It can carry any personal data "
                "(names, phone numbers, IDs, health details); static analysis cannot tell which."
            )
        out.append(
            Evidence(
                kind="processor_data_flow",
                label=f"{category} data sent to {name}",
                severity=severity,
                source="data-flow",
                file=source.rel,
                line=index + 1,
                detail=detail,
                recommendation=(
                    f"Redact personal data before the call (Presidio, scrubadub, llm-guard Anonymize, or your own redact()), or record free_text "
                    f"on the activity and the {name} processor and under policies.ai_allowed_categories after review."
                    if category == FREE_TEXT
                    else f"Confirm {name} needs {category} data for the stated purpose, record it on the processor, and cover it in the contract and the notice."
                ),
                category="Third-party processors",
                metadata=metadata,
            )
        )
    return out
