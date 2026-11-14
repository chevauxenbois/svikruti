"""Processor data flows: which personal data is handed to which third party.

A third-party SDK in a file tells you a processor exists. It does not tell you
what it receives. This detector follows the SDK from its import to the calls
made on it and reports the personal-data categories in those calls' arguments:

    const mixpanel = require("mixpanel").init(token);
    mixpanel.track("refund_requested", { email, pincode });   ->  Contact, Location -> Mixpanel

Scope and honesty: analysis is per file. A handle is an identifier bound to
the SDK by an import/require, by construction from such an identifier, or a
constant holding the vendor's URL. Arguments are followed one assignment back
(``payload = {...}`` then ``sdk.send(payload)``). Data that reaches a vendor
through a wrapper defined in another file is not seen.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from svikruti.models import Evidence
from svikruti.scanner.code import _code_outside_strings, _file_context, _is_fixture_file, _language_for, iter_source_files
from svikruti.scanner.patterns import CATEGORY_SEVERITY, THIRD_PARTY_PATTERNS, normalize_text
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


def _argument_text(statement: str) -> str:
    """Identifiers, interpolations and object/dict keys in a statement; message prose dropped."""
    return _code_outside_strings(statement) + " " + " ".join(_KEY_RE.findall(statement))


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
            if any(needle in lowered_literal for needle in lowered_needles) and ("/" in literal or "." in literal):
                handles.update(_bound_names(line.split(literal)[0]))
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
        seeds = handles | _needle_handles(needles)
        if len(handles) == before:
            break
    return {handle for handle in handles if handle not in _SKIP_HANDLES and len(handle) > 1}


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


def scan_processor_flows(repo_path: str) -> List[Evidence]:
    root = Path(repo_path).resolve()
    evidence: List[Evidence] = []
    for path in iter_source_files(root):
        if path.suffix.lower() not in _FLOW_SUFFIXES:
            continue
        rel = str(path.relative_to(root))
        if _is_fixture_file(root, rel):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        file_context = _file_context(rel, text)
        if file_context == "reference":
            continue
        lowered_text = text.lower()
        present = {name: needles for name, needles in THIRD_PARTY_PATTERNS.items() if any(needle.lower() in lowered_text for needle in needles)}
        if not present:
            continue
        lines = text.splitlines()
        assignments = _assignments(lines)
        for name, needles in present.items():
            evidence.extend(_flows_for_processor(name, needles, lines, assignments, rel, path, file_context))
    return evidence


def _assignments(lines: List[str]) -> List[Tuple[int, str, str]]:
    """(line index, variable, right-hand statement text) for simple assignments."""
    found = []
    for index, line in enumerate(lines):
        match = _ASSIGN_RE.match(line)
        if match and match.group(1) not in _SKIP_HANDLES:
            found.append((index, match.group(1), _statement(lines, index).split("=", 1)[-1]))
    return found


def _flows_for_processor(
    name: str,
    needles: List[str],
    lines: List[str],
    assignments: List[Tuple[int, str, str]],
    rel: str,
    path: Path,
    file_context: str,
) -> List[Evidence]:
    handles = _handles_for(lines, needles)
    call_targets = handles | _needle_handles(needles)
    if not call_targets:
        return []
    alternation = "|".join(re.escape(handle) for handle in sorted(call_targets, key=len, reverse=True))
    # handle.method(  /  handle(  /  new Handle(  /  Handle::method(  /  handle->method(
    target_re = re.compile(rf"(?<![\w.])(?:{alternation})\s*(?:\.|\(|::|->)", re.IGNORECASE)
    # A handle passed as an argument: requests.post(VENDOR_URL, json=...), fetch(vendorUrl, {{...}})
    argument_re = (
        re.compile(rf"(?:[(,]\s*|^\s*)(?:{'|'.join(re.escape(h) for h in sorted(handles, key=len, reverse=True))})\s*(?:[,)]|$)")
        if handles
        else None
    )
    starts = _statement_starts(lines)

    out: List[Evidence] = []
    seen: Set[Tuple[int, str]] = set()
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
        statement = _statement(lines, index)
        if "(" not in statement:
            continue
        argument_text = _argument_text(statement)
        direct = set(_categories_for_text(argument_text))
        hop: Set[str] = set()
        tokens = set(re.findall(_IDENT, _code_outside_strings(statement)))
        for assigned_at, variable, value in assignments:
            if variable in tokens and variable not in call_targets and 0 < index - assigned_at <= _ASSIGN_LOOKBACK:
                hop.update(_categories_for_text(_argument_text(value)))
        for category in sorted(direct | hop):
            if (index, category) in seen:
                continue
            seen.add((index, category))
            via_variable = category not in direct
            detector_id = f"flow.processor.{normalize_text(name)}.{normalize_text(category)}"
            out.append(
                Evidence(
                    kind="processor_data_flow",
                    label=f"{category} data sent to {name}",
                    severity=CATEGORY_SEVERITY.get(category, "MEDIUM"),
                    source="data-flow",
                    file=rel,
                    line=index + 1,
                    detail=(
                        f"A variable built from {category} data is passed to a {name} call."
                        if via_variable
                        else f"{category} data is passed as an argument to a {name} call."
                    ),
                    recommendation=f"Confirm {name} needs {category} data for the stated purpose, record it on the processor, and cover it in the contract and the notice.",
                    category="Third-party processors",
                    metadata={
                        "detector_id": detector_id,
                        "confidence": "medium",
                        "evidence_ref": f"{rel}:{index + 1}:{detector_id}",
                        "file_context": file_context,
                        "language": _language_for(path),
                        "data_category": category,
                        "third_party": name,
                        "flow": "one_hop" if via_variable else "direct",
                        "semantic_role": "processor_sink",
                    },
                )
            )
    return out
