"""Inline suppressions: `svikruti-ignore` comments next to the code they excuse.

    logger.info("chargeback dispute for %s", customer.email)  # svikruti-ignore[P001]: chargeback evidence, masked in Q1
    # svikruti-ignore[P006]: support summaries are approved by DPO ticket PRIV-212
    summary = client.chat.completions.create(...)

The comment goes on the flagged line or the line above it. A rule list in
brackets limits it to those rules; without one it covers every rule. A reason
of at least 10 characters is required: a bare `svikruti-ignore` is reported
as a manifest warning and suppresses nothing. Suppressions are listed in the
report next to manifest exceptions, so reviewers can see and challenge them.

For `svikruti scan`, a suppression with no rule list, or with `scan` in it,
also removes scanner evidence on that line from the risk score and SARIF.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SUPPRESS_RE = re.compile(r"svikruti-ignore(?:\[([A-Za-z0-9_,\s-]+)\])?\s*:?\s*(.*)")
_CLOSERS_RE = re.compile(r"\s*(?:\*/|-->|%>|\}\}|#\})\s*$")


class _Lines:
    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.cache: Dict[str, Optional[List[str]]] = {}

    def get(self, rel: str) -> Optional[List[str]]:
        if rel not in self.cache:
            try:
                path = (self.root / rel).resolve()
                path.relative_to(self.root)
                self.cache[rel] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except (OSError, ValueError):
                self.cache[rel] = None
        return self.cache[rel]


def parse(line: str) -> Optional[Tuple[Set[str], str]]:
    """(rules or {'*'}, reason) for a line carrying svikruti-ignore, else None."""
    match = SUPPRESS_RE.search(line)
    if not match:
        return None
    rules = {item.strip().upper() for item in (match.group(1) or "").split(",") if item.strip()} or {"*"}
    reason = _CLOSERS_RE.sub("", match.group(2) or "").strip().strip("\"'").strip()
    return rules, reason


def suppression_at(lines: Optional[List[str]], line: int) -> Optional[Tuple[Set[str], str]]:
    """Suppression on 1-based ``line`` or on the line directly above it."""
    if not lines or not line or line > len(lines):
        return None
    for index in (line - 1, line - 2):
        if 0 <= index < len(lines):
            found = parse(lines[index])
            if found:
                return found
    return None


def _split_ref(ref: str) -> Tuple[str, Optional[int]]:
    head, _, tail = ref.rpartition(":")
    return (head, int(tail)) if head and tail.isdigit() else (ref, None)


def apply_inline_suppressions(findings: list, root: str) -> List[str]:
    """Mark findings whose every located ref carries a matching, reasoned suppression. Returns warnings."""
    lines = _Lines(root)
    warnings: List[str] = []
    for finding in findings:
        if finding.status != "open" or not finding.refs:
            continue
        reasons: List[str] = []
        for ref in finding.refs:
            rel, number = _split_ref(ref)
            found = suppression_at(lines.get(rel), number) if number else None
            if not found or not ({"*", finding.rule} & found[0]):
                reasons = []
                break
            if len(found[1]) < 10:
                warnings.append(f"{ref}: svikruti-ignore without a reason (at least 10 characters) is not applied")
                reasons = []
                break
            reasons.append(f"{found[1]} ({ref})")
        if reasons:
            finding.status = "excepted"
            finding.exception_reason = "inline: " + "; ".join(dict.fromkeys(reasons))
    return warnings


def suppress_scan_evidence(evidence: list, root: Optional[str]) -> int:
    """Tag scanner evidence on lines with a general or `scan` suppression. Returns how many."""
    if not root:
        return 0
    lines = _Lines(root)
    count = 0
    for item in evidence:
        if not item.file or not item.line:
            continue
        found = suppression_at(lines.get(item.file), item.line)
        if found and ({"*", "SCAN"} & found[0]) and len(found[1]) >= 10:
            item.metadata["suppressed"] = found[1]
            count += 1
    return count
