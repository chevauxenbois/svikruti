"""Stable finding fingerprints and baseline diffing.

A fingerprint identifies a finding by *what* it is (file, detector, the
normalised source line) instead of *where* it is (line number), so unrelated
edits above a finding do not make it look new. That is what lets a CI gate
fail on findings a pull request introduces while leaving the existing backlog
to be burned down separately.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from svikruti.models import Evidence
from svikruti.pac.taxonomy import SEVERITY_ORDER, at_least

FINGERPRINT_VERSION = "svk1"

_NON_RISK_KINDS = {
    "encryption_evidence", "security_tooling", "security_monitoring", "endpoint_security",
    "incident_readiness", "resilience_evidence", "cloud_security_evidence",
}


def _digest(*parts: object) -> str:
    joined = "\x1f".join("" if part is None else str(part) for part in parts)
    return f"{FINGERPRINT_VERSION}:{hashlib.sha256(joined.encode('utf-8', 'ignore')).hexdigest()[:24]}"


def _normalize_line(text: str) -> str:
    return " ".join(text.split())


class _LineCache:
    def __init__(self, root: Optional[Path]):
        self.root = root
        self._files: Dict[str, Optional[List[str]]] = {}

    def line(self, rel: Optional[str], number: Optional[int]) -> Optional[str]:
        if not self.root or not rel or not number or number < 1:
            return None
        if rel not in self._files:
            try:
                path = (self.root / rel).resolve()
                path.relative_to(self.root)  # never read outside the repo
                self._files[rel] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except (OSError, ValueError):
                self._files[rel] = None
        lines = self._files[rel]
        if lines is None or number > len(lines):
            return None
        return _normalize_line(lines[number - 1])


def assign_fingerprints(evidence: Iterable[Evidence], repo: Optional[str] = None) -> None:
    """Attach ``metadata['fingerprint']`` to every evidence item in place."""
    root = Path(repo).resolve() if repo else None
    cache = _LineCache(root)
    seen: Dict[str, int] = {}
    for item in evidence:
        detector = item.metadata.get("detector_id") or item.kind
        file_key = (item.file or "").replace("\\", "/")
        line_text = cache.line(item.file, item.line)
        if line_text is not None:
            base = _digest(file_key, detector, line_text)
        elif item.file:
            # File-level finding, or the line is unreadable: identify by content, not position.
            subject = item.metadata.get("third_party") or item.metadata.get("data_category") or item.label
            base = _digest(file_key, detector, "file", subject)
        else:
            subject = item.metadata.get("third_party") or item.metadata.get("domain") or item.metadata.get("evidence_ref") or item.label
            base = _digest(item.source, detector, "global", subject)
        ordinal = seen.get(base, 0)
        seen[base] = ordinal + 1
        item.metadata["fingerprint"] = base if ordinal == 0 else f"{base}-{ordinal}"


def load_report(path: str) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "evidence" not in data:
        raise ValueError(f"{path} is not a Svikruti JSON report (no 'evidence' key)")
    return data


def _fallback_key(item: Dict[str, Any], seen: Dict[str, int]) -> str:
    """Position-free key for reports written before fingerprints existed."""
    metadata = item.get("metadata") or {}
    base = _digest(item.get("file"), metadata.get("detector_id") or item.get("kind"), item.get("label"), "legacy")
    ordinal = seen.get(base, 0)
    seen[base] = ordinal + 1
    return f"{base}-{ordinal}"


def _index(report: Dict[str, Any], legacy: bool) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    seen: Dict[str, int] = {}
    items = report.get("evidence") or []
    if legacy:
        items = sorted(items, key=lambda entry: (str(entry.get("file")), entry.get("line") or 0, str(entry.get("label"))))
    for item in items:
        metadata = item.get("metadata") or {}
        key = _fallback_key(item, seen) if legacy else metadata.get("fingerprint")
        if key:
            index.setdefault(key, item)
    return index


def is_risk(item: Dict[str, Any]) -> bool:
    metadata = item.get("metadata") or {}
    return item.get("kind") not in _NON_RISK_KINDS and not metadata.get("positive_evidence")


def _facts(report: Dict[str, Any]) -> Tuple[set, set, set]:
    """(categories, third parties, (category, file) logging flows) present in a report."""
    categories, third_parties, log_flows = set(), set(), set()
    for item in report.get("evidence") or []:
        metadata = item.get("metadata") or {}
        category = metadata.get("data_category")
        if category:
            categories.add(str(category))
            if "log" in str(item.get("kind", "")):
                log_flows.add((str(category), str(item.get("file"))))
        third_party = metadata.get("third_party") or (metadata.get("domain") if "third_party" in str(item.get("kind")) else None)
        if third_party:
            third_parties.add(str(third_party))
    return categories, third_parties, log_flows


def diff_reports(base: Dict[str, Any], head: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two scan reports. ``new`` is what head introduced, ``resolved`` what it fixed."""
    def has_fingerprints(report: Dict[str, Any]) -> bool:
        items = report.get("evidence") or []
        return bool(items) and all((item.get("metadata") or {}).get("fingerprint") for item in items)

    legacy = not (has_fingerprints(base) or not base.get("evidence")) or not (has_fingerprints(head) or not head.get("evidence"))
    base_index = _index(base, legacy)
    head_index = _index(head, legacy)

    def ordered(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(
            items,
            key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), 0), str(item.get("file")), item.get("line") or 0),
        )

    new = ordered([item for key, item in head_index.items() if key not in base_index and is_risk(item)])
    resolved = ordered([item for key, item in base_index.items() if key not in head_index and is_risk(item)])
    base_categories, base_third, base_logs = _facts(base)
    head_categories, head_third, head_logs = _facts(head)
    return {
        "schema_version": "svikruti-diff-v1",
        "matching": "legacy-position-free" if legacy else "fingerprint",
        "base_generated_at": base.get("generated_at"),
        "head_generated_at": head.get("generated_at"),
        "new": new,
        "resolved": resolved,
        "unchanged_count": len([key for key in head_index if key in base_index]),
        "new_data_categories": sorted(head_categories - base_categories),
        "removed_data_categories": sorted(base_categories - head_categories),
        "new_third_parties": sorted(head_third - base_third),
        "removed_third_parties": sorted(base_third - head_third),
        "new_logging_flows": [{"data_category": c, "file": f} for c, f in sorted(head_logs - base_logs)],
        "risk_score_delta": (head.get("summary") or {}).get("risk_score", 0) - (base.get("summary") or {}).get("risk_score", 0),
    }


def new_at_or_above(diff: Dict[str, Any], threshold: str) -> List[Dict[str, Any]]:
    return [item for item in diff.get("new", []) if at_least(str(item.get("severity", "LOW")), threshold)]


def diff_markdown(diff: Dict[str, Any], limit: int = 25) -> str:
    new, resolved = diff.get("new", []), diff.get("resolved", [])
    lines = [
        "## Svikruti privacy diff",
        "",
        f"**{len(new)} new** finding(s), **{len(resolved)} resolved**, {diff.get('unchanged_count', 0)} unchanged. "
        f"Risk score change: {diff.get('risk_score_delta', 0):+d}.",
        "",
    ]
    headline = []
    if diff.get("new_data_categories"):
        headline.append(f"- New personal data categories: **{', '.join(diff['new_data_categories'])}**")
    if diff.get("new_third_parties"):
        headline.append(f"- New third parties / processors: **{', '.join(diff['new_third_parties'])}**")
    for flow in diff.get("new_logging_flows", [])[:10]:
        headline.append(f"- {flow['data_category']} data now reaches logs in `{flow['file']}`")
    if diff.get("removed_data_categories"):
        headline.append(f"- No longer detected: {', '.join(diff['removed_data_categories'])}")
    if headline:
        lines += ["### What changed in the data map", "", *headline, ""]
    if new:
        lines += ["### New findings", "", "| Severity | Finding | Location |", "|---|---|---|"]
        # Several detector layers can report the same line; show it once with a count.
        rows: Dict[Tuple[str, str, str], int] = {}
        for item in new:
            location = f"`{item.get('file')}:{item.get('line')}`" if item.get("line") else f"`{item.get('file') or item.get('source')}`"
            key = (str(item.get("severity")), _cell(item.get("label")), location)
            rows[key] = rows.get(key, 0) + 1
        for (severity, label, location), count in list(rows.items())[:limit]:
            lines.append(f"| {severity} | {label}{f' (x{count})' if count > 1 else ''} | {location} |")
        if len(rows) > limit:
            lines.append(f"| | ...and {len(rows) - limit} more | |")
        lines.append("")
    if resolved:
        lines += [f"### Resolved ({len(resolved)})", ""]
        for item in resolved[:10]:
            lines.append(f"- {_cell(item.get('label'))} (`{item.get('file')}`)")
        lines.append("")
    if not new and not resolved and not headline:
        lines.append("No change in privacy evidence.")
    return "\n".join(lines).rstrip() + "\n"


def _cell(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")
