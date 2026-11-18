"""Field-level data inventory: every stored personal-data field, and where it goes.

The record of processing says "repayments handles contact data". A rights
request, a breach assessment or a DPIA needs the next level down: which table
or model, which column, and whether that category reaches logs or a processor
from the same activity. This builds that list from scanner evidence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from svikruti.models import ScanResult
from svikruti.pac.datastore import _CONTAINER_RES, cascades, entry_label, model_cascades, erasure_coverage, erasure_paths, field_protection, protection_index, rights_request_entrypoints
from svikruti.pac.globs import match_any
from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES, category_slug
from svikruti.reports.exports import _write_rows



def _container(lines: Optional[List[str]], line: Optional[int]) -> str:
    """Nearest enclosing table / model / class above ``line``."""
    if not lines or not line:
        return ""
    for index in range(min(line, len(lines)) - 1, max(line - 120, 0) - 1, -1):
        for pattern in _CONTAINER_RES:
            match = pattern.search(lines[index])
            if match:
                return match.group(1)
    return ""


def production_files(root: Optional[Path]) -> List[str]:
    """Source files outside tests and docs: where protection and erasure code lives."""
    if root is None:
        return []
    from svikruti.scanner.code import _file_context, _is_fixture_file, iter_source_files

    files = []
    for path in iter_source_files(root):
        rel = str(path.relative_to(root)).replace("\\", "/")
        if path.suffix.lower() in {".md", ".txt", ".csv", ".json", ".lock", ".svg", ".html", ".htm"} or _is_fixture_file(root, rel):
            continue
        try:
            head = path.read_text(encoding="utf-8", errors="ignore")[:20000]
        except OSError:
            continue
        if _file_context(rel, head) in {"test", "reference"}:
            continue
        files.append(rel)
    return files


def build_inventory(scan: ScanResult, check: Any = None) -> List[Dict[str, Any]]:
    """One row per stored personal-data field. ``check`` (a CheckResult) adds the declared side."""
    root = Path(scan.repo_path).resolve() if scan.repo_path else None
    cache: Dict[str, Optional[List[str]]] = {}

    def lines_for(rel: str) -> Optional[List[str]]:
        if rel not in cache:
            try:
                path = (root / rel).resolve()
                path.relative_to(root)
                cache[rel] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except (OSError, ValueError, TypeError):
                cache[rel] = None
        return cache[rel]

    activities = check.activities_view if check is not None else []
    ignore = check.manifest.policies.ignore_paths if check is not None else []

    def activity_for(rel: str) -> Optional[Dict[str, Any]]:
        return next((activity for activity in activities if rel in activity["files"]), None)

    rows: List[Dict[str, Any]] = []
    seen = set()
    for item in scan.evidence:
        metadata = item.metadata
        if metadata.get("semantic_role") != "storage_field" or not metadata.get("field") or not item.file:
            continue
        rel = item.file.replace("\\", "/")
        if metadata.get("file_context") in {"test", "reference"} or (ignore and match_any(rel, ignore)):
            continue
        container = str(metadata.get("class") or metadata.get("table") or "") or _container(lines_for(rel), item.line)
        key = (rel, container, metadata["field"])
        if key in seen:
            continue
        seen.add(key)
        category = str(metadata.get("data_category") or "")
        slug = category_slug(category)
        activity = activity_for(rel)
        sent_to = sorted(flow["processor"] for flow in (activity or {}).get("detected_flows", []) if category in flow["categories"])
        rows.append(
            {
                "store": container,
                "field": str(metadata["field"]),
                "data_category": category,
                "high_risk": slug in HIGH_RISK_CATEGORIES,
                "file": rel,
                "line": item.line,
                "activity": (activity or {}).get("id", ""),
                "declared": None if activity is None else category in activity["declared_categories"],
                "reaches_logs": bool(activity) and category in activity["logged_categories"],
                "sent_to": sent_to,
                "retention": (activity or {}).get("retention", ""),
                "parser": str(metadata.get("parser") or ""),
                "confidence": str(metadata.get("confidence") or ""),
            }
        )
    rows.sort(key=lambda row: (row["file"], row["store"], row["line"] or 0))
    _annotate(rows, root, lines_for, check)
    return rows


def _annotate(rows: List[Dict[str, Any]], root: Optional[Path], lines_for: Any, check: Any) -> None:
    """Add protection and erasure coverage to each inventory row."""
    if not rows:
        return
    files = production_files(root)
    index = protection_index(root, files)
    for row in rows:
        lines = lines_for(row["file"]) or []
        declaration = lines[row["line"] - 1] if row["line"] and row["line"] <= len(lines) else ""
        # Annotations sit on the lines above a Java / Kotlin / TypeScript field:
        # @Convert(converter = AttributeEncryptor.class) / @Column({ transformer: encrypted })
        above = row["line"] - 2 if row["line"] else -1
        while 0 <= above < len(lines) and lines[above].strip().startswith("@"):
            declaration = lines[above] + " " + declaration
            above -= 1
        protection = field_protection(row["field"], declaration, f"{row['file']}:{row['line']}", index)
        row["protection"] = protection.kind
        row["protection_evidence"] = protection.evidence
    from svikruti.pac.datastore import is_persistent_store, store_header

    for row in rows:
        lines = lines_for(row["file"]) or []
        row["persistent"] = bool(row["store"]) and is_persistent_store(row["file"], store_header(lines, row["line"] or 1))
    erasure = check.manifest.erasure if check is not None else None
    paths = erasure_paths(root, files, erasure.handlers if erasure else ())
    stores: Dict[str, Any] = {}
    for row in rows:
        if row["store"] and row["persistent"]:
            stores.setdefault(row["store"], (row["file"], row["line"] or 1))
    cascade_map = cascades(root, stores)
    model_parents = model_cascades(root, files)
    coverage = erasure_coverage(stores, paths, erasure.retained if erasure else {}, cascade_map, model_parents)
    # Which of those deletions a data subject's request actually reaches.
    entries = rights_request_entrypoints(root, files, erasure.entrypoints if erasure else ())
    from_request = erasure_coverage(stores, entries, {}, cascade_map, model_parents) if entries else {}
    for row in rows:
        row["erasure"] = coverage.get(row["store"], "") if row["persistent"] else "n/a (not a stored table or model)"
        if not row["persistent"]:
            row["rights_request"] = "n/a"
        elif row["erasure"].startswith("retained"):
            row["rights_request"] = "retained"
        else:
            row["rights_request"] = from_request.get(row["store"], "").replace("reached by ", "reached from ")
    if rows:
        rows[0].setdefault("_erasure_paths", [f"{path.name}:{path.file}:{path.line}" for path in paths])
        rows[0].setdefault("_rights_entries", [entry_label(entry) for entry in entries])


def write_inventory_csv(rows: List[Dict[str, Any]], path: str) -> None:
    def declared(value: Optional[bool]) -> str:
        return "no manifest" if value is None else ("yes" if value else "NO")

    _write_rows(
        path,
        [
            "Store (table / model)", "Field", "Data Category", "High Risk", "File", "Line", "Processing Activity", "Category Declared",
            "Category Reaches Logs (activity)", "Category Sent To (activity)", "Persistent Store", "Field Protection", "Protection Evidence", "Erasure Path",
            "Reached By Rights Request", "Retention", "Parser", "Confidence",
        ],
        [
            [
                row["store"], row["field"], row["data_category"], "yes" if row["high_risk"] else "no", row["file"], row["line"] or "",
                row["activity"], declared(row["declared"]), "yes" if row["reaches_logs"] else "no", "; ".join(row["sent_to"]),
                "yes" if row.get("persistent") else "no", row.get("protection", ""), row.get("protection_evidence", ""), row.get("erasure", "") or "not found",
                row.get("rights_request", "") or ("no" if row.get("persistent") else "n/a"), row["retention"], row["parser"], row["confidence"],
            ]
            for row in rows
        ],
    )
