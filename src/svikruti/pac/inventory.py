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
from svikruti.pac.globs import match_any
from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES, category_slug
from svikruti.reports.exports import _write_rows

_CONTAINER_RES = (
    re.compile(r"^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?([\w.]+)", re.IGNORECASE),   # SQL
    re.compile(r"^\s*(?:model|type|enum)\s+(\w+)\s*\{"),                                              # Prisma / GraphQL
    re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?(?:public\s+|final\s+|data\s+)*class\s+(\w+)"),   # Python / Java / Kotlin / TS / PHP / Ruby
    re.compile(r"^\s*type\s+(\w+)\s+struct\b"),                                                       # Go
    re.compile(r"^\s*(?:export\s+)?interface\s+(\w+)"),                                               # TS
    re.compile(r"\b(?:define|model)\(\s*[\"'](\w+)[\"']"),                                            # Sequelize / Mongoose
    re.compile(r"\bcreate_table\s+[:\"'](\w+)"),                                                      # Rails migration
)


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
    return rows


def write_inventory_csv(rows: List[Dict[str, Any]], path: str) -> None:
    def declared(value: Optional[bool]) -> str:
        return "no manifest" if value is None else ("yes" if value else "NO")

    _write_rows(
        path,
        ["Store (table / model)", "Field", "Data Category", "High Risk", "File", "Line", "Processing Activity", "Category Declared", "Category Reaches Logs (activity)", "Category Sent To (activity)", "Retention", "Parser", "Confidence"],
        [
            [
                row["store"], row["field"], row["data_category"], "yes" if row["high_risk"] else "no", row["file"], row["line"] or "",
                row["activity"], declared(row["declared"]), "yes" if row["reaches_logs"] else "no", "; ".join(row["sent_to"]), row["retention"], row["parser"], row["confidence"],
            ]
            for row in rows
        ],
    )
