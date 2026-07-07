"""
Scanner Import bridge for Svikruti.ai

Turns the Svikruti CLI scanner's evidence-pack output into structures ready
for the app's database registries. The scanner (`svikruti scan --evidence-pack DIR`)
produces:
    - report.json  (structured evidence, ropa_starter, third parties, actions)
    - ropa.csv     (Records of Processing Activities)
    - vendors.csv  (third-party processors)
    - actions.csv  (remediation tasks)

This module is intentionally PURE (no Streamlit, no database imports) so the
parse functions are unit-testable and safe to import anywhere. The Streamlit
page that consumes these functions lives in app.py.

Design notes:
  * create_ropa_entry(org_id, activity_name, data_categories, data_subjects,
    purpose, lawful_basis, **kwargs) only reads these kwargs:
        department, retention_period, data_processor, processing_location,
        security_measures, cross_border
    so we ONLY emit those keys. Scanner fields with no home in the RoPA table
    (risk_tier, evidence references, notes) are preserved on the parsed dict
    under an underscore-prefixed key (ignored by the DB) so the preview can
    still surface them.
  * create_vendor(org_id, vendor_name, service_type, data_shared, **kwargs)
    only reads: dpa_status, risk_level, notes. Transfer location and
    sub-processors are folded into `notes`.
  * create_task(org_id, title, category, priority, due_date, description,
    assigned_to) — we emit title/category/priority/description; due_date is
    left to the caller (page) since it is an app-side scheduling decision.

All functions are defensive: missing columns/keys never raise; an unknown
shape returns empty lists plus a human-readable note.
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional, Union

# Kwargs actually consumed by database.Database.create_ropa_entry(**kwargs)
ROPA_ALLOWED_KWARGS = {
    "department",
    "retention_period",
    "data_processor",
    "processing_location",
    "security_measures",
    "cross_border",
}

# Kwargs actually consumed by database.Database.create_vendor(**kwargs)
VENDOR_ALLOWED_KWARGS = {"dpa_status", "risk_level", "notes"}

# Priority letters used by the scanner action pack -> app priority levels.
_ACTION_PRIORITY_MAP = {
    "P0": "CRITICAL",
    "P1": "HIGH",
    "P2": "MEDIUM",
    "P3": "LOW",
}
_SEVERITY_PRIORITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Values the scanner emits as placeholders; we treat them as "no data".
_PLACEHOLDERS = {
    "",
    "to be confirmed",
    "to be defined",
    "to be mapped",
    "to be scheduled",
    "to be compared",
    "none",
    "n/a",
}


# ==================== helpers ====================

def _to_text(value: Union[bytes, str, None]) -> str:
    """Coerce bytes/str/None into a decoded text string (never raises)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return value.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return value.decode("utf-8", errors="replace")
    return str(value)


def _clean(value: Any) -> str:
    """Normalize a scalar cell to a trimmed string, dropping scanner placeholders."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        parts = [_clean(v) for v in value]
        return "; ".join(p for p in parts if p)
    text = str(value).strip()
    if text.lower() in _PLACEHOLDERS:
        return ""
    return text


def _first_nonempty(row: Dict[str, Any], *keys: str) -> str:
    """Return the first cleaned, non-empty value across candidate column names."""
    for key in keys:
        if key in row:
            cleaned = _clean(row[key])
            if cleaned:
                return cleaned
    return ""


def _is_truthy_transfer(value: str) -> int:
    """Map an 'International Transfer' cell to the cross_border integer flag."""
    text = value.strip().lower()
    if not text:
        return 0
    if text in ("no", "none", "false", "0", "no transfer", "domestic"):
        return 0
    return 1


def _filter_ropa_kwargs(candidate: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in candidate.items() if k in ROPA_ALLOWED_KWARGS and v not in (None, "")}


def _filter_vendor_kwargs(candidate: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in candidate.items() if k in VENDOR_ALLOWED_KWARGS and v not in (None, "")}


# ==================== RoPA CSV ====================

def parse_ropa_csv(file_bytes_or_text: Union[bytes, str, None]) -> List[Dict[str, Any]]:
    """
    Parse the scanner's ROPA CSV into dicts ready for create_ropa_entry().

    Each returned dict has the required positional-ish params plus a `kwargs`
    dict containing only allowlisted RoPA kwargs, plus underscore-prefixed
    display-only fields (_risk_tier, _evidence) for preview use.

    Robust to missing columns and empty input.
    """
    text = _to_text(file_bytes_or_text)
    if not text.strip():
        return []

    results: List[Dict[str, Any]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error:
        return []

    for row in reader:
        if not row:
            continue
        activity_name = _first_nonempty(row, "Processing Activity", "Activity")
        if not activity_name:
            # Without an activity name there is nothing meaningful to import.
            continue

        data_categories = _first_nonempty(row, "Personal Data Categories", "Data Categories")
        data_subjects = _first_nonempty(row, "Data Subjects")
        purpose = _first_nonempty(row, "Processing Purposes", "Purpose")
        lawful_basis = _first_nonempty(row, "DPDPA Basis", "Lawful Basis")
        recipients = _first_nonempty(row, "Processors / Recipients", "Processors/Recipients")
        retention = _first_nonempty(row, "Retention Period", "Retention")
        security = _first_nonempty(row, "Security Measures")
        transfer = _first_nonempty(row, "International Transfer")
        storage = _first_nonempty(row, "Storage Locations")
        risk_tier = _first_nonempty(row, "Risk Tier")
        evidence = _first_nonempty(row, "Evidence References")
        business_function = _first_nonempty(row, "Business Function")

        kwargs = _filter_ropa_kwargs({
            "department": business_function,
            "retention_period": retention,
            "data_processor": recipients,
            "processing_location": storage,
            "security_measures": security,
            "cross_border": _is_truthy_transfer(transfer),
        })

        results.append({
            "activity_name": activity_name,
            "data_categories": data_categories or "Not specified",
            "data_subjects": data_subjects or "Not specified",
            "purpose": purpose or "Not specified",
            "lawful_basis": lawful_basis or "To be confirmed",
            "kwargs": kwargs,
            # Display-only (not passed to DB — no matching column):
            "_risk_tier": risk_tier,
            "_evidence": evidence,
        })

    return results


# ==================== Vendors CSV ====================

def parse_vendors_csv(file_bytes_or_text: Union[bytes, str, None]) -> List[Dict[str, Any]]:
    """
    Parse the scanner's VENDORS CSV into dicts ready for create_vendor().

    create_vendor accepts only dpa_status/risk_level/notes as kwargs, so
    transfer location, sub-processors, and security evidence are folded into
    a composed `notes` string. Robust to missing columns and empty input.
    """
    text = _to_text(file_bytes_or_text)
    if not text.strip():
        return []

    results: List[Dict[str, Any]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error:
        return []

    for row in reader:
        if not row:
            continue
        vendor_name = _first_nonempty(row, "Vendor / Processor", "Vendor/Processor", "Vendor")
        if not vendor_name:
            continue

        service_type = _first_nonempty(row, "Service Category", "Service Type") or "To be confirmed"
        data_shared = _first_nonempty(row, "Data Categories Shared", "Data Shared") or "To be mapped"
        dpa_status = _first_nonempty(row, "DPA / Contract Status", "DPA Status")
        risk_tier = _first_nonempty(row, "Risk Tier")
        transfer_location = _first_nonempty(row, "Transfer Location")
        sub_processors = _first_nonempty(row, "Sub-processors")
        purpose = _first_nonempty(row, "Processing Purpose")
        retention = _first_nonempty(row, "Retention / Deletion Commitment")

        note_parts = []
        if purpose:
            note_parts.append(f"Purpose: {purpose}")
        if transfer_location:
            note_parts.append(f"Transfer location: {transfer_location}")
        if sub_processors:
            note_parts.append(f"Sub-processors: {sub_processors}")
        if retention:
            note_parts.append(f"Retention: {retention}")
        notes = " | ".join(note_parts)

        kwargs = _filter_vendor_kwargs({
            "dpa_status": _normalize_dpa_status(dpa_status),
            "risk_level": _normalize_risk(risk_tier),
            "notes": notes,
        })

        results.append({
            "vendor_name": vendor_name,
            "service_type": service_type,
            "data_shared": data_shared,
            "kwargs": kwargs,
            "_transfer_location": transfer_location,
        })

    return results


def _normalize_dpa_status(value: str) -> str:
    """Map a free-text DPA status into the app's DPA status vocabulary."""
    text = value.strip().lower()
    if not text:
        return "NOT_STARTED"
    if "signed" in text or "complete" in text or "executed" in text:
        return "COMPLETED"
    if "progress" in text or "review" in text or "draft" in text:
        return "IN_PROGRESS"
    return "NOT_STARTED"


def _normalize_risk(value: str) -> str:
    """Map a scanner risk tier ('High'/'Medium'/'Low') to the vendor risk_level."""
    text = value.strip().upper()
    if text in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return text
    if "HIGH" in text or "CRITICAL" in text:
        return "HIGH"
    if "LOW" in text:
        return "LOW"
    return "MEDIUM"


# ==================== report.json ====================

def parse_report_json(file_bytes_or_text: Union[bytes, str, None]) -> Dict[str, Any]:
    """
    Parse the scanner's report.json into {ropa, vendors, actions, summary, note}.

    The report carries:
      * ropa_starter[]        -> RoPA entries (preferred source)
      * summary.third_parties -> vendor names
      * evidence[] category "Third-party processors" -> vendor detail/detector
      * evidence_graph.proof_pack[] and technical_controls[] -> actions/tasks

    Always returns the four lists (possibly empty) plus a human-readable `note`.
    Never raises on malformed input.
    """
    result: Dict[str, Any] = {
        "ropa": [],
        "vendors": [],
        "actions": [],
        "summary": {},
        "note": "",
    }

    text = _to_text(file_bytes_or_text)
    if not text.strip():
        result["note"] = "Empty file."
        return result

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        result["note"] = "Could not parse JSON — file is not valid report.json."
        return result

    if not isinstance(data, dict):
        result["note"] = "Unexpected JSON shape — expected a report object."
        return result

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    result["summary"] = {
        "files_scanned": summary.get("files_scanned"),
        "risk_score": summary.get("risk_score"),
        "risk_level": summary.get("risk_level"),
        "personal_data_categories": summary.get("personal_data_categories") or [],
        "third_parties": summary.get("third_parties") or [],
    }

    # ---- RoPA from ropa_starter ----
    ropa_starter = data.get("ropa_starter")
    if isinstance(ropa_starter, list):
        for rec in ropa_starter:
            if not isinstance(rec, dict):
                continue
            activity_name = _clean(rec.get("activity"))
            if not activity_name:
                continue
            kwargs = _filter_ropa_kwargs({
                "retention_period": _clean(rec.get("retention")),
                "data_processor": _clean(rec.get("third_parties")),
                "processing_location": _clean(rec.get("storage_locations")),
                "security_measures": _clean(rec.get("security_measures")),
                "cross_border": 0,
            })
            result["ropa"].append({
                "activity_name": activity_name,
                "data_categories": _clean(rec.get("data_categories")) or "Not specified",
                "data_subjects": _clean(rec.get("data_subjects")) or "Not specified",
                "purpose": _clean(rec.get("purposes")) or "Not specified",
                "lawful_basis": _clean(rec.get("dpdpa_basis")) or "To be confirmed",
                "kwargs": kwargs,
                "_risk_tier": _clean(rec.get("risk_tier")),
                "_evidence": _clean(rec.get("evidence_refs")),
            })

    # ---- Vendors: names from summary.third_parties, enriched by evidence ----
    vendor_detail: Dict[str, Dict[str, str]] = {}
    evidence = data.get("evidence")
    if isinstance(evidence, list):
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            if ev.get("category") != "Third-party processors" and ev.get("kind") != "third_party":
                continue
            label = _clean(ev.get("label"))
            # label form: "Third-party service detected: Razorpay"
            name = label.split(":", 1)[1].strip() if ":" in label else label
            if not name:
                continue
            info = vendor_detail.setdefault(name, {"detail": "", "detector": ""})
            if not info["detail"]:
                info["detail"] = _clean(ev.get("detail"))
            meta = ev.get("metadata") if isinstance(ev.get("metadata"), dict) else {}
            if not info["detector"]:
                info["detector"] = _clean(meta.get("detector_id"))

    vendor_names = list(result["summary"]["third_parties"])
    for name in vendor_detail:
        if name not in vendor_names:
            vendor_names.append(name)

    for name in vendor_names:
        name_clean = _clean(name)
        if not name_clean:
            continue
        info = vendor_detail.get(name_clean, {})
        notes = _clean(info.get("detail"))
        kwargs = _filter_vendor_kwargs({
            "dpa_status": "NOT_STARTED",
            "risk_level": "MEDIUM",
            "notes": notes,
        })
        result["vendors"].append({
            "vendor_name": name_clean,
            "service_type": "Third-party processor",
            "data_shared": "To be mapped",
            "kwargs": kwargs,
        })

    # ---- Actions/tasks from proof_pack, fall back to technical_controls ----
    proof_pack = None
    graph = data.get("evidence_graph")
    if isinstance(graph, dict):
        proof_pack = graph.get("proof_pack")

    if isinstance(proof_pack, list) and proof_pack:
        for item in proof_pack:
            if not isinstance(item, dict):
                continue
            title = _clean(item.get("title"))
            if not title:
                continue
            severity = _clean(item.get("severity")).upper()
            result["actions"].append({
                "title": title,
                "category": _clean(item.get("control_area")) or "Compliance",
                "priority": _SEVERITY_PRIORITY_MAP.get(severity, "MEDIUM"),
                "description": _clean(item.get("why")),
                "owner": _clean(item.get("owner")),
            })
    else:
        controls = data.get("technical_controls")
        if isinstance(controls, list):
            for ctrl in controls:
                if not isinstance(ctrl, dict):
                    continue
                # Only surface controls that are not passing.
                if _clean(ctrl.get("status")).lower() in ("pass", "passed", "ok"):
                    continue
                title = _clean(ctrl.get("next_action")) or _clean(ctrl.get("title"))
                if not title:
                    continue
                severity = _clean(ctrl.get("severity")).upper()
                result["actions"].append({
                    "title": title,
                    "category": _clean(ctrl.get("area")) or "Security safeguards",
                    "priority": _SEVERITY_PRIORITY_MAP.get(severity, "MEDIUM"),
                    "description": "; ".join(ctrl.get("gaps", []))
                    if isinstance(ctrl.get("gaps"), list) else _clean(ctrl.get("gaps")),
                    "owner": _clean(ctrl.get("owner")),
                })

    if not result["ropa"] and not result["vendors"] and not result["actions"]:
        result["note"] = (
            "No importable records found in this report.json. "
            "It may be from an incompatible scanner version."
        )
    else:
        result["note"] = (
            f"Parsed {len(result['ropa'])} RoPA, {len(result['vendors'])} vendor(s), "
            f"and {len(result['actions'])} action(s) from report.json."
        )

    return result


# ==================== parse actions CSV (bonus, used by page) ====================

def parse_actions_csv(file_bytes_or_text: Union[bytes, str, None]) -> List[Dict[str, Any]]:
    """
    Parse the scanner's ACTIONS CSV into dicts ready for create_task().

    Columns: Action ID, Priority, Severity, Control Area, Title, Owner,
    Status, Due, ... We emit title/category/priority/description/owner.
    Robust to missing columns and empty input.
    """
    text = _to_text(file_bytes_or_text)
    if not text.strip():
        return []

    results: List[Dict[str, Any]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
    except csv.Error:
        return []

    for row in reader:
        if not row:
            continue
        title = _first_nonempty(row, "Title")
        if not title:
            continue
        priority_code = _first_nonempty(row, "Priority")
        severity = _first_nonempty(row, "Severity").upper()
        priority = (
            _ACTION_PRIORITY_MAP.get(priority_code.upper())
            or _SEVERITY_PRIORITY_MAP.get(severity)
            or "MEDIUM"
        )
        results.append({
            "title": title,
            "category": _first_nonempty(row, "Control Area") or "Compliance",
            "priority": priority,
            "description": _first_nonempty(row, "Why"),
            "owner": _first_nonempty(row, "Owner"),
        })

    return results


# ==================== dedup / import summary ====================

def import_summary(
    parsed: Dict[str, List[Dict[str, Any]]],
    existing_ropa: Optional[List[Dict[str, Any]]] = None,
    existing_vendors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compute new vs duplicate counts for a parsed import.

    Dedup RoPA by activity_name (case-insensitive) and vendors by vendor_name
    (case-insensitive) against the org's existing registries.

    `parsed` is a dict with any of the keys 'ropa', 'vendors', 'actions'
    (each a list). Pure function — no side effects.

    Returns:
        {
          'ropa': {'new': int, 'duplicate': int, 'total': int},
          'vendors': {'new': int, 'duplicate': int, 'total': int},
          'actions': {'new': int, 'total': int},
          'ropa_new': [...], 'ropa_duplicate': [...],
          'vendors_new': [...], 'vendors_duplicate': [...],
        }
    """
    existing_ropa = existing_ropa or []
    existing_vendors = existing_vendors or []

    existing_ropa_names = {
        str(r.get("activity_name", "")).strip().lower()
        for r in existing_ropa
        if r.get("activity_name")
    }
    existing_vendor_names = {
        str(v.get("vendor_name", "")).strip().lower()
        for v in existing_vendors
        if v.get("vendor_name")
    }

    ropa_new, ropa_dup = [], []
    seen_ropa = set(existing_ropa_names)
    for entry in parsed.get("ropa", []) or []:
        key = str(entry.get("activity_name", "")).strip().lower()
        if key and key in seen_ropa:
            ropa_dup.append(entry)
        else:
            ropa_new.append(entry)
            if key:
                seen_ropa.add(key)

    vend_new, vend_dup = [], []
    seen_vendors = set(existing_vendor_names)
    for entry in parsed.get("vendors", []) or []:
        key = str(entry.get("vendor_name", "")).strip().lower()
        if key and key in seen_vendors:
            vend_dup.append(entry)
        else:
            vend_new.append(entry)
            if key:
                seen_vendors.add(key)

    actions = parsed.get("actions", []) or []

    return {
        "ropa": {"new": len(ropa_new), "duplicate": len(ropa_dup), "total": len(ropa_new) + len(ropa_dup)},
        "vendors": {"new": len(vend_new), "duplicate": len(vend_dup), "total": len(vend_new) + len(vend_dup)},
        "actions": {"new": len(actions), "total": len(actions)},
        "ropa_new": ropa_new,
        "ropa_duplicate": ropa_dup,
        "vendors_new": vend_new,
        "vendors_duplicate": vend_dup,
    }
