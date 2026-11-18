"""
Scanner Import bridge for Svikruti.ai

Turns the Svikruti CLI scanner's evidence-pack output into structures ready
for the app's database registries. The scanner (`svikruti scan --evidence-pack DIR`)
produces:
    - report.json  (structured evidence, ropa_starter, third parties, actions)
    - ropa.csv     (Records of Processing Activities)
    - vendors.csv  (third-party processors)
    - actions.csv  (remediation tasks)

It also reads the privacy-as-code manifest (privacy.yaml / privacy.json), so
the reviewed record that lives in the repository and the registries in this
app are the same record rather than two that drift apart.

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


# ==================== privacy.yaml (privacy-as-code manifest) ====================

_HIGH_RISK_CATEGORIES = {"health", "children", "government_id", "biometric"}


def looks_like_manifest(file_bytes_or_text: Union[bytes, str, None]) -> bool:
    """True when a JSON/YAML upload is a privacy manifest rather than a scan report."""
    text = _to_text(file_bytes_or_text)
    # Attestations in a manifest carry an "evidence" link, so that key cannot
    # tell the two apart; a scan report always has "ropa_starter".
    return "processing_activities" in text and "ropa_starter" not in text


def _label(slug: Any) -> str:
    return str(slug).replace("_", " ").strip().title() if slug else ""


def _todo(value: Any) -> str:
    """Manifest placeholders ('TODO', '[TODO]') count as empty."""
    if isinstance(value, (list, tuple)):
        return ", ".join(part for part in (_todo(item) for item in value) if part)
    text = _clean(value)
    return "" if text.lower().startswith("todo") else text


def parse_privacy_manifest(file_bytes_or_text: Union[bytes, str, None]) -> Dict[str, Any]:
    """
    Turn privacy.yaml into RoPA and vendor records.

    Each processing activity becomes a RoPA entry; each processor becomes a
    vendor. Unlike a scan report, these carry the fields a human reviewed:
    purpose, lawful basis, retention, contract and country.

    Returns {'ropa': [...], 'vendors': [...], 'actions': [...], 'note': str}.
    A TODO left in the manifest becomes a task instead of a made-up value.
    """
    empty = {"ropa": [], "vendors": [], "actions": [], "note": ""}
    text = _to_text(file_bytes_or_text)
    if not text.strip():
        return dict(empty, note="The manifest file is empty.")
    try:
        if text.lstrip().startswith("{"):
            data = json.loads(text)
        else:
            import yaml  # PyYAML ships with the svikruti package and requirements.txt

            data = yaml.safe_load(text)
    except Exception as exc:
        return dict(empty, note=f"Could not parse the manifest: {exc}")
    if not isinstance(data, dict) or not isinstance(data.get("processing_activities", []), list):
        return dict(empty, note="This file is not a privacy manifest (no processing_activities list).")

    processors: Dict[str, Dict[str, Any]] = {}
    for raw in data.get("processors") or []:
        if isinstance(raw, dict) and (raw.get("id") or raw.get("name")):
            processors[str(raw.get("id") or raw.get("name")).strip().lower()] = raw
    policies = data.get("policies") if isinstance(data.get("policies"), dict) else {}
    allowed = {str(code).upper() for code in (policies.get("allowed_transfer_countries") or [])}

    ropa: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []
    for raw in data.get("processing_activities") or []:
        if not isinstance(raw, dict):
            continue
        activity_id = _clean(raw.get("id")) or _clean(raw.get("name"))
        name = _clean(raw.get("name")) or activity_id
        if not name:
            continue
        categories = [str(item) for item in (raw.get("data_categories") or [])]
        basis = raw.get("legal_basis")
        if isinstance(basis, dict):
            basis_text = "; ".join(f"{str(key).upper()}: {_label(value)}" for key, value in basis.items() if _todo(value))
        else:
            basis_text = _label(_todo(basis))
        linked = [processors.get(str(pid).strip().lower(), {"name": pid}) for pid in (raw.get("processors") or [])]
        countries = sorted({_todo(p.get("country")).upper() for p in linked if _todo(p.get("country"))})
        cross_border = int(bool(allowed and any(country not in allowed for country in countries)))
        purpose, retention = _todo(raw.get("purposes")), _todo(raw.get("retention"))
        missing = [label for label, value in (("purpose", purpose), ("lawful basis", basis_text), ("retention", retention), ("owner", _todo(raw.get("owner")))) if not value]
        if missing:
            actions.append({
                "title": f"Complete the processing record for {name}"[:200],
                "category": "RoPA",
                "priority": "HIGH" if set(categories) & _HIGH_RISK_CATEGORIES else "MEDIUM",
                "description": f"privacy.yaml activity '{activity_id}' is missing: {', '.join(missing)}. Fill these in the manifest and re-import.",
            })
        ropa.append({
            "activity_name": name,
            "data_categories": ", ".join(_label(item) for item in categories) or "Not specified",
            "data_subjects": _todo(raw.get("data_subjects")) or "Not specified",
            "purpose": purpose or "Not specified",
            "lawful_basis": basis_text or "To be confirmed",
            "kwargs": _filter_ropa_kwargs({
                "department": _todo(raw.get("owner")),
                "retention_period": retention,
                "data_processor": ", ".join(_clean(p.get("name")) for p in linked if _clean(p.get("name"))),
                "processing_location": ", ".join(countries),
                "security_measures": f"DPIA: {_todo(raw.get('dpia'))}" if _todo(raw.get("dpia")) else "",
                "cross_border": cross_border,
            }),
            "_risk_tier": "High" if set(categories) & _HIGH_RISK_CATEGORIES else "Medium",
            "_evidence": ", ".join(str(path) for path in (raw.get("paths") or [])),
        })

    vendors: List[Dict[str, Any]] = []
    for raw in processors.values():
        name = _clean(raw.get("name")) or _clean(raw.get("id"))
        if not name:
            continue
        contract, country = _todo(raw.get("contract")), _todo(raw.get("country")).upper()
        categories = [str(item) for item in (raw.get("data_categories") or [])]
        note_parts = [part for part in (
            f"Contract: {contract}" if contract else "",
            f"Country: {country}" if country else "",
            f"Transfer mechanism: {_todo(raw.get('transfer_mechanism'))}" if _todo(raw.get("transfer_mechanism")) else "",
            "Source: privacy.yaml",
        ) if part]
        vendors.append({
            "vendor_name": name,
            "service_type": _todo(raw.get("purpose")) or "Not specified",
            "data_shared": ", ".join(_label(item) for item in categories) or "Not specified",
            "kwargs": _filter_vendor_kwargs({
                "dpa_status": "COMPLETED" if contract else "NOT_STARTED",
                "risk_level": "HIGH" if set(categories) & _HIGH_RISK_CATEGORIES or (allowed and country and country not in allowed) else "MEDIUM",
                "notes": " | ".join(note_parts),
            }),
            "_transfer_location": country,
        })
        if not contract:
            actions.append({
                "title": f"Record the contract / DPA for {name}"[:200],
                "category": "Vendor Management",
                "priority": "HIGH",
                "description": f"privacy.yaml lists {name} as a processor with no contract reference.",
            })

    return {
        "ropa": ropa,
        "vendors": vendors,
        "actions": actions,
        "note": f"privacy manifest: {len(ropa)} processing activit(ies), {len(vendors)} processor(s), {len(actions)} follow-up task(s).",
    }


# ==================== privacy-check.json / org-summary.json ====================

_CHECK_SCHEMAS = {"svikruti-privacy-check-v1", "svikruti-org-v1"}
_VENDOR_RULES = {"D003", "D005", "D007", "D009", "P004", "P006"}
_SECURITY_RULES = {"P001", "P002", "P007"}


def looks_like_check(file_bytes_or_text: Union[bytes, str, None]) -> bool:
    """True for `svikruti check` (privacy-check.json) or `svikruti org` (org-summary.json) output."""
    head = _to_text(file_bytes_or_text)[:400]
    return any(f'"{schema}"' in head for schema in _CHECK_SCHEMAS)


def _basis_text(basis: Any) -> str:
    if isinstance(basis, dict):
        return "; ".join(f"{str(key).upper()}: {_label(value)}" for key, value in basis.items() if _todo(value))
    return _label(_todo(basis))


def _finding_category(rule: str) -> str:
    if rule in _VENDOR_RULES:
        return "Vendor Management"
    if rule in _SECURITY_RULES:
        return "Security safeguards"
    if rule == "D010":
        return "Data Subject Rights"
    return "RoPA"


def parse_privacy_check(file_bytes_or_text: Union[bytes, str, None]) -> Dict[str, Any]:
    """
    Turn the verdict of `svikruti check` (or `svikruti org`) into registry records.

    A manifest import gives what was declared; this gives what was verified:
    RoPA entries carry the data the code was found to process (declared plus
    detected), vendors include processors found in code but not on record,
    and every open drift or policy finding (unprotected Aadhaar, a store no
    erasure path reaches, an undeclared AI provider) becomes a task with its
    fix and code location. Org summaries add the repository to each record.
    """
    empty = {"ropa": [], "vendors": [], "actions": [], "note": ""}
    try:
        data = json.loads(_to_text(file_bytes_or_text))
    except (json.JSONDecodeError, ValueError) as exc:
        return dict(empty, note=f"Could not parse JSON: {exc}")
    if not isinstance(data, dict) or data.get("schema_version") not in _CHECK_SCHEMAS:
        return dict(empty, note="Not a Svikruti privacy-check.json or org-summary.json file.")
    is_org = data["schema_version"] == "svikruti-org-v1"

    transfer_gaps = {
        (str(item.get("repo") or ""), str(item.get("processor") or "").lower())
        for item in data.get("findings") or []
        if isinstance(item, dict) and item.get("rule") == "P004" and item.get("status", "open") == "open"
    }
    ropa: List[Dict[str, Any]] = []
    for raw in data.get("activities") or []:
        if not isinstance(raw, dict) or not _clean(raw.get("name")):
            continue
        repo = _clean(raw.get("repo"))
        categories = sorted(set(raw.get("declared_categories") or []) | set(raw.get("detected_categories") or []))
        declared = [p for p in (raw.get("declared_processors") or []) if isinstance(p, dict)]
        names = sorted({_clean(p.get("name")) for p in declared} | {str(name) for name in (raw.get("detected_processors") or [])} - {""})
        countries = sorted({_todo(p.get("country")).upper() for p in declared if _todo(p.get("country"))})
        open_rules = list(raw.get("open_rules") or [])
        ropa.append({
            "activity_name": f"{raw['name']} ({repo})" if is_org and repo else _clean(raw["name"]),
            "data_categories": ", ".join(categories) or "Not specified",
            "data_subjects": _todo(raw.get("data_subjects")) or "Not specified",
            "purpose": _todo(raw.get("purposes")) or "Not specified",
            "lawful_basis": _basis_text(raw.get("legal_basis")) or "To be confirmed",
            "kwargs": _filter_ropa_kwargs({
                "department": _todo(raw.get("owner")),
                "retention_period": _todo(raw.get("retention")),
                "data_processor": ", ".join(names),
                "processing_location": ", ".join(countries),
                "security_measures": f"DPIA: {_todo(raw.get('dpia'))}" if _todo(raw.get("dpia")) else "",
                "cross_border": int(any(_todo(p.get("transfer_mechanism")) or (repo, _clean(p.get("name")).lower().replace(" ", "_")) in transfer_gaps for p in declared)),
            }),
            "_risk_tier": "High" if {"Government ID", "Health", "Biometric", "Children"} & set(categories) else "Medium",
            "_evidence": "; ".join(filter(None, [", ".join(raw.get("paths") or []), "verified against code" if raw.get("in_sync") else f"drift: {', '.join(open_rules)}"])),
        })

    vendors: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []
    for raw in data.get("processors") or []:
        if not isinstance(raw, dict) or not _clean(raw.get("name")):
            continue
        name = _clean(raw["name"])
        if is_org:
            contract = ", ".join(raw.get("contracts") or [])
            country = ", ".join(raw.get("countries") or [])
            categories = sorted(set(raw.get("categories_declared") or []) | set(raw.get("categories_sent") or []))
            declared_anywhere = bool(raw.get("declared_in"))
            issues = list(raw.get("issues") or [])
            extra = [f"Declared in: {', '.join(raw['declared_in'])}" if raw.get("declared_in") else "", f"Used without a record in: {', '.join(raw['used_undeclared_in'])}" if raw.get("used_undeclared_in") else ""]
        else:
            contract, country = _todo(raw.get("contract")), _todo(raw.get("country")).upper()
            categories = list(raw.get("data_categories") or [])
            declared_anywhere, issues = True, []
            extra = [f"Transfer mechanism: {_todo(raw.get('transfer_mechanism'))}" if _todo(raw.get("transfer_mechanism")) else ""]
        notes = [part for part in [f"Contract: {contract}" if contract else "", f"Country: {country}" if country else "", *extra, "AI model provider" if raw.get("ai_provider") else "", *(f"Issue: {issue}" for issue in issues), "Source: svikruti " + ("org" if is_org else "check")] if part]
        vendors.append({
            "vendor_name": name,
            "service_type": _todo(raw.get("purpose")) or ("AI model provider" if raw.get("ai_provider") else "Not specified"),
            "data_shared": ", ".join(categories) or "Not specified",
            "kwargs": _filter_vendor_kwargs({
                "dpa_status": "COMPLETED" if contract and declared_anywhere else "NOT_STARTED",
                "risk_level": "HIGH" if issues or raw.get("ai_provider") or not declared_anywhere or {"Government ID", "Health", "Biometric"} & set(categories) else "MEDIUM",
                "notes": " | ".join(notes),
            }),
            "_transfer_location": country,
        })
        if is_org and issues:
            actions.append({
                "title": f"Reconcile the {name} processor record across repositories"[:200],
                "category": "Vendor Management",
                "priority": "HIGH",
                "description": "; ".join(issues),
            })

    if not is_org:
        # Processors the code sends data to that privacy.yaml does not list.
        known = {v["vendor_name"].lower() for v in vendors}
        for finding in data.get("findings") or []:
            if isinstance(finding, dict) and finding.get("rule") == "D003" and finding.get("status", "open") == "open":
                flows = [flow for activity in data.get("activities") or [] for flow in activity.get("detected_flows") or []]
                match = next((flow for flow in flows if flow.get("processor", "").lower().replace(" ", "_") == str(finding.get("processor", "")).lower()), None)
                name = match["processor"] if match else _clean(finding.get("processor"))
                if name and name.lower() not in known:
                    known.add(name.lower())
                    vendors.append({
                        "vendor_name": name,
                        "service_type": "Not specified",
                        "data_shared": ", ".join(match["categories"]) if match else "Not specified",
                        "kwargs": _filter_vendor_kwargs({"dpa_status": "NOT_STARTED", "risk_level": "HIGH", "notes": "Found in code, not in privacy.yaml | Source: svikruti check"}),
                        "_transfer_location": "",
                    })

    for finding in data.get("findings") or []:
        if not isinstance(finding, dict) or finding.get("status", "open") != "open":
            continue
        rule = _clean(finding.get("rule"))
        repo = _clean(finding.get("repo"))
        refs = ", ".join(str(ref) for ref in (finding.get("refs") or [])[:3])
        prefix = f"[{repo}] " if repo else ""
        actions.append({
            "title": f"{prefix}{rule}: {_clean(finding.get('detail')) or _clean(finding.get('title'))}"[:200],
            "category": _finding_category(rule),
            "priority": _SEVERITY_PRIORITY_MAP.get(_clean(finding.get("severity")).upper(), "MEDIUM"),
            "description": " ".join(part for part in [_clean(finding.get("fix")), f"Where: {refs}." if refs else ""] if part),
        })

    label = "org summary" if is_org else "privacy check"
    repos = f" across {len(data.get('repositories') or [])} repositories" if is_org else ""
    return {
        "ropa": ropa,
        "vendors": vendors,
        "actions": actions,
        "note": f"{label}{repos}: {len(ropa)} verified processing activit(ies), {len(vendors)} processor(s), {len(actions)} open finding task(s).",
    }


def parse_upload(filename: str, file_bytes_or_text: Union[bytes, str, None]) -> Dict[str, Any]:
    """
    Route one uploaded file to the right parser by name and content.

    Returns {'ropa': [...], 'vendors': [...], 'actions': [...], 'note': str}.
    Kept here (not in the Streamlit page) so the routing is unit-tested:
    privacy-check.json / org-summary.json -> verified record and findings,
    privacy.yaml / privacy.json -> manifest, other .json -> scan report,
    *vendor*.csv -> vendors, *action*.csv -> tasks, any other .csv -> RoPA.
    """
    name = (filename or "").lower()
    out: Dict[str, Any] = {"ropa": [], "vendors": [], "actions": [], "note": ""}
    try:
        if name.endswith(".json") and looks_like_check(file_bytes_or_text):
            parsed = parse_privacy_check(file_bytes_or_text)
            out.update({key: parsed.get(key, []) for key in ("ropa", "vendors", "actions")})
            out["note"] = parsed.get("note", "")
        elif name.endswith((".yaml", ".yml")) or (name.endswith(".json") and looks_like_manifest(file_bytes_or_text)):
            parsed = parse_privacy_manifest(file_bytes_or_text)
            out.update({key: parsed.get(key, []) for key in ("ropa", "vendors", "actions")})
            out["note"] = parsed.get("note", "")
        elif name.endswith(".json"):
            parsed = parse_report_json(file_bytes_or_text)
            out.update({key: parsed.get(key, []) for key in ("ropa", "vendors", "actions")})
            out["note"] = parsed.get("note", "")
        elif name.endswith(".csv") and "vendor" in name:
            out["vendors"] = parse_vendors_csv(file_bytes_or_text)
            out["note"] = f"parsed {len(out['vendors'])} vendor row(s)."
        elif name.endswith(".csv") and "action" in name:
            out["actions"] = parse_actions_csv(file_bytes_or_text)
            out["note"] = f"parsed {len(out['actions'])} action row(s)."
        elif name.endswith(".csv"):
            # Any other CSV is treated as RoPA: that is the primary registry.
            out["ropa"] = parse_ropa_csv(file_bytes_or_text)
            out["note"] = f"parsed {len(out['ropa'])} RoPA row(s)."
        else:
            out["note"] = "unrecognized file type, skipped."
    except Exception as exc:  # a bad upload must never take the page down
        out["note"] = f"parse error - {exc}"
    return out


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
