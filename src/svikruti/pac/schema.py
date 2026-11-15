"""JSON Schema for privacy.yaml, for editor completion and validation.

Editors that speak the YAML language server protocol pick it up from the
`# yaml-language-server: $schema=...` comment `svikruti init` writes. The
schema is generated from the same key sets the loader validates against, so
the two cannot disagree.
"""

from __future__ import annotations

from typing import Any, Dict

from svikruti.pac import manifest as m
from svikruti.pac.frameworks import builtin_pack_ids
from svikruti.pac.obligations import OBLIGATIONS
from svikruti.pac.reconcile import RULES
from svikruti.pac.taxonomy import CATEGORY_LABELS

SCHEMA_URL = "https://raw.githubusercontent.com/chevauxenbois/svikruti/main/docs/privacy.schema.json"

_STR = {"type": "string"}
_STR_LIST = {"type": "array", "items": {"type": "string"}}


def _categories(description: str) -> Dict[str, Any]:
    return {
        "type": "array",
        "description": description,
        "items": {"anyOf": [{"enum": sorted(CATEGORY_LABELS)}, {"type": "string"}]},
    }


def _object(properties: Dict[str, Any], allowed: set, required: list, description: str) -> Dict[str, Any]:
    missing = allowed - set(properties)
    assert not missing, f"schema is missing keys the loader accepts: {sorted(missing)}"
    return {"type": "object", "description": description, "properties": properties, "required": required, "additionalProperties": False}


def manifest_schema() -> Dict[str, Any]:
    activity = _object(
        {
            "id": {**_STR, "description": "Stable identifier, used by exceptions and reports."},
            "name": _STR,
            "owner": {**_STR, "description": "Team accountable for this processing."},
            "paths": {**_STR_LIST, "minItems": 1, "description": "Globs binding this record to the code that implements it (* within a segment, ** across segments)."},
            "data_categories": _categories("Personal data categories this activity is declared to process."),
            "data_subjects": _STR_LIST,
            "purposes": _STR_LIST,
            "legal_basis": {
                "description": "One lawful basis, or one per framework: {gdpr: contract, dpdpa: legitimate_use}.",
                "anyOf": [_STR, {"type": "object", "additionalProperties": _STR}],
            },
            "retention": {**_STR, "description": "How long data is kept, or what triggers erasure."},
            "processors": {**_STR_LIST, "description": "Ids of processors (declared under top-level `processors`) this activity sends data to."},
            "dpia": {**_STR, "description": "Reference to the impact assessment. Required when high-risk categories are involved."},
            "logging": {
                "type": "object",
                "properties": {"allow": _categories("Categories allowed to appear in logs for this activity.")},
                "additionalProperties": False,
            },
            "notes": _STR,
        },
        m._ACTIVITY_KEYS,
        ["id", "paths"],
        "One processing activity: a record of processing bound to code paths.",
    )
    processor = _object(
        {
            "id": _STR,
            "name": {**_STR, "description": "Vendor name as the scanner reports it (for example Razorpay, Mixpanel)."},
            "aliases": _STR_LIST,
            "purpose": _STR,
            "country": {**_STR, "description": "ISO country code where the processor handles the data."},
            "contract": {**_STR, "description": "Contract / DPA reference."},
            "transfer_mechanism": {**_STR, "description": "For example Standard Contractual Clauses. Needed outside allowed_transfer_countries."},
            "data_categories": _categories("What the code is allowed to pass to this processor (rule D009)."),
            "notes": _STR,
        },
        m._PROCESSOR_KEYS,
        [],
        "A third party that receives personal data.",
    )
    policies = _object(
        {
            "personal_data_in_logs": {"enum": sorted(m._LOG_POLICIES), "default": "deny"},
            "forbidden_categories": _categories("Categories this codebase must never process (rule P002)."),
            "allowed_transfer_countries": {**_STR_LIST, "description": "Processors elsewhere need a transfer_mechanism (rule P004)."},
            "require_dpia_for": _categories("Categories that require a `dpia` reference (rule P003). Defaults to the high-risk set."),
            "ignore_paths": {**_STR_LIST, "description": "Globs excluded from reconciliation."},
            "attestation_max_age_days": {"type": "integer", "minimum": 1, "default": 365},
            "min_confidence": {"enum": sorted(m._CONFIDENCE), "default": "medium"},
            "ai_allowed_categories": _categories("Categories that may appear in prompts or payloads sent to AI model providers (rule P006). [] allows none; omit to not enforce."),
            "require_field_protection_for": _categories("Categories whose stored fields must be encrypted, tokenised, hashed or masked (rule P007), e.g. government_id for the Aadhaar Data Vault."),
        },
        m._POLICY_KEYS,
        [],
        "Organisation-wide rules enforced on every check.",
    )
    exception = _object(
        {
            "rule": {"enum": sorted(RULES), "description": "Rule this exception suppresses."},
            "activity": _STR,
            "category": _STR,
            "processor": _STR,
            "path": {**_STR, "description": "Glob; the exception applies to findings with evidence under it."},
            "reason": {**_STR, "minLength": 10},
            "approved_by": _STR,
            "expires": {**_STR, "format": "date", "description": "After this date the finding is enforced again."},
        },
        m._EXCEPTION_KEYS,
        ["rule", "reason"],
        "A time-boxed, reasoned exception.",
    )
    attestation = _object(
        {
            "obligation": {"enum": [item["id"] for item in OBLIGATIONS]},
            "statement": {**_STR, "description": "What is in place."},
            "evidence": {**_STR, "description": "Link or path to the proof."},
            "owner": _STR,
            "reviewed": {**_STR, "format": "date", "description": "Stops counting after policies.attestation_max_age_days."},
        },
        m._ATTESTATION_KEYS,
        ["obligation", "statement"],
        "What a repository cannot prove, attested by an owner on a date.",
    )
    return _object(
        {
            "version": {"const": m.MANIFEST_VERSION},
            "organization": {
                "type": "object",
                "properties": {
                    "name": _STR,
                    "role": {"enum": ["controller", "processor", "both"]},
                    "privacy_contact": {**_STR, "description": "Published DPO / grievance contact (obligation OBL-23)."},
                },
            },
            "frameworks": {
                "type": "array",
                "description": "Built-in pack ids or paths to custom pack files.",
                "items": {"anyOf": [{"enum": builtin_pack_ids()}, {"type": "string"}]},
            },
            "processing_activities": {"type": "array", "items": activity},
            "processors": {"type": "array", "items": processor},
            "policies": policies,
            "erasure": _object(
                {
                    "handlers": {**_STR_LIST, "description": "Extra function or class names that erase personal data, beyond those named for it (delete_user, handle_erasure_request, ...)."},
                    "retained": {
                        "type": "object",
                        "description": "Store (table / model) -> the legal reason it is kept and for how long. Retained stores are exempt from rule D010.",
                        "additionalProperties": {"type": "string", "minLength": 10},
                    },
                },
                m._ERASURE_KEYS,
                [],
                "How the code erases personal data, and which stores are kept on purpose.",
            ),
            "exceptions": {"type": "array", "items": exception},
            "attestations": {"type": "array", "items": attestation},
        },
        m._TOP_KEYS,
        ["version"],
        "Svikruti privacy-as-code manifest.",
    ) | {"$schema": "http://json-schema.org/draft-07/schema#", "$id": SCHEMA_URL, "title": "Svikruti privacy.yaml"}
