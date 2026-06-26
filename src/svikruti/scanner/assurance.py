"""Assurance profile for scan accuracy and production-readiness claims."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence

from svikruti.models import Evidence, ScanResult


DIMENSIONS = [
    {
        "id": "data_inventory",
        "title": "Personal-data inventory",
        "owner": "Privacy Engineering",
        "required": {
            "collection_point",
            "storage_point",
            "form_field",
            "website_form_field",
            "literal_personal_data",
            "semantic_collection_point",
            "semantic_storage_field",
            "semantic_storage_sink",
        },
        "unknown": "No direct code, website, form, schema, or literal-data evidence was found for personal-data inventory.",
    },
    {
        "id": "notice_coverage",
        "title": "Privacy notice coverage",
        "owner": "Legal / Privacy",
        "required": set(),
        "unknown": "No privacy notice was supplied, so notice coverage cannot be verified.",
    },
    {
        "id": "third_party_processing",
        "title": "Third-party / processor evidence",
        "owner": "Procurement / Legal / Security",
        "required": {"third_party", "website_third_party", "website_third_party_script"},
        "unknown": "No third-party code, website, or vendor evidence was found. Contracts and subprocessors remain unverified.",
    },
    {
        "id": "encryption",
        "title": "Encryption and key management",
        "owner": "Cloud / Platform / Security",
        "required": {"encryption_evidence"},
        "bad": {"weak_crypto", "insecure_transport"},
        "unknown": "No production-grade TLS, KMS, managed-key, storage-encryption, or modern crypto evidence was found.",
    },
    {
        "id": "secrets",
        "title": "Secrets hygiene",
        "owner": "Engineering / Security",
        "required": {"encryption_evidence"},
        "required_subtypes": {"Secret manager"},
        "bad": {"secret_exposure"},
        "unknown": "No managed secret-store evidence was found.",
    },
    {
        "id": "vulnerability_management",
        "title": "Vulnerability management",
        "owner": "Security / Engineering",
        "required": {"security_tooling", "imported_security_finding"},
        "bad": {"imported_security_finding"},
        "unknown": "No dependency, container, static-analysis, or secret-scan evidence was supplied.",
    },
    {
        "id": "monitoring",
        "title": "Security monitoring and alerting",
        "owner": "Security / Platform",
        "required": {"security_monitoring", "endpoint_security"},
        "unknown": "No SIEM, APM, alerting, endpoint, workload, or cloud-detection evidence was found.",
    },
    {
        "id": "incident_response",
        "title": "Incident / breach response",
        "owner": "Security / Legal / Privacy",
        "required": {"incident_readiness"},
        "unknown": "No breach-response runbook, escalation, severity, notification, or evidence-retention workflow was found.",
    },
    {
        "id": "backup_recovery",
        "title": "Backup, retention, and recovery",
        "owner": "Platform / Engineering",
        "required": {"resilience_evidence"},
        "unknown": "No backup, restore, retention, lifecycle, or deletion-protection evidence was found.",
    },
    {
        "id": "consent_journey",
        "title": "Consent and rights journey",
        "owner": "Product / Privacy",
        "required": {"consent_banner", "consent_control", "privacy_text"},
        "unknown": "No browser consent journey or rights-flow evidence was verified.",
    },
    {
        "id": "cloud_iac",
        "title": "Cloud / IaC safeguards",
        "owner": "Cloud / Platform",
        "required": {"cloud_security_evidence", "encryption_evidence", "resilience_evidence"},
        "bad": {"cloud_misconfiguration"},
        "unknown": "No cloud/IaC safeguards were verified from Terraform, Kubernetes, or deployment configuration.",
    },
    {
        "id": "parser_coverage",
        "title": "Parser coverage and scan quality",
        "owner": "Privacy Engineering / Security Engineering",
        "required": set(),
        "unknown": "No semantic parser coverage was available for this scan.",
    },
]


def build_assurance_profile(
    result: ScanResult,
    *,
    privacy_notice_available: bool,
    security_evidence_paths: Sequence[str] | None,
    browser_consent: bool,
) -> Dict[str, Any]:
    """Build a product-facing assurance view from scan evidence.

    The purpose is to prevent overclaiming. A static scan can produce strong
    evidence, but production assurance must distinguish verified signals from
    inferred signals and unknown areas.
    """

    evidence = list(result.evidence)
    dimensions = [
        _dimension_status(
            spec,
            evidence,
            privacy_notice_available=privacy_notice_available,
            security_evidence_paths=security_evidence_paths,
            browser_consent=browser_consent,
            result=result,
        )
        for spec in DIMENSIONS
    ]
    verified = sum(1 for item in dimensions if item["status"] == "verified")
    inferred = sum(1 for item in dimensions if item["status"] == "inferred")
    failing = sum(1 for item in dimensions if item["status"] == "failing")
    unknown = sum(1 for item in dimensions if item["status"] == "unknown")
    score = int(sum(item["score"] for item in dimensions) / max(1, len(dimensions)))
    production_claim = _production_claim(score, failing, unknown)
    return {
        "schema_version": "svikruti-assurance-v1",
        "score": score,
        "production_claim": production_claim,
        "counts": {
            "verified": verified,
            "inferred": inferred,
            "failing": failing,
            "unknown": unknown,
        },
        "dimensions": dimensions,
        "unknowns": [item["unknown_reason"] for item in dimensions if item["status"] == "unknown"],
        "limitations": [
            "Static scanning cannot prove runtime-only data flows unless browser, API, cloud, or telemetry evidence is attached.",
            "Vendor contracts, DPAs, subprocessors, transfer locations, and retention commitments require external evidence.",
            "Encryption and breach readiness are production claims only when infrastructure, CI, SIEM, ticket, or cloud evidence is supplied.",
        ],
    }


def _dimension_status(
    spec: Dict[str, Any],
    evidence: Sequence[Evidence],
    *,
    privacy_notice_available: bool,
    security_evidence_paths: Sequence[str] | None,
    browser_consent: bool,
    result: ScanResult,
) -> Dict[str, Any]:
    dimension_id = str(spec["id"])
    if dimension_id == "parser_coverage":
        return _parser_coverage_status(spec, result)
    if dimension_id == "notice_coverage":
        return _notice_status(spec, result, privacy_notice_available)
    if dimension_id == "consent_journey" and browser_consent:
        matched = [item for item in evidence if item.kind in spec.get("required", set())]
        if matched:
            return _status(spec, "verified", 85, matched, "Browser consent journey evidence was collected.")

    required = set(spec.get("required", set()))
    required_subtypes = set(spec.get("required_subtypes", set()))
    bad_kinds = set(spec.get("bad", set()))
    matched = [item for item in evidence if item.kind in required]
    if required_subtypes:
        matched = [item for item in matched if item.metadata.get("subtype") in required_subtypes]
    bad = [item for item in evidence if item.kind in bad_kinds]
    if dimension_id == "vulnerability_management":
        imported_bad = [
            item
            for item in bad
            if item.severity in {"HIGH", "CRITICAL"} and item.kind == "imported_security_finding"
        ]
        bad = imported_bad
        if security_evidence_paths and matched and not bad:
            return _status(spec, "verified", 90, matched, "Security scanner outputs were imported without high-severity blockers.")
    if bad:
        return _status(spec, "failing", 15, bad + matched, _failure_reason(dimension_id, bad))
    if _has_high_confidence(matched):
        return _status(spec, "verified", 85, matched, "Direct high-confidence evidence is present.")
    if matched:
        return _status(spec, "inferred", 65, matched, "Evidence is present, but production scope still needs confirmation.")
    return _status(spec, "unknown", 25, [], str(spec["unknown"]))


def _notice_status(spec: Dict[str, Any], result: ScanResult, privacy_notice_available: bool) -> Dict[str, Any]:
    if not privacy_notice_available:
        return _status(spec, "unknown", 20, [], str(spec["unknown"]))
    gaps = result.notice_gaps or []
    if gaps:
        return {
            **_status(spec, "failing", 25, [], "Privacy notice was supplied, but scanner found coverage gaps."),
            "gaps": gaps[:10],
        }
    return _status(spec, "verified", 85, [], "Privacy notice was supplied and no scanner-detected coverage gaps remain.")


def _parser_coverage_status(spec: Dict[str, Any], result: ScanResult) -> Dict[str, Any]:
    quality = result.scan_quality or {}
    coverage = int(quality.get("parser_coverage_percent") or 0)
    engines = quality.get("parser_engines") or {}
    if coverage >= 60:
        return {
            **_status(spec, "verified", min(95, coverage), [], f"Semantic parser coverage is {coverage}% with engines: {', '.join(engines) or 'none'}."),
            "parser_engines": engines,
        }
    if coverage > 0:
        return {
            **_status(spec, "inferred", max(45, coverage), [], f"Semantic parser coverage is partial at {coverage}%. Regex and heuristic fallback still contributed evidence."),
            "parser_engines": engines,
        }
    return {
        **_status(spec, "unknown", 20, [], str(spec["unknown"])),
        "parser_engines": engines,
    }


def _status(
    spec: Dict[str, Any],
    status: str,
    score: int,
    evidence: Sequence[Evidence],
    reason: str,
) -> Dict[str, Any]:
    refs = sorted({_evidence_ref(item) for item in evidence})[:25]
    return {
        "id": spec["id"],
        "title": spec["title"],
        "owner": spec["owner"],
        "status": status,
        "score": score,
        "evidence_count": len(refs),
        "evidence_refs": refs,
        "reason": reason,
        "unknown_reason": reason if status == "unknown" else "",
    }


def _has_high_confidence(evidence: Iterable[Evidence]) -> bool:
    return any(item.metadata.get("confidence") == "high" for item in evidence)


def _failure_reason(dimension_id: str, evidence: Sequence[Evidence]) -> str:
    labels = ", ".join(sorted({item.label for item in evidence})[:4])
    if dimension_id == "encryption":
        return f"Transport or cryptography weakness detected: {labels}."
    if dimension_id == "secrets":
        return f"Secret exposure evidence detected: {labels}."
    if dimension_id == "vulnerability_management":
        return f"Imported high-severity vulnerability evidence detected: {labels}."
    if dimension_id == "cloud_iac":
        return f"Cloud/IaC misconfiguration evidence detected: {labels}."
    return f"Blocking evidence detected: {labels}."


def _production_claim(score: int, failing: int, unknown: int) -> str:
    if failing:
        return "not production-assured"
    if score >= 80 and unknown <= 1:
        return "strong evidence, production review required"
    if score >= 60:
        return "partial evidence, production gaps remain"
    return "insufficient evidence for production assurance"


def _evidence_ref(item: Evidence) -> str:
    return str(item.metadata.get("evidence_ref") or item.file or item.source)
