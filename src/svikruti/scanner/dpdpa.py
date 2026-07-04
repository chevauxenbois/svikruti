"""DPDPA-oriented aggregation for scanner evidence."""

from __future__ import annotations

import math
from typing import Dict, Iterable, List, Optional, Set, Tuple

from svikruti.models import Evidence, EvidenceGraph, GraphEdge, GraphNode, ScanResult, ScanSummary
from svikruti.scanner.patterns import INDIA_NOTICE_TERMS


# Per-severity weights feeding the saturating risk model below.
SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 8,
    "CRITICAL": 16,
}

# Backwards-compatible alias (older code/tests referenced SEVERITY_POINTS).
SEVERITY_POINTS = SEVERITY_WEIGHTS

# Severity-tiered scoring: each severity tier contributes a bounded amount,
#   tier_score = tier_cap * (1 - exp(-count / tier_n0))
# and the total is their sum (max 97). Benchmark-driven design (healthchecks,
# saleor, excalidraw): any volume-additive model pins every data-heavy real
# repository at 100, because hundreds of genuine MEDIUM/HIGH inventory
# findings swamp it. Bounded tiers mean the CRITICAL band (75+) is reachable
# only through actual critical evidence (several CRITICAL findings plus a
# meaningful HIGH tail), never through sheer volume of inventory findings.
RISK_TIER_PARAMS = {
    # severity: (cap, n0)
    "CRITICAL": (55.0, 2.5),
    "HIGH": (35.0, 12.0),
    "MEDIUM": (6.0, 40.0),
    "LOW": (1.0, 50.0),
}

# Evidence kinds that represent a control being PRESENT / PASSING (good news).
# They stay in the report as evidence but must never add risk points.
# Anything with metadata {"positive_evidence": True} is also excluded.
NON_RISK_EVIDENCE_KINDS = {
    "encryption_evidence",
    "security_tooling",
    "security_monitoring",
    "endpoint_security",
    "incident_readiness",
    "resilience_evidence",
    "cloud_security_evidence",
}


def _risk_level(score: int) -> str:
    """Map a 0-100 risk score to a band.

    Band meanings:
      0-24   LOW      - hygiene items only; no urgent privacy/security risk detected.
      25-49  MEDIUM   - real gaps found; schedule remediation before next release.
      50-74  HIGH     - serious gaps (multiple critical/high findings); block-launch review.
      75-100 CRITICAL - widespread critical exposure; treat as an incident-level backlog.
    """
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _is_risk_evidence(item: Evidence) -> bool:
    """Return True when the evidence item represents a gap/risk (not a passing control)."""
    if item.kind in NON_RISK_EVIDENCE_KINDS:
        return False
    if item.metadata.get("positive_evidence"):
        return False
    return True


def _dedup_key(item: Evidence) -> Tuple[Optional[str], Optional[int], str]:
    """Key used to collapse the same finding reported by multiple detector layers.

    Findings sharing (file, line, data category / detector family) from the
    code, semantic, and tree-sitter layers describe the same underlying line.
    """
    data_category = item.metadata.get("data_category")
    if data_category:
        family = str(data_category).lower()
    else:
        detector_id = str(item.metadata.get("detector_id") or "")
        family = detector_id.split(".")[-1] if detector_id else item.kind
    return (item.file, item.line, family)


def _mark_scoring_duplicates(items: List[Evidence]) -> List[Evidence]:
    """Collapse cross-layer duplicates for SCORING only.

    All evidence items stay in the report; duplicates are tagged with
    metadata {"scoring_duplicate": True} so the evidence explorer stays
    complete while each (file, line, category) counts once for the score.
    The highest-severity duplicate is the one that gets scored.
    """
    best: Dict[Tuple[Optional[str], Optional[int], str], Evidence] = {}
    scored: List[Evidence] = []
    for item in items:
        if item.file is None or item.line is None:
            scored.append(item)
            continue
        key = _dedup_key(item)
        current = best.get(key)
        if current is None:
            best[key] = item
        elif SEVERITY_WEIGHTS.get(item.severity, 1) > SEVERITY_WEIGHTS.get(current.severity, 1):
            current.metadata["scoring_duplicate"] = True
            best[key] = item
        else:
            item.metadata["scoring_duplicate"] = True
    scored.extend(best.values())
    return scored


def _risk_score(scorable: List[Evidence]) -> int:
    """Severity-tiered bounded risk score (0-100).

    Each severity tier saturates independently:
        tier_score = cap * (1 - exp(-count / n0))
    with (cap, n0) from RISK_TIER_PARAMS, and the total is the sum.

    Calibration (deduped, risk-only counts; benchmarked on real OSS repos):
      - 0 findings                      -> 0
      - 3 CRITICAL + 5 HIGH             -> ~50 (HIGH band: block-launch review)
      - 100s of MEDIUM inventory items  -> at most +6 (they inform, not alarm)
      - CRITICAL band (75+) requires ~5+ CRITICAL findings alongside a real
        HIGH tail; volume of lower-severity findings can never reach it.
    """
    counts: Dict[str, int] = {}
    for item in scorable:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    score = 0.0
    for severity, (cap, n0) in RISK_TIER_PARAMS.items():
        count = counts.get(severity, 0)
        if count > 0:
            score += cap * (1.0 - math.exp(-count / n0))
    return int(round(score))


def summarize(evidence: Iterable[Evidence], files_scanned: int, pages_scanned: int) -> ScanSummary:
    items = list(evidence)
    categories: Set[str] = set()
    third_parties: Set[str] = set()

    for item in items:
        data_category = item.metadata.get("data_category")
        if data_category:
            categories.add(str(data_category))
        if item.kind in {"third_party", "website_third_party", "website_third_party_script"}:
            third_party = item.metadata.get("third_party") or item.metadata.get("domain")
            if third_party:
                third_parties.add(str(third_party))

    # Score only genuine risk evidence, deduplicated across detector layers.
    risk_items = [item for item in items if _is_risk_evidence(item)]
    scorable = _mark_scoring_duplicates(risk_items)
    score = _risk_score(scorable)

    return ScanSummary(
        files_scanned=files_scanned,
        website_pages_scanned=pages_scanned,
        personal_data_categories=sorted(categories),
        third_parties=sorted(third_parties),
        risk_score=score,
        risk_level=_risk_level(score),
    )


def build_ropa_starter(evidence: Iterable[Evidence]) -> List[Dict[str, object]]:
    grouped: Dict[str, Dict[str, object]] = {}
    for item in evidence:
        data_category = item.metadata.get("data_category")
        if not data_category:
            continue
        key = str(data_category)
        evidence_ref = _evidence_ref(item)
        entry = grouped.setdefault(
            key,
            {
                "record_id": f"ROPA-{len(grouped) + 1:03d}",
                "activity": f"{key} personal-data processing",
                "data_categories": key,
                "data_subjects": "Users / customers / website visitors",
                "purposes": set(),
                "systems_or_sources": set(),
                "collection_points": set(),
                "storage_locations": set(),
                "logging_locations": set(),
                "third_parties": set(),
                "dpdpa_basis": "Consent or legitimate use to be confirmed",
                "consent_required": "To be confirmed",
                "retention": "To be defined",
                "deletion_trigger": "Purpose completion / withdrawal / legal retention review",
                "security_measures": set(),
                "notice_coverage": "To be compared",
                "rights_impact": "Access, correction, erasure, grievance, and nomination handling to be confirmed",
                "risk_tier": "Medium",
                "owner": "Privacy / Product owner to assign",
                "review_status": "Draft - scanner inferred",
                "dpdpa_notes": set(),
                "evidence_refs": set(),
                "confidence": set(),
                "languages": set(),
                "frameworks": set(),
            },
        )
        entry["systems_or_sources"].add(item.file or item.source)
        entry["purposes"].add(_purpose_from_kind(item.kind))
        entry["evidence_refs"].add(evidence_ref)
        entry["confidence"].add(str(item.metadata.get("confidence", "unknown")))
        language = item.metadata.get("language")
        if language:
            entry["languages"].add(str(language))
        for framework in item.metadata.get("frameworks", []) or []:
            entry["frameworks"].add(str(framework))
        if "collection" in item.kind or "form" in item.kind or "website_form" in item.kind:
            entry["collection_points"].add(evidence_ref)
        if "storage" in item.kind:
            entry["storage_locations"].add(evidence_ref)
        if "logging" in item.kind:
            entry["logging_locations"].add(evidence_ref)
        if item.category:
            entry["dpdpa_notes"].add(item.category)
            if item.category in {"Security safeguards", "Data minimization", "Children's data"}:
                entry["risk_tier"] = "High"
        if key in {"Government ID", "Health", "Children"}:
            entry["risk_tier"] = "High"
            entry["security_measures"].add("Strict access control, encryption, audit logging, and minimization review")
        elif key in {"Contact", "Financial", "Location"}:
            entry["security_measures"].add("Access control, retention control, and purpose review")
        else:
            entry["security_measures"].add("Standard application access control and retention review")
        third_party = item.metadata.get("third_party") or item.metadata.get("domain")
        if third_party:
            entry["third_parties"].add(str(third_party))

    normalized: List[Dict[str, object]] = []
    for entry in grouped.values():
        normalized.append(
            {
                "record_id": entry["record_id"],
                "activity": entry["activity"],
                "data_categories": entry["data_categories"],
                "data_subjects": entry["data_subjects"],
                "purposes": sorted(entry["purposes"]),
                "systems_or_sources": sorted(entry["systems_or_sources"]),
                "collection_points": sorted(entry["collection_points"]),
                "storage_locations": sorted(entry["storage_locations"]),
                "logging_locations": sorted(entry["logging_locations"]),
                "third_parties": sorted(entry["third_parties"]),
                "dpdpa_basis": entry["dpdpa_basis"],
                "consent_required": entry["consent_required"],
                "retention": entry["retention"],
                "deletion_trigger": entry["deletion_trigger"],
                "security_measures": sorted(entry["security_measures"]),
                "notice_coverage": entry["notice_coverage"],
                "rights_impact": entry["rights_impact"],
                "risk_tier": entry["risk_tier"],
                "owner": entry["owner"],
                "review_status": entry["review_status"],
                "dpdpa_notes": sorted(entry["dpdpa_notes"]),
                "evidence_refs": sorted(entry["evidence_refs"]),
                "confidence": sorted(entry["confidence"]),
                "languages": sorted(entry["languages"]),
                "frameworks": sorted(entry["frameworks"]),
            }
        )
    return normalized


def build_evidence_graph(result: ScanResult, privacy_notice_text: str) -> EvidenceGraph:
    nodes: Dict[str, GraphNode] = {}
    edges: Dict[tuple[str, str, str], GraphEdge] = {}
    data_flows: Dict[str, Dict[str, object]] = {}
    notice_lower = privacy_notice_text.lower()

    def add_node(node_id: str, label: str, node_type: str, **metadata: object) -> str:
        if node_id not in nodes:
            nodes[node_id] = GraphNode(id=node_id, label=label, type=node_type, metadata=dict(metadata))
        else:
            nodes[node_id].metadata.update(metadata)
        return node_id

    def add_edge(source: str, target: str, label: str, evidence_index: int) -> None:
        key = (source, target, label)
        if key not in edges:
            edges[key] = GraphEdge(source=source, target=target, label=label, evidence_refs=[])
        edges[key].evidence_refs.append(evidence_index)

    app_node = add_node("system:application", "Application / website", "system")
    notice_node = add_node("notice:privacy", "Privacy notice", "notice", available=bool(privacy_notice_text))

    for index, item in enumerate(result.evidence):
        source_label = item.file or item.source
        source_node = add_node(f"source:{source_label}", source_label, "source", source=item.source)

        data_category = item.metadata.get("data_category")
        if data_category:
            data_node = add_node(f"data:{data_category}", str(data_category), "data_category")
            add_edge(source_node, data_node, "contains", index)
            add_edge(app_node, data_node, _flow_label(item.kind), index)

            flow = data_flows.setdefault(
                str(data_category),
                {
                    "data_category": str(data_category),
                    "collection_points": set(),
                    "storage_points": set(),
                    "logging_risks": set(),
                    "third_parties": set(),
                    "notice_status": "covered" if _notice_mentions_category(str(data_category), notice_lower) else "missing",
                    "dpdpa_obligations": set(),
                    "dpdpa_references": set(),
                    "remediation": set(),
                },
            )
            if "collection" in item.kind or "form" in item.kind or "website_form" in item.kind:
                flow["collection_points"].add(source_label)
            elif "storage" in item.kind:
                flow["storage_points"].add(source_label)
            elif "logging" in item.kind:
                flow["logging_risks"].add(source_label)
            if item.category:
                obligation_node = add_node(
                    f"obligation:{item.category}",
                    item.category,
                    "dpdpa_obligation",
                    description=_obligation_description(item.category),
                    dpdpa_reference=dpdpa_reference(item.category),
                )
                add_edge(data_node, obligation_node, "triggers", index)
                flow["dpdpa_obligations"].add(item.category)
                reference = dpdpa_reference(item.category)
                if reference:
                    flow["dpdpa_references"].add(reference)
            if flow["notice_status"] == "covered":
                add_edge(notice_node, data_node, "discloses", index)
            else:
                add_edge(data_node, notice_node, "missing disclosure", index)
                flow["remediation"].add(f"Update privacy notice to disclose {data_category} data.")
            if item.kind == "logging_risk":
                flow["remediation"].add(f"Mask or remove {data_category} data from logs in {source_label}.")
            if str(data_category) in {"Government ID", "Health", "Children"}:
                flow["remediation"].add(f"Document strict purpose, retention, and access controls for {data_category}.")

        third_party = item.metadata.get("third_party") or item.metadata.get("domain")
        if third_party:
            third_node = add_node(f"third_party:{third_party}", str(third_party), "third_party")
            add_edge(source_node, third_node, "references", index)
            add_edge(app_node, third_node, "shares or may share data", index)
            if not _notice_mentions_third_party(str(third_party), notice_lower):
                add_edge(third_node, notice_node, "missing disclosure", index)

    proof_pack = build_proof_pack(result, privacy_notice_text, data_flows)
    return EvidenceGraph(
        nodes=sorted(nodes.values(), key=lambda node: (node.type, node.label)),
        edges=sorted(edges.values(), key=lambda edge: (edge.source, edge.target, edge.label)),
        data_flows=[_normalize_flow(flow) for flow in data_flows.values()],
        proof_pack=proof_pack,
    )


def _purpose_from_kind(kind: str) -> str:
    if "form" in kind or "collection" in kind:
        return "Collection through product or website interface"
    if "storage" in kind:
        return "Storage in application data store"
    if "logging" in kind:
        return "Operational logging or debugging"
    if "third_party" in kind:
        return "Third-party processing or analytics"
    return "Application processing"


def notice_gap_check(result: ScanResult, privacy_notice_text: str) -> List[str]:
    if not privacy_notice_text:
        return ["No privacy notice text was available for comparison."]

    # Normalize the notice text (case + whitespace) and match each detected
    # data category against a synonym set instead of a single literal token.
    lower_notice = " ".join(privacy_notice_text.lower().split())
    gaps: List[str] = []
    for category in result.summary.personal_data_categories:
        if not _notice_mentions_category(category, lower_notice):
            gaps.append(f"Detected {category} data, but the privacy notice does not clearly mention that category.")
    for third_party in result.summary.third_parties:
        token = str(third_party).split(".")[0].lower()
        if token and token not in lower_notice:
            gaps.append(f"Detected third party '{third_party}', but the privacy notice does not clearly mention it or its category.")
    if "withdraw" not in lower_notice:
        gaps.append("Privacy notice does not clearly mention consent withdrawal.")
    if "grievance" not in lower_notice and "complaint" not in lower_notice:
        gaps.append("Privacy notice does not clearly mention grievance or complaint handling.")
    return gaps


def build_proof_pack(
    result: ScanResult,
    privacy_notice_text: str,
    data_flows: Dict[str, Dict[str, object]],
) -> List[Dict[str, object]]:
    notice_lower = privacy_notice_text.lower()
    actions: List[Dict[str, object]] = []

    for category, flow in sorted(data_flows.items()):
        if flow["notice_status"] == "missing":
            actions.append(
                {
                    "title": f"Update privacy notice for {category}",
                    "control_area": "Notice transparency",
                    "dpdpa_reference": dpdpa_reference("Notice transparency"),
                    "severity": "CRITICAL" if category in {"Government ID", "Health", "Children"} else "HIGH",
                    "owner": "Legal / Privacy",
                    "status": "Open",
                    "due": "Before launch / next release",
                    "why": f"Svikruti detected {category} data in engineering evidence, but not in the notice text.",
                    "evidence": sorted(flow["collection_points"] | flow["storage_points"] | flow["logging_risks"]),
                    "artifact": "Privacy notice change",
                    "priority": "P0" if category in {"Government ID", "Health", "Children"} else "P1",
                    "acceptance_criteria": [
                        f"Privacy notice explicitly covers {category} data or documents why it is out of scope.",
                        "Purpose, retention, rights path, and withdrawal/complaint path are reviewed.",
                        "Svikruti scan is rerun and attached to the ticket.",
                    ],
                }
            )
        if flow["logging_risks"]:
            actions.append(
                {
                    "title": f"Reduce {category} logging exposure",
                    "control_area": "Security safeguards",
                    "dpdpa_reference": dpdpa_reference("Security safeguards"),
                    "severity": "CRITICAL" if category in {"Government ID", "Health", "Children"} else "HIGH",
                    "owner": "Engineering / Security",
                    "status": "Open",
                    "due": "Before launch / next release",
                    "why": "Personal data appears near logging statements.",
                    "evidence": sorted(flow["logging_risks"]),
                    "artifact": "Logging redaction control",
                    "priority": "P0" if category in {"Government ID", "Health", "Children"} else "P1",
                    "acceptance_criteria": [
                        "Personal data is masked, hashed, removed, or justified in logs.",
                        "Log retention is documented.",
                        "Regression test or code review evidence is attached.",
                    ],
                }
            )

    for key, terms in INDIA_NOTICE_TERMS.items():
        if not privacy_notice_text:
            break
        if not any(term in notice_lower for term in terms):
            actions.append(
                {
                    "title": f"Add {key.replace('_', ' ')} language to privacy notice",
                    "control_area": "Notice transparency",
                    "dpdpa_reference": _notice_term_reference(key),
                    "severity": "HIGH",
                    "owner": "Legal / Privacy",
                    "status": "Open",
                    "due": "Before launch / next release",
                    "why": f"The notice does not clearly include DPDPA-relevant {key.replace('_', ' ')} terms.",
                    "evidence": ["privacy notice text"],
                    "artifact": "Privacy notice change",
                    "priority": "P1",
                    "acceptance_criteria": [
                        f"Notice includes reviewed {key.replace('_', ' ')} language.",
                        "Language is understandable and reachable from product/privacy paths.",
                    ],
                }
            )

    if result.summary.third_parties and not any(term in notice_lower for term in INDIA_NOTICE_TERMS["third_parties"]):
        actions.append(
            {
                "title": "Disclose processor/vendor categories",
                "control_area": "Vendor governance",
                "dpdpa_reference": dpdpa_reference("Vendor governance"),
                "severity": "HIGH",
                "owner": "Legal / Procurement",
                "status": "Open",
                "due": "Before launch / next release",
                "why": "Third-party services were detected but processor/vendor disclosure language is missing or weak.",
                "evidence": result.summary.third_parties,
                "artifact": "Vendor register + notice update",
                "priority": "P1",
                "acceptance_criteria": [
                    "Vendor register includes detected processors/tools.",
                    "DPA/contract status and transfer location are confirmed.",
                    "Privacy notice discloses recipient/vendor categories where applicable.",
                ],
            }
        )

    return actions


def _normalize_flow(flow: Dict[str, object]) -> Dict[str, object]:
    normalized: Dict[str, object] = {}
    for key, value in flow.items():
        if isinstance(value, set):
            normalized[key] = sorted(value)
        else:
            normalized[key] = value
    return normalized


def _evidence_ref(item: Evidence) -> str:
    ref = item.metadata.get("evidence_ref")
    if ref:
        return str(ref)
    location = item.file or item.source
    if item.line:
        return f"{location}:{item.line}:{item.kind}"
    return f"{location}:{item.kind}"


def _flow_label(kind: str) -> str:
    if "form" in kind or "collection" in kind:
        return "collects"
    if "storage" in kind:
        return "stores"
    if "logging" in kind:
        return "logs"
    return "processes"


# Synonym sets used to check whether a privacy notice discloses a detected
# data category. Matching is case-insensitive on normalized notice text.
NOTICE_CATEGORY_SYNONYMS: Dict[str, List[str]] = {
    "Identity": ["identity", "name", "profile", "username", "date of birth"],
    "Contact": ["contact", "email", "e-mail", "phone", "mobile", "telephone", "phone number", "postal address"],
    "Government ID": [
        "government",
        "aadhaar",
        "aadhar",
        "pan",
        "passport",
        "government id",
        "kyc",
        "identity document",
        "voter id",
    ],
    "Financial": ["financial", "payment", "card", "bank", "upi", "billing", "transaction"],
    "Location": ["location", "address", "geolocation", "gps", "pincode", "pin code"],
    "Children": ["children", "child", "minor", "under 18", "guardian", "parental consent", "parent"],
    "Health": ["health", "medical", "fitness", "wellness"],
    "Device": ["device", "cookie", "ip address", "identifier", "advertising id"],
    "Credentials": ["password", "credential", "login"],
    "Biometric": ["biometric", "fingerprint", "face recognition", "facial"],
}


def _notice_mentions_category(category: str, notice_lower: str) -> bool:
    if not notice_lower:
        return False
    return any(term in notice_lower for term in NOTICE_CATEGORY_SYNONYMS.get(category, [category.lower()]))


def _notice_mentions_third_party(third_party: str, notice_lower: str) -> bool:
    if not notice_lower:
        return False
    token = third_party.split(".")[0].lower()
    return token in notice_lower or any(term in notice_lower for term in INDIA_NOTICE_TERMS["third_parties"])


# Statutory references for obligation/control areas under the Digital Personal
# Data Protection Act, 2023 (India) and the DPDP Rules, 2025. Descriptive
# labels (e.g. "Purpose limitation") remain, but every statutory claim below
# maps to an actual DPDPA provision. Areas without a defensible citation carry
# no reference at all rather than a borrowed GDPR concept.
DPDPA_AREA_REFERENCES: Dict[str, str] = {
    "Notice transparency": "DPDP Act 2023, Sec. 5 (Notice)",
    "Consent and notice": "DPDP Act 2023, Sec. 6 (Consent and its withdrawal)",
    "Legitimate uses": "DPDP Act 2023, Sec. 7 (Certain legitimate uses)",
    "Security safeguards": "DPDP Act 2023, Sec. 8(5) (Reasonable security safeguards)",
    "Breach notification": "DPDP Act 2023, Sec. 8(6) + DPDP Rules 2025 (intimation to Board and affected Data Principals; detailed report to the Board within 72 hours)",
    "Breach readiness": "DPDP Act 2023, Sec. 8(6) + DPDP Rules 2025 (intimation to Board and affected Data Principals; detailed report to the Board within 72 hours)",
    "Data accuracy": "DPDP Act 2023, Sec. 8(3) (Completeness, accuracy, and consistency)",
    "Data minimization": "DPDP Act 2023, Sec. 6(1) (consent limited to personal data necessary for the specified purpose)",
    "Erasure and retention": "DPDP Act 2023, Sec. 8(7) (Erasure when purpose is served or consent withdrawn)",
    "Resilience": "DPDP Act 2023, Sec. 8(5) (Reasonable security safeguards, including availability/recovery measures)",
    "Grievance redressal": "DPDP Act 2023, Sec. 8(10) read with Sec. 13 (Grievance redressal)",
    "Grievance": "DPDP Act 2023, Sec. 8(10) read with Sec. 13 (Grievance redressal)",
    "Children's data": "DPDP Act 2023, Sec. 9 (verifiable parental consent; no tracking, behavioural monitoring, or targeted advertising directed at children)",
    "Tracking and consent": "DPDP Act 2023, Sec. 6 (consent and withdrawal); Sec. 9(3) for tracking or behavioural monitoring of children",
    "Third-party processors": "DPDP Act 2023, Sec. 8(2) (processing by Data Processors only under valid contract)",
    "Vendor governance": "DPDP Act 2023, Sec. 8(2) (processing by Data Processors only under valid contract)",
    "Purpose limitation": "DPDP Act 2023, Sec. 4 read with Secs. 6-7 (processing only for a lawful purpose with consent or a legitimate use)",
    "SDF duties": "DPDP Act 2023, Sec. 10 (Significant Data Fiduciary: DPIA, independent audit, DPO based in India)",
    "Data principal rights": "DPDP Act 2023, Secs. 11-14 (access, correction and erasure, grievance redressal, nomination)",
    "Cross-border transfers": "DPDP Act 2023, Sec. 16 (transfers permitted except to countries restricted by the Central Government - negative list)",
}


def dpdpa_reference(category: str) -> str:
    """Return the DPDPA citation string for an obligation/control area ('' if unmapped)."""
    return DPDPA_AREA_REFERENCES.get(category, "")


# Citations for the INDIA_NOTICE_TERMS keys used in notice-language checks.
_NOTICE_TERM_REFERENCES: Dict[str, str] = {
    "grievance": DPDPA_AREA_REFERENCES["Grievance redressal"],
    "withdrawal": DPDPA_AREA_REFERENCES["Consent and notice"],
    "rights": DPDPA_AREA_REFERENCES["Data principal rights"],
    "children": DPDPA_AREA_REFERENCES["Children's data"],
    "retention": DPDPA_AREA_REFERENCES["Erasure and retention"],
    "third_parties": DPDPA_AREA_REFERENCES["Third-party processors"],
}


def _notice_term_reference(key: str) -> str:
    return _NOTICE_TERM_REFERENCES.get(key, DPDPA_AREA_REFERENCES["Notice transparency"])


def _obligation_description(category: str) -> str:
    descriptions = {
        "Notice transparency": "Tell data principals what personal data is processed and for what purpose.",
        "Consent and notice": "Ensure consent/notice basis is clear, specific, and withdrawable where applicable.",
        "Legitimate uses": "Rely on a Sec. 7 legitimate use only where it genuinely applies, and document it.",
        "Data minimization": "Collect only what is necessary for a stated purpose.",
        "Security safeguards": "Protect personal data against breach and unauthorized access.",
        "Breach notification": "Intimate the Board and affected data principals of a breach; file the detailed report to the Board within 72 hours.",
        "Breach readiness": "Be able to detect, assess, and notify personal data breaches within the statutory timelines.",
        "Data accuracy": "Keep personal data complete, accurate, and consistent where it affects decisions or disclosures.",
        "Erasure and retention": "Erase personal data when the purpose is served or consent is withdrawn, unless retention is legally required.",
        "Purpose limitation": "Use personal data only for disclosed and lawful purposes.",
        "Children's data": "Obtain verifiable parental consent; no tracking, behavioural monitoring, or targeted advertising directed at children.",
        "Tracking and consent": "Gate non-essential tracking and make withdrawal discoverable.",
        "Third-party processors": "Control processors/vendors contractually and disclose recipient categories.",
        "Grievance redressal": "Publish and operate an effective grievance redressal path for data principals.",
        "SDF duties": "If notified as a Significant Data Fiduciary: conduct DPIAs, appoint an independent auditor, and a DPO based in India.",
        "Data principal rights": "Honor access, correction, erasure, grievance, and nomination requests.",
        "Cross-border transfers": "Transfers are permitted except to countries restricted by the Central Government (negative list).",
    }
    description = descriptions.get(category, "Map this evidence to a documented privacy control.")
    reference = dpdpa_reference(category)
    if reference:
        return f"{description} [{reference}]"
    return description
