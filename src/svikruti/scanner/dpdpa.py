"""DPDPA-oriented aggregation for scanner evidence."""

from __future__ import annotations

from typing import Dict, Iterable, List, Set

from svikruti.models import Evidence, EvidenceGraph, GraphEdge, GraphNode, ScanResult, ScanSummary
from svikruti.scanner.patterns import INDIA_NOTICE_TERMS


SEVERITY_POINTS = {
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 10,
    "CRITICAL": 16,
}


def _risk_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 18:
        return "MEDIUM"
    return "LOW"


def summarize(evidence: Iterable[Evidence], files_scanned: int, pages_scanned: int) -> ScanSummary:
    categories: Set[str] = set()
    third_parties: Set[str] = set()
    score = 0

    for item in evidence:
        score += SEVERITY_POINTS.get(item.severity, 1)
        data_category = item.metadata.get("data_category")
        if data_category:
            categories.add(str(data_category))
        if item.kind in {"third_party", "website_third_party", "website_third_party_script"}:
            third_party = item.metadata.get("third_party") or item.metadata.get("domain")
            if third_party:
                third_parties.add(str(third_party))

    capped_score = min(score, 100)
    return ScanSummary(
        files_scanned=files_scanned,
        website_pages_scanned=pages_scanned,
        personal_data_categories=sorted(categories),
        third_parties=sorted(third_parties),
        risk_score=capped_score,
        risk_level=_risk_level(capped_score),
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
                )
                add_edge(data_node, obligation_node, "triggers", index)
                flow["dpdpa_obligations"].add(item.category)
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

    lower_notice = privacy_notice_text.lower()
    gaps: List[str] = []
    for category in result.summary.personal_data_categories:
        if category.lower() not in lower_notice:
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


def _notice_mentions_category(category: str, notice_lower: str) -> bool:
    if not notice_lower:
        return False
    synonyms = {
        "Identity": ["identity", "name", "profile"],
        "Contact": ["contact", "email", "phone", "mobile"],
        "Government ID": ["government", "aadhaar", "aadhar", "pan", "identity document"],
        "Financial": ["financial", "payment", "upi", "bank", "card"],
        "Location": ["location", "address", "pincode"],
        "Children": ["children", "child", "minor", "guardian"],
        "Health": ["health", "medical"],
        "Device": ["device", "cookie", "ip address", "identifier"],
    }
    return any(term in notice_lower for term in synonyms.get(category, [category.lower()]))


def _notice_mentions_third_party(third_party: str, notice_lower: str) -> bool:
    if not notice_lower:
        return False
    token = third_party.split(".")[0].lower()
    return token in notice_lower or any(term in notice_lower for term in INDIA_NOTICE_TERMS["third_parties"])


def _obligation_description(category: str) -> str:
    descriptions = {
        "Notice transparency": "Tell data principals what personal data is processed and for what purpose.",
        "Consent and notice": "Ensure consent/notice basis is clear, specific, and withdrawable where applicable.",
        "Data minimization": "Collect only what is necessary for a stated purpose.",
        "Security safeguards": "Protect personal data against breach and unauthorized access.",
        "Purpose limitation": "Use personal data only for disclosed and lawful purposes.",
        "Children's data": "Apply heightened checks for children or guardian-linked processing.",
        "Tracking and consent": "Gate non-essential tracking and make withdrawal discoverable.",
        "Third-party processors": "Control processors/vendors contractually and disclose recipient categories.",
    }
    return descriptions.get(category, "Map this evidence to a documented privacy control.")
