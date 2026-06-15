"""Shared data models for scanner output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    """One concrete observation produced by a scanner."""

    kind: str
    label: str
    severity: str
    source: str
    detail: str
    recommendation: str
    file: Optional[str] = None
    line: Optional[int] = None
    category: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSummary:
    files_scanned: int = 0
    website_pages_scanned: int = 0
    personal_data_categories: List[str] = field(default_factory=list)
    third_parties: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str
    evidence_refs: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    data_flows: List[Dict[str, Any]] = field(default_factory=list)
    proof_pack: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "data_flows": self.data_flows,
            "proof_pack": self.proof_pack,
        }


@dataclass
class ScanResult:
    product: str
    generated_at: str
    repo_path: Optional[str]
    url: Optional[str]
    summary: ScanSummary
    evidence: List[Evidence]
    ropa_starter: List[Dict[str, Any]]
    notice_gaps: List[str]
    evidence_graph: EvidenceGraph
    disclaimers: List[str]
    ai_insights: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def empty(cls, repo_path: Optional[str], url: Optional[str]) -> "ScanResult":
        return cls(
            product="Svikruti PrivacyOps Evidence Scanner",
            generated_at=datetime.now(timezone.utc).isoformat(),
            repo_path=repo_path,
            url=url,
            summary=ScanSummary(),
            evidence=[],
            ropa_starter=[],
            notice_gaps=[],
            evidence_graph=EvidenceGraph(),
            disclaimers=[
                "This report is engineering evidence for DPDPA readiness. It is not legal advice or a compliance certification.",
                "Static code scanning can miss runtime-only flows. Website scanning without browser execution can miss client-side behavior.",
            ],
            ai_insights={},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": self.product,
            "generated_at": self.generated_at,
            "repo_path": self.repo_path,
            "url": self.url,
            "summary": self.summary.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "ropa_starter": self.ropa_starter,
            "notice_gaps": self.notice_gaps,
            "evidence_graph": self.evidence_graph.to_dict(),
            "disclaimers": self.disclaimers,
            "ai_insights": self.ai_insights,
        }
