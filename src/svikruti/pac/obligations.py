"""Framework-neutral privacy obligations and how each one is assessed.

Statuses are deliberately blunt:

- ``pass``            evidenced by code / config / manifest reconciliation
- ``fail``            contradicted by code evidence
- ``attested``        cannot be proven from a repository; a dated, owned human
                      attestation is on record in privacy.yaml
- ``manual``          cannot be proven from a repository and nobody has attested
- ``not_applicable``  the triggering processing does not exist in this codebase

An attestation never overrides a ``fail``: if the code contradicts the claim,
the code wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from svikruti.models import ScanResult
from svikruti.pac.manifest import Attestation, Manifest
from svikruti.pac.reconcile import CodeModel, Finding
from svikruti.pac.taxonomy import is_placeholder


@dataclass
class Assessment:
    id: str
    title: str
    question: str
    proof: str  # code | manifest | attestation
    status: str = "manual"
    summary: str = ""
    findings: List[str] = field(default_factory=list)  # drift/policy fingerprints
    evidence: List[str] = field(default_factory=list)
    attestation: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "question": self.question,
            "proof": self.proof,
            "status": self.status,
            "summary": self.summary,
            "findings": self.findings,
            "evidence": self.evidence,
            "attestation": self.attestation,
        }


@dataclass
class Context:
    result: ScanResult
    manifest: Manifest
    model: CodeModel
    findings: List[Finding]
    today: date

    def open(self, rule: str, field_name: Optional[str] = None, min_severity: Optional[str] = None) -> List[Finding]:
        out = []
        for finding in self.findings:
            if finding.rule != rule or finding.status != "open":
                continue
            if field_name and field_name not in finding.fields:
                continue
            if min_severity == "MEDIUM" and finding.severity == "LOW":
                continue
            out.append(finding)
        return out

    def categories(self) -> Set[str]:
        declared = {slug for activity in self.manifest.activities for slug in activity.data_categories}
        return declared | self.model.categories()

    def control(self, control_id: str) -> Dict[str, Any]:
        return next((item for item in self.result.technical_controls if item.get("id") == control_id), {})


OBLIGATIONS: List[Dict[str, str]] = [
    {"id": "OBL-01", "proof": "code", "title": "The processing record matches the code", "question": "Is every place the code handles personal data, and every processor it calls, covered by a declared processing activity?"},
    {"id": "OBL-02", "proof": "manifest", "title": "Every activity has a specified purpose", "question": "Does each processing activity state why the data is processed?"},
    {"id": "OBL-03", "proof": "manifest", "title": "Every activity has a lawful basis", "question": "Does each processing activity record a lawful basis valid under the selected frameworks?"},
    {"id": "OBL-04", "proof": "manifest", "title": "Retention is defined", "question": "Does each processing activity state how long data is kept or what triggers erasure?"},
    {"id": "OBL-05", "proof": "code", "title": "Only declared data is collected", "question": "Is the code free of personal data categories that were never declared or that policy forbids?"},
    {"id": "OBL-06", "proof": "code", "title": "No personal data in logs", "question": "Is personal data kept out of application logs unless explicitly allowed?"},
    {"id": "OBL-07", "proof": "code", "title": "The privacy notice matches actual processing", "question": "Does the published notice cover every data category and recipient found in code?"},
    {"id": "OBL-08", "proof": "code", "title": "Processors are identified and under contract", "question": "Is every third party the code sends data to declared, with a contract reference?"},
    {"id": "OBL-09", "proof": "manifest", "title": "Cross-border transfers are documented", "question": "Is each processor's country recorded, with a transfer mechanism where policy requires one?"},
    {"id": "OBL-10", "proof": "code", "title": "High-risk processing has an impact assessment", "question": "Does every activity touching high-risk data reference a completed DPIA?"},
    {"id": "OBL-11", "proof": "attestation", "title": "Children's data has verifiable safeguards", "question": "Where children's data is processed, is verifiable parental consent in place and tracking disabled?"},
    {"id": "OBL-12", "proof": "code", "title": "Encryption in transit", "question": "Is personal data transported only over TLS?"},
    {"id": "OBL-13", "proof": "code", "title": "Encryption at rest and key management", "question": "Is stored personal data encrypted with managed keys and no weak cryptography?"},
    {"id": "OBL-14", "proof": "code", "title": "Secrets and credential hygiene", "question": "Is the repository free of hard-coded credentials?"},
    {"id": "OBL-15", "proof": "code", "title": "Vulnerability management", "question": "Do security scanners run on this code, with no unresolved critical findings?"},
    {"id": "OBL-16", "proof": "code", "title": "Security monitoring and logging", "question": "Is there monitoring that would detect unauthorised access to personal data?"},
    {"id": "OBL-17", "proof": "code", "title": "Breach response readiness", "question": "Is there an incident / breach runbook with owners and escalation?"},
    {"id": "OBL-18", "proof": "code", "title": "Backup and recovery", "question": "Is there evidence of backup, restore and recovery for personal-data stores?"},
    {"id": "OBL-19", "proof": "code", "title": "Infrastructure guardrails", "question": "Is infrastructure-as-code free of public storage, public databases and disabled encryption?"},
    {"id": "OBL-20", "proof": "code", "title": "Tracking waits for consent", "question": "Do non-essential trackers stay off until the visitor consents, and after they reject?"},
    {"id": "OBL-21", "proof": "attestation", "title": "Individuals' rights requests are handled", "question": "Is there an operating process for access, correction and erasure requests?"},
    {"id": "OBL-22", "proof": "attestation", "title": "Consent is recorded and withdrawable", "question": "Is consent stored as a provable record, with withdrawal as easy as giving it?"},
    {"id": "OBL-23", "proof": "manifest", "title": "A privacy contact is published", "question": "Is there a named contact or DPO for privacy questions and grievances?"},
    {"id": "OBL-24", "proof": "attestation", "title": "Breach notification procedure exists", "question": "Is there a tested procedure to notify the regulator and affected individuals within statutory timelines?"},
]

_TECH_CONTROLS = {
    "OBL-12": "DPDPA-TECH-001",
    "OBL-13": "DPDPA-TECH-002",
    "OBL-14": "DPDPA-TECH-003",
    "OBL-15": "DPDPA-TECH-004",
    "OBL-16": "DPDPA-TECH-005",
    "OBL-17": "DPDPA-TECH-006",
    "OBL-18": "DPDPA-TECH-007",
    "OBL-19": "DPDPA-TECH-008",
}


def _from_findings(assessment: Assessment, findings: List[Finding], ok: str) -> None:
    if findings:
        assessment.status = "fail"
        assessment.summary = f"{len(findings)} open finding(s): " + "; ".join(sorted({f.title for f in findings}))
        assessment.findings = [finding.fingerprint for finding in findings]
        assessment.evidence = sorted({ref for finding in findings for ref in finding.refs})[:10]
    else:
        assessment.status = "pass"
        assessment.summary = ok


def _obl01(a: Assessment, c: Context) -> None:
    drift = c.open("D001") + c.open("D002") + [f for f in c.open("D003") if f.severity == "HIGH"] + c.open("D008")
    _from_findings(a, drift, f"{len(c.manifest.activities)} declared activit(ies) cover all {len(c.model.files)} file(s) with personal-data evidence.")


def _field(field_name: str, ok: str) -> Callable[[Assessment, Context], None]:
    def evaluate(a: Assessment, c: Context) -> None:
        if not c.manifest.activities:
            if c.model.files:
                a.status, a.summary = "fail", "Code handles personal data but no processing activities are declared."
            else:
                a.status, a.summary = "not_applicable", "No personal-data processing is declared or detected."
            return
        _from_findings(a, c.open("D006", field_name=field_name), ok)

    return evaluate


def _obl04(a: Assessment, c: Context) -> None:
    if not c.manifest.activities:
        a.status, a.summary = ("fail", "Code handles personal data but no processing activities are declared.") if c.model.files else ("not_applicable", "No personal-data processing is declared or detected.")
        return
    _from_findings(a, c.open("D006", field_name="retention") + c.open("D010"), "Every activity defines retention, and every stored table or model is reached by erasure or retention code, or is retained for a recorded reason.")


def _obl05(a: Assessment, c: Context) -> None:
    _from_findings(a, c.open("D002") + c.open("P002"), "Every personal data category found in code is declared, and none is forbidden.")


def _obl06(a: Assessment, c: Context) -> None:
    if c.manifest.policies.personal_data_in_logs == "allow":
        a.status, a.summary = "manual", "policies.personal_data_in_logs is set to allow, so logging is not assessed."
        return
    _from_findings(a, c.open("P001", min_severity="MEDIUM"), "No personal data reaches a logging sink outside recorded allowances.")


def _obl07(a: Assessment, c: Context) -> None:
    gaps = [gap for gap in c.result.notice_gaps if gap.startswith("Detected ")]
    if any(gap.startswith("No privacy notice text") for gap in c.result.notice_gaps):
        a.status, a.summary = "manual", "No privacy notice was supplied (use --privacy-file or --privacy-url) so code-to-notice comparison did not run."
    elif gaps:
        a.status = "fail"
        a.summary = f"The notice omits {len(gaps)} item(s) the code processes."
        a.evidence = gaps[:10]
    else:
        a.status, a.summary = "pass", "The notice mentions every data category and third party found in code."


def _obl08(a: Assessment, c: Context) -> None:
    if not c.manifest.processors and not c.model.processors():
        a.status, a.summary = "not_applicable", "No processors are declared and none were detected."
        return
    _from_findings(
        a,
        c.open("D003") + c.open("D007", field_name="contract") + c.open("D009") + c.open("P006"),
        f"All {len(c.manifest.processors)} processor(s) used in code are declared with a contract reference, and receive only the data recorded for them.",
    )


def _obl09(a: Assessment, c: Context) -> None:
    if not c.manifest.processors and not c.model.processors():
        a.status, a.summary = "not_applicable", "No processors, so no onward transfers to document."
        return
    _from_findings(a, c.open("P004") + c.open("D007", field_name="country"), "Every processor has a recorded country and, where required, a transfer mechanism.")
    if a.status == "pass" and not c.manifest.policies.allowed_transfer_countries:
        a.summary += " Set policies.allowed_transfer_countries to enforce a transfer allow-list."


def _obl10(a: Assessment, c: Context) -> None:
    policies = c.manifest.policies
    from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES

    risky = c.categories() & set(HIGH_RISK_CATEGORIES if policies.require_dpia_for is None else policies.require_dpia_for)
    if not risky:
        a.status, a.summary = "not_applicable", "No high-risk data categories are declared or detected."
        return
    _from_findings(a, c.open("P003"), "Every activity handling high-risk data references an impact assessment.")


def _tech(control_id: str, rules: Tuple[str, ...] = ()) -> Callable[[Assessment, Context], None]:
    def evaluate(a: Assessment, c: Context) -> None:
        extra = [finding for rule in rules for finding in c.open(rule)]
        if extra:
            _from_findings(a, extra, "")
            return
        control = c.control(control_id)
        status = control.get("status")
        a.evidence = list(control.get("evidence_refs") or [])[:10]
        if status == "pass":
            a.status, a.summary = "pass", f"{control.get('evidence_count', 0)} piece(s) of repository evidence."
        elif status == "fail":
            a.status = "fail"
            a.summary = "; ".join(control.get("gaps") or []) or str(control.get("next_action") or "Failing evidence found.")
        else:
            a.status = "manual"
            a.summary = "No evidence in this repository. " + str(control.get("next_action") or "")

    return evaluate


def _obl20(a: Assessment, c: Context) -> None:
    kinds = {item.kind for item in c.result.evidence}
    bad = [item for item in c.result.evidence if item.kind in {"consent_preload_tracking", "consent_reject_tracking"}]
    if bad:
        a.status = "fail"
        a.summary = "; ".join(sorted({item.label for item in bad}))
        a.evidence = [str(item.metadata.get("evidence_ref") or item.label) for item in bad][:10]
    elif any(kind.startswith(("consent_", "browser_")) for kind in kinds):
        a.status, a.summary = "pass", "Browser consent journey ran; no tracking before consent or after reject."
    else:
        a.status, a.summary = "manual", "Run with --url and --browser-consent to test the consent journey."


def _obl11(a: Assessment, c: Context) -> None:
    if "children" not in c.categories():
        a.status, a.summary = "not_applicable", "No children's data is declared or detected."
    else:
        a.status = "fail"
        a.summary = "Children's data is processed, and no current attestation of verifiable parental consent and tracking restrictions is on record."


def _obl23(a: Assessment, c: Context) -> None:
    organization = c.manifest.organization
    contact = organization.get("privacy_contact") or organization.get("dpo") or organization.get("grievance_officer")
    if is_placeholder(contact):
        a.status, a.summary = "fail", "organization.privacy_contact is not set in the manifest."
    else:
        a.status, a.summary = "pass", f"Privacy contact recorded: {contact}."


def _attest_only(a: Assessment, c: Context) -> None:
    a.status, a.summary = "manual", "Cannot be proven from a repository. Add an attestation with an owner, evidence link and review date."


_EVALUATORS: Dict[str, Callable[[Assessment, Context], None]] = {
    "OBL-01": _obl01,
    "OBL-02": _field("purposes", "Every activity states its purposes."),
    "OBL-03": _field("legal_basis", "Every activity records a lawful basis valid under the selected frameworks."),
    "OBL-04": _obl04,
    "OBL-05": _obl05,
    "OBL-06": _obl06,
    "OBL-07": _obl07,
    "OBL-08": _obl08,
    "OBL-09": _obl09,
    "OBL-10": _obl10,
    "OBL-11": _obl11,
    "OBL-20": _obl20,
    "OBL-21": _attest_only,
    "OBL-22": _attest_only,
    "OBL-23": _obl23,
    "OBL-24": _attest_only,
}
_EVALUATORS.update({obligation_id: _tech(control_id) for obligation_id, control_id in _TECH_CONTROLS.items()})
_EVALUATORS["OBL-13"] = _tech("DPDPA-TECH-002", ("P007",))
_EVALUATORS["OBL-21"] = lambda a, c: _from_findings(a, c.open("D010") + c.open("D011"), "") if (c.open("D010") or c.open("D011")) else _attest_only(a, c)


def _obl22(a: Assessment, c: Context) -> None:
    from svikruti.pac.consent import consent_based

    if c.open("P008"):
        _from_findings(a, c.open("P008"), "")
        return
    _attest_only(a, c)
    if any(consent_based(activity) for activity in c.manifest.activities):
        a.summary = (
            "Code checks consent before every consent-based hand-off to a processor. "
            "That consent is stored as a provable record and can be withdrawn needs an attestation."
        )


_EVALUATORS["OBL-22"] = _obl22

# Obligations where a human attestation may stand in for missing repo evidence.
# OBL-11 is special: children's data in code plus an attestation is "attested",
# because the safeguard (parental consent flow) lives outside static analysis.
_ATTESTABLE_WHEN = {"manual"}
_ATTESTABLE_FAIL = {"OBL-11"}


def evaluate_obligations(context: Context) -> List[Assessment]:
    attestations: Dict[str, Attestation] = {item.obligation: item for item in context.manifest.attestations}
    max_age = context.manifest.policies.attestation_max_age_days
    assessments: List[Assessment] = []
    for spec in OBLIGATIONS:
        assessment = Assessment(id=spec["id"], title=spec["title"], question=spec["question"], proof=spec["proof"])
        _EVALUATORS[spec["id"]](assessment, context)
        attestation = attestations.get(spec["id"])
        if attestation:
            age = (context.today - attestation.reviewed).days if attestation.reviewed else None
            fresh = age is not None and 0 <= age <= max_age
            assessment.attestation = {
                "statement": attestation.statement,
                "evidence": attestation.evidence,
                "owner": attestation.owner,
                "reviewed": attestation.reviewed.isoformat() if attestation.reviewed else None,
                "fresh": fresh,
            }
            eligible = assessment.status in _ATTESTABLE_WHEN or (assessment.status == "fail" and spec["id"] in _ATTESTABLE_FAIL)
            if eligible and fresh:
                assessment.status = "attested"
                owner = f" by {attestation.owner}" if attestation.owner else ""
                assessment.summary = f"Attested{owner} on {attestation.reviewed.isoformat()}: {attestation.statement}"
            elif eligible:
                reason = "has no review date" if age is None else f"was last reviewed {age} days ago (limit {max_age})"
                assessment.summary = f"Attestation {reason}, so it does not count. " + assessment.summary
            elif assessment.status == "fail":
                assessment.summary += " (An attestation is on record, but code evidence contradicts it; the code wins.)"
        assessments.append(assessment)
    return assessments
