"""`svikruti check`: scan result + manifest + framework packs -> one verdict."""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

from svikruti.models import ScanResult
from svikruti.pac.frameworks import Pack, load_packs
from svikruti.pac.manifest import Manifest
from svikruti.pac.obligations import Assessment, Context, evaluate_obligations
from svikruti.pac.reconcile import CodeModel, Finding, assign_files, build_code_model, reconcile
from svikruti.pac.taxonomy import at_least, category_label

SCHEMA_VERSION = "svikruti-privacy-check-v1"


def _ai_slugs() -> set:
    from svikruti.pac.taxonomy import slugify
    from svikruti.scanner.patterns import AI_PROVIDERS

    return {slugify(name) for name in AI_PROVIDERS}


_AI_PROVIDER_SLUGS = _ai_slugs()


@dataclass
class CheckResult:
    manifest: Manifest
    packs: List[Pack]
    model: CodeModel
    findings: List[Finding]
    assessments: List[Assessment]
    scan: ScanResult
    generated_at: str
    baseline_fingerprints: Optional[set] = None
    activities_view: List[Dict[str, Any]] = field(default_factory=list)
    inventory: List[Dict[str, Any]] = field(default_factory=list)
    consent: Dict[str, Any] = field(default_factory=dict)

    # -- findings ---------------------------------------------------------
    def open_findings(self) -> List[Finding]:
        return [finding for finding in self.findings if finding.status == "open"]

    def is_new(self, finding: Finding) -> bool:
        return self.baseline_fingerprints is None or finding.fingerprint not in self.baseline_fingerprints

    def gating_findings(self, threshold: str) -> List[Finding]:
        """Open findings at/above threshold; only new ones when a baseline is set."""
        return [f for f in self.open_findings() if at_least(f.severity, threshold) and self.is_new(f)]

    # -- frameworks -------------------------------------------------------
    def framework_matrix(self, pack: Pack) -> List[Dict[str, Any]]:
        rows = []
        for assessment in self.assessments:
            for control in pack.refs(assessment.id):
                rows.append(
                    {
                        "framework": pack.id,
                        "ref": control["ref"],
                        "legacy_ref": control.get("legacy", ""),
                        "control": control.get("title", ""),
                        "obligation": assessment.id,
                        "obligation_title": assessment.title,
                        "status": assessment.status,
                        "proof": assessment.proof,
                        "summary": assessment.summary,
                    }
                )
        return rows

    def framework_summary(self, pack: Pack) -> Dict[str, Any]:
        counts = {"pass": 0, "fail": 0, "attested": 0, "manual": 0, "not_applicable": 0}
        mapped = [a for a in self.assessments if pack.refs(a.id)]
        for assessment in mapped:
            counts[assessment.status] += 1
        applicable = len(mapped) - counts["not_applicable"]
        return {
            "id": pack.id,
            "name": pack.name,
            "short_name": pack.short_name,
            "version": pack.version,
            "verified": pack.verified,
            "obligations": len(mapped),
            "applicable": applicable,
            "counts": counts,
            "code_verified_percent": round(100 * counts["pass"] / applicable) if applicable else 0,
            "covered_percent": round(100 * (counts["pass"] + counts["attested"]) / applicable) if applicable else 0,
        }

    def to_dict(self) -> Dict[str, Any]:
        open_findings = self.open_findings()
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "manifest": self.manifest.path,
            "repo": self.scan.repo_path,
            "organization": self.manifest.organization,
            "processors": [
                {
                    "id": processor.id,
                    "name": processor.name,
                    "purpose": processor.purpose,
                    "country": processor.country,
                    "contract": processor.contract,
                    "transfer_mechanism": processor.transfer_mechanism,
                    "data_categories": [category_label(slug) for slug in processor.data_categories],
                    "ai_provider": processor.id in self.model.ai_processors or processor.id in _AI_PROVIDER_SLUGS,
                }
                for processor in self.manifest.processors
            ],
            "summary": {
                "activities": len(self.manifest.activities),
                "processors": len(self.manifest.processors),
                "files_with_personal_data": len(self.model.files),
                "open_findings": len(open_findings),
                "open_by_severity": {level: len([f for f in open_findings if f.severity == level]) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "excepted_findings": len(self.findings) - len(open_findings),
                "new_findings": None if self.baseline_fingerprints is None else len([f for f in open_findings if self.is_new(f)]),
                "detected_categories": sorted(self.model.categories()),
                "detected_processors": sorted(self.model.processors().values()),
                "detected_flows": {slug: sorted(categories) for slug, categories in sorted(self.model.flows().items())},
            },
            "frameworks": [self.framework_summary(pack) for pack in self.packs],
            "findings": [dict(finding.to_dict(), new=self.is_new(finding)) for finding in self.findings],
            "obligations": [assessment.to_dict() for assessment in self.assessments],
            "matrix": [row for pack in self.packs for row in self.framework_matrix(pack)],
            "activities": self.activities_view,
            "inventory": [{key: value for key, value in row.items() if not key.startswith("_")} for row in self.inventory],
            "rights_request_entrypoints": (self.inventory[0].get("_rights_entries") if self.inventory else None) or [],
            "consent_check": self.consent,
            "manifest_warnings": self.manifest.warnings,
            "scan_summary": self.scan.summary.to_dict(),
            "disclaimers": [
                "Engineering evidence, not legal advice or a certification. A passing check supports a clause; it does not establish compliance with it.",
                "Static analysis sees the repository, not production. Attested and manual items need review by a privacy professional.",
            ],
        }


def run_check(
    scan: ScanResult,
    manifest: Manifest,
    frameworks: Optional[List[str]] = None,
    baseline: Optional[Dict[str, Any]] = None,
    today: Optional[date] = None,
) -> CheckResult:
    today = today or date.today()
    base_dir = str(Path(manifest.path).parent) if manifest.path else None
    packs = load_packs(frameworks or manifest.frameworks, base_dir)
    from svikruti.pac.inventory import build_inventory
    from svikruti.pac.reconcile import finalize_findings

    model = build_code_model(scan.evidence, manifest.policies.min_confidence, manifest.policies.ignore_paths)
    legal_bases = {pack.id: pack.legal_bases for pack in packs if pack.legal_bases}
    root = str(Path(scan.repo_path).resolve()) if scan.repo_path else None
    findings = reconcile(model, manifest, legal_bases=legal_bases, today=today, finalize=False)
    result = CheckResult(
        manifest=manifest,
        packs=packs,
        model=model,
        findings=findings,
        assessments=[],
        scan=scan,
        generated_at=scan.generated_at,
        activities_view=_activities_view(manifest, model, findings),
    )
    # The inventory needs the activity view; storage findings need the inventory.
    result.inventory = build_inventory(scan, result)
    findings.extend(_storage_findings(result.inventory, manifest))
    from svikruti.pac.consent import consent_findings
    from svikruti.pac.inventory import production_files

    consent = consent_findings(scan, model, manifest, root, production_files(Path(root)) if root else [])
    findings.extend(consent.findings)
    result.consent = {"activities": consent.activities, "flows_checked": consent.checked_flows, "flows_guarded": consent.guarded_flows}
    result.findings = finalize_findings(findings, manifest, today, root)
    result.activities_view = _activities_view(manifest, model, result.findings)
    context = Context(result=scan, manifest=manifest, model=model, findings=result.findings, today=today)
    result.assessments = evaluate_obligations(context)
    if baseline is not None:
        result.baseline_fingerprints = {item.get("fingerprint") for item in baseline.get("findings", []) if item.get("status", "open") == "open"}
    return result


def _rights_request_findings(inventory: List[Dict[str, Any]], stores: Dict[str, List[Dict[str, Any]]]) -> List[Finding]:
    """D011: stores that erasure code deletes, but no rights-request entry point reaches that code."""
    from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES, category_slug

    erased = {
        store: rows
        for store, rows in stores.items()
        if rows[0].get("erasure", "").startswith(("reached", "cascade")) and not rows[0].get("rights_request")
    }
    if not erased:
        return []
    entries = (inventory[0].get("_rights_entries") if inventory else None) or []
    categories = sorted({category_slug(row["data_category"]) for rows in erased.values() for row in rows})
    severity = "HIGH" if set(categories) & HIGH_RISK_CATEGORIES else "MEDIUM"
    if not entries:
        return [
            Finding(
                rule="D011",
                severity=severity,
                detail=(
                    f"Erasure code exists for {len(erased)} store(s) ({', '.join(sorted(erased))}), but no rights-request entry point was found: "
                    "no erasure or account-deletion route, mutation, DSAR handler or command. Nothing shows that a person's request reaches this code."
                ),
                category=",".join(categories),
                fields=["*"],
                refs=[f"{rows[0]['file']}:{rows[0]['line']}" for rows in list(erased.values())[:8]],
            )
        ]
    out = []
    for store, rows in sorted(erased.items()):
        how = rows[0]["erasure"].replace("reached by ", "")
        entry_text = "; ".join(entries[:3]) + (f" and {len(entries) - 3} more" if len(entries) > 3 else "")
        if re.search(r"expire|expiry|retention|retain|stale|old|ttl|cleanup|clean_up|prune|housekeep", how, re.IGNORECASE):
            detail = f"`{store}` is deleted only by a retention job, {how}. An erasure request ({entry_text}) leaves it in place until then."
        else:
            detail = f"`{store}` is deleted by {how}, but no rights-request entry point ({entry_text}) reaches that code."
        out.append(
            Finding(
                rule="D011",
                severity="HIGH" if {category_slug(row["data_category"]) for row in rows} & HIGH_RISK_CATEGORIES else "MEDIUM",
                detail=detail,
                activity=rows[0].get("activity", ""),
                category=",".join(sorted({category_slug(row["data_category"]) for row in rows})),
                fields=[store],
                refs=[f"{rows[0]['file']}:{rows[0]['line']}"],
            )
        )
    return out


def _storage_findings(inventory: List[Dict[str, Any]], manifest: Manifest) -> List[Finding]:
    """P007 (unprotected high-risk fields) and D010 (stores no erasure path reaches)."""
    from svikruti.pac.datastore import PROTECTED_KINDS
    from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES, category_severity, category_slug

    findings: List[Finding] = []
    stored = [row for row in inventory if row.get("persistent")]
    protect = set(manifest.policies.require_field_protection_for)
    for row in stored:
        slug = category_slug(row["data_category"])
        if slug in protect and row.get("protection") not in PROTECTED_KINDS:
            how = " (a binary column, but no encryption, tokenisation or hashing was found where it is written)" if row.get("protection") == "binary" else ""
            findings.append(
                Finding(
                    rule="P007",
                    severity=category_severity(slug),
                    detail=f"`{row['store']}.{row['field']}` stores {row['data_category']} data with no field-level protection{how}.",
                    activity=row.get("activity", ""),
                    category=slug,
                    fields=[f"{row['store']}.{row['field']}"],
                    refs=[f"{row['file']}:{row['line']}"],
                )
            )
    stores: Dict[str, List[Dict[str, Any]]] = {}
    for row in stored:
        stores.setdefault(row["store"], []).append(row)
    if not stores:
        return findings
    paths = (inventory[0].get("_erasure_paths") if inventory else None) or []
    uncovered = {store: rows for store, rows in stores.items() if not rows[0].get("erasure")}
    if not paths and uncovered:
        categories = sorted({category_slug(row["data_category"]) for rows in uncovered.values() for row in rows})
        findings.append(
            Finding(
                rule="D010",
                severity="HIGH" if set(categories) & HIGH_RISK_CATEGORIES else "MEDIUM",
                detail=f"No erasure or retention code was found, and {len(uncovered)} store(s) hold personal data ({', '.join(sorted(uncovered))}).",
                category=",".join(categories),
                fields=["*"],
                refs=[f"{rows[0]['file']}:{rows[0]['line']}" for rows in list(uncovered.values())[:8]],
            )
        )
        return findings
    findings.extend(_rights_request_findings(inventory, stores))
    for store, rows in sorted(uncovered.items()):
        categories = sorted({category_slug(row["data_category"]) for row in rows})
        findings.append(
            Finding(
                rule="D010",
                severity="HIGH" if set(categories) & HIGH_RISK_CATEGORIES else "MEDIUM",
                detail=f"`{store}` holds {', '.join(sorted({row['data_category'] for row in rows}))} data, but no erasure or retention path deletes or anonymises it.",
                activity=rows[0].get("activity", ""),
                category=",".join(categories),
                fields=[store],
                refs=[f"{rows[0]['file']}:{rows[0]['line']}"],
            )
        )
    return findings


def attach_check(scan: ScanResult, manifest_path: str, frameworks: Optional[List[str]] = None) -> Optional[CheckResult]:
    """Reconcile ``manifest_path`` against ``scan`` and store the result on the scan.

    Used by `svikruti scan` so the evidence report, the JSON and the dashboard
    carry the privacy-as-code verdict. A broken manifest never fails a scan:
    the problem is recorded and shown instead.
    """
    from svikruti.pac.frameworks import PackError
    from svikruti.pac.manifest import ManifestError, load_manifest

    try:
        result = run_check(scan, load_manifest(manifest_path), frameworks=frameworks)
    except ManifestError as exc:
        scan.privacy_as_code = {"schema_version": SCHEMA_VERSION, "manifest": str(manifest_path), "error": "Invalid manifest: " + "; ".join(exc.errors)}
        return None
    except PackError as exc:
        scan.privacy_as_code = {"schema_version": SCHEMA_VERSION, "manifest": str(manifest_path), "error": str(exc)}
        return None
    data = result.to_dict()
    data.pop("scan_summary", None)
    scan.privacy_as_code = data
    return result


def _activities_view(manifest: Manifest, model: CodeModel, findings: List[Finding]) -> List[Dict[str, Any]]:
    """The reconciled record: declared fields side by side with code evidence."""
    assignment = assign_files(model.files, manifest.activities)
    processors = {processor.id: processor for processor in manifest.processors}
    view = []
    for activity in manifest.activities:
        files = sorted(rel for rel, owner in assignment.items() if owner == activity.id)
        detected = sorted({slug for rel in files for slug in model.files[rel].categories})
        logged = sorted({slug for rel in files for slug in model.files[rel].log_categories})
        detected_processors = sorted({name for rel in files for name, _ in model.files[rel].processors.values()})
        flows: Dict[str, set] = {}
        for rel in files:
            for slug, categories in model.files[rel].flows.items():
                flows.setdefault(model.files[rel].processors[slug][0], set()).update(categories)
        open_rules = sorted({f.rule for f in findings if f.activity == activity.id and f.status == "open"})
        view.append(
            {
                "id": activity.id,
                "name": activity.name,
                "owner": activity.owner,
                "purposes": activity.purposes,
                "legal_basis": activity.legal_basis,
                "retention": activity.retention,
                "data_subjects": activity.data_subjects,
                "dpia": activity.dpia,
                "declared_categories": [category_label(slug) for slug in activity.data_categories],
                "detected_categories": [category_label(slug) for slug in detected],
                "logged_categories": [category_label(slug) for slug in logged],
                "declared_processors": [
                    {
                        "name": processors[pid].name,
                        "country": processors[pid].country,
                        "contract": processors[pid].contract,
                        "transfer_mechanism": processors[pid].transfer_mechanism,
                        "data_categories": [category_label(slug) for slug in processors[pid].data_categories],
                    }
                    for pid in activity.processors
                    if pid in processors
                ],
                "detected_processors": detected_processors,
                "detected_flows": [{"processor": name, "categories": [category_label(slug) for slug in sorted(cats)]} for name, cats in sorted(flows.items())],
                "paths": activity.paths,
                "files": files,
                "in_sync": not any(rule.startswith("D") and rule not in {"D004", "D005"} for rule in open_rules),
                "open_rules": open_rules,
            }
        )
    return view
