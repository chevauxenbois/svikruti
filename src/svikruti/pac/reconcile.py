"""Reconcile the declared manifest against what the code actually does.

Two inputs: scanner evidence (the detected side) and ``privacy.yaml`` (the
declared side). Output: drift findings (D-rules: the record is wrong or
incomplete) and policy findings (P-rules: the code does something the
organisation has said it must not).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from svikruti.models import Evidence
from svikruti.pac.globs import match_any, match_path, specificity
from svikruti.pac.manifest import Activity, ExceptionRule, Manifest
from svikruti.pac.taxonomy import (
    HIGH_RISK_CATEGORIES,
    SEVERITY_ORDER,
    category_label,
    category_severity,
    category_slug,
    is_placeholder,
    slugify,
)

_CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
_NON_PRODUCTION_CONTEXTS = {"test", "reference"}
_WEBSITE_PROCESSOR_KINDS = {"website_third_party", "browser_known_vendor"}

RULES: Dict[str, Dict[str, str]] = {
    "D001": {"title": "Personal data processed outside any declared activity", "fix": "Add the path to an existing processing activity in privacy.yaml, or declare a new one."},
    "D002": {"title": "Undeclared personal data category", "fix": "Declare the category on the activity (and update the notice and legal basis), or remove the data from the code."},
    "D003": {"title": "Undeclared processor / third party", "fix": "Add the processor with country and contract reference, link it to the activity, or remove the integration."},
    "D004": {"title": "Declared category no longer found in code", "fix": "Remove the stale category from the activity so the record and the notice do not overstate processing."},
    "D005": {"title": "Declared processor no longer found in code", "fix": "Confirm the integration is gone, then remove the processor and close out the contract and data return."},
    "D006": {"title": "Processing record is incomplete", "fix": "Fill in the missing fields; code cannot tell you purpose, lawful basis or retention."},
    "D007": {"title": "Processor record is incomplete", "fix": "Record the processor's country, purpose and contract / DPA reference."},
    "D009": {"title": "Processor receives data that is not declared for it", "fix": "Add the category to the processor's data_categories (and check the contract covers it), or stop sending it."},
    "D008": {"title": "Declared activity matches no code", "fix": "Fix the path globs after the refactor, or delete the activity if the processing was removed."},
    "P001": {"title": "Personal data written to logs", "fix": "Remove or mask the field before logging, or record a time-boxed exception with a reason."},
    "P002": {"title": "Forbidden data category present", "fix": "Remove the data: organisational policy says this category must not be processed here."},
    "P003": {"title": "High-risk processing without an impact assessment", "fix": "Complete a DPIA and reference it in the activity's `dpia` field."},
    "P004": {"title": "Cross-border transfer without a recorded mechanism", "fix": "Record the transfer mechanism on the processor, or add the country to allowed_transfer_countries after review."},
    "P006": {"title": "Personal data sent to an AI model provider beyond the allowlist", "fix": "Remove or redact the field before it reaches the prompt, or add the category to policies.ai_allowed_categories after review."},
    "P007": {"title": "High-risk field stored without field-level protection", "fix": "Encrypt, tokenise (vault), hash or mask the field before it is stored, or record a time-boxed exception."},
    "D010": {"title": "Stored personal data no erasure path reaches", "fix": "Delete or anonymise this store from your erasure / retention code, list the function under erasure.handlers, or record the legal reason under erasure.retained."},
    "P005": {"title": "Exception has expired", "fix": "Fix the underlying finding or renew the exception with a new review date."},
}


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str
    activity: str = ""
    category: str = ""
    processor: str = ""
    refs: List[str] = field(default_factory=list)
    fields: List[str] = field(default_factory=list)
    status: str = "open"  # open | excepted
    exception_reason: str = ""
    fingerprint: str = ""

    @property
    def title(self) -> str:
        return RULES[self.rule]["title"]

    @property
    def fix(self) -> str:
        return RULES[self.rule]["fix"]

    @property
    def kind(self) -> str:
        return "policy" if self.rule.startswith("P") else "drift"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "activity": self.activity,
            "category": self.category,
            "processor": self.processor,
            "fields": self.fields,
            "refs": self.refs,
            "status": self.status,
            "exception_reason": self.exception_reason,
            "fingerprint": self.fingerprint,
        }


@dataclass
class FileFacts:
    categories: Dict[str, List[str]] = field(default_factory=dict)       # slug -> refs
    log_categories: Dict[str, List[str]] = field(default_factory=dict)   # slug -> refs
    processors: Dict[str, Tuple[str, List[str]]] = field(default_factory=dict)  # slug -> (name, refs)
    flows: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)  # processor slug -> category slug -> refs


@dataclass
class CodeModel:
    """What the scanner saw, reduced to the facts a manifest makes claims about."""

    files: Dict[str, FileFacts] = field(default_factory=dict)
    website_processors: Dict[str, Tuple[str, List[str]]] = field(default_factory=dict)
    ignored_files: Set[str] = field(default_factory=set)
    ai_processors: Set[str] = field(default_factory=set)  # slugs of AI model providers seen in flows

    def categories(self) -> Set[str]:
        return {slug for facts in self.files.values() for slug in facts.categories}

    def flows(self) -> Dict[str, Set[str]]:
        """processor slug -> category slugs seen as arguments of calls to it."""
        out: Dict[str, Set[str]] = {}
        for facts in self.files.values():
            for processor, categories in facts.flows.items():
                out.setdefault(processor, set()).update(categories)
        return out

    def processors(self) -> Dict[str, str]:
        found = {slug: name for facts in self.files.values() for slug, (name, _) in facts.processors.items()}
        found.update({slug: name for slug, (name, _) in self.website_processors.items()})
        return found


def _ref(item: Evidence) -> str:
    if item.file and item.line:
        return f"{item.file}:{item.line}"
    return item.file or str(item.metadata.get("evidence_ref") or item.source)


def build_code_model(evidence: Iterable[Evidence], min_confidence: str = "medium", ignore_paths: Optional[List[str]] = None) -> CodeModel:
    model = CodeModel()
    floor = _CONFIDENCE_RANK.get(min_confidence, 2)
    ignore_paths = ignore_paths or []
    for item in evidence:
        metadata = item.metadata
        if item.kind in _WEBSITE_PROCESSOR_KINDS and metadata.get("third_party"):
            name = str(metadata["third_party"])
            model.website_processors.setdefault(slugify(name), (name, []))[1].append(_ref(item))
            continue
        if not item.file or item.source not in {"code", "semantic-parser", "data-flow"}:
            continue
        rel = item.file.replace("\\", "/")
        if ignore_paths and match_any(rel, ignore_paths):
            model.ignored_files.add(rel)
            continue
        if metadata.get("file_context") in _NON_PRODUCTION_CONTEXTS:
            continue
        if _CONFIDENCE_RANK.get(str(metadata.get("confidence", "medium")), 2) < floor:
            continue
        if item.kind == "third_party" and metadata.get("third_party"):
            name = str(metadata["third_party"])
            facts = model.files.setdefault(rel, FileFacts())
            facts.processors.setdefault(slugify(name), (name, []))[1].append(_ref(item))
            continue
        category = category_slug(metadata.get("data_category"))
        if not category:
            continue
        facts = model.files.setdefault(rel, FileFacts())
        facts.categories.setdefault(category, []).append(_ref(item))
        if item.kind == "processor_data_flow" and metadata.get("third_party"):
            name = str(metadata["third_party"])
            if metadata.get("ai_provider"):
                model.ai_processors.add(slugify(name))
            facts.processors.setdefault(slugify(name), (name, []))
            facts.flows.setdefault(slugify(name), {}).setdefault(category, []).append(_ref(item))
        if "log" in item.kind:
            facts.log_categories.setdefault(category, []).append(_ref(item))
    return model


def assign_files(files: Iterable[str], activities: List[Activity]) -> Dict[str, Optional[str]]:
    """Map each file to the activity whose most specific glob claims it."""
    assignment: Dict[str, Optional[str]] = {}
    for rel in files:
        best: Tuple[int, Optional[str]] = (-1, None)
        for activity in activities:
            for pattern in activity.paths:
                if match_path(rel, pattern):
                    score = specificity(pattern)
                    if score > best[0]:
                        best = (score, activity.id)
        assignment[rel] = best[1]
    return assignment


def reconcile(
    model: CodeModel,
    manifest: Manifest,
    legal_bases: Optional[Dict[str, List[str]]] = None,
    today: Optional[date] = None,
    finalize: bool = True,
    root: Optional[str] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    policies = manifest.policies
    assignment = assign_files(model.files, manifest.activities)
    by_activity: Dict[str, List[str]] = {activity.id: [] for activity in manifest.activities}
    for rel, activity_id in assignment.items():
        if activity_id:
            by_activity[activity_id].append(rel)
    processors = manifest.processor_by_key()
    dpia_categories = set(HIGH_RISK_CATEGORIES if policies.require_dpia_for is None else policies.require_dpia_for)
    forbidden = set(policies.forbidden_categories)
    seen_processor_ids: Set[str] = set()

    # --- Unmapped files -------------------------------------------------
    for rel in sorted(rel for rel, activity_id in assignment.items() if activity_id is None):
        facts = model.files[rel]
        if facts.categories:
            slugs = sorted(facts.categories)
            findings.append(
                Finding(
                    rule="D001",
                    severity=_max_severity(category_severity(slug) for slug in slugs),
                    detail=f"`{rel}` handles {_labels(slugs)} data but no processing activity in the manifest covers this path.",
                    category=",".join(slugs),
                    refs=_first_refs(ref for slug in slugs for ref in facts.categories[slug]),
                )
            )
        for slug, (name, refs) in sorted(facts.processors.items()):
            processor = processors.get(slug)
            if processor:
                seen_processor_ids.add(processor.id)
            else:
                findings.append(Finding(rule="D003", severity="HIGH", detail=f"`{rel}` integrates {name}, which is not a declared processor.", processor=slug, refs=_first_refs(refs)))

    # --- Per-activity reconciliation ------------------------------------
    for activity in manifest.activities:
        files = sorted(by_activity[activity.id])
        detected: Dict[str, List[str]] = {}
        detected_processors: Dict[str, Tuple[str, List[str]]] = {}
        for rel in files:
            facts = model.files[rel]
            for slug, refs in facts.categories.items():
                detected.setdefault(slug, []).extend(refs)
            for slug, (name, refs) in facts.processors.items():
                detected_processors.setdefault(slug, (name, []))[1].extend(refs)
        declared = set(activity.data_categories)

        if not files:
            findings.append(
                Finding(
                    rule="D008",
                    severity="MEDIUM",
                    detail=f"Activity '{activity.id}' declares paths {activity.paths} but no scanned file with personal-data evidence matches them.",
                    activity=activity.id,
                )
            )
        else:
            for slug in sorted(set(detected) - declared):
                findings.append(
                    Finding(
                        rule="D002",
                        severity=category_severity(slug),
                        detail=f"Activity '{activity.id}' processes {category_label(slug)} data in code, but the record does not declare it.",
                        activity=activity.id,
                        category=slug,
                        refs=_first_refs(detected[slug]),
                    )
                )
            for slug in sorted(declared - set(detected)):
                findings.append(
                    Finding(
                        rule="D004",
                        severity="LOW",
                        detail=f"Activity '{activity.id}' declares {category_label(slug)} data, but nothing under its paths handles it any more.",
                        activity=activity.id,
                        category=slug,
                    )
                )

        for slug, (name, refs) in sorted(detected_processors.items()):
            processor = processors.get(slug)
            if processor is None:
                sent = sorted({cat for rel in files for cat in model.files[rel].flows.get(slug, {})})
                what = f"{_labels(sent)} data" if sent else "data"
                flow_refs = [ref for rel in files for cat_refs in model.files[rel].flows.get(slug, {}).values() for ref in cat_refs]
                findings.append(Finding(rule="D003", severity="HIGH", detail=f"Activity '{activity.id}' sends {what} to {name}, which is not a declared processor.", activity=activity.id, processor=slug, refs=_first_refs(flow_refs or refs)))
                continue
            seen_processor_ids.add(processor.id)
            if processor.id not in activity.processors:
                findings.append(
                    Finding(
                        rule="D003",
                        severity="MEDIUM",
                        detail=f"{processor.name} is a declared processor but is not linked to activity '{activity.id}', which uses it in code.",
                        activity=activity.id,
                        processor=processor.id,
                        refs=_first_refs(refs),
                    )
                )

        missing = [name for name, value in (("purposes", activity.purposes), ("retention", activity.retention), ("owner", activity.owner), ("data_subjects", activity.data_subjects)) if is_placeholder(value)]
        if is_placeholder(activity.legal_basis):
            missing.append("legal_basis")
        notes = []
        for framework_id, allowed in (legal_bases or {}).items():
            basis = activity.basis_for(framework_id)
            if allowed and not is_placeholder(basis) and basis not in allowed:
                if "legal_basis" not in missing:
                    missing.append("legal_basis")
                notes.append(f"'{basis}' is not a lawful basis under {framework_id} (expected one of: {', '.join(allowed)})")
            elif allowed and is_placeholder(basis) and "legal_basis" not in missing:
                missing.append("legal_basis")
                notes.append(f"no lawful basis recorded for {framework_id}")
        if missing:
            detail = f"Activity '{activity.id}' is missing: {', '.join(missing)}."
            if notes:
                detail += " " + "; ".join(notes) + "."
            findings.append(Finding(rule="D006", severity="MEDIUM", detail=detail, activity=activity.id, fields=missing))

        risky = sorted((declared | set(detected)) & dpia_categories)
        if risky and is_placeholder(activity.dpia):
            findings.append(
                Finding(
                    rule="P003",
                    severity="HIGH",
                    detail=f"Activity '{activity.id}' processes {_labels(risky)} data and has no `dpia` reference.",
                    activity=activity.id,
                    category=",".join(risky),
                    refs=_first_refs(ref for slug in risky for ref in detected.get(slug, [])),
                )
            )

    # --- Logging policy (applies to every file, mapped or not) -----------
    if policies.personal_data_in_logs != "allow":
        grouped: Dict[Tuple[str, str], List[str]] = {}
        for rel, facts in model.files.items():
            activity_id = assignment.get(rel) or ""
            activity = manifest.activity(activity_id) if activity_id else None
            for slug, refs in facts.log_categories.items():
                if activity and slug in activity.logging_allow:
                    continue
                grouped.setdefault((activity_id, slug), []).extend(refs)
        for (activity_id, slug), refs in sorted(grouped.items()):
            severity = "LOW" if policies.personal_data_in_logs == "warn" else category_severity(slug)
            scope = f"activity '{activity_id}'" if activity_id else "undeclared code"
            findings.append(
                Finding(
                    rule="P001",
                    severity=severity,
                    detail=f"{category_label(slug)} data is written to logs in {scope} ({len(set(refs))} location(s)).",
                    activity=activity_id,
                    category=slug,
                    refs=_first_refs(refs),
                )
            )

    # --- What each declared processor actually receives ------------------
    flow_groups: Dict[Tuple[str, str], Tuple[Set[str], List[str]]] = {}
    for rel, facts in model.files.items():
        for slug, categories in facts.flows.items():
            processor = processors.get(slug)
            if processor is None:
                continue  # undeclared processors are D003; the categories are named there
            for category, refs in categories.items():
                if category in processor.data_categories:
                    continue
                activities, all_refs = flow_groups.setdefault((processor.id, category), (set(), []))
                activities.add(assignment.get(rel) or "")
                all_refs.extend(refs)
    for (processor_id, category), (activities, refs) in sorted(flow_groups.items()):
        name = next(p.name for p in manifest.processors if p.id == processor_id)
        findings.append(
            Finding(
                rule="D009",
                severity=category_severity(category),
                detail=f"Code sends {category_label(category)} data to {name}, but the processor record does not list that category.",
                activity=next(iter(activities)) if len(activities) == 1 else "",
                category=category,
                processor=processor_id,
                refs=_first_refs(refs),
            )
        )

    # --- Forbidden categories -------------------------------------------
    for slug in sorted(forbidden & model.categories()):
        refs = [ref for facts in model.files.values() for ref in facts.categories.get(slug, [])]
        findings.append(Finding(rule="P002", severity="CRITICAL", detail=f"{category_label(slug)} data is present in code but listed under policies.forbidden_categories.", category=slug, refs=_first_refs(refs)))

    # --- Website-only processors ----------------------------------------
    for slug, (name, refs) in sorted(model.website_processors.items()):
        processor = processors.get(slug)
        if processor:
            seen_processor_ids.add(processor.id)
        else:
            findings.append(Finding(rule="D003", severity="HIGH", detail=f"The website loads {name}, which is not a declared processor.", processor=slug, refs=_first_refs(refs)))

    # --- Processor register ---------------------------------------------
    allowed_countries = set(policies.allowed_transfer_countries)
    for processor in manifest.processors:
        if processor.id not in seen_processor_ids:
            findings.append(Finding(rule="D005", severity="LOW", detail=f"Processor '{processor.name}' is declared but no code or website evidence references it.", processor=processor.id))
        missing = [name for name, value in (("country", processor.country), ("purpose", processor.purpose), ("contract", processor.contract)) if is_placeholder(value)]
        if missing:
            findings.append(
                Finding(
                    rule="D007",
                    severity="HIGH" if "contract" in missing else "MEDIUM",
                    detail=f"Processor '{processor.name}' is missing: {', '.join(missing)}.",
                    processor=processor.id,
                    fields=missing,
                )
            )
        if allowed_countries and not is_placeholder(processor.country) and processor.country not in allowed_countries and is_placeholder(processor.transfer_mechanism):
            findings.append(
                Finding(
                    rule="P004",
                    severity="HIGH",
                    detail=f"Processor '{processor.name}' is in {processor.country}, outside allowed_transfer_countries, with no transfer_mechanism recorded.",
                    processor=processor.id,
                )
            )

    # --- Personal data in prompts to AI model providers --------------------
    allowed_ai = policies.ai_allowed_categories
    if allowed_ai is not None:
        ai_groups: Dict[Tuple[str, str], Tuple[str, Set[str], List[str]]] = {}
        for rel, facts in model.files.items():
            for slug, categories in facts.flows.items():
                if slug not in model.ai_processors:
                    continue
                name = facts.processors[slug][0]
                for category, refs in categories.items():
                    if category in allowed_ai:
                        continue
                    _, activities, all_refs = ai_groups.setdefault((slug, category), (name, set(), []))
                    activities.add(assignment.get(rel) or "")
                    all_refs.extend(refs)
        for (slug, category), (name, activities, refs) in sorted(ai_groups.items()):
            processor = processors.get(slug)
            findings.append(
                Finding(
                    rule="P006",
                    severity=category_severity(category),
                    detail=f"{category_label(category)} data is sent to {name} (AI model provider) but is not in policies.ai_allowed_categories.",
                    activity=next(iter(activities)) if len(activities) == 1 else "",
                    category=category,
                    processor=processor.id if processor else slug,
                    refs=_first_refs(refs),
                )
            )

    if finalize:
        return finalize_findings(findings, manifest, today, root)
    return findings


def finalize_findings(findings: List[Finding], manifest: Manifest, today: Optional[date] = None, root: Optional[str] = None) -> List[Finding]:
    """Apply manifest exceptions and inline suppressions, fingerprint, and sort."""
    _apply_exceptions(findings, manifest.exceptions, today or date.today())
    if root:
        from svikruti.pac.suppress import apply_inline_suppressions

        for warning in apply_inline_suppressions(findings, root):
            if warning not in manifest.warnings:
                manifest.warnings.append(warning)
    for finding in findings:
        finding.fingerprint = _fingerprint(finding)
    findings.sort(key=lambda item: (item.status != "open", -SEVERITY_ORDER.get(item.severity, 0), item.rule, item.activity, item.category, item.processor))
    return findings


def _apply_exceptions(findings: List[Finding], exceptions: List[ExceptionRule], today: date) -> None:
    for exception in exceptions:
        if exception.expired(today):
            scope = ", ".join(f"{key}={value}" for key, value in (("activity", exception.activity), ("category", exception.category), ("processor", exception.processor), ("path", exception.path)) if value)
            findings.append(
                Finding(
                    rule="P005",
                    severity="MEDIUM",
                    detail=f"Exception for {exception.rule} ({scope}) expired on {exception.expires.isoformat()}; the finding it covered is enforced again.",
                    activity=exception.activity,
                    category=exception.category,
                    processor=exception.processor,
                )
            )
            continue
        for finding in findings:
            if finding.rule != exception.rule or finding.rule == "P005":
                continue
            if exception.activity and exception.activity != finding.activity:
                continue
            if exception.category and exception.category not in finding.category.split(","):
                continue
            if exception.processor and exception.processor != finding.processor:
                continue
            if exception.path and not any(match_path(ref.rsplit(":", 1)[0] if ref.rsplit(":", 1)[-1].isdigit() else ref, exception.path) for ref in finding.refs):
                continue
            finding.status = "excepted"
            approver = f" (approved by {exception.approved_by})" if exception.approved_by else ""
            until = f", until {exception.expires.isoformat()}" if exception.expires else ""
            finding.exception_reason = f"{exception.reason}{approver}{until}"


def _fingerprint(finding: Finding) -> str:
    """Identity of a drift finding: the rule and its subject, never line numbers."""
    files = sorted({ref.rsplit(":", 1)[0] if ref.rsplit(":", 1)[-1].isdigit() else ref for ref in finding.refs}) if finding.rule == "D001" else []
    raw = "\x1f".join([finding.rule, finding.activity, finding.category, finding.processor, ",".join(sorted(finding.fields)), ",".join(files)])
    return "svkd:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _labels(slugs: Iterable[str]) -> str:
    return ", ".join(category_label(slug) for slug in slugs)


def _max_severity(severities: Iterable[str]) -> str:
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0), default="HIGH")


def _first_refs(refs: Iterable[str], limit: int = 8) -> List[str]:
    out: List[str] = []
    for ref in refs:
        if ref not in out:
            out.append(ref)
    def sort_key(ref: str) -> Tuple[str, int]:
        head, _, tail = ref.rpartition(":")
        return (head, int(tail)) if tail.isdigit() and head else (ref, 0)
    return sorted(out, key=sort_key)[:limit]
