"""P008: processing that relies on consent must check it in code.

When an activity's lawful basis is consent, every hand-off of that data to a
processor (an SMS gateway, an analytics SDK, an AI model) should run only for
people who gave it, and stop when they withdraw. Static analysis can see
whether the code that makes the call, or the code that calls it, tests a
consent signal first:

    if borrower.reminder_consent:               # guard in the caller
        send_reminder(borrower.phone_number)

    @requires_consent("marketing")              # guard as a decorator
    def sync_contact(user): mailchimp...

    User.objects.filter(marketing_opt_in=True)  # guard in the query

Recognised signals: identifiers about consent, opt-in, subscription, tracking
permission and do-not-track, consent-management platforms (OneTrust, Didomi,
Cookiebot, the IAB TCF API, Usercentrics ...), and any guard named under
``consent.checks`` in privacy.yaml. A signal counts only in a guard position:
a condition, a filter, an assertion, an early return, or a decorator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from svikruti.models import ScanResult
from svikruti.pac.manifest import Activity, Manifest
from svikruti.pac.reconcile import CodeModel, Finding, assign_files
from svikruti.pac.taxonomy import category_slug, slugify

_SIGNAL = (
    r"consent\w*|\w*_consent\w*|\w*Consent\w*|opt_?in\w*|\w*_opt_?in\w*|\w*OptIn\w*|\w*opted_?in\w*|\w*OptedIn\w*"
    r"|\w*subscribed\w*|\w*Subscribed\w*|marketing_?(?:allowed|accepted|permission|ok|enabled|agreed)\w*"
    r"|tracking_?(?:allowed|enabled|ok|permitted)\w*|can_?track\w*|canTrack\w*|allow_?tracking\w*|allowTracking\w*"
    r"|do_?not_?track\w*|doNotTrack\w*|\bdnt\b|gdpr_?applies|gdprApplies|\w*permission_?for_?marketing\w*"
    r"|OneTrust|Optanon\w*|OnetrustActiveGroups|Didomi\w*|Cookiebot\w*|__tcfapi|__cmp|Usercentrics\w*|UC_UI|klaro\w*|iubenda\w*|Osano\w*|CookieYes|cookieyes|Termly\w*"
)
_GUARD_CONTEXT_RE = re.compile(
    r"^\s*(?:if|elif|elsif|unless|when|while|guard|assert|require|return|raise|throw|abort|@)|\b(?:if|unless|and|or|not)\b|&&|\|\||\?|!\s*\w|\.filter\s*\(|\.where\s*\(|\.exclude\s*\(|\bwhere\b|WHERE|\.find\w*\s*\(\s*\{|\bcontinue\b|\bbreak\b|=>\s*\w+\.\w*(?:consent|optin|opt_in)",
    re.IGNORECASE,
)
_COMMENT_RE = re.compile(r"(?:#|//).*$")
_MAX_CALLER_DEPTH = 2
_MAX_CALL_SITES = 40


@dataclass
class ConsentCheck:
    findings: List[Finding]
    activities: List[str]   # consent-based activity ids
    checked_flows: int      # flows in those activities
    guarded_flows: int      # flows with a consent guard found


def consent_based(activity: Activity) -> bool:
    basis = activity.legal_basis
    values = basis.values() if isinstance(basis, dict) else [basis]
    return any(slugify(str(value)) in {"consent", "explicit_consent"} for value in values)


class _Code:
    def __init__(self, root: Path, files: Iterable[str]):
        self.root = root
        self.files = sorted(set(files))
        self._lines: Dict[str, List[str]] = {}
        self._functions: Dict[str, list] = {}

    def lines(self, rel: str) -> List[str]:
        if rel not in self._lines:
            try:
                self._lines[rel] = (self.root / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                self._lines[rel] = []
        return self._lines[rel]

    def functions(self, rel: str) -> list:
        if rel not in self._functions:
            from svikruti.scanner.flows import _functions

            self._functions[rel] = _functions(self.lines(rel), Path(rel).suffix.lower())
        return self._functions[rel]

    def enclosing(self, rel: str, index: int):
        best = None
        for function in self.functions(rel):
            if function.start <= index <= function.end and (best is None or function.start >= best.start):
                best = function
        return best


def _signal_re(extra: Iterable[str]) -> "re.Pattern[str]":
    names = [re.escape(name.split(".")[-1]) for name in extra if name]
    custom = "|" + "|".join(rf"\b{name}\b" for name in names) if names else ""
    return re.compile(rf"(?:{_SIGNAL}{custom})")


def _guarded_region(lines: List[str], start: int, stop: int, signal: "re.Pattern[str]") -> Optional[str]:
    """The guard line between a function's decorators and ``stop``, if any."""
    first = start
    while first > 0 and lines[first - 1].strip().startswith("@"):
        first -= 1
    for index in range(first, min(stop + 1, len(lines))):
        code = _COMMENT_RE.sub("", lines[index]) if not lines[index].lstrip().startswith(("'", '"')) else lines[index]
        if signal.search(code) and _GUARD_CONTEXT_RE.search(code):
            return f"{index + 1}"
    return None


def _is_guarded(code: _Code, rel: str, index: int, signal: "re.Pattern[str]", depth: int = 0, seen: Optional[Set[Tuple[str, str]]] = None) -> Optional[str]:
    """Where the consent guard for the call at ``rel:index`` is, or None."""
    lines = code.lines(rel)
    function = code.enclosing(rel, index)
    start = function.start if function is not None else max(0, index - 30)
    found = _guarded_region(lines, start, index, signal)
    if found:
        return f"{rel}:{found}"
    if function is None or depth >= _MAX_CALLER_DEPTH or len(function.name) < 3:
        return None
    seen = seen if seen is not None else set()
    if (rel, function.name) in seen:
        return None
    seen.add((rel, function.name))
    call_re = re.compile(rf"(?<![\w$]){re.escape(function.name)}\s*\(")
    sites = 0
    for other in code.files:
        if function.name not in "\n".join(code.lines(other)):
            continue
        for number, line in enumerate(code.lines(other)):
            if not call_re.search(line) or re.search(rf"\b(?:def|function|func|fun)\s+{re.escape(function.name)}\b", line):
                continue
            if other == rel and function.start <= number <= function.end:
                continue
            sites += 1
            hit = _is_guarded(code, other, number, signal, depth + 1, seen)
            if hit:
                return hit
            if sites >= _MAX_CALL_SITES:
                return None
    return None


def consent_findings(scan: ScanResult, model: CodeModel, manifest: Manifest, root: Optional[str], files: Iterable[str]) -> ConsentCheck:
    activities = [activity for activity in manifest.activities if consent_based(activity)]
    if not activities or not root:
        return ConsentCheck([], [activity.id for activity in activities], 0, 0)
    ids = {activity.id for activity in activities}
    flows = [
        item
        for item in scan.evidence
        if item.kind == "processor_data_flow" and item.file and item.line and item.file.replace("\\", "/") in model.files
    ]
    assignment = assign_files({item.file.replace("\\", "/") for item in flows}, manifest.activities)
    code = _Code(Path(root), files)
    signal = _signal_re(manifest.consent.checks)
    open_sites: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    names: Dict[str, str] = {}
    checked = guarded = 0
    cache: Dict[Tuple[str, int], Optional[str]] = {}
    for item in flows:
        rel = item.file.replace("\\", "/")
        activity = assignment.get(rel)
        if activity not in ids:
            continue
        checked += 1
        key = (rel, item.line)
        if key not in cache:
            cache[key] = _is_guarded(code, rel, item.line - 1, signal)
        if cache[key]:
            guarded += 1
            continue
        processor = str(item.metadata.get("third_party", ""))
        names[slugify(processor)] = processor
        open_sites.setdefault((activity, slugify(processor)), []).append((f"{rel}:{item.line}", category_slug(item.metadata.get("data_category"))))
    findings = []
    for (activity, processor), sites in sorted(open_sites.items()):
        refs = sorted({ref for ref, _ in sites}, key=lambda ref: (ref.rsplit(":", 1)[0], int(ref.rsplit(":", 1)[1])))
        categories = sorted({category for _, category in sites if category})
        findings.append(
            Finding(
                rule="P008",
                severity="HIGH",
                detail=(
                    f"Activity '{activity}' relies on consent, but {len(refs)} call(s) sending {', '.join(c.replace('_', ' ') for c in categories) or 'personal'} data "
                    f"to {names[processor]} run with no consent check in the calling function or its callers."
                ),
                activity=activity,
                processor=processor,
                category=",".join(categories),
                refs=refs[:8],
            )
        )
    return ConsentCheck(findings, sorted(ids), checked, guarded)
