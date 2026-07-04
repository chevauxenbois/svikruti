"""Browser-based consent journey scanner.

This module is optional because Playwright downloads browser binaries. The CLI
exposes it through --browser-consent and returns an explicit setup message when
the dependency is missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urlparse

from svikruti.models import Evidence
from svikruti.scanner.patterns import THIRD_PARTY_PATTERNS


# Conservative consent-family terms only. "yes" was removed: it matched
# arbitrary yes/no dialogs (newsletters, age gates, chat prompts) that have
# nothing to do with consent.
ACCEPT_TERMS = ["accept", "agree", "allow all", "i agree"]
REJECT_TERMS = ["reject", "decline", "deny", "necessary only", "essential only"]
WITHDRAW_TERMS = ["withdraw", "cookie settings", "privacy settings", "manage consent", "preferences"]

# Default post-click observation window. 2.5s proved too short — many tag
# managers batch/fire trackers several seconds after consent interaction.
DEFAULT_IDLE_WAIT_MS = 6000


@dataclass
class ConsentJourneyResult:
    evidence: List[Evidence]
    phases: Dict[str, List[str]] = field(default_factory=dict)


def scan_consent_journey(url: str, timeout_ms: int = 12000, idle_wait_ms: int = DEFAULT_IDLE_WAIT_MS) -> ConsentJourneyResult:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Browser consent scan requires Playwright. Install with: "
            "python -m pip install 'svikruti[browser]' && python -m playwright install chromium"
        ) from exc

    evidence: List[Evidence] = []
    phases: Dict[str, List[str]] = {}
    base_domain = _domain(url)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            initial_domains = _observe_phase(page, url, timeout_ms)
            phases["before_consent"] = sorted(initial_domains)

            # Limitation: we only observe network traffic for a fixed idle
            # window in the same page state after clicking reject. CMPs that
            # apply the rejected state after a reload, persist it in storage,
            # or queue tracker calls beyond the window are not fully
            # captured — absence of traffic here is not proof of compliance.
            reject_clicked = _click_by_terms(page, REJECT_TERMS, timeout_ms)
            reject_domains = _observe_idle(page, timeout_ms, idle_wait_ms)
            phases["after_reject"] = sorted(reject_domains)

            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            accept_clicked = _click_by_terms(page, ACCEPT_TERMS, timeout_ms)
            accept_domains = _observe_idle(page, timeout_ms, idle_wait_ms)
            phases["after_accept"] = sorted(accept_domains)

            page_text = page.locator("body").inner_text(timeout=timeout_ms).lower()
            has_withdrawal = any(term in page_text for term in WITHDRAW_TERMS)
        except PlaywrightTimeoutError as exc:
            evidence.append(
                Evidence(
                    kind="browser_scan_timeout",
                    label="Browser consent scan timed out",
                    severity="MEDIUM",
                    source="browser",
                    detail=f"Timed out while testing consent journey: {exc}",
                    recommendation="Retry with a higher timeout or test a faster page.",
                    category="Tracking and consent",
                )
            )
            return ConsentJourneyResult(evidence=evidence, phases=phases)
        finally:
            browser.close()

    before_third_parties = _third_party_domains(initial_domains, base_domain)
    reject_third_parties = _third_party_domains(reject_domains, base_domain)
    accept_third_parties = _third_party_domains(accept_domains, base_domain)

    if before_third_parties:
        evidence.append(
            Evidence(
                kind="consent_preload_tracking",
                label="Third-party tracking before consent",
                severity="HIGH",
                source="browser",
                detail=f"Third-party domains were contacted before consent: {', '.join(sorted(before_third_parties))}.",
                recommendation="Gate non-essential trackers until consent is accepted.",
                category="Tracking and consent",
                metadata={"phase": "before_consent", "domains": sorted(before_third_parties)},
            )
        )

    if not reject_clicked:
        evidence.append(
            Evidence(
                kind="consent_reject_missing",
                label="No obvious reject control found",
                severity="HIGH",
                source="browser",
                detail="The browser scan could not find a reject/decline/necessary-only control.",
                recommendation="Provide a reject option that is as easy to access as accept.",
                category="Consent and withdrawal",
            )
        )
    elif reject_third_parties:
        evidence.append(
            Evidence(
                kind="consent_reject_tracking",
                label="Third-party tracking after reject",
                severity="CRITICAL",
                source="browser",
                detail=f"Third-party domains were contacted after reject: {', '.join(sorted(reject_third_parties))}.",
                recommendation="Ensure reject disables non-essential trackers and advertising/analytics SDKs.",
                category="Tracking and consent",
                metadata={"phase": "after_reject", "domains": sorted(reject_third_parties)},
            )
        )

    if not accept_clicked:
        evidence.append(
            Evidence(
                kind="consent_accept_missing",
                label="No obvious accept control found",
                severity="MEDIUM",
                source="browser",
                detail="The browser scan could not find an accept/agree control.",
                recommendation="Confirm consent controls are visible, labelled clearly, and keyboard-accessible.",
                category="Consent and withdrawal",
            )
        )

    if accept_third_parties:
        evidence.append(
            Evidence(
                kind="consent_accept_tracking",
                label="Third-party tracking after accept",
                severity="LOW",
                source="browser",
                detail=f"Third-party domains contacted after accept: {', '.join(sorted(accept_third_parties))}.",
                recommendation="Confirm these vendors are disclosed and mapped in the processor register.",
                category="Third-party processors",
                metadata={"phase": "after_accept", "domains": sorted(accept_third_parties)},
            )
        )

    if not has_withdrawal:
        evidence.append(
            Evidence(
                kind="consent_withdrawal_missing",
                label="No obvious consent withdrawal path found",
                severity="HIGH",
                source="browser",
                detail="The page text did not contain a clear withdrawal or cookie settings path.",
                recommendation="Add a persistent cookie/privacy settings entry point for withdrawal or preference changes.",
                category="Consent and withdrawal",
            )
        )

    for phase, domains in phases.items():
        known = _known_tools(domains)
        if known:
            evidence.append(
                Evidence(
                    kind="browser_known_vendor",
                    label=f"Known tracking/vendor tools in {phase}",
                    severity="MEDIUM" if phase != "after_reject" else "HIGH",
                    source="browser",
                    detail=f"Known tools observed in browser traffic: {', '.join(known)}.",
                    recommendation="Map each tool to purpose, notice disclosure, and vendor/processor controls.",
                    category="Third-party processors",
                    metadata={"phase": phase, "third_parties": known},
                )
            )

    return ConsentJourneyResult(evidence=evidence, phases=phases)


def _observe_phase(page, url: str, timeout_ms: int) -> Set[str]:
    domains: Set[str] = set()
    handler = lambda request: domains.add(_domain(request.url))
    page.on("request", handler)
    try:
        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
    finally:
        page.remove_listener("request", handler)
    return {domain for domain in domains if domain}


def _observe_idle(page, timeout_ms: int, idle_wait_ms: int = DEFAULT_IDLE_WAIT_MS) -> Set[str]:
    domains: Set[str] = set()
    handler = lambda request: domains.add(_domain(request.url))
    page.on("request", handler)
    try:
        page.wait_for_timeout(min(timeout_ms, idle_wait_ms))
    finally:
        page.remove_listener("request", handler)
    return {domain for domain in domains if domain}


def _click_by_terms(page, terms: List[str], timeout_ms: int) -> bool:
    pattern = re.compile("|".join(re.escape(term) for term in terms), re.IGNORECASE)
    for role in ["button", "link"]:
        try:
            locator = page.get_by_role(role, name=pattern).first
            if locator.count() > 0:
                locator.click(timeout=min(timeout_ms, 5000))
                return True
        except Exception:
            continue
    # Fallback: only click obvious clickable controls whose own text matches
    # a consent-family term. The old fallback clicked ANY page text matching
    # a term (e.g. the word "accept" in a paragraph), which could interact
    # with unrelated UI.
    try:
        locator = page.locator(
            "button, [role='button'], input[type='submit'], input[type='button'], a",
            has_text=pattern,
        ).first
        if locator.count() > 0:
            locator.click(timeout=min(timeout_ms, 5000))
            return True
    except Exception:
        pass
    return False


def _domain(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _third_party_domains(domains: Set[str], base_domain: str) -> Set[str]:
    return {
        domain
        for domain in domains
        if domain
        and domain != base_domain
        and not domain.endswith("." + base_domain)
        and not domain.startswith("127.0.0.1")
        and domain not in {"localhost"}
    }


def _known_tools(domains: List[str]) -> List[str]:
    text = " ".join(domains).lower()
    found = []
    for name, needles in THIRD_PARTY_PATTERNS.items():
        if any(needle.lower() in text for needle in needles):
            found.append(name)
    return sorted(set(found))
