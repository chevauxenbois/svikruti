"""Website scanner using Python stdlib networking and HTML parsing.

This scanner fetches a single page (plus, optionally, the linked privacy
notice). Any copy surfaced from this module must therefore say "page",
singular — pages_scanned is always 1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from svikruti.models import Evidence
from svikruti.scanner.patterns import PERSONAL_DATA_PATTERNS, THIRD_PARTY_PATTERNS, normalize_text


MAX_RESPONSE_BYTES = 2_500_000


@dataclass
class WebsiteScanResult:
    evidence: List[Evidence]
    # Always 1 today: this module scans a single page. Keep any user-facing
    # wording singular ("page scanned") until multi-page crawling exists.
    pages_scanned: int
    privacy_notice_text: str = ""
    detected_data_categories: Set[str] = field(default_factory=set)
    third_parties: Set[str] = field(default_factory=set)


class PageParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: List[Dict[str, str]] = []
        self.scripts: List[str] = []
        self.iframes: List[str] = []
        self.links: List[Dict[str, str]] = []
        self.text_chunks: List[str] = []
        self.script_blocks: List[str] = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs):
        attr = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script":
            self._in_script = True
            src = attr.get("src")
            if src:
                self.scripts.append(urljoin(self.base_url, src))
        elif tag == "iframe":
            src = attr.get("src")
            if src:
                self.iframes.append(urljoin(self.base_url, src))
        elif tag == "style":
            self._in_style = True
        elif tag in {"input", "textarea", "select"}:
            self.forms.append(
                {
                    "tag": tag,
                    "name": attr.get("name", ""),
                    "id": attr.get("id", ""),
                    "placeholder": attr.get("placeholder", ""),
                    "type": attr.get("type", ""),
                }
            )
        elif tag == "a":
            href = attr.get("href", "")
            label = attr.get("aria-label", "") or attr.get("title", "")
            self.links.append({"href": urljoin(self.base_url, href), "label": label})

    def handle_endtag(self, tag: str):
        if tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str):
        if self._in_script:
            # Inline <script> bodies are kept separately so third-party
            # detection can require domain-like references inside them.
            if data.strip():
                self.script_blocks.append(data)
        elif not self._in_style:
            stripped = " ".join(data.split())
            if stripped:
                self.text_chunks.append(stripped)


class _HttpOnlyRedirectHandler(HTTPRedirectHandler):
    """SSRF hardening: refuse redirects to non-http(s) schemes (file:// etc.)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urljoin(req.full_url, newurl)
        if urlparse(target).scheme not in {"http", "https"}:
            raise ValueError(f"Refusing to follow redirect to non-http(s) URL: {target}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = build_opener(_HttpOnlyRedirectHandler())


def _fetch(url: str) -> tuple[str, Dict[str, str], List[str]]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https URLs are supported for website scans.")
    request = Request(url, headers={"User-Agent": "SvikrutiPrivacyOps/0.4 (+https://svikruti.ai)"})
    with _OPENER.open(request, timeout=20) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("Website response is too large to scan safely.")
        charset = response.headers.get_content_charset() or "utf-8"
        headers = {key.lower(): value for key, value in response.headers.items()}
        # A dict comprehension collapses repeated Set-Cookie headers to the
        # last one; get_all (email.message API) preserves every cookie.
        set_cookies = list(response.headers.get_all("Set-Cookie") or [])
    return body.decode(charset, errors="ignore"), headers, set_cookies


def _domain(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _find_privacy_url(parser: PageParser, base_url: str) -> Optional[str]:
    candidates = []
    for link in parser.links:
        blob = f"{link.get('href', '')} {link.get('label', '')}".lower()
        if "privacy" in blob or "data-protection" in blob or "data protection" in blob:
            candidates.append(link["href"])
    return candidates[0] if candidates else None


def _cookie_names(set_cookie_headers: List[str]) -> List[str]:
    """Parse every Set-Cookie header (there is typically one per cookie)."""
    names: List[str] = []
    for raw in set_cookie_headers:
        parsed: List[str] = []
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
            parsed = list(cookie.keys())
        except Exception:
            parsed = []
        if not parsed and "=" in raw:
            parsed = [raw.split("=", 1)[0].strip()]
        for name in parsed:
            if name and name not in names:
                names.append(name)
    return names


def _third_party_present(needles: List[str], hosts: Set[str], urls_blob: str, inline_js: str) -> bool:
    """Vendor detection without bare-substring matching over page text.

    - Call-style needles ("gtag(", "fbq(") are looked for in inline <script>
      blocks only.
    - Domain-like needles ("checkout.razorpay.com", "payu.in") may appear in
      resource URLs (script src / link href / iframe src) or inline scripts.
    - Bare vendor words ("stripe", "mixpanel") must appear either in a
      resource URL host, or inside inline scripts as part of a domain-like
      pattern (e.g. "cdn.mixpanel.com/") — never as a bare word in HTML text.
    """
    for needle in needles:
        lowered = needle.lower()
        if "(" in lowered:
            if lowered in inline_js:
                return True
            continue
        if "." in lowered or "/" in lowered:
            if lowered in urls_blob or lowered in inline_js:
                return True
            continue
        if any(lowered in host for host in hosts):
            return True
        if re.search(rf"\b{re.escape(lowered)}\.[a-z]{{2,}}(?:[/'\"]|\b)", inline_js):
            return True
    return False


def _matched_terms(normalized_value: str, terms: List[str]) -> List[str]:
    tokens = normalized_value.split("_")
    matches: List[str] = []
    for term in terms:
        term_tokens = normalize_text(term).split("_")
        width = len(term_tokens)
        if width and any(tokens[index : index + width] == term_tokens for index in range(0, len(tokens) - width + 1)):
            matches.append(term)
    return matches


def _metadata(detector_id: str, confidence: str, evidence_ref: str, **extra: object) -> Dict[str, object]:
    metadata: Dict[str, object] = {
        "detector_id": detector_id,
        "confidence": confidence,
        "evidence_ref": evidence_ref,
    }
    metadata.update(extra)
    return metadata


def scan_website(url: str, fetch_notice: bool = True) -> WebsiteScanResult:
    """Scan a single page (pages_scanned is always 1)."""
    html, headers, set_cookies = _fetch(url)
    parser = PageParser(url)
    parser.feed(html)

    evidence: List[Evidence] = []
    detected_categories: Set[str] = set()
    third_parties: Set[str] = set()
    base_domain = _domain(url)
    full_text = " ".join(parser.text_chunks)

    for field in parser.forms:
        field_blob = normalize_text(" ".join(value for value in field.values() if value))
        for pattern in PERSONAL_DATA_PATTERNS:
            matched_terms = _matched_terms(field_blob, pattern.terms)
            if matched_terms:
                detected_categories.add(pattern.category)
                evidence.append(
                    Evidence(
                        kind="website_form_field",
                        label=f"Website form collects {pattern.category}",
                        severity=pattern.severity,
                        source="website",
                        detail=f"Live page field {field} appears to collect {pattern.category.lower()} data.",
                        recommendation="Confirm this collection is covered by notice text, purpose, retention, and consent/withdrawal workflow.",
                        category="Notice transparency",
                        metadata=_metadata(
                            f"website.form_field.{normalize_text(pattern.category)}",
                            "high",
                            f"{url}:form:{field.get('name') or field.get('id') or field.get('placeholder') or pattern.category}",
                            field=field,
                            data_category=pattern.category,
                            matched_terms=sorted(set(matched_terms)),
                            context_type="website_form_field",
                        ),
                    )
                )

    for script in parser.scripts:
        script_domain = _domain(script)
        if script_domain and script_domain != base_domain:
            third_parties.add(script_domain)
            evidence.append(
                Evidence(
                    kind="website_third_party_script",
                    label=f"Third-party script loaded: {script_domain}",
                    severity="MEDIUM",
                    source="website",
                    detail=f"The live page loads script {script}.",
                    recommendation="Confirm the third party is disclosed, contractually controlled, and only receives data for declared purposes.",
                    category="Third-party processors",
                    metadata=_metadata(
                        "website.third_party_script",
                        "high",
                        f"{url}:script:{script_domain}",
                        domain=script_domain,
                        script=script,
                    ),
                )
            )

    # Vendor tokens must appear in resource URLs (script src / link href /
    # iframe src) or, as a fallback, inside inline <script> blocks with a
    # domain-like pattern — never as bare substrings of visible page text.
    resource_urls = parser.scripts + parser.iframes + [link.get("href", "") for link in parser.links]
    resource_hosts = {urlparse(resource).netloc.lower() for resource in resource_urls if resource}
    resource_hosts.discard("")
    urls_blob = " ".join(resource_urls).lower()
    inline_js = "\n".join(parser.script_blocks).lower()
    for name, needles in THIRD_PARTY_PATTERNS.items():
        if _third_party_present(needles, resource_hosts, urls_blob, inline_js):
            third_parties.add(name)
            evidence.append(
                Evidence(
                    kind="website_third_party",
                    label=f"Known third-party detected: {name}",
                    severity="MEDIUM",
                    source="website",
                    detail=f"The live HTML references {name}.",
                    recommendation="Map this processor/tool to data categories, purposes, transfer location, and notice text.",
                    category="Third-party processors",
                    metadata=_metadata(
                        "website.third_party_known_tool",
                        "medium",
                        f"{url}:third_party:{normalize_text(name)}",
                        third_party=name,
                    ),
                )
            )

    cookies = _cookie_names(set_cookies)
    if cookies:
        evidence.append(
            Evidence(
                kind="website_cookie",
                label="Cookies set on first response",
                severity="MEDIUM",
                source="website",
                detail=f"The server sets cookies before an explicit consent interaction: {', '.join(cookies)}.",
                recommendation="Classify cookies as necessary or non-necessary; ensure non-necessary cookies are gated by consent.",
                category="Tracking and consent",
                metadata=_metadata("website.cookie.first_response", "medium", f"{url}:cookies:first_response", cookies=cookies),
            )
        )

    privacy_url = _find_privacy_url(parser, url)
    notice_text = ""
    if not privacy_url:
        evidence.append(
            Evidence(
                kind="privacy_notice_missing",
                label="No obvious privacy notice link found",
                severity="HIGH",
                source="website",
                detail="The scanner could not identify a privacy notice link from the page anchors.",
                recommendation="Add a clear privacy notice link and ensure it explains personal data categories, purposes, rights, grievance contact, and consent withdrawal.",
                category="Notice transparency",
                metadata=_metadata("website.privacy_notice.missing_link", "high", f"{url}:privacy_link"),
            )
        )
    elif fetch_notice:
        try:
            notice_html, _headers, _notice_cookies = _fetch(privacy_url)
            notice_parser = PageParser(privacy_url)
            notice_parser.feed(notice_html)
            notice_text = " ".join(notice_parser.text_chunks)
            evidence.append(
                Evidence(
                    kind="privacy_notice_found",
                    label="Privacy notice found",
                    severity="LOW",
                    source="website",
                    detail=f"Privacy notice detected at {privacy_url}.",
                    recommendation="Compare notice language against detected collection points and third-party services.",
                    category="Notice transparency",
                    metadata=_metadata(
                        "website.privacy_notice.found",
                        "high",
                        f"{url}:privacy_link",
                        privacy_url=privacy_url,
                    ),
                )
            )
        except Exception as exc:
            evidence.append(
                Evidence(
                    kind="privacy_notice_fetch_failed",
                    label="Privacy notice link could not be fetched",
                    severity="MEDIUM",
                    source="website",
                    detail=f"Privacy notice link was detected at {privacy_url}, but fetching failed: {exc}",
                    recommendation="Ensure the privacy notice is publicly reachable and crawlable.",
                    category="Notice transparency",
                    metadata=_metadata(
                        "website.privacy_notice.fetch_failed",
                        "medium",
                        f"{url}:privacy_link",
                        privacy_url=privacy_url,
                    ),
                )
            )

    if "withdraw" not in full_text.lower() and "consent" in full_text.lower():
        evidence.append(
            Evidence(
                kind="withdrawal_copy_missing",
                label="Consent copy appears without withdrawal copy",
                severity="MEDIUM",
                source="website",
                detail="The page mentions consent but does not obviously mention withdrawal.",
                recommendation="Make withdrawal of consent as discoverable as giving consent, where consent is the basis.",
                category="Consent and withdrawal",
                metadata=_metadata("website.consent.withdrawal_copy_missing", "medium", f"{url}:consent_copy"),
            )
        )

    return WebsiteScanResult(
        evidence=evidence,
        pages_scanned=1,
        privacy_notice_text=notice_text,
        detected_data_categories=detected_categories,
        third_parties=third_parties,
    )
