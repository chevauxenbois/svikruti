"""Top-level scanner orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen

from svikruti.ai import generate_ai_insights
from svikruti.models import ScanResult
from svikruti.scanner.browser import scan_consent_journey
from svikruti.scanner.code import scan_repo
from svikruti.scanner.dpdpa import build_evidence_graph, build_ropa_starter, notice_gap_check, summarize
from svikruti.scanner.website import scan_website


def run_scan(
    repo: Optional[str],
    url: Optional[str],
    fetch_notice: bool = True,
    privacy_url: Optional[str] = None,
    privacy_file: Optional[str] = None,
    browser_consent: bool = False,
    ai_enabled: bool = False,
    ai_provider: str = "openai",
    ai_model: Optional[str] = None,
) -> ScanResult:
    if not repo and not url and not privacy_file and not privacy_url:
        raise ValueError("Provide at least one of --repo, --url, --privacy-url, or --privacy-file.")

    result = ScanResult.empty(repo_path=repo, url=url)
    files_scanned = 0
    pages_scanned = 0
    privacy_notice_text = ""

    if repo:
        code_result = scan_repo(repo)
        files_scanned = code_result.files_scanned
        result.evidence.extend(code_result.evidence)

    if url:
        website_result = scan_website(url, fetch_notice=fetch_notice)
        pages_scanned = website_result.pages_scanned
        privacy_notice_text = website_result.privacy_notice_text
        result.evidence.extend(website_result.evidence)

        if browser_consent:
            consent_result = scan_consent_journey(url)
            result.evidence.extend(consent_result.evidence)

    if privacy_file:
        privacy_notice_text = Path(privacy_file).read_text(encoding="utf-8", errors="ignore")

    if privacy_url:
        privacy_notice_text = _fetch_privacy_url(privacy_url)

    result.summary = summarize(result.evidence, files_scanned, pages_scanned)
    result.ropa_starter = build_ropa_starter(result.evidence)
    result.notice_gaps = notice_gap_check(result, privacy_notice_text)
    result.evidence_graph = build_evidence_graph(result, privacy_notice_text)
    if ai_enabled:
        result.ai_insights = generate_ai_insights(result, provider=ai_provider, model=ai_model)
    return result


def _fetch_privacy_url(url: str) -> str:
    request = Request(url, headers={"User-Agent": "SvikrutiPrivacyOps/0.4 (+https://svikruti.ai)"})
    with urlopen(request, timeout=20) as response:
        body = response.read(2_500_001)
        if len(body) > 2_500_000:
            raise ValueError("Privacy notice response is too large to scan safely.")
        charset = response.headers.get_content_charset() or "utf-8"
    return body.decode(charset, errors="ignore")
