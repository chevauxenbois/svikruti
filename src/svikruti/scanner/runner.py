"""Top-level scanner orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from svikruti.ai import generate_ai_insights
from svikruti.models import Evidence, ScanResult
from svikruti.scanner.assurance import build_assurance_profile
from svikruti.scanner.browser import scan_consent_journey
from svikruti.scanner.code import MAX_FILE_BYTES, scan_repo
from svikruti.scanner.dpdpa import build_evidence_graph, build_ropa_starter, notice_gap_check, summarize
from svikruti.scanner.semantic import scan_semantic_evidence
from svikruti.scanner.technical import (
    build_breach_readiness,
    build_technical_controls,
    ingest_security_findings,
    scan_technical_evidence,
)
from svikruti.scanner.website import scan_website


def run_scan(
    repo: Optional[str],
    url: Optional[str],
    fetch_notice: bool = True,
    privacy_url: Optional[str] = None,
    privacy_file: Optional[str] = None,
    browser_consent: bool = False,
    security_evidence: Optional[list[str]] = None,
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
        semantic_result = scan_semantic_evidence(repo)
        result.evidence.extend(semantic_result.evidence)
        result.scan_quality = semantic_result.quality_profile(files_scanned)
        # Surface size-based skips so coverage claims stay honest.
        result.scan_quality["skipped_large_files"] = code_result.skipped_large_files
        if code_result.skipped_large_files:
            result.scan_quality.setdefault("limitations", []).append(
                f"{code_result.skipped_large_files} file(s) larger than {MAX_FILE_BYTES} bytes were skipped and not scanned."
            )
        result.scan_quality["skipped_vendored_files"] = code_result.skipped_vendored_files
        if code_result.skipped_vendored_files:
            result.scan_quality.setdefault("limitations", []).append(
                f"{code_result.skipped_vendored_files} vendored/minified third-party file(s) (node_modules, vendor/, *.min.js, ...) were skipped; first-party code only."
            )
        result.evidence.extend(scan_technical_evidence(repo))
    else:
        result.scan_quality = {
            "schema_version": "svikruti-scan-quality-v1",
            "parser_coverage_percent": 0,
            "parsed_files": 0,
            "total_files": 0,
            "parser_engines": {},
            "parser_errors": [],
            "limitations": ["No repository was supplied, so parser coverage is unavailable."],
        }

    result.evidence.extend(ingest_security_findings(security_evidence))

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
        try:
            privacy_notice_text = _fetch_privacy_url(privacy_url)
        except ValueError as exc:
            # Rejected (e.g. non-http(s) scheme): record honest error
            # evidence instead of silently proceeding or crashing.
            result.evidence.append(
                Evidence(
                    kind="privacy_notice_fetch_failed",
                    label="Privacy notice URL rejected",
                    severity="MEDIUM",
                    source="website",
                    detail=str(exc),
                    recommendation="Provide a publicly reachable http(s) URL for the privacy notice.",
                    category="Notice transparency",
                    metadata={
                        "detector_id": "runner.privacy_url.rejected",
                        "confidence": "high",
                        "evidence_ref": f"{privacy_url}:privacy_url",
                    },
                )
            )

    result.summary = summarize(result.evidence, files_scanned, pages_scanned)
    result.ropa_starter = build_ropa_starter(result.evidence)
    result.notice_gaps = notice_gap_check(result, privacy_notice_text)
    result.evidence_graph = build_evidence_graph(result, privacy_notice_text)
    result.technical_controls = build_technical_controls(result.evidence)
    result.breach_readiness = build_breach_readiness(result.evidence, result.technical_controls)
    result.assurance_profile = build_assurance_profile(
        result,
        privacy_notice_available=bool(privacy_notice_text),
        security_evidence_paths=security_evidence,
        browser_consent=browser_consent,
    )
    if ai_enabled:
        result.ai_insights = generate_ai_insights(result, provider=ai_provider, model=ai_model)
    return result


def _fetch_privacy_url(url: str) -> str:
    # SSRF hardening: never fetch non-http(s) URLs (file://, ftp://, ...).
    scheme = urlparse(url).scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(
            f"Privacy notice URL must use http or https; refusing to fetch scheme '{scheme or 'none'}' ({url})."
        )
    request = Request(url, headers={"User-Agent": "SvikrutiPrivacyOps/0.4 (+https://svikruti.ai)"})
    with urlopen(request, timeout=20) as response:
        body = response.read(2_500_001)
        if len(body) > 2_500_000:
            raise ValueError("Privacy notice response is too large to scan safely.")
        charset = response.headers.get_content_charset() or "utf-8"
    return body.decode(charset, errors="ignore")
