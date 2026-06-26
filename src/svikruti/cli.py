"""Command-line interface for Svikruti PrivacyOps."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from svikruti import __version__
from svikruti.reports.exports import (
    write_actions_csv,
    write_ai_markdown,
    write_breach_markdown,
    write_controls_csv,
    write_github_action,
    write_issues_markdown,
    write_notice_patch,
    write_ropa_csv,
    write_vendor_csv,
)
from svikruti.reports.html import write_html
from svikruti.reports.json_report import write_json
from svikruti.reports.sarif import write_sarif
from svikruti.scanner.runner import run_scan
from svikruti.store import default_db_path, save_scan_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="svikruti",
        description="Svikruti PrivacyOps: open-source DPDPA evidence scanner.",
    )
    parser.add_argument("--version", action="version", version=f"svikruti {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan a repository and/or website for DPDPA privacy evidence.")
    scan.add_argument("--repo", help="Path to local repository to scan.")
    scan.add_argument("--url", help="Public website URL to scan.")
    scan.add_argument("--privacy-url", help="Explicit privacy notice URL for code-to-notice comparison.")
    scan.add_argument("--privacy-file", help="Local privacy notice file for code-to-notice comparison.")
    scan.add_argument(
        "--browser-consent",
        action="store_true",
        help="Use Playwright to test consent behavior before/after reject/accept. Requires svikruti[browser].",
    )
    scan.add_argument("--out", default="svikruti-report.html", help="HTML report output path.")
    scan.add_argument("--json-out", help="Optional JSON report output path.")
    scan.add_argument("--sarif-out", help="Optional SARIF report output path for GitHub code scanning.")
    scan.add_argument("--ropa-out", help="Optional RoPA starter CSV output path.")
    scan.add_argument("--actions-out", help="Optional remediation action tracker CSV output path.")
    scan.add_argument("--vendors-out", help="Optional vendor/processor register CSV output path.")
    scan.add_argument("--controls-out", help="Optional technical-control register CSV output path.")
    scan.add_argument("--breach-out", help="Optional breach-readiness Markdown output path.")
    scan.add_argument("--notice-patch-out", help="Optional privacy notice patch draft Markdown output path.")
    scan.add_argument("--issues-out", help="Optional copy-ready GitHub/Jira issue pack Markdown output path.")
    scan.add_argument(
        "--security-evidence",
        action="append",
        default=[],
        help="Import SARIF, Trivy, Gitleaks, OSV, or compatible JSON security scanner output. Repeat for multiple files.",
    )
    scan.add_argument("--ai", action="store_true", help="Generate optional AI co-pilot commentary using a configured provider key.")
    scan.add_argument("--ai-provider", default="gemini", choices=["gemini", "openai"], help="AI provider for --ai.")
    scan.add_argument("--ai-model", help="AI model for --ai. Defaults to SVIKRUTI_AI_MODEL or the package default.")
    scan.add_argument("--ai-out", help="Optional AI co-pilot brief Markdown output path.")
    scan.add_argument(
        "--save-history",
        action="store_true",
        help="Save the scan into the local Svikruti evidence database for `svikruti dashboard`.",
    )
    scan.add_argument("--history-db", default=str(default_db_path()), help="SQLite scan history DB path.")
    scan.add_argument("--no-fetch-notice", action="store_true", help="Do not fetch privacy notice links discovered on the website.")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        help="Exit with code 3 when the scan reaches this risk level or higher.",
    )

    init = subparsers.add_parser("init-github-action", help="Create a Svikruti GitHub Actions workflow.")
    init.add_argument("--out", default=".github/workflows/svikruti.yml", help="Workflow file path to write.")

    dashboard = subparsers.add_parser("dashboard", help="Launch the interactive local Svikruti control room.")
    dashboard.add_argument("--db", default=str(default_db_path()), help="SQLite scan history DB path.")
    dashboard.add_argument("--report", help="Open a specific Svikruti JSON report in the dashboard.")
    dashboard.add_argument("--port", type=int, default=8501, help="Streamlit port.")
    dashboard.add_argument("--host", default="127.0.0.1", help="Streamlit host/address.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-github-action":
        try:
            write_github_action(args.out)
        except Exception as exc:
            print(f"svikruti init-github-action failed: {exc}", file=sys.stderr)
            return 1
        print(f"Svikruti GitHub Action written: {Path(args.out).resolve()}")
        return 0

    if args.command == "dashboard":
        return _launch_dashboard(args.db, args.report, args.port, args.host)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        result = run_scan(
            args.repo,
            args.url,
            fetch_notice=not args.no_fetch_notice,
            privacy_url=args.privacy_url,
            privacy_file=args.privacy_file,
            browser_consent=args.browser_consent,
            security_evidence=args.security_evidence,
            ai_enabled=args.ai,
            ai_provider=args.ai_provider,
            ai_model=args.ai_model,
        )
        output_path = Path(args.out)
        write_html(result, str(output_path))
        if args.json_out:
            write_json(result, args.json_out)
        if args.sarif_out:
            write_sarif(result, args.sarif_out)
        if args.ropa_out:
            write_ropa_csv(result, args.ropa_out)
        if args.actions_out:
            write_actions_csv(result, args.actions_out)
        if args.vendors_out:
            write_vendor_csv(result, args.vendors_out)
        if args.controls_out:
            write_controls_csv(result, args.controls_out)
        if args.breach_out:
            write_breach_markdown(result, args.breach_out)
        if args.notice_patch_out:
            write_notice_patch(result, args.notice_patch_out)
        if args.issues_out:
            write_issues_markdown(result, args.issues_out)
        if args.ai_out:
            write_ai_markdown(result, args.ai_out)
        if args.save_history:
            scan_id = save_scan_result(result, args.history_db)
            print(f"Svikruti scan saved: {scan_id} ({Path(args.history_db).resolve()})")
    except Exception as exc:
        print(f"svikruti scan failed: {exc}", file=sys.stderr)
        return 1

    print(f"Svikruti report written: {output_path.resolve()}")
    print(
        f"Risk: {result.summary.risk_level} ({result.summary.risk_score}/100), "
        f"evidence items: {len(result.evidence)}, files scanned: {result.summary.files_scanned}"
    )
    if args.fail_on and _reaches_threshold(result.summary.risk_level, args.fail_on):
        print(f"Risk gate failed: {result.summary.risk_level} >= {args.fail_on.upper()}", file=sys.stderr)
        return 3
    return 0


def _launch_dashboard(db_path: str, report_path: str | None, port: int, host: str) -> int:
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print(
            "svikruti dashboard requires the app extra. Install with: python -m pip install 'svikruti[app]'",
            file=sys.stderr,
        )
        return 1

    dashboard_path = Path(__file__).with_name("dashboard.py")
    env = os.environ.copy()
    env["SVIKRUTI_DASHBOARD_DB"] = str(Path(db_path))
    if report_path:
        env["SVIKRUTI_DASHBOARD_REPORT"] = str(Path(report_path).resolve())
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(dashboard_path),
        "--server.port",
        str(port),
        "--server.address",
        host,
        "--server.headless",
        "true",
    ]
    print(f"Opening Svikruti dashboard: http://{host}:{port}")
    return subprocess.call(command, env=env)


def _reaches_threshold(level: str, threshold: str) -> bool:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return order[level.upper()] >= order[threshold.upper()]
