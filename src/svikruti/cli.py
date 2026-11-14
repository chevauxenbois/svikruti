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
    write_privacy_check_action,
    write_ropa_csv,
    write_vendor_csv,
)
from svikruti.reports.html import write_html
from svikruti.reports.json_report import write_json
from svikruti.reports.sarif import write_sarif
from svikruti.scanner.runner import run_scan
from svikruti.store import default_db_path, save_scan_result

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_GATE = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="svikruti",
        description=(
            "Svikruti: open-source privacy-as-code. Scan code for privacy evidence, reconcile it against "
            "privacy.yaml, and map the result to DPDPA, GDPR and ISO/IEC 27701."
        ),
    )
    parser.add_argument("--version", action="version", version=f"svikruti {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    scan = subparsers.add_parser("scan", help="Scan a repository and/or website for privacy evidence.")
    scan.add_argument("--repo", help="Path to local repository to scan.")
    scan.add_argument("--url", help="Public website URL to scan.")
    scan.add_argument("--privacy-url", help="Explicit privacy notice URL for code-to-notice comparison.")
    scan.add_argument("--privacy-file", help="Local privacy notice file for code-to-notice comparison.")
    scan.add_argument(
        "--browser-consent",
        action="store_true",
        help="Use Playwright to test consent behavior before/after reject/accept. Requires svikruti[browser].",
    )
    scan.add_argument(
        "--out",
        help="HTML report output path (default: svikruti-report.html, or report.html inside --evidence-pack).",
    )
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
        "--evidence-pack",
        metavar="DIR",
        help=(
            "Write the full artifact set into DIR with default names (report.html, report.json, "
            "report.sarif, ropa.csv, actions.csv, vendors.csv, controls.csv, breach-readiness.md, "
            "notice-patch.md, fix-pack.md). Explicit individual output flags override the matching pack file. "
            "DIR is created if missing."
        ),
    )
    scan.add_argument(
        "--security-evidence",
        action="append",
        default=[],
        help="Import SARIF, Trivy, Gitleaks, OSV, or compatible JSON security scanner output. Repeat for multiple files.",
    )
    scan.add_argument("--ai", action="store_true", help="Generate optional AI co-pilot commentary using a configured provider key.")
    scan.add_argument("--ai-provider", default="gemini", choices=["gemini", "openai"], help="AI provider for --ai (default: gemini).")
    scan.add_argument(
        "--ai-model",
        help="AI model for --ai. Defaults to SVIKRUTI_AI_MODEL or the package default (gemini-2.5-flash for gemini, gpt-4.1-mini for openai).",
    )
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
        help=(
            "Exit with code 3 when the scan reaches this risk level or higher. "
            "Risk-score bands: LOW 0-24, MEDIUM 25-49, HIGH 50-74, CRITICAL 75-100 "
            "(severity-tiered model; ~3 critical + 5 high findings land in HIGH; "
            "the CRITICAL band requires sustained critical evidence)."
        ),
    )
    scan.add_argument("--baseline", help="Previous Svikruti JSON report. Findings already in it are treated as existing backlog.")
    scan.add_argument(
        "--fail-on-new",
        choices=["low", "medium", "high", "critical"],
        help="With --baseline: exit with code 3 only when this scan introduces a finding at this severity or higher.",
    )
    scan.add_argument("--diff-out", help="With --baseline: write the new/resolved findings diff as Markdown.")

    init_manifest = subparsers.add_parser("init", help="Generate privacy.yaml from what the code does today.")
    init_manifest.add_argument("--repo", default=".", help="Repository to scan (default: current directory).")
    init_manifest.add_argument("--out", help="Manifest path to write (default: <repo>/privacy.yaml).")
    init_manifest.add_argument("--frameworks", default="", help="Comma-separated framework ids (default: dpdpa,gdpr,iso27701).")
    init_manifest.add_argument("--organization", default="TODO", help="Organisation name to record.")
    init_manifest.add_argument("--force", action="store_true", help="Overwrite an existing manifest.")

    check = subparsers.add_parser("check", help="Reconcile privacy.yaml against the code and gate on drift.")
    check.add_argument("--repo", default=".", help="Repository to scan (default: current directory).")
    check.add_argument("--manifest", help="Manifest path (default: privacy.yaml in the repo).")
    check.add_argument("--framework", action="append", default=[], help="Framework id or custom pack path. Repeatable. Overrides the manifest's list.")
    check.add_argument("--url", help="Public website URL to include in the scan.")
    check.add_argument("--privacy-url", help="Privacy notice URL for code-to-notice comparison.")
    check.add_argument("--privacy-file", help="Local privacy notice file for code-to-notice comparison.")
    check.add_argument("--browser-consent", action="store_true", help="Test the consent journey with Playwright (needs --url).")
    check.add_argument("--security-evidence", action="append", default=[], help="SARIF/Trivy/Gitleaks/OSV output to import. Repeatable.")
    check.add_argument("--baseline", help="Previous privacy-check.json. Only findings not in it can fail the gate.")
    check.add_argument(
        "--fail-on",
        default="high",
        choices=["low", "medium", "high", "critical", "none"],
        help="Exit with code 3 when an open finding reaches this severity (default: high). 'none' reports only.",
    )
    check.add_argument("--out-dir", default="svikruti-check", help="Directory for the report pack (default: svikruti-check).")
    check.add_argument("--scan-json-out", help="Also write the underlying scan report JSON (usable as a scan --baseline).")

    diff = subparsers.add_parser("diff", help="Compare two Svikruti JSON scan reports.")
    diff.add_argument("base", help="Baseline report JSON (for example from the main branch).")
    diff.add_argument("head", help="New report JSON (for example from the pull request).")
    diff.add_argument("--md-out", help="Write the diff as Markdown.")
    diff.add_argument("--json-out", help="Write the diff as JSON.")
    diff.add_argument("--fail-on-new", choices=["low", "medium", "high", "critical"], help="Exit with code 3 when a new finding reaches this severity.")

    subparsers.add_parser("frameworks", help="List built-in framework packs.")

    init = subparsers.add_parser("init-github-action", help="Create a Svikruti GitHub Actions workflow.")
    init.add_argument("--out", help="Workflow file path to write (default depends on --mode).")
    init.add_argument(
        "--mode",
        choices=["scan", "check"],
        default="scan",
        help="scan: evidence-report workflow. check: privacy-as-code gate that reconciles privacy.yaml on every pull request.",
    )

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
        if args.out is None:
            args.out = ".github/workflows/svikruti-privacy-check.yml" if args.mode == "check" else ".github/workflows/svikruti.yml"
        try:
            (write_privacy_check_action if args.mode == "check" else write_github_action)(args.out)
        except Exception as exc:
            print(f"svikruti init-github-action failed: {exc}", file=sys.stderr)
            return 1
        print(f"Svikruti GitHub Action written: {Path(args.out).resolve()}")
        return 0

    if args.command == "dashboard":
        return _launch_dashboard(args.db, args.report, args.port, args.host)

    if args.command == "init":
        return _cmd_init(args)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "diff":
        return _cmd_diff(args)
    if args.command == "frameworks":
        return _cmd_frameworks()

    if args.command != "scan":
        parser.print_help()
        return 2

    if args.fail_on_new and not args.baseline:
        print("svikruti scan: --fail-on-new requires --baseline", file=sys.stderr)
        return EXIT_USAGE
    pack_files = _apply_evidence_pack(args)
    if args.out is None:
        args.out = "svikruti-report.html"

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
    if args.evidence_pack:
        pack_summary = ", ".join(pack_files) if pack_files else "none (all outputs overridden by explicit flags)"
        print(f"Svikruti evidence pack written: {Path(args.evidence_pack).resolve()} [{pack_summary}]")
    print(
        f"Risk: {result.summary.risk_level} ({result.summary.risk_score}/100), "
        f"evidence items: {len(result.evidence)}, files scanned: {result.summary.files_scanned}"
    )
    exit_code = EXIT_OK
    if args.baseline:
        from svikruti.pac.fingerprint import diff_markdown, diff_reports, load_report, new_at_or_above

        try:
            diff = diff_reports(load_report(args.baseline), result.to_dict())
        except Exception as exc:
            print(f"svikruti scan: could not read baseline: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if args.diff_out:
            Path(args.diff_out).write_text(diff_markdown(diff), encoding="utf-8")
        print(f"Against baseline: {len(diff['new'])} new, {len(diff['resolved'])} resolved, {diff['unchanged_count']} unchanged")
        if args.fail_on_new:
            blocking = new_at_or_above(diff, args.fail_on_new)
            if blocking:
                print(f"New-finding gate failed: {len(blocking)} new finding(s) at {args.fail_on_new.upper()} or above", file=sys.stderr)
                for item in blocking[:10]:
                    where = f"{item.get('file')}:{item.get('line')}" if item.get("line") else str(item.get("file") or item.get("source"))
                    print(f"  {item.get('severity'):8} {where}  {item.get('label')}", file=sys.stderr)
                exit_code = EXIT_GATE
    if args.fail_on and _reaches_threshold(result.summary.risk_level, args.fail_on):
        print(f"Risk gate failed: {result.summary.risk_level} >= {args.fail_on.upper()}", file=sys.stderr)
        exit_code = EXIT_GATE
    return exit_code


def _cmd_init(args: argparse.Namespace) -> int:
    from svikruti.pac.generate import generate_manifest
    from svikruti.pac.frameworks import PackError, load_packs

    out = Path(args.out) if args.out else Path(args.repo) / "privacy.yaml"
    if out.exists() and not args.force:
        print(f"svikruti init: {out} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_USAGE
    frameworks = [item.strip() for item in args.frameworks.split(",") if item.strip()]
    try:
        load_packs(frameworks)
        result = run_scan(args.repo, None)
    except PackError as exc:
        print(f"svikruti init: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        print(f"svikruti init failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    text = generate_manifest(result, frameworks or None, args.organization)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    todo = text.count("TODO")
    print(f"Svikruti manifest written: {out.resolve()}")
    print(
        f"Found {len(result.summary.personal_data_categories)} data categor(ies) and {len(result.summary.third_parties)} third part(ies) "
        f"across {result.summary.files_scanned} files. {todo} TODO field(s) need a human."
    )
    print("Next: fill in the TODOs, commit the file, then run `svikruti check`.")
    return EXIT_OK


def _cmd_check(args: argparse.Namespace) -> int:
    from svikruti.pac.engine import run_check
    from svikruti.pac.frameworks import PackError
    from svikruti.pac.manifest import ManifestError, find_manifest, load_manifest
    from svikruti.pac.report import write_check_pack

    manifest_path = Path(args.manifest) if args.manifest else find_manifest(args.repo)
    if manifest_path is None:
        print(f"svikruti check: no privacy.yaml found in {args.repo}. Run `svikruti init` first, or pass --manifest.", file=sys.stderr)
        return EXIT_USAGE
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        print(f"svikruti check: invalid manifest {manifest_path}:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return EXIT_USAGE
    baseline = None
    if args.baseline:
        try:
            import json

            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            if not isinstance(baseline, dict) or "findings" not in baseline:
                raise ValueError("not a privacy-check.json file (no 'findings' key)")
        except Exception as exc:
            print(f"svikruti check: could not read baseline: {exc}", file=sys.stderr)
            return EXIT_ERROR
    try:
        scan = run_scan(
            args.repo,
            args.url,
            privacy_url=args.privacy_url,
            privacy_file=args.privacy_file,
            browser_consent=args.browser_consent,
            security_evidence=args.security_evidence,
        )
        result = run_check(scan, manifest, frameworks=args.framework or None, baseline=baseline)
        files = write_check_pack(result, args.out_dir, args.fail_on)
        if args.scan_json_out:
            write_json(scan, args.scan_json_out)
    except PackError as exc:
        print(f"svikruti check: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:
        print(f"svikruti check failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    for warning in manifest.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    open_findings = result.open_findings()
    print(f"Svikruti privacy check: {manifest_path} vs {len(result.model.files)} file(s) with personal-data evidence")
    for finding in open_findings[:20]:
        marker = " (new)" if baseline is not None and result.is_new(finding) else ""
        where = finding.refs[0] if finding.refs else "privacy.yaml"
        print(f"  {finding.severity:8} {finding.rule}{marker}  {finding.detail}  [{where}]")
    if len(open_findings) > 20:
        print(f"  ...and {len(open_findings) - 20} more (see {files['markdown']})")
    for pack in result.packs:
        summary = result.framework_summary(pack)
        counts = summary["counts"]
        print(
            f"  {summary['short_name']:10} {counts['pass']}/{summary['applicable']} verified, "
            f"{counts['attested']} attested, {counts['fail']} failing, {counts['manual']} not verified"
        )
    print(f"Report pack written: {Path(args.out_dir).resolve()}")
    if args.fail_on != "none":
        gating = result.gating_findings(args.fail_on)
        if gating:
            scope = "new " if baseline is not None else ""
            print(f"Privacy gate failed: {len(gating)} {scope}finding(s) at {args.fail_on.upper()} or above", file=sys.stderr)
            return EXIT_GATE
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace) -> int:
    import json

    from svikruti.pac.fingerprint import diff_markdown, diff_reports, load_report, new_at_or_above

    try:
        diff = diff_reports(load_report(args.base), load_report(args.head))
    except Exception as exc:
        print(f"svikruti diff failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    markdown = diff_markdown(diff)
    if args.md_out:
        Path(args.md_out).write_text(markdown, encoding="utf-8")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(diff, indent=2), encoding="utf-8")
    print(markdown, end="")
    if args.fail_on_new and new_at_or_above(diff, args.fail_on_new):
        print(f"New-finding gate failed at {args.fail_on_new.upper()} or above", file=sys.stderr)
        return EXIT_GATE
    return EXIT_OK


def _cmd_frameworks() -> int:
    from svikruti.pac.frameworks import builtin_pack_ids, load_pack

    for pack_id in builtin_pack_ids():
        pack = load_pack(pack_id)
        clauses = sum(len(refs) for refs in pack.controls.values())
        print(f"{pack.id:10} {pack.name}  [{pack.version}; {len(pack.controls)} obligations -> {clauses} clause references; verified {pack.verified}]")
    print("Custom packs: pass a YAML/JSON path to --framework or list it under `frameworks:` in privacy.yaml.")
    return EXIT_OK


_EVIDENCE_PACK_DEFAULTS = (
    ("out", "report.html"),
    ("json_out", "report.json"),
    ("sarif_out", "report.sarif"),
    ("ropa_out", "ropa.csv"),
    ("actions_out", "actions.csv"),
    ("vendors_out", "vendors.csv"),
    ("controls_out", "controls.csv"),
    ("breach_out", "breach-readiness.md"),
    ("notice_patch_out", "notice-patch.md"),
    ("issues_out", "fix-pack.md"),
)


def _apply_evidence_pack(args: argparse.Namespace) -> list[str]:
    """Fill unset output paths from --evidence-pack DIR. Explicit flags win."""
    if not getattr(args, "evidence_pack", None):
        return []
    pack_dir = Path(args.evidence_pack)
    pack_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for attr, filename in _EVIDENCE_PACK_DEFAULTS:
        if getattr(args, attr) is None:
            setattr(args, attr, str(pack_dir / filename))
            written.append(filename)
    return written


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
