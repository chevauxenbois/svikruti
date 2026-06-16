"""Export helpers for operational DPDPA artifacts."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from svikruti.models import ScanResult


def _write_rows(output_path: str, headers: Iterable[str], rows: Iterable[Iterable[object]]) -> None:
    with Path(output_path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(headers))
        for row in rows:
            writer.writerow(["" if value is None else value for value in row])


def _join(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "; ".join(str(item) for item in value)
    return str(value)


def write_ropa_csv(result: ScanResult, output_path: str) -> None:
    _write_rows(
        output_path,
        [
            "Schema Version",
            "Record ID",
            "Processing Activity",
            "Data Fiduciary / Controller",
            "Business Function",
            "Product / System",
            "Data Subjects",
            "Personal Data Categories",
            "Special / High-Risk Category",
            "Processing Purposes",
            "DPDPA Basis",
            "Consent Required",
            "Source Systems",
            "Collection Points",
            "Storage Locations",
            "Logging Locations",
            "Processors / Recipients",
            "International Transfer",
            "Retention Period",
            "Deletion Trigger",
            "Security Measures",
            "Privacy Notice Coverage",
            "Data Principal Rights Impact",
            "Risk Tier",
            "Owner",
            "Review Status",
            "Evidence References",
            "Scanner Confidence",
            "Detected Languages",
            "Detected Frameworks",
            "DPDPA Notes",
        ],
        (
            [
                "svikruti-ropa-v1",
                entry.get("record_id"),
                entry.get("activity"),
                "To be confirmed",
                "To be confirmed",
                _join(entry.get("systems_or_sources")),
                entry.get("data_subjects"),
                entry.get("data_categories"),
                "Yes" if entry.get("risk_tier") == "High" else "No / review",
                _join(entry.get("purposes")),
                entry.get("dpdpa_basis"),
                entry.get("consent_required"),
                _join(entry.get("systems_or_sources")),
                _join(entry.get("collection_points")),
                _join(entry.get("storage_locations")),
                _join(entry.get("logging_locations")),
                _join(entry.get("third_parties")),
                "To be confirmed",
                entry.get("retention"),
                entry.get("deletion_trigger"),
                _join(entry.get("security_measures")),
                entry.get("notice_coverage"),
                entry.get("rights_impact"),
                entry.get("risk_tier"),
                entry.get("owner"),
                entry.get("review_status"),
                _join(entry.get("evidence_refs")),
                _join(entry.get("confidence")),
                _join(entry.get("languages")),
                _join(entry.get("frameworks")),
                _join(entry.get("dpdpa_notes")),
            ]
            for entry in result.ropa_starter
        ),
    )


def write_actions_csv(result: ScanResult, output_path: str) -> None:
    _write_rows(
        output_path,
        [
            "Schema Version",
            "Action ID",
            "Priority",
            "Severity",
            "Control Area",
            "Title",
            "Owner",
            "Status",
            "Due",
            "Artifact",
            "Why",
            "Evidence References",
            "Acceptance Criteria",
        ],
        (
            [
                "svikruti-actions-v1",
                f"SVK-ACT-{index:03d}",
                action.get("priority"),
                action.get("severity", "HIGH" if action.get("priority") == "P1" else "CRITICAL"),
                action.get("control_area", "Privacy control"),
                action.get("title"),
                action.get("owner"),
                action.get("status", "Open"),
                action.get("due", "Before launch / next release"),
                action.get("artifact"),
                action.get("why"),
                _join(action.get("evidence")),
                _join(action.get("acceptance_criteria")),
            ]
            for index, action in enumerate(result.evidence_graph.proof_pack, start=1)
        ),
    )


def write_vendor_csv(result: ScanResult, output_path: str) -> None:
    vendors = sorted(result.summary.third_parties)
    rows = []
    for vendor in vendors:
        matched = [
            item
            for item in result.evidence
            if item.metadata.get("third_party") == vendor or item.metadata.get("domain") == vendor
        ]
        evidence_refs = sorted(set(str(item.metadata.get("evidence_ref") or item.file or item.source) for item in matched))
        data_categories = sorted(set(str(item.metadata.get("data_category")) for item in matched if item.metadata.get("data_category")))
        detector_ids = sorted(set(str(item.metadata.get("detector_id")) for item in matched if item.metadata.get("detector_id")))
        rows.append(
            [
                "svikruti-vendors-v1",
                vendor,
                "To be confirmed",
                _join(data_categories) or "To be mapped",
                "To be confirmed",
                "To be confirmed",
                "To be confirmed",
                "To be confirmed",
                "To be confirmed",
                "To be confirmed",
                "Medium" if matched else "Review",
                "Procurement / Legal / Security",
                "Open",
                "To be scheduled",
                _join(evidence_refs),
                _join(detector_ids),
            ]
        )
    _write_rows(
        output_path,
        [
            "Schema Version",
            "Vendor / Processor",
            "Service Category",
            "Data Categories Shared",
            "Processing Purpose",
            "DPA / Contract Status",
            "Sub-processors",
            "Transfer Location",
            "Security Evidence",
            "Retention / Deletion Commitment",
            "Risk Tier",
            "Owner",
            "Review Status",
            "Next Review Date",
            "Evidence References",
            "Detector IDs",
        ],
        rows,
    )


def write_notice_patch(result: ScanResult, output_path: str) -> None:
    lines = [
        "# Privacy Notice Patch Draft",
        "",
        "This is a generated drafting aid, not legal advice. Review before publishing.",
        "",
    ]
    if result.notice_gaps:
        lines.extend(["## Gaps To Address", ""])
        lines.extend(f"- {gap}" for gap in result.notice_gaps)
        lines.append("")
    if result.summary.personal_data_categories:
        lines.extend(["## Data Categories To Mention", ""])
        lines.append(
            "We may process the following categories of personal data where relevant to the service: "
            + ", ".join(result.summary.personal_data_categories)
            + "."
        )
        lines.append("")
    if result.summary.third_parties:
        lines.extend(["## Vendor / Processor Disclosure", ""])
        lines.append(
            "We may use service providers or processors for analytics, payments, hosting, support, communications, "
            "security, and product operations. Detected vendors or tools for review: "
            + ", ".join(result.summary.third_parties)
            + "."
        )
        lines.append("")
    lines.extend(
        [
            "## Consent And Withdrawal",
            "",
            "Where consent is used, users should be able to withdraw consent through an accessible privacy or account setting path.",
            "",
            "## Retention",
            "",
            "Personal data should be retained only for the period needed for the disclosed purpose, legal obligations, security, or dispute resolution.",
            "",
            "## Grievance",
            "",
            "Add the name/contact path for the grievance or complaint handling contact before publishing.",
            "",
        ]
    )
    Path(output_path).write_text("\n".join(lines), encoding="utf-8")


def issue_markdown(result: ScanResult) -> str:
    lines = [
        "# Svikruti Fix Pack",
        "",
        "Copy these into GitHub/Jira/Linear. Generated from scanner evidence; review before assigning.",
        "",
    ]
    if not result.evidence_graph.proof_pack:
        lines.extend(["No fix-pack actions were generated.", ""])
        return "\n".join(lines)

    for index, action in enumerate(result.evidence_graph.proof_pack, start=1):
        evidence = "; ".join(str(item) for item in action.get("evidence", [])) or "None"
        acceptance_criteria = action.get("acceptance_criteria") or [
            "Owner confirmed",
            "Evidence reviewed",
            "Remediation implemented or risk accepted",
            "Privacy notice / RoPA / vendor register updated where applicable",
            "Svikruti scan rerun and result attached",
        ]
        lines.extend(
            [
                f"## {index}. [{action.get('priority', 'P1')}] {action.get('title', 'Untitled action')}",
                "",
                f"**Severity:** {action.get('severity', 'HIGH')}",
                f"**Control Area:** {action.get('control_area', 'Privacy control')}",
                f"**Owner:** {action.get('owner', 'To be assigned')}",
                f"**Status:** {action.get('status', 'Open')}",
                f"**Due:** {action.get('due', 'Before launch / next release')}",
                f"**Artifact:** {action.get('artifact', 'To be confirmed')}",
                "",
                "### Why",
                str(action.get("why", "")),
                "",
                "### Evidence",
                evidence,
                "",
                "### Acceptance Criteria",
                *[f"- [ ] {item}" for item in acceptance_criteria],
                "",
            ]
        )
    return "\n".join(lines)


def write_issues_markdown(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(issue_markdown(result), encoding="utf-8")


def ai_markdown(result: ScanResult) -> str:
    insights = result.ai_insights or {}
    status = insights.get("status", "not_generated")
    lines = ["# Svikruti AI Co-pilot Brief", ""]
    lines.append(f"Status: {status}")
    if insights.get("model"):
        lines.append(f"Model: {insights.get('model')}")
    lines.append("")

    if status != "generated":
        lines.append(str(insights.get("message", "Run `svikruti scan --ai` with a configured provider key.")))
        lines.append("")
        return "\n".join(lines)

    for heading, key in [
        ("Executive Brief", "executive_brief"),
        ("Launch Risk", "launch_risk"),
        ("Buyer Summary", "buyer_summary"),
        ("Notice Patch", "notice_patch"),
        ("Caveats", "caveats"),
    ]:
        value = insights.get(key)
        if value:
            lines.extend([f"## {heading}", "", str(value), ""])

    priorities = insights.get("top_priorities") or []
    if priorities:
        lines.extend(["## Top Priorities", ""])
        for priority in priorities:
            lines.extend(
                [
                    f"### {priority.get('title', 'Priority')}",
                    f"Owner: {priority.get('owner', 'To be assigned')}",
                    "",
                    str(priority.get("why", "")),
                    "",
                    "Evidence: " + "; ".join(str(item) for item in priority.get("evidence", [])),
                    "",
                ]
            )
    return "\n".join(lines)


def write_ai_markdown(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(ai_markdown(result), encoding="utf-8")


def write_github_action(output_path: str = ".github/workflows/svikruti.yml") -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """name: Svikruti Privacy Evidence

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  privacy-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Svikruti
        run: pip install svikruti

      - name: Scan repository
        run: |
          svikruti scan \\
            --repo . \\
            --out svikruti-report.html \\
            --json-out svikruti-report.json \\
            --sarif-out svikruti.sarif \\
            --ropa-out svikruti-ropa.csv \\
            --actions-out svikruti-actions.csv \\
            --vendors-out svikruti-vendors.csv \\
            --notice-patch-out svikruti-notice-patch.md \\
            --issues-out svikruti-fix-pack.md \\
            --fail-on critical

      # Optional AI co-pilot. Configure the API key for your selected provider
      # as a repository secret before enabling.
      # - name: Generate AI co-pilot brief
      #   run: |
      #     svikruti scan \\
      #       --repo . \\
      #       --ai \\
      #       --out svikruti-ai-report.html \\
      #       --json-out svikruti-ai-report.json \\
      #       --ai-out svikruti-ai-brief.md

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: svikruti.sarif

      - name: Upload evidence artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: svikruti-privacy-evidence
          path: |
            svikruti-report.html
            svikruti-report.json
            svikruti-ropa.csv
            svikruti-actions.csv
            svikruti-vendors.csv
            svikruti-notice-patch.md
            svikruti-fix-pack.md
            svikruti-ai-brief.md
""",
        encoding="utf-8",
    )
