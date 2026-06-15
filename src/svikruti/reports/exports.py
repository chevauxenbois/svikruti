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


def write_ropa_csv(result: ScanResult, output_path: str) -> None:
    _write_rows(
        output_path,
        ["Activity", "Data Categories", "Data Subjects", "Purposes", "Sources", "Third Parties", "Retention", "DPDPA Notes"],
        (
            [
                entry.get("activity"),
                entry.get("data_categories"),
                entry.get("data_subjects"),
                "; ".join(entry.get("purposes", [])),
                "; ".join(entry.get("systems_or_sources", [])),
                "; ".join(entry.get("third_parties", [])),
                entry.get("retention"),
                "; ".join(entry.get("dpdpa_notes", [])),
            ]
            for entry in result.ropa_starter
        ),
    )


def write_actions_csv(result: ScanResult, output_path: str) -> None:
    _write_rows(
        output_path,
        ["Priority", "Title", "Owner", "Artifact", "Why", "Evidence"],
        (
            [
                action.get("priority"),
                action.get("title"),
                action.get("owner"),
                action.get("artifact"),
                action.get("why"),
                "; ".join(str(item) for item in action.get("evidence", [])),
            ]
            for action in result.evidence_graph.proof_pack
        ),
    )


def write_vendor_csv(result: ScanResult, output_path: str) -> None:
    vendors = sorted(result.summary.third_parties)
    rows = []
    for vendor in vendors:
        evidence_refs = [
            item.file or item.source
            for item in result.evidence
            if item.metadata.get("third_party") == vendor or item.metadata.get("domain") == vendor
        ]
        rows.append([vendor, "To be confirmed", "To be confirmed", "To be confirmed", "; ".join(sorted(set(evidence_refs)))])
    _write_rows(output_path, ["Vendor", "Purpose", "DPA Status", "Transfer Location", "Evidence"], rows)


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
        lines.extend(
            [
                f"## {index}. [{action.get('priority', 'P1')}] {action.get('title', 'Untitled action')}",
                "",
                f"**Owner:** {action.get('owner', 'To be assigned')}",
                f"**Artifact:** {action.get('artifact', 'To be confirmed')}",
                "",
                "### Why",
                str(action.get("why", "")),
                "",
                "### Evidence",
                evidence,
                "",
                "### Acceptance Criteria",
                "- [ ] Owner confirmed",
                "- [ ] Evidence reviewed",
                "- [ ] Remediation implemented or risk accepted",
                "- [ ] Privacy notice / RoPA / vendor register updated where applicable",
                "- [ ] Svikruti scan rerun and result attached",
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
        lines.append(str(insights.get("message", "Run `svikruti scan --ai` with OPENAI_API_KEY configured.")))
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

      # Optional AI co-pilot. Add GEMINI_API_KEY as a repository secret before enabling.
      # - name: Generate AI co-pilot brief
      #   env:
      #     GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
      #   run: |
      #     svikruti scan \\
      #       --repo . \\
      #       --ai \\
      #       --ai-provider gemini \\
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
