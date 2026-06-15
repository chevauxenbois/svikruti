"""Static HTML report renderer."""

from __future__ import annotations

import json
from textwrap import dedent
from html import escape
from pathlib import Path
from typing import Iterable

from svikruti.models import Evidence, ScanResult
from svikruti.reports.exports import issue_markdown


def _badge(level: str) -> str:
    colors = {
        "LOW": "#18794e",
        "MEDIUM": "#946200",
        "HIGH": "#b42318",
        "CRITICAL": "#7a271a",
    }
    return f'<span class="badge" style="background:{colors.get(level, "#475569")}">{escape(level)}</span>'


def _evidence_rows(items: Iterable[Evidence]) -> str:
    rows = []
    for index, item in enumerate(items):
        location = item.file or item.source
        if item.line:
            location = f"{location}:{item.line}"
        rows.append(
            f'<tr data-severity="{escape(item.severity)}" data-kind="{escape(item.kind)}">'
            f"<td>{_badge(item.severity)}</td>"
            f"<td><strong>{escape(item.label)}</strong><div>{escape(item.detail)}</div><div class=\"small\">Evidence #{index}</div></td>"
            f"<td>{escape(item.kind)}</td>"
            f"<td>{escape(location)}</td>"
            f"<td>{escape(item.recommendation)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _list(items: Iterable[str]) -> str:
    values = list(items)
    if not values:
        return "<li>None detected</li>"
    return "\n".join(f"<li>{escape(str(item))}</li>" for item in values)


def _ropa_rows(result: ScanResult) -> str:
    rows = []
    for entry in result.ropa_starter:
        rows.append(
            "<tr>"
            f"<td>{escape(str(entry['activity']))}</td>"
            f"<td>{escape(str(entry['data_categories']))}</td>"
            f"<td>{escape(', '.join(entry['purposes']))}</td>"
            f"<td>{escape(', '.join(entry['systems_or_sources']))}</td>"
            f"<td>{escape(', '.join(entry['third_parties']) or 'To be confirmed')}</td>"
            f"<td>{escape(str(entry['retention']))}</td>"
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="6">No RoPA starter rows generated.</td></tr>'
    return "\n".join(rows)


def _flow_rows(result: ScanResult) -> str:
    rows = []
    for flow in result.evidence_graph.data_flows:
        rows.append(
            "<tr>"
            f"<td><strong>{escape(str(flow['data_category']))}</strong><div>Notice: {escape(str(flow['notice_status']))}</div></td>"
            f"<td>{escape(', '.join(flow['collection_points']) or 'Not detected')}</td>"
            f"<td>{escape(', '.join(flow['storage_points']) or 'Not detected')}</td>"
            f"<td>{escape(', '.join(flow['logging_risks']) or 'None detected')}</td>"
            f"<td>{escape(', '.join(flow['dpdpa_obligations']) or 'To be mapped')}</td>"
            f"<td>{escape('; '.join(flow['remediation']) or 'No immediate action')}</td>"
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="6">No data flows generated.</td></tr>'
    return "\n".join(rows)


def _proof_pack(result: ScanResult, limit: int | None = 8) -> str:
    items = []
    actions = result.evidence_graph.proof_pack if limit is None else result.evidence_graph.proof_pack[:limit]
    for index, action in enumerate(actions):
        evidence = action.get("evidence", [])
        items.append(
            f'<div class="action" data-action-id="{index}">'
            f'<div class="action-priority">{escape(str(action.get("priority", "P1")))}</div>'
            '<div>'
            '<label class="action-check">'
            f'<input type="checkbox" data-action-check="{index}">'
            '<span>Mark reviewed</span>'
            '</label>'
            f'<strong>{escape(str(action.get("title", "")))}</strong>'
            f'<p>{escape(str(action.get("why", "")))}</p>'
            f'<p class="small">Owner: {escape(str(action.get("owner", "")))} | Artifact: {escape(str(action.get("artifact", "")))}</p>'
            f'<p class="small">Evidence: {escape(", ".join(str(item) for item in evidence) or "None")}</p>'
            "</div></div>"
        )
    if not items:
        return '<div class="box">No proof-pack actions generated.</div>'
    return "\n".join(items)


def _proof_count_note(result: ScanResult) -> str:
    remaining = len(result.evidence_graph.proof_pack) - 8
    if remaining <= 0:
        return ""
    return f'<p class="small">{remaining} additional actions are available in the JSON report.</p>'


def _decision_brief(result: ScanResult) -> str:
    summary = result.summary
    missing_notice_count = sum(1 for flow in result.evidence_graph.data_flows if flow.get("notice_status") == "missing")
    logging_count = sum(1 for item in result.evidence if item.kind == "logging_risk")
    browser_count = sum(1 for item in result.evidence if item.source == "browser")
    high_count = sum(1 for item in result.evidence if item.severity in {"HIGH", "CRITICAL"})

    if summary.risk_level in {"CRITICAL", "HIGH"}:
        posture = "Do not treat this as launch-ready until the P0/P1 actions are reviewed."
    elif summary.risk_level == "MEDIUM":
        posture = "Launchable for a controlled beta after the top actions are assigned."
    else:
        posture = "Low scanner risk, but still needs human privacy/legal review before external claims."

    coverage = [
        f"{summary.files_scanned} files scanned",
        f"{summary.website_pages_scanned} website pages scanned",
        f"{len(summary.personal_data_categories)} data categories",
        f"{len(summary.third_parties)} third parties",
    ]
    if browser_count:
        coverage.append("browser consent journey tested")

    signals = []
    if missing_notice_count:
        signals.append(f"{missing_notice_count} data flows are not clearly covered by the privacy notice.")
    if logging_count:
        signals.append(f"{logging_count} logging risks need engineering review.")
    if high_count:
        signals.append(f"{high_count} high/critical evidence items need owner assignment.")
    if not signals:
        signals.append("No high-priority scanner concern was detected in this scope.")

    return (
        '<section class="brief-grid">'
        '<div class="brief"><span>Launch posture</span>'
        f'<strong>{escape(posture)}</strong></div>'
        '<div class="brief"><span>Evidence coverage</span>'
        f'<strong>{escape(" | ".join(coverage))}</strong></div>'
        f'{_ai_status_card(result)}'
        '<div class="brief"><span>What matters now</span>'
        f'<strong>{escape(" ".join(signals))}</strong></div>'
        '</section>'
    )


def _graph_edges(result: ScanResult) -> str:
    node_labels = {node.id: node.label for node in result.evidence_graph.nodes}
    rows = []
    for edge in result.evidence_graph.edges[:80]:
        rows.append(
            "<tr>"
            f"<td>{escape(node_labels.get(edge.source, edge.source))}</td>"
            f"<td>{escape(edge.label)}</td>"
            f"<td>{escape(node_labels.get(edge.target, edge.target))}</td>"
            f"<td>{escape(', '.join(str(ref) for ref in edge.evidence_refs[:8]))}</td>"
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="4">No graph edges generated.</td></tr>'
    return "\n".join(rows)


def _short(value: str, limit: int = 26) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "..."


def _flow_graph(result: ScanResult) -> str:
    flows = result.evidence_graph.data_flows[:8]
    if not flows:
        return '<div class="box">No evidence flows generated.</div>'

    lanes = []
    for flow in flows:
        sources = ", ".join(flow["collection_points"] or flow["storage_points"] or flow["logging_risks"]) or "Not detected"
        obligations = ", ".join(flow["dpdpa_obligations"]) or "To be mapped"
        remediation = "; ".join(flow["remediation"]) or "No immediate action"
        notice_status = str(flow["notice_status"])
        notice_class = "ok" if notice_status == "covered" else "missing"
        lanes.append(
            '<div class="flow-lane">'
            f'<div class="flow-node source"><span>Source</span><strong>{escape(sources)}</strong></div>'
            '<div class="arrow">-></div>'
            f'<div class="flow-node data"><span>Data</span><strong>{escape(str(flow["data_category"]))}</strong></div>'
            '<div class="arrow">-></div>'
            f'<div class="flow-node notice {notice_class}"><span>Notice</span><strong>{escape(notice_status.title())}</strong></div>'
            '<div class="arrow">-></div>'
            f'<div class="flow-node obligation"><span>DPDPA area</span><strong>{escape(obligations)}</strong></div>'
            '<div class="arrow">-></div>'
            f'<div class="flow-node action-node"><span>Action</span><strong>{escape(remediation)}</strong></div>'
            '</div>'
        )
    return '<div class="flow-graph">' + "\n".join(lanes) + "</div>"


def _top_notice_gaps(result: ScanResult) -> str:
    gaps = result.notice_gaps[:6]
    if not gaps:
        return '<li>No immediate notice gaps detected.</li>'
    return _list(gaps)


def _severity_distribution(result: ScanResult) -> str:
    counts = {level: 0 for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    for item in result.evidence:
        if item.severity in counts:
            counts[item.severity] += 1
    max_count = max(counts.values()) if counts else 0
    bars = []
    for level, count in counts.items():
        width = 0 if max_count == 0 else max(8, int((count / max_count) * 100))
        bars.append(
            '<div class="bar-row">'
            f'<span>{escape(level)}</span>'
            '<div class="bar-track">'
            f'<div class="bar-fill {escape(level.lower())}" style="width:{width}%"></div>'
            '</div>'
            f'<strong>{count}</strong>'
            '</div>'
        )
    return "\n".join(bars)


def _control_items(result: ScanResult) -> list[dict[str, object]]:
    categories = set(result.summary.personal_data_categories)
    evidence_kinds = {item.kind for item in result.evidence}
    gaps = " ".join(result.notice_gaps).lower()
    actions = " ".join(str(action.get("title", "")) for action in result.evidence_graph.proof_pack).lower()

    def item(name: str, status: str, owner: str, evidence: str, action: str) -> dict[str, object]:
        return {"name": name, "status": status, "owner": owner, "evidence": evidence, "action": action}

    return [
        item(
            "Notice coverage",
            "Needs work" if result.notice_gaps else "Ready",
            "Legal / Privacy",
            f"{len(result.notice_gaps)} notice gaps",
            "Patch the privacy notice so detected data and vendors are disclosed.",
        ),
        item(
            "Consent and withdrawal",
            "Needs work" if "withdraw" in gaps or any(item.source == "browser" for item in result.evidence) else "Review",
            "Product / Legal",
            "Withdrawal gap detected" if "withdraw" in gaps else "No browser consent journey attached",
            "Verify reject, accept, and withdrawal paths with browser consent mode.",
        ),
        item(
            "Data minimization",
            "Needs work" if {"Government ID", "Health", "Children"} & categories or "minimization" in actions else "Review",
            "Engineering / Privacy",
            ", ".join(sorted({"Government ID", "Health", "Children"} & categories)) or "No sensitive category spike",
            "Confirm strict purpose, retention, and access controls for sensitive data.",
        ),
        item(
            "Vendor governance",
            "Needs work" if result.summary.third_parties else "Ready",
            "Procurement / Legal",
            f"{len(result.summary.third_parties)} vendors/tools detected",
            "Confirm DPA status, purpose, transfer location, and notice disclosure.",
        ),
        item(
            "RoPA readiness",
            "Review" if result.ropa_starter else "Missing",
            "Privacy Ops",
            f"{len(result.ropa_starter)} RoPA starter rows",
            "Export RoPA CSV and complete retention, lawful basis, and owners.",
        ),
        item(
            "Tracking controls",
            "Needs work" if "Device" in categories or result.summary.third_parties else "Ready",
            "Product / Engineering",
            "Device/tracking signals detected" if "Device" in categories else "No tracker signal in this scope",
            "Gate non-essential tracking and make preference changes discoverable.",
        ),
        item(
            "Logging and security",
            "Needs work" if "logging_risk" in evidence_kinds else "Ready",
            "Engineering / Security",
            f"{sum(1 for item in result.evidence if item.kind == 'logging_risk')} logging risks",
            "Mask or remove personal data from logs and define retention.",
        ),
        item(
            "Children data",
            "Needs work" if "Children" in categories else "Ready",
            "Legal / Product",
            "Children data detected" if "Children" in categories else "No children data signal",
            "If children data exists, verify guardian consent and age-gating controls.",
        ),
    ]


def _control_board(result: ScanResult) -> str:
    cards = []
    for control in _control_items(result):
        status = str(control["status"])
        status_class = status.lower().replace(" ", "-")
        cards.append(
            f'<div class="control-card {escape(status_class)}">'
            f'<span>{escape(status)}</span>'
            f'<strong>{escape(str(control["name"]))}</strong>'
            f'<p>{escape(str(control["evidence"]))}</p>'
            f'<p class="small">Owner: {escape(str(control["owner"]))}</p>'
            f'<p class="small">Next: {escape(str(control["action"]))}</p>'
            '</div>'
        )
    return '<div class="control-grid">' + "\n".join(cards) + "</div>"


def _fix_pack(result: ScanResult) -> str:
    items = []
    for index, action in enumerate(result.evidence_graph.proof_pack[:10], start=1):
        body = issue_markdown_for_action(action, index)
        items.append(
            '<div class="issue-card">'
            f'<div><span>{escape(str(action.get("priority", "P1")))}</span><strong>{escape(str(action.get("title", "")))}</strong></div>'
            f'<p>{escape(str(action.get("why", "")))}</p>'
            f'<textarea readonly>{escape(body)}</textarea>'
            '<button type="button" data-copy-issue>Copy issue</button>'
            '</div>'
        )
    if not items:
        return '<div class="box">No fix-pack issues generated.</div>'
    return "\n".join(items)


def issue_markdown_for_action(action: dict[str, object], index: int) -> str:
    evidence = "; ".join(str(item) for item in action.get("evidence", [])) or "None"
    return "\n".join(
        [
            f"[{action.get('priority', 'P1')}] {action.get('title', 'Untitled action')}",
            "",
            f"Owner: {action.get('owner', 'To be assigned')}",
            f"Artifact: {action.get('artifact', 'To be confirmed')}",
            "",
            "Why",
            str(action.get("why", "")),
            "",
            "Evidence",
            evidence,
            "",
            "Acceptance criteria",
            "- [ ] Owner confirmed",
            "- [ ] Evidence reviewed",
            "- [ ] Remediation implemented or risk accepted",
            "- [ ] Privacy notice / RoPA / vendor register updated where applicable",
            "- [ ] Svikruti scan rerun and result attached",
        ]
    )


def _ai_panel(result: ScanResult) -> str:
    insights = result.ai_insights or {"status": "not_generated", "message": "Run this scan with --ai and OPENAI_API_KEY to generate AI commentary."}
    status = str(insights.get("status", "not_generated"))
    status_class = status.lower().replace("_", "-")

    if status != "generated":
        key_hint = "GEMINI_API_KEY" if insights.get("provider") == "gemini" else "OPENAI_API_KEY"
        provider_hint = "--ai-provider gemini" if insights.get("provider") == "gemini" else "--ai-provider openai"
        return (
            f'<div class="ai-empty {escape(status_class)}">'
            f'<span>{escape(status.replace("_", " ").title())}</span>'
            '<strong>AI Co-pilot not generated</strong>'
            f'<p>{escape(str(insights.get("message", "Run with --ai to generate AI commentary.")))}</p>'
            f'<code>{escape(key_hint)}=... svikruti scan --ai {escape(provider_hint)} --ai-out ai-brief.md ...</code>'
            '</div>'
        )

    priority_cards = []
    for priority in insights.get("top_priorities", [])[:6]:
        evidence = priority.get("evidence", [])
        if isinstance(evidence, str):
            evidence_text = evidence
        else:
            evidence_text = ", ".join(str(item) for item in evidence)
        priority_cards.append(
            '<div class="ai-priority">'
            f'<strong>{escape(str(priority.get("title", "Priority")))}</strong>'
            f'<p>{escape(str(priority.get("why", "")))}</p>'
            f'<p class="small">Owner: {escape(str(priority.get("owner", "To be assigned")))}</p>'
            f'<p class="small">Evidence: {escape(evidence_text or "None")}</p>'
            '</div>'
        )

    control_rows = []
    for item in insights.get("control_commentary", [])[:8]:
        control_rows.append(
            "<tr>"
            f'<td><strong>{escape(str(item.get("control", "")))}</strong></td>'
            f'<td>{escape(str(item.get("status", "")))}</td>'
            f'<td>{escape(str(item.get("comment", "")))}</td>'
            "</tr>"
        )
    if not control_rows:
        control_rows.append('<tr><td colspan="3">No AI control commentary returned.</td></tr>')

    return (
        '<div class="ai-header">'
        '<span>Generated</span>'
        f'<strong>{escape(str(insights.get("model", "AI model")))}</strong>'
        f'<p>{escape(str(insights.get("executive_brief", "")))}</p>'
        '</div>'
        '<section class="split">'
        '<div class="box"><h2>Launch Risk</h2>'
        f'<p>{escape(str(insights.get("launch_risk", "")))}</p></div>'
        '<div class="box"><h2>Buyer Summary</h2>'
        f'<p>{escape(str(insights.get("buyer_summary", "")))}</p></div>'
        '</section>'
        '<section><h2>AI Priorities</h2><div class="ai-priority-grid">'
        + "\n".join(priority_cards or ['<div class="box">No AI priorities returned.</div>'])
        + '</div></section>'
        '<section><h2>AI Control Commentary</h2><table><thead><tr><th>Control</th><th>Status</th><th>Comment</th></tr></thead><tbody>'
        + "\n".join(control_rows)
        + '</tbody></table></section>'
        '<section class="split">'
        '<div class="box"><h2>AI Notice Patch</h2>'
        f'<p>{escape(str(insights.get("notice_patch", "")))}</p></div>'
        '<div class="box"><h2>Fix Pack Improvements</h2>'
        f'<p>{escape(str(insights.get("fix_pack_improvements", "")))}</p></div>'
        '</section>'
        '<section><h2>AI Caveats</h2>'
        f'<div class="callout">{escape(str(insights.get("caveats", "AI output is drafting support only.")))}</div></section>'
    )


def _artifact_links(result: ScanResult) -> str:
    return dedent(f"""
      <div class="artifact-grid">
        <div class="artifact"><span>1</span><strong>Assign actions</strong><p>Use the action checklist to assign owners before launch.</p></div>
        <div class="artifact"><span>2</span><strong>Patch notice</strong><p>Copy the generated drafting aid for privacy/legal review.</p><button type="button" data-copy-notice>Copy notice draft</button></div>
        <div class="artifact"><span>3</span><strong>Export artifacts</strong><p>Generate CSV/Markdown outputs from the CLI for RoPA, vendors, and remediation.</p><code>--ropa-out --actions-out --vendors-out --notice-patch-out</code></div>
        <div class="artifact"><span>4</span><strong>AI co-pilot</strong><p>Generate evidence-grounded AI brief and rewritten fixes.</p><code>--ai --ai-provider gemini --ai-out ai-brief.md</code></div>
        <div class="artifact"><span>5</span><strong>CI gate</strong><p>Install the PR workflow so privacy evidence changes are caught during engineering review.</p><code>svikruti init-github-action</code></div>
      </div>
      <p class="small">Scope: {escape(str(result.repo_path or "not scanned"))} | URL: {escape(str(result.url or "not scanned"))}</p>
    """).strip()


def _report_payload(result: ScanResult) -> str:
    return json.dumps(result.to_dict()).replace("</", "<\\/")


def _notice_draft_text(result: ScanResult) -> str:
    lines = ["Privacy notice drafting aid", "", "Gaps to review:"]
    lines.extend(f"- {gap}" for gap in result.notice_gaps[:12])
    if result.summary.personal_data_categories:
        lines.extend(["", "Detected data categories:", ", ".join(result.summary.personal_data_categories)])
    if result.summary.third_parties:
        lines.extend(["", "Detected third parties:", ", ".join(result.summary.third_parties)])
    lines.extend(
        [
            "",
            "Add or verify: consent withdrawal, data principal rights, retention, grievance handling, and vendor/processor disclosure.",
        ]
    )
    return escape("\n".join(lines))


def _plain_summary(result: ScanResult) -> str:
    data_count = len(result.summary.personal_data_categories)
    vendor_count = len(result.summary.third_parties)
    action_count = len(result.evidence_graph.proof_pack)
    if action_count:
        return (
            f"Svikruti found {data_count} personal-data categories, {vendor_count} third parties, "
            f"and {action_count} proof-pack actions. Start with the decision brief and top actions."
        )
    return (
        f"Svikruti found {data_count} personal-data categories and {vendor_count} third parties. "
        "Review the flow map and appendices for supporting evidence."
    )


def _workflow_strip(result: ScanResult) -> str:
    ai_state = (result.ai_insights or {}).get("status", "not_generated")
    steps = [
        ("Scan", f"{result.summary.files_scanned + result.summary.website_pages_scanned} sources"),
        ("Map", f"{len(result.evidence_graph.data_flows)} flows"),
        ("Control", f"{len(_control_items(result))} controls"),
        ("Fix", f"{len(result.evidence_graph.proof_pack)} actions"),
        ("AI", str(ai_state).replace("_", " ")),
        ("Gate", "SARIF / CI"),
    ]
    return (
        '<section class="workflow-strip">'
        + "\n".join(
            '<div class="workflow-step">'
            f'<span>{escape(str(index))}</span>'
            f'<strong>{escape(title)}</strong>'
            f'<small>{escape(detail)}</small>'
            '</div>'
            for index, (title, detail) in enumerate(steps, start=1)
        )
        + "</section>"
    )


def _ai_status_card(result: ScanResult) -> str:
    insights = result.ai_insights or {}
    status = str(insights.get("status", "not generated")).replace("_", " ")
    model = str(insights.get("model", "Configure Gemini or OpenAI"))
    provider = str(insights.get("provider", "ai"))
    return (
        '<div class="brief ai-brief">'
        '<span>AI co-pilot</span>'
        f'<strong>{escape(status.title())}</strong>'
        f'<p>{escape(provider)} | {escape(model)}</p>'
        '</div>'
    )


def render_html(result: ScanResult) -> str:
    summary = result.summary
    payload = _report_payload(result)
    notice_draft = _notice_draft_text(result)
    fix_pack_text = escape(issue_markdown(result))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Svikruti PrivacyOps Evidence Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #182235;
      --muted: #667085;
      --line: #d7dee8;
      --panel: #f7f9fc;
      --panel-strong: #eef4f8;
      --accent: #047a78;
      --accent-2: #17324d;
      --amber: #b7791f;
      --rose: #b42318;
      --green: #18794e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: #f8fafc;
      line-height: 1.5;
    }}
    header {{
      padding: 34px 56px 28px;
      background:
        linear-gradient(135deg, rgba(5, 122, 120, 0.22), rgba(23, 50, 77, 0.92)),
        #14283c;
      color: white;
    }}
    .eyebrow {{
      margin: 0 0 8px;
      color: #9ee0da;
      font-size: 12px;
      font-weight: 850;
      text-transform: uppercase;
      letter-spacing: 0;
    }}
    header h1 {{ margin: 0 0 8px; font-size: 36px; letter-spacing: 0; }}
    header p {{ margin: 0; color: #c7d5df; max-width: 860px; }}
    .header-grid {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 28px;
      align-items: end;
    }}
    .header-stat {{
      min-width: 178px;
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      padding: 14px 16px;
      background: rgba(255,255,255,0.08);
    }}
    .header-stat span {{
      display: block;
      color: #b8c9d6;
      font-size: 11px;
      font-weight: 850;
      text-transform: uppercase;
    }}
    .header-stat strong {{
      display: block;
      font-size: 25px;
      margin-top: 4px;
    }}
    main {{ padding: 34px 56px 56px; }}
    section {{ margin: 0 0 34px; }}
    h2 {{ margin: 0 0 16px; font-size: 22px; }}
    h3 {{ margin: 20px 0 10px; font-size: 16px; }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 5;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 12px 56px;
      background: rgba(255,255,255,0.96);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(10px);
    }}
    .tab-btn, button {{
      border: 1px solid #b8c5d3;
      border-radius: 8px;
      background: #fff;
      color: var(--ink);
      padding: 8px 11px;
      font: inherit;
      font-size: 13px;
      font-weight: 750;
      cursor: pointer;
    }}
    .tab-btn.active, button.primary {{
      background: var(--accent-2);
      border-color: var(--accent-2);
      color: white;
    }}
    .workspace-section {{ display: none; }}
    .workspace-section.active {{ display: block; }}
    .workflow-strip {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 24px;
    }}
    .workflow-step {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: white;
      padding: 12px;
      min-width: 0;
    }}
    .workflow-step span {{
      display: inline-flex;
      width: 24px;
      height: 24px;
      align-items: center;
      justify-content: center;
      border-radius: 999px;
      background: #e7f5f3;
      color: #075c5a;
      font-size: 12px;
      font-weight: 850;
      margin-bottom: 8px;
    }}
    .workflow-step strong, .workflow-step small {{
      display: block;
      overflow-wrap: anywhere;
    }}
    .workflow-step small {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 2px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      background: var(--panel);
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 700; }}
    .metric .value {{ font-size: 26px; font-weight: 750; margin-top: 6px; }}
    .split {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }}
    .hero-summary {{
      border: 1px solid #b8d8d5;
      background: linear-gradient(135deg, #f0fbfa, #fff);
      border-radius: 8px;
      padding: 18px 20px;
      margin-bottom: 24px;
      font-size: 16px;
    }}
    .brief-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr 1fr 1.2fr;
      gap: 14px;
      margin-bottom: 28px;
    }}
    .brief {{
      border: 1px solid #bfd0df;
      border-radius: 8px;
      background: #fff;
      padding: 15px 16px;
      min-width: 0;
    }}
    .brief span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 800;
      margin-bottom: 8px;
    }}
    .brief strong {{
      display: block;
      font-size: 15px;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }}
    .brief p {{
      margin: 7px 0 0;
      color: var(--muted);
      font-size: 13px;
    }}
    .ai-brief {{
      border-color: #cbbce8;
      background: #fbf8ff;
    }}
    .box {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px 18px;
      background: #fff;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      border: 1px solid var(--line);
      font-size: 13px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      vertical-align: top;
      text-align: left;
    }}
    th {{ background: var(--panel); font-size: 12px; text-transform: uppercase; color: var(--muted); }}
    td div {{ color: var(--muted); margin-top: 4px; }}
    .badge {{
      display: inline-block;
      color: white;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 700;
      white-space: nowrap;
    }}
    .callout {{
      border-left: 4px solid var(--accent);
      background: #eef8f7;
      padding: 14px 16px;
      border-radius: 6px;
    }}
    .action {{
      display: grid;
      grid-template-columns: 52px 1fr;
      gap: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 10px;
      background: #fff;
    }}
    .action-priority {{
      width: 42px;
      height: 42px;
      border-radius: 8px;
      background: var(--accent-2);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 13px;
    }}
    .action p {{ margin: 5px 0; }}
    .action.done {{
      opacity: 0.62;
      background: #f7faf8;
    }}
    .action-check {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 760;
      margin-bottom: 7px;
    }}
    .artifact-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
    }}
    .control-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }}
    .control-card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      background: #fff;
      min-width: 0;
    }}
    .control-card span, .issue-card span {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 11px;
      font-weight: 850;
      margin-bottom: 10px;
    }}
    .control-card.ready span {{ background: #e8f6ef; color: #12633d; }}
    .control-card.review span {{ background: #fff4dc; color: #7b4e00; }}
    .control-card.missing span,
    .control-card.needs-work span {{ background: #fee4df; color: #9f1f16; }}
    .control-card strong {{
      display: block;
      margin-bottom: 6px;
      font-size: 15px;
    }}
    .control-card p {{ margin: 6px 0; color: var(--muted); font-size: 13px; }}
    .issue-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }}
    .issue-card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      background: #fff;
      min-width: 0;
    }}
    .issue-card span {{ background: #eef2f6; color: #243246; }}
    .issue-card strong {{ display: block; margin-bottom: 8px; }}
    .issue-card p {{ color: var(--muted); font-size: 13px; }}
    .issue-card textarea {{
      width: 100%;
      min-height: 190px;
      resize: vertical;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: #263244;
      background: #fbfcfe;
      margin-bottom: 10px;
    }}
    .ai-header, .ai-empty {{
      border: 1px solid #b9d9d6;
      border-radius: 8px;
      padding: 18px;
      background: #f0fbfa;
      margin-bottom: 20px;
    }}
    .ai-header span, .ai-empty span {{
      display: inline-block;
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 850;
      background: #dff3f1;
      color: #075c5a;
      margin-bottom: 10px;
    }}
    .ai-header strong, .ai-empty strong {{
      display: block;
      font-size: 19px;
      margin-bottom: 8px;
    }}
    .ai-priority-grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
    }}
    .ai-priority {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      background: #fff;
      min-width: 0;
    }}
    .ai-priority strong {{ display: block; margin-bottom: 8px; }}
    .ai-priority p {{ margin: 6px 0; color: var(--muted); font-size: 13px; }}
    .artifact {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 15px;
      background: #fff;
      min-width: 0;
    }}
    .artifact span {{
      display: inline-flex;
      width: 28px;
      height: 28px;
      align-items: center;
      justify-content: center;
      border-radius: 8px;
      background: #e8f2f1;
      color: #075c5a;
      font-weight: 850;
      margin-bottom: 10px;
    }}
    .artifact strong {{ display: block; margin-bottom: 6px; }}
    .artifact p {{ margin: 0 0 10px; color: var(--muted); font-size: 13px; }}
    .bar-row {{
      display: grid;
      grid-template-columns: 78px 1fr 42px;
      gap: 10px;
      align-items: center;
      margin: 9px 0;
      font-size: 13px;
    }}
    .bar-track {{
      height: 10px;
      background: #eef2f6;
      border-radius: 999px;
      overflow: hidden;
    }}
    .bar-fill {{ height: 100%; border-radius: 999px; }}
    .bar-fill.critical {{ background: #7a271a; }}
    .bar-fill.high {{ background: #b42318; }}
    .bar-fill.medium {{ background: #946200; }}
    .bar-fill.low {{ background: #18794e; }}
    .flow-graph {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      padding: 14px;
    }}
    .flow-lane {{
      display: grid;
      grid-template-columns: minmax(150px, 1.1fr) 24px minmax(120px, 0.8fr) 24px minmax(115px, 0.75fr) 24px minmax(150px, 1fr) 24px minmax(260px, 1.65fr);
      align-items: stretch;
      gap: 8px;
      padding: 10px 0;
      border-bottom: 1px solid #e6ebf2;
    }}
    .flow-lane:last-child {{ border-bottom: none; }}
    .flow-node {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
      background: white;
      min-width: 0;
    }}
    .flow-node span {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 760;
      margin-bottom: 5px;
    }}
    .flow-node strong {{
      display: block;
      font-size: 13px;
      line-height: 1.25;
      white-space: normal;
      overflow-wrap: anywhere;
      word-break: normal;
    }}
    .flow-node.source {{ background: #f0f6fb; border-color: #9ab4ca; }}
    .flow-node.data {{ background: #eef8f7; border-color: #82c5c0; }}
    .flow-node.notice.ok {{ background: #effaf3; border-color: #9fd7b4; }}
    .flow-node.notice.missing {{ background: #fff1f0; border-color: #e5a19b; }}
    .flow-node.obligation {{ background: #f7f1ff; border-color: #b9a0de; }}
    .flow-node.action-node {{ background: #fff8e8; border-color: #e2bd6f; }}
    .arrow {{
      color: #8a96a6;
      font-weight: 800;
      text-align: center;
      align-self: center;
    }}
    details {{
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-bottom: 14px;
      background: #fff;
    }}
    summary {{
      cursor: pointer;
      padding: 14px 16px;
      font-weight: 760;
      background: var(--panel);
      border-radius: 8px;
    }}
    details[open] summary {{
      border-bottom: 1px solid var(--line);
      border-radius: 8px 8px 0 0;
    }}
    .details-body {{ padding: 16px; }}
    .details-body table {{ margin-top: 0; }}
    .compact-list {{
      margin: 0;
      padding-left: 20px;
    }}
    .small {{ color: var(--muted); font-size: 12px; }}
    .toolbar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 12px;
    }}
    input[type="search"], select {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 9px 11px;
      font: inherit;
      min-width: 220px;
    }}
    code {{ background: #eef2f6; padding: 2px 5px; border-radius: 4px; }}
    @media (max-width: 900px) {{
      header, main, .topbar {{ padding-left: 22px; padding-right: 22px; }}
      .header-grid, .grid, .split, .brief-grid, .artifact-grid, .control-grid, .issue-grid, .ai-priority-grid, .workflow-strip {{ grid-template-columns: 1fr; }}
      .flow-lane {{ grid-template-columns: 1fr; }}
      .arrow {{ transform: rotate(90deg); }}
      table {{ display: block; overflow-x: auto; white-space: nowrap; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-grid">
      <div>
        <div class="eyebrow">India-first PrivacyOps evidence workbench</div>
        <h1>Svikruti Evidence Workbench</h1>
        <p>Engineering evidence for DPDPA readiness: code, website, consent, controls, artifacts, tickets, and optional AI synthesis. Generated {escape(result.generated_at)}.</p>
      </div>
      <div class="header-stat"><span>Risk level</span><strong>{escape(summary.risk_level)}</strong></div>
    </div>
  </header>
  <nav class="topbar" aria-label="Report views">
    <button type="button" class="tab-btn active" data-tab="overview">Overview</button>
    <button type="button" class="tab-btn" data-tab="controls">Control Board</button>
    <button type="button" class="tab-btn" data-tab="actions">Actions</button>
    <button type="button" class="tab-btn" data-tab="flows">Evidence Flow</button>
    <button type="button" class="tab-btn" data-tab="artifacts">Artifacts</button>
    <button type="button" class="tab-btn" data-tab="ai">AI Co-pilot</button>
    <button type="button" class="tab-btn" data-tab="fixpack">Fix Pack</button>
    <button type="button" class="tab-btn" data-tab="evidence">Evidence</button>
  </nav>
  <main>
    <section class="workspace-section active" data-section="overview">
      <div class="hero-summary">{_plain_summary(result)}</div>
      {_workflow_strip(result)}
      {_decision_brief(result)}
      <section class="grid">
        <div class="metric"><div class="label">Risk level</div><div class="value">{escape(summary.risk_level)}</div></div>
        <div class="metric"><div class="label">Risk score</div><div class="value">{summary.risk_score}/100</div></div>
        <div class="metric"><div class="label">Files scanned</div><div class="value">{summary.files_scanned}</div></div>
        <div class="metric"><div class="label">Website pages</div><div class="value">{summary.website_pages_scanned}</div></div>
      </section>
      <section class="split">
        <div class="box">
          <h2>Detected Personal Data</h2>
          <ul>{_list(summary.personal_data_categories)}</ul>
        </div>
        <div class="box">
          <h2>Detected Third Parties</h2>
          <ul>{_list(summary.third_parties)}</ul>
        </div>
      </section>
      <section class="split">
        <div class="box">
          <h2>Severity Mix</h2>
          {_severity_distribution(result)}
        </div>
        <div class="box">
          <h2>Notice Gaps</h2>
          <ul class="compact-list">{_top_notice_gaps(result)}</ul>
        </div>
      </section>
    </section>

    <section class="workspace-section" data-section="controls">
      <h2>DPDPA Control Board</h2>
      <p class="small">A launch-readiness view that maps scanner evidence to practical DPDPA control areas.</p>
      {_control_board(result)}
    </section>

    <section class="workspace-section" data-section="actions">
      <h2>Action Workbench</h2>
      <p class="small">Checkboxes are stored in this browser so you can use the report as a lightweight review tracker.</p>
      {_proof_pack(result, limit=None)}
    </section>

    <section class="workspace-section" data-section="flows">
      <h2>Evidence Flow</h2>
      <p class="small">Each lane shows how Svikruti connects engineering evidence to notice coverage, DPDPA concern, and action.</p>
      {_flow_graph(result)}
      <h3>Data flow table</h3>
      <table>
        <thead>
          <tr><th>Data</th><th>Collection</th><th>Storage</th><th>Logging</th><th>DPDPA Areas</th><th>Remediation</th></tr>
        </thead>
        <tbody>{_flow_rows(result)}</tbody>
      </table>
    </section>

    <section class="workspace-section" data-section="artifacts">
      <h2>Launch Artifacts</h2>
      {_artifact_links(result)}
      <textarea id="notice-draft" hidden>{notice_draft}</textarea>
      <textarea id="fix-pack-draft" hidden>{fix_pack_text}</textarea>
      <h3>RoPA starter</h3>
      <table>
        <thead>
          <tr><th>Activity</th><th>Data Categories</th><th>Purposes</th><th>Sources</th><th>Third Parties</th><th>Retention</th></tr>
        </thead>
        <tbody>{_ropa_rows(result)}</tbody>
      </table>
    </section>

    <section class="workspace-section" data-section="fixpack">
      <h2>Fix Pack</h2>
      <p class="small">Copy-ready implementation tickets for GitHub, Jira, or Linear.</p>
      <div class="issue-grid">
        {_fix_pack(result)}
      </div>
    </section>

    <section class="workspace-section" data-section="ai">
      <h2>AI Co-pilot</h2>
      <p class="small">Optional AI-generated synthesis grounded in this scan result. It is drafting support, not legal advice.</p>
      {_ai_panel(result)}
    </section>

    <section class="workspace-section" data-section="evidence">
      <h2>Evidence Explorer</h2>
      <div class="toolbar">
        <input type="search" id="evidence-search" placeholder="Search evidence, files, recommendations">
        <select id="severity-filter" aria-label="Filter by severity">
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <span class="small" id="evidence-count"></span>
      </div>
      <table id="evidence-table">
        <thead>
          <tr><th>Severity</th><th>Finding</th><th>Type</th><th>Location</th><th>Recommendation</th></tr>
        </thead>
        <tbody>{_evidence_rows(result.evidence)}</tbody>
      </table>
    </section>

    <section>
      <h2>Appendix</h2>
      <details>
        <summary>Graph edges</summary>
        <div class="details-body">
          <table>
            <thead>
              <tr><th>Source</th><th>Relationship</th><th>Target</th><th>Evidence refs</th></tr>
            </thead>
            <tbody>{_graph_edges(result)}</tbody>
          </table>
        </div>
      </details>
    </section>

    <section>
      <h2>Scope And Limitations</h2>
      <ul>{_list(result.disclaimers)}</ul>
      <p class="small">Repository: <code>{escape(str(result.repo_path or "not scanned"))}</code> | URL: <code>{escape(str(result.url or "not scanned"))}</code></p>
    </section>
  </main>
  <script type="application/json" id="svikruti-data">{payload}</script>
  <script>
    const reportData = JSON.parse(document.getElementById('svikruti-data').textContent);
    const reportKey = 'svikruti:' + (reportData.generated_at || document.title);

    function selectTab(name) {{
      document.querySelectorAll('[data-section]').forEach(section => section.classList.toggle('active', section.dataset.section === name));
      document.querySelectorAll('[data-tab]').forEach(button => button.classList.toggle('active', button.dataset.tab === name));
      window.location.hash = name;
    }}

    document.querySelectorAll('[data-tab]').forEach(button => {{
      button.addEventListener('click', () => selectTab(button.dataset.tab));
    }});
    if (window.location.hash) {{
      const target = window.location.hash.slice(1);
      if (document.querySelector(`[data-section="${{target}}"]`)) selectTab(target);
    }}

    function updateEvidenceFilter() {{
      const query = document.getElementById('evidence-search').value.toLowerCase();
      const severity = document.getElementById('severity-filter').value;
      let visible = 0;
      document.querySelectorAll('#evidence-table tbody tr').forEach(row => {{
        const matchesQuery = !query || row.textContent.toLowerCase().includes(query);
        const matchesSeverity = !severity || row.dataset.severity === severity;
        const show = matchesQuery && matchesSeverity;
        row.hidden = !show;
        if (show) visible += 1;
      }});
      document.getElementById('evidence-count').textContent = `${{visible}} visible / ${{reportData.evidence.length}} total`;
    }}

    document.getElementById('evidence-search')?.addEventListener('input', updateEvidenceFilter);
    document.getElementById('severity-filter')?.addEventListener('change', updateEvidenceFilter);
    updateEvidenceFilter();

    const reviewed = new Set(JSON.parse(localStorage.getItem(reportKey + ':reviewed') || '[]'));
    document.querySelectorAll('[data-action-check]').forEach(check => {{
      const id = check.dataset.actionCheck;
      check.checked = reviewed.has(id);
      check.closest('.action')?.classList.toggle('done', check.checked);
      check.addEventListener('change', () => {{
        if (check.checked) reviewed.add(id); else reviewed.delete(id);
        check.closest('.action')?.classList.toggle('done', check.checked);
        localStorage.setItem(reportKey + ':reviewed', JSON.stringify([...reviewed]));
      }});
    }});

    document.querySelector('[data-copy-notice]')?.addEventListener('click', async event => {{
      const text = document.getElementById('notice-draft').value;
      await navigator.clipboard.writeText(text);
      event.currentTarget.textContent = 'Copied';
      setTimeout(() => event.currentTarget.textContent = 'Copy notice draft', 1400);
    }});

    document.querySelectorAll('[data-copy-issue]').forEach(button => {{
      button.addEventListener('click', async event => {{
        const text = event.currentTarget.closest('.issue-card').querySelector('textarea').value;
        await navigator.clipboard.writeText(text);
        event.currentTarget.textContent = 'Copied';
        setTimeout(() => event.currentTarget.textContent = 'Copy issue', 1400);
      }});
    }});
  </script>
</body>
</html>
"""


def write_html(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(render_html(result), encoding="utf-8")
