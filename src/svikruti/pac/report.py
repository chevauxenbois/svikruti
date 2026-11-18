"""Writers for `svikruti check`: JSON, Markdown, PR comment, CSV, SARIF, HTML."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List

from svikruti import __version__
from svikruti.pac.engine import CheckResult
from svikruti.pac.inventory import write_inventory_csv
from svikruti.pac.reconcile import RULES, Finding
from svikruti.reports.exports import _join, _write_rows

STATUS_LABEL = {
    "pass": "Verified",
    "fail": "Failing",
    "attested": "Attested",
    "manual": "Not verified",
    "not_applicable": "Not applicable",
}
_STATUS_ICON = {"pass": "✅", "fail": "❌", "attested": "📝", "manual": "⚪", "not_applicable": "➖"}
_SARIF_LEVEL = {"LOW": "note", "MEDIUM": "warning", "HIGH": "error", "CRITICAL": "error"}


def write_check_json(result: CheckResult, path: str) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


# --------------------------------------------------------------------- markdown
def _cell(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _refs(finding: Finding, limit: int = 3) -> str:
    if not finding.refs:
        return "privacy.yaml"
    shown = ", ".join(f"`{ref}`" for ref in finding.refs[:limit])
    return shown + (f" +{len(finding.refs) - limit}" if len(finding.refs) > limit else "")


def _verdict(result: CheckResult, threshold: str) -> str:
    gating = result.gating_findings(threshold) if threshold != "none" else []
    scope = "new " if result.baseline_fingerprints is not None else ""
    if gating:
        return f"❌ **Blocked**: {len(gating)} {scope}finding(s) at {threshold.upper()} or above."
    return f"✅ **Passed**: no {scope}findings at {threshold.upper()} or above." if threshold != "none" else "Gate disabled (`--fail-on none`)."


def _findings_table(findings: List[Finding], result: CheckResult, limit: int) -> List[str]:
    lines = ["| Severity | Rule | What drifted | Where | Fix |", "|---|---|---|---|---|"]
    for finding in findings[:limit]:
        new = " 🆕" if result.baseline_fingerprints is not None and result.is_new(finding) else ""
        lines.append(f"| {finding.severity} | {finding.rule}{new} | {_cell(finding.detail)} | {_refs(finding)} | {_cell(finding.fix)} |")
    if len(findings) > limit:
        lines.append(f"| | | ...and {len(findings) - limit} more in the full report | | |")
    return lines


def _flows_text(activity: Dict[str, Any]) -> str:
    """'Razorpay (receives Contact)' for declared processors, plus undeclared ones seen in code."""
    received = {flow["processor"]: flow["categories"] for flow in activity["detected_flows"]}
    declared = [p["name"] for p in activity["declared_processors"]]
    parts = [f"{name} (receives {', '.join(received[name])})" if received.get(name) else name for name in declared]
    parts += [f"{name} (undeclared)" for name in activity["detected_processors"] if name not in declared]
    return "; ".join(parts)


def check_markdown(result: CheckResult, threshold: str = "high") -> str:
    data = result.to_dict()
    summary = data["summary"]
    open_findings = result.open_findings()
    lines = [
        "# Svikruti privacy check",
        "",
        _verdict(result, threshold),
        "",
        f"Manifest `{result.manifest.path or 'privacy.yaml'}` reconciled against {summary['files_with_personal_data']} file(s) with personal-data evidence: "
        f"{summary['activities']} activit(ies), {summary['processors']} processor(s), "
        f"**{summary['open_findings']} open finding(s)** ({summary['excepted_findings']} under exception).",
        "",
        "## Frameworks",
        "",
        "| Framework | Verified | Attested | Failing | Not verified | N/A | Verified share |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in data["frameworks"]:
        counts = item["counts"]
        lines.append(
            f"| {item['short_name']} | {counts['pass']} | {counts['attested']} | {counts['fail']} | {counts['manual']} | {counts['not_applicable']} | {item['code_verified_percent']}% of {item['applicable']} |"
        )
    lines += ["", "## Drift and policy findings", ""]
    if open_findings:
        lines += _findings_table(open_findings, result, 200)
    else:
        lines.append("None. The manifest and the code agree.")
    excepted = [finding for finding in result.findings if finding.status == "excepted"]
    if excepted:
        lines += ["", "### Under exception", ""]
        for finding in excepted:
            lines.append(f"- {finding.rule} {_cell(finding.detail)} — _{_cell(finding.exception_reason)}_")
    lines += ["", "## Processing record, reconciled with code", ""]
    lines += ["| Activity | Declared data | Detected in code | Processors | Lawful basis | Retention | In sync |", "|---|---|---|---|---|---|---|"]
    for activity in data["activities"]:
        basis = activity["legal_basis"]
        basis_text = ", ".join(f"{key}: {value}" for key, value in basis.items()) if isinstance(basis, dict) else basis
        lines.append(
            f"| {_cell(activity['name'])} | {_cell(', '.join(activity['declared_categories']))} | {_cell(', '.join(activity['detected_categories']))} | "
            f"{_cell(_flows_text(activity))} | {_cell(basis_text)} | {_cell(activity['retention'])} | {'yes' if activity['in_sync'] else '**no**'} |"
        )
    lines += ["", "## Obligation crosswalk", ""]
    header = "| | Obligation | " + " | ".join(pack.short_name for pack in result.packs) + " | Result |"
    lines += [header, "|---|---|" + "---|" * len(result.packs) + "---|"]
    for assessment in result.assessments:
        refs = [", ".join(control["ref"] for control in pack.refs(assessment.id)) or "-" for pack in result.packs]
        lines.append(
            f"| {_STATUS_ICON[assessment.status]} | **{assessment.id}** {_cell(assessment.title)} | " + " | ".join(_cell(ref) for ref in refs) + f" | {STATUS_LABEL[assessment.status]}: {_cell(assessment.summary)} |"
        )
    if result.manifest.warnings:
        lines += ["", "## Manifest warnings", ""] + [f"- {warning}" for warning in result.manifest.warnings]
    lines += ["", "---", ""] + [f"_{text}_" for text in data["disclaimers"]]
    return "\n".join(lines) + "\n"


def pr_comment_markdown(result: CheckResult, threshold: str = "high") -> str:
    """Short version for a pull-request comment: verdict, what drifted, how to fix."""
    open_findings = result.open_findings()
    shown = [f for f in open_findings if result.is_new(f)] if result.baseline_fingerprints is not None else open_findings
    lines = ["## Svikruti privacy check", "", _verdict(result, threshold), ""]
    if shown:
        heading = "New in this change" if result.baseline_fingerprints is not None else "Open findings"
        lines += [f"### {heading}", ""] + _findings_table(shown, result, 15) + [""]
    else:
        lines += ["The privacy manifest and the code agree.", ""]
    parts = []
    for item in result.to_dict()["frameworks"]:
        counts = item["counts"]
        parts.append(f"**{item['short_name']}** {counts['pass']}/{item['applicable']} verified, {counts['fail']} failing")
    lines += [" · ".join(parts), "", "<sub>Engineering evidence, not legal advice. Update `privacy.yaml` in this PR when processing changes on purpose.</sub>"]
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------------- csv
def write_matrix_csv(result: CheckResult, path: str) -> None:
    rows = result.to_dict()["matrix"]
    _write_rows(
        path,
        ["Framework", "Clause / Control", "Legacy Ref", "Control Title", "Obligation", "Obligation Title", "Status", "Proof Type", "Summary"],
        [[r["framework"], r["ref"], r["legacy_ref"], r["control"], r["obligation"], r["obligation_title"], STATUS_LABEL[r["status"]], r["proof"], r["summary"]] for r in rows],
    )


def write_record_csv(result: CheckResult, path: str) -> None:
    """Record of processing built from the manifest and verified against code."""
    rows = []
    for activity in result.to_dict()["activities"]:
        basis = activity["legal_basis"]
        processors = activity["declared_processors"]
        rows.append(
            [
                activity["id"], activity["name"], activity["owner"], _join(activity["purposes"]),
                "; ".join(f"{k}: {v}" for k, v in basis.items()) if isinstance(basis, dict) else basis,
                _join(activity["data_subjects"]), _join(activity["declared_categories"]), _join(activity["detected_categories"]),
                _join([p["name"] for p in processors]), _join(sorted({p["country"] for p in processors if p["country"]})),
                _join(sorted({p["transfer_mechanism"] for p in processors if p["transfer_mechanism"]})),
                "; ".join(f"{flow['processor']}: {', '.join(flow['categories'])}" for flow in activity["detected_flows"]),
                activity["retention"], activity["dpia"], _join(activity["logged_categories"]), _join(activity["paths"]),
                len(activity["files"]), "yes" if activity["in_sync"] else "no", _join(activity["open_rules"]), result.generated_at,
            ]
        )
    _write_rows(
        path,
        [
            "Activity ID", "Processing Activity", "Owner", "Purposes", "Lawful Basis", "Data Subjects",
            "Declared Data Categories", "Categories Detected In Code", "Processors / Recipients", "Processor Countries",
            "Transfer Mechanisms", "Data Sent To Processors (Detected)", "Retention", "DPIA Reference", "Categories Reaching Logs", "Code Paths",
            "Files With Evidence", "In Sync With Code", "Open Rules", "Verified At",
        ],
        rows,
    )


# ------------------------------------------------------------------------ sarif
def write_check_sarif(result: CheckResult, path: str) -> None:
    manifest_uri = (Path(result.manifest.path).name if result.manifest.path else "privacy.yaml")
    results = []
    for finding in result.open_findings():
        locations = []
        for ref in finding.refs[:10] or [manifest_uri]:
            head, _, tail = ref.rpartition(":")
            uri, line = (head, int(tail)) if tail.isdigit() and head else (ref, 1)
            if "://" in uri:
                continue
            locations.append({"physicalLocation": {"artifactLocation": {"uri": uri.replace("\\", "/")}, "region": {"startLine": line}}})
        results.append(
            {
                "ruleId": f"svikruti.pac.{finding.rule}",
                "level": _SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": f"{finding.detail} Fix: {finding.fix}"},
                "locations": locations or [{"physicalLocation": {"artifactLocation": {"uri": manifest_uri}, "region": {"startLine": 1}}}],
                "partialFingerprints": {"svikrutiFinding/v1": finding.fingerprint},
                "properties": {"severity": finding.severity, "activity": finding.activity, "category": finding.category},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Svikruti privacy-as-code",
                        "version": __version__,
                        "informationUri": "https://github.com/chevauxenbois/svikruti",
                        "rules": [
                            {"id": f"svikruti.pac.{rule}", "name": f"svikruti_pac_{rule}", "shortDescription": {"text": spec["title"]}, "help": {"text": spec["fix"]}}
                            for rule, spec in RULES.items()
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")


# ------------------------------------------------------------------------- html
_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202b;--mute:#5b6876;--line:#e2e6ea;--accent:#0b6e69;
--pass:#17794a;--fail:#b3261e;--att:#8a5a00;--man:#5b6876;--passbg:#e5f4ec;--failbg:#fbe9e7;--attbg:#fdf2dc;--manbg:#eceff2}
@media (prefers-color-scheme:dark){:root{--bg:#10151a;--card:#182028;--ink:#e8edf2;--mute:#9aa7b4;--line:#2a3541;--accent:#4fc3bc;
--pass:#6fd39b;--fail:#ff8a80;--att:#f2c063;--man:#9aa7b4;--passbg:#163324;--failbg:#3d1c1a;--attbg:#3a2c10;--manbg:#232d37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 20px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 12px}
.sub{color:var(--mute);margin:0 0 20px}.verdict{padding:14px 18px;border-radius:10px;font-weight:600;margin-bottom:20px}
.verdict.ok{background:var(--passbg);color:var(--pass)}.verdict.bad{background:var(--failbg);color:var(--fail)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h3{margin:0 0 2px;font-size:16px}.card small{color:var(--mute)}.big{font-size:30px;font-weight:700;margin:8px 0 2px}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--manbg);margin:10px 0 8px}
.bar i{display:block}.bar .p{background:var(--pass)}.bar .a{background:var(--att)}.bar .f{background:var(--fail)}
.legend{font-size:12.5px;color:var(--mute)}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute);white-space:nowrap}tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.pass{background:var(--passbg);color:var(--pass)}.fail,.CRITICAL,.HIGH{background:var(--failbg);color:var(--fail)}
.attested,.MEDIUM{background:var(--attbg);color:var(--att)}.manual,.not_applicable,.LOW{background:var(--manbg);color:var(--man)}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--manbg);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
.chip{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:0 7px;margin:0 4px 4px 0;font-size:12.5px}
.chip.miss{border-color:var(--fail);color:var(--fail)}.chip.stale{border-style:dashed;color:var(--mute)}
.mute{color:var(--mute)}.ref{white-space:nowrap}td code{display:inline-block;margin:0 0 3px}footer{margin-top:36px;color:var(--mute);font-size:12.5px}
"""


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _pill(value: str, label: str = "") -> str:
    return f'<span class="pill {_e(value)}">{_e(label or value)}</span>'


def _protection_cell(row: Dict[str, Any]) -> str:
    kind = row.get("protection") or "none"
    if not row.get("persistent"):
        return '<span class="mute">-</span>'
    if kind in {"encrypted", "tokenised", "hashed", "masked"}:
        return _pill("pass", kind) + (f'<div class="mute">{_e(row.get("protection_evidence", ""))}</div>' if row.get("protection_evidence") else "")
    if kind == "binary":
        return _pill("MEDIUM", "binary, unverified")
    return _pill("HIGH", "none") if row.get("high_risk") else '<span class="mute">none</span>'


def _erasure_cell(row: Dict[str, Any]) -> str:
    value = row.get("erasure") or ""
    if not row.get("persistent"):
        return '<span class="mute">not stored</span>'
    if value.startswith("retained"):
        return _pill("attested", "retained") + f'<div class="mute">{_e(value[len("retained: "):])}</div>'
    if value:
        request = row.get("rights_request")
        note = (
            '<div class="mute">rights request: reaches it</div>'
            if request
            else ('<div class="mute">' + _pill("MEDIUM", "no rights request reaches it") + "</div>" if "rights_request" in row else "")
        )
        return _pill("pass", "reached") + f'<div class="mute">{_e(value.replace("reached by ", ""))}</div>' + note
    return _pill("HIGH", "no erasure path")


def render_check_html(result: CheckResult, threshold: str = "high") -> str:
    data = result.to_dict()
    summary = data["summary"]
    gating = result.gating_findings(threshold) if threshold != "none" else []
    scope = "new " if result.baseline_fingerprints is not None else ""
    verdict = (
        f'<div class="verdict bad">Blocked: {len(gating)} {scope}finding(s) at {_e(threshold.upper())} or above</div>'
        if gating
        else f'<div class="verdict ok">Passed: no {scope}findings at {_e(threshold.upper())} or above</div>'
    )
    cards = []
    for item in data["frameworks"]:
        counts, applicable = item["counts"], max(item["applicable"], 1)
        cards.append(
            f'<div class="card"><h3>{_e(item["short_name"])}</h3><small>{_e(item["version"])}</small>'
            f'<div class="big">{item["code_verified_percent"]}%</div><small>of {item["applicable"]} applicable obligations verified from code and manifest</small>'
            f'<div class="bar"><i class="p" style="width:{100 * counts["pass"] / applicable:.1f}%"></i><i class="a" style="width:{100 * counts["attested"] / applicable:.1f}%"></i>'
            f'<i class="f" style="width:{100 * counts["fail"] / applicable:.1f}%"></i></div>'
            f'<div class="legend">{counts["pass"]} verified · {counts["attested"]} attested · {counts["fail"]} failing · {counts["manual"]} not verified</div></div>'
        )
    finding_rows = []
    for finding in result.findings:
        refs = " ".join(f"<code>{_e(ref)}</code>" for ref in finding.refs[:4]) or '<span class="mute">privacy.yaml</span>'
        state = f'<br><span class="mute">Exception: {_e(finding.exception_reason)}</span>' if finding.status == "excepted" else ""
        new = " · new" if result.baseline_fingerprints is not None and result.is_new(finding) and finding.status == "open" else ""
        finding_rows.append(
            f"<tr><td>{_pill(finding.severity if finding.status == 'open' else 'manual', finding.severity if finding.status == 'open' else 'excepted')}</td>"
            f"<td><b>{_e(finding.rule)}</b>{new}<br>{_e(finding.title)}</td><td>{_e(finding.detail)}{state}</td><td>{refs}</td><td>{_e(finding.fix)}</td></tr>"
        )
    activity_rows = []
    for activity in data["activities"]:
        declared, detected = set(activity["declared_categories"]), set(activity["detected_categories"])
        chips = "".join(f'<span class="chip">{_e(name)}</span>' for name in sorted(declared & detected))
        chips += "".join(f'<span class="chip miss" title="in code, not declared">+ {_e(name)}</span>' for name in sorted(detected - declared))
        chips += "".join(f'<span class="chip stale" title="declared, not found in code">{_e(name)}</span>' for name in sorted(declared - detected))
        basis = activity["legal_basis"]
        basis_text = ", ".join(f"{k}: {v}" for k, v in basis.items()) if isinstance(basis, dict) else basis
        received = {flow["processor"]: flow["categories"] for flow in activity["detected_flows"]}
        declared_names = [p["name"] for p in activity["declared_processors"]]
        processors = "".join(
            f'<span class="chip">{_e(p["name"])}{" · " + _e(p["country"]) if p["country"] else ""}</span>'
            + (f'<div class="mute">receives {_e(", ".join(received[p["name"]]))}</div>' if received.get(p["name"]) else "")
            for p in activity["declared_processors"]
        )
        processors += "".join(
            f'<span class="chip miss" title="in code, not declared">+ {_e(name)}</span>'
            + (f'<div class="mute">receives {_e(", ".join(received[name]))}</div>' if received.get(name) else "")
            for name in activity["detected_processors"]
            if name not in declared_names
        )
        activity_rows.append(
            f"<tr><td><b>{_e(activity['name'])}</b><br><span class='mute'>{_e(', '.join(activity['paths']))}</span></td><td>{chips}</td><td>{processors}</td>"
            f"<td>{_e(', '.join(activity['purposes']))}</td><td>{_e(basis_text)}</td><td>{_e(activity['retention'])}</td>"
            f"<td>{_pill('pass', 'in sync') if activity['in_sync'] else _pill('fail', 'drifted')}</td></tr>"
        )
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for row in result.inventory:
        groups.setdefault((row["store"] or "-", row["file"]), []).append(row)
    inventory_rows = []
    for (store, rel), rows in list(groups.items())[:200]:
        first = rows[0]
        fields = "".join(
            f'<span class="chip{" miss" if row["declared"] is False else ""}" title="{_e(row["data_category"])}{" · undeclared" if row["declared"] is False else ""}">'
            f'<code>{_e(row["field"])}</code> {_e(row["data_category"])}{" · " + _e(row["protection"]) if row.get("protection") not in (None, "none", "") else ""}</span>'
            for row in rows
        )
        unprotected = [row for row in rows if row["high_risk"] and row.get("persistent") and row.get("protection") not in {"encrypted", "tokenised", "hashed", "masked"}]
        flags = ""
        if any(row["reaches_logs"] for row in rows):
            flags += _pill("fail", "category in logs") + " "
        sent = sorted({name for row in rows for name in row["sent_to"]})
        flags += "".join(f'<span class="chip">{_e(name)}</span>' for name in sent)
        protection = (
            _pill("HIGH", f"{len(unprotected)} high-risk unprotected")
            if unprotected
            else (_pill("pass", "high-risk protected") if any(row["high_risk"] for row in rows) and first.get("persistent") else '<span class="mute">-</span>')
        )
        inventory_rows.append(
            f"<tr><td><b>{_e(store)}</b><br><code>{_e(rel)}:{_e(first['line'])}</code></td><td>{_e(first['activity'] or '-')}</td>"
            f"<td>{fields}</td><td>{flags or '<span class=mute>-</span>'}</td><td>{protection}</td><td>{_erasure_cell(first)}</td></tr>"
        )
    more_inventory = f'<p class="legend">Showing 200 of {len(groups)} stores. The full field list is in data-inventory.csv.</p>' if len(groups) > 200 else ""
    no_inventory = '<tr><td colspan="6">No model or schema fields with personal data were found.</td></tr>'
    pack_heads = "".join(f"<th>{_e(pack.short_name)}</th>" for pack in result.packs)
    obligation_rows = []
    for assessment in result.assessments:
        cells = "".join("<td>" + ("<br>".join(f'<span class="ref" title="{_e(c.get("title", ""))}">{_e(c["ref"])}</span>' for c in pack.refs(assessment.id)) or "-") + "</td>" for pack in result.packs)
        obligation_rows.append(
            f"<tr><td>{_pill(assessment.status, STATUS_LABEL[assessment.status])}</td><td><b>{_e(assessment.id)}</b> {_e(assessment.title)}<br><span class='mute'>{_e(assessment.question)}</span></td>"
            f"{cells}<td>{_e(assessment.summary)}</td></tr>"
        )
    no_findings = '<tr><td colspan="5">None. The manifest and the code agree.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Svikruti privacy check</title><style>{_CSS}</style></head><body><main>
<h1>Privacy check</h1>
<p class="sub">Manifest <code>{_e(result.manifest.path or "privacy.yaml")}</code> reconciled against {summary["files_with_personal_data"]} file(s) with personal-data evidence · {_e(result.generated_at[:19])} UTC · svikruti {_e(__version__)}</p>
{verdict}
<div class="grid">{"".join(cards)}</div>
<h2>Drift and policy findings ({summary["open_findings"]} open, {summary["excepted_findings"]} under exception)</h2>
<div class="wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>What drifted</th><th>Where</th><th>Fix</th></tr></thead><tbody>{"".join(finding_rows) or no_findings}</tbody></table></div>
<h2>Processing record, reconciled with code</h2>
<div class="wrap"><table><thead><tr><th>Activity</th><th>Data categories</th><th>Processors</th><th>Purposes</th><th>Lawful basis</th><th>Retention</th><th>State</th></tr></thead><tbody>{"".join(activity_rows)}</tbody></table></div>
<p class="legend"><span class="chip">declared and found</span><span class="chip miss">+ in code, not declared</span><span class="chip stale">declared, not in code</span></p>
<h2>Data inventory ({len(groups)} tables and models, {len(result.inventory)} fields)</h2>
<div class="wrap"><table><thead><tr><th>Table / model</th><th>Activity</th><th>Personal-data fields</th><th>Category also goes to</th><th>Protection</th><th>Erasure</th></tr></thead><tbody>{"".join(inventory_rows) or no_inventory}</tbody></table></div>
{more_inventory}
<h2>Obligation crosswalk</h2>
<div class="wrap"><table><thead><tr><th>Result</th><th>Obligation</th>{pack_heads}<th>Evidence</th></tr></thead><tbody>{"".join(obligation_rows)}</tbody></table></div>
<footer>{"<br>".join(_e(text) for text in data["disclaimers"])}</footer>
</main></body></html>
"""


def write_check_html(result: CheckResult, path: str, threshold: str = "high") -> None:
    Path(path).write_text(render_check_html(result, threshold), encoding="utf-8")


def write_check_pack(result: CheckResult, directory: str, threshold: str = "high") -> Dict[str, str]:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "json": out / "privacy-check.json",
        "markdown": out / "privacy-check.md",
        "pr_comment": out / "pr-comment.md",
        "html": out / "privacy-check.html",
        "sarif": out / "privacy-check.sarif",
        "matrix": out / "compliance-matrix.csv",
        "record": out / "processing-record.csv",
        "inventory": out / "data-inventory.csv",
    }
    write_check_json(result, str(files["json"]))
    files["markdown"].write_text(check_markdown(result, threshold), encoding="utf-8")
    files["pr_comment"].write_text(pr_comment_markdown(result, threshold), encoding="utf-8")
    write_check_html(result, str(files["html"]), threshold)
    write_check_sarif(result, str(files["sarif"]))
    write_matrix_csv(result, str(files["matrix"]))
    write_record_csv(result, str(files["record"]))
    write_inventory_csv(result.inventory, str(files["inventory"]))
    return {key: str(value) for key, value in files.items()}
