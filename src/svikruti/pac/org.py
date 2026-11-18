"""`svikruti org`: one privacy picture across many repositories.

Each service keeps its own privacy.yaml and runs `svikruti check` in CI. The
privacy team needs the union: one record of processing, one processor
register, one data inventory, and the framework posture of the whole estate.
This merges `privacy-check.json` files (CI artifacts) or repository
directories into that view, and flags what only shows up across repositories:

* a processor declared with different countries, contracts or transfer
  mechanisms in different services;
* a processor one service uses without declaring it while another service
  already has it on record (copy the record across);
* the data each AI provider receives across the estate;
* high-risk stored data with no protection, and stores no erasure path reaches.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from svikruti import __version__
from svikruti.pac.taxonomy import SEVERITY_ORDER, at_least, category_label, slugify

ORG_SCHEMA_VERSION = "svikruti-org-v1"
CHECK_SCHEMA_VERSION = "svikruti-privacy-check-v1"
# When repositories disagree, the worst status wins.
_STATUS_RANK = {"fail": 5, "manual": 4, "attested": 3, "pass": 2, "not_applicable": 1}


class OrgInputError(ValueError):
    pass


@dataclass
class RepoResult:
    name: str
    source: str
    data: Dict[str, Any]

    @property
    def open_findings(self) -> List[Dict[str, Any]]:
        return [item for item in self.data.get("findings", []) if item.get("status", "open") == "open"]


@dataclass
class OrgResult:
    repos: List[RepoResult]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    skipped: List[str] = field(default_factory=list)

    # ---------------------------------------------------------------- findings
    def findings(self) -> List[Dict[str, Any]]:
        rows = []
        for repo in self.repos:
            for item in repo.open_findings:
                rows.append(dict(item, repo=repo.name))
        rows.sort(key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), 0), item["repo"], item.get("rule", "")))
        return rows

    def gating(self, threshold: str) -> List[Dict[str, Any]]:
        return [item for item in self.findings() if at_least(str(item.get("severity", "LOW")), threshold)]

    # -------------------------------------------------------------- frameworks
    def frameworks(self) -> List[Dict[str, Any]]:
        """Per framework clause: the worst status across repositories, and which repositories fail it."""
        clauses: Dict[Tuple[str, str], Dict[str, Any]] = {}
        names: Dict[str, str] = {}
        for repo in self.repos:
            for item in repo.data.get("frameworks", []):
                names[item["id"]] = item.get("short_name") or item["id"]
            for row in repo.data.get("matrix", []):
                key = (row["framework"], row["ref"])
                entry = clauses.setdefault(
                    key,
                    {"framework": row["framework"], "ref": row["ref"], "control": row.get("control", ""), "obligations": set(), "status": "not_applicable", "failing": set(), "unverified": set()},
                )
                entry["obligations"].add(row["obligation"])
                if _STATUS_RANK[row["status"]] > _STATUS_RANK[entry["status"]]:
                    entry["status"] = row["status"]
                if row["status"] == "fail":
                    entry["failing"].add(repo.name)
                elif row["status"] == "manual":
                    entry["unverified"].add(repo.name)
        summaries = []
        for framework_id in sorted({key[0] for key in clauses}):
            rows = [entry for key, entry in clauses.items() if key[0] == framework_id]
            counts = {status: sum(1 for entry in rows if entry["status"] == status) for status in _STATUS_RANK}
            summaries.append(
                {
                    "id": framework_id,
                    "short_name": names.get(framework_id, framework_id),
                    "clauses": len(rows),
                    "counts": counts,
                    "rows": sorted(
                        (
                            dict(entry, obligations=sorted(entry["obligations"]), failing=sorted(entry["failing"]), unverified=sorted(entry["unverified"]))
                            for entry in rows
                        ),
                        key=lambda entry: (-_STATUS_RANK[entry["status"]], entry["ref"]),
                    ),
                }
            )
        return summaries

    # ------------------------------------------------------------ processors
    def processors(self) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        display: Dict[str, str] = {}
        for repo in self.repos:
            for activity in repo.data.get("activities", []):
                for name in [flow["processor"] for flow in activity.get("detected_flows", [])] + list(activity.get("detected_processors", [])):
                    display.setdefault(slugify(name), name)
        for repo in self.repos:
            for processor in repo.data.get("processors", []):
                entry = merged.setdefault(
                    slugify(processor["id"]),
                    {"id": processor["id"], "name": processor.get("name") or processor["id"], "declared_in": [], "used_undeclared_in": [], "records": {}, "categories_declared": set(), "categories_sent": set(), "ai_provider": False},
                )
                entry["declared_in"].append(repo.name)
                entry["records"][repo.name] = {key: processor.get(key, "") for key in ("purpose", "country", "contract", "transfer_mechanism")}
                entry["categories_declared"].update(processor.get("data_categories") or [])
                entry["ai_provider"] = entry["ai_provider"] or bool(processor.get("ai_provider"))
            for slug, categories in ((repo.data.get("summary") or {}).get("detected_flows") or {}).items():
                entry = merged.setdefault(
                    slug,
                    {"id": slug, "name": display.get(slug, slug), "declared_in": [], "used_undeclared_in": [], "records": {}, "categories_declared": set(), "categories_sent": set(), "ai_provider": False},
                )
                entry["categories_sent"].update(categories)
            for finding in repo.open_findings:
                if finding.get("rule") == "D003" and finding.get("processor"):
                    entry = merged.setdefault(
                        slugify(finding["processor"]),
                        {"id": finding["processor"], "name": display.get(slugify(finding["processor"]), finding["processor"]), "declared_in": [], "used_undeclared_in": [], "records": {}, "categories_declared": set(), "categories_sent": set(), "ai_provider": False},
                    )
                    if repo.name not in entry["used_undeclared_in"] and repo.name not in entry["declared_in"]:
                        entry["used_undeclared_in"].append(repo.name)
        out = []
        for entry in merged.values():
            issues = []
            for key, label in (("country", "country"), ("contract", "contract"), ("transfer_mechanism", "transfer mechanism")):
                values = {record[key] for record in entry["records"].values() if record.get(key) and not str(record[key]).upper().startswith("TODO")}
                if len(values) > 1:
                    issues.append(f"{label} differs across repositories: {', '.join(sorted(values))}")
            missing_contract = [repo for repo, record in entry["records"].items() if not record.get("contract") or str(record["contract"]).upper().startswith("TODO")]
            if missing_contract and len(missing_contract) < len(entry["records"]):
                issues.append(f"no contract recorded in {', '.join(missing_contract)} although other repositories have one")
            if entry["used_undeclared_in"] and entry["declared_in"]:
                issues.append(f"used without a record in {', '.join(entry['used_undeclared_in'])}; already declared in {', '.join(entry['declared_in'])}")
            elif entry["used_undeclared_in"]:
                issues.append(f"used without a record in {', '.join(entry['used_undeclared_in'])}; declared nowhere")
            countries = sorted({record["country"] for record in entry["records"].values() if record.get("country") and not str(record["country"]).upper().startswith("TODO")})
            out.append(
                {
                    "id": entry["id"],
                    "name": entry["name"],
                    "ai_provider": entry["ai_provider"],
                    "declared_in": sorted(entry["declared_in"]),
                    "used_undeclared_in": sorted(entry["used_undeclared_in"]),
                    "countries": countries,
                    "contracts": sorted({record["contract"] for record in entry["records"].values() if record.get("contract") and not str(record["contract"]).upper().startswith("TODO")}),
                    "categories_declared": sorted(entry["categories_declared"]),
                    "categories_sent": sorted(category_label(slug) for slug in entry["categories_sent"]),
                    "issues": issues,
                }
            )
        out.sort(key=lambda item: (not item["issues"], not item["ai_provider"], item["name"].lower()))
        return out

    # ------------------------------------------------------------- inventory
    def inventory(self) -> List[Dict[str, Any]]:
        rows = []
        for repo in self.repos:
            for row in repo.data.get("inventory", []):
                rows.append(dict(row, repo=repo.name))
        return rows

    def data_map(self) -> List[Dict[str, Any]]:
        """Per data category: where it is stored, who receives it, and what is unprotected or unerasable."""
        categories: Dict[str, Dict[str, Any]] = {}
        for repo in self.repos:
            for activity in repo.data.get("activities", []):
                for label in set(activity.get("declared_categories", [])) | set(activity.get("detected_categories", [])):
                    entry = categories.setdefault(label, {"category": label, "repos": set(), "activities": set(), "stores": set(), "processors": set(), "ai_providers": set(), "unprotected_high_risk": set(), "no_erasure": set(), "in_logs": set()})
                    entry["repos"].add(repo.name)
                    entry["activities"].add(f"{repo.name}:{activity['id']}")
                    if label in activity.get("logged_categories", []):
                        entry["in_logs"].add(repo.name)
                for flow in activity.get("detected_flows", []):
                    for label in flow["categories"]:
                        entry = categories.setdefault(label, {"category": label, "repos": set(), "activities": set(), "stores": set(), "processors": set(), "ai_providers": set(), "unprotected_high_risk": set(), "no_erasure": set(), "in_logs": set()})
                        entry["processors"].add(flow["processor"])
            ai_names = {processor.get("name") for processor in repo.data.get("processors", []) if processor.get("ai_provider")}
            for row in repo.data.get("inventory", []):
                if not row.get("persistent"):
                    continue
                entry = categories.setdefault(row["data_category"], {"category": row["data_category"], "repos": set(), "activities": set(), "stores": set(), "processors": set(), "ai_providers": set(), "unprotected_high_risk": set(), "no_erasure": set(), "in_logs": set()})
                store = f"{repo.name}:{row['store']}"
                entry["repos"].add(repo.name)
                entry["stores"].add(store)
                if row.get("high_risk") and row.get("protection") not in {"encrypted", "tokenised", "hashed", "masked"}:
                    entry["unprotected_high_risk"].add(f"{store}.{row['field']}")
                if not row.get("erasure"):
                    entry["no_erasure"].add(store)
            for entry in categories.values():
                entry["ai_providers"].update(name for name in entry["processors"] if name in ai_names)
        out = [{key: (sorted(value) if isinstance(value, set) else value) for key, value in entry.items()} for entry in categories.values()]
        out.sort(key=lambda item: (-len(item["repos"]), item["category"]))
        return out

    # ----------------------------------------------------------------- export
    def to_dict(self) -> Dict[str, Any]:
        findings = self.findings()
        return {
            "schema_version": ORG_SCHEMA_VERSION,
            "generated_at": self.generated_at,
            "svikruti_version": __version__,
            "repositories": [
                {
                    "name": repo.name,
                    "source": repo.source,
                    "organization": repo.data.get("organization", {}),
                    "generated_at": repo.data.get("generated_at"),
                    "activities": (repo.data.get("summary") or {}).get("activities", 0),
                    "processors": (repo.data.get("summary") or {}).get("processors", 0),
                    "open_findings": len(repo.open_findings),
                    "open_by_severity": (repo.data.get("summary") or {}).get("open_by_severity", {}),
                    "frameworks": {item["id"]: {"verified": item["counts"]["pass"], "applicable": item["applicable"], "failing": item["counts"]["fail"]} for item in repo.data.get("frameworks", [])},
                }
                for repo in self.repos
            ],
            "summary": {
                "repositories": len(self.repos),
                "activities": sum((repo.data.get("summary") or {}).get("activities", 0) for repo in self.repos),
                "open_findings": len(findings),
                "open_by_severity": {level: sum(1 for item in findings if item.get("severity") == level) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "stored_fields": len(self.inventory()),
            },
            "frameworks": self.frameworks(),
            "activities": [
                {key: value for key, value in dict(activity, repo=repo.name).items() if key not in {"files"}}
                for repo in self.repos
                for activity in repo.data.get("activities", [])
            ],
            "processors": self.processors(),
            "data_map": self.data_map(),
            "findings": findings,
            "skipped": self.skipped,
        }


# ------------------------------------------------------------------ loading
def _repo_name(path: Path, data: Dict[str, Any]) -> str:
    repo = data.get("repo")
    if repo and repo not in {".", "./"}:
        return Path(repo).resolve().name if Path(repo).exists() else Path(repo).name
    # privacy-check.json usually sits in <repo>/svikruti-check/ or an artifact folder named after the repo
    parent = path.parent
    if parent.name in {"svikruti-check", "privacy-check", "out", "artifacts"}:
        parent = parent.parent
    return parent.name or path.stem


def load_inputs(paths: List[str], names: Optional[List[str]] = None) -> OrgResult:
    """Accept privacy-check.json files, directories holding one, or repositories with privacy.yaml."""
    repos: List[RepoResult] = []
    skipped: List[str] = []
    for index, raw in enumerate(paths):
        path = Path(raw)
        label = names[index] if names and index < len(names) and names[index] else None
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("schema_version") != CHECK_SCHEMA_VERSION:
                raise OrgInputError(f"{path}: not a privacy-check.json ({CHECK_SCHEMA_VERSION}); got {data.get('schema_version')!r}")
            repos.append(RepoResult(label or _repo_name(path, data), str(path), data))
            continue
        if path.is_dir():
            for candidate in (path / "privacy-check.json", path / "svikruti-check" / "privacy-check.json"):
                if candidate.is_file():
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                    repos.append(RepoResult(label or path.resolve().name, str(candidate), data))
                    break
            else:
                from svikruti.pac.manifest import find_manifest

                manifest = find_manifest(str(path))
                if manifest is None:
                    skipped.append(f"{path}: no privacy-check.json and no privacy.yaml; run `svikruti init` there first")
                    continue
                repos.append(RepoResult(label or path.resolve().name, str(path), _check_repo(path, manifest)))
            continue
        raise OrgInputError(f"{path}: no such file or directory")
    seen: Dict[str, int] = {}
    for repo in repos:
        seen[repo.name] = seen.get(repo.name, 0) + 1
        if seen[repo.name] > 1:
            repo.name = f"{repo.name}-{seen[repo.name]}"
    if not repos:
        raise OrgInputError("no repositories to aggregate" + (": " + "; ".join(skipped) if skipped else ""))
    return OrgResult(repos=repos, skipped=skipped)


def _check_repo(path: Path, manifest_path: Path) -> Dict[str, Any]:
    from svikruti.pac.engine import run_check
    from svikruti.pac.manifest import load_manifest
    from svikruti.scanner.runner import run_scan

    result = run_check(run_scan(str(path), None), load_manifest(manifest_path))
    return result.to_dict()


# ------------------------------------------------------------------ reports
def _processor_name(item: Any) -> str:
    return str(item.get("name", "")) if isinstance(item, dict) else str(item)


def _md(value: object) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def org_markdown(org: OrgResult, threshold: str = "high") -> str:
    data = org.to_dict()
    summary = data["summary"]
    gating = org.gating(threshold) if threshold != "none" else []
    lines = [
        "# Svikruti organisation privacy report",
        "",
        f"{summary['repositories']} repositories, {summary['activities']} processing activities, {summary['stored_fields']} stored personal-data fields, "
        f"{summary['open_findings']} open findings ({', '.join(f'{count} {level.lower()}' for level, count in summary['open_by_severity'].items() if count) or 'none'}).",
        "",
    ]
    if threshold != "none":
        lines += [f"**{'Blocked' if gating else 'Passed'}:** {len(gating)} finding(s) at {threshold.upper()} or above across the estate.", ""]
    lines += ["## Repositories", "", "| Repository | Activities | Open findings | " + " | ".join(item["short_name"] for item in data["frameworks"]) + " |", "|---|---|---|" + "---|" * len(data["frameworks"])]
    for repo in data["repositories"]:
        cells = []
        for framework in data["frameworks"]:
            stats = repo["frameworks"].get(framework["id"])
            cells.append(f"{stats['verified']}/{stats['applicable']} verified, {stats['failing']} failing" if stats else "-")
        lines.append(f"| {_md(repo['name'])} | {repo['activities']} | {repo['open_findings']} | " + " | ".join(cells) + " |")
    lines += ["", "## Framework posture (worst status per clause across repositories)", ""]
    for framework in data["frameworks"]:
        counts = framework["counts"]
        lines.append(f"- **{framework['short_name']}**: {counts['pass']} verified everywhere, {counts['attested']} attested, {counts['fail']} failing somewhere, {counts['manual']} not verified ({framework['clauses']} clauses)")
        failing = [row for row in framework["rows"] if row["status"] == "fail"][:8]
        for row in failing:
            lines.append(f"  - {_md(row['ref'])} {_md(row['control'])}: failing in {', '.join(row['failing'])}")
    lines += ["", "## Processor register", "", "| Processor | AI | Declared in | Used without record in | Countries | Data sent | Issues |", "|---|---|---|---|---|---|---|"]
    for item in data["processors"]:
        lines.append(
            f"| {_md(item['name'])} | {'yes' if item['ai_provider'] else ''} | {_md(', '.join(item['declared_in']))} | {_md(', '.join(item['used_undeclared_in']))} | "
            f"{_md(', '.join(item['countries']))} | {_md(', '.join(item['categories_sent']))} | {_md('; '.join(item['issues']))} |"
        )
    lines += ["", "## Data map", "", "| Category | Repositories | Stored in | Sent to | Unprotected high-risk fields | Stores with no erasure path | In logs |", "|---|---|---|---|---|---|---|"]
    for item in data["data_map"]:
        lines.append(
            f"| {_md(item['category'])} | {len(item['repos'])} | {_md(', '.join(item['stores']))} | {_md(', '.join(item['processors']))} | "
            f"{_md(', '.join(item['unprotected_high_risk']))} | {_md(', '.join(item['no_erasure']))} | {_md(', '.join(item['in_logs']))} |"
        )
    findings = data["findings"]
    lines += ["", f"## Open findings ({len(findings)})", ""]
    if findings:
        lines += ["| Severity | Repository | Rule | Finding | Where |", "|---|---|---|---|---|"]
        for item in findings[:200]:
            where = (item.get("refs") or ["privacy.yaml"])[0]
            lines.append(f"| {item['severity']} | {_md(item['repo'])} | {item['rule']} | {_md(item['detail'])} | `{_md(where)}` |")
        if len(findings) > 200:
            lines.append(f"\n...and {len(findings) - 200} more in findings.csv.")
    else:
        lines.append("None.")
    if data["skipped"]:
        lines += ["", "## Skipped", ""] + [f"- {_md(item)}" for item in data["skipped"]]
    lines += ["", f"_Generated by Svikruti {__version__}. Evidence from static analysis of each repository; obligations it cannot see are marked not verified. Not legal advice._", ""]
    return "\n".join(lines)


def _chips(values: List[str], cls: str = "") -> str:
    from svikruti.pac.report import _e

    css = f"chip {cls}".strip()
    return "".join(f'<span class="{css}">{_e(value)}</span>' for value in values)


def render_org_html(org: OrgResult, threshold: str = "high") -> str:
    from svikruti.pac.report import _CSS, _e, _pill

    data = org.to_dict()
    summary = data["summary"]
    gating = org.gating(threshold) if threshold != "none" else []
    verdict = ""
    if threshold != "none":
        verdict = (
            f'<div class="verdict bad">Blocked: {len(gating)} finding(s) at {_e(threshold.upper())} or above across the estate</div>'
            if gating
            else f'<div class="verdict ok">Passed: no findings at {_e(threshold.upper())} or above in any repository</div>'
        )
    cards = []
    for framework in data["frameworks"]:
        counts, total = framework["counts"], max(framework["clauses"] - framework["counts"]["not_applicable"], 1)
        width = lambda key: f"{100 * counts[key] / total:.1f}%"  # noqa: E731
        cards.append(
            f'<div class="card"><h3>{_e(framework["short_name"])}</h3><small>worst status per clause across {summary["repositories"]} repositories</small>'
            f'<div class="big">{counts["pass"]}/{total}</div><small>verified in every repository</small>'
            f'<div class="bar"><i class="p" style="width:{width("pass")}"></i><i class="a" style="width:{width("attested")}"></i><i class="f" style="width:{width("fail")}"></i></div>'
            f'<div class="legend">{counts["attested"]} attested, {counts["fail"]} failing somewhere, {counts["manual"]} not verified</div></div>'
        )
    repo_rows = []
    for repo in data["repositories"]:
        sev = repo["open_by_severity"] or {}
        badges = " ".join(_pill(level, f"{sev[level]} {level.lower()}") for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev.get(level)) or _pill("pass", "clean")
        frameworks = " ".join(
            f'<span class="chip">{_e(fw["short_name"])} {repo["frameworks"][fw["id"]]["verified"]}/{repo["frameworks"][fw["id"]]["applicable"]}</span>'
            for fw in data["frameworks"]
            if fw["id"] in repo["frameworks"]
        )
        repo_rows.append(f"<tr><td><b>{_e(repo['name'])}</b><div class=\"mute\">{_e(repo['source'])}</div></td><td>{repo['activities']}</td><td>{badges}</td><td>{frameworks}</td></tr>")
    proc_rows = []
    for item in data["processors"]:
        issues = _chips(item["issues"], "miss") or '<span class="mute">consistent</span>'
        ai = " " + _pill("MEDIUM", "AI") if item["ai_provider"] else ""
        declared = _chips(item["declared_in"]) or '<span class="mute">nowhere</span>'
        proc_rows.append(
            f"<tr><td><b>{_e(item['name'])}</b>{ai}</td><td>{declared}</td><td>{_chips(item['used_undeclared_in'], 'miss')}</td>"
            f"<td>{_e(', '.join(item['countries']))}</td><td>{_e(', '.join(item['categories_sent']))}</td><td>{issues}</td></tr>"
        )
    map_rows = []
    for item in data["data_map"]:
        map_rows.append(
            f"<tr><td><b>{_e(item['category'])}</b></td><td>{_chips(item['repos'])}</td><td>{_chips(item['stores'])}</td><td>{_chips(item['processors'])}</td>"
            f"<td>{_chips(item['unprotected_high_risk'], 'miss')}</td><td>{_chips(item['no_erasure'], 'miss')}</td><td>{_chips(item['in_logs'], 'miss')}</td></tr>"
        )
    finding_rows = []
    for item in data["findings"][:300]:
        refs = "<br>".join(f"<code>{_e(ref)}</code>" for ref in (item.get("refs") or [])[:3]) or "<code>privacy.yaml</code>"
        finding_rows.append(
            f"<tr><td>{_pill(item['severity'])}</td><td>{_e(item['repo'])}</td><td><b>{_e(item['rule'])}</b> {_e(item.get('title', ''))}<div>{_e(item['detail'])}</div>"
            f"<div class=\"mute\">{_e(item.get('fix', ''))}</div></td><td>{refs}</td></tr>"
        )
    failing_rows = []
    for framework in data["frameworks"]:
        for row in framework["rows"]:
            if row["status"] in {"fail", "manual"}:
                where = row["failing"] if row["status"] == "fail" else row["unverified"]
                failing_rows.append(
                    f"<tr><td>{_e(framework['short_name'])}</td><td><b>{_e(row['ref'])}</b> {_e(row['control'])}</td><td>{_pill(row['status'], 'failing' if row['status'] == 'fail' else 'not verified')}</td>"
                    f"<td>{_chips(where)}</td></tr>"
                )
    skipped = "".join(f"<li>{_e(item)}</li>" for item in data["skipped"])
    table = lambda head, rows, empty: (  # noqa: E731
        f'<div class="wrap"><table><tr>{"".join(f"<th>{h}</th>" for h in head)}</tr>{"".join(rows)}</table></div>' if rows else f'<p class="mute">{empty}</p>'
    )
    sev = summary["open_by_severity"]
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Svikruti organisation privacy report</title><style>{_CSS}</style></head><body><main>
<h1>Organisation privacy report</h1>
<p class="sub">{summary['repositories']} repositories, {summary['activities']} processing activities, {summary['stored_fields']} stored personal-data fields, {summary['open_findings']} open findings
({sev['CRITICAL']} critical, {sev['HIGH']} high, {sev['MEDIUM']} medium, {sev['LOW']} low). Generated {_e(data['generated_at'][:19].replace('T', ' '))} UTC.</p>
{verdict}
<div class="grid">{''.join(cards)}</div>
<h2>Repositories</h2>{table(['Repository', 'Activities', 'Open findings', 'Frameworks (verified/applicable)'], repo_rows, 'No repositories.')}
<h2>Processor register</h2><p class="mute">One row per vendor across the estate. Conflicting country, contract or transfer records, and services that use a vendor without recording it, are flagged.</p>
{table(['Processor', 'Declared in', 'Used without record in', 'Countries', 'Data sent (from code)', 'Issues'], proc_rows, 'No processors declared or detected.')}
<h2>Data map</h2><p class="mute">Per data category: which services hold it, where it is stored, who receives it, and the gaps a DSAR or breach would hit.</p>
{table(['Category', 'Repositories', 'Stored in', 'Sent to', 'Unprotected high-risk fields', 'No erasure path', 'Reaches logs'], map_rows, 'No personal data found.')}
<h2>Clauses failing or not verified somewhere</h2>{table(['Framework', 'Clause', 'Status', 'Repositories'], failing_rows, 'Every applicable clause is verified or attested in every repository.')}
<h2>Open findings</h2>{table(['Severity', 'Repository', 'Finding', 'Where'], finding_rows, 'No open findings.')}
{f'<h2>Skipped</h2><ul>{skipped}</ul>' if skipped else ''}
<footer>Generated by Svikruti {_e(__version__)} from each repository's privacy.yaml and code. Static analysis cannot see runtime configuration, data outside the repositories, or contracts; those obligations are marked not verified. Not legal advice.</footer>
</main></body></html>"""


def write_org_pack(org: OrgResult, directory: str, threshold: str = "high") -> Dict[str, str]:
    from svikruti.reports.exports import _join, _write_rows

    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    data = org.to_dict()
    files = {
        "json": str(out / "org-summary.json"),
        "html": str(out / "org-report.html"),
        "markdown": str(out / "org-report.md"),
        "record": str(out / "org-processing-record.csv"),
        "processors": str(out / "processor-register.csv"),
        "inventory": str(out / "data-inventory.csv"),
        "findings": str(out / "findings.csv"),
        "matrix": str(out / "framework-matrix.csv"),
    }
    Path(files["json"]).write_text(json.dumps(data, indent=2), encoding="utf-8")
    Path(files["html"]).write_text(render_org_html(org, threshold), encoding="utf-8")
    Path(files["markdown"]).write_text(org_markdown(org, threshold), encoding="utf-8")
    record_rows = []
    for repo in org.repos:
        organization = repo.data.get("organization") or {}
        for activity in repo.data.get("activities", []):
            record_rows.append(
                [
                    repo.name, organization.get("name", ""), activity["id"], activity.get("name", ""), activity.get("owner", ""),
                    _join(activity.get("purposes")), activity.get("legal_basis", ""), _join(activity.get("data_subjects")),
                    _join(sorted(set(activity.get("declared_categories", [])) | set(activity.get("detected_categories", [])))),
                    _join(sorted({_processor_name(item) for item in activity.get("declared_processors", [])} | set(activity.get("detected_processors", [])))),
                    activity.get("retention", ""), activity.get("dpia", ""), "yes" if activity.get("in_sync") else "no", _join(activity.get("open_rules")),
                ]
            )
    _write_rows(
        files["record"],
        ["repository", "controller", "activity_id", "activity", "owner", "purposes", "legal_basis", "data_subjects", "data_categories", "recipients", "retention", "dpia", "code_matches_record", "open_rules"],
        record_rows,
    )
    _write_rows(
        files["processors"],
        ["processor", "ai_provider", "declared_in", "used_without_record_in", "countries", "categories_declared", "categories_sent_in_code", "issues"],
        [[item["name"], "yes" if item["ai_provider"] else "", _join(item["declared_in"]), _join(item["used_undeclared_in"]), _join(item["countries"]), _join(item["categories_declared"]), _join(item["categories_sent"]), _join(item["issues"])] for item in data["processors"]],
    )
    _write_rows(
        files["inventory"],
        ["repository", "store", "field", "data_category", "high_risk", "persistent", "protection", "erasure", "reaches_logs", "sent_to", "activity", "retention", "file", "line"],
        [
            [row["repo"], row.get("store", ""), row.get("field", ""), row.get("data_category", ""), "yes" if row.get("high_risk") else "", "yes" if row.get("persistent") else "",
             row.get("protection", ""), row.get("erasure", ""), "yes" if row.get("reaches_logs") else "", _join(row.get("sent_to")), row.get("activity", ""), row.get("retention", ""), row.get("file", ""), row.get("line", "")]
            for row in org.inventory()
        ],
    )
    _write_rows(
        files["findings"],
        ["repository", "severity", "rule", "title", "detail", "fix", "activity", "category", "processor", "where", "fingerprint"],
        [[item["repo"], item["severity"], item["rule"], item.get("title", ""), item.get("detail", ""), item.get("fix", ""), item.get("activity", ""), item.get("category", ""), item.get("processor", ""), _join(item.get("refs")), item.get("fingerprint", "")] for item in data["findings"]],
    )
    _write_rows(
        files["matrix"],
        ["framework", "clause", "control", "status", "failing_in", "not_verified_in", "obligations"],
        [[framework["short_name"], row["ref"], row["control"], row["status"], _join(row["failing"]), _join(row["unverified"]), _join(row["obligations"])] for framework in data["frameworks"] for row in framework["rows"]],
    )
    return files
