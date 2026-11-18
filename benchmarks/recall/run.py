"""Measure Svikruti's recall on seeded privacy leaks.

    python benchmarks/recall/run.py                       # seeds on their own
    python benchmarks/recall/run.py --into ../saleor      # seeds planted inside a copy of a real repository
    python benchmarks/recall/run.py --markdown out.md --json out.json

Every expectation in cases.yaml is one check. A positive check passes when
the scanner reports it; a trap (`none-*`) passes when the scanner stays quiet.
Planting the seeds inside a real repository tests that a large, noisy
codebase does not hide them (wrapper resolution, vendor detection and
inventory all run repository-wide).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

HERE = Path(__file__).resolve().parent
SEED_ROOT = "svk_recall_seeds"
LINE_TOLERANCE = (-1, 3)  # evidence may sit on the statement's first line or a few lines into it


def _language(case_id: str) -> str:
    return {"py": "Python", "js": "JavaScript", "ts": "TypeScript", "go": "Go", "java": "Java", "rb": "Ruby", "php": "PHP", "cs": "C#"}[case_id.split("-")[0]]


def plant(cases: List[Dict[str, Any]], root: Path) -> None:
    for case in cases:
        files = {case["path"]: case["code"], **(case.get("extra_files") or {})}
        for rel, text in files.items():
            target = root / SEED_ROOT / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            # Seeds reference each other by their own paths (from app.py.sms_gateway import ...).
            target.write_text(text.replace("app.py.", f"{SEED_ROOT}.app.py."), encoding="utf-8")


def _line_of(root: Path, rel: str, needle: str) -> int:
    lines = (root / SEED_ROOT / rel).read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        if needle in line:
            return number
    raise ValueError(f"{rel}: marker {needle!r} not found")


def evaluate(cases: List[Dict[str, Any]], root: Path) -> List[Dict[str, Any]]:
    sys.path.insert(0, str(HERE.parents[1] / "src"))
    from svikruti.pac.inventory import build_inventory
    from svikruti.scanner.runner import run_scan

    scan = run_scan(str(root), None)
    inventory = build_inventory(scan)
    by_file: Dict[str, List[Any]] = defaultdict(list)
    for item in scan.evidence:
        if item.file:
            by_file[item.file.replace("\\", "/")].append(item)
    rows = {(row["file"], row["field"]): row for row in inventory}
    stores = {}
    for row in inventory:
        stores.setdefault((row["file"], row["store"]), row)

    results = []
    for case in cases:
        rel = f"{SEED_ROOT}/{case['path']}"
        evidence = by_file.get(rel, [])
        for expect in case["expect"]:
            kind = expect["type"]
            ok, got = False, ""
            if kind in {"log", "flow"}:
                line = _line_of(root, case["path"], expect["at"])
                low, high = line + LINE_TOLERANCE[0], line + LINE_TOLERANCE[1]
                matches = [
                    item
                    for item in evidence
                    if item.line is not None
                    and low <= item.line <= high
                    and str(item.metadata.get("data_category")) == expect["category"]
                    and (("log" in item.kind) if kind == "log" else (item.kind == "processor_data_flow" and item.metadata.get("third_party") == expect["vendor"]))
                ]
                ok = bool(matches)
                got = ", ".join(sorted({f"{item.kind}:{item.metadata.get('data_category')}@{item.line}" for item in evidence if ("log" in item.kind or item.kind == "processor_data_flow")}))
            elif kind == "vendor":
                vendors = {str(item.metadata.get("third_party")) for item in evidence if item.metadata.get("third_party")}
                ok, got = expect["vendor"] in vendors, ", ".join(sorted(vendors))
            elif kind == "none-log":
                hits = [f"{item.metadata.get('data_category')}@{item.line}" for item in evidence if "log" in item.kind]
                ok, got = not hits, ", ".join(hits)
            elif kind == "none-flow":
                hits = [f"{item.metadata.get('third_party')}:{item.metadata.get('data_category')}@{item.line}" for item in evidence if item.kind == "processor_data_flow"]
                ok, got = not hits, ", ".join(hits)
            elif kind == "none-vendor":
                hits = sorted({str(item.metadata.get("third_party")) for item in evidence if item.metadata.get("third_party")})
                ok, got = not hits, ", ".join(hits)
            elif kind == "protection":
                row = rows.get((rel, expect["field"]))
                got = row["protection"] if row else "field not inventoried"
                ok = bool(row) and row["protection"] in expect["kinds"]
            elif kind == "erasure":
                row = stores.get((rel, expect["store"]))
                got = (row.get("erasure") or "not reached") if row else "store not inventoried"
                covered = bool(row and row.get("persistent") and row.get("erasure") and not row["erasure"].startswith("n/a"))
                ok = bool(row) and covered == expect["covered"]
            results.append(
                {
                    "case": case["id"],
                    "language": _language(case["id"]),
                    "type": kind,
                    "expect": {key: value for key, value in expect.items() if key != "type"},
                    "passed": ok,
                    "got": got,
                }
            )
    return results


def summarise(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    def rate(items: List[Dict[str, Any]]) -> Tuple[int, int]:
        return sum(1 for item in items if item["passed"]), len(items)

    positives = [r for r in results if not r["type"].startswith("none")]
    traps = [r for r in results if r["type"].startswith("none")]
    by_type = {kind: rate([r for r in positives if r["type"] == kind]) for kind in sorted({r["type"] for r in positives})}
    by_language = {lang: rate([r for r in positives if r["language"] == lang]) for lang in sorted({r["language"] for r in positives})}
    return {"recall": rate(positives), "traps": rate(traps), "by_type": by_type, "by_language": by_language}


def markdown(results: List[Dict[str, Any]], summary: Dict[str, Any], label: str) -> str:
    found, total = summary["recall"]
    quiet, traps = summary["traps"]
    lines = [
        f"### {label}",
        "",
        f"Recall: **{found}/{total}** expected findings reported ({100 * found / total:.0f}%). "
        f"Traps: **{quiet}/{traps}** stayed quiet.",
        "",
        "| By type | Found |",
        "|---|---|",
        *[f"| {kind} | {a}/{b} |" for kind, (a, b) in summary["by_type"].items()],
        "",
        "| By language | Found |",
        "|---|---|",
        *[f"| {lang} | {a}/{b} |" for lang, (a, b) in summary["by_language"].items()],
        "",
    ]
    misses = [r for r in results if not r["passed"]]
    if misses:
        lines += ["Missed or wrong:", "", "| Case | Expected | Got |", "|---|---|---|"]
        for miss in misses:
            expected = ", ".join(f"{k}={v}" for k, v in miss["expect"].items() if k != "at")
            lines.append(f"| {miss['case']} | {miss['type']} {expected} | {str(miss['got'] or '-').replace('|', '/')} |")
        lines.append("")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", default=str(HERE / "cases.yaml"))
    parser.add_argument("--into", help="Plant the seeds inside a copy of this repository.")
    parser.add_argument("--json", help="Write per-check results as JSON.")
    parser.add_argument("--markdown", help="Write a Markdown summary.")
    parser.add_argument("--label", help="Heading for the Markdown summary.")
    args = parser.parse_args(argv)

    cases = yaml.safe_load(Path(args.cases).read_text(encoding="utf-8"))["cases"]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        if args.into:
            shutil.copytree(args.into, root, ignore=shutil.ignore_patterns(".git", "node_modules", ".venv", "__pycache__"))
        else:
            root.mkdir()
        plant(cases, root)
        results = evaluate(cases, root)
    summary = summarise(results)
    label = args.label or (f"Seeds planted in {Path(args.into).name}" if args.into else "Seeds on their own")
    text = markdown(results, summary, label)
    print(text)
    if args.markdown:
        Path(args.markdown).write_text(text, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")
    counts = Counter(r["passed"] for r in results)
    return 0 if counts[False] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
