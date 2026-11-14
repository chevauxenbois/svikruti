import json
import shutil
import tempfile
import unittest
from datetime import date
from pathlib import Path

from svikruti.cli import main
from svikruti.pac.engine import run_check
from svikruti.pac.fingerprint import diff_reports
from svikruti.pac.frameworks import PackError, builtin_pack_ids, load_pack
from svikruti.pac.generate import generate_manifest
from svikruti.pac.globs import match_path
from svikruti.pac.manifest import ManifestError, load_manifest, parse_manifest
from svikruti.pac.obligations import OBLIGATIONS
from svikruti.pac.report import check_markdown, render_check_html, write_check_pack
from svikruti.scanner.runner import run_scan

EXAMPLE = Path("examples/privacy-as-code")
DRIFT_FILE = Path("examples/pac-scenarios/refund.js")
TODAY = date(2026, 11, 13)


def _copy_example(tmp: str) -> Path:
    target = Path(tmp) / "repo"
    shutil.copytree(EXAMPLE, target)
    return target


def _check(repo: Path, baseline=None, today=TODAY, notice=True):
    scan = run_scan(str(repo), None, privacy_file=str(repo / "privacy-notice.md") if notice else None)
    return run_check(scan, load_manifest(repo / "privacy.yaml"), baseline=baseline, today=today)


def _rules(result):
    return sorted({finding.rule for finding in result.open_findings()})


def _edit_manifest(repo: Path, old: str, new: str) -> None:
    path = repo / "privacy.yaml"
    text = path.read_text(encoding="utf-8")
    assert old in text, old
    path.write_text(text.replace(old, new), encoding="utf-8")


class GlobTests(unittest.TestCase):
    def test_glob_semantics(self):
        self.assertTrue(match_path("services/payments/checkout.js", "services/payments/**"))
        self.assertTrue(match_path("services/payments/a/b.js", "services/**/*.js"))
        self.assertTrue(match_path("services/payments/checkout.js", "services/payments"))
        self.assertTrue(match_path("web/signup.tsx", "web/*.tsx"))
        self.assertFalse(match_path("web/forms/signup.tsx", "web/*.tsx"))
        self.assertFalse(match_path("services/payments_v2/x.js", "services/payments"))
        self.assertTrue(match_path("a.py", "*"))
        self.assertFalse(match_path("src/a.py", "*"))


class ManifestTests(unittest.TestCase):
    def test_example_manifest_loads(self):
        manifest = load_manifest(EXAMPLE / "privacy.yaml")
        self.assertEqual([a.id for a in manifest.activities], ["applicant_onboarding", "repayments", "reminders"])
        self.assertEqual(manifest.activities[0].basis_for("gdpr"), "legal_obligation")
        self.assertEqual(manifest.activities[0].basis_for("dpdpa"), "consent")
        self.assertEqual(manifest.warnings, [])

    def test_validation_reports_every_problem_at_once(self):
        with self.assertRaises(ManifestError) as caught:
            parse_manifest(
                {
                    "version": 1,
                    "processing_activities": [
                        {"id": "a", "paths": [], "processors": ["ghost"]},
                        {"id": "a", "paths": ["x/**"]},
                    ],
                    "policies": {"personal_data_in_logs": "maybe"},
                    "exceptions": [{"rule": "P001", "reason": "short"}],
                    "attestations": [{"obligation": "OBL-21", "statement": "TODO", "reviewed": "yesterday"}],
                }
            )
        text = " | ".join(caught.exception.errors)
        for expected in ("at least one path glob", "'ghost' is not defined", "duplicate activity id", "personal_data_in_logs", "real justification", "scope the exception", "ISO date", "what is in place"):
            self.assertIn(expected, text)

    def test_unknown_keys_are_warnings_not_errors(self):
        manifest = parse_manifest({"version": 1, "processing_activites": [], "processing_activities": [{"id": "a", "paths": ["a/**"], "purpose": "typo"}]})
        self.assertEqual(len(manifest.warnings), 2)

    def test_future_manifest_version_is_rejected(self):
        with self.assertRaises(ManifestError):
            parse_manifest({"version": 2})


class FrameworkPackTests(unittest.TestCase):
    def test_builtin_packs_map_every_obligation(self):
        obligation_ids = {item["id"] for item in OBLIGATIONS}
        self.assertEqual(builtin_pack_ids(), ["dpdpa", "gdpr", "iso27701"])
        for pack_id in builtin_pack_ids():
            pack = load_pack(pack_id)
            self.assertEqual(set(pack.controls), obligation_ids, pack_id)
            for refs in pack.controls.values():
                for control in refs:
                    self.assertTrue(control["ref"] and control["title"])

    def test_iso_pack_carries_2019_legacy_numbers(self):
        pack = load_pack("iso27701")
        record = pack.refs("OBL-01")[0]
        self.assertEqual((record["ref"], record["legacy"]), ("A.1.2.9", "A.7.2.8"))

    def test_custom_pack_and_unknown_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "internal.yaml"
            path.write_text("id: acme\nname: Acme Privacy Standard\ncontrols:\n  OBL-06:\n    - {ref: 'APS-4.2', title: 'No PII in logs'}\n", encoding="utf-8")
            pack = load_pack(str(path))
            self.assertEqual(pack.id, "acme")
            self.assertFalse(pack.builtin)
            repo = _copy_example(tmp)
            scan = run_scan(str(repo), None)
            result = run_check(scan, load_manifest(repo / "privacy.yaml"), frameworks=["gdpr", str(path)], today=TODAY)
            self.assertEqual([p.id for p in result.packs], ["gdpr", "acme"])
            self.assertEqual(result.framework_summary(result.packs[1])["obligations"], 1)
        with self.assertRaises(PackError):
            load_pack("hipaa")


class ReconcileTests(unittest.TestCase):
    def test_complete_example_is_in_sync_and_passes(self):
        result = _check(EXAMPLE)
        self.assertEqual(result.open_findings(), [])
        statuses = {a.id: a.status for a in result.assessments}
        self.assertNotIn("fail", statuses.values())
        self.assertEqual(statuses["OBL-01"], "pass")
        self.assertEqual(statuses["OBL-07"], "pass")
        self.assertEqual(statuses["OBL-11"], "not_applicable")
        self.assertEqual(statuses["OBL-21"], "attested")
        for pack in result.packs:
            summary = result.framework_summary(pack)
            self.assertEqual(summary["counts"]["fail"], 0)
            self.assertEqual(summary["covered_percent"], 100)
        self.assertTrue(all(activity["in_sync"] for activity in result.activities_view))

    def test_manifest_is_never_scanned_as_code(self):
        result = _check(EXAMPLE)
        self.assertNotIn("privacy.yaml", result.model.files)
        self.assertFalse(any(item.file == "privacy.yaml" for item in result.scan.evidence))

    def test_new_code_creates_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            result = _check(repo)
            by_rule = {finding.rule: finding for finding in result.open_findings()}
            self.assertEqual(sorted(by_rule), ["D002", "D003", "P001"])
            self.assertEqual(by_rule["D002"].category, "location")
            self.assertEqual(by_rule["D002"].activity, "repayments")
            self.assertEqual(by_rule["D003"].processor, "mixpanel")
            self.assertTrue(all("refund.js" in ref for ref in by_rule["P001"].refs))
            statuses = {a.id: a.status for a in result.assessments}
            for failing in ("OBL-01", "OBL-05", "OBL-06", "OBL-07", "OBL-08"):
                self.assertEqual(statuses[failing], "fail", failing)
            self.assertFalse(next(a for a in result.activities_view if a["id"] == "repayments")["in_sync"])

    def test_unmapped_code_is_shadow_processing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "services/analytics").mkdir()
            (repo / "services/analytics/export.py").write_text(
                "def export(request):\n    row = {'email': request.json['email'], 'aadhaar': request.json['aadhaar']}\n    db.insert(row)\n", encoding="utf-8"
            )
            result = _check(repo)
            finding = next(f for f in result.open_findings() if f.rule == "D001")
            self.assertEqual(finding.severity, "CRITICAL")
            self.assertIn("services/analytics/export.py", finding.detail)

    def test_stale_and_incomplete_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            _edit_manifest(repo, "data_categories: [contact, financial]", "data_categories: [contact, financial, location]")
            _edit_manifest(repo, 'retention: "Message logs kept 90 days"', "retention: TODO")
            _edit_manifest(repo, "    contract: DPA-2025-019\n", "    contract: TODO\n")
            _edit_manifest(repo, "legal_basis: {dpdpa: legitimate_use, gdpr: contract}", "legal_basis: {dpdpa: contract, gdpr: contract}")
            result = _check(repo)
            findings = {(f.rule, f.activity or f.processor): f for f in result.open_findings()}
            self.assertEqual(findings[("D004", "repayments")].severity, "LOW")
            self.assertEqual(findings[("D006", "reminders")].fields, ["retention"])
            self.assertEqual(findings[("D007", "msg91")].severity, "HIGH")
            self.assertIn("not a lawful basis under dpdpa", findings[("D006", "repayments")].detail)
            statuses = {a.id: a.status for a in result.assessments}
            self.assertEqual((statuses["OBL-03"], statuses["OBL-04"], statuses["OBL-08"]), ("fail", "fail", "fail"))
            self.assertEqual(statuses["OBL-02"], "pass")

    def test_policies_dpia_forbidden_and_transfers(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            _edit_manifest(repo, "    dpia: DPIA-2026-003\n", "")
            _edit_manifest(repo, "forbidden_categories: [health, children, biometric]", "forbidden_categories: [financial]")
            _edit_manifest(repo, "    country: IN\n    contract: DPA-2025-019", "    country: US\n    contract: DPA-2025-019")
            result = _check(repo)
            rules = _rules(result)
            self.assertEqual(rules, ["P002", "P003", "P004"])
            _edit_manifest(repo, "    contract: DPA-2025-019", "    contract: DPA-2025-019\n    transfer_mechanism: Standard Contractual Clauses")
            self.assertEqual(_rules(_check(repo)), ["P002", "P003"])

    def test_exception_suppresses_until_it_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            _edit_manifest(
                repo,
                "exceptions: []",
                "exceptions:\n  - rule: P001\n    activity: repayments\n    category: contact\n    reason: Refund emails are logged for chargeback disputes until masking ships.\n    approved_by: ciso\n    expires: 2026-12-31",
            )
            result = _check(repo)
            self.assertNotIn("P001", _rules(result))
            excepted = [f for f in result.findings if f.status == "excepted"]
            self.assertEqual(len(excepted), 1)
            self.assertIn("approved by ciso", excepted[0].exception_reason)
            expired = _check(repo, today=date(2027, 1, 15))
            self.assertIn("P001", _rules(expired))
            self.assertIn("P005", _rules(expired))

    def test_attestation_goes_stale_and_never_overrides_code(self):
        result = _check(EXAMPLE, today=date(2028, 6, 1))
        stale = next(a for a in result.assessments if a.id == "OBL-21")
        self.assertEqual(stale.status, "manual")
        self.assertIn("does not count", stale.summary)
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "services/payments/legacy.js").write_text('const hash = crypto.createHash("md5").update(card_number).digest("hex");\nfetch("http://internal-ledger.lendflow.example/api/customer?email=" + email);\n', encoding="utf-8")
            _edit_manifest(repo, "attestations:\n", "attestations:\n  - obligation: OBL-13\n    statement: All data is encrypted with strong cryptography.\n    owner: security\n    reviewed: 2026-11-01\n")
            result = _check(repo)
            crypto = next(a for a in result.assessments if a.id == "OBL-13")
            self.assertEqual(crypto.status, "fail")
            self.assertIn("the code wins", crypto.summary)

    def test_notice_not_supplied_is_manual_not_pass(self):
        result = _check(EXAMPLE, notice=False)
        self.assertEqual(next(a for a in result.assessments if a.id == "OBL-07").status, "manual")


class LogSinkPrecisionTests(unittest.TestCase):
    """The gate is only as good as P001's precision."""

    def _log_categories(self, source: str, name: str = "handler.py"):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / name).write_text(source, encoding="utf-8")
            scan = run_scan(tmp, None)
            return sorted({str(item.metadata.get("data_category")) for item in scan.evidence if "log" in item.kind})

    def test_logging_an_id_next_to_personal_data_is_clean(self):
        source = (
            "def create(request):\n"
            "    payload = request.json\n"
            "    user = User(email=payload['email'], aadhaar=payload['aadhaar'])\n"
            "    user.save()\n"
            "    logger.info('user created id=%s', user.id)\n"
        )
        self.assertEqual(self._log_categories(source), [])

    def test_logging_fields_directly_is_flagged(self):
        source = "def create(request):\n    email = request.json['email']\n    logger.info('signup %s', email)\n    print(f\"pan={request.json['pan_number']}\")\n"
        self.assertEqual(self._log_categories(source), ["Contact", "Government ID"])

    def test_logging_whole_payload_is_flagged_one_hop(self):
        source = "def create(request):\n    payload = {'email': request.json['email'], 'aadhaar': request.json['aadhaar']}\n    logger.debug(payload)\n"
        self.assertEqual(self._log_categories(source), ["Contact", "Government ID"])

    def test_personal_data_word_in_log_message_is_not_a_leak(self):
        prose = "def send(ping):\n    try:\n        deliver(ping)\n    except Exception:\n        logger.exception(f\"Exception while parsing email (ping {ping.id})\")\n        logger.error('could not send email')\n"
        self.assertEqual(self._log_categories(prose), [])
        self.assertEqual(self._log_categories("function f(u) {\n  console.log(`sending email to ${u.email}`);\n}\n", "f.js"), ["Contact"])
        self.assertEqual(self._log_categories("def f(user)\n  Rails.logger.info \"phone=#{user.phone_number}\"\nend\n", "f.rb"), ["Contact"])

    def test_multiline_log_call_is_flagged_and_neighbour_line_is_not(self):
        flagged = "function f(req) {\n  console.log(\n    'refund',\n    req.body.phone_number\n  );\n}\n"
        self.assertEqual(self._log_categories(flagged, "f.js"), ["Contact"])
        clean = "async function f(req) {\n  await Order.create({ email: req.body.email });\n  console.log('order created', order.id);\n}\n"
        self.assertEqual(self._log_categories(clean, "f.js"), [])


class FingerprintTests(unittest.TestCase):
    def test_fingerprints_survive_line_shifts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            base = run_scan(str(repo), None).to_dict()
            self.assertTrue(all(item["metadata"].get("fingerprint") for item in base["evidence"]))
            target = repo / "services/payments/checkout.js"
            target.write_text("// header comment\n// another line\n\n" + target.read_text(encoding="utf-8"), encoding="utf-8")
            head = run_scan(str(repo), None).to_dict()
            diff = diff_reports(base, head)
            self.assertEqual((diff["new"], diff["resolved"]), ([], []))
            self.assertEqual(diff["matching"], "fingerprint")

    def test_diff_reports_semantic_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            base = run_scan(str(repo), None).to_dict()
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            diff = diff_reports(base, run_scan(str(repo), None).to_dict())
            self.assertEqual(diff["new_data_categories"], ["Location"])
            self.assertEqual(diff["new_third_parties"], ["Mixpanel"])
            self.assertIn({"data_category": "Contact", "file": "services/payments/refund.js"}, diff["new_logging_flows"])
            self.assertTrue(all(item["file"] == "services/payments/refund.js" for item in diff["new"]))

    def test_legacy_reports_without_fingerprints_still_diff(self):
        base = run_scan(str(EXAMPLE), None).to_dict()
        for item in base["evidence"]:
            item["metadata"].pop("fingerprint")
        diff = diff_reports(base, run_scan(str(EXAMPLE), None).to_dict())
        self.assertEqual(diff["matching"], "legacy-position-free")
        self.assertEqual((diff["new"], diff["resolved"]), ([], []))


class InitTests(unittest.TestCase):
    def test_generated_manifest_is_in_sync_by_construction(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "privacy.yaml").unlink()
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            text = generate_manifest(run_scan(str(repo), None))
            (repo / "privacy.yaml").write_text(text, encoding="utf-8")
            result = _check(repo)
            rules = set(_rules(result))
            self.assertFalse(rules & {"D001", "D002", "D003", "D004", "D005", "D008"}, rules)
            self.assertTrue({"D006", "D007", "P001", "P003"} <= rules)
            ids = [a.id for a in result.manifest.activities]
            self.assertEqual(ids, ["services_notifications", "services_onboarding", "services_payments", "web"])


class ReportAndCliTests(unittest.TestCase):
    def test_report_pack_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            result = _check(repo)
            files = write_check_pack(result, str(Path(tmp) / "out"))
            data = json.loads(Path(files["json"]).read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], "svikruti-privacy-check-v1")
            self.assertEqual(len(data["obligations"]), 24)
            self.assertEqual({row["framework"] for row in data["matrix"]}, {"dpdpa", "gdpr", "iso27701"})
            sarif = json.loads(Path(files["sarif"]).read_text(encoding="utf-8"))
            results = sarif["runs"][0]["results"]
            self.assertEqual(len(results), 3)
            self.assertTrue(all(r["partialFingerprints"]["svikrutiFinding/v1"] for r in results))
            self.assertIn("Art. 30(1)", Path(files["matrix"]).read_text(encoding="utf-8"))
            self.assertIn("Loan applicant onboarding and KYC", Path(files["record"]).read_text(encoding="utf-8"))
            markdown = check_markdown(result)
            self.assertIn("Blocked", markdown)
            self.assertIn("A.1.2.9", markdown)
            html = render_check_html(result)
            self.assertIn("Obligation crosswalk", html)
            self.assertIn("+ Location", html)

    def test_html_escapes_manifest_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            _edit_manifest(repo, "name: EMI repayment collection", 'name: "<script>alert(1)</script>"')
            html = render_check_html(_check(repo))
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;", html)

    def test_cli_check_gate_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            out = Path(tmp) / "out"
            args = ["check", "--repo", str(repo), "--privacy-file", str(repo / "privacy-notice.md"), "--out-dir", str(out)]
            self.assertEqual(main(args), 0)
            baseline = Path(tmp) / "baseline.json"
            shutil.copy(out / "privacy-check.json", baseline)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            self.assertEqual(main(args), 3)
            self.assertEqual(main(args + ["--fail-on", "none"]), 0)
            self.assertEqual(main(args + ["--fail-on", "critical"]), 0)
            # Accept the drift as backlog: it stops blocking, anything newer still does.
            shutil.copy(out / "privacy-check.json", baseline)
            self.assertEqual(main(args + ["--baseline", str(baseline)]), 0)
            (repo / "services/payments/export.js").write_text("const hubspot = require('@hubspot/api-client');\nhubspot.push({ email: req.body.email });\n", encoding="utf-8")
            self.assertEqual(main(args + ["--baseline", str(baseline)]), 3)
            comment = (out / "pr-comment.md").read_text(encoding="utf-8")
            self.assertIn("HubSpot", comment)
            self.assertNotIn("Mixpanel", comment)

    def test_cli_usage_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main(["check", "--repo", tmp]), 2)
            (Path(tmp) / "privacy.yaml").write_text("version: 1\nprocessing_activities:\n  - id: a\n", encoding="utf-8")
            self.assertEqual(main(["check", "--repo", tmp]), 2)
            self.assertEqual(main(["init", "--repo", tmp]), 2)
            self.assertEqual(main(["init", "--repo", tmp, "--force", "--frameworks", "nope"]), 2)
            self.assertEqual(main(["scan", "--repo", tmp, "--fail-on-new", "high", "--out", str(Path(tmp) / "r.html")]), 2)

    def test_cli_init_scan_baseline_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "privacy.yaml").unlink()
            self.assertEqual(main(["init", "--repo", str(repo), "--frameworks", "gdpr"]), 0)
            self.assertEqual(load_manifest(repo / "privacy.yaml").frameworks, ["gdpr"])
            base, head = Path(tmp) / "base.json", Path(tmp) / "head.json"
            common = ["scan", "--repo", str(repo), "--out", str(Path(tmp) / "r.html")]
            self.assertEqual(main(common + ["--json-out", str(base)]), 0)
            self.assertEqual(main(common + ["--json-out", str(head), "--baseline", str(base), "--fail-on-new", "low"]), 0)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            diff_md = Path(tmp) / "diff.md"
            self.assertEqual(main(common + ["--json-out", str(head), "--baseline", str(base), "--fail-on-new", "high", "--diff-out", str(diff_md)]), 3)
            self.assertIn("Mixpanel", diff_md.read_text(encoding="utf-8"))
            self.assertEqual(main(["diff", str(base), str(head), "--fail-on-new", "critical"]), 0)
            self.assertEqual(main(["diff", str(base), str(head), "--fail-on-new", "high"]), 3)
            self.assertEqual(main(["frameworks"]), 0)


if __name__ == "__main__":
    unittest.main()
