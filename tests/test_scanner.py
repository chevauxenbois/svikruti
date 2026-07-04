import json
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from svikruti.ai import generate_ai_insights
from svikruti.cli import build_parser
from svikruti.reports.exports import (
    breach_markdown,
    write_ai_markdown,
    write_actions_csv,
    write_breach_markdown,
    write_controls_csv,
    write_issues_markdown,
    write_notice_patch,
    write_ropa_csv,
    write_vendor_csv,
)
from svikruti.reports.html import render_html
from svikruti.reports.sarif import write_sarif
from svikruti.scanner.browser import _known_tools, _third_party_domains
from svikruti.scanner.code import scan_repo
from svikruti.scanner.runner import run_scan
from svikruti.store import list_scans, load_latest_scan, load_scan, save_scan_result


class ScannerTests(unittest.TestCase):
    def test_example_repo_scan_generates_evidence_and_ropa(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")

        self.assertGreaterEqual(len(result.evidence), 10)
        self.assertIn("Contact", result.summary.personal_data_categories)
        self.assertIn("Government ID", result.summary.personal_data_categories)
        self.assertIn("Google Analytics", result.summary.third_parties)
        self.assertGreaterEqual(len(result.ropa_starter), 1)
        self.assertGreaterEqual(len(result.evidence_graph.nodes), 1)
        self.assertGreaterEqual(len(result.evidence_graph.data_flows), 1)
        self.assertGreaterEqual(len(result.evidence_graph.proof_pack), 1)
        self.assertGreaterEqual(len(result.technical_controls), 1)
        self.assertIn("posture", result.breach_readiness)
        self.assertIn("production_claim", result.assurance_profile)

    def test_html_report_contains_summary_sections(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")
        html = render_html(result)

        self.assertIn("Svikruti PrivacyOps Evidence Report", html)
        self.assertIn("Detected Personal Data", html)
        self.assertIn("Evidence Flow", html)
        self.assertIn("Action Workbench", html)
        self.assertIn("DPDPA Control Board", html)
        self.assertIn("Technical Control Plane", html)
        self.assertIn("Breach Readiness", html)
        self.assertIn("Fix Pack", html)
        self.assertIn("AI Co-pilot", html)
        self.assertIn("Evidence Explorer", html)
        self.assertIn("Scan Quality & Limitations", html)
        self.assertIn("Trust the evidence, not just the score.", html)
        self.assertIn("Human verification before launch", html)
        self.assertIn("Parser engines", html)
        self.assertIn("Launch Artifacts", html)
        self.assertIn("RoPA starter", html)
        self.assertIn("Launch posture", html)
        self.assertIn("Document strict purpose, retention, and access controls", html)

    def test_sarif_report_is_valid_json(self):
        result = run_scan(repo="examples", url=None)

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "svikruti.sarif"
            write_sarif(result, str(output))
            parsed = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(parsed["version"], "2.1.0")
        self.assertGreater(len(parsed["runs"][0]["results"]), 0)

    def test_browser_domain_helpers_classify_third_party_tools(self):
        domains = {
            "example.com",
            "app.example.com",
            "googletagmanager.com",
            "checkout.razorpay.com",
            "localhost",
        }

        third_parties = _third_party_domains(domains, "example.com")

        self.assertEqual(third_parties, {"googletagmanager.com", "checkout.razorpay.com"})
        self.assertIn("Google Analytics", _known_tools(sorted(third_parties)))
        self.assertIn("Razorpay", _known_tools(sorted(third_parties)))

    def test_operational_artifact_exports(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ropa = root / "ropa.csv"
            actions = root / "actions.csv"
            vendors = root / "vendors.csv"
            controls = root / "controls.csv"
            breach = root / "breach.md"
            notice = root / "notice.md"
            issues = root / "issues.md"
            ai = root / "ai.md"

            write_ropa_csv(result, str(ropa))
            write_actions_csv(result, str(actions))
            write_vendor_csv(result, str(vendors))
            write_controls_csv(result, str(controls))
            write_breach_markdown(result, str(breach))
            write_notice_patch(result, str(notice))
            write_issues_markdown(result, str(issues))
            result.ai_insights = {"status": "not_configured", "model": "test-model", "message": "Set a key"}
            write_ai_markdown(result, str(ai))

            with ropa.open(encoding="utf-8") as handle:
                ropa_rows = list(csv.reader(handle))
            with actions.open(encoding="utf-8") as handle:
                action_rows = list(csv.reader(handle))
            with vendors.open(encoding="utf-8") as handle:
                vendor_rows = list(csv.reader(handle))
            with controls.open(encoding="utf-8") as handle:
                control_rows = list(csv.reader(handle))
            breach_text = breach.read_text(encoding="utf-8")
            notice_text = notice.read_text(encoding="utf-8")
            issue_text = issues.read_text(encoding="utf-8")
            ai_text = ai.read_text(encoding="utf-8")

        self.assertEqual(ropa_rows[0][0], "Schema Version")
        self.assertIn("DPDPA Basis", ropa_rows[0])
        self.assertIn("Evidence References", ropa_rows[0])
        self.assertIn("Scanner Confidence", ropa_rows[0])
        self.assertGreater(len(ropa_rows), 1)
        self.assertEqual(action_rows[0][0], "Schema Version")
        self.assertIn("Acceptance Criteria", action_rows[0])
        self.assertIn("Control Area", action_rows[0])
        self.assertGreater(len(action_rows), 1)
        self.assertEqual(vendor_rows[0][0], "Schema Version")
        self.assertIn("DPA / Contract Status", vendor_rows[0])
        self.assertIn("Data Categories Shared", vendor_rows[0])
        self.assertIn("Google Analytics", "\n".join(",".join(row) for row in vendor_rows))
        self.assertEqual(control_rows[0][0], "Schema Version")
        self.assertIn("Control ID", control_rows[0])
        self.assertIn("Evidence References", control_rows[0])
        self.assertIn("Svikruti Breach Readiness Pack", breach_text)
        self.assertIn("Priority Actions", breach_text)
        self.assertIn("Privacy Notice Patch Draft", notice_text)
        self.assertIn("Svikruti Fix Pack", issue_text)
        self.assertIn("Acceptance Criteria", issue_text)
        self.assertIn("Svikruti AI Co-pilot Brief", ai_text)

    def test_realistic_multi_framework_examples_are_detected(self):
        result = run_scan(
            repo="examples/realistic",
            url=None,
            security_evidence=[
                "examples/security/trivy.json",
                "examples/security/gitleaks.json",
                "examples/security/semgrep.sarif",
            ],
        )
        categories = set(result.summary.personal_data_categories)
        languages = {item.metadata.get("language") for item in result.evidence}
        detector_ids = {item.metadata.get("detector_id") for item in result.evidence}
        confidence_values = {item.metadata.get("confidence") for item in result.evidence}
        semantic_roles = {item.metadata.get("semantic_role") for item in result.evidence}
        control_statuses = {item["id"]: item["status"] for item in result.technical_controls}

        self.assertIn("Contact", categories)
        self.assertIn("Government ID", categories)
        self.assertIn("Health", categories)
        self.assertIn("Children", categories)
        self.assertIn("Financial", categories)
        self.assertIn("SQL", languages)
        self.assertIn("JavaScript", languages)
        self.assertIn("React/TypeScript", languages)
        self.assertIn("Python", languages)
        self.assertIn("Terraform", languages)
        self.assertIn("Java", languages)
        self.assertIn("Go", languages)
        self.assertIn("Ruby", languages)
        self.assertIn("PHP", languages)
        self.assertIn("code.collection_point.contact", detector_ids)
        self.assertIn("code.storage_point.health", detector_ids)
        self.assertIn("code.logging_risk.government_id", detector_ids)
        self.assertIn("semantic.python.model_field.health", detector_ids)
        self.assertIn("semantic.js.request_body.government_id", detector_ids)
        self.assertIn("semantic.java.field.government_id", detector_ids)
        self.assertIn("semantic.go.field.health", detector_ids)
        # The route line "post /students" alone is ambiguous (students ->
        # student needs corroboration); the permit() line carries the real
        # children signal through unambiguous student_age/guardian tokens.
        self.assertIn("semantic.ruby.storage_sink.children", detector_ids)
        self.assertIn("semantic.php.request_source.financial", detector_ids)
        self.assertIn("semantic.prisma.schema_field.government_id", detector_ids)
        self.assertIn("semantic.openapi.request_source.government_id", detector_ids)
        self.assertIn("semantic.kubernetes.runtime_config.contact", detector_ids)
        self.assertIn("request_source", semantic_roles)
        self.assertIn("storage_sink", semantic_roles)
        self.assertIn("high", confidence_values)
        self.assertTrue(any("Razorpay" == item.metadata.get("third_party") for item in result.evidence))
        self.assertEqual(control_statuses["DPDPA-TECH-003"], "fail")
        self.assertEqual(control_statuses["DPDPA-TECH-004"], "fail")
        self.assertEqual(control_statuses["DPDPA-TECH-008"], "fail")
        self.assertIn("not_ready", result.breach_readiness["posture"])
        self.assertIn("not production-assured", result.assurance_profile["production_claim"])
        self.assertGreaterEqual(result.assurance_profile["counts"]["failing"], 1)
        self.assertTrue(any(item["id"] == "cloud_iac" for item in result.assurance_profile["dimensions"]))
        self.assertGreater(result.scan_quality["parser_coverage_percent"], 0)
        self.assertIn("python.ast", result.scan_quality["parser_engines"])
        self.assertIn("java.spring_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("go.handler_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("ruby.rails_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("php.laravel_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("openapi.schema_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("kubernetes.manifest_heuristic", result.scan_quality["parser_engines"])
        self.assertIn("limitations", result.scan_quality)
        self.assertIn("Vulnerability Management", breach_markdown(result))

    def test_ai_not_configured_does_not_call_network(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")

        insights = generate_ai_insights(result, api_key="")

        self.assertEqual(insights["status"], "not_configured")
        self.assertIn("configured AI provider", insights["message"])

    def test_gemini_not_configured_does_not_call_network(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")

        insights = generate_ai_insights(result, provider="gemini", api_key="")

        self.assertEqual(insights["status"], "not_configured")
        self.assertIn("configured AI provider", insights["message"])

    def test_gemini_response_parsing_with_mocked_network(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")
        gemini_body = json.dumps(
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "executive_brief": "AI generated brief",
                                            "launch_risk": "Review before launch",
                                            "top_priorities": [],
                                            "control_commentary": [],
                                            "buyer_summary": "Evidence-grounded buyer summary",
                                            "notice_patch": "Patch notice",
                                            "fix_pack_improvements": "Improve fixes",
                                            "caveats": "Drafting support only",
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }
        ).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return gemini_body

        with patch("svikruti.ai.urlopen", return_value=FakeResponse()) as mocked_urlopen:
            insights = generate_ai_insights(result, provider="gemini", api_key="test-key", model="gemini-test")

        self.assertEqual(insights["status"], "generated")
        self.assertEqual(insights["provider"], "gemini")
        self.assertEqual(insights["model"], "gemini-test")
        self.assertIn("AI generated brief", insights["executive_brief"])
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.headers["X-goog-api-key"], "test-key")
        self.assertIn("gemini-test:generateContent", request.full_url)

    def test_runner_can_attach_ai_insights_with_mocked_generator(self):
        with patch(
            "svikruti.scanner.runner.generate_ai_insights",
            return_value={
                "status": "generated",
                "model": "test-model",
                "executive_brief": "Evidence-grounded brief",
                "top_priorities": [],
                "control_commentary": [],
            },
        ):
            result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html", ai_enabled=True)

        self.assertEqual(result.ai_insights["status"], "generated")
        self.assertIn("Evidence-grounded brief", render_html(result))

    def test_personal_data_terms_are_token_aware(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text('document.head.appendChild(script);\nconst child_age = request.body.child_age;\n', encoding="utf-8")

            result = scan_repo(tmp)

        children_hits = [item for item in result.evidence if item.metadata.get("data_category") == "Children"]
        self.assertEqual(len(children_hits), 1)
        self.assertEqual(children_hits[0].line, 2)

    def test_scan_history_store_roundtrip(self):
        result = run_scan(repo="examples", url=None, privacy_file="examples/privacy.html")

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "evidence.db"
            scan_id = save_scan_result(result, db_path)
            scans = list_scans(db_path)
            loaded = load_scan(scan_id, db_path)
            latest = load_latest_scan(db_path)

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["id"], scan_id)
        self.assertEqual(loaded["summary"]["risk_level"], result.summary.risk_level)
        self.assertEqual(latest["generated_at"], result.generated_at)
        self.assertIn("technical_controls", loaded)
        self.assertIn("assurance_profile", loaded)
        self.assertIn("scan_quality", loaded)

    def test_dashboard_command_is_registered(self):
        parser = build_parser()
        args = parser.parse_args(["dashboard", "--db", "example.db", "--report", "report.json", "--port", "8765"])

        self.assertEqual(args.command, "dashboard")
        self.assertEqual(args.db, "example.db")
        self.assertEqual(args.report, "report.json")
        self.assertEqual(args.port, 8765)


if __name__ == "__main__":
    unittest.main()
