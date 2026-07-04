import csv
import json
import tempfile
import unittest
from pathlib import Path

from svikruti.models import Evidence, ScanResult
from svikruti.reports.exports import write_vendor_csv
from svikruti.scanner.code import scan_repo
from svikruti.scanner.dpdpa import _risk_level, summarize
from svikruti.scanner.patterns import (
    is_valid_aadhaar,
    verhoeff_check_digit,
    verhoeff_checksum_valid,
)
from svikruti.scanner.semantic import scan_semantic_evidence
from svikruti.scanner.technical import ingest_security_findings, scan_technical_evidence


def _valid_aadhaar(base: str = "23412341234") -> str:
    """Build a Verhoeff-valid Aadhaar-format vector (12 digits, first digit 2-9)."""
    return base + verhoeff_check_digit(base)


def _write(root: str, name: str, content: str) -> Path:
    path = Path(root) / name
    path.write_text(content, encoding="utf-8")
    return path


def _risk_item(severity: str, category: str) -> Evidence:
    return Evidence(
        kind="collection_point",
        label=f"{category} data signal",
        severity=severity,
        source="code",
        detail="synthetic risk finding",
        recommendation="review",
        metadata={"data_category": category},
    )


class VerhoeffValidationTests(unittest.TestCase):
    def test_generated_check_digit_produces_valid_aadhaar(self):
        valid = _valid_aadhaar()

        self.assertEqual(len(valid), 12)
        self.assertTrue(verhoeff_checksum_valid(valid))
        self.assertTrue(is_valid_aadhaar(valid))
        self.assertTrue(is_valid_aadhaar(f"{valid[:4]} {valid[4:8]} {valid[8:]}"))
        self.assertTrue(is_valid_aadhaar(f"{valid[:4]}-{valid[4:8]}-{valid[8:]}"))

    def test_single_digit_mutation_fails_checksum(self):
        valid = _valid_aadhaar()
        mutated = valid[:5] + str((int(valid[5]) + 1) % 10) + valid[6:]

        self.assertNotEqual(mutated, valid)
        self.assertFalse(verhoeff_checksum_valid(mutated))
        self.assertFalse(is_valid_aadhaar(mutated))

    def test_adjacent_transposition_fails_checksum(self):
        valid = _valid_aadhaar()
        # base "23412341234": digits at index 1 and 2 differ ("3" and "4").
        transposed = valid[0] + valid[2] + valid[1] + valid[3:]

        self.assertNotEqual(transposed, valid)
        self.assertFalse(verhoeff_checksum_valid(transposed))

    def test_first_digit_zero_or_one_is_rejected(self):
        valid = _valid_aadhaar()

        self.assertFalse(is_valid_aadhaar("0" + valid[1:]))
        self.assertFalse(is_valid_aadhaar("1" + valid[1:]))

    def test_random_twelve_digit_numbers_are_not_flagged_by_repo_scan(self):
        base = "22345678901"
        wrong_check = str((int(verhoeff_check_digit(base)) + 1) % 10)
        invalid_checksum = base + wrong_check
        self.assertFalse(is_valid_aadhaar(invalid_checksum))

        with tempfile.TemporaryDirectory() as tmp:
            _write(
                tmp,
                "orders.py",
                'order_reference = "123456789012"\n'
                f'tracking_code = "{invalid_checksum}"\n',
            )

            result = scan_repo(tmp)

        aadhaar_hits = [
            item
            for item in result.evidence
            if item.kind == "literal_personal_data" and "Aadhaar" in item.label
        ]
        self.assertEqual(aadhaar_hits, [])


class FalsePositiveSuiteTests(unittest.TestCase):
    def test_common_engineering_tokens_produce_no_critical_or_high_findings(self):
        content = (
            'import { useState } from "react";\n'
            "\n"
            'const ORDER_REFERENCE = "123456789012";\n'
            'const GIT_COMMIT = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";\n'
            'const SVG_NS = "http://www.w3.org/2000/svg";\n'
            "// des: shorthand for design tokens used below\n"
            "\n"
            "export function OrderStatus() {\n"
            "  const [state, setState] = useState({ zip: null });\n"
            "  const inputStream = openInputStream();\n"
            "  registerServiceWorker();\n"
            "  return state && inputStream ? SVG_NS : null;\n"
            "}\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "order_status.tsx", content)

            evidence = list(scan_repo(tmp).evidence)
            evidence.extend(scan_technical_evidence(tmp))
            evidence.extend(scan_semantic_evidence(tmp).evidence)

        noisy = [item for item in evidence if item.severity in {"CRITICAL", "HIGH"}]
        self.assertEqual(
            noisy,
            [],
            msg=f"Unexpected CRITICAL/HIGH findings: {[(item.kind, item.label, item.line) for item in noisy]}",
        )


class TruePositiveSuiteTests(unittest.TestCase):
    def test_real_indian_identifiers_are_detected_with_expected_severity(self):
        valid = _valid_aadhaar()
        content = (
            "def submit_kyc_documents(payload):\n"
            f'    customer_aadhaar = "{valid}"\n'
            '    pan_number = "ABCPK1234F"\n'
            '    contact_mobile = "+91 98765 43210"\n'
            '    upi_handle = "someone@ybl"\n'
            "    return customer_aadhaar\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "kyc.py", content)

            result = scan_repo(tmp)

        literals = {
            item.label: item.severity
            for item in result.evidence
            if item.kind == "literal_personal_data"
        }
        self.assertEqual(literals.get("Aadhaar-like literal detected"), "CRITICAL")
        self.assertEqual(literals.get("PAN literal detected"), "CRITICAL")
        self.assertEqual(literals.get("Indian mobile literal detected"), "HIGH")
        self.assertEqual(literals.get("UPI ID literal detected"), "HIGH")


class EnvFileScanningTests(unittest.TestCase):
    def test_dotenv_file_is_scanned_for_literals_and_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(
                tmp,
                ".env",
                "ADMIN_EMAIL=admin@corp.example.in\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
            )

            code_evidence = list(scan_repo(tmp).evidence)
            technical_evidence = scan_technical_evidence(tmp)

        scanned_files = {item.file for item in code_evidence + technical_evidence}
        self.assertIn(".env", scanned_files)
        email_hits = [
            item
            for item in code_evidence
            if item.kind == "literal_personal_data" and "Email" in item.label
        ]
        self.assertEqual(len(email_hits), 1)
        self.assertEqual(email_hits[0].file, ".env")
        secret_hits = [item for item in technical_evidence if item.kind == "secret_exposure"]
        self.assertTrue(secret_hits)
        self.assertEqual(secret_hits[0].severity, "CRITICAL")


class AmbiguousTermCorroborationTests(unittest.TestCase):
    def test_patient_with_nearby_contact_data_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(
                tmp,
                "clinic.py",
                'patient_name = record["patient_name"]\n'
                'email = record["email"]\n',
            )

            result = scan_repo(tmp)

        health_hits = [
            item for item in result.evidence if item.metadata.get("data_category") == "Health"
        ]
        self.assertTrue(health_hits)
        self.assertEqual(health_hits[0].severity, "CRITICAL")
        self.assertEqual(health_hits[0].label, "Health data signal")

    def test_patient_without_corroboration_is_downgraded_to_possible_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(
                tmp,
                "repository.py",
                "patient = fetch_row()\n"
                "process(patient)\n",
            )

            result = scan_repo(tmp)

        health_hits = [
            item for item in result.evidence if item.metadata.get("data_category") == "Health"
        ]
        self.assertTrue(health_hits)
        for item in health_hits:
            self.assertNotEqual(item.severity, "CRITICAL")
        self.assertEqual(health_hits[0].severity, "MEDIUM")
        self.assertIn("Possible", health_hits[0].label)


class RiskScoringTests(unittest.TestCase):
    def test_positive_evidence_only_scores_zero(self):
        items = [
            Evidence(
                kind="encryption_evidence",
                label="TLS enforced evidence",
                severity="LOW",
                source="technical-control",
                detail="TLS evidence",
                recommendation="confirm",
                metadata={"positive_evidence": True, "subtype": "TLS enforced"},
            ),
            Evidence(
                kind="security_tooling",
                label="Dependabot evidence",
                severity="LOW",
                source="technical-control",
                detail="scanner evidence",
                recommendation="confirm",
                metadata={"positive_evidence": True, "subtype": "Dependabot"},
            ),
        ]

        summary = summarize(items, 5, 0)

        self.assertEqual(summary.risk_score, 0)
        self.assertEqual(summary.risk_level, "LOW")

    def test_three_critical_and_five_high_land_in_high_band(self):
        items = [
            _risk_item("CRITICAL", "Government ID"),
            _risk_item("CRITICAL", "Health"),
            _risk_item("CRITICAL", "Children"),
            _risk_item("HIGH", "Contact"),
            _risk_item("HIGH", "Contact"),
            _risk_item("HIGH", "Financial"),
            _risk_item("HIGH", "Financial"),
            _risk_item("HIGH", "Location"),
        ]

        summary = summarize(items, 10, 0)

        # Severity-tiered model: 55*(1-e^-3/2.5) + 35*(1-e^-5/8) ~= 55.
        self.assertGreaterEqual(summary.risk_score, 45)
        self.assertLessEqual(summary.risk_score, 70)
        self.assertEqual(summary.risk_level, "HIGH")

    def test_risk_band_boundaries(self):
        expected = {
            0: "LOW",
            24: "LOW",
            25: "MEDIUM",
            49: "MEDIUM",
            50: "HIGH",
            74: "HIGH",
            75: "CRITICAL",
            100: "CRITICAL",
        }
        for score, band in expected.items():
            self.assertEqual(_risk_level(score), band, msg=f"score {score}")


class SecurityImportTests(unittest.TestCase):
    def _ingest(self, tmp: str, name: str, payload: object):
        path = _write(tmp, name, json.dumps(payload))
        return ingest_security_findings([str(path)])

    def test_sarif_severity_mapping(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestScanner",
                            "rules": [
                                {
                                    "id": "rule-critical",
                                    "properties": {"security-severity": "9.8"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "rule-critical",
                            "level": "warning",
                            "message": {"text": "CVSS 9.8 issue"},
                        },
                        {
                            "ruleId": "rule-warning",
                            "level": "warning",
                            "message": {"text": "warning-level issue"},
                        },
                        {
                            "ruleId": "rule-nolevel",
                            "message": {"text": "no level provided"},
                        },
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            findings = self._ingest(tmp, "scan.sarif.json", sarif)

        by_rule = {item.metadata.get("rule_id"): item for item in findings}
        self.assertEqual(by_rule["rule-critical"].severity, "CRITICAL")
        self.assertEqual(by_rule["rule-warning"].severity, "MEDIUM")
        self.assertEqual(by_rule["rule-nolevel"].severity, "MEDIUM")
        for item in findings:
            self.assertEqual(item.kind, "imported_security_finding")

    def test_osv_scanner_json_format_is_parsed(self):
        payload = {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "lodash",
                                "version": "4.17.20",
                                "ecosystem": "npm",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-35jh-r3h4-6jhm",
                                    "summary": "Command injection in lodash",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp:
            findings = self._ingest(tmp, "osv-scanner.json", payload)

        imported = [item for item in findings if item.kind == "imported_security_finding"]
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0].severity, "HIGH")
        self.assertEqual(imported[0].metadata.get("scanner"), "osv-scanner")
        self.assertEqual(imported[0].metadata.get("package"), "lodash")
        self.assertEqual(imported[0].file, "package-lock.json")

    def test_bare_json_list_of_non_gitleaks_dicts_is_not_misparsed(self):
        payload = [{"widget": "blue", "count": 3}, {"status": "ok"}]

        with tempfile.TemporaryDirectory() as tmp:
            findings = self._ingest(tmp, "random-list.json", payload)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "import_error")
        self.assertEqual(findings[0].label, "Unknown security scan format")
        self.assertEqual(
            findings[0].metadata.get("detector_id"), "security_import.unknown_format"
        )
        kinds = {item.kind for item in findings}
        self.assertNotIn("imported_security_finding", kinds)
        self.assertNotIn("secret_exposure", kinds)

    def test_imported_sarif_message_secrets_are_redacted(self):
        secret_hex = "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432"
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestScanner", "rules": []}},
                    "results": [
                        {
                            "ruleId": "hardcoded-secret",
                            "level": "error",
                            "message": {
                                "text": f"Hardcoded secret {secret_hex} committed to repo"
                            },
                        }
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            findings = self._ingest(tmp, "secrets.sarif.json", sarif)

        self.assertEqual(len(findings), 1)
        self.assertIn("REDACTED", findings[0].detail)
        self.assertNotIn(secret_hex, findings[0].detail)


class CsvInjectionTests(unittest.TestCase):
    def test_formula_prefixed_vendor_cell_is_neutralized(self):
        result = ScanResult.empty(repo_path=None, url=None)
        result.summary.third_parties = ["=HYPERLINK(evil)"]

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "vendors.csv"
            write_vendor_csv(result, str(output))
            raw = output.read_text(encoding="utf-8")
            with output.open(encoding="utf-8") as handle:
                rows = list(csv.reader(handle))

        self.assertIn("'=HYPERLINK(evil)", raw)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1][1].startswith("'="))


class SemanticConfidenceTests(unittest.TestCase):
    def test_python_ast_findings_report_high_confidence(self):
        content = (
            "from flask import request\n"
            "\n"
            "\n"
            "class UserModel(Model):\n"
            "    email = None\n"
            "    phone_number = None\n"
            "\n"
            "\n"
            "def signup():\n"
            "    payload = request.json\n"
            '    email = payload["email"]\n'
            "    db.save(email)\n"
            "    return email\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "app.py", content)

            result = scan_semantic_evidence(tmp)

        python_findings = [
            item
            for item in result.evidence
            if str(item.metadata.get("detector_id", "")).startswith("semantic.python.")
        ]
        self.assertTrue(python_findings)
        for item in python_findings:
            self.assertEqual(item.metadata.get("confidence"), "high")
            self.assertEqual(item.metadata.get("parser"), "python.ast")
        self.assertIn("python.ast", result.parser_engines)

    def test_js_heuristic_findings_report_medium_confidence(self):
        content = (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/signup', (req, res) => {\n"
            "  const { email, phone } = req.body;\n"
            "  res.json({ ok: true });\n"
            "});\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "server.js", content)

            result = scan_semantic_evidence(tmp)

        js_findings = [
            item
            for item in result.evidence
            if str(item.metadata.get("detector_id", "")).startswith("semantic.js.")
        ]
        self.assertTrue(js_findings)
        for item in js_findings:
            self.assertEqual(item.metadata.get("confidence"), "medium")


if __name__ == "__main__":
    unittest.main()


class BenchmarkDrivenBehaviorTests(unittest.TestCase):
    """Regression tests for false-positive classes found by scanning real
    OSS repositories (excalidraw, healthchecks, saleor)."""

    def test_test_directory_findings_are_downgraded_and_semantic_skipped(self):
        content = (
            "def test_signup(client):\n"
            "    email = 'person@corp.example'\n"
            "    db.save(email=email, phone_number='+91 98765 43210')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "hc" / "api" / "tests").mkdir(parents=True)
            _write(tmp, "hc/api/tests/test_signup.py", content)

            code_result = scan_repo(tmp)
            semantic_result = scan_semantic_evidence(tmp)

        keyword = [e for e in code_result.evidence if e.kind in ("collection_point", "storage_point", "personal_data_reference", "logging_risk")]
        for item in keyword:
            self.assertEqual(item.severity, "LOW", msg=f"{item.label} not downgraded in test dir")
            self.assertIn("test code", item.label)
        self.assertEqual([e.label for e in semantic_result.evidence], [])

    def test_url_embedded_and_asset_emails_are_not_flagged(self):
        content = (
            'SENTRY_DSN = "https://7bfc12a87afc7601@o12345.sentry.io/5179260"\n'
            'icon = "add_to_slack@2x.png"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "settings.py", content)
            result = scan_repo(tmp)
        emails = [e for e in result.evidence if "Email" in e.label or "email" in str(e.metadata.get("detector_id", ""))]
        self.assertEqual(emails, [], msg=f"unexpected: {[e.label for e in emails]}")

    def test_metadata_file_emails_are_low(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "package.json", '{"author": "Jane Doe <jane@realcorp.io>"}')
            result = scan_repo(tmp)
        emails = [e for e in result.evidence if e.kind == "literal_personal_data" and "mail" in e.label.lower()]
        self.assertTrue(emails)
        self.assertEqual(emails[0].severity, "LOW")

    def test_vendored_and_minified_files_are_skipped(self):
        content = 'var email = "someone@realcorp.io"; node.children.forEach(f);\n'
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "static" / "vendor").mkdir(parents=True)
            _write(tmp, "static/vendor/lib.js", content)
            _write(tmp, "app.min.js", content)
            result = scan_repo(tmp)
        self.assertEqual(result.evidence, [])
        self.assertEqual(result.skipped_vendored_files, 2)

    def test_bare_ten_digit_constant_is_only_possible_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "consts.py", 'APP_STORE_ID = "6746335356"\nid_ref = "id6746335356"\n')
            result = scan_repo(tmp)
        mobiles = [e for e in result.evidence if "mobile" in e.label.lower()]
        # letter-attached run must not match at all; bare constant is MEDIUM "possible"
        self.assertLessEqual(len(mobiles), 1)
        for item in mobiles:
            self.assertEqual(item.severity, "MEDIUM")
            self.assertIn("Possible", item.label)

    def test_react_children_and_mobile_classname_are_not_critical(self):
        content = (
            "export const Menu = (props) => (\n"
            '  <div className="mobile-toolbar">{props.children}</div>\n'
            ");\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "Menu.tsx", content)
            result = scan_repo(tmp)
        noisy = [e for e in result.evidence if e.severity in ("CRITICAL", "HIGH")]
        self.assertEqual(noisy, [], msg=f"unexpected: {[(e.label, e.severity) for e in noisy]}")
