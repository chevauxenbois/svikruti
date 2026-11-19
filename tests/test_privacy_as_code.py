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
from svikruti.pac.sync import apply_plan_yaml, build_plan, sync_manifest
from svikruti.reports.html import render_html
from svikruti.reports.sarif import write_sarif
from svikruti.scanner.flows import scan_processor_flows
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
    def test_builtin_packs_map_known_obligations(self):
        obligation_ids = {item["id"] for item in OBLIGATIONS}
        self.assertEqual(builtin_pack_ids(), ["ccpa", "dpdpa", "gdpr", "iso27701", "iso27701_processor", "lgpd", "rbi", "sebi_cscrf", "soc2"])
        for pack_id in builtin_pack_ids():
            pack = load_pack(pack_id)
            self.assertTrue(set(pack.controls) <= obligation_ids, pack_id)
            if pack_id in {"dpdpa", "gdpr", "iso27701", "lgpd"}:
                self.assertEqual(set(pack.controls), obligation_ids, pack_id)
            for refs in pack.controls.values():
                for control in refs:
                    self.assertTrue(control["ref"] and control["title"])
        # Frameworks without a concept do not get a borrowed clause.
        self.assertEqual(load_pack("ccpa").refs("OBL-03"), [])
        self.assertEqual(load_pack("iso27701_processor").refs("OBL-10"), [])

    def test_lawful_basis_is_validated_per_framework(self):
        scan = run_scan(str(EXAMPLE), None)
        result = run_check(scan, load_manifest(EXAMPLE / "privacy.yaml"), frameworks=["lgpd", "ccpa"], today=TODAY)
        basis = [f for f in result.open_findings() if f.rule == "D006"]
        self.assertEqual(len(basis), 3)
        self.assertTrue(all("lgpd" in f.detail and "ccpa" not in f.detail for f in basis))
        statuses = {a.id: a.status for a in result.assessments}
        self.assertEqual(statuses["OBL-03"], "fail")
        summary = {p.id: result.framework_summary(p) for p in result.packs}
        self.assertEqual(summary["ccpa"]["counts"]["fail"], 0)   # CCPA has no lawful-basis obligation
        self.assertEqual(summary["lgpd"]["counts"]["fail"], 1)

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

    def test_closed_log_call_does_not_claim_later_lines(self):
        # Found by reviewing real findings on saleor: a log call that had already
        # closed was "still open" for the def / raise / call that followed it.
        source = (
            "def f(order, user_email):\n"
            "    logger.warning('Multiple users returned for single sub ID')\n"
            "    user = User.objects.get_or_create(\n"
            "        email=user_email,\n"
            "    )\n"
            "    logger.warning(\n"
            "        'Failed to complete checkout %s.', order.pk\n"
            "    )\n"
            "\n"
            "def g(\n"
            "    phone_number: str, home_address: str\n"
            "):\n"
            "    pass\n"
        )
        self.assertEqual(self._log_categories(source), [])

    def test_record_ids_and_owner_names_are_not_the_data(self):
        ids = (
            "def f(payment, payment_intent_id, payment_information):\n"
            "    logger.warning('not found', extra={'payment_intent': payment_intent_id})\n"
            "    logger.exception('void failed %s, %s', payment.id, payment.psp_reference)\n"
            "    logger.info('order', extra={'order_id': payment.order_id})\n"
            "    logger.error(\n"
            "        'gateway %s unavailable',\n"
            "        payment_information.gateway,\n"
            "    )\n"
        )
        self.assertEqual(self._log_categories(ids), [])
        self.assertEqual(self._log_categories("function f(payment) {\n  console.log('paid', payment.id, payment.orderId);\n}\n", "f.js"), [])
        # Identifiers that are themselves personal data still count, and so does the leaf of a chain.
        real = "def f(user, order):\n    logger.info('upi %s device %s', user.upi_id, user.device_id)\n    print(order.customer.email)\n"
        self.assertEqual(self._log_categories(real), ["Contact", "Device", "Financial"])

    def test_multiline_log_call_is_flagged_and_neighbour_line_is_not(self):
        flagged = "function f(req) {\n  console.log(\n    'refund',\n    req.body.phone_number\n  );\n}\n"
        self.assertEqual(self._log_categories(flagged, "f.js"), ["Contact"])
        clean = "async function f(req) {\n  await Order.create({ email: req.body.email });\n  console.log('order created', order.id);\n}\n"
        self.assertEqual(self._log_categories(clean, "f.js"), [])


class ProcessorFlowTests(unittest.TestCase):
    """Which data reaches which third party."""

    def _flows(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                (Path(tmp) / name).write_text(text, encoding="utf-8")
            return sorted((e.file, e.line, e.metadata["data_category"], e.metadata["third_party"], e.metadata["flow"]) for e in scan_processor_flows(tmp))

    def test_direct_arguments_across_languages(self):
        flows = self._flows(
            {
                "a.py": "import stripe\n\ndef charge(user):\n    stripe.Customer.create(\n        email=user.email,\n        name=user.full_name,\n    )\n",
                "c.ts": 'import mixpanel from "mixpanel-browser";\nexport function track(u: User) {\n  mixpanel.identify(u.id);\n  mixpanel.people.set({ $email: u.email, plan: u.plan });\n  saveLocal({ aadhaar: u.aadhaar });\n}\n',
                "d.html": '<script async src="https://www.googletagmanager.com/gtag/js"></script><script>\ngtag("event", "signup", { email: form.email.value });\n</script>\n',
                "e.php": '<?php\n$hubspot = \\HubSpot\\Factory::createWithAccessToken($t);\n$hubspot->crm()->contacts()->basicApi()->create(["email" => $email, "phone" => $phone_number]);\n',
                "f.go": 'package x\nimport "github.com/razorpay/razorpay-go"\nfunc pay(u User) {\n\tclient := razorpay.NewClient(k, s)\n\tclient.Order.Create(map[string]interface{}{"email": u.Email}, nil)\n\tfmt.Println(u.Aadhaar)\n}\n',
            }
        )
        self.assertEqual(
            flows,
            [
                ("a.py", 4, "Contact", "Stripe", "direct"),
                ("a.py", 4, "Identity", "Stripe", "direct"),
                ("c.ts", 4, "Contact", "Mixpanel", "direct"),
                ("d.html", 2, "Contact", "Google Analytics", "direct"),
                ("e.php", 3, "Contact", "HubSpot", "direct"),
                ("f.go", 5, "Contact", "Razorpay", "direct"),
            ],
        )

    def test_one_hop_variable_and_url_constant(self):
        flows = self._flows(
            {
                "b.py": 'import razorpay\nclient = razorpay.Client(auth=(K, S))\n\ndef pay(req):\n    payload = {"amount": 1, "notes": {"phone_number": req.phone_number}}\n    order = client.order.create(payload)\n    save(order.id, req.email)\n',
                "s.py": 'import requests\nMSG91_URL = "https://control.msg91.com/api/v5/flow/"\n\ndef remind(phone_number):\n    requests.post(\n        MSG91_URL,\n        json={"recipients": [{"mobiles": phone_number}]},\n    )\n',
            }
        )
        self.assertEqual(flows, [("b.py", 6, "Contact", "Razorpay", "one_hop"), ("s.py", 5, "Contact", "MSG91", "direct")])

    def test_injected_and_instance_held_clients(self):
        flows = self._flows(
            {
                "pay.py": 'import razorpay\n\nclass Gateway:\n    def __init__(self):\n        self.client = razorpay.Client(auth=(K, S))\n\n    def charge(self, user):\n        self.client.order.create({"email": user.email, "amount": 1})\n',
                "svc.ts": 'import Stripe from "stripe";\n\nexport class Billing {\n  constructor(private readonly stripe: Stripe, private db: Db) {}\n\n  async createCustomer(user: User) {\n    return this.stripe.customers.create({ email: user.email, name: user.full_name });\n  }\n}\n',
                "Svc.java": 'import com.razorpay.RazorpayClient;\n\npublic class PayService {\n  private final RazorpayClient razorpayClient;\n\n  public void pay(User u) {\n    razorpayClient.orders.create(Map.of("email", u.getEmail()));\n  }\n}\n',
                "inj.py": 'from mixpanel import Mixpanel\n\ndef track_signup(mp: Mixpanel, user):\n    mp.track(user.id, "signup", {"email": user.email})\n',
                "h.go": 'package x\nimport razorpay "github.com/razorpay/razorpay-go"\ntype Svc struct {\n\trzp *razorpay.Client\n}\nfunc (s *Svc) Pay(u User) {\n\ts.rzp.Order.Create(map[string]interface{}{"phone_number": u.Phone}, nil)\n}\n',
            }
        )
        self.assertEqual(
            [(f[0], f[2], f[3]) for f in flows],
            [
                ("Svc.java", "Contact", "Razorpay"),
                ("h.go", "Contact", "Razorpay"),
                ("inj.py", "Contact", "Mixpanel"),
                ("pay.py", "Contact", "Razorpay"),
                ("svc.ts", "Contact", "Stripe"),
                ("svc.ts", "Identity", "Stripe"),
            ],
        )

    def test_vendor_data_objects_and_record_ids_are_not_flows(self):
        # A parameter typed as the vendor's data object is a response, not a client;
        # passing an id is not passing the record.
        flows = self._flows(
            {
                "hooks.py": "import stripe\nfrom stripe.stripe_object import StripeObject\n\ndef handle(payment_intent: StripeObject, payment):\n"
                "    update(payment, payment_intent.amount)\n    stripe.PaymentIntent.retrieve(payment_intent_id)\n"
                "    stripe.Refund.create(payment_intent=payment.intent_id, metadata={'payment': payment.id})\n"
            }
        )
        self.assertEqual(flows, [])

    def test_vendor_response_is_not_followed(self):
        # `order` is what Razorpay returned. Saving it next to an email is not sending the email to Razorpay.
        flows = self._flows(
            {"x.js": 'const Razorpay = require("razorpay");\nconst rzp = new Razorpay({ key_id: K });\nasync function f(req) {\n  const order = await rzp.orders.create({ amount: 1 });\n  await Repayment.create({ email: req.body.email, razorpay_order: order.id });\n}\n'}
        )
        self.assertEqual(flows, [])

    def test_flows_reconcile_against_processor_record(self):
        result = _check(EXAMPLE)
        self.assertEqual(result.model.flows(), {"msg91": {"contact"}, "razorpay": {"contact"}})
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            _edit_manifest(repo, "    data_categories: [contact]      # what the code passes to Razorpay\n", "")
            result = _check(repo)
            finding = next(f for f in result.open_findings() if f.rule == "D009")
            self.assertEqual((finding.processor, finding.category, finding.activity), ("razorpay", "contact", "repayments"))
            self.assertEqual(next(a for a in result.assessments if a.id == "OBL-08").status, "fail")
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            undeclared = next(f for f in _check(repo).open_findings() if f.rule == "D003")
            self.assertIn("sends Contact, Location data to Mixpanel", undeclared.detail)
            flows = next(a for a in _check(repo).activities_view if a["id"] == "repayments")["detected_flows"]
            self.assertIn({"processor": "Mixpanel", "categories": ["Contact", "Location"]}, flows)


class CrossFileFlowTests(unittest.TestCase):
    """Data that reaches a vendor through a wrapper defined somewhere else."""

    FILES = {
        "lib/notify.py": 'import requests\nMSG91_URL = "https://control.msg91.com/api/v5/flow/"\n\ndef send_sms(phone, text):\n    requests.post(\n        MSG91_URL,\n        json={"mobiles": phone, "body": text},\n    )\n\ndef healthcheck():\n    requests.get(MSG91_URL)\n',
        "app/signup.py": 'from lib.notify import send_sms\n\ndef signup(user):\n    send_sms(user.phone_number, "welcome")\n    audit(user.aadhaar)\n',
        "app/other.py": "def send_sms(a, b):\n    pass\n\ndef x(user):\n    send_sms(user.email, 1)\n",
        "app/reminders.py": 'from lib import notify\n\ndef remind_all(users):\n    for u in users:\n        notify_user(u.mobile_number)\n\ndef notify_user(number):\n    notify.send_sms(number, "due")\n',
        "web/analytics.ts": 'import mixpanel from "mixpanel-browser";\n\nexport const track = (event: string, props: Record<string, unknown>) => {\n  mixpanel.track(event, props);\n};\n\nexport function identify(userId: string, traits: object) {\n  mixpanel.people.set(traits);\n}\n',
        "web/checkout.tsx": 'import { track, identify } from "./analytics";\n\nexport function Checkout({ user }) {\n  track("checkout", { email: user.email, pincode: user.pincode });\n  identify(user.id, {\n    full_name: user.full_name,\n  });\n  return null;\n}\n',
        "web/unrelated.tsx": 'const track = (a, b) => {};\ntrack("x", { email: 1 });\n',
        "svc/sms.go": 'package svc\n\nconst exotelURL = "https://api.exotel.com/v1/Accounts/x/Sms/send"\n\nfunc SendOTP(phoneNumber string, otp string) error {\n\t_, err := http.PostForm(exotelURL, url.Values{"To": {phoneNumber}, "Body": {otp}})\n\treturn err\n}\n',
        "svc/login.go": "package svc\n\nfunc Login(u User) {\n\tSendOTP(u.PhoneNumber, gen())\n}\n",
        "php/Crm.php": '<?php\nclass Crm {\n  public function pushContact($email, $name) {\n    $hubspot = \\HubSpot\\Factory::createWithAccessToken($t);\n    $hubspot->crm()->contacts()->basicApi()->create(["e" => $email]);\n  }\n}\n',
        "php/Register.php": "<?php\nclass Register {\n  function handle($req) {\n    $crm->pushContact($req->email, $req->full_name);\n  }\n}\n",
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        for name, text in self.FILES.items():
            path = Path(self.tmp.name) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.flows = {
            (e.file, e.line, e.metadata["data_category"], e.metadata["third_party"]): e.metadata for e in scan_processor_flows(self.tmp.name)
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_wrapper_calls_are_followed_across_files(self):
        self.assertEqual(self.flows[("app/signup.py", 4, "Contact", "MSG91")]["via"], "lib/notify.py:4:send_sms")
        self.assertEqual(self.flows[("web/checkout.tsx", 4, "Contact", "Mixpanel")]["flow"], "wrapper")
        self.assertIn(("web/checkout.tsx", 4, "Location", "Mixpanel"), self.flows)
        self.assertEqual(self.flows[("web/checkout.tsx", 5, "Identity", "Mixpanel")]["via"], "web/analytics.ts:7:identify")
        self.assertIn(("svc/login.go", 4, "Contact", "Exotel"), self.flows)       # same Go package, no import needed
        self.assertIn(("php/Register.php", 4, "Contact", "HubSpot"), self.flows)

    def test_wrapper_of_a_wrapper(self):
        flow = self.flows[("app/reminders.py", 5, "Contact", "MSG91")]
        self.assertEqual((flow["via"], flow["wrapper_depth"]), ("app/reminders.py:7:notify_user", 2))

    def test_same_name_without_an_import_is_not_the_wrapper(self):
        files = {key[0] for key in self.flows}
        self.assertNotIn("app/other.py", files)
        self.assertNotIn("web/unrelated.tsx", files)
        # Aadhaar goes to audit(), not to send_sms().
        self.assertFalse(any(key[2] == "Government ID" for key in self.flows))

    def test_arguments_only_and_no_config_constants(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "pay.py").write_text(
                'import stripe\n\ndef f(pm_id, user):\n    payment_method = stripe.PaymentMethod.retrieve(pm_id)\n'
                '    session = stripe.checkout.Session.create(mode="payment", billing_address_collection="required", customer_update={"address": "auto"})\n'
                "    customer = create_customer(user.email)\n    stripe.billing_portal.Session.create(customer=customer)\n",
                encoding="utf-8",
            )
            (Path(tmp) / "tests").mkdir()
            (Path(tmp) / "tests" / "test_pay.py").write_text("import stripe\n\ndef test_x(user):\n    stripe.Customer.create(email=user.email)\n", encoding="utf-8")
            self.assertEqual(scan_processor_flows(tmp), [])

    def test_cross_file_flow_reaches_the_processor_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "services/onboarding/welcome.py").write_text(
                "from services.notifications.sms import send_reminder\n\ndef welcome(applicant):\n    send_reminder(applicant.phone_number, 'welcome')\n    send_reminder(applicant.aadhaar, 'kyc')\n",
                encoding="utf-8",
            )
            result = _check(repo)
            finding = next(f for f in result.open_findings() if f.rule == "D009")
            self.assertEqual((finding.processor, finding.category, finding.severity), ("msg91", "government_id", "CRITICAL"))
            self.assertEqual(finding.refs, ["services/onboarding/welcome.py:5"])
            link = next(f for f in result.open_findings() if f.rule == "D003")
            self.assertEqual((link.activity, link.processor, link.severity), ("applicant_onboarding", "msg91", "MEDIUM"))


class RiskScoreTests(unittest.TestCase):
    """Sensitive is not the same as broken."""

    def test_clean_service_with_government_ids_scores_low(self):
        summary = run_scan(str(EXAMPLE), None).summary
        self.assertEqual(summary.risk_level, "LOW")
        self.assertEqual(summary.risk_findings_score, 0)
        self.assertGreater(summary.risk_exposure_score, 0)
        self.assertLessEqual(summary.risk_exposure_score, 15)
        self.assertEqual(summary.risk_score, summary.risk_findings_score + summary.risk_exposure_score)

    def test_defects_drive_the_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            before = run_scan(str(repo), None).summary
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            after = run_scan(str(repo), None).summary
            self.assertGreater(after.risk_findings_score, before.risk_findings_score)
        bad = run_scan("examples/realistic", None).summary
        self.assertIn(bad.risk_level, {"HIGH", "CRITICAL"})
        self.assertGreater(bad.risk_findings_score, 50)

    def test_documentation_placeholders_attribution_and_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text("Send pings to `your-uuid-here@your-hc-domain.com`. Ask priya.sharma@lentra-demo.io.\n", encoding="utf-8")
            (Path(tmp) / "wasm.ts").write_text(
                "/**\n * @author Ebrahim B <ebrahim@gnu.org>\n */\n// length 40 to align with the HEX length of SHA-1 (which is 160 bit)\n"
                "const sample = 'a@b.com';\nconst owner = 'priya.sharma@lentra-demo.io';\nconst digest = crypto.createHash('sha1');\n",
                encoding="utf-8",
            )
            scan = run_scan(tmp, None)
            literals = {(item.file, item.line): item.severity for item in scan.evidence if item.kind == "literal_personal_data"}
            self.assertEqual(literals, {("README.md", 1): "LOW", ("wasm.ts", 2): "LOW", ("wasm.ts", 5): "LOW", ("wasm.ts", 6): "HIGH"})
            self.assertEqual([item.line for item in scan.evidence if item.kind == "weak_crypto"], [7])

    def test_secret_references_are_not_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "config.toml").write_text(
                'secret = "env(SUPABASE_AUTH_EXTERNAL_GITHUB_SECRET)"\napi_key = "<your-api-key>"\nclient_secret = "changeme"\n'
                'client_secret = "q7Rk2Vt9Xw4Lm8Pz3Hn6Bc1Dj5Fg0Ys"\n',
                encoding="utf-8",
            )
            lines = sorted(item.line for item in run_scan(tmp, None).evidence if item.kind == "secret_exposure")
            self.assertEqual(lines, [4])

    def test_role_mailboxes_and_lock_files_are_not_exposure(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ci.yml").write_text("run: git config user.email 'bot@acme.io'\ncontact: privacy@acme.io\nowner: priya.sharma@acme.io\n", encoding="utf-8")
            (Path(tmp) / "yarn.lock").write_text('"stripe@^1.0.0":\n  integrity sha512-234567890123 2345 6789 0123\n', encoding="utf-8")
            scan = run_scan(tmp, None)
            literals = {(item.line, item.severity) for item in scan.evidence if item.kind == "literal_personal_data"}
            self.assertEqual(literals, {(1, "LOW"), (2, "LOW"), (3, "HIGH")})
            self.assertFalse(any(item.file == "yarn.lock" for item in scan.evidence))
            self.assertEqual(scan.summary.third_parties, [])


class SyncTests(unittest.TestCase):
    def _drifted(self, tmp):
        repo = _copy_example(tmp)
        shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
        (repo / "services/analytics").mkdir()
        (repo / "services/analytics/export.py").write_text(
            "def export(request):\n    row = {'email': request.json['email'], 'aadhaar': request.json['aadhaar']}\n    db.insert(row)\n", encoding="utf-8"
        )
        return repo

    def test_sync_fixes_mechanical_drift_and_keeps_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._drifted(tmp)
            plan, original, updated = sync_manifest(_check(repo))
            self.assertEqual(plan.add_categories, {"repayments": ["location"]})
            self.assertEqual(plan.link_processors, {"repayments": ["mixpanel"]})
            self.assertEqual(plan.new_processors["mixpanel"]["data_categories"], ["contact", "location"])
            self.assertEqual([a["id"] for a in plan.new_activities], ["services_analytics"])
            self.assertIn("# LendFlow: a worked example of privacy as code.", updated)
            self.assertIn("# what the code passes to Razorpay", updated)
            self.assertIn("data_categories: [contact, financial, location]", updated)
            (repo / "privacy.yaml").write_text(updated, encoding="utf-8")
            after = _check(repo)
            rules = set(_rules(after))
            self.assertFalse(rules & {"D001", "D002", "D003", "D009"}, rules)
            # What needs a human is still open, and sync does not pretend otherwise.
            self.assertTrue({"D006", "D007", "P001", "P003"} <= rules)
            self.assertTrue(build_plan(after).empty())

    def test_prune_removes_stale_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "services/notifications/sms.py").unlink()
            _edit_manifest(repo, "data_categories: [contact, financial]", "data_categories: [contact, financial, location]")
            keep, _, unchanged = sync_manifest(_check(repo))
            self.assertTrue(keep.empty())
            self.assertTrue(any("--prune" in note for note in keep.notes))
            plan, _, updated = sync_manifest(_check(repo), prune=True)
            self.assertEqual(plan.remove_categories, {"repayments": ["location"]})
            self.assertEqual(plan.remove_processors, ["msg91"])
            manifest = parse_manifest(__import__("yaml").safe_load(updated))
            self.assertEqual([p.id for p in manifest.processors], ["razorpay"])
            self.assertEqual(manifest.activity("reminders").processors, [])
            self.assertEqual(manifest.activity("repayments").data_categories, ["contact", "financial"])

    def test_block_style_lists_and_json_manifests(self):
        block = (
            "version: 1\nprocessing_activities:\n  - id: repayments\n    paths:\n      - services/payments/**\n    data_categories:\n      - contact   # email and phone\n      - financial\n"
            "    processors:\n      - razorpay\nprocessors:\n  - id: razorpay\n    data_categories:\n      - contact\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            for name in ("services/onboarding", "services/notifications", "web"):
                shutil.rmtree(repo / name)
            (repo / "privacy.yaml").write_text(block, encoding="utf-8")
            plan, _, updated = sync_manifest(_check(repo))
            self.assertIn("      - financial\n      - location\n", updated)
            self.assertIn("      - razorpay\n      - mixpanel\n", updated)
            self.assertIn("      - contact   # email and phone\n", updated)
            (repo / "privacy.yaml").unlink()
            (repo / "privacy.json").write_text(json.dumps(__import__("yaml").safe_load(block)), encoding="utf-8")
            scan = run_scan(str(repo), None)
            result = run_check(scan, load_manifest(repo / "privacy.json"), today=TODAY)
            _, _, updated_json = sync_manifest(result)
            data = json.loads(updated_json)
            self.assertEqual(data["processing_activities"][0]["data_categories"], ["contact", "financial", "location"])
            self.assertEqual([p["id"] for p in data["processors"]], ["razorpay", "mixpanel"])

    def test_cli_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._drifted(tmp)
            before = (repo / "privacy.yaml").read_text(encoding="utf-8")
            self.assertEqual(main(["sync", "--repo", str(repo)]), 0)
            self.assertEqual((repo / "privacy.yaml").read_text(encoding="utf-8"), before)
            self.assertEqual(main(["sync", "--repo", str(repo), "--write"]), 0)
            self.assertNotEqual((repo / "privacy.yaml").read_text(encoding="utf-8"), before)
            self.assertEqual(main(["sync", "--repo", str(repo), "--write"]), 0)
            self.assertEqual(main(["sync", "--repo", tmp]), 2)


class ScanIntegrationTests(unittest.TestCase):
    def test_scan_carries_the_privacy_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            pack = Path(tmp) / "pack"
            self.assertEqual(main(["scan", "--repo", str(repo), "--evidence-pack", str(pack)]), 0)
            report = json.loads((pack / "report.json").read_text(encoding="utf-8"))
            pac = report["privacy_as_code"]
            self.assertEqual(pac["summary"]["open_findings"], 3)
            self.assertEqual({f["rule"] for f in pac["findings"] if f["status"] == "open"}, {"D002", "D003", "P001"})
            self.assertTrue((pack / "privacy-check" / "privacy-check.html").is_file())
            html = (pack / "report.html").read_text(encoding="utf-8")
            self.assertIn('data-tab="pac"', html)
            self.assertIn("sends Contact, Location data to Mixpanel", html)
            flows = {(e["metadata"]["data_category"], e["metadata"]["third_party"]) for e in report["evidence"] if e["kind"] == "processor_data_flow"}
            self.assertEqual(flows, {("Contact", "Razorpay"), ("Contact", "MSG91"), ("Contact", "Mixpanel"), ("Location", "Mixpanel")})
            contact_flow = next(f for f in report["evidence_graph"]["data_flows"] if f["data_category"] == "Location")
            self.assertEqual(contact_flow["third_parties"], ["Mixpanel"])
            out = Path(tmp) / "plain.json"
            self.assertEqual(main(["scan", "--repo", str(repo), "--no-manifest", "--out", str(Path(tmp) / "p.html"), "--json-out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["privacy_as_code"], {})

    def test_broken_manifest_never_fails_a_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "privacy.yaml").write_text("version: 1\nprocessing_activities:\n  - id: a\n", encoding="utf-8")
            out = Path(tmp) / "r.json"
            self.assertEqual(main(["scan", "--repo", str(repo), "--out", str(Path(tmp) / "r.html"), "--json-out", str(out)]), 0)
            self.assertIn("Invalid manifest", json.loads(out.read_text(encoding="utf-8"))["privacy_as_code"]["error"])

    def test_report_without_manifest_explains_how_to_start(self):
        html = render_html(run_scan("examples/realistic", None))
        self.assertIn("No privacy manifest in this repository", html)
        self.assertIn("svikruti init", html)

    def test_dashboard_tab_renders(self):
        try:
            from streamlit.testing.v1 import AppTest
        except ImportError:
            self.skipTest("streamlit not installed")
        import os

        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            report = Path(tmp) / "report.json"
            self.assertEqual(main(["scan", "--repo", str(repo), "--out", str(Path(tmp) / "r.html"), "--json-out", str(report)]), 0)
            os.environ["SVIKRUTI_DASHBOARD_REPORT"] = str(report)
            try:
                app = AppTest.from_file(str(Path("src/svikruti/dashboard.py").resolve()), default_timeout=60).run()
            finally:
                os.environ.pop("SVIKRUTI_DASHBOARD_REPORT", None)
            self.assertEqual(list(app.exception), [])
            self.assertIn("Privacy as Code", [tab.label for tab in app.tabs])
            self.assertIn(("Open findings", "3"), [(m.label, m.value) for m in app.metric])
            self.assertIn("Mixpanel: Contact, Location", " ".join(block.value for block in app.markdown))
            self.assertIn(("Unprotected high-risk fields", "0"), [(m.label, m.value) for m in app.metric])
            self.assertIn("#### Where personal data is stored", [block.value for block in app.markdown])


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
            self.assertEqual(
                diff["new_processor_flows"],
                [{"data_category": "Contact", "third_party": "Mixpanel"}, {"data_category": "Location", "third_party": "Mixpanel"}],
            )
            self.assertTrue(all(item["file"] == "services/payments/refund.js" for item in diff["new"]))

    def test_legacy_reports_without_fingerprints_still_diff(self):
        base = run_scan(str(EXAMPLE), None).to_dict()
        for item in base["evidence"]:
            item["metadata"].pop("fingerprint")
        diff = diff_reports(base, run_scan(str(EXAMPLE), None).to_dict())
        self.assertEqual(diff["matching"], "legacy-position-free")
        self.assertEqual((diff["new"], diff["resolved"]), ([], []))


class InventoryTests(unittest.TestCase):
    """Which table, which column, and where that category goes."""

    def test_inventory_joins_fields_to_the_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            result = _check(repo)
            rows = {(row["store"], row["field"]): row for row in result.inventory}
            aadhaar = rows[("Applicant", "aadhaar")]
            self.assertEqual((aadhaar["data_category"], aadhaar["high_risk"], aadhaar["activity"], aadhaar["declared"]), ("Government ID", True, "applicant_onboarding", True))
            self.assertEqual(aadhaar["file"], "services/onboarding/models.py")
            email = rows[("Repayment", "email")]   # Sequelize model in a .js file
            self.assertEqual((email["activity"], email["reaches_logs"], email["sent_to"]), ("repayments", True, ["Mixpanel", "Razorpay"]))
            files = write_check_pack(result, str(Path(tmp) / "out"))
            csv_text = Path(files["inventory"]).read_text(encoding="utf-8")
            self.assertIn("Applicant,pan_number,Government ID,yes,services/onboarding/models.py", csv_text)
            self.assertIn("Data inventory (", render_check_html(result))

    def test_inventory_without_manifest_and_container_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inv.csv"
            self.assertEqual(main(["scan", "--repo", "examples/realistic", "--no-manifest", "--out", str(Path(tmp) / "r.html"), "--inventory-out", str(out)]), 0)
            text = out.read_text(encoding="utf-8")
            self.assertIn("customers,aadhaar_number,Government ID,yes,customer_schema.sql", text)   # table name from CREATE TABLE
            self.assertIn("Patient,diagnosis,Health,yes,django_patient.py", text)
            self.assertIn("no manifest", text)

    def test_js_orm_models_are_stored_fields(self):
        from svikruti.scanner.semantic import scan_semantic_evidence

        files = {
            "seq.js": 'const Repayment = sequelize.define("Repayment", {\n  email: DataTypes.STRING,\n  phone_number: { type: DataTypes.STRING, allowNull: false },\n  amount: DataTypes.INTEGER,\n});\n',
            "mongo.ts": "const userSchema = new mongoose.Schema({\n  full_name: String,\n  aadhaar: { type: String, select: false },\n});\n",
            "drizzle.ts": 'export const users = pgTable("users", {\n  id: serial("id"),\n  email: text("email").notNull(),\n});\n',
            "entity.ts": "@Entity()\nexport class Patient {\n  @Column()\n  email: string;\n\n  @Column({ nullable: true })\n  diagnosis?: string;\n\n  notStored: string;\n}\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in files.items():
                (Path(tmp) / name).write_text(text, encoding="utf-8")
            found = sorted(
                (e.file, e.metadata.get("class"), e.metadata["field"], e.metadata["data_category"])
                for e in scan_semantic_evidence(tmp).evidence
                if e.metadata.get("semantic_role") == "storage_field"
            )
        self.assertEqual(
            found,
            [
                ("drizzle.ts", "users", "email", "Contact"),
                ("entity.ts", "Patient", "diagnosis", "Health"),
                ("entity.ts", "Patient", "email", "Contact"),
                ("mongo.ts", "user", "aadhaar", "Government ID"),
                ("mongo.ts", "user", "full_name", "Identity"),
                ("seq.js", "Repayment", "email", "Contact"),
                ("seq.js", "Repayment", "phone_number", "Contact"),
            ],
        )


class AiProviderTests(unittest.TestCase):
    """Personal data in prompts is personal data sent to a processor."""

    FILES = {
        "summarise.py": 'from openai import OpenAI\n\nclient = OpenAI()\n\ndef summarise(customer):\n    prompt = f"Summarise the account of {customer.full_name} ({customer.email})"\n    return client.chat.completions.create(\n        model="gpt-4o",\n        messages=[{"role": "user", "content": prompt}],\n    )\n',
        "draft.ts": 'import Anthropic from "@anthropic-ai/sdk";\nconst anthropic = new Anthropic();\nexport async function draft(user) {\n  return anthropic.messages.create({\n    model: "claude",\n    messages: [{ role: "user", content: `Write to ${user.email} about ${user.aadhaar}` }],\n  });\n}\n',
        "chain.py": 'from langchain_openai import ChatOpenAI\nfrom langchain_core.prompts import ChatPromptTemplate\n\nllm = ChatOpenAI(model="gpt-4o-mini")\nprompt = ChatPromptTemplate.from_template("Advise {name} on {question}")\nchain = prompt | llm\n\ndef ask(user, question):\n    return chain.invoke({"name": user.full_name, "question": question})\n',
        "gemini.py": 'from google import genai\nclient = genai.Client()\n\ndef go(p):\n    client.models.generate_content(model="gemini", contents=f"Patient {p.diagnosis}")\n',
        "bedrock.py": 'import boto3\nbedrock = boto3.client("bedrock-runtime")\n\ndef go(u):\n    bedrock.converse(modelId="x", messages=[{"role": "user", "content": [{"text": u.email}]}])\n',
        "embed.py": 'from openai import OpenAI\nclient = OpenAI()\n\ndef ok(doc):\n    client.embeddings.create(model="e", input=doc.text)\n',
    }

    def test_flows_to_ai_providers(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in self.FILES.items():
                (Path(tmp) / name).write_text(text, encoding="utf-8")
            flows = sorted((e.file, e.metadata["data_category"], e.metadata["third_party"], e.metadata["ai_provider"]) for e in scan_processor_flows(tmp))
        self.assertEqual(
            flows,
            [
                ("bedrock.py", "Contact", "AWS Bedrock", True),
                ("chain.py", "Identity", "OpenAI", True),
                ("draft.ts", "Contact", "Anthropic", True),
                ("draft.ts", "Government ID", "Anthropic", True),
                ("gemini.py", "Health", "Google Gemini", True),
                ("summarise.py", "Contact", "OpenAI", True),
                ("summarise.py", "Identity", "OpenAI", True),
            ],
        )

    def test_ai_allowlist_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            (repo / "services/notifications/assist.py").write_text(self.FILES["summarise.py"], encoding="utf-8")
            _edit_manifest(repo, "    processors: [msg91]\n", "    processors: [msg91, openai]\n")
            _edit_manifest(repo, "data_categories: [contact]\n    data_subjects: [borrowers]\n    purposes: [repayment reminders]", "data_categories: [contact, identity]\n    data_subjects: [borrowers]\n    purposes: [repayment reminders]")
            _edit_manifest(
                repo,
                "processors:\n  - id: razorpay",
                "processors:\n  - id: openai\n    name: OpenAI\n    purpose: Drafting reminders\n    country: US\n    contract: DPA-2026-002\n    transfer_mechanism: SCC\n    data_categories: [contact, identity]\n  - id: razorpay",
            )
            result = _check(repo)
            p006 = sorted((f.category, f.severity) for f in result.open_findings() if f.rule == "P006")
            self.assertEqual(p006, [("contact", "HIGH"), ("identity", "HIGH")])
            self.assertEqual(next(a for a in result.assessments if a.id == "OBL-08").status, "fail")
            _edit_manifest(repo, "  ai_allowed_categories: []", "  ai_allowed_categories: [identity]")
            self.assertEqual([f.category for f in _check(repo).open_findings() if f.rule == "P006"], ["contact"])
            _edit_manifest(repo, "  ai_allowed_categories: [identity]", "  ai_allowed_categories: [identity, contact]")
            # Allowed for AI, but reminders rely on consent and this call never checks it.
            self.assertEqual(_rules(_check(repo)), ["P008"])


    def test_vendor_names_in_prose_are_not_integrations(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "prompts.py").write_text(
                'SYSTEM = """You answer questions about LLM providers such as OpenAI, Anthropic, Groq and Cohere."""\n'
                "# TODO: compare with Mistral\n"
                "def check_coherence(x):\n    return x.striped\n",
                encoding="utf-8",
            )
            (Path(tmp) / "catalog.json").write_text('{"integrations": ["Stripe", "Cohere"]}', encoding="utf-8")
            (Path(tmp) / "real.py").write_text("from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n", encoding="utf-8")
            (Path(tmp) / "package.json").write_text('{"dependencies": {"stripe": "^14.0.0"}}', encoding="utf-8")
            vendors = sorted(run_scan(tmp, None).summary.third_parties)
        self.assertEqual(vendors, ["OpenAI", "Stripe"])


class StoredDataTests(unittest.TestCase):
    """Field protection (P007) and erasure coverage (D010)."""

    def test_example_fields_are_protected_and_erasable(self):
        result = _check(EXAMPLE)
        rows = {(row["store"], row["field"]): row for row in result.inventory}
        self.assertEqual(rows[("Applicant", "aadhaar")]["protection"], "encrypted")
        self.assertEqual(rows[("Applicant", "aadhaar")]["protection_evidence"], "services/onboarding/kyc.py:19")
        self.assertTrue(rows[("Applicant", "email")]["erasure"].startswith("reached by handle_erasure_request()"))
        self.assertTrue(rows[("Repayment", "email")]["erasure"].startswith("retained: Repayment records kept 8 years"))
        self.assertEqual(_rules(result), [])

    def test_unprotected_aadhaar_and_unerased_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            kyc = repo / "services/onboarding/kyc.py"
            kyc.write_text(kyc.read_text(encoding="utf-8").replace('encrypt_field(payload["aadhaar"])', 'payload["aadhaar"].encode()'), encoding="utf-8")
            (repo / "services/onboarding/erasure.py").unlink()
            _edit_manifest(repo, '    Repayment: "Repayment records kept 8 years after loan closure under the PML Rules and tax law"\n', "")
            _edit_manifest(repo, "erasure:\n  retained:\n", "erasure:\n  retained: {}\n")
            findings = {(f.rule, tuple(f.fields)): f for f in _check(repo).open_findings()}
            p007 = findings[("P007", ("Applicant.aadhaar",))]
            self.assertEqual((p007.severity, p007.refs), ("CRITICAL", ["services/onboarding/models.py:12"]))
            self.assertIn("binary column", p007.detail)
            self.assertNotIn(("P007", ("Applicant.pan_number",)), findings)   # still encrypted where it is written
            d010 = findings[("D010", ("*",))]
            self.assertIn("No erasure or retention code was found", d010.detail)
            self.assertEqual(d010.severity, "HIGH")

    def test_erasure_paths_cascades_and_dev_tools(self):
        from svikruti.pac.datastore import cascades, erasure_coverage, erasure_paths, is_erasure_name

        for name, expected in {
            "deleteUser": True, "handle_erasure_request": True, "purgeExpiredUsers": True, "process_dsar": True,
            "AccountDelete": True, "delete_item": False, "deleteFile": False, "get_users_to_remove": False,
        }.items():
            self.assertEqual(is_erasure_name(name), expected, name)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "models.py").write_text(
                "class Customer(models.Model):\n    email = models.EmailField()\n\nclass Address(models.Model):\n    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)\n    pincode = models.CharField()\n\n"
                "class Invoice(models.Model):\n    customer = models.ForeignKey(\"Customer\", on_delete=models.PROTECT)\n    pan_number = models.CharField()\n\n"
                "class Subscription(models.Model):\n    user = models.OneToOneField(User, models.CASCADE)\n    invoice_email = models.EmailField()\n",
                encoding="utf-8",
            )
            (root / "gdpr.py").write_text("def delete_customer(customer_id):\n    Customer.objects.filter(id=customer_id).delete()\n\ndef delete_user_stats():\n    Invoice.objects.filter(x=1).count()\n", encoding="utf-8")
            (root / "views.py").write_text("def close(request):\n    user = request.user\n    user.delete()\n", encoding="utf-8")
            (root / "cleardb.py").write_text("def handle():\n    Invoice.objects.all().delete()\n", encoding="utf-8")
            files = ["models.py", "gdpr.py", "views.py", "cleardb.py"]
            paths = erasure_paths(root, files)
            self.assertEqual(sorted(path.name for path in paths), ["close", "delete_customer", "delete_user_stats"])
            stores = {"Customer": ("models.py", 2), "Address": ("models.py", 6), "Invoice": ("models.py", 10), "Subscription": ("models.py", 14)}
            coverage = erasure_coverage(stores, paths, {}, cascades(root, stores))
            self.assertTrue(coverage["Customer"].startswith("reached by delete_customer()"))
            self.assertEqual(coverage["Address"], "cascade from Customer")
            self.assertEqual(coverage["Invoice"], "")   # PROTECT, a count() is not a delete, and cleardb is a dev tool
            self.assertTrue(coverage["Subscription"].startswith("cascade from User (close()"))

    def test_persistent_vs_transient_classes(self):
        from svikruti.pac.datastore import is_persistent_store

        self.assertTrue(is_persistent_store("app/models.py", "class Customer(models.Model):"))
        self.assertTrue(is_persistent_store("db/schema.sql", "CREATE TABLE users ("))
        self.assertTrue(is_persistent_store("src/user.entity.ts", "@Entity()"))
        self.assertFalse(is_persistent_store("hc/api/models.py", "class ZulipConf(BaseModel):"))
        self.assertFalse(is_persistent_store("saleor/graphql/account/types.py", "class User(ModelObjectType):"))
        self.assertFalse(is_persistent_store("api/SpringCustomerController.java", "public class CustomerPayload {"))


class InlineSuppressionTests(unittest.TestCase):
    def test_inline_suppression_with_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            drift = DRIFT_FILE.read_text(encoding="utf-8").replace(
                '  console.log("refund requested for", email, phone_number);',
                '  // svikruti-ignore[P001]: chargeback evidence, masking ships in Q1\n  console.log("refund requested for", email, phone_number);',
            )
            (repo / "services/payments/refund.js").write_text(drift, encoding="utf-8")
            result = _check(repo)
            self.assertNotIn("P001", _rules(result))
            excepted = next(f for f in result.findings if f.rule == "P001")
            self.assertEqual(excepted.status, "excepted")
            self.assertIn("inline: chargeback evidence", excepted.exception_reason)
            self.assertIn("D002", _rules(result))   # the rule list limits the suppression

    def test_suppression_without_reason_is_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            drift = DRIFT_FILE.read_text(encoding="utf-8").replace('console.log("refund requested for", email, phone_number);', 'console.log("refund requested for", email, phone_number); // svikruti-ignore')
            (repo / "services/payments/refund.js").write_text(drift, encoding="utf-8")
            result = _check(repo)
            self.assertIn("P001", _rules(result))
            self.assertTrue(any("without a reason" in warning for warning in result.manifest.warnings))

    def test_scan_suppression_leaves_score_and_marks_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.py").write_text("def f(user):\n    logger.info('x %s', user.email)  # svikruti-ignore: masked by the log formatter\n", encoding="utf-8")
            (Path(tmp) / "b.py").write_text("def f(user):\n    logger.info('x %s', user.email)\n", encoding="utf-8")
            scan = run_scan(tmp, None)
            logged = {item.file: item.metadata.get("suppressed") for item in scan.evidence if "log" in item.kind}
            self.assertEqual(logged["a.py"], "masked by the log formatter")
            self.assertIsNone(logged["b.py"])
            out = Path(tmp) / "r.sarif"
            write_sarif(scan, str(out))
            results = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
            suppressed = [r for r in results if r.get("suppressions")]
            self.assertTrue(suppressed and all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.py" for r in suppressed))


class InventoryCliTests(unittest.TestCase):
    def test_inventory_command(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(main(["inventory", "--repo", str(EXAMPLE), "--category", "government_id"]), 0)
        text = buffer.getvalue()
        self.assertIn("Applicant.aadhaar", text)
        self.assertIn("encrypted", text)
        self.assertNotIn("Applicant.email", text)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inv.json"
            self.assertEqual(main(["inventory", "--repo", "examples/realistic", "--stored-only", "--format", "json", "--out", str(out)]), 0)
            rows = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(rows and all(row["persistent"] for row in rows))
            self.assertNotIn("CustomerPayload", {row["store"] for row in rows})


class RecallBenchmarkTests(unittest.TestCase):
    """benchmarks/recall must not regress: every expected finding stays found."""

    def _run(self, cases):
        import importlib.util

        spec = importlib.util.spec_from_file_location("recall_run", Path("benchmarks/recall/run.py").resolve())
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import yaml

        loaded = yaml.safe_load(Path(cases).read_text(encoding="utf-8"))["cases"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            module.plant(loaded, root)
            return module.evaluate(loaded, root)

    def test_tuning_set(self):
        results = self._run("benchmarks/recall/cases.yaml")
        self.assertEqual([r["case"] + ":" + r["type"] for r in results if not r["passed"]], [])

    def test_channels_set(self):
        results = self._run("benchmarks/recall/channels.yaml")
        self.assertEqual([r["case"] + ":" + r["type"] for r in results if not r["passed"]], [])

    def test_held_out_set(self):
        results = self._run("benchmarks/recall/holdout.yaml")
        misses = [r["case"] + ":" + r["type"] for r in results if not r["passed"]]
        # Documented in RESULTS.md: an identifier named after a vendor reads as that vendor.
        self.assertEqual(misses, ["py-vendor-comment-trap:none-vendor"])


class SchemaAndToolingTests(unittest.TestCase):
    def test_committed_schema_matches_the_loader(self):
        from svikruti.pac.schema import manifest_schema

        schema = manifest_schema()
        committed = json.loads(Path("docs/privacy.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(committed, json.loads(json.dumps(schema)), "run `svikruti schema --out docs/privacy.schema.json`")
        bundled = json.loads(Path("editors/vscode/privacy.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(bundled, committed, "copy docs/privacy.schema.json to editors/vscode/")
        activity = schema["properties"]["processing_activities"]["items"]
        self.assertEqual(activity["required"], ["id", "paths"])
        self.assertIn("lgpd", schema["properties"]["frameworks"]["items"]["anyOf"][0]["enum"])
        self.assertIn("D009", schema["properties"]["exceptions"]["items"]["properties"]["rule"]["enum"])

    def test_example_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        import yaml

        schema = json.loads(Path("docs/privacy.schema.json").read_text(encoding="utf-8"))
        data = json.loads(json.dumps(yaml.safe_load((EXAMPLE / "privacy.yaml").read_text(encoding="utf-8")), default=str))
        validator = jsonschema.Draft7Validator(schema)
        self.assertEqual([e.message for e in validator.iter_errors(data)], [])
        data["processing_activites"] = []
        self.assertEqual(len(list(validator.iter_errors(data))), 1)

    def test_init_writes_editor_hint_and_precommit_hooks_parse(self):
        import yaml

        text = generate_manifest(run_scan(str(EXAMPLE), None))
        self.assertTrue(text.startswith("# yaml-language-server: $schema=https://"))
        from svikruti.reports.exports import PRIVACY_CHECK_WORKFLOW

        with tempfile.TemporaryDirectory() as tmp:
            scan_wf = Path(tmp) / "scan.yml"
            self.assertEqual(main(["init-github-action", "--out", str(scan_wf)]), 0)
            for workflow in (scan_wf.read_text(encoding="utf-8"), PRIVACY_CHECK_WORKFLOW):
                self.assertIn('pip install "svikruti[parsers]"', workflow)   # from PyPI, not the user's checkout
                self.assertNotIn("pip install -e", workflow)
                yaml.safe_load(workflow)
        hooks = yaml.safe_load(Path(".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
        self.assertEqual([hook["id"] for hook in hooks], ["svikruti-check", "svikruti-sync"])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "schema.json"
            self.assertEqual(main(["schema", "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["title"], "Svikruti privacy.yaml")


class GovernanceAppImportTests(unittest.TestCase):
    """The Streamlit workbench reads the same manifest the CI gate enforces."""

    def setUp(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("scanner_import", Path("scanner_import.py").resolve())
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_manifest_becomes_ropa_and_vendor_records(self):
        parsed = self.module.parse_privacy_manifest((EXAMPLE / "privacy.yaml").read_bytes())
        self.assertEqual([r["activity_name"] for r in parsed["ropa"]], ["Loan applicant onboarding and KYC", "EMI repayment collection", "Repayment reminders"])
        repayments = parsed["ropa"][1]
        self.assertEqual(repayments["lawful_basis"], "DPDPA: Legitimate Use; GDPR: Contract")
        self.assertEqual(repayments["kwargs"]["data_processor"], "Razorpay")
        self.assertEqual(repayments["kwargs"]["retention_period"], "8 years after loan closure (tax and PML records)")
        self.assertEqual(parsed["ropa"][0]["_risk_tier"], "High")
        self.assertEqual(parsed["ropa"][0]["kwargs"]["security_measures"], "DPIA: DPIA-2026-003")
        razorpay = parsed["vendors"][0]
        self.assertEqual((razorpay["vendor_name"], razorpay["data_shared"], razorpay["kwargs"]["dpa_status"]), ("Razorpay", "Contact", "COMPLETED"))
        self.assertEqual(parsed["actions"], [])
        summary = self.module.import_summary(parsed, existing_ropa=[{"activity_name": "repayment reminders"}])
        self.assertEqual(summary["ropa"], {"new": 2, "duplicate": 1, "total": 3})

    def test_todos_become_tasks_not_made_up_values(self):
        text = generate_manifest(run_scan(str(EXAMPLE), None))
        parsed = self.module.parse_privacy_manifest(text)
        self.assertTrue(all(r["purpose"] == "Not specified" and r["lawful_basis"] == "To be confirmed" for r in parsed["ropa"]))
        titles = [a["title"] for a in parsed["actions"]]
        self.assertTrue(any(title.startswith("Complete the processing record") for title in titles))
        self.assertIn("Record the contract / DPA for Razorpay", titles)
        self.assertTrue(all(v["kwargs"]["dpa_status"] == "NOT_STARTED" for v in parsed["vendors"]))

    def test_upload_routing(self):
        route = self.module.parse_upload
        self.assertEqual(len(route("privacy.yaml", (EXAMPLE / "privacy.yaml").read_bytes())["ropa"]), 3)
        as_json = json.dumps(__import__("yaml").safe_load((EXAMPLE / "privacy.yaml").read_text(encoding="utf-8")), default=str)
        self.assertEqual(len(route("privacy.json", as_json)["vendors"]), 2)
        report = route("report.json", Path("examples/sample-report.json").read_bytes())
        self.assertGreaterEqual(len(report["ropa"]), 1)
        self.assertGreaterEqual(len(route("sample-vendors.csv", Path("examples/sample-vendors.csv").read_bytes())["vendors"]), 1)
        self.assertGreaterEqual(len(route("sample-actions.csv", Path("examples/sample-actions.csv").read_bytes())["actions"]), 1)
        self.assertGreaterEqual(len(route("sample-ropa.csv", Path("examples/sample-ropa.csv").read_bytes())["ropa"]), 1)
        self.assertIn("unrecognized", route("notes.docx", b"x")["note"])

    def test_check_and_org_results_become_verified_records_and_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            self.assertEqual(main(["check", "--repo", str(repo), "--out-dir", str(Path(tmp) / "c"), "--fail-on", "none"]), 0)
            raw = (Path(tmp) / "c" / "privacy-check.json").read_bytes()
            self.assertTrue(self.module.looks_like_check(raw))
            self.assertFalse(self.module.looks_like_check(Path("examples/sample-report.json").read_bytes()))
            parsed = self.module.parse_upload("privacy-check.json", raw)
            repayments = next(r for r in parsed["ropa"] if r["activity_name"] == "EMI repayment collection")
            self.assertIn("Location", repayments["data_categories"])
            self.assertIn("drift: D002", repayments["_evidence"])
            mixpanel = next(v for v in parsed["vendors"] if v["vendor_name"] == "Mixpanel")
            self.assertEqual((mixpanel["kwargs"]["dpa_status"], mixpanel["kwargs"]["risk_level"]), ("NOT_STARTED", "HIGH"))
            rules = {a["title"].split(":")[0] for a in parsed["actions"]}
            self.assertTrue({"D002", "D003", "P001"} <= rules)
            self.assertIn("refund.js", " ".join(a["description"] for a in parsed["actions"]))

            other = Path(tmp) / "lending"
            shutil.copytree(EXAMPLE, other)
            self.assertEqual(main(["org", str(Path(tmp) / "c"), str(other), "--name", "payments", "--out-dir", str(Path(tmp) / "o")]), 0)
            org = self.module.parse_upload("org-summary.json", (Path(tmp) / "o" / "org-summary.json").read_bytes())
            self.assertEqual(len(org["ropa"]), 6)
            self.assertIn("EMI repayment collection (payments)", [r["activity_name"] for r in org["ropa"]])
            self.assertTrue(any(a["title"].startswith("[payments] D003") for a in org["actions"]))
            self.assertIn("Declared in: lending, payments", next(v for v in org["vendors"] if v["vendor_name"] == "Razorpay")["kwargs"]["notes"])
        self.assertIn("Not a Svikruti", self.module.parse_privacy_check('{"schema_version": "x"}')["note"])

    def test_manifest_detection_and_bad_input(self):
        self.assertTrue(self.module.looks_like_manifest('{"version": 1, "processing_activities": []}'))
        self.assertFalse(self.module.looks_like_manifest(Path("examples/sample-report.json").read_text(encoding="utf-8")))
        self.assertIn("not a privacy manifest", self.module.parse_privacy_manifest("- just\n- a list\n")["note"])
        self.assertIn("Could not parse", self.module.parse_privacy_manifest("a: [unclosed")["note"])


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
            self.assertEqual({p.id: p.data_categories for p in result.manifest.processors}["mixpanel"], ["contact", "location"])
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

    def test_cli_creates_missing_output_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "not" / "yet"
            self.assertEqual(main(["scan", "--repo", str(EXAMPLE), "--out", str(out / "r.html"), "--json-out", str(out / "deeper" / "r.json")]), 0)
            self.assertTrue((out / "r.html").is_file() and (out / "deeper" / "r.json").is_file())

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


class StoredDataSurfaceTests(unittest.TestCase):
    def test_scan_report_and_dashboard_show_where_data_is_stored(self):
        from svikruti.dashboard import inventory_rows

        from svikruti.pac.engine import attach_check

        scan = run_scan(str(EXAMPLE), None)
        attach_check(scan, str(EXAMPLE / "privacy.yaml"))
        self.assertTrue(scan.privacy_as_code.get("inventory"))
        page = render_html(scan)
        self.assertIn("Where personal data is stored", page)
        self.assertIn("Unprotected high-risk fields", page)
        self.assertIn("Processors on record", page)
        stored = [row for row in scan.privacy_as_code["inventory"] if row.get("persistent")]
        rows = inventory_rows(stored + [{"store": "Lead", "field": "pan", "data_category": "Government ID", "high_risk": True, "persistent": True, "protection": "none", "erasure": "", "file": "a.py", "line": 3}])
        self.assertEqual((rows[0]["Store"], rows[0]["Protection"], rows[0]["Erasure"]), ("Lead", "NONE", "No erasure path"))
        aadhaar = next(row for row in rows if row["Field"] == "aadhaar")
        self.assertEqual(aadhaar["Protection"], "encrypted")
        self.assertTrue(any(row["Erasure"].startswith("Retained:") for row in rows))


class OrgAggregationTests(unittest.TestCase):
    def _estate(self, tmp: str):
        lending = Path(tmp) / "lending"
        shutil.copytree(EXAMPLE, lending)
        payments = Path(tmp) / "payments-svc"
        shutil.copytree(EXAMPLE, payments)
        shutil.copy(DRIFT_FILE, payments / "services/payments/refund.js")
        text = (payments / "privacy.yaml").read_text(encoding="utf-8")
        text = text.replace("    country: IN\n    contract: DPA-2025-011", "    country: SG\n    contract: DPA-2025-099", 1)
        (payments / "privacy.yaml").write_text(text, encoding="utf-8")
        return lending, payments

    def test_cross_repo_processor_register_and_rollup(self):
        from svikruti.pac.org import load_inputs

        with tempfile.TemporaryDirectory() as tmp:
            lending, payments = self._estate(tmp)
            org = load_inputs([str(lending), str(payments)])
            self.assertEqual([repo.name for repo in org.repos], ["lending", "payments-svc"])
            register = {item["name"]: item for item in org.processors()}
            self.assertEqual(register["Razorpay"]["countries"], ["IN", "SG"])
            self.assertTrue(any("country differs" in issue for issue in register["Razorpay"]["issues"]))
            self.assertTrue(any("contract differs" in issue for issue in register["Razorpay"]["issues"]))
            self.assertEqual(register["Mixpanel"]["used_undeclared_in"], ["payments-svc"])
            self.assertEqual(register["MSG91"]["issues"], [])
            self.assertTrue({item["repo"] for item in org.findings()} == {"payments-svc"})
            gdpr = next(item for item in org.frameworks() if item["id"] == "gdpr")
            art28 = next(row for row in gdpr["rows"] if row["ref"] == "Art. 28(3)")
            self.assertEqual((art28["status"], art28["failing"]), ("fail", ["payments-svc"]))
            contact = next(item for item in org.data_map() if item["category"] == "Contact")
            self.assertIn("Mixpanel", contact["processors"])
            self.assertEqual(contact["repos"], ["lending", "payments-svc"])

    def test_cli_mixes_check_artifacts_and_repos(self):
        with tempfile.TemporaryDirectory() as tmp:
            lending, payments = self._estate(tmp)
            artifact = Path(tmp) / "ci" / "payments-svc"
            self.assertEqual(main(["check", "--repo", str(payments), "--out-dir", str(artifact), "--fail-on", "none"]), 0)
            out = Path(tmp) / "org"
            args = ["org", str(artifact / "privacy-check.json"), str(lending), "--out-dir", str(out)]
            self.assertEqual(main(args), 0)
            self.assertEqual(main(args + ["--fail-on", "high"]), 3)
            for name in ("org-report.html", "org-report.md", "org-summary.json", "processor-register.csv", "data-inventory.csv", "findings.csv", "org-processing-record.csv", "framework-matrix.csv"):
                self.assertTrue((out / name).is_file(), name)
            summary = json.loads((out / "org-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["schema_version"], "svikruti-org-v1")
            self.assertEqual({repo["name"] for repo in summary["repositories"]}, {"payments-svc", "lending"})
            self.assertIn("lending,Applicant", (out / "data-inventory.csv").read_text(encoding="utf-8"))
            record = (artifact / "processing-record.csv").read_text(encoding="utf-8")
            self.assertNotIn("generator object", record)
            self.assertIn("Razorpay", record)
            self.assertNotIn("_erasure_paths", (artifact / "privacy-check.json").read_text(encoding="utf-8"))
            self.assertIn("Razorpay", (out / "org-report.html").read_text(encoding="utf-8"))
            self.assertEqual(main(["org", str(Path(tmp) / "missing")]), 2)
            empty = Path(tmp) / "empty"
            empty.mkdir()
            self.assertEqual(main(["org", str(empty)]), 2)


class SectorPackTests(unittest.TestCase):
    def test_soc2_rbi_sebi_packs(self):
        for pack_id, expected in {"soc2": {"OBL-04": "P4.2", "OBL-21": "P5.1", "OBL-24": "P6.6"}, "rbi": {"OBL-09": "DL 13(iv)", "OBL-15": "ITG 26(a)-(f)"}, "sebi_cscrf": {"OBL-15": "DE.CM.S5", "OBL-09": "Part I, Definition 16(e)"}}.items():
            pack = load_pack(pack_id)
            self.assertFalse({key for key in pack.controls} - {item["id"] for item in OBLIGATIONS})
            for obligation, ref in expected.items():
                self.assertIn(ref, [entry["ref"] for entry in pack.refs(obligation)])
        result = run_check(run_scan(str(EXAMPLE), None), load_manifest(EXAMPLE / "privacy.yaml"), frameworks=["dpdpa", "rbi", "sebi_cscrf", "soc2"], today=TODAY)
        self.assertEqual([pack.id for pack in result.packs], ["dpdpa", "rbi", "sebi_cscrf", "soc2"])
        self.assertEqual(result.framework_summary(result.packs[1])["counts"]["fail"], 0)


class RuntimeRedactionTests(unittest.TestCase):
    def test_detectors_validate_and_shared_cases_hold(self):
        from svikruti.redact import find, redact, redact_messages

        for text, expected in json.loads(Path("packages/redact-js/test/cases.json").read_text(encoding="utf-8")):
            self.assertEqual(redact(text), expected)
        self.assertEqual([m.kind for m in find("4111 1111 1111 1112 and 234567890123")], [])  # bad Luhn, bad Verhoeff
        self.assertEqual(redact("call 9876543210", style="partial"), "call [PHONE ...3210]")
        self.assertEqual(redact("a@b.com", style="hash", key="k"), redact("A@B.com", style="hash", key="k"))
        message = [{"role": "user", "content": [{"type": "text", "text": "I am ravi@x.com"}]}]
        self.assertEqual(redact_messages(message)[0]["content"][0]["text"], "I am [EMAIL]")
        self.assertEqual(message[0]["content"][0]["text"], "I am ravi@x.com")

    def test_logging_install(self):
        import io
        import logging

        from svikruti.redact import install_logging_redaction, uninstall_logging_redaction

        stream = io.StringIO()
        logger = logging.getLogger("svk-redact-test")
        logger.addHandler(logging.StreamHandler(stream))
        logger.setLevel(logging.INFO)
        install_logging_redaction()
        try:
            logger.info("refund for %s, PAN %s", "ravi@x.com", "ABCPE1234F")
        finally:
            uninstall_logging_redaction()
        self.assertEqual(stream.getvalue().strip(), "refund for [EMAIL], PAN [PAN]")

    def test_vscode_extension_core(self):
        import shutil as _shutil
        import subprocess

        if not _shutil.which("node"):
            self.skipTest("node not installed")
        done = subprocess.run(["node", "--test"], cwd="editors/vscode", capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stdout[-2000:])

    def test_js_port_agrees(self):
        import shutil as _shutil
        import subprocess

        if not _shutil.which("node"):
            self.skipTest("node not installed")
        done = subprocess.run(["node", "--test"], cwd="packages/redact-js", capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stdout[-2000:])

    def test_scanner_treats_redaction_as_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            shutil.copy(DRIFT_FILE, repo / "services/payments/refund.js")
            self.assertIn("P001", _rules(_check(repo)))
            checkout = repo / "services/payments/checkout.js"
            checkout.write_text('const { installConsoleRedaction } = require("svikruti-redact");\ninstallConsoleRedaction();\n' + checkout.read_text(encoding="utf-8"), encoding="utf-8")
            result = _check(repo)
            p001 = next(f for f in result.findings if f.rule == "P001")
            self.assertEqual(p001.status, "excepted")
            self.assertIn("checkout.js:2", p001.exception_reason)
            _write(repo, {"services/onboarding/audit.py": "import logging\nlogger = logging.getLogger(__name__)\n\ndef audit(applicant):\n    logger.info('kyc for %s', redact(applicant.email))\n    logger.info('kyc for %s', mask_phone(applicant.phone_number))\n"})
            self.assertFalse([f for f in _check(repo).open_findings() if f.rule == "P001" and "audit.py" in " ".join(f.refs)])


class FineractPrecisionTests(unittest.TestCase):
    """Patterns from the Apache Fineract review (Java/Spring lending platform)."""

    def test_scan_noise_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "api/UsersApiResourceSwagger.java": 'class S {\n    @Schema(example = "demomfi@mifos.org")\n    public String email;\n}\n',
                ".asf.yaml": "notifications:\n  commits: commits@fineract.apache.org\n",
                "db/multi-tenant-demo-backups/bk_demo.sql": "INSERT INTO m_appuser VALUES (1,'ravi.k@gmail.com');\n",
                "src/test/java/ValidatorTest.java": 'class T { String m = "+919876543210"; }\n',
                "docker-compose.yml": "services:\n  app:\n    environment:\n      OTLP: http://tempo:4318/v1/traces\n",
                "svc/Bureau.java": 'class B { String body(String password) { return "user=x&password=" + password + "&\\r"; } }\n',
                "svc/Steps.java": 'class S { void run(Loan loan) { log.info("payment {} {}", loan.periodPayment(), emailCampaign.getCampaignName()); } }\n',
                "svc/Leak.java": 'class L { void run(String email) { log.debug("reset for {}", email); } }\n',
            })
            scan = run_scan(str(root), None)
            severe = sorted((e.file, e.kind) for e in scan.evidence if e.severity in {"CRITICAL", "HIGH"} and e.kind in {"literal_personal_data", "insecure_transport", "secret_exposure", "logging_risk"})
            self.assertEqual(severe, [("svc/Leak.java", "logging_risk")])

    def test_jpa_entities_cascades_and_rights_requests(self):
        from svikruti.pac.datastore import _erases, is_request_entry_name, store_variants

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "core/domain/Client.java": (
                    "package d;\n@Entity\n@Table(name = \"m_client\")\npublic class Client {\n"
                    "    @Column(name = \"firstname\")\n    private String firstname;\n"
                    "    @Column(name = \"mobile_no\")\n    private String mobileNo;\n"
                    "    @OneToMany(cascade = CascadeType.ALL, mappedBy = \"client\", orphanRemoval = true)\n    protected Set<ClientIdentifier> identifiers;\n}\n"
                ),
                "core/domain/ClientIdentifier.java": "package d;\n@Entity\npublic class ClientIdentifier {\n    @Column(name = \"document_key\")\n    private String documentKey;\n}\n",
                "svc/handler/DeleteClientCommandHandler.java": "package h;\npublic class DeleteClientCommandHandler {\n    public Result processCommand(Command c) {\n        return this.service.deleteClient(c.entityId());\n    }\n}\n",
                "svc/ClientService.java": "package s;\npublic class ClientService {\n    public Result deleteClient(final Long id) {\n        final Client client = this.clientRepository.findById(id);\n        this.clientRepository.delete(client);\n        return null;\n    }\n}\n",
            })
            rows = {(r["store"], r["field"]): r for r in __import__("svikruti.pac.inventory", fromlist=["build_inventory"]).build_inventory(run_scan(str(root), None))}
            self.assertTrue(rows[("Client", "firstname")]["persistent"])
            self.assertTrue(rows[("Client", "mobileNo")]["persistent"])
            identifier = rows[("ClientIdentifier", "documentKey")]
            self.assertTrue(identifier["erasure"].startswith("cascade from Client"))
            self.assertTrue(identifier["rights_request"].startswith("cascade from Client"))
        self.assertTrue(_erases("final AppUser user = repo.findById(id);\nuser.delete();", store_variants("AppUser")))
        self.assertTrue(_erases("this.appUserRepository.deleteById(id);", store_variants("AppUser")))
        self.assertFalse(_erases("final AppUser user = x;\nlog(user.getName());", store_variants("AppUser")))
        self.assertEqual(
            [is_request_entry_name(n) for n in ["DeleteClientCommandHandler", "AccountDelete", "DeleteClientChargeCommandHandler", "DeleteAccountNumberFormatCommandHandler", "AccountDeleteRequested"]],
            [True, True, False, False, False],
        )

    def test_payment_and_system_account_names(self):
        from svikruti.scanner.code import drop_not_the_data
        from svikruti.scanner.semantic import _categories_for_text

        for name in ["graceOnPrincipalPayment", "periodPaymentRate", "chargePaymentMode", "isCashPayment", "emailSubject", "jobDisplayName", "tenant.getUsername()", "readOnlyUsername"]:
            self.assertEqual(_categories_for_text(name), [], name)
        for name in ["paymentMethod", "payment_details", "default_payment_method", "user.username", "emailAddress"]:
            self.assertTrue(_categories_for_text(drop_not_the_data(name)), name)


def _write(root: Path, files: dict) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _flows(root: Path):
    return {(e.file, e.metadata["third_party"], e.metadata["data_category"], e.metadata["flow"]) for e in scan_processor_flows(str(root))}


class QueueAndInjectionFlowTests(unittest.TestCase):
    def test_celery_task_and_bull_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "tasks.py": "import mailchimp_marketing as MailchimpMarketing\nfrom celery import shared_task\nclient = MailchimpMarketing.Client()\n\n@shared_task\ndef subscribe(address):\n    client.lists.add_list_member('l', {'email_address': address})\n",
                "views.py": "from .tasks import subscribe\n\ndef signup(user):\n    subscribe.delay(user.email)\n",
                "worker.js": "const twilio = require('twilio')(a, b);\nnew Worker('sms', async (job) => {\n  await twilio.messages.create({ to: job.data.to });\n});\n",
                "enqueue.js": "const sms = new Queue('sms');\nasync function remind(c) {\n  await sms.add('due', { to: c.phone });\n}\n",
            })
            flows = _flows(root)
            self.assertIn(("views.py", "Mailchimp", "Contact", "queue"), flows)
            self.assertIn(("enqueue.js", "Twilio", "Contact", "queue"), flows)
            detail = next(e.detail for e in scan_processor_flows(str(root)) if e.file == "views.py")
            self.assertIn("task `subscribe`", detail)

    def test_spring_event_with_constant_topic_and_unrelated_event_stays_quiet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "Topics.java": "package a;\npublic final class Topics {\n    public static final String KYC = \"kyc-events\";\n}\n",
                "Listener.java": "package a;\nimport com.sendgrid.SendGrid;\npublic class Listener {\n    private final SendGrid sendgrid = new SendGrid(\"k\");\n    @KafkaListener(topics = \"kyc-events\")\n    public void onKyc(String payload) {\n        sendgrid.api(payload);\n    }\n}\n",
                "Signup.java": "package a;\npublic class Signup {\n    void register(User user) {\n        kafkaTemplate.send(Topics.KYC, user.getPanNumber());\n        kafkaTemplate.send(\"audit\", user.getEmail());\n    }\n}\n",
            })
            flows = _flows(root)
            self.assertIn(("Signup.java", "SendGrid", "Government ID", "queue"), flows)
            self.assertNotIn(("Signup.java", "SendGrid", "Contact", "queue"), flows)

    def test_interface_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "di/Notifier.java": "package di;\npublic interface Notifier {\n    void notifyUser(String phone, String text);\n}\n",
                "di/impl/SmsNotifier.java": "package di.impl;\nimport com.twilio.Twilio;\npublic class SmsNotifier implements Notifier {\n    public void notifyUser(String phone, String text) {\n        Twilio.messages.create(phone, text);\n    }\n}\n",
                "app/LoanService.java": "package app;\nimport di.Notifier;\npublic class LoanService {\n    private Notifier notifier;\n    void approve(Applicant a) {\n        notifier.notifyUser(a.getMobileNumber(), \"ok\");\n    }\n}\n",
            })
            flows = _flows(root)
            self.assertIn(("app/LoanService.java", "Twilio", "Contact", "wrapper"), flows)
            self.assertFalse(any(f[0] == "di/Notifier.java" for f in flows))


class FreeTextToAiTests(unittest.TestCase):
    APP = (
        "from flask import request\nfrom openai import OpenAI\nclient = OpenAI()\n\n"
        "@app.post('/ask')\ndef ask():\n    q = request.json['question']\n    return client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n\n"
        "@app.post('/safe')\ndef safe():\n    q = redact(request.json['question'])\n    return client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': q}])\n\n"
        "def digest(stats):\n    text = f'approved {stats.approved}'\n    return client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': text}])\n"
    )

    def test_request_text_flagged_redacted_and_server_text_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {"app.py": self.APP})
            hits = [e for e in scan_processor_flows(str(root)) if e.metadata["data_category"] == "Free text"]
            self.assertEqual([e.line for e in hits], [8])
            self.assertEqual(hits[0].severity, "HIGH")
            self.assertIn("request.json", hits[0].metadata["free_text_source"])

    def test_free_text_is_held_to_the_ai_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            _write(repo, {"services/payments/assist.py": self.APP})
            _edit_manifest(repo, "processors:\n  - id: razorpay", "processors:\n  - id: openai\n    name: OpenAI\n    purpose: Support answers\n    country: US\n    contract: DPA-9\n    transfer_mechanism: SCC\n    data_categories: [free_text]\n  - id: razorpay")
            _edit_manifest(repo, "    processors: [razorpay]", "    processors: [razorpay, openai]")
            _edit_manifest(repo, "data_categories: [contact, financial]", "data_categories: [contact, financial, free_text]")
            p006 = [f for f in _check(repo).open_findings() if f.rule == "P006"]
            self.assertEqual([f.category for f in p006], ["free_text"])
            _edit_manifest(repo, "  ai_allowed_categories: []", "  ai_allowed_categories: [free_text]")
            self.assertEqual([f for f in _check(repo).open_findings() if f.rule == "P006"], [])


class RightsRequestTests(unittest.TestCase):
    def test_entry_point_reaches_store_or_d011(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            result = _check(repo)
            self.assertEqual(result.to_dict()["rights_request_entrypoints"], ["handle_erasure_request (services/onboarding/erasure.py:10)"])
            applicant = next(r for r in result.inventory if r["store"] == "Applicant")
            self.assertTrue(applicant["rights_request"].startswith("reached from handle_erasure_request()"))
            # Rename the handler: the deletion still exists, but nothing a person can trigger reaches it.
            path = repo / "services/onboarding/erasure.py"
            path.write_text(path.read_text(encoding="utf-8").replace("handle_erasure_request", "delete_applicant_records"), encoding="utf-8")
            d011 = [f for f in _check(repo).open_findings() if f.rule == "D011"]
            self.assertEqual(len(d011), 1)
            self.assertIn("no rights-request entry point was found", d011[0].detail)
            self.assertEqual(d011[0].severity, "HIGH")  # Applicant holds government IDs
            _edit_manifest(repo, "erasure:\n", "erasure:\n  entrypoints: [delete_applicant_records]\n")
            self.assertEqual([f for f in _check(repo).open_findings() if f.rule == "D011"], [])

    def test_routes_and_retention_jobs(self):
        from svikruti.pac.datastore import rights_request_entrypoints

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root, {
                "accounts/urls.py": "urlpatterns = [\n    path('accounts/close/', views.close),\n    path('accounts/two_factor/totp/remove/', views.remove_totp),\n]\n",
                "accounts/views.py": "def close(request):\n    purge_profile(request.user)\n\ndef remove_totp(request):\n    pass\n\ndef purge_profile(user):\n    Profile.objects.filter(user=user).delete()\n",
                "api/routes.js": "router.delete('/me', async (req, res) => {\n  await Customer.destroy({ where: { id: req.user.id } });\n});\nrouter.post('/items/remove', removeItem);\n",
            })
            entries = rights_request_entrypoints(root, ["accounts/urls.py", "accounts/views.py", "api/routes.js"])
            names = sorted(entry.name for entry in entries)
            self.assertEqual(names, ["DELETE /me", "close"])
            close = next(entry for entry in entries if entry.name == "close")
            self.assertIn("Profile.objects.filter", close.text)  # reached through purge_profile()


class ConsentGateTests(unittest.TestCase):
    def test_guard_in_caller_custom_guard_and_missing_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _copy_example(tmp)
            result = _check(repo)
            self.assertEqual(result.consent["flows_guarded"], result.consent["flows_checked"])
            self.assertNotIn("P008", _rules(result))
            sms = repo / "services/notifications/sms.py"
            text = sms.read_text(encoding="utf-8")
            sms.write_text(text.replace("        if not borrower.reminder_consent:\n            continue\n", ""), encoding="utf-8")
            result = _check(repo)
            p008 = [f for f in result.open_findings() if f.rule == "P008"]
            self.assertEqual((len(p008), p008[0].activity, p008[0].processor), (1, "reminders", "msg91"))
            self.assertEqual(next(a for a in result.assessments if a.id == "OBL-22").status, "fail")
            sms.write_text(sms.read_text(encoding="utf-8").replace("    for borrower in borrowers:\n", "    for borrower in borrowers:\n        if not may_contact(borrower):\n            continue\n"), encoding="utf-8")
            self.assertIn("P008", _rules(_check(repo)))
            (repo / "privacy.yaml").write_text((repo / "privacy.yaml").read_text(encoding="utf-8") + "\nconsent:\n  checks: [may_contact]\n", encoding="utf-8")
            self.assertNotIn("P008", _rules(_check(repo)))


if __name__ == "__main__":
    unittest.main()
