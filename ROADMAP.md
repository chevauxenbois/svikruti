# Svikruti Roadmap

Svikruti is open-source privacy as code: the repository is the source of truth,
reconciled against a reviewed manifest and mapped to DPDPA, GDPR and ISO/IEC 27701.
The roadmap prioritizes technical evidence, transparent limitations, and
review-ready artifacts over generic compliance checklists.

## Current Release: 0.12.0

- SOC 2, RBI (Digital Lending 2025, IT Governance 2023, payment data storage)
  and SEBI CSCRF framework packs.
- Runtime redaction library for Python and Node, recognised by the check.
- VS Code extension.

## 0.11.0

- Data followed through queues, task runners and event buses (Celery,
  Dramatiq, RQ, Kafka, RabbitMQ, SQS, NATS, BullMQ, NestJS, Spring, Sidekiq,
  Laravel) and through dependency injection.
- Free text from a request sent to an AI model is tracked as its own
  category; redaction clears it.
- Rights-request entry points found and followed to each store (D011).
- Consent checked in code for consent-based processing (P008).

## 0.10.0

- `svikruti org`: one processing record, processor register, data map and
  framework posture across many repositories, flagging vendors recorded
  inconsistently between services.
- Recall benchmark with a held-out set, run in the test suite.
- Stored data (protection, erasure) in the scan report, dashboard and
  governance import; governance app imports `privacy-check.json` and
  `org-summary.json`.

## 0.9.x

- Privacy as code: `privacy.yaml` manifest, `svikruti init` / `check` / `diff`,
  drift and policy rules, framework packs (DPDPA, GDPR, ISO/IEC 27701:2025),
  baselines with stable fingerprints, a pull-request gate, `svikruti sync`,
  and processor data flows (which data reaches which third party, followed
  through wrapper functions across files).
- Risk score split into defects and data exposure.
- Manifest JSON Schema, pre-commit hooks, and manifest import in the
  governance app.
- Six framework packs: DPDPA, GDPR, ISO/IEC 27701 controller and processor,
  LGPD, CCPA/CPRA.
- Argument-level log-sink detection.

- Local CLI scanner for repository, website, privacy notice, browser-consent,
  vendor, and security-evidence signals.
- Validated identifier detection (Verhoeff-checked Aadhaar, holder-type and
  context-checked PAN, boundary-safe mobile numbers) and a calibrated
  saturating risk score with LOW/MEDIUM/HIGH/CRITICAL bands.
- Legal content aligned to the DPDP Act 2023 as enacted (44 sections plus the
  Schedule of penalties) and the DPDP Rules 2025.
- HTML evidence workbench and Streamlit scanner dashboard.
- Scan Quality views that show parser coverage, confidence mix, inspected
  scope, limitations, and manual verification steps.
- Technical controls and breach-readiness evidence for encryption, secrets,
  vulnerability management, monitoring, incident response, cloud/IaC guardrails,
  endpoint/workload detection, backup, and recovery.
- JSON, SARIF, CSV, Markdown, fix-pack, `--evidence-pack` directory, and local
  SQLite history outputs.
- Optional AI evidence packet and synthesis (redacted, untrusted-marked).

## Near Term

- More framework packs: Singapore PDPA, UK GDPR deltas, IRDAI overlay.
- JetBrains plugin (VS Code is done); publish the VS Code extension to the Marketplace.
- Join producers and consumers that live in different repositories
  (`svikruti org` already sees both ends).
- Grow the recall benchmark: more languages and frameworks, and a third set
  written by someone other than the maintainer.
- `svikruti org` straight from a GitHub organisation (download the latest
  check artifact of every repository).

- Improve JavaScript/TypeScript, Java, Go, Ruby, and PHP semantic coverage with
  deeper tree-sitter packs.
- Add more framework-specific detectors for Django, FastAPI, Express, Next.js,
  Spring, Rails, Laravel, and mobile/API backends.
- Add stronger privacy-notice comparison for retention, rights, grievance,
  consent withdrawal, children's data, transfers, and processor disclosures.
- Extend secret and sensitive-value redaction to all report surfaces
  (partially done: imported secret-scanner runs are redacted and imported
  messages truncated before report generation).
- Improve report screenshots and launch demo artifacts.
- Published on PyPI (`pip install svikruti`) with build provenance.
- Add more realistic examples for fintech, healthcare, ecommerce, SaaS, BFSI,
  and edtech.

## Product Direction

- Consent journey capture with richer browser evidence.
- Cloud evidence imports from common security and posture tools.
- Hosted/self-hosted evidence vault with org dashboards.
- Jira, Linear, GitHub Issues, Slack, and GRC integrations.
- SSO, RBAC, audit logs, approvals, and exception workflows.
- Sector packs for India-specific PrivacyOps programs.

## Contribution Areas

- False-positive and false-negative examples.
- New parser/language support.
- India-specific vendor and SDK dictionaries.
- DPDPA control mapping improvements.
- Security evidence import formats.
- Report/dashboard UX improvements.
- Documentation, examples, and launch demos.
