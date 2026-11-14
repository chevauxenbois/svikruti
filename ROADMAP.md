# Svikruti Roadmap

Svikruti is open-source privacy as code: the repository is the source of truth,
reconciled against a reviewed manifest and mapped to DPDPA, GDPR and ISO/IEC 27701.
The roadmap prioritizes technical evidence, transparent limitations, and
review-ready artifacts over generic compliance checklists.

## Current Release: 0.9.0

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

- More framework packs: SOC 2 Privacy criteria, RBI/SEBI sector overlays,
  Singapore PDPA, UK GDPR deltas.
- Deeper data flow: dependency injection, queues and event buses between the
  caller and the processor (wrapper functions are already followed across
  files).
- Re-run the real-repository precision review against the 0.9.0 detectors.
- Data-model sources: SQL migrations, ORM models and OpenAPI schemas as
  first-class inputs to the manifest (field-level inventory).

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
- First PyPI release (the tag-driven workflow with build provenance is in place).
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
