# Svikruti Roadmap

Svikruti is an open-source privacy engineering workbench for DPDPA readiness.
The roadmap prioritizes technical evidence, transparent limitations, and
review-ready artifacts over generic compliance checklists.

## Current Release: 0.8.1

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
- Add signed release artifacts and PyPI publishing.
- Add more realistic examples for fintech, healthcare, ecommerce, SaaS, BFSI,
  and edtech.

## Product Direction

- CI release gates for privacy evidence regressions.
- Consent journey capture with richer browser evidence.
- Cloud evidence imports from common security and posture tools.
- Evidence diffing between scans.
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
