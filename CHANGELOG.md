# Changelog

## Unreleased

### Governance app

- New "Import from Scanner" module: upload the CLI scanner's report.json or
  ropa.csv/vendors.csv evidence pack and auto-populate the RoPA registry,
  vendor register, and task tracker (with duplicate detection). The scanner
  and the workbench are now one workflow instead of two disconnected tools.
- Home dashboard upgraded to a command center: compliance score, RoPA /
  vendor / open-rights-request / open-breach / overdue-task counts, and a
  first-run call-to-action for empty organizations.
- Every module now has guidance-rich empty states citing the relevant DPDP
  Act section and a concrete next step, plus a one-line description under
  each page header. AI pages show a friendly opt-in / bring-your-own-key
  notice when unconfigured instead of a dead form.

### Detection quality

- Email literals in test files matched by NAME (test_*.py, *.spec.ts,
  *.cy.js), in cypress/e2e directories, in i18n/locale translation files,
  and in CODE_OF_CONDUCT files now report at LOW (fixture/UI copy, not
  exposure). Benchmark: frappe/hrms dropped from 176 to 5 HIGH email
  literals, knadh/listmonk from 70 to 17 - the survivors are real.

### Fixed

- Secret detection no longer flags template/environment references
  (`${{ secrets.X }}` in GitHub Actions, `${VAR}`, `{{ var }}`,
  `process.env`, `os.environ`) as hard-coded credentials - referencing a
  secret store is correct practice, not exposure.
- SARIF output: rule names are identifier-style (no spaces) and artifact
  URIs use forward slashes on Windows, per the SARIF 2.1.0 spec.
- Dashboard HTML escaping now covers single quotes.
- Sample reports and the hosted demo regenerated with the current scanner
  (README benchmark table re-verified: excalidraw 37/6, healthchecks 42/141,
  saleor 60/678 - unchanged).

## 0.8.1 - 2026-07-04

Benchmark release. Detectors, scoring, and docs calibrated against three real
OSS repositories (excalidraw, healthchecks, saleor) with a manually verified
precision table published in the README.

### Detection quality (benchmark-driven)

- Test/fixture code is now recognised (tests/, spec/, test_*.py, *.test.*):
  keyword findings downgrade to LOW, semantic sinks are skipped, weak-crypto/
  HTTP/cloud-misconfig patterns are skipped, and secrets found in test code
  report at MEDIUM with a "verify it is not a real key" note.
- Vendored/minified assets (node_modules, vendor/, *.min.js, bundles) are
  skipped entirely and counted in scan-quality limitations.
- Bare "children" removed from detection terms (DOM/ORM tree structures);
  children's-data signals now come from age/guardian/consent compounds.
- "mobile", "health", "medical", "address", "location", "city", "minor"
  require corroborating context before full severity; semantic body-text
  matching excludes ambiguous tokens entirely.
- Aadhaar literals additionally require 4-4-4 grouping or Aadhaar/KYC context
  for CRITICAL (Verhoeff-valid bare 12-digit values in code report as MEDIUM,
  and are skipped in prose - epoch timestamps pass checksums ~8% of the time).
- 10-digit mobile candidates require +91/grouping/phone-context for HIGH;
  letter-attached digit runs (App Store IDs) no longer match.
- Email literals: URL-embedded values (Sentry DSNs) and asset references
  (icon@2x.png) are no longer emails; project-metadata files (package.json,
  CHANGELOG, LICENSE, SECURITY.md) report at LOW.
- Context-less references to HIGH-severity terms cap at MEDIUM; HIGH is
  reserved for collection/storage/logging contexts.
- Math.random()/random.random() reports at MEDIUM (verify-usage), not HIGH.
- Font/license URL allowlist for insecure-HTTP (scripts.sil.org, GNU, CC).

### Scoring

- Risk score rebuilt as a severity-tiered bounded model: each severity tier
  saturates independently (CRITICAL cap 55, HIGH 35, MEDIUM 6, LOW 1), so
  the CRITICAL band is reachable only through actual critical evidence.
  Benchmark: a no-PII drawing tool scores 37 MEDIUM, a real alerting service
  42 MEDIUM, a heavy-PII e-commerce platform 60 HIGH.

### Performance

- Combined-regex prefilter for the keyword loop: full scan of a ~1M-line
  repository (saleor, 4,528 files) completes in about a minute.

### Legal content

- DPDP Rules 2025 commencement phasing verified against the gazetted text
  (G.S.R. 846(E), November 13, 2025): Rules 1, 2, 17-21 immediate; Rule 4
  (Consent Managers) from November 13, 2026; Rules 3, 5-16, 22-23 from
  May 13, 2027. Rule 3 = Notice confirmed from the gazette.

## 0.8.0 - 2026-07-03

Accuracy release. Detection, scoring, legal content, and app hardening fixes
so scan results and generated documents can be trusted with less manual
second-guessing.

### Legal accuracy

- Knowledge base, assessment config, and document generator rewritten against
  the DPDP Act 2023 as enacted: 44 sections and the Schedule of penalties
  (up to ₹250 crore for s.8(5) security safeguards, ₹200 crore for s.8(6)
  breach-notification failure, ₹200 crore for s.9 children obligations,
  ₹150 crore for s.10 Significant Data Fiduciary obligations, ₹10,000 for
  s.15 duties of Data Principals, ₹50 crore residual).
- Cross-border transfers now described per Section 16 (negative-list model),
  appeals per TDSAT with the 60-day window, and terminology standardized on
  Data Fiduciary.
- Removed the incorrect claim that the DPDP Act imposes a statutory RoPA
  requirement; RoPA remains a recommended operational practice.

### Detection quality

- Aadhaar detection now requires a valid Verhoeff checksum and a first digit
  of 2-9, eliminating random 12-digit false positives.
- PAN detection validates the holder-type character and requires supporting
  context.
- Indian mobile-number matching is boundary-safe and no longer fires inside
  longer digit runs, IDs, or hashes.
- UPI handle detection uses an expanded provider allowlist.
- Ambiguous standalone terms (`state`, `ip`, `zip`, `pan`, and similar) are no
  longer treated as personal-data evidence.
- Children-data and health-data findings now need corroborating evidence
  before escalating a scan to CRITICAL.
- `.env` and `.env.*` files are now scanned.
- Heuristic parser engines now report `medium` confidence; only Python AST
  evidence is reported as `high`.
- Website scan counts every `Set-Cookie` header on the response, classifies
  third parties by script URL host, and is documented as single-page.
- Browser consent journey: idle wait defaults to 6 seconds, and accept-click
  detection requires consent context around the control.

### Scoring

- Risk score rebuilt as a severity-tiered bounded model (each severity tier
  saturates independently; calibrated on real OSS repositories), with
  cross-layer evidence deduplication and
  positive (passing) evidence excluded from the score.
- Risk bands: LOW 0-24, MEDIUM 25-49, HIGH 50-74, CRITICAL 75-100.

### Security

- Imported SARIF severity now honors `security-severity`; findings without a
  level default to MEDIUM.
- `osv-scanner --json` output format is now parsed.
- Imported scanner messages are truncated, and secret values from
  secret-scanner runs are redacted before report generation.
- CSV exports are guarded against spreadsheet formula injection.
- AI evidence packet is redacted before sending, and evidence strings are
  marked as untrusted data in the prompt.
- CLI AI defaults: provider `gemini`, model `gemini-2.5-flash`.
- Documented that the optional tree-sitter language pack may download
  grammars on first use (offline/supply-chain consideration).

### App

- Streamlit workbench: real invite codes (local-first, no email dependency),
  Fernet-encrypted API keys at rest (new `cryptography` dependency), and
  login lockout after 5 failed attempts within 15 minutes.
- Corrected model IDs for gemini and anthropic providers
  (`claude-sonnet-4-5`, `claude-haiku-4-5`) and enforced the AI monthly usage
  limit.
- AI Notice Reviewer scores are parsed from model output instead of being
  hardcoded, RoPA editing works, user-supplied content is HTML-escaped
  against XSS, and the app database defaults to `~/.svikruti`.

### Added

- `svikruti scan --evidence-pack DIR` writes the full artifact set into DIR
  with default names (report.html, report.json, report.sarif, ropa.csv,
  actions.csv, vendors.csv, controls.csv, breach-readiness.md,
  notice-patch.md, fix-pack.md); explicit individual output flags override
  the matching pack file.

## 0.7.0 - 2026-06-29

Launch trust and production-assurance release.

### Added

- Assurance profile (`svikruti-assurance-v1`) that separates verified,
  inferred, failing, and unknown production-readiness dimensions.
- Scan quality profile (`svikruti-scan-quality-v1`) with parser coverage,
  parser engines, parser errors, and limitations.
- Dedicated Scan Quality views in the HTML report and dashboard that show
  inspected scope, parser coverage, confidence mix, limitations, and manual
  verification steps before teams rely on a scan.
- Semantic parser layer using Python AST and structured heuristics for
  JavaScript/TypeScript, Java, Go, Ruby, PHP, SQL, Prisma, GraphQL, OpenAPI,
  Postman, and Kubernetes evidence.
- Optional `parsers` extra with `tree-sitter-language-pack` for AST-backed
  JS/TS, Java, Go, Ruby, and PHP evidence.
- Dashboard Assurance tab with production claim, score, dimension chart,
  evidence counts, and unknowns to close before production claims.
- Dashboard Evidence Explorer columns for confidence, detector ID, and language.
- Launch demo artifacts generated from the realistic multi-language fixture.
- GitHub issue templates for bugs, false positives/negatives, parser requests,
  and DPDPA control suggestions.
- Cloud/IaC guardrail detection for public storage, public databases, disabled
  encryption, permissive IAM, wildcard CORS, audit logging, WAF/private network
  evidence, and public-access blocking evidence.
- `DPDPA-TECH-008` technical control for cloud and infrastructure guardrails.
- Breach-readiness domain for cloud and IaC guardrails.

## 0.6.0 - 2026-06-20

Interactive dashboard and local evidence-store release.

### Added

- `svikruti dashboard` command for a scanner-native local Streamlit control
  room.
- Local SQLite evidence store at `.svikruti/evidence.db` for saved scan history.
- `svikruti scan --save-history` and `--history-db` options.
- Dashboard views for Command Center, Control Plane, Evidence Flow, Breach
  Readiness, Evidence Explorer, AI Workbench, and Exports.
- Interactive technical-control cards with filters, evidence references, and
  AI prompts.
- Evidence-flow Sankey visualization for source -> data -> notice -> DPDPA area
  -> action.
- Downloadable AI evidence packet from the dashboard.
- Tests for scan-history storage and dashboard CLI registration.

### Changed

- Svikruti is now positioned as a local-first privacy engineering workbench,
  with HTML/CSV/SARIF/Markdown as exports rather than the only product surface.

## 0.5.0 - 2026-06-19

Technical-control and breach-readiness release.

### Added

- Technical-control scanner for TLS/HTTPS, KMS or managed keys, secret-manager
  usage, password hashing, storage encryption, backup/restore signals,
  monitoring, endpoint/workload detection, and incident-response evidence.
- Negative technical evidence for weak crypto, hard-coded secrets, insecure
  HTTP endpoints, and imported high/critical scanner findings.
- Security evidence import for SARIF, Trivy, Gitleaks, OSV, and compatible JSON
  outputs through repeatable `--security-evidence` CLI arguments.
- Schema-versioned technical controls CSV through `--controls-out`.
- Breach-readiness Markdown pack through `--breach-out`.
- HTML workbench tabs for Technical Controls and Breach Readiness.
- AI evidence packet fields for technical controls and breach posture.
- Realistic Terraform, CI security pipeline, insecure-control, Trivy, Gitleaks,
  and SARIF fixtures.

### Changed

- GitHub Action template now emits technical-control and breach-readiness
  artifacts.
- README and output schema docs now frame Svikruti as a privacy-engineering
  control plane, not only a DPDPA evidence scanner.
- Source discovery now includes Terraform, HCL, config files, lockfiles,
  Dockerfile, Containerfile, Jenkinsfile, and Procfile.

## 0.4.0 - 2026-06-16

Scanner and artifact hardening release.

### Added

- Schema-versioned RoPA/privacy inventory CSV with owner, status, DPDPA basis,
  collection/storage/logging locations, transfer, retention, safeguards, rights
  impact, evidence references, confidence, language, and framework columns.
- Schema-versioned remediation action CSV with action IDs, severity, control
  area, status, due window, evidence references, and acceptance criteria.
- Schema-versioned vendor/processor register CSV with DPA status, transfer,
  security evidence, retention commitment, risk tier, review status, evidence
  references, and detector IDs.
- `docs/OUTPUT_SCHEMAS.md` with column-level documentation and inferred vs
  to-confirm field guidance.
- Evidence metadata for detector ID, confidence, evidence reference, language,
  framework hints, file context, and context type.
- Realistic multi-framework examples for Express, React/TypeScript, Django, and
  SQL schema scanning.
- Tests proving multi-framework personal-data, storage, collection, vendor, and
  logging detection.

### Changed

- Logging exposure classification now wins over nearby collection context when
  personal data appears directly in a logging statement.
- Scanner patterns now cover more realistic names such as `email_address`,
  `phone_number`, `upi_id`, `address_line`, `student_age`, `diagnosis`, and
  SQL files.
- HTML evidence report now includes an executive command center, top action
  rail, schema-versioned export callout, richer RoPA preview, evidence
  confidence metadata, and more complete ticket cards.

## 0.3.0 - 2026-06-15

Initial launch-ready open-source v1.

### Added

- `svikruti scan` CLI.
- Static repository scanner for personal-data signals, collection points,
  storage points, logging risks, and third-party SDKs.
- Public website scanner for forms, scripts, cookies, privacy links, and consent
  copy signals.
- Optional Playwright browser-consent journey scanner.
- Offline HTML Evidence Workbench with overview, Control Board, action tracker,
  Evidence Flow, Artifacts, AI Co-pilot, Fix Pack, and Evidence Explorer tabs.
- DPDPA mapping, RoPA starter, notice gaps, proof-pack actions, and evidence
  graph.
- CSV/Markdown exports for RoPA, remediation actions, vendor register, privacy
  notice patch, fix pack, and AI brief.
- SARIF output for GitHub code scanning.
- `svikruti init-github-action` workflow generator.
- Optional Gemini and OpenAI AI Co-pilot.

### Notes

- Svikruti is evidence support, not legal advice or compliance certification.
- AI is opt-in and sends a compact evidence packet only when enabled.
