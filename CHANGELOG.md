# Changelog

## Unreleased

No unreleased changes yet.

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
