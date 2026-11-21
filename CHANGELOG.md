# Changelog

## 0.13.0 - Licence change

### Changed

- Licence: from MIT to the Functional Source License 1.1, MIT Future License
  (FSL-1.1-MIT). Use, modification and self-hosting stay free, including at
  work and by consultants for their clients; offering Svikruti or a
  substantially similar product built from it as a competing commercial
  product or service is not permitted. Each release converts to MIT two years
  after publication. Releases up to and including 0.12.1 remain available
  under MIT.

## 0.12.1 - Java/Spring precision from an Apache Fineract review

### Fixed

- Java entities: `@Entity` / `@Table` on the lines above a class, and
  `@Column` / `@JoinColumn` above a field, mark it as stored. Fineract went
  from 0 to 59 inventoried fields.
- Erasure: JPA parent-side cascades (`@OneToMany(cascade = ALL)`,
  `orphanRemoval = true`), deletes through typed variables and Spring Data
  repositories, and a call tree that skips builder and factory classes.
- Rights-request entry names need a person as their whole object
  (`DeleteClient`, not `DeleteClientCharge`).
- Not reported as personal data: Swagger / OpenAPI example values, project
  mailing lists, demo database dumps and test modules (`integration-tests`),
  container service URLs (`http://tempo:4318`), concatenated variables after
  `password=`, payment configuration and amounts (`periodPaymentRate`),
  "email" or "phone" modifying another noun (`emailCampaign`), system account
  usernames (`tenant.getUsername()`), and uncorroborated or low-severity
  signals in the processing record (`/actuator/health` is not health data).
- Output folders are created when missing (`--out /tmp/new/report.html`).
- Identity, contact and ID terms: `firstname`, `lastname`, `fullname`,
  `mobile_no`, `phone_no`, `national_id`, `document_key`.

## 0.12.0 - Sector packs, runtime redaction, VS Code

### Added

- Framework packs: `soc2` (2017 Trust Services Criteria, revised points of
  focus 2022), `rbi` (Digital Lending Directions 2025, IT Governance Master
  Direction 2023, Storage of Payment System Data 2018) and `sebi_cscrf`
  (CSCRF, August 2024). RBI and SEBI are overlays meant to run with `dpdpa`.
- `svikruti.redact`: validated runtime redaction for text, nested payloads,
  chat messages and stdlib logging (`install_logging_redaction()`,
  `RedactingFilter`), with label, partial and keyed-hash styles.
- `svikruti-redact` (packages/redact-js): the same for Node, with console
  and pino integration. Python and JS share test cases.
- The check recognises redaction: values passed through `redact()`, `mask*()`,
  `hash*()`, `sha*()`, `encrypt*()` or `tokenize*()` are not log leaks;
  process-wide installs mark covered P001 findings as redacted at runtime;
  `privacy-check.json` reports `runtime_redaction`.
- VS Code extension (editors/vscode): check on save, findings as diagnostics
  on the offending line or the matching `privacy.yaml` entry, suppression
  quick fix, status bar count, bundled manifest schema.

## 0.11.0 - Queues, free text, rights requests, consent

### Added

- Processor flows follow queues, task runners and event buses: Celery,
  Dramatiq, Huey and RQ tasks; Kafka, RabbitMQ, SQS, NATS and Redis
  producers and listeners; Node `EventEmitter`, BullMQ and kafkajs; NestJS
  `@OnEvent` / `@EventPattern` / `@Processor`; Spring `@KafkaListener`,
  `@RabbitListener` and `@EventListener`; Sidekiq and ActiveJob; Laravel jobs
  and event listeners; Django signals. Producer and consumer meet on the
  channel name, with string constants resolved; findings name the channel and
  the consumer.
- Dependency injection: a caller holding an interface or base class reaches
  the implementation that wraps the vendor (Java, Kotlin, C#, TypeScript,
  Python).
- Free text sent to AI: text from the request (`req.body.message`,
  destructured `messages` from `req.json()`, `request.POST["question"]`,
  request-body DTO fields, `st.chat_input`) reaching an AI provider call is a
  new category, `free_text`, held to D002, D009 and P006. Redaction in the
  same function (Presidio, scrubadub, llm-guard, Comprehend, Google DLP,
  `redact*`) clears it.
- Rights requests: erasure routes, account-deletion endpoints, erasure
  mutations, DSAR handlers, management commands and `erasure.entrypoints` are
  followed four levels deep (calls, queued tasks, constructed classes) and
  through cascades. New inventory column "Reached By Rights Request" and rule
  D011 for stores that only unconnected code (often a retention job) deletes.
- Cascades resolve through tables that hold no personal data
  (`Channel -> Project -> User`).
- Consent in code: rule P008 for processor flows in consent-based activities
  with no consent guard in the function, its decorators or its callers;
  `consent.checks` names your own guards. OBL-22 fails on P008. OBL-21 fails
  on D011.
- `privacy-check.json` adds `rights_request_entrypoints` and `consent_check`.
- C# files are read by the flow detector. Mailgun added; Twilio's C#
  `MessageResource` and namespaced constructions (`new \Vendor\Client()`)
  are recognised.
- Field names read out of a request or mapping (`$request->input('email')`,
  `data["phone"]`) count as the data they name.
- Recall set `benchmarks/recall/channels.yaml`: 9/14 on its first run, 14/14
  after fixes, also inside three real repositories.

## 0.10.0 - Organisation view and measured recall

### Added

- `svikruti org`: merges `privacy-check.json` files, folders holding one, or
  repositories with `privacy.yaml` into one organisation report (HTML,
  Markdown, JSON `svikruti-org-v1`, and CSVs for the processing record,
  processor register, data inventory, findings and framework matrix).
  Flags processors recorded with different countries, contracts or transfer
  mechanisms across services, processors used without a record in one
  service, and per data category the stores, recipients, unprotected
  high-risk fields, stores without erasure and logging exposure. Each
  framework clause takes its worst status across repositories. `--fail-on`
  gates estate-wide.
- Recall benchmark (`benchmarks/recall`): planted leaks in seven languages,
  a tuning set and a held-out set, a harness that can plant them inside any
  repository, and published results including misses. Both sets run in the
  test suite.
- Scan HTML report and dashboard: the Privacy as Code tab shows where
  personal data is stored, field protection, erasure coverage, and the
  processors on record (with AI providers marked).
- Governance app imports `privacy-check.json` and `org-summary.json`:
  verified activities, processors found in code but not on record, and one
  task per open finding with its fix and location.
- `privacy-check.json` carries `organization` and a `processors` list (with
  an `ai_provider` flag).
- Vendors: Twilio, SendGrid, PostHog, Amplitude, Mailchimp, Brevo, Postmark,
  Customer.io, Braze, Gupshup, Karix; more Segment and Sentry SDK spellings.
- Logging sinks: `console.error/warn/info/debug`, Go `slog`, PHP Monolog and
  `error_log`/`syslog`, Ruby `puts`, C# `ILogger` and Serilog.
- Stored data: SQLAlchemy, SQLModel and mongoengine models; Prisma and
  TypeORM `onDelete: Cascade`; SHA-2/3, BLAKE2, Argon2, bcrypt, scrypt and
  PBKDF2 as hashing protection; Java annotations directly above a field.

### Fixed

- A keyword argument (`json=payload`) split a call at `=` and hid flows made
  with a URL constant.
- A vendor client passed as a value (`generateText({ model: openai(...) })`)
  was not bound.
- SDK set-up calls (`sentry_sdk.init(...)`) were reported as data flows.
- Boolean and timestamp fields (`email_verified`, `phone_confirmed_at`) were
  treated as personal data.
- Type annotations naming a vendor (`Stripe.PaymentMethod`) were reported as
  flows.
- Internal `_erasure_paths` no longer leaks into `privacy-check.json`.
- Processor `data_categories` in `privacy-check.json` are labels, matching
  the rest of the file.

## 0.9.1

### Fixed

- `svikruti init-github-action` (scan mode) generated a workflow that ran
  `pip install -e '.[parsers]'`, which only works inside the Svikruti
  repository itself. Both generated workflows now install `svikruti[parsers]`
  from PyPI.
- Erasure-path detection read no files when the repository path went through a
  symlink (macOS `/var` -> `/private/var`).

### Changed

- README, guide and site install from PyPI.

## 0.9.0 - Privacy as Code

### Added

- `privacy.yaml` manifest: processing activities bound to code paths, with
  purposes, lawful basis (single or per framework), retention, processors,
  DPIA reference, logging allowances, policies, time-boxed exceptions and
  dated attestations. Validation reports every problem at once; unknown keys
  are warnings.
- `svikruti init`: generates the manifest from a scan, in sync with the code
  by construction, with TODO placeholders for what code cannot know.
- `svikruti check`: reconciles the manifest against scanner evidence.
  Drift rules D001-D010 (shadow processing, undeclared category, undeclared
  processor, stale declarations, incomplete records) and policy rules
  P001-P007 (personal data in logs, forbidden categories, missing DPIA,
  undocumented transfers, expired exceptions, data in AI prompts,
  unprotected high-risk fields). Exit code 3 on findings at or
  above `--fail-on` (default high).
- Framework packs: 24 framework-neutral obligations mapped to DPDPA (Act and
  Rules 2025), GDPR and ISO/IEC 27701:2025 (with 2019 legacy numbers). Custom
  packs load from a YAML/JSON path. `svikruti frameworks` lists built-ins.
- Obligation states: verified, failing, attested, not verified, not
  applicable. Attestations go stale after `attestation_max_age_days` and never
  override a failing check.
- Report pack for `check`: self-contained HTML, Markdown, PR comment, JSON
  (`svikruti-privacy-check-v1`), SARIF, compliance-matrix CSV and a
  processing-record CSV verified against code.
- Stable finding fingerprints (file, detector, normalised line; not line
  number) on every evidence item and in SARIF `partialFingerprints`.
- Baselines: `svikruti scan --baseline --fail-on-new`, `svikruti check
  --baseline`, and `svikruti diff base.json head.json` with a semantic summary
  (new data categories, new third parties, new logging flows).
- Processor data flows (`processor_data_flow` evidence): follows a third-party
  SDK from import to call and reports which data categories are passed to it
  (direct arguments, constructed clients, endpoint URL constants, one
  assignment hop; per file). Feeds the evidence graph, RoPA starter, `diff`
  and the reconciled record. New rule D009: a declared processor receives a
  category its record does not list. D003 now names the data sent.
- `svikruti sync [--write] [--prune]`: updates `privacy.yaml` from drift as a
  reviewable diff (categories, processor stubs and links, processor data,
  activity stubs for unmapped paths). Text-level edits keep comments; the
  result is re-parsed and verified before it is offered. YAML flow and block
  lists and `privacy.json` are supported.
- `svikruti scan` reconciles `privacy.yaml` automatically (`--manifest`,
  `--no-manifest`): `privacy_as_code` block in the JSON, a Privacy as Code tab
  in the HTML report and the dashboard, and `privacy-check/` in the evidence
  pack. A broken manifest never fails a scan.
- Framework packs: `iso27701_processor` (Tables A.2/A.3), `lgpd`, `ccpa`.
  Packs map only obligations the framework has.
- `release.yml`: tag-driven build, wheel test, build provenance and PyPI
  trusted publishing (`docs/RELEASING.md`).
- Cross-file processor flows: a function that passes its own parameter to a
  vendor call is a wrapper, and calls to it are followed across files (up to
  three levels) where the caller imports its module or shares its package.
  Flows count call arguments only, ignore constant configuration pairs and
  vendor responses, and skip test suites.
- JSON Schema for the manifest (`svikruti schema`, `docs/privacy.schema.json`)
  generated from the loader's key sets; `init` writes the editor hint.
- `.pre-commit-hooks.yaml` with `svikruti-check` and `svikruti-sync`.
- Governance app: Import from Scanner accepts `privacy.yaml` / `privacy.json`
  and creates RoPA entries, vendors, and tasks for any TODO.
- Field-level data inventory (`data-inventory.csv`, `scan --inventory-out`,
  a section in the check report): table or model, field, category, activity,
  and whether that category reaches logs or a processor.
- Stored-field detection for Sequelize, Mongoose, Drizzle and
  TypeORM/MikroORM models.
- Processor flows follow instance-held and injected clients
  (`self.client`, `this.stripe`, typed constructor and function parameters,
  Java fields, Go struct fields).
- AI model providers as processors: OpenAI, Anthropic, Google Gemini, AWS
  Bedrock, Cohere, Mistral and Groq SDKs, LangChain chat models and pipes,
  and clients built by service name. `policies.ai_allowed_categories` and
  rule P006 limit which personal data may reach a prompt; an undeclared AI
  provider is D003.
- Field protection: each stored field is classified as encrypted, tokenised,
  hashed, masked, binary or none, from its declaration or the call that wraps
  it where it is written. `policies.require_field_protection_for` and rule
  P007 (for example `[government_id]` for the Aadhaar Data Vault).
- Erasure coverage: erasure and retention paths (named functions and
  classes, functions that delete the subject's own record, `erasure.handlers`,
  one level of calls, SQL `DELETE`) and ON DELETE CASCADE relationships.
  Rule D010 for stored data no path reaches; `erasure.retained` records
  stores kept for a legal reason. D010 also fails OBL-04 and OBL-21.
- Stores are classified as persistent (ORM models, SQL tables, Prisma) or
  transient (DTOs, forms, API types, pydantic models); P007 and D010 apply to
  persistent stores only.
- Inline suppressions: `svikruti-ignore[RULE]: reason` on or above a line.
  A reason is required. In `scan`, suppressed evidence leaves the risk score
  and is marked as suppressed in SARIF.
- `svikruti inventory`: list stored personal-data fields by category or
  field name, with protection and erasure, as a table, CSV or JSON.
- `svikruti init-github-action --mode check`: pull-request gate that builds
  its baseline from the base branch, posts a PR comment and uploads SARIF.
- Worked example `examples/privacy-as-code` (passes), drift scenario
  `examples/pac-scenarios/refund.js`, sample output
  `examples/sample-privacy-check`.
- `tests.yml` workflow running the suite on Python 3.9, 3.11 and 3.13.

### Changed (risk score)

- `risk_score` is now `risk_findings_score` + `risk_exposure_score`. Inventory
  evidence (a field, form, storage point, third party or processor flow
  exists) no longer counts as a finding; it feeds a data-exposure component
  capped at 15, based on medium-or-better confidence categories. Only defects
  (personal data in logs, secrets, weak crypto, cloud misconfiguration,
  consent failures) can move a repository into HIGH or CRITICAL. A clean KYC
  service that stores government IDs now scores LOW instead of HIGH. Scores
  are not comparable with 0.8.x.

### Changed (detection quality)

- Manual review of every CRITICAL/HIGH defect finding on excalidraw,
  healthchecks and saleor (44 before, 11 after) drove these fixes:
  - A log call that had already closed was treated as still open for the
    `def`, `raise` or call that followed it (bug in the multi-line log
    detection added earlier in this release).
  - Record references (`payment.id`, `order_id`, `{"payment_intent":
    intent.id}`) no longer count as the data they point to, in logs or in
    processor flows. Identifiers that are personal data (`upi_id`,
    `device_id`) still count.
  - Only the last attribute of an access chain is classified:
    `payment_information.gateway` is a gateway name.
  - Emails in documentation, author/licence lines and placeholders
    (`you@yourdomain.com`, `a@b.com`) are LOW.
  - A comment that mentions SHA-1 or MD5 is not a weak-crypto finding.
  - References to a secret held elsewhere (`"env(VAR)"`, `<your-api-key>`,
    `vault://`, `changeme`) are not hard-coded secrets.
- Role and system mailboxes (`privacy@`, `support@`, `noreply@`, `bot@`) are
  reported at LOW instead of HIGH.
- Dependency lock files are no longer scanned (integrity hashes matched
  Aadhaar-format literals; package names matched vendors).

- Python log-sink detection now inspects the arguments of the logging call
  (names, attributes, subscript keys, f-string expressions, one assignment
  hop for whole-variable logging). Previously every category mentioned
  anywhere in a function containing a log statement was flagged, so
  `logger.info("created id=%s", user.id)` in a KYC handler was CRITICAL.
- Line-level `logging_risk` no longer fires because a log statement sits on a
  neighbouring line. Arguments of a multi-line log call are still detected.
- A personal-data word inside a log message string ("could not send email")
  is no longer a logging finding in any language; interpolated expressions
  (f-strings, `${}`, `#{}`, `$var`) still are.
- `privacy.yaml` and privacy-check outputs are excluded from scanning.

### Dependencies

- PyYAML is now a core dependency (manifest and framework packs).

## Unreleased

### Fixed (app rendering)

- Knowledge Base page crashed (AttributeError) after the legal-content
  rewrite changed FAQ/TIMELINE to lists and PENALTY_MATRIX/SECTOR_GUIDANCE
  to new keys; all four tabs now read the current data shapes.
- Vendor Management and Rights Requests crashed on processors/requests with
  null date columns; all date parsing now tolerates missing/blank/invalid
  values via a shared safe-date helper.
- Settings crashed when an org's industry/size/SDF/compliance value was not
  in the config enum; selectbox indices now fall back safely.
- Sidebar navigation now reruns on click, so the selected page renders
  immediately instead of one click behind (this also made imported RoPA/
  vendor data look "missing" when it was actually present).
- Knowledge Base Checklist tab now renders the grouped checklist items
  (category, item, priority, section reference) instead of dumping raw
  Python dicts.
- Verified: all 19 app pages render and all Knowledge Base tabs display
  clean content (no raw-dict leakage) via Streamlit AppTest.

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
