# Svikruti Output Schemas

Svikruti produces evidence artifacts for privacy, security, legal, and
engineering review. The exports are intentionally split between human review
files and machine-readable files.

The CSV schemas are versioned through the first column. This lets downstream
teams import Svikruti outputs into spreadsheets, GRC tools, Jira, Linear, or a
future hosted Svikruti evidence vault without guessing the format.

## Evidence Confidence

Many columns are inferred from scanner evidence. Svikruti marks those rows as
drafts and includes evidence references so reviewers can validate them.

Confidence values:

| Value | Meaning |
| --- | --- |
| high | Direct form field, literal personal-data pattern, logging exposure, or live website field evidence |
| medium | Strong code context such as storage, collection, or known vendor/tool reference |
| low | Weak contextual reference that needs human review |

## Parser Coverage

Svikruti now emits a `scan_quality` object in JSON reports.

Schema version: `svikruti-scan-quality-v1`

Fields:

| Field | Meaning |
| --- | --- |
| `parser_coverage_percent` | Percentage of scanned files handled by the semantic/parser layer |
| `parsed_files` | Number of files parsed by a structured parser or endpoint heuristic |
| `total_files` | Repository files scanned |
| `parser_engines` | Engines used, such as `python.ast` and `js_ts.endpoint_heuristic` |
| `parser_errors` | Parse failures with file and engine |
| `limitations` | What the current parser layer cannot prove |

Current parser strategy:

- Python uses the standard-library AST to detect model/schema fields, request
  sources, logging sinks, and database writes.
- JavaScript/TypeScript uses conservative endpoint/body/log/database heuristics
  until an optional tree-sitter backend is added.
- Java, Go, Ruby, and PHP use framework-aware heuristics for common controller,
  request, logging, and persistence patterns.
- SQL, Prisma, GraphQL, OpenAPI, Postman, and Kubernetes manifests are scanned
  for schema, API request, runtime config, and secret-reference evidence.
- Optional `svikruti[parsers]` installs `tree-sitter-language-pack` and enables
  AST-backed evidence for JS/TS, Java, Go, Ruby, and PHP. Parser engines appear
  as values such as `tree_sitter.javascript` in `scan_quality.parser_engines`.
- Regex scanning still runs as a fallback and coverage layer.

Every evidence-backed row should include one or more `Evidence References`.
These references use file, line, URL, or detector identifiers such as:

```text
realistic/express_checkout.js:15:code.logging_risk.government_id
https://example.com:script:googletagmanager.com
```

## HTML Report

The HTML report is the primary review surface.

Use it for:

- launch readiness review
- privacy/security/legal discussion
- evidence exploration
- remediation triage
- AI-assisted summary when enabled

The report is offline and self-contained.

## Interactive Dashboard

The dashboard is launched with:

```bash
svikruti dashboard
```

It reads from either a saved SQLite scan history database or a specific JSON
report:

```bash
svikruti scan --repo . --save-history
svikruti dashboard

svikruti dashboard --report svikruti-report.json
```

Use it for:

- scan history review
- command-center release decisions
- technical-control filtering
- evidence-flow visualization
- breach-readiness review
- evidence search
- AI prompt and packet generation
- JSON control/breach/report downloads

## SQLite Evidence Store

Default path: `.svikruti/evidence.db`

The local evidence store keeps the full JSON scan result plus indexed summary
fields:

- scan ID
- generated timestamp
- repository path and URL
- risk level and score
- evidence count
- files/pages scanned
- personal-data categories
- third parties
- technical controls
- breach-readiness posture
- full result JSON

This is the local-first base for future diffing, scan history, trend charts,
hosted evidence vaults, and enterprise dashboards.

## JSON Report

The JSON report is the complete structured scan result.

Use it for:

- API ingestion
- hosted dashboard development
- diffing scans over time
- custom analytics
- debugging scanner output

### Assurance Profile

Schema version: `svikruti-assurance-v1`

The assurance profile is Svikruti's honesty layer. It separates what the scan
can verify from what it can only infer and what remains unknown.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `score` | Average assurance score across dimensions |
| `production_claim` | Plain-language claim Svikruti can safely make from available evidence |
| `counts.verified` | Dimensions with direct evidence |
| `counts.inferred` | Dimensions with useful but not production-confirmed evidence |
| `counts.failing` | Dimensions with blocking negative evidence |
| `counts.unknown` | Dimensions where evidence was not supplied or not detectable |
| `dimensions` | Per-domain status, score, owner, reason, and evidence refs |
| `unknowns` | Items to close before making production assurance claims |
| `limitations` | Built-in caveats about static/runtime/cloud/vendor gaps |

Current assurance dimensions:

- personal-data inventory
- privacy notice coverage
- third-party / processor evidence
- encryption and key management
- secrets hygiene
- vulnerability management
- security monitoring and alerting
- incident / breach response
- backup, retention, and recovery
- consent and rights journey
- cloud / IaC safeguards

Status values:

| Status | Meaning |
| --- | --- |
| `verified` | Direct high-confidence evidence exists |
| `inferred` | Evidence exists, but production scope still needs confirmation |
| `failing` | Negative evidence exists and should block or require exception |
| `unknown` | Svikruti cannot verify this area from supplied evidence |

## SARIF

SARIF is for GitHub code scanning and developer security workflows.

Use it for:

- PR annotations
- GitHub Security / Code Scanning
- CI gates

## RoPA CSV

Schema version: `svikruti-ropa-v1`

This export is a privacy inventory / RoPA starter. It is aligned with common
records-of-processing inventory fields: purposes, personal-data categories,
data subjects, recipients/processors, transfers, retention, safeguards, owner,
status, and evidence. It also includes DPDPA-specific operational fields such
as Data Fiduciary / Controller, DPDPA Basis, Consent Required, Privacy Notice
Coverage, and Data Principal Rights Impact.

Generated rows are **not final legal RoPA records**. They are scanner-inferred
draft rows that help a privacy owner complete the inventory faster.

| Column | Source | Meaning |
| --- | --- | --- |
| Schema Version | System | Fixed value: `svikruti-ropa-v1` |
| Record ID | System | Stable row identifier in the export |
| Processing Activity | Inferred | Human-readable activity name grouped by data category |
| Data Fiduciary / Controller | To confirm | Organization responsible for processing |
| Business Function | To confirm | Function such as Product, Marketing, Support, Finance, HR |
| Product / System | Inferred | Source systems/files where evidence was found |
| Data Subjects | Default draft | Users / customers / website visitors unless edited |
| Personal Data Categories | Inferred | Detected category such as Contact, Location, Government ID |
| Special / High-Risk Category | Inferred | Marks high-risk categories for review |
| Processing Purposes | Inferred | Collection, storage, logging, third-party processing, or application processing |
| DPDPA Basis | To confirm | Consent or legitimate use basis to be reviewed |
| Consent Required | To confirm | Whether consent is required for this activity |
| Source Systems | Inferred | Files, URLs, or systems containing evidence |
| Collection Points | Inferred | Evidence refs for forms/API/body collection |
| Storage Locations | Inferred | Evidence refs for schemas/models/db writes |
| Logging Locations | Inferred | Evidence refs for logging exposure |
| Processors / Recipients | Inferred/To confirm | Detected vendors/tools or recipients |
| International Transfer | To confirm | Transfer country/region or no transfer |
| Retention Period | To define | Retention schedule for the activity |
| Deletion Trigger | Draft | Purpose completion / withdrawal / legal retention review |
| Security Measures | Draft | Safeguards suggested by risk category |
| Privacy Notice Coverage | To compare | Notice match status when available |
| Data Principal Rights Impact | Draft | Rights workflows to confirm |
| Risk Tier | Inferred | Medium or High based on category/control area |
| Owner | To assign | Privacy/product/business owner |
| Review Status | System | Starts as `Draft - scanner inferred` |
| Evidence References | Inferred | File/line/URL evidence refs |
| Scanner Confidence | Inferred | high, medium, low |
| Detected Languages | Inferred | Languages seen in evidence files |
| Detected Frameworks | Inferred | Framework hints such as Express, React, Django, FastAPI |
| DPDPA Notes | Inferred | DPDPA control area notes |

## Actions CSV

Schema version: `svikruti-actions-v1`

This export is a remediation tracker. It is meant to be imported into a
spreadsheet, Jira, Linear, or GRC task list.

| Column | Source | Meaning |
| --- | --- | --- |
| Schema Version | System | Fixed value: `svikruti-actions-v1` |
| Action ID | System | Stable action identifier in the export |
| Priority | Inferred | P0/P1 based on risk and launch impact |
| Severity | Inferred | CRITICAL/HIGH/MEDIUM/LOW |
| Control Area | Inferred | Notice transparency, security safeguards, vendor governance, etc. |
| Title | Inferred | Short action title |
| Owner | Draft | Suggested owner group |
| Status | System | Starts as Open |
| Due | Draft | Suggested due window |
| Artifact | Inferred | Privacy notice, vendor register, logging control, etc. |
| Why | Inferred | Reason the action exists |
| Evidence References | Inferred | Evidence refs supporting the action |
| Acceptance Criteria | Draft | Completion criteria for the ticket |

## Vendors CSV

Schema version: `svikruti-vendors-v1`

This export is a vendor / processor register starter. Svikruti can detect
third-party tools and scripts, but it cannot know your contract status or exact
transfer terms from code alone. Those fields are intentionally marked for
confirmation.

| Column | Source | Meaning |
| --- | --- | --- |
| Schema Version | System | Fixed value: `svikruti-vendors-v1` |
| Vendor / Processor | Inferred | Detected vendor, processor, script domain, or tool |
| Service Category | To confirm | Analytics, payments, support, messaging, hosting, etc. |
| Data Categories Shared | Inferred/To map | Data categories tied to evidence, if known |
| Processing Purpose | To confirm | Why the vendor is used |
| DPA / Contract Status | To confirm | DPA, MSA, SCCs, addendum, or not reviewed |
| Sub-processors | To confirm | Vendor subprocessors if relevant |
| Transfer Location | To confirm | Country/region or data residency statement |
| Security Evidence | To confirm | SOC 2, ISO 27001, audit report, security page, questionnaire |
| Retention / Deletion Commitment | To confirm | Vendor retention and deletion commitments |
| Risk Tier | Inferred draft | Medium by default until reviewed |
| Owner | Draft | Suggested Procurement / Legal / Security ownership |
| Review Status | System | Starts as Open |
| Next Review Date | To schedule | Review cadence |
| Evidence References | Inferred | File/URL evidence refs |
| Detector IDs | Inferred | Detector rules that created the vendor row |

## Technical Controls CSV

Schema version: `svikruti-technical-controls-v1`

This export is a privacy-engineering control register. It maps technical
evidence to DPDPA-oriented safeguards and breach-readiness controls.

The controls are deliberately practical:

- encryption in transit
- encryption at rest and key management
- secrets and credential hygiene
- vulnerability management
- security monitoring and alerting
- incident and breach response readiness
- backup, retention, and recovery evidence

Rows can be `pass`, `fail`, or `missing`. A `pass` means Svikruti found
evidence that should be confirmed against production scope. A `fail` means
negative evidence or imported high/critical findings need remediation. A
`missing` status means the scanner did not find enough evidence in this scope.

| Column | Source | Meaning |
| --- | --- | --- |
| Schema Version | System | Fixed value: `svikruti-technical-controls-v1` |
| Control ID | System | Stable technical-control ID such as `DPDPA-TECH-004` |
| Control | System | Human-readable control title |
| Area | System | Security safeguards, Breach readiness, or Resilience |
| Status | Inferred | `pass`, `fail`, or `missing` |
| Severity | Inferred | Control impact based on gaps/findings |
| Score | Inferred | 0-100 control score used for posture review |
| Owner | Draft | Suggested accountable function |
| Evidence Count | Inferred | Count of unique evidence refs |
| Evidence References | Inferred | File, line, scanner, or detector refs |
| Gaps | Inferred | Missing evidence or negative findings to review |
| Next Action | Draft | Owner-ready remediation or confirmation step |
| AI Prompt | System | Evidence-grounded prompt for optional AI review |

## Breach Readiness Markdown

Schema version in JSON: `svikruti-breach-readiness-v1`

The breach-readiness pack summarizes whether the scanned product has evidence
for practical incident readiness:

- vulnerability management
- security monitoring
- endpoint or workload detection
- incident response
- secrets and crypto
- backup and recovery
- personal-data impact mapping

The Markdown export is for security, privacy, legal, and leadership review. It
does not certify readiness. It shows evidence coverage, missing domains,
failed controls, and priority actions to complete before relying on the pack.

## Notice Patch Markdown

The notice patch is a drafting aid. It lists missing data categories, vendor
disclosures, consent withdrawal language, retention language, and grievance
language suggested from the scan.

It is not legal advice and should be reviewed before publishing.

## Fix Pack Markdown

The fix pack is a copy-ready ticket pack. Each item includes:

- priority
- severity
- control area
- owner
- due window
- reason
- evidence
- acceptance criteria

Use it to create GitHub, Jira, Linear, or GRC tasks.

## AI Brief Markdown

The AI brief is produced only when `--ai` is enabled and a provider key is
configured. It summarizes evidence and suggests priorities using only the scan
packet supplied to the model.

The AI brief is drafting support, not certification.

## Known Limits

Svikruti v1 is intentionally transparent. It does not execute customer source
code and it does not claim legal compliance.

Current scanner strengths:

- multi-language text and pattern scanning
- token-aware personal-data detection
- India-specific identifier and vendor detection
- collection/storage/logging context classification
- technical-control evidence for encryption, secrets, vulnerability management,
  monitoring, endpoint/workload detection, incident response, and recovery
- SARIF, Trivy, Gitleaks, and OSV-style JSON ingestion
- privacy notice comparison
- website form/script/cookie detection
- optional browser consent journey evidence

Current limits:

- static analysis can miss runtime-only flows
- unauthenticated website scans can miss logged-in products
- framework-specific dataflow analysis is still shallow
- vendor purpose, DPA status, transfers, and retention need human confirmation
- cloud/security-tool coverage is inferred from repository/config/imported
  evidence and must be confirmed against production architecture
- privacy notice comparison is semantic-light and should be legally reviewed
