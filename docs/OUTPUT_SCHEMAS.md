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

## JSON Report

The JSON report is the complete structured scan result.

Use it for:

- API ingestion
- hosted dashboard development
- diffing scans over time
- custom analytics
- debugging scanner output

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
- privacy notice comparison
- website form/script/cookie detection
- optional browser consent journey evidence

Current limits:

- static analysis can miss runtime-only flows
- unauthenticated website scans can miss logged-in products
- framework-specific dataflow analysis is still shallow
- vendor purpose, DPA status, transfers, and retention need human confirmation
- privacy notice comparison is semantic-light and should be legally reviewed
