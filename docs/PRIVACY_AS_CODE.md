# Privacy as Code

Most privacy programmes are built from documents: a policy, a record of
processing, a DPIA, a vendor register. Those documents describe what the
organisation believes its software does. Production runs the code.

Svikruti treats the repository as the source of truth:

1. `svikruti init` reads the code and writes `privacy.yaml`, a manifest of the
   processing the code performs today.
2. People add what code cannot know: purpose, lawful basis, retention,
   contracts.
3. `svikruti check` runs in CI. It scans the code again, reconciles it against
   the manifest, and fails the pull request when the two disagree.
4. The same evidence is mapped to DPDPA, GDPR and ISO/IEC 27701 through
   framework packs, so one check answers every framework you select.

The record of processing stops being a spreadsheet someone updates before an
audit. It becomes a file that cannot be merged out of date.

## Five-minute walkthrough

```bash
pip install "svikruti[parsers]"
git clone https://github.com/chevauxenbois/svikruti.git   # for the worked example

cd svikruti/examples/privacy-as-code           # a small lending app with a finished manifest
svikruti check --repo . --privacy-file privacy-notice.md
# Privacy check: 0 open findings, exit code 0

cp ../pac-scenarios/refund.js services/payments/
svikruti check --repo . --privacy-file privacy-notice.md
#   HIGH  D002  Activity 'repayments' processes Location data in code, but the record does not declare it.
#   HIGH  D003  Activity 'repayments' sends data to Mixpanel, which is not a declared processor.
#   HIGH  P001  Contact data is written to logs in activity 'repayments' (1 location(s)).
# Privacy gate failed: 3 finding(s) at HIGH or above, exit code 3
```

A developer added a refund handler. Nobody filed a ticket with the privacy
team, and nobody had to: the pull request is blocked until the code changes or
`privacy.yaml` is updated in the same PR, where the privacy owner reviews it.

For your own repository:

```bash
svikruti init --repo .                       # writes privacy.yaml with TODOs
$EDITOR privacy.yaml                         # fill in purpose, lawful basis, retention, contracts
svikruti check --repo .                      # reconcile; writes svikruti-check/
svikruti sync --repo .                       # later: show the manifest changes the code now needs
svikruti init-github-action --mode check     # CI gate for every pull request
```

`svikruti scan` picks up `privacy.yaml` automatically: the evidence report gets
a Privacy as Code tab, the JSON a `privacy_as_code` block, the evidence pack a
`privacy-check/` folder, and `svikruti dashboard` a matching tab. Use
`--no-manifest` to skip it.

## The manifest

```yaml
version: 1

organization:
  name: LendFlow Financial Services
  role: controller                 # controller | processor | both
  privacy_contact: privacy@lendflow.example

frameworks: [dpdpa, gdpr, iso27701]   # built-in ids, or paths to custom packs

policies:
  personal_data_in_logs: deny         # deny | warn | allow
  forbidden_categories: [health, children, biometric]
  allowed_transfer_countries: [IN]    # processors elsewhere need a transfer_mechanism
  require_dpia_for: [health, children, government_id, biometric]   # this is the default
  ignore_paths: ["fixtures/**"]
  min_confidence: medium              # ignore low-confidence scanner signals when reconciling
  attestation_max_age_days: 365
  ai_allowed_categories: []           # personal data allowed in prompts to AI providers; [] = none; omit = not enforced
  require_field_protection_for: [government_id, health]   # stored fields must be encrypted / tokenised / hashed / masked

erasure:
  handlers: [close_account]           # extra functions that delete personal data, if not named delete_user / erase_* / ...
  retained:                           # stores kept on purpose, with the legal reason
    Repayment: "Kept 8 years after loan closure under the PML Rules and tax law"

processing_activities:
  - id: repayments
    name: EMI repayment collection
    owner: payments
    paths: ["services/payments/**"]   # binds this record to the code that implements it
    data_categories: [contact, financial]
    data_subjects: [borrowers]
    purposes: [repayment collection]
    legal_basis: {dpdpa: legitimate_use, gdpr: contract}   # or a single value
    retention: "8 years after loan closure (tax and PML records)"
    processors: [razorpay]
    dpia: DPIA-2026-003               # required when high-risk categories are involved
    logging: {allow: [device]}        # categories allowed in logs for this activity

processors:
  - id: razorpay
    name: Razorpay
    purpose: Payment processing
    data_categories: [contact]        # what the code is allowed to pass to this processor
    country: IN
    contract: DPA-2025-011
    transfer_mechanism: ""            # e.g. Standard Contractual Clauses

exceptions:                           # time-boxed, reasoned, owned
  - rule: P001
    activity: repayments
    category: contact
    reason: "Refund emails are logged for chargeback disputes until masking ships."
    approved_by: ciso
    expires: 2027-03-31

attestations:                         # what a repository cannot prove
  - obligation: OBL-21
    statement: "Rights requests are handled by the support desk within 30 days."
    evidence: https://wiki.example.com/privacy/rights-runbook
    owner: privacy-office
    reviewed: 2026-10-01
```

Data category ids: `identity`, `contact`, `government_id`, `financial`,
`location`, `children`, `health`, `device`, `biometric`. `paths` are globs
(`*` within a path segment, `**` across segments, a bare directory matches
everything under it). When two activities claim a file, the more specific glob
wins. `privacy.json` is accepted where YAML is not wanted.

## Rules

Drift rules compare the record with the code. Policy rules enforce what the
organisation has decided.

| Rule | Default severity | Meaning |
|---|---|---|
| D001 | HIGH / CRITICAL | Code handles personal data under a path no activity covers |
| D002 | HIGH / CRITICAL | A data category is in the code but not on the activity |
| D003 | HIGH | Code integrates a third party that is not a declared processor (MEDIUM if declared but not linked to the activity) |
| D004 | LOW | A declared category is no longer found in the code |
| D005 | LOW | A declared processor is no longer referenced anywhere |
| D006 | MEDIUM | Activity lacks purpose, lawful basis, retention, owner or data subjects, or the basis is not valid for a selected framework |
| D007 | MEDIUM / HIGH | Processor lacks country, purpose or contract (HIGH when the contract is missing) |
| D008 | MEDIUM | An activity's paths match no code with personal-data evidence |
| D009 | HIGH / CRITICAL | Code passes a data category to a declared processor whose record does not list it |
| P001 | HIGH / CRITICAL | Personal data is passed to a logging call |
| P002 | CRITICAL | A category under `forbidden_categories` is present |
| P003 | HIGH | High-risk data with no `dpia` reference |
| P004 | HIGH | Processor outside `allowed_transfer_countries` with no `transfer_mechanism` |
| P005 | MEDIUM | An exception has expired; its finding is enforced again |
| P006 | HIGH / CRITICAL | Personal data is sent to an AI model provider and its category is not in `ai_allowed_categories` |
| P007 | HIGH / CRITICAL | A stored field in `require_field_protection_for` has no encryption, tokenisation, hashing or masking |
| D010 | MEDIUM / HIGH | A stored table or model holds personal data and no erasure or retention code reaches it, and it is not under `erasure.retained` |

CRITICAL applies where the category is high-risk (health, children,
government ID, biometric).

## Processor data flows

A third-party SDK in a file shows a processor exists. Svikruti also follows the
SDK from its import to the calls made on it and reports which personal-data
categories are in those calls:

```js
const mixpanel = require("mixpanel").init(token);
mixpanel.track("refund_requested", { email, pincode });   // Contact, Location -> Mixpanel
```

These flows appear as `processor_data_flow` evidence, in the evidence graph
(`data category -> sent to -> third party`), in `svikruti diff` ("Location
data is now sent to Mixpanel") and in the reconciled record. Rule D009 fires
when a declared processor receives a category its record does not list.

Wrappers are followed across files. If `lib/notify.py` defines
`send_sms(phone, text)` and that function posts to MSG91, then
`send_sms(user.phone_number, ...)` in any file that imports it is reported as
Contact -> MSG91, with the wrapper named in the finding. Chains up to three
wrappers deep are followed.

What counts, and what does not:

- Only call arguments count. `stripe.PaymentMethod.retrieve(pm_id)` sends an
  id, whatever the method is called.
- A key set to a constant (`address: "auto"`, `mode="payment"`) is
  configuration, not data.
- The vendor's answer is not followed: `customer = create_customer(email)`
  then `portal.create(customer=customer)` sends an id, not the email.
- A call to a same-named function counts only where the caller imports the
  wrapper's module, or shares its package in Go, Java, Kotlin, Ruby and PHP.
- A record reference is not the record: passing `customer_id` or
  `intent.id` is not a flow of personal data.
- Clients held on an instance or injected by type are followed:
  `self.client.orders.create(...)`, `constructor(private stripe: Stripe)`,
  `mp: Mixpanel`, a Java `RazorpayClient` field, a Go `*razorpay.Client`
  struct field. A parameter typed as the vendor's data object
  (`StripeObject`) is a response, not a client.
- Test suites are skipped.

Limits: dynamic dispatch, service locators, queues and event buses between
the caller and the vendor are not followed. On saleor (4,600 files) the
detector reports 13 Stripe flows in under a second, on a Next.js subscription
starter 6. Reading them by hand, each passes a customer email, name, address
or payment-method detail to Stripe. That is two repositories with one vendor,
not a precision benchmark.

## AI model providers

OpenAI, Anthropic, Google Gemini, AWS Bedrock, Cohere, Mistral and Groq are
processors like any other, so a prompt that carries a customer's email is a
processor flow:

```python
prompt = f"Summarise the account of {customer.full_name} ({customer.email})"
client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])
#  -> Identity, Contact sent to OpenAI
```

The same detector covers the provider SDKs, LangChain chat models and pipes
(`chain = prompt | llm`), and clients built by service name
(`boto3.client("bedrock-runtime")`). Calls through LangChain are attributed
to the real provider; Azure OpenAI is reported as OpenAI.

An AI provider the manifest does not declare is a D003 finding, which is how
shadow AI shows up in a pull request. `policies.ai_allowed_categories` then
limits what declared providers may receive: `[]` allows no personal data in
prompts, `[device]` allows only device data, and leaving the key out disables
the check. Anything else is P006.

What it cannot see: free-text user input forwarded as-is (a chat box passed
straight to the model) carries no field name, so its contents are unknown to a
static scanner. A proxy or DLP layer at runtime is the control for that.

## Stored data: protection and erasure

For every stored table or model, the inventory answers two more questions.

**Is it protected?** A field counts as protected when its declaration says so
(`EncryptedCharField`, `@Convert`, `aadhaar_hash`, `pan_last4`, a vault
reference) or when the value is wrapped where it is written
(`aadhaar=encrypt_field(payload["aadhaar"])`, `tokenize(user.pan_number)`).
Comments do not count. A binary column with no such write is reported as
"binary, unverified". `policies.require_field_protection_for` turns this into
rule P007. For Indian requesting entities, `[government_id]` is the code-level
check behind UIDAI's Aadhaar Data Vault requirement (Aadhaar numbers stored
encrypted, in a vault, behind reference keys).

**Can it be erased?** An erasure path is a function or class named for it
(`delete_user`, `handle_erasure_request`, `AccountDelete`,
`purge_expired_records`, `apply_retention`), any function that deletes the
data subject's own record (`user.delete()`), anything listed under
`erasure.handlers`, and the functions those call. A store is reached when one
of them deletes, updates or anonymises it (`Applicant.objects.filter(...).delete()`,
`DELETE FROM customers`, `applicant.email = "erased"`), or when it cascades
from a store that is (`ForeignKey(Customer, on_delete=CASCADE)`,
`REFERENCES users ON DELETE CASCADE`). Seed, cleardb and populate scripts are
not erasure paths. A store nothing reaches, and that is not listed under
`erasure.retained` with a reason, is rule D010.

"Reached" means code that deletes or overwrites the store exists; it does not
prove that your rights-request process calls it, or that it runs. Only stored
tables and models count: DTOs, forms, API types and pydantic models are
inventoried but not held to D010 or P007.

## Inline suppressions

When a finding is accepted where it happens, say so next to the code:

```python
logger.info("chargeback for %s", customer.email)  # svikruti-ignore[P001]: chargeback evidence, masked from Q1
```

The comment goes on the flagged line or the line above. The rule list in
brackets limits it to those rules; without one it covers every rule. A reason
of at least 10 characters is required: a bare `svikruti-ignore` is reported
as a manifest warning and suppresses nothing. Suppressed findings appear in
the report under exception with the reason, so reviewers can challenge them.
In `svikruti scan`, a suppression without a rule list (or with `scan`) takes
that line's evidence out of the risk score and marks it suppressed in SARIF.

Use manifest `exceptions` instead for anything time-boxed or approved by
someone other than the author.

## Data inventory

`svikruti check` also writes `data-inventory.csv`: one row per stored
personal-data field, taken from ORM models and schemas (Django and SQLAlchemy
models, SQL `CREATE TABLE`, Prisma, Sequelize, Mongoose, Drizzle, TypeORM,
Java and Go structs).

| Table / model | Field | Category | Where | Activity | Declared | Reaches logs | Sent to |
|---|---|---|---|---|---|---|---|
| Applicant | aadhaar | Government ID | services/onboarding/models.py:12 | applicant_onboarding | yes | no | |
| Repayment | email | Contact | services/payments/models.js:5 | repayments | yes | yes | Razorpay |

"Reaches logs" and "Sent to" are at category level within the same activity:
the row says contact data from this activity reaches Razorpay, not that this
exact column does. Use it to answer a rights request ("where do we hold
email?"), scope a breach, or seed a DPIA. `svikruti scan --inventory-out`
produces the same file without a manifest.

From the command line:

```bash
svikruti inventory --repo . --field email               # every column that holds an email
svikruti inventory --repo . --category government_id    # where Aadhaar / PAN live, and whether they are protected
svikruti inventory --repo . --stored-only --format csv --out inventory.csv
```

Each row also carries `protection` (encrypted, tokenised, hashed, masked,
binary, none) and `erasure` (which code reaches the store, a cascade, or the
reason it is retained).

## Keeping the manifest current: `svikruti sync`

```bash
svikruti sync --repo .            # print a unified diff of privacy.yaml
svikruti sync --repo . --write    # apply it
svikruti sync --repo . --prune    # also remove categories and processors no longer in code
```

Sync fixes drift that has one mechanical answer: it adds a newly handled
category to its activity, creates a processor stub for a new SDK and links it,
records what each processor receives, and adds an activity stub for unmapped
paths. Purpose, lawful basis, retention and contracts are written as TODO, so
`check` keeps failing until a person fills them in. Policy findings (logs,
forbidden data, missing DPIA) are never auto-resolved. The file is edited as
text, so comments and layout survive, and the result is re-parsed and compared
with the intended state before it is offered.

## Obligations and frameworks

Every check is evaluated once, against a framework-neutral obligation
(`OBL-01` to `OBL-24`). A framework pack is a YAML file that says which clause
each obligation supports:

| Obligation | DPDPA | GDPR | ISO/IEC 27701:2025 |
|---|---|---|---|
| OBL-01 The processing record matches the code | Sec. 8(1) | Art. 30(1) | A.1.2.9 |
| OBL-03 Every activity has a lawful basis | Sec. 4(1), 6, 7 | Art. 6(1) | A.1.2.3 |
| OBL-06 No personal data in logs | Sec. 8(5), Rule 6 | Art. 5(1)(c), 32(1) | A.1.4.3, A.3.25 |
| OBL-08 Processors identified and under contract | Sec. 8(2) | Art. 28 | A.1.2.7 |
| OBL-09 Cross-border transfers documented | Sec. 16, Rule 15 | Arts. 44, 46 | A.1.5.2 to A.1.5.4 |
| ... 24 in total | | | |

`svikruti frameworks` lists the built-in packs:

| Id | Framework |
|---|---|
| `dpdpa` | India DPDP Act 2023 and DPDP Rules 2025 |
| `gdpr` | EU GDPR |
| `iso27701` | ISO/IEC 27701:2025, PII controllers (2019 control numbers kept as `legacy`) |
| `iso27701_processor` | ISO/IEC 27701:2025, PII processors (Tables A.2 and A.3) |
| `lgpd` | Brazil LGPD |
| `ccpa` | California CCPA as amended by the CPRA |

A pack only maps obligations its framework actually has. The CCPA has no
lawful-basis requirement, so `OBL-03` carries no CCPA clause instead of a
borrowed one. Lawful bases are validated per framework: `contract` is valid
under GDPR and LGPD, and rejected under DPDPA.

Each obligation ends in one of five states:

| State | Meaning |
|---|---|
| Verified | Evidenced by the scan and by reconciling the manifest against it |
| Failing | Contradicted by code evidence |
| Attested | Not provable from a repository; a dated, owned attestation is on record |
| Not verified | Not provable from a repository and nobody has attested |
| Not applicable | The triggering processing does not exist in this codebase |

Two rules keep this honest. An attestation older than
`attestation_max_age_days` stops counting. An attestation never overrides a
failing check: if someone attests "all data is encrypted" and the scan finds
MD5, the obligation fails.

### Adding a framework

```yaml
# packs/acme-privacy-standard.yaml
id: acme
name: Acme Privacy Standard v4
legal_bases: []                 # optional vocabulary check for legal_basis
controls:
  OBL-06:
    - {ref: "APS-4.2", title: "No personal data in application logs"}
  OBL-08:
    - {ref: "APS-7.1", title: "Vendor contracts"}
```

```bash
svikruti check --framework gdpr --framework packs/acme-privacy-standard.yaml
```

A new law or an internal standard is a data file. No scanner change is needed.

## Editor and local tooling

`svikruti init` starts the manifest with a `yaml-language-server` schema
comment, so editors with YAML support complete keys, category names, rule ids
and obligation ids, and flag typos as you type. `svikruti schema` prints the
JSON Schema ([docs/privacy.schema.json](privacy.schema.json)); it is generated
from the loader's own key sets.

Pre-commit users can run the gate before a push:

```yaml
repos:
  - repo: https://github.com/chevauxenbois/svikruti
    rev: v0.9.0
    hooks:
      - id: svikruti-check
```

The governance workbench (`streamlit run app.py`) imports `privacy.yaml` on
its Import from Scanner page: activities become RoPA entries, processors
become vendors, and any TODO becomes a task instead of an invented value.

## Outputs

`svikruti check` writes a report pack (default `svikruti-check/`):

| File | Use |
|---|---|
| `privacy-check.html` | Self-contained report: verdict, framework coverage, drift, reconciled record, crosswalk |
| `privacy-check.md` | The same content for wikis and audit folders |
| `pr-comment.md` | Short verdict for a pull-request comment or job summary |
| `privacy-check.json` | Machine-readable result (`svikruti-privacy-check-v1`); also the `--baseline` input |
| `privacy-check.sarif` | Drift findings for GitHub code scanning, with stable fingerprints |
| `compliance-matrix.csv` | One row per framework clause: status, proof type, summary |
| `processing-record.csv` | Record of processing built from the manifest and verified against code |
| `data-inventory.csv` | Every stored personal-data field: table or model, column, category, activity, where the category goes |

Exit codes: `0` passed, `1` error, `2` usage or invalid manifest, `3` gate failed.

## Many repositories: `svikruti org`

Each service keeps its own `privacy.yaml` and runs `svikruti check` in its own
CI. The privacy team needs one picture. `svikruti org` merges them:

```bash
# from CI artifacts (privacy-check.json files, or folders holding one)
svikruti org artifacts/onboarding artifacts/payments artifacts/notifications --out-dir org

# or straight from checked-out repositories that have privacy.yaml
svikruti org ../onboarding ../payments ../notifications --fail-on high
```

```text
Svikruti org report: 3 repositories, 9 activities, 4 open findings
  onboarding                      0 open  dpdpa 18/23  gdpr 18/23  iso27701 18/23
  payments                        4 open  dpdpa 13/23  gdpr 13/23  iso27701 13/23
  processor Mixpanel: used without a record in payments; declared nowhere
  processor Razorpay: country differs across repositories: IN, SG; contract differs across repositories: DPA-2025-011, DPA-2025-099
```

It flags what no single repository can see:

- **Processor register.** One row per vendor across the estate: which
  services declare it, which use it without a record, its countries and
  contracts. A vendor recorded as `IN` in one service and `SG` in another, or
  with a contract in one and none in the next, is an issue to reconcile.
- **Data map.** Per data category: which services hold it, the tables it is
  stored in, which processors and AI providers receive it, high-risk fields
  stored without protection, stores no erasure path reaches, and where it
  reaches logs. This is the DSAR and breach-scoping view for the whole company.
- **Framework posture.** Every clause takes its worst status across
  repositories, with the repositories that fail it, so "GDPR Art. 28(3):
  failing in payments" is one line rather than a hunt through reports.

Outputs in `--out-dir` (default `svikruti-org/`):

| File | Use |
|---|---|
| `org-report.html` | Self-contained report: repositories, framework posture, processor register, data map, failing clauses, findings |
| `org-report.md` | The same for wikis and audit folders |
| `org-summary.json` | Machine-readable (`svikruti-org-v1`); imports into the governance app |
| `org-processing-record.csv` | Every activity in every repository, with a repository column |
| `processor-register.csv` | One row per vendor with declared-in, used-without-record-in, countries and issues |
| `data-inventory.csv` | Every stored personal-data field, with a repository column |
| `findings.csv` | Every open finding, with a repository column |
| `framework-matrix.csv` | One row per clause: worst status, failing in, not verified in |

`--fail-on` (default `none`) gates on any repository's open findings, for a
scheduled estate-wide job. `--name` sets display names in input order.

A GitHub Actions pattern: each service uploads `svikruti-check/` as an
artifact; a nightly job in a central repository downloads them with
`gh run download` and runs `svikruti org` over the folders.

### Governance app

The Streamlit workbench (`app.py`, Import from Scanner) accepts
`privacy-check.json` and `org-summary.json` as well as `privacy.yaml`. A
manifest import gives what was declared; a check import gives what was
verified: activities carry the data the code was found to process, vendors
include processors found in code but not on record, and every open finding
becomes a task with its fix and file location.

## Adopting on an existing codebase

A first run on a large repository will report a backlog. Two mechanisms keep
the gate usable from day one.

**Baseline the check.** Only findings that are not in the baseline can fail
the gate:

```bash
svikruti check --repo . --fail-on none                 # on main: produce svikruti-check/privacy-check.json
svikruti check --repo . --baseline main-check.json     # on the PR: only new drift blocks
```

The generated workflow does this automatically by checking the base branch
out into a worktree.

**Baseline the scan.** For repositories without a manifest yet, gate the raw
scanner on new findings only:

```bash
svikruti scan --repo . --json-out main.json
svikruti scan --repo . --baseline main.json --fail-on-new high --diff-out diff.md
svikruti diff main.json pr.json
```

Findings are matched by fingerprint (file, detector, normalised source line),
not line number, so edits elsewhere in a file do not make old findings look
new. The same fingerprints are written to SARIF `partialFingerprints`.

## What code can and cannot prove

Static analysis sees a repository, not production. Svikruti is explicit about
the boundary:

- It can show that a category of personal data is handled under a path, that a
  third-party SDK is integrated, that a field reaches a logging call, and that
  infrastructure code enables or disables a safeguard.
- It cannot show that a lawful basis is correct, that a contract was signed,
  or that a rights request was answered on time. Those are recorded as
  attestations with an owner and a review date, and reported separately from
  code-verified items.
- Detection is heuristic outside Python (regex and tree-sitter based). Dynamic
  dispatch, generated code and data that only exists at runtime can be missed.
  The scan-quality section of the scan report states parser coverage.

A passing check is engineering evidence that supports a clause. It is not
legal advice and not a certification.

## How this relates to other tools

Based on each project's public README at the time of writing (November 2026):

| Tool | Approach | What Svikruti does differently |
|---|---|---|
| Privado (open source) | Static data-flow scan producing a JSON data map; RoPA through its cloud platform | Reconciles against a declared manifest and gates on drift; maps to several frameworks offline |
| Fides / fideslang | Declared manifests and policy evaluation; humans write the declarations | Generates the manifest from code and verifies it stays true |
| Bearer CLI | Security SAST with a privacy report | Privacy record, drift and framework crosswalk are the primary output |
| HoundDog.ai | Privacy code scanner distributed as binaries under vendor terms | MIT-licensed source; rules, packs and taxonomy are plain files |
| privacy-radar | Node/TypeScript scanner mapping to LGPD and GDPR | Python, JS/TS, Java, Go, Ruby, PHP, SQL, Prisma, OpenAPI and IaC; India-specific identifiers; manifest reconciliation |

Scanners tell you what the code does. Declaration tools tell you what you
said. Svikruti's position is that the useful signal is the difference between
the two, checked on every commit.
