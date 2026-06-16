# Svikruti.ai

India-first open-source PrivacyOps platform for DPDPA readiness, engineering
evidence, consent governance, and audit artifacts.

Svikruti combines two workflows that are usually separate:

1. **Governance workbench**: a Streamlit app for gap assessment, RoPA, consent,
   rights requests, vendors, breach response, document generation, and DPDPA
   knowledge management.
2. **Evidence scanner**: a developer-first CLI that scans code, websites,
   privacy notices, and consent journeys, then produces an offline evidence
   dashboard, SARIF, CSVs, Markdown fix packs, and optional AI commentary.

Most privacy tools start with questionnaires. Svikruti starts with both
questionnaires and engineering evidence, so privacy, security, engineering, and
legal teams can work from the same facts.

```bash
svikruti scan \
  --repo . \
  --url https://example.com \
  --privacy-url https://example.com/privacy \
  --out svikruti-report.html \
  --json-out svikruti-report.json \
  --sarif-out svikruti.sarif \
  --ropa-out ropa.csv \
  --actions-out actions.csv \
  --vendors-out vendors.csv \
  --notice-patch-out notice-patch.md \
  --issues-out fix-pack.md
```

## Why This Is Different

Svikruti is not another static compliance checklist.

- **India-first**: built around DPDPA concepts, Indian privacy operations, and
  India-relevant vendors such as Razorpay, Cashfree, Juspay, PayU, PhonePe,
  Exotel, MSG91, Shiprocket, Delhivery, MoEngage, CleverTap, and WebEngage.
- **Evidence-first**: connects files, forms, SDKs, privacy notices, consent
  journeys, and DPDPA control areas.
- **Open-source by default**: useful locally without a hosted account.
- **AI optional**: AI can summarize evidence and draft remediation, but the core
  scanner works without sending data to any model.
- **Launch-ready artifacts**: produces RoPA starters, vendor registers, action
  plans, privacy notice patch drafts, GitHub issues, and SARIF.
- **Board-to-code coverage**: combines executive dashboarding with developer
  pull-request gates.

## Product Surfaces

### 1. Governance Workbench

Run the Streamlit app when you want a business-facing DPDPA workspace.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

The app opens at `http://localhost:8501`.

Core modules:

| Module | What it does |
| --- | --- |
| Dashboard | Compliance score, category posture, readiness metrics, activity overview |
| Gap Assessment | Weighted DPDPA readiness assessment across major compliance categories |
| RoPA Registry | Records of Processing Activities with purposes, data categories, recipients, retention, and safeguards |
| Consent Manager | Consent record tracking, DPDPA consent checklist, children's data handling |
| Privacy Notices | Notice builder with plain-language preview and version-oriented workflow |
| Rights Requests | Data Principal access, correction, erasure, grievance, and nomination request tracker |
| Vendor Management | Processor/vendor inventory, DPA tracking, security posture, risk dashboard |
| Document Generator | Privacy policy, consent notice, DPA, DPIA, RoPA, breach notification, grievance policy |
| Compliance Tracker | Tasks, owners, priorities, deadlines, progress tracking |
| Breach Response | Incident logging, severity classification, notification workflow, timeline |
| Knowledge Base | DPDPA sections, definitions, checklist items, FAQs, and practical guidance |
| Settings | Organization profile, user/org configuration, SDF-related setup |

AI app modules:

| Module | What it does |
| --- | --- |
| AI Assistant | Conversational DPDPA guidance with section-aware answers |
| AI Doc Drafter | Drafts privacy policies, DPAs, consent notices, breach notices, and RoPA summaries |
| AI Compliance Advisor | Turns assessment gaps into prioritized remediation plans |
| AI Breach Analyzer | Classifies breach scenarios and drafts notification language |
| AI Notice Reviewer | Reviews privacy notices for completeness, readability, and DPDPA fit |
| AI Configuration | Provider, model, API key, and usage configuration |

### 2. Evidence Scanner

Run the CLI when you want developer evidence and a launch/audit pack.

```bash
python -m pip install -e .

svikruti scan \
  --repo examples \
  --privacy-file examples/privacy.html \
  --out examples-report.html \
  --json-out examples-report.json \
  --sarif-out examples-report.sarif \
  --ropa-out examples-ropa.csv \
  --actions-out examples-actions.csv \
  --vendors-out examples-vendors.csv \
  --notice-patch-out examples-notice-patch.md \
  --issues-out examples-fix-pack.md
```

Open `examples-report.html`.

The HTML output is an offline evidence workbench:

| View | What it shows |
| --- | --- |
| Overview | Launch posture, risk score, scan coverage, severity mix, next actions |
| Control Board | Notice, consent, minimization, vendors, RoPA, tracking, logging/security, children-data readiness |
| Actions | Prioritized proof-pack actions with local checkbox state |
| Evidence Flow | Source -> data category -> notice coverage -> DPDPA area -> remediation |
| Artifacts | RoPA starter, export guidance, notice patch, fix-pack copy actions |
| AI Co-pilot | Optional Gemini/OpenAI synthesis grounded in scan evidence |
| Fix Pack | Copy-ready GitHub/Jira/Linear implementation tickets |
| Evidence Explorer | Searchable, severity-filtered evidence table |

Scanner inputs:

- repository source code
- public website URL
- privacy notice URL or local privacy notice file
- optional browser consent journey through Playwright

Scanner outputs:

- offline HTML evidence dashboard
- structured JSON report
- SARIF for GitHub code scanning
- schema-versioned RoPA / privacy inventory CSV
- schema-versioned remediation action CSV
- schema-versioned vendor / processor register CSV
- privacy notice patch Markdown
- GitHub/Jira/Linear-ready fix-pack Markdown
- optional AI brief Markdown

CSV schemas are documented in [docs/OUTPUT_SCHEMAS.md](docs/OUTPUT_SCHEMAS.md).
Each row includes evidence references and separates scanner-inferred fields
from fields that privacy, legal, procurement, or engineering must confirm.

## AI Co-pilot

AI is opt-in. The CLI does not call an AI provider unless `--ai` is passed.
The scanner sends a compact evidence packet, not full repository files.

Gemini is the default CLI provider:

```bash
export GEMINI_API_KEY=...

svikruti scan \
  --repo . \
  --privacy-url https://example.com/privacy \
  --ai \
  --ai-provider gemini \
  --out ai-report.html \
  --ai-out ai-brief.md
```

OpenAI is also supported in the CLI:

```bash
export OPENAI_API_KEY=...
svikruti scan --repo . --ai --ai-provider openai --ai-out ai-brief.md
```

The Streamlit app also includes AI pages for assistant, drafting, compliance
advisor, breach analysis, and notice review.

## Browser Consent Journey

Install optional browser dependencies:

```bash
python -m pip install ".[browser]"
python -m playwright install chromium
```

Then scan:

```bash
svikruti scan \
  --url https://example.com \
  --privacy-url https://example.com/privacy \
  --browser-consent \
  --out consent-report.html
```

Browser mode checks:

- third-party requests before consent
- reject button presence
- tracking after reject
- accept button presence
- withdrawal/preferences discoverability

## GitHub Pull-Request Gate

Generate a workflow:

```bash
svikruti init-github-action
```

The generated workflow can:

- scan the repository on pull requests
- create HTML, JSON, CSV, Markdown, and SARIF artifacts
- upload SARIF to GitHub code scanning
- fail builds above a configured severity threshold

More detail: [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md).

## Detection Coverage

Repository scan currently detects signals for:

- identity data
- contact data
- government identifiers
- financial/payment data
- location data
- children-related data
- health data
- device and tracking data
- form collection points
- request body collection points
- database/schema/storage hints
- logging near personal-data terms
- India-relevant and global third-party tools

Website scan currently detects:

- visible form fields
- third-party scripts
- cookies on first response
- privacy notice links
- consent copy without obvious withdrawal copy

Privacy notice comparison maps detected data categories and vendors against
notice coverage to identify gaps such as "Location data detected but not clearly
disclosed."

## Project Structure

```text
svikruti/
  app.py                  # Streamlit governance workbench and routing
  ai_engine.py            # Streamlit app AI provider layer
  ai_pages.py             # App AI assistant, drafting, advisor, breach, notice review
  new_pages.py            # RoPA, consent, notices, rights, vendors
  database.py             # SQLite persistence for app workflows
  doc_generator.py        # DPDPA document generation
  knowledge_base.py       # DPDPA knowledge base content
  config.py               # Categories, questions, templates, settings

  src/svikruti/
    ai.py                 # CLI Gemini/OpenAI evidence synthesis
    cli.py                # `svikruti` command line entry point
    models.py             # report/evidence dataclasses
    scanner/
      code.py             # static repository scanner
      website.py          # public website scanner
      browser.py          # optional Playwright consent journey scanner
      dpdpa.py            # DPDPA aggregation and RoPA starter
      patterns.py         # transparent rules and dictionaries
      runner.py           # scan orchestration
    reports/
      html.py             # offline evidence workbench renderer
      exports.py          # CSV/Markdown exports
      json_report.py      # JSON report
      sarif.py            # GitHub code scanning output

  examples/               # sample app/site/privacy notice and generated report
  tests/                  # scanner tests
  docs/                   # launch and GitHub Action docs
```

## Free And Enterprise Model

Open-source/free:

- local Streamlit governance workbench
- local evidence scanner
- DPDPA knowledge base
- document generation
- BYOK AI flows
- GitHub Action
- HTML/JSON/SARIF/CSV/Markdown exports

Enterprise/hosted direction:

- managed scan history and evidence vault
- org dashboards across many products
- hosted AI with provider management
- Jira/Linear integrations
- vendor evidence collection workflows
- SSO, RBAC, audit logs, and policy approvals
- sector packs for BFSI, healthcare, education, SaaS, ecommerce, and fintech
- continuous privacy posture monitoring

## Security And Privacy

- Static scanner mode does not execute customer source code.
- CLI scan runs locally by default.
- AI is disabled unless explicitly enabled.
- AI requests are compact evidence packets, not full repositories.
- Reports may contain file paths, line numbers, inferred data categories, and
  vendor names; review before sharing externally.
- Svikruti is an evidence and workflow tool, not legal advice or compliance
  certification.

## Launch Plan

See [docs/LAUNCH_PLAN.md](docs/LAUNCH_PLAN.md) for the initial launch motion,
positioning, free tier, enterprise tier, and follow-up roadmap.

Suggested launch wedge:

> Open-source PrivacyOps for India: scan your product, map engineering evidence
> to DPDPA readiness, and generate the first audit pack in minutes.

## Roadmap

- richer privacy notice semantic comparison
- secret and sensitive value redaction before report generation
- authenticated app scanning
- deeper framework-specific code analysis
- hosted evidence vault
- consent receipt verification
- DSR workflow automation
- breach workflow automation
- Jira/Linear ticket sync
- Hindi and Indian language notice support
- sector-specific DPDPA packs

## Contributing

Useful contributions:

- new detection patterns
- additional India-specific vendors and SDKs
- tests for common web frameworks
- privacy notice examples
- DPDPA document templates
- language translations
- UI improvements
- deployment recipes

## License

MIT License. Free for personal and commercial use.

## Author

Harsh Kahate

Information Security and Data Privacy Professional

- LinkedIn: [hkahate](https://linkedin.com/in/hkahate)
- Blog: [substack.com/@harshkahate](https://substack.com/@harshkahate)

Svikruti.ai is built to make DPDPA readiness practical for Indian startups,
security teams, privacy teams, and engineering teams.
