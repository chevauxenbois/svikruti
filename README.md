# Svikruti

India-first open-source PrivacyOps evidence workbench.

Svikruti scans code, websites, and consent journeys, then turns engineering
evidence into DPDPA-ready controls, artifacts, tickets, and optional AI
commentary.

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

## Why It Exists

Most privacy tools start with questionnaires. Svikruti starts with evidence:

- What personal data appears in the code?
- Which forms collect it?
- Where is it stored or logged?
- Which SDKs, scripts, and vendors are present?
- Does the privacy notice match the product?
- What DPDPA artifacts and engineering tickets should be created next?

The goal is not to certify compliance. The goal is to give privacy, security,
engineering, and legal teams a shared evidence pack they can act on.

## What You Get

The generated HTML is an offline workbench, not a static dump:

- **Overview**: launch posture, risk, scan coverage, severity mix.
- **Control Board**: notice, consent, minimization, vendors, RoPA, tracking,
  logging/security, and children-data readiness.
- **Actions**: reviewable proof-pack actions with persistent local checkboxes.
- **Evidence Flow**: source -> data category -> notice coverage -> DPDPA area
  -> remediation.
- **Artifacts**: RoPA starter and export guidance.
- **AI Co-pilot**: optional Gemini/OpenAI synthesis grounded in scan evidence.
- **Fix Pack**: copy-ready GitHub/Jira/Linear issue bodies.
- **Evidence Explorer**: searchable, severity-filtered evidence table.

It also exports:

- `svikruti-report.json`
- `svikruti.sarif` for GitHub code scanning
- RoPA CSV
- remediation actions CSV
- vendor register CSV
- privacy notice patch draft
- fix-pack Markdown
- optional AI brief Markdown

## Install

From a checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

For browser consent journey testing:

```bash
python -m pip install ".[browser]"
python -m playwright install chromium
```

## Quick Demo

```bash
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

## Optional AI Co-pilot

AI is opt-in. Svikruti does not call an AI provider unless `--ai` is passed.
The AI request sends a compact evidence packet, not repository files.

Gemini is the default provider:

```bash
export GEMINI_API_KEY=...

svikruti scan \
  --repo . \
  --ai \
  --ai-provider gemini \
  --out ai-report.html \
  --ai-out ai-brief.md
```

OpenAI is also supported:

```bash
export OPENAI_API_KEY=...
svikruti scan --repo . --ai --ai-provider openai --ai-out ai-brief.md
```

## GitHub Action

Generate a pull-request privacy evidence workflow:

```bash
svikruti init-github-action
```

This writes `.github/workflows/svikruti.yml`, uploads SARIF to GitHub code
scanning, and stores evidence artifacts for review.

## Scanner Coverage

Repository scan:

- personal-data signals: identity, contact, government ID, financial, location,
  children, health, and device/tracking data
- collection points: forms, request bodies, signup/profile/checkout flows
- storage points: SQL/schema/model/database write hints
- logging risks near personal-data terms
- India-relevant vendors and SDKs such as Razorpay, Cashfree, Juspay, PayU,
  PhonePe, Exotel, MSG91, Shiprocket, Delhivery, MoEngage, CleverTap,
  WebEngage, plus common global tools such as Google Analytics, Meta Pixel,
  Segment, Mixpanel, Hotjar, Intercom, HubSpot, Firebase, Sentry, and Stripe

Website scan:

- visible form fields
- third-party scripts
- cookies on first response
- privacy notice links
- consent copy without obvious withdrawal copy

Optional browser mode:

- tracking before consent
- reject button presence
- tracking after reject
- accept button presence
- withdrawal/preferences discoverability

## Architecture

```text
src/svikruti/
  ai.py                   # optional Gemini/OpenAI synthesis
  cli.py                  # command line entry point
  models.py               # report/evidence dataclasses
  scanner/
    browser.py            # optional Playwright consent journey scanner
    code.py               # static repo scanner
    website.py            # public website scanner
    dpdpa.py              # DPDPA aggregation and RoPA starter
    patterns.py           # transparent rules and dictionaries
    runner.py             # orchestration
  reports/
    exports.py            # CSV/Markdown artifact exports
    html.py               # offline workbench report
    json_report.py        # JSON report
    sarif.py              # GitHub code scanning output
```

The original Streamlit dashboard remains in the repository as a legacy/manual
workspace. The launch product is the evidence workbench and scanner package.

## Security And Privacy

- Svikruti does not execute customer source code.
- Static scan mode runs locally.
- AI is opt-in and sends only a compact evidence packet.
- Reports may contain file paths, inferred data categories, and line numbers;
  review before sharing externally.
- This is not legal advice and not a compliance certification.

## Roadmap

- richer privacy notice semantic comparison
- secret redaction before report generation
- authenticated web-app scanning
- hosted scan history and evidence vault
- Jira/Linear integrations
- DSR, breach, and vendor workflow modules

## License

MIT.
