# Svikruti PrivacyOps Launch Plan

Svikruti should launch as a broader open-source PrivacyOps platform, with the
Evidence Scanner as the first product module.

## Positioning

**Svikruti PrivacyOps** is an open-source privacy operations platform for Indian
companies preparing for the Digital Personal Data Protection Act.

The first module is **Svikruti Evidence Workbench**:

> Scan your codebase, website, and consent journey to generate an interactive
> DPDPA evidence workbench, RoPA starter, vendor register, notice patch draft,
> copy-ready fix pack, optional AI co-pilot brief, SARIF file, and PR privacy gate.

## Day-1 Product

The day-1 launchable product is a local CLI plus offline workbench:

```bash
pipx run svikruti scan --repo . --url https://example.com --out dpdpa-report.html
```

It produces:

- Static repository evidence: personal-data fields, collection points, storage
  points, logging risks, and third-party SDKs.
- Website evidence: visible forms, third-party scripts, cookies set on first
  response, privacy-notice link detection, and consent/withdrawal copy signals.
- Optional browser consent journey evidence: third-party requests before
  consent, after reject, and after accept, plus missing reject/withdrawal paths.
- DPDPA mapping: practical readiness areas such as notice transparency, consent
  and withdrawal, data minimization, tracking, children data, third-party
  processors, and rights readiness.
- RoPA starter: processing activities inferred from detected evidence.
- Privacy notice gap list: detected data categories or third parties that are
  not clearly covered by the fetched notice.
- Interactive report: overview, action checklist, evidence flow, artifacts, and
  searchable evidence explorer.
- DPDPA Control Board: launch-readiness status by notice, consent, minimization,
  vendor, RoPA, tracking, logging/security, and children-data controls.
- Evidence graph: source file -> data category -> third party / notice /
  DPDPA obligation -> remediation artifact.
- Proof pack: prioritized actions with owner, artifact, and evidence references.
- Exportable artifacts: RoPA CSV, action tracker CSV, vendor register CSV, and
  privacy notice patch draft.
- Fix Pack: copy-ready GitHub/Jira/Linear issue bodies with acceptance criteria.
- Optional AI Co-pilot: executive brief, launch risk, control commentary,
  buyer summary, notice patch, and improved fix wording grounded in scan output.
- HTML workbench suitable for sharing with engineering, compliance, security,
  or counsel.
- SARIF output for GitHub code scanning.
- One-command GitHub Action installer.

Best demo command:

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

Best live-site consent demo after installing Playwright:

```bash
svikruti scan \
  --url https://yourdomain.com \
  --privacy-url https://yourdomain.com/privacy \
  --browser-consent \
  --out consent-evidence.html
```

## Free And Enterprise Packaging

### Open-source Free

- Local CLI scanner.
- Interactive HTML workbench and JSON reports.
- Repo scan.
- Public URL scan.
- Transparent rules and pattern dictionaries.
- RoPA, vendor, action, and notice-patch exports.
- Copy-ready fix-pack issue export.
- GitHub Action / SARIF.
- BYOK AI explanations.
  For v1, Gemini can be used via `--ai --ai-provider gemini` with `GEMINI_API_KEY`;
  OpenAI remains available with `--ai-provider openai`.

### Hosted Free Tier

- One public website scan.
- One public repository scan by URL or upload.
- Watermarked/shareable report.
- Email capture for launch demand.

### Enterprise

- Private repo scanning.
- GitHub/GitLab CI integration.
- Authenticated web-app scanning.
- Browser-based consent journey testing.
- India-hosted evidence vault.
- Report history and audit trail.
- Slack/Jira workflows.
- SSO/RBAC.
- Custom legal/privacy playbooks.
- Vendor and processor register.

## Hosting Options

### Fastest Launch

Use the existing Streamlit app on Railway for the current dashboard and publish
the new CLI as the main open-source product.

1. Push this repo to GitHub.
2. Create a Railway project from the repo.
3. Keep `DATA_DIR=/data` for persistent SQLite storage.
4. Point `svikruti.ai` DNS to Railway.
5. Add a landing page section that links to the CLI quickstart and sample report.

This is fastest, but Streamlit should not be the long-term product core.

### Recommended Public Product Architecture

Use a separate web app for `svikruti.ai` and keep this Python package as the
scanner engine.

- `svikruti` Python package: scanner, CLI, report generator.
- Hosted web app: upload repo archive or enter public URL, run scanner in a
  worker, store report metadata.
- Object storage: report HTML/JSON artifacts.
- Database: scans, users, organizations, audit trail.
- Queue/worker: isolates long-running scans.

Good hosting choices:

- Landing and hosted UI: Vercel, Cloudflare Workers, or Fly.io.
- Scanner worker: Railway, Fly.io, Render, ECS, or Kubernetes.
- Storage: S3/R2.
- Database: Postgres.
- Secrets: platform secrets manager.

### Security Baseline

- Do not execute untrusted repository code.
- Treat all repository uploads as hostile input.
- Set scan size limits.
- Run scanners in isolated containers.
- Use short-lived signed URLs for report download.
- Do not store customer source code by default.
- Encrypt reports at rest for enterprise.
- Redact secrets and access tokens before report generation.
- Clearly state that reports are not legal advice or certification.

## Two-Week Roadmap

### Week 1

- Publish CLI package.
- Add GitHub Action.
- Add sample reports for Indian SaaS, fintech, healthcare, and edtech.
- Add more browser consent fixtures and screenshots.
- Improve privacy notice comparison.
- Add JSON schema for integrations.

### Week 2

- Hosted public scan flow.
- Report history.
- Organization accounts.
- Payment waitlist.
- Enterprise demo mode.
- India-specific templates: RoPA, DSR SOP, breach pack, vendor register.

## Launch Copy

Headline:

> Open-source PrivacyOps for India.

Subheadline:

> Svikruti scans your code and website to produce DPDPA evidence reports,
> RoPA starters, third-party maps, and privacy notice gaps.

Primary CTA:

```bash
pipx run svikruti scan --repo . --url https://yourdomain.com
```

Launch claim:

> Not another questionnaire. Svikruti uses engineering evidence.
