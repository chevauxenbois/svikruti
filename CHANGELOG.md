# Changelog

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
