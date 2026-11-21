# Svikruti for VS Code

Privacy drift in the editor. On every save the extension runs
`svikruti check` against your `privacy.yaml` and puts the findings on the
lines that cause them:

- personal data written to logs (P001),
- data categories or processors the record does not declare (D002, D003),
- personal data or user free text sent to an AI model (P006),
- unprotected Aadhaar, PAN or health fields (P007),
- stores no erasure path, or no rights request, reaches (D010, D011),
- consent-based processing without a consent check (P008).

Record-level findings (a processor with no contract) land on the matching
entry in `privacy.yaml`. A quick fix inserts an inline
`svikruti-ignore[RULE]: reason` comment. The status bar shows the open count
and opens the full HTML report. `privacy.yaml` gets completion and validation
from the bundled JSON Schema (with the Red Hat YAML extension).

## Setup

```bash
pip install svikruti        # the extension calls the CLI
svikruti init --repo .      # if the repository has no privacy.yaml yet
```

Settings: `svikruti.command` (CLI path, e.g. a virtualenv's
`.venv/bin/svikruti`), `svikruti.runOnSave`, `svikruti.frameworks`
(`["dpdpa", "rbi", "soc2"]`), `svikruti.minimumSeverity`,
`svikruti.showExcepted`.

## Build

```bash
cd editors/vscode
npm test                 # unit tests for the finding -> diagnostic mapping
npm run package          # copies the schema and builds svikruti-<version>.vsix
code --install-extension svikruti-0.13.0.vsix
```
