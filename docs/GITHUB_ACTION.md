# GitHub Action Usage

Svikruti can run in pull requests and upload SARIF results to GitHub code
scanning.

Generate the workflow from the CLI:

```bash
svikruti init-github-action
```

That writes `.github/workflows/svikruti.yml`. The equivalent workflow is:

```yaml
name: Svikruti Privacy Evidence

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  privacy-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Svikruti
        run: pip install svikruti

      - name: Scan repository
        run: |
          svikruti scan \
            --repo . \
            --out svikruti-report.html \
            --json-out svikruti-report.json \
            --sarif-out svikruti.sarif \
            --ropa-out svikruti-ropa.csv \
            --actions-out svikruti-actions.csv \
            --vendors-out svikruti-vendors.csv \
            --controls-out svikruti-technical-controls.csv \
            --breach-out svikruti-breach-readiness.md \
            --notice-patch-out svikruti-notice-patch.md \
            --issues-out svikruti-fix-pack.md \
            --fail-on critical

      # Optional: import existing security scanner outputs into the same
      # privacy evidence pack by adding --security-evidence semgrep.sarif,
      # --security-evidence trivy.json, --security-evidence gitleaks.json, or
      # --security-evidence osv.json to the scan command above.

      # Optional AI co-pilot. Configure the API key for your selected provider
      # as a repository secret before enabling.
      # - name: Generate AI co-pilot brief
      #   run: |
      #     svikruti scan \
      #       --repo . \
      #       --ai \
      #       --out svikruti-ai-report.html \
      #       --json-out svikruti-ai-report.json \
      #       --ai-out svikruti-ai-brief.md

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: svikruti.sarif

      - name: Upload evidence report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: svikruti-evidence-report
          path: |
            svikruti-report.html
            svikruti-report.json
            svikruti-ropa.csv
            svikruti-actions.csv
            svikruti-vendors.csv
            svikruti-technical-controls.csv
            svikruti-breach-readiness.md
            svikruti-notice-patch.md
            svikruti-fix-pack.md
            svikruti-ai-brief.md
```

Use the technical-control CSV and breach-readiness Markdown when security,
privacy, or legal reviewers ask whether the product has evidence for
encryption, third-party processing, vulnerability management, endpoint/workload
detection, monitoring, incident response, backup, and impact mapping.

For private repositories, review the generated report before sharing it outside
the organization because it may contain file names, line numbers, and inferred
data categories.
