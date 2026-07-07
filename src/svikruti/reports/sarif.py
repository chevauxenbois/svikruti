"""SARIF report writer for GitHub code scanning integrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from svikruti.models import Evidence, ScanResult


LEVELS: Dict[str, str] = {
    "LOW": "note",
    "MEDIUM": "warning",
    "HIGH": "error",
    "CRITICAL": "error",
}


def _rule_id(item: Evidence) -> str:
    return f"svikruti.{item.kind}.{(item.category or 'privacy').lower().replace(' ', '_')}"


def write_sarif(result: ScanResult, output_path: str) -> None:
    rules = {}
    findings = []

    for item in result.evidence:
        if not item.file:
            continue
        rule_id = _rule_id(item)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                # SARIF spec wants identifier-like names (no spaces).
                "name": rule_id.replace(".", "_"),
                "shortDescription": {"text": item.label},
                "fullDescription": {"text": item.recommendation},
                "help": {"text": item.recommendation},
            },
        )
        findings.append(
            {
                "ruleId": rule_id,
                "level": LEVELS.get(item.severity, "warning"),
                "message": {"text": f"{item.detail} Recommendation: {item.recommendation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                # SARIF URIs must use forward slashes even on Windows.
                                "uri": item.file.replace("\\", "/")
                            },
                            "region": {"startLine": item.line or 1},
                        }
                    }
                ],
                "properties": {
                    "severity": item.severity,
                    "source": item.source,
                    "kind": item.kind,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Svikruti PrivacyOps",
                        "informationUri": "https://svikruti.ai",
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
            }
        ],
    }
    Path(output_path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
