"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from svikruti.models import ScanResult


def write_json(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
