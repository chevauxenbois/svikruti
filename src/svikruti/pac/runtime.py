"""Runtime redaction installed in the repository mitigates P001 for the loggers it covers.

`svikruti.redact.install_logging_redaction()` rewrites every stdlib `logging`
record in the process, so a Python logging call that carries personal data is
redacted before any handler sees it. `installConsoleRedaction()` from
`svikruti-redact` does the same for `console.*` in Node, and `pinoLogMethod()`
for a pino logger. When one of these is called in production code, P001
findings whose every location it covers are marked as handled at runtime,
with the installation named in the reason. Loggers it does not cover (loguru,
structlog, winston, bunyan) stay open.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from svikruti.pac.reconcile import Finding

_INSTALLS = {
    "python": re.compile(r"(?<!def )\binstall_logging_redaction\s*\(|\baddFilter\s*\(\s*(?:[\w.]+\.)?RedactingFilter\s*\("),
    "console": re.compile(r"(?<!function )\binstallConsoleRedaction\s*\("),
    "pino": re.compile(r"\bpinoLogMethod\s*\("),
}
_PY_OTHER_LOGGERS_RE = re.compile(r"^\s*(?:from|import)\s+(?:loguru|structlog|logbook|eliot)\b", re.MULTILINE)
_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def installations(root: Path, files: Iterable[str]) -> Dict[str, str]:
    """kind -> "file:line" where runtime redaction is installed."""
    found: Dict[str, str] = {}
    for rel in files:
        if not rel.endswith((".py",) + _JS_SUFFIXES) or "svikruti/redact" in rel or "redact-js/index" in rel:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(token in text for token in ("install_logging_redaction", "RedactingFilter", "installConsoleRedaction", "pinoLogMethod")):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith(("#", "//", "*")):
                continue
            for kind, pattern in _INSTALLS.items():
                if kind not in found and pattern.search(line):
                    found[kind] = f"{rel}:{number}"
    return found


def apply_runtime_redaction(findings: List[Finding], root: Optional[str], files: Iterable[str]) -> Dict[str, str]:
    if not root:
        return {}
    base = Path(root)
    installed = installations(base, files)
    if not installed:
        return installed
    cache: Dict[str, List[str]] = {}

    def line_of(rel: str, number: int) -> str:
        if rel not in cache:
            try:
                cache[rel] = (base / rel).read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                cache[rel] = []
        lines = cache[rel]
        return lines[number - 1] if 0 < number <= len(lines) else ""

    def covered_by(ref: str) -> Optional[str]:
        rel, _, number = ref.rpartition(":")
        if not number.isdigit():
            return None
        if rel.endswith(".py") and "python" in installed:
            if rel not in cache:
                line_of(rel, 1)
            return None if _PY_OTHER_LOGGERS_RE.search("\n".join(cache.get(rel, []))) else installed["python"]
        if rel.endswith(_JS_SUFFIXES):
            text = line_of(rel, int(number))
            if "console" in installed and re.search(r"\bconsole\.\w+\s*\(", text):
                return installed["console"]
            if "pino" in installed and not re.search(r"\bconsole\.", text):
                return installed["pino"]
        return None

    for finding in findings:
        if finding.rule != "P001" or finding.status != "open" or not finding.refs:
            continue
        where = [covered_by(ref) for ref in finding.refs]
        if all(where):
            finding.status = "excepted"
            finding.exception_reason = "Redacted at runtime: " + "; ".join(sorted(set(filter(None, where)))) + " installs svikruti redaction for these log calls."
    return installed
