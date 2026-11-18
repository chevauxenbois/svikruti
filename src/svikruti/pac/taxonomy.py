"""Framework-neutral vocabulary shared by the manifest, drift engine and packs."""

from __future__ import annotations

import re
from typing import Dict, Optional

# Scanner display label -> manifest slug. The scanner labels come from
# svikruti.scanner.patterns.PERSONAL_DATA_PATTERNS; slugs are what people write
# in privacy.yaml. Unknown labels are slugified, so custom detectors keep working.
CATEGORY_LABELS: Dict[str, str] = {
    "identity": "Identity",
    "contact": "Contact",
    "government_id": "Government ID",
    "financial": "Financial",
    "location": "Location",
    "children": "Children",
    "health": "Health",
    "device": "Device",
    "biometric": "Biometric",
    # User-typed text sent to an AI model: it can hold any category, so it is tracked on its own.
    "free_text": "Free text",
}

# Categories whose presence requires a recorded impact assessment before the
# gate passes. Deliberately framework-neutral: GDPR Art. 9/35, DPDPA Sec. 9/10
# and ISO/IEC 27701 A.1.2.6 all converge on "assess before you process this".
HIGH_RISK_CATEGORIES = {"health", "children", "government_id", "biometric"}

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Placeholder values written by `svikruti init`. A field still holding one of
# these counts as undocumented.
PLACEHOLDERS = {"", "todo", "tbd", "unknown", "to be confirmed", "to be defined", "n/a", "na", "none", "-"}


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def category_slug(label: Optional[str]) -> str:
    return slugify(label or "")


def category_label(slug: str) -> str:
    return CATEGORY_LABELS.get(slug, slug.replace("_", " ").title())


def is_placeholder(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0 or all(is_placeholder(item) for item in (value.values() if isinstance(value, dict) else value))
    text = str(value).strip().lower()
    return text in PLACEHOLDERS or text.startswith("todo")


def category_severity(slug: str) -> str:
    """Drift severity for an undeclared category: high-risk data is critical."""
    return "CRITICAL" if slug in HIGH_RISK_CATEGORIES else "HIGH"


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.upper(), 0) >= SEVERITY_ORDER.get(threshold.upper(), 99)
