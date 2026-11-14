"""Privacy-as-code: the repository is the source of truth.

A declared manifest (``privacy.yaml``) is reconciled against what the scanner
actually finds in code. Drift between the two, policy violations, and
framework obligations (DPDPA, GDPR, ISO/IEC 27701, custom packs) are evaluated
from the same evidence and gated in CI.
"""

from svikruti.pac.manifest import Manifest, ManifestError, load_manifest  # noqa: F401
from svikruti.pac.engine import CheckResult, run_check  # noqa: F401
