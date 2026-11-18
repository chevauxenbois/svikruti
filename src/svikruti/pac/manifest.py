"""privacy.yaml: the declared side of privacy-as-code.

The manifest lives in the repository next to the code it describes, is
reviewed in pull requests, and is reconciled against scanner evidence by
``svikruti check``. It records only what code cannot say for itself (purpose,
lawful basis, retention, contracts) and binds each processing activity to the
paths that implement it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from svikruti.pac.taxonomy import is_placeholder, slugify

MANIFEST_VERSION = 1
DEFAULT_MANIFEST_NAMES = ("privacy.yaml", "privacy.yml", ".svikruti/privacy.yaml", "privacy.json")

_TOP_KEYS = {"version", "organization", "frameworks", "processing_activities", "processors", "policies", "erasure", "consent", "exceptions", "attestations"}
_ERASURE_KEYS = {"handlers", "retained", "entrypoints"}
_CONSENT_KEYS = {"checks"}
_ACTIVITY_KEYS = {
    "id", "name", "owner", "paths", "data_categories", "data_subjects", "purposes",
    "legal_basis", "retention", "processors", "dpia", "logging", "notes",
}
_PROCESSOR_KEYS = {"id", "name", "aliases", "purpose", "country", "contract", "transfer_mechanism", "data_categories", "notes"}
_POLICY_KEYS = {
    "personal_data_in_logs", "forbidden_categories", "allowed_transfer_countries",
    "require_dpia_for", "ignore_paths", "attestation_max_age_days", "min_confidence",
    "ai_allowed_categories", "require_field_protection_for",
}
_EXCEPTION_KEYS = {"rule", "activity", "category", "processor", "path", "reason", "approved_by", "expires"}
_ATTESTATION_KEYS = {"obligation", "statement", "evidence", "owner", "reviewed"}
_LOG_POLICIES = {"deny", "warn", "allow"}
_CONFIDENCE = {"low", "medium", "high"}


class ManifestError(ValueError):
    """Raised with every validation problem at once, not just the first."""

    def __init__(self, errors: List[str], path: Optional[str] = None):
        self.errors = errors
        self.path = path
        prefix = f"{path}: " if path else ""
        super().__init__(prefix + "; ".join(errors))


@dataclass
class Activity:
    id: str
    name: str = ""
    owner: str = ""
    paths: List[str] = field(default_factory=list)
    data_categories: List[str] = field(default_factory=list)
    data_subjects: List[str] = field(default_factory=list)
    purposes: List[str] = field(default_factory=list)
    legal_basis: Union[str, Dict[str, str]] = ""
    retention: str = ""
    processors: List[str] = field(default_factory=list)
    dpia: str = ""
    logging_allow: List[str] = field(default_factory=list)
    notes: str = ""

    def basis_for(self, framework_id: str) -> str:
        if isinstance(self.legal_basis, dict):
            return str(self.legal_basis.get(framework_id) or self.legal_basis.get("default") or "")
        return str(self.legal_basis or "")


@dataclass
class Processor:
    id: str
    name: str = ""
    aliases: List[str] = field(default_factory=list)
    purpose: str = ""
    country: str = ""
    contract: str = ""
    transfer_mechanism: str = ""
    data_categories: List[str] = field(default_factory=list)
    notes: str = ""

    def keys(self) -> List[str]:
        """Normalised names this processor can be detected under."""
        return sorted({slugify(value) for value in [self.id, self.name, *self.aliases] if value})


@dataclass
class Policies:
    personal_data_in_logs: str = "deny"
    forbidden_categories: List[str] = field(default_factory=list)
    allowed_transfer_countries: List[str] = field(default_factory=list)
    require_dpia_for: Optional[List[str]] = None  # None -> taxonomy default
    ignore_paths: List[str] = field(default_factory=list)
    attestation_max_age_days: int = 365
    min_confidence: str = "medium"
    # None: not enforced. []: no personal data may be sent to AI model providers.
    ai_allowed_categories: Optional[List[str]] = None
    # Categories whose stored fields must be encrypted, tokenised, hashed or masked
    # (for example government_id, for the UIDAI Aadhaar Data Vault requirement).
    require_field_protection_for: List[str] = field(default_factory=list)


@dataclass
class Erasure:
    """How the code deletes personal data, and which stores are kept on purpose."""

    handlers: List[str] = field(default_factory=list)       # extra function names that erase data
    retained: Dict[str, str] = field(default_factory=dict)  # store (table / model) -> legal reason it is kept
    entrypoints: List[str] = field(default_factory=list)    # functions / classes a rights request enters through


@dataclass
class Consent:
    """How the code checks consent before consent-based processing."""

    checks: List[str] = field(default_factory=list)  # names of your own consent helpers / guards (has_marketing_consent)


@dataclass
class ExceptionRule:
    rule: str
    reason: str
    activity: str = ""
    category: str = ""
    processor: str = ""
    path: str = ""
    approved_by: str = ""
    expires: Optional[date] = None

    def expired(self, today: Optional[date] = None) -> bool:
        return bool(self.expires and self.expires < (today or date.today()))


@dataclass
class Attestation:
    obligation: str
    statement: str
    evidence: str = ""
    owner: str = ""
    reviewed: Optional[date] = None


@dataclass
class Manifest:
    version: int = MANIFEST_VERSION
    organization: Dict[str, Any] = field(default_factory=dict)
    frameworks: List[str] = field(default_factory=list)
    activities: List[Activity] = field(default_factory=list)
    processors: List[Processor] = field(default_factory=list)
    policies: Policies = field(default_factory=Policies)
    exceptions: List[ExceptionRule] = field(default_factory=list)
    attestations: List[Attestation] = field(default_factory=list)
    erasure: Erasure = field(default_factory=Erasure)
    consent: Consent = field(default_factory=Consent)
    warnings: List[str] = field(default_factory=list)
    path: Optional[str] = None

    def processor_by_key(self) -> Dict[str, Processor]:
        index: Dict[str, Processor] = {}
        for processor in self.processors:
            for key in processor.keys():
                index.setdefault(key, processor)
        return index

    def activity(self, activity_id: str) -> Optional[Activity]:
        return next((item for item in self.activities if item.id == activity_id), None)


def find_manifest(repo: Optional[str]) -> Optional[Path]:
    if not repo:
        return None
    root = Path(repo)
    for name in DEFAULT_MANIFEST_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_manifest(path: Union[str, Path]) -> Manifest:
    path = Path(path)
    if not path.is_file():
        raise ManifestError([f"manifest not found: {path}"])
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else _load_yaml(text)
    except ManifestError:
        raise
    except Exception as exc:  # malformed YAML/JSON: report it as a manifest problem
        raise ManifestError([f"could not parse manifest: {exc}"], str(path)) from exc
    manifest = parse_manifest(data, source=str(path))
    manifest.path = str(path)
    return manifest


def _load_yaml(text: str) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - PyYAML is a core dependency
        raise ManifestError(["PyYAML is required to read privacy.yaml (pip install pyyaml), or use privacy.json"]) from exc
    return yaml.safe_load(text)


def parse_manifest(data: Any, source: Optional[str] = None) -> Manifest:
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(data, dict):
        raise ManifestError(["manifest must be a mapping at the top level"], source)

    _unknown(data, _TOP_KEYS, "manifest", warnings)
    version = data.get("version", MANIFEST_VERSION)
    if version != MANIFEST_VERSION:
        errors.append(f"version: unsupported manifest version {version!r} (this release reads version {MANIFEST_VERSION})")

    organization = data.get("organization") or {}
    if not isinstance(organization, dict):
        errors.append("organization: must be a mapping")
        organization = {}

    frameworks = _str_list(data.get("frameworks"), "frameworks", errors)

    processors: List[Processor] = []
    seen_processors: set = set()
    for index, raw in enumerate(_dict_list(data.get("processors"), "processors", errors)):
        where = f"processors[{index}]"
        _unknown(raw, _PROCESSOR_KEYS, where, warnings)
        processor_id = slugify(str(raw.get("id") or raw.get("name") or ""))
        if not processor_id:
            errors.append(f"{where}: needs an id or name")
            continue
        if processor_id in seen_processors:
            errors.append(f"{where}: duplicate processor id '{processor_id}'")
            continue
        seen_processors.add(processor_id)
        processors.append(
            Processor(
                id=processor_id,
                name=str(raw.get("name") or raw.get("id")),
                aliases=_str_list(raw.get("aliases"), f"{where}.aliases", errors),
                purpose=_text(raw.get("purpose")),
                country=_text(raw.get("country")).upper(),
                contract=_text(raw.get("contract")),
                transfer_mechanism=_text(raw.get("transfer_mechanism")),
                data_categories=[slugify(item) for item in _str_list(raw.get("data_categories"), f"{where}.data_categories", errors)],
                notes=_text(raw.get("notes")),
            )
        )

    activities: List[Activity] = []
    seen_activities: set = set()
    for index, raw in enumerate(_dict_list(data.get("processing_activities"), "processing_activities", errors)):
        where = f"processing_activities[{index}]"
        _unknown(raw, _ACTIVITY_KEYS, where, warnings)
        activity_id = slugify(str(raw.get("id") or raw.get("name") or ""))
        if not activity_id:
            errors.append(f"{where}: needs an id")
            continue
        where = f"processing_activities[{activity_id}]"
        if activity_id in seen_activities:
            errors.append(f"{where}: duplicate activity id")
            continue
        seen_activities.add(activity_id)
        paths = _str_list(raw.get("paths"), f"{where}.paths", errors)
        if not paths:
            errors.append(f"{where}.paths: bind the activity to at least one path glob so code can be reconciled against it")
        legal_basis = raw.get("legal_basis") or ""
        if isinstance(legal_basis, dict):
            legal_basis = {slugify(str(key)): slugify(str(value)) for key, value in legal_basis.items() if value}
        elif isinstance(legal_basis, str):
            legal_basis = legal_basis.strip() if is_placeholder(legal_basis) else slugify(legal_basis)
        else:
            errors.append(f"{where}.legal_basis: must be a string or a per-framework mapping")
            legal_basis = ""
        logging_raw = raw.get("logging") or {}
        if not isinstance(logging_raw, dict):
            errors.append(f"{where}.logging: must be a mapping such as {{allow: [device]}}")
            logging_raw = {}
        activity_processors = [slugify(item) for item in _str_list(raw.get("processors"), f"{where}.processors", errors)]
        for processor_id in activity_processors:
            if processor_id not in seen_processors:
                errors.append(f"{where}.processors: '{processor_id}' is not defined under top-level processors")
        activities.append(
            Activity(
                id=activity_id,
                name=_text(raw.get("name")) or activity_id,
                owner=_text(raw.get("owner")),
                paths=paths,
                data_categories=[slugify(item) for item in _str_list(raw.get("data_categories"), f"{where}.data_categories", errors)],
                data_subjects=_str_list(raw.get("data_subjects"), f"{where}.data_subjects", errors),
                purposes=_str_list(raw.get("purposes"), f"{where}.purposes", errors),
                legal_basis=legal_basis,
                retention=_text(raw.get("retention")),
                processors=activity_processors,
                dpia=_text(raw.get("dpia")),
                logging_allow=[slugify(item) for item in _str_list(logging_raw.get("allow"), f"{where}.logging.allow", errors)],
                notes=_text(raw.get("notes")),
            )
        )

    policies_raw = data.get("policies") or {}
    if not isinstance(policies_raw, dict):
        errors.append("policies: must be a mapping")
        policies_raw = {}
    _unknown(policies_raw, _POLICY_KEYS, "policies", warnings)
    log_policy = str(policies_raw.get("personal_data_in_logs", "deny")).lower()
    if log_policy not in _LOG_POLICIES:
        errors.append(f"policies.personal_data_in_logs: must be one of {sorted(_LOG_POLICIES)}")
        log_policy = "deny"
    min_confidence = str(policies_raw.get("min_confidence", "medium")).lower()
    if min_confidence not in _CONFIDENCE:
        errors.append(f"policies.min_confidence: must be one of {sorted(_CONFIDENCE)}")
        min_confidence = "medium"
    max_age = policies_raw.get("attestation_max_age_days", 365)
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
        errors.append("policies.attestation_max_age_days: must be a positive integer")
        max_age = 365
    require_dpia = policies_raw.get("require_dpia_for")
    policies = Policies(
        personal_data_in_logs=log_policy,
        forbidden_categories=[slugify(item) for item in _str_list(policies_raw.get("forbidden_categories"), "policies.forbidden_categories", errors)],
        allowed_transfer_countries=[item.upper() for item in _str_list(policies_raw.get("allowed_transfer_countries"), "policies.allowed_transfer_countries", errors)],
        require_dpia_for=None if require_dpia is None else [slugify(item) for item in _str_list(require_dpia, "policies.require_dpia_for", errors)],
        ignore_paths=_str_list(policies_raw.get("ignore_paths"), "policies.ignore_paths", errors),
        attestation_max_age_days=max_age,
        min_confidence=min_confidence,
        ai_allowed_categories=(
            None
            if policies_raw.get("ai_allowed_categories") is None
            else [slugify(item) for item in _str_list(policies_raw.get("ai_allowed_categories"), "policies.ai_allowed_categories", errors)]
        ),
        require_field_protection_for=[
            slugify(item) for item in _str_list(policies_raw.get("require_field_protection_for"), "policies.require_field_protection_for", errors)
        ],
    )

    erasure_raw = data.get("erasure") or {}
    if not isinstance(erasure_raw, dict):
        errors.append("erasure: must be a mapping with `handlers` and/or `retained`")
        erasure_raw = {}
    _unknown(erasure_raw, _ERASURE_KEYS, "erasure", warnings)
    retained_raw = erasure_raw.get("retained") or {}
    retained: Dict[str, str] = {}
    if isinstance(retained_raw, dict):
        for store, reason in retained_raw.items():
            if len(_text(reason)) < 10:
                errors.append(f"erasure.retained.{store}: say why this store is kept (at least 10 characters, e.g. the law and period)")
            retained[str(store).strip()] = _text(reason)
    else:
        errors.append("erasure.retained: must be a mapping of store name to the reason it is kept")
    erasure = Erasure(
        handlers=_str_list(erasure_raw.get("handlers"), "erasure.handlers", errors),
        retained=retained,
        entrypoints=_str_list(erasure_raw.get("entrypoints"), "erasure.entrypoints", errors),
    )
    consent_raw = data.get("consent") or {}
    if not isinstance(consent_raw, dict):
        errors.append("consent: must be a mapping with `checks`")
        consent_raw = {}
    _unknown(consent_raw, _CONSENT_KEYS, "consent", warnings)
    consent = Consent(checks=_str_list(consent_raw.get("checks"), "consent.checks", errors))

    exceptions: List[ExceptionRule] = []
    for index, raw in enumerate(_dict_list(data.get("exceptions"), "exceptions", errors)):
        where = f"exceptions[{index}]"
        _unknown(raw, _EXCEPTION_KEYS, where, warnings)
        rule = _text(raw.get("rule")).upper()
        reason = _text(raw.get("reason"))
        if not rule:
            errors.append(f"{where}.rule: required (for example P001)")
        if len(reason) < 10:
            errors.append(f"{where}.reason: an exception needs a real justification (at least 10 characters)")
        if not any(raw.get(key) for key in ("activity", "category", "processor", "path")):
            errors.append(f"{where}: scope the exception with at least one of activity, category, processor, path")
        exceptions.append(
            ExceptionRule(
                rule=rule,
                reason=reason,
                activity=slugify(_text(raw.get("activity"))),
                category=slugify(_text(raw.get("category"))),
                processor=slugify(_text(raw.get("processor"))),
                path=_text(raw.get("path")),
                approved_by=_text(raw.get("approved_by")),
                expires=_date(raw.get("expires"), f"{where}.expires", errors),
            )
        )

    attestations: List[Attestation] = []
    for index, raw in enumerate(_dict_list(data.get("attestations"), "attestations", errors)):
        where = f"attestations[{index}]"
        _unknown(raw, _ATTESTATION_KEYS, where, warnings)
        obligation = _text(raw.get("obligation")).upper()
        statement = _text(raw.get("statement"))
        if not obligation:
            errors.append(f"{where}.obligation: required (for example OBL-21)")
        if is_placeholder(statement):
            errors.append(f"{where}.statement: say what is in place and where the proof lives")
        attestations.append(
            Attestation(
                obligation=obligation,
                statement=statement,
                evidence=_text(raw.get("evidence")),
                owner=_text(raw.get("owner")),
                reviewed=_date(raw.get("reviewed"), f"{where}.reviewed", errors),
            )
        )

    if errors:
        raise ManifestError(errors, source)
    return Manifest(
        version=MANIFEST_VERSION,
        organization=organization,
        frameworks=[slugify(item) if not _looks_like_path(item) else item for item in frameworks],
        activities=activities,
        processors=processors,
        policies=policies,
        exceptions=exceptions,
        attestations=attestations,
        erasure=erasure,
        consent=consent,
        warnings=warnings,
    )


def _looks_like_path(value: str) -> bool:
    return "/" in value or value.endswith((".yaml", ".yml", ".json"))


def _unknown(raw: Dict[str, Any], allowed: set, where: str, warnings: List[str]) -> None:
    for key in raw:
        if key not in allowed:
            warnings.append(f"{where}: unknown key '{key}' is ignored (typo?)")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _str_list(value: Any, where: str, errors: List[str]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, (dict, list)):
                errors.append(f"{where}: entries must be plain values")
                continue
            if item is not None and str(item).strip():
                out.append(str(item).strip())
        return out
    errors.append(f"{where}: must be a list")
    return []


def _dict_list(value: Any, where: str, errors: List[str]) -> List[Dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{where}: must be a list of mappings")
        return []
    out = []
    for index, item in enumerate(value):
        if isinstance(item, dict):
            out.append(item)
        else:
            errors.append(f"{where}[{index}]: must be a mapping")
    return out


def _date(value: Any, where: str, errors: List[str]) -> Optional[date]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError:
        errors.append(f"{where}: use an ISO date (YYYY-MM-DD)")
        return None
