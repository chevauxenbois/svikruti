"""Static repository scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from svikruti.models import Evidence
from svikruti.scanner.patterns import (
    COLLECTION_HINTS,
    FILE_EXTENSIONS,
    IGNORED_FILE_PATTERNS,
    FORM_FIELD_RE,
    IGNORED_DIRS,
    LOGGING_HINTS,
    LITERAL_DATA_REGEXES,
    PERSONAL_DATA_PATTERNS,
    PRIVACY_NOTICE_HINTS,
    STORAGE_HINTS,
    THIRD_PARTY_PATTERNS,
    normalize_text,
)


MAX_FILE_BYTES = 1_000_000

LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "React/JavaScript",
    ".ts": "TypeScript",
    ".tsx": "React/TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".html": "HTML",
    ".htm": "HTML",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".json": "JSON",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".toml": "TOML",
    ".env": "Environment",
    ".sql": "SQL",
    ".tf": "Terraform",
    ".tfvars": "Terraform",
    ".hcl": "HCL",
    ".conf": "Config",
    ".ini": "Config",
    ".properties": "Config",
    ".gradle": "Gradle",
    ".lock": "Lockfile",
}

SPECIAL_SOURCE_FILENAMES = {
    "Dockerfile",
    "Containerfile",
    "Jenkinsfile",
    "Procfile",
}

FRAMEWORK_HINTS = {
    "Django": ["django", "models.model", "forms.form"],
    "FastAPI": ["fastapi", "pydantic", "basemodel"],
    "Flask": ["flask", "request.form", "request.json"],
    "Express": ["express", "req.body", "router.post"],
    "Next.js": ["next/server", "nextresponse", "getserversideprops"],
    "React": ["react", "usestate", "formcontrolname"],
    "Prisma": ["prisma", "prisma/client"],
    "Mongoose": ["mongoose.schema", "mongoose.model"],
    "Spring": ["@restcontroller", "@entity", "@requestbody"],
    "Rails": ["activerecord", "applicationrecord", "params.require"],
}


class CodeScanResult:
    def __init__(self, evidence: List[Evidence], files_scanned: int):
        self.evidence = evidence
        self.files_scanned = files_scanned


def iter_source_files(repo_path: Path) -> Iterable[Path]:
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS or part.startswith(".venv") for part in path.parts):
            continue
        if path.suffix.lower() not in FILE_EXTENSIONS and path.name not in SPECIAL_SOURCE_FILENAMES:
            continue
        if any(path.name.endswith(pattern) for pattern in IGNORED_FILE_PATTERNS):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _line_context(lines: List[str], index: int) -> str:
    start = max(index - 1, 0)
    end = min(index + 2, len(lines))
    return " ".join(line.strip() for line in lines[start:end])


def _is_collection_context(context: str) -> bool:
    lowered = context.lower()
    return any(hint in lowered for hint in COLLECTION_HINTS)


def _is_storage_context(context: str) -> bool:
    lowered = context.lower()
    return any(hint in lowered for hint in STORAGE_HINTS)


def _is_logging_context(context: str) -> bool:
    lowered = context.lower()
    return any(hint in lowered for hint in LOGGING_HINTS)


def _matched_terms(normalized_line: str, terms: List[str]) -> List[str]:
    tokens = normalized_line.split("_")
    matches: List[str] = []
    for term in terms:
        term_tokens = normalize_text(term).split("_")
        if not term_tokens:
            continue
        width = len(term_tokens)
        if any(tokens[index : index + width] == term_tokens for index in range(0, len(tokens) - width + 1)):
            matches.append(term)
    return matches


def _file_context(rel_path: str, text: str) -> str:
    lowered_path = rel_path.lower()
    lowered_text = text[:8000].lower()
    if lowered_path.startswith(("docs/", "examples/sample-report", "src/svikruti/", "tests/")):
        return "reference"
    if lowered_path in {"readme.md", "knowledge_base.py"}:
        return "reference"
    if lowered_path.endswith(("patterns.py", "launch_plan.md", "github_action.md")):
        return "reference"
    if "dpdpa_sections" in lowered_text or "compliance_checklist" in lowered_text:
        return "reference"
    if lowered_path.endswith((".md", ".txt")):
        return "reference"
    if lowered_path.endswith((".json", ".yml", ".yaml", ".toml")):
        return "config"
    return "application"


def _is_fixture_file(root: Path, rel_path: str) -> bool:
    return root.name != "examples" and rel_path.lower().startswith("examples/")


def _language_for(path: Path) -> str:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "Unknown")


def _frameworks_for(rel_path: str, text: str) -> List[str]:
    blob = f"{rel_path}\n{text[:12000]}".lower()
    return sorted(name for name, hints in FRAMEWORK_HINTS.items() if any(hint in blob for hint in hints))


def _confidence(kind: str, file_context: str, matched_terms: Optional[List[str]] = None) -> str:
    if file_context == "reference":
        return "low"
    if kind in {"literal_personal_data", "form_field", "website_form_field", "logging_risk"}:
        return "high"
    if kind in {"collection_point", "storage_point", "third_party"}:
        return "medium"
    if matched_terms and len(matched_terms) > 1:
        return "medium"
    return "low"


def _metadata(
    *,
    detector_id: str,
    rel: str,
    path: Path,
    file_context: str,
    line: Optional[int] = None,
    confidence: str = "medium",
    extra: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    evidence_ref = f"{rel}:{line}:{detector_id}" if line else f"{rel}:{detector_id}"
    metadata: Dict[str, object] = {
        "detector_id": detector_id,
        "confidence": confidence,
        "evidence_ref": evidence_ref,
        "file_context": file_context,
        "language": _language_for(path),
    }
    if extra:
        metadata.update(extra)
    return metadata


def scan_repo(repo_path: str) -> CodeScanResult:
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Repository path does not exist or is not a directory: {repo_path}")

    evidence: List[Evidence] = []
    files_scanned = 0
    seen: Set[str] = set()

    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(path.relative_to(root))
        if _is_fixture_file(root, rel):
            continue
        files_scanned += 1
        lowered_text = text.lower()
        lines = text.splitlines()
        file_context = _file_context(rel, text)
        frameworks = _frameworks_for(rel, text)

        for name, needles in THIRD_PARTY_PATTERNS.items():
            if file_context == "reference":
                continue
            if any(needle.lower() in lowered_text for needle in needles):
                key = f"third_party:{rel}:{name}"
                if key not in seen:
                    seen.add(key)
                    evidence.append(
                        Evidence(
                            kind="third_party",
                            label=f"Third-party service detected: {name}",
                            severity="MEDIUM",
                            source="code",
                            file=rel,
                            detail=f"Code references {name}, which may receive personal data or tracking events.",
                            recommendation="Confirm purpose, contract/DPA status, transfer location, retention, and whether the privacy notice names this recipient category.",
                            category="Third-party processors",
                            metadata=_metadata(
                                detector_id="third_party.reference",
                                rel=rel,
                                path=path,
                                file_context=file_context,
                                confidence="medium",
                                extra={"third_party": name, "frameworks": frameworks},
                            ),
                        )
                    )

        for index, line in enumerate(lines):
            normalized_line = normalize_text(line)
            context = _line_context(lines, index)

            for literal_label, literal_re in LITERAL_DATA_REGEXES.items():
                if file_context == "reference":
                    continue
                matches = literal_re.findall(line)
                if not matches:
                    continue
                key = f"literal:{rel}:{index + 1}:{literal_label}"
                if key in seen:
                    continue
                seen.add(key)
                severity = "CRITICAL" if "Aadhaar" in literal_label or "PAN" in literal_label else "HIGH"
                evidence.append(
                    Evidence(
                        kind="literal_personal_data",
                        label=f"{literal_label} detected",
                        severity=severity,
                        source="code",
                        file=rel,
                        line=index + 1,
                        detail=f"Detected a hard-coded {literal_label.lower()} pattern in source text.",
                        recommendation="Remove real personal data from source control, replace samples with safe fixtures, and rotate any exposed credentials if applicable.",
                        category="Data minimization",
                        metadata=_metadata(
                            detector_id=f"literal.{normalize_text(literal_label)}",
                            rel=rel,
                            path=path,
                            file_context=file_context,
                            line=index + 1,
                            confidence="high",
                            extra={
                                "data_category": _literal_category(literal_label),
                                "sample_count": len(matches),
                                "frameworks": frameworks,
                            },
                        ),
                    )
                )

            for pattern in PERSONAL_DATA_PATTERNS:
                if file_context == "reference":
                    continue
                matched_terms = _matched_terms(normalized_line, pattern.terms)
                if not matched_terms:
                    continue

                context_type = "personal_data_reference"
                recommendation = "Review purpose, notice coverage, retention, access controls, and minimization for this data element."
                if _is_logging_context(line):
                    context_type = "logging_risk"
                    recommendation = "Avoid logging personal data unless strictly necessary; mask or hash values and define retention."
                elif _is_collection_context(context):
                    context_type = "collection_point"
                    recommendation = "Ensure the collection point has a clear purpose, notice, consent/legitimate-use basis, and withdrawal path where applicable."
                elif _is_storage_context(context):
                    context_type = "storage_point"
                    recommendation = "Document storage location, retention, access controls, and deletion process for this data category."
                elif _is_logging_context(context):
                    context_type = "logging_risk"
                    recommendation = "Avoid logging personal data unless strictly necessary; mask or hash values and define retention."

                key = f"{context_type}:{rel}:{index + 1}:{pattern.category}:{','.join(matched_terms)}"
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    Evidence(
                        kind=context_type,
                        label=f"{pattern.category} data signal",
                        severity=pattern.severity,
                        source="code",
                        file=rel,
                        line=index + 1,
                        detail=f"Detected terms {', '.join(sorted(set(matched_terms)))} in code context.",
                        recommendation=recommendation,
                        category=pattern.dpdpa_area,
                        metadata=_metadata(
                            detector_id=f"code.{context_type}.{normalize_text(pattern.category)}",
                            rel=rel,
                            path=path,
                            file_context=file_context,
                            line=index + 1,
                            confidence=_confidence(context_type, file_context, matched_terms),
                            extra={
                                "data_category": pattern.category,
                                "matched_terms": sorted(set(matched_terms)),
                                "context_type": context_type,
                                "frameworks": frameworks,
                            },
                        ),
                    )
                )

            if path.suffix.lower() in {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"}:
                for field in FORM_FIELD_RE.findall(line):
                    normalized_field = normalize_text(field)
                    for pattern in PERSONAL_DATA_PATTERNS:
                        matched_terms = _matched_terms(normalized_field, pattern.terms)
                        if matched_terms:
                            key = f"form_field:{rel}:{index + 1}:{field}"
                            if key in seen:
                                continue
                            seen.add(key)
                            evidence.append(
                                Evidence(
                                    kind="form_field",
                                    label=f"Form field collects {pattern.category}",
                                    severity=pattern.severity,
                                    source="code",
                                    file=rel,
                                    line=index + 1,
                                    detail=f"Form field '{field}' appears to collect {pattern.category.lower()} data.",
                                    recommendation="Map this field to a purpose, notice text, retention rule, and withdrawal/deletion workflow.",
                                    category="Notice transparency",
                                    metadata=_metadata(
                                        detector_id=f"code.form_field.{normalize_text(pattern.category)}",
                                        rel=rel,
                                        path=path,
                                        file_context=file_context,
                                        line=index + 1,
                                        confidence="high",
                                        extra={
                                            "field": field,
                                            "data_category": pattern.category,
                                            "matched_terms": sorted(set(matched_terms)),
                                            "context_type": "form_field",
                                            "frameworks": frameworks,
                                        },
                                    ),
                                )
                            )

        if file_context != "reference" and any(hint in lowered_text for hint in PRIVACY_NOTICE_HINTS):
            evidence.append(
                Evidence(
                    kind="privacy_text",
                    label="Privacy/consent copy detected",
                    severity="LOW",
                    source="code",
                    file=rel,
                    detail="The repository contains privacy or consent-related copy.",
                    recommendation="Compare this copy against detected personal-data flows and third-party services.",
                    category="Notice transparency",
                    metadata=_metadata(
                        detector_id="code.privacy_text",
                        rel=rel,
                        path=path,
                        file_context=file_context,
                        confidence="low",
                        extra={"frameworks": frameworks},
                    ),
                )
            )

    return CodeScanResult(evidence=evidence, files_scanned=files_scanned)


def _literal_category(label: str) -> str:
    if "PAN" in label or "Aadhaar" in label:
        return "Government ID"
    if "mobile" in label or "Email" in label:
        return "Contact"
    if "UPI" in label:
        return "Financial"
    return "Identity"
