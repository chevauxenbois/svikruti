"""Static repository scanner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from svikruti.models import Evidence
from svikruti.scanner.patterns import (
    AADHAAR_CONTEXT_TOKENS,
    AMBIGUOUS_SENSITIVE_TERMS,
    AMBIGUOUS_TERM_CORROBORATION,
    MOBILE_CONTEXT_TOKENS,
    COLLECTION_HINT_PATTERNS,
    CORROBORATION_TERMS,
    EXAMPLE_EMAIL_DOMAINS,
    FILE_EXTENSIONS,
    FIXTURE_PATH_SEGMENTS,
    IGNORED_FILE_PATTERNS,
    FORM_FIELD_RE,
    IGNORED_DIRS,
    LOGGING_HINT_PATTERNS,
    LITERAL_DATA_REGEXES,
    PAN_CONTEXT_TOKENS,
    PERSONAL_DATA_PATTERNS,
    PRIVACY_NOTICE_HINTS,
    STORAGE_HINT_PATTERNS,
    THIRD_PARTY_PATTERNS,
    WEB_PLUMBING_TERMS,
    is_valid_aadhaar,
    is_vendored_path,
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

# Dotfiles like ".env" have no Path.suffix, so extension checks miss them.
# These are prime locations for literal identifiers and secrets-adjacent
# terms, so they are included by name (".env.*" variants via prefix check).
ENV_FILE_NAMES = {".env", ".flaskenv", "docker.env"}


def _is_env_file(name: str) -> bool:
    lowered = name.lower()
    return lowered in ENV_FILE_NAMES or lowered.startswith(".env.")

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
    def __init__(
        self,
        evidence: List[Evidence],
        files_scanned: int,
        skipped_large_files: int = 0,
        skipped_vendored_files: int = 0,
    ):
        self.evidence = evidence
        self.files_scanned = files_scanned
        # Files skipped because they exceed MAX_FILE_BYTES; surfaced in scan
        # quality/limitations so coverage claims stay honest.
        self.skipped_large_files = skipped_large_files
        # Vendored/minified third-party assets skipped (node_modules, vendor/,
        # *.min.js, ...); also surfaced in scan quality.
        self.skipped_vendored_files = skipped_vendored_files


def iter_source_files(repo_path: Path, stats: Optional[Dict[str, int]] = None) -> Iterable[Path]:
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS or part.startswith(".venv") for part in path.parts):
            continue
        if (
            path.suffix.lower() not in FILE_EXTENSIONS
            and path.name not in SPECIAL_SOURCE_FILENAMES
            and not _is_env_file(path.name)
        ):
            continue
        if any(path.name.endswith(pattern) for pattern in IGNORED_FILE_PATTERNS):
            continue
        try:
            rel = str(path.relative_to(repo_path))
        except ValueError:
            rel = path.name
        if is_vendored_path(rel):
            # Vendored/minified third-party assets: not first-party data
            # flows, and a dominant source of keyword false positives
            # (e.g. DOM ".children" in *.min.js bundles).
            if stats is not None:
                stats["skipped_vendored_files"] = stats.get("skipped_vendored_files", 0) + 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                if stats is not None:
                    stats["skipped_large_files"] = stats.get("skipped_large_files", 0) + 1
                continue
        except OSError:
            continue
        yield path


def _line_context(lines: List[str], index: int) -> str:
    start = max(index - 1, 0)
    end = min(index + 2, len(lines))
    return " ".join(line.strip() for line in lines[start:end])


# The hint checks use boundary-aware compiled patterns (see
# compile_hint_patterns in patterns.py) so "input" does not match
# "inputStream", "register" does not match "registerServiceWorker", and
# "model" does not match "ModelSerializer".
def _is_collection_context(context: str) -> bool:
    lowered = context.lower()
    return any(pattern.search(lowered) for pattern in COLLECTION_HINT_PATTERNS)


def _is_storage_context(context: str) -> bool:
    lowered = context.lower()
    return any(pattern.search(lowered) for pattern in STORAGE_HINT_PATTERNS)


def _is_logging_context(context: str) -> bool:
    lowered = context.lower()
    return any(pattern.search(lowered) for pattern in LOGGING_HINT_PATTERNS)


# Underscores are word characters, so plain \b misses snake_case usage like
# "customer_aadhaar" or "pan_number". Treat letters/digits as the only
# boundary-blocking characters so snake_case identifiers count as context.
_PAN_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(PAN_CONTEXT_TOKENS) + r")(?![A-Za-z0-9])", re.IGNORECASE
)
_AADHAAR_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(AADHAAR_CONTEXT_TOKENS) + r")(?![A-Za-z0-9])", re.IGNORECASE
)
_MOBILE_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(MOBILE_CONTEXT_TOKENS) + r")(?![A-Za-z0-9])", re.IGNORECASE
)


def _mobile_confidence(lines: List[str], index: int, matches: List[str]) -> str:
    """Classify a 10-digit mobile-format candidate.

    A bare 10-digit constant starting 6-9 is often an ID, seed, or test value
    (benchmark: 48 false HIGHs on excalidraw). Returns:
      "contextual" - "+91" prefix, grouped formatting, or a phone/mobile/OTP
                     context token within +/-3 lines: flag HIGH.
      "bare"       - continuous digits, no context: MEDIUM in code files,
                     skipped in prose/reference files.
    """
    if any(("+91" in value) or (" " in value) or ("-" in value) for value in matches):
        return "contextual"
    start = max(index - 3, 0)
    end = min(index + 4, len(lines))
    if _MOBILE_CONTEXT_RE.search(" ".join(lines[start:end])):
        return "contextual"
    return "bare"


def _aadhaar_confidence(lines: List[str], index: int, matches: List[str]) -> str:
    """Classify a Verhoeff-valid 12-digit candidate.

    ~8% of random 12-digit numbers pass Verhoeff (epoch-millisecond examples
    in API docs pass regularly), so checksum alone is not proof. Returns:
      "contextual" - grouped 4-4-4 formatting OR an Aadhaar/KYC context token
                     within +/-3 lines: flag CRITICAL.
      "bare"       - continuous digits, no context: flag MEDIUM in code files,
                     skip entirely in prose/reference files.
    """
    if any((" " in value) or ("-" in value) for value in matches):
        return "contextual"
    start = max(index - 3, 0)
    end = min(index + 4, len(lines))
    if _AADHAAR_CONTEXT_RE.search(" ".join(lines[start:end])):
        return "contextual"
    return "bare"


# Project-metadata files where emails are intentional public attribution
# (package authors, changelog co-authors, maintainer contacts), not exposure.
_METADATA_FILENAME_PREFIXES = (
    "package.json", "package-lock.json", "setup.py", "setup.cfg",
    "pyproject.toml", "composer.json", "cargo.toml", "authors",
    "contributors", "changelog", "license", "notice", "codeowners",
    "security.md", "humans.txt", ".mailmap", "code_of_conduct",
)


def _email_literal_is_fixture(rel: str, line: str) -> bool:
    """Emails in tests/fixtures/docs, on reserved example domains, or in
    project-metadata files are fixture/attribution data, not personal-data
    exposure: reported at LOW severity."""
    lowered_line = line.lower()
    if any("@" + domain in lowered_line or "." + domain in lowered_line for domain in EXAMPLE_EMAIL_DOMAINS):
        return True
    lowered_rel = rel.replace("\\", "/").lower()
    # Test files by NAME (test_*.py, *.spec.ts, *.cy.js) count as fixtures
    # too, not just test directories - benchmark: 100+ fixture emails in
    # frappe/hrms doctype test files were reported at HIGH.
    if _is_test_path(lowered_rel):
        return True
    parts = lowered_rel.split("/")
    if any(part in FIXTURE_PATH_SEGMENTS for part in parts):
        return True
    return parts[-1].startswith(_METADATA_FILENAME_PREFIXES)


# "Domains" that are actually file extensions: srcset/asset references like
# "add_to_slack@2x.png" are email-shaped but not emails (benchmark-confirmed).
_NON_EMAIL_DOMAIN_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
    ".ts", ".map", ".json", ".html", ".woff", ".woff2", ".ttf", ".mp4", ".webm",
)


def _filter_email_candidates(line: str, matches: List[str]) -> List[str]:
    """Drop email-shaped matches that are not emails.

    Two benchmark-confirmed non-email shapes:
      - values embedded in URLs (Sentry DSNs: https://<hexkey>@sentry.io/1),
      - asset references whose "domain" is a file extension (icon@2x.png).
    """
    kept: List[str] = []
    for value in matches:
        if value.lower().endswith(_NON_EMAIL_DOMAIN_SUFFIXES):
            continue
        if re.search(r"https?://\S*" + re.escape(value), line):
            continue
        kept.append(value)
    return kept


def _pan_in_context(lines: List[str], index: int, line: str, matched_values: List[str]) -> bool:
    """Decide whether a PAN-shaped literal should be flagged.

    PAN-shaped strings (5 letters, 4 digits, 1 letter) collide with ticket
    IDs, hashes, and config constants. We require either:
      (a) a PAN/tax context token on the same line or within +/-2 lines, or
      (b) mixed-case context: the line contains lowercase text outside the
          matched value, i.e. it is not an ALL_CAPS_CONSTANT/config-key line.
    Without either signal the candidate is not flagged at all.
    """
    start = max(index - 2, 0)
    end = min(index + 3, len(lines))
    if _PAN_CONTEXT_RE.search(" ".join(lines[start:end])):
        return True
    remainder = line
    for value in matched_values:
        remainder = remainder.replace(value, "")
    return any(char.islower() for char in remainder)


def _has_corroboration(lines: List[str], index: int, ambiguous_terms: Optional[List[str]] = None) -> bool:
    """True when a corroborating token appears within +/-3 lines.

    Used for ambiguous tokens: "student" in an LMS class name, "patient" in a
    design-pattern comment, "children" on a DOM node, "minor" in a version
    string, or "address" meaning an IP/email/web address are not personal
    data by themselves. The corroboration set is term-specific (see
    AMBIGUOUS_TERM_CORROBORATION in patterns.py); a nearby postal/person
    token is what makes the signal credible enough for full severity.
    """
    corroboration: List[str] = []
    for term in ambiguous_terms or []:
        corroboration.extend(AMBIGUOUS_TERM_CORROBORATION.get(term, CORROBORATION_TERMS))
    if not corroboration:
        corroboration = list(CORROBORATION_TERMS)
    start = max(index - 3, 0)
    end = min(index + 4, len(lines))
    window = normalize_text(" ".join(lines[start:end]))
    return bool(_matched_terms(window, sorted(set(corroboration))))


# Performance prefilter: one combined regex over the normalized line decides
# whether the per-pattern token matching is worth running at all. On a ~1M
# line repository (saleor) this cuts the keyword loop from minutes to seconds
# because the overwhelming majority of lines contain no candidate token.
_PREFILTER_TOKENS = sorted(
    {normalize_text(term).split("_")[0] for pattern in PERSONAL_DATA_PATTERNS for term in pattern.terms if term},
    key=len,
    reverse=True,
)
_PREFILTER_RE = re.compile("|".join(re.escape(token) for token in _PREFILTER_TOKENS))


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
    """Classify the file so detectors can weight findings.

    Note: the previous hardcoded self-repo exemptions (src/svikruti/,
    knowledge_base.py, patterns.py, content sniffing for dpdpa_sections)
    were removed deliberately. They created coverage holes for any scanned
    repository that happened to use the same paths/names, and hiding our own
    files from our own scanner is dishonest — self-scan noise is acceptable.

    .md/.txt prose files are classified "reference" so keyword-category,
    third-party, semantic, and technical detectors skip them (documentation
    noise), but scan_repo still scans them for LITERAL identifier patterns
    (Aadhaar/PAN/mobile/UPI/email) — a real value in a README is a real
    exposure. See the literal loop in scan_repo.
    """
    lowered_path = rel_path.lower()
    if lowered_path.endswith((".md", ".txt")):
        return "reference"
    if lowered_path.startswith(("docs/", "examples/sample-report", "tests/")):
        return "reference"
    if _is_test_path(lowered_path):
        # Test/fixture code: keyword findings are downgraded to LOW test
        # signals, semantic sinks are skipped, and non-secret technical
        # patterns are skipped. Benchmark: 61% of contact findings on a real
        # Django app sat in test files that only exercise production flows.
        return "test"
    if lowered_path.endswith((".json", ".yml", ".yaml", ".toml")):
        return "config"
    return "application"


_TEST_PATH_SEGMENTS = {"test", "tests", "testing", "spec", "specs", "__tests__", "mocks", "fixtures", "cypress", "e2e"}


def _is_test_path(lowered_path: str) -> bool:
    parts = lowered_path.replace("\\", "/").split("/")
    if any(part in _TEST_PATH_SEGMENTS for part in parts[:-1]):
        return True
    filename = parts[-1]
    stem = filename.rsplit(".", 1)[0]
    return (
        stem.startswith("test_")
        or stem.endswith("_test")
        or ".spec." in filename
        or ".test." in filename
        or ".cy." in filename
    )


def _is_fixture_file(root: Path, rel_path: str) -> bool:
    return root.name != "examples" and rel_path.lower().startswith("examples/")


def _language_for(path: Path) -> str:
    if _is_env_file(path.name):
        return "Environment"
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
    scan_stats: Dict[str, int] = {}

    for path in iter_source_files(root, scan_stats):
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
        # Prose files are "reference" context but still get LITERAL identifier
        # scanning below (keyword/third-party detectors stay excluded).
        is_prose = rel.lower().endswith((".md", ".txt"))

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
            # Skip the per-pattern keyword work (and context assembly) when
            # no candidate token is present at all - true for the vast
            # majority of lines in a real repository.
            line_has_candidates = bool(_PREFILTER_RE.search(normalized_line))
            context = _line_context(lines, index) if line_has_candidates else ""

            for literal_label, literal_re in LITERAL_DATA_REGEXES.items():
                # Literals run on prose (.md/.txt) too, even though prose is
                # "reference" context: a real Aadhaar/PAN value in a README is
                # still a real exposure.
                if file_context == "reference" and not is_prose:
                    continue
                matches = literal_re.findall(line)
                aadhaar_mode = ""
                mobile_mode = ""
                if "Email" in literal_label and matches:
                    matches = _filter_email_candidates(line, matches)
                if "Aadhaar" in literal_label:
                    # Only Verhoeff-validated candidates (first digit 2-9)
                    # are kept; random 12-digit runs are not flagged at all.
                    matches = [value for value in matches if is_valid_aadhaar(value)]
                    if matches:
                        aadhaar_mode = _aadhaar_confidence(lines, index, matches)
                        if aadhaar_mode == "bare" and (is_prose or file_context == "reference"):
                            # Bare 12-digit numbers in docs are usually epoch
                            # timestamps/IDs that happen to pass Verhoeff.
                            continue
                if "mobile" in literal_label.lower() and matches:
                    mobile_mode = _mobile_confidence(lines, index, matches)
                    if mobile_mode == "bare" and (is_prose or file_context == "reference"):
                        # Bare 10-digit numbers in docs are usually IDs.
                        continue
                if not matches:
                    continue
                if "PAN" in literal_label and not _pan_in_context(lines, index, line, matches):
                    # PAN-shaped strings without any PAN/tax context nearby
                    # and sitting on ALL_CAPS constant lines are not flagged.
                    continue
                key = f"literal:{rel}:{index + 1}:{literal_label}"
                if key in seen:
                    continue
                seen.add(key)
                severity = "CRITICAL" if "Aadhaar" in literal_label or "PAN" in literal_label else "HIGH"
                detail = f"Detected a hard-coded {literal_label.lower()} pattern in source text."
                label_text = f"{literal_label} detected"
                if "Aadhaar" in literal_label:
                    if aadhaar_mode == "contextual":
                        detail = "Detected a Verhoeff-validated Aadhaar-format value with grouping or Aadhaar/KYC context nearby."
                    else:
                        severity = "MEDIUM"
                        label_text = "Possible Aadhaar-format literal"
                        detail = "Verhoeff-valid 12-digit value with no Aadhaar/KYC context nearby; may be an unrelated numeric ID. Verify manually."
                elif "Email" in literal_label and _email_literal_is_fixture(rel, line):
                    severity = "LOW"
                    label_text = "Email literal (test/example context)"
                    detail = "Email-format value on a reserved example domain or in a test/fixture/docs path; likely fixture data rather than real exposure."
                elif "mobile" in literal_label.lower() and mobile_mode == "bare":
                    severity = "MEDIUM"
                    label_text = "Possible Indian mobile literal"
                    detail = "10-digit value in mobile-number format with no phone/contact context nearby; may be an unrelated numeric constant. Verify manually."
                evidence.append(
                    Evidence(
                        kind="literal_personal_data",
                        label=label_text,
                        severity=severity,
                        source="code",
                        file=rel,
                        line=index + 1,
                        detail=detail,
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
                # Keyword-category findings are skipped for reference/prose
                # files to avoid documentation noise; literals above apply.
                if file_context == "reference":
                    continue
                if not line_has_candidates:
                    break
                matched_terms = _matched_terms(normalized_line, pattern.terms)
                # Bare "children" in JS/React/DOM file types is component
                # plumbing (props.children, node.children), and in JSON/YAML
                # it is a tree-structure key - never personal data.
                # Benchmark-confirmed on excalidraw/healthchecks: corroboration
                # alone cannot save it because UI code legitimately contains
                # "mobile"/"email" tokens (viewport checks, social links).
                if "children" in matched_terms and rel.lower().endswith(
                    (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".json", ".yml", ".yaml")
                ):
                    matched_terms = [term for term in matched_terms if term != "children"]
                if not matched_terms:
                    continue

                # Classification precedence (most specific evidence wins):
                #   line logging > line storage > line collection
                #   > context logging > context storage > context collection.
                # A hint on the flagged line itself always beats a hint that
                # only appears in adjacent lines, so a print() next door can
                # no longer hijack a storage/collection classification. (The
                # old code checked context-collection before context-logging
                # and re-checked logging in a dead elif branch.)
                context_type = "personal_data_reference"
                if _is_logging_context(line):
                    context_type = "logging_risk"
                elif _is_storage_context(line):
                    context_type = "storage_point"
                elif _is_collection_context(line):
                    context_type = "collection_point"
                elif _is_logging_context(context):
                    context_type = "logging_risk"
                elif _is_storage_context(context):
                    context_type = "storage_point"
                elif _is_collection_context(context):
                    context_type = "collection_point"

                recommendation = "Review purpose, notice coverage, retention, access controls, and minimization for this data element."
                if context_type == "logging_risk":
                    recommendation = "Avoid logging personal data unless strictly necessary; mask or hash values and define retention."
                elif context_type == "collection_point":
                    recommendation = "Ensure the collection point has a clear purpose, notice, consent/legitimate-use basis, and withdrawal path where applicable."
                elif context_type == "storage_point":
                    recommendation = "Document storage location, retention, access controls, and deletion process for this data category."

                severity = pattern.severity
                label = f"{pattern.category} data signal"
                detail = f"Detected terms {', '.join(sorted(set(matched_terms)))} in code context."
                # Ambiguous tokens (student/school/patient, children/minor,
                # address/location/city) only earn full category severity when
                # a term-specific corroborating token appears within +/-3
                # lines; otherwise they are a MEDIUM "possible" signal. This
                # covers DOM ".children", "minor version", IP/email addresses,
                # window.location, and similar benchmark-confirmed noise.
                if pattern.category in {"Children", "Health", "Location", "Contact"} and all(
                    term in AMBIGUOUS_SENSITIVE_TERMS for term in matched_terms
                ):
                    if not _has_corroboration(lines, index, matched_terms):
                        severity = "MEDIUM"
                        label = f"Possible {pattern.category} data signal"
                        detail += " No corroborating personal-data token was found nearby, so this is a possible signal only."
                # Test/fixture code exercises production flows with fake
                # data; keyword findings there are LOW test signals, not
                # production evidence.
                if file_context == "test" and severity in {"CRITICAL", "HIGH", "MEDIUM"}:
                    severity = "LOW"
                    label = f"{label} (test code)"
                # Web-plumbing tokens (session_id/cookie/user_agent) stay LOW
                # unless they co-occur with a collection/storage/logging hint.
                if (
                    pattern.category == "Device"
                    and all(term in WEB_PLUMBING_TERMS for term in matched_terms)
                    and context_type == "personal_data_reference"
                ):
                    severity = "LOW"
                # A bare *reference* to a HIGH-category term (email/phone/
                # payment/address in ordinary code, no collection/storage/
                # logging context) is inventory evidence, not risk evidence:
                # cap it at MEDIUM. Full severity is reserved for findings
                # with a data-flow context. CRITICAL categories (Government
                # ID/Children/Health) keep their severity - a bare "aadhaar"
                # reference is significant on its own. Benchmark-driven: an
                # email-alerting app produced 1,300+ context-less HIGH
                # "contact" references that drowned real findings.
                if severity == "HIGH" and context_type == "personal_data_reference":
                    severity = "MEDIUM"

                key = f"{context_type}:{rel}:{index + 1}:{pattern.category}:{','.join(matched_terms)}"
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    Evidence(
                        kind=context_type,
                        label=label,
                        severity=severity,
                        source="code",
                        file=rel,
                        line=index + 1,
                        detail=detail,
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
                        # Ambiguous-only matches (e.g. "mobile" in
                        # class="mobile-toolbar") need corroboration here
                        # too - CSS/meta attributes are not form fields.
                        if matched_terms and all(
                            term in AMBIGUOUS_SENSITIVE_TERMS for term in matched_terms
                        ) and not _has_corroboration(lines, index, matched_terms):
                            continue
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

    return CodeScanResult(
        evidence=evidence,
        files_scanned=files_scanned,
        skipped_large_files=scan_stats.get("skipped_large_files", 0),
        skipped_vendored_files=scan_stats.get("skipped_vendored_files", 0),
    )


def _literal_category(label: str) -> str:
    if "PAN" in label or "Aadhaar" in label:
        return "Government ID"
    if "mobile" in label or "Email" in label:
        return "Contact"
    if "UPI" in label:
        return "Financial"
    return "Identity"
