"""Optional tree-sitter semantic backend.

This module is deliberately optional. If `tree-sitter-language-pack` is not
installed, the scanner continues with dependency-free semantic heuristics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from svikruti.models import Evidence
from svikruti.scanner.code import _language_for
from svikruti.scanner.patterns import PERSONAL_DATA_PATTERNS, normalize_text


LANGUAGE_BY_SUFFIX = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
}

IDENTIFIER_KINDS = {
    "identifier",
    "property_identifier",
    "field_identifier",
    "shorthand_property_identifier",
    "variable_name",
    "constant",
    "simple_identifier",
}

FIELD_CONTEXTS = {
    "field_declaration",
    "property_signature",
    "public_field_definition",
    "pair",
    "struct_field_declaration",
}


def available() -> bool:
    try:
        import tree_sitter_language_pack  # noqa: F401
    except Exception:
        return False
    return True


def scan_tree_sitter_evidence(
    path: Path,
    rel: str,
    text: str,
    file_context: str,
    seen: Set[str],
) -> Tuple[List[Evidence], Optional[str], Optional[Dict[str, object]]]:
    language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
    if not language:
        return [], None, None
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError:
        return [], None, None

    try:
        parser = get_parser(language)
        root = parser.parse(text).root_node()
    except Exception as exc:  # pragma: no cover - optional backend path
        return [], None, {"file": rel, "engine": f"tree_sitter.{language}", "error": str(exc)}

    evidence: List[Evidence] = []
    lines = text.splitlines()
    for node in _walk(root):
        if _kind(node) not in IDENTIFIER_KINDS:
            continue
        token = _node_text(text, node)
        category = _category_for_text(token)
        if not category:
            continue
        role = _role_for_node(text, lines, node)
        if role is None:
            continue
        line = _line_number(node)
        key = f"tree_sitter:{language}:{role}:{rel}:{line}:{token}:{category}"
        if key in seen:
            continue
        seen.add(key)
        kind, label_suffix, area = _role_shape(role)
        detector_id = f"semantic.treesitter.{language}.{role}.{normalize_text(category)}"
        evidence.append(
            Evidence(
                kind=kind,
                label=f"{category} {label_suffix}",
                severity=_severity_for(category, role),
                source="semantic-parser",
                file=rel,
                line=line,
                detail=f"Tree-sitter parsed `{token}` as {category} data in a {label_suffix}.",
                recommendation=_recommendation_for_role(role),
                category=area,
                metadata={
                    "detector_id": detector_id,
                    "confidence": "high",
                    "evidence_ref": f"{rel}:{line}:{detector_id}",
                    "file_context": file_context,
                    "language": _language_for(path),
                    "parser": f"tree_sitter.{language}",
                    "data_category": category,
                    "field": token,
                    "semantic_role": role,
                },
            )
        )
    return evidence, f"tree_sitter.{language}", None


def _walk(node: Any) -> Iterable[Any]:
    yield node
    try:
        count = node.named_child_count()
    except Exception:
        return
    for index in range(count):
        child = node.named_child(index)
        if child is not None:
            yield from _walk(child)


def _kind(node: Any) -> str:
    try:
        return str(node.kind())
    except Exception:
        return ""


def _node_text(text: str, node: Any) -> str:
    try:
        return text[node.start_byte() : node.end_byte()]
    except Exception:
        return ""


def _line_number(node: Any) -> int:
    try:
        return int(node.start_position().row) + 1
    except Exception:
        return 1


def _role_for_node(text: str, lines: List[str], node: Any) -> Optional[str]:
    ancestor_kinds = set(_ancestor_kinds(node, limit=6))
    line_number = _line_number(node)
    line = lines[line_number - 1] if 0 <= line_number - 1 < len(lines) else ""
    window = "\n".join(lines[max(0, line_number - 6) : min(len(lines), line_number + 6)])
    lowered_line = line.lower()
    lowered_window = window.lower()
    if ancestor_kinds & FIELD_CONTEXTS:
        return "storage_field"
    if any(token in lowered_line for token in ("console.", "logger", "log.", "log::", "rails.logger", "fmt.print", "log.print")):
        return "log_sink"
    if any(token in lowered_window for token in ("req.body", "request.body", "@requestbody", "formvalue", "params.", "$request->", "requestparam")):
        return "request_source"
    if any(token in lowered_window for token in ("repository.save", ".save(", ".create(", ".insert(", ".update(", "db.", "prisma.", "entitymanager", "order::create")):
        return "storage_sink"
    return None


def _ancestor_kinds(node: Any, limit: int) -> Iterable[str]:
    parent = None
    try:
        parent = node.parent()
    except Exception:
        parent = None
    depth = 0
    while parent is not None and depth < limit:
        yield _kind(parent)
        try:
            parent = parent.parent()
        except Exception:
            parent = None
        depth += 1


def _role_shape(role: str) -> Tuple[str, str, str]:
    if role == "log_sink":
        return "semantic_logging_sink", "logging sink", "Security safeguards"
    if role == "storage_sink":
        return "semantic_storage_sink", "database write", "Storage limitation"
    if role == "storage_field":
        return "semantic_storage_field", "model/schema field", "Storage limitation"
    return "semantic_collection_point", "request source", "Notice transparency"


def _recommendation_for_role(role: str) -> str:
    if role == "log_sink":
        return "Mask, remove, hash, or justify personal data in logs and attach log-retention evidence."
    if role in {"storage_sink", "storage_field"}:
        return "Attach storage encryption, access-control, retention, deletion, and backup/restore evidence for this data path."
    return "Confirm notice, purpose, consent/legitimate-use basis, validation, and retention for this endpoint."


def _category_for_text(text: str) -> Optional[str]:
    normalized = normalize_text(text)
    matches = []
    for pattern in PERSONAL_DATA_PATTERNS:
        if _pattern_matches(normalized, pattern.terms):
            matches.append(pattern.category)
    if not matches:
        return None
    return sorted(matches, key=lambda item: _severity_rank(_severity_for(item, "")), reverse=True)[0]


def _pattern_matches(normalized_text: str, terms: List[str]) -> bool:
    tokens = normalized_text.split("_")
    for term in terms:
        term_tokens = normalize_text(term).split("_")
        width = len(term_tokens)
        if width and any(tokens[index : index + width] == term_tokens for index in range(0, len(tokens) - width + 1)):
            return True
    return False


def _severity_for(category: str, role: str) -> str:
    if role == "log_sink" and category in {"Government ID", "Health", "Children"}:
        return "CRITICAL"
    if category in {"Government ID", "Health", "Children", "Financial"}:
        return "HIGH"
    if category in {"Location", "Device"}:
        return "MEDIUM"
    return "LOW"


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 0)
