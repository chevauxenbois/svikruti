"""Semantic/parser-assisted privacy evidence extraction.

This module complements the regex scanner. It intentionally starts with
standard-library Python AST and conservative JavaScript/TypeScript endpoint
heuristics so Svikruti stays installable with zero mandatory parser
dependencies. The output records parser coverage so users can see where the
scan used structured parsing versus fallback heuristics.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from svikruti.models import Evidence
from svikruti.scanner.code import _file_context, _language_for, iter_source_files
from svikruti.scanner.patterns import (
    AMBIGUOUS_SENSITIVE_TERMS,
    CATEGORY_SEVERITY,
    PERSONAL_DATA_PATTERNS,
    normalize_text,
)
from svikruti.scanner.tree_sitter_backend import scan_tree_sitter_evidence


JS_ROUTE_RE = re.compile(r"\b(?:router|app)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
JS_BODY_RE = re.compile(r"\b(?:req|request)\.body\.([A-Za-z0-9_$]+)|\bconst\s*\{([^}]+)\}\s*=\s*(?:req|request)\.body", re.IGNORECASE)
JS_BODY_BLOCK_RE = re.compile(r"\bconst\s*\{(?P<fields>[^}]+)\}\s*=\s*(?:req|request)\.body", re.IGNORECASE | re.DOTALL)
JS_LOG_RE = re.compile(r"\bconsole\.(log|warn|error|info)\s*\((.*)\)", re.IGNORECASE)
JS_DB_RE = re.compile(r"\b(db|prisma|mongoose|sequelize|knex)\.[A-Za-z0-9_.$]*(insert|create|save|update|upsert)\b", re.IGNORECASE)

PY_REQUEST_HINTS = {"request.json", "request.get_json", "request.data", "request.form", "request.POST", "request.body"}
PY_LOG_HINTS = {"logger.", "logging.", "print("}
PY_DB_WRITE_HINTS = {".objects.create", ".objects.update", ".save(", ".create(", ".insert(", ".upsert("}

JAVA_FIELD_RE = re.compile(r"\b(?:private|protected|public)\s+[A-Za-z0-9_<>, ?]+\s+([A-Za-z0-9_]+)\s*[;=]", re.IGNORECASE)
JAVA_ROUTE_RE = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\s*(?:\(\s*[\"']([^\"']+)[\"'])?", re.IGNORECASE)
JAVA_BODY_RE = re.compile(r"@RequestBody|@RequestParam|@PathVariable", re.IGNORECASE)
JAVA_LOG_RE = re.compile(r"\b(log|logger)\.(info|warn|error|debug)\s*\((.*)\)", re.IGNORECASE)
JAVA_DB_RE = re.compile(r"\b(repository|repo|dao|entityManager)\.[A-Za-z0-9_]*(save|persist|merge|update)\s*\(", re.IGNORECASE)

GO_STRUCT_FIELD_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s+[^`\n]+`[^`]*(?:json|form|db):[\"']([^\"']+)[\"'][^`]*`", re.MULTILINE)
GO_ROUTE_RE = re.compile(r"\b(router|r|mux)\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\s*\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
GO_BODY_RE = re.compile(r"\b(json\.NewDecoder|ShouldBind|BindJSON|ParseForm|FormValue|PostFormValue|r\.FormValue)\b", re.IGNORECASE)
GO_LOG_RE = re.compile(r"\b(log\.Printf|log\.Println|fmt\.Println|fmt\.Printf)\s*\((.*)\)", re.IGNORECASE)
GO_DB_RE = re.compile(r"\b(db|tx)\.(Exec|Query|Create|Save|Updates?)\b", re.IGNORECASE)

RUBY_PARAMS_RE = re.compile(r"\bparams\.(?:require|permit)\s*\(([^)]+)\)|\bparams\[['\"]([^'\"]+)['\"]\]", re.IGNORECASE)
RUBY_ROUTE_RE = re.compile(r"^\s*(get|post|put|patch|delete)\s+[\"']([^\"']+)[\"']", re.IGNORECASE | re.MULTILINE)
RUBY_LOG_RE = re.compile(r"\bRails\.logger\.(info|warn|error|debug)\s+(.*)", re.IGNORECASE)
RUBY_DB_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\.(create|update|save|insert_all|upsert)\b", re.IGNORECASE)

PHP_REQUEST_RE = re.compile(r"\$request->(?:input|get|post)\(['\"]([^'\"]+)['\"]\]?", re.IGNORECASE)
PHP_ROUTE_RE = re.compile(r"Route::(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PHP_LOG_RE = re.compile(r"\bLog::(info|warning|error|debug)\s*\((.*)\)", re.IGNORECASE)
PHP_DB_RE = re.compile(r"\b(DB::table|->create|->update|->save|::create)\b", re.IGNORECASE)

SQL_COLUMN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(?:varchar|text|char|uuid|int|bigint|date|timestamp|json|jsonb|decimal|numeric)", re.IGNORECASE | re.MULTILINE)
PRISMA_FIELD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(String|Int|DateTime|Float|Decimal|Json|Boolean)", re.MULTILINE)
GRAPHQL_FIELD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(String|ID|Int|Float|DateTime|Boolean)", re.MULTILINE)

K8S_KIND_RE = re.compile(r"^\s*kind:\s*(Secret|ConfigMap|Deployment|StatefulSet|DaemonSet|Pod|Ingress)\s*$", re.IGNORECASE | re.MULTILINE)
K8S_ENV_RE = re.compile(r"^\s*-\s*name:\s*([A-Za-z0-9_]+)\s*$", re.IGNORECASE | re.MULTILINE)
K8S_SECRET_REF_RE = re.compile(r"\b(secretKeyRef|configMapKeyRef|imagePullSecrets|tls:)\b", re.IGNORECASE)


@dataclass
class SemanticScanResult:
    evidence: List[Evidence]
    parsed_files: int
    parser_errors: List[Dict[str, object]] = field(default_factory=list)
    parser_engines: Dict[str, int] = field(default_factory=dict)

    def quality_profile(self, total_files: int) -> Dict[str, object]:
        coverage = int((self.parsed_files / max(1, total_files)) * 100)
        return {
            "schema_version": "svikruti-scan-quality-v1",
            "parser_coverage_percent": coverage,
            "parsed_files": self.parsed_files,
            "total_files": total_files,
            "parser_engines": self.parser_engines,
            "parser_errors": self.parser_errors[:25],
            "limitations": [
                "Python parser evidence uses stdlib AST and is strongest for model fields, request sources, log sinks, and database writes.",
                "JavaScript/TypeScript, Java, Go, Ruby, PHP, OpenAPI/Postman, Kubernetes, Prisma, GraphQL, and SQL semantic evidence uses tree-sitter when the optional parser pack is installed, plus conservative structured heuristics as fallback.",
                "Runtime-only flows still require browser/API/cloud/telemetry evidence.",
            ],
        }


def scan_semantic_evidence(repo_path: str) -> SemanticScanResult:
    root = Path(repo_path).resolve()
    evidence: List[Evidence] = []
    parser_errors: List[Dict[str, object]] = []
    parser_engines: Dict[str, int] = {}
    parsed_files = 0
    seen: Set[str] = set()

    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        file_context = _file_context(rel, text)
        # Prose (.md/.txt) is "reference" context: it is scanned only for
        # literal identifiers by code.py; semantic parsing does not apply.
        # Test/fixture code is skipped too: its request/db/log flows exercise
        # production paths with fake data (benchmark: the majority of
        # semantic contact-sink findings on a real Django app were tests).
        if file_context in ("reference", "test"):
            continue

        suffix = path.suffix.lower()
        tree_evidence, tree_engine, tree_error = scan_tree_sitter_evidence(path, rel, text, file_context, seen)
        if tree_engine:
            parsed_files += 1
            parser_engines[tree_engine] = parser_engines.get(tree_engine, 0) + 1
            evidence.extend(tree_evidence)
        if tree_error:
            parser_errors.append(tree_error)

        if suffix == ".py":
            try:
                tree = ast.parse(text, filename=rel)
            except SyntaxError as exc:
                parser_errors.append({"file": rel, "engine": "python.ast", "error": str(exc)})
                continue
            if not tree_engine:
                parsed_files += 1
            parser_engines["python.ast"] = parser_engines.get("python.ast", 0) + 1
            evidence.extend(_scan_python_ast(tree, rel, path, text, file_context, seen))
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            if not tree_engine:
                parsed_files += 1
            parser_engines["js_ts.endpoint_heuristic"] = parser_engines.get("js_ts.endpoint_heuristic", 0) + 1
            evidence.extend(_scan_js_ts_semantics(text, rel, path, file_context, seen))
        elif suffix == ".java":
            if not tree_engine:
                parsed_files += 1
            parser_engines["java.spring_heuristic"] = parser_engines.get("java.spring_heuristic", 0) + 1
            evidence.extend(_scan_c_style_semantics(text, rel, path, file_context, seen, "java", JAVA_ROUTE_RE, JAVA_BODY_RE, JAVA_LOG_RE, JAVA_DB_RE, JAVA_FIELD_RE))
        elif suffix == ".go":
            if not tree_engine:
                parsed_files += 1
            parser_engines["go.handler_heuristic"] = parser_engines.get("go.handler_heuristic", 0) + 1
            evidence.extend(_scan_c_style_semantics(text, rel, path, file_context, seen, "go", GO_ROUTE_RE, GO_BODY_RE, GO_LOG_RE, GO_DB_RE, GO_STRUCT_FIELD_RE))
        elif suffix == ".rb":
            if not tree_engine:
                parsed_files += 1
            parser_engines["ruby.rails_heuristic"] = parser_engines.get("ruby.rails_heuristic", 0) + 1
            evidence.extend(_scan_dynamic_web_semantics(text, rel, path, file_context, seen, "ruby", RUBY_ROUTE_RE, RUBY_PARAMS_RE, RUBY_LOG_RE, RUBY_DB_RE))
        elif suffix == ".php":
            if not tree_engine:
                parsed_files += 1
            parser_engines["php.laravel_heuristic"] = parser_engines.get("php.laravel_heuristic", 0) + 1
            evidence.extend(_scan_dynamic_web_semantics(text, rel, path, file_context, seen, "php", PHP_ROUTE_RE, PHP_REQUEST_RE, PHP_LOG_RE, PHP_DB_RE))
        elif suffix in {".sql", ".prisma", ".graphql", ".gql"}:
            if not tree_engine:
                parsed_files += 1
            parser_engines["schema.field_heuristic"] = parser_engines.get("schema.field_heuristic", 0) + 1
            evidence.extend(_scan_schema_semantics(text, rel, path, file_context, seen))
        elif suffix in {".json", ".yml", ".yaml"}:
            structured = _scan_structured_artifact(text, rel, path, file_context, seen)
            if structured:
                if not tree_engine:
                    parsed_files += 1
                parser_engines[structured["engine"]] = parser_engines.get(structured["engine"], 0) + 1
                evidence.extend(structured["evidence"])

    return SemanticScanResult(
        evidence=evidence,
        parsed_files=parsed_files,
        parser_errors=parser_errors,
        parser_engines=parser_engines,
    )


def _scan_python_ast(
    tree: ast.AST,
    rel: str,
    path: Path,
    text: str,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    source_lines = text.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            evidence.extend(_python_model_fields(node, rel, path, file_context, seen))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body_text = _node_text(node, source_lines)
            endpoint_hint = _python_endpoint_hint(node)
            evidence.extend(_python_request_sources(node, body_text, rel, path, file_context, seen, endpoint_hint))
            evidence.extend(_python_log_sinks(node, body_text, rel, path, file_context, seen, endpoint_hint))
            evidence.extend(_python_db_writes(node, body_text, rel, path, file_context, seen, endpoint_hint))
    return evidence


def _python_model_fields(
    node: ast.ClassDef,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    base_names = ".".join(_name(base) for base in node.bases)
    is_model = "Model" in base_names or "BaseModel" in base_names or "Schema" in node.name
    if not is_model:
        return evidence
    for stmt in node.body:
        field_name: Optional[str] = None
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    field_name = target.id
                    break
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            field_name = stmt.target.id
        if not field_name:
            continue
        category = _category_for_text(field_name)
        if not category:
            continue
        key = f"semantic_python_model:{rel}:{node.name}:{field_name}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_storage_field",
                label=f"{category} model field",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=getattr(stmt, "lineno", getattr(node, "lineno", None)),
                category="Storage limitation",
                detail=f"Parser identified `{field_name}` as a personal-data field on model/schema `{node.name}`.",
                recommendation="Map this model field to purpose, retention, access control, deletion, and production data-store evidence.",
                file_context=file_context,
                detector_id=f"semantic.python.model_field.{normalize_text(category)}",
                extra={"data_category": category, "field": field_name, "class": node.name, "semantic_role": "storage_field"},
            )
        )
    return evidence


def _python_request_sources(
    node: ast.AST,
    body_text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
    endpoint_hint: str,
) -> List[Evidence]:
    evidence: List[Evidence] = []
    if not any(hint in body_text for hint in PY_REQUEST_HINTS):
        return evidence
    for category in _categories_for_text(body_text):
        key = f"semantic_python_request:{rel}:{getattr(node, 'lineno', 0)}:{category}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_collection_point",
                label=f"{category} request collection",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=getattr(node, "lineno", None),
                category="Notice transparency",
                detail=f"Parser identified request-body handling for {category} data in `{getattr(node, 'name', 'function')}`.",
                recommendation="Confirm notice, purpose, consent/legitimate-use basis, validation, and retention for this endpoint.",
                file_context=file_context,
                detector_id=f"semantic.python.request_source.{normalize_text(category)}",
                extra={"data_category": category, "endpoint_hint": endpoint_hint, "semantic_role": "request_source"},
            )
        )
    return evidence


def _python_log_sinks(
    node: ast.AST,
    body_text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
    endpoint_hint: str,
) -> List[Evidence]:
    if not any(hint in body_text for hint in PY_LOG_HINTS):
        return []
    evidence: List[Evidence] = []
    for category in _categories_for_text(body_text):
        key = f"semantic_python_log:{rel}:{getattr(node, 'lineno', 0)}:{category}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_logging_sink",
                label=f"{category} logging sink",
                severity="CRITICAL" if category in {"Government ID", "Health", "Children"} else "HIGH",
                rel=rel,
                path=path,
                line=getattr(node, "lineno", None),
                category="Security safeguards",
                detail=f"Parser identified logging/printing near {category} data in `{getattr(node, 'name', 'function')}`.",
                recommendation="Mask, remove, hash, or justify personal data in logs and attach log-retention evidence.",
                file_context=file_context,
                detector_id=f"semantic.python.log_sink.{normalize_text(category)}",
                extra={"data_category": category, "endpoint_hint": endpoint_hint, "semantic_role": "log_sink"},
            )
        )
    return evidence


def _python_db_writes(
    node: ast.AST,
    body_text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
    endpoint_hint: str,
) -> List[Evidence]:
    if not any(hint in body_text for hint in PY_DB_WRITE_HINTS):
        return []
    evidence: List[Evidence] = []
    for category in _categories_for_text(body_text):
        key = f"semantic_python_db:{rel}:{getattr(node, 'lineno', 0)}:{category}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_storage_sink",
                label=f"{category} database write",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=getattr(node, "lineno", None),
                category="Storage limitation",
                detail=f"Parser identified a database write path for {category} data in `{getattr(node, 'name', 'function')}`.",
                recommendation="Attach storage encryption, access-control, retention, deletion, and backup/restore evidence for this data path.",
                file_context=file_context,
                detector_id=f"semantic.python.db_sink.{normalize_text(category)}",
                extra={"data_category": category, "endpoint_hint": endpoint_hint, "semantic_role": "storage_sink"},
            )
        )
    return evidence


def _scan_js_ts_semantics(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    current_route = ""
    lines = text.splitlines()
    for match in JS_BODY_BLOCK_RE.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        route_hint = _nearest_js_route(text[: match.start()])
        for field in _split_js_fields(match.group("fields")):
            category = _category_for_text(field)
            if not category:
                continue
            key = f"semantic_js_body_block:{rel}:{line_number}:{field}"
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                _evidence(
                    kind="semantic_collection_point",
                    label=f"{category} request body field",
                    severity=_severity_for_category(category),
                    rel=rel,
                    path=path,
                    line=line_number,
                    category="Notice transparency",
                    detail=f"Parser heuristic identified request-body field `{field}` on route `{route_hint or 'unknown route'}`.",
                    recommendation="Confirm notice, purpose, consent/legitimate-use basis, validation, and retention for this endpoint.",
                    file_context=file_context,
                    detector_id=f"semantic.js.request_body.{normalize_text(category)}",
                    extra={"data_category": category, "field": field, "endpoint_hint": route_hint, "semantic_role": "request_source"},
                )
            )
    for line_number, line in enumerate(lines, start=1):
        route_match = JS_ROUTE_RE.search(line)
        if route_match:
            current_route = f"{route_match.group(1).upper()} {route_match.group(2)}"
        body_fields = _js_body_fields(line)
        for field in body_fields:
            category = _category_for_text(field)
            if not category:
                continue
            key = f"semantic_js_body:{rel}:{line_number}:{field}"
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                _evidence(
                    kind="semantic_collection_point",
                    label=f"{category} request body field",
                    severity=_severity_for_category(category),
                    rel=rel,
                    path=path,
                    line=line_number,
                    category="Notice transparency",
                    detail=f"Parser heuristic identified request-body field `{field}` on route `{current_route or 'unknown route'}`.",
                    recommendation="Confirm notice, purpose, consent/legitimate-use basis, validation, and retention for this endpoint.",
                    file_context=file_context,
                    detector_id=f"semantic.js.request_body.{normalize_text(category)}",
                    extra={"data_category": category, "field": field, "endpoint_hint": current_route, "semantic_role": "request_source"},
                )
            )
        log_match = JS_LOG_RE.search(line)
        if log_match:
            for category in _categories_for_text(log_match.group(2)):
                key = f"semantic_js_log:{rel}:{line_number}:{category}"
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    _evidence(
                        kind="semantic_logging_sink",
                        label=f"{category} logging sink",
                        severity="CRITICAL" if category in {"Government ID", "Health", "Children"} else "HIGH",
                        rel=rel,
                        path=path,
                        line=line_number,
                        category="Security safeguards",
                        detail=f"Parser heuristic identified {category} data being logged.",
                        recommendation="Mask, remove, hash, or justify personal data in logs and attach log-retention evidence.",
                        file_context=file_context,
                        detector_id=f"semantic.js.log_sink.{normalize_text(category)}",
                        extra={"data_category": category, "endpoint_hint": current_route, "semantic_role": "log_sink"},
                    )
                )
        if JS_DB_RE.search(line):
            context = "\n".join(lines[max(0, line_number - 12) : min(len(lines), line_number + 12)])
            for category in _categories_for_text(context):
                key = f"semantic_js_db:{rel}:{line_number}:{category}"
                if key in seen:
                    continue
                seen.add(key)
                evidence.append(
                    _evidence(
                        kind="semantic_storage_sink",
                        label=f"{category} database write",
                        severity=_severity_for_category(category),
                        rel=rel,
                        path=path,
                        line=line_number,
                        category="Storage limitation",
                        detail=f"Parser heuristic identified a database write path for {category} data.",
                        recommendation="Attach storage encryption, access-control, retention, deletion, and backup/restore evidence for this data path.",
                        file_context=file_context,
                        detector_id=f"semantic.js.db_sink.{normalize_text(category)}",
                        extra={"data_category": category, "endpoint_hint": current_route, "semantic_role": "storage_sink"},
                    )
                )
    return evidence


def _js_body_fields(line: str) -> List[str]:
    fields: List[str] = []
    for match in JS_BODY_RE.finditer(line):
        direct = match.group(1)
        destructured = match.group(2)
        if direct:
            fields.append(direct)
        if destructured:
            fields.extend(_split_js_fields(destructured))
    return fields


def _split_js_fields(raw_fields: str) -> List[str]:
    fields: List[str] = []
    for raw in raw_fields.split(","):
        field = raw.strip().split(":", 1)[0].strip()
        field = field.split("=", 1)[0].strip()
        if field:
            fields.append(field)
    return fields


def _nearest_js_route(prefix: str) -> str:
    route = ""
    for match in JS_ROUTE_RE.finditer(prefix):
        route = f"{match.group(1).upper()} {match.group(2)}"
    return route


def _scan_c_style_semantics(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
    language_key: str,
    route_re: re.Pattern[str],
    body_re: re.Pattern[str],
    log_re: re.Pattern[str],
    db_re: re.Pattern[str],
    field_re: re.Pattern[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    lines = text.splitlines()
    current_route = ""
    for match in route_re.finditer(text):
        route = " ".join(part for part in match.groups() if part)
        if route:
            current_route = route
    for match in field_re.finditer(text):
        field = _field_from_match(match)
        category = _category_for_text(field)
        if not category:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        key = f"semantic_{language_key}_field:{rel}:{line_number}:{field}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_storage_field",
                label=f"{category} model/schema field",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=line_number,
                category="Storage limitation",
                detail=f"Parser heuristic identified `{field}` as a personal-data field.",
                recommendation="Map this field to purpose, retention, access control, deletion, and production data-store evidence.",
                file_context=file_context,
                detector_id=f"semantic.{language_key}.field.{normalize_text(category)}",
                extra={"data_category": category, "field": field, "semantic_role": "storage_field"},
            )
        )
    for line_number, line in enumerate(lines, start=1):
        route_match = route_re.search(line)
        if route_match:
            current_route = " ".join(part for part in route_match.groups() if part)
        context = "\n".join(lines[max(0, line_number - 8) : min(len(lines), line_number + 8)])
        if body_re.search(line):
            evidence.extend(
                _semantic_context_evidence(
                    context,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "request_source",
                    "semantic_collection_point",
                    "request source",
                    "Notice transparency",
                    current_route,
                )
            )
        if log_re.search(line):
            evidence.extend(
                _semantic_context_evidence(
                    line,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "log_sink",
                    "semantic_logging_sink",
                    "logging sink",
                    "Security safeguards",
                    current_route,
                )
            )
        if db_re.search(line):
            evidence.extend(
                _semantic_context_evidence(
                    context,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "storage_sink",
                    "semantic_storage_sink",
                    "database write",
                    "Storage limitation",
                    current_route,
                )
            )
    return evidence


def _scan_dynamic_web_semantics(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
    language_key: str,
    route_re: re.Pattern[str],
    request_re: re.Pattern[str],
    log_re: re.Pattern[str],
    db_re: re.Pattern[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    lines = text.splitlines()
    current_route = ""
    for line_number, line in enumerate(lines, start=1):
        route_match = route_re.search(line)
        if route_match:
            current_route = " ".join(part for part in route_match.groups() if part)
        context = "\n".join(lines[max(0, line_number - 8) : min(len(lines), line_number + 8)])
        for request_match in request_re.finditer(line):
            field_blob = " ".join(part for part in request_match.groups() if part)
            evidence.extend(
                _semantic_context_evidence(
                    field_blob or context,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "request_source",
                    "semantic_collection_point",
                    "request source",
                    "Notice transparency",
                    current_route,
                )
            )
        if log_re.search(line):
            evidence.extend(
                _semantic_context_evidence(
                    line,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "log_sink",
                    "semantic_logging_sink",
                    "logging sink",
                    "Security safeguards",
                    current_route,
                )
            )
        if db_re.search(line):
            evidence.extend(
                _semantic_context_evidence(
                    context,
                    rel,
                    path,
                    line_number,
                    file_context,
                    seen,
                    language_key,
                    "storage_sink",
                    "semantic_storage_sink",
                    "database write",
                    "Storage limitation",
                    current_route,
                )
            )
    return evidence


def _scan_schema_semantics(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    regexes = [
        ("sql", SQL_COLUMN_RE),
        ("prisma", PRISMA_FIELD_RE),
        ("graphql", GRAPHQL_FIELD_RE),
    ]
    for schema_key, regex in regexes:
        for match in regex.finditer(text):
            field = match.group(1)
            category = _category_for_text(field)
            if not category:
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            key = f"semantic_schema:{schema_key}:{rel}:{line_number}:{field}"
            if key in seen:
                continue
            seen.add(key)
            evidence.append(
                _evidence(
                    kind="semantic_storage_field",
                    label=f"{category} schema field",
                    severity=_severity_for_category(category),
                    rel=rel,
                    path=path,
                    line=line_number,
                    category="Storage limitation",
                    detail=f"Schema parser identified `{field}` as a personal-data field.",
                    recommendation="Map this schema field to purpose, retention, access control, deletion, and production data-store evidence.",
                    file_context=file_context,
                    detector_id=f"semantic.{schema_key}.schema_field.{normalize_text(category)}",
                    extra={"data_category": category, "field": field, "semantic_role": "storage_field"},
                )
            )
    return evidence


def _scan_structured_artifact(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> Optional[Dict[str, object]]:
    lowered = text[:20000].lower()
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
            return {"engine": "openapi.schema_heuristic", "evidence": _scan_openapi_json(data, rel, path, file_context, seen)}
        if isinstance(data, dict) and "item" in data and "info" in data:
            return {"engine": "postman.collection_heuristic", "evidence": _scan_postman_json(data, rel, path, file_context, seen)}
    if "openapi:" in lowered or "swagger:" in lowered:
        return {"engine": "openapi.yaml_heuristic", "evidence": _scan_openapi_yaml(text, rel, path, file_context, seen)}
    if K8S_KIND_RE.search(text):
        return {"engine": "kubernetes.manifest_heuristic", "evidence": _scan_kubernetes_manifest(text, rel, path, file_context, seen)}
    return None


def _scan_openapi_json(
    data: Dict[str, object],
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    paths = data.get("paths") if isinstance(data.get("paths"), dict) else {}
    for api_path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, spec in methods.items():
            blob = json.dumps(spec, sort_keys=True)
            evidence.extend(
                _semantic_context_evidence(
                    blob,
                    rel,
                    path,
                    None,
                    file_context,
                    seen,
                    "openapi",
                    "request_source",
                    "semantic_collection_point",
                    "API request schema",
                    "Notice transparency",
                    f"{str(method).upper()} {api_path}",
                )
            )
    return evidence


def _scan_postman_json(
    data: Dict[str, object],
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    for endpoint, blob in _postman_items(data.get("item", [])):
        evidence.extend(
            _semantic_context_evidence(
                blob,
                rel,
                path,
                None,
                file_context,
                seen,
                "postman",
                "request_source",
                "semantic_collection_point",
                "API collection request",
                "Notice transparency",
                endpoint,
            )
        )
    return evidence


def _scan_openapi_yaml(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    for category in _categories_for_text(text):
        key = f"semantic_openapi_yaml:{rel}:{category}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_collection_point",
                label=f"{category} API schema field",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=None,
                category="Notice transparency",
                detail=f"OpenAPI YAML heuristic identified {category} fields in API schema.",
                recommendation="Confirm API purpose, notice coverage, validation, retention, and downstream storage controls.",
                file_context=file_context,
                detector_id=f"semantic.openapi.schema.{normalize_text(category)}",
                extra={"data_category": category, "endpoint_hint": "OpenAPI YAML", "semantic_role": "request_source"},
            )
        )
    return evidence


def _scan_kubernetes_manifest(
    text: str,
    rel: str,
    path: Path,
    file_context: str,
    seen: Set[str],
) -> List[Evidence]:
    evidence: List[Evidence] = []
    kind_match = K8S_KIND_RE.search(text)
    kind = kind_match.group(1) if kind_match else "Kubernetes"
    for match in K8S_ENV_RE.finditer(text):
        field = match.group(1)
        category = _category_for_text(field)
        if not category:
            continue
        line_number = text.count("\n", 0, match.start()) + 1
        key = f"semantic_k8s_env:{rel}:{line_number}:{field}"
        if key in seen:
            continue
        seen.add(key)
        evidence.append(
            _evidence(
                kind="semantic_runtime_config",
                label=f"{category} runtime config reference",
                severity=_severity_for_category(category),
                rel=rel,
                path=path,
                line=line_number,
                category="Security safeguards",
                detail=f"Kubernetes manifest references `{field}` in {kind} configuration.",
                recommendation="Confirm this runtime config does not expose personal data and is backed by secrets/config governance.",
                file_context=file_context,
                detector_id=f"semantic.kubernetes.runtime_config.{normalize_text(category)}",
                extra={"data_category": category, "field": field, "semantic_role": "runtime_config"},
            )
        )
    if K8S_SECRET_REF_RE.search(text):
        evidence.append(
            _evidence(
                kind="semantic_secret_reference",
                label="Kubernetes secret/config reference",
                severity="LOW",
                rel=rel,
                path=path,
                line=None,
                category="Security safeguards",
                detail="Kubernetes manifest references Secret, ConfigMap, image pull secret, or TLS material.",
                recommendation="Confirm secrets are encrypted at rest, access-controlled, rotated, and not storing personal data unnecessarily.",
                file_context=file_context,
                detector_id="semantic.kubernetes.secret_reference",
                extra={"semantic_role": "secret_reference"},
            )
        )
    return evidence


def _semantic_context_evidence(
    context: str,
    rel: str,
    path: Path,
    line: Optional[int],
    file_context: str,
    seen: Set[str],
    language_key: str,
    role: str,
    kind: str,
    label_suffix: str,
    category_area: str,
    endpoint_hint: str,
) -> List[Evidence]:
    evidence: List[Evidence] = []
    for category in _categories_for_text(context):
        key = f"semantic_context:{language_key}:{role}:{rel}:{line}:{category}:{endpoint_hint}"
        if key in seen:
            continue
        seen.add(key)
        severity = "CRITICAL" if role == "log_sink" and category in {"Government ID", "Health", "Children"} else _severity_for_category(category)
        evidence.append(
            _evidence(
                kind=kind,
                label=f"{category} {label_suffix}",
                severity=severity,
                rel=rel,
                path=path,
                line=line,
                category=category_area,
                detail=f"{language_key.title()} parser heuristic identified {category} data in {label_suffix}.",
                recommendation=_recommendation_for_role(role),
                file_context=file_context,
                detector_id=f"semantic.{language_key}.{role}.{normalize_text(category)}",
                extra={"data_category": category, "endpoint_hint": endpoint_hint, "semantic_role": role},
            )
        )
    return evidence


def _field_from_match(match: re.Match[str]) -> str:
    groups = [group for group in match.groups() if group]
    if len(groups) >= 2 and match.re is GO_STRUCT_FIELD_RE:
        return groups[1]
    return groups[0] if groups else ""


def _postman_items(items: object, prefix: str = "") -> Iterable[tuple[str, str]]:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or prefix or "Postman request")
        if isinstance(item.get("item"), list):
            yield from _postman_items(item.get("item"), name)
            continue
        yield name, json.dumps(item, sort_keys=True)


def _recommendation_for_role(role: str) -> str:
    if role == "log_sink":
        return "Mask, remove, hash, or justify personal data in logs and attach log-retention evidence."
    if role == "storage_sink":
        return "Attach storage encryption, access-control, retention, deletion, and backup/restore evidence for this data path."
    if role == "runtime_config":
        return "Confirm runtime configuration is protected, minimized, and does not expose personal data."
    return "Confirm notice, purpose, consent/legitimate-use basis, validation, and retention for this endpoint."


def _categories_for_text(text: str) -> List[str]:
    found: Set[str] = set()
    normalized = normalize_text(text)
    for pattern in PERSONAL_DATA_PATTERNS:
        # Ambiguous tokens (minor/school/patient/address/mobile/health/...)
        # are excluded here: semantic matching runs over whole function-body
        # text, which is far too coarse for corroboration checks. code.py
        # still covers those terms line-by-line with corroboration.
        # Benchmark: "amount in minor units" in payment code produced
        # CRITICAL Children findings via this path.
        unambiguous = [t for t in pattern.terms if t not in AMBIGUOUS_SENSITIVE_TERMS]
        if unambiguous and _pattern_matches(normalized, unambiguous):
            found.add(pattern.category)
    return sorted(found)


def _category_for_text(text: str) -> Optional[str]:
    categories = _categories_for_text(text)
    if not categories:
        return None
    return sorted(categories, key=lambda item: _severity_rank(_severity_for_category(item)), reverse=True)[0]


def _pattern_matches(normalized_text: str, terms: List[str]) -> bool:
    tokens = normalized_text.split("_")
    for term in terms:
        term_tokens = normalize_text(term).split("_")
        if not term_tokens:
            continue
        width = len(term_tokens)
        if any(tokens[index : index + width] == term_tokens for index in range(0, len(tokens) - width + 1)):
            return True
    return False


def _severity_for_category(category: str) -> str:
    # Single source of truth: the category -> severity table lives in
    # patterns.py (CATEGORY_SEVERITY). This module previously kept its own
    # divergent copy (Contact/Identity=LOW, Location=MEDIUM), which
    # contradicted the patterns.py table in reports.
    return CATEGORY_SEVERITY.get(category, "LOW")


def _severity_rank(severity: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 0)


def _python_endpoint_hint(node: ast.AST) -> str:
    decorators = getattr(node, "decorator_list", []) or []
    hints = [_name(item) for item in decorators]
    return ", ".join(hint for hint in hints if hint) or getattr(node, "name", "function")


def _node_text(node: ast.AST, source_lines: List[str]) -> str:
    start = max(getattr(node, "lineno", 1) - 1, 0)
    end = getattr(node, "end_lineno", None) or min(len(source_lines), start + 80)
    return "\n".join(source_lines[start:end])


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    if isinstance(node, ast.Constant):
        return str(node.value)
    return ""


def _evidence(
    *,
    kind: str,
    label: str,
    severity: str,
    rel: str,
    path: Path,
    line: Optional[int],
    category: str,
    detail: str,
    recommendation: str,
    file_context: str,
    detector_id: str,
    extra: Dict[str, object],
) -> Evidence:
    evidence_ref = f"{rel}:{line}:{detector_id}" if line else f"{rel}:{detector_id}"
    parser = _parser_for_path(path)
    # Confidence honesty: only the stdlib Python AST engine performs real
    # structural parsing. Every *_heuristic engine is regex/substring based
    # and reports "medium" so downstream consumers do not over-trust it.
    confidence = "high" if parser == "python.ast" else "medium"
    return Evidence(
        kind=kind,
        label=label,
        severity=severity,
        source="semantic-parser",
        file=rel,
        line=line,
        detail=detail,
        recommendation=recommendation,
        category=category,
        metadata={
            "detector_id": detector_id,
            "confidence": confidence,
            "evidence_ref": evidence_ref,
            "file_context": file_context,
            "language": _language_for(path),
            "parser": parser,
            **extra,
        },
    )


def _parser_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".py":
        return "python.ast"
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "js_ts.endpoint_heuristic"
    if suffix == ".java":
        return "java.spring_heuristic"
    if suffix == ".go":
        return "go.handler_heuristic"
    if suffix == ".rb":
        return "ruby.rails_heuristic"
    if suffix == ".php":
        return "php.laravel_heuristic"
    if suffix in {".sql", ".prisma", ".graphql", ".gql"}:
        return "schema.field_heuristic"
    if suffix in {".json", ".yaml", ".yml"}:
        return "structured_artifact_heuristic"
    return "semantic_heuristic"
