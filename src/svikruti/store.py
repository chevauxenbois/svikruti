"""Local-first scan history storage for Svikruti."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from svikruti.models import ScanResult


DEFAULT_DB_PATH = Path(".svikruti") / "evidence.db"


def default_db_path() -> Path:
    return DEFAULT_DB_PATH


def init_store(db_path: str | Path = DEFAULT_DB_PATH) -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                repo_path TEXT,
                url TEXT,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                evidence_count INTEGER NOT NULL,
                files_scanned INTEGER NOT NULL,
                website_pages_scanned INTEGER NOT NULL,
                data_categories_json TEXT NOT NULL,
                third_parties_json TEXT NOT NULL,
                controls_json TEXT NOT NULL,
                breach_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_generated_at ON scans(generated_at DESC)")
        conn.commit()
    finally:
        conn.close()
    return path


def save_scan_result(result: ScanResult, db_path: str | Path = DEFAULT_DB_PATH) -> str:
    path = init_store(db_path)
    payload = result.to_dict()
    result_json = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    scan_id = hashlib.sha256(
        f"{result.generated_at}|{result.repo_path}|{result.url}|{result_json}".encode("utf-8")
    ).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (
                id, generated_at, created_at, repo_path, url, risk_level, risk_score,
                evidence_count, files_scanned, website_pages_scanned, data_categories_json,
                third_parties_json, controls_json, breach_json, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.generated_at,
                now,
                result.repo_path,
                result.url,
                result.summary.risk_level,
                result.summary.risk_score,
                len(result.evidence),
                result.summary.files_scanned,
                result.summary.website_pages_scanned,
                json.dumps(result.summary.personal_data_categories, ensure_ascii=True),
                json.dumps(result.summary.third_parties, ensure_ascii=True),
                json.dumps(result.technical_controls, ensure_ascii=True),
                json.dumps(result.breach_readiness, ensure_ascii=True),
                result_json,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return scan_id


def list_scans(db_path: str | Path = DEFAULT_DB_PATH, limit: int = 50) -> List[Dict[str, Any]]:
    path = init_store(db_path)
    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, generated_at, created_at, repo_path, url, risk_level, risk_score,
                   evidence_count, files_scanned, website_pages_scanned,
                   data_categories_json, third_parties_json, breach_json
            FROM scans
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    scans: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["data_categories"] = _loads(item.pop("data_categories_json"), [])
        item["third_parties"] = _loads(item.pop("third_parties_json"), [])
        item["breach_readiness"] = _loads(item.pop("breach_json"), {})
        scans.append(item)
    return scans


def load_scan(scan_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    path = init_store(db_path)
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return _loads(row[0], {})


def load_latest_scan(db_path: str | Path = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    path = init_store(db_path)
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT result_json FROM scans ORDER BY generated_at DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return _loads(row[0], {})


def load_report_json(report_path: str | Path) -> Dict[str, Any]:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


def _loads(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback
