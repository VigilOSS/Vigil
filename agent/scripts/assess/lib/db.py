"""SQLite helpers with parameterized queries — replaces lib/db.sh.

Kills the 19-positional-parameter db_insert_case() function and SQL injection surface.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA_FILE = Path(__file__).resolve().parent.parent.parent / "schema.sql"

_SKIP_TYPES = frozenset({"image", "video", "font", "archive"})


def db_init(db_path: str) -> None:
    """Ensure database exists and schema is applied."""
    if not Path(db_path).is_file():
        raise SystemExit(f"db_init: database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        schema_sql = _SCHEMA_FILE.read_text(encoding="utf-8")
        conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()


def db_query(db_path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Execute a query and return results as list of dicts."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def db_exec(db_path: str, sql: str, params: tuple = ()) -> int:
    """Execute a non-query statement. Returns number of rows affected."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def db_insert_work_item(
    db_path: str,
    *,
    queue_key: str,
    method: str,
    url: str,
    url_path: str,
    query_params: str = "{}",
    body_params: str = "{}",
    path_params: str = "{}",
    cookie_params: str = "{}",
    headers: str = "",
    body: str = "",
    content_type: str = "",
    content_length: int = 0,
    response_status: int = 0,
    response_headers: str = "",
    response_size: int = 0,
    response_snippet: str = "",
    case_type: str = "unknown",
    source: str = "",
    params_key_sig: str = "",
    request_variant_id: int | None = None,
    service_id: int | None = None,
    coverage_item_id: int | None = None,
    auth_context: str = "anonymous",
) -> None:
    """Insert a work item using parameterized SQL. No SQL injection surface."""
    if not url or url == "null":
        return
    if not url_path or url_path == "null":
        return
    if not method or method == "null":
        method = "GET"

    status = "skipped" if case_type in _SKIP_TYPES else "pending"

    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(
            """INSERT OR IGNORE INTO work_items (
                queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                method, url, url_path,
                query_params, body_params, path_params, cookie_params,
                headers, body, content_type, content_length,
                response_status, response_headers, response_size, response_snippet,
                type, source, status, params_key_sig
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )""",
            (
                queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                method, url, url_path,
                query_params, body_params, path_params, cookie_params,
                headers, body, content_type, content_length,
                response_status, response_headers, response_size, response_snippet,
                case_type, source, status, params_key_sig,
            ),
        )
        conn.commit()
    finally:
        conn.close()
