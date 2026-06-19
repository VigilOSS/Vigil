"""SQLite helpers with parameterized queries — replaces lib/db.sh.

Kills the 19-positional-parameter db_insert_case() function and SQL injection surface.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# Absolute import — every consumer of this module either runs through
# `assess.cli` (which has the scripts dir on sys.path) or via the
# `_load_script_module` test loader (which also inserts the scripts dir on
# sys.path before exec_module). A relative `from .classify_buckets` fails
# in the test path because the file is loaded without a parent package.
from assess.lib.classify_buckets import INERT_TYPES

_SCHEMA_FILE = Path(__file__).resolve().parent.parent.parent / "schema.sql"

# Inert work-item types live in `classify_buckets.INERT_TYPES` so all three
# consumers (this insert path, classify_buckets.classify_row, and
# classify-work --reclassify-all) read from the same set. See that module's
# docstring for the rationale and the consumer list. Re-export here so
# `db._SKIP_TYPES` stays a stable internal name for the insert path; new
# code should import the public symbol from `classify_buckets`.
_SKIP_TYPES: frozenset[str] = INERT_TYPES

# Idempotent ALTER-based migration for pre-existing work_items tables that
# predate the signal-first dispatch columns. SQLite lacks `ADD COLUMN IF NOT
# EXISTS`, so we inspect PRAGMA table_info and add only the missing columns.
_WORK_ITEMS_PRIORITY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("priority_score", "INTEGER NOT NULL DEFAULT 0"),
    ("priority_reason", "TEXT"),
    ("cluster_key", "TEXT"),
    ("terminal_reason", "TEXT"),
    ("signals", "TEXT"),
    ("selected_by", "TEXT"),
    ("triage_rationale", "TEXT"),
    ("live_status", "TEXT"),
    # Truncation flags. The producer (mitmproxy addon, kali wrapper, etc.)
    # writes 1 when `content_length > saved body size` or `response_size >
    # response_snippet size`. NULL on rows from older DBs is interpreted
    # as "unknown" by consumers; rows from current producers always have
    # an explicit 0/1.
    ("request_body_truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("response_truncated", "INTEGER NOT NULL DEFAULT 0"),
)
_CASES_TRUNCATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("request_body_truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("response_truncated", "INTEGER NOT NULL DEFAULT 0"),
)


def db_init(db_path: str) -> None:
    """Ensure the database exists and schema is applied.

    Run the column-add migration before the full schema executescript so that
    older DBs pick up the priority columns before any CREATE INDEX statement
    references them. The CREATE TABLE IF NOT EXISTS path is still authoritative
    for fresh DBs; the migration helper is a no-op when the table does not
    exist yet, and a no-op when the columns are already present.

    After executescript runs the schema, drop and recreate the
    ``work_items_per_host`` view so legacy DBs pick up the port-stripping
    fix. ``CREATE VIEW IF NOT EXISTS`` in the schema file is a no-op when an
    older view already exists with the buggy host expression, so the helper
    DROPs first and re-runs CREATE — the view is purely derived state, no
    rows to lose.
    """
    if not Path(db_path).is_file():
        raise SystemExit(f"db_init: database not found: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        _apply_work_items_priority_migration(conn)
        _apply_cases_truncation_migration(conn)
        schema_sql = _SCHEMA_FILE.read_text(encoding="utf-8")
        conn.executescript(schema_sql)
        _apply_work_items_per_host_view(conn)
        conn.commit()
    finally:
        conn.close()


def _apply_work_items_per_host_view(conn: sqlite3.Connection) -> None:
    """Install the per-host aggregate view (1D.2), refreshing it on legacy DBs.

    The view is purely derived state: dropping and recreating it does not
    touch any work_items row. We always drop first so an older engagement
    that already has the buggy pre-port-strip host expression cached in the
    schema picks up the corrected expression on the next ingest pass. Fresh
    DBs got the right expression via ``executescript``; this helper is the
    catch-up path for upgrades.
    """
    has_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='work_items'"
    ).fetchone()
    if not has_table:
        return
    conn.execute("DROP VIEW IF EXISTS work_items_per_host")
    conn.execute(
        """
        CREATE VIEW work_items_per_host AS
        WITH host_with_port AS (
            SELECT
                id,
                status,
                cluster_key,
                CASE
                    WHEN instr(substr(url, instr(url, '://') + 3), '/') > 0
                        THEN substr(
                            substr(url, instr(url, '://') + 3),
                            1,
                            instr(substr(url, instr(url, '://') + 3), '/') - 1
                        )
                    ELSE substr(url, instr(url, '://') + 3)
                END AS host_authority
            FROM work_items
            WHERE url IS NOT NULL AND url != ''
        )
        SELECT
            lower(
                CASE
                    WHEN host_authority LIKE '[%]%' AND instr(host_authority, ']') > 0
                        THEN substr(host_authority, 2, instr(host_authority, ']') - 2)
                    WHEN instr(host_authority, ':') > 0
                        THEN substr(host_authority, 1, instr(host_authority, ':') - 1)
                    ELSE host_authority
                END
            ) AS host,
            SUM(CASE WHEN status IN ('pending', 'processing', 'done') THEN 1 ELSE 0 END) AS active_count,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
            SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) AS done_count,
            SUM(CASE WHEN cluster_key LIKE 'deferred:%' THEN 1 ELSE 0 END) AS deferred_count
        FROM host_with_port
        GROUP BY host
        """
    )


def _apply_work_items_priority_migration(conn: sqlite3.Connection) -> None:
    """Add priority/cluster columns when missing.

    PRAGMA table_info tells us which columns the current file already has. We
    only issue ALTER TABLE for the missing ones because ALTER TABLE is not
    wrapped by `IF NOT EXISTS` in SQLite, and a duplicate add would abort the
    whole db_init flow. When the table does not exist yet (fresh DB) we leave
    the work to the CREATE TABLE IF NOT EXISTS in schema.sql.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(work_items)").fetchall()}
    if not existing:
        return
    for name, decl in _WORK_ITEMS_PRIORITY_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE work_items ADD COLUMN {name} {decl}")


def _apply_cases_truncation_migration(conn: sqlite3.Connection) -> None:
    """Add truncation flag columns to `cases` for legacy engagement DBs.

    Same PRAGMA-table_info pattern as the work_items migration. Without
    this, inserts into `cases` on a pre-schema-change DB would silently
    drop the new truncation columns.
    """
    existing = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    if not existing:
        return
    for name, decl in _CASES_TRUNCATION_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE cases ADD COLUMN {name} {decl}")


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


def db_exec_returning(db_path: str, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Execute a write statement with a ``RETURNING`` clause and commit.

    Used for ``UPDATE ... RETURNING *`` where the caller needs the mutated rows
    as dicts. Opens a Row-factory connection, fetchalls before commit, then
    returns ``[dict(row) ...]``.
    """
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        rows = conn.execute(sql, params).fetchall()
        conn.commit()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@contextmanager
def db_connect(db_path: str) -> Iterator[sqlite3.Connection]:
    """Yield a Row-factory connection (busy_timeout=5000), closing it on exit.

    For multi-statement transactions that must share one connection — e.g. a
    ``BEGIN IMMEDIATE`` claim that interleaves SELECT / UPDATE ... RETURNING and
    hands the live connection to a downstream stamping helper. The caller owns
    the transaction (BEGIN / COMMIT); this manager only guarantees the
    connection is configured identically to the other helpers and is always
    closed.
    """
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        yield conn
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
    body: str | None = "",
    content_type: str = "",
    content_length: int = 0,
    request_body_truncated: bool = False,
    response_status: int = 0,
    response_headers: str = "",
    response_size: int = 0,
    response_snippet: str | None = "",
    response_truncated: bool = False,
    case_type: str = "unknown",
    source: str = "",
    params_key_sig: str = "",
    request_variant_id: int | None = None,
    service_id: int | None = None,
    coverage_item_id: int | None = None,
    auth_context: str = "anonymous",
    priority_score: int | None = None,
    priority_reason: str | None = None,
    cluster_key: str | None = None,
    terminal_reason: str | None = None,
    signals: str | None = None,
    selected_by: str | None = None,
    triage_rationale: str | None = None,
    live_status: str | None = None,
    curated: bool = False,
    connection: sqlite3.Connection | None = None,
) -> None:
    """Insert a work item using parameterized SQL. No SQL injection surface."""
    if not url or url == "null":
        return
    if not url_path or url_path == "null":
        return
    if not method or method == "null":
        method = "GET"

    status = "skipped" if case_type in _SKIP_TYPES else "pending"

    # Inline classification at insert time. Previously, classification ran as
    # a separate `vigil assess classify-work` step that operators routinely
    # forgot, leaving the work buffer unscored and the priority-mode dispatch
    # with nothing to sort by. The classification helper is pure string
    # matching (<1ms per row, no I/O) so doing it here is effectively free
    # and removes the entire forgotten-step class of bug.
    from assess.lib.classify_buckets import classify_from_fields

    assignment = classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=query_params,
        body_params=body_params,
        path_params=path_params,
    )
    curated_metadata = curated or any(
        value is not None
        for value in (
            priority_score,
            priority_reason,
            cluster_key,
            terminal_reason,
            signals,
            selected_by,
            triage_rationale,
            live_status,
        )
    )

    should_close = connection is None
    conn = connection or sqlite3.connect(db_path, timeout=5.0)
    try:
        if should_close:
            conn.execute("PRAGMA busy_timeout=5000")
        existing_id: int | None = None
        if curated_metadata:
            existing = conn.execute(
                "SELECT id FROM work_items WHERE queue_key = ?",
                (queue_key,),
            ).fetchone()
            if existing is None and request_variant_id is not None:
                existing = conn.execute(
                    "SELECT id FROM work_items WHERE request_variant_id = ? ORDER BY id LIMIT 1",
                    (request_variant_id,),
                ).fetchone()
            if existing is None:
                existing = conn.execute(
                    "SELECT id FROM work_items WHERE method = ? AND url = ? ORDER BY id LIMIT 1",
                    (method, url),
                ).fetchone()
            if existing is not None:
                existing_id = int(existing[0])
                conn.execute(
                    """UPDATE work_items
                    SET queue_key = ?,
                        request_variant_id = ?,
                        service_id = ?,
                        coverage_item_id = ?,
                        auth_context = ?,
                        method = ?,
                        url = ?,
                        url_path = ?,
                        query_params = ?,
                        body_params = ?,
                        path_params = ?,
                        cookie_params = ?,
                        headers = ?,
                        body = ?,
                        content_type = ?,
                        content_length = ?,
                        request_body_truncated = ?,
                        response_status = ?,
                        response_headers = ?,
                        response_size = ?,
                        response_snippet = ?,
                        response_truncated = ?,
                        type = ?,
                        source = ?,
                        params_key_sig = ?
                    WHERE id = ?""",
                    (
                        queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                        method, url, url_path,
                        query_params, body_params, path_params, cookie_params,
                        headers, body, content_type, content_length,
                        1 if request_body_truncated else 0,
                        response_status, response_headers, response_size, response_snippet,
                        1 if response_truncated else 0,
                        case_type, source, params_key_sig,
                        existing_id,
                    ),
                )
        if existing_id is None:
            conn.execute(
                """INSERT OR IGNORE INTO work_items (
                    queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                    method, url, url_path,
                    query_params, body_params, path_params, cookie_params,
                    headers, body, content_type, content_length, request_body_truncated,
                    response_status, response_headers, response_size, response_snippet, response_truncated,
                    type, source, status, params_key_sig
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?
                )""",
                (
                    queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
                    method, url, url_path,
                    query_params, body_params, path_params, cookie_params,
                    headers, body, content_type, content_length, 1 if request_body_truncated else 0,
                    response_status, response_headers, response_size, response_snippet, 1 if response_truncated else 0,
                    case_type, source, status, params_key_sig,
                ),
            )
        if curated_metadata:
            # Candidate-record ingest is an explicit curated path. Apply its
            # metadata even when a URL was already inserted through a plain URL
            # path, so a high-signal candidate can be upgraded instead of being
            # trapped behind the previous URL-shape default.
            conn.execute(
                """UPDATE work_items
                SET priority_score = ?,
                    priority_reason = ?,
                    cluster_key = ?,
                    terminal_reason = ?,
                    signals = COALESCE(?, signals),
                    selected_by = COALESCE(?, selected_by),
                    triage_rationale = COALESCE(?, triage_rationale),
                    live_status = COALESCE(?, live_status)
                WHERE queue_key = ?
                """,
                (
                    priority_score if priority_score is not None else assignment["priority_score"],
                    priority_reason if priority_reason is not None else assignment["priority_reason"],
                    cluster_key if cluster_key is not None else assignment["cluster_key"],
                    terminal_reason if terminal_reason is not None else assignment["terminal_reason"],
                    signals,
                    selected_by,
                    triage_rationale,
                    live_status,
                    queue_key,
                ),
            )
            conn.commit()
            return

        # `INSERT OR IGNORE` above means a re-ingest of the same `queue_key`
        # leaves the existing row untouched. The UPDATE here is scoped to
        # rows that are still at the schema-default classification — so a
        # newly-inserted row gets its inline assignment, while a row that
        # was already ingested and possibly re-classified by hand or by
        # `vigil assess classify-work --reclassify-all` keeps its existing
        # priority_score / cluster_key. Without the default-only predicate,
        # every re-ingest would clobber operator triage.
        conn.execute(
            """UPDATE work_items
            SET priority_score = ?,
                priority_reason = ?,
                cluster_key = ?,
                terminal_reason = COALESCE(?, terminal_reason)
            WHERE queue_key = ?
              AND priority_score = 0
              AND cluster_key IS NULL
            """,
            (
                assignment["priority_score"],
                assignment["priority_reason"],
                assignment["cluster_key"],
                assignment["terminal_reason"],
                queue_key,
            ),
        )
        conn.commit()
    finally:
        if should_close:
            conn.close()
