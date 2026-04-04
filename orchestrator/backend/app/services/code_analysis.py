from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _json_list_text(value: Any) -> str:
    return json.dumps(value if value is not None else [], sort_keys=True, separators=(",", ":"))


def _scalar_row(connection, query: str, params: tuple[Any, ...]) -> int:
    row = connection.execute(query, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _fetch_all(connection, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, params).fetchall()]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# =========================================================================
# Repository Management
# =========================================================================

def create_code_repo(
    engagement_id: int,
    *,
    repo_key: str,
    name: str,
    language: str,
    repo_path: str,
    total_files: int,
    analyzable_files: int,
    total_loc: int,
    commit_hash: str,
    branch: str,
    git_churn: dict | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, language, repo_path,
                total_files, analyzable_files, total_loc,
                commit_hash, branch, git_churn_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id, repo_key, name, language, repo_path,
                total_files, analyzable_files, total_loc,
                commit_hash, branch, _json_text(git_churn),
            ),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return dict(row)


def list_code_repos(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        return _fetch_all(
            connection,
            "SELECT * FROM code_repos WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC",
            (engagement.id,),
        )


def get_code_repo(engagement_id: int, repo_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return dict(row)


# =========================================================================
# File Management
# =========================================================================

def bulk_create_code_files(
    engagement_id: int,
    repo_id: int,
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = 0
    skipped = 0
    with get_connection() as connection:
        for f in files:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO code_files (
                    engagement_id, repo_id, file_path, language, loc,
                    file_hash, header_snippet, git_churn_score, has_past_cve_fix
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    repo_id,
                    f["file_path"],
                    f.get("language", ""),
                    f.get("loc", 0),
                    f.get("file_hash", ""),
                    f.get("header_snippet", ""),
                    f.get("git_churn_score", 0),
                    1 if f.get("has_past_cve_fix") else 0,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
    return {"inserted": inserted, "skipped": skipped, "total": len(files)}


def list_code_files(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    classification: str | None = None,
    analysis_status: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if repo_id is not None:
        clauses.append("repo_id = ?")
        params.append(repo_id)
    if classification is not None:
        clauses.append("classification = ?")
        params.append(classification)
    if analysis_status is not None:
        clauses.append("analysis_status = ?")
        params.append(analysis_status)
    query = f"SELECT * FROM code_files WHERE {' AND '.join(clauses)} ORDER BY analysis_priority DESC, id ASC"
    if limit is not None:
        query += f" LIMIT {int(limit)}"
    with get_connection() as connection:
        return _fetch_all(connection, query, tuple(params))


def get_code_file(engagement_id: int, file_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_files WHERE engagement_id = ? AND id = ?",
            (engagement.id, file_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
    return dict(row)


_VALID_CLASSIFICATIONS = frozenset({"critical", "high", "medium", "low", "skip"})


def bulk_classify_code_files(
    engagement_id: int,
    classifications: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    updated = 0
    with get_connection() as connection:
        for c in classifications:
            classification = c.get("classification", "")
            if classification not in _VALID_CLASSIFICATIONS:
                continue
            priority = max(0, min(100, int(c.get("analysis_priority", 0))))
            cursor = connection.execute(
                """
                UPDATE code_files
                SET classification = ?,
                    role = ?,
                    slot_types_json = ?,
                    analysis_priority = ?,
                    analysis_status = 'classified',
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (
                    classification,
                    c.get("role", ""),
                    _json_list_text(c.get("slot_types")),
                    priority,
                    engagement.id,
                    c["file_id"],
                ),
            )
            if cursor.rowcount > 0:
                updated += 1
    return {"updated": updated, "total": len(classifications)}


_CODE_FILE_ALLOWED_FIELDS = frozenset({
    "classification", "role", "analysis_priority", "analysis_status",
    "analysis_depth", "skip_reason", "variant_check_status", "module_id",
    "notes", "slot_types_json",
})


def update_code_file(
    engagement_id: int,
    file_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_file(engagement_id, file_id)

    set_clauses = []
    params: list[Any] = []
    json_list_fields = {"slot_types_json"}
    json_object_fields: set[str] = set()

    for key, value in kwargs.items():
        if key not in _CODE_FILE_ALLOWED_FIELDS:
            continue  # silently ignore disallowed fields
        if key in json_list_fields:
            set_clauses.append(f"{key} = ?")
            params.append(_json_list_text(value))
        elif key in json_object_fields:
            set_clauses.append(f"{key} = ?")
            params.append(_json_text(value))
        else:
            set_clauses.append(f"{key} = ?")
            params.append(value)

    if not set_clauses:
        return get_code_file(engagement_id, file_id)

    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([engagement.id, file_id])

    with get_connection() as connection:
        connection.execute(
            f"UPDATE code_files SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        row = connection.execute(
            "SELECT * FROM code_files WHERE engagement_id = ? AND id = ?",
            (engagement.id, file_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
    return dict(row)


# =========================================================================
# Module Management
# =========================================================================

def bulk_create_code_modules(
    engagement_id: int,
    repo_id: int,
    modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    created: list[dict[str, Any]] = []
    with get_connection() as connection:
        for m in modules:
            cursor = connection.execute(
                """
                INSERT INTO code_modules (
                    engagement_id, repo_id, module_key, name, description, trust_boundary
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, module_key) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    trust_boundary = excluded.trust_boundary,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    engagement.id,
                    repo_id,
                    m["module_key"],
                    m["name"],
                    m.get("description", ""),
                    m.get("trust_boundary", ""),
                ),
            )
            row = connection.execute(
                "SELECT * FROM code_modules WHERE engagement_id = ? AND repo_id = ? AND module_key = ?",
                (engagement.id, repo_id, m["module_key"]),
            ).fetchone()
            assert row is not None
            created.append(dict(row))
    return created


def list_code_modules(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if repo_id is not None:
        query = "SELECT * FROM code_modules WHERE engagement_id = ? AND repo_id = ? ORDER BY id ASC"
        params: tuple[Any, ...] = (engagement.id, repo_id)
    else:
        query = "SELECT * FROM code_modules WHERE engagement_id = ? ORDER BY id ASC"
        params = (engagement.id,)
    with get_connection() as connection:
        return _fetch_all(connection, query, params)


# =========================================================================
# Context Slices
# =========================================================================

def bulk_create_code_contexts(
    engagement_id: int,
    contexts: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = 0
    skipped = 0
    with get_connection() as connection:
        for ctx in contexts:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO code_contexts (
                    engagement_id, file_id, function_name, start_line, end_line,
                    slot_types_json, call_chain_json, data_flow_json,
                    cross_refs_json, guard_annotations_json, sink_annotations_json,
                    context_text
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    ctx["file_id"],
                    ctx["function_name"],
                    ctx.get("start_line", 0),
                    ctx.get("end_line", 0),
                    _json_list_text(ctx.get("slot_types")),
                    _json_text(ctx.get("call_chain")),
                    _json_text(ctx.get("data_flow")),
                    _json_list_text(ctx.get("cross_refs")),
                    _json_list_text(ctx.get("guard_annotations")),
                    _json_list_text(ctx.get("sink_annotations")),
                    ctx.get("context_text", ""),
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
            else:
                skipped += 1
    return {"inserted": inserted, "skipped": skipped, "total": len(contexts)}


def list_code_contexts(
    engagement_id: int,
    *,
    file_id: int | None = None,
    analysis_status: str | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if file_id is not None:
        clauses.append("file_id = ?")
        params.append(file_id)
    if analysis_status is not None:
        clauses.append("analysis_status = ?")
        params.append(analysis_status)
    query = f"SELECT * FROM code_contexts WHERE {' AND '.join(clauses)} ORDER BY id ASC"
    with get_connection() as connection:
        return _fetch_all(connection, query, tuple(params))


_CODE_CONTEXT_ALLOWED_FIELDS = frozenset({
    "analysis_status", "slot_types_json", "call_chain_json", "data_flow_json",
    "cross_refs_json", "guard_annotations_json", "sink_annotations_json",
    "context_text",
})


def update_code_context(
    engagement_id: int,
    context_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT * FROM code_contexts WHERE engagement_id = ? AND id = ?",
                (engagement.id, context_id),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code context not found")
        return dict(row)

    json_list_fields = {"slot_types_json", "cross_refs_json", "guard_annotations_json", "sink_annotations_json"}
    json_object_fields = {"call_chain_json", "data_flow_json"}

    set_clauses = []
    params: list[Any] = []
    for key, value in kwargs.items():
        if key not in _CODE_CONTEXT_ALLOWED_FIELDS:
            continue  # silently ignore disallowed fields
        if key in json_list_fields:
            set_clauses.append(f"{key} = ?")
            params.append(_json_list_text(value))
        elif key in json_object_fields:
            set_clauses.append(f"{key} = ?")
            params.append(_json_text(value))
        else:
            set_clauses.append(f"{key} = ?")
            params.append(value)

    if not set_clauses:
        with get_connection() as connection:
            row = connection.execute(
                "SELECT * FROM code_contexts WHERE engagement_id = ? AND id = ?",
                (engagement.id, context_id),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code context not found")
        return dict(row)

    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([engagement.id, context_id])

    with get_connection() as connection:
        connection.execute(
            f"UPDATE code_contexts SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        row = connection.execute(
            "SELECT * FROM code_contexts WHERE engagement_id = ? AND id = ?",
            (engagement.id, context_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code context not found")
    return dict(row)


# =========================================================================
# Analysis Queue
# =========================================================================

def bulk_create_queue_items(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = 0
    with get_connection() as connection:
        for item in items:
            priority = max(0, min(100, int(item.get("priority", 50))))
            cursor = connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, context_id, file_id, priority
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    item.get("context_id"),
                    item["file_id"],
                    priority,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
    return {"inserted": inserted, "total": len(items)}


def queue_stats(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM code_analysis_queue WHERE engagement_id = ? GROUP BY status",
            (engagement.id,),
        ).fetchall()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = int(row["total"])
    return {
        "pending": counts.get("pending", 0),
        "processing": counts.get("processing", 0),
        "done": counts.get("done", 0),
        "error": counts.get("error", 0),
        "needs_context": counts.get("needs_context", 0),
        "total": sum(counts.values()),
    }


def fetch_queue_items(
    engagement_id: int,
    limit: int,
    agent_name: str,
) -> list[dict[str, Any]]:
    """Atomically claim pending queue items for an agent.

    Uses UPDATE ... WHERE id IN (SELECT ... LIMIT) to prevent two concurrent
    callers from claiming the same rows.
    """
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    with get_connection() as connection:
        # Atomic claim: UPDATE with subquery SELECT in one statement
        connection.execute(
            """
            UPDATE code_analysis_queue
            SET status = 'processing',
                assigned_agent = ?,
                consumed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id IN (
                SELECT id FROM code_analysis_queue
                WHERE engagement_id = ? AND status = 'pending'
                ORDER BY priority DESC, id ASC
                LIMIT ?
            )
            """,
            (agent_name, now, engagement.id, limit),
        )
        # Fetch the rows we just claimed
        rows = connection.execute(
            """
            SELECT * FROM code_analysis_queue
            WHERE engagement_id = ? AND assigned_agent = ? AND status = 'processing'
              AND consumed_at = ?
            ORDER BY priority DESC, id ASC
            """,
            (engagement.id, agent_name, now),
        ).fetchall()
    return [dict(row) for row in rows]


_VALID_DISPOSITIONS = frozenset({"finding", "suspicious", "clean", "needs_context"})


def complete_queue_items(
    engagement_id: int,
    item_ids: list[int],
    disposition: str,
    notes: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    if disposition not in _VALID_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid disposition '{disposition}'. Must be one of: {', '.join(sorted(_VALID_DISPOSITIONS))}",
        )
    now = _now_iso()
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'done',
                disposition = ?,
                analysis_notes = ?,
                completed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id IN ({placeholders})
            """,
            (disposition, notes, now, engagement.id, *item_ids),
        )
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def error_queue_items(
    engagement_id: int,
    item_ids: list[int],
    notes: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'error',
                analysis_notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id IN ({placeholders})
            """,
            (notes, engagement.id, *item_ids),
        )
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def needs_context_queue_items(
    engagement_id: int,
    item_ids: list[int],
    expansion_request: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'needs_context',
                expansion_request_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id IN ({placeholders})
            """,
            (_json_text(expansion_request), engagement.id, *item_ids),
        )
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def reset_stale_queue_items(
    engagement_id: int,
    minutes: int,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET status = 'pending',
                assigned_agent = '',
                consumed_at = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ?
              AND status = 'processing'
              AND (consumed_at < datetime('now', ? || ' minutes') OR consumed_at IS NULL)
            """,
            (engagement.id, f"-{minutes}"),
        )
        return {"reset": cursor.rowcount}


# =========================================================================
# Analysis Results
# =========================================================================

def create_analysis_result(
    engagement_id: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, context_id, file_id,
                agent_name, function_name, hypothesis, evidence,
                disposition, confidence, finding_slug, cwe_id,
                slot_type, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                result["queue_item_id"],
                result.get("context_id"),
                result["file_id"],
                result.get("agent_name", ""),
                result.get("function_name", ""),
                result.get("hypothesis", ""),
                result.get("evidence", ""),
                result.get("disposition", ""),
                result.get("confidence", "medium"),
                result.get("finding_slug", ""),
                result.get("cwe_id", ""),
                result.get("slot_type", ""),
                result.get("notes", ""),
            ),
        )
        row = connection.execute(
            "SELECT * FROM code_analysis_results WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return dict(row)


def list_analysis_results(
    engagement_id: int,
    *,
    file_id: int | None = None,
    disposition: str | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if file_id is not None:
        clauses.append("file_id = ?")
        params.append(file_id)
    if disposition is not None:
        clauses.append("disposition = ?")
        params.append(disposition)
    query = f"SELECT * FROM code_analysis_results WHERE {' AND '.join(clauses)} ORDER BY id DESC"
    with get_connection() as connection:
        return _fetch_all(connection, query, tuple(params))


# =========================================================================
# Threat Model
# =========================================================================

def record_threat_model(
    engagement_id: int,
    repo_id: int,
    threat_model: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE code_repos
            SET threat_model_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (_json_text(threat_model), engagement.id, repo_id),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return dict(row)


def get_threat_model(
    engagement_id: int,
    repo_id: int,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT threat_model_json FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    raw = row["threat_model_json"]
    if isinstance(raw, str) and raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


# =========================================================================
# Coverage
# =========================================================================

def code_coverage_summary(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    repo_clause = ""
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = " AND repo_id = ?"
        repo_params = (repo_id,)

    with get_connection() as connection:
        # -- Total files --
        total_files = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ?{repo_clause}",
            (engagement.id, *repo_params),
        )

        # -- By classification --
        classification_rows = connection.execute(
            f"""
            SELECT classification,
                   COUNT(*) AS total,
                   SUM(CASE WHEN analysis_status IN ('analyzed', 'done') THEN 1 ELSE 0 END) AS analyzed
            FROM code_files
            WHERE engagement_id = ?{repo_clause}
            GROUP BY classification
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        by_classification: dict[str, dict[str, int]] = {}
        for row in classification_rows:
            by_classification[row["classification"]] = {
                "count": int(row["total"]),
                "analyzed": int(row["analyzed"]),
            }

        # -- By analysis status --
        status_rows = connection.execute(
            f"""
            SELECT analysis_status, COUNT(*) AS total
            FROM code_files
            WHERE engagement_id = ?{repo_clause}
            GROUP BY analysis_status
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        by_status: dict[str, int] = {}
        for row in status_rows:
            by_status[row["analysis_status"]] = int(row["total"])

        # -- Function-level context stats --
        # Build file_id filter for contexts if repo scoped
        if repo_id is not None:
            ctx_filter = (
                " AND file_id IN (SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ?)"
            )
            ctx_params: tuple[Any, ...] = (engagement.id, repo_id)
        else:
            ctx_filter = ""
            ctx_params = ()

        total_contexts = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_contexts WHERE engagement_id = ?{ctx_filter}",
            (engagement.id, *ctx_params),
        )
        analyzed_contexts = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_contexts WHERE engagement_id = ? AND analysis_status IN ('analyzed', 'done'){ctx_filter}",
            (engagement.id, *ctx_params),
        )
        needs_context_contexts = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_contexts WHERE engagement_id = ? AND analysis_status = 'needs_context'{ctx_filter}",
            (engagement.id, *ctx_params),
        )
        pending_contexts = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_contexts WHERE engagement_id = ? AND analysis_status = 'pending'{ctx_filter}",
            (engagement.id, *ctx_params),
        )

        # -- Findings summary (from assessment_findings where canonical_location starts with 'file:') --
        total_code_findings = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ? AND canonical_location LIKE 'file:%'",
            (engagement.id,),
        )
        severity_rows = connection.execute(
            """
            SELECT severity, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ? AND canonical_location LIKE 'file:%'
            GROUP BY severity
            """,
            (engagement.id,),
        ).fetchall()
        by_severity: dict[str, int] = {}
        for row in severity_rows:
            by_severity[row["severity"]] = int(row["total"])

        variant_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM assessment_finding_links WHERE engagement_id = ? AND link_kind = 'variant_of'",
            (engagement.id,),
        )

        # -- Confidence metrics --
        critical_total = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'critical'{repo_clause}",
            (engagement.id, *repo_params),
        )
        critical_analyzed = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'critical' AND analysis_status IN ('analyzed', 'done'){repo_clause}",
            (engagement.id, *repo_params),
        )
        high_total = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'high'{repo_clause}",
            (engagement.id, *repo_params),
        )
        high_analyzed = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'high' AND analysis_status IN ('analyzed', 'done'){repo_clause}",
            (engagement.id, *repo_params),
        )
        overall_loc_analyzed = _scalar_row(
            connection,
            f"SELECT COALESCE(SUM(loc), 0) FROM code_files WHERE engagement_id = ? AND analysis_status IN ('analyzed', 'done'){repo_clause}",
            (engagement.id, *repo_params),
        )
        unresolved_needs_context = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = ? AND status = 'needs_context'",
            (engagement.id,),
        )
        skip_reason_rows = connection.execute(
            f"""
            SELECT skip_reason, COUNT(*) AS total
            FROM code_files
            WHERE engagement_id = ? AND skip_reason != ''{repo_clause}
            GROUP BY skip_reason
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        skip_reasons: dict[str, int] = {}
        for row in skip_reason_rows:
            skip_reasons[row["skip_reason"]] = int(row["total"])

    critical_coverage = (critical_analyzed / critical_total * 100.0) if critical_total > 0 else 0.0
    high_coverage = (high_analyzed / high_total * 100.0) if high_total > 0 else 0.0

    # -- Coverage gate --
    gate_reasons: list[str] = []
    if critical_total > 0 and critical_analyzed < critical_total:
        gate_reasons.append(
            f"Critical files not fully analyzed: {critical_analyzed}/{critical_total}"
        )
    if high_total > 0 and high_analyzed < high_total:
        gate_reasons.append(
            f"High files not fully analyzed: {high_analyzed}/{high_total}"
        )
    if unresolved_needs_context > 0:
        gate_reasons.append(
            f"Unresolved needs-context items: {unresolved_needs_context}"
        )
    gate_passed = len(gate_reasons) == 0

    return {
        "total_files": total_files,
        "by_classification": by_classification,
        "by_status": by_status,
        "function_level": {
            "total_contexts": total_contexts,
            "analyzed": analyzed_contexts,
            "needs_context": needs_context_contexts,
            "pending": pending_contexts,
        },
        "findings_summary": {
            "total_code_findings": total_code_findings,
            "by_severity": by_severity,
            "variant_count": variant_count,
        },
        "confidence": {
            "critical_coverage_pct": round(critical_coverage, 1),
            "high_coverage_pct": round(high_coverage, 1),
            "overall_loc_analyzed": overall_loc_analyzed,
            "unresolved_needs_context": unresolved_needs_context,
            "skip_reasons": skip_reasons,
        },
        "gate": {
            "passed": gate_passed,
            "reasons": gate_reasons,
        },
    }
