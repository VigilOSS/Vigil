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


def _json_decode(value: Any, default: Any) -> Any:
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _hydrate_code_repo(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["lsp_config"] = _json_decode(payload.get("lsp_config_json"), {})
    payload["git_churn"] = _json_decode(payload.get("git_churn_json"), {})
    payload["threat_model"] = _json_decode(payload.get("threat_model_json"), {})
    return payload


def _hydrate_code_file(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["slot_types"] = _json_decode(payload.get("slot_types_json"), [])
    return payload


def _hydrate_code_analysis_result(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["audit_metadata"] = _json_decode(payload.get("audit_metadata_json"), {})
    payload["cwe_coverage"] = _json_decode(payload.get("cwe_coverage_json"), [])
    payload["cross_file_triggers"] = _json_decode(payload.get("cross_file_triggers_json"), [])
    return payload


def _analysis_result_row(connection, result_id: int) -> Any:
    return connection.execute(
        """
        SELECT
            results.*,
            findings.status AS finding_status
        FROM code_analysis_results AS results
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = results.engagement_id
         AND findings.slug = results.finding_slug
        WHERE results.id = ?
        """,
        (result_id,),
    ).fetchone()


def _get_repo_row(connection, engagement_id: int, repo_id: int) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
        (engagement_id, repo_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return dict(row)


def _get_repo_rows(connection, engagement_id: int, repo_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not repo_ids:
        return {}
    placeholders = ",".join("?" for _ in repo_ids)
    rows = connection.execute(
        f"SELECT * FROM code_repos WHERE engagement_id = ? AND id IN ({placeholders})",
        (engagement_id, *sorted(repo_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(repo_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return found


def _get_file_rows(connection, engagement_id: int, file_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not file_ids:
        return {}
    placeholders = ",".join("?" for _ in file_ids)
    rows = connection.execute(
        f"SELECT * FROM code_files WHERE engagement_id = ? AND id IN ({placeholders})",
        (engagement_id, *sorted(file_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(file_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
    return found


def _get_queue_rows(connection, engagement_id: int, item_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not item_ids:
        return {}
    placeholders = ",".join("?" for _ in item_ids)
    rows = connection.execute(
        f"SELECT * FROM code_analysis_queue WHERE engagement_id = ? AND id IN ({placeholders})",
        (engagement_id, *sorted(item_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(item_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")
    return found


def _sync_file_analysis_status(connection, engagement_id: int, file_id: int) -> None:
    queue_rows = connection.execute(
        """
        SELECT status, COUNT(*) AS total
        FROM code_analysis_queue
        WHERE engagement_id = ? AND file_id = ?
        GROUP BY status
        """,
        (engagement_id, file_id),
    ).fetchall()
    queue_counts = {str(row["status"]): int(row["total"]) for row in queue_rows}
    pending_queue = queue_counts.get("pending", 0)
    processing_queue = queue_counts.get("processing", 0)
    done_queue = queue_counts.get("done", 0)
    queue_needs_context = queue_counts.get("needs_context", 0)

    # File-direct mode: derive status from queue items alone
    if not queue_counts:
        return  # No queue items — nothing to sync
    if queue_needs_context > 0:
        next_status = "needs_context"
    elif pending_queue == 0 and processing_queue == 0 and done_queue > 0:
        next_status = "analyzed"
    elif processing_queue > 0 or done_queue > 0:
        next_status = "in_progress"
    elif pending_queue > 0:
        next_status = "queued"
    else:
        next_status = "classified"

    connection.execute(
        """
        UPDATE code_files
        SET analysis_status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (next_status, engagement_id, file_id),
    )


_TRIGGER_STATUS_PENDING = "pending"
_TRIGGER_STATUS_QUEUED = "queued"
_TRIGGER_STATUS_RESOLVED = "resolved"


def _trigger_status_for_file(connection, engagement_id: int, file_id: int) -> str:
    file_row = _get_file_rows(connection, engagement_id, {file_id})[file_id]
    queue_rows = connection.execute(
        """
        SELECT status, COUNT(*) AS total
        FROM code_analysis_queue
        WHERE engagement_id = ? AND file_id = ?
        GROUP BY status
        """,
        (engagement_id, file_id),
    ).fetchall()
    queue_counts = {str(row["status"]): int(row["total"]) for row in queue_rows}
    if (
        queue_counts.get("pending", 0) > 0
        or queue_counts.get("processing", 0) > 0
        or queue_counts.get("needs_context", 0) > 0
        or str(file_row.get("analysis_status", "")) in {"queued", "in_progress", "needs_context"}
    ):
        return _TRIGGER_STATUS_QUEUED
    if (
        queue_counts.get("done", 0) > 0
        or str(file_row.get("analysis_status", "")) in {"analyzed", "done"}
    ):
        return _TRIGGER_STATUS_RESOLVED
    return _TRIGGER_STATUS_PENDING


def _sync_trigger_status_for_file(connection, engagement_id: int, file_id: int) -> None:
    file_row = _get_file_rows(connection, engagement_id, {file_id})[file_id]
    next_status = _trigger_status_for_file(connection, engagement_id, file_id)
    connection.execute(
        """
        UPDATE code_analysis_triggers
        SET target_file_id = ?,
            status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ?
          AND (
              target_file_id = ?
              OR (
                  target_file_id IS NULL
                  AND target_file_path = ?
                  AND source_file_id IN (
                      SELECT id
                      FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
              )
          )
        """,
        (
            file_id,
            next_status,
            engagement_id,
            file_id,
            str(file_row["file_path"]),
            engagement_id,
            int(file_row["repo_id"]),
        ),
    )


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
        connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, language, repo_path,
                total_files, analyzable_files, total_loc,
                commit_hash, branch, git_churn_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, repo_key) DO UPDATE SET
                name = excluded.name,
                language = excluded.language,
                repo_path = excluded.repo_path,
                total_files = excluded.total_files,
                analyzable_files = excluded.analyzable_files,
                total_loc = excluded.total_loc,
                commit_hash = excluded.commit_hash,
                branch = excluded.branch,
                git_churn_json = excluded.git_churn_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                engagement.id, repo_key, name, language, repo_path,
                total_files, analyzable_files, total_loc,
                commit_hash, branch, _json_text(git_churn),
            ),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND repo_key = ?",
            (engagement.id, repo_key),
        ).fetchone()
        assert row is not None
        return _hydrate_code_repo(row)


def list_code_repos(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC",
            (engagement.id,),
        ).fetchall()
        return [_hydrate_code_repo(row) for row in rows]


def get_code_repo(engagement_id: int, repo_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return _hydrate_code_repo(row)


_CODE_REPO_ALLOWED_FIELDS = frozenset({
    "name", "language", "repo_path", "analysis_status",
    "lsp_config_json",
})


def update_code_repo(
    engagement_id: int,
    repo_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_repo(engagement_id, repo_id)

    json_object_fields = {"lsp_config_json"}
    set_clauses = []
    params: list[Any] = []
    for key, value in kwargs.items():
        if key not in _CODE_REPO_ALLOWED_FIELDS:
            continue
        if key in json_object_fields:
            set_clauses.append(f"{key} = ?")
            params.append(_json_text(value))
        else:
            set_clauses.append(f"{key} = ?")
            params.append(value)

    if not set_clauses:
        return get_code_repo(engagement_id, repo_id)

    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([engagement.id, repo_id])

    with get_connection() as connection:
        connection.execute(
            f"UPDATE code_repos SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return _hydrate_code_repo(row)


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
        _get_repo_row(connection, engagement.id, repo_id)
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
    module_id: int | None = None,
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
    if module_id is not None:
        clauses.append("module_id = ?")
        params.append(module_id)
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
        return [_hydrate_code_file(row) for row in connection.execute(query, tuple(params)).fetchall()]


def get_code_file(engagement_id: int, file_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_files WHERE engagement_id = ? AND id = ?",
            (engagement.id, file_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
    return _hydrate_code_file(row)


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
    return _hydrate_code_file(row)


# =========================================================================
# Module Management
# =========================================================================

def bulk_create_code_modules(
    engagement_id: int,
    repo_id: int,
    modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    created: list[int] = []
    with get_connection() as connection:
        _get_repo_row(connection, engagement.id, repo_id)
        repo_files = connection.execute(
            """
            SELECT id, file_path
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ?
            """,
            (engagement.id, repo_id),
        ).fetchall()
        file_by_path = {str(row["file_path"]): int(row["id"]) for row in repo_files}
        repo_file_ids = {int(row["id"]) for row in repo_files}

        for m in modules:
            connection.execute(
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
            module_id = int(row["id"])
            created.append(module_id)

            selected_ids: set[int] = set()
            for file_id in m.get("file_ids", []):
                selected_ids.add(int(file_id))
            for file_path in m.get("files", []):
                if file_path not in file_by_path:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
                selected_ids.add(file_by_path[file_path])
            if not selected_ids.issubset(repo_file_ids):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")

            if selected_ids:
                keep_placeholders = ",".join("?" for _ in selected_ids)
                connection.execute(
                    f"""
                    UPDATE code_files
                    SET module_id = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND module_id = ? AND id NOT IN ({keep_placeholders})
                    """,
                    (engagement.id, module_id, *sorted(selected_ids)),
                )
                assign_placeholders = ",".join("?" for _ in selected_ids)
                connection.execute(
                    f"""
                    UPDATE code_files
                    SET module_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND repo_id = ? AND id IN ({assign_placeholders})
                    """,
                    (module_id, engagement.id, repo_id, *sorted(selected_ids)),
                )
            else:
                connection.execute(
                    """
                    UPDATE code_files
                    SET module_id = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND module_id = ?
                    """,
                    (engagement.id, module_id),
                )

        repo_module_ids = [
            int(row["id"])
            for row in connection.execute(
                "SELECT id FROM code_modules WHERE engagement_id = ? AND repo_id = ?",
                (engagement.id, repo_id),
            ).fetchall()
        ]
        for module_id in repo_module_ids:
            file_count = _scalar_row(
                connection,
                "SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND module_id = ?",
                (engagement.id, module_id),
            )
            critical_file_count = _scalar_row(
                connection,
                """
                SELECT COUNT(*)
                FROM code_files
                WHERE engagement_id = ? AND module_id = ? AND classification = 'critical'
                """,
                (engagement.id, module_id),
            )
            connection.execute(
                """
                UPDATE code_modules
                SET file_count = ?, critical_file_count = ?, updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (file_count, critical_file_count, engagement.id, module_id),
            )

        rows = []
        for module_id in created:
            row = connection.execute(
                "SELECT * FROM code_modules WHERE engagement_id = ? AND id = ?",
                (engagement.id, module_id),
            ).fetchone()
            assert row is not None
            rows.append(dict(row))
    return rows


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
# Analysis Queue
# =========================================================================

def bulk_create_queue_items(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = 0
    with get_connection() as connection:
        _get_file_rows(connection, engagement.id, {int(item["file_id"]) for item in items})

        for item in items:
            priority = max(0, min(100, int(item.get("priority", 50))))
            file_id = int(item["file_id"])

            batch_theme = item.get("batch_theme", "")
            slot_types_json = _json_list_text(item.get("slot_types"))
            guidance_hypotheses_json = _json_list_text(item.get("guidance_hypotheses"))

            cursor = connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority,
                    batch_theme, slot_types_json, guidance_hypotheses_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    file_id,
                    priority,
                    batch_theme,
                    slot_types_json,
                    guidance_hypotheses_json,
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
                _sync_file_analysis_status(connection, engagement.id, file_id)
                _sync_trigger_status_for_file(connection, engagement.id, file_id)
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
        if not rows:
            return []

        file_rows = _get_file_rows(connection, engagement.id, {int(row["file_id"]) for row in rows})
        repo_rows = _get_repo_rows(connection, engagement.id, {int(file_rows[int(row["file_id"])]["repo_id"]) for row in rows})

        for file_id in {int(row["file_id"]) for row in rows}:
            _sync_file_analysis_status(connection, engagement.id, file_id)
        payload: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["batch_theme"] = item.get("batch_theme", "")
            item["slot_types"] = _json_decode(item.get("slot_types_json"), [])
            item["guidance_hypotheses"] = _json_decode(item.get("guidance_hypotheses_json"), [])
            item["file"] = _hydrate_code_file(file_rows[int(row["file_id"])])
            item["repo"] = _hydrate_code_repo(repo_rows[int(file_rows[int(row["file_id"])]["repo_id"])])
            payload.append(item)
    return payload


def _normalize_cwe_coverage(cwe_coverage: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not isinstance(cwe_coverage, list) or not cwe_coverage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cwe_coverage is required when completing a queue item",
        )
    normalized: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    for idx, entry in enumerate(cwe_coverage):
        if not isinstance(entry, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cwe_coverage entry {idx} must be an object",
            )
        family = str(entry.get("family", "")).strip()
        if not family:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cwe_coverage entry {idx} is missing family",
            )
        if family in seen_families:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Duplicate cwe_coverage family '{family}'",
            )
        seen_families.add(family)
        normalized_entry = dict(entry)
        normalized_entry["family"] = family
        normalized.append(normalized_entry)
    return normalized


def _validate_completion_coverage(file_row: dict[str, Any], cwe_coverage: list[dict[str, Any]]) -> None:
    classification = str(file_row.get("classification", ""))
    slot_types = _json_decode(file_row.get("slot_types_json"), [])
    language = str(file_row.get("language", ""))

    if classification in {"critical", "high"} and not slot_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot complete {classification} file {file_row['file_path']} without slot_types; "
                "classification metadata is incomplete"
            ),
        )

    applicable = _applicable_families_for_slots(slot_types, language)
    if classification in {"critical", "high"} and not applicable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot complete {classification} file {file_row['file_path']} without "
                "applicable vulnerability families"
            ),
        )

    provided = {str(entry.get("family", "")) for entry in cwe_coverage}
    missing = [family for family in applicable if family not in provided]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Missing cwe_coverage families for {file_row['file_path']}: "
                + ", ".join(missing)
            ),
        )


def _normalize_cross_file_triggers(
    cross_file_triggers: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not cross_file_triggers:
        return []
    normalized_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for idx, trigger in enumerate(cross_file_triggers):
        if not isinstance(trigger, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} must be an object",
            )
        file_path = str(trigger.get("file_path", "")).strip()
        vuln_class = str(trigger.get("vuln_class", "")).strip()
        reason = str(trigger.get("reason", "")).strip()
        if not file_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing file_path",
            )
        if not vuln_class:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing vuln_class",
            )
        if not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing reason",
            )
        normalized = dict(trigger)
        normalized["file_path"] = file_path
        normalized["vuln_class"] = vuln_class
        normalized["reason"] = reason
        normalized_by_key[(file_path, vuln_class)] = normalized
    return list(normalized_by_key.values())


def _record_cross_file_triggers(
    connection,
    engagement_id: int,
    *,
    source_queue_item_id: int | None,
    source_file_id: int,
    cross_file_triggers: list[dict[str, Any]],
) -> None:
    if not cross_file_triggers:
        return
    source_file_row = _get_file_rows(connection, engagement_id, {source_file_id})[source_file_id]
    source_repo_id = int(source_file_row["repo_id"])
    for trigger in cross_file_triggers:
        target_file_path = str(trigger["file_path"])
        vuln_class = str(trigger["vuln_class"])
        reason = str(trigger["reason"])
        target_row = connection.execute(
            """
            SELECT id
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND file_path = ?
            """,
            (engagement_id, source_repo_id, target_file_path),
        ).fetchone()
        target_file_id = int(target_row["id"]) if target_row is not None else None
        trigger_status = (
            _trigger_status_for_file(connection, engagement_id, target_file_id)
            if target_file_id is not None
            else _TRIGGER_STATUS_PENDING
        )

        if target_file_id is not None:
            existing = connection.execute(
                """
                SELECT id
                FROM code_analysis_triggers
                WHERE engagement_id = ? AND target_file_id = ? AND vuln_class = ?
                """,
                (engagement_id, target_file_id, vuln_class),
            ).fetchone()
        else:
            existing = connection.execute(
                """
                SELECT id
                FROM code_analysis_triggers
                WHERE engagement_id = ? AND source_file_id = ? AND target_file_id IS NULL
                  AND target_file_path = ? AND vuln_class = ?
                """,
                (engagement_id, source_file_id, target_file_path, vuln_class),
            ).fetchone()

        resolution_note = ""
        if trigger_status == _TRIGGER_STATUS_QUEUED:
            resolution_note = "Target file already queued or in progress"
        elif trigger_status == _TRIGGER_STATUS_RESOLVED:
            resolution_note = "Target file already analyzed"

        if existing is None:
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_queue_item_id, source_file_id, target_file_id,
                    target_file_path, vuln_class, reason, status, resolution_note
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    source_queue_item_id,
                    source_file_id,
                    target_file_id,
                    target_file_path,
                    vuln_class,
                    reason,
                    trigger_status,
                    resolution_note,
                ),
            )
            continue

        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET source_queue_item_id = ?,
                source_file_id = ?,
                target_file_id = ?,
                target_file_path = ?,
                vuln_class = ?,
                reason = ?,
                status = ?,
                resolution_note = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (
                source_queue_item_id,
                source_file_id,
                target_file_id,
                target_file_path,
                vuln_class,
                reason,
                trigger_status,
                resolution_note,
                engagement_id,
                int(existing["id"]),
            ),
        )


_VALID_DISPOSITIONS = frozenset({"finding", "suspicious", "clean"})


def complete_queue_items(
    engagement_id: int,
    item_ids: list[int],
    disposition: str,
    notes: str = "",
    cwe_coverage: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    if len(item_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="complete_queue_items accepts exactly one queue item per call",
        )
    if disposition not in _VALID_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid disposition '{disposition}'. Must be one of: {', '.join(sorted(_VALID_DISPOSITIONS))}",
        )
    now = _now_iso()
    normalized_cwe_coverage = _normalize_cwe_coverage(cwe_coverage)
    cwe_coverage_text = _json_list_text(normalized_cwe_coverage)
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        queue_row = next(iter(queue_rows.values()))
        file_row = _get_file_rows(connection, engagement.id, {int(queue_row["file_id"])})[
            int(queue_row["file_id"])
        ]
        _validate_completion_coverage(file_row, normalized_cwe_coverage)
        next_status = "done"
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = ?,
                disposition = ?,
                analysis_notes = ?,
                cwe_coverage_json = ?,
                completed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id IN ({placeholders})
            """,
            (next_status, disposition, notes, cwe_coverage_text, now, engagement.id, *item_ids),
        )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
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
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
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
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
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
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
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
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def reset_stale_queue_items(
    engagement_id: int,
    minutes: int,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        stale_rows = connection.execute(
            """
            SELECT id, file_id
            FROM code_analysis_queue
            WHERE engagement_id = ?
              AND status = 'processing'
              AND (consumed_at < datetime('now', ? || ' minutes') OR consumed_at IS NULL)
            """,
            (engagement.id, f"-{minutes}"),
        ).fetchall()
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
        for row in stale_rows:
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
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
        queue_item_id = result.get("queue_item_id")
        file_row = _get_file_rows(connection, engagement.id, {int(result["file_id"])})[
            int(result["file_id"])
        ]
        normalized_cross_file_triggers = _normalize_cross_file_triggers(result.get("cross_file_triggers"))

        if queue_item_id is not None:
            queue_row = _get_queue_rows(connection, engagement.id, {int(queue_item_id)})[
                int(queue_item_id)
            ]
            if int(queue_row["file_id"]) != int(file_row["id"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Analysis result file/context references do not match the queue item",
                )

        cursor = connection.execute(
            """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, file_id,
                agent_name, function_name, hypothesis, evidence,
                disposition, confidence, finding_slug, cwe_id,
                slot_type, notes, audit_metadata_json,
                cwe_coverage_json, cross_file_triggers_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                queue_item_id,
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
                _json_text(result.get("audit_metadata")),
                _json_list_text(result.get("cwe_coverage")),
                _json_list_text(normalized_cross_file_triggers),
            ),
        )
        row = _analysis_result_row(connection, int(cursor.lastrowid))
        assert row is not None
        _record_cross_file_triggers(
            connection,
            engagement.id,
            source_queue_item_id=int(queue_item_id) if queue_item_id is not None else None,
            source_file_id=int(file_row["id"]),
            cross_file_triggers=normalized_cross_file_triggers,
        )
        _sync_file_analysis_status(connection, engagement.id, int(file_row["id"]))
        return _hydrate_code_analysis_result(row)


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
    query = f"""
        SELECT
            results.*,
            findings.status AS finding_status
        FROM code_analysis_results AS results
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = results.engagement_id
         AND findings.slug = results.finding_slug
        WHERE {' AND '.join(f'results.{clause}' for clause in clauses)}
        ORDER BY results.id DESC
    """
    with get_connection() as connection:
        return [_hydrate_code_analysis_result(row) for row in connection.execute(query, tuple(params)).fetchall()]


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
        _get_repo_row(connection, engagement.id, repo_id)
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
    return _hydrate_code_repo(row)


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

        # -- Findings summary (from assessment_findings where canonical_location starts with 'file:') --
        total_code_findings = _scalar_row(
            connection,
            """
            SELECT COUNT(*)
            FROM assessment_findings
            WHERE engagement_id = ?
              AND canonical_location LIKE 'file:%'
              AND status NOT IN ('merged', 'false_positive')
            """,
            (engagement.id,),
        )
        severity_rows = connection.execute(
            """
            SELECT severity, COUNT(*) AS total
            FROM assessment_findings
            WHERE engagement_id = ?
              AND canonical_location LIKE 'file:%'
              AND status NOT IN ('merged', 'false_positive')
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
            (
                "SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = ? AND status = 'needs_context'"
                if repo_id is None
                else """
                SELECT COUNT(*)
                FROM code_analysis_queue
                WHERE engagement_id = ? AND status = 'needs_context'
                  AND file_id IN (
                      SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ?
                  )
                """
            ),
            (engagement.id,) if repo_id is None else (engagement.id, engagement.id, repo_id),
        )
        unresolved_active_queue = _scalar_row(
            connection,
            (
                "SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = ? AND status IN ('pending', 'processing')"
                if repo_id is None
                else """
                SELECT COUNT(*)
                FROM code_analysis_queue
                WHERE engagement_id = ? AND status IN ('pending', 'processing')
                  AND file_id IN (
                      SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ?
                  )
                """
            ),
            (engagement.id,) if repo_id is None else (engagement.id, engagement.id, repo_id),
        )
        trigger_rows = connection.execute(
            (
                """
                SELECT status, COUNT(*) AS total
                FROM code_analysis_triggers
                WHERE engagement_id = ?
                GROUP BY status
                """
                if repo_id is None
                else """
                SELECT t.status, COUNT(*) AS total
                FROM code_analysis_triggers t
                JOIN code_files sf
                  ON sf.id = t.source_file_id
                 AND sf.engagement_id = t.engagement_id
                WHERE t.engagement_id = ? AND sf.repo_id = ?
                GROUP BY t.status
                """
            ),
            (engagement.id,) if repo_id is None else (engagement.id, repo_id),
        ).fetchall()
        trigger_counts: dict[str, int] = {}
        for row in trigger_rows:
            trigger_counts[str(row["status"])] = int(row["total"])
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
    if unresolved_active_queue > 0:
        gate_reasons.append(
            f"Queue items still pending or processing: {unresolved_active_queue}"
        )
    if trigger_counts.get(_TRIGGER_STATUS_PENDING, 0) > 0:
        gate_reasons.append(
            f"Unprocessed cross-file triggers: {trigger_counts[_TRIGGER_STATUS_PENDING]}"
        )

    # -- Effort-threshold gate (blocking for critical/high files) --
    effort_warnings: list[str] = []
    with get_connection() as connection:
        effort_file_rows = connection.execute(
            f"""
            SELECT f.id AS file_id, f.file_path, f.classification, f.analysis_status, f.slot_types_json,
                   f.language, q.cwe_coverage_json
            FROM code_files f
            LEFT JOIN code_analysis_queue q ON q.file_id = f.id AND q.engagement_id = f.engagement_id AND q.status = 'done'
            WHERE f.engagement_id = ? AND f.classification IN ('critical', 'high'){repo_clause}
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        # Accumulate max effort per family per file
        file_efforts: dict[int, dict[str, float]] = {}
        file_meta: dict[int, dict[str, Any]] = {}
        for erow in effort_file_rows:
            fid = int(erow["file_id"])
            if fid not in file_meta:
                file_meta[fid] = {
                    "file_path": erow["file_path"],
                    "classification": erow["classification"],
                    "analysis_status": erow["analysis_status"] or "",
                    "has_done_item": False,
                    "slot_types": _json_decode(erow["slot_types_json"], []),
                    "language": erow["language"] or "",
                }
            if erow["cwe_coverage_json"] is not None:
                file_meta[fid]["has_done_item"] = True
            cwe_cov = _json_decode(erow["cwe_coverage_json"], [])
            if fid not in file_efforts:
                file_efforts[fid] = {}
            for entry in cwe_cov:
                family = entry.get("family", "")
                effort = float(entry.get("effort", 0))
                if family and effort > file_efforts[fid].get(family, 0):
                    file_efforts[fid][family] = effort

        for fid, meta in file_meta.items():
            threshold = 70 if meta["classification"] == "critical" else 50
            slot_types = meta["slot_types"]
            if not slot_types:
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "missing slot_types"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            applicable = _applicable_families_for_slots(slot_types, meta.get("language", ""))
            if not applicable:
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "no applicable vulnerability families"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            efforts = file_efforts.get(fid, {})
            if not efforts:
                if meta["analysis_status"] not in {"analyzed", "done"} and not meta["has_done_item"]:
                    continue
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "analyzed but missing CWE coverage data"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            for family in applicable:
                if efforts.get(family, 0) < threshold:
                    msg = (
                        f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                        f"family '{family}' effort {efforts.get(family, 0):.0f} < {threshold}"
                    )
                    gate_reasons.append(msg)
                    effort_warnings.append(msg)
                    break  # One reason per file is enough

    gate_passed = len(gate_reasons) == 0

    return {
        "total_files": total_files,
        "by_classification": by_classification,
        "by_status": by_status,
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
            "active_queue_items": unresolved_active_queue,
            "unprocessed_triggers": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "skip_reasons": skip_reasons,
        },
        "trigger_summary": {
            "pending": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "queued": trigger_counts.get(_TRIGGER_STATUS_QUEUED, 0),
            "resolved": trigger_counts.get(_TRIGGER_STATUS_RESOLVED, 0),
        },
        "gate": {
            "passed": gate_passed,
            "reasons": gate_reasons,
            "effort_warnings": effort_warnings,
        },
    }


# =========================================================================
# Slot-to-vuln-class mapping (mirrors agent CLI SLOT_VULN_CLASSES)
# =========================================================================

SLOT_VULN_CLASSES: dict[str, dict[str, list[str]]] = {
    "NETWORK-INPUT": {
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "ssrf", "open-redirect", "path-traversal"],
    },
    "PROTOCOL-FIELD": {
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "race-condition"],
    },
    "URL-COMPONENT": {"all": ["injection", "auth-bypass", "ssrf", "open-redirect", "web-app-auth"]},
    "FILE-CONTENT": {"all": ["injection", "buffer-overflow", "type-confusion", "path-traversal", "xxe", "file-upload"]},
    "CMD-ARGUMENT": {"all": ["injection", "format-string", "path-traversal"]},
    "CALLBACK-DATA": {"all": ["use-after-free", "race-condition", "type-confusion", "deserialization"]},
    "ENV-VARIABLE": {"all": ["injection", "path-traversal"]},
    "_crypto": {"all": ["crypto-misuse"]},
    "_auth": {"all": ["auth-bypass", "web-app-auth"]},
    "_error": {"all": ["error-handling"]},
}


NATIVE_LANGUAGES = frozenset({"c", "c++", "cpp"})


def _applicable_families_for_slots(slot_types: list[str], language: str = "") -> list[str]:
    """Compute the set of applicable vuln families from a list of slot types.

    When *language* is known, only include families for the matching language
    group (native for C/C++, managed for everything else).  When unknown,
    include all groups as a conservative fallback.
    """
    lang_lower = language.lower().strip()
    is_native = lang_lower in NATIVE_LANGUAGES
    lang_known = bool(lang_lower)

    families: set[str] = set()
    for slot in slot_types:
        mapping = SLOT_VULN_CLASSES.get(slot, {})
        for group, group_families in mapping.items():
            if group == "all":
                families.update(group_families)
            elif group == "native" and (is_native or not lang_known):
                families.update(group_families)
            elif group == "managed" and (not is_native or not lang_known):
                families.update(group_families)
    return sorted(families)


# =========================================================================
# Requeue triggered files
# =========================================================================

def requeue_triggered_files(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create new queue items for triggered files (cross-file analysis triggers).

    Each item must have at least ``file_path`` (or ``file_id``).  Optional
    fields: ``priority``, ``batch_theme``, ``slot_types``,
    ``guidance_hypotheses``.
    """
    engagement = _engagement_or_404(engagement_id)
    inserted = 0
    not_found: list[str] = []
    ambiguous: list[str] = []
    already_queued = 0
    already_completed = 0
    with get_connection() as connection:
        aggregated: dict[int, dict[str, Any]] = {}
        for item in items:
            raw_file_id = item.get("file_id")
            raw_file_path = str(item.get("file_path", "")).strip()
            repo_id = item.get("repo_id")

            file_id: int | None
            if raw_file_id is not None:
                row = connection.execute(
                    "SELECT id FROM code_files WHERE engagement_id = ? AND id = ?",
                    (engagement.id, int(raw_file_id)),
                ).fetchone()
                if row is None:
                    not_found.append(str(raw_file_id))
                    continue
                file_id = int(row["id"])
            elif raw_file_path:
                rows = connection.execute(
                    (
                        "SELECT id FROM code_files WHERE engagement_id = ? AND file_path = ?"
                        if repo_id is None
                        else "SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ? AND file_path = ?"
                    ),
                    (engagement.id, raw_file_path)
                    if repo_id is None
                    else (engagement.id, int(repo_id), raw_file_path),
                ).fetchall()
                if not rows:
                    not_found.append(raw_file_path)
                    continue
                if len(rows) > 1:
                    ambiguous.append(raw_file_path)
                    continue
                file_id = int(rows[0]["id"])
            else:
                continue

            bucket = aggregated.setdefault(
                file_id,
                {
                    "priority": 0,
                    "batch_theme": "cross-file-trigger",
                    "slot_types": [],
                    "guidance_hypotheses": [],
                },
            )
            bucket["priority"] = max(
                int(bucket["priority"]),
                max(0, min(100, int(item.get("priority", 50)))),
            )
            batch_theme = str(item.get("batch_theme", "")).strip()
            if batch_theme:
                bucket["batch_theme"] = batch_theme

            existing_slots = {str(slot) for slot in bucket["slot_types"]}
            for slot in item.get("slot_types") or []:
                slot_name = str(slot).strip()
                if slot_name and slot_name not in existing_slots:
                    bucket["slot_types"].append(slot_name)
                    existing_slots.add(slot_name)

            guidance = list(item.get("guidance_hypotheses") or [])
            reason = item.get("reason", "")
            trigger_ctx = item.get("trigger_context")
            if reason or trigger_ctx:
                hint: dict[str, Any] = {"source": "cross_file_trigger"}
                if reason:
                    hint["reason"] = reason
                if isinstance(trigger_ctx, dict):
                    hint.update(trigger_ctx)
                guidance.append(hint)

            bucket_guidance = bucket["guidance_hypotheses"]
            existing_guidance = {
                json.dumps(entry, sort_keys=True, default=str)
                for entry in bucket_guidance
            }
            for entry in guidance:
                signature = json.dumps(entry, sort_keys=True, default=str)
                if signature in existing_guidance:
                    continue
                bucket_guidance.append(entry)
                existing_guidance.add(signature)

        for file_id, item in aggregated.items():
            current_status = _trigger_status_for_file(connection, engagement.id, file_id)
            if current_status == _TRIGGER_STATUS_RESOLVED:
                already_completed += 1
                _sync_trigger_status_for_file(connection, engagement.id, file_id)
                continue
            if current_status == _TRIGGER_STATUS_QUEUED:
                already_queued += 1
                _sync_trigger_status_for_file(connection, engagement.id, file_id)
                continue

            cursor = connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority,
                    batch_theme, slot_types_json, guidance_hypotheses_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    file_id,
                    int(item["priority"]),
                    str(item["batch_theme"]),
                    _json_list_text(item["slot_types"]),
                    _json_list_text(item["guidance_hypotheses"]),
                ),
            )
            if cursor.rowcount > 0:
                inserted += 1
                _sync_file_analysis_status(connection, engagement.id, file_id)
                _sync_trigger_status_for_file(connection, engagement.id, file_id)
    return {
        "inserted": inserted,
        "total": len(items),
        "not_found": not_found,
        "ambiguous": ambiguous,
        "already_queued": already_queued,
        "already_completed": already_completed,
    }


# =========================================================================
# CWE Coverage Detail
# =========================================================================

def code_coverage_cwe_detail(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> dict[str, Any]:
    """Return per-file coverage with accumulated CWE coverage from queue done
    records, plus applicable_families computed from file slot_types."""
    engagement = _engagement_or_404(engagement_id)

    repo_clause = ""
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = " AND f.repo_id = ?"
        repo_params = (repo_id,)

    with get_connection() as connection:
        # Fetch critical/high files with their slot_types
        file_rows = connection.execute(
            f"""
            SELECT f.id AS file_id, f.file_path, f.classification, f.slot_types_json,
                   f.analysis_status, f.loc, f.language
            FROM code_files f
            WHERE f.engagement_id = ? AND f.classification IN ('critical', 'high'){repo_clause}
            ORDER BY f.analysis_priority DESC, f.id ASC
            """,
            (engagement.id, *repo_params),
        ).fetchall()

        # Fetch all done queue items for these files to accumulate cwe_coverage
        file_ids = [int(r["file_id"]) for r in file_rows]
        cwe_by_file: dict[int, dict[str, dict[str, Any]]] = {}  # file_id -> family -> merged entry
        if file_ids:
            placeholders = ",".join("?" for _ in file_ids)
            queue_done_rows = connection.execute(
                f"""
                SELECT file_id, cwe_coverage_json
                FROM code_analysis_queue
                WHERE engagement_id = ? AND status = 'done' AND file_id IN ({placeholders})
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for qr in queue_done_rows:
                fid = int(qr["file_id"])
                cwe_cov = _json_decode(qr["cwe_coverage_json"], [])
                if fid not in cwe_by_file:
                    cwe_by_file[fid] = {}
                for entry in cwe_cov:
                    family = entry.get("family", "")
                    if not family:
                        continue
                    existing = cwe_by_file[fid].get(family)
                    if existing is None:
                        cwe_by_file[fid][family] = dict(entry)
                    else:
                        # Max-effort merge
                        if float(entry.get("effort", 0)) > float(existing.get("effort", 0)):
                            existing["effort"] = entry["effort"]
                        # Sum entry_chains_traced (approximates union across passes)
                        existing_chains = int(existing.get("entry_chains_traced", 0))
                        new_chains = int(entry.get("entry_chains_traced", 0))
                        existing["entry_chains_traced"] = existing_chains + new_chains
                        # Max for functions_analyzed and total_entry_chains
                        for merge_key in ("functions_analyzed", "total_entry_chains"):
                            new_val = int(entry.get(merge_key, 0))
                            old_val = int(existing.get(merge_key, 0))
                            if new_val > old_val:
                                existing[merge_key] = new_val
                        # Keep latest non-empty notes
                        new_notes = entry.get("notes", "")
                        if new_notes:
                            existing["notes"] = new_notes

        files_detail: list[dict[str, Any]] = []
        for fr in file_rows:
            fid = int(fr["file_id"])
            slot_types = _json_decode(fr["slot_types_json"], [])
            applicable = _applicable_families_for_slots(slot_types, fr["language"] or "")
            merged_entries = list(cwe_by_file.get(fid, {}).values())
            files_detail.append({
                "file_id": fid,
                "file_path": fr["file_path"],
                "classification": fr["classification"],
                "analysis_status": fr["analysis_status"],
                "loc": int(fr["loc"]),
                "slot_types": slot_types,
                "applicable_families": applicable,
                "cwe_coverage": merged_entries,
            })

        # Also include the standard coverage summary fields
        summary = code_coverage_summary(engagement_id, repo_id=repo_id)

    return {
        "files": files_detail,
        "total_files": summary["total_files"],
        "by_classification": summary["by_classification"],
        "by_status": summary["by_status"],
        "gate": summary["gate"],
    }
