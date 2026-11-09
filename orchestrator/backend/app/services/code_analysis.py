from __future__ import annotations

import difflib
import hashlib
import json
import re
import sqlite3
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status

from ..code_snapshot import (
    SOURCE_MANIFEST_VERSION,
    SnapshotAttestationError,
    VerifiedSnapshotAttestation,
    attest_verified_snapshot,
    source_manifest_digest,
)
from ..db import get_connection
from . import code_fuzz_completion
from .code_analysis_support import (
    ANALYSIS_REPO_ROLE,
    DEFAULT_VARIANT_RECEIPT_PAGE,
    MAX_ADOPTED_LEASE_CHAIN,
    MAX_OPEN_LEASE_ROWS,
    MAX_PROGRESS_RECEIPTS,
    MAX_VARIANT_RECEIPT_PAGE,
    STRUCTURAL_INDEX_SCHEMA,
    VARIANT_INPUT_IDENTITY_SCHEMA as VARIANT_INPUT_IDENTITY_SCHEMA,
    _CANONICAL_STRUCTURAL_LANGUAGES as _CANONICAL_STRUCTURAL_LANGUAGES,
    _CURRENT_ACCOUNTED_FILE_EXISTS_SQL,
    _CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL,
    CURRENT_ANALYSIS_STATUSES,
    _LEAD_OPEN_STATUS_PLACEHOLDERS,
    _LEAD_OPEN_STATUS_VALUES,
    _queue_lane_sql,
    _REPORTABLE_FINDING_STATUSES,
    _TERMINAL_TRIGGER_RESOLUTION_STATUSES,
    _TRIGGER_STATUSES,
    _TRIGGER_STATUS_EXTERNAL_CONTEXT,
    _TRIGGER_STATUS_NOT_APPLICABLE,
    _TRIGGER_STATUS_PENDING,
    _TRIGGER_STATUS_QUEUED,
    _TRIGGER_STATUS_RESOLVED,
    _TRIGGER_STATUS_SOURCE_EQUIVALENT,
    _analysis_repo_files_sql,
    _analysis_repo_sql,
    _analysis_result_row,
    _attempt_lease_tokens,
    _bind_legacy_analysis_results,
    _canonical_queue_attempt_state,
    _canonical_structural_callables,
    _coerce_float,
    _coerce_int,
    _awaiting_verdict_column_sql,
    awaiting_verdict_attempt_ids,
    _current_analysis_results_sql,
    _current_attempt_result_count_sql,
    _current_result_receipt_sql,
    _current_analysis_status_sql,
    _current_suspicious_analysis_counts,
    _fetch_all,
    _file_path_scope_sql,
    _finding_snapshot_repo_id,
    _get_file_rows,
    _get_published_repo_row,
    _get_queue_rows,
    _get_repo_row_raw,
    _get_repo_rows,
    _has_current_successful_review,
    _hydrate_code_analysis_result,
    _hydrate_code_file,
    _hydrate_code_repo,
    _invalid_active_history_exists_sql,
    _is_cwe_entry_not_applicable,
    _json_decode,
    _json_list_text,
    _json_text,
    _latest_current_queue_attempt_sql,
    canonical_current_attempt_sql,
    queue_file_repo_join_sql,
    _lease_activity_age_seconds_sql,
    _lease_activity_sql,
    _merge_cwe_coverage_entries,
    _merge_file_effort_entry,
    _no_superseded_active_attempt_sql,
    _normalize_analysis_receipt_anchors,
    _normalize_variant_evidence_ref,
    _normalized_variant_language,
    _now_iso,
    _QUEUE_ACTIVE_STATUSES,
    _reject_unknown_fields,
    _require_reportable_root_file_finding,
    _require_queue_generation,
    _require_queue_lease,
    _require_queue_status,
    _require_strict_positive_id,
    _REPLACED_BY_RESULT_ID_SQL,
    _result_not_replaced_sql,
    _safe_int,
    _scalar_row,
    _structural_debt_sql,
    _successful_terminal_review_row_sql,
    _sync_file_analysis_status,
    _sync_module_rollup,
    _sync_trigger_status_for_file,
    canonical_structural_language,
    code_track_enabled,
    register_path_scope_functions,
    structural_index_state,
    structural_input_identity_digest,
    function_callable_link_sql,
    structural_review_gaps,
    variant_input_identity_digest,
)
from .events import _engagement_or_404
from .state_manager.finding_snapshots import (
    resolve_snapshot_location,
    snapshot_location_problem,
)
from .state_manager.findings import (
    finding_code_snapshot_status,
    is_file_finding,
    load_code_repo_snapshot_states,
)
from .state_manager.taxonomy_bridge import vuln_taxonomy
from .state_manager import run_accounting
from .variant_scopes import (
    MAX_VARIANT_PARENT_FINDINGS,
    VARIANT_DISPATCH_ROLE as _VARIANT_DISPATCH_ROLE,
    variant_parent_finding_set_digest as _variant_parent_finding_set_digest,
)

from .code_analysis_support import (
    require_current_source_binding,
    CODE_REPO_ROLES as CODE_REPO_ROLES,
    REFERENCE_REPO_ROLE as REFERENCE_REPO_ROLE,
    STRUCTURAL_CALLABLE_IDENTITY_SCHEMA as STRUCTURAL_CALLABLE_IDENTITY_SCHEMA,
    STRUCTURAL_INPUT_IDENTITY_SCHEMA as STRUCTURAL_INPUT_IDENTITY_SCHEMA,
)
from .sql_like import like_contains

# =========================================================================
# Repository Management
# =========================================================================

def verified_snapshot_identity_problem(repo: dict[str, Any]) -> str | None:
    """The refusal a declared `verified` source snapshot earns, or None.

    One implementation of the rule, enforced twice: the request model raises it
    as a 422 for HTTP callers and this module raises it as a 400 for every
    other entry into the refresh. A snapshot that is not declared verified has
    no identity obligation and so no problem.
    """
    if repo.get("source_snapshot_quality") != "verified":
        return None
    missing = sorted(
        field_name
        for field_name in ("source_origin_path", "snapshot_manifest_path", "snapshot_digest")
        if not repo.get(field_name)
    )
    if repo.get("source_kind") not in {"git", "directory"}:
        missing.append("source_kind")
    if repo.get("source_kind") == "git" and repo.get("worktree_dirty") is None:
        missing.append("worktree_dirty")
    if missing:
        return (
            "verified source snapshot is missing identity fields: "
            + ", ".join(sorted(set(missing)))
        )
    snapshot_digest = str(repo["snapshot_digest"])
    if len(snapshot_digest) != 64 or any(
        char not in "0123456789abcdef" for char in snapshot_digest
    ):
        return "snapshot_digest must be a lowercase SHA-256 digest"
    return None


def start_code_repo_refresh(engagement_id: int, repo: dict[str, Any]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    identity_problem = verified_snapshot_identity_problem(repo)
    if identity_problem is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=identity_problem,
        )
    refresh_token = str(uuid.uuid4())
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND repo_key = ?",
            (engagement.id, repo["repo_key"]),
        ).fetchone()
        if row is None:
            cursor = connection.execute(
                """
                INSERT INTO code_repos (
                    engagement_id, repo_key, name, language, repo_path,
                    commit_hash, branch, pending_refresh_token, pending_refresh_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id, repo["repo_key"], repo["name"], repo.get("language", ""),
                    repo["repo_path"], repo.get("commit_hash", ""), repo.get("branch", ""),
                    refresh_token, _json_text(repo),
                ),
            )
            repo_id = int(cursor.lastrowid)
        else:
            repo_id = int(row["id"])
            old_token = str(row["pending_refresh_token"] or "")
            if old_token:
                connection.execute(
                    "DELETE FROM code_ingest_staging WHERE repo_id = ? AND refresh_token = ?",
                    (repo_id, old_token),
                )
            connection.execute(
                """
                UPDATE code_repos
                SET pending_refresh_token = ?, pending_refresh_json = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (refresh_token, _json_text(repo), engagement.id, repo_id),
            )
    return {"repo_id": repo_id, "refresh_token": refresh_token}


def _normalized_file_manifest_record(record: Any) -> dict[str, Any]:
    record = dict(record)
    return {
        "file_hash": str(record.get("file_hash", "") or ""),
        "language": str(record.get("language", "") or ""),
        "loc": int(record.get("loc", 0) or 0),
        "header_snippet": str(record.get("header_snippet", "") or ""),
        "git_churn_score": int(record.get("git_churn_score", 0) or 0),
        "has_past_cve_fix": bool(record.get("has_past_cve_fix")),
    }


def preview_code_repo_refresh(
    engagement_id: int, *, repo_key: str, files: list[dict[str, Any]]
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    incoming = {str(row["file_path"]): row for row in files}
    with get_connection() as connection:
        repo = connection.execute(
            "SELECT id FROM code_repos WHERE engagement_id = ? AND repo_key = ?",
            (engagement.id, repo_key),
        ).fetchone()
        if repo is None:
            return {"added": sorted(incoming), "changed": [], "renamed": [], "removed": [], "unchanged": []}
        rows = connection.execute(
            """
            SELECT file_path, file_hash, language, loc, header_snippet,
                   git_churn_score, has_past_cve_fix
            FROM code_files WHERE engagement_id = ? AND repo_id = ?
              AND retired_at IS NULL
            """,
            (engagement.id, int(repo["id"])),
        ).fetchall()
    existing = {str(row["file_path"]): _normalized_file_manifest_record(row) for row in rows}
    normalized_incoming = {
        path: _normalized_file_manifest_record(record) for path, record in incoming.items()
    }
    changed = sorted(
        path for path in set(existing) & set(incoming)
        if existing[path] != normalized_incoming[path]
    )
    unchanged = sorted((set(existing) & set(incoming)) - set(changed))
    removed = set(existing) - set(incoming)
    added = set(incoming) - set(existing)
    removed_by_hash: dict[str, list[str]] = {}
    added_by_hash: dict[str, list[str]] = {}
    for path in removed:
        removed_by_hash.setdefault(str(existing[path]["file_hash"]), []).append(path)
    for path in added:
        added_by_hash.setdefault(str(normalized_incoming[path]["file_hash"]), []).append(path)
    renamed: list[dict[str, str]] = []
    for file_hash, old_paths in removed_by_hash.items():
        new_paths = added_by_hash.get(file_hash, [])
        if file_hash and len(old_paths) == 1 and len(new_paths) == 1:
            renamed.append({"from": old_paths[0], "to": new_paths[0], "file_hash": file_hash})
            removed.discard(old_paths[0])
            added.discard(new_paths[0])
    return {
        "added": sorted(added), "changed": changed,
        "renamed": sorted(renamed, key=lambda row: (row["from"], row["to"])),
        "removed": sorted(removed), "unchanged": unchanged,
    }


def stage_code_repo_refresh_files(
    engagement_id: int, repo_id: int, *, refresh_token: str, files: list[dict[str, Any]]
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_repo_row_raw(connection, engagement.id, repo_id)
        if str(repo.get("pending_refresh_token", "")) != refresh_token:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="repo refresh token is stale")
        for file_record in files:
            # The staged record IS the repository manifest, and `code-index
            # sync` binds the structural index from every file's language at
            # once, so one non-canonical value here refuses the WHOLE
            # repository later. The staged record is also attested
            # byte-for-byte against the sealed manifest at commit
            # (`VerifiedSnapshotAttestation.assert_staged_inventory`), so the
            # exact spelling the snapshot sealed is what has to be canonical:
            # folding one into shape would only move the refusal to the commit
            # door and report it there as metadata drift.
            _require_canonical_language(
                str(file_record.get("language", "") or ""),
                file_label=str(file_record["file_path"]),
            )
            connection.execute(
                """
                INSERT INTO code_ingest_staging (
                    engagement_id, repo_id, refresh_token, file_path, file_json
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(repo_id, refresh_token, file_path)
                DO UPDATE SET file_json = excluded.file_json
                """,
                (engagement.id, repo_id, refresh_token, file_record["file_path"], _json_text(file_record)),
            )
    return {"staged": len(files)}


def _invalidate_file_analysis(connection, engagement_id: int, file_id: int) -> None:
    """Reset current file state without erasing generation-bound audit history."""
    connection.execute(
        """
        UPDATE code_analysis_results
        SET superseded_at = COALESCE(superseded_at, ?)
        WHERE engagement_id = ? AND file_id = ?
        """,
        (_now_iso(), engagement_id, file_id),
    )
    connection.execute(
        """
        UPDATE code_files
        SET classification = 'unclassified', role = '', slot_types_json = '[]',
            analysis_priority = 0, analysis_status = 'pending', analysis_depth = 'none',
            skip_reason = '', variant_check_status = 'pending', module_id = NULL,
            notes = '', total_functions = 0, total_entry_points = 0,
            total_sinks = 0, total_exports = 0,
            structural_analysis_status = 'pending', structural_analysis_mode = '',
            structural_degradation_reason = '', structural_source_size = 0,
            structural_bytes_scanned = 0,
            structural_unavailable_dimensions_json = '[]',
            structural_artifact_truncated = 0,
            structural_truncated_dimensions_json = '[]',
            structural_signal_counts_json = '{}'
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, file_id),
    )


def _invalidate_repo_structural_index(connection, engagement_id: int, repo_id: int) -> None:
    """Discard parser- and language-dependent facts for an entire repository."""
    connection.execute(
        """
        UPDATE code_files
        SET total_functions = 0, total_entry_points = 0, total_sinks = 0,
            total_exports = 0, structural_analysis_status = 'pending',
            structural_analysis_mode = '', structural_degradation_reason = '',
            structural_source_size = 0, structural_bytes_scanned = 0,
            structural_unavailable_dimensions_json = '[]',
            structural_artifact_truncated = 0,
            structural_truncated_dimensions_json = '[]',
            structural_signal_counts_json = '{}', updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND repo_id = ?
        """,
        (engagement_id, repo_id),
    )
    connection.execute(
        """
        UPDATE code_repos
        SET structural_index_schema = '', structural_index_generation = NULL,
            structural_index_manifest_path = '',
            structural_degraded_files = 0,
            structural_degraded_file_paths_json = '[]',
            structural_artifact_truncated_files = 0,
            structural_artifact_truncated_file_paths_json = '[]',
            structural_analysis_status_counts_json = '{}', lsp_config_json = '{}',
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, repo_id),
    )


_METADATA_REFRESH_REVIEW_THEME = "metadata-refresh-review"
# Hand one claimed row back to the unleased pending rotation: clear ownership,
# the adoption chain and the claim timestamps, and re-read the file's current
# analysis_priority -- except on a metadata-refresh row, whose priority belongs
# to the refresh lane and not to the file's review ranking. The one bound
# parameter is `_METADATA_REFRESH_REVIEW_MODE`, and it is first in the
# parameter tuple at every site that applies this clause.
_RETURN_TO_PENDING_SET_SQL = """status = 'pending', assigned_agent = '', lease_token = '',
                adopted_leases_json = '[]',
                consumed_at = NULL, last_heartbeat_at = NULL,
                priority = CASE
                    WHEN queue_mode = ? THEN priority
                    ELSE COALESCE((
                        SELECT files.analysis_priority
                        FROM code_files AS files
                        WHERE files.engagement_id = code_analysis_queue.engagement_id
                          AND files.id = code_analysis_queue.file_id
                    ), priority)
                END"""


_METADATA_REFRESH_REVIEW_MODE = "metadata-refresh"
_SOURCE_GENERATION_REPLACED_REASON = "source_generation_replaced"


def _record_source_generation(
    connection,
    *,
    engagement_id: int,
    repo_id: int,
    previous_generation: int,
    repo_generation: int,
    metadata: dict[str, Any],
    source_manifest_version: str,
    source_manifest_digest_value: str,
    source_review_identity_digest: str,
    staged_paths: set[str],
) -> None:
    promoted_at = _now_iso()
    if previous_generation > 0:
        connection.execute(
            """
            UPDATE code_source_generations
            SET source_superseded_at = ?,
                source_supersession_reason = ?,
                replacement_repo_generation = ?
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
              AND source_superseded_at IS NULL
            """,
            (
                promoted_at,
                _SOURCE_GENERATION_REPLACED_REASON,
                repo_generation,
                engagement_id,
                repo_id,
                previous_generation,
            ),
        )
        for table_name in ("code_analysis_queue", "code_analysis_results"):
            connection.execute(
                f"""
                UPDATE {table_name}
                SET source_superseded_at = ?,
                    source_supersession_reason = ?,
                    replacement_repo_generation = ?
                WHERE engagement_id = ? AND repo_generation = ?
                  AND file_id IN (
                      SELECT id FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
                  AND source_superseded_at IS NULL
                """,
                (
                    promoted_at,
                    _SOURCE_GENERATION_REPLACED_REASON,
                    repo_generation,
                    engagement_id,
                    previous_generation,
                    engagement_id,
                    repo_id,
                ),
            )
        connection.execute(
            """
            UPDATE code_analysis_results
            SET superseded_at = COALESCE(superseded_at, ?)
            WHERE engagement_id = ? AND repo_generation = ?
              AND file_id IN (
                  SELECT id FROM code_files
                  WHERE engagement_id = ? AND repo_id = ?
              )
            """,
            (
                promoted_at,
                engagement_id,
                previous_generation,
                engagement_id,
                repo_id,
            ),
        )
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET source_superseded_at = ?,
                source_supersession_reason = ?,
                replacement_repo_generation = ?
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
              AND source_superseded_at IS NULL
            """,
            (
                promoted_at,
                _SOURCE_GENERATION_REPLACED_REASON,
                repo_generation,
                engagement_id,
                repo_id,
                previous_generation,
            ),
        )

    connection.execute(
        """
        INSERT INTO code_source_generations (
            engagement_id, repo_id, repo_generation,
            source_manifest_version, source_manifest_digest,
            source_review_identity_digest, snapshot_manifest_path,
            snapshot_digest, source_snapshot_quality, repo_path,
            source_origin_path, source_kind, commit_hash, branch,
            worktree_dirty, promoted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            repo_id,
            repo_generation,
            source_manifest_version,
            source_manifest_digest_value,
            source_review_identity_digest,
            str(metadata.get("snapshot_manifest_path") or ""),
            str(metadata.get("snapshot_digest") or ""),
            str(metadata.get("source_snapshot_quality") or "legacy-unverified"),
            str(metadata.get("repo_path") or ""),
            str(metadata.get("source_origin_path") or metadata.get("repo_path") or ""),
            str(metadata.get("source_kind") or "legacy"),
            str(metadata.get("commit_hash") or ""),
            str(metadata.get("branch") or ""),
            (
                1
                if metadata.get("worktree_dirty") is True
                else 0
                if metadata.get("worktree_dirty") is False
                else None
            ),
            promoted_at,
        ),
    )
    if not staged_paths:
        _rebase_lead_bindings(
            connection,
            engagement_id=engagement_id,
            repo_id=repo_id,
            previous_generation=previous_generation,
            repo_generation=repo_generation,
            promoted_at=promoted_at,
        )
        return
    placeholders = ",".join("?" for _ in staged_paths)
    file_rows = connection.execute(
        f"""
        SELECT id, file_path, file_hash, language, loc, header_snippet,
               git_churn_score, has_past_cve_fix
        FROM code_files
        WHERE engagement_id = ? AND repo_id = ?
          AND retired_at IS NULL
          AND file_path IN ({placeholders})
        ORDER BY file_path
        """,
        (engagement_id, repo_id, *sorted(staged_paths)),
    ).fetchall()
    if len(file_rows) != len(staged_paths):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="source generation file identity changed before promotion",
        )
    connection.executemany(
        """
        INSERT INTO code_source_generation_files (
            engagement_id, repo_id, repo_generation, file_id, file_path,
            file_hash, language, loc, header_snippet, git_churn_score,
            has_past_cve_fix
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                engagement_id,
                repo_id,
                repo_generation,
                int(row["id"]),
                str(row["file_path"]),
                str(row["file_hash"]),
                str(row["language"]),
                int(row["loc"]),
                str(row["header_snippet"]),
                int(row["git_churn_score"]),
                int(row["has_past_cve_fix"]),
            )
            for row in file_rows
        ],
    )
    _rebase_lead_bindings(
        connection,
        engagement_id=engagement_id,
        repo_id=repo_id,
        previous_generation=previous_generation,
        repo_generation=repo_generation,
        promoted_at=promoted_at,
    )


def _rebase_lead_bindings(
    connection,
    *,
    engagement_id: int,
    repo_id: int,
    previous_generation: int,
    repo_generation: int,
    promoted_at: str,
) -> None:
    """Carry a lead's file/line binding across a generation, or stale it.

    A binding is a pointer into specific bytes. When the new generation holds
    that exact file content, the pointer is still exactly right and moves
    forward untouched; when the content changed — or the file left the
    repository — the line numbers become a guess, so the row is stamped
    superseded and has to be re-read and re-bound before it is trusted again.
    Unlike a queue row, it is never discharged: the lead keeps owing an answer
    either way (see ``_unresolved_code_lead_rows``).
    """
    if previous_generation <= 0:
        return
    connection.execute(
        """
        UPDATE code_lead_bindings
        SET repo_generation = ?, updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
          AND unbound_at IS NULL AND source_superseded_at IS NULL
          AND EXISTS (
            SELECT 1 FROM code_source_generation_files AS generation_files
            WHERE generation_files.engagement_id = code_lead_bindings.engagement_id
              AND generation_files.repo_id = code_lead_bindings.repo_id
              AND generation_files.repo_generation = ?
              AND generation_files.file_id = code_lead_bindings.file_id
              AND generation_files.file_hash = code_lead_bindings.file_hash
          )
        """,
        (
            repo_generation,
            engagement_id,
            repo_id,
            previous_generation,
            repo_generation,
        ),
    )
    connection.execute(
        """
        UPDATE code_lead_bindings
        SET source_superseded_at = ?,
            source_supersession_reason = ?,
            replacement_repo_generation = ?
        WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
          AND unbound_at IS NULL AND source_superseded_at IS NULL
        """,
        (
            promoted_at,
            _SOURCE_GENERATION_REPLACED_REASON,
            repo_generation,
            engagement_id,
            repo_id,
            previous_generation,
        ),
    )


def _has_current_file_analysis_activity(
    connection,
    engagement_id: int,
    file_id: int,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE queue.engagement_id = ? AND queue.file_id = ?
          AND queue.repo_generation = repos.active_generation
          AND queue.source_superseded_at IS NULL
        LIMIT 1
        """,
        (engagement_id, file_id),
    ).fetchone()
    return row is not None


def _reopen_file_metadata_review(
    connection,
    engagement_id: int,
    file_row: dict[str, Any],
    *,
    invalidate_architecture: bool,
) -> None:
    """Retire stale conclusions while preserving them as non-covering history."""
    file_id = int(file_row["id"])
    prior_priority = int(file_row.get("analysis_priority", 0) or 0)
    if prior_priority <= 0:
        row = connection.execute(
            "SELECT MAX(priority) AS priority FROM code_analysis_queue WHERE engagement_id = ? AND file_id = ?",
            (engagement_id, file_id),
        ).fetchone()
        prior_priority = int(row["priority"] or 50) if row is not None else 50
    review_priority = max(0, min(100, prior_priority))
    superseded_at = _now_iso()
    connection.execute(
        """
        UPDATE code_analysis_results
        SET superseded_at = ?
        WHERE engagement_id = ? AND file_id = ? AND superseded_at IS NULL
        """,
        (superseded_at, engagement_id, file_id),
    )
    connection.execute(
        "DELETE FROM code_analysis_triggers WHERE engagement_id = ? AND source_file_id = ?",
        (engagement_id, file_id),
    )
    connection.execute(
        """
        UPDATE code_analysis_triggers
        SET status = CASE
                WHEN status IN (?, ?, ?) THEN status ELSE 'pending' END,
            resolved_queue_item_id = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ?
          AND (
              target_file_id = ?
              OR (
                  target_file_id IS NULL
                  AND target_file_path = ?
                  AND source_file_id IN (
                      SELECT id FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
              )
          )
        """,
        (
            *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
            engagement_id,
            file_id,
            str(file_row["file_path"]),
            engagement_id,
            int(file_row["repo_id"]),
        ),
    )
    connection.execute(
        """
        UPDATE code_analysis_queue
        SET status = 'done', disposition = 'superseded',
            cwe_coverage_json = '[]', cross_file_triggers_json = '[]',
            guidance_hypotheses_json = '[]', completed_at = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND file_id = ?
        """,
        (superseded_at, engagement_id, file_id),
    )
    architecture_fields = (
        "role = '', slot_types_json = '[]', module_id = NULL," if invalidate_architecture else ""
    )
    connection.execute(
        f"""
        UPDATE code_files
        SET classification = 'unclassified', {architecture_fields}
            analysis_priority = 0, analysis_status = 'pending',
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, file_id),
    )
    # Retiring the stale conclusions above is right for any repository; opening
    # a fresh review is not. `POST /analysis-queue` and `requeue` both refuse to
    # create work in a reference repository, and this third insert has to refuse
    # for the same reason -- a role read straight from the row it selects from,
    # so a demoted repository cannot gain a claimable row from a churn update.
    connection.execute(
        f"""
        INSERT INTO code_analysis_queue (
            engagement_id, file_id, priority, status, batch_theme,
            slot_types_json, guidance_hypotheses_json, repo_generation, queue_mode
        )
        SELECT ?, ?, ?, 'pending', ?, '[]', '[]', active_generation, ?
        FROM code_repos
        WHERE engagement_id = ? AND id = ?
          AND {_analysis_repo_sql("code_repos")}
        """,
        (
            engagement_id,
            file_id,
            review_priority,
            _METADATA_REFRESH_REVIEW_THEME,
            _METADATA_REFRESH_REVIEW_MODE,
            engagement_id,
            int(file_row["repo_id"]),
        ),
    )
    _sync_trigger_status_for_file(connection, engagement_id, file_id)


def _sync_metadata_review_queue_identity(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    priority: int | None = None,
) -> None:
    priority_assignment = "priority = ?," if priority is not None else ""
    params: list[Any] = []
    if priority is not None:
        params.append(priority)
    params.extend(
        [
            engagement_id,
            file_id,
            engagement_id,
            file_id,
            _METADATA_REFRESH_REVIEW_MODE,
        ]
    )
    connection.execute(
        f"""
        UPDATE code_analysis_queue
        SET {priority_assignment}
            slot_types_json = COALESCE((
                SELECT slot_types_json
                FROM code_files
                WHERE engagement_id = ? AND id = ?
            ), '[]'),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = (
            SELECT MAX(id)
            FROM code_analysis_queue
            WHERE engagement_id = ? AND file_id = ?
              AND queue_mode = ? AND status = 'pending'
        )
        """,
        tuple(params),
    )


def _staged_refresh_inventory(
    connection, engagement_id: int, repo_id: int, refresh_token: str
) -> dict[str, Any]:
    """The staged file inventory this refresh token carries, keyed by path."""
    return {
        str(row["file_path"]): _json_decode(row["file_json"], {})
        for row in connection.execute(
            """
            SELECT file_path, file_json FROM code_ingest_staging
            WHERE engagement_id = ? AND repo_id = ? AND refresh_token = ?
            ORDER BY file_path
            """,
            (engagement_id, repo_id, refresh_token),
        ).fetchall()
    }


def commit_code_repo_refresh(
    engagement_id: int, repo_id: int, *, refresh_token: str, manifest_complete: bool
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = changed = renamed = retired_count = unchanged = 0
    attestation: VerifiedSnapshotAttestation | None = None
    try:
        # Hash and validate the sealed tree before taking SQLite's global write
        # reservation. The returned proof keeps pinned engagement/snapshot/source
        # descriptors live; the write transaction below rechecks the token,
        # staged inventory, and every filesystem identity before it can commit.
        with get_connection() as connection:
            claimed_repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(claimed_repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            claimed_metadata = _json_decode(
                claimed_repo.get("pending_refresh_json"), {}
            )
        requested_quality = str(
            claimed_metadata.get(
                "source_snapshot_quality",
                claimed_repo.get("source_snapshot_quality", "legacy-unverified"),
            )
            or "legacy-unverified"
        )
        if requested_quality == "verified":
            attestation = attest_verified_snapshot(
                engagement_root=engagement.engagement_root,
                metadata={**claimed_repo, **claimed_metadata},
            )

        # First reconcile the staged inventory against the live attestation
        # without a writer reservation. A second exact read under BEGIN
        # IMMEDIATE below is the CAS that authorizes promotion.
        with get_connection() as connection:
            repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            staged = _staged_refresh_inventory(
                connection, engagement.id, repo_id, refresh_token
            )
            if not manifest_complete:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="repo refresh manifest is incomplete",
                )
            metadata = _json_decode(repo.get("pending_refresh_json"), {})
            if metadata != claimed_metadata:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh metadata changed during snapshot attestation",
                )
            # Persisted quality is derived from backend proof, never copied from
            # the caller's assertion. Legacy/unverified refreshes remain supported
            # but continue to fail the later source-integrity readiness gate.
            metadata = dict(metadata)
            metadata["source_snapshot_quality"] = (
                "verified" if attestation is not None else "legacy-unverified"
            )
            if attestation is not None:
                attestation.assert_staged_inventory(staged, metadata)

        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            live_metadata = _json_decode(repo.get("pending_refresh_json"), {})
            if live_metadata != claimed_metadata:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh metadata changed during snapshot attestation",
                )
            live_staged = _staged_refresh_inventory(
                connection, engagement.id, repo_id, refresh_token
            )
            if live_staged != staged:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh staged inventory changed during snapshot attestation",
                )
            metadata = dict(live_metadata)
            metadata["source_snapshot_quality"] = (
                "verified" if attestation is not None else "legacy-unverified"
            )
            staged = live_staged
            if attestation is not None:
                attestation.assert_staged_inventory(staged, metadata)
            manifest_version = str(
                metadata.get(
                    "source_manifest_version",
                    repo.get("source_manifest_version", SOURCE_MANIFEST_VERSION),
                )
                or SOURCE_MANIFEST_VERSION
            )
            manifest_digest = source_manifest_digest(staged.values(), version=manifest_version)
            # An ingest that does not name a role keeps the one already
            # recorded, so re-ingesting a reference repository after an upstream
            # update cannot silently re-arm its coverage obligation.
            repo_role = str(
                metadata.get("repo_role")
                or repo.get("repo_role")
                or ANALYSIS_REPO_ROLE
            )
            current_generation = int(repo.get("active_generation", 0) or 0)
            incoming_snapshot_digest = str(
                metadata.get("snapshot_digest", repo.get("snapshot_digest", "")) or ""
            )
            incoming_snapshot_quality = str(
                metadata.get(
                    "source_snapshot_quality",
                    repo.get("source_snapshot_quality", "legacy-unverified"),
                )
                or "legacy-unverified"
            )
            incoming_review_identity_digest = (
                attestation.review_identity_digest
                if attestation is not None
                else incoming_snapshot_digest
            )
            stored_review_identity_digest = str(
                repo.get("source_review_identity_digest") or ""
            )
            stored_snapshot_digest = str(repo.get("snapshot_digest") or "")
            stored_snapshot_quality = str(
                repo.get("source_snapshot_quality") or "legacy-unverified"
            )
            # The review-identity column was introduced additively and is empty on
            # upgraded rows. Seed it without reopening work only when a verified
            # refresh proves the exact previously stored snapshot. If the full
            # snapshot digest differs, legacy state cannot distinguish a benign
            # provenance change from an exclusion-boundary change, so advance the
            # generation conservatively.
            seeds_legacy_review_identity = (
                not stored_review_identity_digest
                and current_generation > 0
                and attestation is not None
                and incoming_snapshot_quality == "verified"
                and stored_snapshot_quality == "verified"
                and bool(incoming_snapshot_digest)
                and incoming_snapshot_digest == stored_snapshot_digest
                and manifest_digest
                == str(repo.get("source_manifest_digest", "") or "")
            )
            source_review_identity_changed = (
                incoming_review_identity_digest != stored_review_identity_digest
                and not seeds_legacy_review_identity
            )
            snapshot_trust_boundary_changed = (
                incoming_snapshot_quality != stored_snapshot_quality
            )
            generation_changed = (
                current_generation == 0
                or manifest_digest != str(repo.get("source_manifest_digest", "") or "")
                or source_review_identity_changed
                or snapshot_trust_boundary_changed
            )
            repo_generation = current_generation + 1 if generation_changed else current_generation
            all_existing_rows = connection.execute(
                "SELECT * FROM code_files WHERE engagement_id = ? AND repo_id = ?",
                (engagement.id, repo_id),
            ).fetchall()
            all_existing = {
                str(row["file_path"]): dict(row) for row in all_existing_rows
            }
            existing_rows = [row for row in all_existing_rows if row["retired_at"] is None]
            existing = {str(row["file_path"]): dict(row) for row in existing_rows}
            retired_paths = set(all_existing) - set(existing)

            missing_paths = set(existing) - set(staged)
            new_paths = set(staged) - set(existing)
            missing_by_hash: dict[str, list[str]] = {}
            new_by_hash: dict[str, list[str]] = {}
            for path in missing_paths:
                missing_by_hash.setdefault(str(existing[path].get("file_hash", "")), []).append(path)
            for path in new_paths:
                new_by_hash.setdefault(str(staged[path].get("file_hash", "")), []).append(path)
            renamed_old: set[str] = set()
            renamed_new: set[str] = set()
            for file_hash, old_paths in missing_by_hash.items():
                new_matches = new_by_hash.get(file_hash, [])
                if not file_hash or len(old_paths) != 1 or len(new_matches) != 1:
                    continue
                old_path, new_path = old_paths[0], new_matches[0]
                if new_path in retired_paths:
                    continue
                record = staged[new_path]
                file_id = int(existing[old_path]["id"])
                _invalidate_file_analysis(connection, engagement.id, file_id)
                connection.execute(
                    """
                    UPDATE code_files SET file_path = ?, language = ?, loc = ?, file_hash = ?,
                        header_snippet = ?, git_churn_score = ?, has_past_cve_fix = ?,
                        retired_at = NULL, retirement_reason = NULL,
                        replacement_repo_generation = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ?
                    """,
                    (
                        new_path, record.get("language", ""), record.get("loc", 0), file_hash,
                        record.get("header_snippet", ""), record.get("git_churn_score", 0),
                        1 if record.get("has_past_cve_fix") else 0, engagement.id, file_id,
                    ),
                )
                renamed_old.add(old_path)
                renamed_new.add(new_path)
                renamed += 1

            for path, record in staged.items():
                if path in renamed_new:
                    continue
                current = existing.get(path)
                if current is None:
                    retired = all_existing.get(path)
                    if retired is None:
                        connection.execute(
                            """
                            INSERT INTO code_files (
                                engagement_id, repo_id, file_path, language, loc, file_hash,
                                header_snippet, git_churn_score, has_past_cve_fix
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                engagement.id, repo_id, path, record.get("language", ""),
                                record.get("loc", 0), record.get("file_hash", ""),
                                record.get("header_snippet", ""),
                                record.get("git_churn_score", 0),
                                1 if record.get("has_past_cve_fix") else 0,
                            ),
                        )
                    else:
                        _invalidate_file_analysis(
                            connection, engagement.id, int(retired["id"])
                        )
                        connection.execute(
                            """
                            UPDATE code_files
                            SET language = ?, loc = ?, file_hash = ?, header_snippet = ?,
                                git_churn_score = ?, has_past_cve_fix = ?,
                                retired_at = NULL, retirement_reason = NULL,
                                replacement_repo_generation = NULL,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE engagement_id = ? AND id = ?
                            """,
                            (
                                record.get("language", ""), record.get("loc", 0),
                                record.get("file_hash", ""),
                                record.get("header_snippet", ""),
                                record.get("git_churn_score", 0),
                                1 if record.get("has_past_cve_fix") else 0,
                                engagement.id, retired["id"],
                            ),
                        )
                    inserted += 1
                    continue
                content_changed = str(current.get("file_hash", "")) != str(record.get("file_hash", ""))
                language_changed = str(current.get("language", "")) != str(record.get("language", ""))
                loc_changed = int(current.get("loc", 0) or 0) != int(record.get("loc", 0) or 0)
                header_changed = str(current.get("header_snippet", "")) != str(record.get("header_snippet", ""))
                risk_metadata_changed = (
                    int(current.get("git_churn_score", 0) or 0)
                    != int(record.get("git_churn_score", 0) or 0)
                    or bool(current.get("has_past_cve_fix"))
                    != bool(record.get("has_past_cve_fix"))
                )
                if content_changed or language_changed or loc_changed:
                    _invalidate_file_analysis(connection, engagement.id, int(current["id"]))
                    connection.execute(
                        """
                        UPDATE code_files SET language = ?, loc = ?, file_hash = ?, header_snippet = ?,
                            git_churn_score = ?, has_past_cve_fix = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (
                            record.get("language", ""), record.get("loc", 0), record.get("file_hash", ""),
                            record.get("header_snippet", ""), record.get("git_churn_score", 0),
                            1 if record.get("has_past_cve_fix") else 0, engagement.id, current["id"],
                        ),
                    )
                    changed += 1
                else:
                    # Metadata-only review reopening and a wholly unchanged file
                    # write the same row; only the reopen and which counter the
                    # file lands in differ.
                    if header_changed or risk_metadata_changed:
                        _reopen_file_metadata_review(
                            connection,
                            engagement.id,
                            current,
                            invalidate_architecture=header_changed,
                        )
                        changed += 1
                    else:
                        unchanged += 1
                    connection.execute(
                        """
                        UPDATE code_files SET language = ?, loc = ?, header_snippet = ?,
                            git_churn_score = ?, has_past_cve_fix = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (
                            record.get("language", ""), record.get("loc", 0), record.get("header_snippet", ""),
                            record.get("git_churn_score", 0), 1 if record.get("has_past_cve_fix") else 0,
                            engagement.id, current["id"],
                        ),
                    )

            for path in missing_paths - renamed_old:
                file_id = int(existing[path]["id"])
                prior_module_id = existing[path].get("module_id")
                _invalidate_file_analysis(connection, engagement.id, file_id)
                connection.execute(
                    """
                    UPDATE code_files
                    SET retired_at = ?, retirement_reason = ?,
                        replacement_repo_generation = ?, module_id = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ?
                    """,
                    (
                        _now_iso(),
                        _SOURCE_GENERATION_REPLACED_REASON,
                        repo_generation,
                        engagement.id,
                        file_id,
                    ),
                )
                if prior_module_id is not None:
                    _sync_module_rollup(
                        connection, engagement.id, int(prior_module_id)
                    )
                retired_count += 1

            if generation_changed:
                connection.execute(
                    """
                    UPDATE code_files
                    SET analysis_status = CASE
                            WHEN classification = 'unclassified' THEN 'pending'
                            ELSE 'classified'
                        END,
                        variant_check_status = 'pending',
                        structural_analysis_status = 'pending', structural_analysis_mode = '',
                        structural_degradation_reason = '', structural_source_size = 0,
                        structural_bytes_scanned = 0,
                        structural_unavailable_dimensions_json = '[]',
                        structural_artifact_truncated = 0,
                        structural_truncated_dimensions_json = '[]',
                        structural_signal_counts_json = '{}'
                    WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
                    """,
                    (engagement.id, repo_id),
                )
                _record_source_generation(
                    connection,
                    engagement_id=engagement.id,
                    repo_id=repo_id,
                    previous_generation=current_generation,
                    repo_generation=repo_generation,
                    metadata=metadata,
                    source_manifest_version=manifest_version,
                    source_manifest_digest_value=manifest_digest,
                    source_review_identity_digest=incoming_review_identity_digest,
                    staged_paths=set(staged),
                )

            connection.execute(
                """
                UPDATE code_repos SET name = ?, language = ?, repo_path = ?, repo_role = ?,
                    total_files = ?,
                    analyzable_files = ?, total_loc = ?, commit_hash = ?, branch = ?,
                    git_churn_json = ?, active_generation = ?, source_origin_path = ?,
                    source_kind = ?, snapshot_manifest_path = ?, snapshot_digest = ?,
                    source_review_identity_digest = ?, source_manifest_version = ?,
                    source_manifest_digest = ?,
                    source_snapshot_quality = ?, worktree_dirty = ?,
                    structural_index_schema = ?, structural_index_generation = ?,
                    structural_index_manifest_path = ?,
                    structural_degraded_files = ?, structural_degraded_file_paths_json = ?,
                    structural_artifact_truncated_files = ?,
                    structural_artifact_truncated_file_paths_json = ?,
                    structural_analysis_status_counts_json = ?,
                    lsp_config_json = ?,
                    pending_refresh_token = '', pending_refresh_json = '{}',
                    analysis_status = 'ingested', updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND pending_refresh_token = ?
                """,
                (
                    metadata.get("name", repo["name"]), metadata.get("language", ""),
                    metadata.get("repo_path", repo["repo_path"]), repo_role,
                    metadata.get("total_files", len(staged)),
                    metadata.get("analyzable_files", len(staged)), metadata.get("total_loc", 0),
                    metadata.get("commit_hash", ""), metadata.get("branch", ""),
                    _json_text(metadata.get("git_churn")), repo_generation,
                    metadata.get("source_origin_path", repo.get("source_origin_path") or metadata.get("repo_path", repo["repo_path"])),
                    metadata.get("source_kind", repo.get("source_kind", "legacy")),
                    metadata.get("snapshot_manifest_path", repo.get("snapshot_manifest_path", "")),
                    metadata.get("snapshot_digest", repo.get("snapshot_digest", "")),
                    incoming_review_identity_digest, manifest_version, manifest_digest,
                    metadata.get("source_snapshot_quality", repo.get("source_snapshot_quality", "legacy-unverified")),
                    (
                        1 if metadata.get("worktree_dirty") is True else 0
                        if metadata.get("worktree_dirty") is False else None
                        if "worktree_dirty" in metadata else repo.get("worktree_dirty")
                    ),
                    "" if generation_changed else repo.get("structural_index_schema", ""),
                    None if generation_changed else repo.get("structural_index_generation"),
                    "" if generation_changed else repo.get("structural_index_manifest_path", ""),
                    0 if generation_changed else repo.get("structural_degraded_files", 0),
                    "[]"
                    if generation_changed
                    else repo.get("structural_degraded_file_paths_json", "[]"),
                    0 if generation_changed else repo.get("structural_artifact_truncated_files", 0),
                    "[]"
                    if generation_changed
                    else repo.get("structural_artifact_truncated_file_paths_json", "[]"),
                    "{}"
                    if generation_changed
                    else repo.get("structural_analysis_status_counts_json", "{}"),
                    "{}" if generation_changed else repo.get("lsp_config_json", "{}"),
                    engagement.id, repo_id, refresh_token,
                ),
            )
            connection.execute(
                "DELETE FROM code_ingest_staging WHERE repo_id = ? AND refresh_token = ?",
                (repo_id, refresh_token),
            )
            for module_row in connection.execute(
                "SELECT id FROM code_modules WHERE engagement_id = ? AND repo_id = ?", (engagement.id, repo_id)
            ).fetchall():
                _sync_module_rollup(connection, engagement.id, int(module_row["id"]))
            if attestation is not None:
                attestation.verify_unchanged()
            connection.commit()
    except SnapshotAttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"verified snapshot attestation failed: {exc}",
        ) from exc
    finally:
        if attestation is not None:
            attestation.close()
    return {
        "repo_id": repo_id, "inserted": inserted, "changed": changed, "renamed": renamed,
        "retired": retired_count, "unchanged": unchanged,
        "repo_generation": repo_generation,
        "repo_role": repo_role,
        "source_manifest_version": manifest_version,
        "source_manifest_digest": manifest_digest,
        "generation_changed": generation_changed,
    }


def list_code_repos(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM code_repos
            WHERE engagement_id = ?
              AND active_generation > 0
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()
        return [_hydrate_code_repo(row) for row in rows]


def get_code_repo(engagement_id: int, repo_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = _get_published_repo_row(connection, engagement.id, repo_id)
    return _hydrate_code_repo(row)


_CODE_REPO_ALLOWED_FIELDS = frozenset({
    "name", "language", "analysis_status",
})


def update_code_repo(
    engagement_id: int,
    repo_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_repo(engagement_id, repo_id)
    _reject_unknown_fields(kwargs, _CODE_REPO_ALLOWED_FIELDS, entity_name="repo patch")

    set_clauses = []
    params: list[Any] = []
    for key, value in kwargs.items():
        set_clauses.append(f"{key} = ?")
        params.append(value)

    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([engagement.id, repo_id])

    with get_connection() as connection:
        _get_published_repo_row(connection, engagement.id, repo_id)
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


def publish_code_repo_lsp_config(
    engagement_id: int,
    repo_id: int,
    *,
    repo_generation: int,
    source_manifest_digest: str,
    lsp_config: dict[str, Any],
) -> dict[str, Any]:
    """Publish derived tooling state only for the source generation it indexed."""

    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        require_current_source_binding(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="LSP",
        )
        cursor = connection.execute(
            """
            UPDATE code_repos
            SET lsp_config_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
              AND active_generation = ? AND source_manifest_digest = ?
            """,
            (
                _json_text(lsp_config),
                engagement.id,
                repo_id,
                repo_generation,
                source_manifest_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LSP source generation changed before publication",
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


# The columns `code/files` may order by, mapped to their SQL. Closed on purpose:
# the sort reaches the ORDER BY as text, and a caller-supplied column name is
# the one place a listing could grow an injection or a silent no-op.
CODE_FILE_SORT_COLUMNS: dict[str, str] = {
    "analysis_priority": "files.analysis_priority",
    "file_path": "files.file_path",
    "loc": "files.loc",
    "git_churn_score": "files.git_churn_score",
    "id": "files.id",
}
CODE_FILE_SORT_ORDERS: tuple[str, ...] = ("asc", "desc")
# What a caller that names no sort has always received.
DEFAULT_CODE_FILE_SORT = "analysis_priority"
DEFAULT_CODE_FILE_ORDER = "desc"


def _append_optional_filters(
    clauses: list[str],
    params: list[Any],
    spec: tuple[tuple[str, Any], ...],
) -> None:
    """Append one WHERE predicate and its bound value per supplied filter.

    `spec` order is the append order, because these queries bind positionally.
    Only filters whose value is used verbatim belong here; anything that
    coerces, validates or builds a subquery stays at its own site.
    """
    for clause, value in spec:
        if value is not None:
            clauses.append(clause)
            params.append(value)


def list_code_files(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    module_id: int | None = None,
    classification: str | None = None,
    analysis_status: str | None = None,
    search: str | None = None,
    file_paths: list[str] | None = None,
    path_prefix: list[str] | None = None,
    path_glob: list[str] | None = None,
    sort: str | None = None,
    order: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    include_header_snippet: bool = False,
) -> dict[str, Any]:
    """Page the admitted file inventory.

    `path_prefix` / `path_glob` scope the page, `total` and `has_more` through
    `_file_path_scope_sql` — the same owner `fetch` claims with and
    `coverage --by-path` groups with, so a subtree wave plan read here and the
    claim that executes it cannot disagree about what the subtree holds.
    `search` stays a substring match on the whole path, which is a different
    question and keeps answering it.
    """
    engagement = _engagement_or_404(engagement_id)
    sort_key = sort or DEFAULT_CODE_FILE_SORT
    order_key = (order or DEFAULT_CODE_FILE_ORDER).lower()
    if sort_key not in CODE_FILE_SORT_COLUMNS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "sort must be one of: "
                + ", ".join(sorted(CODE_FILE_SORT_COLUMNS))
            ),
        )
    if order_key not in CODE_FILE_SORT_ORDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="order must be one of: " + ", ".join(CODE_FILE_SORT_ORDERS),
        )
    clauses = [
        "files.engagement_id = ?",
        "files.retired_at IS NULL",
        "repos.active_generation > 0",
    ]
    params: list[Any] = [engagement.id]
    _append_optional_filters(clauses, params, (
        ("files.repo_id = ?", repo_id),
        ("files.module_id = ?", module_id),
        ("files.classification = ?", classification),
        ("files.analysis_status = ?", analysis_status),
    ))
    if search is not None:
        clauses.append("files.file_path LIKE ? ESCAPE '\\'")
        params.append(like_contains(search))
    if file_paths is not None:
        clauses.append("files.file_path IN (SELECT value FROM json_each(?))")
        params.append(json.dumps(file_paths))
    path_scope, path_params = _file_path_scope_sql("files", path_prefix, path_glob)
    if path_scope:
        clauses.append(path_scope)
        params.extend(path_params)
    from_where = f"""
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id AND repos.engagement_id = files.engagement_id
        WHERE {' AND '.join(clauses)}
    """
    # `files.id ASC` stays the tiebreaker on every sort so a page is stable and
    # an offset cannot skip or repeat a row.
    query = f"""
        SELECT files.*
        {from_where}
        ORDER BY {CODE_FILE_SORT_COLUMNS[sort_key]} {order_key.upper()}, files.id ASC
    """
    if limit is not None:
        query += f" LIMIT {int(limit)}"
        if offset > 0:
            query += f" OFFSET {int(offset)}"
    with get_connection() as connection:
        register_path_scope_functions(connection)
        total = int(
            connection.execute(
                f"SELECT COUNT(*) {from_where}", tuple(params)
            ).fetchone()[0]
        )
        rows = connection.execute(query, tuple(params)).fetchall()
        file_ids = [int(row["id"]) for row in rows]
        queue_rows_by_file: dict[int, list[dict[str, Any]]] = {
            file_id: [] for file_id in file_ids
        }
        active_generation_by_file: dict[int, int] = {}
        if file_ids:
            placeholders = ",".join("?" for _ in file_ids)
            queue_rows = connection.execute(
                f"""
                SELECT queue.*, repos.active_generation
                FROM code_analysis_queue AS queue
                JOIN code_files AS files
                  ON files.id = queue.file_id
                 AND files.engagement_id = queue.engagement_id
                JOIN code_repos AS repos
                  ON repos.id = files.repo_id
                 AND repos.engagement_id = files.engagement_id
                WHERE queue.engagement_id = ?
                  AND queue.file_id IN ({placeholders})
                ORDER BY queue.id DESC
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for queue_row in queue_rows:
                file_id = int(queue_row["file_id"])
                queue_rows_by_file[file_id].append(dict(queue_row))
                active_generation_by_file[file_id] = int(
                    queue_row["active_generation"]
                )
        variant_projection = _load_variant_receipt_projection(
            connection, engagement.id, file_rows=[dict(row) for row in rows],
            restrict_to_files=True,
        )
        records: list[dict[str, Any]] = []
        for row in rows:
            file_row = dict(row)
            payload = _hydrate_code_file(file_row)
            if not include_header_snippet:
                payload.pop("header_snippet", None)
            file_id = int(file_row["id"])
            attempts = queue_rows_by_file.get(file_id, [])
            active_generation = active_generation_by_file.get(file_id)
            current = next(
                (
                    attempt
                    for attempt in attempts
                    if int(attempt["repo_generation"]) == active_generation
                ),
                None,
            )
            current_attempt = None
            if current is not None:
                current_attempt = {
                    "id": int(current["id"]),
                    "status": str(current["status"]),
                    "priority": int(current["priority"]),
                    "queue_mode": str(current.get("queue_mode") or "initial"),
                    "batch_theme": str(current.get("batch_theme") or ""),
                    "repo_generation": int(current["repo_generation"]),
                    "agent_name": str(current.get("assigned_agent") or ""),
                    "lease_token": str(current.get("lease_token") or ""),
                }
            payload["queue"] = {
                "state": (
                    "current"
                    if current_attempt is not None
                    else ("historical_only" if attempts else "none")
                ),
                "current_attempt": current_attempt,
                "historical_attempts": len(attempts) - (1 if current else 0),
            }
            payload["variant_check_status"] = _current_variant_check_status(
                connection,
                engagement.id,
                file_row,
                projection=variant_projection,
            )
            records.append(payload)
        return {
            "total": total,
            "offset": offset,
            "count": len(records),
            "has_more": offset + len(records) < total,
            "items": records,
        }


def get_code_file(engagement_id: int, file_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = _get_file_rows(connection, engagement.id, {file_id})[file_id]
        payload = _hydrate_code_file(row)
        payload["variant_check_status"] = _current_variant_check_status(
            connection,
            engagement.id,
            row,
        )
        return payload


CLASSIFICATION_PRIORITY_BANDS = {
    "critical": (80, 100),
    "high": (50, 79),
    "medium": (20, 49),
    "low": (5, 19),
    "skip": (0, 0),
}
# Per-family effort each reviewed tier is measured against. `done` already
# demands one `cwe_coverage` entry per applicable family at every tier, but an
# `effort: 0` entry satisfies that, so a tier absent from this map could close
# with a token number and nothing would say so. `low` is absent on purpose:
# build and test infrastructure is admitted and accounted, not held to a
# review-depth floor.
EFFORT_THRESHOLDS = {"critical": 70, "high": 50, "medium": 30}
# Which of those tiers the coverage gate actually REFUSES on. `effort` is a
# number the reviewing agent writes into its own `cwe_coverage` entry and
# nothing but a float parse stands behind it, so ADR 0001 decision 3 (left
# standing by ADR 0012) bars it from carrying a gate on its own: under pressure
# a hard block on self-attested signal gets gamed, forced or mass-deferred into
# false confidence. Critical and high keep refusing because that scope is what
# the dispatch contract promises and what the operator reads as the depth floor;
# every other measured tier is reported through `effort_warnings` — the harness
# channel that reaches readiness `quality_gate.warnings` and every review-quality
# rendering — and never withholds `gate.passed`. The terminal structural blocks
# (an untouched, undeferred high-value unit; `uncovered_high_risk_files`) are
# unaffected.
_BLOCKING_EFFORT_TIERS = frozenset({"critical", "high"})
_VALID_CLASSIFICATIONS = frozenset(CLASSIFICATION_PRIORITY_BANDS)
_VALID_SLOT_TYPES = frozenset({
    "NETWORK-INPUT",
    "URL-COMPONENT",
    "CMD-ARGUMENT",
    "FILE-CONTENT",
    "ENV-VARIABLE",
    "CALLBACK-DATA",
    "PROTOCOL-FIELD",
    "SERIALIZED-DATA",
    "EXEC-POLICY",
})


def _require_strict_priority(value: Any, *, field_name: str) -> int:
    if type(value) is not int:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer",
        )
    if not 0 <= value <= 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0 and 100",
        )
    return value


def _require_classification_priority(
    classification: str,
    value: Any,
    *,
    field_name: str,
) -> int:
    priority = _require_strict_priority(value, field_name=field_name)
    minimum, maximum = CLASSIFICATION_PRIORITY_BANDS[classification]
    if not minimum <= priority <= maximum:
        expected = str(minimum) if minimum == maximum else f"between {minimum} and {maximum}"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{field_name} must be {expected} when classification is "
                f"{classification}"
            ),
        )
    return priority


def _current_file_queue_attempts(
    connection, engagement_id: int, file_id: int
) -> list[dict[str, Any]]:
    """One file's current-generation queue attempts, oldest first."""
    return [
        dict(row)
        for row in connection.execute(
        """
        SELECT queue.id, queue.status, queue.assigned_agent, queue.lease_token
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE queue.engagement_id = ? AND queue.file_id = ?
          AND queue.repo_generation = repos.active_generation
          AND queue.source_superseded_at IS NULL
        ORDER BY queue.id
        """,
        (engagement_id, file_id),
        ).fetchall()
    ]


def _require_no_live_lease(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    action: str,
    current_rows: list[dict[str, Any]] | None = None,
) -> None:
    """Refuse a metadata write that would discharge work an agent still holds.

    `_reopen_file_metadata_review` closes every current queue row `done` /
    `superseded` and supersedes every receipt on the file. That is right for an
    unclaimed row and catastrophic for a live one: the holder's next heartbeat
    and every receipt it already wrote come back as "not processing" and
    "current status is done", which is exactly what a reclaim looks like. So
    every door that can reopen a review — `analysis_priority` on one side,
    the review identity (classification / role / slot_types / language) on the
    other — asks this first, and the refusal names the holder with the same
    identity `_queue_lease_mismatch` prints so the operator can find the agent
    that owns the work.

    A processing row with no recorded owner is named too: it is unclaimable and
    equally unsafe to discharge silently. Only an ACTIVE attempt can hold a live
    lease: a terminal row keeps the identity that closed it as its audit trail,
    and retiring that row is what a reopen is for.
    """
    rows = (
        _current_file_queue_attempts(connection, engagement_id, file_id)
        if current_rows is None
        else current_rows
    )
    held: list[str] = []
    for row in rows:
        if str(row["status"]) not in _QUEUE_ACTIVE_STATUSES:
            continue
        holder = str(row["assigned_agent"] or "")
        token = str(row["lease_token"] or "")
        if str(row["status"]) != "processing" and not holder and not token:
            continue
        if holder or token:
            held.append(
                f"queue item {int(row['id'])} is {row['status']} and held by "
                f"agent {holder!r} under lease {token!r}"
            )
        else:
            held.append(
                f"queue item {int(row['id'])} is processing with no recorded lease owner"
            )
    if not held:
        return
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"file {file_id} has live or inconsistently leased queue work: "
            + "; ".join(held)
            + ". Close it with `code-dispatch done`, `error` or `needs-context`, "
            "hand it to a replacement with `code-dispatch adopt-lease`, return it "
            "unclaimed with `code-dispatch release`, or discard it with "
            f"`code-dispatch reset-stale` before {action}"
        ),
    )


def _synchronize_pending_queue_priority(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    current_priority: int,
    new_priority: int,
) -> None:
    if current_priority == new_priority:
        return
    current_rows = _current_file_queue_attempts(connection, engagement_id, file_id)
    _, active_row, active_issue = _canonical_queue_attempt_state(current_rows)
    if active_issue is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"file {file_id} has {active_issue} queue history; reconcile it before "
                "changing analysis_priority"
            ),
        )
    if active_row is None:
        return
    row = active_row
    _require_no_live_lease(
        connection,
        engagement_id,
        file_id,
        action="changing analysis_priority",
        current_rows=current_rows,
    )
    cursor = connection.execute(
        """
        UPDATE code_analysis_queue
        SET priority = ?, updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ? AND status = 'pending'
          AND assigned_agent = '' AND lease_token = ''
        """,
        (new_priority, engagement_id, int(row["id"])),
    )
    if cursor.rowcount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="pending queue work changed while analysis_priority was being updated",
        )


def _normalize_slot_types(value: Any, *, field_name: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a list of slot type strings",
        )

    normalized: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for raw_slot in value:
        if not isinstance(raw_slot, str):
            invalid.append(repr(raw_slot))
            continue
        slot = raw_slot.strip()
        if slot not in _VALID_SLOT_TYPES:
            invalid.append(slot or "<empty>")
            continue
        if slot not in seen:
            normalized.append(slot)
            seen.add(slot)

    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{field_name} contains invalid values: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(sorted(_VALID_SLOT_TYPES))}"
            ),
        )
    return normalized


def _require_canonical_language(value: str, *, file_label: str) -> str:
    """Hold a classify-time language to the set the structural index can bind.

    `canonical_structural_language` runs over every file in a repository from
    `structural_input_identity_digest`, so one non-canonical value makes
    `code-index sync` refuse the WHOLE repository, unbind its structural index
    and then block every new dispatch — a failure that surfaces long after the
    classify call that caused it. Validating at the write door turns that into
    one 400 naming the file. The accepted spelling is returned unchanged rather
    than folded (`c++` stays `c++`): the alias is canonical for the index and
    the code-track family maps carry both spellings.
    """
    try:
        canonical_structural_language(value)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{file_label}: {exc.detail}. Allowed values: "
                + ", ".join(sorted(_CANONICAL_STRUCTURAL_LANGUAGES - {""}))
            ),
        ) from exc
    return value


def _require_classification_skip_reason(
    classification: str, skip_reason: str, *, field_name: str
) -> str:
    """A `skip` is an exclusion decision, so it owes one of the standard reasons.

    The close path has demanded this since C50 and accounting only admits a skip
    that carries a reason (`code_analysis_support._CURRENT_ACCOUNTED_FILE_EXISTS_SQL`).
    Classifying a file `skip` is the same decision taken earlier, so an
    unexplained one is the same unaccounted file.
    """
    if classification != "skip":
        if skip_reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"{field_name} only describes classification='skip'; "
                    f"got {skip_reason!r} on a {classification} classification"
                ),
            )
        return ""
    if skip_reason not in SKIP_REASONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{field_name} is required when classification='skip', one of: "
                + ", ".join(SKIP_REASONS)
                + (f"; got {skip_reason!r}" if skip_reason else "")
            ),
        )
    return skip_reason


def _require_slot_types_for_classification(classification: str, slot_types: list[str], *, field_name: str) -> None:
    if classification in {"critical", "high"} and not slot_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} is required for {classification} classifications",
        )


def _normalize_guidance_hypotheses(value: Any, *, field_name: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a list of strings",
        )
    normalized: list[str] = []
    for idx, raw_value in enumerate(value):
        if not isinstance(raw_value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name}[{idx}] must be a string",
            )
        normalized.append(raw_value)
    return normalized


def bulk_classify_code_files(
    engagement_id: int,
    classifications: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    submitted_file_ids = [
        _require_strict_positive_id(
            item.get("file_id"),
            field_name=f"classifications[{idx}].file_id",
        )
        for idx, item in enumerate(classifications)
    ]
    if len(submitted_file_ids) != len(set(submitted_file_ids)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="classification request contains duplicate file IDs",
        )
    updated = 0
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_rows = _get_file_rows(
            connection,
            engagement.id,
            set(submitted_file_ids),
        )
        affected_module_ids: set[int] = set()
        structurally_invalidated_repo_ids: set[int] = set()
        language_changes: list[dict[str, Any]] = []
        for idx, c in enumerate(classifications):
            file_id = submitted_file_ids[idx]
            classification = str(c.get("classification", "")).strip()
            if classification not in _VALID_CLASSIFICATIONS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"classifications[{idx}].classification must be one of: "
                        f"{', '.join(sorted(_VALID_CLASSIFICATIONS))}"
                    ),
                )
            slot_types = _normalize_slot_types(
                c.get("slot_types"),
                field_name=f"classifications[{idx}].slot_types",
            )
            _require_slot_types_for_classification(
                classification,
                slot_types,
                field_name=f"classifications[{idx}].slot_types",
            )
            role = str(c.get("role", "")).strip()
            current_file = file_rows[file_id]
            skip_reason = _require_classification_skip_reason(
                classification,
                str(c.get("skip_reason", "") or "").strip(),
                field_name=f"classifications[{idx}].skip_reason",
            )
            language = c.get("language")
            normalized_language = (
                str(current_file.get("language", ""))
                if language is None
                else _require_canonical_language(
                    str(language).strip(),
                    file_label=str(current_file["file_path"]),
                )
            )
            priority = _require_classification_priority(
                classification,
                c.get("analysis_priority"),
                field_name=f"classifications[{idx}].analysis_priority",
            )
            language_changed = normalized_language != str(current_file.get("language", ""))
            review_identity_changed = (
                classification != str(current_file.get("classification", ""))
                or role != str(current_file.get("role", ""))
                or slot_types != _json_decode(current_file.get("slot_types_json"), [])
                or language_changed
            )
            if review_identity_changed:
                _require_no_live_lease(
                    connection,
                    engagement.id,
                    file_id,
                    action=(
                        f"re-classifying classifications[{idx}] "
                        f"({current_file['file_path']})"
                    ),
                )
            review_reopened = review_identity_changed and _has_current_file_analysis_activity(
                connection,
                engagement.id,
                file_id,
            )
            _synchronize_pending_queue_priority(
                connection,
                engagement.id,
                file_id,
                current_priority=int(current_file.get("analysis_priority", 0) or 0),
                new_priority=priority,
            )
            if language_changed:
                structurally_invalidated_repo_ids.add(int(current_file["repo_id"]))
                language_changes.append(
                    {
                        "file_id": file_id,
                        "file_path": str(current_file["file_path"]),
                        "previous_language": str(current_file.get("language", "")),
                        "language": normalized_language,
                    }
                )
            if review_reopened:
                if current_file.get("module_id") is not None:
                    affected_module_ids.add(int(current_file["module_id"]))
                _reopen_file_metadata_review(
                    connection,
                    engagement.id,
                    current_file,
                    invalidate_architecture=False,
                )
            cursor = connection.execute(
                """
                UPDATE code_files
                SET classification = ?,
                    role = ?,
                    slot_types_json = ?,
                    language = ?,
                    analysis_priority = ?,
                    skip_reason = ?,
                    analysis_status = 'classified',
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (
                    classification,
                    role,
                    _json_list_text(slot_types),
                    normalized_language,
                    priority,
                    skip_reason,
                    engagement.id,
                    file_id,
                ),
            )
            if cursor.rowcount > 0:
                updated += 1
                if review_identity_changed:
                    connection.execute(
                        """
                        UPDATE code_files
                        SET variant_check_status = 'pending', updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (engagement.id, file_id),
                    )
                if review_reopened:
                    _sync_metadata_review_queue_identity(
                        connection,
                        engagement.id,
                        file_id,
                        priority=priority,
                    )
                    _sync_file_analysis_status(
                        connection,
                        engagement.id,
                        file_id,
                    )
                module_row = connection.execute(
                    "SELECT module_id FROM code_files WHERE engagement_id = ? AND id = ?",
                    (engagement.id, file_id),
                ).fetchone()
                if module_row is not None and module_row["module_id"] is not None:
                    affected_module_ids.add(int(module_row["module_id"]))
        for repo_id in structurally_invalidated_repo_ids:
            _invalidate_repo_structural_index(connection, engagement.id, repo_id)
        for module_id in affected_module_ids:
            _sync_module_rollup(connection, engagement.id, module_id)
    # A language correction discards the whole repository's parser-derived
    # facts, and nothing else in this response says so — which is why the
    # client's `code-index build` + `sync --repo-id` repair hint could never
    # fire. Reported per repository and per file so the operator can see which
    # correction cost which index.
    return {
        "updated": updated,
        "total": len(classifications),
        "structural_index_invalidated_repo_ids": sorted(structurally_invalidated_repo_ids),
        "language_changes": language_changes,
    }


_CODE_FILE_ALLOWED_FIELDS = frozenset({
    "classification", "role", "analysis_priority",
    "analysis_depth", "module_id",
    "notes", "slot_types_json", "language", "skip_reason",
})


def update_code_file(
    engagement_id: int,
    file_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_file(engagement_id, file_id)
    _reject_unknown_fields(kwargs, _CODE_FILE_ALLOWED_FIELDS, entity_name="file patch")

    set_clauses = []
    params: list[Any] = []

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_row = _get_file_rows(connection, engagement.id, {file_id})[file_id]

        normalized_kwargs = dict(kwargs)
        if "language" in normalized_kwargs:
            normalized_kwargs["language"] = _require_canonical_language(
                str(normalized_kwargs["language"]).strip(),
                file_label=str(file_row["file_path"]),
            )
        if "role" in normalized_kwargs:
            normalized_kwargs["role"] = str(normalized_kwargs["role"]).strip()
        language_changed = (
            "language" in normalized_kwargs
            and normalized_kwargs["language"] != str(file_row.get("language", ""))
        )
        if "module_id" in normalized_kwargs:
            raw_module_id = normalized_kwargs["module_id"]
            if raw_module_id in ("", None):
                normalized_kwargs["module_id"] = None
            else:
                module_id = _coerce_int(raw_module_id, field_name="module_id")
                module_row = connection.execute(
                    """
                    SELECT id
                    FROM code_modules
                    WHERE engagement_id = ? AND id = ? AND repo_id = ?
                    """,
                    (engagement.id, module_id, int(file_row["repo_id"])),
                ).fetchone()
                if module_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="module_id must reference a module in the same repo",
                    )
                normalized_kwargs["module_id"] = module_id

        if "classification" in normalized_kwargs:
            classification = str(normalized_kwargs["classification"]).strip()
            if classification not in _VALID_CLASSIFICATIONS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "classification must be one of: "
                        + ", ".join(sorted(_VALID_CLASSIFICATIONS))
                    ),
                )
            normalized_kwargs["classification"] = classification

        if "analysis_priority" in normalized_kwargs:
            normalized_kwargs["analysis_priority"] = _require_strict_priority(
                normalized_kwargs["analysis_priority"],
                field_name="analysis_priority",
            )

        if "slot_types_json" in normalized_kwargs:
            normalized_kwargs["slot_types_json"] = _normalize_slot_types(
                normalized_kwargs["slot_types_json"],
                field_name="slot_types_json",
            )

        effective_classification = str(
            normalized_kwargs.get("classification", file_row["classification"] or "")
        ).strip()
        effective_priority = normalized_kwargs.get(
            "analysis_priority",
            int(file_row.get("analysis_priority", 0) or 0),
        )
        if effective_classification in _VALID_CLASSIFICATIONS:
            effective_priority = _require_classification_priority(
                effective_classification,
                effective_priority,
                field_name="analysis_priority",
            )
        elif "classification" in normalized_kwargs or "analysis_priority" in normalized_kwargs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="classification and analysis_priority must form a valid classified pair",
            )
        effective_slot_types = (
            normalized_kwargs["slot_types_json"]
            if "slot_types_json" in normalized_kwargs
            else _json_decode(file_row["slot_types_json"], [])
        )
        _require_slot_types_for_classification(
            effective_classification,
            effective_slot_types,
            field_name="slot_types_json",
        )
        # A reason only describes a skip, so a patch that leaves the file off
        # `skip` drops the reason rather than leaving a `low` file explaining
        # why it was never reviewed. The rule is applied to the EFFECTIVE reason
        # the row is left holding, exactly as the bulk door applies it to the
        # payload it stores: a patch that does not name a reason keeps the row's
        # own, so correcting a skipped file's priority is not also a demand to
        # restate why it was skipped, but a patch that leaves the file `skip`
        # with no reason at all is the same unaccounted file bulk classify
        # refuses. A patch that NAMES a reason is held to the standard
        # vocabulary either way.
        patched_skip_reason = str(normalized_kwargs.get("skip_reason", "") or "").strip()
        effective_skip_reason = (
            patched_skip_reason
            if "skip_reason" in normalized_kwargs
            else str(file_row.get("skip_reason", "") or "").strip()
        )
        if effective_classification == "skip":
            normalized_kwargs["skip_reason"] = _require_classification_skip_reason(
                "skip", effective_skip_reason, field_name="skip_reason"
            )
        else:
            _require_classification_skip_reason(
                effective_classification, patched_skip_reason, field_name="skip_reason"
            )
            normalized_kwargs["skip_reason"] = ""
        review_identity_changed = (
            (
                "classification" in normalized_kwargs
                and normalized_kwargs["classification"]
                != str(file_row.get("classification", ""))
            )
            or (
                "role" in normalized_kwargs
                and normalized_kwargs["role"] != str(file_row.get("role", ""))
            )
            or (
                "slot_types_json" in normalized_kwargs
                and normalized_kwargs["slot_types_json"]
                != _json_decode(file_row.get("slot_types_json"), [])
            )
            or language_changed
        )
        if review_identity_changed:
            _require_no_live_lease(
                connection,
                engagement.id,
                file_id,
                action=f"changing the review identity of {file_row['file_path']}",
            )
        review_reopened = review_identity_changed and _has_current_file_analysis_activity(
            connection,
            engagement.id,
            file_id,
        )
        _synchronize_pending_queue_priority(
            connection,
            engagement.id,
            file_id,
            current_priority=int(file_row.get("analysis_priority", 0) or 0),
            new_priority=int(effective_priority),
        )

        # Reopening first retires the old semantic receipt and resets derived
        # review state. Restore the complete effective identity so a partial
        # PATCH cannot accidentally erase a high-risk file's valid slots.
        if review_reopened:
            normalized_kwargs["classification"] = effective_classification
            normalized_kwargs["analysis_priority"] = int(effective_priority)

        for key, value in normalized_kwargs.items():
            set_clauses.append(f"{key} = ?")
            if key == "slot_types_json":
                params.append(_json_list_text(value))
            else:
                params.append(value)

        if review_identity_changed:
            set_clauses.append("variant_check_status = 'pending'")

        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([engagement.id, file_id])

        previous_module_id = file_row["module_id"]
        if review_reopened:
            _reopen_file_metadata_review(
                connection,
                engagement.id,
                file_row,
                invalidate_architecture=False,
            )
        connection.execute(
            f"UPDATE code_files SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        if language_changed:
            _invalidate_repo_structural_index(
                connection,
                engagement.id,
                int(file_row["repo_id"]),
            )
        if review_reopened:
            _sync_metadata_review_queue_identity(
                connection,
                engagement.id,
                file_id,
                priority=int(normalized_kwargs["analysis_priority"]),
            )
            _sync_file_analysis_status(connection, engagement.id, file_id)
        module_ids_to_sync: set[int] = set()
        if previous_module_id is not None:
            module_ids_to_sync.add(int(previous_module_id))
        row = connection.execute(
            "SELECT * FROM code_files WHERE engagement_id = ? AND id = ?",
            (engagement.id, file_id),
        ).fetchone()
        if row is not None and row["module_id"] is not None:
            module_ids_to_sync.add(int(row["module_id"]))
        for module_id in module_ids_to_sync:
            _sync_module_rollup(connection, engagement.id, module_id)
        payload = _hydrate_code_file(row)
        payload["variant_check_status"] = _current_variant_check_status(
            connection,
            engagement.id,
            dict(row),
        )
    return payload


def bulk_update_structural_metadata(
    engagement_id: int,
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    structural_index_schema: str,
    structural_input_digest: str,
    structural_index_manifest_path: str,
    degraded_files: int,
    degraded_file_paths: list[str],
    artifact_truncated_files: int,
    artifact_truncated_file_paths: list[str],
    analysis_status_counts: dict[str, int],
    updates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Publish one complete structural index against an exact source snapshot."""
    engagement = _engagement_or_404(engagement_id)
    if structural_index_schema != STRUCTURAL_INDEX_SCHEMA:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "structural index schema is stale; "
                f"expected {STRUCTURAL_INDEX_SCHEMA}"
            ),
        )
    structural_fields = {
        "total_functions",
        "total_top_level_segments",
        "total_entry_points",
        "total_sinks",
        "total_exports",
        "structural_analysis_status",
        "structural_analysis_mode",
        "structural_degradation_reason",
        "structural_source_size",
        "structural_bytes_scanned",
        "structural_unavailable_dimensions",
        "structural_artifact_truncated",
        "structural_truncated_dimensions",
        "structural_signal_counts",
        "callables",
    }

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        require_current_source_binding(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="structural index",
        )

        submitted_ids = [int(item["file_id"]) for item in updates]
        if len(submitted_ids) != len(set(submitted_ids)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index contains duplicate file IDs",
            )
        current_rows = connection.execute(
            """
            SELECT * FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
            ORDER BY id
            """,
            (engagement.id, repo_id),
        ).fetchall()
        current_by_id = {int(row["id"]): dict(row) for row in current_rows}
        if set(submitted_ids) != set(current_by_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index must cover every file in the current repository snapshot",
            )

        for item in updates:
            _reject_unknown_fields(
                item,
                structural_fields | {"file_id", "source_sha256", "indexed_language"},
                entity_name="bulk structural metadata update",
            )
            file_id = int(item["file_id"])
            if str(current_by_id[file_id].get("file_hash", "") or "") != str(item["source_sha256"]):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"structural index source hash is stale for file_id={file_id}",
                )
            expected_language = canonical_structural_language(
                current_by_id[file_id].get("language", "")
            )
            indexed_language = canonical_structural_language(item["indexed_language"])
            if indexed_language != str(item["indexed_language"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "indexed_language must already be canonical for "
                        f"file_id={file_id}; expected {indexed_language!r}"
                    ),
                )
            if indexed_language != expected_language:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"structural index language is stale for file_id={file_id}",
                )

        expected_input_digest = structural_input_identity_digest(
            repo_id=repo_id,
            repo_generation=repo_generation,
            source_manifest_digest_value=source_manifest_digest,
            files=list(current_by_id.values()),
        )
        if structural_input_digest != expected_input_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="structural index input identity is stale",
            )

        callable_registry_flags = ["callables" in item for item in updates]
        if any(callable_registry_flags) and not all(callable_registry_flags):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural callable registry publication must cover every file",
            )
        publishes_callable_registry = all(callable_registry_flags)

        canonical_callables = [
            callable_record
            for item in updates
            for callable_record in _canonical_structural_callables(
                item,
                current_by_id[int(item["file_id"])],
                repo_id=repo_id,
                repo_generation=repo_generation,
                source_manifest_digest=source_manifest_digest,
            )
        ]
        submitted_callable_keys = {
            str(callable_record["callable_key"])
            for callable_record in canonical_callables
        }
        existing_callable_keys = {
            str(row["callable_key"])
            for row in connection.execute(
                """
                SELECT callable_key
                FROM code_structural_callables
                WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
                """,
                (engagement.id, repo_id, repo_generation),
            ).fetchall()
        }
        callable_registry_published = connection.execute(
            """
            SELECT 1
            FROM code_structural_callable_publications
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
            """,
            (engagement.id, repo_id, repo_generation),
        ).fetchone() is not None
        if callable_registry_published and not publishes_callable_registry:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "structural callable registry is already sealed; every replay "
                    "must publish the exact complete registry"
                ),
            )
        added_callables_by_span: dict[tuple[int, str, int, int], list[dict[str, Any]]] = {}
        for callable_record in canonical_callables:
            if callable_record["callable_key"] not in existing_callable_keys:
                added_callables_by_span.setdefault(
                    (
                        int(callable_record["file_id"]),
                        str(callable_record["name"]),
                        int(callable_record["start_line"]),
                        int(callable_record["end_line"]),
                    ),
                    [],
                ).append(callable_record)
        removed_callable_keys = json.dumps(
            sorted(existing_callable_keys - submitted_callable_keys)
        )
        receipt_bound_rows = connection.execute(
            """
            SELECT callables.id, callables.file_id, callables.name,
                   files.file_path, callables.qualified_name, callables.callable_key,
                   callables.start_line, callables.end_line
            FROM code_structural_callables AS callables
            JOIN code_files AS files ON files.id = callables.file_id
            WHERE callables.engagement_id = ? AND callables.repo_id = ?
              AND callables.repo_generation = ?
              AND callables.callable_key IN (SELECT value FROM json_each(?))
              AND EXISTS (
                  SELECT 1 FROM code_analysis_result_callables AS links
                  WHERE links.callable_id = callables.id
              )
            ORDER BY files.file_path, callables.start_line
            """,
            (engagement.id, repo_id, repo_generation, removed_callable_keys),
        ).fetchall()
        requalified_callables: list[tuple[int, dict[str, Any]]] = []
        requalified_keys: dict[str, dict[str, Any]] = {}
        receipt_bound_removals = []
        bound_spans = Counter(
            (int(row["file_id"]), str(row["name"]), int(row["start_line"]), int(row["end_line"]))
            for row in receipt_bound_rows
        )
        for row in receipt_bound_rows:
            span = (int(row["file_id"]), str(row["name"]), int(row["start_line"]), int(row["end_line"]))
            candidates = added_callables_by_span.get(span, [])
            if len(candidates) == 1 and bound_spans[span] == 1:
                requalified_callables.append((int(row["id"]), candidates[0]))
                requalified_keys[str(row["callable_key"])] = candidates[0]
            else:
                receipt_bound_removals.append(row)
        if receipt_bound_removals:
            shown = ", ".join(
                f"{row['file_path']}:{row['qualified_name']}"
                f" ({row['start_line']}-{row['end_line']})"
                for row in receipt_bound_removals[:20]
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"structural index would drop {len(receipt_bound_removals)} "
                    "receipt-bound callable(s) from this repository generation: "
                    f"{shown}; reingest to advance the generation instead"
                ),
            )

        canonical_status_counts = {"complete": 0, "degraded": 0, "unsupported": 0}
        canonical_degraded_paths: list[str] = []
        canonical_truncated_paths: list[str] = []
        for item in updates:
            file_id = int(item["file_id"])
            structural_status = str(item["structural_analysis_status"])
            canonical_status_counts[structural_status] += 1
            file_path = str(current_by_id[file_id]["file_path"])
            if structural_status == "degraded":
                canonical_degraded_paths.append(file_path)
            if bool(item["structural_artifact_truncated"]):
                canonical_truncated_paths.append(file_path)
        canonical_degraded_paths.sort()
        canonical_truncated_paths.sort()
        if (
            degraded_files != len(canonical_degraded_paths)
            or degraded_file_paths != canonical_degraded_paths
            or artifact_truncated_files != len(canonical_truncated_paths)
            or artifact_truncated_file_paths != canonical_truncated_paths
            or analysis_status_counts != canonical_status_counts
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index aggregate debt metadata does not match per-file updates",
            )

        for item in updates:
            connection.execute(
                """
                UPDATE code_files
                SET total_functions = ?, total_entry_points = ?, total_sinks = ?,
                    total_exports = ?, structural_analysis_status = ?,
                    structural_analysis_mode = ?, structural_degradation_reason = ?,
                    structural_source_size = ?, structural_bytes_scanned = ?,
                    structural_unavailable_dimensions_json = ?,
                    structural_artifact_truncated = ?,
                    structural_truncated_dimensions_json = ?,
                    structural_signal_counts_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND repo_id = ? AND id = ?
                """,
                (
                    int(item["total_functions"]),
                    int(item["total_entry_points"]),
                    int(item["total_sinks"]),
                    int(item["total_exports"]),
                    str(item["structural_analysis_status"]),
                    str(item["structural_analysis_mode"]),
                    str(item.get("structural_degradation_reason") or ""),
                    int(item["structural_source_size"]),
                    int(item["structural_bytes_scanned"]),
                    _json_list_text(item["structural_unavailable_dimensions"]),
                    1 if item["structural_artifact_truncated"] else 0,
                    _json_list_text(item["structural_truncated_dimensions"]),
                    _json_text(item["structural_signal_counts"]),
                    engagement.id,
                    repo_id,
                    int(item["file_id"]),
                ),
            )
        connection.execute(
            """
            DELETE FROM code_structural_callables
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
              AND callable_key IN (SELECT value FROM json_each(?))
              AND id NOT IN (SELECT value FROM json_each(?))
            """,
            (
                engagement.id,
                repo_id,
                repo_generation,
                removed_callable_keys,
                json.dumps([callable_id for callable_id, _ in requalified_callables]),
            ),
        )
        for callable_id, callable_record in requalified_callables:
            connection.execute(
                """
                UPDATE code_structural_callables
                SET qualified_name = ?, callable_key = ?
                WHERE id = ?
                """,
                (
                    callable_record["qualified_name"],
                    callable_record["callable_key"],
                    callable_id,
                ),
            )
        # A receipt's stored refs name the callables it is linked to, so they follow
        # the rebind; otherwise the receipt reads, searches and supersedes under a
        # name the registry no longer holds.
        if requalified_callables:
            linked_results = connection.execute(
                """
                SELECT DISTINCT results.id, results.callable_refs_json
                FROM code_analysis_results AS results
                JOIN code_analysis_result_callables AS links ON links.result_id = results.id
                WHERE results.engagement_id = ?
                  AND links.callable_id IN (SELECT value FROM json_each(?))
                """,
                (
                    engagement.id,
                    json.dumps([callable_id for callable_id, _ in requalified_callables]),
                ),
            ).fetchall()
            for linked_result in linked_results:
                refs = _json_decode(linked_result["callable_refs_json"], [])
                for ref in refs:
                    replacement = requalified_keys.get(str(ref.get("callable_key", "")))
                    if replacement is not None and int(ref["file_id"]) == int(
                        replacement["file_id"]
                    ):
                        ref["qualified_name"] = replacement["qualified_name"]
                        ref["callable_key"] = replacement["callable_key"]
                connection.execute(
                    "UPDATE code_analysis_results SET callable_refs_json = ? WHERE id = ?",
                    (_json_list_text(refs), int(linked_result["id"])),
                )
        for callable_record in canonical_callables:
            connection.execute(
                """
                INSERT INTO code_structural_callables (
                    engagement_id, repo_id, repo_generation,
                    source_manifest_digest, file_id, file_sha256,
                    callable_key, name, qualified_name, start_line, end_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, repo_generation, callable_key)
                DO NOTHING
                """,
                (
                    callable_record["engagement_id"],
                    callable_record["repo_id"],
                    callable_record["repo_generation"],
                    callable_record["source_manifest_digest"],
                    callable_record["file_id"],
                    callable_record["file_sha256"],
                    callable_record["callable_key"],
                    callable_record["name"],
                    callable_record["qualified_name"],
                    callable_record["start_line"],
                    callable_record["end_line"],
                ),
            )
        if publishes_callable_registry:
            connection.execute(
                """
                INSERT INTO code_structural_callable_publications (
                    engagement_id, repo_id, repo_generation, source_manifest_digest
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, repo_generation) DO NOTHING
                """,
                (engagement.id, repo_id, repo_generation, source_manifest_digest),
            )
            _bind_legacy_analysis_results(
                connection,
                engagement_id=engagement.id,
                repo_id=repo_id,
                repo_generation=repo_generation,
            )
        connection.execute(
            """
            UPDATE code_repos
            SET structural_index_schema = ?, structural_index_generation = ?,
                structural_index_manifest_path = ?,
                structural_degraded_files = ?, structural_degraded_file_paths_json = ?,
                structural_artifact_truncated_files = ?,
                structural_artifact_truncated_file_paths_json = ?,
                structural_analysis_status_counts_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (
                structural_index_schema,
                repo_generation,
                structural_index_manifest_path,
                degraded_files,
                _json_list_text(degraded_file_paths),
                artifact_truncated_files,
                _json_list_text(artifact_truncated_file_paths),
                _json_text(analysis_status_counts),
                engagement.id,
                repo_id,
            ),
        )

    return {
        "repo_id": repo_id,
        "repo_generation": repo_generation,
        "source_manifest_digest": source_manifest_digest,
        "structural_index_schema": structural_index_schema,
        "structural_input_digest": structural_input_digest,
        "structural_index_manifest_path": structural_index_manifest_path,
        "degraded_files": degraded_files,
        "degraded_file_paths": degraded_file_paths,
        "artifact_truncated_files": artifact_truncated_files,
        "artifact_truncated_file_paths": artifact_truncated_file_paths,
        "analysis_status_counts": analysis_status_counts,
        "registered_callables": len(canonical_callables),
        "callable_registry_published": publishes_callable_registry,
        "updated": len(updates),
    }


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
        _get_published_repo_row(connection, engagement.id, repo_id)
        repo_files = connection.execute(
            """
            SELECT id, file_path
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
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
            _sync_module_rollup(connection, engagement.id, module_id)

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
    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)
            repo_clause = " AND modules.repo_id = ?"
            params: tuple[Any, ...] = (engagement.id, repo_id)
        else:
            repo_clause = ""
            params = (engagement.id,)
        query = f"""
            SELECT modules.*
            FROM code_modules AS modules
            JOIN code_repos AS repos
              ON repos.id = modules.repo_id
             AND repos.engagement_id = modules.engagement_id
             AND repos.active_generation > 0
            WHERE modules.engagement_id = ?{repo_clause}
            ORDER BY modules.id ASC
        """
        module_rows = connection.execute(query, params).fetchall()
        for row in module_rows:
            _sync_module_rollup(connection, engagement.id, int(row["id"]))
        return _fetch_all(connection, query, params)


# =========================================================================
# Analysis Queue
# =========================================================================

_QUEUE_BLOCKED_TERMINAL_STATUSES = frozenset({"error", "needs_context"})
_QUEUE_STATUSES = frozenset(
    {"pending", "processing", "done", "error", "needs_context"}
)
_QUEUE_MODES = frozenset(
    {"initial", "reanalysis", "trigger", _METADATA_REFRESH_REVIEW_MODE}
)


def _queue_item_matches(row: dict[str, Any], item: dict[str, Any]) -> bool:
    return (
        int(row["priority"]) == int(item["priority"])
        and str(row["batch_theme"]) == str(item["batch_theme"])
        and _json_decode(row.get("slot_types_json"), []) == item["slot_types"]
        and _json_decode(row.get("guidance_hypotheses_json"), [])
        == item["guidance_hypotheses"]
        and _json_decode(row.get("cross_file_triggers_json"), [])
        == item["cross_file_triggers"]
    )


def _queue_outcome(
    *,
    file_id: int,
    queue_item_id: int | None,
    outcome: str,
    status_value: str,
    detail: str,
    file_path: str = "",
    supersedes: int | None = None,
) -> dict[str, Any]:
    """One per-item verdict from a queue submission.

    `file_path` and `supersedes` carry the two facts a per-file warning needs
    and could not reach: which file the outcome is about without a second
    lookup, and — on a reanalysis — WHICH predecessor attempt the new one
    suspends. A reanalysis withdraws the predecessor's verdict and coverage
    credit until it closes, so naming only the new attempt leaves out the half
    of the message the operator acts on.
    """
    return {
        "file_id": file_id,
        "file_path": file_path,
        "queue_item_id": queue_item_id,
        "supersedes": supersedes,
        "outcome": outcome,
        "status": status_value,
        "detail": detail,
    }


def bulk_create_queue_items(
    engagement_id: int,
    items: list[dict[str, Any]],
    *,
    mode: str = "initial",
    reason: str = "",
) -> dict[str, Any]:
    """Create canonical initial work or an explicit terminal-to-pending reanalysis.

    ``BEGIN IMMEDIATE`` makes the read/decide/write sequence the concurrency
    boundary. Initial retries can refresh only an unleased pending initial row;
    they never alter a processing lease or any completed/error/context evidence.
    Reanalysis is a separate, reasoned attempt chained to the latest completed
    row, so depth is auditable instead of emerging from duplicate inserts.
    """
    engagement = _engagement_or_404(engagement_id)
    normalized_mode = str(mode).strip().lower()
    normalized_reason = str(reason).strip()
    if normalized_mode not in {"initial", "reanalysis"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="queue mode must be initial or reanalysis",
        )
    if normalized_mode == "reanalysis" and not normalized_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reason is required when mode=reanalysis",
        )

    submitted_file_ids = [
        _require_strict_positive_id(
            item.get("file_id"),
            field_name=f"items[{idx}].file_id",
        )
        for idx, item in enumerate(items)
    ]
    if len(submitted_file_ids) != len(set(submitted_file_ids)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="queue request contains duplicate file IDs",
        )
    submitted_priorities: list[int | None] = []
    for item in items:
        if normalized_mode == "initial" and item.get("priority") is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="every initial queue item requires an integer priority",
            )
        priority = (
            None
            if item.get("priority") is None
            else _require_strict_priority(item["priority"], field_name="queue priority")
        )
        submitted_priorities.append(priority)

    counts = {
        "inserted": 0,
        "updated": 0,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
    }
    outcomes: list[dict[str, Any]] = []
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_rows = _get_file_rows(connection, engagement.id, set(submitted_file_ids))
        repo_rows = _get_repo_rows(
            connection,
            engagement.id,
            {int(file_row["repo_id"]) for file_row in file_rows.values()},
        )
        # A reference repository is read, never reviewed, so a queue row for one
        # of its files would manufacture an obligation the engagement declined
        # and that readiness deliberately ignores. Refuse the whole batch before
        # any write, the same way a priority drift is refused.
        reference_file_counts: dict[int, int] = {}
        for file_id in submitted_file_ids:
            repo = repo_rows[int(file_rows[file_id]["repo_id"])]
            if str(repo.get("repo_role") or ANALYSIS_REPO_ROLE) != ANALYSIS_REPO_ROLE:
                reference_file_counts[int(repo["id"])] = (
                    reference_file_counts.get(int(repo["id"]), 0) + 1
                )
        if reference_file_counts:
            named = ", ".join(
                f"{repo_rows[reference_repo_id]['repo_key']} "
                f"(repo {reference_repo_id}, {count} file(s))"
                for reference_repo_id, count in sorted(reference_file_counts.items())
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"queue request names files in a reference repository: {named}. "
                    "A reference repository is indexed and citable but owns no "
                    "review obligation. Scope the batch to the analysis "
                    "repository, or re-ingest with --role analysis to review it."
                ),
            )
        for file_id, priority in zip(
            submitted_file_ids, submitted_priorities, strict=True
        ):
            expected_priority = int(file_rows[file_id]["analysis_priority"])
            if priority is not None and priority != expected_priority:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"queue priority for file {file_id} must equal current "
                        f"analysis_priority {expected_priority} (received {priority})"
                    ),
                )

        affected_modules: set[int] = set()
        for idx, (item, priority) in enumerate(
            zip(items, submitted_priorities, strict=True)
        ):
            file_id = submitted_file_ids[idx]
            file_path = str(file_rows[file_id]["file_path"])
            expected_priority = int(file_rows[file_id]["analysis_priority"])
            repo_generation = int(
                repo_rows[int(file_rows[file_id]["repo_id"])]["active_generation"]
            )
            normalized_item = {
                "priority": expected_priority,
                "batch_theme": str(item.get("batch_theme", "")),
                "slot_types": _normalize_slot_types(
                    item.get("slot_types"), field_name="slot_types"
                ),
                "guidance_hypotheses": _normalize_guidance_hypotheses(
                    item.get("guidance_hypotheses"),
                    field_name="guidance_hypotheses",
                ),
                "cross_file_triggers": list(item.get("cross_file_triggers") or []),
            }
            current_rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM code_analysis_queue
                    WHERE engagement_id = ? AND file_id = ? AND repo_generation = ?
                    ORDER BY id ASC
                    """,
                    (engagement.id, file_id, repo_generation),
                ).fetchall()
            ]
            latest, active, active_issue = _canonical_queue_attempt_state(current_rows)
            if active_issue is not None:
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        file_path=file_path,
                        queue_item_id=(
                            None if active is None else int(active["id"])
                        ),
                        outcome="conflict",
                        status_value=active_issue,
                        detail=(
                            f"{active_issue} queue history requires operator reconciliation"
                        ),
                    )
                )
                continue

            requested_predecessor = item.get("supersedes")
            expected_predecessor = None
            if normalized_mode == "reanalysis":
                if active is not None and str(active.get("queue_mode")) == "reanalysis":
                    expected_predecessor = active.get("reanalysis_of_queue_item_id")
                elif latest is not None:
                    expected_predecessor = latest.get("id")
                if (
                    requested_predecessor is not None
                    and (
                        expected_predecessor is None
                        or int(requested_predecessor) != int(expected_predecessor)
                    )
                ):
                    counts["conflicts"] += 1
                    outcomes.append(
                        _queue_outcome(
                            file_id=file_id,
                            file_path=file_path,
                            queue_item_id=(
                                None
                                if expected_predecessor is None
                                else int(expected_predecessor)
                            ),
                            outcome="conflict",
                            status_value=(
                                "missing" if expected_predecessor is None else "done"
                            ),
                            detail=(
                                f"reanalysis supersedes={requested_predecessor} does not "
                                "match the current predecessor queue row "
                                f"{expected_predecessor} for file {file_id}"
                            ),
                        )
                    )
                    continue
                requested_predecessor = expected_predecessor

            if active is not None:
                active_status = str(active["status"])
                active_mode = str(active.get("queue_mode") or "initial")
                if active_mode == "initial" and (
                    str(active.get("batch_theme") or "") == "cross-file-trigger"
                    or _json_decode(active.get("cross_file_triggers_json"), [])
                ):
                    active_mode = "trigger"
                same_payload = _queue_item_matches(active, normalized_item)
                same_attempt = active_mode == normalized_mode and (
                    normalized_mode == "initial"
                    or str(active.get("reanalysis_reason") or "") == normalized_reason
                )
                pending_is_unleased = not str(
                    active.get("assigned_agent") or ""
                ) and not str(active.get("lease_token") or "")
                if active_status == "pending" and same_attempt:
                    if same_payload and pending_is_unleased:
                        counts["already_active"] += 1
                        outcomes.append(
                            _queue_outcome(
                                file_id=file_id,
                                file_path=file_path,
                                queue_item_id=int(active["id"]),
                                outcome="already_active",
                                status_value=active_status,
                                detail=f"identical pending {normalized_mode} queue item already exists",
                            )
                        )
                        continue
                    if normalized_mode == "initial" and pending_is_unleased:
                        cursor = connection.execute(
                            """
                            UPDATE code_analysis_queue
                            SET priority = ?, batch_theme = ?, slot_types_json = ?,
                                guidance_hypotheses_json = ?,
                                cross_file_triggers_json = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE engagement_id = ? AND id = ? AND status = 'pending'
                              AND queue_mode = 'initial'
                              AND assigned_agent = '' AND lease_token = ''
                            """,
                            (
                                expected_priority,
                                normalized_item["batch_theme"],
                                _json_list_text(normalized_item["slot_types"]),
                                _json_list_text(normalized_item["guidance_hypotheses"]),
                                _json_list_text(normalized_item["cross_file_triggers"]),
                                engagement.id,
                                int(active["id"]),
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise HTTPException(
                                status_code=status.HTTP_409_CONFLICT,
                                detail="pending queue item changed during retry",
                            )
                        counts["updated"] += 1
                        outcomes.append(
                            _queue_outcome(
                                file_id=file_id,
                                file_path=file_path,
                                queue_item_id=int(active["id"]),
                                outcome="updated",
                                status_value="pending",
                                detail="updated pending initial queue item",
                            )
                        )
                        _sync_file_analysis_status(
                            connection, engagement.id, file_id, deferred_modules=affected_modules
                        )
                        _sync_trigger_status_for_file(connection, engagement.id, file_id)
                        continue

                if active_status == "processing" and same_attempt and same_payload:
                    counts["already_active"] += 1
                    outcomes.append(
                        _queue_outcome(
                            file_id=file_id,
                            file_path=file_path,
                            queue_item_id=int(active["id"]),
                            outcome="already_active",
                            status_value=active_status,
                            detail="identical live lease already owns this queue item",
                        )
                    )
                    continue

                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        file_path=file_path,
                        queue_item_id=int(active["id"]),
                        outcome="conflict",
                        status_value=active_status,
                        detail="active queue item differs; live work was not mutated",
                    )
                )
                continue

            if normalized_mode == "initial" and latest is not None:
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        file_path=file_path,
                        queue_item_id=int(latest["id"]),
                        outcome="conflict",
                        status_value=str(latest["status"]),
                        detail="current-generation evidence exists; use explicit reanalysis",
                    )
                )
                continue

            if normalized_mode == "reanalysis" and (
                latest is None or str(latest["status"]) != "done"
            ):
                latest_status = "missing" if latest is None else str(latest["status"])
                detail = "reanalysis requires a completed predecessor"
                if latest_status in _QUEUE_BLOCKED_TERMINAL_STATUSES:
                    detail = f"{latest_status} item must use its dedicated retry workflow"
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        file_path=file_path,
                        queue_item_id=None if latest is None else int(latest["id"]),
                        outcome="conflict",
                        status_value=latest_status,
                        detail=detail,
                    )
                )
                continue

            predecessor_id = (
                None
                if normalized_mode == "initial"
                else int(requested_predecessor)
            )
            cursor = connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority,
                    batch_theme, slot_types_json, guidance_hypotheses_json,
                    cross_file_triggers_json, repo_generation, queue_mode,
                    reanalysis_reason, reanalysis_of_queue_item_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    file_id,
                    expected_priority,
                    normalized_item["batch_theme"],
                    _json_list_text(normalized_item["slot_types"]),
                    _json_list_text(normalized_item["guidance_hypotheses"]),
                    _json_list_text(normalized_item["cross_file_triggers"]),
                    repo_generation,
                    normalized_mode,
                    normalized_reason if normalized_mode == "reanalysis" else "",
                    predecessor_id,
                ),
            )
            outcome_name = "reanalysis" if normalized_mode == "reanalysis" else "inserted"
            counts[outcome_name] += 1
            outcomes.append(
                _queue_outcome(
                    file_id=file_id,
                    file_path=file_path,
                    queue_item_id=int(cursor.lastrowid),
                    # The attempt this one suspends: its verdict and coverage
                    # credit are withdrawn until the new attempt closes.
                    supersedes=predecessor_id,
                    outcome=outcome_name,
                    status_value="pending",
                    detail=(
                        "created explicit reanalysis queue item"
                        if normalized_mode == "reanalysis"
                        else "created initial queue item"
                    ),
                )
            )
            _sync_file_analysis_status(
                connection, engagement.id, file_id, deferred_modules=affected_modules
            )
            _sync_trigger_status_for_file(connection, engagement.id, file_id)

        for module_id in sorted(affected_modules):
            _sync_module_rollup(connection, engagement.id, module_id)

        return {
            "mode": normalized_mode,
            **counts,
            "total": len(items),
            "outcomes": outcomes,
        }


def queue_stats(engagement_id: int) -> dict[str, Any]:
    """Count the work that is actually claimable, and disclose what is not.

    `fetch` will never hand out a row in a `reference` repository, so counting
    one here would describe a queue that can never drain. They are excluded
    from the counts and named in `reference_repo_items` instead -- the same
    exclude-and-disclose shape `coverage` uses for reference files -- because an
    operator who demoted a repository still needs to see the rows it holds.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        lanes = {
            str(row["lane"]): int(row["total"])
            for row in connection.execute(
                f"SELECT lane, COUNT(*) AS total FROM ({_queue_lane_sql()}) GROUP BY lane",
                (engagement.id,),
            ).fetchall()
        }
        historical_total = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ? AND repos.active_generation > 0
              AND {_analysis_repo_sql("repos")}
            """,
            (engagement.id,),
        )
        # Only a reference repository that actually holds rows: one that holds
        # none is excluding nothing and has nothing for an operator to act on.
        reference_repo_items = [
            {
                "repo_id": int(row["id"]),
                "repo_key": str(row["repo_key"]),
                "name": str(row["name"]),
                "queue_items": int(row["queue_items"]),
            }
            for row in connection.execute(
                f"""
                SELECT repos.id, repos.repo_key, repos.name,
                       (
                           SELECT COUNT(*)
                           FROM code_analysis_queue AS queue
                           JOIN code_files AS files
                             ON files.id = queue.file_id
                            AND files.engagement_id = queue.engagement_id
                           WHERE queue.engagement_id = repos.engagement_id
                             AND files.repo_id = repos.id
                             AND queue.repo_generation = repos.active_generation
                             AND queue.source_superseded_at IS NULL
                       ) AS queue_items
                FROM code_repos AS repos
                WHERE repos.engagement_id = ?
                  AND repos.active_generation > 0
                  AND NOT ({_analysis_repo_sql("repos")})
                ORDER BY repos.id
                """,
                (engagement.id,),
            ).fetchall()
            if int(row["queue_items"]) > 0
        ]
    invalid_active_identity = lanes.pop("invalid_active_identity", 0)
    invalid_active_history = lanes.pop("invalid_active_history", 0)
    current_attempt_total = sum(lanes.values()) + invalid_active_identity + invalid_active_history
    return {
        "pending": lanes.get("pending", 0),
        "processing": lanes.get("processing", 0),
        "done": lanes.get("done", 0),
        "error": lanes.get("error", 0),
        "needs_context": lanes.get("needs_context", 0),
        "total": sum(lanes.values()),
        "historical_total": historical_total,
        "superseded_history": historical_total - current_attempt_total,
        "invalid_active_identity": invalid_active_identity,
        "invalid_active_history": invalid_active_history,
        "reference_repo_items": reference_repo_items,
    }


def _adopted_lease_identities(raw: Any) -> list[dict[str, str]]:
    """Project the stored adoption chain as plain identity pairs.

    Rendered verbatim: agent names and lease tokens are the operator's own
    audit trail, and the whole point of the chain is to say exactly which lease
    wrote which receipt.
    """
    identities: list[dict[str, str]] = []
    for entry in _json_decode(raw, []):
        if not isinstance(entry, dict):
            continue
        identities.append(
            {
                "agent_name": str(entry.get("agent_name") or ""),
                "lease_token": str(entry.get("lease_token") or ""),
            }
        )
    return identities


def _lease_activity_projection(row: Any) -> dict[str, Any]:
    """Ownership truth an operator needs to tell a working lease from an
    abandoned one: when it last proved life, how long ago that was on the
    database clock, how much durable work the row already carries, and which
    earlier leases were adopted into it. The queue listing and the open-lease
    view read it identically."""
    return {
        "consumed_at": row["consumed_at"],
        "last_heartbeat_at": row["last_heartbeat_at"],
        "lease_activity_at": row["lease_activity_at"],
        "heartbeat_age_seconds": (
            None
            if row["heartbeat_age_seconds"] is None
            else int(row["heartbeat_age_seconds"])
        ),
        "current_result_count": int(row["current_result_count"] or 0),
        "adopted_leases": _adopted_lease_identities(row["adopted_leases_json"]),
    }


def _hydrate_queue_listing_row(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "file_id": int(row["file_id"]),
        "file_path": str(row["file_path"]),
        "loc": int(row["file_loc"]),
        "applicable_vuln_classes": _applicable_families_for_file(
            _json_decode(row["file_slot_types_json"], []),
            language=str(row["file_language"] or ""), role=str(row["file_role"] or ""),
        ),
        "path_suggested_vuln_classes": _path_suggested_families_for_file(
            _json_decode(row["file_slot_types_json"], []),
            language=str(row["file_language"] or ""), role=str(row["file_role"] or ""),
            file_path=str(row["file_path"]),
        ),
        "classification": str(row["classification"] or ""),
        "analysis_priority": int(row["analysis_priority"]),
        "repo_id": int(row["repo_id"]),
        "repo_key": str(row["repo_key"]),
        # A row in a reference repository is unclaimable but must stay findable
        # by ID, so the listing names the role rather than dropping the row.
        "repo_role": str(row["repo_role"] or ANALYSIS_REPO_ROLE),
        "status": str(row["status"]),
        "queue_mode": str(row["queue_mode"] or "initial"),
        "priority": int(row["priority"]),
        "batch_theme": str(row["batch_theme"] or ""),
        "slot_types": _json_decode(row["slot_types_json"], []),
        "guidance_hypotheses": _json_decode(row["guidance_hypotheses_json"], []),
        "cross_file_triggers": _json_decode(row["cross_file_triggers_json"], []),
        "agent_name": str(row["assigned_agent"] or ""),
        "lease_token": str(row["lease_token"] or ""),
        "repo_generation": int(row["repo_generation"]),
        "disposition": str(row["disposition"] or ""),
        "skip_reason": str(row["skip_reason"] or ""),
        "reanalysis_of_queue_item_id": row["reanalysis_of_queue_item_id"],
        **_lease_activity_projection(row),
        "completed_at": row["completed_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_queue_items(
    engagement_id: int,
    *,
    status_filter: str | None = None,
    agent_name: str | None = None,
    item_ids: list[int] | None = None,
    repo_id: int | None = None,
    classification: str | None = None,
    batch_theme: str | None = None,
    queue_mode: str | None = None,
    stale_minutes: int | None = None,
    current_only: bool = False,
    path_prefix: list[str] | None = None,
    path_glob: list[str] | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Page the current-generation queue so its row IDs stay recoverable.

    Every current-generation, non-source-superseded attempt is listed, including
    an older active row that overlaps the latest one and a row in a repository
    demoted to `reference`. `fetch` refuses to claim those and `stats` reports
    them separately, so a listing that dropped them would hide the exact IDs an
    operator needs to reconcile the history; each row carries `repo_role` so an
    unclaimable one is identifiable rather than invisible. Ordering matches the
    claim order `fetch` applies, so a page fed back through `--ids-file` is
    claimed in the order it was shown.

    `current_only` narrows the page to the rows `stats` counts: each
    analysis-repository file's latest attempt, in its status lane, without the
    invalid active rows `stats` reports separately (`_queue_lane_sql`).

    `stale_minutes` narrows the page to processing rows whose lease has not
    proved life inside that window — the same abandonment measure `reset-stale`
    and `adopt-lease` apply. Both of those additionally refuse a row that is not
    the sole canonical latest current-generation attempt, so a listed row can be
    stale without being recoverable; `stats` reports that history separately as
    `invalid_active_history`.

    `path_prefix` / `path_glob` scope the page, `total` and `has_more` to a
    source subtree through `_file_path_scope_sql`, the predicate `fetch` claims
    with.
    """
    engagement = _engagement_or_404(engagement_id)
    if status_filter is not None and status_filter not in _QUEUE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid queue status: {status_filter}",
        )
    if queue_mode is not None and queue_mode not in _QUEUE_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid queue mode: {queue_mode}",
        )
    if classification is not None and classification not in _VALID_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid classification: {classification}",
        )
    clauses = [
        "queue.engagement_id = ?",
        "files.retired_at IS NULL",
        "queue.repo_generation = repos.active_generation",
        "queue.source_superseded_at IS NULL",
    ]
    params: list[Any] = [engagement.id]
    if status_filter is not None:
        clauses.append("queue.status = ?")
        params.append(status_filter)
    if agent_name is not None:
        clauses.append("queue.assigned_agent = ?")
        params.append(agent_name)
    if item_ids is not None:
        clauses.append("queue.id IN (SELECT value FROM json_each(?))")
        params.append(json.dumps(item_ids))
    if current_only:
        statuses = sorted(_QUEUE_STATUSES)
        clauses.append(
            f"queue.id IN (SELECT attempt_id FROM ({_queue_lane_sql()})"
            f" WHERE lane IN ({', '.join('?' for _ in statuses)}))"
        )
        params.extend([engagement.id, *statuses])
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(_coerce_int(repo_id, field_name="repo_id"))
    _append_optional_filters(clauses, params, (
        ("files.classification = ?", classification),
        ("queue.batch_theme = ?", batch_theme),
        ("queue.queue_mode = ?", queue_mode),
    ))
    if stale_minutes is not None:
        if stale_minutes < 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="stale_minutes must be at least 1",
            )
        # Only a processing row holds a lease that can go stale; a pending row
        # has no owner to lose. A claimed row with neither timestamp has never
        # proved life, which `reset-stale` also treats as abandoned.
        clauses.append("queue.status = 'processing'")
        clauses.append(
            f"({_lease_activity_sql('queue')} IS NULL"
            f" OR datetime({_lease_activity_sql('queue')})"
            " < datetime('now', ? || ' minutes'))"
        )
        params.append(f"-{int(stale_minutes)}")
    path_scope, path_params = _file_path_scope_sql("files", path_prefix, path_glob)
    if path_scope:
        clauses.append(path_scope)
        params.extend(path_params)
    from_where = f"""
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE {' AND '.join(clauses)}
    """
    query = f"""
        SELECT queue.*, files.file_path, files.classification,
               files.loc AS file_loc, files.language AS file_language,
               files.role AS file_role, files.slot_types_json AS file_slot_types_json,
               files.analysis_priority, files.repo_id, repos.repo_key,
               repos.repo_role,
               {_lease_activity_sql('queue')} AS lease_activity_at,
               {_lease_activity_age_seconds_sql('queue')} AS heartbeat_age_seconds,
               ({_current_attempt_result_count_sql('queue')}) AS current_result_count
        {from_where}
        ORDER BY queue.priority DESC, queue.id ASC
    """
    if offset > 0:
        # SQLite has no bare OFFSET, so an unbounded listing still needs a
        # LIMIT to skip rows at all. Dropping the offset instead would return
        # page one while `has_more` described a page the caller never got.
        query += f" LIMIT {int(limit) if limit is not None else -1} OFFSET {int(offset)}"
    elif limit is not None:
        query += f" LIMIT {int(limit)}"
    with get_connection() as connection:
        register_path_scope_functions(connection)
        total = _scalar_row(connection, f"SELECT COUNT(*) {from_where}", tuple(params))
        rows = connection.execute(query, tuple(params)).fetchall()
    items = [_hydrate_queue_listing_row(row) for row in rows]
    return {
        "total": total,
        "offset": offset,
        "count": len(items),
        "has_more": offset + len(items) < total,
        # The exact shape `code-dispatch fetch --ids-file` consumes, so a page
        # of this response is itself a valid ids file.
        "item_ids": [item["id"] for item in items],
        "items": items,
    }


def fetch_queue_items(
    engagement_id: int,
    limit: int,
    agent_name: str,
    *,
    repo_id: int | None = None,
    classification: str | None = None,
    batch_theme: str | None = None,
    queue_mode: str | None = None,
    item_ids: list[int] | None = None,
    path_prefix: list[str] | None = None,
    path_glob: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Atomically claim pending queue items for an agent.

    Uses UPDATE ... WHERE id IN (SELECT ... LIMIT) to prevent two concurrent
    callers from claiming the same rows.

    The role is read here, live, rather than at the rows: demoting a repository
    to ``reference`` changes no source, so the generation does not move and
    nothing supersedes the rows it already carries. Retiring them at the
    demotion would also make the reverse trip lossy, and would still miss a row
    created afterwards. This is the one place work is handed out, so this is
    where a repository that owes no review stops receiving agents.
    """
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    filter_clauses: list[str] = []
    filter_params: list[Any] = []
    _append_optional_filters(filter_clauses, filter_params, (
        ("files.repo_id = ?", repo_id),
        ("files.classification = ?", classification),
        ("queue.batch_theme = ?", batch_theme),
    ))
    if queue_mode is not None:
        if queue_mode not in _QUEUE_MODES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid queue mode: {queue_mode}",
            )
        filter_clauses.append("queue.queue_mode = ?")
        filter_params.append(queue_mode)
    if item_ids is not None:
        normalized_ids = sorted(set(item_ids))
        placeholders = ",".join("?" for _ in normalized_ids)
        filter_clauses.append(f"queue.id IN ({placeholders})")
        filter_params.extend(normalized_ids)
    # Inside the claim SELECT, never after it: a subtree filtered once rows are
    # claimed would hand this agent leases outside the subtree it was sent to.
    path_scope, path_params = _file_path_scope_sql("files", path_prefix, path_glob)
    if path_scope:
        filter_clauses.append(path_scope)
        filter_params.extend(path_params)
    filter_sql = "" if not filter_clauses else " AND " + " AND ".join(filter_clauses)
    with get_connection() as connection:
        register_path_scope_functions(connection)
        connection.execute("BEGIN IMMEDIATE")
        selected = connection.execute(
            f"""
            SELECT queue.id, queue.repo_generation
            {queue_file_repo_join_sql(
                repo_join_predicates=("repos.active_generation > 0",)
            )}
            WHERE queue.engagement_id = ? AND queue.status = 'pending'
              AND queue.assigned_agent = '' AND queue.lease_token = ''
              AND {_analysis_repo_sql("repos")}
              AND {canonical_current_attempt_sql("queue", "repos")}
              {filter_sql}
            ORDER BY queue.priority DESC, queue.id ASC
            LIMIT ?
            """,
            (engagement.id, *filter_params, limit),
        ).fetchall()
        claimed_ids: list[int] = []
        for selected_row in selected:
            item_id = int(selected_row["id"])
            repo_generation = int(selected_row["repo_generation"])
            lease_token = str(uuid.uuid4())
            cursor = connection.execute(
                """
                UPDATE code_analysis_queue
                SET status = 'processing', assigned_agent = ?, lease_token = ?,
                    consumed_at = ?, last_heartbeat_at = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND status = 'pending'
                  AND assigned_agent = '' AND lease_token = ''
                  AND repo_generation = ?
                """,
                (
                    agent_name,
                    lease_token,
                    now,
                    now,
                    engagement.id,
                    item_id,
                    repo_generation,
                ),
            )
            if cursor.rowcount == 1:
                claimed_ids.append(item_id)
        if not claimed_ids:
            return []
        placeholders = ",".join("?" for _ in claimed_ids)
        rows = connection.execute(
            f"""
            SELECT * FROM code_analysis_queue
            WHERE engagement_id = ? AND id IN ({placeholders})
            ORDER BY priority DESC, id ASC
            """,
            (engagement.id, *claimed_ids),
        ).fetchall()

        file_rows = _get_file_rows(connection, engagement.id, {int(row["file_id"]) for row in rows})
        repo_rows = _get_repo_rows(connection, engagement.id, {int(file_rows[int(row["file_id"])]["repo_id"]) for row in rows})

        affected_modules: set[int] = set()
        for file_id in {int(row["file_id"]) for row in rows}:
            _sync_file_analysis_status(
                connection, engagement.id, file_id, deferred_modules=affected_modules
            )
        for module_id in sorted(affected_modules):
            _sync_module_rollup(connection, engagement.id, module_id)
        lead_bindings = _open_lead_bindings_by_file(
            connection, engagement.id, {int(row["file_id"]) for row in rows}
        )
        payload = [
            _hydrate_claimed_queue_item(row, file_rows, repo_rows, lead_bindings)
            for row in rows
        ]
    return payload


def _open_lead_bindings_by_file(
    connection, engagement_id: int, file_ids: set[int]
) -> dict[int, list[dict[str, Any]]]:
    """Unanswered prior-art leads pointing into each of ``file_ids``.

    A stale binding is included and labelled rather than hidden: the lead still
    names this file, and "these line numbers came from source that has since
    changed" is context a reader can use, while silence is not.
    """
    if not file_ids:
        return {}
    placeholders = ",".join("?" for _ in file_ids)
    rows = _fetch_all(
        connection,
        f"""
        SELECT bindings.file_id AS file_id,
               bindings.note_id AS note_id,
               notes.title AS lead_title,
               notes.lead_status AS lead_status,
               bindings.prior_art_ref AS prior_art_ref,
               bindings.rationale AS rationale,
               bindings.line_start AS line_start,
               bindings.line_end AS line_end,
               CASE
                 WHEN {_lead_binding_stale_sql("bindings", "repos")} THEN 'stale' ELSE 'current'
               END AS binding_status
        FROM code_lead_bindings AS bindings
        JOIN intel_notes AS notes
          ON notes.id = bindings.note_id
         AND notes.engagement_id = bindings.engagement_id
        JOIN code_repos AS repos
          ON repos.id = bindings.repo_id
         AND repos.engagement_id = bindings.engagement_id
        WHERE bindings.engagement_id = ?
          AND bindings.unbound_at IS NULL
          AND notes.superseded_by_id IS NULL
          AND bindings.file_id IN ({placeholders})
          AND COALESCE(notes.lead_status, '') IN ({_LEAD_OPEN_STATUS_PLACEHOLDERS})
        ORDER BY bindings.file_id, bindings.note_id
        """,
        (engagement_id, *sorted(file_ids), *_LEAD_OPEN_STATUS_VALUES),
    )
    by_file: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        by_file.setdefault(int(row.pop("file_id")), []).append(row)
    return by_file


def _hydrate_claimed_queue_item(
    row: Any,
    file_rows: dict[int, dict[str, Any]],
    repo_rows: dict[int, dict[str, Any]],
    lead_bindings: dict[int, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """The owned dispatch context a claim hands back.

    Shared by `fetch` and `adopt-lease` so an adopted item is the same shape as
    a freshly claimed one — the replacement agent reads the fields it already
    knows instead of learning a second vocabulary for the same work.
    """
    item = dict(row)
    item["agent_name"] = str(item.pop("assigned_agent", ""))
    # `id` is the column name; `queue_item_id` is what every write that spends
    # this lease asks for (`AnalysisResultRecord.queue_item_id`, the `done` /
    # `error` / `needs-context` item_ids, the prompts' "include the fetched
    # queue_item_id"). Both are published so neither vocabulary has to be
    # translated by the caller.
    item["queue_item_id"] = int(row["id"])
    item["batch_theme"] = item.get("batch_theme", "")
    item["slot_types"] = _json_decode(item.get("slot_types_json"), [])
    item["guidance_hypotheses"] = _json_decode(item.get("guidance_hypotheses_json"), [])
    item["cross_file_triggers"] = _json_decode(item.get("cross_file_triggers_json"), [])
    item["adopted_leases"] = _adopted_lease_identities(item.get("adopted_leases_json"))
    file_row = file_rows[int(row["file_id"])]
    item["file"] = _hydrate_code_file(file_row)
    item["repo"] = _hydrate_code_repo(repo_rows[int(file_row["repo_id"])])
    slot_types = item["file"].get("slot_types", [])
    language = str(item["file"].get("language", ""))
    role = str(item["file"].get("role", ""))
    item["applicable_vuln_classes"] = _applicable_families_for_file(
        slot_types, language=language, role=role
    )
    item["path_suggested_vuln_classes"] = _path_suggested_families_for_file(
        slot_types,
        language=language,
        role=role,
        file_path=str(item["file"].get("file_path", "")),
    )
    # B2: prior art bound to this file travels with the claim. Nearly every
    # admitted file already carries a queue row by hunt time (A5), so this is
    # where a bound lead actually reaches the specialist reading the code.
    item["prior_art_leads"] = (lead_bindings or {}).get(int(row["file_id"]), [])
    return item


# The one coverage family that is not a vulnerability class: the marker some
# lanes write in place of the `not_applicable` flag to say a family was
# inspected and ruled out. A trigger is an obligation and carries no such
# marker, so it is admitted for coverage entries only.
NOT_APPLICABLE_COVERAGE_FAMILY = "not_applicable"


def _require_canonical_vuln_class(
    value: str, *, field_name: str, extra: frozenset[str] = frozenset()
) -> str:
    """Hold a durable code-track class name to the one cross-track vocabulary.

    A `cwe_coverage` family is rendered as a real column by `code-coverage
    --cwe-matrix`, so a non-canonical one is phantom coverage in the operator's
    primary effort view: a column nobody can satisfy and no required-family set
    ever asked for. A `cross_file_triggers` vuln_class becomes a durable
    obligation that can never match a canonical family, so it can never be
    discharged. Required families were already membership-checked at closeout
    (`_validate_completion_coverage`); this closes the EXTRA-entry door.

    In a backend-only deployment the agent tree — and therefore the canonical
    taxonomy — is absent. Validation is then skipped rather than failing closed,
    the same way the depth ledger treats an unavailable taxonomy.
    """
    if vuln_taxonomy is None:
        return value
    allowed = frozenset(vuln_taxonomy.VULN_CLASSES) | extra
    if value in allowed:
        return value
    # The hint folds case before matching and keeps difflib's own cutoff, so a
    # class typed in the wrong case resolves to the spelling that exists
    # (`SQLI` -> `sqli`) instead of to whatever sorts nearest at cutoff 0.0.
    # When nothing is plausibly close the roster is named instead, the way
    # `_require_canonical_language` names its own.
    canonical_by_folded = {candidate.casefold(): candidate for candidate in allowed}
    nearest = difflib.get_close_matches(
        value.casefold(), sorted(canonical_by_folded), n=1, cutoff=0.6
    )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            f"{field_name} '{value}' is not a canonical vulnerability class"
            + (
                f"; nearest canonical class: '{canonical_by_folded[nearest[0]]}'"
                if nearest
                else ". Allowed values: " + ", ".join(sorted(allowed))
            )
        ),
    )


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
        _require_canonical_vuln_class(
            family,
            field_name=f"cwe_coverage entry {idx} family",
            extra=frozenset({NOT_APPLICABLE_COVERAGE_FAMILY}),
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


def _completion_coverage_basis(
    file_row: dict[str, Any],
    queue_row: dict[str, Any],
    applicable: list[str],
) -> str:
    """Say where the required family set came from and how to re-read it.

    The required set is derived from the FILE's review identity — the
    architect's classification slot types, role and language — and never from
    the queue row's own ``slot_types``, which is batch metadata the operator
    typed at submission time. Both travel on the same claim, under names a
    reader can easily swap, so a refusal that names only the missing families
    leaves the obvious field (``slot_types``) contradicting the rule. Naming
    the basis — and the queue row's narrower list when it differs — is what
    makes one refusal the last one.
    """
    slot_types = _json_decode(file_row.get("slot_types_json"), [])
    language = str(file_row.get("language", ""))
    role = str(file_row.get("role", ""))
    basis = (
        f"The required set for this file is: {', '.join(applicable) or 'none'}. "
        "It is derived from the file's own review identity — classification "
        f"slot_types [{', '.join(slot_types) or 'none'}], role "
        f"{role or '(unset)'!r}, language {language or '(unset)'!r}"
    )
    item_slot_types = _json_decode(queue_row.get("slot_types_json"), [])
    if sorted(item_slot_types) != sorted(slot_types):
        basis += (
            f" — and not from queue item {int(queue_row['id'])}'s own slot_types "
            f"[{', '.join(item_slot_types) or 'none'}], which is submission batch "
            "metadata and never the review surface"
        )
    basis += (
        f". Read the authoritative list back with `code-dispatch progress "
        f"{int(queue_row['id'])}`; it also ships on every claim as "
        "`applicable_vuln_classes`"
    )
    return basis


def _validate_completion_coverage(
    file_row: dict[str, Any],
    cwe_coverage: list[dict[str, Any]],
    *,
    queue_row: dict[str, Any],
) -> None:
    classification = str(file_row.get("classification", ""))
    slot_types = _json_decode(file_row.get("slot_types_json"), [])
    language = str(file_row.get("language", ""))
    role = str(file_row.get("role", ""))

    if classification in {"critical", "high"} and not slot_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot complete {classification} file {file_row['file_path']} without slot_types; "
                "classification metadata is incomplete"
            ),
        )

    applicable = _applicable_families_for_file(slot_types, language=language, role=role)
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
                + ". "
                + _completion_coverage_basis(file_row, queue_row, applicable)
            ),
        )


def _compute_coverage_integrity(
    connection,
    engagement_id: int,
    queue_item_id: int,
    file_id: int,
    total_functions: int,
    cwe_coverage: list[dict[str, Any]],
) -> dict[str, Any]:
    """Derive source coverage from current grouped receipts and structural bindings."""
    receipt_counts = connection.execute(
        f"""
        SELECT
            COUNT(*) AS current_receipt_rows,
            COALESCE(SUM(
                CASE WHEN trim(evidence) != '' OR trim(evidence_ref) != '' THEN 1 ELSE 0 END
            ), 0) AS evidenced_receipt_rows
        FROM code_analysis_results
        WHERE engagement_id = ? AND queue_item_id = ? AND file_id = ?
          AND superseded_at IS NULL
          AND receipt_binding_status NOT IN (
              'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
          )
          AND ({_result_not_replaced_sql("code_analysis_results")})
        """,
        (engagement_id, queue_item_id, file_id),
    ).fetchone()
    current_receipt_rows = int(receipt_counts["current_receipt_rows"] or 0)
    evidenced_receipt_rows = int(receipt_counts["evidenced_receipt_rows"] or 0)

    distinct_structural_callables = connection.execute(
        f"""
        SELECT COUNT(DISTINCT links.callable_id)
        FROM code_analysis_results AS results
        JOIN code_analysis_result_callables AS links
          ON links.result_id = results.id AND links.file_id = ?
        WHERE results.engagement_id = ? AND results.queue_item_id = ?
          AND results.file_id = ? AND results.superseded_at IS NULL
          AND ({function_callable_link_sql("links")})
          AND results.receipt_binding_status NOT IN (
              'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
          )
          AND ({_result_not_replaced_sql("results")})
        """,
        (file_id, engagement_id, queue_item_id, file_id),
    ).fetchone()[0] or 0

    analyzed_entries = [
        e for e in cwe_coverage if not _is_cwe_entry_not_applicable(e)
    ]
    max_claimed_functions = max(
        (_safe_int(e.get("functions_analyzed", 0)) for e in analyzed_entries),
        default=0,
    )
    max_effort = max(
        (_coerce_float(e.get("effort", 0)) for e in analyzed_entries),
        default=0.0,
    )

    authoritative_blockers: list[str] = []
    advisories: list[str] = []

    if current_receipt_rows == 0 and max_claimed_functions > 0:
        authoritative_blockers.append(
            f"functions_analyzed={max_claimed_functions} claimed but 0 analysis-result rows recorded"
        )

    if distinct_structural_callables > 0 and max_claimed_functions > 0:
        ratio = distinct_structural_callables / max_claimed_functions
        if ratio < 0.3:
            advisories.append(
                f"functions_analyzed={max_claimed_functions} claimed but only "
                f"{distinct_structural_callables} structurally bound callables recorded "
                f"(ratio={ratio:.2f})"
            )

    if total_functions > 0 and max_claimed_functions > total_functions:
        advisories.append(
            f"functions_analyzed={max_claimed_functions} exceeds file total_functions={total_functions}"
        )

    if total_functions > 0 and max_effort >= 60 and current_receipt_rows == 0:
        authoritative_blockers.append(
            f"effort={max_effort:.0f} claimed for file with {total_functions} functions "
            f"but 0 analysis-result rows"
        )

    return {
        "current_receipt_rows": current_receipt_rows,
        "evidenced_receipt_rows": evidenced_receipt_rows,
        "distinct_structural_callables_reviewed": distinct_structural_callables,
        "callable_coverage_pct": round(
            min(100.0, distinct_structural_callables / total_functions * 100.0), 1
        ) if total_functions > 0 else 0.0,
        "max_claimed_functions_analyzed": max_claimed_functions,
        "total_functions_on_file": total_functions,
        "max_effort": max_effort,
        "authoritative_blockers": authoritative_blockers,
        "advisories": advisories,
        "warnings": [*authoritative_blockers, *advisories],
        "plausible": not authoritative_blockers,
    }


def _trigger_repository_path(value: Any) -> str:
    """A trigger target as its repository path: a rooted or `./` spelling names
    the same snapshot file, as finding locations do."""
    path = str(value or "").strip().lstrip("/")
    while path.startswith("./"):
        path = path[2:].lstrip("/")
    return path


# Keys a hunter plausibly writes in place of a canonical trigger key. Naming
# the near miss is what turns "entry 0 is missing file_path" on a payload that
# plainly carries a path into a one-read fix. These are reported, never
# accepted: a second accepted spelling would be a second vocabulary for the
# same durable obligation.
_CROSS_FILE_TRIGGER_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "file_path": ("target_path", "target_file_path", "path", "target", "file"),
    "vuln_class": ("vuln", "vulnerability_class", "class", "cwe", "family"),
    "reason": ("why", "rationale", "note", "notes", "description"),
}


def _trigger_key_alias_hint(trigger: dict[str, Any], canonical: str) -> str:
    present = [
        alias
        for alias in _CROSS_FILE_TRIGGER_KEY_ALIASES[canonical]
        if alias in trigger
    ]
    if not present:
        return ""
    return (
        f" (the entry carries {', '.join(repr(alias) for alias in present)}; "
        f"{canonical!r} is the one accepted spelling)"
    )


def _normalize_cross_file_triggers(
    cross_file_triggers: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Validate every entry and every required key in one pass.

    Failing on the first problem charged one refused round trip per missing key
    per entry, and nothing about the payload changes between those calls — so
    every defect is knowable on the first read. The refusal names each one
    against its entry index.
    """
    if not cross_file_triggers:
        return []
    normalized_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    problems: list[str] = []
    for idx, trigger in enumerate(cross_file_triggers):
        if not isinstance(trigger, dict):
            problems.append(f"cross_file_triggers entry {idx} must be an object")
            continue
        file_path = _trigger_repository_path(trigger.get("file_path", ""))
        vuln_class = str(trigger.get("vuln_class", "")).strip()
        reason = str(trigger.get("reason", "")).strip()
        if not file_path:
            problems.append(
                f"cross_file_triggers entry {idx} is missing file_path"
                + _trigger_key_alias_hint(trigger, "file_path")
            )
        if not vuln_class:
            problems.append(
                f"cross_file_triggers entry {idx} is missing vuln_class"
                + _trigger_key_alias_hint(trigger, "vuln_class")
            )
        else:
            try:
                _require_canonical_vuln_class(
                    vuln_class, field_name=f"cross_file_triggers entry {idx} vuln_class"
                )
            except HTTPException as exc:
                problems.append(str(exc.detail))
        if not reason:
            problems.append(
                f"cross_file_triggers entry {idx} is missing reason"
                + _trigger_key_alias_hint(trigger, "reason")
            )
        if "outside_snapshot" in trigger and type(trigger["outside_snapshot"]) is not bool:
            problems.append(
                f"cross_file_triggers entry {idx} outside_snapshot must be a boolean"
            )
        if file_path and vuln_class and reason:
            normalized = dict(trigger)
            normalized["file_path"] = file_path
            normalized["vuln_class"] = vuln_class
            normalized["reason"] = reason
            normalized_by_key[(file_path, vuln_class, reason)] = normalized
    if problems:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="; ".join(problems),
        )
    return list(normalized_by_key.values())


def _validate_cross_file_trigger_targets(
    connection,
    engagement_id: int,
    *,
    source_file_row: dict[str, Any],
    cross_file_triggers: list[dict[str, Any]],
) -> None:
    """Hold each trigger target to the source repository's current snapshot.

    A target the snapshot genuinely lacks (a binary, a dependency outside the
    checkout, a file in another repository) is declared ``outside_snapshot`` and
    recorded as a pending obligation; any other missing path is a typo that would
    block the coverage gate on a file nobody can review. Runs before the result
    writes anything, so the caller keeps its lease and can resubmit.
    """
    if not cross_file_triggers:
        return
    repo_id = int(source_file_row["repo_id"])
    generation = int(
        _get_published_repo_row(connection, engagement_id, repo_id)["active_generation"]
    )
    for trigger in cross_file_triggers:
        target_path = str(trigger["file_path"])
        file_row, problem = snapshot_location_problem(
            connection, engagement_id, repo_id, generation, target_path
        )
        if trigger.get("outside_snapshot") is True:
            if file_row is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"cross_file_triggers target '{target_path}' is declared "
                        f"outside_snapshot, but '{target_path}' is a file in generation "
                        f"{generation} of repository {repo_id}; drop outside_snapshot"
                    ),
                )
            continue
        if problem:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"cross_file_triggers target: {problem}. Correct file_path, or set "
                    "outside_snapshot: true when the target genuinely lies outside "
                    "this repository's snapshot"
                ),
            )


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
    source_repo = _get_published_repo_row(connection, engagement_id, source_repo_id)
    source_repo_generation = int(source_repo["active_generation"])
    source_manifest_digest_value = str(source_repo["source_manifest_digest"])
    for trigger in cross_file_triggers:
        target_file_path = str(trigger["file_path"])
        vuln_class = str(trigger["vuln_class"])
        reason = str(trigger["reason"])
        target_row = connection.execute(
            """
            SELECT id
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND file_path = ?
              AND retired_at IS NULL
            """,
            (engagement_id, source_repo_id, target_file_path),
        ).fetchone()
        target_file_id = int(target_row["id"]) if target_row is not None else None
        # A trigger is a new review obligation. An older review of the target
        # cannot satisfy a hypothesis that did not exist when that review ran.
        trigger_status = _TRIGGER_STATUS_PENDING

        # The identity of an already-recorded trigger differs only in how the
        # target is named: a resolved file row, or the path no admitted file
        # carries yet. Every other predicate is shared, so it is written once.
        target_predicate = (
            "target_file_id = ?"
            if target_file_id is not None
            else "target_file_id IS NULL AND target_file_path = ?"
        )
        existing = connection.execute(
            f"""
            SELECT id, status, resolution_note
            FROM code_analysis_triggers
            WHERE engagement_id = ? AND vuln_class = ? AND reason = ?
              AND source_file_id IS ? AND source_queue_item_id IS ?
              AND repo_id = ? AND repo_generation = ?
              AND {target_predicate}
            """,
            (
                engagement_id,
                vuln_class,
                reason,
                source_file_id,
                source_queue_item_id,
                source_repo_id,
                source_repo_generation,
                target_file_path if target_file_id is None else target_file_id,
            ),
        ).fetchone()

        resolution_note = ""

        if existing is None:
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_queue_item_id, source_file_id, target_file_id,
                    target_file_path, vuln_class, reason, status, resolution_note,
                    repo_id, repo_generation, source_manifest_digest
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    source_repo_id,
                    source_repo_generation,
                    source_manifest_digest_value,
                ),
            )
            continue

        existing_status = str(existing["status"])
        resolved_status = (
            existing_status
            if existing_status in _TERMINAL_TRIGGER_RESOLUTION_STATUSES
            else trigger_status
        )
        resolved_note = (
            str(existing["resolution_note"] or "")
            if existing_status in _TERMINAL_TRIGGER_RESOLUTION_STATUSES
            else resolution_note
        )
        connection.execute(
            f"""
            UPDATE code_analysis_triggers
            SET source_queue_item_id = ?,
                source_file_id = ?,
                target_file_id = ?,
                target_file_path = ?,
                vuln_class = ?,
                reason = ?,
                status = ?,
                resolved_queue_item_id = CASE
                    WHEN status IN ({','.join('?' for _ in _TERMINAL_TRIGGER_RESOLUTION_STATUSES)})
                    THEN resolved_queue_item_id ELSE NULL END,
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
                resolved_status,
                *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
                resolved_note,
                engagement_id,
                int(existing["id"]),
            ),
        )


_VALID_DISPOSITIONS = frozenset({"finding", "suspicious", "clean", "skipped"})
_VALID_DISPOSITION_PLACEHOLDERS = ", ".join("?" for _ in _VALID_DISPOSITIONS)
SKIP_REASONS = (
    "test-fixture", "generated-code", "minified", "out-of-scope-language", "vendored-dependency",
)
_VALID_ANALYSIS_RESULT_DISPOSITIONS = frozenset({"finding", "suspicious", "clean", "needs_context", "skipped"})
_UNSKIPPABLE_CLASSIFICATIONS = frozenset({"critical", "high", "medium"})


def _require_skippable_classification(file_row: dict[str, Any]) -> None:
    if str(file_row["classification"]) in _UNSKIPPABLE_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{file_row['file_path']} is {file_row['classification']}; "
                "review it and close it clean, finding or suspicious"
            ),
        )


def _require_correctable_completion(
    queue_row: dict[str, Any],
    file_row: dict[str, Any],
    *,
    disposition: str,
    result: dict[str, Any],
) -> None:
    """Hold a correction to the gates that produced the row it rewrites.

    A correction is the only write that rewrites `code_analysis_queue` on a row
    already `status='done'`, and it arrives in the WIDER receipt vocabulary
    (`_VALID_ANALYSIS_RESULT_DISPOSITIONS`) rather than the column's own
    (`_VALID_DISPOSITIONS`). Without these checks a completed row could end up
    carrying `needs_context` — a state no verb can produce — or `skipped` on a
    file no verb may skip, or `finding`/`suspicious` with nothing evidenced.
    `_successful_terminal_review_row_sql` re-derives all of it from the row plus
    its receipts, so the damage is never false credit: it is a row-level
    projection that contradicts its own receipt and an unexplained coverage
    regression. Every check runs before the insert, so a refusal leaves both
    the receipt chain and the lease exactly as they were.
    """
    item_id = int(queue_row["id"])
    if disposition not in _VALID_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot correct completed queue item {item_id} to disposition "
                f"'{disposition}'; a completed row carries one of: "
                f"{', '.join(sorted(_VALID_DISPOSITIONS))}. Open a fresh attempt "
                "with `code-dispatch reanalyze` to record anything else"
            ),
        )
    if disposition == "skipped":
        # The correction payload carries no skip_reason, so the row's own reason
        # is the only one available and `done`'s rule still applies to it.
        if str(queue_row.get("skip_reason") or "") not in SKIP_REASONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Cannot correct completed queue item {item_id} to "
                    "disposition='skipped': the completed row carries no standard "
                    f"skip_reason ({', '.join(SKIP_REASONS)}). Close a fresh "
                    "`code-dispatch reanalyze` attempt with --skip-reason instead"
                ),
            )
        _require_skippable_classification(file_row)
    if disposition == "clean" and not str(queue_row.get("analysis_notes") or "").strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot correct completed queue item {item_id} to "
                "disposition='clean': the completed row carries no analysis_notes, "
                "which a clean review requires. Close a fresh `code-dispatch "
                "reanalyze` attempt with --notes instead"
            ),
        )
    if disposition in {"finding", "suspicious"} and not (
        str(result.get("evidence", "")).strip()
        or str(result.get("evidence_ref", "")).strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"disposition='{disposition}' requires a current analysis result "
                "with evidence or evidence_ref"
            ),
        )


def _completed_queue_retry(
    connection,
    engagement_id: int,
    queue_row: dict[str, Any],
    *,
    agent_name: str,
    lease_token: str,
    disposition: str,
    notes: str,
    cwe_coverage: list[dict[str, Any]],
    skip_reason: str,
) -> dict[str, Any]:
    """Reconcile an exact completed attempt without changing or re-auditing it."""
    _require_queue_lease(connection, {int(queue_row["id"]): queue_row}, agent_name=agent_name,
                         lease_token=lease_token, action="reconcile completion")
    _require_queue_generation(connection, engagement_id, {int(queue_row["id"]): queue_row},
                              action="reconcile completion", lock=False)
    if (
        str(queue_row.get("disposition") or "") != disposition
        or str(queue_row.get("analysis_notes") or "") != notes
        or str(queue_row.get("skip_reason") or "") != skip_reason
        or _json_list_text(_json_decode(queue_row.get("cwe_coverage_json"), [])) != _json_list_text(cwe_coverage)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="completed queue item differs from this closeout; inspect progress before retrying",
        )
    file_row = _get_file_rows(connection, engagement_id, {int(queue_row["file_id"])})[
        int(queue_row["file_id"])
    ]
    return {
        "updated": 0,
        "total": 1,
        "already_applied": True,
        "coverage_integrity": _compute_coverage_integrity(
            connection, engagement_id, int(queue_row["id"]), int(queue_row["file_id"]),
            _safe_int(file_row.get("total_functions", 0)), cwe_coverage,
        ),
    }


def complete_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    disposition: str,
    notes: str = "",
    cwe_coverage: list[dict[str, Any]] | None = None,
    skip_reason: str = "",
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
    if disposition == "skipped" and skip_reason not in SKIP_REASONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"skip_reason is required when disposition='skipped', one of: {', '.join(SKIP_REASONS)}",
        )
    if disposition == "clean" and not notes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="notes are required when disposition='clean'",
        )
    now = _now_iso()
    # Skipped items had no CWE analysis run; empty cwe_coverage is the
    # natural payload. Skip both the required-non-empty check and the
    # per-CWE shape normalization.
    if disposition == "skipped":
        normalized_cwe_coverage: list[dict[str, Any]] = []
    else:
        normalized_cwe_coverage = _normalize_cwe_coverage(cwe_coverage)
    cwe_coverage_text = _json_list_text(normalized_cwe_coverage)
    placeholders = ",".join("?" for _ in item_ids)
    finding_associations: dict[str, dict[str, Any]] = {}
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        queue_row = next(iter(queue_rows.values()))
        if str(queue_row["status"]) == "done":
            return _completed_queue_retry(
                connection, engagement.id, queue_row, agent_name=agent_name,
                lease_token=lease_token, disposition=disposition, notes=notes,
                cwe_coverage=normalized_cwe_coverage, skip_reason=skip_reason,
            )
        _require_queue_status(queue_rows, expected_status="processing", action="complete")
        _require_queue_lease(connection, queue_rows, agent_name=agent_name, lease_token=lease_token, action="complete")
        _require_queue_generation(connection, engagement.id, queue_rows, action="complete")
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        queue_row = next(iter(queue_rows.values()))
        if str(queue_row["status"]) == "done":
            return _completed_queue_retry(
                connection, engagement.id, queue_row, agent_name=agent_name,
                lease_token=lease_token, disposition=disposition, notes=notes,
                cwe_coverage=normalized_cwe_coverage, skip_reason=skip_reason,
            )
        _require_queue_status(queue_rows, expected_status="processing", action="complete")
        _require_queue_lease(connection, queue_rows, agent_name=agent_name,
                             lease_token=lease_token, action="complete")
        file_row = _get_file_rows(connection, engagement.id, {int(queue_row["file_id"])})[
            int(queue_row["file_id"])
        ]
        # Receipts belong to the ATTEMPT, whose owners are the current lease plus
        # any lease adopted into it; closing under the current lease alone would
        # make an adopting agent re-record work adoption exists to preserve.
        attempt_tokens = _attempt_lease_tokens(queue_row)
        token_placeholders = ",".join("?" for _ in attempt_tokens)
        # The four reads below ask four different questions of the same row set:
        # the attempt's current, unreplaced receipts. The identity is written
        # once so no question can drift onto a different set of receipts.
        attempt_receipt_where = f"""results.engagement_id = ? AND results.queue_item_id = ?
                  AND results.file_id = ?
                  AND results.lease_token IN ({token_placeholders})
                  AND results.superseded_at IS NULL
                  AND ({_result_not_replaced_sql("results")})"""
        attempt_receipt_params = (
            engagement.id,
            int(queue_row["id"]),
            int(queue_row["file_id"]),
            *attempt_tokens,
        )
        candidate_rows = connection.execute(
            f"""
            SELECT DISTINCT disposition
            FROM code_analysis_results AS results
            WHERE {attempt_receipt_where}
              AND results.disposition IN ('finding', 'suspicious')
            ORDER BY disposition
            """,
            attempt_receipt_params,
        ).fetchall()
        candidate_dispositions = [str(row["disposition"]) for row in candidate_rows]
        if len(candidate_dispositions) > 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "conflicting candidate-bearing analysis result dispositions "
                    f"exist for this lease: {', '.join(candidate_dispositions)}"
                ),
            )
        if candidate_dispositions and disposition != candidate_dispositions[0]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "candidate-bearing analysis result requires queue disposition="
                    f"'{candidate_dispositions[0]}'; cannot complete as '{disposition}'"
                ),
            )
        if disposition == "skipped":
            _require_skippable_classification(file_row)
        if disposition == "finding":
            finding_results = connection.execute(
                f"""
                SELECT finding_slug
                FROM code_analysis_results AS results
                WHERE {attempt_receipt_where}
                  AND results.disposition = 'finding'
                ORDER BY id
                """,
                attempt_receipt_params,
            ).fetchall()
            for finding_result in finding_results:
                association = _require_reportable_root_file_finding(
                    connection,
                    engagement.id,
                    file_row,
                    finding_result["finding_slug"],
                )
                if association is not None:
                    finding_associations[str(finding_result["finding_slug"])] = association
        if disposition in {"finding", "suspicious"}:
            evidenced_result = connection.execute(
                f"""
                SELECT id
                FROM code_analysis_results AS results
                WHERE {attempt_receipt_where}
                  AND results.disposition = ?
                  AND (trim(evidence) != '' OR trim(evidence_ref) != '')
                LIMIT 1
                """,
                (*attempt_receipt_params, disposition),
            ).fetchone()
            if evidenced_result is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"disposition='{disposition}' requires a current analysis result "
                        "with evidence or evidence_ref"
                    ),
                )
        if disposition != "skipped":
            source_receipt = connection.execute(
                f"""
                SELECT results.id
                FROM code_analysis_results AS results
                WHERE {attempt_receipt_where}
                  AND results.repo_generation = ? AND results.disposition = ?
                  AND results.receipt_binding_status NOT IN (
                      'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
                  )
                  AND (
                      (results.receipt_binding_status = 'empty_file'
                       AND ? = 0 AND ? = ?)
                      OR
                      EXISTS (
                          SELECT 1 FROM code_analysis_result_callables AS links
                          WHERE links.result_id = results.id AND links.file_id = ?
                      )
                      OR EXISTS (
                          SELECT 1 FROM json_each(results.reviewed_spans_json) AS span
                          WHERE CAST(json_extract(span.value, '$.file_id') AS INTEGER) = ?
                      )
                  )
                LIMIT 1
                """,
                (
                    *attempt_receipt_params,
                    int(queue_row["repo_generation"]),
                    disposition,
                    int(file_row["loc"]),
                    str(file_row["file_hash"]),
                    hashlib.sha256(b"").hexdigest(),
                    int(queue_row["file_id"]),
                    int(queue_row["file_id"]),
                ),
            ).fetchone()
            if source_receipt is None:
                # The likeliest cause is that the preceding `code-record
                # analysis` never landed — a receipt refused on validation
                # leaves exactly this state — so the refusal names the file,
                # the attempt and the identity it searched under rather than
                # restating the rule. Without them this reads as a lease fault
                # on an unnamed file and sends the reader looking at the wrong
                # verb.
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"review of {file_row['file_path']} requires a current "
                        "source-level receipt with a matching disposition, bound "
                        f"to this file and lease: no receipt on queue item "
                        f"{int(queue_row['id'])} carries disposition="
                        f"'{disposition}' under agent {agent_name!r} with a "
                        f"structural reference into {file_row['file_path']}. "
                        f"Read what the attempt holds with `code-dispatch "
                        f"progress {int(queue_row['id'])}`; if it holds nothing, "
                        "the preceding `code-record analysis` did not land — "
                        "record it and close again"
                    ),
                )
        # Skipped items bypass the cwe-coverage completeness check — by
        # definition the analyst did not analyze the file. Other dispositions
        # still enforce the existing coverage rule.
        if disposition != "skipped":
            _validate_completion_coverage(
                file_row, normalized_cwe_coverage, queue_row=queue_row
            )
        next_status = "done"
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = ?,
                disposition = ?,
                analysis_notes = ?,
                skip_reason = ?,
                cwe_coverage_json = ?,
                completed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (next_status, disposition, notes, skip_reason, cwe_coverage_text, now, engagement.id,
             agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before completion; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        total_functions = _safe_int(file_row.get("total_functions", 0))
        integrity = _compute_coverage_integrity(
            connection,
            engagement.id,
            item_ids[0],
            int(queue_row["file_id"]),
            total_functions,
            normalized_cwe_coverage,
        )
        return {
            "updated": cursor.rowcount,
            "total": len(item_ids),
            "coverage_integrity": integrity,
            **({"finding_associations": list(finding_associations.values())}
               if finding_associations else {}),
        }


def error_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    notes: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="processing", action="mark as error")
        _require_queue_lease(connection, queue_rows, agent_name=agent_name, lease_token=lease_token, action="mark as error")
        _require_queue_generation(connection, engagement.id, queue_rows, action="mark as error")
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'error',
                analysis_notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (notes, engagement.id, agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before error transition; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def needs_context_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    expansion_request: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="processing", action="mark as needs_context")
        _require_queue_lease(
            connection,
            queue_rows, agent_name=agent_name, lease_token=lease_token, action="mark as needs_context"
        )
        _require_queue_generation(
            connection, engagement.id, queue_rows, action="mark as needs_context"
        )
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'needs_context',
                expansion_request_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (_json_text(expansion_request), engagement.id, agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before needs_context transition; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def reset_stale_queue_items(
    engagement_id: int,
    minutes: int,
    *,
    repo_id: int | None = None,
    batch_theme: str | None = None,
    queue_mode: str | None = None,
    path_prefix: list[str] | None = None,
    path_glob: list[str] | None = None,
) -> dict[str, Any]:
    """Discard every abandoned lease inside one lane.

    The sweep is destructive: it clears ownership and supersedes every receipt
    the dead lease wrote. A single global window therefore collides with a lane
    that legitimately runs longer than another — a ten-minute sweep aimed at a
    stalled triage lane also discards a deep-analysis lane's accumulated work.
    So the destructive verb takes the same predicates its read-only preview
    takes (`list --stale-minutes N`, down to the one `_file_path_scope_sql`
    owner), and what the preview showed is exactly what the sweep takes.

    A row whose lease left receipts behind is deliberately NOT exempt: keeping
    those receipts is what `adopt-lease` is for, and exempting them here would
    make the sweep unable to recover the rows it exists to recover.
    """
    engagement = _engagement_or_404(engagement_id)
    clauses = [
        "queue.engagement_id = ?",
        "queue.status = 'processing'",
        canonical_current_attempt_sql("queue", "repos"),
        f"({_lease_activity_sql('queue')} IS NULL"
        f" OR datetime({_lease_activity_sql('queue')})"
        " < datetime('now', ? || ' minutes'))",
    ]
    params: list[Any] = [engagement.id, f"-{minutes}"]
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(_coerce_int(repo_id, field_name="repo_id"))
    if batch_theme is not None:
        clauses.append("queue.batch_theme = ?")
        params.append(batch_theme)
    if queue_mode is not None:
        if queue_mode not in _QUEUE_MODES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid queue mode: {queue_mode}",
            )
        clauses.append("queue.queue_mode = ?")
        params.append(queue_mode)
    path_scope, path_params = _file_path_scope_sql("files", path_prefix, path_glob)
    if path_scope:
        clauses.append(path_scope)
        params.extend(path_params)
    with get_connection() as connection:
        register_path_scope_functions(connection)
        # Serialize stale selection with heartbeat writers. The per-row CAS
        # below is defense in depth for connections whose transaction mode is
        # changed by an embedding caller.
        connection.execute("BEGIN IMMEDIATE")
        stale_rows = connection.execute(
            f"""
            SELECT queue.id, queue.file_id, queue.lease_token,
                   COALESCE({_lease_activity_sql("queue")}, '') AS lease_activity_at
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE {' AND '.join(clauses)}
            """,
            tuple(params),
        ).fetchall()
        reset_count = 0
        for row in stale_rows:
            cursor = connection.execute(
                f"""
                UPDATE code_analysis_queue
                SET {_RETURN_TO_PENDING_SET_SQL},
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND status = 'processing'
                  AND lease_token = ?
                  AND COALESCE({_lease_activity_sql("code_analysis_queue")}, '') = ?
                """,
                (
                    _METADATA_REFRESH_REVIEW_MODE,
                    engagement.id,
                    int(row["id"]),
                    str(row["lease_token"] or ""),
                    str(row["lease_activity_at"] or ""),
                ),
            )
            if cursor.rowcount != 1:
                continue
            reset_count += 1
            # Every current receipt on this attempt, not just the last owner's:
            # an adopted attempt carries receipts written under the leases it
            # inherited, and a reset that left those current would hand them to
            # whoever claims the row next. Identical for a row never adopted,
            # whose only current receipts belong to its one lease.
            connection.execute(
                """
                UPDATE code_analysis_results SET superseded_at = ?
                WHERE queue_item_id = ? AND superseded_at IS NULL
                """,
                (_now_iso(), int(row["id"])),
            )
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"reset": reset_count}


def heartbeat_queue_item(
    engagement_id: int, *, item_id: int, agent_name: str, lease_token: str
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, {item_id})
        _require_queue_generation(connection, engagement.id, queue_rows, action="heartbeat")
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET last_heartbeat_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
            """,
            (now, engagement.id, item_id, agent_name, lease_token),
        )
        if cursor.rowcount != 1:
            _require_queue_lease(
                connection, queue_rows, agent_name=agent_name, lease_token=lease_token, action="heartbeat"
            )
            # The lease matched, so only the status can be wrong. Name it: an
            # owner that reads "not processing" cannot tell a closed row from a
            # reclaimed one, and `_require_queue_status` already names the
            # status everywhere else.
            _require_queue_status(
                queue_rows, expected_status="processing", action="heartbeat"
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot heartbeat: queue item {item_id} is not processing",
            )
    return {"item_id": item_id, "last_heartbeat_at": now}


def adopt_queue_lease(
    engagement_id: int,
    *,
    item_id: int,
    expected_agent: str,
    expected_lease_token: str,
    agent_name: str,
    stale_minutes: int,
    reason: str,
) -> dict[str, Any]:
    """Hand one abandoned processing attempt to a replacement agent.

    `reset-stale` is the other recovery and it *discards* the attempt: ownership
    is cleared, every receipt the dead lease wrote is superseded, and the file
    returns to pending for someone to analyse from scratch. Adoption makes the
    opposite trade — every accumulated row value and every receipt survives and
    only the owner changes — so it must never take a lease that is still alive,
    or two agents would author receipts for the same file.

    "Still live" is decided by the only signal a lease emits: its last
    heartbeat, falling back to a claim that has not heartbeated yet
    (:func:`_lease_activity_sql`, the same expression `reset-stale` selects on).
    A lease whose proof of life falls inside ``stale_minutes`` is live and the
    swap is refused. That window is the caller's explicit assertion of death and
    is re-evaluated on the database clock *inside* the transaction that performs
    the swap, because a window measured before the transaction could have
    expired by the time the write lands.

    The caller also pins the identity it observed, so this is a compare-and-swap
    and not a grab: the UPDATE matches the expected agent, the expected token,
    the processing status, and the exact activity timestamp read in this
    transaction. A "dead" agent that heartbeats between the read and the write
    moves that timestamp and wins the row, instead of losing its work.
    """
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    with get_connection() as connection:
        # Serialize against heartbeat and stale-reset writers for the whole
        # read-check-swap, exactly as `reset_stale_queue_items` does.
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, {item_id})
        _require_queue_status(
            queue_rows, expected_status="processing", action="adopt the lease on"
        )
        _require_queue_lease(
            connection,
            queue_rows,
            agent_name=expected_agent,
            lease_token=expected_lease_token,
            action="adopt the lease",
        )
        _require_queue_generation(
            connection, engagement.id, queue_rows, action="adopt the lease"
        )
        queue_row = queue_rows[item_id]
        liveness = connection.execute(
            f"""
            SELECT {_lease_activity_sql("queue")} AS lease_activity_at,
                   {_lease_activity_age_seconds_sql("queue")} AS heartbeat_age_seconds,
                   CASE
                       WHEN {_lease_activity_sql("queue")} IS NULL THEN 0
                       WHEN datetime({_lease_activity_sql("queue")})
                            < datetime('now', ? || ' minutes') THEN 0
                       ELSE 1
                   END AS lease_is_live
            FROM code_analysis_queue AS queue
            WHERE queue.engagement_id = ? AND queue.id = ?
            """,
            (f"-{int(stale_minutes)}", engagement.id, item_id),
        ).fetchone()
        assert liveness is not None
        if int(liveness["lease_is_live"]):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Cannot adopt queue item {item_id}: the lease held by "
                    f"{expected_agent} is still live — it last proved life at "
                    f"{liveness['lease_activity_at']}, inside the declared "
                    f"{stale_minutes}-minute window. Wait for the window to pass, "
                    "or let the current owner close the item."
                ),
            )
        adopted_leases = _adopted_lease_identities(queue_row.get("adopted_leases_json"))
        adopted_leases.append(
            {"agent_name": expected_agent, "lease_token": expected_lease_token}
        )
        if len(adopted_leases) > MAX_ADOPTED_LEASE_CHAIN:
            # The chain is walked by every readiness and coverage query, and a
            # row this often abandoned is not making progress worth preserving.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Queue item {item_id} has already been adopted "
                    f"{MAX_ADOPTED_LEASE_CHAIN} times; reset it with "
                    "`code-dispatch reset-stale` and requeue the file instead"
                ),
            )
        lease_token = str(uuid.uuid4())
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET assigned_agent = ?, lease_token = ?, adopted_leases_json = ?,
                last_heartbeat_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
              AND COALESCE({_lease_activity_sql("code_analysis_queue")}, '') = ?
            """,
            (
                agent_name,
                lease_token,
                _json_list_text(adopted_leases),
                now,
                engagement.id,
                item_id,
                expected_agent,
                expected_lease_token,
                str(liveness["lease_activity_at"] or ""),
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "queue lease changed before adoption; re-read "
                    "`code-dispatch list` and retry"
                ),
            )
        # consumed_at is deliberately left alone: the attempt started when the
        # dead lease claimed it, and that is what its elapsed work describes.
        row = connection.execute(
            "SELECT * FROM code_analysis_queue WHERE engagement_id = ? AND id = ?",
            (engagement.id, item_id),
        ).fetchone()
        file_rows = _get_file_rows(connection, engagement.id, {int(row["file_id"])})
        repo_rows = _get_repo_rows(
            connection,
            engagement.id,
            {int(file_rows[int(row["file_id"])]["repo_id"])},
        )
        item = _hydrate_claimed_queue_item(
            row,
            file_rows,
            repo_rows,
            _open_lead_bindings_by_file(
                connection, engagement.id, {int(row["file_id"])}
            ),
        )
        preserved_result_count = _scalar_row(
            connection,
            f"""
            SELECT ({_current_attempt_result_count_sql("queue")})
            FROM code_analysis_queue AS queue
            WHERE queue.engagement_id = ? AND queue.id = ?
            """,
            (engagement.id, item_id),
        )
    return {
        "item_id": item_id,
        "stale_minutes": int(stale_minutes),
        "reason": reason,
        "previous_agent_name": expected_agent,
        "previous_lease_token": expected_lease_token,
        "previous_lease_activity_at": liveness["lease_activity_at"],
        "previous_lease_age_seconds": (
            None
            if liveness["heartbeat_age_seconds"] is None
            else int(liveness["heartbeat_age_seconds"])
        ),
        "preserved_result_count": preserved_result_count,
        "adopted_leases": adopted_leases,
        "item": item,
    }


def release_queue_lease(
    engagement_id: int,
    *,
    item_id: int,
    agent_name: str,
    lease_token: str,
    reason: str,
) -> dict[str, Any]:
    """Hand one claimed row back to the pending rotation without a verdict.

    The terminal verbs are `done`, `error` and `needs-context`, and all three
    assert something about the file: a disposition, a failure, or an outstanding
    context request. A lane that claimed files another lane turns out to own has
    none of those to assert — `clean` and `skipped` would be false and
    `needs-context` would claim context is owed — so standing down forced a
    mislabel. This is the honest exit, and it deliberately adds no sixth
    disposition: a disposition is a verdict and is consumed as one by
    `_successful_terminal_review_row_sql`, `_CURRENT_ACCOUNTED_FILE_EXISTS_SQL`,
    coverage, readiness, the Code view and the report.

    Mechanically it is `reset-stale` for one row, authorized by the lease
    instead of by a staleness window: the holder presents the identity it was
    given, the row returns to unleased `pending` under the same per-row
    compare-and-swap on the lease plus its last proof of life, every receipt the
    attempt accumulated is superseded, and the reason is appended to
    `analysis_notes` exactly as `retry-error` appends its own.
    """
    engagement = _engagement_or_404(engagement_id)
    reason_text = (reason or "").strip()
    note_suffix = f"\n[released: {reason_text}]" if reason_text else "\n[released]"
    with get_connection() as connection:
        # Serialize against heartbeat and stale-reset writers for the whole
        # read-check-swap, exactly as `reset_stale_queue_items` does.
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, {item_id})
        _require_queue_status(
            queue_rows, expected_status="processing", action="release the lease on"
        )
        _require_queue_lease(
            connection,
            queue_rows,
            agent_name=agent_name,
            lease_token=lease_token,
            action="release the lease",
        )
        _require_queue_generation(
            connection, engagement.id, queue_rows, action="release the lease"
        )
        queue_row = queue_rows[item_id]
        file_id = int(queue_row["file_id"])
        file_row = _get_file_rows(connection, engagement.id, {file_id})[file_id]
        lease_activity_at = str(
            connection.execute(
                f"""
                SELECT COALESCE({_lease_activity_sql("queue")}, '')
                FROM code_analysis_queue AS queue
                WHERE queue.engagement_id = ? AND queue.id = ?
                """,
                (engagement.id, item_id),
            ).fetchone()[0]
        )
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET {_RETURN_TO_PENDING_SET_SQL},
                analysis_notes = analysis_notes || ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
              AND COALESCE({_lease_activity_sql("code_analysis_queue")}, '') = ?
            """,
            (
                _METADATA_REFRESH_REVIEW_MODE,
                note_suffix,
                engagement.id,
                item_id,
                agent_name,
                lease_token,
                lease_activity_at,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "queue lease changed before release; re-read "
                    "`code-dispatch list` and retry"
                ),
            )
        # Every current receipt on this attempt, not just the last owner's: an
        # adopted attempt carries receipts written under the leases it
        # inherited, and a release that left those current would hand them to
        # whoever claims the row next. Identical to `reset-stale`.
        discarded = connection.execute(
            """
            UPDATE code_analysis_results SET superseded_at = ?
            WHERE queue_item_id = ? AND superseded_at IS NULL
            """,
            (_now_iso(), item_id),
        ).rowcount
        _sync_file_analysis_status(connection, engagement.id, file_id)
        _sync_trigger_status_for_file(connection, engagement.id, file_id)
    return {
        "item_id": item_id,
        "file_id": file_id,
        "file_path": str(file_row["file_path"]),
        "reason": reason_text,
        "previous_agent_name": agent_name,
        "previous_lease_token": lease_token,
        "previous_lease_activity_at": lease_activity_at or None,
        "discarded_result_count": int(discarded or 0),
    }


def queue_item_progress(engagement_id: int, item_id: int) -> dict[str, Any]:
    """What one queue attempt already carries, and what closeout still owes.

    Receipts are durable the moment `code-record analysis` writes them, but
    nothing read them back per item — so a hunter recording cluster by cluster
    could not verify its own progress, and a replacement that adopted the lease
    could not tell which clusters were already reviewed. Every number here is
    derived from the helpers closeout itself uses, so this preview cannot drift
    from the rules it previews.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        queue_row = _get_queue_rows(connection, engagement.id, {item_id})[item_id]
        file_id = int(queue_row["file_id"])
        file_row = _get_file_rows(connection, engagement.id, {file_id})[file_id]
        activity = connection.execute(
            f"""
            SELECT {_lease_activity_sql("queue")} AS lease_activity_at,
                   {_lease_activity_age_seconds_sql("queue")} AS heartbeat_age_seconds
            FROM code_analysis_queue AS queue
            WHERE queue.engagement_id = ? AND queue.id = ?
            """,
            (engagement.id, item_id),
        ).fetchone()
        receipt_rows = connection.execute(
            f"""
            SELECT * FROM code_analysis_results AS results
            WHERE results.engagement_id = ? AND results.queue_item_id = ?
              AND results.superseded_at IS NULL
              AND ({_result_not_replaced_sql("results")})
            ORDER BY results.id ASC
            """,
            (engagement.id, item_id),
        ).fetchall()
        merged: dict[int, dict[str, dict[str, Any]]] = {}
        receipts: list[dict[str, Any]] = []
        for index, receipt_row in enumerate(receipt_rows):
            entries = _json_decode(receipt_row["cwe_coverage_json"], [])
            # Coverage merges over EVERY receipt; only the rendered list is
            # capped, so a long attempt still reports honest family coverage.
            _merge_cwe_coverage_entries(merged, file_id, entries)
            if index >= MAX_PROGRESS_RECEIPTS:
                continue
            receipts.append(
                {
                    "id": int(receipt_row["id"]),
                    "agent_name": str(receipt_row["agent_name"] or ""),
                    "lease_token": str(receipt_row["lease_token"] or ""),
                    "disposition": str(receipt_row["disposition"] or ""),
                    "receipt_kind": str(receipt_row["receipt_kind"] or ""),
                    "receipt_binding_status": str(
                        receipt_row["receipt_binding_status"] or ""
                    ),
                    "evidence_present": bool(
                        str(receipt_row["evidence"] or "").strip()
                        or str(receipt_row["evidence_ref"] or "").strip()
                    ),
                    "callable_count": len(
                        _json_decode(receipt_row["callable_refs_json"], [])
                    ),
                    "reviewed_span_count": len(
                        _json_decode(receipt_row["reviewed_spans_json"], [])
                    ),
                    "cwe_families": [
                        str(entry.get("family", ""))
                        for entry in entries
                        if isinstance(entry, dict) and entry.get("family")
                    ],
                    "finding_slug": str(receipt_row["finding_slug"] or ""),
                    "created_at": receipt_row["created_at"],
                }
            )
        recorded_entries = list(merged.get(file_id, {}).values())
        recorded_families = sorted(merged.get(file_id, {}))
        slot_types = _json_decode(file_row.get("slot_types_json"), [])
        language = str(file_row.get("language", ""))
        role = str(file_row.get("role", ""))
        applicable = _applicable_families_for_file(slot_types, language=language, role=role)
        path_suggested = _path_suggested_families_for_file(
            slot_types,
            language=language,
            role=role,
            file_path=str(file_row.get("file_path", "")),
        )
        integrity = _compute_coverage_integrity(
            connection,
            engagement.id,
            item_id,
            file_id,
            _safe_int(file_row.get("total_functions", 0)),
            recorded_entries,
        )
    return {
        "item_id": item_id,
        "file_id": file_id,
        "file_path": str(file_row["file_path"]),
        "classification": str(file_row.get("classification") or ""),
        "status": str(queue_row["status"]),
        "queue_mode": str(queue_row.get("queue_mode") or "initial"),
        "disposition": str(queue_row.get("disposition") or ""),
        "agent_name": str(queue_row.get("assigned_agent") or ""),
        "lease_token": str(queue_row.get("lease_token") or ""),
        "repo_generation": int(queue_row.get("repo_generation", 0) or 0),
        "consumed_at": queue_row.get("consumed_at"),
        "last_heartbeat_at": queue_row.get("last_heartbeat_at"),
        "lease_activity_at": activity["lease_activity_at"],
        "heartbeat_age_seconds": (
            None
            if activity["heartbeat_age_seconds"] is None
            else int(activity["heartbeat_age_seconds"])
        ),
        "adopted_leases": _adopted_lease_identities(queue_row.get("adopted_leases_json")),
        "applicable_vuln_classes": applicable,
        "path_suggested_vuln_classes": path_suggested,
        "recorded_cwe_families": recorded_families,
        "missing_cwe_families": [
            family for family in applicable if family not in recorded_families
        ],
        "receipts": receipts,
        # The rendered list is capped; the count is the true total, so a long
        # attempt still reports its real depth.
        "receipt_count": len(receipt_rows),
        "coverage_integrity": integrity,
    }


def retry_error_queue_items(
    engagement_id: int,
    item_ids: list[int],
    reason: str = "",
) -> dict[str, Any]:
    """C5.1: recover queue items stuck at status='error' back to 'pending'.

    `reset_stale_queue_items` only recovers abandoned 'processing' rows on a
    time window; an 'error' row has no recovery path at all today — a stuck
    error item is a permanently un-analyzed source file (silent coverage
    loss). Id-scoped like `error_queue_items` (not time-windowed): every id
    must currently be 'error' via `_require_queue_status`, so a caller cannot
    silently no-op on the wrong status. `reason` is appended to the existing
    `analysis_notes` as an audit breadcrumb rather than overwriting prior
    notes from the failed run.
    """
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"retried": 0, "total": 0, "item_ids": []}
    # Dedupe (preserving order) so `retry-error 5,5` does not fail its own
    # rowcount==len(item_ids) check — `id IN (5,5)` updates one row while len is 2.
    item_ids = list(dict.fromkeys(item_ids))
    reason_text = (reason or "").strip()
    note_suffix = f"\n[retried: {reason_text}]" if reason_text else "\n[retried]"
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="error", action="retry")
        _require_queue_generation(connection, engagement.id, queue_rows, action="retry")
        for row in queue_rows.values():
            # Every current receipt on the attempt, not just the last owner's —
            # an adopted attempt also carries the receipts it inherited, and the
            # row is about to be handed back to the fetch rotation.
            connection.execute(
                """
                UPDATE code_analysis_results SET superseded_at = ?
                WHERE queue_item_id = ? AND superseded_at IS NULL
                """,
                (_now_iso(), int(row["id"])),
            )
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET {_RETURN_TO_PENDING_SET_SQL},
                analysis_notes = analysis_notes || ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'error' AND id IN ({placeholders})
            """,
            (_METADATA_REFRESH_REVIEW_MODE, note_suffix, engagement.id, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before retry; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"retried": cursor.rowcount, "total": len(item_ids), "item_ids": sorted(item_ids)}


def retry_needs_context_queue_items(
    engagement_id: int, item_ids: list[int], reason: str
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    item_ids = list(dict.fromkeys(item_ids))
    placeholders = ",".join("?" for _ in item_ids)
    note_suffix = f"\n[context supplied: {reason.strip()}]"
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="needs_context", action="retry")
        _require_queue_generation(connection, engagement.id, queue_rows, action="retry")
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET {_RETURN_TO_PENDING_SET_SQL},
                analysis_notes = analysis_notes || ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'needs_context' AND id IN ({placeholders})
            """,
            (_METADATA_REFRESH_REVIEW_MODE, note_suffix, engagement.id, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before needs-context retry; refetch and retry",
            )
        connection.execute(
            f"""
            UPDATE code_analysis_results SET superseded_at = ?
            WHERE engagement_id = ? AND superseded_at IS NULL
              AND queue_item_id IN ({placeholders})
            """,
            (_now_iso(), engagement.id, *item_ids),
        )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
    return {"retried": len(item_ids), "total": len(item_ids), "item_ids": sorted(item_ids)}


# =========================================================================
# Analysis Results
# =========================================================================

def _require_current_run_candidate_for_finding_result(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    file_row: dict[str, Any],
    finding_slug: str | None,
) -> sqlite3.Row:
    repository = connection.execute(
        """
        SELECT repo_key, active_generation, source_manifest_digest
        FROM code_repos WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, int(file_row["repo_id"])),
    ).fetchone()
    assert repository is not None
    rows = connection.execute(
        """
        SELECT candidates.id, candidates.run_id, candidates.state,
               candidates.source_id, candidates.proof_receipt_ids_json,
               runs.source_generations_json,
               sources.target_key, sources.path, sources.content_sha256
        FROM assessment_run_candidates AS candidates
        JOIN assessment_runs AS runs ON runs.id = candidates.run_id
        JOIN assessment_run_sources AS sources ON sources.id = candidates.source_id
        WHERE candidates.engagement_id = ?
          AND candidates.state IN ('promoted', 'duplicate')
          AND candidates.finding_slug = ?
          AND runs.run_kind = 'code' AND runs.run_purpose = 'scan'
          AND runs.status IN ('queued', 'running')
          AND sources.path = ? AND sources.content_sha256 = ?
          AND sources.target_key = ?
        ORDER BY candidates.id
        """,
        (
            engagement_id,
            str(finding_slug or ""),
            str(file_row["file_path"]),
            str(file_row["file_hash"]),
            str(repository["repo_key"]),
        ),
    ).fetchall()
    exact_ids: list[int] = []
    for row in rows:
        generation_matches = [
            generation
            for generation in json.loads(str(row["source_generations_json"] or "[]"))
            if isinstance(generation, dict)
            and str(generation.get("target_key") or "")
            == str(repository["repo_key"])
        ]
        if len(generation_matches) != 1:
            continue
        generation = generation_matches[0]
        if (
            int(generation.get("generation", -1))
            == int(repository["active_generation"])
            and str(generation.get("manifest_digest") or "")
            == str(repository["source_manifest_digest"])
        ):
            if row["state"] == "duplicate":
                receipt_ids = run_accounting._json_value(row["proof_receipt_ids_json"], [])
                run_accounting._validate_receipt_ids(
                    connection, engagement_id, int(row["run_id"]), receipt_ids
                )
                if not run_accounting._proof_receipts_are_healthy(
                    connection, engagement_id, receipt_ids
                ):
                    continue
                placeholders = ",".join("?" for _ in receipt_ids)
                source_proof = connection.execute(
                    f"""
                    SELECT 1 FROM assessment_proof_receipts AS receipts
                    JOIN assessment_run_source_reads AS reads
                      ON reads.id = receipts.source_read_id
                    WHERE receipts.engagement_id = ? AND receipts.run_id = ?
                      AND receipts.id IN ({placeholders})
                      AND receipts.evidence_kind = 'source_observation'
                      AND reads.run_id = ? AND reads.source_id = ?
                    LIMIT 1
                    """,
                    (engagement_id, int(row["run_id"]), *receipt_ids,
                     int(row["run_id"]), int(row["source_id"])),
                ).fetchone()
                if source_proof is None:
                    continue
            exact_ids.append(int(row["id"]))
    if len(exact_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "finding analysis in an active code scan requires exactly one "
                "promoted or source-proven duplicate candidate bound to the current file "
                "and repository generation"
            ),
        )
    candidate = connection.execute(
        "SELECT * FROM assessment_run_candidates WHERE id = ?",
        (exact_ids[0],),
    ).fetchone()
    assert candidate is not None
    return candidate

def create_analysis_result(
    engagement_id: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if "function_name" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "function_name is historical read/filter data and is not accepted "
                "for new grouped source receipts"
            ),
        )
    disposition = str(result.get("disposition", "")).strip()
    if disposition not in _VALID_ANALYSIS_RESULT_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid disposition '{disposition}'. Must be one of: "
                f"{', '.join(sorted(_VALID_ANALYSIS_RESULT_DISPOSITIONS))}"
            ),
        )
    assessment_run_id = result.get("assessment_run_id")
    assessment_source_id = result.get("assessment_source_id")
    if (assessment_run_id is None) != (assessment_source_id is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "assessment_run_id and assessment_source_id must be supplied together"
            ),
        )
    if assessment_run_id is not None and disposition != "suspicious":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run candidate binding is only valid for suspicious analysis results",
        )
    with get_connection() as connection:
        queue_item_id = result.get("queue_item_id")
        if queue_item_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="queue_item_id is required; analysis results must be tied to a claimed queue item",
            )
        queue_row = _get_queue_rows(connection, engagement.id, {int(queue_item_id)})[
            int(queue_item_id)
        ]
        supersedes = result.get("supersedes")
        correction_mode = supersedes is not None and str(queue_row.get("status")) == "done"
        if correction_mode:
            # Serialize predecessor-currentness validation with the append below.
            connection.execute("BEGIN IMMEDIATE")
            queue_row = _get_queue_rows(
                connection, engagement.id, {int(queue_item_id)}
            )[int(queue_item_id)]
            if str(queue_row.get("status")) != "done":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="completed queue item changed state before correction; refetch and retry",
                )
        queue_file_id = int(queue_row["file_id"])
        payload_file_id = result.get("file_id")
        if payload_file_id is not None and int(payload_file_id) != queue_file_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Analysis result file_id does not match the queue item",
            )
        file_row = _get_file_rows(connection, engagement.id, {queue_file_id})[queue_file_id]
        normalized_cross_file_triggers = _normalize_cross_file_triggers(result.get("cross_file_triggers"))
        agent_name = str(result.get("agent_name", ""))
        lease_token = str(result.get("lease_token", ""))

        if not correction_mode:
            _require_queue_status(
                {int(queue_item_id): queue_row},
                expected_status="processing",
                action="record analysis results for",
            )
        _require_queue_lease(
            connection,
            {int(queue_item_id): queue_row},
            agent_name=agent_name,
            lease_token=lease_token,
            action="record analysis results",
        )
        _require_queue_generation(
            connection,
            engagement.id,
            {int(queue_item_id): queue_row},
            action="record analysis results",
        )
        _validate_cross_file_trigger_targets(
            connection,
            engagement.id,
            source_file_row=file_row,
            cross_file_triggers=normalized_cross_file_triggers,
        )
        if correction_mode:
            _require_correctable_completion(
                queue_row,
                file_row,
                disposition=disposition,
                result=result,
            )
        receipt_kind = str(result.get("receipt_kind") or "file")
        has_source_anchors = bool(
            result.get("callable_refs") or result.get("reviewed_spans")
        )
        empty_file_reviewed = result.get("empty_file_reviewed") is True
        if empty_file_reviewed:
            if (
                disposition != "clean"
                or receipt_kind != "file"
                or has_source_anchors
                or int(file_row["loc"]) != 0
                or str(file_row["file_hash"]) != hashlib.sha256(b"").hexdigest()
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "empty_file_reviewed requires a clean file receipt with no "
                        "anchors for a sealed zero-byte file"
                    ),
                )
            canonical_callable_refs = []
            callable_ids = []
            canonical_reviewed_spans = []
            receipt_binding_status = "empty_file"
        elif disposition == "skipped" and not has_source_anchors:
            canonical_callable_refs: list[dict[str, Any]] = []
            callable_ids: list[int] = []
            canonical_reviewed_spans: list[dict[str, Any]] = []
            receipt_binding_status = "skipped_unbound"
        else:
            (
                canonical_callable_refs,
                callable_ids,
                canonical_reviewed_spans,
                receipt_binding_status,
            ) = _normalize_analysis_receipt_anchors(
                connection,
                engagement_id=engagement.id,
                queue_row=queue_row,
                queue_file=file_row,
                receipt_kind=receipt_kind,
                callable_refs=result.get("callable_refs", []),
                reviewed_spans=result.get("reviewed_spans", []),
            )
        active_scan = connection.execute(
            """
            SELECT id FROM assessment_runs
            WHERE engagement_id = ? AND run_kind = 'code'
              AND run_purpose = 'scan' AND status IN ('queued', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (engagement.id,),
        ).fetchone()
        if (
            disposition == "suspicious"
            and active_scan is not None
            and assessment_run_id is None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "suspicious analysis in an active code scan requires exact "
                    "assessment_run_id and assessment_source_id candidate binding"
                ),
            )
        finding_run_candidate = None
        finding_association = None
        if disposition == "finding":
            finding_association = _require_reportable_root_file_finding(
                connection,
                engagement.id,
                file_row,
                result.get("finding_slug"),
            )
            if active_scan is not None:
                finding_run_candidate = (
                    _require_current_run_candidate_for_finding_result(
                        connection,
                        engagement_id=engagement.id,
                        file_row=file_row,
                        finding_slug=result.get("finding_slug"),
                    )
                )
        fingerprint_payload = {
            key: value
            for key, value in result.items()
            if key not in {"audit_metadata"}
        }
        fingerprint_payload["file_id"] = int(file_row["id"])
        fingerprint_payload["cross_file_triggers"] = normalized_cross_file_triggers
        fingerprint_payload["receipt_kind"] = receipt_kind
        fingerprint_payload["callable_refs"] = canonical_callable_refs
        fingerprint_payload["reviewed_spans"] = canonical_reviewed_spans
        result_fingerprint = hashlib.sha256(
            _json_text(fingerprint_payload).encode("utf-8")
        ).hexdigest()
        run_candidate_context: dict[str, Any] | None = None
        run_candidate_identity = ""
        if assessment_run_id is not None:
            repo = connection.execute(
                """
                SELECT repo_key, active_generation, source_manifest_digest
                FROM code_repos WHERE engagement_id = ? AND id = ?
                """,
                (engagement.id, int(file_row["repo_id"])),
            ).fetchone()
            assert repo is not None
            if canonical_callable_refs:
                primary_anchor = next(
                    (
                        ref
                        for ref in canonical_callable_refs
                        if int(ref["file_id"]) == int(file_row["id"])
                    ),
                    canonical_callable_refs[0],
                )
                source_anchor = (
                    f"{primary_anchor['file_path']}:{primary_anchor['start_line']}-"
                    f"{primary_anchor['end_line']}:{primary_anchor['qualified_name']}"
                )
            elif canonical_reviewed_spans:
                primary_span = next(
                    (
                        span
                        for span in canonical_reviewed_spans
                        if int(span["file_id"]) == int(file_row["id"])
                    ),
                    canonical_reviewed_spans[0],
                )
                source_anchor = (
                    f"{primary_span['file_path']}:{primary_span['start_line']}-"
                    f"{primary_span['end_line']}"
                )
            else:
                source_anchor = f"{file_row['file_path']}:(skipped)"
            # Keep exact queue/run/lease ids in the result provenance, but not in
            # the identity used to compare the same candidate across later scans.
            candidate_fingerprint_payload = {
                key: value
                for key, value in result.items()
                if key
                not in {
                    "audit_metadata",
                    "queue_item_id",
                    "file_id",
                    "agent_name",
                    "lease_token",
                    "assessment_run_id",
                    "assessment_source_id",
                }
            }
            candidate_fingerprint_payload["cross_file_triggers"] = (
                normalized_cross_file_triggers
            )
            candidate_fingerprint_payload["receipt_kind"] = receipt_kind
            candidate_fingerprint_payload["callable_refs"] = canonical_callable_refs
            candidate_fingerprint_payload["reviewed_spans"] = canonical_reviewed_spans
            result_identity_fingerprint = hashlib.sha256(
                _json_text(candidate_fingerprint_payload).encode("utf-8")
            ).hexdigest()
            run_candidate_context = {
                "engagement_id": engagement.id,
                "run_id": int(assessment_run_id),
                "source_id": int(assessment_source_id),
                "result_identity_fingerprint": result_identity_fingerprint,
                "dispatch_agent_id": agent_name,
                "target_key": str(repo["repo_key"]),
                "source_path": str(file_row["file_path"]),
                "source_sha256": str(file_row["file_hash"]),
                "repo_generation": int(repo["active_generation"]),
                "source_manifest_digest": str(repo["source_manifest_digest"]),
                "source_anchor": source_anchor,
                "vulnerability_family": str(
                    result.get("cwe_id") or result.get("slot_type") or "unclassified"
                ),
                "hypothesis": str(
                    result.get("hypothesis") or "suspicious analysis result"
                ),
            }
            run_candidate_identity = run_accounting._analysis_result_candidate_identity(
                target_key=str(run_candidate_context["target_key"]),
                source_path=str(run_candidate_context["source_path"]),
                source_sha256=str(run_candidate_context["source_sha256"]),
                source_anchor=str(run_candidate_context["source_anchor"]),
                result_identity_fingerprint=result_identity_fingerprint,
            )
        if not correction_mode:
            cursor = connection.execute(
                """
            UPDATE code_analysis_queue
            SET updated_at = updated_at
            WHERE engagement_id = ? AND id = ? AND file_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
                """,
                (engagement.id, int(queue_item_id), int(file_row["id"]), agent_name, lease_token),
            )
            if cursor.rowcount != 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="queue item changed state before recording analysis result; refetch and retry",
                )

        existing_result = connection.execute(
            """
            SELECT id FROM code_analysis_results
            WHERE engagement_id = ? AND queue_item_id = ? AND lease_token = ?
              AND result_fingerprint = ?
            """,
            (engagement.id, int(queue_item_id), lease_token, result_fingerprint),
        ).fetchone()
        if existing_result is not None:
            row = _analysis_result_row(connection, int(existing_result["id"]))
            assert row is not None
            hydrated = _hydrate_code_analysis_result(row)
            if finding_association is not None:
                hydrated["finding_association"] = finding_association
            if assessment_run_id is not None:
                candidate = connection.execute(
                    """
                    SELECT * FROM assessment_run_candidates
                    WHERE engagement_id = ? AND run_id = ? AND originating_result_id = ?
                    """,
                    (engagement.id, int(assessment_run_id), int(row["id"])),
                ).fetchone()
                if candidate is None:
                    candidate = connection.execute(
                        """
                        SELECT * FROM assessment_run_candidates
                        WHERE engagement_id = ? AND run_id = ? AND identity_key = ?
                        """,
                        (engagement.id, int(assessment_run_id), run_candidate_identity),
                    ).fetchone()
                if candidate is None:
                    raise HTTPException(
                        status_code=409,
                        detail="analysis result retry is missing its atomic run candidate",
                    )
                hydrated["run_candidate"] = run_accounting._serialize_candidate(
                    candidate
                )
            elif finding_run_candidate is not None:
                hydrated["run_candidate"] = run_accounting._serialize_candidate(
                    finding_run_candidate
                )
            return hydrated

        if supersedes is not None:
            superseded_result = connection.execute(
                """
                SELECT original.*,
                       original_queue.status AS original_queue_status,
                       replacement.id AS replaced_by_result_id
                FROM code_analysis_results AS original
                JOIN code_analysis_queue AS original_queue
                  ON original_queue.engagement_id = original.engagement_id
                 AND original_queue.id = original.queue_item_id
                LEFT JOIN code_analysis_results AS replacement
                  ON replacement.supersedes_result_id = original.id
                WHERE original.engagement_id = ? AND original.id = ?
                """,
                (engagement.id, int(supersedes)),
            ).fetchone()
            if superseded_result is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="supersedes analysis result was not found in this engagement",
                )
            if superseded_result["replaced_by_result_id"] is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result is already replaced",
                )
            if superseded_result["superseded_at"] is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result is not current for this source generation",
                )
            same_receipt_identity = (
                int(file_row["id"]),
                int(queue_row.get("repo_generation", 0) or 0),
                receipt_kind,
                _json_list_text(canonical_callable_refs),
                _json_list_text(canonical_reviewed_spans),
            )
            actual_identity = (
                int(superseded_result["file_id"]),
                int(superseded_result["repo_generation"]),
                str(superseded_result["receipt_kind"]),
                str(superseded_result["callable_refs_json"]),
                str(superseded_result["reviewed_spans_json"]),
            )
            same_attempt = (
                int(superseded_result["queue_item_id"]) == int(queue_item_id)
                and str(superseded_result["lease_token"])
                in _attempt_lease_tokens(queue_row)
            )
            completed_item_correction = (
                correction_mode
                and int(superseded_result["queue_item_id"]) == int(queue_item_id)
                and str(superseded_result["original_queue_status"]) == "done"
            )
            if (
                actual_identity != same_receipt_identity
                or not (same_attempt or completed_item_correction)
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "supersedes must identify a current result with the same file, "
                        "source anchors, and repository generation, recorded under "
                        "this attempt's lease/adoption or this completed queue item's lease"
                    ),
                )

        try:
            cursor = connection.execute(
                """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, file_id,
                agent_name, receipt_kind, callable_refs_json, reviewed_spans_json,
                receipt_binding_status, hypothesis, evidence, evidence_ref,
                disposition, confidence, finding_slug, cwe_id,
                slot_type, notes, audit_metadata_json,
                cwe_coverage_json, cross_file_triggers_json,
                lease_token, repo_generation, result_fingerprint,
                supersedes_result_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    queue_item_id,
                    int(file_row["id"]),
                    agent_name,
                    receipt_kind,
                    _json_list_text(canonical_callable_refs),
                    _json_list_text(canonical_reviewed_spans),
                    receipt_binding_status,
                    result.get("hypothesis", ""),
                    result.get("evidence", ""),
                    result.get("evidence_ref", ""),
                    disposition,
                    result.get("confidence", "medium"),
                    result.get("finding_slug", ""),
                    result.get("cwe_id", ""),
                    result.get("slot_type", ""),
                    result.get("notes", ""),
                    _json_text(result.get("audit_metadata")),
                    _json_list_text(result.get("cwe_coverage")),
                    _json_list_text(normalized_cross_file_triggers),
                    lease_token,
                    int(queue_row.get("repo_generation", 0) or 0),
                    result_fingerprint,
                    supersedes,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if supersedes is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result was concurrently replaced",
                ) from exc
            raise
        for ordinal, callable_id in enumerate(callable_ids):
            connection.execute(
                """
                INSERT INTO code_analysis_result_callables (
                    result_id, callable_id, file_id, ordinal
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    int(cursor.lastrowid),
                    callable_id,
                    int(canonical_callable_refs[ordinal]["file_id"]),
                    ordinal,
                ),
            )
        row = _analysis_result_row(connection, int(cursor.lastrowid))
        assert row is not None
        if correction_mode:
            # The completed queue row is the operator-facing decision projection.
            # Keep it aligned with the corrected receipt while preserving its
            # independently recorded coverage when the correction omits coverage.
            corrected_coverage = result.get("cwe_coverage")
            if corrected_coverage:
                corrected_coverage = _normalize_cwe_coverage(corrected_coverage)
                if disposition != "skipped":
                    _validate_completion_coverage(
                        file_row, corrected_coverage, queue_row=queue_row
                    )
            else:
                corrected_coverage = _json_decode(queue_row.get("cwe_coverage_json"), [])
            queue_update = connection.execute(
                """
                UPDATE code_analysis_queue
                SET disposition = ?, cwe_coverage_json = ?, skip_reason = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND status = 'done'
                  AND assigned_agent = ? AND lease_token = ?
                """,
                (
                    disposition,
                    _json_list_text(corrected_coverage),
                    # A corrected verdict that is no longer a skip must not keep
                    # the skip's reason: `skip_reason` is what the accounting
                    # query reads to admit a skip, and a `finding` row carrying
                    # `vendored-dependency` contradicts its own receipt.
                    str(queue_row.get("skip_reason") or "") if disposition == "skipped" else "",
                    engagement.id,
                    int(queue_item_id),
                    agent_name,
                    lease_token,
                ),
            )
            if queue_update.rowcount != 1:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="completed queue item changed state before correction; refetch and retry",
                )
        run_candidate = None
        if assessment_run_id is not None:
            assert run_candidate_context is not None
            run_candidate = run_accounting.record_analysis_result_candidate_with_connection(
                connection,
                result_id=int(row["id"]),
                **run_candidate_context,
            )
        _record_cross_file_triggers(
            connection,
            engagement.id,
            source_queue_item_id=int(queue_item_id),
            source_file_id=int(file_row["id"]),
            cross_file_triggers=normalized_cross_file_triggers,
        )
        _sync_file_analysis_status(connection, engagement.id, int(file_row["id"]))
        hydrated = _hydrate_code_analysis_result(row)
        if finding_association is not None:
            hydrated["finding_association"] = finding_association
        if run_candidate is not None:
            hydrated["run_candidate"] = run_candidate
        elif finding_run_candidate is not None:
            hydrated["run_candidate"] = run_accounting._serialize_candidate(
                finding_run_candidate
            )
        return hydrated


# Every receipt of an active repository, superseded ones included. Superseded
# receipts keep the path their own snapshot recorded and may outlive their
# queue attempt.
_ALL_ANALYSIS_RESULTS_SQL = """
        FROM code_analysis_results AS results
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = results.engagement_id
         AND findings.slug = results.finding_slug
        LEFT JOIN code_analysis_queue AS result_queue
          ON result_queue.id = results.queue_item_id
         AND result_queue.engagement_id = results.engagement_id
        JOIN code_files AS files
          ON files.id = results.file_id
         AND files.engagement_id = results.engagement_id
        LEFT JOIN code_source_generation_files AS generation_files
          ON generation_files.engagement_id = results.engagement_id
         AND generation_files.repo_id = files.repo_id
         AND generation_files.repo_generation = results.repo_generation
         AND generation_files.file_id = results.file_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE results.engagement_id = ?
"""
_RECORDED_RESULT_FILE_PATH_SQL = "COALESCE(generation_files.file_path, files.file_path)"


def get_analysis_result(engagement_id: int, result_id: int) -> dict[str, Any]:
    """One receipt by id, current or not, for the operator record view.

    Carries everything the full listing does, plus where the receipt stands:
    ``current`` (listed by the current-receipt reads), ``awaiting_verdict``
    (backs a suspicious review still awaiting a verdict), the attempt that
    wrote it, and the file's latest attempt.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        awaiting_ids = awaiting_verdict_attempt_ids(connection, engagement.id)
        row = connection.execute(
            f"""
            SELECT
                results.*,
                findings.status AS finding_workflow_status,
                findings.verification_status AS finding_verification_status,
                {_RECORDED_RESULT_FILE_PATH_SQL} AS file_path,
                files.repo_id, repos.repo_key, repos.repo_role,
                result_queue.status AS queue_status,
                result_queue.disposition AS queue_disposition,
                {_REPLACED_BY_RESULT_ID_SQL} AS replaced_by_result_id,
                (
                    SELECT latest.id || ':' || latest.status
                    FROM code_analysis_queue AS latest
                    WHERE latest.engagement_id = results.engagement_id
                      AND latest.file_id = results.file_id
                      AND latest.repo_generation = repos.active_generation
                      AND latest.source_superseded_at IS NULL
                    ORDER BY latest.id DESC LIMIT 1
                ) AS latest_attempt,
                results.id IN (SELECT results.id {_current_analysis_results_sql()}) AS current,
                {_awaiting_verdict_column_sql()}
            {_ALL_ANALYSIS_RESULTS_SQL}
              AND results.id = ?
            """,
            (engagement.id, awaiting_ids, engagement.id, result_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="analysis result not found")
    record = _hydrate_code_analysis_result(row)
    latest_id, _, latest_status = str(record.pop("latest_attempt") or "").partition(":")
    record["latest_attempt"] = {"id": int(latest_id), "status": latest_status} if latest_id else None
    record["current"] = bool(record["current"])
    record["awaiting_verdict"] = bool(record["awaiting_verdict"])
    return record


def list_analysis_results(
    engagement_id: int,
    *,
    file_id: int | None = None,
    queue_item_id: int | None = None,
    lease_token: str | None = None,
    function_name: str | None = None,
    disposition: str | None = None,
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    clauses: list[str] = []
    params: list[Any] = [engagement.id]
    _append_optional_filters(clauses, params, (
        ("results.file_id = ?", file_id),
        ("results.queue_item_id = ?", queue_item_id),
        ("results.lease_token = ?", lease_token),
        ("results.function_name = ?", function_name),
        ("results.disposition = ?", disposition),
    ))
    file_path_projection = "files.file_path"
    if include_superseded:
        file_path_projection = _RECORDED_RESULT_FILE_PATH_SQL
        source_sql = _ALL_ANALYSIS_RESULTS_SQL
    else:
        source_sql = _current_analysis_results_sql()
    query = f"""
        SELECT
            results.*,
            findings.status AS finding_workflow_status,
            findings.verification_status AS finding_verification_status,
            {file_path_projection} AS file_path,
            {_REPLACED_BY_RESULT_ID_SQL} AS replaced_by_result_id
        {source_sql}
        {''.join(f" AND {clause}" for clause in clauses)}
        ORDER BY results.id DESC
    """
    with get_connection() as connection:
        return [_hydrate_code_analysis_result(row) for row in connection.execute(query, tuple(params)).fetchall()]


# =========================================================================
# Variant-check receipts
# =========================================================================


def _current_variant_parent_rows_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
    *,
    report_durable_only: bool,
) -> dict[int, list[Any]]:
    reportable_statuses = sorted(_REPORTABLE_FINDING_STATUSES)
    status_placeholders = ",".join("?" for _ in reportable_statuses)
    lifecycle_clause = (
        "AND findings.verification_status IN ('confirmed', 'downgraded')"
        if report_durable_only
        else (
            "AND COALESCE(findings.verification_status, 'unreviewed') "
            "NOT IN ('blocked', 'false_positive')"
        )
    )
    rows = connection.execute(
        f"""
        SELECT findings.*
        FROM assessment_findings AS findings
        WHERE findings.engagement_id = ?
          AND findings.status IN ({status_placeholders})
          {lifecycle_clause}
          AND NOT EXISTS (
              SELECT 1
              FROM assessment_finding_links AS links
              WHERE links.engagement_id = findings.engagement_id
                AND links.finding_id = findings.id
                AND links.link_kind = 'variant_of'
              AND links.target_kind = 'finding'
                AND links.retired_at IS NULL
          )
        ORDER BY findings.slug
        """,
        (engagement_id, *reportable_statuses),
    ).fetchall()
    repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    eligible: dict[int, list[Any]] = {repo_id: [] for repo_id in repo_ids}
    for row in rows:
        repo_id = _finding_snapshot_repo_id(row)
        if (
            not is_file_finding(str(row["canonical_location"] or ""))
            or repo_id not in repo_ids
            or finding_code_snapshot_status(
                connection,
                engagement_id,
                row,
                repo_states=repo_states,
            )
            != "current"
        ):
            continue
        assert repo_id is not None
        eligible[repo_id].append(row)
    return eligible


def _current_phase2_variant_parent_slugs_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
) -> dict[int, list[str]]:
    return {
        repo_id: [str(row["slug"]) for row in rows]
        for repo_id, rows in _current_variant_parent_rows_by_repo(
            connection,
            engagement_id,
            repo_ids,
            report_durable_only=False,
        ).items()
    }


def _current_report_durable_variant_parent_slugs_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
) -> dict[int, list[str]]:
    return {
        repo_id: [str(row["slug"]) for row in rows]
        for repo_id, rows in _current_variant_parent_rows_by_repo(
            connection,
            engagement_id,
            repo_ids,
            report_durable_only=True,
        ).items()
    }


def _current_phase2_variant_parent_slugs(
    connection,
    engagement_id: int,
    repo_id: int,
) -> list[str]:
    return _current_phase2_variant_parent_slugs_by_repo(
        connection,
        engagement_id,
        {repo_id},
    )[repo_id]


def variant_dispatch_scope_instruction(
    repo_id: int, parent_finding_slugs: list[str]
) -> str:
    """Name the exact parent set a covering variant dispatch must freeze."""
    return (
        "Freeze the exact current Phase 2 root set "
        f"({len(parent_finding_slugs)}) on the covering dispatch: "
        "vigil assess agent start --role code-variant-hunter "
        f"--code-repo-id {repo_id} "
        f"--finding-slugs {','.join(parent_finding_slugs)}"
    )


def validate_variant_dispatch_parent_scope(
    connection,
    engagement_id: int,
    parent_finding_slugs: list[str],
) -> None:
    """Require receipt authority to freeze one repository's exact Phase 2 roots."""
    placeholders = ",".join("?" for _ in parent_finding_slugs)
    rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ? AND slug IN ({placeholders})
        """,
        (engagement_id, *parent_finding_slugs),
    ).fetchall()
    repo_ids = {_finding_snapshot_repo_id(row) for row in rows}
    if None in repo_ids or len(repo_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "code-variant-hunter finding_slugs must equal the exact current "
                "Phase 2 root set for one repository"
            ),
        )
    repo_id = next(iter(repo_ids))
    assert repo_id is not None
    expected = _current_phase2_variant_parent_slugs(
        connection,
        engagement_id,
        repo_id,
    )
    if parent_finding_slugs != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "code-variant-hunter finding_slugs must equal the exact current "
                "Phase 2 root set for one repository; expected "
                f"{expected}"
            ),
        )


@dataclass(frozen=True, slots=True)
class _VariantReceiptProjection:
    repos: dict[int, dict[str, Any]]
    files: dict[int, dict[str, Any]]
    latest_receipts: dict[int, dict[str, Any]]
    dispatch_scopes: dict[int, dict[str, Any]]
    parent_slugs: dict[int, list[str]]


_LATEST_CURRENT_VARIANT_RECEIPTS_SQL = """
    SELECT receipts.*,
           scopes.dispatch_id AS projection_scope_dispatch_id,
           scopes.parent_finding_slugs_json AS projection_scope_slugs_json,
           scopes.parent_finding_set_digest AS projection_scope_digest
    FROM code_files AS current_files
    JOIN code_repos AS current_repos
      ON current_repos.id = current_files.repo_id
     AND current_repos.engagement_id = current_files.engagement_id
     AND current_repos.active_generation > 0
    JOIN code_variant_check_receipts AS receipts
      ON receipts.id = (
          SELECT candidate.id
          FROM code_variant_check_receipts AS candidate
          WHERE candidate.engagement_id = ?
            AND candidate.current_file_id = current_files.id
          ORDER BY candidate.id DESC
          LIMIT 1
      )
    LEFT JOIN assessment_dispatches AS dispatches
      ON dispatches.id = receipts.dispatch_id
     AND dispatches.engagement_id = receipts.engagement_id
     AND dispatches.agent_role = ?
    LEFT JOIN code_variant_dispatch_scopes AS scopes
      ON scopes.dispatch_id = dispatches.id
     AND scopes.engagement_id = dispatches.engagement_id
    WHERE current_files.engagement_id = ?
      AND current_files.retired_at IS NULL
    ORDER BY current_files.id
"""


def _load_variant_receipt_projection(
    connection,
    engagement_id: int,
    *,
    file_rows: list[dict[str, Any]],
    repo_rows: list[dict[str, Any]] | None = None,
    parent_slugs: dict[int, list[str]] | None = None,
    restrict_to_files: bool = False,
) -> _VariantReceiptProjection:
    latest_receipts: dict[int, dict[str, Any]] = {}
    dispatch_scopes: dict[int, dict[str, Any]] = {}
    query = _LATEST_CURRENT_VARIANT_RECEIPTS_SQL
    params: tuple[Any, ...] = (engagement_id, _VARIANT_DISPATCH_ROLE, engagement_id)
    if restrict_to_files:
        file_ids = [int(row["id"]) for row in file_rows]
        query = query.replace(
            "ORDER BY current_files.id",
            "AND current_files.id IN (SELECT value FROM json_each(?)) ORDER BY current_files.id",
        )
        params += (json.dumps(file_ids),)
    raw_receipts = connection.execute(query, params).fetchall() if file_rows else []
    for raw_row in raw_receipts:
        row = dict(raw_row)
        scope_dispatch_id = row.pop("projection_scope_dispatch_id")
        scope_slugs_json = row.pop("projection_scope_slugs_json")
        scope_digest = row.pop("projection_scope_digest")
        latest_receipts[int(row["current_file_id"])] = row
        if scope_dispatch_id is not None:
            dispatch_scopes[int(scope_dispatch_id)] = {
                "dispatch_id": int(scope_dispatch_id),
                "parent_finding_slugs_json": scope_slugs_json,
                "parent_finding_set_digest": scope_digest,
            }
    if repo_rows is None:
        repo_ids = sorted({int(row["repo_id"]) for row in latest_receipts.values()})
        placeholders = ",".join("?" for _ in repo_ids)
        repo_rows = [dict(row) for row in connection.execute(
            f"SELECT * FROM code_repos WHERE engagement_id=? AND id IN ({placeholders})",
            (engagement_id, *repo_ids),
        ).fetchall()] if repo_ids else []
    if parent_slugs is None:
        parent_slugs = _current_phase2_variant_parent_slugs_by_repo(
            connection, engagement_id, {int(row["id"]) for row in repo_rows},
        ) if repo_rows else {}
    return _VariantReceiptProjection(
        repos={int(row["id"]): dict(row) for row in repo_rows},
        files={int(row["id"]): dict(row) for row in file_rows},
        latest_receipts=latest_receipts,
        dispatch_scopes=dispatch_scopes,
        parent_slugs=parent_slugs,
    )


def _validate_dispatch_variant_parent_slugs(
    connection,
    engagement_id: int,
    repo_id: int,
    parent_finding_slugs: list[str],
) -> None:
    if not parent_finding_slugs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check requires a non-empty parent finding scope",
        )
    placeholders = ",".join("?" for _ in parent_finding_slugs)
    rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ? AND slug IN ({placeholders})
        """,
        (engagement_id, *parent_finding_slugs),
    ).fetchall()
    if len(rows) != len(parent_finding_slugs):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="variant check dispatch references an unknown parent finding",
        )
    repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    if any(
        not is_file_finding(str(row["canonical_location"] or ""))
        or _finding_snapshot_repo_id(row) != repo_id
        or finding_code_snapshot_status(
            connection,
            engagement_id,
            row,
            repo_states=repo_states,
        )
        != "current"
        for row in rows
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "variant check dispatch parent findings must be code findings bound "
                "to the current repository snapshot"
            ),
        )


def _variant_receipt_context(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    parent_finding_slugs: list[str],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    file_row = _get_file_rows(connection, engagement_id, {file_id})[file_id]
    repo = _get_published_repo_row(connection, engagement_id, int(file_row["repo_id"]))
    finding_set_digest = _variant_parent_finding_set_digest(parent_finding_slugs)
    input_digest = variant_input_identity_digest(
        repo=repo,
        file_row=file_row,
        parent_finding_slugs=parent_finding_slugs,
    )
    return repo, file_row, finding_set_digest, input_digest


def _hydrate_variant_check_receipt(row: Any, *, current: bool) -> dict[str, Any]:
    payload = dict(row)
    payload["slot_types"] = _json_decode(payload.pop("slot_types_json", "[]"), [])
    payload["parent_finding_slugs"] = _json_decode(
        payload.pop("parent_finding_slugs_json", "[]"), []
    )
    payload["current"] = current
    return payload


def _variant_receipt_currency(connection, engagement_id: int, row, *, current: bool,
                              parent_finding_cache: dict[int, list[str]]) -> dict[str, Any]:
    repo_id = int(row["repo_id"])
    if repo_id not in parent_finding_cache:
        parent_finding_cache[repo_id] = _current_phase2_variant_parent_slugs(connection, engagement_id, repo_id)
    parents = parent_finding_cache[repo_id]
    frozen = _json_decode(row["parent_finding_slugs_json"], [])
    uncovered = sorted(set(parents) - set(frozen))
    return {
        "reason_codes": [] if current else ["parent_scope_expanded" if uncovered else "receipt_context_changed"],
        "current_parent_finding_slugs": parents,
        "uncovered_parent_finding_slugs": uncovered,
        "no_longer_required_parent_finding_slugs": sorted(set(frozen) - set(parents)),
        "next_action": "" if current else (
            "Inspect current roots and source/file identity; start a new code-variant-hunter "
            "with the exact current parent scope and record fresh covering receipts. "
            "Historical receipts and frozen dispatch scopes are not rewritten."
        ),
    }


def _variant_receipt_fingerprint(
    *,
    dispatch_id: int,
    current_file_id: int,
    variant_input_digest: str,
    status_value: str,
    evidence_ref: str,
    rationale: str,
) -> str:
    identity = {
        "dispatch_id": dispatch_id,
        "current_file_id": current_file_id,
        "variant_input_digest": variant_input_digest,
        "status": status_value,
        "evidence_ref": evidence_ref,
        "rationale": rationale,
    }
    return hashlib.sha256(_json_text(identity).encode("utf-8")).hexdigest()


def _variant_receipt_is_current(
    connection,
    engagement_id: int,
    receipt: Any,
    *,
    parent_finding_cache: dict[int, list[str]] | None = None,
    projection: _VariantReceiptProjection | None = None,
) -> bool:
    row = dict(receipt)
    file_id = row.get("current_file_id")
    if file_id is None:
        return False
    covered_parent_slugs = _json_decode(
        row.get("parent_finding_slugs_json"), []
    )
    dispatch_scope = (
        projection.dispatch_scopes.get(int(row["dispatch_id"]))
        if projection is not None
        else connection.execute(
            """
            SELECT scopes.parent_finding_slugs_json, scopes.parent_finding_set_digest
            FROM code_variant_dispatch_scopes AS scopes
            JOIN assessment_dispatches AS dispatches
              ON dispatches.id = scopes.dispatch_id
             AND dispatches.engagement_id = scopes.engagement_id
            WHERE scopes.engagement_id = ? AND scopes.dispatch_id = ?
              AND dispatches.agent_role = ?
            """,
            (engagement_id, int(row["dispatch_id"]), _VARIANT_DISPATCH_ROLE),
        ).fetchone()
    )
    if dispatch_scope is None:
        return False
    scope_parent_slugs = _json_decode(
        dispatch_scope["parent_finding_slugs_json"], []
    )
    if (
        scope_parent_slugs != covered_parent_slugs
        or str(dispatch_scope["parent_finding_set_digest"] or "")
        != _variant_parent_finding_set_digest(scope_parent_slugs)
    ):
        return False
    latest_id = (
        int(projection.latest_receipts.get(int(file_id), {}).get("id", 0) or 0)
        if projection is not None
        else int(
            (
                connection.execute(
                    """
                    SELECT MAX(id)
                    FROM code_variant_check_receipts
                    WHERE engagement_id = ? AND repo_id = ? AND current_file_id = ?
                    """,
                    (engagement_id, int(row["repo_id"]), int(file_id)),
                ).fetchone()
                or (0,)
            )[0]
            or 0
        )
    )
    if latest_id != int(row["id"]):
        return False
    file_row = (
        projection.files.get(int(file_id))
        if projection is not None
        else connection.execute(
            """
            SELECT files.*
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE files.engagement_id = ? AND files.id = ?
              AND files.retired_at IS NULL
            """,
            (engagement_id, int(file_id)),
        ).fetchone()
    )
    if file_row is None or int(file_row["repo_id"]) != int(row["repo_id"]):
        return False
    repo = (
        projection.repos.get(int(row["repo_id"]))
        if projection is not None
        else _get_published_repo_row(connection, engagement_id, int(row["repo_id"]))
    )
    if repo is None:
        return False
    cache = parent_finding_cache if parent_finding_cache is not None else {}
    current_parent_slugs = (
        projection.parent_slugs.get(int(row["repo_id"]))
        if projection is not None
        else cache.get(int(row["repo_id"]))
    )
    if current_parent_slugs is None:
        current_parent_slugs = _current_phase2_variant_parent_slugs(
            connection,
            engagement_id,
            int(row["repo_id"]),
        )
        cache[int(row["repo_id"])] = current_parent_slugs
    current_slots = sorted(set(_json_decode(file_row["slot_types_json"], [])))
    receipt_slots = sorted(set(_json_decode(row.get("slot_types_json"), [])))
    expected_input_digest = variant_input_identity_digest(
        repo=dict(repo),
        file_row=dict(file_row),
        parent_finding_slugs=covered_parent_slugs,
    )
    expected_fingerprint = _variant_receipt_fingerprint(
        dispatch_id=int(row["dispatch_id"]),
        current_file_id=int(file_id),
        variant_input_digest=str(row.get("variant_input_digest", "")),
        status_value=str(row.get("status", "")),
        evidence_ref=str(row.get("evidence_ref", "")),
        rationale=str(row.get("rationale", "")),
    )
    return (
        str(row.get("status", "")) == "completed"
        and int(row.get("repo_generation", 0) or 0)
        == int(repo.get("active_generation", 0) or 0)
        and str(row.get("source_manifest_digest", "") or "")
        == str(repo.get("source_manifest_digest", "") or "")
        and str(row.get("file_path", "") or "")
        == str(file_row["file_path"] or "")
        and str(row.get("file_sha256", "") or "")
        == str(file_row["file_hash"] or "")
        and str(row.get("language", "") or "")
        == _normalized_variant_language(file_row["language"])
        and str(row.get("classification", "") or "")
        == str(file_row["classification"] or "").strip().lower()
        and str(row.get("role", "") or "") == str(file_row["role"] or "").strip()
        and receipt_slots == current_slots
        and set(current_parent_slugs).issubset(set(covered_parent_slugs))
        and str(row.get("parent_finding_set_digest", ""))
        == _variant_parent_finding_set_digest(covered_parent_slugs)
        and str(row.get("variant_input_digest", "")) == expected_input_digest
        and str(row.get("receipt_fingerprint", "")) == expected_fingerprint
    )


def _current_variant_check_status(
    connection,
    engagement_id: int,
    file_row: dict[str, Any],
    *,
    parent_finding_cache: dict[int, list[str]] | None = None,
    projection: _VariantReceiptProjection | None = None,
) -> str:
    receipt = (
        projection.latest_receipts.get(int(file_row["id"]))
        if projection is not None
        else connection.execute(
            """
            SELECT *
            FROM code_variant_check_receipts
            WHERE engagement_id = ? AND repo_id = ? AND current_file_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (engagement_id, int(file_row["repo_id"]), int(file_row["id"])),
        ).fetchone()
    )
    if receipt is None:
        return "pending"
    return "done" if _variant_receipt_is_current(
        connection,
        engagement_id,
        receipt,
        parent_finding_cache=parent_finding_cache,
        projection=projection,
    ) else "pending"


def record_variant_check_receipt(
    engagement_id: int,
    *,
    dispatch_id: int,
    file_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    file_sha256: str,
    parent_finding_slugs: list[str],
    status_value: str,
    evidence_ref: str,
    rationale: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not parent_finding_slugs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check requires a non-empty parent_finding_slugs scope",
        )
    if (
        len(parent_finding_slugs) > MAX_VARIANT_PARENT_FINDINGS
        or parent_finding_slugs != sorted(set(parent_finding_slugs))
        or any(
            not isinstance(slug, str)
            or not slug
            or slug != slug.strip()
            or len(slug) > 256
            for slug in parent_finding_slugs
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "variant check parent_finding_slugs must be canonical, sorted, unique, "
                f"and contain at most {MAX_VARIANT_PARENT_FINDINGS} entries"
            ),
        )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        dispatch = connection.execute(
            """
            SELECT dispatches.*, scopes.parent_finding_slugs_json AS scope_slugs_json,
                   scopes.parent_finding_set_digest AS scope_finding_set_digest
            FROM assessment_dispatches AS dispatches
            LEFT JOIN code_variant_dispatch_scopes AS scopes
              ON scopes.dispatch_id = dispatches.id
             AND scopes.engagement_id = dispatches.engagement_id
            WHERE dispatches.engagement_id = ? AND dispatches.id = ?
            """,
            (engagement.id, dispatch_id),
        ).fetchone()
        if (
            dispatch is None
            or str(dispatch["agent_role"] or "") != _VARIANT_DISPATCH_ROLE
            or str(dispatch["status"] or "") not in {"in-progress", "completed"}
            or dispatch["scope_slugs_json"] is None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "variant check receipt requires a dispatch in this engagement "
                    f"with role={_VARIANT_DISPATCH_ROLE}, active/completed status, "
                    "and an immutable start-time scope"
                ),
            )
        dispatch_parent_slugs = sorted(
            set(_json_decode(dispatch["scope_slugs_json"], []))
        )
        if str(dispatch["scope_finding_set_digest"] or "") != (
            _variant_parent_finding_set_digest(dispatch_parent_slugs)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check dispatch scope failed its integrity digest",
            )
        if parent_finding_slugs != dispatch_parent_slugs:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "variant check parent_finding_slugs must exactly match the canonical "
                    "immutable start-time scope of the code-variant-hunter dispatch"
                ),
            )
        repo, file_row, finding_set_digest, input_digest = _variant_receipt_context(
            connection,
            engagement.id,
            file_id,
            parent_finding_slugs=parent_finding_slugs,
        )
        if int(repo["id"]) != repo_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check repository binding is stale",
            )
        require_current_source_binding(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="variant check",
        )
        if str(file_row.get("file_hash", "") or "") != file_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check file hash is stale",
            )
        _validate_dispatch_variant_parent_slugs(
            connection,
            engagement.id,
            repo_id,
            parent_finding_slugs,
        )
        if status_value != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="variant check status must be completed",
            )
        normalized_evidence_ref = _normalize_variant_evidence_ref(
            engagement.engagement_root,
            evidence_ref,
        )
        normalized_rationale = rationale.strip()
        if not normalized_evidence_ref or not normalized_rationale:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="variant check evidence_ref and rationale must contain non-whitespace text",
            )
        fingerprint = _variant_receipt_fingerprint(
            dispatch_id=dispatch_id,
            current_file_id=file_id,
            variant_input_digest=input_digest,
            status_value=status_value,
            evidence_ref=normalized_evidence_ref,
            rationale=normalized_rationale,
        )
        connection.execute(
            """
            INSERT INTO code_variant_check_receipts (
                engagement_id, dispatch_id, dispatch_agent_id, dispatch_agent_role,
                current_file_id, repo_id,
                repo_generation, source_manifest_digest, file_path, file_sha256,
                language, classification, role, slot_types_json,
                parent_finding_slugs_json, parent_finding_set_digest,
                variant_input_digest, status, evidence_ref, rationale,
                receipt_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, receipt_fingerprint) DO NOTHING
            """,
            (
                engagement.id,
                dispatch_id,
                str(dispatch["agent_id"] or ""),
                str(dispatch["agent_role"] or ""),
                file_id,
                repo_id,
                repo_generation,
                source_manifest_digest,
                str(file_row["file_path"]),
                file_sha256,
                _normalized_variant_language(file_row.get("language", "")),
                str(file_row.get("classification", "") or "").strip().lower(),
                str(file_row.get("role", "") or "").strip(),
                _json_list_text(sorted(set(_json_decode(file_row.get("slot_types_json"), [])))),
                _json_list_text(parent_finding_slugs),
                finding_set_digest,
                input_digest,
                status_value,
                normalized_evidence_ref,
                normalized_rationale,
                fingerprint,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM code_variant_check_receipts
            WHERE engagement_id = ? AND receipt_fingerprint = ?
            """,
            (engagement.id, fingerprint),
        ).fetchone()
        assert row is not None
        returned_receipt_current = _variant_receipt_is_current(
            connection,
            engagement.id,
            row,
        )
        current_status = _current_variant_check_status(
            connection,
            engagement.id,
            file_row,
        )
        connection.execute(
            """
            UPDATE code_files
            SET variant_check_status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (current_status, engagement.id, file_id),
        )
        return _hydrate_variant_check_receipt(
            row,
            current=returned_receipt_current,
        )


def list_variant_check_receipts(
    engagement_id: int,
    *,
    file_id: int | None = None,
    repo_id: int | None = None,
    include_stale: bool = False,
    limit: int = DEFAULT_VARIANT_RECEIPT_PAGE,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if not 1 <= limit <= MAX_VARIANT_RECEIPT_PAGE or offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"variant receipt limit must be 1..{MAX_VARIANT_RECEIPT_PAGE} "
                "and offset must be nonnegative"
            ),
        )
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if file_id is not None:
        clauses.append("current_file_id = ?")
        params.append(file_id)
    if repo_id is not None:
        clauses.append("repo_id = ?")
        params.append(repo_id)
    with get_connection() as connection:
        query = f"""
            SELECT * FROM code_variant_check_receipts
            WHERE {' AND '.join(clauses)}
            ORDER BY id DESC
        """
        parent_finding_cache: dict[int, list[str]] = {}
        if include_stale:
            rows = connection.execute(
                query + " LIMIT ? OFFSET ?", (*params, limit, offset),
            ).fetchall()
            records = []
            for row in rows:
                current = _variant_receipt_is_current(
                    connection, engagement.id, row, parent_finding_cache=parent_finding_cache,
                )
                receipt = _hydrate_variant_check_receipt(row, current=current)
                receipt["currency"] = _variant_receipt_currency(
                    connection, engagement.id, row, current=current, parent_finding_cache=parent_finding_cache,
                )
                records.append(receipt)
            return records

        records: list[dict[str, Any]] = []
        current_seen = 0
        cursor = connection.execute(query, tuple(params))
        while len(records) < limit:
            rows = cursor.fetchmany(MAX_VARIANT_RECEIPT_PAGE)
            if not rows:
                break
            for row in rows:
                if not _variant_receipt_is_current(
                    connection,
                    engagement.id,
                    row,
                    parent_finding_cache=parent_finding_cache,
                ):
                    continue
                if current_seen < offset:
                    current_seen += 1
                    continue
                records.append(_hydrate_variant_check_receipt(row, current=True))
                if len(records) == limit:
                    break
        return records


def unresolved_suspicious_analysis_obligations(
    engagement_id: int,
) -> list[dict[str, int]]:
    """Return current-generation canonical suspicious attempt counts by repo."""
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        counts = _current_suspicious_analysis_counts(connection, engagement.id)
    return [
        {"repo_id": repo_id, "suspicious_count": suspicious_count}
        for repo_id, suspicious_count in sorted(counts.items())
    ]


def report_durable_finding_variant_receipt_obligations(
    engagement_id: int,
) -> list[dict[str, Any]]:
    """Return current variant-receipt gaps for report-durable code root findings.

    The receipt table is authoritative for completed per-file variant work, but
    Vigil does not yet own an immutable candidate ledger. Until it does, fail
    closed over every admitted file in the current repository inventory instead
    of letting a scheduling classification or an intel/prose artifact exclude a
    possible variant carrier.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        repo_rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT * FROM code_repos
                WHERE engagement_id = ? AND active_generation > 0
                ORDER BY id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        repo_ids = {int(row["id"]) for row in repo_rows}
        report_durable_by_repo = _current_report_durable_variant_parent_slugs_by_repo(
            connection,
            engagement.id,
            repo_ids,
        )
        if not any(report_durable_by_repo.values()):
            return []
        currency_parent_slugs_by_repo = (
            _current_phase2_variant_parent_slugs_by_repo(
                connection,
                engagement.id,
                repo_ids,
            )
        )
        inventory_files = [
            dict(row)
            for row in connection.execute(
                f"""
                SELECT files.*
                FROM code_files AS files
                JOIN code_repos AS repos
                  ON repos.id = files.repo_id
                 AND repos.engagement_id = files.engagement_id
                 AND repos.active_generation > 0
                 AND {_analysis_repo_sql("repos")}
                WHERE files.engagement_id = ?
                  AND files.retired_at IS NULL
                ORDER BY files.repo_id, files.file_path, files.id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        files_by_repo: dict[int, list[dict[str, Any]]] = {}
        for file_row in inventory_files:
            files_by_repo.setdefault(int(file_row["repo_id"]), []).append(file_row)
        projection = _load_variant_receipt_projection(
            connection,
            engagement.id,
            repo_rows=repo_rows,
            file_rows=inventory_files,
            parent_slugs=currency_parent_slugs_by_repo,
        )
        obligations: list[dict[str, Any]] = []
        for repo_id, finding_slugs in sorted(report_durable_by_repo.items()):
            if not finding_slugs:
                continue
            repo_inventory = files_by_repo.get(repo_id, [])
            missing_files = [
                file_row
                for file_row in repo_inventory
                if _current_variant_check_status(
                    connection,
                    engagement.id,
                    file_row,
                    projection=projection,
                )
                != "done"
            ]
            if not missing_files:
                continue
            obligations.append(
                {
                    "repo_id": repo_id,
                    "finding_slugs": sorted(finding_slugs),
                    # The report-durable slugs only say why coverage is owed.
                    # Dispatch validation and receipt currency both bind the
                    # wider Phase 2 root set, so that is the scope to freeze.
                    "variant_parent_finding_slugs": list(
                        currency_parent_slugs_by_repo.get(repo_id, [])
                    ),
                    "missing_file_ids": [int(row["id"]) for row in missing_files],
                    "missing_file_paths": [
                        str(row["file_path"]) for row in missing_files
                    ],
                }
            )
        return obligations


# =========================================================================
# Threat Model
# =========================================================================

def record_threat_model(
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    threat_model: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        require_current_source_binding(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="threat model",
        )
        connection.execute(
            """
            UPDATE code_repos
            SET threat_model_json = ?, threat_model_generation = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (_json_text(threat_model), repo_generation, engagement.id, repo_id),
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
        row = _get_published_repo_row(connection, engagement.id, repo_id)
    return _threat_model_state(row)


def _threat_model_state(row: dict[str, Any]) -> dict[str, Any]:
    repo_id = int(row['id'])
    threat_model = _json_decode(row.get("threat_model_json"), {})
    threat_generation = row.get("threat_model_generation")
    active_generation = int(row.get("active_generation", 0) or 0)
    return {
        "repo_id": repo_id,
        "repo_generation": int(threat_generation) if threat_generation is not None else None,
        "active_generation": active_generation,
        "source_manifest_digest": str(row.get("source_manifest_digest", "") or ""),
        "current": threat_generation is not None and int(threat_generation) == active_generation,
        "threat_model": threat_model,
    }


def require_proof_source_prerequisites(connection, engagement_id: int, binding: dict) -> None:
    """Check only the source context a proof specialist needs, inside its claim transaction."""
    repo = _get_published_repo_row(connection, engagement_id, binding['repo_id'])
    if (repo['active_generation'] != binding['repo_generation']
            or repo['source_manifest_digest'] != binding['source_manifest_digest']):
        raise HTTPException(status_code=409, detail='Proof source generation changed; prepare current work')
    if not _threat_model_state(repo)['current']:
        raise HTTPException(status_code=409, detail='Source-bound proof requires a current generation threat model')
    if not _structural_index_current(repo):
        raise HTTPException(status_code=409, detail='Source-bound proof requires a current generation structural index')


def _structural_index_current(repo: dict[str, Any]) -> bool:
    return bool(structural_index_state(repo)["current"])


# =========================================================================
# Coverage
# =========================================================================

def _open_authoring_lease_rows(
    connection,
    engagement_id: int,
    *,
    repo_id: int | None = None,
    limit: int = MAX_OPEN_LEASE_ROWS,
) -> tuple[list[dict[str, Any]], int]:
    """Claimed analysis attempts that never reached closeout, oldest first.

    Each row is a dispatch that was authoring durable state when it stopped: the
    lease is still held, receipts may already be recorded, and nothing has
    closed the file. Counts alone read as ordinary in-flight work, which is why
    a died-mid-file dispatch used to be invisible until someone paged the queue.

    Scoped to the canonical latest attempt of an analysis repository — the same
    row set the `unresolved_active_queue` gate reason counts, so this is its
    itemization rather than a second definition of open work. Non-canonical
    active history stays separately reported as `invalid_active_history` and
    remains addressable by id through `code-dispatch list`.
    """
    repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
    repo_params: tuple[Any, ...] = () if repo_id is None else (repo_id,)
    from_where = f"""
        {queue_file_repo_join_sql(
            repo_join_predicates=(
                "repos.active_generation > 0",
                _analysis_repo_sql("repos"),
            )
        )}
        WHERE queue.engagement_id = ?
          AND queue.status = 'processing'
          AND files.retired_at IS NULL
          AND {canonical_current_attempt_sql("queue", "repos")}
          {repo_clause}
    """
    total = _scalar_row(
        connection,
        f"SELECT COUNT(*) {from_where}",
        (engagement_id, *repo_params),
    )
    rows = connection.execute(
        f"""
        SELECT queue.id AS queue_item_id, queue.file_id, queue.assigned_agent,
               queue.lease_token, queue.queue_mode, queue.batch_theme,
               queue.consumed_at, queue.last_heartbeat_at,
               queue.adopted_leases_json,
               files.file_path, files.classification, files.repo_id,
               repos.repo_key,
               {_lease_activity_sql("queue")} AS lease_activity_at,
               {_lease_activity_age_seconds_sql("queue")} AS heartbeat_age_seconds,
               ({_current_attempt_result_count_sql("queue")}) AS current_result_count
        {from_where}
        ORDER BY (lease_activity_at IS NULL) DESC, lease_activity_at ASC,
                 queue.id ASC
        LIMIT ?
        """,
        (engagement_id, *repo_params, int(limit)),
    ).fetchall()
    leases = [
        {
            "queue_item_id": int(row["queue_item_id"]),
            "file_id": int(row["file_id"]),
            "file_path": str(row["file_path"]),
            "classification": str(row["classification"] or ""),
            "repo_id": int(row["repo_id"]),
            "repo_key": str(row["repo_key"]),
            "queue_mode": str(row["queue_mode"] or "initial"),
            "batch_theme": str(row["batch_theme"] or ""),
            "agent_name": str(row["assigned_agent"] or ""),
            "lease_token": str(row["lease_token"] or ""),
            **_lease_activity_projection(row),
        }
        for row in rows
    ]
    return leases, total


def open_authoring_leases(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    limit: int = MAX_OPEN_LEASE_ROWS,
) -> dict[str, Any]:
    """Connection-owning front door for :func:`_open_authoring_lease_rows`."""
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        leases, total = _open_authoring_lease_rows(
            connection, engagement.id, repo_id=repo_id, limit=limit
        )
    return {"open_leases": leases, "open_leases_count": total}


# The receipts -> attempt -> file -> repository spine every current-receipt
# read walks. One spelling, so the alias set the receipt predicate below is
# written against cannot drift away from the joins that supply it.
_RESULT_RECEIPT_FROM_SQL = """
        FROM code_analysis_results AS results
        JOIN code_analysis_queue AS result_queue
          ON result_queue.id = results.queue_item_id
        JOIN code_files AS result_files
          ON result_files.id = results.file_id
        JOIN code_repos AS result_repos
          ON result_repos.id = result_files.repo_id"""


def _result_receipt_source(*, allow_processing: bool) -> str:
    """The current-receipt predicate over `_RESULT_RECEIPT_FROM_SQL`'s aliases."""
    return _current_result_receipt_sql(
        "results",
        "result_queue",
        "result_files",
        "result_repos",
        allow_processing=allow_processing,
    )


def _empty_receipt_effort() -> dict[str, int]:
    """Zeroed per-file review effort, in the order the views serialize it."""
    return {
        "current_receipt_rows": 0,
        "evidenced_receipt_rows": 0,
        "distinct_structural_callables_reviewed": 0,
    }


def _current_receipt_coverage_rows(
    connection,
    engagement_id: int,
    file_ids_json: str,
    *,
    allow_processing: bool,
) -> list[Any]:
    """Each current receipt's own `cwe_coverage` over the named files."""
    return connection.execute(
        f"""
        SELECT results.file_id, results.cwe_coverage_json
        {_RESULT_RECEIPT_FROM_SQL}
        WHERE results.engagement_id = ?
          AND results.file_id IN (SELECT value FROM json_each(?))
          AND ({_result_receipt_source(allow_processing=allow_processing)})
        """,
        (engagement_id, file_ids_json),
    ).fetchall()


def _current_receipt_effort_by_file(
    connection,
    engagement_id: int,
    file_ids_json: str,
    *,
    allow_processing: bool,
) -> dict[int, dict[str, int]]:
    """Per-file review effort behind the current receipts on the named files.

    ``{file_id: {current_receipt_rows, evidenced_receipt_rows,
    distinct_structural_callables_reviewed}}``. The two aggregates are read
    separately because a file can carry receipts with no structurally bound
    callable, and can carry a bound callable through a receipt recorded against
    another file; each dimension keeps its zero rather than dropping the file.
    """
    receipt_source = _result_receipt_source(allow_processing=allow_processing)
    effort: dict[int, dict[str, int]] = {}
    receipt_rows = connection.execute(
        f"""
        SELECT results.file_id,
               COUNT(DISTINCT results.id) AS current_receipt_rows,
               COUNT(DISTINCT
                   CASE WHEN trim(results.evidence) != '' OR trim(results.evidence_ref) != ''
                        THEN results.id END
               ) AS evidenced_receipt_rows
        {_RESULT_RECEIPT_FROM_SQL}
        WHERE results.engagement_id = ?
          AND results.file_id IN (SELECT value FROM json_each(?))
          AND ({receipt_source})
        GROUP BY results.file_id
        """,
        (engagement_id, file_ids_json),
    ).fetchall()
    for row in receipt_rows:
        entry = effort.setdefault(int(row["file_id"]), _empty_receipt_effort())
        entry["current_receipt_rows"] = int(row["current_receipt_rows"] or 0)
        entry["evidenced_receipt_rows"] = int(row["evidenced_receipt_rows"] or 0)
    callable_rows = connection.execute(
        f"""
        SELECT links.file_id,
               COUNT(DISTINCT links.callable_id)
                   AS distinct_structural_callables_reviewed
        {_RESULT_RECEIPT_FROM_SQL}
        JOIN code_analysis_result_callables AS links
          ON links.result_id = results.id
        WHERE results.engagement_id = ?
          AND links.file_id IN (SELECT value FROM json_each(?))
          AND ({receipt_source})
          AND ({function_callable_link_sql("links")})
        GROUP BY links.file_id
        """,
        (engagement_id, file_ids_json),
    ).fetchall()
    for row in callable_rows:
        effort.setdefault(int(row["file_id"]), _empty_receipt_effort())[
            "distinct_structural_callables_reviewed"
        ] = int(row["distinct_structural_callables_reviewed"] or 0)
    return effort


def code_coverage_summary(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    # Coverage is the obligation view, so it counts only files an analysis
    # repository owes review for. An explicit --repo-id naming a reference
    # repository therefore reports zero rather than an obligation the
    # engagement never accepted; `reference_repos` below names what was left out
    # so the smaller denominator is never a silent one.
    repo_clause = (
        " AND repo_id IN (SELECT id FROM code_repos WHERE active_generation > 0"
        f" AND {_analysis_repo_sql('code_repos')})"
        " AND retired_at IS NULL"
    )
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = (
            " AND repo_id = ? AND retired_at IS NULL"
            " AND repo_id IN (SELECT id FROM code_repos WHERE"
            f" {_analysis_repo_sql('code_repos')})"
        )
        repo_params = (repo_id,)

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)

        # -- Reference repositories (counted, never owed) --
        reference_repos = [
            {
                "repo_id": int(row["id"]),
                "repo_key": str(row["repo_key"]),
                "name": str(row["name"]),
                "admitted_files": int(row["admitted_files"]),
            }
            for row in connection.execute(
                f"""
                SELECT repos.id, repos.repo_key, repos.name,
                       (
                           SELECT COUNT(*)
                           FROM code_files AS files
                           WHERE files.engagement_id = repos.engagement_id
                             AND files.repo_id = repos.id
                             AND files.retired_at IS NULL
                       ) AS admitted_files
                FROM code_repos AS repos
                WHERE repos.engagement_id = ?
                  AND repos.active_generation > 0
                  AND NOT ({_analysis_repo_sql("repos")})
                  {"AND repos.id = ?" if repo_id is not None else ""}
                ORDER BY repos.id
                """,
                (engagement.id, *repo_params),
            ).fetchall()
        ]

        # -- Total files --
        total_files = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ?{repo_clause}",
            (engagement.id, *repo_params),
        )

        # -- By classification --
        classification_rows = connection.execute(
            f"""
            SELECT files.classification,
                   COUNT(*) AS total,
                   SUM(CASE WHEN ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) THEN 1 ELSE 0 END) AS analyzed
            FROM code_files AS files
            WHERE files.engagement_id = ?{repo_clause}
            GROUP BY files.classification
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
            SELECT current_analysis_status AS analysis_status, COUNT(*) AS total
            FROM (
                SELECT files.id,
                       {_current_analysis_status_sql()} AS current_analysis_status
                FROM code_files AS files
                WHERE files.engagement_id = ?{repo_clause}
            ) AS current_files
            GROUP BY current_analysis_status
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        by_status: dict[str, int] = {}
        for row in status_rows:
            by_status[row["analysis_status"]] = int(row["total"])

        # -- Findings summary (from assessment_findings where canonical_location starts with 'file:') --
        finding_rows = connection.execute(
            """
            SELECT f.*
            FROM assessment_findings AS f
            WHERE f.engagement_id = ?
              AND f.status NOT IN ('merged', 'false_positive')
            """,
            (engagement.id,),
        ).fetchall()
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        current_findings = [
            row
            for row in finding_rows
            if is_file_finding(str(row["canonical_location"] or ""))
            and finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            == "current"
            and (repo_id is None or _finding_snapshot_repo_id(row) == repo_id)
        ]
        total_code_findings = len(current_findings)
        by_severity: dict[str, int] = {}
        for row in current_findings:
            severity = str(row["severity"])
            by_severity[severity] = by_severity.get(severity, 0) + 1

        variant_rows = connection.execute(
            """
            SELECT DISTINCT f.*
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS f
              ON f.id = links.finding_id
             AND f.engagement_id = links.engagement_id
            WHERE f.engagement_id = ?
              AND links.link_kind = 'variant_of'
              AND links.target_kind = 'finding'
              AND links.retired_at IS NULL
              AND f.status NOT IN ('merged', 'false_positive')
            """,
            (engagement.id,),
        ).fetchall()
        variant_count = sum(
            is_file_finding(str(row["canonical_location"] or ""))
            and finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            == "current"
            and (repo_id is None or _finding_snapshot_repo_id(row) == repo_id)
            for row in variant_rows
        )

        # -- Confidence metrics --
        # The two tiers the gate refuses on, counted by one pair of statements
        # with the classification bound rather than inlined, so neither tier can
        # be counted under a predicate the other does not share.
        tier_counts: dict[str, dict[str, int]] = {
            tier: {
                "total": _scalar_row(
                    connection,
                    f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = ?{repo_clause}",
                    (engagement.id, tier, *repo_params),
                ),
                "analyzed": _scalar_row(
                    connection,
                    f"""
                    SELECT COUNT(*) FROM code_files AS files
                    WHERE files.engagement_id = ? AND files.classification = ?
                      AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}){repo_clause}
                    """,
                    (engagement.id, tier, *repo_params),
                ),
            }
            for tier in ("critical", "high")
        }
        critical_total = tier_counts["critical"]["total"]
        critical_analyzed = tier_counts["critical"]["analyzed"]
        high_total = tier_counts["high"]["total"]
        high_analyzed = tier_counts["high"]["analyzed"]
        overall_loc_analyzed = _scalar_row(
            connection,
            f"""
            SELECT COALESCE(SUM(files.loc), 0) FROM code_files AS files
            WHERE files.engagement_id = ?
              AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}){repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        queue_repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
        unresolved_needs_context = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            {queue_file_repo_join_sql(
                repo_join_predicates=(_analysis_repo_sql("repos"),)
            )}
            WHERE queue.engagement_id = ? AND queue.status = 'needs_context'
              AND repos.active_generation > 0
              AND {canonical_current_attempt_sql("queue", "repos")}
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        direct_needs_context = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_analysis_results AS results
            JOIN code_analysis_queue AS result_queue
              ON result_queue.id = results.queue_item_id
            JOIN code_files AS files
              ON files.id = results.file_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND {_analysis_repo_sql("repos")}
            WHERE results.engagement_id = ? AND results.disposition = 'needs_context'
              AND ({_current_result_receipt_sql(
                  "results", "result_queue", "files", "repos", allow_processing=True
              )})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        unresolved_needs_context += direct_needs_context
        unresolved_active_queue = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            {queue_file_repo_join_sql(
                repo_join_predicates=(_analysis_repo_sql("repos"),)
            )}
            WHERE queue.engagement_id = ?
              AND queue.status IN ('pending', 'processing')
              AND repos.active_generation > 0
              AND {canonical_current_attempt_sql("queue", "repos")}
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        invalid_active_history = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_files AS files
            WHERE files.engagement_id = ?
              AND ({_invalid_active_history_exists_sql("files")})
              AND ({_analysis_repo_files_sql("files")})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        open_leases, open_leases_count = _open_authoring_lease_rows(
            connection, engagement.id, repo_id=repo_id
        )
        trigger_repo_clause = "" if repo_id is None else " AND sf.repo_id = ?"
        trigger_rows = connection.execute(
            f"""
            SELECT t.status, COUNT(*) AS total
            FROM code_analysis_triggers AS t
            JOIN code_files AS sf
              ON sf.id = t.source_file_id
             AND sf.engagement_id = t.engagement_id
            JOIN code_repos AS repos
              ON repos.id = sf.repo_id
             AND repos.engagement_id = sf.engagement_id
             AND repos.active_generation > 0
             AND {_analysis_repo_sql("repos")}
            WHERE t.engagement_id = ?{trigger_repo_clause}
              AND t.repo_generation = repos.active_generation
              AND t.source_superseded_at IS NULL
            GROUP BY t.status
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        trigger_counts: dict[str, int] = {}
        for row in trigger_rows:
            trigger_counts[str(row["status"])] = int(row["total"])
        skip_repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
        skip_reason_rows = connection.execute(
            f"""
            SELECT queue.skip_reason, COUNT(DISTINCT queue.file_id) AS total
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND {_analysis_repo_sql("repos")}
            WHERE queue.engagement_id = ?
              AND queue.status = 'done'
              AND queue.disposition = 'skipped'
              AND trim(queue.skip_reason) != ''
              AND repos.active_generation > 0
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND queue.id = (
                  SELECT MAX(latest_queue.id)
                  FROM code_analysis_queue AS latest_queue
                  WHERE latest_queue.engagement_id = queue.engagement_id
                    AND latest_queue.file_id = queue.file_id
                    AND latest_queue.repo_generation = repos.active_generation
                    AND latest_queue.source_superseded_at IS NULL
              )
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              {skip_repo_clause}
            GROUP BY queue.skip_reason
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
    if invalid_active_history > 0:
        gate_reasons.append(
            f"Files with superseded active queue attempts: {invalid_active_history}"
        )
    if trigger_counts.get(_TRIGGER_STATUS_PENDING, 0) > 0:
        gate_reasons.append(
            f"Unprocessed cross-file triggers: {trigger_counts[_TRIGGER_STATUS_PENDING]}"
        )

    # -- Effort-threshold harness --
    effort_warnings: list[str] = []

    def record_effort_gap(classification: str, message: str) -> None:
        """Report one measured effort gap under its tier's gating class.

        Every gap reaches `effort_warnings` whatever the tier, because that is
        the instrument the operator reads (readiness `quality_gate.warnings`,
        the CWE matrix, the review-quality panel). Only a tier in
        `_BLOCKING_EFFORT_TIERS` also becomes a reason the gate refuses on, so
        the blocking scope has exactly one owner and a new call site here cannot
        quietly widen it.
        """

        effort_warnings.append(message)
        if classification in _BLOCKING_EFFORT_TIERS:
            gate_reasons.append(message)

    # W3b structural-verification accumulators (populated alongside the effort
    # harness so the uncovered-high-risk-file sub-gate reuses the same merge pass).
    file_applicable: dict[int, list[str]] = {}
    uncovered_high_risk_files: list[dict[str, Any]] = []
    with get_connection() as connection:
        successful_queue_review = _successful_terminal_review_row_sql("q")
        effort_file_rows = connection.execute(
            f"""
            SELECT files.id AS file_id, files.file_path, files.classification,
                   files.analysis_status, files.slot_types_json, files.language, files.role,
                   ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) AS review_completed,
                   q.cwe_coverage_json
            FROM code_files AS files
            JOIN code_repos AS effort_repos
              ON effort_repos.id = files.repo_id
             AND effort_repos.engagement_id = files.engagement_id
             AND effort_repos.active_generation > 0
             AND {_analysis_repo_sql("effort_repos")}
            LEFT JOIN code_analysis_queue AS q
              ON q.file_id = files.id
             AND q.engagement_id = files.engagement_id
             AND q.status = 'done'
             AND q.disposition IN ('clean', 'finding', 'suspicious')
             AND q.repo_generation = effort_repos.active_generation
             AND ({_latest_current_queue_attempt_sql("q", "effort_repos")})
             AND ({_no_superseded_active_attempt_sql("q", "effort_repos")})
             AND ({successful_queue_review})
            WHERE files.engagement_id = ?
              AND files.classification IN ('critical', 'high', 'medium'){repo_clause}
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        file_efforts: dict[int, dict[str, float]] = {}
        file_not_applicable: dict[int, set[str]] = {}
        file_meta: dict[int, dict[str, Any]] = {}
        for erow in effort_file_rows:
            fid = int(erow["file_id"])
            if fid not in file_meta:
                file_meta[fid] = {
                    "file_path": erow["file_path"],
                    "classification": erow["classification"],
                    "analysis_status": erow["analysis_status"] or "",
                    "review_completed": bool(erow["review_completed"]),
                    "has_coverage_record": False,
                    "slot_types": _json_decode(erow["slot_types_json"], []),
                    "language": erow["language"] or "",
                    "role": erow["role"] or "",
                }
            if erow["cwe_coverage_json"] is not None:
                file_meta[fid]["has_coverage_record"] = True
            cwe_cov = _json_decode(erow["cwe_coverage_json"], [])
            if fid not in file_efforts:
                file_efforts[fid] = {}
            if fid not in file_not_applicable:
                file_not_applicable[fid] = set()
            for entry in cwe_cov:
                _merge_file_effort_entry(file_efforts, file_not_applicable, fid, entry)

        if file_meta:
            file_ids_json = json.dumps(list(file_meta))
            direct_rows = _current_receipt_coverage_rows(
                connection, engagement.id, file_ids_json, allow_processing=False
            )
            for drow in direct_rows:
                fid = int(drow["file_id"])
                file_meta[fid]["has_coverage_record"] = True
                cwe_cov = _json_decode(drow["cwe_coverage_json"], [])
                if fid not in file_efforts:
                    file_efforts[fid] = {}
                if fid not in file_not_applicable:
                    file_not_applicable[fid] = set()
                for entry in cwe_cov:
                    _merge_file_effort_entry(file_efforts, file_not_applicable, fid, entry)

        for fid, meta in file_meta.items():
            classification = str(meta["classification"])
            threshold = EFFORT_THRESHOLDS[classification]
            slot_types = meta["slot_types"]
            # Classification metadata completeness is a critical/high
            # obligation: `_require_slot_types_for_classification` only demands
            # slot types on those tiers, so flagging a medium file for not
            # carrying them would make the harness noise on every medium file it
            # measures. A medium file still has applicable families from its
            # language and role baseline, and those are still measured.
            metadata_is_required = classification in {"critical", "high"}
            if not slot_types:
                if metadata_is_required:
                    record_effort_gap(
                        classification,
                        f"{classification.capitalize()} file {meta['file_path']}: "
                        "missing slot_types",
                    )
                    continue

            applicable = _applicable_families_for_file(
                slot_types,
                language=meta.get("language", ""),
                role=meta.get("role", ""),
            )
            if not applicable:
                if metadata_is_required:
                    record_effort_gap(
                        classification,
                        f"{classification.capitalize()} file {meta['file_path']}: "
                        "no applicable vulnerability families",
                    )
                continue

            # Remember the applicable family set for the W3b structural sub-gate
            # (only files with a real applicable surface are candidates).
            file_applicable[fid] = applicable

            efforts = file_efforts.get(fid, {})
            not_applicable = file_not_applicable.get(fid, set())
            if not efforts:
                if applicable and all(family in not_applicable for family in applicable):
                    continue
                if not meta["review_completed"] and not meta["has_coverage_record"]:
                    continue
                record_effort_gap(
                    classification,
                    f"{classification.capitalize()} file {meta['file_path']}: "
                    "analyzed but missing CWE coverage data",
                )
                continue

            for family in applicable:
                if family in not_applicable:
                    continue
                if efforts.get(family, 0) < threshold:
                    record_effort_gap(
                        classification,
                        f"{classification.capitalize()} file {meta['file_path']}: "
                        f"family '{family}' effort {efforts.get(family, 0):.0f} < {threshold}",
                    )

    gate_passed = len(gate_reasons) == 0

    # -- Coverage integrity cross-reference (advisory, not blocking) --
    integrity_warnings: list[dict[str, Any]] = []
    if file_meta:
        with get_connection() as connection:
            file_id_list = list(file_meta.keys())
            file_ids_json = json.dumps(list(file_id_list))
            current_result_receipt = _result_receipt_source(allow_processing=False)
            result_counts = _current_receipt_effort_by_file(
                connection, engagement.id, file_ids_json, allow_processing=False
            )
            file_func_rows = connection.execute(
                """
                SELECT id, loc, total_functions, structural_analysis_status,
                       structural_unavailable_dimensions_json
                FROM code_files
                WHERE engagement_id = ? AND id IN (SELECT value FROM json_each(?))
                """,
                (engagement.id, file_ids_json),
            ).fetchall()
            file_total_functions = {
                int(r["id"]): _safe_int(r["total_functions"]) for r in file_func_rows
            }
            # What review proof each file's structural index leaves it owing --
            # a cited function, every `<top-level>` segment, or a whole-file
            # span -- and which files current receipts leave without it.
            # Counting a file with nothing citable as "nothing to verify" is
            # what let a zero-callable critical file close with no proof at all.
            files_owing_review, files_unproven = structural_review_gaps(
                connection, engagement.id, file_id_list, current_result_receipt
            )

            for fid, meta in file_meta.items():
                if not meta["has_coverage_record"]:
                    continue
                actual = result_counts.get(fid, _empty_receipt_effort())
                total_funcs = file_total_functions.get(fid, 0)
                file_warnings: list[str] = []
                if actual["current_receipt_rows"] == 0 and meta["has_coverage_record"]:
                    efforts = file_efforts.get(fid, {})
                    max_effort = max(efforts.values(), default=0.0)
                    if max_effort >= 60 and fid in files_owing_review:
                        file_warnings.append(
                            f"effort={max_effort:.0f} with 0 source-review receipts"
                        )
                if file_warnings:
                    integrity_warnings.append({
                        "file_id": fid,
                        "file_path": meta["file_path"],
                        "classification": meta["classification"],
                        "total_functions": total_funcs,
                        "current_receipt_rows": actual["current_receipt_rows"],
                        "distinct_structural_callables_reviewed": actual[
                            "distinct_structural_callables_reviewed"
                        ],
                        "warnings": file_warnings,
                    })

            # -- W3b: uncovered high-risk files (callable-receipt structural
            # verification). A critical/high file that is terminal
            # (analyzed/done) and whose structural index found functions, but
            # which shows ZERO structurally bound callable coverage, has no linked finding, and no
            # accepted-gap resolution (all applicable families marked
            # not_applicable), is a coverage hole the effort gate alone misses
            # — the broad-18 near-miss where high files were closed with
            # functions_analyzed=0. Surfaced separately from gate.passed so the
            # phase gate can block on it while the effort dimension stays WARN.
            finding_loc_rows = connection.execute(
                """
                SELECT *
                FROM assessment_findings
                WHERE engagement_id = ?
                  AND status NOT IN ('merged', 'false_positive')
                """,
                (engagement.id,),
            ).fetchall()
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            finding_locations = [
                str(row["canonical_location"] or "").strip()
                for row in finding_loc_rows
                if is_file_finding(str(row["canonical_location"] or ""))
                and finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                == "current"
            ]
            for fid, meta in file_meta.items():
                if meta["classification"] not in ("critical", "high"):
                    continue
                # Only terminal files: unfinished files are the (a) critical/high
                # coverage sub-gate's job, not this structural one.
                if not meta["review_completed"]:
                    continue
                total_funcs = file_total_functions.get(fid, 0)
                if fid not in files_owing_review:
                    continue  # no structural index to verify against
                applicable = file_applicable.get(fid, [])
                if not applicable:
                    continue
                not_applicable = file_not_applicable.get(fid, set())
                if all(family in not_applicable for family in applicable):
                    continue  # accepted gap: every applicable family is not_applicable
                if fid not in files_unproven:
                    continue  # structurally attributable review covers what it owes
                file_path = str(meta["file_path"])
                prefix = f"file:{file_path}"
                if any(loc == prefix or loc.startswith(prefix + ":") for loc in finding_locations):
                    continue  # a finding is linked to this file
                uncovered_high_risk_files.append({
                    "file_id": fid,
                    "file_path": file_path,
                    "classification": meta["classification"],
                    "total_functions": total_funcs,
                })

    return {
        "total_files": total_files,
        # Named so a shrunken denominator is never a silent one: these repos are
        # fully readable and were deliberately excluded from every count above.
        "reference_repos": reference_repos,
        # The item-level form of the "still pending or processing" gate reason:
        # which claimed attempts never closed, how stale each lease is, and how
        # many receipts would be discarded by resetting instead of adopting.
        "open_leases": open_leases,
        "open_leases_count": open_leases_count,
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
            "invalid_active_history": invalid_active_history,
            "unprocessed_triggers": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "skip_reasons": skip_reasons,
        },
        "trigger_summary": {
            "pending": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "queued": trigger_counts.get(_TRIGGER_STATUS_QUEUED, 0),
            "resolved": trigger_counts.get(_TRIGGER_STATUS_RESOLVED, 0),
            "external_context_unavailable": trigger_counts.get(_TRIGGER_STATUS_EXTERNAL_CONTEXT, 0),
            "source_equivalent_analyzed": trigger_counts.get(_TRIGGER_STATUS_SOURCE_EQUIVALENT, 0),
            "not_applicable": trigger_counts.get(_TRIGGER_STATUS_NOT_APPLICABLE, 0),
        },
        "gate": {
            "passed": gate_passed,
            "reasons": gate_reasons,
            "effort_warnings": effort_warnings,
            "coverage_integrity": integrity_warnings,
            "uncovered_high_risk_files": uncovered_high_risk_files,
        },
    }


MAX_INHERITED_COVERAGE_PAGE = 2000


def code_coverage_inherited(
    engagement_id: int,
    *,
    generation: int,
    repo_id: int | None = None,
    path_prefix: list[str] | None = None,
    limit: int = MAX_INHERITED_COVERAGE_PAGE,
    offset: int = 0,
) -> dict[str, Any]:
    """Which uncovered current files already have a byte-identical verdict.

    A new source generation supersedes every queue row, receipt and trigger for
    the repository, so re-ingesting at a new commit takes a reviewed repository
    back to zero analyzed — including for files whose bytes never moved. That is
    the correct CURRENCY rule (a verdict attests to the bytes its author read,
    and `_record_source_generation` cannot know which files moved until the new
    roster lands), but it leaves the operator unable to tell "never reviewed"
    from "reviewed against identical bytes last generation".

    This is the read that tells them apart, and nothing more. Each row is
    labelled ``inherited`` and carries its origin generation; no row is made
    current, counted by `code_coverage_summary`, admitted by
    `_CURRENT_ACCOUNTED_FILE_EXISTS_SQL`, or allowed to satisfy the coverage
    gate — a current row would claim a currency it does not have. The predicate
    is the hash-keyed carry-forward `_rebase_lead_bindings` already applies to a
    lead's file binding, read off `code_source_generation_files.file_hash`.

    Only files that owe review now are candidates: once a file carries a current
    accounted terminal attempt it is covered, not inherited.
    """
    engagement = _engagement_or_404(engagement_id)
    origin_generation = _require_strict_positive_id(
        generation, field_name="generation"
    )
    clauses = [
        "files.engagement_id = ?",
        "files.retired_at IS NULL",
        "repos.active_generation > generation_files.repo_generation",
        f"NOT ({_CURRENT_ACCOUNTED_FILE_EXISTS_SQL})",
    ]
    params: list[Any] = [engagement.id]
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(_coerce_int(repo_id, field_name="repo_id"))
    path_scope, path_params = _file_path_scope_sql("files", path_prefix)
    if path_scope:
        clauses.append(path_scope)
        params.extend(path_params)
    with get_connection() as connection:
        register_path_scope_functions(connection)
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, int(repo_id))
        repo_clause = "" if repo_id is None else "AND generations.repo_id = ?"
        repo_params = () if repo_id is None else (int(repo_id),)
        recorded = [
            int(row["repo_generation"])
            for row in connection.execute(
                f"""
                SELECT DISTINCT generations.repo_generation
                FROM code_source_generations AS generations
                JOIN code_repos AS repos
                  ON repos.id = generations.repo_id
                 AND repos.engagement_id = generations.engagement_id
                 AND repos.active_generation > generations.repo_generation
                 AND {_analysis_repo_sql("repos")}
                WHERE generations.engagement_id = ?
                  {repo_clause}
                ORDER BY generations.repo_generation
                """,
                (engagement.id, *repo_params),
            ).fetchall()
        ]
        if origin_generation not in recorded:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"generation {origin_generation} is not a superseded source "
                    "generation of an analysis repository in scope. Superseded "
                    "generations available to inherit from: "
                    + (", ".join(str(value) for value in recorded) or "none")
                ),
            )
        # The generation each listed file now owes an attempt against. Repository
        # counters are independent, so with several in scope a single value
        # exists only where they agree; each row carries its own either way.
        # Read off the repositories in scope so that an empty page still names
        # the generation the work is owed against.
        scoped_active_generations = {
            int(row["active_generation"])
            for row in connection.execute(
                f"""
                SELECT DISTINCT repos.active_generation
                FROM code_repos AS repos
                WHERE repos.engagement_id = ?
                  AND repos.active_generation > 0
                  AND {_analysis_repo_sql("repos")}
                  {"" if repo_id is None else "AND repos.id = ?"}
                """,
                (engagement.id, *repo_params),
            ).fetchall()
        }
        rows = connection.execute(
            f"""
            SELECT files.id AS file_id, files.file_path, files.classification,
                   files.repo_id, files.file_hash, repos.repo_key,
                   repos.active_generation AS current_generation,
                   inherited.id AS inherited_queue_item_id,
                   inherited.disposition, inherited.skip_reason,
                   inherited.analysis_notes, inherited.cwe_coverage_json,
                   inherited.assigned_agent, inherited.completed_at
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
             AND {_analysis_repo_sql("repos")}
            JOIN code_source_generation_files AS generation_files
              ON generation_files.engagement_id = files.engagement_id
             AND generation_files.repo_id = files.repo_id
             AND generation_files.repo_generation = ?
             AND generation_files.file_id = files.id
             AND generation_files.file_hash = files.file_hash
            JOIN code_analysis_queue AS inherited
              ON inherited.id = (
                  SELECT MAX(candidate.id)
                  FROM code_analysis_queue AS candidate
                  WHERE candidate.engagement_id = files.engagement_id
                    AND candidate.file_id = files.id
                    AND candidate.repo_generation = generation_files.repo_generation
                    AND candidate.status = 'done'
                    AND candidate.disposition IN ({_VALID_DISPOSITION_PLACEHOLDERS})
              )
            WHERE {' AND '.join(clauses)}
            ORDER BY files.analysis_priority DESC, files.id ASC
            """,
            (origin_generation, *sorted(_VALID_DISPOSITIONS), *params),
        ).fetchall()
    total = len(rows)
    page = rows[offset : offset + limit]
    # Narrow to the repositories this answer actually spans: a page drawn from
    # one repository has a single active generation even where the engagement
    # holds several that disagree.
    active_generations = {
        int(row["current_generation"]) for row in rows
    } or scoped_active_generations
    by_disposition: dict[str, int] = {}
    for row in rows:
        disposition = str(row["disposition"])
        by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
    return {
        "repo_id": repo_id,
        "origin_generation": origin_generation,
        "active_generation": (
            next(iter(active_generations)) if len(active_generations) == 1 else None
        ),
        "path_prefix": sorted(set(path_prefix or [])),
        "total": total,
        "offset": offset,
        "count": len(page),
        "has_more": offset + len(page) < total,
        "by_disposition": by_disposition,
        "files": [
            {
                "file_id": int(row["file_id"]),
                "file_path": str(row["file_path"]),
                "classification": str(row["classification"] or ""),
                "repo_id": int(row["repo_id"]),
                "repo_key": str(row["repo_key"]),
                "file_hash": str(row["file_hash"] or ""),
                # The two labels that make the row safe to read: the verdict
                # comes from an earlier generation, and it is offered only
                # because the bytes it attests to never moved. Neither is a
                # current `analysis_status` value, so no reader can compare one
                # against a current one by accident.
                "inherited": True,
                "file_hash_unchanged": True,
                "origin_generation": origin_generation,
                "current_generation": int(row["current_generation"]),
                "inherited_queue_item_id": int(row["inherited_queue_item_id"]),
                "disposition": str(row["disposition"] or ""),
                "skip_reason": str(row["skip_reason"] or ""),
                "analysis_notes": str(row["analysis_notes"] or ""),
                "cwe_coverage": _json_decode(row["cwe_coverage_json"], []),
                "agent_name": str(row["assigned_agent"] or ""),
                "recorded_at": row["completed_at"],
            }
            for row in page
        ],
    }


DEFAULT_COVERAGE_PATH_DEPTH = 2
MAX_COVERAGE_PATH_DEPTH = 32
DEFAULT_COVERAGE_PATH_PAGE = 50
MAX_COVERAGE_PATH_PAGE = 1000


def _coverage_directory(file_path: str, depth: int) -> str:
    """The first ``depth`` directory segments of a path, or ``.`` at the root."""
    directories = file_path.split("/")[:-1]
    return "/".join(directories[:depth]) or "."


def code_coverage_by_path(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    depth: int = DEFAULT_COVERAGE_PATH_DEPTH,
    path_prefix: list[str] | None = None,
    limit: int = DEFAULT_COVERAGE_PATH_PAGE,
    offset: int = 0,
) -> dict[str, Any]:
    """Break the coverage obligation down by directory.

    Each row groups an analysis repository's admitted files by their first
    ``depth`` directory segments and carries the same projections the summary
    and readiness make, each read from its single owner: the status bucket
    (`_current_analysis_status_sql`), analyzed-by-classification
    (`_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL`), unreviewed structural debt
    (`_structural_debt_sql`) and accounted skips (`_CURRENT_ACCOUNTED_FILE_EXISTS_SQL`
    without a successful review). The terminal-verdict split reads the same
    current attempt under the same accounting guard, so a directory can never
    report a verdict for a file its own status column calls unreviewed.
    Reference repositories owe nothing and are left out, as in the summary.
    Rows sort by uncovered critical+high files, most first, then by path, so
    the directory owing the most high-risk review leads.
    """
    engagement = _engagement_or_404(engagement_id)
    if not 1 <= depth <= MAX_COVERAGE_PATH_DEPTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"depth must be between 1 and {MAX_COVERAGE_PATH_DEPTH}",
        )
    clauses = ["files.engagement_id = ?", "files.retired_at IS NULL"]
    params: list[Any] = [engagement.id]
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(_coerce_int(repo_id, field_name="repo_id"))
    path_scope, path_params = _file_path_scope_sql("files", path_prefix)
    if path_scope:
        clauses.append(path_scope)
        params.extend(path_params)
    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, int(repo_id))
        file_rows = connection.execute(
            f"""
            SELECT files.repo_id, repos.repo_key, files.file_path, files.loc,
                   files.classification, files.structural_analysis_status,
                   files.structural_artifact_truncated,
                   {_current_analysis_status_sql()} AS current_analysis_status,
                   ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) AS analyzed,
                   {_structural_debt_sql()} AS structural_debt,
                   (({_CURRENT_ACCOUNTED_FILE_EXISTS_SQL})
                    AND NOT ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL})) AS accounted_skip,
                   (
                       SELECT terminal.disposition
                       FROM code_analysis_queue AS terminal
                       WHERE terminal.engagement_id = files.engagement_id
                         AND terminal.file_id = files.id
                         AND terminal.status = 'done'
                         AND terminal.repo_generation = repos.active_generation
                         AND terminal.source_superseded_at IS NULL
                         AND ({_latest_current_queue_attempt_sql("terminal", "repos")})
                         AND ({_no_superseded_active_attempt_sql("terminal", "repos")})
                         -- The verdict is drawn from the same population
                         -- `analyzed` and `accounted_skip` are: this is the one
                         -- row all three read, so without the accounting guard
                         -- a `done` row that never proved a claimed attempt
                         -- would report a verdict beside a status that says the
                         -- file was never reviewed.
                         AND ({_CURRENT_ACCOUNTED_FILE_EXISTS_SQL})
                   ) AS latest_disposition
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
             AND {_analysis_repo_sql("repos")}
            WHERE {' AND '.join(clauses)}
            """,
            tuple(params),
        ).fetchall()

    directories: dict[tuple[int, str], dict[str, Any]] = {}
    for row in file_rows:
        key = (int(row["repo_id"]), _coverage_directory(str(row["file_path"]), depth))
        entry = directories.get(key)
        if entry is None:
            entry = directories[key] = {
                "repo_id": key[0],
                "repo_key": str(row["repo_key"]),
                "path": key[1],
                "files": 0,
                "loc": 0,
                "by_classification": {},
                "by_disposition": {},
                "uncovered_critical_high": 0,
                "by_status": dict.fromkeys(CURRENT_ANALYSIS_STATUSES, 0),
                "structural_debt": {
                    "count": 0, "degraded": 0, "unsupported": 0, "truncated": 0,
                },
                "accounted_skips": 0,
            }
        analyzed = bool(row["analyzed"])
        classification = str(row["classification"])
        entry["files"] += 1
        entry["loc"] += _safe_int(row["loc"])
        tier = entry["by_classification"].setdefault(
            classification, {"count": 0, "analyzed": 0}
        )
        tier["count"] += 1
        tier["analyzed"] += int(analyzed)
        if classification in {"critical", "high"} and not analyzed:
            entry["uncovered_critical_high"] += 1
        entry["by_status"][str(row["current_analysis_status"])] += 1
        if row["structural_debt"]:
            debt = entry["structural_debt"]
            debt["count"] += 1
            structural_status = str(row["structural_analysis_status"] or "")
            if structural_status in {"degraded", "unsupported"}:
                debt[structural_status] += 1
            if row["structural_artifact_truncated"]:
                debt["truncated"] += 1
        entry["accounted_skips"] += int(bool(row["accounted_skip"]))
        disposition = str(row["latest_disposition"] or "")
        if disposition in _VALID_DISPOSITIONS:
            entry["by_disposition"][disposition] = (
                entry["by_disposition"].get(disposition, 0) + 1
            )

    ordered = sorted(
        directories.values(),
        key=lambda item: (-item["uncovered_critical_high"], item["path"], item["repo_id"]),
    )
    page = ordered[offset : offset + limit]
    return {
        "repo_id": repo_id,
        "depth": depth,
        "path_prefix": sorted(set(path_prefix or [])),
        "total": len(ordered),
        "offset": offset,
        "count": len(page),
        "has_more": offset + len(page) < len(ordered),
        "directories": page,
    }


# =========================================================================
# B2: prior-art lead → code-location bindings
# =========================================================================
#
# A lead is, and stays, one row in ``intel_notes`` carrying a ``lead_status``.
# This section adds the half that was missing: *where* in the reviewed source
# the lead points, so the queue can turn it into work and completion
# accounting can notice it was never answered. There is deliberately no second
# lead identity here — every disposition still reads and writes
# ``intel_notes.lead_status``.

MAX_LEAD_BINDING_PAGE = 500
DEFAULT_LEAD_BINDING_PAGE = 200
# Sampled into the completion blocker so the operator can open each lead
# directly instead of re-deriving the worklist from a bare count.
LEAD_BLOCKER_SAMPLE = 5


def _lead_binding_stale_sql(binding_alias: str, repo_alias: str) -> str:
    """True when a binding's line range was read from bytes that moved on.

    Either the refresh path stamped the row, or the repository advanced a
    generation without carrying it forward. Both mean the same thing to a
    reader: the range has to be re-read before it can be trusted. One
    expression, so the worklist filter, the claimed-item projection and the
    completion blocker's stale count cannot come to disagree about which
    bindings are stale.
    """
    return (
        f"({binding_alias}.source_superseded_at IS NOT NULL"
        f" OR {binding_alias}.repo_generation != {repo_alias}.active_generation)"
    )


# ``lead_superseded_by_id`` is the lead's own disposition arriving by the intel
# route: superseding the note IS answering it, so the binding stops carrying an
# obligation while staying readable and naming the note that replaced it.
_LEAD_BINDING_SELECT = f"""
SELECT bindings.*,
       notes.title AS lead_title,
       notes.lead_status AS lead_status,
       notes.superseded_by_id AS lead_superseded_by_id,
       CASE
         WHEN bindings.unbound_at IS NOT NULL THEN 'unbound'
         WHEN {_lead_binding_stale_sql("bindings", "repos")} THEN 'stale'
         ELSE 'current'
       END AS binding_status,
       repos.repo_key AS repo_key,
       repos.repo_role AS repo_role,
       files.analysis_priority AS analysis_priority,
       files.classification AS classification,
       files.retired_at AS file_retired_at,
       (
         SELECT queue.id || ':' || queue.status FROM code_analysis_queue AS queue
         WHERE queue.engagement_id = bindings.engagement_id
           AND queue.file_id = bindings.file_id
           AND queue.repo_generation = repos.active_generation
           AND queue.source_superseded_at IS NULL
         ORDER BY queue.id DESC LIMIT 1
       ) AS latest_queue_attempt
FROM code_lead_bindings AS bindings
JOIN intel_notes AS notes
  ON notes.id = bindings.note_id
 AND notes.engagement_id = bindings.engagement_id
JOIN code_repos AS repos
  ON repos.id = bindings.repo_id
 AND repos.engagement_id = bindings.engagement_id
JOIN code_files AS files
  ON files.id = bindings.file_id
 AND files.engagement_id = bindings.engagement_id
"""


def _lead_binding_row(row: Any) -> dict[str, Any]:
    record = dict(row)
    lead_status = str(record.get("lead_status") or "")
    repo_role = str(record.get("repo_role") or ANALYSIS_REPO_ROLE)
    binding_status = str(record["binding_status"])
    # The latest attempt arrives as one `id:status` pair so the projection
    # reads one correlated row rather than the same row twice.
    attempt_id, _, attempt_status = str(
        record.pop("latest_queue_attempt", None) or ""
    ).partition(":")
    # Key order matches the two subqueries this one replaced: `queue_item_id`
    # then `queue_status` sat at the end of the SELECT list, and `queued` was
    # appended after them. The row is JSON-serialised into API responses and
    # recorded receipts, so the emission order is part of the payload.
    record["queue_item_id"] = int(attempt_id) if attempt_id else None
    record["queue_status"] = attempt_status
    record["queued"] = record["queue_item_id"] is not None
    # An obligation exists only where the engagement agreed to review the code
    # (B8) and the lead is still unanswered. Everything else is a citation.
    record["carries_obligation"] = (
        repo_role == ANALYSIS_REPO_ROLE
        and binding_status != "unbound"
        and lead_status in _LEAD_OPEN_STATUS_VALUES
        and record.get("lead_superseded_by_id") is None
    )
    record["lead_status"] = lead_status
    record["repo_role"] = repo_role
    return record


def _require_lead_note(connection, engagement_id: int, note_id: int) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM intel_notes WHERE engagement_id = ? AND id = ?",
        (engagement_id, note_id),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"intel note {note_id} not found in this engagement",
        )
    note = dict(row)
    if not str(note.get("lead_status") or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"intel note {note_id} is a plain reference note (lead_status is "
                "null) and owes no work. Promote it first: vigil assess intel "
                f"update note {note_id} --inline '{{\"lead_status\": \"open\"}}'"
            ),
        )
    if note.get("superseded_by_id") is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"intel note {note_id} was superseded by note "
                f"{int(note['superseded_by_id'])}; bind the canonical lead instead"
            ),
        )
    return note


def _validate_lead_binding_lines(
    line_start: int | None,
    line_end: int | None,
) -> tuple[int | None, int | None]:
    """Whole-file (both None) or an ordered range; the snapshot checks its bounds."""
    if line_start is None and line_end is None:
        return None, None
    if line_start is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="line_end requires line_start",
        )
    end = line_start if line_end is None else line_end
    if end < line_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"line_end {end} precedes line_start {line_start}",
        )
    return line_start, end


def bind_code_lead(
    engagement_id: int,
    *,
    note_id: int,
    repo_id: int,
    file_path: str,
    line_start: int | None = None,
    line_end: int | None = None,
    prior_art_ref: str = "",
    rationale: str = "",
    bound_by: str = "",
) -> dict[str, Any]:
    """Point one tracked lead at one file, optionally at one line range.

    Idempotent per (lead, file): re-binding refines the same row rather than
    accumulating near-duplicates, which is also how a stale binding is
    repaired after the snapshot advances.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_lead_note(connection, engagement.id, note_id)
        repo = _get_repo_rows(connection, engagement.id, {repo_id})[repo_id]
        start, end = _validate_lead_binding_lines(line_start, line_end)
        # A range past the sealed file names code that does not exist, a typo
        # worth refusing now rather than handing a specialist a dead pointer.
        file_row = resolve_snapshot_location(
            connection,
            engagement.id,
            repo_id,
            int(repo.get("active_generation", 0) or 0),
            file_path,
            start,
            end_line=end,
        )
        connection.execute(
            """
            INSERT INTO code_lead_bindings (
                engagement_id, note_id, repo_id, file_id, repo_generation,
                file_path, file_hash, line_start, line_end,
                prior_art_ref, rationale, bound_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, note_id, file_id) DO UPDATE SET
                repo_id = excluded.repo_id,
                repo_generation = excluded.repo_generation,
                file_path = excluded.file_path,
                file_hash = excluded.file_hash,
                line_start = excluded.line_start,
                line_end = excluded.line_end,
                prior_art_ref = excluded.prior_art_ref,
                rationale = excluded.rationale,
                bound_by = excluded.bound_by,
                unbound_at = NULL,
                unbound_reason = '',
                source_superseded_at = NULL,
                source_supersession_reason = '',
                replacement_repo_generation = NULL,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                engagement.id,
                note_id,
                repo_id,
                int(file_row["id"]),
                int(repo.get("active_generation", 0) or 0),
                str(file_row["file_path"]),
                str(file_row.get("file_hash") or ""),
                start,
                end,
                prior_art_ref,
                rationale,
                bound_by,
            ),
        )
        row = connection.execute(
            f"{_LEAD_BINDING_SELECT} WHERE bindings.engagement_id = ? "
            "AND bindings.note_id = ? AND bindings.file_id = ?",
            (engagement.id, note_id, int(file_row["id"])),
        ).fetchone()
    return _lead_binding_row(row)


def unbind_code_lead(
    engagement_id: int, binding_id: int, *, reason: str
) -> dict[str, Any]:
    """Retract one binding without touching the lead it points at.

    Soft, never deleted: "this lead turned out not to live here" is itself
    part of the record, and the lead keeps its own disposition either way. The
    retraction is equally part of the record, so a second unbind is refused
    rather than allowed to overwrite the reason and time the first one stored.
    """
    engagement = _engagement_or_404(engagement_id)
    if not reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unbind requires a reason",
        )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE code_lead_bindings
            SET unbound_at = ?,
                unbound_reason = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND unbound_at IS NULL
            """,
            (_now_iso(), reason, engagement.id, binding_id),
        )
        if cursor.rowcount != 1:
            existing = connection.execute(
                "SELECT unbound_at, unbound_reason FROM code_lead_bindings "
                "WHERE engagement_id = ? AND id = ?",
                (engagement.id, binding_id),
            ).fetchone()
            if existing is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"code lead binding {binding_id} not found in this engagement",
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"code lead binding {binding_id} was already retracted at "
                    f"{existing['unbound_at']} ({str(existing['unbound_reason'])!r}); "
                    "bind the lead again if it belongs here after all"
                ),
            )
        row = connection.execute(
            f"{_LEAD_BINDING_SELECT} WHERE bindings.engagement_id = ? "
            "AND bindings.id = ?",
            (engagement.id, binding_id),
        ).fetchone()
    return _lead_binding_row(row)


def list_code_lead_bindings(
    engagement_id: int,
    *,
    note_id: int | None = None,
    repo_id: int | None = None,
    lead_status: str | None = None,
    include_superseded: bool = False,
    limit: int = DEFAULT_LEAD_BINDING_PAGE,
    offset: int = 0,
) -> dict[str, Any]:
    """Page lead-to-code bindings.

    ``include_superseded`` widens the page to stale and retracted rows; by
    default it is the live worklist, ordered the way an operator works it —
    unanswered leads first, then by repository and path.
    """
    engagement = _engagement_or_404(engagement_id)
    clauses = ["bindings.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    _append_optional_filters(clauses, params, (
        ("bindings.note_id = ?", note_id),
        ("bindings.repo_id = ?", repo_id),
        ("notes.lead_status = ?", lead_status),
    ))
    if not include_superseded:
        clauses.append("bindings.unbound_at IS NULL")
        clauses.append(f"NOT {_lead_binding_stale_sql('bindings', 'repos')}")
    where = " AND ".join(clauses)
    with get_connection() as connection:
        total = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_lead_bindings AS bindings
            JOIN intel_notes AS notes
              ON notes.id = bindings.note_id
             AND notes.engagement_id = bindings.engagement_id
            JOIN code_repos AS repos
              ON repos.id = bindings.repo_id
             AND repos.engagement_id = bindings.engagement_id
            WHERE {where}
            """,
            tuple(params),
        )
        rows = connection.execute(
            f"""
            {_LEAD_BINDING_SELECT}
            WHERE {where}
            ORDER BY
              CASE
                WHEN notes.lead_status IN ({_LEAD_OPEN_STATUS_PLACEHOLDERS}) THEN 0
                ELSE 1
              END,
              bindings.repo_id, bindings.file_path, bindings.id
            LIMIT ? OFFSET ?
            """,
            (
                *params,
                *_LEAD_OPEN_STATUS_VALUES,
                max(1, min(limit, MAX_LEAD_BINDING_PAGE)),
                max(0, offset),
            ),
        ).fetchall()
    return {"total": total, "items": [_lead_binding_row(row) for row in rows]}


def _unresolved_code_lead_rows(connection, engagement_id: int) -> list[dict[str, Any]]:
    """Bindings that still owe an answer: analysis repository, lead not closed.

    A superseded *binding* deliberately does not clear the debt. The
    obligation belongs to the lead and the binding only says where to look, so
    a refresh that invalidates the line range has to surface a rebind — never
    a quietly discharged lead.

    A superseded *note* is the opposite case and does clear it, because the
    lead itself is the note: `intel list-leads` already reports it as gone and
    `bind` refuses to point at it, so counting it here would block completion
    on a lead the intel surface says does not exist. The debt moves to the
    canonical note, which owes its own binding.
    """
    return _fetch_all(
        connection,
        f"""
        SELECT bindings.note_id AS note_id,
               bindings.repo_id AS repo_id,
               notes.title AS lead_title,
               {_lead_binding_stale_sql("bindings", "repos")} AS binding_is_stale
        FROM code_lead_bindings AS bindings
        JOIN intel_notes AS notes
          ON notes.id = bindings.note_id
         AND notes.engagement_id = bindings.engagement_id
        JOIN code_repos AS repos
          ON repos.id = bindings.repo_id
         AND repos.engagement_id = bindings.engagement_id
         AND repos.active_generation > 0
         AND {_analysis_repo_sql("repos")}
        WHERE bindings.engagement_id = ?
          AND bindings.unbound_at IS NULL
          AND notes.superseded_by_id IS NULL
          AND COALESCE(notes.lead_status, '') IN ({_LEAD_OPEN_STATUS_PLACEHOLDERS})
        ORDER BY bindings.repo_id, bindings.note_id
        """,
        (engagement_id, *_LEAD_OPEN_STATUS_VALUES),
    )


def open_code_lead_binding_counts(engagement_id: int) -> dict[int, dict[str, int]]:
    """Per-lead binding counts for unanswered leads, for resume hydration."""
    with get_connection() as connection:
        rows = _unresolved_code_lead_rows(connection, engagement_id)
    counts: dict[int, dict[str, int]] = {}
    for row in rows:
        entry = counts.setdefault(int(row["note_id"]), {"bindings": 0, "stale": 0})
        entry["bindings"] += 1
        if row["binding_is_stale"]:
            entry["stale"] += 1
    return counts


_CODE_READINESS_PHASES = (
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
    "complete",
)


def next_code_readiness_phase(current_phase: str) -> str | None:
    """Return the next transition target for the persisted code-track phase."""
    if current_phase == "ingest":
        return _CODE_READINESS_PHASES[0]
    try:
        index = _CODE_READINESS_PHASES.index(current_phase)
    except ValueError:
        return None
    return (
        _CODE_READINESS_PHASES[index + 1]
        if index + 1 < len(_CODE_READINESS_PHASES)
        else None
    )


def _readiness_blocker(
    code: str,
    message: str,
    *,
    repo_id: int | None = None,
    overrideable: bool = False,
    **fields: Any,
) -> dict[str, Any]:
    blocker: dict[str, Any] = {
        "code": code,
        "message": message,
        "overrideable": overrideable,
    }
    if repo_id is not None:
        blocker["repo_id"] = repo_id
    blocker.update(fields)
    return blocker


def code_readiness(
    engagement_id: int, *, target_phase: str, include_debt_paths: bool = False
) -> dict[str, Any]:
    """Project durable code-analysis state into explicit phase-transition blockers."""
    engagement = _engagement_or_404(engagement_id)
    if target_phase not in _CODE_READINESS_PHASES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported code-analysis target phase: {target_phase}",
        )

    blockers: list[dict[str, Any]] = []
    structural_quality_warnings: list[str] = []
    structural_debt: list[dict[str, Any]] = []
    structural_debt_count = 0
    with get_connection() as connection:
        repos = [
            dict(row)
            for row in connection.execute(
                """
                SELECT * FROM code_repos
                WHERE engagement_id = ? AND active_generation > 0
                ORDER BY id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        # Findings, snapshot currency and variant parentage still resolve
        # against every active repository — a finding in framework source is a
        # real, bindable finding. Only the per-repo obligation loop below is
        # narrowed to the repositories this engagement agreed to review.
        ambiguous_links = connection.execute(
            "SELECT COUNT(*) FROM assessment_finding_links WHERE engagement_id=? "
            "AND link_kind='variant-of' AND retired_at IS NULL", (engagement.id,),
        ).fetchone()[0]
        if ambiguous_links:
            structural_quality_warnings.append(
                f"{ambiguous_links} historical ambiguous variant relationship(s) retain their recorded "
                "generic semantics; inspect finding-links relationship_warning before explicitly "
                "recording child or independent relationships. No historical links were rewritten."
            )
        active_repo_ids = {int(repo["id"]) for repo in repos}
        analysis_repos = [
            repo
            for repo in repos
            if str(repo.get("repo_role") or ANALYSIS_REPO_ROLE) == ANALYSIS_REPO_ROLE
        ]
        suspicious_counts = _current_suspicious_analysis_counts(
            connection, engagement.id
        )
        unresolved_lead_rows: list[dict[str, Any]] = (
            _unresolved_code_lead_rows(connection, engagement.id)
            if target_phase == "complete"
            else []
        )
        unresolved_draft_counts: dict[int, int] = {}
        stale_draft_counts: dict[int, int] = {}
        unbound_draft_count = 0
        if target_phase in {"fuzz", "complete"}:
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            draft_rows = connection.execute(
                """
                SELECT *
                FROM assessment_findings
                WHERE engagement_id = ? AND status = 'draft'
                  AND COALESCE(verification_status, '') != 'blocked'
                ORDER BY slug
                """,
                (engagement.id,),
            ).fetchall()
            for row in draft_rows:
                repo_id = _finding_snapshot_repo_id(row)
                if not is_file_finding(str(row["canonical_location"] or "")):
                    continue
                snapshot_status = finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                if (
                    repo_id is None
                    or repo_id not in active_repo_ids
                    or snapshot_status == "unbound"
                ):
                    unbound_draft_count += 1
                    continue
                unresolved_draft_counts[repo_id] = (
                    unresolved_draft_counts.get(repo_id, 0) + 1
                )
                if snapshot_status == "stale":
                    stale_draft_counts[repo_id] = (
                        stale_draft_counts.get(repo_id, 0) + 1
                    )
        if unbound_draft_count:
            blockers.append(
                _readiness_blocker(
                    "unbound_draft_code_findings_unresolved",
                    (
                        f"Engagement has {unbound_draft_count} draft code finding(s) "
                        "without a resolvable repository binding; re-review and rebind, "
                        "then promote, merge, or kill each draft."
                    ),
                )
            )
        variant_inventory_by_repo: dict[int, list[dict[str, Any]]] = {}
        variant_parent_slugs_by_repo: dict[int, list[str]] = {}
        variant_unready_parent_slugs_by_repo: dict[int, list[str]] = {}
        variant_projection: _VariantReceiptProjection | None = None
        if target_phase in {"fuzz", "complete"} and active_repo_ids:
            phase2_parent_rows_by_repo = _current_variant_parent_rows_by_repo(
                connection,
                engagement.id,
                active_repo_ids,
                report_durable_only=False,
            )
            variant_parent_slugs_by_repo = {
                repo_id: [str(row["slug"]) for row in rows]
                for repo_id, rows in phase2_parent_rows_by_repo.items()
            }
            variant_unready_parent_slugs_by_repo = {
                repo_id: [
                    str(row["slug"])
                    for row in rows
                    if str(row["verification_status"] or "")
                    not in {"confirmed", "downgraded", "pending_runtime_proof"}
                ]
                for repo_id, rows in phase2_parent_rows_by_repo.items()
            }
            if any(variant_parent_slugs_by_repo.values()):
                variant_inventory_files = [
                    dict(row)
                    for row in connection.execute(
                        f"""
                        SELECT files.*
                        FROM code_files AS files
                        JOIN code_repos AS repos
                          ON repos.id = files.repo_id
                         AND repos.engagement_id = files.engagement_id
                         AND repos.active_generation > 0
                         AND {_analysis_repo_sql("repos")}
                        WHERE files.engagement_id = ?
                          AND files.retired_at IS NULL
                        ORDER BY files.repo_id, files.id
                        """,
                        (engagement.id,),
                    ).fetchall()
                ]
                for file_row in variant_inventory_files:
                    variant_inventory_by_repo.setdefault(
                        int(file_row["repo_id"]), []
                    ).append(file_row)
                variant_projection = _load_variant_receipt_projection(
                    connection,
                    engagement.id,
                    repo_rows=repos,
                    file_rows=variant_inventory_files,
                    parent_slugs=variant_parent_slugs_by_repo,
                )
        if not analysis_repos:
            blockers.append(
                _readiness_blocker(
                    "no_repositories",
                    "No committed repository snapshot is available for code analysis.",
                )
            )

        for repo in analysis_repos:
            repo_id = int(repo["id"])
            active_generation = int(repo.get("active_generation", 0) or 0)
            structural_debt_rows: list[Any] = []
            if str(repo.get("source_snapshot_quality", "")) != "verified":
                blockers.append(
                    _readiness_blocker(
                        "source_snapshot_unverified",
                        "Repository source identity is legacy-unverified and must be re-ingested.",
                        repo_id=repo_id,
                    )
                )
            if (
                str(repo.get("source_manifest_version", "") or "") != SOURCE_MANIFEST_VERSION
                or len(str(repo.get("source_manifest_digest", "") or "")) != 64
            ):
                blockers.append(
                    _readiness_blocker(
                        "source_manifest_missing",
                        "Repository source manifest identity is missing or unsupported.",
                        repo_id=repo_id,
                    )
                )
            structural_index_current = _structural_index_current(repo)
            if not structural_index_current:
                blockers.append(
                    _readiness_blocker(
                        "structural_index_stale",
                        "Structural index is not bound to the current repository snapshot.",
                        repo_id=repo_id,
                    )
                )
            else:
                incomplete_structural_metadata = _scalar_row(
                    connection,
                    """
                    SELECT COUNT(*)
                    FROM code_files
                    WHERE engagement_id = ? AND repo_id = ?
                      AND retired_at IS NULL
                      AND structural_analysis_status NOT IN (
                        'complete', 'degraded', 'unsupported'
                      )
                    """,
                    (engagement.id, repo_id),
                )
                if incomplete_structural_metadata:
                    blockers.append(
                        _readiness_blocker(
                            "structural_index_metadata_incomplete",
                            (
                                f"Structural index metadata is missing for "
                                f"{incomplete_structural_metadata} admitted source file(s); "
                                "rebuild and sync the current structural index."
                            ),
                            repo_id=repo_id,
                        )
                    )
                else:
                    structural_debt_rows = connection.execute(
                        f"""
                        SELECT files.file_path, files.structural_analysis_status,
                               files.structural_artifact_truncated,
                               files.classification
                        FROM code_files AS files
                        WHERE files.engagement_id = ? AND files.repo_id = ?
                          AND files.retired_at IS NULL
                          AND {_structural_debt_sql()}
                        ORDER BY files.file_path
                        """,
                        (engagement.id, repo_id),
                    ).fetchall()
                    structural_debt_count += len(structural_debt_rows)
                    if include_debt_paths:
                        structural_debt.extend(
                            {
                                "repo_id": repo_id,
                                "file_path": str(row["file_path"]),
                                "classification": str(row["classification"] or ""),
                                "structural_analysis_status": str(
                                    row["structural_analysis_status"] or ""
                                ),
                                "structural_artifact_truncated": bool(
                                    row["structural_artifact_truncated"]
                                ),
                            }
                            for row in structural_debt_rows
                        )
                    if structural_debt_rows and target_phase in {"classify-map", "hunt"}:
                        degraded_count = sum(
                            str(row["structural_analysis_status"]) == "degraded"
                            for row in structural_debt_rows
                        )
                        unsupported_count = sum(
                            str(row["structural_analysis_status"]) == "unsupported"
                            for row in structural_debt_rows
                        )
                        truncated_count = sum(
                            bool(row["structural_artifact_truncated"])
                            for row in structural_debt_rows
                        )
                        structural_quality_warnings.append(
                            f"Repository {repo_id} structural coverage debt: "
                            f"{len(structural_debt_rows)} unreviewed admitted file(s) "
                            f"({degraded_count} degraded, {unsupported_count} unsupported, "
                            f"{truncated_count} truncated); direct sealed-source specialist "
                            "review is required before Verify + Variant."
                        )

            if target_phase == "classify-map":
                continue

            threat_generation = repo.get("threat_model_generation")
            if threat_generation is None or int(threat_generation) != active_generation:
                blockers.append(
                    _readiness_blocker(
                        "threat_model_stale",
                        "Threat model is not bound to the current repository snapshot.",
                        repo_id=repo_id,
                    )
                )
            unclassified = _scalar_row(
                connection,
                """
                SELECT COUNT(*) FROM code_files
                WHERE engagement_id = ? AND repo_id = ? AND classification = 'unclassified'
                  AND retired_at IS NULL
                """,
                (engagement.id, repo_id),
            )
            if unclassified:
                blockers.append(
                    _readiness_blocker(
                        "files_unclassified",
                        f"Repository has {unclassified} unclassified source file(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )

            if target_phase == "hunt":
                # A5: the durable queue is what Phase 2 claims work from, so an
                # admitted file with no current-generation row can never be
                # dispatched and never reaches accounting. The on-disk queue
                # artifact is planning input and proves nothing about this.
                unqueued_files = _scalar_row(
                    connection,
                    """
                    SELECT COUNT(*)
                    FROM code_files AS files
                    WHERE files.engagement_id = ? AND files.repo_id = ?
                      AND files.retired_at IS NULL
                      AND NOT EXISTS (
                        SELECT 1
                        FROM code_analysis_queue AS queue
                        WHERE queue.engagement_id = files.engagement_id
                          AND queue.file_id = files.id
                          AND queue.repo_generation = ?
                          AND queue.source_superseded_at IS NULL
                      )
                    """,
                    (engagement.id, repo_id, active_generation),
                )
                if unqueued_files:
                    blockers.append(
                        _readiness_blocker(
                            "admitted_files_unqueued",
                            (
                                f"Repository has {unqueued_files} admitted file(s) with no "
                                "current-generation analysis queue row; every admitted file "
                                "needs one before hunting, including skip-tier files."
                            ),
                            repo_id=repo_id,
                            overrideable=True,
                        )
                    )
                continue

            unaccounted_files = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND NOT ({_CURRENT_ACCOUNTED_FILE_EXISTS_SQL})
                """,
                (engagement.id, repo_id),
            )
            if unaccounted_files:
                blockers.append(
                    _readiness_blocker(
                        "admitted_files_unaccounted",
                        (
                            f"Repository has {unaccounted_files} admitted file(s) without a "
                            "current terminal review or evidence-based structured skip."
                        ),
                        repo_id=repo_id,
                    )
                )

            if target_phase == "complete":
                # A prior-art lead pointed at this repository is code work the
                # engagement accepted. Completing with it still open would seal
                # a scan that never answered its own strongest question, so the
                # seal waits for a terminal disposition — resolved when it led
                # somewhere, ruled_out when it did not.
                repo_lead_rows = [
                    row
                    for row in unresolved_lead_rows
                    if int(row["repo_id"]) == repo_id
                ]
                if repo_lead_rows:
                    note_ids = sorted({int(row["note_id"]) for row in repo_lead_rows})
                    stale_notes = sorted(
                        {
                            int(row["note_id"])
                            for row in repo_lead_rows
                            if row["binding_is_stale"]
                        }
                    )
                    lead_sample = ", ".join(
                        f"note {note_id}" for note_id in note_ids[:LEAD_BLOCKER_SAMPLE]
                    )
                    if len(note_ids) > LEAD_BLOCKER_SAMPLE:
                        lead_sample += (
                            f", and {len(note_ids) - LEAD_BLOCKER_SAMPLE} more"
                        )
                    stale_detail = (
                        f" {len(stale_notes)} of them are bound at a superseded "
                        "generation and need rebinding before the line range is "
                        "trustworthy."
                        if stale_notes
                        else ""
                    )
                    blockers.append(
                        _readiness_blocker(
                            "code_leads_unresolved",
                            (
                                f"Repository has {len(note_ids)} unanswered prior-art "
                                f"lead(s) bound to its source ({lead_sample}); record a "
                                "resolved or ruled_out disposition on each with "
                                "`vigil assess intel update note <id> --inline "
                                "'{\"lead_status\": \"resolved\"}'`."
                                f"{stale_detail}"
                            ),
                            repo_id=repo_id,
                            overrideable=True,
                        )
                    )

            if structural_debt_rows:
                debt_paths = [str(row["file_path"]) for row in structural_debt_rows]
                sample = ", ".join(debt_paths[:5])
                if len(debt_paths) > 5:
                    sample += f", and {len(debt_paths) - 5} more"
                blockers.append(
                    _readiness_blocker(
                        "structural_analysis_debt_unreviewed",
                        (
                            f"Repository has {len(debt_paths)} admitted source file(s) with "
                            "degraded, unsupported, or truncated structural analysis and no "
                            f"durable specialist/manual review: {sample}."
                        ),
                        repo_id=repo_id,
                    )
                )

            incomplete_high_risk = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*) FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND files.classification IN ('critical', 'high')
                  AND NOT ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL})
                """,
                (engagement.id, repo_id),
            )
            if incomplete_high_risk:
                blockers.append(
                    _readiness_blocker(
                        "critical_high_incomplete",
                        f"Repository has {incomplete_high_risk} incomplete critical/high file(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            # Counted apart because they clear apart: `reset-stale` sweeps
            # `processing` rows only, so an `error` row survives every recovery
            # verb except `retry-error`. Rolled into one number, the operator's
            # only visible escape was `--force`, which drops those files'
            # coverage silently.
            queue_item_ids = _scalar_rows_by_status(
                connection,
                f"""
                SELECT queue.status, COUNT(*) AS items
                {queue_file_repo_join_sql(repos_alias="queue_repos")}
                WHERE queue.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND queue.status IN ('pending', 'processing', 'error')
                  AND {canonical_current_attempt_sql("queue", "queue_repos")}
                GROUP BY queue.status
                """,
                (engagement.id, repo_id),
            )
            invalid_active_history = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND ({_invalid_active_history_exists_sql("files")})
                """,
                (engagement.id, repo_id),
            )
            errored_queue = queue_item_ids.get("error", 0)
            open_queue = (
                queue_item_ids.get("pending", 0)
                + queue_item_ids.get("processing", 0)
                + invalid_active_history
            )
            active_queue = open_queue + errored_queue
            if active_queue:
                # The leading number stays the TOTAL: the Code view reads the
                # first number in the message as the outstanding-item count
                # (`codeLabels.blockerCount`). The split follows it so the
                # operator can see which remedy applies to how many.
                if open_queue and errored_queue:
                    kinds = (
                        f"active or errored analysis queue item(s) "
                        f"({open_queue} active, {errored_queue} errored)"
                    )
                elif errored_queue:
                    kinds = "errored analysis queue item(s)"
                else:
                    kinds = "active analysis queue item(s)"
                remedies = []
                if open_queue:
                    remedies.append(
                        "close each active item with `code-dispatch done`, `error` or "
                        "`needs-context`, return it unclaimed with `code-dispatch "
                        "release`, or discard an abandoned lease with `code-dispatch "
                        "reset-stale`"
                    )
                if errored_queue:
                    remedies.append(
                        "recover each errored item with `code-dispatch retry-error "
                        "<ids> <reason>` — `reset-stale` sweeps processing rows only "
                        "and cannot touch an errored one"
                    )
                blockers.append(
                    _readiness_blocker(
                        "analysis_queue_active",
                        f"Repository has {active_queue} {kinds}; "
                        + "; ".join(remedies)
                        + ".",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            needs_context = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                {queue_file_repo_join_sql(repos_alias="queue_repos")}
                WHERE queue.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND queue.status = 'needs_context'
                  AND {canonical_current_attempt_sql("queue", "queue_repos")}
                """,
                (engagement.id, repo_id),
            )
            if needs_context:
                blockers.append(
                    _readiness_blocker(
                        "needs_context_unresolved",
                        f"Repository has {needs_context} unresolved needs-context item(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            if target_phase in {"verify-variant", "fuzz", "complete"}:
                unresolved_suspicious = suspicious_counts.get(repo_id, 0)
                if unresolved_suspicious:
                    blockers.append(
                        _readiness_blocker(
                            "unresolved_suspicious_analysis",
                            (
                                f"Repository has {unresolved_suspicious} current "
                                "suspicious analysis attempt(s) requiring a finding "
                                "or clean terminal reanalysis."
                            ),
                            repo_id=repo_id,
                        )
                    )
            pending_triggers = _scalar_row(
                connection,
                """
                SELECT COUNT(*)
                FROM code_analysis_triggers AS triggers
                JOIN code_files AS files ON files.id = triggers.source_file_id
                JOIN code_repos AS repos
                  ON repos.id = triggers.repo_id
                 AND repos.engagement_id = triggers.engagement_id
                 AND repos.active_generation > 0
                WHERE triggers.engagement_id = ? AND files.repo_id = ?
                  AND triggers.status = 'pending'
                  AND triggers.repo_generation = repos.active_generation
                  AND triggers.source_superseded_at IS NULL
                """,
                (engagement.id, repo_id),
            )
            if pending_triggers:
                blockers.append(
                    _readiness_blocker(
                        "pending_triggers",
                        f"Repository has {pending_triggers} unprocessed cross-file trigger(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )

            if target_phase in {"fuzz", "complete"}:
                parent_finding_slugs = variant_parent_slugs_by_repo.get(repo_id, [])
                if parent_finding_slugs:
                    unready_parent_slugs = (
                        variant_unready_parent_slugs_by_repo.get(repo_id, [])
                    )
                    if unready_parent_slugs:
                        blockers.append(
                            _readiness_blocker(
                                "variant_parent_verification_incomplete",
                                (
                                    f"Repository has {len(unready_parent_slugs)} current "
                                    "Phase 2 root finding(s) without a verified "
                                    "confirmed, downgraded, or pending-runtime-proof "
                                    "disposition; finish evidence triage before entering fuzz."
                                ),
                                repo_id=repo_id,
                            )
                        )
                    incomplete_variants = sum(
                        _current_variant_check_status(
                            connection,
                            engagement.id,
                            file_row,
                            projection=variant_projection,
                        )
                        != "done"
                        for file_row in variant_inventory_by_repo.get(repo_id, [])
                    )
                    if incomplete_variants:
                        uncovered_parents = sorted({
                            slug for file_row in variant_inventory_by_repo.get(repo_id, [])
                            if variant_projection is not None
                            and (receipt := variant_projection.latest_receipts.get(int(file_row["id"]))) is not None
                            for slug in set(parent_finding_slugs) - set(_json_decode(receipt["parent_finding_slugs_json"], []))
                        })
                        drift_detail = (
                            " Current roots outside the frozen receipt scope: " + ", ".join(uncovered_parents)
                            + "; inspect code/variant-checks?include_stale=true for currency diagnostics."
                        ) if uncovered_parents else ""
                        blockers.append(
                            _readiness_blocker(
                                "variant_checks_incomplete",
                                (
                                    f"Repository has {incomplete_variants} incomplete "
                                    "admitted-file variant check(s)." + drift_detail
                                    + " "
                                    + variant_dispatch_scope_instruction(
                                        repo_id, parent_finding_slugs
                                    )
                                ),
                                repo_id=repo_id,
                                overrideable=True,
                                variant_parent_finding_slugs=list(
                                    parent_finding_slugs
                                ),
                            )
                        )

        if target_phase in {"fuzz", "complete"}:
            # Drafts are the engagement's own authored evidence, not an
            # obligation over a second codebase, so this gate spans every active
            # repository: a real bug found while reading framework source must
            # still be promoted, merged or killed rather than silently dropped.
            for draft_repo_id in sorted(unresolved_draft_counts):
                unresolved_draft_count = unresolved_draft_counts[draft_repo_id]
                stale_draft_count = stale_draft_counts.get(draft_repo_id, 0)
                stale_detail = (
                    f"; {stale_draft_count} have stale snapshot bindings"
                    if stale_draft_count
                    else ""
                )
                blockers.append(
                    _readiness_blocker(
                        "draft_code_findings_unresolved",
                        (
                            f"Repository has {unresolved_draft_count} unresolved draft "
                            f"code finding(s){stale_detail}; re-review and rebind when "
                            "needed, then promote, merge, or kill each "
                            "draft before leaving verification."
                        ),
                        repo_id=draft_repo_id,
                    )
                )

    coverage = code_coverage_summary(engagement.id)
    coverage_gate = coverage.get("gate", {})
    uncovered = coverage_gate.get("uncovered_high_risk_files", [])
    if target_phase in {"verify-variant", "fuzz", "complete"} and uncovered:
        blockers.append(
            _readiness_blocker(
                "structural_coverage_unresolved",
                f"Structural coverage found {len(uncovered)} uncovered critical/high file(s).",
                overrideable=True,
            )
        )

    if target_phase == "complete":
        with get_connection() as connection:
            finding_rows = connection.execute(
                """
                SELECT * FROM assessment_findings
                WHERE engagement_id = ?
                  AND status IN (
                      'active', 'blocked', 'exploited', 'contained',
                      'eradicated', 'recovered', 'reported'
                  )
                  AND verification_status != 'blocked'
                """,
                (engagement.id,),
            ).fetchall()
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            finding_snapshot_statuses = []
            for row in finding_rows:
                snapshot_status = finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                if snapshot_status != "not_applicable":
                    finding_snapshot_statuses.append((row, snapshot_status))
            stale_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status != "current"
            ]
            unverified_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status == "current"
                and str(row["verification_status"] or "")
                not in {"confirmed", "downgraded", "false_positive"}
            ]
            blind_triage_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status == "current"
                and str(row["verification_status"] or "")
                not in {"confirmed", "downgraded"}
            ]
        if stale_findings:
            blockers.append(
                _readiness_blocker(
                    "finding_snapshot_stale",
                    f"{len(stale_findings)} reportable code finding(s) are not bound to the current verified source snapshot.",
                )
            )
        if unverified_findings:
            blockers.append(
                _readiness_blocker(
                    "findings_unverified",
                    f"{len(unverified_findings)} current code finding(s) have not completed verification triage.",
                )
            )
        if blind_triage_findings:
            blockers.append(
                _readiness_blocker(
                    "findings_blind_triage_incomplete",
                    f"{len(blind_triage_findings)} current code finding(s) lack a report-durable triage disposition.",
                )
            )

    fuzz_completion: dict[str, Any] | None = None
    if target_phase in {"fuzz", "complete"}:
        fuzz_states = code_fuzz_completion.fuzz_states(engagement.id)
        pending_targets = sorted(
            {
                target_id
                for state in fuzz_states
                for target_id in state["pending_target_ids"]
            }
        )
        pending_findings = sorted(
            {
                slug
                for state in fuzz_states
                for slug in state["pending_finding_slugs"]
            }
        )
        fuzz_completion = {
            "repos": fuzz_states,
            "pending_target_ids": pending_targets,
            "pending_finding_slugs": pending_findings,
            "applicability_ready": all(
                state["applicability_ready"] for state in fuzz_states
            ),
            "completion_ready": all(
                state["completion_ready"] for state in fuzz_states
            ),
        }
        for state in fuzz_states:
            if not state["applicability_ready"]:
                blockers.append(
                    _readiness_blocker(
                        "fuzz_decision_missing",
                        (
                            "Repository has no agent-attested, evidence-hashed current-source fuzz "
                            "applicability decision; record required targets or a "
                            "not-required rationale before entering Phase 4."
                        ),
                        repo_id=int(state["repo_id"]),
                    )
                )
            if target_phase == "complete" and not state["completion_ready"]:
                blockers.append(
                    _readiness_blocker(
                        "fuzz_campaign_incomplete",
                        (
                            "Repository has incomplete generation-bound fuzz obligations: "
                            f"{len(state['pending_target_ids'])} target(s), "
                            f"{len(state['pending_finding_slugs'])} current native memory-safety "
                            "finding(s). Record covering terminal campaign receipts."
                        ),
                        repo_id=int(state["repo_id"]),
                    )
                )

    warnings = list(structural_quality_warnings)
    warnings.extend(str(warning) for warning in coverage_gate.get("effort_warnings", []))
    for item in coverage_gate.get("coverage_integrity", []):
        if not isinstance(item, dict):
            continue
        for warning in item.get("warnings", []):
            warnings.append(f"{item.get('file_path', 'unknown file')}: {warning}")
    warnings = list(dict.fromkeys(warnings))
    payload = {
        "track": "code",
        # Blockers stay fail-closed for transitions; this says whether they
        # describe owed work at all.
        "track_enabled": code_track_enabled(engagement, has_repositories=bool(repos)),
        "target_phase": target_phase,
        "transition_ready": not blockers,
        "blockers": blockers,
        "structural_debt_count": structural_debt_count,
        "quality_gate": {"passed": not warnings, "warnings": warnings},
    }
    if include_debt_paths:
        payload["structural_debt"] = structural_debt
    if fuzz_completion is not None:
        payload["fuzz_completion"] = fuzz_completion
    return payload


# =========================================================================
# Slot-to-vuln-class mapping
# =========================================================================

SLOT_VULN_CLASSES: dict[str, dict[str, list[str]]] = {
    "NETWORK-INPUT": {
        "all": ["algorithmic-dos", "error-handling", "deserialization"],
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": [
            "web-app-injection", "web-app-auth", "ssrf", "open-redirect", "path-traversal",
            "file-upload",
        ],
    },
    "PROTOCOL-FIELD": {
        "all": ["algorithmic-dos", "error-handling"],
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "race-condition"],
    },
    "URL-COMPONENT": {
        "all": [
            "injection", "web-app-injection", "path-traversal", "auth-bypass", "ssrf",
            "open-redirect", "web-app-auth", "algorithmic-dos", "error-handling",
        ]
    },
    "FILE-CONTENT": {
        "all": ["injection", "type-confusion", "path-traversal", "xxe", "file-upload"],
        "memory-unsafe": ["buffer-overflow"],
    },
    "CMD-ARGUMENT": {"all": ["injection", "format-string", "path-traversal"]},
    "CALLBACK-DATA": {
        "all": ["race-condition", "type-confusion", "deserialization"],
        "memory-unsafe": ["use-after-free"],
    },
    "ENV-VARIABLE": {"all": ["injection", "path-traversal"]},
    "SERIALIZED-DATA": {
        "native": ["buffer-overflow", "integer-overflow", "type-confusion", "deserialization"],
        "managed": ["deserialization"],
    },
    "EXEC-POLICY": {"all": ["injection", "auth-bypass", "crypto-misuse", "error-handling"]},
}


NATIVE_LANGUAGES = frozenset({"c", "c++", "cpp"})
MEMORY_UNSAFE_LANGUAGES = NATIVE_LANGUAGES | {"objectivec"}
STRUCTURALLY_ANALYZED_LANGUAGES = frozenset(
    {
        "blade",
        "c",
        "c++",
        "cpp",
        "freemarker",
        "powershell",
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "ruby",
        "php",
        "csharp",
        "shell",
        "lua",
        "html",
        "css",
        "twig",
        "dockerfile",
    }
)

ROLE_CONTEXT_VULN_CLASSES: tuple[tuple[tuple[str, ...], dict[str, list[str]]], ...] = (
    (("crypto", "cipher", "tls", "ssl", "digest", "hmac", "jwt", "x509"), {"all": ["crypto-misuse"]}),
    (("auth", "oauth", "session", "login", "signin", "permission", "rbac", "acl", "sso"), {"all": ["auth-bypass", "web-app-auth"]}),
    # A credential or session token presented to the server is only as strong
    # as the limit on guessing it, so the entry point that accepts one owes
    # brute-force and credential-stuffing review — the cheapest attacks on
    # exactly that file. Split from the row above rather than added to it: an
    # authorization policy point (`permission`, `rbac`, `acl`) decides on an
    # already-authenticated principal and presents nothing to guess, so
    # demanding throttling review there would be noise. The one-time-code
    # workflow row covers the OTP spellings separately.
    (("auth", "oauth", "session", "login", "signin", "sso"), {"all": ["rate-limit"]}),
    (("error", "exception", "fallback", "retry", "recovery"), {"all": ["error-handling"], "native": ["null-dereference"]}),
    (("allocator", "allocation", "memory", "arena", "pool"), {"native": ["uninitialized-memory"], "all": ["algorithmic-dos"]}),
    (("parser", "decoder", "deserializer", "deserialize", "serializer", "serialization", "codec", "marshal", "unmarshal", "regex", "regexp"), {"all": ["algorithmic-dos"]}),
    (("graphql", "resolver", "serializer", "orm", "resource", "controller", "view"), {"managed": ["web-app-data-exposure"]}),
    (("llm", "prompt", "rag", "mcp", "embedding"), {"all": ["ai-ml-security"]}),
)

# Matched against whole words (`_context_words`), never as substrings as the
# role rows above are: `load_balancer` is not a balance and `placeholder` holds
# nothing. A hyphenated entry is a phrase of consecutive words. Request handlers
# run concurrently across requests, so a file that moves money, stock, quota or
# one-time grants owes check-then-act and workflow review whatever its slot
# types say. The architect's role label makes these families required. The
# file's own path (`_workflow_path_words`) only suggests them: a directory word
# such as `Checkout` names whole trees of value objects and helpers that never
# move anything, so a path match is a hint that never blocks closeout or the
# effort gate.
WORKFLOW_CONTEXT_VULN_CLASSES: tuple[tuple[tuple[str, ...], dict[str, list[str]]], ...] = (
    (
        (
            "booking", "reservation", "hold", "quota", "credit", "refund", "coupon",
            "voucher", "redeem", "redemption", "wallet", "balance", "ledger",
            "payment", "checkout", "payout", "withdraw", "withdrawal", "inventory",
            "entitlement",
        ),
        {"all": ["race-condition", "business-logic"]},
    ),
    # Providers retry and replay deliveries, often concurrently, and each one
    # usually settles a payment or grants something.
    (("webhook", "ipn"), {"all": ["race-condition", "business-logic"]}),
    # A short secret is only as strong as the limit on guessing it.
    (
        ("otp", "mfa", "totp", "passcode", "password-reset", "reset-password"),
        {"all": ["rate-limit"]},
    ),
)

# Path words come only from source the index reads as code. Markup, style and
# template languages name pages rather than request handling.
_WORKFLOW_PATH_SKIPPED_LANGUAGES = frozenset(
    {"html", "css", "dockerfile", "freemarker", "blade", "twig"}
)
_WORD_PATTERN = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+")


def _context_words(text: str) -> list[str]:
    """Split on non-alphanumerics and camelCase boundaries, lower-cased."""
    return [word.lower() for word in _WORD_PATTERN.findall(text)]


def _workflow_path_words(file_path: str, language: str) -> list[str]:
    if (
        language not in STRUCTURALLY_ANALYZED_LANGUAGES
        or language in _WORKFLOW_PATH_SKIPPED_LANGUAGES
    ):
        return []
    segments = [segment for segment in file_path.split("/") if segment]
    if not segments:
        return []
    directories, name = segments[:-1], segments[-1]
    stem = name.rsplit(".", 1)[0] if "." in name.lstrip(".") else name
    return [word for segment in (*directories, stem) for word in _context_words(segment)]


def _has_context_keyword(words: list[str], keyword: str) -> bool:
    """True when ``keyword`` (a word or hyphenated phrase) occurs as whole words.

    The phrase's last word may carry a plural ``s``.
    """
    phrase = keyword.split("-")
    width = len(phrase)
    for start in range(len(words) - width + 1):
        window = words[start : start + width]
        if window[:-1] == phrase[:-1] and window[-1] in (phrase[-1], f"{phrase[-1]}s"):
            return True
    return False


def _apply_grouped_families(
    families: set[str],
    mapping: dict[str, list[str]],
    *,
    is_native: bool,
    lang_known: bool,
    is_memory_unsafe: bool,
) -> None:
    for group, group_families in mapping.items():
        if group == "all":
            families.update(group_families)
        elif group == "native" and (is_native or not lang_known):
            families.update(group_families)
        elif group == "managed" and (not is_native or not lang_known):
            families.update(group_families)
        elif group == "memory-unsafe" and (is_memory_unsafe or not lang_known):
            families.update(group_families)


def _workflow_families(words: list[str], language: str) -> set[str]:
    """The `WORKFLOW_CONTEXT_VULN_CLASSES` families whole ``words`` name."""
    families: set[str] = set()
    for keywords, mapping in WORKFLOW_CONTEXT_VULN_CLASSES:
        if any(_has_context_keyword(words, keyword) for keyword in keywords):
            _apply_grouped_families(
                families,
                mapping,
                is_native=language in NATIVE_LANGUAGES,
                lang_known=bool(language),
                is_memory_unsafe=language in MEMORY_UNSAFE_LANGUAGES,
            )
    return families


def _applicable_families_for_file(
    slot_types: list[str],
    *,
    language: str = "",
    role: str = "",
) -> list[str]:
    """Compute canonical applicable vulnerability classes for a classified file.

    These are required: `done` refuses a result that omits one, and the
    coverage harness measures each against its tier's effort threshold —
    refusing the gate for the tiers in `_BLOCKING_EFFORT_TIERS` and reporting
    the rest as advisories. Recomputed on every read, never stored, so a row
    added here applies to every open engagement at once.
    """
    lang_lower = language.lower().strip()
    is_native = lang_lower in NATIVE_LANGUAGES
    is_memory_unsafe = lang_lower in MEMORY_UNSAFE_LANGUAGES
    lang_known = bool(lang_lower)
    role_lower = role.lower().strip()

    families: set[str] = (
        {"algorithmic-dos", "error-handling"}
        if lang_lower in STRUCTURALLY_ANALYZED_LANGUAGES
        else set()
    )
    for slot in slot_types:
        _apply_grouped_families(
            families,
            SLOT_VULN_CLASSES.get(slot, {}),
            is_native=is_native,
            lang_known=lang_known,
            is_memory_unsafe=is_memory_unsafe,
        )

    for keywords, mapping in ROLE_CONTEXT_VULN_CLASSES:
        if any(keyword in role_lower for keyword in keywords):
            _apply_grouped_families(
                families,
                mapping,
                is_native=is_native,
                lang_known=lang_known,
                is_memory_unsafe=is_memory_unsafe,
            )

    families |= _workflow_families(_context_words(role), lang_lower)

    if lang_lower == "freemarker":
        # FILE-CONTENT describes a template's input, not a native parser. Its
        # generic families omit the rendering bug class and demand impossible
        # type/serialization work from template-only source.
        families.add("web-app-injection")
        families.difference_update({"type-confusion", "deserialization"})

    return sorted(families)


def _path_suggested_families_for_file(
    slot_types: list[str],
    *,
    language: str = "",
    role: str = "",
    file_path: str = "",
) -> list[str]:
    """Workflow families the file's path suggests beyond what it already requires.

    Advisory only: a hint points a hunter at a family worth considering, and
    never blocks `done`, counts toward the effort gate, or becomes a
    readiness reason. Writing a transactional role is what makes them required.
    """
    lang_lower = language.lower().strip()
    suggested = _workflow_families(_workflow_path_words(file_path, lang_lower), lang_lower)
    required = _applicable_families_for_file(slot_types, language=language, role=role)
    return sorted(suggested.difference(required))


# =========================================================================
# Requeue triggered files
# =========================================================================

def _scalar_rows_by_status(
    connection, query: str, params: tuple[Any, ...]
) -> dict[str, int]:
    """One grouped COUNT(*) read back as ``{status: count}``."""
    return {
        str(row["status"]): int(row["items"])
        for row in connection.execute(query, params).fetchall()
    }


def _merge_unique_values(existing: list[Any], additions: list[Any]) -> list[Any]:
    merged = list(existing)
    signatures = {json.dumps(value, sort_keys=True, default=str) for value in merged}
    for value in additions:
        signature = json.dumps(value, sort_keys=True, default=str)
        if signature not in signatures:
            merged.append(value)
            signatures.add(signature)
    return merged


def _contains_all_values(existing: list[Any], requested: list[Any]) -> bool:
    existing_signatures = {
        json.dumps(value, sort_keys=True, default=str) for value in existing
    }
    return all(
        json.dumps(value, sort_keys=True, default=str) in existing_signatures
        for value in requested
    )


class _TriggerTargetBlocked(Exception):
    """One trigger target cannot be written; every other target still commits."""


def _requeue_selector(item: dict[str, Any], index: int) -> dict[str, Any]:
    """Reduce one requeue input to exactly one target selector.

    Ambiguity is the defect this rejects. An input naming two targets used to
    resolve to whichever branch was tested first, and an input naming none was
    dropped in silence while still counting toward the reported total.
    """
    selector: dict[str, Any] = {}
    if item.get("file_id") is not None:
        selector["file_id"] = _require_strict_positive_id(
            item["file_id"], field_name=f"items[{index}].file_id"
        )
    if item.get("trigger_id") is not None:
        selector["trigger_id"] = _require_strict_positive_id(
            item["trigger_id"], field_name=f"items[{index}].trigger_id"
        )
    file_path = _trigger_repository_path(item.get("file_path", ""))
    if file_path:
        selector["file_path"] = file_path
    if len(selector) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"items[{index}] needs exactly one selector — file_id, trigger_id, "
                f"or file_path — but named {len(selector)}"
            ),
        )
    if item.get("repo_id") is not None:
        if "file_path" not in selector:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"items[{index}].repo_id only disambiguates a file_path selector"
                ),
            )
        selector["repo_id"] = _require_strict_positive_id(
            item["repo_id"], field_name=f"items[{index}].repo_id"
        )
    return selector


_REQUEUE_TARGET_COLUMNS = """
    files.id, files.file_path, files.classification,
    files.analysis_priority, repos.active_generation, repos.repo_role
"""


def _requeue_target_by_file_id(connection, engagement_id: int, file_id: int) -> Any:
    return connection.execute(
        f"""
        SELECT {_REQUEUE_TARGET_COLUMNS}
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE files.engagement_id = ? AND files.id = ?
          AND files.retired_at IS NULL
        """,
        (engagement_id, file_id),
    ).fetchone()


def _resolve_requeue_target(
    connection, engagement_id: int, selector: dict[str, Any]
) -> tuple[Any, str, str]:
    """Resolve one selector to its current target file row.

    Returns ``(row, outcome, label)``; ``row`` is None unless ``outcome`` is
    ``resolved``. The label is what the not_found/ambiguous summaries name.
    """
    if "file_id" in selector:
        file_id = int(selector["file_id"])
        row = _requeue_target_by_file_id(connection, engagement_id, file_id)
        return (row, "resolved", "") if row is not None else (None, "not_found", str(file_id))

    if "trigger_id" in selector:
        trigger_id = int(selector["trigger_id"])
        label = f"trigger:{trigger_id}"
        trigger = connection.execute(
            """
            SELECT triggers.target_file_id, triggers.target_file_path,
                   source_files.repo_id AS source_repo_id
            FROM code_analysis_triggers AS triggers
            JOIN code_files AS source_files
              ON source_files.id = triggers.source_file_id
             AND source_files.engagement_id = triggers.engagement_id
            JOIN code_repos AS source_repos
              ON source_repos.id = source_files.repo_id
             AND source_repos.engagement_id = source_files.engagement_id
             AND source_repos.active_generation > 0
            WHERE triggers.engagement_id = ? AND triggers.id = ?
              AND triggers.repo_generation = source_repos.active_generation
              AND triggers.source_superseded_at IS NULL
            """,
            (engagement_id, trigger_id),
        ).fetchone()
        if trigger is None:
            return None, "not_found", label
        if trigger["target_file_id"] is not None:
            row = _requeue_target_by_file_id(
                connection, engagement_id, int(trigger["target_file_id"])
            )
            return (row, "resolved", "") if row is not None else (None, "not_found", label)
        # An unbound trigger names its target by path inside the source repo,
        # which is the same repository the requeue insert must land in.
        row, outcome, problem = _requeue_target_by_path(
            connection,
            engagement_id,
            str(trigger["target_file_path"]),
            int(trigger["source_repo_id"]),
        )
        if problem:
            label += f": {problem}"
        return row, outcome, label

    file_path = str(selector["file_path"])
    row, outcome, problem = _requeue_target_by_path(
        connection, engagement_id, file_path, selector.get("repo_id")
    )
    if outcome == "resolved":
        return row, outcome, ""
    return row, outcome, f"{file_path}: {problem}" if problem else file_path


def _requeue_target_by_path(
    connection, engagement_id: int, file_path: str, repo_id: Any
) -> tuple[Any, str, str]:
    """Resolve one repository path to its current file row, with a diagnosis.

    Returns ``(row, outcome, problem)``. ``problem`` is the sealed-roster reason
    the path did not resolve — "not a file in generation N of repository M" plus
    the closest admitted spelling — and is only derivable when a repository is
    named, because without one there is no single generation to search. Shared
    by the `file_path` selector and the unbound-`trigger_id` selector so neither
    can diagnose a miss the other cannot.
    """
    repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
    rows = connection.execute(
        f"""
        SELECT {_REQUEUE_TARGET_COLUMNS}
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE files.engagement_id = ?{repo_clause}
          AND files.file_path = ?
          AND files.retired_at IS NULL
        """,
        (engagement_id, file_path)
        if repo_id is None
        else (engagement_id, int(repo_id), file_path),
    ).fetchall()
    if not rows:
        if repo_id is None:
            return None, "not_found", ""
        repo_row = _get_published_repo_row(connection, engagement_id, int(repo_id))
        _row, problem = snapshot_location_problem(
            connection,
            engagement_id,
            int(repo_id),
            int(repo_row["active_generation"]),
            file_path,
        )
        return None, "not_found", problem
    if len(rows) > 1:
        return None, "ambiguous", ""
    return rows[0], "resolved", ""


def _requeue_trigger_payload(
    item: dict[str, Any], *, file_path: str
) -> dict[str, Any] | None:
    """Project one input's free-text trigger context into a queue-row entry."""
    reason = item.get("reason", "")
    trigger_ctx = item.get("trigger_context")
    if not reason and not trigger_ctx:
        return None
    payload: dict[str, Any] = {"file_path": file_path, "source": "cross_file_trigger"}
    if reason:
        payload["reason"] = str(reason)
    if isinstance(trigger_ctx, dict):
        reserved_context_keys = {
            "file_path",
            "reason",
            "source",
            "trigger_id",
            "source_file_id",
            "source_file_path",
            "source_queue_item_id",
        }
        payload.update(
            {
                key: value
                for key, value in trigger_ctx.items()
                if key not in reserved_context_keys
            }
        )
    return {
        key: value for key, value in payload.items() if value not in (None, "", [], {})
    }


def _apply_requeue_target(
    connection,
    engagement_id: int,
    file_id: int,
    target: dict[str, Any],
) -> tuple[str, int | None, str, bool]:
    """Write one aggregated target. Returns (outcome, queue_item_id, detail, reopened).

    Raises :class:`_TriggerTargetBlocked` when durable state refuses the write,
    so the caller can roll back this target alone.
    """
    if target["blocked_reason"] is not None:
        raise _TriggerTargetBlocked(target["blocked_reason"])

    pending_trigger_rows = connection.execute(
        """
        SELECT triggers.id, triggers.source_queue_item_id,
               triggers.source_file_id, source_files.file_path AS source_file_path,
               triggers.target_file_path, triggers.vuln_class, triggers.reason
        FROM code_analysis_triggers AS triggers
        JOIN code_files AS source_files
          ON source_files.id = triggers.source_file_id
         AND source_files.engagement_id = triggers.engagement_id
        JOIN code_repos AS source_repos
          ON source_repos.id = triggers.repo_id
         AND source_repos.engagement_id = triggers.engagement_id
         AND source_repos.active_generation > 0
        JOIN code_files AS target_files
          ON target_files.id = ?
         AND target_files.engagement_id = triggers.engagement_id
        WHERE triggers.engagement_id = ? AND triggers.status = ?
          AND triggers.repo_generation = source_repos.active_generation
          AND triggers.source_superseded_at IS NULL
          AND (
              triggers.target_file_id = target_files.id
              OR (
                  triggers.target_file_id IS NULL
                  AND triggers.target_file_path = target_files.file_path
                  AND source_files.repo_id = target_files.repo_id
              )
          )
        ORDER BY triggers.id
        """,
        (file_id, engagement_id, _TRIGGER_STATUS_PENDING),
    ).fetchall()
    bucket_triggers = target["cross_file_triggers"]
    existing_trigger_ids = {
        int(entry["trigger_id"])
        for entry in bucket_triggers
        if isinstance(entry, dict) and entry.get("trigger_id") is not None
    }
    for trigger_row in pending_trigger_rows:
        trigger_id = int(trigger_row["id"])
        if trigger_id in existing_trigger_ids:
            continue
        trigger_payload = {
            "trigger_id": trigger_id,
            "file_path": str(trigger_row["target_file_path"]),
            "source": "code_analysis_trigger",
            "source_file_id": int(trigger_row["source_file_id"]),
            "source_file_path": str(trigger_row["source_file_path"]),
            "vuln_class": str(trigger_row["vuln_class"]),
            "reason": str(trigger_row["reason"]),
        }
        if trigger_row["source_queue_item_id"] is not None:
            trigger_payload["source_queue_item_id"] = int(
                trigger_row["source_queue_item_id"]
            )
        bucket_triggers.append(trigger_payload)
        existing_trigger_ids.add(trigger_id)

    current_rows = [
        dict(queue_row)
        for queue_row in connection.execute(
            """
            SELECT *
            FROM code_analysis_queue
            WHERE engagement_id = ? AND file_id = ? AND repo_generation = ?
            ORDER BY id
            """,
            (engagement_id, file_id, int(target["repo_generation"])),
        ).fetchall()
    ]
    latest, active, active_issue = _canonical_queue_attempt_state(current_rows)
    if active_issue is not None:
        raise _TriggerTargetBlocked(
            f"{active_issue} queue history requires operator reconciliation"
        )

    # A15b: a requeue is added depth on the file's existing lane, not a move to
    # a synthetic one. Provenance rides in queue_mode='trigger' instead.
    batch_theme = target["batch_theme"]
    if batch_theme is None:
        inherited = active if active is not None else latest
        batch_theme = str((inherited or {}).get("batch_theme") or "")

    if active is not None:
        active_status = str(active["status"])
        existing_slots = _json_decode(active.get("slot_types_json"), [])
        existing_guidance = _json_decode(active.get("guidance_hypotheses_json"), [])
        existing_triggers = _json_decode(active.get("cross_file_triggers_json"), [])
        requested_is_present = (
            int(active["priority"]) == int(target["priority"])
            and _contains_all_values(existing_slots, target["slot_types"])
            and _contains_all_values(existing_guidance, target["guidance_hypotheses"])
            and _contains_all_values(existing_triggers, target["cross_file_triggers"])
        )
        if active_status == "processing":
            if not requested_is_present:
                raise _TriggerTargetBlocked(
                    "file is processing; new trigger context cannot be merged into a "
                    "live lease"
                )
            result = (
                "already_queued",
                int(active["id"]),
                "live lease already carries this context",
                False,
            )
            return _finish_requeue_target(
                connection, engagement_id, file_id, pending_trigger_rows, result
            )
        if str(active.get("assigned_agent") or "") or str(
            active.get("lease_token") or ""
        ):
            raise _TriggerTargetBlocked(
                "pending queue attempt has an inconsistent lease identity"
            )
        if str(active.get("queue_mode") or "initial") == "reanalysis":
            raise _TriggerTargetBlocked(
                "pending explicit reanalysis owns this file; close that attempt "
                "before merging trigger context"
            )
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET priority = ?, batch_theme = ?, slot_types_json = ?,
                guidance_hypotheses_json = ?, cross_file_triggers_json = ?,
                queue_mode = 'trigger', updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'pending'
              AND assigned_agent = '' AND lease_token = ''
            """,
            (
                int(target["priority"]),
                batch_theme,
                _json_list_text(_merge_unique_values(existing_slots, target["slot_types"])),
                _json_list_text(
                    _merge_unique_values(existing_guidance, target["guidance_hypotheses"])
                ),
                _json_list_text(
                    _merge_unique_values(existing_triggers, target["cross_file_triggers"])
                ),
                engagement_id,
                int(active["id"]),
            ),
        )
        if cursor.rowcount != 1:
            raise _TriggerTargetBlocked("pending queue item changed during trigger merge")
        return _finish_requeue_target(
            connection,
            engagement_id,
            file_id,
            pending_trigger_rows,
            (
                "already_queued",
                int(active["id"]),
                "merged into the pending attempt",
                False,
            ),
        )

    latest_contains_request = (
        latest is not None
        and int(latest["priority"]) == int(target["priority"])
        and _contains_all_values(
            _json_decode(latest.get("slot_types_json"), []), target["slot_types"]
        )
        and _contains_all_values(
            _json_decode(latest.get("guidance_hypotheses_json"), []),
            target["guidance_hypotheses"],
        )
        and _contains_all_values(
            _json_decode(latest.get("cross_file_triggers_json"), []),
            target["cross_file_triggers"],
        )
    )
    if (
        latest is not None
        and str(latest["status"]) == "done"
        and latest_contains_request
        and _has_current_successful_review(connection, engagement_id, file_id)
    ):
        # A completed review that already carries this context is not reopened,
        # so its pending triggers stay pending for an explicit disposition.
        _sync_trigger_status_for_file(connection, engagement_id, file_id)
        return (
            "already_completed",
            int(latest["id"]),
            "current review already covers this context",
            False,
        )

    cursor = connection.execute(
        """
        INSERT INTO code_analysis_queue (
            engagement_id, file_id, priority,
            batch_theme, slot_types_json, guidance_hypotheses_json,
            cross_file_triggers_json, repo_generation, queue_mode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'trigger')
        """,
        (
            engagement_id,
            file_id,
            int(target["priority"]),
            batch_theme,
            _json_list_text(target["slot_types"]),
            _json_list_text(target["guidance_hypotheses"]),
            _json_list_text(target["cross_file_triggers"]),
            int(target["repo_generation"]),
        ),
    )
    reopened = latest is not None
    detail = (
        "reopened a terminal file with a new trigger attempt"
        if reopened
        else "created the first trigger attempt"
    )
    return _finish_requeue_target(
        connection,
        engagement_id,
        file_id,
        pending_trigger_rows,
        ("inserted", int(cursor.lastrowid), detail, reopened),
    )


def _finish_requeue_target(
    connection,
    engagement_id: int,
    file_id: int,
    pending_trigger_rows: list[Any],
    result: tuple[str, int, str, bool],
) -> tuple[str, int, str, bool]:
    """Bind the target's pending triggers to the written row and resync rollups."""
    _outcome, queue_item_id, _detail, _reopened = result
    pending_trigger_ids = [int(row["id"]) for row in pending_trigger_rows]
    if pending_trigger_ids:
        placeholders = ",".join("?" for _ in pending_trigger_ids)
        connection.execute(
            f"""
            UPDATE code_analysis_triggers
            SET target_file_id = ?, resolved_queue_item_id = ?,
                status = ?, resolution_note = '',
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = ?
              AND id IN ({placeholders})
            """,
            (
                file_id,
                queue_item_id,
                _TRIGGER_STATUS_QUEUED,
                engagement_id,
                _TRIGGER_STATUS_PENDING,
                *pending_trigger_ids,
            ),
        )
    _sync_file_analysis_status(connection, engagement_id, file_id)
    _sync_trigger_status_for_file(connection, engagement_id, file_id)
    return result


def requeue_triggered_files(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Turn cross-file triggers into linked current analysis attempts.

    Every input names exactly one target — ``file_id``, ``trigger_id``, or
    ``file_path`` (with ``repo_id`` to disambiguate) — and receives exactly one
    outcome. Inputs aggregate per target file, so ``input_trigger_count`` and
    ``target_count`` are reported separately and the target buckets (inserted,
    already_queued, already_completed, blocked) sum to ``target_count`` exactly.
    Each target is written inside its own savepoint: a blocked target is
    reported with its reason instead of discarding every other target's work.
    """
    engagement = _engagement_or_404(engagement_id)
    selectors = [_requeue_selector(item, index) for index, item in enumerate(items)]
    counts = {
        "inserted": 0,
        "already_queued": 0,
        "already_completed": 0,
        "blocked": 0,
    }
    reopened_terminal_files = 0
    not_found: list[str] = []
    ambiguous: list[str] = []
    input_file_ids: list[int | None] = []
    input_outcomes: list[str] = []
    target_outcomes: list[dict[str, Any]] = []
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        aggregated: dict[int, dict[str, Any]] = {}
        for item, selector in zip(items, selectors, strict=True):
            row, outcome, label = _resolve_requeue_target(
                connection, engagement.id, selector
            )
            if row is None:
                (not_found if outcome == "not_found" else ambiguous).append(label)
                input_file_ids.append(None)
                input_outcomes.append(outcome)
                continue
            file_id = int(row["id"])
            input_file_ids.append(file_id)
            input_outcomes.append("")
            target = aggregated.setdefault(
                file_id,
                {
                    "priority": int(row["analysis_priority"]),
                    "repo_generation": int(row["active_generation"]),
                    "file_path": str(row["file_path"]),
                    "batch_theme": None,
                    "slot_types": [],
                    "guidance_hypotheses": [],
                    "cross_file_triggers": [],
                    "blocked_reason": None,
                },
            )
            classification = str(row["classification"] or "").strip()
            if classification not in _VALID_CLASSIFICATIONS:
                target["blocked_reason"] = (
                    "target file must be classified before requeue"
                )
            supplied_priority = item.get("priority")
            if supplied_priority is not None:
                supplied_priority = _require_strict_priority(
                    supplied_priority, field_name="trigger priority"
                )
                if supplied_priority != target["priority"]:
                    target["blocked_reason"] = (
                        f"trigger priority must equal the current analysis_priority "
                        f"{target['priority']} (received {supplied_priority})"
                    )
            if str(row["repo_role"] or ANALYSIS_REPO_ROLE) != ANALYSIS_REPO_ROLE:
                # Checked last so it outranks the other refusals: a trigger may
                # legitimately point into framework source and the specialist
                # reads and cites it, but turning that into durable work is the
                # obligation the reference role exists to decline.
                target["blocked_reason"] = (
                    "target file is in a reference repository, which owns no "
                    "review obligation"
                )
            batch_theme = str(item.get("batch_theme", "")).strip()
            if batch_theme:
                target["batch_theme"] = batch_theme
            target["slot_types"] = _merge_unique_values(
                target["slot_types"],
                _normalize_slot_types(item.get("slot_types"), field_name="slot_types"),
            )
            target["guidance_hypotheses"] = _merge_unique_values(
                target["guidance_hypotheses"],
                _normalize_guidance_hypotheses(
                    item.get("guidance_hypotheses"),
                    field_name="guidance_hypotheses",
                ),
            )
            trigger_payload = _requeue_trigger_payload(
                item, file_path=target["file_path"]
            )
            if trigger_payload is not None:
                target["cross_file_triggers"] = _merge_unique_values(
                    target["cross_file_triggers"], [trigger_payload]
                )

        for file_id, target in aggregated.items():
            connection.execute("SAVEPOINT requeue_target")
            try:
                outcome, queue_item_id, detail, reopened = _apply_requeue_target(
                    connection, engagement.id, file_id, target
                )
            except _TriggerTargetBlocked as blocked:
                connection.execute("ROLLBACK TO requeue_target")
                connection.execute("RELEASE requeue_target")
                counts["blocked"] += 1
                target_outcomes.append(
                    {
                        "file_id": file_id,
                        "file_path": target["file_path"],
                        "queue_item_id": None,
                        "outcome": "blocked",
                        "detail": str(blocked),
                    }
                )
                continue
            connection.execute("RELEASE requeue_target")
            counts[outcome] += 1
            reopened_terminal_files += 1 if reopened else 0
            target_outcomes.append(
                {
                    "file_id": file_id,
                    "file_path": target["file_path"],
                    "queue_item_id": queue_item_id,
                    "outcome": outcome,
                    "detail": detail,
                }
            )

    outcome_by_file = {row["file_id"]: row["outcome"] for row in target_outcomes}
    inputs = [
        {
            "index": index,
            "selector": selector,
            "file_id": file_id,
            "outcome": outcome or outcome_by_file[file_id],
        }
        for index, (selector, file_id, outcome) in enumerate(
            zip(selectors, input_file_ids, input_outcomes, strict=True)
        )
    ]
    return {
        "input_trigger_count": len(items),
        "target_count": len(aggregated),
        **counts,
        "reopened_terminal_files": reopened_terminal_files,
        "not_found": not_found,
        "ambiguous": ambiguous,
        "outcomes": target_outcomes,
        "inputs": inputs,
    }


def list_code_triggers(
    engagement_id: int,
    *,
    status_filter: str | None = None,
    repo_id: int | None = None,
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if status_filter and status_filter not in _TRIGGER_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid trigger status: {status_filter}",
        )
    clauses = ["t.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if not include_superseded:
        clauses.extend(
            [
                "t.repo_generation = repos.active_generation",
                "t.source_superseded_at IS NULL",
            ]
        )
    if status_filter:
        clauses.append("t.status = ?")
        params.append(status_filter)
    if repo_id is not None:
        _coerce_int(repo_id, field_name="repo_id")
        clauses.append("sf.repo_id = ?")
        params.append(repo_id)

    source_file_path = "sf.file_path"
    resolved_target_file_path = "tf.file_path"
    generation_file_joins = ""
    if include_superseded:
        source_file_path = "COALESCE(source_generation_file.file_path, sf.file_path)"
        resolved_target_file_path = (
            "COALESCE(target_generation_file.file_path, tf.file_path, t.target_file_path)"
        )
        generation_file_joins = """
            LEFT JOIN code_source_generation_files AS source_generation_file
              ON source_generation_file.engagement_id = t.engagement_id
             AND source_generation_file.repo_id = t.repo_id
             AND source_generation_file.repo_generation = t.repo_generation
             AND source_generation_file.file_id = t.source_file_id
            LEFT JOIN code_source_generation_files AS target_generation_file
              ON target_generation_file.engagement_id = t.engagement_id
             AND target_generation_file.repo_id = t.repo_id
             AND target_generation_file.repo_generation = t.repo_generation
             AND target_generation_file.file_id = t.target_file_id
        """

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, int(repo_id))
        rows = connection.execute(
            f"""
            SELECT
                t.*,
                {source_file_path} AS source_file_path,
                {resolved_target_file_path} AS resolved_target_file_path
            FROM code_analysis_triggers AS t
            JOIN code_files AS sf
              ON sf.id = t.source_file_id
             AND sf.engagement_id = t.engagement_id
            JOIN code_repos AS repos
              ON repos.id = sf.repo_id
             AND repos.engagement_id = sf.engagement_id
             AND repos.active_generation > 0
            LEFT JOIN code_files AS tf
              ON tf.id = t.target_file_id
             AND tf.engagement_id = t.engagement_id
            {generation_file_joins}
            WHERE {' AND '.join(clauses)}
            ORDER BY
                CASE t.status
                    WHEN 'pending' THEN 0
                    WHEN 'queued' THEN 1
                    WHEN 'resolved' THEN 2
                    ELSE 3
                END,
                t.updated_at DESC,
                t.id DESC
            """,
            tuple(params),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_code_triggers(
    engagement_id: int,
    *,
    items: list[dict[str, Any]],
    resolution_status: str,
    resolution_note: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    normalized_status = resolution_status.strip()
    if normalized_status not in _TERMINAL_TRIGGER_RESOLUTION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "resolution_status must be one of: "
                + ", ".join(sorted(_TERMINAL_TRIGGER_RESOLUTION_STATUSES))
            ),
        )
    note = resolution_note.strip()
    if not note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="resolution_note is required",
        )

    resolved = 0
    not_resolved: list[str] = []
    with get_connection() as connection:
        for idx, item in enumerate(items):
            trigger_id = item.get("trigger_id", item.get("id"))
            if trigger_id is not None:
                validated_id = _coerce_int(trigger_id, field_name="trigger_id")
                cursor = connection.execute(
                    """
                    UPDATE code_analysis_triggers
                    SET status = ?,
                        resolution_note = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ? AND status = ?
                      AND source_superseded_at IS NULL
                      AND repo_generation = (
                          SELECT active_generation
                          FROM code_repos
                          WHERE id = code_analysis_triggers.repo_id
                            AND engagement_id = code_analysis_triggers.engagement_id
                            AND active_generation > 0
                      )
                      AND source_file_id IN (
                          SELECT files.id
                          FROM code_files AS files
                          JOIN code_repos AS repos
                            ON repos.id = files.repo_id
                           AND repos.engagement_id = files.engagement_id
                           AND repos.active_generation > 0
                          WHERE files.engagement_id = ?
                      )
                    """,
                    (
                        normalized_status,
                        note,
                        engagement.id,
                        validated_id,
                        _TRIGGER_STATUS_PENDING,
                        engagement.id,
                    ),
                )
                if cursor.rowcount == 0:
                    not_resolved.append(str(validated_id))
                else:
                    resolved += cursor.rowcount
                continue

            file_path = _trigger_repository_path(item.get("file_path", item.get("target_file_path", "")))
            if not file_path:
                not_resolved.append(f"item[{idx}]")
                continue
            vuln_class = str(item.get("vuln_class", "")).strip()
            repo_id = item.get("repo_id")

            clauses = [
                "engagement_id = ?",
                "target_file_path = ?",
                "status = ?",
                "source_superseded_at IS NULL",
                "repo_generation = ("
                "SELECT active_generation FROM code_repos "
                "WHERE id = code_analysis_triggers.repo_id "
                "AND engagement_id = code_analysis_triggers.engagement_id "
                "AND active_generation > 0)",
                "source_file_id IN ("
                "SELECT files.id FROM code_files AS files "
                "JOIN code_repos AS repos ON repos.id = files.repo_id "
                "AND repos.engagement_id = files.engagement_id "
                "AND repos.active_generation > 0 "
                "WHERE files.engagement_id = ?)",
            ]
            params: list[Any] = [
                engagement.id,
                file_path,
                _TRIGGER_STATUS_PENDING,
                engagement.id,
            ]
            if vuln_class:
                clauses.append("vuln_class = ?")
                params.append(vuln_class)
            if repo_id is not None:
                validated_repo_id = _coerce_int(repo_id, field_name="repo_id")
                clauses.append(
                    "source_file_id IN ("
                    "SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ?"
                    ")"
                )
                params.extend([engagement.id, validated_repo_id])

            cursor = connection.execute(
                f"""
                UPDATE code_analysis_triggers
                SET status = ?,
                    resolution_note = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE {' AND '.join(clauses)}
                """,
                (normalized_status, note, *params),
            )
            if cursor.rowcount == 0:
                label = f"{file_path}:{vuln_class}" if vuln_class else file_path
                not_resolved.append(label)
            else:
                resolved += cursor.rowcount

    return {
        "resolved": resolved,
        "items_requested": len(items),
        "total": len(items),
        "not_resolved": not_resolved,
        "resolution_status": normalized_status,
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
    records, plus applicable_families from `_applicable_families_for_file` and
    the advisory path_suggested_families from `_path_suggested_families_for_file`."""
    engagement = _engagement_or_404(engagement_id)

    repo_clause = f"""
      AND f.repo_id IN (SELECT id FROM code_repos WHERE active_generation > 0
                        AND {_analysis_repo_sql("code_repos")})
      AND f.retired_at IS NULL
    """
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = (
            " AND f.repo_id = ? AND f.retired_at IS NULL"
            " AND f.repo_id IN (SELECT id FROM code_repos WHERE"
            f" {_analysis_repo_sql('code_repos')})"
        )
        repo_params = (repo_id,)

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)
        file_rows = connection.execute(
            f"""
            SELECT f.id AS file_id, f.file_path, f.classification, f.slot_types_json,
                   f.analysis_status, f.loc, f.language, f.role,
                   f.total_functions, f.total_entry_points, f.total_sinks, f.total_exports,
                   f.structural_unavailable_dimensions_json
            FROM code_files f
            WHERE f.engagement_id = ? AND f.classification IN ('critical', 'high'){repo_clause}
            ORDER BY f.analysis_priority DESC, f.id ASC
            """,
            (engagement.id, *repo_params),
        ).fetchall()

        file_ids = [int(r["file_id"]) for r in file_rows]
        cwe_by_file: dict[int, dict[str, dict[str, Any]]] = {}  # file_id -> family -> merged entry
        result_effort_by_file: dict[int, dict[str, int]] = {}
        if file_ids:
            file_ids_json = json.dumps(list(file_ids))
            successful_queue_review = _successful_terminal_review_row_sql("queue")
            queue_done_rows = connection.execute(
                f"""
                SELECT queue.file_id, queue.cwe_coverage_json
                {queue_file_repo_join_sql(
                    files_alias="queue_files", repos_alias="queue_repos"
                )}
                WHERE queue.engagement_id = ?
                  AND queue.file_id IN (SELECT value FROM json_each(?))
                  AND {canonical_current_attempt_sql("queue", "queue_repos")}
                  AND ({successful_queue_review})
                """,
                (engagement.id, file_ids_json),
            ).fetchall()
            for qr in queue_done_rows:
                fid = int(qr["file_id"])
                cwe_cov = _json_decode(qr["cwe_coverage_json"], [])
                _merge_cwe_coverage_entries(cwe_by_file, fid, cwe_cov)

            direct_rows = _current_receipt_coverage_rows(
                connection, engagement.id, file_ids_json, allow_processing=True
            )
            for dr in direct_rows:
                fid = int(dr["file_id"])
                cwe_cov = _json_decode(dr["cwe_coverage_json"], [])
                _merge_cwe_coverage_entries(cwe_by_file, fid, cwe_cov)

            result_effort_by_file = _current_receipt_effort_by_file(
                connection, engagement.id, file_ids_json, allow_processing=True
            )

        files_detail: list[dict[str, Any]] = []
        for fr in file_rows:
            fid = int(fr["file_id"])
            slot_types = _json_decode(fr["slot_types_json"], [])
            language = fr["language"] or ""
            role = fr["role"] or ""
            applicable = _applicable_families_for_file(slot_types, language=language, role=role)
            path_suggested = _path_suggested_families_for_file(
                slot_types,
                language=language,
                role=role,
                file_path=str(fr["file_path"] or ""),
            )
            merged_entries = list(cwe_by_file.get(fid, {}).values())
            total_functions = int(fr["total_functions"] or 0)
            result_effort = result_effort_by_file.get(fid, _empty_receipt_effort())
            distinct_callables = int(
                result_effort["distinct_structural_callables_reviewed"]
            )
            callable_coverage_pct = (
                min(100.0, distinct_callables / total_functions * 100.0)
                if total_functions > 0
                else 0.0
            )
            files_detail.append({
                "file_id": fid,
                "file_path": fr["file_path"],
                "classification": fr["classification"],
                "analysis_status": fr["analysis_status"],
                "loc": int(fr["loc"]),
                "total_functions": total_functions,
                "total_entry_points": int(fr["total_entry_points"] or 0),
                "total_sinks": int(fr["total_sinks"] or 0),
                "total_exports": int(fr["total_exports"] or 0),
                # A file can report zero of everything because nothing was
                # scanned; the CWE matrix cannot tell that from a clean read
                # without the index's own coverage declaration.
                "structural_unavailable_dimensions": _json_decode(
                    fr["structural_unavailable_dimensions_json"], []
                ),
                "slot_types": slot_types,
                "applicable_families": applicable,
                "path_suggested_families": path_suggested,
                "cwe_coverage": merged_entries,
                "analysis_effort": {
                    **result_effort,
                    "total_functions": total_functions,
                    "callable_coverage_pct": round(callable_coverage_pct, 1),
                },
            })

        # Also include the standard coverage summary fields
        summary = code_coverage_summary(engagement_id, repo_id=repo_id)

    return {
        "files": files_detail,
        "total_files": summary["total_files"],
        "reference_repos": summary["reference_repos"],
        "open_leases": summary["open_leases"],
        "open_leases_count": summary["open_leases_count"],
        "by_classification": summary["by_classification"],
        "by_status": summary["by_status"],
        "gate": summary["gate"],
    }
