"""Durable shared run accounting, inventory, debt, and comparison.

This module extends the Phase 2 proof-run identity without coupling the generic
run ledger to the code-analysis monolith. It records facts produced elsewhere;
it never launches tools, models, or target-facing work.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlsplit

from fastapi import HTTPException, status

from . import _common
from ._common import _engagement_or_404
from .proofs import _command_output_evidence_healths


RUN_KINDS = frozenset({"code", "web", "blue", "shared"})
RUN_PURPOSES = frozenset({"proof", "scan"})
RUN_STATUSES = frozenset(
    {"queued", "running", "partial", "completed", "failed", "interrupted", "canceled"}
)
ACTIVE_RUN_STATUSES = frozenset({"queued", "running"})
TERMINAL_RUN_STATUSES = RUN_STATUSES - ACTIVE_RUN_STATUSES
INVENTORY_STATUSES = frozenset({"included", "excluded", "missing"})
PARSER_STATUSES = frozenset({"parsed", "failed", "not_applicable"})
OBLIGATION_STATUSES = frozenset(
    {"open", "resolved", "blocked", "deferred", "accepted_gap"}
)
CANDIDATE_STATES = frozenset(
    {"open", "promoted", "rejected", "duplicate", "deferred"}
)
TOOL_SIGNAL_KINDS = frozenset(
    {"sanitizer_violation", "reproducible_crash", "attributed_oob_callback"}
)
DISCOVERY_TERMINAL_REASONS = frozenset(
    {"frontier_exhausted", "no_new_candidates", "cap_reached", "interrupted", "failed"}
)
DISCOVERY_COMPLETE_REASONS = frozenset(
    {"frontier_exhausted", "no_new_candidates"}
)
CODE_RECEIPT_KINDS = frozenset(
    {"variant_check", "fuzz_decision", "fuzz_campaign"}
)
_CODE_RECEIPT_TABLES = {
    "variant_check": "code_variant_check_receipts",
    "fuzz_decision": "code_fuzz_decisions",
    "fuzz_campaign": "code_fuzz_campaign_receipts",
}
_CODE_RECEIPT_OBLIGATION_KINDS = {
    "variant_check": frozenset({"variant", "variant_check"}),
    "fuzz_decision": frozenset({"fuzz_applicability", "fuzz_decision"}),
    "fuzz_campaign": frozenset({"fuzz_campaign", "fuzz_target"}),
}


def _invalid(name: str, value: str, allowed: Iterable[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"invalid {name} {value!r}; expected one of {', '.join(sorted(allowed))}",
    )


def _json_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _json_value(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _sha256(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()


_INVENTORY_COMMITMENT_VERSION = "v1"
_SOURCE_IDENTITY_FIELDS = (
    "target_key",
    "declared_root",
    "path",
    "content_sha256",
    "byte_size",
    "line_count",
    "encoding",
    "inventory_status",
    "exclusion_reason",
    "parser_status",
    "parser_error",
)


def source_inventory_commitment(
    target_key: str, sources: Iterable[sqlite3.Row | dict[str, Any]]
) -> dict[str, Any]:
    """Return the canonical exact-inventory commitment for one generation."""

    identities = sorted(
        _sha256({field: source[field] for field in _SOURCE_IDENTITY_FIELDS})
        for source in sources
        if str(source["target_key"]) == target_key
    )
    return {
        "inventory_commitment_version": _INVENTORY_COMMITMENT_VERSION,
        "inventory_count": len(identities),
        "inventory_digest": _sha256(
            {
                "version": _INVENTORY_COMMITMENT_VERSION,
                "target_key": target_key,
                "source_identity_sha256": identities,
            }
        ),
    }


def _positive_int_list(values: Iterable[Any]) -> list[int]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if type(value) is not int or value < 1:
            raise HTTPException(status_code=400, detail="proof receipt ids must be positive integers")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _stored_receipt_ids(value: Any) -> list[int]:
    """Return the usable receipt ids inside one stored ``*_json`` column.

    Write paths gate on ``_positive_int_list``, which refuses anything else, so
    a well-formed row round-trips unchanged. Read paths cannot refuse: a run
    resumed from a row that predates that gate still has to be creatable, and
    reading it must not raise. One shared reader also keeps the health lookup
    and its consumers filtering the same values, so a malformed entry can never
    be counted by one and dereferenced by the other.
    """

    return [
        entry
        for entry in _json_value(value, [])
        if type(entry) is int and entry > 0
    ]


def _assessment_run_row(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    run_id: int | None = None,
    run_uuid: str | None = None,
) -> sqlite3.Row | None:
    if (run_id is None) == (run_uuid is None):
        raise ValueError("exactly one assessment run identity is required")
    predicate = "runs.id = ?" if run_id is not None else "runs.run_uuid = ?"
    identity: int | str = int(run_id) if run_id is not None else str(run_uuid)
    return connection.execute(
        f"""
        SELECT runs.*,
               dispatches.agent_id AS producer_dispatch_agent_id,
               dispatches.agent_role AS producer_dispatch_agent_role,
               dispatches.requested_model,
               dispatches.actual_model,
               dispatches.requested_reasoning,
               dispatches.actual_reasoning,
               dispatches.launcher_effective_model,
               dispatches.launcher_effective_reasoning,
               dispatches.launcher_effective_source,
               dispatches.client_name,
               dispatches.requested_client,
               dispatches.launcher_effective_client,
               dispatches.provider_observed_client,
               dispatches.source_revision,
               dispatches.operator_instruction_path,
               dispatches.operator_instruction_sha256,
               dispatches.specialist_instruction_path,
               dispatches.specialist_instruction_sha256,
               dispatches.instruction_identity_status,
               dispatches.instructions_stale
        FROM assessment_runs AS runs
        JOIN assessment_dispatches AS dispatches
          ON dispatches.id = runs.producer_dispatch_id
        WHERE runs.engagement_id = ? AND {predicate}
        """,
        (engagement_id, identity),
    ).fetchone()


def _run_or_404(
    connection: sqlite3.Connection, engagement_id: int, run_id: int
) -> sqlite3.Row:
    row = _assessment_run_row(connection, engagement_id, run_id=run_id)
    if row is None:
        raise HTTPException(status_code=404, detail="assessment run not found")
    return row


def _dispatch_provenance(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Return the exact dispatch identity that a terminal seal freezes."""

    record = dict(row)
    stale = record.get("instructions_stale")
    return {
        "dispatch_id": int(record["producer_dispatch_id"]),
        "agent_id": str(record["producer_dispatch_agent_id"]),
        "agent_role": str(record["producer_dispatch_agent_role"]),
        "requested_model": record.get("requested_model"),
        "actual_model": str(record.get("actual_model") or "unknown"),
        "requested_reasoning": record.get("requested_reasoning"),
        "actual_reasoning": str(record.get("actual_reasoning") or "unknown"),
        "launcher_effective_model": record.get("launcher_effective_model"),
        "launcher_effective_reasoning": record.get("launcher_effective_reasoning"),
        "launcher_effective_source": record.get("launcher_effective_source"),
        "requested_client": str(record.get("requested_client") or "unknown"),
        "launcher_effective_client": str(
            record.get("launcher_effective_client") or "unknown"
        ),
        "provider_observed_client": str(
            record.get("provider_observed_client") or "unknown"
        ),
        # Compatibility projection of launcher_effective_client. New consumers
        # use the three explicit identity fields above.
        "client_name": str(record.get("client_name") or "unknown"),
        "source_revision": str(record.get("source_revision") or "unknown"),
        "operator_instruction_path": record.get("operator_instruction_path"),
        "operator_instruction_sha256": record.get("operator_instruction_sha256"),
        "specialist_instruction_path": record.get("specialist_instruction_path"),
        "specialist_instruction_sha256": record.get("specialist_instruction_sha256"),
        "instruction_identity_status": str(
            record.get("instruction_identity_status") or "incomplete"
        ),
        "instructions_stale": bool(stale) if stale is not None else None,
    }


def _require_active_run(row: sqlite3.Row, *, operation: str) -> None:
    current = str(row["status"])
    if current != "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"assessment run is status={current!r}; {operation} requires a running run",
        )


def _validate_receipt_ids(
    connection: sqlite3.Connection,
    engagement_id: int,
    run_id: int,
    values: Iterable[Any],
) -> list[int]:
    receipt_ids = _positive_int_list(values)
    if not receipt_ids:
        return []
    placeholders = ",".join("?" for _ in receipt_ids)
    lineage_ids = _run_lineage_ids(connection, run_id)
    lineage_placeholders = ",".join("?" for _ in lineage_ids)
    rows = connection.execute(
        f"""
        SELECT id FROM assessment_proof_receipts
        WHERE engagement_id = ? AND run_id IN ({lineage_placeholders})
          AND id IN ({placeholders})
        """,
        (engagement_id, *lineage_ids, *receipt_ids),
    ).fetchall()
    if {int(row["id"]) for row in rows} != set(receipt_ids):
        raise HTTPException(
            status_code=400,
            detail="proof receipts must belong to the same assessment run",
        )
    return receipt_ids


def _run_lineage_ids(connection: sqlite3.Connection, run_id: int) -> list[int]:
    rows = connection.execute(
        """
        WITH RECURSIVE lineage(id, parent_id) AS (
            SELECT id, resumed_from_run_id FROM assessment_runs WHERE id = ?
            UNION ALL
            SELECT runs.id, runs.resumed_from_run_id
            FROM assessment_runs AS runs
            JOIN lineage ON runs.id = lineage.parent_id
        )
        SELECT id FROM lineage
        """,
        (run_id,),
    ).fetchall()
    return [int(row["id"]) for row in rows]


def _page(
    connection: sqlite3.Connection,
    *,
    table: str,
    engagement_id: int,
    run_id: int,
    limit: int,
    offset: int,
    order_by: str = "id",
) -> dict[str, Any]:
    total = int(
        connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ? AND run_id = ?",
            (engagement_id, run_id),
        ).fetchone()[0]
    )
    rows = connection.execute(
        f"""
        SELECT * FROM {table}
        WHERE engagement_id = ? AND run_id = ?
        ORDER BY {order_by}
        LIMIT ? OFFSET ?
        """,
        (engagement_id, run_id, limit, offset),
    ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(rows) < total,
    }


def _evidence_health(row: sqlite3.Row | dict[str, Any]) -> str:
    record = dict(row)
    recorded = str(record.get("recorded_health") or "healthy")
    if recorded != "healthy":
        return recorded
    if str(record.get("evidence_kind") or "") == "command":
        command_health = str(record.get("command_output_evidence_health") or "stale")
        if command_health != "healthy":
            return command_health
    if (
        str(record.get("evidence_kind") or "") == "source_observation"
        and record.get("source_read_id") is None
        and record.get("artifact_id") is None
    ):
        return "stale"
    if (
        str(record.get("evidence_kind") or "")
        in {"artifact", "http_exchange", "browser_action", "oob_event"}
        and record.get("artifact_id") is None
    ):
        return "stale"
    if record.get("artifact_id") is not None:
        integrity = str(record.get("integrity_status") or "")
        current_sha = str(record.get("current_sha256") or "")
        if integrity == "missing":
            return "missing"
        if (
            integrity == "mismatch"
            or not current_sha
            or current_sha != record.get("evidence_sha256")
        ):
            return "stale"
        if not bool(record.get("present")):
            return "tombstoned"
    elif str(record.get("artifact_relative_path") or ""):
        return "tombstoned"
    return "healthy"


def _receipt_health_rows(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    where_sql: str,
    parameters: tuple[Any, ...],
) -> list[dict[str, Any]]:
    rows = connection.execute(
        f"""
        SELECT receipts.id, receipts.recorded_health, receipts.evidence_kind,
               receipts.source_read_id,
               receipts.command_run_id,
               receipts.artifact_id,
               receipts.artifact_relative_path, receipts.evidence_sha256,
               artifacts.present, artifacts.integrity_status,
               artifacts.sha256 AS current_sha256
        FROM assessment_proof_receipts AS receipts
        LEFT JOIN assessment_artifacts AS artifacts ON artifacts.id = receipts.artifact_id
        WHERE receipts.engagement_id = ? AND {where_sql}
        """,
        (engagement_id, *parameters),
    ).fetchall()
    records = [dict(row) for row in rows]
    command_health = _command_output_evidence_healths(
        connection,
        engagement_id,
        (
            int(record["command_run_id"])
            for record in records
            if record.get("command_run_id") is not None
        ),
    )
    for record in records:
        if record.get("command_run_id") is not None:
            record["command_output_evidence_health"] = command_health.get(
                int(record["command_run_id"]), "stale"
            )
    return records


def _receipt_health_by_id(
    connection: sqlite3.Connection,
    engagement_id: int,
    receipt_ids: Iterable[int],
) -> dict[int, str]:
    ordered_ids = sorted(set(receipt_ids))
    health_by_id: dict[int, str] = {}
    for offset in range(0, len(ordered_ids), 500):
        batch = ordered_ids[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = _receipt_health_rows(
            connection,
            engagement_id,
            where_sql=f"receipts.id IN ({placeholders})",
            parameters=tuple(batch),
        )
        health_by_id.update(
            (int(row["id"]), _evidence_health(row)) for row in rows
        )
    return health_by_id


def _evidence_health_counts(
    connection: sqlite3.Connection, engagement_id: int, run_id: int
) -> dict[str, int]:
    lineage_ids = _run_lineage_ids(connection, run_id)
    placeholders = ",".join("?" for _ in lineage_ids)
    rows = _receipt_health_rows(
        connection,
        engagement_id,
        where_sql=f"receipts.run_id IN ({placeholders})",
        parameters=tuple(lineage_ids),
    )
    return _health_counts(rows)


def _health_counts(rows: Iterable[sqlite3.Row | dict[str, Any]]) -> dict[str, int]:
    counts = {"healthy": 0, "missing": 0, "stale": 0, "tombstoned": 0}
    for row in rows:
        health = _evidence_health(row)
        counts[health] = counts.get(health, 0) + 1
    return counts


def _effective_proof_receipt_ids(
    connection: sqlite3.Connection,
    engagement_id: int,
    run: sqlite3.Row,
) -> list[int]:
    """Return evidence that still participates in this recovery attempt.

    Parent receipts remain immutable lineage history. A resumed run evaluates
    its own newly captured receipts plus parent receipts still named by copied
    child state; unrelated parent attempts are not an unrepairable completion
    blocker.
    """

    run_id = int(run["id"])
    receipt_ids = {
        int(row["id"])
        for row in connection.execute(
            "SELECT id FROM assessment_proof_receipts "
            "WHERE engagement_id = ? AND run_id = ?",
            (engagement_id, run_id),
        ).fetchall()
    }
    if run["resumed_from_run_id"] is None:
        return sorted(receipt_ids)

    source_read_receipts = connection.execute(
        """
        SELECT proof_receipt_id
        FROM assessment_run_source_reads
        WHERE engagement_id = ? AND run_id = ? AND proof_receipt_id IS NOT NULL
        """,
        (engagement_id, run_id),
    ).fetchall()
    receipt_ids.update(int(row["proof_receipt_id"]) for row in source_read_receipts)
    for table in (
        "assessment_run_obligations",
        "assessment_run_candidates",
        "assessment_run_tool_signals",
        "assessment_run_discovery_passes",
        "assessment_run_code_receipt_links",
    ):
        rows = connection.execute(
            f"SELECT proof_receipt_ids_json FROM {table} "
            "WHERE engagement_id = ? AND run_id = ?",
            (engagement_id, run_id),
        ).fetchall()
        for row in rows:
            receipt_ids.update(_stored_receipt_ids(row["proof_receipt_ids_json"]))

    pending = set(receipt_ids)
    while pending:
        placeholders = ",".join("?" for _ in pending)
        rows = connection.execute(
            f"""
            SELECT derivative_of_receipt_id
            FROM assessment_proof_receipts
            WHERE engagement_id = ? AND id IN ({placeholders})
              AND derivative_of_receipt_id IS NOT NULL
            """,
            (engagement_id, *sorted(pending)),
        ).fetchall()
        dependencies = {
            int(row["derivative_of_receipt_id"])
            for row in rows
            if int(row["derivative_of_receipt_id"]) not in receipt_ids
        }
        receipt_ids.update(dependencies)
        pending = dependencies
    return sorted(receipt_ids)


def _effective_evidence_health_counts(
    connection: sqlite3.Connection,
    engagement_id: int,
    run: sqlite3.Row,
) -> dict[str, int]:
    receipt_ids = _effective_proof_receipt_ids(connection, engagement_id, run)
    if not receipt_ids:
        return {"healthy": 0, "missing": 0, "stale": 0, "tombstoned": 0}
    placeholders = ",".join("?" for _ in receipt_ids)
    rows = _receipt_health_rows(
        connection,
        engagement_id,
        where_sql=f"receipts.id IN ({placeholders})",
        parameters=tuple(receipt_ids),
    )
    counts = _health_counts(rows)
    counts["stale"] += len(receipt_ids) - len(rows)
    return counts


def _proof_receipts_are_healthy(
    connection: sqlite3.Connection, engagement_id: int, receipt_ids: list[int]
) -> bool:
    if not receipt_ids:
        return False
    placeholders = ",".join("?" for _ in receipt_ids)
    rows = _receipt_health_rows(
        connection,
        engagement_id,
        where_sql=f"receipts.id IN ({placeholders})",
        parameters=tuple(receipt_ids),
    )
    return len(rows) == len(set(receipt_ids)) and all(
        _evidence_health(row) == "healthy" for row in rows
    )


def _discovery_receipts_match_dispatch(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    dispatch_id: int,
    dispatch_agent_id: str,
    receipt_ids: list[int],
) -> bool:
    """Require durable discovery evidence produced by the attributed dispatch."""

    if not _proof_receipts_are_healthy(connection, engagement_id, receipt_ids):
        return False
    placeholders = ",".join("?" for _ in receipt_ids)
    rows = connection.execute(
        f"""
        SELECT receipts.evidence_kind,
               commands.agent_name AS command_agent_id,
               source_reads.dispatch_id AS source_dispatch_id,
               artifacts.producer_agent_id AS artifact_agent_id,
               artifact_commands.agent_name AS artifact_command_agent_id
        FROM assessment_proof_receipts AS receipts
        LEFT JOIN assessment_command_runs AS commands
          ON commands.id = receipts.command_run_id
        LEFT JOIN assessment_run_source_reads AS source_reads
          ON source_reads.id = receipts.source_read_id
        LEFT JOIN assessment_artifacts AS artifacts
          ON artifacts.id = receipts.artifact_id
        LEFT JOIN assessment_command_runs AS artifact_commands
          ON artifact_commands.id = artifacts.producer_command_run_id
        WHERE receipts.engagement_id = ? AND receipts.id IN ({placeholders})
        """,
        (engagement_id, *receipt_ids),
    ).fetchall()
    def attributed(row: sqlite3.Row) -> bool:
        evidence_kind = str(row["evidence_kind"])
        if evidence_kind == "command" and str(row["command_agent_id"] or "") == dispatch_agent_id:
            return True
        if (
            evidence_kind == "source_observation"
            and row["source_dispatch_id"] is not None
            and int(row["source_dispatch_id"]) == dispatch_id
        ):
            return True
        if evidence_kind in {
            "source_observation",
            "artifact",
            "http_exchange",
            "browser_action",
            "oob_event",
        } and dispatch_agent_id in {
            str(row["artifact_agent_id"] or ""),
            str(row["artifact_command_agent_id"] or ""),
        }:
            return True
        return False

    return len(rows) == len(set(receipt_ids)) and all(attributed(row) for row in rows)


def _code_receipt_has_exact_artifact_proof(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    receipt_kind: str,
    receipt: sqlite3.Row,
    proof_receipt_ids: list[int],
) -> bool:
    if not _proof_receipts_are_healthy(
        connection, engagement_id, proof_receipt_ids
    ):
        return False
    evidence_ref = str(receipt["evidence_ref"] or "").strip()
    path = PurePosixPath(evidence_ref)
    if not evidence_ref or path.is_absolute() or ".." in path.parts:
        return False
    normalized_ref = str(path)
    placeholders = ",".join("?" for _ in proof_receipt_ids)
    rows = connection.execute(
        f"""
        SELECT receipts.evidence_kind, receipts.evidence_sha256,
               artifacts.relative_path, artifacts.sha256
        FROM assessment_proof_receipts AS receipts
        JOIN assessment_artifacts AS artifacts ON artifacts.id = receipts.artifact_id
        WHERE receipts.engagement_id = ? AND receipts.id IN ({placeholders})
        """,
        (engagement_id, *proof_receipt_ids),
    ).fetchall()
    expected_digest = (
        str(receipt["evidence_sha256"] or "").strip().lower()
        if receipt_kind in {"fuzz_decision", "fuzz_campaign"}
        else None
    )
    return any(
        str(row["evidence_kind"]) == "artifact"
        and str(row["relative_path"]) == normalized_ref
        and (
            expected_digest is None
            or (
                str(row["evidence_sha256"]) == expected_digest
                and str(row["sha256"]) == expected_digest
            )
        )
        for row in rows
    )


def _run_counts(
    connection: sqlite3.Connection, engagement_id: int, run_id: int
) -> dict[str, int]:
    def scalar(query: str, parameters: tuple[Any, ...] = ()) -> int:
        return int(connection.execute(query, (engagement_id, run_id, *parameters)).fetchone()[0])

    counts = {
        "inventory_total": scalar(
            "SELECT COUNT(*) FROM assessment_run_sources WHERE engagement_id = ? AND run_id = ?"
        ),
        "inventory_included": scalar(
            "SELECT COUNT(*) FROM assessment_run_sources WHERE engagement_id = ? AND run_id = ? AND inventory_status = 'included'"
        ),
        "inventory_excluded": scalar(
            "SELECT COUNT(*) FROM assessment_run_sources WHERE engagement_id = ? AND run_id = ? AND inventory_status = 'excluded'"
        ),
        "inventory_missing": scalar(
            "SELECT COUNT(*) FROM assessment_run_sources WHERE engagement_id = ? AND run_id = ? AND inventory_status = 'missing'"
        ),
        "source_reads": scalar(
            "SELECT COUNT(*) FROM assessment_run_source_reads WHERE engagement_id = ? AND run_id = ?"
        ),
        "obligations": scalar(
            "SELECT COUNT(*) FROM assessment_run_obligations WHERE engagement_id = ? AND run_id = ?"
        ),
        "open_hard_obligations": scalar(
            "SELECT COUNT(*) FROM assessment_run_obligations WHERE engagement_id = ? AND run_id = ? AND hard = 1 AND status IN ('open', 'blocked', 'deferred', 'accepted_gap')"
        ),
        "candidates": scalar(
            "SELECT COUNT(*) FROM assessment_run_candidates WHERE engagement_id = ? AND run_id = ?"
        ),
        "open_candidates": scalar(
            "SELECT COUNT(*) FROM assessment_run_candidates WHERE engagement_id = ? AND run_id = ? AND state IN ('open', 'deferred')"
        ),
        "tool_signals": scalar(
            "SELECT COUNT(*) FROM assessment_run_tool_signals WHERE engagement_id = ? AND run_id = ?"
        ),
        "discovery_passes": scalar(
            "SELECT COUNT(*) FROM assessment_run_discovery_passes WHERE engagement_id = ? AND run_id = ?"
        ),
        "code_receipt_links": scalar(
            "SELECT COUNT(*) FROM assessment_run_code_receipt_links WHERE engagement_id = ? AND run_id = ?"
        ),
    }
    lineage_ids = _run_lineage_ids(connection, run_id)
    placeholders = ",".join("?" for _ in lineage_ids)
    linked_findings = connection.execute(
        f"""
        SELECT COUNT(DISTINCT finding_id)
        FROM assessment_finding_proof_receipts
        WHERE engagement_id = ? AND proof_receipt_id IN (
            SELECT id FROM assessment_proof_receipts
            WHERE engagement_id = ? AND run_id IN ({placeholders})
        )
        """,
        (engagement_id, engagement_id, *lineage_ids),
    ).fetchone()
    counts["findings"] = int(linked_findings[0])
    counts["proof_receipts"] = int(
        connection.execute(
            f"""
            SELECT COUNT(*) FROM assessment_proof_receipts
            WHERE engagement_id = ? AND run_id IN ({placeholders})
            """,
            (engagement_id, *lineage_ids),
        ).fetchone()[0]
    )
    return counts


def _current_blockers(
    connection: sqlite3.Connection,
    run: sqlite3.Row,
) -> list[dict[str, Any]]:
    run_id = int(run["id"])
    engagement_id = int(run["engagement_id"])
    blockers: list[dict[str, Any]] = []
    counts = _run_counts(connection, engagement_id, run_id)
    effective_proof_health = _effective_evidence_health_counts(
        connection, engagement_id, run
    )
    if str(run["run_purpose"]) == "scan":
        if not _json_value(run["target_identity_json"], {}):
            blockers.append(
                {
                    "code": "target_identity_missing",
                    "message": "Scan target identity is missing.",
                    "object_type": "run",
                    "object_id": run_id,
                    "action": "record exact scan target identity before completion",
                }
            )
        source_generations = _json_value(run["source_generations_json"], [])
        if not source_generations:
            blockers.append(
                {
                    "code": "source_generation_missing",
                    "message": "Scan source generation identity is missing.",
                    "object_type": "run",
                    "object_id": run_id,
                    "action": "record source generation and manifest digests",
                }
            )
        else:
            generation_targets: set[str] = set()
            for index, generation in enumerate(source_generations):
                target_key = (
                    str(generation.get("target_key") or "").strip()
                    if isinstance(generation, dict)
                    else ""
                )
                generation_number = (
                    generation.get("generation")
                    if isinstance(generation, dict)
                    else None
                )
                manifest_digest = (
                    str(generation.get("manifest_digest") or "")
                    if isinstance(generation, dict)
                    else ""
                )
                valid_generation = (
                    bool(target_key)
                    and type(generation_number) is int
                    and generation_number >= 0
                    and len(manifest_digest) == 64
                    and all(
                        character in "0123456789abcdef"
                        for character in manifest_digest
                    )
                )
                if not valid_generation:
                    blockers.append(
                        {
                            "code": "source_generation_invalid",
                            "message": (
                                f"Source generation record {index} lacks exact target, "
                                "generation, or manifest digest identity."
                            ),
                            "object_type": "source_generation",
                            "object_id": target_key or index,
                            "action": (
                                "record target_key, nonnegative generation, and lowercase "
                                "SHA-256 manifest_digest"
                            ),
                        }
                    )
                    continue
                if target_key in generation_targets:
                    blockers.append(
                        {
                            "code": "source_generation_duplicate",
                            "message": (
                                f"Source generation target {target_key} is declared more "
                                "than once."
                            ),
                            "object_type": "source_generation",
                            "object_id": target_key,
                            "action": "declare exactly one inventory commitment per target",
                        }
                    )
                    continue
                generation_targets.add(target_key)
                expected_version = generation.get("inventory_commitment_version")
                expected_count = generation.get("inventory_count")
                expected_digest = str(generation.get("inventory_digest") or "")
                valid_commitment = (
                    expected_version == _INVENTORY_COMMITMENT_VERSION
                    and type(expected_count) is int
                    and expected_count >= 0
                    and len(expected_digest) == 64
                    and all(
                        character in "0123456789abcdef"
                        for character in expected_digest
                    )
                )
                if not valid_commitment:
                    blockers.append(
                        {
                            "code": "source_inventory_commitment_missing",
                            "message": (
                                f"Source generation {target_key} lacks a valid exact "
                                "inventory count and digest commitment."
                            ),
                            "object_type": "source_generation",
                            "object_id": target_key,
                            "action": (
                                "record inventory_commitment_version=v1, inventory_count, "
                                "and lowercase SHA-256 inventory_digest before the run"
                            ),
                        }
                    )
                    continue
                recorded_sources = connection.execute(
                    """
                    SELECT * FROM assessment_run_sources
                    WHERE engagement_id = ? AND run_id = ? AND target_key = ?
                    """,
                    (engagement_id, run_id, target_key),
                ).fetchall()
                actual = source_inventory_commitment(target_key, recorded_sources)
                if (
                    actual["inventory_count"] != expected_count
                    or actual["inventory_digest"] != expected_digest
                ):
                    blockers.append(
                        {
                            "code": "source_inventory_incomplete",
                            "message": (
                                f"Source generation {target_key} expected {expected_count} "
                                f"inventory rows but recorded {actual['inventory_count']}; "
                                "the exact inventory digest does not match."
                            ),
                            "object_type": "source_generation",
                            "object_id": target_key,
                            "action": (
                                "resume bounded inventory import until count and digest match"
                            ),
                        }
                    )
        if counts["inventory_total"] == 0:
            blockers.append(
                {
                    "code": "inventory_missing",
                    "message": "Scan has no source inventory.",
                    "object_type": "sources",
                    "object_id": run_id,
                    "action": "publish every included, excluded, and missing source",
                }
            )
        else:
            declared_targets = {
                str(generation.get("target_key") or "").strip()
                for generation in source_generations
                if isinstance(generation, dict)
                and str(generation.get("target_key") or "").strip()
            }
            represented_targets = {
                str(row["target_key"])
                for row in connection.execute(
                    """
                    SELECT DISTINCT target_key FROM assessment_run_sources
                    WHERE engagement_id = ? AND run_id = ?
                    """,
                    (engagement_id, run_id),
                ).fetchall()
            }
            for target_key in sorted(declared_targets - represented_targets):
                blockers.append(
                    {
                        "code": "source_inventory_missing",
                        "message": (
                            f"Declared source generation {target_key} has no inventory rows."
                        ),
                        "object_type": "source_generation",
                        "object_id": target_key,
                        "action": (
                            "publish included, excluded, and missing rows for this target"
                        ),
                    }
                )
        if str(run["run_kind"]) == "code":
            discovery = connection.execute(
                """
                SELECT passes.*, dispatches.agent_id AS dispatch_agent_id
                FROM assessment_run_discovery_passes AS passes
                JOIN assessment_dispatches AS dispatches
                  ON dispatches.id = passes.dispatch_id
                WHERE passes.engagement_id = ? AND passes.run_id = ?
                ORDER BY passes.id DESC LIMIT 1
                """,
                (engagement_id, run_id),
            ).fetchone()
            if discovery is None:
                blockers.append(
                    {
                        "code": "discovery_terminal_missing",
                        "message": "Code scan has no terminal discovery pass.",
                        "object_type": "discovery_passes",
                        "object_id": run_id,
                        "action": (
                            "record an evidence-backed discovery pass with the current "
                            "frontier outcome"
                        ),
                    }
                )
            elif str(discovery["terminal_reason"]) not in DISCOVERY_COMPLETE_REASONS:
                blockers.append(
                    {
                        "code": "discovery_unresolved",
                        "message": (
                            "Latest discovery pass ended "
                            f"{str(discovery['terminal_reason'])}."
                        ),
                        "object_type": "discovery_pass",
                        "object_id": int(discovery["id"]),
                        "action": (
                            "resume discovery until the recorded frontier is exhausted, "
                            "or has no new candidates; retain cap-reached work as unresolved"
                        ),
                    }
                )
            else:
                discovery_receipt_ids = _json_value(
                    discovery["proof_receipt_ids_json"], []
                )
                if not _discovery_receipts_match_dispatch(
                    connection,
                    engagement_id,
                    dispatch_id=int(discovery["dispatch_id"]),
                    dispatch_agent_id=str(discovery["dispatch_agent_id"]),
                    receipt_ids=discovery_receipt_ids,
                ):
                    blockers.append(
                        {
                            "code": "discovery_proof_unhealthy",
                            "message": (
                                "Latest terminal discovery pass no longer has healthy "
                                "evidence attributable to its dispatch."
                            ),
                            "object_type": "discovery_pass",
                            "object_id": int(discovery["id"]),
                            "action": "record a fresh evidence-backed discovery pass",
                        }
                    )
    elif sum(effective_proof_health.values()) == 0:
        blockers.append(
            {
                "code": "proof_missing",
                "message": "Proof run has no recorded evidence receipt.",
                "object_type": "proof_receipts",
                "object_id": run_id,
                "action": "record the observed proof before completion",
            }
        )
    obligation_rows = connection.execute(
        """
        SELECT id, identity_key, status FROM assessment_run_obligations
        WHERE engagement_id = ? AND run_id = ? AND hard = 1
          AND status IN ('open', 'blocked', 'deferred', 'accepted_gap')
        ORDER BY id
        """,
        (engagement_id, run_id),
    ).fetchall()
    for row in obligation_rows:
        blockers.append(
            {
                "code": "unresolved_obligation",
                "message": f"Hard obligation {row['identity_key']} is {row['status']}.",
                "object_type": "obligation",
                "object_id": int(row["id"]),
                "action": "resolve with recorded evidence or retain a partial run",
            }
        )
    candidate_rows = connection.execute(
        """
        SELECT id, identity_key, state FROM assessment_run_candidates
        WHERE engagement_id = ? AND run_id = ? AND state IN ('open', 'deferred')
        ORDER BY id
        """,
        (engagement_id, run_id),
    ).fetchall()
    for row in candidate_rows:
        blockers.append(
            {
                "code": "unresolved_candidate",
                "message": f"Candidate {row['identity_key']} is {row['state']}.",
                "object_type": "candidate",
                "object_id": int(row["id"]),
                "action": "record a supported terminal candidate disposition",
            }
        )
    promoted_rows = connection.execute(
        """
        SELECT candidates.id, candidates.finding_slug,
               findings.verification_status
        FROM assessment_run_candidates AS candidates
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = candidates.engagement_id
         AND findings.slug = candidates.finding_slug
        WHERE candidates.engagement_id = ? AND candidates.run_id = ?
          AND candidates.state = 'promoted'
          AND COALESCE(findings.verification_status, '')
              NOT IN ('confirmed', 'downgraded', 'false_positive')
        ORDER BY candidates.id
        """,
        (engagement_id, run_id),
    ).fetchall()
    for row in promoted_rows:
        finding_slug = str(row["finding_slug"])
        verification_status = str(row["verification_status"] or "missing")
        blockers.append(
            {
                "code": "promoted_finding_unverified",
                "message": (
                    f"Promoted finding {finding_slug} is {verification_status}."
                ),
                "object_type": "finding",
                "object_id": finding_slug,
                "action": (
                    "complete independent verification as confirmed, downgraded, "
                    "or false positive"
                ),
            }
        )
    for health, count in effective_proof_health.items():
        if health != "healthy" and count:
            blockers.append(
                {
                    "code": f"proof_{health}",
                    "message": f"{count} proof receipt(s) are {health}.",
                    "object_type": "proof_receipts",
                    "object_id": run_id,
                    "action": "restore or replace the proof before completion",
                }
            )
    return blockers


def _serialize_run(
    connection: sqlite3.Connection, row: sqlite3.Row | dict[str, Any]
) -> dict[str, Any]:
    record = dict(row)
    run_id = int(record["id"])
    engagement_id = int(record["engagement_id"])
    record["target_identity"] = _json_value(record.pop("target_identity_json", "{}"), {})
    record["source_generations"] = _json_value(record.pop("source_generations_json", "[]"), [])
    record["exclusions"] = _json_value(record.pop("exclusions_json", "[]"), [])
    seal_json = record.pop("seal_json", None)
    record["seal"] = _json_value(seal_json, None)
    record["instructions_stale"] = (
        bool(record["instructions_stale"])
        if record.get("instructions_stale") is not None
        else None
    )
    record["counts"] = _run_counts(connection, engagement_id, run_id)
    record["proof_health"] = _evidence_health_counts(connection, engagement_id, run_id)
    record["blockers"] = _current_blockers(connection, row)
    record["lifecycle_history"] = [
        dict(event)
        for event in connection.execute(
            """
            SELECT id, from_status, to_status, reason, created_at
            FROM assessment_run_lifecycle_events
            WHERE engagement_id = ? AND run_id = ? ORDER BY id
            """,
            (engagement_id, run_id),
        ).fetchall()
    ]
    lineage_ids = _run_lineage_ids(connection, run_id)
    lineage_placeholders = ",".join("?" for _ in lineage_ids)
    record["finding_slugs"] = [
        str(finding["slug"])
        for finding in connection.execute(
            f"""
            SELECT DISTINCT findings.slug
            FROM assessment_findings AS findings
            JOIN assessment_finding_proof_receipts AS links ON links.finding_id = findings.id
            JOIN assessment_proof_receipts AS receipts ON receipts.id = links.proof_receipt_id
            WHERE findings.engagement_id = ?
              AND receipts.run_id IN ({lineage_placeholders})
            ORDER BY findings.slug
            """,
            (engagement_id, *lineage_ids),
        ).fetchall()
    ]
    warnings: list[str] = []
    if str(record.get("actual_model") or "unknown") == "unknown":
        warnings.append("provider-observed model identity is unknown")
    if record.get("launcher_effective_model") is None:
        warnings.append("launcher-effective model identity is unknown")
    if record.get("instructions_stale"):
        warnings.append("installed instructions were stale at dispatch time")
    record["warnings"] = warnings
    record["observed_cost"] = None
    if record.get("started_at") and record.get("finished_at"):
        try:
            from datetime import datetime

            started = datetime.fromisoformat(str(record["started_at"]).replace("Z", "+00:00"))
            finished = datetime.fromisoformat(str(record["finished_at"]).replace("Z", "+00:00"))
            record["elapsed_seconds"] = max(0.0, (finished - started).total_seconds())
        except ValueError:
            record["elapsed_seconds"] = None
    else:
        record["elapsed_seconds"] = None
    return record


_RESUME_REASON = "resumed from terminal run"
_RESUME_PROOF_REPLACEMENT_REASON = (
    "resumed from terminal run with proof requiring replacement"
)


def _partition_inherited_receipts(
    health_by_id: dict[int, str], receipt_ids: Iterable[int]
) -> tuple[list[int], list[int]]:
    """Split bound receipts into the ones a resumed run inherits and the rest.

    An id with no health row lands in the dropped half: the receipt it named is
    not readable from this engagement, so the child cannot stand behind it.
    """

    inherited: list[int] = []
    dropped: list[int] = []
    for receipt_id in receipt_ids:
        bucket = inherited if health_by_id.get(receipt_id) == "healthy" else dropped
        bucket.append(receipt_id)
    return inherited, dropped


def _resume_reason(dropped_receipt_ids: list[int], origin: str = "") -> str:
    """Return the reason a resumed run records for one copied record.

    A resume never edits its parent, so the child's own event row is the only
    place an operator can read which bindings were dropped and what the parent
    had concluded with them. ``origin`` carries that parent conclusion — the
    finding slug, the resolution text — which the reopened child row no longer
    asserts.
    """

    if not dropped_receipt_ids:
        return _RESUME_REASON
    origin_detail = f" from {origin}" if origin else ""
    return (
        f"{_RESUME_PROOF_REPLACEMENT_REASON}; dropped unhealthy proof receipts "
        f"{dropped_receipt_ids}{origin_detail}"
    )


def create_assessment_run(
    engagement_id: int,
    *,
    run_uuid: str,
    run_kind: str,
    producer_dispatch_agent_id: str,
    run_purpose: str = "proof",
    target_identity: dict[str, Any] | None = None,
    source_generations: list[dict[str, Any]] | None = None,
    exclusions: list[dict[str, Any]] | None = None,
    resumed_from_run_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    run_uuid = str(run_uuid or "").strip()
    if not run_uuid:
        raise HTTPException(status_code=400, detail="run_uuid is required")
    run_kind = str(run_kind or "").strip().lower()
    run_purpose = str(run_purpose or "proof").strip().lower()
    if run_kind not in RUN_KINDS:
        raise _invalid("run_kind", run_kind, RUN_KINDS)
    if run_purpose not in RUN_PURPOSES:
        raise _invalid("run_purpose", run_purpose, RUN_PURPOSES)
    target_identity = target_identity or {}
    source_generations = source_generations or []
    exclusions = exclusions or []
    with _common.get_connection() as connection:
        dispatch = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, str(producer_dispatch_agent_id or "").strip()),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(status_code=404, detail="producer dispatch not found")
        if resumed_from_run_id is not None:
            parent = _run_or_404(connection, engagement.id, resumed_from_run_id)
            if str(parent["status"]) not in TERMINAL_RUN_STATUSES:
                raise HTTPException(status_code=409, detail="only a terminal run can be resumed")
            if (
                str(parent["run_kind"]) != run_kind
                or str(parent["run_purpose"]) != run_purpose
            ):
                raise HTTPException(
                    status_code=409,
                    detail="resumed run must preserve its parent's kind and purpose",
                )
            parent_target_identity = _json_value(parent["target_identity_json"], {})
            parent_source_generations = _json_value(
                parent["source_generations_json"], []
            )
            parent_exclusions = _json_value(parent["exclusions_json"], [])
            if (
                (target_identity and target_identity != parent_target_identity)
                or (
                    source_generations
                    and source_generations != parent_source_generations
                )
                or (exclusions and exclusions != parent_exclusions)
            ):
                raise HTTPException(
                    status_code=409,
                    detail="resumed run must preserve its parent's identity",
                )
            target_identity = parent_target_identity
            source_generations = parent_source_generations
            exclusions = parent_exclusions
        existing = _assessment_run_row(connection, engagement.id, run_uuid=run_uuid)
        identity = {
            "run_kind": run_kind,
            "run_purpose": run_purpose,
            "producer_dispatch_id": int(dispatch["id"]),
            "target_identity_json": _json_text(target_identity),
            "source_generations_json": _json_text(source_generations),
            "exclusions_json": _json_text(exclusions),
            "resumed_from_run_id": resumed_from_run_id,
        }
        if existing is not None:
            if any(existing[key] != value for key, value in identity.items()):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="run_uuid already belongs to different run identity",
                )
            return _serialize_run(connection, existing)
        initial_status = "queued" if run_purpose == "scan" else "running"
        cursor = connection.execute(
            """
            INSERT INTO assessment_runs (
                engagement_id, run_uuid, run_kind, run_purpose,
                producer_dispatch_id, status, target_identity_json,
                source_generations_json, exclusions_json, resumed_from_run_id,
                started_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      CASE WHEN ? = 'running' THEN CURRENT_TIMESTAMP END)
            """,
            (
                engagement.id,
                run_uuid,
                run_kind,
                run_purpose,
                int(dispatch["id"]),
                initial_status,
                identity["target_identity_json"],
                identity["source_generations_json"],
                identity["exclusions_json"],
                resumed_from_run_id,
                initial_status,
            ),
        )
        run_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO assessment_run_lifecycle_events (
                engagement_id, run_id, from_status, to_status, reason
            ) VALUES (?, ?, NULL, ?, ?)
            """,
            (
                engagement.id,
                run_id,
                initial_status,
                _RESUME_REASON if resumed_from_run_id is not None else "created",
            ),
        )
        relevant_repositories = target_identity.get("security_relevant_repositories", [])
        if relevant_repositories:
            if (
                not isinstance(relevant_repositories, list)
                or any(
                    not isinstance(value, str) or not value.strip()
                    for value in relevant_repositories
                )
                or relevant_repositories
                != sorted(set(value.strip() for value in relevant_repositories))
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "target_identity.security_relevant_repositories must be a "
                        "sorted unique list of nonempty repository identities"
                    ),
                )
            generation_targets = {
                str(generation.get("target_key") or "").strip()
                for generation in source_generations
                if isinstance(generation, dict)
            }
            for repository in relevant_repositories if resumed_from_run_id is None else []:
                if repository in generation_targets:
                    continue
                _insert_obligation(
                    connection,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    identity_key=f"missing_dependency:repository:{repository}",
                    obligation_kind="missing_dependency",
                    object_type="repository",
                    object_key=repository,
                    hard=True,
                    status_value="open",
                    resolution="",
                    proof_receipt_ids=[],
                )
        if resumed_from_run_id is not None:
            source_id_map: dict[int, int] = {}
            for source in connection.execute(
                "SELECT * FROM assessment_run_sources WHERE run_id = ? ORDER BY id",
                (resumed_from_run_id,),
            ).fetchall():
                copied = connection.execute(
                    """
                    INSERT INTO assessment_run_sources (
                        engagement_id, run_id, target_key, declared_root, path,
                        content_sha256, byte_size, line_count, encoding,
                        inventory_status, exclusion_reason, parser_status,
                        parser_error, identity_sha256, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        source["target_key"],
                        source["declared_root"],
                        source["path"],
                        source["content_sha256"],
                        source["byte_size"],
                        source["line_count"],
                        source["encoding"],
                        source["inventory_status"],
                        source["exclusion_reason"],
                        source["parser_status"],
                        source["parser_error"],
                        source["identity_sha256"],
                        source["created_at"],
                    ),
                )
                source_id_map[int(source["id"])] = int(copied.lastrowid)
            source_reads = connection.execute(
                "SELECT * FROM assessment_run_source_reads WHERE run_id = ? ORDER BY id",
                (resumed_from_run_id,),
            ).fetchall()
            obligations = connection.execute(
                "SELECT * FROM assessment_run_obligations WHERE run_id = ? ORDER BY id",
                (resumed_from_run_id,),
            ).fetchall()
            candidates = connection.execute(
                "SELECT * FROM assessment_run_candidates WHERE run_id = ? ORDER BY id",
                (resumed_from_run_id,),
            ).fetchall()
            # One recovery rule for every copied binding: a resumed run inherits
            # only proof that is still healthy at resume time. Anything else
            # would follow the parent's receipt into the child's effective proof
            # set, raise a proof_* blocker the child cannot clear, and hold the
            # run at partial forever — the parent's rows are sealed and the
            # child's copy of a closed disposition is immutable.
            inherited_health = _receipt_health_by_id(
                connection,
                engagement.id,
                [
                    *(
                        int(read["proof_receipt_id"])
                        for read in source_reads
                        if read["proof_receipt_id"] is not None
                    ),
                    *(
                        receipt_id
                        for row in (*obligations, *candidates)
                        for receipt_id in _stored_receipt_ids(
                            row["proof_receipt_ids_json"]
                        )
                    ),
                ],
            )
            dropped_source_read_receipt_ids: list[int] = []
            copied_read_fingerprints: set[str] = set()
            for source_read in source_reads:
                copied_source_id = source_id_map[int(source_read["source_id"])]
                parent_receipt_id = source_read["proof_receipt_id"]
                _, dropped_receipt_ids = _partition_inherited_receipts(
                    inherited_health,
                    [] if parent_receipt_id is None else [int(parent_receipt_id)],
                )
                dropped_source_read_receipt_ids.extend(dropped_receipt_ids)
                # A read's observed byte coverage stands on its own — nothing in
                # the ledger derives coverage from the receipt — so the read is
                # copied intact and only loses the proof pointer. Re-recording
                # the same range against fresh proof yields a new fingerprint,
                # so the child can rebind without colliding with this row.
                copied_receipt_id = None if dropped_receipt_ids else parent_receipt_id
                read_fingerprint = _sha256(
                    {
                        "source_id": copied_source_id,
                        "source_sha256": connection.execute(
                            "SELECT content_sha256 FROM assessment_run_sources WHERE id = ?",
                            (copied_source_id,),
                        ).fetchone()[0],
                        "dispatch_id": int(source_read["dispatch_id"]),
                        "attempt": int(source_read["attempt"]),
                        "byte_start": int(source_read["byte_start"]),
                        "byte_end": int(source_read["byte_end"]),
                        "line_start": int(source_read["line_start"]),
                        "line_end": int(source_read["line_end"]),
                        "proof_receipt_id": copied_receipt_id,
                    }
                )
                # Two parent rows over the same range that differed ONLY by proof
                # binding become one row once both bindings are dropped, and the
                # (run_id, read_fingerprint) unique index would abort the whole
                # resume on the second insert. Collapse them the way the write
                # path already does — it returns the existing row for a repeated
                # fingerprint rather than adding a second — since the surviving
                # row asserts exactly the same observed bytes. The receipts they
                # carried are named in the lifecycle event written below, so the
                # collapse loses no lineage.
                if read_fingerprint in copied_read_fingerprints:
                    continue
                copied_read_fingerprints.add(read_fingerprint)
                connection.execute(
                    """
                    INSERT INTO assessment_run_source_reads (
                        engagement_id, run_id, source_id, dispatch_id, attempt,
                        byte_start, byte_end, line_start, line_end,
                        proof_receipt_id, read_fingerprint, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        copied_source_id,
                        source_read["dispatch_id"],
                        source_read["attempt"],
                        source_read["byte_start"],
                        source_read["byte_end"],
                        source_read["line_start"],
                        source_read["line_end"],
                        copied_receipt_id,
                        read_fingerprint,
                        source_read["created_at"],
                    ),
                )
            if dropped_source_read_receipt_ids:
                # Source reads have no per-row event table, so the run's own
                # lifecycle history carries the drop; it is returned on every
                # run read, so the resuming agent sees it without a second call.
                connection.execute(
                    """
                    INSERT INTO assessment_run_lifecycle_events (
                        engagement_id, run_id, from_status, to_status, reason
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        initial_status,
                        initial_status,
                        _resume_reason(
                            dropped_source_read_receipt_ids,
                            "parent source-read proof bindings",
                        ),
                    ),
                )
            for obligation in obligations:
                obligation_kind = str(obligation["obligation_kind"])
                identity_key = str(obligation["identity_key"])
                if obligation_kind in {
                    "source_read",
                    "manual_enumeration",
                    "missing_dependency",
                }:
                    prefix = f"{obligation_kind}:"
                    suffix = identity_key.removeprefix(prefix)
                    if identity_key.startswith(prefix) and suffix.isdigit():
                        mapped_source_id = source_id_map.get(int(suffix))
                        if mapped_source_id is not None:
                            identity_key = f"{prefix}{mapped_source_id}"
                parent_status = str(obligation["status"])
                parent_resolution = str(obligation["resolution"])
                parent_receipt_ids = _stored_receipt_ids(
                    obligation["proof_receipt_ids_json"]
                )
                copied_receipt_ids, dropped_receipt_ids = _partition_inherited_receipts(
                    inherited_health, parent_receipt_ids
                )
                # A closed obligation is immutable, so a child that inherits one
                # whose evidence has decayed can never re-resolve it. Reopening
                # returns it to the one status an agent can still move, and its
                # unevidenced resolution text is retired with the proof it rested on.
                requires_new_proof = bool(dropped_receipt_ids) and parent_status in {
                    "resolved",
                    "accepted_gap",
                }
                copied_status = "open" if requires_new_proof else parent_status
                copied_resolution = "" if requires_new_proof else parent_resolution
                obligation_record_sha256 = _sha256(
                    {
                        "identity_key": identity_key,
                        "obligation_kind": obligation_kind,
                        "object_type": str(obligation["object_type"]),
                        "object_key": str(obligation["object_key"]),
                        "hard": bool(obligation["hard"]),
                        "status": copied_status,
                        "resolution": copied_resolution,
                        "proof_receipt_ids": copied_receipt_ids,
                    }
                )
                copied = connection.execute(
                    """
                    INSERT INTO assessment_run_obligations (
                        engagement_id, run_id, identity_key, obligation_kind,
                        object_type, object_key, hard, status, resolution,
                        proof_receipt_ids_json, record_sha256, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        identity_key,
                        obligation_kind,
                        obligation["object_type"],
                        obligation["object_key"],
                        obligation["hard"],
                        copied_status,
                        copied_resolution,
                        _json_text(copied_receipt_ids),
                        obligation_record_sha256,
                        obligation["created_at"],
                        obligation["updated_at"],
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO assessment_run_obligation_events (
                        engagement_id, run_id, obligation_id, from_status,
                        to_status, resolution, proof_receipt_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        int(copied.lastrowid),
                        parent_status,
                        copied_status,
                        _resume_reason(
                            dropped_receipt_ids,
                            f"parent status={parent_status!r} "
                            f"resolution={parent_resolution!r}",
                        ),
                        _json_text(parent_receipt_ids),
                    ),
                )
            for candidate in candidates:
                copied_source_id = (
                    source_id_map[int(candidate["source_id"])]
                    if candidate["source_id"] is not None
                    else None
                )
                parent_state = str(candidate["state"])
                parent_finding_slug = str(candidate["finding_slug"])
                parent_receipt_ids = _stored_receipt_ids(
                    candidate["proof_receipt_ids_json"]
                )
                copied_receipt_ids, dropped_receipt_ids = _partition_inherited_receipts(
                    inherited_health, parent_receipt_ids
                )
                # Same rule as obligations: a terminal candidate state is
                # immutable, so an inherited disposition whose proof decayed has
                # to reopen or the child can never dispose of it again. The
                # promoted finding slug is retired with it and named in the
                # event, so the child still has the pointer to re-work from.
                requires_new_proof = bool(dropped_receipt_ids) and parent_state in {
                    "promoted",
                    "rejected",
                    "duplicate",
                }
                copied_state = "open" if requires_new_proof else parent_state
                copied_finding_slug = "" if requires_new_proof else parent_finding_slug
                copied_record_sha256 = _sha256(
                    {
                        "identity_key": str(candidate["identity_key"]),
                        "target_key": str(candidate["target_key"]),
                        "source_id": copied_source_id,
                        "source_anchor": str(candidate["source_anchor"]),
                        "vulnerability_family": str(candidate["vulnerability_family"]),
                        "hypothesis": str(candidate["hypothesis"]),
                        "originating_result_id": candidate["originating_result_id"],
                        "originating_signal_id": candidate["originating_signal_id"],
                        "dispatch_id": int(candidate["dispatch_id"]),
                        "proof_receipt_ids": copied_receipt_ids,
                        "state": copied_state,
                        "finding_slug": copied_finding_slug,
                    }
                )
                copied = connection.execute(
                    """
                    INSERT INTO assessment_run_candidates (
                        engagement_id, run_id, identity_key, target_key, source_id,
                        source_anchor, vulnerability_family, hypothesis,
                        originating_result_id, originating_signal_id, dispatch_id,
                        proof_receipt_ids_json,
                        state, finding_slug, record_sha256, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        candidate["identity_key"],
                        candidate["target_key"],
                        copied_source_id,
                        candidate["source_anchor"],
                        candidate["vulnerability_family"],
                        candidate["hypothesis"],
                        candidate["originating_result_id"],
                        candidate["originating_signal_id"],
                        candidate["dispatch_id"],
                        _json_text(copied_receipt_ids),
                        copied_state,
                        copied_finding_slug,
                        copied_record_sha256,
                        candidate["created_at"],
                        candidate["updated_at"],
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO assessment_run_candidate_events (
                        engagement_id, run_id, candidate_id, from_state, to_state,
                        reason, proof_receipt_ids_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement.id,
                        run_id,
                        int(copied.lastrowid),
                        parent_state,
                        copied_state,
                        _resume_reason(
                            dropped_receipt_ids,
                            f"parent state={parent_state!r} "
                            f"finding_slug={parent_finding_slug!r}",
                        ),
                        _json_text(parent_receipt_ids),
                    ),
                )
        row = _run_or_404(connection, engagement.id, run_id)
        return _serialize_run(connection, row)


def list_assessment_runs(
    engagement_id: int, *, limit: int = 100, offset: int = 0
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT runs.*,
                   dispatches.agent_id AS producer_dispatch_agent_id,
                   dispatches.agent_role AS producer_dispatch_agent_role,
                   dispatches.requested_model, dispatches.actual_model,
                   dispatches.requested_reasoning, dispatches.actual_reasoning,
                   dispatches.launcher_effective_model,
                   dispatches.launcher_effective_reasoning,
                   dispatches.launcher_effective_source,
                   dispatches.client_name, dispatches.requested_client,
                   dispatches.launcher_effective_client,
                   dispatches.provider_observed_client,
                   dispatches.source_revision,
                   dispatches.operator_instruction_path,
                   dispatches.operator_instruction_sha256,
                   dispatches.specialist_instruction_path,
                   dispatches.specialist_instruction_sha256,
                   dispatches.instruction_identity_status,
                   dispatches.instructions_stale
            FROM assessment_runs AS runs
            JOIN assessment_dispatches AS dispatches ON dispatches.id = runs.producer_dispatch_id
            WHERE runs.engagement_id = ?
            ORDER BY runs.created_at DESC, runs.id DESC LIMIT ? OFFSET ?
            """,
            (engagement.id, limit, offset),
        ).fetchall()
        return [_serialize_run(connection, row) for row in rows]


def get_assessment_run(engagement_id: int, run_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _serialize_run(connection, _run_or_404(connection, engagement.id, run_id))


def transition_assessment_run(
    engagement_id: int, *, run_id: int, status_value: str, reason: str = ""
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    requested = str(status_value or "").strip().lower()
    if requested not in RUN_STATUSES - {"queued"}:
        raise _invalid("run status", requested, RUN_STATUSES - {"queued"})
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        current = str(run["status"])
        if current == requested:
            return _serialize_run(connection, run)
        if current in TERMINAL_RUN_STATUSES:
            seal = _json_value(run["seal_json"], {})
            if str(seal.get("requested_status") or "") == requested:
                return _serialize_run(connection, run)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"assessment run id={run_id} is sealed with status={current!r}",
            )
        if current == "queued" and requested not in {"running", "failed", "interrupted", "canceled"}:
            raise HTTPException(status_code=409, detail="queued run must start before completion")

        effective = requested
        seal: dict[str, Any] | None = None
        seal_sha256 = ""
        blockers: list[dict[str, Any]] = []
        if requested in TERMINAL_RUN_STATUSES:
            blockers = _current_blockers(connection, run)
            if requested == "completed" and blockers:
                effective = "partial"
        lifecycle_cursor = connection.execute(
            """
            INSERT INTO assessment_run_lifecycle_events (
                engagement_id, run_id, from_status, to_status, reason
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (engagement.id, run_id, current, effective, str(reason or "")),
        )
        lifecycle_event = connection.execute(
            """
            SELECT id, from_status, to_status, reason, created_at
            FROM assessment_run_lifecycle_events WHERE id = ?
            """,
            (int(lifecycle_cursor.lastrowid),),
        ).fetchone()
        assert lifecycle_event is not None
        transition_at = str(lifecycle_event["created_at"])
        if requested in TERMINAL_RUN_STATUSES:
            counts = _run_counts(connection, engagement.id, run_id)
            lifecycle_history = [
                dict(event)
                for event in connection.execute(
                    """
                    SELECT id, from_status, to_status, reason, created_at
                    FROM assessment_run_lifecycle_events
                    WHERE run_id = ? ORDER BY id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            obligation_identity = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT identity_key, obligation_kind, object_type, object_key,
                           hard, status, resolution, proof_receipt_ids_json
                    FROM assessment_run_obligations WHERE run_id = ? ORDER BY identity_key
                    """,
                    (run_id,),
                ).fetchall()
            ]
            candidate_identity = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT identity_key, target_key, source_anchor,
                           vulnerability_family, state, finding_slug,
                           proof_receipt_ids_json
                    FROM assessment_run_candidates WHERE run_id = ? ORDER BY identity_key
                    """,
                    (run_id,),
                ).fetchall()
            ]
            seal = {
                "version": "v1",
                "run_uuid": str(run["run_uuid"]),
                "run_kind": str(run["run_kind"]),
                "run_purpose": str(run["run_purpose"]),
                "requested_status": requested,
                "effective_status": effective,
                "target_identity": _json_value(run["target_identity_json"], {}),
                "source_generations": _json_value(run["source_generations_json"], []),
                "exclusions": _json_value(run["exclusions_json"], []),
                "dispatch_provenance": _dispatch_provenance(run),
                "inventory_digest": _sha256(_inventory_identity(connection, run_id)),
                "obligation_digest": _sha256(obligation_identity),
                "candidate_digest": _sha256(candidate_identity),
                "counts": counts,
                "proof_health": _evidence_health_counts(connection, engagement.id, run_id),
                "blockers": blockers,
                "lifecycle_history": lifecycle_history,
            }
            seal_sha256 = _sha256(seal)
        cursor = connection.execute(
            """
            UPDATE assessment_runs
            SET status = ?,
                started_at = CASE
                    WHEN ? = 'running' THEN COALESCE(started_at, ?)
                    ELSE started_at END,
                finished_at = CASE WHEN ? IN ('partial', 'completed', 'failed', 'interrupted', 'canceled')
                    THEN ? ELSE NULL END,
                seal_json = ?, seal_sha256 = ?, updated_at = ?
            WHERE engagement_id = ? AND id = ? AND status = ?
            """,
            (
                effective,
                effective,
                transition_at,
                effective,
                transition_at,
                _json_text(seal) if seal is not None else None,
                seal_sha256,
                transition_at,
                engagement.id,
                run_id,
                current,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=409,
                detail="assessment run changed concurrently; inspect durable state",
            )
        if effective in TERMINAL_RUN_STATUSES and str(run["run_purpose"]) == "scan":
            baseline = _latest_comparison_baseline(
                connection,
                engagement_id=engagement.id,
                run_id=run_id,
                run_kind=str(run["run_kind"]),
                run_purpose=str(run["run_purpose"]),
                target_identity_json=str(run["target_identity_json"]),
            )
            if baseline is not None:
                _record_comparison(
                    connection,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    baseline_run_id=int(baseline["id"]),
                    selection="automatic",
                )
        return _serialize_run(connection, _run_or_404(connection, engagement.id, run_id))


from .run_inventory import (  # noqa: E402
    _insert_obligation,
    list_obligation_history as list_obligation_history,
    list_run_dispatches as list_run_dispatches,
    list_run_obligations as list_run_obligations,
    list_run_sources as list_run_sources,
    list_source_reads as list_source_reads,
    record_run_obligation as record_run_obligation,
    record_run_sources as record_run_sources,
    record_source_read as record_source_read,
    update_run_obligation as update_run_obligation,
)


def _serialize_candidate(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    record["proof_receipt_ids"] = _json_value(record.pop("proof_receipt_ids_json"), [])
    return record


def _exact_run_source_generation(
    run: sqlite3.Row, *, target_key: str
) -> dict[str, Any]:
    matches = [
        generation
        for generation in _json_value(run["source_generations_json"], [])
        if isinstance(generation, dict)
        and str(generation.get("target_key") or "") == target_key
    ]
    if len(matches) != 1:
        raise HTTPException(
            status_code=409,
            detail="run does not declare one exact source generation for the target",
        )
    return matches[0]


def _require_code_result_source_identity(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run: sqlite3.Row,
    source: sqlite3.Row,
    originating_result_id: int,
    target_key: str,
) -> None:
    result = connection.execute(
        """
        SELECT results.id, results.repo_generation, files.file_path,
               files.file_hash, repos.repo_key, repos.active_generation,
               repos.source_manifest_digest
        FROM code_analysis_results AS results
        JOIN code_files AS files
          ON files.engagement_id = results.engagement_id
         AND files.id = results.file_id
        JOIN code_repos AS repos
          ON repos.engagement_id = files.engagement_id
         AND repos.id = files.repo_id
        WHERE results.engagement_id = ? AND results.id = ?
        """,
        (engagement_id, originating_result_id),
    ).fetchone()
    if result is None:
        raise HTTPException(status_code=404, detail="originating analysis result not found")
    source_generation = _exact_run_source_generation(run, target_key=target_key)
    exact_identity = (
        str(source["target_key"]) == target_key
        and str(source["path"]) == str(result["file_path"])
        and str(source["content_sha256"]) == str(result["file_hash"])
        and str(result["repo_key"]) == target_key
        and int(result["repo_generation"]) == int(result["active_generation"])
        and int(source_generation.get("generation", -1))
        == int(result["repo_generation"])
        and str(source_generation.get("manifest_digest") or "")
        == str(result["source_manifest_digest"])
    )
    if not exact_identity:
        raise HTTPException(
            status_code=409,
            detail=(
                "originating analysis result does not match the exact run source "
                "path, content, and repository generation"
            ),
        )


def record_run_candidate(
    engagement_id: int,
    *,
    run_id: int,
    identity_key: str,
    target_key: str,
    source_id: int | None,
    source_anchor: str,
    vulnerability_family: str,
    hypothesis: str,
    originating_result_id: int | None,
    dispatch_agent_id: str,
    proof_receipt_ids: list[int],
    state_value: str,
    finding_slug: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if state_value not in CANDIDATE_STATES:
        raise _invalid("candidate state", state_value, CANDIDATE_STATES)
    if state_value != "open":
        raise HTTPException(
            status_code=400,
            detail="new candidates must start open; use a transition to change their state",
        )
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="candidate writes")
        dispatch = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, dispatch_agent_id),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(status_code=404, detail="candidate dispatch not found")
        source = None
        if source_id is not None:
            source = connection.execute(
                """
                SELECT id, target_key, path, content_sha256
                FROM assessment_run_sources
                WHERE engagement_id = ? AND run_id = ? AND id = ?
                """,
                (engagement.id, run_id, source_id),
            ).fetchone()
            if source is None:
                raise HTTPException(status_code=404, detail="candidate source not found")
        if originating_result_id is not None:
            if source is None:
                raise HTTPException(
                    status_code=400,
                    detail="originating analysis results require an exact run source",
                )
            _require_code_result_source_identity(
                connection,
                engagement_id=engagement.id,
                run=run,
                source=source,
                originating_result_id=originating_result_id,
                target_key=target_key,
            )
        receipt_ids = _validate_receipt_ids(connection, engagement.id, run_id, proof_receipt_ids)
        record = {
            "identity_key": identity_key,
            "target_key": target_key,
            "source_id": source_id,
            "source_anchor": source_anchor,
            "vulnerability_family": vulnerability_family,
            "hypothesis": hypothesis,
            "originating_result_id": originating_result_id,
            "dispatch_id": int(dispatch["id"]),
            "proof_receipt_ids": receipt_ids,
            "state": state_value,
            "finding_slug": finding_slug,
        }
        record_sha256 = _sha256(record)
        existing = connection.execute(
            "SELECT * FROM assessment_run_candidates WHERE run_id = ? AND identity_key = ?",
            (run_id, identity_key),
        ).fetchone()
        if existing is not None:
            if str(existing["record_sha256"]) != record_sha256:
                raise HTTPException(status_code=409, detail="candidate identity already has different content")
            return _serialize_candidate(existing)
        cursor = connection.execute(
            """
            INSERT INTO assessment_run_candidates (
                engagement_id, run_id, identity_key, target_key, source_id,
                source_anchor, vulnerability_family, hypothesis,
                originating_result_id, dispatch_id, proof_receipt_ids_json,
                state, finding_slug, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                run_id,
                identity_key,
                target_key,
                source_id,
                source_anchor,
                vulnerability_family,
                hypothesis,
                originating_result_id,
                int(dispatch["id"]),
                _json_text(receipt_ids),
                state_value,
                finding_slug,
                record_sha256,
            ),
        )
        candidate_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO assessment_run_candidate_events (
                engagement_id, run_id, candidate_id, from_state, to_state,
                reason, proof_receipt_ids_json
            ) VALUES (?, ?, ?, NULL, ?, 'created', ?)
            """,
            (engagement.id, run_id, candidate_id, state_value, _json_text(receipt_ids)),
        )
        row = connection.execute(
            "SELECT * FROM assessment_run_candidates WHERE id = ?", (candidate_id,)
        ).fetchone()
        assert row is not None
        return _serialize_candidate(row)


def _analysis_result_candidate_identity(
    *,
    target_key: str,
    source_path: str,
    source_sha256: str,
    source_anchor: str,
    result_identity_fingerprint: str,
) -> str:
    return "candidate:v1:" + _sha256(
        {
            "target_key": target_key,
            "source_path": source_path,
            "source_sha256": source_sha256,
            "source_anchor": source_anchor,
            "result_fingerprint": result_identity_fingerprint,
        }
    )


def record_analysis_result_candidate_with_connection(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    source_id: int,
    result_id: int,
    result_identity_fingerprint: str,
    dispatch_agent_id: str,
    target_key: str,
    source_path: str,
    source_sha256: str,
    repo_generation: int,
    source_manifest_digest: str,
    source_anchor: str,
    vulnerability_family: str,
    hypothesis: str,
) -> dict[str, Any]:
    """Create the candidate for one suspicious analysis result in its transaction."""

    run = _run_or_404(connection, engagement_id, run_id)
    _require_active_run(run, operation="analysis-result candidate creation")
    source = connection.execute(
        """
        SELECT target_key, path, content_sha256 FROM assessment_run_sources
        WHERE engagement_id = ? AND run_id = ? AND id = ?
        """,
        (engagement_id, run_id, source_id),
    ).fetchone()
    if source is None:
        raise HTTPException(status_code=404, detail="analysis candidate source not found")
    run_generation = _exact_run_source_generation(run, target_key=target_key)
    if (
        str(source["target_key"]) != target_key
        or str(source["path"]) != source_path
        or str(source["content_sha256"]) != source_sha256
        or int(run_generation.get("generation", -1)) != repo_generation
        or str(run_generation.get("manifest_digest") or "")
        != source_manifest_digest
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "analysis candidate does not match its exact run source path, "
                "content, and repository generation"
            ),
        )
    dispatch = connection.execute(
        "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
        (engagement_id, dispatch_agent_id),
    ).fetchone()
    if dispatch is None:
        raise HTTPException(status_code=404, detail="analysis candidate dispatch not found")
    identity_key = _analysis_result_candidate_identity(
        target_key=target_key,
        source_path=source_path,
        source_sha256=source_sha256,
        source_anchor=source_anchor,
        result_identity_fingerprint=result_identity_fingerprint,
    )
    existing = connection.execute(
        """
        SELECT * FROM assessment_run_candidates
        WHERE engagement_id = ? AND run_id = ? AND identity_key = ?
        """,
        (engagement_id, run_id, identity_key),
    ).fetchone()
    if existing is not None:
        return _serialize_candidate(existing)
    record = {
        "identity_key": identity_key,
        "target_key": target_key,
        "source_id": source_id,
        "source_anchor": source_anchor,
        "vulnerability_family": vulnerability_family,
        "hypothesis": hypothesis,
        "originating_result_id": result_id,
        "originating_signal_id": None,
        "dispatch_id": int(dispatch["id"]),
        "proof_receipt_ids": [],
        "state": "open",
        "finding_slug": "",
    }
    cursor = connection.execute(
        """
        INSERT INTO assessment_run_candidates (
            engagement_id, run_id, identity_key, target_key, source_id,
            source_anchor, vulnerability_family, hypothesis,
            originating_result_id, originating_signal_id, dispatch_id,
            proof_receipt_ids_json, state, finding_slug, record_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, '[]', 'open', '', ?)
        """,
        (
            engagement_id,
            run_id,
            identity_key,
            target_key,
            source_id,
            source_anchor,
            vulnerability_family,
            hypothesis,
            result_id,
            int(dispatch["id"]),
            _sha256(record),
        ),
    )
    candidate_id = int(cursor.lastrowid)
    connection.execute(
        """
        INSERT INTO assessment_run_candidate_events (
            engagement_id, run_id, candidate_id, from_state, to_state,
            reason, proof_receipt_ids_json
        ) VALUES (?, ?, ?, NULL, 'open', 'created from suspicious analysis result', '[]')
        """,
        (engagement_id, run_id, candidate_id),
    )
    row = connection.execute(
        "SELECT * FROM assessment_run_candidates WHERE id = ?", (candidate_id,)
    ).fetchone()
    assert row is not None
    return _serialize_candidate(row)


def list_run_candidates(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_candidates",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_candidate(row) for row in page["items"]]
        return page


def _finding_file_path(canonical_location: str) -> str | None:
    location = canonical_location.strip()
    if not location.startswith("file:"):
        return None
    segments = location[len("file:") :].lstrip("/").split(":")
    while len(segments) > 1 and segments[-1].isdigit():
        segments.pop()
    return ":".join(segments)


def _target_identity_strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return set().union(*(_target_identity_strings(item) for item in value))
    if isinstance(value, dict):
        return set().union(*(_target_identity_strings(item) for item in value.values()))
    return set()


def _require_candidate_finding_identity(
    connection: sqlite3.Connection,
    *,
    run: sqlite3.Row,
    candidate: sqlite3.Row,
    finding: sqlite3.Row,
) -> None:
    target_key = str(candidate["target_key"])
    canonical_location = str(finding["canonical_location"])
    if str(run["run_kind"]) == "code":
        if candidate["source_id"] is None:
            raise HTTPException(
                status_code=409,
                detail="code candidate promotion requires an exact run source",
            )
        source = connection.execute(
            """
            SELECT target_key, path FROM assessment_run_sources
            WHERE engagement_id = ? AND run_id = ? AND id = ?
            """,
            (int(run["engagement_id"]), int(run["id"]), int(candidate["source_id"])),
        ).fetchone()
        provenance = _json_value(finding["provenance_json"], {})
        binding = provenance.get("code_snapshot") if isinstance(provenance, dict) else None
        if not isinstance(binding, dict):
            raise HTTPException(
                status_code=409,
                detail="code candidate finding requires exact code snapshot provenance",
            )
        repository = connection.execute(
            """
            SELECT repo_key FROM code_repos
            WHERE engagement_id = ? AND id = ?
            """,
            (int(run["engagement_id"]), binding.get("repo_id")),
        ).fetchone()
        generation = _exact_run_source_generation(run, target_key=target_key)
        exact = (
            source is not None
            and str(source["target_key"]) == target_key
            and _finding_file_path(canonical_location) == str(source["path"])
            and repository is not None
            and str(repository["repo_key"]) == target_key
            and binding.get("repo_generation") == generation.get("generation")
            and binding.get("source_manifest_digest")
            == generation.get("manifest_digest")
        )
        if not exact:
            raise HTTPException(
                status_code=409,
                detail=(
                    "code candidate and finding do not share the exact source path "
                    "and repository generation"
                ),
            )
        return

    declared_targets = _target_identity_strings(
        _json_value(run["target_identity_json"], {})
    )
    parsed = urlsplit(canonical_location)
    location_matches = canonical_location == target_key or (
        parsed.hostname is not None and parsed.hostname == target_key
    )
    if target_key not in declared_targets or not location_matches:
        raise HTTPException(
            status_code=409,
            detail="candidate and finding do not share the run's exact target identity",
        )


def promote_run_candidate_with_connection(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    candidate_id: int,
    finding_slug: str,
    reason: str,
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    """Link one candidate to a finding inside the finding writer's transaction."""

    run = _run_or_404(connection, engagement_id, run_id)
    _require_active_run(run, operation="candidate promotion")
    existing = connection.execute(
        """
        SELECT * FROM assessment_run_candidates
        WHERE engagement_id = ? AND run_id = ? AND id = ?
        """,
        (engagement_id, run_id, candidate_id),
    ).fetchone()
    if existing is None:
        raise HTTPException(status_code=404, detail="run candidate not found")
    receipt_ids = _validate_receipt_ids(
        connection, engagement_id, run_id, proof_receipt_ids
    )
    if not reason.strip() or not receipt_ids:
        raise HTTPException(
            status_code=400,
            detail="candidate promotion requires a reason and durable proof receipts",
        )
    finding = connection.execute(
        """
        SELECT slug, canonical_location, provenance_json
        FROM assessment_findings WHERE engagement_id = ? AND slug = ?
        """,
        (engagement_id, finding_slug),
    ).fetchone()
    if finding is None:
        raise HTTPException(
            status_code=400, detail="promoted candidate requires an existing finding"
        )
    _require_candidate_finding_identity(
        connection,
        run=run,
        candidate=existing,
        finding=finding,
    )
    current = str(existing["state"])
    if current == "promoted":
        latest_event = connection.execute(
            """
            SELECT reason, proof_receipt_ids_json
            FROM assessment_run_candidate_events
            WHERE engagement_id = ? AND run_id = ? AND candidate_id = ?
            ORDER BY id DESC LIMIT 1
            """,
            (engagement_id, run_id, candidate_id),
        ).fetchone()
        if (
            str(existing["finding_slug"]) == finding_slug
            and latest_event is not None
            and str(latest_event["reason"]) == reason
            and _json_value(latest_event["proof_receipt_ids_json"], [])
            == receipt_ids
        ):
            return _serialize_candidate(existing)
        raise HTTPException(
            status_code=409,
            detail="candidate retry differs from the recorded terminal transition",
        )
    if current not in {"open", "deferred"}:
        raise HTTPException(
            status_code=409, detail="terminal candidate state is immutable"
        )
    record = {
        "identity_key": str(existing["identity_key"]),
        "target_key": str(existing["target_key"]),
        "source_id": existing["source_id"],
        "source_anchor": str(existing["source_anchor"]),
        "vulnerability_family": str(existing["vulnerability_family"]),
        "hypothesis": str(existing["hypothesis"]),
        "originating_result_id": existing["originating_result_id"],
        "originating_signal_id": existing["originating_signal_id"],
        "dispatch_id": int(existing["dispatch_id"]),
        "proof_receipt_ids": receipt_ids,
        "state": "promoted",
        "finding_slug": finding_slug,
    }
    connection.execute(
        """
        UPDATE assessment_run_candidates
        SET state = 'promoted', finding_slug = ?, proof_receipt_ids_json = ?,
            record_sha256 = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (finding_slug, _json_text(receipt_ids), _sha256(record), candidate_id),
    )
    connection.execute(
        """
        INSERT INTO assessment_run_candidate_events (
            engagement_id, run_id, candidate_id, from_state, to_state,
            reason, proof_receipt_ids_json
        ) VALUES (?, ?, ?, ?, 'promoted', ?, ?)
        """,
        (
            engagement_id,
            run_id,
            candidate_id,
            current,
            reason,
            _json_text(receipt_ids),
        ),
    )
    updated = connection.execute(
        "SELECT * FROM assessment_run_candidates WHERE id = ?", (candidate_id,)
    ).fetchone()
    assert updated is not None
    return _serialize_candidate(updated)


def update_run_candidate(
    engagement_id: int,
    *,
    run_id: int,
    candidate_id: int,
    state_value: str,
    reason: str,
    proof_receipt_ids: list[int],
    finding_slug: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if state_value not in CANDIDATE_STATES - {"open"}:
        raise _invalid("candidate state", state_value, CANDIDATE_STATES - {"open"})
    if not reason.strip():
        raise HTTPException(status_code=400, detail="candidate transition requires a reason")
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="candidate updates")
        existing = connection.execute(
            "SELECT * FROM assessment_run_candidates WHERE engagement_id = ? AND run_id = ? AND id = ?",
            (engagement.id, run_id, candidate_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="run candidate not found")
        if state_value == "promoted":
            return promote_run_candidate_with_connection(
                connection,
                engagement_id=engagement.id,
                run_id=run_id,
                candidate_id=candidate_id,
                finding_slug=finding_slug,
                reason=reason,
                proof_receipt_ids=proof_receipt_ids,
            )
        current = str(existing["state"])
        receipt_ids = _validate_receipt_ids(
            connection, engagement.id, run_id, proof_receipt_ids
        )
        if state_value in {"promoted", "rejected", "duplicate"} and not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"candidate state={state_value!r} requires proof receipts; "
                    "free-text reason alone cannot close a candidate"
                ),
            )
        if current == state_value:
            latest_event = connection.execute(
                """
                SELECT reason, proof_receipt_ids_json
                FROM assessment_run_candidate_events
                WHERE engagement_id = ? AND run_id = ? AND candidate_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (engagement.id, run_id, candidate_id),
            ).fetchone()
            if (
                latest_event is not None
                and str(latest_event["reason"]) == reason
                and _json_value(latest_event["proof_receipt_ids_json"], [])
                == receipt_ids
                and str(existing["finding_slug"]) == finding_slug
            ):
                return _serialize_candidate(existing)
            raise HTTPException(
                status_code=409,
                detail="candidate retry differs from the recorded terminal transition",
            )
        if current not in {"open", "deferred"}:
            raise HTTPException(status_code=409, detail="terminal candidate state is immutable")
        record = {
            "identity_key": str(existing["identity_key"]),
            "target_key": str(existing["target_key"]),
            "source_id": existing["source_id"],
            "source_anchor": str(existing["source_anchor"]),
            "vulnerability_family": str(existing["vulnerability_family"]),
            "hypothesis": str(existing["hypothesis"]),
            "originating_result_id": existing["originating_result_id"],
            "originating_signal_id": existing["originating_signal_id"],
            "dispatch_id": int(existing["dispatch_id"]),
            "proof_receipt_ids": receipt_ids,
            "state": state_value,
            "finding_slug": finding_slug,
        }
        connection.execute(
            """
            UPDATE assessment_run_candidates
            SET state = ?, finding_slug = ?, proof_receipt_ids_json = ?,
                record_sha256 = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (state_value, finding_slug, _json_text(receipt_ids), _sha256(record), candidate_id),
        )
        connection.execute(
            """
            INSERT INTO assessment_run_candidate_events (
                engagement_id, run_id, candidate_id, from_state, to_state,
                reason, proof_receipt_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement.id, run_id, candidate_id, current, state_value, reason, _json_text(receipt_ids)),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_run_candidates WHERE id = ?", (candidate_id,)
        ).fetchone()
        assert updated is not None
        return _serialize_candidate(updated)


def list_candidate_history(
    engagement_id: int, *, run_id: int, candidate_id: int
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        exists = connection.execute(
            "SELECT id FROM assessment_run_candidates WHERE engagement_id = ? AND run_id = ? AND id = ?",
            (engagement.id, run_id, candidate_id),
        ).fetchone()
        if exists is None:
            raise HTTPException(status_code=404, detail="run candidate not found")
        rows = connection.execute(
            """
            SELECT * FROM assessment_run_candidate_events
            WHERE engagement_id = ? AND run_id = ? AND candidate_id = ? ORDER BY id
            """,
            (engagement.id, run_id, candidate_id),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            record["proof_receipt_ids"] = _json_value(record.pop("proof_receipt_ids_json"), [])
            result.append(record)
        return result


from .run_evidence import (  # noqa: E402
    list_run_code_receipt_links as list_run_code_receipt_links,
    list_run_decision_history as list_run_decision_history,
    list_run_discovery_passes as list_run_discovery_passes,
    list_run_tool_signals as list_run_tool_signals,
    record_run_code_receipt_link as record_run_code_receipt_link,
    record_run_discovery_pass as record_run_discovery_pass,
    record_run_tool_signal as record_run_tool_signal,
)

from .run_comparisons import (  # noqa: E402
    _inventory_identity,
    _latest_comparison_baseline,
    _record_comparison,
    compare_assessment_runs as compare_assessment_runs,
    list_run_comparisons as list_run_comparisons,
    record_assessment_run_comparison as record_assessment_run_comparison,
)
