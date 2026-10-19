from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from fastapi import HTTPException, status

from .. import artifact_index
from . import _common
from ._common import _engagement_or_404


PROOF_EVIDENCE_KINDS = frozenset(
    {
        "source_observation",
        "command",
        "http_exchange",
        "browser_action",
        "oob_event",
        "artifact",
    }
)
EVIDENCE_HEALTH_VALUES = frozenset({"healthy", "missing", "stale", "tombstoned"})
TERMINAL_VERIFICATION_STATUSES = frozenset(
    {"confirmed", "downgraded", "false_positive"}
)
VERIFICATION_AUDIT_RECORD_LIMIT = 100

_COMMAND_OUTPUT_DEGRADED_RETENTION_STATUSES = frozenset(
    {
        "integrity_failure",
        "measurement_conflict",
        "partially_measured",
        "preview_only",
        "suppression_deferred",
        "suppression_pending",
        "unmeasured",
        "untrusted",
    }
)
_COMMAND_OUTPUT_HEALTHY_RETENTION_STATUSES = frozenset(
    {"artifact", "empty", "retained", "suppressed"}
)
_COMMAND_OUTPUT_DEGRADED_CLEANUP_STATUSES = frozenset(
    {"deferred", "pending", "warning"}
)
_COMMAND_OUTPUT_DEGRADED_INTEGRITY_STATUSES = frozenset({"pending", "warning"})
_ARTIFACT_SNAPSHOT_EVIDENCE_KINDS = frozenset(
    {"artifact", "source_observation", "http_exchange", "browser_action", "oob_event"}
)


def _invalid(name: str, value: str, allowed: frozenset[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"invalid {name} {value!r}; expected one of {', '.join(sorted(allowed))}",
    )


def _receipt_row(
    connection: sqlite3.Connection,
    engagement_id: int,
    receipt_id: int,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT receipts.*, artifacts.present AS artifact_present,
               artifacts.integrity_status AS artifact_integrity_status,
               artifacts.sha256 AS artifact_current_sha256
        FROM assessment_proof_receipts AS receipts
        LEFT JOIN assessment_artifacts AS artifacts ON artifacts.id = receipts.artifact_id
        WHERE receipts.engagement_id = ? AND receipts.id = ?
        """,
        (engagement_id, receipt_id),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="proof receipt not found",
        )
    return row


def _serialize_receipt(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    legacy_status = str(record.pop("redaction_status", "raw") or "raw")
    legacy_parent_id = record.pop("derivative_of_receipt_id", None)
    artifact_present = record.pop("artifact_present", None)
    integrity_status = str(record.pop("artifact_integrity_status", "") or "")
    artifact_sha256 = str(record.pop("artifact_current_sha256", "") or "")
    recorded_health = str(record.get("recorded_health") or "healthy")
    if record.get("artifact_id") is not None:
        if recorded_health != "healthy":
            record["evidence_health"] = recorded_health
        elif integrity_status == "missing":
            record["evidence_health"] = "missing"
        elif integrity_status == "mismatch":
            record["evidence_health"] = "stale"
        elif not bool(artifact_present):
            record["evidence_health"] = "tombstoned"
        elif not artifact_sha256:
            record["evidence_health"] = "stale"
        elif artifact_sha256 != str(record["evidence_sha256"]):
            record["evidence_health"] = "stale"
        else:
            record["evidence_health"] = "healthy"
    elif record.get("artifact_relative_path"):
        record["evidence_health"] = "tombstoned"
    else:
        record["evidence_health"] = str(record.get("recorded_health") or "healthy")
    if (
        record.get("evidence_kind") == "command"
        and record.get("command_run_id") is None
        and record["evidence_health"] == "healthy"
    ):
        record["evidence_health"] = "stale"
    if (
        record.get("evidence_kind") == "source_observation"
        and record.get("source_read_id") is None
        and record.get("artifact_id") is None
        and record["evidence_health"] == "healthy"
    ):
        record["evidence_health"] = "stale"
    if (
        record.get("evidence_kind")
        in {"artifact", "http_exchange", "browser_action", "oob_event"}
        and record.get("artifact_id") is None
        and record["evidence_health"] == "healthy"
    ):
        record["evidence_health"] = "stale"
    if legacy_status != "raw" or legacy_parent_id is not None:
        record["legacy_derivative_provenance"] = {
            "source_receipt_id": (
                int(legacy_parent_id) if legacy_parent_id is not None else None
            ),
            "exact_bytes_are_historical_derivative": True,
        }
    record.pop("recorded_health", None)
    return record


def _command_output_relative_path(root: Path, path_value: object) -> str | None:
    value = str(path_value or "").strip()
    if not value:
        return ""
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        return candidate.resolve(strict=False).relative_to(root).as_posix()
    except (OSError, ValueError):
        return None


def _command_output_evidence_healths(
    connection: sqlite3.Connection,
    engagement_id: int,
    command_run_ids: Iterable[int],
) -> dict[int, str]:
    """Derive command-proof health from measured, retained output truth."""

    command_ids = sorted({int(command_id) for command_id in command_run_ids})
    if not command_ids:
        return {}
    placeholders = ",".join("?" for _ in command_ids)
    rows = connection.execute(
        f"""
        SELECT commands.id, commands.status, commands.route,
               commands.output_retention_status,
               commands.output_cleanup_status,
               commands.output_integrity_status,
               commands.stdout_bytes, commands.stderr_bytes,
               commands.stdout_sha256, commands.stderr_sha256,
               commands.stdout_preview, commands.stderr_preview,
               commands.stdout_artifact_ref, commands.stderr_artifact_ref,
               commands.stdout_path, commands.stderr_path,
               engagements.engagement_root
        FROM assessment_command_runs AS commands
        JOIN engagements ON engagements.id = commands.engagement_id
        WHERE commands.engagement_id = ?
          AND commands.id IN ({placeholders})
        """,
        (engagement_id, *command_ids),
    ).fetchall()
    artifacts = connection.execute(
        f"""
        SELECT producer_command_run_id, relative_path, kind, present,
               integrity_status, sha256, size_bytes,
               verified_device, verified_inode
        FROM assessment_artifacts
        WHERE engagement_id = ?
          AND producer_command_run_id IN ({placeholders})
        """,
        (engagement_id, *command_ids),
    ).fetchall()
    artifacts_by_command: dict[int, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        command_id = int(artifact["producer_command_run_id"])
        artifacts_by_command.setdefault(command_id, []).append(dict(artifact))

    result = {command_id: "stale" for command_id in command_ids}
    for row in rows:
        command = dict(row)
        command_id = int(command["id"])
        retention_status = str(command["output_retention_status"] or "")
        if str(command["status"] or "") not in _common.COMMAND_RUN_TERMINAL_STATUSES:
            continue
        if (
            retention_status in _COMMAND_OUTPUT_DEGRADED_RETENTION_STATUSES
            or retention_status not in _COMMAND_OUTPUT_HEALTHY_RETENTION_STATUSES
            or str(command["output_cleanup_status"] or "")
            in _COMMAND_OUTPUT_DEGRADED_CLEANUP_STATUSES
            or str(command["output_integrity_status"] or "")
            in _COMMAND_OUTPUT_DEGRADED_INTEGRITY_STATUSES
        ):
            continue

        stdout_bytes = int(command["stdout_bytes"] or 0)
        stderr_bytes = int(command["stderr_bytes"] or 0)
        if retention_status == "empty":
            if (
                stdout_bytes != 0
                or stderr_bytes != 0
                or bool(command["stdout_preview"])
                or bool(command["stderr_preview"])
            ):
                continue
            result[command_id] = "healthy"
            continue
        if retention_status == "suppressed":
            result[command_id] = "healthy"
            continue

        root = Path(str(command["engagement_root"])).expanduser().resolve()
        command_artifacts = artifacts_by_command.get(command_id, [])
        artifact_health: list[str] = []
        for stream in ("stdout", "stderr"):
            byte_count = int(command[f"{stream}_bytes"] or 0)
            expected_sha256 = str(command[f"{stream}_sha256"] or "")
            artifact_ref = str(command[f"{stream}_artifact_ref"] or "")
            output_path = (
                ""
                if str(command["route"] or "") == "host_exec"
                else str(command[f"{stream}_path"] or "")
            )
            retained_path = artifact_ref or output_path
            if retained_path:
                relative_path = _command_output_relative_path(root, retained_path)
                if relative_path is None:
                    artifact_health.append("stale")
                    continue
                matching = [
                    artifact
                    for artifact in command_artifacts
                    if artifact["kind"] == "command-run-output"
                    and artifact["relative_path"] == relative_path
                ]
                if not matching:
                    artifact_health.append("missing")
                    continue
                artifact = matching[0]
                if (
                    str(artifact["integrity_status"] or "") == "missing"
                    or not bool(artifact["present"])
                ):
                    artifact_health.append("missing")
                elif not expected_sha256 and byte_count == 0:
                    # A stream measured at ZERO bytes records no digest, because
                    # there are no bytes to digest. That empty digest is the
                    # measurement, not the absence of one — reading it as
                    # unmeasured left every real audited run permanently stale
                    # (almost all of them write nothing to stderr). What tells
                    # the two apart is output_retention_status, filtered above,
                    # NOT the zero itself: only 'artifact'/'retained' reach here,
                    # and a caller that could not read its spill lands
                    # 'unmeasured'/'partially_measured' instead. The retained
                    # file still has to agree: bytes that appeared after the
                    # measurement are a different fact.
                    artifact_health.append(
                        "healthy"
                        if int(artifact["size_bytes"] or 0) == 0
                        else "stale"
                    )
                elif (
                    not expected_sha256
                    or str(artifact["integrity_status"] or "") == "mismatch"
                    or str(artifact["sha256"] or "") != expected_sha256
                ):
                    artifact_health.append("stale")
                else:
                    artifact_health.append(
                        artifact_index.registered_snapshot_evidence_health(
                            root,
                            relative_path,
                            expected_size=int(artifact["size_bytes"] or 0),
                            expected_sha256=expected_sha256,
                            verified_device=(
                                int(artifact["verified_device"])
                                if artifact["verified_device"] is not None
                                else None
                            ),
                            verified_inode=(
                                int(artifact["verified_inode"])
                                if artifact["verified_inode"] is not None
                                else None
                            ),
                        )
                    )
                continue
            if byte_count > 0 and (
                not expected_sha256 or not bool(command[f"{stream}_preview"])
            ):
                artifact_health.append("stale")

        if retention_status == "artifact" and not artifact_health:
            result[command_id] = "missing"
        elif "missing" in artifact_health:
            result[command_id] = "missing"
        elif "stale" not in artifact_health:
            result[command_id] = "healthy"
    return result


def _apply_command_output_health(
    connection: sqlite3.Connection,
    engagement_id: int,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    command_ids = [
        int(record["command_run_id"])
        for record in records
        if record.get("evidence_kind") == "command"
        and record.get("command_run_id") is not None
    ]
    health_by_command = _command_output_evidence_healths(
        connection, engagement_id, command_ids
    )
    for record in records:
        command_run_id = record.get("command_run_id")
        if (
            record.get("evidence_kind") == "command"
            and command_run_id is not None
            and record.get("evidence_health") == "healthy"
        ):
            record["evidence_health"] = health_by_command.get(
                int(command_run_id), "stale"
            )
    return records


def _apply_artifact_snapshot_health(
    connection: sqlite3.Connection,
    engagement_id: int,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    artifact_ids = sorted(
        {
            int(record["artifact_id"])
            for record in records
            if record.get("evidence_kind") in _ARTIFACT_SNAPSHOT_EVIDENCE_KINDS
            and record.get("artifact_id") is not None
            and record.get("evidence_health") == "healthy"
        }
    )
    if not artifact_ids:
        return records
    placeholders = ",".join("?" for _ in artifact_ids)
    rows = connection.execute(
        f"""
        SELECT artifacts.id, artifacts.relative_path, artifacts.size_bytes,
               artifacts.verified_device, artifacts.verified_inode,
               engagements.engagement_root
        FROM assessment_artifacts AS artifacts
        JOIN engagements ON engagements.id = artifacts.engagement_id
        WHERE artifacts.engagement_id = ?
          AND artifacts.id IN ({placeholders})
        """,
        (engagement_id, *artifact_ids),
    ).fetchall()
    artifacts = {int(row["id"]): dict(row) for row in rows}
    for record in records:
        artifact_id = record.get("artifact_id")
        if (
            record.get("evidence_kind") not in _ARTIFACT_SNAPSHOT_EVIDENCE_KINDS
            or artifact_id is None
            or record.get("evidence_health") != "healthy"
        ):
            continue
        artifact = artifacts.get(int(artifact_id))
        if artifact is None:
            record["evidence_health"] = "stale"
            continue
        record["evidence_health"] = artifact_index.registered_snapshot_evidence_health(
            Path(str(artifact["engagement_root"])).expanduser().resolve(),
            str(artifact["relative_path"]),
            expected_size=int(artifact["size_bytes"] or 0),
            expected_sha256=str(record["evidence_sha256"]),
            verified_device=(
                int(artifact["verified_device"])
                if artifact["verified_device"] is not None
                else None
            ),
            verified_inode=(
                int(artifact["verified_inode"])
                if artifact["verified_inode"] is not None
                else None
            ),
        )
    return records


def _apply_live_evidence_health(
    connection: sqlite3.Connection,
    engagement_id: int,
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records = _apply_artifact_snapshot_health(connection, engagement_id, records)
    return _apply_command_output_health(connection, engagement_id, records)


def _serialize_receipts(
    connection: sqlite3.Connection,
    engagement_id: int,
    rows: Iterable[sqlite3.Row | dict[str, Any]],
) -> list[dict[str, Any]]:
    return _apply_live_evidence_health(
        connection, engagement_id, [_serialize_receipt(row) for row in rows]
    )


def _serialize_run_receipt(row: sqlite3.Row) -> dict[str, Any]:
    """Serialize a run receipt with bounded command detail when it cites one."""

    record = _serialize_receipt(row)
    command_fields = {
        "id": record.pop("linked_command_id", None),
        "run_uuid": record.pop("linked_command_run_uuid", None),
        "command": record.pop("linked_command_text", None),
        "argv": record.pop("linked_command_argv_json", None),
        "tool_name": record.pop("linked_command_tool_name", None),
        "agent_name": record.pop("linked_command_agent_name", None),
        "phase": record.pop("linked_command_phase", None),
        "status": record.pop("linked_command_status", None),
        "return_code": record.pop("linked_command_return_code", None),
        "timed_out": record.pop("linked_command_timed_out", None),
        "success": record.pop("linked_command_success", None),
        "started_at": record.pop("linked_command_started_at", None),
        "completed_at": record.pop("linked_command_completed_at", None),
        "duration_ms": record.pop("linked_command_duration_ms", None),
        "command_hash": record.pop("linked_command_hash", None),
        "stdout_sha256": record.pop("linked_command_stdout_sha256", None),
        "stderr_sha256": record.pop("linked_command_stderr_sha256", None),
        "output_retention_status": record.pop(
            "linked_command_output_retention_status", None
        ),
        "stdout_artifact_ref": record.pop(
            "linked_command_stdout_artifact_ref", None
        ),
        "stderr_artifact_ref": record.pop(
            "linked_command_stderr_artifact_ref", None
        ),
    }
    if command_fields["id"] is None:
        record["command"] = None
        return record
    try:
        command_fields["argv"] = json.loads(str(command_fields["argv"] or "[]"))
    except json.JSONDecodeError:
        command_fields["argv"] = []
    command_fields["id"] = int(command_fields["id"])
    command_fields["timed_out"] = bool(command_fields["timed_out"])
    command_fields["success"] = bool(command_fields["success"])
    record["command"] = command_fields
    return record


def create_proof_receipt(
    engagement_id: int,
    *,
    run_id: int,
    evidence_kind: str,
    expected_result: str,
    observed_result: str,
    artifact_id: int | None,
    source_read_id: int | None,
    command_run_id: int | None,
    evidence_sha256: str,
    evidence_health: str,
    tombstone_reason: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    evidence_kind = str(evidence_kind or "").strip().lower()
    evidence_health = str(evidence_health or "healthy").strip().lower()
    if evidence_kind not in PROOF_EVIDENCE_KINDS:
        raise _invalid("evidence_kind", evidence_kind, PROOF_EVIDENCE_KINDS)
    if evidence_health not in EVIDENCE_HEALTH_VALUES:
        raise _invalid("evidence_health", evidence_health, EVIDENCE_HEALTH_VALUES)
    if evidence_kind == "command" and command_run_id is None:
        raise HTTPException(
            status_code=400,
            detail="command proof receipt requires command_run_id",
        )
    if evidence_kind != "command" and command_run_id is not None:
        raise HTTPException(
            status_code=400,
            detail="command_run_id applies only to command proof receipts",
        )
    if evidence_kind == "source_observation":
        if (source_read_id is None) == (artifact_id is None):
            raise HTTPException(
                status_code=400,
                detail=(
                    "source observation requires exactly one durable source_read_id "
                    "or artifact_id"
                ),
            )
    elif source_read_id is not None:
        raise HTTPException(
            status_code=400,
            detail="source_read_id applies only to source-observation proof receipts",
        )
    if (
        evidence_kind in {"artifact", "http_exchange", "browser_action", "oob_event"}
        and artifact_id is None
    ):
        raise HTTPException(
            status_code=400,
            detail=f"{evidence_kind} proof receipt requires artifact_id",
        )

    with _common.get_connection() as connection:
        run = connection.execute(
            "SELECT * FROM assessment_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, run_id),
        ).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail="assessment run not found")
        if str(run["status"]) != "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"assessment run id={run_id} is sealed with status="
                    f"{str(run['status'])!r}; proof receipts must be recorded "
                    "while the run is running"
                ),
            )

        if command_run_id is not None:
            command_run = connection.execute(
                """
                SELECT id, status FROM assessment_command_runs
                WHERE engagement_id = ? AND id = ?
                """,
                (engagement.id, command_run_id),
            ).fetchone()
            if command_run is None:
                raise HTTPException(status_code=404, detail="command run not found")
            if str(command_run["status"]) not in _common.COMMAND_RUN_TERMINAL_STATUSES:
                raise HTTPException(
                    status_code=409,
                    detail="command proof receipt requires a terminal command run",
                )

        source_read = None
        if source_read_id is not None:
            source_read = connection.execute(
                """
                WITH RECURSIVE lineage(id) AS (
                    SELECT id FROM assessment_runs
                    WHERE engagement_id = ? AND id = ?
                    UNION ALL
                    SELECT runs.resumed_from_run_id
                    FROM assessment_runs AS runs
                    JOIN lineage ON lineage.id = runs.id
                    WHERE runs.engagement_id = ?
                      AND runs.resumed_from_run_id IS NOT NULL
                )
                SELECT reads.id, reads.read_fingerprint
                FROM assessment_run_source_reads AS reads
                WHERE reads.engagement_id = ? AND reads.id = ?
                  AND reads.run_id IN (SELECT id FROM lineage)
                """,
                (
                    engagement.id,
                    run_id,
                    engagement.id,
                    engagement.id,
                    source_read_id,
                ),
            ).fetchone()
            if source_read is None:
                raise HTTPException(
                    status_code=400,
                    detail="source_read_id must belong to this assessment run lineage",
                )

        artifact_path = ""
        resolved_sha256 = str(evidence_sha256 or "").strip().lower()
        if artifact_id is not None:
            artifact = connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
                (engagement.id, artifact_id),
            ).fetchone()
            if artifact is None:
                raise HTTPException(status_code=404, detail="artifact not found")
            artifact_path = str(artifact["relative_path"] or "")
            resolved_sha256 = str(artifact["sha256"] or "").strip().lower()
            if len(resolved_sha256) != 64 or any(
                character not in "0123456789abcdef"
                for character in resolved_sha256
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "artifact-backed proof receipt requires a current "
                        "content SHA-256"
                    ),
                )
            if not str(artifact["producer_agent_id"] or "").strip() and artifact["producer_command_run_id"] is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "artifact-backed proof receipt requires producer attribution; "
                        "re-register the artifact with producer agent or command run before binding proof"
                    ),
                )

        if not resolved_sha256:
            canonical = json.dumps(
                {
                    "evidence_kind": evidence_kind,
                    "expected_result": expected_result,
                    "observed_result": observed_result,
                    "run_id": int(run_id),
                    "source_read_id": source_read_id,
                    "command_run_id": command_run_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            resolved_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if source_read is not None:
            resolved_sha256 = str(source_read["read_fingerprint"])
        if len(resolved_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in resolved_sha256
        ):
            raise HTTPException(status_code=400, detail="evidence_sha256 must be lowercase SHA-256")

        cursor = connection.execute(
            """
            INSERT INTO assessment_proof_receipts (
                engagement_id, run_id, producer_dispatch_id, evidence_kind,
                expected_result, observed_result, artifact_id,
                source_read_id, command_run_id, artifact_relative_path,
                evidence_sha256, recorded_health, tombstone_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                int(run_id),
                int(run["producer_dispatch_id"]),
                evidence_kind,
                str(expected_result or ""),
                str(observed_result or ""),
                artifact_id,
                source_read_id,
                command_run_id,
                artifact_path,
                resolved_sha256,
                evidence_health,
                str(tombstone_reason or ""),
            ),
        )
        return _serialize_receipts(
            connection,
            engagement.id,
            [_receipt_row(connection, engagement.id, int(cursor.lastrowid))],
        )[0]


def get_proof_receipt(engagement_id: int, receipt_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _serialize_receipts(
            connection,
            engagement.id,
            [_receipt_row(connection, engagement.id, receipt_id)],
        )[0]


def list_proof_receipts(
    engagement_id: int,
    *,
    finding_slug: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Receipts, newest first; ``finding_slug`` narrows to that finding's receipts.

    A finding's receipts are those its verification cites and those produced by a
    run associated with it (``proof-run start --for-finding`` or ``finding link
    --link-kind proof_run``). Each filtered row names which one it is in
    ``finding_association``: ``verification`` (cited) or ``proof_run`` (associated
    run, not cited), so an associated receipt never reads as decision evidence.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        params: list[Any] = []
        association = ""
        where = "receipts.engagement_id = ?"
        if finding_slug:
            cited = (
                "EXISTS (SELECT 1 FROM assessment_finding_proof_receipts AS cited "
                "WHERE cited.proof_receipt_id = receipts.id AND cited.finding_id = findings.id)"
            )
            association = (
                f", CASE WHEN {cited} THEN 'verification' ELSE 'proof_run' END "
                "AS finding_association"
            )
            where = (
                "receipts.engagement_id = ? AND findings.engagement_id = receipts.engagement_id "
                f"AND findings.slug = ? AND ({cited} OR EXISTS ("
                "SELECT 1 FROM assessment_finding_links AS links "
                "WHERE links.finding_id = findings.id AND links.link_kind = 'proof_run' "
                "AND links.target_kind = 'assessment_run' AND links.retired_at IS NULL "
                "AND links.target_id = receipts.run_id))"
            )
            params.append(str(finding_slug))
        rows = connection.execute(
            f"""
            SELECT receipts.*, artifacts.present AS artifact_present,
                   artifacts.integrity_status AS artifact_integrity_status,
                   artifacts.sha256 AS artifact_current_sha256{association}
            FROM assessment_proof_receipts AS receipts
            {"CROSS JOIN assessment_findings AS findings" if finding_slug else ""}
            LEFT JOIN assessment_artifacts AS artifacts ON artifacts.id = receipts.artifact_id
            WHERE {where}
            ORDER BY receipts.created_at DESC, receipts.id DESC
            LIMIT ? OFFSET ?
            """,
            (engagement.id, *params, limit, offset),
        ).fetchall()
        return _serialize_receipts(connection, engagement.id, rows)


def list_run_proof_receipts(
    engagement_id: int,
    *,
    run_id: int,
    limit: int = 100,
    offset: int = 0,
    evidence_kinds: frozenset[str] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if evidence_kinds and not evidence_kinds.issubset(PROOF_EVIDENCE_KINDS):
        raise ValueError("run proof receipt filter contains an unknown evidence kind")
    ordered_kinds = sorted(evidence_kinds or ())
    kind_clause = ""
    if ordered_kinds:
        placeholders = ",".join("?" for _ in ordered_kinds)
        kind_clause = f" AND evidence_kind IN ({placeholders})"
    with _common.get_connection() as connection:
        run = connection.execute(
            "SELECT id FROM assessment_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, run_id),
        ).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail="assessment run not found")
        lineage_cte = """
            WITH RECURSIVE lineage(id) AS (
                SELECT id FROM assessment_runs
                WHERE engagement_id = ? AND id = ?
                UNION ALL
                SELECT runs.resumed_from_run_id
                FROM assessment_runs AS runs
                JOIN lineage ON lineage.id = runs.id
                WHERE runs.engagement_id = ? AND runs.resumed_from_run_id IS NOT NULL
            )
        """
        total = int(
            connection.execute(
                f"""
                {lineage_cte}
                SELECT COUNT(*) FROM assessment_proof_receipts
                WHERE engagement_id = ? AND run_id IN (SELECT id FROM lineage)
                {kind_clause}
                """,
                (
                    engagement.id,
                    run_id,
                    engagement.id,
                    engagement.id,
                    *ordered_kinds,
                ),
            ).fetchone()[0]
        )
        rows = connection.execute(
            f"""
            {lineage_cte}
            SELECT receipts.*, receipts.run_id AS origin_run_id,
                   dispatches.agent_id AS producer_dispatch_agent_id,
                   dispatches.agent_role AS producer_dispatch_agent_role,
                   artifacts.present AS artifact_present,
                   artifacts.integrity_status AS artifact_integrity_status,
                   artifacts.sha256 AS artifact_current_sha256,
                   commands.id AS linked_command_id,
                   commands.run_uuid AS linked_command_run_uuid,
                   commands.command AS linked_command_text,
                   commands.argv_json AS linked_command_argv_json,
                   commands.tool_name AS linked_command_tool_name,
                   commands.agent_name AS linked_command_agent_name,
                   commands.phase AS linked_command_phase,
                   commands.status AS linked_command_status,
                   commands.return_code AS linked_command_return_code,
                   commands.timed_out AS linked_command_timed_out,
                   commands.success AS linked_command_success,
                   commands.started_at AS linked_command_started_at,
                   commands.completed_at AS linked_command_completed_at,
                   commands.duration_ms AS linked_command_duration_ms,
                   commands.command_hash AS linked_command_hash,
                   commands.stdout_sha256 AS linked_command_stdout_sha256,
                   commands.stderr_sha256 AS linked_command_stderr_sha256,
                   commands.output_retention_status
                       AS linked_command_output_retention_status,
                   commands.stdout_artifact_ref
                       AS linked_command_stdout_artifact_ref,
                   commands.stderr_artifact_ref
                       AS linked_command_stderr_artifact_ref
            FROM assessment_proof_receipts AS receipts
            JOIN assessment_dispatches AS dispatches
              ON dispatches.id = receipts.producer_dispatch_id
            LEFT JOIN assessment_artifacts AS artifacts
              ON artifacts.id = receipts.artifact_id
            LEFT JOIN assessment_command_runs AS commands
              ON commands.id = receipts.command_run_id
            WHERE receipts.engagement_id = ?
              AND receipts.run_id IN (SELECT id FROM lineage)
              {kind_clause}
            ORDER BY receipts.created_at DESC, receipts.id DESC
            LIMIT ? OFFSET ?
            """,
            (
                engagement.id,
                run_id,
                engagement.id,
                engagement.id,
                *ordered_kinds,
                limit,
                offset,
            ),
        ).fetchall()
        serialized = _apply_live_evidence_health(
            connection,
            engagement.id,
            [_serialize_run_receipt(row) for row in rows],
        )
        return {
            "items": serialized,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < total,
        }


def list_run_command_receipts(
    engagement_id: int, *, run_id: int, limit: int = 100, offset: int = 0
) -> dict[str, Any]:
    page = list_run_proof_receipts(
        engagement_id,
        run_id=run_id,
        limit=limit,
        offset=offset,
        evidence_kinds=frozenset({"command"}),
    )
    page["items"] = [
        {**item, "audit_run_id": run_id} for item in page["items"]
    ]
    return page


def list_run_observed_events(
    engagement_id: int, *, run_id: int, limit: int = 100, offset: int = 0
) -> dict[str, Any]:
    page = list_run_proof_receipts(
        engagement_id,
        run_id=run_id,
        limit=limit,
        offset=offset,
        evidence_kinds=frozenset({"http_exchange", "browser_action", "oob_event"}),
    )
    page["items"] = [
        {**item, "audit_run_id": run_id} for item in page["items"]
    ]
    return page


def proof_receipts_for_finding(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT receipts.*, artifacts.present AS artifact_present,
               artifacts.integrity_status AS artifact_integrity_status,
               artifacts.sha256 AS artifact_current_sha256
        FROM assessment_finding_proof_receipts AS links
        JOIN assessment_proof_receipts AS receipts ON receipts.id = links.proof_receipt_id
        JOIN assessment_findings AS findings ON findings.id = links.finding_id
        LEFT JOIN assessment_artifacts AS artifacts ON artifacts.id = receipts.artifact_id
        WHERE links.engagement_id = ? AND links.finding_id = ?
          AND (
            links.transition_id = (
              SELECT MAX(current_links.transition_id)
              FROM assessment_finding_proof_receipts AS current_links
              JOIN assessment_finding_transitions AS current_transition
                ON current_transition.id = current_links.transition_id
              WHERE current_links.engagement_id = links.engagement_id
                AND current_links.finding_id = links.finding_id
                AND current_transition.to_verification_status =
                    findings.verification_status
            )
            OR (
              links.transition_id IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM assessment_finding_proof_receipts AS mapped_links
                WHERE mapped_links.engagement_id = links.engagement_id
                  AND mapped_links.finding_id = links.finding_id
                  AND mapped_links.transition_id IS NOT NULL
              )
            )
          )
        ORDER BY links.id
        """,
        (engagement_id, finding_id),
    ).fetchall()
    return _serialize_receipts(connection, engagement_id, rows)


def _serialize_counterchecks(
    connection: sqlite3.Connection,
    rows: list[sqlite3.Row],
) -> list[dict[str, Any]]:
    receipt_ids: dict[int, list[int]] = {int(row["id"]): [] for row in rows}
    if receipt_ids:
        placeholders = ", ".join("?" for _ in receipt_ids)
        links = connection.execute(
            f"""
            SELECT countercheck_id, proof_receipt_id
            FROM assessment_finding_countercheck_receipts
            WHERE countercheck_id IN ({placeholders})
            ORDER BY countercheck_id, proof_receipt_id
            """,
            tuple(receipt_ids),
        ).fetchall()
        for link in links:
            receipt_ids[int(link["countercheck_id"])].append(
                int(link["proof_receipt_id"])
            )

    records: list[dict[str, Any]] = []
    for row in rows:
        records.append(
            {
                "id": int(row["id"]),
                "transition_id": int(row["transition_id"]),
                "verifier_dispatch_id": int(row["verifier_dispatch_id"]),
                "method": str(row["method"]),
                "expected_result": str(row["expected_result"]),
                "observed_result": str(row["observed_result"]),
                "falsified_claim": str(row["falsified_claim"]),
                "completed": bool(row["completed"]),
                "proof_receipt_ids": receipt_ids[int(row["id"])],
                "created_at": str(row["created_at"]),
            }
        )
    return records


def _serialize_severity_variances(
    rows: list[sqlite3.Row],
) -> list[dict[str, Any]]:
    return [
        {
            "id": int(row["id"]),
            "transition_id": int(row["transition_id"]),
            "normal_band": str(row["normal_band"]),
            "chosen_severity": str(row["chosen_severity"]),
            "actor": str(row["actor"]),
            "reason": str(row["reason"]),
            "proof_receipt_id": int(row["proof_receipt_id"]),
            "created_at": str(row["created_at"]),
        }
        for row in rows
    ]


def _verification_audit_payload(
    proof_receipt_ids: list[int],
    counter_checks: list[dict[str, Any]],
    severity_variances: list[dict[str, Any]],
    *,
    proof_receipt_total: int,
    counter_check_total: int,
    severity_variance_total: int,
) -> dict[str, Any]:
    return {
        "proof_receipt_ids": proof_receipt_ids,
        "proof_receipt_total": proof_receipt_total,
        "counter_checks": counter_checks,
        "counter_check_total": counter_check_total,
        "severity_variances": severity_variances,
        "severity_variance_total": severity_variance_total,
        "record_limit": VERIFICATION_AUDIT_RECORD_LIMIT,
        "truncated": (
            proof_receipt_total > len(proof_receipt_ids)
            or counter_check_total > len(counter_checks)
            or severity_variance_total > len(severity_variances)
        ),
    }


def verification_audit_for_finding(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
) -> dict[str, Any]:
    """Return a bounded point-read summary; full records remain on history pages."""

    totals = connection.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM assessment_finding_proof_receipts
           WHERE engagement_id = ? AND finding_id = ?) AS proof_receipt_total,
          (SELECT COUNT(*) FROM assessment_finding_counterchecks
           WHERE engagement_id = ? AND finding_id = ?) AS counter_check_total,
          (SELECT COUNT(*) FROM assessment_finding_severity_variances
           WHERE engagement_id = ? AND finding_id = ?) AS severity_variance_total
        """,
        (
            engagement_id,
            finding_id,
            engagement_id,
            finding_id,
            engagement_id,
            finding_id,
        ),
    ).fetchone()
    assert totals is not None
    proof_link_rows = connection.execute(
        """
        SELECT proof_receipt_id
        FROM assessment_finding_proof_receipts
        WHERE engagement_id = ? AND finding_id = ?
        ORDER BY COALESCE(transition_id, 0) DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, finding_id, VERIFICATION_AUDIT_RECORD_LIMIT),
    ).fetchall()
    counter_rows = connection.execute(
        """
        SELECT *
        FROM assessment_finding_counterchecks
        WHERE engagement_id = ? AND finding_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, finding_id, VERIFICATION_AUDIT_RECORD_LIMIT),
    ).fetchall()
    variance_rows = connection.execute(
        """
        SELECT *
        FROM assessment_finding_severity_variances
        WHERE engagement_id = ? AND finding_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, finding_id, VERIFICATION_AUDIT_RECORD_LIMIT),
    ).fetchall()
    return _verification_audit_payload(
        [int(row["proof_receipt_id"]) for row in proof_link_rows],
        _serialize_counterchecks(connection, list(counter_rows)),
        _serialize_severity_variances(list(variance_rows)),
        proof_receipt_total=int(totals["proof_receipt_total"]),
        counter_check_total=int(totals["counter_check_total"]),
        severity_variance_total=int(totals["severity_variance_total"]),
    )


def verification_audit_by_transition(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
    transition_ids: list[int],
) -> dict[int, dict[str, Any]]:
    """Attach each structured decision record to its paginated history event."""

    unique_ids = list(dict.fromkeys(int(value) for value in transition_ids))
    if not unique_ids:
        return {}
    placeholders = ", ".join("?" for _ in unique_ids)
    params = (engagement_id, finding_id, *unique_ids)
    counter_rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_finding_counterchecks
        WHERE engagement_id = ? AND finding_id = ?
          AND transition_id IN ({placeholders})
        ORDER BY created_at DESC, id DESC
        """,
        params,
    ).fetchall()
    variance_rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_finding_severity_variances
        WHERE engagement_id = ? AND finding_id = ?
          AND transition_id IN ({placeholders})
        ORDER BY created_at DESC, id DESC
        """,
        params,
    ).fetchall()
    proof_link_rows = connection.execute(
        f"""
        SELECT transition_id, proof_receipt_id
        FROM assessment_finding_proof_receipts
        WHERE engagement_id = ? AND finding_id = ?
          AND transition_id IN ({placeholders})
        ORDER BY transition_id, id
        """,
        params,
    ).fetchall()
    counters = _serialize_counterchecks(connection, list(counter_rows))
    variances = _serialize_severity_variances(list(variance_rows))
    counters_by_transition: dict[int, list[dict[str, Any]]] = {
        transition_id: [] for transition_id in unique_ids
    }
    variances_by_transition: dict[int, list[dict[str, Any]]] = {
        transition_id: [] for transition_id in unique_ids
    }
    receipts_by_transition: dict[int, list[int]] = {
        transition_id: [] for transition_id in unique_ids
    }
    for row in proof_link_rows:
        receipts_by_transition[int(row["transition_id"])].append(
            int(row["proof_receipt_id"])
        )
    for row in counters:
        counters_by_transition[int(row["transition_id"])].append(row)
    for row in variances:
        variances_by_transition[int(row["transition_id"])].append(row)

    result: dict[int, dict[str, Any]] = {}
    for transition_id in unique_ids:
        transition_counters = counters_by_transition[transition_id]
        transition_variances = variances_by_transition[transition_id]
        transition_receipts = receipts_by_transition[transition_id]
        result[transition_id] = _verification_audit_payload(
            transition_receipts,
            transition_counters,
            transition_variances,
            proof_receipt_total=len(transition_receipts),
            counter_check_total=len(transition_counters),
            severity_variance_total=len(transition_variances),
        )
    return result


def proof_evidence_health_issues_for_finding(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding_id: int,
) -> list[dict[str, Any]]:
    """Return only degraded evidence that a finding's decision depends on."""

    issues: list[dict[str, Any]] = []
    for receipt in proof_receipts_for_finding(connection, engagement_id, finding_id):
        receipt_id = int(receipt["id"])
        if receipt["evidence_health"] != "healthy":
            issues.append(
                {
                    "proof_receipt_id": receipt_id,
                    "evidence_health": receipt["evidence_health"],
                }
            )
        legacy = receipt.get("legacy_derivative_provenance")
        parent_id = legacy.get("source_receipt_id") if isinstance(legacy, dict) else None
        if parent_id is None:
            continue
        raw = _serialize_receipts(
            connection,
            engagement_id,
            [_receipt_row(connection, engagement_id, int(parent_id))],
        )[0]
        if raw["evidence_health"] != "healthy":
            issues.append(
                {
                    "proof_receipt_id": receipt_id,
                    "dependent_raw_receipt_id": int(parent_id),
                    "evidence_health": raw["evidence_health"],
                }
            )
    return issues


def _require_verifier_owned_evidence(
    connection: sqlite3.Connection,
    engagement_id: int,
    receipt_id: int,
) -> None:
    """Require the receipt's durable evidence to belong to its named producer."""

    row = connection.execute(
        """
        SELECT receipts.evidence_kind, receipts.command_run_id,
               receipts.source_read_id, receipts.artifact_id,
               receipts.producer_dispatch_id,
               dispatches.agent_id AS verifier_agent_id,
               commands.agent_name AS command_agent_id,
               source_reads.dispatch_id AS source_dispatch_id,
               artifacts.producer_agent_id AS artifact_agent_id,
               artifacts.producer_command_run_id AS artifact_command_run_id,
               artifact_commands.agent_name AS artifact_command_agent_id
        FROM assessment_proof_receipts AS receipts
        JOIN assessment_dispatches AS dispatches
          ON dispatches.id = receipts.producer_dispatch_id
         AND dispatches.engagement_id = receipts.engagement_id
        LEFT JOIN assessment_command_runs AS commands
          ON commands.id = receipts.command_run_id
         AND commands.engagement_id = receipts.engagement_id
        LEFT JOIN assessment_run_source_reads AS source_reads
          ON source_reads.id = receipts.source_read_id
         AND source_reads.engagement_id = receipts.engagement_id
        LEFT JOIN assessment_artifacts AS artifacts
          ON artifacts.id = receipts.artifact_id
         AND artifacts.engagement_id = receipts.engagement_id
        LEFT JOIN assessment_command_runs AS artifact_commands
          ON artifact_commands.id = artifacts.producer_command_run_id
         AND artifact_commands.engagement_id = receipts.engagement_id
        WHERE receipts.engagement_id = ? AND receipts.id = ?
        """,
        (engagement_id, receipt_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=400, detail="proof receipt attribution is missing")

    evidence_kind = str(row["evidence_kind"])
    verifier_agent_id = str(row["verifier_agent_id"])
    if evidence_kind == "command":
        attributed = (
            row["command_run_id"] is not None
            and str(row["command_agent_id"] or "") == verifier_agent_id
        )
    elif row["source_read_id"] is not None:
        attributed = (
            row["source_dispatch_id"] is not None
            and int(row["source_dispatch_id"]) == int(row["producer_dispatch_id"])
        )
    elif row["artifact_id"] is not None:
        if row["artifact_command_run_id"] is not None:
            attributed = (
                str(row["artifact_command_agent_id"] or "") == verifier_agent_id
            )
        else:
            attributed = str(row["artifact_agent_id"] or "") == verifier_agent_id
    else:
        attributed = False
    if attributed:
        return
    action = "was not executed" if evidence_kind == "command" else "was not produced"
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"proof receipt {receipt_id} evidence {action} by the verifier dispatch"
        ),
    )


def _verification_receipts(
    connection: sqlite3.Connection,
    engagement_id: int,
    receipt_ids: list[int],
) -> tuple[list[dict[str, Any]], int]:
    unique_ids = list(dict.fromkeys(receipt_ids))
    if not unique_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="terminal verification requires at least one proof_receipt_id",
        )
    receipts: list[dict[str, Any]] = []
    producer_dispatch_ids: set[int] = set()
    for receipt_id in unique_ids:
        row = connection.execute(
            """
            SELECT receipts.*, runs.status AS run_status,
                   artifacts.present AS artifact_present,
                   artifacts.integrity_status AS artifact_integrity_status,
                   artifacts.sha256 AS artifact_current_sha256
            FROM assessment_proof_receipts AS receipts
            JOIN assessment_runs AS runs ON runs.id = receipts.run_id
            LEFT JOIN assessment_artifacts AS artifacts
              ON artifacts.id = receipts.artifact_id
            WHERE receipts.engagement_id = ? AND receipts.id = ?
            """,
            (engagement_id, receipt_id),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"proof_receipt_id {receipt_id} does not belong to this engagement",
            )
        receipt = _serialize_receipts(connection, engagement_id, [row])[0]
        run_status = str(receipt.pop("run_status") or "")
        if run_status != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"proof_receipt_id {receipt_id} belongs to a run that is not completed",
            )
        if receipt["evidence_health"] != "healthy":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"proof receipt {receipt_id} evidence is "
                    f"{receipt['evidence_health']}; capture fresh evidence before a "
                    "terminal verification decision"
                ),
            )
        _require_verifier_owned_evidence(
            connection,
            engagement_id,
            receipt_id,
        )
        legacy = receipt.get("legacy_derivative_provenance")
        legacy_parent_id = (
            legacy.get("source_receipt_id") if isinstance(legacy, dict) else None
        )
        if legacy_parent_id is not None:
            raw = _serialize_receipts(
                connection,
                engagement_id,
                [
                    _receipt_row(
                        connection,
                        engagement_id,
                        int(legacy_parent_id),
                    )
                ],
            )[0]
            if raw["evidence_health"] != "healthy":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"proof receipt {receipt_id} depends on raw evidence that is "
                        f"{raw['evidence_health']}"
                    ),
                )
            if int(raw["producer_dispatch_id"]) != int(
                receipt["producer_dispatch_id"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"proof receipt {receipt_id} depends on raw evidence from "
                        "a different verifier dispatch"
                    ),
                )
            _require_verifier_owned_evidence(
                connection,
                engagement_id,
                int(raw["id"]),
            )
        producer_dispatch_ids.add(int(receipt["producer_dispatch_id"]))
        receipts.append(receipt)
    if len(producer_dispatch_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="one independent verifier dispatch must own all decision proof receipts",
        )
    return receipts, producer_dispatch_ids.pop()


def record_finding_verification_evidence(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    finding: sqlite3.Row | dict[str, Any],
    transition_id: int,
    verification_status: str,
    proof_receipt_ids: list[int],
    counter_check: dict[str, Any] | None,
    confirm_check: dict[str, Any] | None,
    severity_variance: dict[str, Any] | None,
    normal_severity_band: str | None,
) -> dict[str, Any]:
    """Validate and durably link the evidence behind one verification event."""

    terminal = verification_status in TERMINAL_VERIFICATION_STATUSES
    if not terminal:
        if proof_receipt_ids or counter_check is not None or confirm_check is not None or severity_variance is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="proof decision records apply only to terminal verification statuses",
            )
        return {"proof_receipts": [], "counter_check": None, "severity_variance": None}

    counter_receipt_ids = (
        [int(value) for value in counter_check.get("proof_receipt_ids", [])]
        if counter_check is not None
        else []
    )
    decision_receipt_ids = proof_receipt_ids or counter_receipt_ids
    receipts, verifier_dispatch_id = _verification_receipts(
        connection, engagement_id, decision_receipt_ids
    )
    receipt_id_set = {int(receipt["id"]) for receipt in receipts}
    linked_runs = connection.execute(
        """
        SELECT target_id FROM assessment_finding_links
        WHERE engagement_id = ? AND finding_id = ?
          AND link_kind = 'proof_run' AND target_kind = 'assessment_run'
          AND retired_at IS NULL
        """,
        (engagement_id, int(finding["id"])),
    ).fetchall()
    linked_run_ids = {int(link["target_id"]) for link in linked_runs}
    if not any(int(receipt["run_id"]) in linked_run_ids for receipt in receipts):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "terminal verification requires a decision proof receipt from an "
                "active proof_run link to this finding"
            ),
        )

    provenance = json.loads(str(finding["provenance_json"] or "{}"))
    origin_agent_id = str(provenance.get("agent_id") or "").strip()
    if not origin_agent_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "terminal verification cannot establish an independent verifier: "
                "the finding has no durable author provenance.agent_id"
            ),
        )
    origin = connection.execute(
        "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
        (engagement_id, origin_agent_id),
    ).fetchone()
    if origin is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "terminal verification cannot establish an independent verifier: "
                "the finding author provenance.agent_id does not resolve to a dispatch"
            ),
        )
    if int(origin["id"]) == verifier_dispatch_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="terminal verification requires an independent verifier dispatch",
        )

    confirm_receipt_ids: set[int] = set()
    if verification_status in {"confirmed", "downgraded"}:
        if confirm_check is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="confirmed/downgraded verification requires a structured confirm_check",
            )
        if confirm_check.get("completed") is not True:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="confirm_check must be completed to establish terminal verification",
            )
        for name in ("method", "attempted_falsification", "expected_result", "observed_result"):
            if not str(confirm_check.get(name) or "").strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"confirm_check.{name} is required",
                )
        check_receipt_ids = confirm_check.get("proof_receipt_ids") or []
        confirm_receipt_ids = {int(value) for value in check_receipt_ids}
        if not check_receipt_ids or not confirm_receipt_ids <= receipt_id_set:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="confirm_check proof_receipt_ids must name the decision proof receipts",
            )
    elif confirm_check is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="confirm_check applies only to confirmed or downgraded verification",
        )
    if confirm_receipt_ids and not any(
        int(receipt["id"]) in confirm_receipt_ids
        and int(receipt["run_id"]) in linked_run_ids
        for receipt in receipts
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="confirm_check requires a finding-linked decision proof receipt",
        )

    for receipt_id in receipt_id_set:
        existing_link = connection.execute(
            """
            SELECT transition_id
            FROM assessment_finding_proof_receipts
            WHERE finding_id = ? AND proof_receipt_id = ?
              AND relation = 'verification'
            """,
            (int(finding["id"]), receipt_id),
        ).fetchone()
        if existing_link is not None and existing_link["transition_id"] != transition_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"proof_receipt_id {receipt_id} already supports an earlier "
                    "verification event; capture fresh proof for re-verification"
                ),
            )
        connection.execute(
            """
            INSERT OR IGNORE INTO assessment_finding_proof_receipts (
                engagement_id, finding_id, transition_id,
                proof_receipt_id, relation
            ) VALUES (?, ?, ?, ?, 'verification')
            """,
            (engagement_id, int(finding["id"]), transition_id, receipt_id),
        )

    counter_record = None
    if verification_status == "false_positive":
        if counter_check is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="false_positive verification requires a structured counter_check",
            )
        if not bool(counter_check.get("completed")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "an incomplete counter_check cannot establish false_positive; "
                    "record blocked or pending_runtime_proof instead"
                ),
            )
        for name in ("method", "expected_result", "observed_result", "falsified_claim"):
            if not str(counter_check.get(name) or "").strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"counter_check.{name} is required",
                )
        if not counter_receipt_ids or not set(counter_receipt_ids) <= receipt_id_set:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="counter_check proof_receipt_ids must name the decision proof receipts",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_finding_counterchecks (
                engagement_id, finding_id, transition_id, verifier_dispatch_id,
                method, expected_result, observed_result, falsified_claim, completed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                engagement_id,
                int(finding["id"]),
                transition_id,
                verifier_dispatch_id,
                str(counter_check["method"]).strip(),
                str(counter_check["expected_result"]).strip(),
                str(counter_check["observed_result"]).strip(),
                str(counter_check["falsified_claim"]).strip(),
            ),
        )
        countercheck_id = int(cursor.lastrowid)
        for receipt_id in counter_receipt_ids:
            connection.execute(
                """
                INSERT INTO assessment_finding_countercheck_receipts (
                    countercheck_id, proof_receipt_id
                ) VALUES (?, ?)
                """,
                (countercheck_id, receipt_id),
            )
        counter_record = {
            "id": countercheck_id,
            **counter_check,
            "verifier_dispatch_id": verifier_dispatch_id,
        }
    elif counter_check is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="counter_check applies only to false_positive verification",
        )

    variance_record = None
    chosen_severity = str(finding["severity"])
    if normal_severity_band is not None and chosen_severity != normal_severity_band:
        if severity_variance is None:
            example = json.dumps(
                {
                    "normal_band": normal_severity_band,
                    "chosen_severity": chosen_severity,
                    "actor": verifier_dispatch_id,
                    "reason": "Explain why the chosen severity differs from the CVSS band",
                    "proof_receipt_id": min(receipt_id_set),
                },
                separators=(",", ":"),
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "verification severity departs from its CVSS band; an attributed "
                    "severity_variance event is required. Pass --severity-variance-file "
                    f"with a JSON object such as {example}, and also pass its "
                    "proof_receipt_id with --proof-receipt-id. Replace the example reason."
                ),
            )
        proof_receipt_id = int(severity_variance["proof_receipt_id"])
        if (
            str(severity_variance.get("normal_band")) != normal_severity_band
            or str(severity_variance.get("chosen_severity")) != chosen_severity
            or proof_receipt_id not in receipt_id_set
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="severity_variance must match the CVSS band, chosen severity, and proof receipts",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_finding_severity_variances (
                engagement_id, finding_id, transition_id, normal_band,
                chosen_severity, actor, reason, proof_receipt_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                int(finding["id"]),
                transition_id,
                normal_severity_band,
                chosen_severity,
                str(severity_variance["actor"]).strip(),
                str(severity_variance["reason"]).strip(),
                proof_receipt_id,
            ),
        )
        variance_record = {"id": int(cursor.lastrowid), **severity_variance}
    elif severity_variance is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="severity_variance is only valid when severity departs from its CVSS band",
        )

    return {
        "proof_receipts": receipts,
        "counter_check": counter_record,
        "severity_variance": variance_record,
    }
