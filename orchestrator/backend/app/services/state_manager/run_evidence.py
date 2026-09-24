"""Run evidence, discovery, and code-receipt accounting.

These writes connect durable proof to active run debt and typed observations.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import HTTPException

from . import _common
from ._common import _engagement_or_404
from .run_accounting import (
    CODE_RECEIPT_KINDS,
    DISCOVERY_TERMINAL_REASONS,
    TOOL_SIGNAL_KINDS,
    _CODE_RECEIPT_OBLIGATION_KINDS,
    _CODE_RECEIPT_TABLES,
    _discovery_receipts_match_dispatch,
    _exact_run_source_generation,
    _invalid,
    _json_text,
    _json_value,
    _page,
    _positive_int_list,
    _proof_receipts_are_healthy,
    _require_active_run,
    _run_lineage_ids,
    _run_or_404,
    _sha256,
    _validate_receipt_ids,
    _code_receipt_has_exact_artifact_proof,
)


def _serialize_tool_signal(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    record["proof_receipt_ids"] = _json_value(
        record.pop("proof_receipt_ids_json"), []
    )
    return record


def record_run_tool_signal(
    engagement_id: int,
    *,
    run_id: int,
    identity_key: str,
    signal_kind: str,
    dispatch_agent_id: str,
    target_key: str,
    source_id: int | None,
    source_anchor: str,
    vulnerability_family: str,
    hypothesis: str,
    observed_signature: str,
    exact_input_sha256: str,
    command_run_id: int | None,
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    """Persist one narrowly typed tool observation and its candidate atomically."""

    engagement = _engagement_or_404(engagement_id)
    if signal_kind not in TOOL_SIGNAL_KINDS:
        raise _invalid("tool signal kind", signal_kind, TOOL_SIGNAL_KINDS)
    for name, value in (
        ("identity_key", identity_key),
        ("target_key", target_key),
        ("source_anchor", source_anchor),
        ("vulnerability_family", vulnerability_family),
        ("hypothesis", hypothesis),
        ("observed_signature", observed_signature),
    ):
        if not str(value).strip():
            raise HTTPException(status_code=400, detail=f"tool signal {name} is required")
    exact_input_sha256 = str(exact_input_sha256 or "").strip().lower()
    if signal_kind == "reproducible_crash" and (
        len(exact_input_sha256) != 64
        or any(character not in "0123456789abcdef" for character in exact_input_sha256)
    ):
        raise HTTPException(
            status_code=400,
            detail="reproducible crash signals require the exact input SHA-256",
        )
    if command_run_id is None:
        raise HTTPException(
            status_code=400,
            detail=f"{signal_kind} signals require an exact command-run receipt",
        )
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="tool signal writes")
        if str(run["run_kind"]) == "code" and source_id is None:
            raise HTTPException(
                status_code=409,
                detail="code tool signals require an exact inventoried run source",
            )
        dispatch = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, dispatch_agent_id),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(status_code=404, detail="tool signal dispatch not found")
        source_identity: dict[str, str] | None = None
        if source_id is not None:
            source = connection.execute(
                """
                SELECT target_key, path, content_sha256 FROM assessment_run_sources
                WHERE engagement_id = ? AND run_id = ? AND id = ?
                """,
                (engagement.id, run_id, source_id),
            ).fetchone()
            if source is None:
                raise HTTPException(status_code=404, detail="tool signal source not found")
            if str(source["target_key"]) != target_key:
                raise HTTPException(
                    status_code=409,
                    detail="tool signal target does not match its exact run source",
                )
            source_identity = {
                "target_key": str(source["target_key"]),
                "path": str(source["path"]),
                "content_sha256": str(source["content_sha256"]),
            }
            if str(run["run_kind"]) == "code":
                _exact_run_source_generation(run, target_key=target_key)
                source_path = str(source["path"])
                if source_anchor != source_path and not source_anchor.startswith(
                    f"{source_path}:"
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="code tool signal anchor does not match its exact run source",
                    )
        if command_run_id is not None:
            command = connection.execute(
                """
                SELECT id, agent_name FROM assessment_command_runs
                WHERE engagement_id = ? AND id = ?
                """,
                (engagement.id, command_run_id),
            ).fetchone()
            if command is None:
                raise HTTPException(status_code=404, detail="tool signal command run not found")
            if str(command["agent_name"]) != dispatch_agent_id:
                raise HTTPException(
                    status_code=409,
                    detail="tool signal command does not match the attributed dispatch",
                )
        receipt_ids = _validate_receipt_ids(
            connection, engagement.id, run_id, proof_receipt_ids
        )
        if not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail="typed tool signals require durable proof receipts",
            )
        if not _proof_receipts_are_healthy(
            connection, engagement.id, receipt_ids
        ):
            raise HTTPException(
                status_code=400,
                detail="typed tool signal proof receipts must be healthy",
            )
        placeholders = ",".join("?" for _ in receipt_ids)
        receipt_rows = connection.execute(
            f"""
            SELECT receipts.id, receipts.evidence_kind, receipts.command_run_id,
                   artifacts.producer_command_run_id AS artifact_command_run_id
            FROM assessment_proof_receipts AS receipts
            LEFT JOIN assessment_artifacts AS artifacts
              ON artifacts.id = receipts.artifact_id
            WHERE receipts.id IN ({placeholders})
            """,
            tuple(receipt_ids),
        ).fetchall()
        if signal_kind in {"reproducible_crash", "sanitizer_violation"} and not any(
            str(row["evidence_kind"]) == "command"
            and row["command_run_id"] == command_run_id
            for row in receipt_rows
        ):
            raise HTTPException(
                status_code=400,
                detail="tool signal proof must bind the exact command run",
            )
        has_exact_command_proof = any(
            str(row["evidence_kind"]) == "command"
            and row["command_run_id"] == command_run_id
            for row in receipt_rows
        )
        has_oob_proof = any(
            str(row["evidence_kind"]) == "oob_event"
            and row["artifact_command_run_id"] == command_run_id
            for row in receipt_rows
        )
        if signal_kind == "attributed_oob_callback" and not (
            has_exact_command_proof and has_oob_proof
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "attributed OOB signals require both an oob_event proof and "
                    "a command proof bound to the exact command run"
                ),
            )
        # Command/source row ids remain on the signal and proof records. The
        # candidate digest uses their stable content identity so independent
        # scans can classify an exact repeat as persisting.
        candidate_identity = "candidate:v1:" + _sha256(
            {
                "signal_identity_key": identity_key,
                "signal_kind": signal_kind,
                "target_key": target_key,
                "source": source_identity,
                "source_anchor": source_anchor,
                "observed_signature": observed_signature,
                "exact_input_sha256": exact_input_sha256,
            }
        )
        signal_record = {
            "identity_key": identity_key,
            "signal_kind": signal_kind,
            "dispatch_id": int(dispatch["id"]),
            "target_key": target_key,
            "source_id": source_id,
            "source_anchor": source_anchor,
            "vulnerability_family": vulnerability_family,
            "hypothesis": hypothesis,
            "observed_signature": observed_signature,
            "exact_input_sha256": exact_input_sha256,
            "command_run_id": command_run_id,
            "proof_receipt_ids": receipt_ids,
            "candidate_identity_key": candidate_identity,
        }
        record_sha256 = _sha256(signal_record)
        existing = connection.execute(
            "SELECT * FROM assessment_run_tool_signals WHERE run_id = ? AND identity_key = ?",
            (run_id, identity_key),
        ).fetchone()
        if existing is not None:
            if str(existing["record_sha256"]) != record_sha256:
                raise HTTPException(
                    status_code=409,
                    detail="tool signal identity already has different content",
                )
            return _serialize_tool_signal(existing)
        existing_candidate = connection.execute(
            "SELECT * FROM assessment_run_candidates WHERE run_id = ? AND identity_key = ?",
            (run_id, candidate_identity),
        ).fetchone()
        if existing_candidate is not None:
            raise HTTPException(
                status_code=409,
                detail="automatic candidate identity already exists without this signal receipt",
            )
        candidate_record = {
            "identity_key": candidate_identity,
            "target_key": target_key,
            "source_id": source_id,
            "source_anchor": source_anchor,
            "vulnerability_family": vulnerability_family,
            "hypothesis": hypothesis,
            "originating_result_id": None,
            "originating_signal_id": None,
            "dispatch_id": int(dispatch["id"]),
            "proof_receipt_ids": receipt_ids,
            "state": "open",
            "finding_slug": "",
        }
        candidate_cursor = connection.execute(
            """
            INSERT INTO assessment_run_candidates (
                engagement_id, run_id, identity_key, target_key, source_id,
                source_anchor, vulnerability_family, hypothesis,
                originating_result_id, originating_signal_id, dispatch_id,
                proof_receipt_ids_json, state, finding_slug, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 'open', '', ?)
            """,
            (
                engagement.id,
                run_id,
                candidate_identity,
                target_key,
                source_id,
                source_anchor,
                vulnerability_family,
                hypothesis,
                int(dispatch["id"]),
                _json_text(receipt_ids),
                _sha256(candidate_record),
            ),
        )
        candidate_id = int(candidate_cursor.lastrowid)
        signal_cursor = connection.execute(
            """
            INSERT INTO assessment_run_tool_signals (
                engagement_id, run_id, identity_key, signal_kind, dispatch_id,
                target_key, source_id, source_anchor, vulnerability_family,
                hypothesis, observed_signature, exact_input_sha256,
                command_run_id, proof_receipt_ids_json, candidate_id, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                run_id,
                identity_key,
                signal_kind,
                int(dispatch["id"]),
                target_key,
                source_id,
                source_anchor,
                vulnerability_family,
                hypothesis,
                observed_signature,
                exact_input_sha256,
                command_run_id,
                _json_text(receipt_ids),
                candidate_id,
                record_sha256,
            ),
        )
        signal_id = int(signal_cursor.lastrowid)
        candidate_record["originating_signal_id"] = signal_id
        connection.execute(
            """
            UPDATE assessment_run_candidates
            SET originating_signal_id = ?, record_sha256 = ? WHERE id = ?
            """,
            (signal_id, _sha256(candidate_record), candidate_id),
        )
        connection.execute(
            """
            INSERT INTO assessment_run_candidate_events (
                engagement_id, run_id, candidate_id, from_state, to_state,
                reason, proof_receipt_ids_json
            ) VALUES (?, ?, ?, NULL, 'open', ?, ?)
            """,
            (
                engagement.id,
                run_id,
                candidate_id,
                f"created from typed tool signal {signal_kind}",
                _json_text(receipt_ids),
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_run_tool_signals WHERE id = ?", (signal_id,)
        ).fetchone()
        assert row is not None
        return _serialize_tool_signal(row)


def list_run_tool_signals(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_tool_signals",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_tool_signal(row) for row in page["items"]]
        return page


def _serialize_discovery_pass(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    record["candidate_identity_keys"] = _json_value(
        record.pop("candidate_identity_keys_json"), []
    )
    record["proof_receipt_ids"] = _json_value(
        record.pop("proof_receipt_ids_json"), []
    )
    return record


def record_run_discovery_pass(
    engagement_id: int,
    *,
    run_id: int,
    identity_key: str,
    dispatch_agent_id: str,
    frontier_identity_sha256: str,
    terminal_reason: str,
    candidate_identity_keys: list[str],
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if terminal_reason not in DISCOVERY_TERMINAL_REASONS:
        raise _invalid(
            "discovery terminal reason", terminal_reason, DISCOVERY_TERMINAL_REASONS
        )
    frontier_identity_sha256 = frontier_identity_sha256.strip().lower()
    if len(frontier_identity_sha256) != 64 or any(
        character not in "0123456789abcdef"
        for character in frontier_identity_sha256
    ):
        raise HTTPException(status_code=400, detail="invalid frontier identity SHA-256")
    if candidate_identity_keys != sorted(set(candidate_identity_keys)):
        raise HTTPException(
            status_code=400,
            detail="candidate_identity_keys must be sorted and unique",
        )
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="discovery pass writes")
        dispatch = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, dispatch_agent_id),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(status_code=404, detail="discovery dispatch not found")
        receipt_ids = _validate_receipt_ids(
            connection, engagement.id, run_id, proof_receipt_ids
        )
        if not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail="discovery passes require durable evidence rather than self-attestation",
            )
        if not _discovery_receipts_match_dispatch(
            connection,
            engagement.id,
            dispatch_id=int(dispatch["id"]),
            dispatch_agent_id=dispatch_agent_id,
            receipt_ids=receipt_ids,
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "discovery pass proof must be healthy durable evidence "
                    "attributable to the discovery dispatch"
                ),
            )
        if candidate_identity_keys:
            placeholders = ",".join("?" for _ in candidate_identity_keys)
            rows = connection.execute(
                f"""
                SELECT identity_key FROM assessment_run_candidates
                WHERE engagement_id = ? AND run_id = ?
                  AND identity_key IN ({placeholders})
                """,
                (engagement.id, run_id, *candidate_identity_keys),
            ).fetchall()
            if {str(row["identity_key"]) for row in rows} != set(
                candidate_identity_keys
            ):
                raise HTTPException(
                    status_code=400,
                    detail="discovery pass candidates must exist in the same run",
                )
        caller_record = {
            "identity_key": identity_key,
            "dispatch_id": int(dispatch["id"]),
            "frontier_identity_sha256": frontier_identity_sha256,
            "terminal_reason": terminal_reason,
            "candidate_identity_keys": candidate_identity_keys,
            "proof_receipt_ids": receipt_ids,
        }
        existing = connection.execute(
            """
            SELECT * FROM assessment_run_discovery_passes
            WHERE run_id = ? AND identity_key = ?
            """,
            (run_id, identity_key),
        ).fetchone()
        if existing is not None:
            stored_caller_record = {
                "identity_key": str(existing["identity_key"]),
                "dispatch_id": int(existing["dispatch_id"]),
                "frontier_identity_sha256": str(existing["frontier_identity_sha256"]),
                "terminal_reason": str(existing["terminal_reason"]),
                "candidate_identity_keys": _json_value(
                    existing["candidate_identity_keys_json"], []
                ),
                "proof_receipt_ids": _json_value(
                    existing["proof_receipt_ids_json"], []
                ),
            }
            if stored_caller_record != caller_record:
                raise HTTPException(
                    status_code=409,
                    detail="discovery pass identity already has different content",
                )
            return _serialize_discovery_pass(existing)
        previously_observed: set[str] = set()
        for row in connection.execute(
            """
            SELECT candidate_identity_keys_json
            FROM assessment_run_discovery_passes
            WHERE engagement_id = ? AND run_id = ? ORDER BY id
            """,
            (engagement.id, run_id),
        ):
            previously_observed.update(
                str(value)
                for value in _json_value(row["candidate_identity_keys_json"], [])
            )
        candidate_delta = len(set(candidate_identity_keys) - previously_observed)
        record = {
            "identity_key": identity_key,
            "dispatch_id": int(dispatch["id"]),
            "frontier_identity_sha256": frontier_identity_sha256,
            "terminal_reason": terminal_reason,
            "candidate_identity_keys": candidate_identity_keys,
            "candidate_delta": candidate_delta,
            "proof_receipt_ids": receipt_ids,
        }
        record_sha256 = _sha256(record)
        cursor = connection.execute(
            """
            INSERT INTO assessment_run_discovery_passes (
                engagement_id, run_id, identity_key, dispatch_id,
                frontier_identity_sha256, terminal_reason,
                candidate_identity_keys_json, candidate_delta,
                proof_receipt_ids_json, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                run_id,
                identity_key,
                int(dispatch["id"]),
                frontier_identity_sha256,
                terminal_reason,
                _json_text(candidate_identity_keys),
                candidate_delta,
                _json_text(receipt_ids),
                record_sha256,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_run_discovery_passes WHERE id = ?",
            (int(cursor.lastrowid),),
        ).fetchone()
        assert row is not None
        return _serialize_discovery_pass(row)


def list_run_discovery_passes(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_discovery_passes",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_discovery_pass(row) for row in page["items"]]
        return page


def _serialize_code_receipt_link(
    row: sqlite3.Row | dict[str, Any]
) -> dict[str, Any]:
    record = dict(row)
    for field in ("candidate_ids", "signal_ids", "proof_receipt_ids"):
        record[field] = _json_value(record.pop(f"{field}_json"), [])
    return record


def record_run_code_receipt_link(
    engagement_id: int,
    *,
    run_id: int,
    receipt_kind: str,
    receipt_id: int,
    target_key: str,
    obligation_id: int,
    candidate_ids: list[int],
    signal_ids: list[int],
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    """Connect existing code truth to run debt without duplicating that truth."""

    engagement = _engagement_or_404(engagement_id)
    if receipt_kind not in CODE_RECEIPT_KINDS:
        raise _invalid("code receipt kind", receipt_kind, CODE_RECEIPT_KINDS)
    candidate_ids = _positive_int_list(candidate_ids)
    signal_ids = _positive_int_list(signal_ids)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="code receipt accounting")
        receipt = connection.execute(
            f"SELECT * FROM {_CODE_RECEIPT_TABLES[receipt_kind]} WHERE engagement_id = ? AND id = ?",
            (engagement.id, receipt_id),
        ).fetchone()
        if receipt is None:
            raise HTTPException(status_code=404, detail="code receipt not found")
        repository = connection.execute(
            """
            SELECT repo_key FROM code_repos
            WHERE engagement_id = ? AND id = ?
            """,
            (engagement.id, int(receipt["repo_id"])),
        ).fetchone()
        if repository is None:
            raise HTTPException(
                status_code=409,
                detail="code receipt repository identity is unavailable",
            )
        source_generation = _exact_run_source_generation(run, target_key=target_key)
        if (
            str(repository["repo_key"]) != target_key
            or int(source_generation.get("generation", -1))
            != int(receipt["repo_generation"])
            or str(source_generation.get("manifest_digest") or "")
            != str(receipt["source_manifest_digest"])
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "code receipt does not match the run's exact repository "
                    "generation and source manifest"
                ),
            )
        obligation = connection.execute(
            """
            SELECT * FROM assessment_run_obligations
            WHERE engagement_id = ? AND run_id = ? AND id = ?
            """,
            (engagement.id, run_id, obligation_id),
        ).fetchone()
        if obligation is None:
            raise HTTPException(status_code=404, detail="run obligation not found")
        if str(obligation["obligation_kind"]) not in _CODE_RECEIPT_OBLIGATION_KINDS[
            receipt_kind
        ]:
            raise HTTPException(
                status_code=409,
                detail="code receipt kind does not match the linked obligation",
            )
        expected_object_key = target_key
        if receipt_kind == "variant_check":
            expected_object_key = f"{target_key}:{receipt['file_path']}"
            run_source = connection.execute(
                """
                SELECT id FROM assessment_run_sources
                WHERE engagement_id = ? AND run_id = ? AND target_key = ?
                  AND path = ? AND content_sha256 = ?
                  AND inventory_status = 'included'
                """,
                (
                    engagement.id,
                    run_id,
                    target_key,
                    str(receipt["file_path"]),
                    str(receipt["file_sha256"]),
                ),
            ).fetchone()
            if run_source is None:
                raise HTTPException(
                    status_code=409,
                    detail="variant receipt does not match an exact included run source",
                )
            if receipt["current_file_id"] is not None:
                current_file = connection.execute(
                    """
                    SELECT id FROM code_files
                    WHERE engagement_id = ? AND repo_id = ? AND id = ?
                      AND file_path = ? AND file_hash = ?
                    """,
                    (
                        engagement.id,
                        int(receipt["repo_id"]),
                        int(receipt["current_file_id"]),
                        str(receipt["file_path"]),
                        str(receipt["file_sha256"]),
                    ),
                ).fetchone()
                if current_file is None:
                    raise HTTPException(
                        status_code=409,
                        detail="variant receipt current file identity is stale",
                    )
        elif receipt_kind == "fuzz_campaign":
            expected_object_key = f"{target_key}:{receipt['target_id']}"
        if str(obligation["object_key"]) != expected_object_key:
            raise HTTPException(
                status_code=409,
                detail="code receipt does not match the exact obligation object",
            )
        receipt_ids = _validate_receipt_ids(
            connection, engagement.id, run_id, proof_receipt_ids
        )
        if not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail="code receipt accounting requires shared durable proof receipts",
            )
        if not _code_receipt_has_exact_artifact_proof(
            connection,
            engagement.id,
            receipt_kind=receipt_kind,
            receipt=receipt,
            proof_receipt_ids=receipt_ids,
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "code receipt accounting requires healthy artifact proof matching "
                    "the receipt evidence path and digest"
                ),
            )
        if candidate_ids:
            placeholders = ",".join("?" for _ in candidate_ids)
            rows = connection.execute(
                f"""
                SELECT id, target_key FROM assessment_run_candidates
                WHERE engagement_id = ? AND run_id = ? AND id IN ({placeholders})
                """,
                (engagement.id, run_id, *candidate_ids),
            ).fetchall()
            if {int(row["id"]) for row in rows} != set(candidate_ids):
                raise HTTPException(
                    status_code=400,
                    detail="linked candidates must belong to the same run",
                )
            if any(str(row["target_key"]) != target_key for row in rows):
                raise HTTPException(
                    status_code=409,
                    detail="linked candidates must match the code receipt target",
                )
        signal_rows: list[sqlite3.Row] = []
        if signal_ids:
            placeholders = ",".join("?" for _ in signal_ids)
            signal_rows = connection.execute(
                f"""
                SELECT id, signal_kind, candidate_id, target_key
                FROM assessment_run_tool_signals
                WHERE engagement_id = ? AND run_id = ? AND id IN ({placeholders})
                """,
                (engagement.id, run_id, *signal_ids),
            ).fetchall()
            if {int(row["id"]) for row in signal_rows} != set(signal_ids):
                raise HTTPException(
                    status_code=400,
                    detail="linked tool signals must belong to the same run",
                )
            if any(str(row["target_key"]) != target_key for row in signal_rows):
                raise HTTPException(
                    status_code=409,
                    detail="linked tool signals must match the code receipt target",
                )
            signal_candidates = {int(row["candidate_id"]) for row in signal_rows}
            if not signal_candidates.issubset(set(candidate_ids)):
                raise HTTPException(
                    status_code=400,
                    detail="every linked tool signal candidate must be retained",
                )
        obligation_status = "resolved"
        if receipt_kind == "variant_check" and str(receipt["status"]) != "completed":
            raise HTTPException(status_code=409, detail="variant receipt is not complete")
        if receipt_kind == "fuzz_campaign":
            outcome = str(receipt["outcome"])
            crash_count = int(receipt["crash_count"])
            crash_signals = sum(
                str(row["signal_kind"]) == "reproducible_crash"
                for row in signal_rows
            )
            if outcome == "completed_crashes_triaged" and crash_signals != crash_count:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "every fuzz crash must link its own reproducible-crash signal "
                        "and automatic candidate"
                    ),
                )
            if outcome == "completed_no_crash" and signal_ids:
                raise HTTPException(
                    status_code=409,
                    detail="a no-crash campaign cannot discard linked tool signals",
                )
            if outcome not in {"completed_no_crash", "completed_crashes_triaged"}:
                obligation_status = "blocked"
        record = {
            "receipt_kind": receipt_kind,
            "receipt_id": receipt_id,
            "target_key": target_key,
            "obligation_id": obligation_id,
            "candidate_ids": candidate_ids,
            "signal_ids": signal_ids,
            "proof_receipt_ids": receipt_ids,
            "obligation_status": obligation_status,
        }
        record_sha256 = _sha256(record)
        existing = connection.execute(
            """
            SELECT * FROM assessment_run_code_receipt_links
            WHERE run_id = ? AND receipt_kind = ? AND receipt_id = ?
              AND obligation_id = ?
            """,
            (run_id, receipt_kind, receipt_id, obligation_id),
        ).fetchone()
        if existing is not None:
            if str(existing["record_sha256"]) != record_sha256:
                raise HTTPException(
                    status_code=409,
                    detail="code receipt accounting retry has different content",
                )
            return _serialize_code_receipt_link(existing)
        current_obligation_status = str(obligation["status"])
        if current_obligation_status in {"resolved", "accepted_gap"}:
            raise HTTPException(
                status_code=409,
                detail="code receipt cannot rewrite a closed obligation",
            )
        resolution = (
            f"{receipt_kind} receipt {receipt_id} linked with shared proof"
        )
        obligation_record = {
            "identity_key": str(obligation["identity_key"]),
            "obligation_kind": str(obligation["obligation_kind"]),
            "object_type": str(obligation["object_type"]),
            "object_key": str(obligation["object_key"]),
            "hard": bool(obligation["hard"]),
            "status": obligation_status,
            "resolution": resolution,
            "proof_receipt_ids": receipt_ids,
        }
        connection.execute(
            """
            UPDATE assessment_run_obligations
            SET status = ?, resolution = ?, proof_receipt_ids_json = ?,
                record_sha256 = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                obligation_status,
                resolution,
                _json_text(receipt_ids),
                _sha256(obligation_record),
                obligation_id,
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
                obligation_id,
                current_obligation_status,
                obligation_status,
                resolution,
                _json_text(receipt_ids),
            ),
        )
        cursor = connection.execute(
            """
            INSERT INTO assessment_run_code_receipt_links (
                engagement_id, run_id, receipt_kind, receipt_id, target_key,
                obligation_id,
                candidate_ids_json, signal_ids_json, proof_receipt_ids_json,
                obligation_status, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                run_id,
                receipt_kind,
                receipt_id,
                target_key,
                obligation_id,
                _json_text(candidate_ids),
                _json_text(signal_ids),
                _json_text(receipt_ids),
                obligation_status,
                record_sha256,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_run_code_receipt_links WHERE id = ?",
            (int(cursor.lastrowid),),
        ).fetchone()
        assert row is not None
        return _serialize_code_receipt_link(row)


def list_run_code_receipt_links(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_code_receipt_links",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_code_receipt_link(row) for row in page["items"]]
        return page


def list_run_decision_history(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    """Page obligation and candidate transition history across recovery lineage."""

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        lineage_ids = _run_lineage_ids(connection, run_id)
        placeholders = ",".join("?" for _ in lineage_ids)
        decision_query = f"""
            SELECT 'obligation' AS object_type,
                   events.obligation_id AS object_id,
                   events.id AS event_id,
                   events.run_id AS origin_run_id,
                   events.from_status AS from_status,
                   events.to_status AS to_status,
                   events.resolution AS detail,
                   events.proof_receipt_ids_json AS proof_receipt_ids_json,
                   events.created_at AS created_at
            FROM assessment_run_obligation_events AS events
            WHERE events.engagement_id = ? AND events.run_id IN ({placeholders})
            UNION ALL
            SELECT 'candidate' AS object_type,
                   events.candidate_id AS object_id,
                   events.id AS event_id,
                   events.run_id AS origin_run_id,
                   events.from_state AS from_status,
                   events.to_state AS to_status,
                   events.reason AS detail,
                   events.proof_receipt_ids_json AS proof_receipt_ids_json,
                   events.created_at AS created_at
            FROM assessment_run_candidate_events AS events
            WHERE events.engagement_id = ? AND events.run_id IN ({placeholders})
        """
        query_params = (engagement.id, *lineage_ids, engagement.id, *lineage_ids)
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM ({decision_query})", query_params
            ).fetchone()[0]
        )
        rows = connection.execute(
            f"""
            SELECT * FROM ({decision_query})
            ORDER BY created_at, origin_run_id, object_type, event_id
            LIMIT ? OFFSET ?
            """,
            (*query_params, limit, offset),
        ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            record["id"] = f"{record['object_type']}:{record.pop('event_id')}"
            record["audit_run_id"] = run_id
            record["proof_receipt_ids"] = _json_value(
                record.pop("proof_receipt_ids_json"), []
            )
            items.append(record)
        return {
            "items": items,
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(items) < total,
        }
