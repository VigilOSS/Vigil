"""Assessment-run source inventory and obligation state.

Inventory, source-read, dispatch, and debt records share the active-run gate.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import HTTPException

from . import _common
from ._common import _engagement_or_404
from .run_accounting import (
    INVENTORY_STATUSES,
    OBLIGATION_STATUSES,
    PARSER_STATUSES,
    _invalid,
    _json_text,
    _json_value,
    _page,
    _require_active_run,
    _run_lineage_ids,
    _run_or_404,
    _sha256,
    _validate_receipt_ids,
)


def _insert_obligation(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    identity_key: str,
    obligation_kind: str,
    object_type: str,
    object_key: str,
    hard: bool,
    status_value: str,
    resolution: str,
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    record = {
        "identity_key": identity_key,
        "obligation_kind": obligation_kind,
        "object_type": object_type,
        "object_key": object_key,
        "hard": bool(hard),
        "status": status_value,
        "resolution": resolution,
        "proof_receipt_ids": proof_receipt_ids,
    }
    record_sha256 = _sha256(record)
    existing = connection.execute(
        "SELECT * FROM assessment_run_obligations WHERE run_id = ? AND identity_key = ?",
        (run_id, identity_key),
    ).fetchone()
    if existing is not None:
        if str(existing["record_sha256"]) != record_sha256:
            raise HTTPException(status_code=409, detail="obligation identity already has different content")
        return _serialize_obligation(existing)
    cursor = connection.execute(
        """
        INSERT INTO assessment_run_obligations (
            engagement_id, run_id, identity_key, obligation_kind,
            object_type, object_key, hard, status, resolution,
            proof_receipt_ids_json, record_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            run_id,
            identity_key,
            obligation_kind,
            object_type,
            object_key,
            int(hard),
            status_value,
            resolution,
            _json_text(proof_receipt_ids),
            record_sha256,
        ),
    )
    row = connection.execute(
        "SELECT * FROM assessment_run_obligations WHERE id = ?", (int(cursor.lastrowid),)
    ).fetchone()
    assert row is not None
    connection.execute(
        """
        INSERT INTO assessment_run_obligation_events (
            engagement_id, run_id, obligation_id, from_status,
            to_status, resolution, proof_receipt_ids_json
        ) VALUES (?, ?, ?, NULL, ?, ?, ?)
        """,
        (
            engagement_id,
            run_id,
            int(row["id"]),
            status_value,
            resolution,
            _json_text(proof_receipt_ids),
        ),
    )
    return _serialize_obligation(row)


def _serialize_obligation(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    record["hard"] = bool(record["hard"])
    record["proof_receipt_ids"] = _json_value(record.pop("proof_receipt_ids_json"), [])
    return record


def record_run_sources(
    engagement_id: int, *, run_id: int, sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if not sources:
        raise HTTPException(status_code=400, detail="sources must contain at least one inventory row")
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="source inventory writes")
        results: list[dict[str, Any]] = []
        for source in sources:
            inventory_status = str(source["inventory_status"])
            parser_status = str(source["parser_status"])
            if inventory_status not in INVENTORY_STATUSES:
                raise _invalid("inventory_status", inventory_status, INVENTORY_STATUSES)
            if parser_status not in PARSER_STATUSES:
                raise _invalid("parser_status", parser_status, PARSER_STATUSES)
            content_sha256 = str(source["content_sha256"]).lower()
            if len(content_sha256) != 64 or any(c not in "0123456789abcdef" for c in content_sha256):
                raise HTTPException(status_code=400, detail="content_sha256 must be lowercase SHA-256")
            record = {
                "target_key": str(source["target_key"]),
                "declared_root": str(source["declared_root"]),
                "path": str(source["path"]),
                "content_sha256": content_sha256,
                "byte_size": int(source["byte_size"]),
                "line_count": int(source["line_count"]),
                "encoding": str(source["encoding"]),
                "inventory_status": inventory_status,
                "exclusion_reason": str(source.get("exclusion_reason") or ""),
                "parser_status": parser_status,
                "parser_error": str(source.get("parser_error") or ""),
            }
            identity_sha256 = _sha256(record)
            existing = connection.execute(
                """
                SELECT * FROM assessment_run_sources
                WHERE run_id = ? AND target_key = ? AND declared_root = ? AND path = ?
                """,
                (run_id, record["target_key"], record["declared_root"], record["path"]),
            ).fetchone()
            if existing is not None:
                if str(existing["identity_sha256"]) != identity_sha256:
                    raise HTTPException(status_code=409, detail="source inventory identity changed within run")
                results.append(dict(existing))
                continue
            cursor = connection.execute(
                """
                INSERT INTO assessment_run_sources (
                    engagement_id, run_id, target_key, declared_root, path,
                    content_sha256, byte_size, line_count, encoding,
                    inventory_status, exclusion_reason, parser_status,
                    parser_error, identity_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    run_id,
                    record["target_key"],
                    record["declared_root"],
                    record["path"],
                    record["content_sha256"],
                    record["byte_size"],
                    record["line_count"],
                    record["encoding"],
                    inventory_status,
                    record["exclusion_reason"],
                    parser_status,
                    record["parser_error"],
                    identity_sha256,
                ),
            )
            source_id = int(cursor.lastrowid)
            object_key = f"{record['target_key']}:{record['path']}"
            if inventory_status == "included":
                _insert_obligation(
                    connection,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    identity_key=f"source_read:{source_id}",
                    obligation_kind="source_read",
                    object_type="source",
                    object_key=object_key,
                    hard=True,
                    status_value="open",
                    resolution="",
                    proof_receipt_ids=[],
                )
            if parser_status == "failed":
                _insert_obligation(
                    connection,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    identity_key=f"manual_enumeration:{source_id}",
                    obligation_kind="manual_enumeration",
                    object_type="source",
                    object_key=object_key,
                    hard=True,
                    status_value="open",
                    resolution=record["parser_error"],
                    proof_receipt_ids=[],
                )
            if inventory_status == "missing":
                _insert_obligation(
                    connection,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    identity_key=f"missing_dependency:{source_id}",
                    obligation_kind="missing_dependency",
                    object_type="source",
                    object_key=object_key,
                    hard=True,
                    status_value="blocked",
                    resolution=record["exclusion_reason"],
                    proof_receipt_ids=[],
                )
            row = connection.execute(
                "SELECT * FROM assessment_run_sources WHERE id = ?", (source_id,)
            ).fetchone()
            assert row is not None
            results.append(dict(row))
        return results


def list_run_sources(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        return _page(
            connection,
            table="assessment_run_sources",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
            order_by="target_key, declared_root, path, id",
        )


def _source_fully_read(
    connection: sqlite3.Connection, run_id: int, source_id: int, byte_size: int
) -> bool:
    if byte_size == 0:
        return True
    rows = connection.execute(
        """
        SELECT byte_start, byte_end FROM assessment_run_source_reads
        WHERE run_id = ? AND source_id = ? ORDER BY byte_start, byte_end
        """,
        (run_id, source_id),
    ).fetchall()
    covered_end = 0
    for row in rows:
        start = int(row["byte_start"])
        end = int(row["byte_end"])
        if start > covered_end:
            return False
        covered_end = max(covered_end, end)
        if covered_end >= byte_size:
            return True
    return False


def record_source_read(
    engagement_id: int,
    *,
    run_id: int,
    source_id: int,
    dispatch_agent_id: str,
    attempt: int,
    byte_start: int,
    byte_end: int,
    line_start: int,
    line_end: int,
    proof_receipt_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="source-read writes")
        source = connection.execute(
            "SELECT * FROM assessment_run_sources WHERE engagement_id = ? AND run_id = ? AND id = ?",
            (engagement.id, run_id, source_id),
        ).fetchone()
        if source is None:
            raise HTTPException(status_code=404, detail="run source not found")
        if str(source["inventory_status"]) != "included":
            raise HTTPException(status_code=409, detail="only included sources can be read")
        size = int(source["byte_size"])
        if not (0 <= byte_start <= byte_end <= size):
            raise HTTPException(status_code=400, detail="source read byte range is outside inventory size")
        line_count = max(1, int(source["line_count"]))
        if not (
            attempt >= 1
            and 1 <= line_start <= line_end <= line_count
        ):
            raise HTTPException(status_code=400, detail="invalid source read attempt or line range")
        dispatch = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, dispatch_agent_id),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(status_code=404, detail="source-read dispatch not found")
        if proof_receipt_id is not None:
            _validate_receipt_ids(connection, engagement.id, run_id, [proof_receipt_id])
        fingerprint_payload = {
            "source_id": source_id,
            "source_sha256": str(source["content_sha256"]),
            "dispatch_id": int(dispatch["id"]),
            "attempt": attempt,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "line_start": line_start,
            "line_end": line_end,
            "proof_receipt_id": proof_receipt_id,
        }
        fingerprint = _sha256(fingerprint_payload)
        existing = connection.execute(
            "SELECT * FROM assessment_run_source_reads WHERE run_id = ? AND read_fingerprint = ?",
            (run_id, fingerprint),
        ).fetchone()
        if existing is None:
            cursor = connection.execute(
                """
                INSERT INTO assessment_run_source_reads (
                    engagement_id, run_id, source_id, dispatch_id, attempt,
                    byte_start, byte_end, line_start, line_end,
                    proof_receipt_id, read_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    run_id,
                    source_id,
                    int(dispatch["id"]),
                    attempt,
                    byte_start,
                    byte_end,
                    line_start,
                    line_end,
                    proof_receipt_id,
                    fingerprint,
                ),
            )
            existing = connection.execute(
                "SELECT * FROM assessment_run_source_reads WHERE id = ?", (int(cursor.lastrowid),)
            ).fetchone()
        assert existing is not None
        if _source_fully_read(connection, run_id, source_id, size):
            obligation = connection.execute(
                """
                SELECT * FROM assessment_run_obligations
                WHERE run_id = ? AND identity_key = ? AND status = 'open'
                """,
                (run_id, f"source_read:{source_id}"),
            ).fetchone()
            if obligation is not None:
                resolution = "complete observed byte coverage"
                obligation_record = {
                    "identity_key": str(obligation["identity_key"]),
                    "obligation_kind": str(obligation["obligation_kind"]),
                    "object_type": str(obligation["object_type"]),
                    "object_key": str(obligation["object_key"]),
                    "hard": bool(obligation["hard"]),
                    "status": "resolved",
                    "resolution": resolution,
                    "proof_receipt_ids": _json_value(
                        obligation["proof_receipt_ids_json"], []
                    ),
                }
                connection.execute(
                    """
                    UPDATE assessment_run_obligations
                    SET status = 'resolved', resolution = 'complete observed byte coverage',
                        record_sha256 = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (_sha256(obligation_record), int(obligation["id"])),
                )
                connection.execute(
                    """
                    INSERT INTO assessment_run_obligation_events (
                        engagement_id, run_id, obligation_id, from_status,
                        to_status, resolution, proof_receipt_ids_json
                    ) VALUES (?, ?, ?, 'open', 'resolved',
                              'complete observed byte coverage', '[]')
                    """,
                    (engagement.id, run_id, int(obligation["id"])),
                )
        record = dict(existing)
        record["source_sha256"] = str(source["content_sha256"])
        record["source_path"] = str(source["path"])
        record["target_key"] = str(source["target_key"])
        record["encoding"] = str(source["encoding"])
        record["dispatch_agent_id"] = dispatch_agent_id
        return record


def list_source_reads(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        total = int(
            connection.execute(
                "SELECT COUNT(*) FROM assessment_run_source_reads WHERE engagement_id = ? AND run_id = ?",
                (engagement.id, run_id),
            ).fetchone()[0]
        )
        rows = connection.execute(
            """
            SELECT reads.*, sources.target_key, sources.path AS source_path,
                   sources.content_sha256 AS source_sha256, sources.encoding,
                   dispatches.agent_id AS dispatch_agent_id
            FROM assessment_run_source_reads AS reads
            JOIN assessment_run_sources AS sources ON sources.id = reads.source_id
            JOIN assessment_dispatches AS dispatches ON dispatches.id = reads.dispatch_id
            WHERE reads.engagement_id = ? AND reads.run_id = ?
            ORDER BY reads.id LIMIT ? OFFSET ?
            """,
            (engagement.id, run_id, limit, offset),
        ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < total,
        }


def _serialize_linked_dispatch(row: sqlite3.Row) -> dict[str, Any]:
    """The one dispatch shape, plus this listing's tri-state staleness flag.

    The projection and the serializer are the dispatch module's — a second
    hand-rolled dispatch record here would report every specialist as unbound
    and leak the retired legacy columns. Only ``instructions_stale`` is narrowed:
    "not known" is a real answer for a run's linked dispatch, so it stays a
    tri-state bool rather than the stored integer.
    """
    from .dispatches import _serialize_dispatch

    record = _serialize_dispatch(row)
    stale = record.get("instructions_stale")
    record["instructions_stale"] = bool(stale) if stale is not None else None
    return record


def list_run_dispatches(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    """List every dispatch referenced by a run and its recovery lineage."""

    # Local import: `dispatches` reaches `findings`, which reaches this module —
    # the same cycle break `depth_ledger` takes for the sibling dispatch
    # serializer.
    from .dispatches import _DISPATCH_SELECT

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        lineage_ids = _run_lineage_ids(connection, run_id)
        placeholders = ",".join("?" for _ in lineage_ids)
        dispatch_ids = {
            int(row["dispatch_id"])
            for row in connection.execute(
                f"""
                SELECT DISTINCT producer_dispatch_id AS dispatch_id
                FROM assessment_runs
                WHERE engagement_id = ? AND id IN ({placeholders})
                """,
                (engagement.id, *lineage_ids),
            ).fetchall()
        }
        for table, column in (
            ("assessment_run_source_reads", "dispatch_id"),
            ("assessment_run_candidates", "dispatch_id"),
            ("assessment_proof_receipts", "producer_dispatch_id"),
            ("assessment_run_discovery_passes", "dispatch_id"),
            ("assessment_run_tool_signals", "dispatch_id"),
        ):
            rows = connection.execute(
                f"""
                SELECT DISTINCT {column} AS dispatch_id FROM {table}
                WHERE engagement_id = ? AND run_id IN ({placeholders})
                """,
                (engagement.id, *lineage_ids),
            ).fetchall()
            dispatch_ids.update(int(row["dispatch_id"]) for row in rows)
        ordered_ids = sorted(dispatch_ids)
        page_ids = ordered_ids[offset : offset + limit]
        rows: list[sqlite3.Row] = []
        if page_ids:
            page_placeholders = ",".join("?" for _ in page_ids)
            rows = connection.execute(
                f"{_DISPATCH_SELECT} "
                f"WHERE d.engagement_id = ? AND d.id IN ({page_placeholders}) "
                "ORDER BY d.id",
                (engagement.id, *page_ids),
            ).fetchall()
        return {
            "items": [_serialize_linked_dispatch(row) for row in rows],
            "total": len(ordered_ids),
            "offset": offset,
            "limit": limit,
            "has_more": offset + len(rows) < len(ordered_ids),
        }


def record_run_obligation(
    engagement_id: int,
    *,
    run_id: int,
    identity_key: str,
    obligation_kind: str,
    object_type: str,
    object_key: str,
    hard: bool,
    status_value: str,
    resolution: str,
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    status_value = str(status_value)
    if status_value not in OBLIGATION_STATUSES:
        raise _invalid("obligation status", status_value, OBLIGATION_STATUSES)
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="obligation writes")
        receipt_ids = _validate_receipt_ids(
            connection, engagement.id, run_id, proof_receipt_ids
        )
        if status_value in {"resolved", "accepted_gap"} and not resolution.strip():
            raise HTTPException(status_code=400, detail="closed obligation requires a resolution")
        if hard and status_value == "resolved" and not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail=(
                    "hard obligation resolution requires proof receipts; "
                    "free-text resolution alone is not evidence"
                ),
            )
        return _insert_obligation(
            connection,
            engagement_id=engagement.id,
            run_id=run_id,
            identity_key=str(identity_key),
            obligation_kind=str(obligation_kind),
            object_type=str(object_type),
            object_key=str(object_key),
            hard=hard,
            status_value=status_value,
            resolution=str(resolution or ""),
            proof_receipt_ids=receipt_ids,
        )


def list_run_obligations(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_obligations",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_obligation(row) for row in page["items"]]
        return page


def update_run_obligation(
    engagement_id: int,
    *,
    run_id: int,
    obligation_id: int,
    status_value: str,
    resolution: str,
    proof_receipt_ids: list[int],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if status_value not in OBLIGATION_STATUSES - {"open"}:
        raise _invalid("obligation status", status_value, OBLIGATION_STATUSES - {"open"})
    if status_value in {"resolved", "accepted_gap"} and not resolution.strip():
        raise HTTPException(status_code=400, detail="closed obligation requires a resolution")
    with _common.get_connection() as connection:
        run = _run_or_404(connection, engagement.id, run_id)
        _require_active_run(run, operation="obligation updates")
        receipt_ids = _validate_receipt_ids(connection, engagement.id, run_id, proof_receipt_ids)
        existing = connection.execute(
            "SELECT * FROM assessment_run_obligations WHERE engagement_id = ? AND run_id = ? AND id = ?",
            (engagement.id, run_id, obligation_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="run obligation not found")
        if bool(existing["hard"]) and status_value == "resolved" and not receipt_ids:
            raise HTTPException(
                status_code=400,
                detail=(
                    "hard obligation resolution requires proof receipts; "
                    "free-text resolution alone is not evidence"
                ),
            )
        existing_receipt_ids = _json_value(existing["proof_receipt_ids_json"], [])
        if (
            str(existing["status"]) == status_value
            and str(existing["resolution"]) == resolution
            and existing_receipt_ids == receipt_ids
        ):
            return _serialize_obligation(existing)
        if str(existing["status"]) in {"resolved", "accepted_gap"}:
            raise HTTPException(status_code=409, detail="closed obligation status is immutable")
        connection.execute(
            """
            UPDATE assessment_run_obligations
            SET status = ?, resolution = ?, proof_receipt_ids_json = ?,
                record_sha256 = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                status_value,
                resolution,
                _json_text(receipt_ids),
                _sha256(
                    {
                        "identity_key": str(existing["identity_key"]),
                        "obligation_kind": str(existing["obligation_kind"]),
                        "object_type": str(existing["object_type"]),
                        "object_key": str(existing["object_key"]),
                        "hard": bool(existing["hard"]),
                        "status": status_value,
                        "resolution": resolution,
                        "proof_receipt_ids": receipt_ids,
                    }
                ),
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
                existing["status"],
                status_value,
                resolution,
                _json_text(receipt_ids),
            ),
        )
        updated = connection.execute(
            "SELECT * FROM assessment_run_obligations WHERE id = ?", (obligation_id,)
        ).fetchone()
        assert updated is not None
        return _serialize_obligation(updated)


def list_obligation_history(
    engagement_id: int, *, run_id: int, obligation_id: int
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        exists = connection.execute(
            "SELECT id FROM assessment_run_obligations WHERE engagement_id = ? AND run_id = ? AND id = ?",
            (engagement.id, run_id, obligation_id),
        ).fetchone()
        if exists is None:
            raise HTTPException(status_code=404, detail="run obligation not found")
        rows = connection.execute(
            """
            SELECT * FROM assessment_run_obligation_events
            WHERE engagement_id = ? AND run_id = ? AND obligation_id = ? ORDER BY id
            """,
            (engagement.id, run_id, obligation_id),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            record = dict(row)
            record["proof_receipt_ids"] = _json_value(
                record.pop("proof_receipt_ids_json"), []
            )
            result.append(record)
        return result
