"""Assessment-run comparison snapshots.

This module compares terminal run facts without changing run lifecycle state.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import HTTPException

from . import _common
from ._common import _engagement_or_404
from .run_accounting import (
    TERMINAL_RUN_STATUSES,
    _json_text,
    _json_value,
    _page,
    _proof_receipts_are_healthy,
    _run_or_404,
    _sha256,
)


def _inventory_identity(
    connection: sqlite3.Connection, run_id: int
) -> list[tuple[str, str, str, str, str]]:
    return [
        (
            str(row["target_key"]),
            str(row["declared_root"]),
            str(row["path"]),
            str(row["content_sha256"]),
            str(row["inventory_status"]),
        )
        for row in connection.execute(
            """
            SELECT target_key, declared_root, path, content_sha256, inventory_status
            FROM assessment_run_sources WHERE run_id = ?
            ORDER BY target_key, declared_root, path
            """,
            (run_id,),
        ).fetchall()
    ]


def _comparison_inventory_identity(
    connection: sqlite3.Connection, run_id: int
) -> list[tuple[str, str, str, int, str]]:
    """Content identity for comparison; an unchanged file may move paths."""

    return [
        (
            str(row["target_key"]),
            str(row["declared_root"]),
            str(row["content_sha256"]),
            int(row["byte_size"]),
            str(row["inventory_status"]),
        )
        for row in connection.execute(
            """
            SELECT target_key, declared_root, content_sha256, byte_size,
                   inventory_status
            FROM assessment_run_sources WHERE run_id = ?
            ORDER BY target_key, declared_root, content_sha256, byte_size,
                     inventory_status
            """,
            (run_id,),
        ).fetchall()
    ]


def _latest_comparison_baseline(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    run_kind: str,
    run_purpose: str,
    target_identity_json: str,
) -> sqlite3.Row | None:
    # An absent identity is not a shared identity. Treating two empty objects
    # as equal previously made unrelated runs look comparable merely because
    # neither writer supplied the field.
    if not _json_value(target_identity_json, {}):
        return None
    return connection.execute(
        """
        SELECT * FROM assessment_runs
        WHERE engagement_id = ? AND id < ? AND run_kind = ? AND run_purpose = ?
          AND target_identity_json = ? AND status IN ('partial', 'completed')
        ORDER BY id DESC LIMIT 1
        """,
        (
            engagement_id,
            run_id,
            run_kind,
            run_purpose,
            target_identity_json,
        ),
    ).fetchone()


def _comparison_payload(
    connection: sqlite3.Connection,
    *,
    current: sqlite3.Row,
    baseline: sqlite3.Row,
    automatic_baseline: bool,
) -> dict[str, Any]:
    run_id = int(current["id"])
    baseline_run_id = int(baseline["id"])
    same_run_contract = (
        str(current["run_kind"]) == str(baseline["run_kind"])
        and str(current["run_purpose"]) == str(baseline["run_purpose"])
    )
    current_target = _json_value(current["target_identity_json"], {})
    baseline_target = _json_value(baseline["target_identity_json"], {})
    if not same_run_contract:
        target_compatible: bool | None = False
    elif not current_target or not baseline_target:
        target_compatible = None
    else:
        target_compatible = current_target == baseline_target

    current_inventory = _comparison_inventory_identity(connection, run_id)
    baseline_inventory = _comparison_inventory_identity(connection, baseline_run_id)
    if target_compatible is not True:
        source_compatible: bool | None = target_compatible
    elif not current_inventory or not baseline_inventory:
        source_compatible = None
    else:
        source_compatible = current_inventory == baseline_inventory
    current_keys = {
        str(row["identity_key"])
        for row in connection.execute(
            "SELECT identity_key FROM assessment_run_candidates WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    }
    baseline_keys = {
        str(row["identity_key"])
        for row in connection.execute(
            "SELECT identity_key FROM assessment_run_candidates WHERE run_id = ?",
            (baseline_run_id,),
        ).fetchall()
    }
    persisting = sorted(current_keys & baseline_keys)
    new = sorted(current_keys - baseline_keys)
    resolved: list[str] = []
    unknown: list[str] = []
    current_completed = str(current["status"]) == "completed"
    for identity_key in sorted(baseline_keys - current_keys):
        contrary = connection.execute(
            """
            SELECT proof_receipt_ids_json FROM assessment_run_obligations
            WHERE run_id = ? AND obligation_kind = 'candidate_recheck'
              AND object_key = ? AND status = 'resolved'
              AND proof_receipt_ids_json != '[]'
            LIMIT 1
            """,
            (run_id, identity_key),
        ).fetchone()
        receipt_ids = (
            _json_value(contrary["proof_receipt_ids_json"], [])
            if contrary is not None
            else []
        )
        if (
            current_completed
            and source_compatible
            and contrary is not None
            and _proof_receipts_are_healthy(
                connection, int(current["engagement_id"]), receipt_ids
            )
        ):
            resolved.append(identity_key)
        else:
            unknown.append(identity_key)
    return {
        "run_id": run_id,
        "baseline_run_id": baseline_run_id,
        "automatic_baseline": baseline_run_id if automatic_baseline else None,
        "target_compatible": target_compatible,
        "source_compatible": source_compatible,
        "classifications": {
            "new": new,
            "persisting": persisting,
            "resolved": resolved,
            "unknown": unknown,
        },
        "deterministic": True,
    }


def _serialize_comparison(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    record = dict(row)
    payload = _json_value(record.pop("comparison_json"), {})
    return {
        **payload,
        "id": int(record["id"]),
        "selection": str(record["selection"]),
        "comparison_sha256": str(record["comparison_sha256"]),
        "created_at": record["created_at"],
    }


def _record_comparison(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    run_id: int,
    baseline_run_id: int,
    selection: str,
) -> dict[str, Any]:
    current = _run_or_404(connection, engagement_id, run_id)
    baseline = _run_or_404(connection, engagement_id, baseline_run_id)
    if run_id == baseline_run_id:
        raise HTTPException(status_code=400, detail="a run cannot be compared with itself")
    if str(current["status"]) not in TERMINAL_RUN_STATUSES:
        raise HTTPException(status_code=409, detail="only a terminal run comparison can be recorded")
    if str(baseline["status"]) not in TERMINAL_RUN_STATUSES:
        raise HTTPException(status_code=409, detail="comparison baseline must be terminal")
    payload = _comparison_payload(
        connection,
        current=current,
        baseline=baseline,
        automatic_baseline=selection == "automatic",
    )
    comparison_sha256 = _sha256(
        {key: value for key, value in payload.items() if key != "automatic_baseline"}
    )
    existing = connection.execute(
        """
        SELECT * FROM assessment_run_comparisons
        WHERE engagement_id = ? AND run_id = ? AND baseline_run_id = ?
        """,
        (engagement_id, run_id, baseline_run_id),
    ).fetchone()
    if existing is not None:
        if str(existing["comparison_sha256"]) != comparison_sha256:
            raise HTTPException(
                status_code=409,
                detail="recorded comparison differs from current sealed run facts",
            )
        return _serialize_comparison(existing)
    cursor = connection.execute(
        """
        INSERT INTO assessment_run_comparisons (
            engagement_id, run_id, baseline_run_id, selection,
            target_compatible, source_compatible, comparison_json,
            comparison_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            run_id,
            baseline_run_id,
            selection,
            -1 if payload["target_compatible"] is None else int(payload["target_compatible"]),
            -1 if payload["source_compatible"] is None else int(payload["source_compatible"]),
            _json_text(payload),
            comparison_sha256,
        ),
    )
    created = connection.execute(
        "SELECT * FROM assessment_run_comparisons WHERE id = ?",
        (int(cursor.lastrowid),),
    ).fetchone()
    assert created is not None
    return _serialize_comparison(created)


def compare_assessment_runs(
    engagement_id: int, *, run_id: int, baseline_run_id: int | None = None
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        current = _run_or_404(connection, engagement.id, run_id)
        automatic_baseline = baseline_run_id is None
        if baseline_run_id is None:
            baseline = _latest_comparison_baseline(
                connection,
                engagement_id=engagement.id,
                run_id=run_id,
                run_kind=str(current["run_kind"]),
                run_purpose=str(current["run_purpose"]),
                target_identity_json=str(current["target_identity_json"]),
            )
            if baseline is None:
                raise HTTPException(status_code=404, detail="no compatible baseline run found")
            baseline_run_id = int(baseline["id"])
        else:
            baseline = _run_or_404(connection, engagement.id, baseline_run_id)
        return _comparison_payload(
            connection,
            current=current,
            baseline=baseline,
            automatic_baseline=automatic_baseline,
        )


def record_assessment_run_comparison(
    engagement_id: int, *, run_id: int, baseline_run_id: int | None = None
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        current = _run_or_404(connection, engagement.id, run_id)
        if baseline_run_id is None:
            baseline = _latest_comparison_baseline(
                connection,
                engagement_id=engagement.id,
                run_id=run_id,
                run_kind=str(current["run_kind"]),
                run_purpose=str(current["run_purpose"]),
                target_identity_json=str(current["target_identity_json"]),
            )
            if baseline is None:
                raise HTTPException(status_code=404, detail="no compatible baseline run found")
            baseline_run_id = int(baseline["id"])
        return _record_comparison(
            connection,
            engagement_id=engagement.id,
            run_id=run_id,
            baseline_run_id=baseline_run_id,
            selection="manual",
        )


def list_run_comparisons(
    engagement_id: int, *, run_id: int, limit: int, offset: int
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        _run_or_404(connection, engagement.id, run_id)
        page = _page(
            connection,
            table="assessment_run_comparisons",
            engagement_id=engagement.id,
            run_id=run_id,
            limit=limit,
            offset=offset,
        )
        page["items"] = [_serialize_comparison(row) for row in page["items"]]
        return page
