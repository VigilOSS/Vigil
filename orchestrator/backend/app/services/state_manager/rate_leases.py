"""Atomic engagement-wide target-rate lease lifecycle."""
from __future__ import annotations

import datetime as dt
import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ..events import _engagement_or_404
from . import _common


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _aggregate_limit(engagement_root: str) -> float | None:
    path = Path(engagement_root) / "scope.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    raw = payload.get("rate_limit_aggregate_rps")
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _serialize(row) -> dict[str, Any]:
    return dict(row)


def acquire_rate_lease(
    engagement_id: int,
    *,
    owner: str,
    effective_rate_rps: float,
    ttl_seconds: int,
    override_reason: str = "",
    command_run_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    limit = _aggregate_limit(engagement.engagement_root)
    now = _utcnow()
    expires_at = _iso(now + dt.timedelta(seconds=int(ttl_seconds)))
    now_iso = _iso(now)
    requested = float(effective_rate_rps)
    reason = override_reason.strip()

    with _common.get_connection() as connection:
        # Serialize the sum-and-insert decision across backend workers. SQLite
        # WAL permits concurrent readers but only one writer; BEGIN IMMEDIATE
        # makes that ownership explicit before reading the active total.
        connection.execute("BEGIN IMMEDIATE")
        active = connection.execute(
            """
            SELECT COALESCE(SUM(effective_rate_rps), 0) AS total
            FROM assessment_rate_leases
            WHERE engagement_id = ? AND released_at IS NULL AND expires_at > ?
            """,
            (engagement.id, now_iso),
        ).fetchone()
        active_rate = float(active["total"] or 0)
        if limit is not None and active_rate + requested > limit and not reason:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "aggregate target-rate limit would be exceeded; record an override_reason to proceed",
                    "active_rate_rps": active_rate,
                    "requested_rate_rps": requested,
                    "aggregate_limit_rps": limit,
                },
            )
        token = uuid.uuid4().hex
        cursor = connection.execute(
            """
            INSERT INTO assessment_rate_leases (
                engagement_id, lease_token, owner, effective_rate_rps,
                aggregate_limit_rps, override_reason, command_run_id, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                token,
                owner.strip(),
                requested,
                limit,
                reason or None,
                command_run_id,
                expires_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_rate_leases WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return _serialize(row)


def update_rate_lease(
    engagement_id: int,
    *,
    lease_token: str,
    ttl_seconds: int | None = None,
    release: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    now = _utcnow()
    now_iso = _iso(now)
    with _common.get_connection() as connection:
        existing = connection.execute(
            """
            SELECT * FROM assessment_rate_leases
            WHERE engagement_id = ? AND lease_token = ?
            """,
            (engagement.id, lease_token),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rate lease not found")
        if existing["released_at"] is not None:
            if release:
                return _serialize(existing)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="rate lease already released")
        if release:
            connection.execute(
                """
                UPDATE assessment_rate_leases
                SET released_at = ?, updated_at = ?
                WHERE engagement_id = ? AND lease_token = ? AND released_at IS NULL
                """,
                (now_iso, now_iso, engagement.id, lease_token),
            )
        elif ttl_seconds is not None:
            expires_at = _iso(now + dt.timedelta(seconds=int(ttl_seconds)))
            connection.execute(
                """
                UPDATE assessment_rate_leases
                SET expires_at = ?, updated_at = ?
                WHERE engagement_id = ? AND lease_token = ? AND released_at IS NULL
                """,
                (expires_at, now_iso, engagement.id, lease_token),
            )
        row = connection.execute(
            "SELECT * FROM assessment_rate_leases WHERE engagement_id = ? AND lease_token = ?",
            (engagement.id, lease_token),
        ).fetchone()
        assert row is not None
        return _serialize(row)


def list_rate_leases(engagement_id: int, *, active_only: bool = False) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = "engagement_id = ?"
    params: list[Any] = [engagement.id]
    if active_only:
        where += " AND released_at IS NULL AND expires_at > ?"
        params.append(_iso(_utcnow()))
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM assessment_rate_leases WHERE {where} ORDER BY id DESC",
            tuple(params),
        ).fetchall()
    return [_serialize(row) for row in rows]
