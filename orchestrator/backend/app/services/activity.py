"""Per-engagement activity-entry helpers.

``activity_entries`` is the prose/narrative log that replaces ``log.md``.
The existing ``events`` table keeps its structured state-change role; this
module only handles the free-form narrative writes + FTS-backed reads.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status

from ..db import get_connection
from .events import _engagement_or_404
from .search import fts_escape
from .timestamps import iso_z, parse_utc


def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _normalize_timestamp(value: str, *, field_name: str, blank_now: bool = False) -> str:
    raw = str(value or "").strip()
    if not raw:
        if not blank_now:
            return ""
        return iso_z(datetime.now(timezone.utc))
    parsed = parse_utc(raw)
    if parsed is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{field_name} must be an ISO-8601 timestamp",
        )
    return iso_z(parsed)


def _serialise(row: Any) -> dict[str, Any]:
    data = dict(row)
    meta = data.pop("metadata_json", None) or "{}"
    try:
        data["metadata"] = json.loads(meta)
    except json.JSONDecodeError:
        data["metadata"] = {}
    return data


def record_activity_entry(
    engagement_id: int,
    *,
    occurred_at: str = "",
    actor_kind: str = "operator",
    actor_name: str = "",
    title: str = "",
    action: str = "",
    result: str = "",
    artifact_ref: str = "",
    body_markdown: str = "",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append a narrative entry for the engagement.

    ``activity_entries`` is append-only by design — every hook or operator
    message is a new row. The natural-key upsert pattern used for
    ``intel_*`` does not apply here.
    """
    engagement = _engagement_or_404(engagement_id)
    occurred_at_value = _normalize_timestamp(
        occurred_at, field_name="occurred_at", blank_now=True
    )
    columns = [
        "engagement_id",
        "occurred_at",
        "actor_kind",
        "actor_name",
        "title",
        "action",
        "result",
        "artifact_ref",
        "body_markdown",
        "metadata_json",
    ]
    values: list[Any] = [
        engagement.id,
        occurred_at_value,
        actor_kind,
        actor_name,
        title,
        action,
        result,
        artifact_ref,
        body_markdown,
        _json_text(metadata),
    ]
    placeholders = ", ".join(["?"] * len(columns))
    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO activity_entries ({', '.join(columns)}) VALUES ({placeholders})",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM activity_entries WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
    assert row is not None
    return _serialise(row)


def list_activity_entries(
    engagement_id: int,
    *,
    q: str = "",
    actor_kind: str = "",
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """Return paginated activity entries, optionally filtered by FTS term.

    The response shape matches ``ListActivityEntriesResponse``: a ``total``
    count across the filter + the current ``items`` page. ``q`` is optional
    and goes through ``fts_escape`` before hitting ``MATCH``.
    """
    engagement = _engagement_or_404(engagement_id)
    params: list[Any] = [engagement.id]
    where = ["a.engagement_id = ?"]
    join_sql = ""
    fts_term = fts_escape(q) if q else ""
    if fts_term:
        join_sql = "JOIN activity_entries_fts f ON f.rowid = a.id"
        where.append("f.activity_entries_fts MATCH ?")
        params.append(fts_term)
    if actor_kind:
        where.append("a.actor_kind = ?")
        params.append(actor_kind)
    if since:
        where.append("julianday(a.occurred_at) >= julianday(?)")
        params.append(_normalize_timestamp(since, field_name="since"))
    if until:
        where.append("julianday(a.occurred_at) <= julianday(?)")
        params.append(_normalize_timestamp(until, field_name="until"))

    count_sql = (
        f"SELECT COUNT(*) FROM activity_entries a {join_sql} WHERE {' AND '.join(where)}"
    )
    list_sql = (
        f"SELECT a.* FROM activity_entries a {join_sql} "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY julianday(a.occurred_at) DESC, a.id DESC LIMIT ? OFFSET ?"
    )
    with get_connection() as connection:
        total_row = connection.execute(count_sql, tuple(params)).fetchone()
        total = int(total_row[0]) if total_row and total_row[0] is not None else 0
        rows = connection.execute(
            list_sql, tuple(params + [int(limit), int(offset)])
        ).fetchall()
    return {
        "total": total,
        "items": [_serialise(row) for row in rows],
    }
