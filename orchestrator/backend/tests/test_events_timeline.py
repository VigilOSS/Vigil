"""`GET /events`: the structured phase, task, and state-change timeline.

Stored events use SQLite ``YYYY-MM-DD HH:MM:SS`` timestamps while the
activity rows that inferred phase/task rows come from use ISO-8601, so the
timeline must order by instant and return one spelling.
"""
from __future__ import annotations

import re

from app import db
from app.services import events as events_service
from tests.test_activity_feed_api import _audit, _event, _seed, ENGAGEMENT_KEY


EVENTS = f"/engagements/{ENGAGEMENT_KEY}/events"


def _timeline(client, **params) -> list[dict]:
    response = client.get(EVENTS, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def _seed_mixed_timeline(engagement_id: int) -> None:
    _event(engagement_id, "2026-04-17 12:00:02", "surface.updated", summary="Stored early")
    # Inferred phase.started + task.started at 12:00:03 (ISO spelling).
    _audit(
        engagement_id, "2026-04-17T12:00:03Z", "Recon start",
        actor_kind="agent", actor_name="recon-specialist",
    )
    _event(engagement_id, "2026-04-17 12:00:05", "finding.created", task_name="VA-001", summary="Stored middle")
    _audit(
        engagement_id, "2026-04-17T12:00:07.500000Z", "Recon summary",
        actor_kind="agent", actor_name="recon-specialist",
    )
    _event(engagement_id, "2026-04-17 12:00:09", "chain.created", task_name="acme-chain", summary="Stored late")


def test_events_timeline_orders_mixed_timestamp_spellings_by_instant(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    _seed_mixed_timeline(engagement_id)

    timeline = _timeline(client)

    assert [(event["event_type"], event["summary"]) for event in timeline] == [
        ("surface.updated", "Stored early"),
        ("phase.started", "recon phase started"),
        ("task.started", "Recon start"),
        ("finding.created", "Stored middle"),
        ("task.completed", "Recon summary"),
        ("chain.created", "Stored late"),
    ]
    assert [event["created_at"] for event in timeline] == [
        "2026-04-17T12:00:02Z",
        "2026-04-17T12:00:03Z",
        "2026-04-17T12:00:03Z",
        "2026-04-17T12:00:05Z",
        "2026-04-17T12:00:07.500000Z",
        "2026-04-17T12:00:09Z",
    ]


def test_events_limit_keeps_newest_rows_without_loading_full_history(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    _seed_mixed_timeline(engagement_id)
    full = _timeline(client)

    statements: list[str] = []
    with db.get_connection() as connection:
        connection.set_trace_callback(statements.append)
        try:
            events_service.list_events_for_engagement(engagement_id, limit=3)
        finally:
            connection.set_trace_callback(None)
    # Every statement that reads timeline rows (stored events and the
    # activity rows tasks are inferred from) is bounded in SQL.
    row_reads = [
        " ".join(sql.split())
        for sql in statements
        if re.match(r"\s*SELECT id, engagement_id\b.*\bFROM (events|activity_entries)\b", sql, re.S)
    ]
    assert any(" FROM events " in sql and sql.endswith("LIMIT 3") for sql in row_reads), row_reads
    assert any(
        " FROM activity_entries " in sql and sql.endswith("LIMIT 3") for sql in row_reads
    ), row_reads
    assert all(re.search(r"\bLIMIT \d+$", sql) for sql in row_reads), row_reads

    limited = _timeline(client, limit=3)

    assert limited == full[-3:]
    # Inferred rows keep their identity whatever the window.
    assert [event["id"] for event in _timeline(client, limit=5)] == [event["id"] for event in full[-5:]]
    assert all(event["id"] < 0 for event in full if event["event_type"] in {"phase.started", "task.started", "task.completed"})
