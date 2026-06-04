from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app import db as db_module


def _write_engagement(
    engagements_dir: Path,
    key: str,
    *,
    target: str,
    status: str,
    current_phase: str,
    engagement_type: str | None = None,
    customer: str | None = None,
) -> None:
    """Seed an on-disk engagement so the sync registers it in the DB.

    Mirrors the fixture pattern in test_engagements_api.write_engagement but
    parameterizes the dashboard-relevant fields (status / phase / type /
    customer). scope.json is the source of truth for phase/type/customer in
    the EngagementView the dashboard projection reuses.
    """
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps({"key": key, "target": target, "created_at": "2026-05-01T12:00:00Z"}),
        encoding="utf-8",
    )
    scope: dict[str, object] = {
        "hostname": target,
        "scope_hosts": [target],
        "status": status,
        "current_phase": current_phase,
    }
    if engagement_type is not None:
        scope["engagement_type"] = engagement_type
    if customer is not None:
        scope["customer"] = customer
    (engagement_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")


def _engagement_id(key: str) -> int:
    with sqlite3.connect(str(db_module.database_path())) as connection:
        row = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (key,)
        ).fetchone()
    assert row is not None, f"engagement {key} not synced into DB"
    return int(row[0])


def _insert_finding(engagement_id: int, slug: str, severity: str, status: str) -> None:
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (engagement_id, slug, f"Finding {slug}", severity, status),
        )
        connection.commit()


def test_dashboard_summary_empty_db_shape(client, isolate_settings):
    """An install with no engagements returns zeros and empty collections —
    never a 500, never null fields the frontend would have to guard."""
    response = client.get("/dashboard/summary")
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["engagement_counts"] == {
        "total": 0,
        "by_status": {},
        "by_type": {},
        "by_phase": {},
    }
    assert payload["finding_totals"] == {"total": 0, "by_severity": {}}
    assert payload["engagements"] == []
    assert payload["recent_activity"] == []


def test_dashboard_summary_aggregates_two_engagements(client, isolate_settings):
    engagements_dir = isolate_settings["engagements_dir"]
    _write_engagement(
        engagements_dir,
        "2026-05-01-100000-alpha",
        target="alpha.example",
        status="in_progress",
        current_phase="exploit",
        engagement_type="red",
    )
    _write_engagement(
        engagements_dir,
        "2026-05-02-100000-bravo",
        target="bravo.example",
        status="completed",
        current_phase="report",
        engagement_type="blue",
        customer="acme",
    )

    # Trigger the filesystem -> DB sync so the engagement rows (and their ids)
    # exist before we attach findings.
    assert client.get("/engagements").status_code == 200
    alpha_id = _engagement_id("2026-05-01-100000-alpha")
    bravo_id = _engagement_id("2026-05-02-100000-bravo")

    # alpha: 1 critical + 1 high live, plus one merged and one false_positive
    # that MUST be excluded everywhere a "live finding" count is shown.
    _insert_finding(alpha_id, "VA-001", "critical", "active")
    _insert_finding(alpha_id, "VA-002", "high", "exploited")
    _insert_finding(alpha_id, "VA-003", "medium", "merged")
    _insert_finding(alpha_id, "VA-004", "low", "false_positive")
    # bravo: 1 high + 1 medium live.
    _insert_finding(bravo_id, "IR-001", "high", "active")
    _insert_finding(bravo_id, "IR-002", "medium", "draft")

    response = client.get("/dashboard/summary")
    assert response.status_code == 200, response.text
    payload = response.json()

    counts = payload["engagement_counts"]
    assert counts["total"] == 2
    assert counts["by_status"] == {"in_progress": 1, "completed": 1}
    assert counts["by_type"] == {"red": 1, "blue": 1}
    assert counts["by_phase"] == {"exploit": 1, "report": 1}

    # Cross-engagement totals exclude merged/false_positive: critical(1) +
    # high(2) + medium(1) = 4 (NOT 6).
    totals = payload["finding_totals"]
    assert totals["total"] == 4
    assert totals["by_severity"] == {"critical": 1, "high": 2, "medium": 1}

    engagements = {row["key"]: row for row in payload["engagements"]}
    assert set(engagements) == {
        "2026-05-01-100000-alpha",
        "2026-05-02-100000-bravo",
    }

    alpha = engagements["2026-05-01-100000-alpha"]
    assert alpha["finding_count"] == 2
    assert alpha["finding_severities"] == {"critical": 1, "high": 1}
    assert alpha["engagement_type"] == "red"
    assert alpha["customer"] is None
    assert alpha["current_phase"] == "exploit"

    bravo = engagements["2026-05-02-100000-bravo"]
    assert bravo["finding_count"] == 2
    assert bravo["finding_severities"] == {"high": 1, "medium": 1}
    assert bravo["engagement_type"] == "blue"
    assert bravo["customer"] == "acme"

    # Per-engagement rollups sum to the cross-engagement total.
    assert (
        sum(row["finding_count"] for row in payload["engagements"]) == totals["total"]
    )


def test_dashboard_summary_orders_engagements_newest_updated_first(client, isolate_settings):
    engagements_dir = isolate_settings["engagements_dir"]
    for key in (
        "2026-05-01-100000-one",
        "2026-05-01-100000-two",
        "2026-05-01-100000-three",
    ):
        _write_engagement(
            engagements_dir,
            key,
            target=f"{key}.example",
            status="in_progress",
            current_phase="recon",
        )
    assert client.get("/engagements").status_code == 200

    # Force a deterministic updated_at ordering: two is newest, then three,
    # then one. The dashboard must return them newest-updated first.
    with sqlite3.connect(str(db_module.database_path())) as connection:
        for key, updated_at in (
            ("2026-05-01-100000-one", "2026-05-01T00:00:00Z"),
            ("2026-05-01-100000-three", "2026-05-10T00:00:00Z"),
            ("2026-05-01-100000-two", "2026-05-20T00:00:00Z"),
        ):
            connection.execute(
                "UPDATE engagements SET updated_at = ? WHERE key = ?",
                (updated_at, key),
            )
        connection.commit()

    response = client.get("/dashboard/summary")
    assert response.status_code == 200, response.text
    ordered_keys = [row["key"] for row in response.json()["engagements"]]
    assert ordered_keys == [
        "2026-05-01-100000-two",
        "2026-05-01-100000-three",
        "2026-05-01-100000-one",
    ]


def test_dashboard_summary_surfaces_recent_activity_across_engagements(client, isolate_settings):
    engagements_dir = isolate_settings["engagements_dir"]
    _write_engagement(
        engagements_dir,
        "2026-05-01-100000-alpha",
        target="alpha.example",
        status="in_progress",
        current_phase="recon",
    )
    _write_engagement(
        engagements_dir,
        "2026-05-02-100000-bravo",
        target="bravo.example",
        status="in_progress",
        current_phase="recon",
    )
    assert client.get("/engagements").status_code == 200

    # Two activity entries on different engagements; bravo's is newer and must
    # sort first in the cross-engagement feed.
    first = client.post(
        "/engagements/2026-05-01-100000-alpha/activity-entries",
        json={
            "occurred_at": "2026-05-01T09:00:00Z",
            "actor_kind": "operator",
            "actor_name": "alex",
            "title": "Kickoff",
            "action": "started",
            "result": "ok",
        },
    )
    assert first.status_code == 201, first.text
    second = client.post(
        "/engagements/2026-05-02-100000-bravo/activity-entries",
        json={
            "occurred_at": "2026-05-02T09:00:00Z",
            "actor_kind": "agent",
            "actor_name": "recon-specialist",
            "title": "Recon complete",
            "action": "completed",
            "result": "done",
        },
    )
    assert second.status_code == 201, second.text

    response = client.get("/dashboard/summary")
    assert response.status_code == 200, response.text
    activity = response.json()["recent_activity"]
    assert [row["engagement_key"] for row in activity] == [
        "2026-05-02-100000-bravo",
        "2026-05-01-100000-alpha",
    ]
    assert activity[0]["title"] == "Recon complete"
    assert activity[0]["actor_kind"] == "agent"
