from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def write_engagement(engagements_dir: Path, key: str = "2026-03-30-120000-example") -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions" / "session-a" / "proposals").mkdir(parents=True, exist_ok=True)
    (engagements_dir / ".active").write_text(f"{key}\n", encoding="utf-8")
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-03-30T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "out_of_scope_hosts": [],
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_findings": ["FINDING-VA-001"],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_findings": ["FINDING-VA-001"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return engagement_dir


def test_list_engagements_discovers_filesystem_engagements(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["key"] == "2026-03-30-120000-example"
    assert payload[0]["active"] is True
    assert payload[0]["current_phase"] == "exploit"
    assert payload[0]["session_count"] == 1


def test_engagement_artifacts_and_sessions_are_scoped_by_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    artifacts = client.get("/engagements/2026-03-30-120000-example/artifacts")
    assert artifacts.status_code == 200
    artifact_names = {artifact["name"] for artifact in artifacts.json() if artifact["exists"]}
    assert {"scope.json", "log.md", "findings.md", "engagement.json"} <= artifact_names

    sessions = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert sessions.status_code == 200
    payload = sessions.json()
    assert payload[0]["session_id"] == "session-a"
    assert payload[0]["assigned_findings"] == ["FINDING-VA-001"]


def test_engagement_event_and_assessment_routes_use_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_event = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "task.started",
            "phase": "exploit",
            "task_name": "exploit-developer",
            "agent_name": "exploit-developer",
            "summary": "Exploit task started",
        },
    )
    assert create_event.status_code == 201

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example.com/orders/7",
            "source_name": "source-analyzer",
            "rationale": "Observed direct object path",
            "evidence_ref": "log.md",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    create_finding = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "FINDING-VA-001",
            "title": "IDOR in orders",
            "severity": "high",
            "status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Confirmed with adjacent object ids.",
            "source_name": "exploit-developer",
            "details": {"impact": "cross-tenant access"},
            "provenance": {"agent_name": "exploit-developer"},
            "links": [],
        },
    )
    assert create_finding.status_code == 201
    assert create_finding.json()["finding"]["slug"] == "FINDING-VA-001"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    assert findings.json()[0]["slug"] == "FINDING-VA-001"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 1


def test_incompatible_local_database_is_reset(client, isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT)")
        connection.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                event_type TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE assessment_attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                chain_key TEXT NOT NULL
            )
            """
        )
        connection.commit()

    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    assert response.json()[0]["key"] == "2026-03-30-120000-example"

    with sqlite3.connect(str(db_path)) as connection:
        table_names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        assert "runs" not in table_names
        event_columns = {row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()}
        chain_columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_attack_chains)").fetchall()}
        assert "engagement_id" in event_columns
        assert "engagement_id" in chain_columns
        assert "run_id" not in event_columns
        assert "run_id" not in chain_columns
