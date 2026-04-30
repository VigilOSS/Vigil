from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module
from app.services import engagements as engagement_service


def legacy_finding_slug(suffix: str = "VA-001") -> str:
    return f"{'FINDING'}-{suffix}"


def write_engagement(engagements_dir: Path, key: str = "2026-03-30-120000-example") -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions" / "session-a" / "proposals").mkdir(parents=True, exist_ok=True)
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
                "approved_targets": ["VA-001"],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_targets": ["VA-001"],
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
    assert payload[0]["current_phase"] == "exploit"
    assert payload[0]["session_count"] == 1


def test_maybe_sync_engagements_skips_repeated_resync_without_filesystem_changes(isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])
    db_module.init_db()

    monkeypatch.setattr(engagement_service, "_last_sync_signature", None)
    call_count = 0
    original_sync = engagement_service.sync_engagements

    def counted_sync() -> None:
        nonlocal call_count
        call_count += 1
        original_sync()

    monkeypatch.setattr(engagement_service, "sync_engagements", counted_sync)

    engagement_service.maybe_sync_engagements()
    engagement_service.maybe_sync_engagements()

    assert call_count == 1

    write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120500-example")
    engagement_service.maybe_sync_engagements()

    assert call_count == 2


def test_maybe_sync_engagements_resyncs_when_assignment_json_changes(isolate_settings, monkeypatch):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    session_dir = engagement_dir / "sessions" / "session-a"
    assignment_path = session_dir / "assignment.json"
    assignment_path.write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_targets": ["VA-001"],
            }
        ),
        encoding="utf-8",
    )
    db_module.init_db()

    monkeypatch.setattr(engagement_service, "_last_sync_signature", None)
    call_count = 0
    original_sync = engagement_service.sync_engagements

    def counted_sync() -> None:
        nonlocal call_count
        call_count += 1
        original_sync()

    monkeypatch.setattr(engagement_service, "sync_engagements", counted_sync)

    engagement_service.maybe_sync_engagements()
    engagement_service.maybe_sync_engagements()

    assert call_count == 1

    assignment_path.write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_targets": ["VA-001", "VA-002"],
            }
        ),
        encoding="utf-8",
    )
    stat = assignment_path.stat()
    os.utime(assignment_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    engagement_service.maybe_sync_engagements()

    assert call_count == 2


def test_get_connection_requires_startup_initialized_database(isolate_settings, monkeypatch):
    monkeypatch.setattr(db_module, "_startup_database_fingerprint", None)

    with pytest.raises(RuntimeError, match="has not been initialized"):
        with db_module.get_connection():
            pass


def test_get_connection_rejects_database_file_replacement(isolate_settings, monkeypatch):
    db_module.init_db()
    original_path = db_module.database_path()
    fingerprint = db_module._startup_database_fingerprint
    assert fingerprint is not None

    replacement_path = isolate_settings["data_dir"] / "replacement.sqlite3"
    with sqlite3.connect(str(replacement_path)) as connection:
        connection.execute("CREATE TABLE replacement_marker (id INTEGER PRIMARY KEY)")

    original_path.unlink()
    replacement_path.replace(original_path)

    with pytest.raises(RuntimeError, match="database file changed after startup"):
        with db_module.get_connection():
            pass


def test_init_db_renames_legacy_assigned_findings_column(isolate_settings):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE engagement_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                session_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                merge_state TEXT NOT NULL DEFAULT 'pending',
                assigned_findings_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                merged_at TEXT
            )
            """
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(engagement_sessions)").fetchall()}

    assert "assigned_targets_json" in columns
    assert "assigned_findings_json" not in columns


def test_init_db_migrates_legacy_finding_slug_references(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug()

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        finding_id = connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, ?, 'Legacy slug')
            """,
            (engagement_id, legacy),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO engagement_sessions (engagement_id, session_id, session_path, assigned_targets_json)
            VALUES (?, 'session-a', '/tmp/eng/sessions/session-a', ?)
            """,
            (engagement_id, json.dumps([legacy])),
        )
        connection.execute(
            """
            INSERT INTO assessment_finding_links (engagement_id, finding_id, link_kind, target_kind, target_ref)
            VALUES (?, ?, 'variant_of', 'finding', ?)
            """,
            (engagement_id, finding_id, legacy),
        )
        connection.execute(
            """
            INSERT INTO assessment_attack_chains (engagement_id, chain_key, title)
            VALUES (?, 'chain-a', 'Chain A')
            """,
            (engagement_id,),
        )
        chain_id = connection.execute("SELECT id FROM assessment_attack_chains WHERE chain_key = 'chain-a'").fetchone()[0]
        connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (engagement_id, chain_id, relation, entity_kind, entity_ref)
            VALUES (?, ?, 'step', 'finding', ?)
            """,
            (engagement_id, chain_id, legacy),
        )
        connection.execute(
            """
            INSERT INTO code_analysis_results (engagement_id, file_id, finding_slug)
            VALUES (?, 1, ?)
            """,
            (engagement_id, legacy),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        assert connection.execute("SELECT slug FROM assessment_findings").fetchone()[0] == "VA-001"
        assert json.loads(connection.execute("SELECT assigned_targets_json FROM engagement_sessions").fetchone()[0]) == ["VA-001"]
        assert connection.execute("SELECT target_ref FROM assessment_finding_links").fetchone()[0] == "VA-001"
        assert connection.execute("SELECT entity_ref FROM assessment_attack_chain_links").fetchone()[0] == "VA-001"
        assert connection.execute("SELECT finding_slug FROM code_analysis_results").fetchone()[0] == "VA-001"


def test_init_db_migrates_legacy_finding_slug_collision_without_startup_crash(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug()

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        legacy_id = connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, ?, 'Legacy slug')
            """,
            (engagement_id, legacy),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, 'VA-001', 'Already migrated slug')
            """,
            (engagement_id,),
        )
        connection.execute(
            """
            INSERT INTO code_analysis_results (engagement_id, file_id, finding_slug)
            VALUES (?, 1, ?)
            """,
            (engagement_id, legacy),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute(
            "SELECT id, slug FROM assessment_findings ORDER BY id ASC"
        ).fetchall()
        migrated_legacy_slug = rows[0][1]
        assert migrated_legacy_slug.startswith("VA-001-legacy-")
        assert rows[1][1] == "VA-001"
        assert legacy not in {row[1] for row in rows}
        assert connection.execute(
            "SELECT finding_slug FROM code_analysis_results WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()[0] == migrated_legacy_slug
        assert str(legacy_id) in migrated_legacy_slug


def test_init_db_migrates_legacy_finding_slugs_in_finding_json(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug("CH-001")

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, details_json, provenance_json
            )
            VALUES (?, 'CV-001', 'Variant slug', ?, ?)
            """,
            (
                engagement_id,
                json.dumps({"variant_of": legacy, "related": [legacy]}),
                json.dumps(
                    {
                        "source_slug": legacy,
                        "review": {"target_slug": legacy},
                        "evidence": f"Same root cause as {legacy}.",
                    }
                ),
            ),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        details_json, provenance_json = connection.execute(
            "SELECT details_json, provenance_json FROM assessment_findings"
        ).fetchone()
    assert json.loads(details_json) == {"variant_of": "CH-001", "related": ["CH-001"]}
    assert json.loads(provenance_json) == {
        "source_slug": "CH-001",
        "review": {"target_slug": "CH-001"},
        "evidence": "Same root cause as CH-001.",
    }


def test_engagement_artifacts_and_sessions_are_scoped_by_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    artifacts = client.get("/engagements/2026-03-30-120000-example/artifacts")
    assert artifacts.status_code == 200
    artifact_names = {artifact["name"] for artifact in artifacts.json() if artifact["exists"]}
    assert {"scope.json", "engagement.json"} <= artifact_names

    sessions = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert sessions.status_code == 200
    payload = sessions.json()
    assert payload[0]["session_id"] == "session-a"
    assert payload[0]["assigned_targets"] == ["VA-001"]


def test_engagement_sync_migrates_legacy_target_keys_on_disk(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    legacy = legacy_finding_slug()
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
                "approved_findings": [legacy],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    session_dir = engagement_dir / "sessions" / "session-a"
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_findings": [legacy],
                }
            ]
        ),
        encoding="utf-8",
    )
    (session_dir / "assignment.json").write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_findings": [legacy],
            }
        ),
        encoding="utf-8",
    )

    first = client.get("/engagements")
    second = client.get("/engagements")

    assert first.status_code == 200
    assert second.status_code == 200
    scope_payload = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))
    index_payload = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assignment_payload = json.loads((session_dir / "assignment.json").read_text(encoding="utf-8"))
    assert scope_payload["approved_targets"] == ["VA-001"]
    assert "approved_findings" not in scope_payload
    assert index_payload[0]["assigned_targets"] == ["VA-001"]
    assert "assigned_findings" not in index_payload[0]
    assert assignment_payload["assigned_targets"] == ["VA-001"]
    assert "assigned_findings" not in assignment_payload


def test_engagement_sync_skips_invalid_engagement_json_without_aborting(client, isolate_settings, caplog):
    write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120000-valid")
    broken_dir = write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120500-broken")
    (broken_dir / "scope.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        response = client.get("/engagements")

    assert response.status_code == 200
    payload = response.json()
    assert [item["key"] for item in payload] == ["2026-03-30-120000-valid"]
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)


def test_invalid_session_artifacts_preserve_existing_engagement_state(client, isolate_settings, caplog):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    first = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert first.status_code == 200
    assert len(first.json()) == 1

    (engagement_dir / "sessions" / "index.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        sessions_response = client.get("/engagements/2026-03-30-120000-example/sessions")
        engagements_response = client.get("/engagements")

    assert sessions_response.status_code == 200
    assert len(sessions_response.json()) == 1
    assert engagements_response.status_code == 200
    assert [item["key"] for item in engagements_response.json()] == ["2026-03-30-120000-example"]
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)


def test_invalid_scope_preserves_existing_engagement_state(client, isolate_settings, caplog):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    first = client.get("/engagements")
    assert first.status_code == 200
    assert len(first.json()) == 1

    (engagement_dir / "scope.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        response = client.get("/engagements")

    assert response.status_code == 200
    payload = response.json()
    assert [item["key"] for item in payload] == ["2026-03-30-120000-example"]
    assert payload[0]["current_phase"] == "unknown"
    assert payload[0]["approved_targets"] == []
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)
    assert any("Using persisted engagement identity" in message for message in caplog.messages)


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
            "evidence_ref": "activity_entries",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    invalid_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "web_application",
            "target_descriptor": "https://example.com/",
            "source_name": "source-analyzer",
            "status": "covered",
        },
    )
    assert invalid_surface.status_code == 422

    create_finding = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-001",
            "title": "IDOR in orders",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Confirmed with adjacent object ids.",
            "source_name": "exploit-developer",
            "details": {
                "evidence": "GET /orders/7 returns order for user B when authenticated as user A",
                "impact": "cross-tenant access",
                "owasp_category": "A01:2021 Broken Access Control",
                "cwe_id": "CWE-639",
                "request_method": "GET",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "cvss_score": 6.5,
                "remediation": "Enforce server-side ownership checks on order retrieval",
                "steps_to_reproduce": [
                    "Authenticate as user A",
                    "GET /orders/7 (belongs to user B)",
                    "Observe full order data returned"
                ]
            },
            "provenance": {"agent_name": "exploit-developer"},
            "links": [],
        },
    )
    assert create_finding.status_code == 201
    assert create_finding.json()["finding"]["slug"] == "VA-001"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    assert findings.json()[0]["slug"] == "VA-001"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 1
    assert summary.json()["exploit_candidate_count"] == 1
    assert summary.json()["coverage_blocker_count"] == 0
    assert summary.json()["report_blocker_count"] == 0

    exploit_candidates = client.get("/engagements/2026-03-30-120000-example/assessment/exploit-candidates")
    assert exploit_candidates.status_code == 200
    assert [row["slug"] for row in exploit_candidates.json()] == ["VA-001"]

    coverage_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-readiness")
    assert coverage_readiness.status_code == 200
    assert coverage_readiness.json()["ready"] is True
    assert coverage_readiness.json()["blocker_count"] == 0

    report_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/report-readiness")
    assert report_readiness.status_code == 200
    assert report_readiness.json()["ready"] is True
    assert report_readiness.json()["blocker_count"] == 0

    final_report = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=final"
    )
    assert final_report.status_code == 200
    assert [row["slug"] for row in final_report.json()] == ["VA-001"]


def test_events_synthesizes_legacy_log_artifact_timeline(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_start = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "artifact.updated",
            "phase": "recon",
            "task_name": "log.md",
            "agent_name": "recon-specialist",
            "summary": "Recon start",
        },
    )
    assert create_start.status_code == 201

    create_complete = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "artifact.updated",
            "phase": "recon",
            "task_name": "log.md",
            "agent_name": "recon-specialist",
            "summary": "Recon summary",
        },
    )
    assert create_complete.status_code == 201

    response = client.get("/engagements/2026-03-30-120000-example/events")

    assert response.status_code == 200, response.text
    event_types = [event["event_type"] for event in response.json()]
    assert "phase.started" in event_types
    assert "task.started" in event_types
    assert "task.completed" in event_types


def test_final_report_mode_returns_conflict_when_readiness_fails(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example.com/orders/7",
            "source_name": "source-analyzer",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    create_finding = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-009",
            "title": "Unreviewed IDOR in orders",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "orders-idor-unreviewed",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/9",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Needs verification.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "GET /orders/9 returns order for user B when authenticated as user A",
                "impact": "cross-tenant access",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert create_finding.status_code == 201

    report_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/report-readiness")
    assert report_readiness.status_code == 200
    assert report_readiness.json()["ready"] is False
    assert any(
        blocker["kind"] == "finding_verification_state" for blocker in report_readiness.json()["blockers"]
    )

    final_report = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=final"
    )
    assert final_report.status_code == 409
    assert final_report.json()["detail"]["ready"] is False
    assert any(
        blocker["kind"] == "finding_verification_state"
        for blocker in final_report.json()["detail"]["blockers"]
    )


def test_coverage_patch_normalizes_tested_to_covered_and_refreshes_service_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    service_coverage = next(item for item in coverage_items.json() if item["input_slot"] == "service")

    patch = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{service_coverage['id']}",
        json={"status": "tested", "notes": "Validated service reachability"},
    )
    assert patch.status_code == 200
    assert patch.json()["status"] == "covered"

    services = client.get("/engagements/2026-03-30-120000-example/assessment/services")
    assert services.status_code == 200
    assert services.json()[0]["coverage_status"] == "covered"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["service_coverage_gaps"] == []


def test_summary_vendor_saas_decision_reads_dispatch_decisions(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://tenant.auth0.com/login",
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201, ingest.text

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200, summary.text
    pending = {
        row["host"]: row["vendor"]
        for row in summary.json()["vendor_saas_hosts_pending_decision"]
    }
    assert pending.get("tenant.auth0.com") == "auth0"

    decision = client.post(
        "/engagements/2026-03-30-120000-example/assessment/dispatch-decisions",
        json={
            "kind": "scope_decision",
            "payload": {
                "host": "tenant.auth0.com",
                "vendor": "auth0",
                "choice": "in_scope",
            },
            "surfaced_to_user": True,
        },
    )
    assert decision.status_code == 201, decision.text

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["vendor_saas_hosts_pending_decision"] == []


def test_repeat_request_observation_preserves_stronger_coverage_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    first = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert first.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    payload = coverage_items.json()
    query_item = next(item for item in payload if item["input_slot"] == "query")
    service_item = next(item for item in payload if item["input_slot"] == "service")

    for item in (query_item, service_item):
        patch = client.patch(
            f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{item['id']}",
            json={"status": "covered", "notes": "Operator validated this coverage item."},
        )
        assert patch.status_code == 200
        assert patch.json()["status"] == "covered"

    second = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert second.status_code == 201

    refreshed_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert refreshed_items.status_code == 200
    refreshed_by_slot = {item["input_slot"]: item for item in refreshed_items.json()}
    assert refreshed_by_slot["query"]["status"] == "covered"
    assert refreshed_by_slot["service"]["status"] == "covered"

    services = client.get("/engagements/2026-03-30-120000-example/assessment/services")
    assert services.status_code == 200
    assert services.json()[0]["coverage_status"] == "covered"


def test_findings_verify_updates_existing_finding_and_records_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-001",
            "title": "IDOR in orders",
            "severity": "medium",
            "workflow_status": "draft",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential cross-tenant access",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-001/verify",
        json={
            "disposition": "confirmed",
            "reason_code": "reproduced",
            "reason_text": "Adjacent object identifiers reliably return cross-tenant orders.",
            "notes": "Verified with adjacent object identifiers.",
            "source_name": "code-vuln-verifier",
            "evidence_ref": "findings.md",
            "artifact_ref": "findings.md",
            "details": {"impact": "Confirmed cross-tenant order read"},
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["slug"] == "VA-001"
    assert payload["finding"]["workflow_status"] == "draft"
    assert payload["finding"]["verification_state"] == "verified"
    assert payload["finding"]["verification_disposition"] == "confirmed"
    assert payload["finding"]["severity"] == "medium"
    assert payload["transition"]["action"] == "verified_confirmed"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-001/transitions"
    )
    assert transitions.status_code == 200
    assert [item["action"] for item in transitions.json()] == ["verified_confirmed", "created"]

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    finding = next(item for item in findings.json() if item["slug"] == "VA-001")
    assert "Verified with adjacent object identifiers." in finding["notes"]
    assert finding["workflow_status"] == "draft"
    assert finding["verification_state"] == "verified"
    assert finding["verification_disposition"] == "confirmed"
    assert json.loads(finding["details_json"])["impact"] == "Confirmed cross-tenant order read"
    assert json.loads(finding["provenance_json"])["verified_by"] == "code-vuln-verifier"


def test_legacy_finding_status_field_is_rejected(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Legacy status payload",
            "severity": "medium",
            "status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "legacy-status",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Old clients should fail hard.",
            "evidence_ref": "findings.md",
            "notes": "This should be rejected.",
            "details": {"evidence": "legacy payload", "impact": "validation drift"},
        },
    )
    assert response.status_code == 422


def test_findings_patch_can_revive_false_positive_and_lower_severity(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-009",
            "title": "Parser length overflow",
            "severity": "high",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "parser-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:91",
            "summary": "Suppressed after verifier review.",
            "evidence_ref": "tools/analysis-state/verifier.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "validate_length() enforces an 8KB upper bound before arithmetic.",
                "evidence": "validate_length() rejects oversized input.",
                "impact": "Potential overflow avoided by guard.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert created.status_code == 201

    revived = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-009",
        json={
            "workflow_status": "active",
            "severity": "low",
            "notes": "Operator reinstated after manual review.",
            "reason_code": "manual-override",
            "reason_text": "Manual review found the path is live with reduced impact.",
            "provenance": {"reviewed_by": "operator"},
        },
    )
    assert revived.status_code == 200
    assert revived.json()["finding"]["workflow_status"] == "active"
    assert revived.json()["finding"]["verification_state"] == "unreviewed"
    assert revived.json()["finding"]["verification_disposition"] == "none"
    assert revived.json()["finding"]["severity"] == "low"
    assert revived.json()["transition"]["action"] == "operator_override"


def test_findings_patch_rejects_direct_verification_bypass(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-010",
            "title": "Direct patch bypass",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "direct-patch-bypass",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/items/7",
            "summary": "Patch should not be able to persist verifier outcomes.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential unauthorized access",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-010",
        json={
            "workflow_status": "false_positive",
            "reason_text": "Bypass verifier checks",
        },
    )
    assert patched.status_code == 400
    assert "must use POST /findings/{slug}/verify" in patched.json()["detail"]


def test_findings_patch_allows_explicit_workflow_rollback(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-010A",
            "title": "Workflow rollback candidate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "idor",
            "root_cause_key": "workflow-rollback-candidate",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/items/rollback",
            "summary": "Active finding should be movable back to draft.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Initial request/response pair"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-010A",
        json={
            "workflow_status": "draft",
            "reason_code": "needs-retriage",
            "reason_text": "Pushed back for additional review before reactivation.",
        },
    )
    assert patched.status_code == 200
    assert patched.json()["finding"]["workflow_status"] == "draft"


def test_findings_patch_rejects_records_merged_after_validation(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-010B",
            "title": "Patch/merge race candidate",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "patch-merge-race",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/{id}",
            "summary": "Patch should fail if the finding is merged after validation.",
            "evidence_ref": "findings.md",
            "notes": "Created for stale patch race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Object id is user-controlled", "impact": "Cross-tenant read"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    from app.services import state_manager

    original_create_finding = state_manager.create_finding
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(*args, **kwargs):
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                SET status = 'merged',
                    merged_into_finding_id = id,
                    updated_at = '2099-01-01 00:00:00'
                WHERE slug = 'CH-010B'
                """
            )
            connection.commit()
        return original_create_finding(*args, **kwargs)

    monkeypatch.setattr(state_manager, "create_finding", race)

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-010B",
        json={"notes": "Late patch should not overwrite a merged finding."},
    )

    assert patched.status_code == 409
    assert "changed since it was loaded" in patched.json()["detail"]


def test_false_positive_findings_are_suppressed_but_semantically_sticky(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-001",
            "title": "Header length overflow in parser",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Header length appears to overflow before allocation.",
            "evidence_ref": "tools/analysis-state/findings.json",
            "notes": "Initial hunter report.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "len * 4 appears attacker-controlled",
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 201

    killed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-001/verify",
        json={
            "disposition": "false_positive",
            "reason_code": "check-2-guard",
            "reason_text": "validate_header_length() bounds header length to 8192 bytes on all paths.",
            "artifact_ref": "tools/analysis-state/verifier.json",
            "source_name": "code-vuln-verifier",
            "notes": "Check 2 KILL: upstream guard bounds header length to 8192 bytes.",
            "details": {
                "kill_check": 2,
                "kill_reason": "upstream guard bounds header length to 8192 bytes.",
                "evidence": "validate_header_length() rejects oversized input before arithmetic."
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert killed.status_code == 200
    assert killed.json()["finding"]["workflow_status"] == "false_positive"
    assert killed.json()["finding"]["verification_state"] == "verified"
    assert killed.json()["finding"]["verification_disposition"] == "false_positive"
    assert killed.json()["transition"]["action"] == "verified_false_positive"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 0
    assert summary.json()["finding_workflow_statuses"]["false_positive"] == 1
    assert summary.json()["finding_verification_dispositions"]["false_positive"] == 1
    assert summary.json()["top_findings"] == []

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert report_findings.json() == []

    rediscovered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Header length overflow in parser",
            "severity": "critical",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Rediscovery attempt from later analysis pass.",
            "evidence_ref": "tools/analysis-state/rediscovery.json",
            "notes": "Re-raised by later LLM pass.",
            "source_name": "code-vuln-hunter",
            "details": {
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert rediscovered.status_code == 201
    assert rediscovered.json()["finding"]["slug"] == "CH-001"
    assert rediscovered.json()["finding"]["workflow_status"] == "false_positive"
    assert rediscovered.json()["finding"]["verification_disposition"] == "false_positive"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 1
    assert payload[0]["workflow_status"] == "false_positive"
    assert "Re-raised by later LLM pass." in payload[0]["notes"]
    assert json.loads(payload[0]["details_json"])["kill_check"] == 2
    assert json.loads(payload[0]["details_json"])["kill_reason"] == "upstream guard bounds header length to 8192 bytes."


def test_false_positive_title_fallback_does_not_suppress_distinct_finding(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    original = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-020",
            "title": "Shared parser bug title",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "overflow-a",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Suppressed integer overflow hypothesis.",
            "evidence_ref": "tools/analysis-state/a.json",
            "notes": "Verifier killed the original hypothesis.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "size guard blocks the arithmetic path.",
                "evidence": "validate_length() blocks the original path.",
                "impact": "No live issue on this path.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert original.status_code == 201

    distinct = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Shared parser bug title",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "overflow-b",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:128",
            "summary": "Different defect family at the same location.",
            "evidence_ref": "tools/analysis-state/b.json",
            "notes": "Newly verified buffer overwrite path.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "memcpy() uses unchecked attacker length.",
                "impact": "Heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert distinct.status_code == 201
    assert distinct.json()["finding"]["slug"] != "CH-020"
    assert distinct.json()["finding"]["workflow_status"] == "active"
    assert distinct.json()["finding"]["verification_disposition"] == "confirmed"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 2
    assert {item["workflow_status"] for item in payload} == {"false_positive", "active"}


def test_root_cause_free_false_positive_findings_stay_semantically_sticky(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    original = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-025",
            "title": "Shared parser size bug",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:150",
            "summary": "Suppressed parser hypothesis without a root cause key.",
            "evidence_ref": "tools/analysis-state/original.json",
            "notes": "Verifier killed the original hypothesis.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "bounded before arithmetic.",
                "evidence": "size guard blocks the path.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert original.status_code == 201

    rediscovered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Shared parser size bug",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "integer-overflow",
            "root_cause_key": "",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:150",
            "summary": "Rediscovered without a root cause key.",
            "evidence_ref": "tools/analysis-state/rediscovered.json",
            "notes": "Later analysis pass re-raised the same parser concern.",
            "source_name": "code-vuln-hunter",
            "details": {"impact": "Potential heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert rediscovered.status_code == 201
    assert rediscovered.json()["finding"]["slug"] == "CH-025"
    assert rediscovered.json()["finding"]["workflow_status"] == "false_positive"
    assert rediscovered.json()["finding"]["verification_disposition"] == "false_positive"


def test_coverage_items_expression_unique_index_blocks_nullable_duplicates(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201
    service_id = ingest.json()["service"]["id"]

    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?",
                ("2026-03-30-120000-example",),
            ).fetchone()["id"]
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO assessment_coverage_items (
                    engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    None,
                    service_id,
                    "anonymous",
                    "service",
                    "service-validation",
                    "pending",
                    "duplicate logical coverage row",
                ),
            )


def test_merge_into_false_positive_target_is_rejected(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-030",
            "title": "Live parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "live-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:211",
            "summary": "Live finding.",
            "evidence_ref": "tools/analysis-state/live.json",
            "notes": "Confirmed by hunter.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Unchecked copy", "impact": "Heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-031",
            "title": "Suppressed parser issue",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:333",
            "summary": "Suppressed by verifier.",
            "evidence_ref": "tools/analysis-state/suppressed.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 5,
                "kill_reason": "Build flag disables the path in production.",
                "evidence": "Code is behind a debug-only build flag.",
                "impact": "Not reachable in production.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert target.status_code == 201

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-030",
            "target_slug": "CH-031",
            "reason": "Attempted merge into suppressed target.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 400
    assert "false_positive target" in merge.json()["detail"]


def test_merge_false_positive_source_preserves_live_target(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-032",
            "title": "Suppressed parser duplicate",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_state": "verified",
            "verification_disposition": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-duplicate",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:211",
            "summary": "Duplicate was previously suppressed by verifier.",
            "evidence_ref": "tools/analysis-state/suppressed-duplicate.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 6,
                "kill_reason": "Old triage considered the path dead.",
                "evidence": "Verifier marked the duplicate as unreachable.",
                "impact": "No separate issue remained.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-033",
            "title": "Live parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "live-parser-target",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:211",
            "summary": "Target finding is still live.",
            "evidence_ref": "tools/analysis-state/live-target.json",
            "notes": "Confirmed by hunter.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Unchecked copy", "impact": "Heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert target.status_code == 201

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-032",
            "target_slug": "CH-033",
            "reason": "Suppressed duplicate should merge into the live target without downgrading it.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 200
    merge_payload = merge.json()
    assert merge_payload["target"]["workflow_status"] == "active"
    assert merge_payload["target"]["verification_state"] == "verified"
    assert merge_payload["target"]["verification_disposition"] == "confirmed"
    assert merge_payload["source"]["workflow_status"] == "merged"
    assert merge_payload["source"]["verification_state"] == "unreviewed"
    assert merge_payload["source"]["verification_disposition"] == "none"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    by_slug = {item["slug"]: item for item in findings.json()}
    assert by_slug["CH-033"]["workflow_status"] == "active"
    assert by_slug["CH-033"]["verification_state"] == "verified"
    assert by_slug["CH-033"]["verification_disposition"] == "confirmed"
    assert by_slug["CH-032"]["workflow_status"] == "merged"
    assert by_slug["CH-032"]["verification_state"] == "unreviewed"
    assert by_slug["CH-032"]["verification_disposition"] == "none"


def test_findings_verify_downgrade_records_previous_severity_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-040",
            "title": "Privilege escalation via export endpoint",
            "severity": "critical",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "access-control",
            "root_cause_key": "export-privesc",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/export",
            "summary": "Privilege escalation path needs verification.",
            "evidence_ref": "tools/analysis-state/export.json",
            "notes": "Initial hunt output.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Role claim appears attacker-controlled.",
                "impact": "Potential admin export access.",
            },
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-040/verify",
        json={
            "disposition": "downgraded",
            "new_severity": "high",
            "reason_code": "limited-scope",
            "reason_text": "The export bug is real but constrained to project-scoped data.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-040.json",
            "evidence_ref": "tools/analysis-state/code-verification/CH-040.json",
            "notes": "Severity reduced after tracing authorization boundaries.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Project scoping check limits the blast radius.",
                "impact": "Unauthorized project export, not full admin compromise.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["severity"] == "high"
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_state"] == "verified"
    assert payload["finding"]["verification_disposition"] == "downgraded"
    assert payload["transition"]["action"] == "verified_downgraded"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-040/transitions"
    )
    assert transitions.status_code == 200
    latest = transitions.json()[0]
    assert latest["from_severity"] == "critical"
    assert latest["to_severity"] == "high"
    assert json.loads(latest["metadata_json"])["previous_severity"] == "critical"


def test_findings_verify_disputed_keeps_finding_live(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-041",
            "title": "Ambiguous parser state confusion",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "state-confusion",
            "root_cause_key": "parser-state-confusion",
            "auth_context": "anonymous",
            "canonical_location": "file:src/parser.c:411",
            "summary": "Verifier could not conclusively settle exploitability.",
            "evidence_ref": "tools/analysis-state/parser-state.json",
            "notes": "Needs further operator review.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "State machine enters the suspicious branch with malformed input.",
                "impact": "Potential parse confusion with unclear reachability.",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 201

    disputed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-041/verify",
        json={
            "disposition": "disputed",
            "reason_code": "conflicting-evidence",
            "reason_text": "Reachability differs between the static trace and runtime evidence.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-041.json",
            "notes": "Escalated for operator review.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Static path exists, but runtime repro did not reach the sink.",
                "impact": "Exploitability remains disputed.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert disputed.status_code == 200
    payload = disputed.json()
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_state"] == "disputed"
    assert payload["finding"]["verification_disposition"] == "none"
    assert payload["transition"]["action"] == "verification_disputed"

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert all(item["slug"] != "CH-041" for item in report_findings.json())


def test_findings_verify_rejects_records_merged_after_validation(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-042",
            "title": "Verify/merge race candidate",
            "severity": "high",
            "workflow_status": "active",
            "verification_state": "unreviewed",
            "verification_disposition": "none",
            "defect_family": "auth-bypass",
            "root_cause_key": "verify-merge-race",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/export",
            "summary": "Verify should fail if the finding is merged after validation.",
            "evidence_ref": "findings.md",
            "notes": "Created for stale verify race coverage.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Export endpoint skips tenant check", "impact": "Cross-tenant export"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 201

    from app.services import state_manager

    original_patch_finding = state_manager.patch_finding
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(*args, **kwargs):
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                SET status = 'merged',
                    merged_into_finding_id = id,
                    updated_at = '2099-01-01 00:00:00'
                WHERE slug = 'CH-042'
                """
            )
            connection.commit()
        return original_patch_finding(*args, **kwargs)

    monkeypatch.setattr(state_manager, "patch_finding", race)

    verify = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-042/verify",
        json={
            "disposition": "confirmed",
            "reason_code": "validated",
            "reason_text": "Late verify should not overwrite a merged finding.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-042.json",
            "evidence_ref": "tools/analysis-state/code-verification/CH-042.json",
            "notes": "Verification raced with a merge.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Tenant check is bypassable with crafted export ids.",
                "impact": "Cross-tenant export remains reachable.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )

    assert verify.status_code == 409
    assert "changed since it was loaded" in verify.json()["detail"]


def test_findings_verify_rejects_merged_records(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-050",
            "title": "Merged source",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merged-source",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Source finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "source evidence", "impact": "source impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-051",
            "title": "Merge target",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/target",
            "summary": "Target finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "target evidence", "impact": "target impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert target.status_code == 201

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-050",
            "target_slug": "CH-051",
            "reason": "Merged duplicate.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 200

    verify = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-050/verify",
        json={
            "disposition": "confirmed",
            "reason_text": "Should not revive merged finding.",
            "source_name": "code-vuln-verifier",
            "details": {"evidence": "n/a", "impact": "n/a"},
        },
    )
    assert verify.status_code == 400
    assert "merged findings cannot be re-verified" in verify.json()["detail"]


def test_merge_findings_rejects_target_changed_after_snapshot(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    source = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-052",
            "title": "First duplicate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-race-source",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Source finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "source evidence", "impact": "source impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert source.status_code == 201

    target = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-053",
            "title": "Second duplicate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_state": "verified",
            "verification_disposition": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-race-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/target",
            "summary": "Target finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "target evidence", "impact": "target impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert target.status_code == 201

    from app.services import state_manager

    original_append_notes = state_manager._append_notes
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    injected = False

    def race(existing: str, incoming: str) -> str:
        nonlocal injected
        if not injected and incoming.startswith("Merged CH-052"):
            injected = True
            with sqlite3.connect(str(db_path)) as connection:
                connection.execute(
                    """
                    UPDATE assessment_findings
                    SET notes = notes || '\nConcurrent merge writer',
                        updated_at = '2099-01-01 00:00:00'
                    WHERE slug = 'CH-053'
                    """
                )
                connection.commit()
        return original_append_notes(existing, incoming)

    monkeypatch.setattr(state_manager, "_append_notes", race)

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-052",
            "target_slug": "CH-053",
            "reason": "Stale merge should not overwrite a concurrently updated target.",
            "source_name": "operator",
        },
    )

    assert merge.status_code == 409
    assert "changed since it was loaded" in merge.json()["detail"]


def test_coverage_patch_rejects_unknown_status_values(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={"url": "https://example.com/profile", "discovery_source": "recon"},
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    coverage_item_id = coverage_items.json()[0]["id"]

    patch = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{coverage_item_id}",
        json={"status": "complete-ish", "notes": "bad status"},
    )
    assert patch.status_code == 400
    assert "invalid coverage status" in patch.json()["detail"]


def test_incompatible_local_database_refuses_to_start_and_preserves_file(isolate_settings):
    """Auto-reset was removed: an incompatible DB must raise, never be unlinked.

    Silently deleting the orchestrator DB on a schema mismatch is unrecoverable
    data loss (findings, probe runs, command runs, code analysis). The
    orchestrator now refuses to start and tells the operator how to resolve.
    """
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

    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module.init_db()
    message = str(exc.value)
    assert "Refusing to start" in message
    assert "delete engagement history" in message

    assert db_path.exists(), "incompatible DB must NOT be unlinked"
    with sqlite3.connect(str(db_path)) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "runs" in table_names, "legacy table must still be present after refuse"
        event_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        assert "run_id" in event_columns, "legacy column must still be present after refuse"


def test_filesystem_engagement_removal_retains_db_row(client, isolate_settings):
    """Sync must NOT cascade-delete findings when an engagement directory
    vanishes. The old behavior silently wiped every finding/probe/command-run
    when the operator renamed, archived, or cleaned up an engagement dir.
    Deletion is now explicit — via ``DELETE /engagements/{key}`` — and this
    test exists to lock the additive-only sync contract in place.
    """
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    assert len(response.json()) == 1

    for path in sorted(engagement_dir.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    engagement_dir.rmdir()

    response = client.get("/engagements")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1, "DB row must survive filesystem removal"
    assert rows[0]["key"] == "2026-03-30-120000-example"


def test_deleted_session_is_pruned_from_database(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert len(response.json()) == 1

    (engagement_dir / "sessions" / "index.json").write_text("[]\n", encoding="utf-8")

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert response.json() == []
