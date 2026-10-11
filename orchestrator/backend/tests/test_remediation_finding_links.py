from __future__ import annotations

import json
import sqlite3

import pytest

from app import db
from conftest import _real_init_db


def _owners(isolate_settings):
    if db._startup_database_fingerprint is None:
        db.init_db()
    root = isolate_settings["engagements_dir"]
    source = db.create_engagement("assessment", "Assessment", "in_progress", str(root / "assessment"), "web")
    destination = db.create_engagement("repairs", "Repairs", "in_progress", str(root / "repairs"), "remediation")
    (root / "repairs").mkdir()
    with db.get_connection() as connection:
        findings = [connection.execute(
            "INSERT INTO assessment_findings(engagement_id,slug,title,severity,verification_status) VALUES(?,?,?,?,?)",
            (source.id, f"SEC-{index}", f"Finding {index}", "high", "confirmed"),
        ).lastrowid for index in (1, 2)]
    return source, destination, findings


def _legacy_database(destination, findings, *, slug="SEC-1", key="assessment"):
    db.close_thread_connection()
    with sqlite3.connect(db.database_path()) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TABLE IF EXISTS remediation_case_findings")
        connection.execute("DROP TABLE remediation_cases")
        connection.execute("""CREATE TABLE remediation_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            source_type TEXT NOT NULL CHECK(source_type IN ('jira','bounty')),
            source_key TEXT NOT NULL, title TEXT NOT NULL, snapshot_json TEXT NOT NULL,
            linked_finding_engagement_key TEXT, linked_finding_slug TEXT,
            status TEXT NOT NULL DEFAULT 'intake', worktree_path TEXT, worktree_branch TEXT,
            worktree_revision TEXT, verification_plan TEXT NOT NULL DEFAULT '',
            baseline_json TEXT NOT NULL DEFAULT '{}', release_plan_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id,source_type,source_key))""")
        connection.execute(
            "INSERT INTO remediation_cases(id,engagement_id,source_type,source_key,title,snapshot_json,linked_finding_engagement_key,linked_finding_slug) VALUES(7,?,'jira','SEC-7','Original','{}',?,?)",
            (destination.id, key, slug),
        )
        connection.execute("INSERT INTO remediation_approvals(id,case_id,reviewer,review_digest,approved_revision) VALUES(8,7,'owner','old-digest','revision')")
        connection.execute("INSERT INTO remediation_evidence(id,case_id,kind,method,observed,proved) VALUES(9,7,'baseline','HTTP','observed','proved')")
        connection.execute("INSERT INTO remediation_deployments(id,case_id,approval_id,workflow,run_id,environment,expected_revision,observed_revision,actor) VALUES(10,7,8,'deploy','run','development','revision','revision','owner')")
        connection.execute("UPDATE sqlite_sequence SET seq=99 WHERE name='remediation_cases'")


def test_legacy_links_migrate_to_canonical_ids_without_rewriting_history(isolate_settings):
    _, destination, findings = _owners(isolate_settings)
    _legacy_database(destination, findings)
    _real_init_db()
    with db.get_connection() as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(remediation_cases)")}
        assert "linked_finding_slug" not in columns
        assert "linked_finding_engagement_key" not in columns
        assert tuple(connection.execute("SELECT case_id,finding_id FROM remediation_case_findings").fetchone()) == (7, findings[0])
        assert connection.execute("SELECT review_digest FROM remediation_approvals WHERE id=8").fetchone()[0] == "old-digest"
        assert connection.execute("SELECT proved FROM remediation_evidence WHERE id=9").fetchone()[0] == "proved"
        assert connection.execute("SELECT approval_id FROM remediation_deployments WHERE id=10").fetchone()[0] == 8
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT seq FROM sqlite_sequence WHERE name='remediation_cases'").fetchone()[0] == 99
    _real_init_db()
    assert list(db.database_path().parent.glob("*remediation-finding-links*"))


@pytest.mark.parametrize(("key", "slug"), [("assessment", "missing"), ("missing", "SEC-1"), ("assessment", None)])
def test_unresolved_legacy_links_fail_atomically(isolate_settings, key, slug):
    _, destination, findings = _owners(isolate_settings)
    _legacy_database(destination, findings, key=key, slug=slug)
    with pytest.raises(RuntimeError, match="remediation case 7"):
        _real_init_db()
    with sqlite3.connect(db.database_path()) as connection:
        assert connection.execute("SELECT linked_finding_engagement_key,linked_finding_slug FROM remediation_cases WHERE id=7").fetchone() == (key, slug)
        assert connection.execute("SELECT review_digest FROM remediation_approvals WHERE id=8").fetchone()[0] == "old-digest"


def test_migration_refuses_to_reuse_an_existing_replacement_table(isolate_settings):
    _, destination, findings = _owners(isolate_settings)
    _legacy_database(destination, findings)
    with sqlite3.connect(db.database_path()) as connection:
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='remediation_cases'").fetchone()[0]
        connection.execute(schema.replace("CREATE TABLE remediation_cases", "CREATE TABLE remediation_cases_next", 1))
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        _real_init_db()
    with sqlite3.connect(db.database_path()) as connection:
        assert connection.execute("SELECT linked_finding_slug FROM remediation_cases WHERE id=7").fetchone()[0] == "SEC-1"
        assert connection.execute("SELECT COUNT(*) FROM remediation_cases_next").fetchone()[0] == 0


def test_case_links_multiple_findings_with_reciprocal_current_summaries(client, isolate_settings):
    _, _, findings = _owners(isolate_settings)
    created = client.post("/engagements/repairs/remediation/cases", json={
        "source_type": "jira", "source_key": "SEC-7", "title": "Shared fix", "snapshot": {"report": "Immutable"},
        "finding_ids": findings,
    })
    assert created.status_code == 201, created.text
    case = created.json()
    assert [item["id"] for item in case["linked_findings"]] == findings
    digest = case["review_digest"]
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_findings SET title='Current title',verification_status='disproven' WHERE id=?", (findings[0],))
    current = client.get(f"/engagements/repairs/remediation/cases/{case['id']}").json()
    assert current["linked_findings"][0]["title"] == "Current title"
    assert current["linked_findings"][0]["verification_status"] == "disproven"
    assert current["snapshot"] == {"report": "Immutable"}
    reciprocal = client.get("/engagements/assessment/remediation/findings/SEC-1/cases")
    assert reciprocal.status_code == 200, reciprocal.text
    assert reciprocal.json()[0]["engagement_key"] == "repairs"
    assert reciprocal.json()[0]["id"] == case["id"]
    assert "snapshot" not in reciprocal.json()[0]
    patched = client.patch(f"/engagements/repairs/remediation/cases/{case['id']}", json={"finding_ids": [findings[1]]})
    assert patched.status_code == 200, patched.text
    assert patched.json()["review_digest"] != digest
    assert client.get("/engagements/assessment/remediation/findings/SEC-1/cases").json() == []


def test_case_link_validation_is_atomic(client, isolate_settings):
    _, _, findings = _owners(isolate_settings)
    payload = {"source_type": "jira", "source_key": "SEC-7", "title": "Shared fix", "snapshot": {}}
    assert client.post("/engagements/repairs/remediation/cases", json={**payload, "finding_ids": [findings[0], 999999]}).status_code == 400
    assert client.get("/engagements/repairs/remediation/cases").json() == []
    created = client.post("/engagements/repairs/remediation/cases", json={**payload, "finding_ids": findings}).json()
    assert client.patch(f"/engagements/repairs/remediation/cases/{created['id']}", json={"title": "Changed", "finding_ids": [999999]}).status_code == 400
    assert client.get(f"/engagements/repairs/remediation/cases/{created['id']}").json()["title"] == "Shared fix"


def test_finding_origin_requires_explicit_destination_and_captures_truthful_snapshot(client, isolate_settings):
    _, _, findings = _owners(isolate_settings)
    endpoint = "/engagements/assessment/remediation/findings/SEC-1/cases"
    assert client.post(endpoint, json={}).status_code == 422
    assert client.post(endpoint, json={"remediation_engagement_key": "assessment"}).status_code == 404
    created = client.post(endpoint, json={"remediation_engagement_key": "repairs"})
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["source_type"] == "finding"
    assert case["engagement_key"] == "repairs"
    assert case["snapshot"]["finding"]["id"] == findings[0]
    assert case["snapshot"]["finding"]["title"] == "Finding 1"
    assert [item["id"] for item in case["linked_findings"]] == [findings[0]]
    assert client.post(endpoint, json={"remediation_engagement_key": "repairs"}).status_code == 409
    assert json.dumps(case["snapshot"])


@pytest.mark.parametrize("alias", ["VA047", "FINDING-VA-047"])
def test_finding_origin_alias_captures_canonical_identity(client, isolate_settings, alias):
    _, _, findings = _owners(isolate_settings)
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_findings SET slug='VA-047' WHERE id=?", (findings[0],))
    endpoint = f"/engagements/assessment/remediation/findings/{alias}/cases"
    created = client.post(endpoint, json={"remediation_engagement_key": "repairs"})
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["source_key"] == str(findings[0])
    assert case["snapshot"]["finding"]["slug"] == "VA-047"
    assert [(item["id"], item["slug"]) for item in case["linked_findings"]] == [(findings[0], "VA-047")]
    assert client.post("/engagements/assessment/remediation/findings/VA-047/cases", json={"remediation_engagement_key": "repairs"}).status_code == 409


@pytest.mark.parametrize("alias", ["VA047", "FINDING-VA-047"])
def test_finding_cases_alias_reads_only_the_canonical_finding(client, isolate_settings, alias):
    _, _, findings = _owners(isolate_settings)
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_findings SET slug='VA-047' WHERE id=?", (findings[0],))
    created = client.post("/engagements/assessment/remediation/findings/VA-047/cases", json={"remediation_engagement_key": "repairs"})
    assert created.status_code == 201, created.text
    cases = client.get(f"/engagements/assessment/remediation/findings/{alias}/cases")
    assert cases.status_code == 200, cases.text
    assert [item["id"] for item in cases.json()] == [created.json()["id"]]
    assert cases.json()[0]["linked_findings"][0]["slug"] == "VA-047"
    assert client.get("/engagements/assessment/remediation/findings/SEC-2/cases").json() == []
    assert client.get("/engagements/repairs/remediation/findings/VA047/cases").status_code == 404
    assert client.get("/engagements/assessment/remediation/findings/VA999999/cases").status_code == 404
