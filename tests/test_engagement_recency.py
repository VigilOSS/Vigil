"""Recent engagement selection reads durable work without starting a backend."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from vigil_cli import client_sessions, engagements
from vigil_cli.paths import resolve_orchestrator_data_dir


def make_engagement(root: Path, *, created: str = "2026-01-01T00:00:00Z") -> Path:
    folder = root / "engagements/acme"
    folder.mkdir(parents=True)
    (folder / "scope.json").write_text(json.dumps({"engagement_type": "web", "current_phase": "recon", "status": "in_progress"}))
    (folder / "engagement.json").write_text(json.dumps({"target": "https://example.com", "created_at": created}))
    return folder


def database(root: Path) -> sqlite3.Connection:
    path = resolve_orchestrator_data_dir(root) / "orchestrator.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE engagements(id INTEGER PRIMARY KEY, key TEXT, engagement_root TEXT, updated_at TEXT)")
    connection.execute("INSERT INTO engagements VALUES(1,'acme',?,'2099-01-01')", (str(root / "engagements/acme"),))
    connection.commit()
    return connection


@pytest.mark.parametrize("source", ["assessment_findings", "events", "activity_entries", "assessment_proof_work_events", "remediation_approvals"])
def test_recent_durable_work_is_visible_without_narrative_log(tmp_path, source):
    make_engagement(tmp_path)
    with database(tmp_path) as connection:
        if source == "assessment_proof_work_events":
            connection.execute("CREATE TABLE assessment_proof_work(id INTEGER,engagement_id INTEGER)")
            connection.execute("INSERT INTO assessment_proof_work VALUES(3,1)")
            owner, owner_id = "work_id", 3
        elif source == "remediation_approvals":
            connection.execute("CREATE TABLE remediation_cases(id INTEGER,engagement_id INTEGER)")
            connection.execute("INSERT INTO remediation_cases VALUES(3,1)")
            owner, owner_id = "case_id", 3
        else:
            owner, owner_id = "engagement_id", 1
        stamp = "occurred_at" if source == "activity_entries" else "created_at"
        connection.execute(f"CREATE TABLE {source}({owner} INTEGER,{stamp} TEXT)")
        connection.execute(f"INSERT INTO {source} VALUES(?,?)", (owner_id, "2026-10-18T20:30:00.125-04:00"))
    row = engagements.list_engagements(tmp_path)[0]
    assert getattr(row, "last_activity_at", "") == "2026-10-19T00:30:00.125000+00:00"


def test_absent_database_uses_creation_without_creating_runtime_data(tmp_path):
    make_engagement(tmp_path)
    row = engagements.list_engagements(tmp_path)[0]
    assert getattr(row, "last_activity_at", "") == "2026-01-01T00:00:00+00:00"
    assert getattr(row, "activity_incomplete", False)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["engagements"]


def test_expired_official_sessions_retain_historical_start(tmp_path, monkeypatch):
    folder = make_engagement(tmp_path)
    monkeypatch.setattr(client_sessions, "_process_identity", lambda _: "test-birth")
    monkeypatch.setattr(client_sessions, "application_root_for_workspace", lambda _: tmp_path)
    monkeypatch.setattr(client_sessions, "application_provenance", lambda _: {"root": str(tmp_path), "version": "1.0", "content_sha256": "a" * 64})
    receipt = client_sessions.record_client_session(tmp_path, folder, "codex", "web")
    monkeypatch.setattr(client_sessions, "_process_identity", lambda _: None)
    assert client_sessions.active_client_sessions(tmp_path) == ()
    row = engagements.list_engagements(tmp_path)[0]
    assert getattr(row, "last_activity_at", "") == receipt["started_at"]


def test_official_open_marker_is_not_a_fake_process_receipt(tmp_path):
    folder = make_engagement(tmp_path)
    recorder = getattr(client_sessions, "record_client_launch", lambda *a, **kw: None)
    recorder(tmp_path, folder, "zcode", "web", event="workspace_opened")
    row = engagements.list_engagements(tmp_path)[0]
    assert row.last_activity_at > "2026-01-01T00:00:00+00:00"
    assert client_sessions.active_client_sessions(tmp_path) == ()


@pytest.mark.parametrize("timestamps,expected", [
    (["2026-10-19 01:00:00", "2026-10-18T23:30:00-04:00"], "2026-10-19T03:30:00+00:00"),
    (["not-a-date", "2026-10-19T01:00:00.001Z"], "2026-10-19T01:00:00.001000+00:00"),
])
def test_timestamps_compare_chronologically_not_lexically(tmp_path, timestamps, expected):
    make_engagement(tmp_path)
    with database(tmp_path) as connection:
        connection.execute("CREATE TABLE events(engagement_id INTEGER,created_at TEXT)")
        connection.executemany("INSERT INTO events VALUES(1,?)", [(stamp,) for stamp in timestamps])
    assert engagements.list_engagements(tmp_path)[0].last_activity_at == expected


def test_committed_wal_activity_is_visible_while_writer_is_open(tmp_path):
    make_engagement(tmp_path)
    connection = database(tmp_path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE events(engagement_id INTEGER,created_at TEXT)")
        connection.execute("INSERT INTO events VALUES(1,'2026-10-19T01:00:00Z')")
        connection.commit()
        assert engagements.list_engagements(tmp_path)[0].last_activity_at == "2026-10-19T01:00:00+00:00"
    finally:
        connection.close()


def test_housekeeping_sync_timestamp_does_not_advance_activity(tmp_path):
    make_engagement(tmp_path)
    with database(tmp_path) as connection:
        connection.execute("CREATE TABLE code_repos(engagement_id INTEGER,created_at TEXT,updated_at TEXT)")
        connection.execute("INSERT INTO code_repos VALUES(1,'2026-02-01','2099-01-01')")
    assert engagements.list_engagements(tmp_path)[0].last_activity_at == "2026-01-01T00:00:00+00:00"


@pytest.mark.parametrize("table", ["assessment_findings", "assessment_proof_work", "remediation_cases"])
def test_meaningful_work_owner_edits_count_without_extra_log(tmp_path, table):
    make_engagement(tmp_path)
    with database(tmp_path) as connection:
        connection.execute(f"CREATE TABLE {table}(engagement_id INTEGER,created_at TEXT,updated_at TEXT)")
        connection.execute(f"INSERT INTO {table} VALUES(1,'2026-02-01','2026-10-18T23:00:00Z')")
    assert engagements.list_engagements(tmp_path)[0].last_activity_at == "2026-10-18T23:00:00+00:00"


def test_blue_proposal_approval_embedded_clock_is_meaningful_work(tmp_path):
    make_engagement(tmp_path)
    with database(tmp_path) as connection:
        connection.execute("CREATE TABLE assessment_dispatch_decisions(engagement_id INTEGER,created_at TEXT,resolution_json TEXT)")
        connection.execute("INSERT INTO assessment_dispatch_decisions VALUES(1,'2026-02-01',?)",
                           (json.dumps({"approved_at": "2026-10-19T03:00:00Z"}),))
    assert engagements.list_engagements(tmp_path)[0].last_activity_at == "2026-10-19T03:00:00+00:00"


@pytest.mark.parametrize("state", ["corrupt", "locked"])
def test_unavailable_database_preserves_scope_clock(tmp_path, state):
    folder = make_engagement(tmp_path)
    scope = json.loads((folder / "scope.json").read_text())
    scope["phase_changed_at"] = "2026-10-18T20:00:00Z"
    (folder / "scope.json").write_text(json.dumps(scope))
    connection = database(tmp_path)
    try:
        if state == "corrupt":
            connection.close()
            (resolve_orchestrator_data_dir(tmp_path) / "orchestrator.sqlite3").write_bytes(b"invalid SQLite")
        else:
            connection.execute("BEGIN EXCLUSIVE")
        row = engagements.list_engagements(tmp_path)[0]
        assert row.last_activity_at == "2026-10-18T20:00:00+00:00"
        assert row.activity_incomplete
    finally:
        connection.close()


def test_invalid_history_record_does_not_hide_other_history_or_weaken_guard(tmp_path, monkeypatch):
    folder = make_engagement(tmp_path)
    client_sessions.record_client_launch(tmp_path, folder, "zcode", "web", event="workspace_opened")
    directory = client_sessions._registry_directory(tmp_path)
    directory.mkdir(parents=True)
    (directory / "invalid.json").write_text("{}")
    row = engagements.list_engagements(tmp_path)[0]
    assert row.last_activity_at > "2026-01-01T00:00:00+00:00"
    assert row.activity_incomplete
    with pytest.raises(SystemExit, match="Invalid client session registry entry"):
        client_sessions.active_client_sessions(tmp_path)


def test_launch_history_storage_failure_warns_without_blocking_start(tmp_path, monkeypatch, capsys):
    folder = make_engagement(tmp_path)
    def unavailable(_):
        raise OSError("storage unavailable")
    monkeypatch.setattr(client_sessions, "resolve_runtime_state_dir", unavailable)
    client_sessions.record_client_launch(tmp_path, folder, "codex", "web")
    assert "Warning:" in capsys.readouterr().err


def test_history_unsafe_entries_are_unknown_without_following_them(tmp_path):
    folder = make_engagement(tmp_path)
    client_sessions.record_client_launch(tmp_path, folder, "zcode", "web", event="workspace_opened")
    directory = client_sessions._registry_directory(tmp_path)
    directory.mkdir(parents=True)
    (directory / "external.json").symlink_to(tmp_path / "missing-record")
    row = engagements.list_engagements(tmp_path)[0]
    assert row.last_activity_at > "2026-01-01T00:00:00+00:00"
    assert row.activity_incomplete
