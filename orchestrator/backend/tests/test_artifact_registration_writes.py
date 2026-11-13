"""One artifact registration is one row write, and the text index follows content.

``assessment_artifacts`` rows carry each file's full extracted text, and the
content-backed FTS5 index re-tokenizes a row's whole text whenever its update
trigger fires. A registration that wrote its row twice (the upsert, then a
second UPDATE for producer attribution), or an update trigger that fired for
columns the index does not hold, re-indexed megabytes of unchanged text on every
re-registration. These tests pin the write counts and the index contents, not
SQL wording: ``total_changes`` counts every row a statement and its triggers
write, the FTS shadow table grows whenever the index is rewritten, and
``integrity-check`` proves the index matches the table.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module
from app.services import artifact_index
from tests.test_artifact_resume_api import BASE, ENGAGEMENT_KEY, _write_engagement

_FTS_TABLES = (
    ("assessment_artifacts", "assessment_artifacts_fts"),
    ("assessment_command_runs", "assessment_command_runs_fts"),
    ("intel_search_index", "intel_search_fts"),
    ("activity_entries", "activity_entries_fts"),
)


def _engagement(client, isolate_settings):
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id in ("WRITER-1", "WRITER-2"):
        created = client.post(
            f"{BASE}/dispatches",
            json={"agent_id": agent_id, "agent_role": "report-writer", "task": "notes"},
        )
        assert created.status_code in {200, 201}, created.text
    engagement = db_module.get_engagement_by_key(ENGAGEMENT_KEY)
    assert engagement is not None
    return eng, engagement.id


def _fts_segments(connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM assessment_artifacts_fts_data").fetchone()[0])


def _matches(connection, term: str) -> list[int]:
    return [
        int(row[0])
        for row in connection.execute(
            "SELECT rowid FROM assessment_artifacts_fts WHERE assessment_artifacts_fts MATCH ? ORDER BY rowid",
            (term,),
        ).fetchall()
    ]


def _integrity_check(connection, fts: str) -> None:
    connection.execute(f"INSERT INTO {fts}({fts}, rank) VALUES ('integrity-check', 1)")


def _register(engagement_id: int, path: str, **kwargs) -> tuple[dict, int, int]:
    """Register ``path`` and return (row, rows written, FTS segments added)."""
    with db_module.get_connection() as connection:
        changes_before = connection.total_changes
        segments_before = _fts_segments(connection)
    row = artifact_index.register_artifact(engagement_id, path=path, kind="note", **kwargs)
    with db_module.get_connection() as connection:
        return (
            row,
            connection.total_changes - changes_before,
            _fts_segments(connection) - segments_before,
        )


def test_reregistering_unchanged_bytes_writes_the_row_once_and_keeps_the_index(
    client, isolate_settings
) -> None:
    eng, engagement_id = _engagement(client, isolate_settings)
    (eng / "notes").mkdir(exist_ok=True)
    (eng / "notes" / "acme.md").write_text("acmewidget telemetry\n" * 2000, encoding="utf-8")
    first, _, first_segments = _register(engagement_id, "notes/acme.md", producer_agent_id="WRITER-1")
    assert first_segments >= 1

    again, written, segments = _register(engagement_id, "notes/acme.md", producer_agent_id="WRITER-2")

    assert written == 1
    assert segments == 0
    assert again["sha256"] == first["sha256"]
    assert again["producer_history"] == ["WRITER-1", "WRITER-2"]
    assert again["content_producer_agent_id"] == "WRITER-2"
    with db_module.get_connection() as connection:
        assert _matches(connection, "acmewidget") == [int(first["id"])]
        _integrity_check(connection, "assessment_artifacts_fts")


def test_changed_bytes_reindex_the_new_text_and_attribute_the_new_producer(
    client, isolate_settings
) -> None:
    eng, engagement_id = _engagement(client, isolate_settings)
    note = eng / "notes" / "acme.md"
    note.parent.mkdir(exist_ok=True)
    note.write_text("acmeoldterm\n", encoding="utf-8")
    first, _, _ = _register(engagement_id, "notes/acme.md", producer_agent_id="WRITER-1")
    note.write_text("acmenewterm\n", encoding="utf-8")

    changed, written, segments = _register(engagement_id, "notes/acme.md")

    assert segments >= 1
    assert written > 1  # the row plus the FTS rows its trigger rewrote
    assert changed["id"] == first["id"]
    assert changed["producer_history"] == ["WRITER-1"]
    # Unattributed new bytes have no content producer; the last attribution carries.
    assert changed["content_producer_agent_id"] is None
    assert changed["producer_agent_id"] == "WRITER-1"
    with db_module.get_connection() as connection:
        assert _matches(connection, "acmenewterm") == [int(first["id"])]
        assert _matches(connection, "acmeoldterm") == []
        _integrity_check(connection, "assessment_artifacts_fts")


def test_metadata_only_updates_leave_the_index_alone(client, isolate_settings) -> None:
    eng, engagement_id = _engagement(client, isolate_settings)
    (eng / "notes").mkdir(exist_ok=True)
    (eng / "notes" / "acme.md").write_text("acmescratchterm\n", encoding="utf-8")
    row, _, _ = _register(engagement_id, "notes/acme.md")

    with db_module.get_connection() as connection:
        changes_before = connection.total_changes
        connection.execute(
            "UPDATE assessment_artifacts SET scratch = 1, updated_at = '2026-11-14T00:00:00Z' WHERE id = ?",
            (int(row["id"]),),
        )
        assert connection.total_changes - changes_before == 1
        changes_before = connection.total_changes
        connection.execute(
            "UPDATE assessment_artifacts SET related_finding_slug = 'VA-900' WHERE id = ?",
            (int(row["id"]),),
        )
        assert connection.total_changes - changes_before > 1
    with db_module.get_connection() as connection:
        assert _matches(connection, "VA") == [int(row["id"])]
        _integrity_check(connection, "assessment_artifacts_fts")


def _schema_version(db_path) -> int:
    with sqlite3.connect(str(db_path)) as connection:
        return int(connection.execute("PRAGMA schema_version").fetchone()[0])


@pytest.mark.parametrize(("base", "fts"), _FTS_TABLES)
def test_existing_database_gains_the_column_scoped_update_trigger_once(
    client, isolate_settings, base: str, fts: str
) -> None:
    """Startup replaces an update trigger whose stored SQL differs, and only then."""
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        (current,) = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?", (f"{base}_au",)
        ).fetchone()
        assert "WHEN" in current.upper()
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({fts})").fetchall()]
        listed = ", ".join(columns)
        old_values = ", ".join(f"old.{column}" for column in columns)
        new_values = ", ".join(f"new.{column}" for column in columns)
        connection.execute(f"DROP TRIGGER {base}_au")
        connection.execute(
            f"CREATE TRIGGER {base}_au AFTER UPDATE ON {base} BEGIN "
            f"INSERT INTO {fts}({fts}, rowid, {listed}) VALUES ('delete', old.id, {old_values}); "
            f"INSERT INTO {fts}(rowid, {listed}) VALUES (new.id, {new_values}); END"
        )
    db_module.close_thread_connection()

    db_module._startup_database_fingerprint = None
    db_module.init_db()
    upgraded = _schema_version(db_path)
    db_module._startup_database_fingerprint = None
    db_module.init_db()

    assert _schema_version(db_path) == upgraded
    with sqlite3.connect(str(db_path)) as connection:
        (stored,) = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?", (f"{base}_au",)
        ).fetchone()
        assert " ".join(stored.split()) == " ".join(current.split())
        _integrity_check(connection, fts)


def test_bulk_registration_checks_producers_in_one_query_and_refuses_unknown_ones(
    client, isolate_settings
) -> None:
    eng, engagement_id = _engagement(client, isolate_settings)
    (eng / "notes").mkdir(exist_ok=True)
    items = []
    for index in range(12):
        (eng / "notes" / f"n{index}.md").write_text(f"acme note {index}\n", encoding="utf-8")
        producer = ("WRITER-1", "WRITER-2", "NOBODY")[index % 3]
        items.append({"path": f"notes/n{index}.md", "kind": "note", "producer_agent_id": producer})

    statements: list[str] = []
    with db_module.get_connection() as connection:
        connection.set_trace_callback(statements.append)
        try:
            result = artifact_index.register_artifacts_bulk(engagement_id, items)
        finally:
            connection.set_trace_callback(None)

    producer_checks = [sql for sql in statements if "FROM assessment_dispatches" in sql]
    assert len(producer_checks) == 1, producer_checks
    assert result["requested"] == 12 and result["registered"] == 8 and result["failed"] == 4
    refused = [row for row in result["outcomes"] if row["outcome"] == "failed"]
    assert [row["index"] for row in refused] == [2, 5, 8, 11]
    assert all(row["status_code"] == 404 for row in refused)
    assert all("'NOBODY' names no recorded dispatch" in row["detail"] for row in refused)
    assert [row["producer_agent_id"] for row in result["artifacts"]] == ["WRITER-1", "WRITER-2"] * 4
