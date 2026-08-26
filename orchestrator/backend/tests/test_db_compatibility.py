"""Incompatible orchestrator DBs must raise, never silently unlink."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app import db as db_module


def _write_db_with_tables(db_path: Path, sql: str) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.executescript(sql)


def test_check_is_noop_when_db_missing(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    assert not db_path.exists()
    db_module._check_database_compatibility(db_path)  # no raise, no create
    assert not db_path.exists()


def test_check_passes_on_current_schema(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        """
        CREATE TABLE engagements (id INTEGER PRIMARY KEY);
        CREATE TABLE engagement_sessions (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL
        );
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL
        );
        CREATE TABLE assessment_findings (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL
        );
        """,
    )
    db_module._check_database_compatibility(db_path)  # no raise


def test_check_raises_and_preserves_file_on_legacy_tables(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        """
        CREATE TABLE projects (id INTEGER PRIMARY KEY);
        CREATE TABLE runs (id INTEGER PRIMARY KEY);
        CREATE TABLE users (id INTEGER PRIMARY KEY);
        """,
    )
    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module._check_database_compatibility(db_path)
    assert "legacy pre-engagement tables" in str(exc.value)
    assert db_path.exists(), "incompatible DB must NOT be deleted"


def test_check_raises_on_engagement_scoped_table_missing_engagement_id(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        """
        CREATE TABLE assessment_findings (
            id INTEGER PRIMARY KEY,
            run_id INTEGER NOT NULL
        );
        """,
    )
    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module._check_database_compatibility(db_path)
    assert "run_id" in str(exc.value)
    assert db_path.exists()


def test_check_raises_on_known_scoped_table_missing_engagement_id(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        """
        CREATE TABLE assessment_findings (
            id INTEGER PRIMARY KEY,
            slug TEXT NOT NULL
        );
        """,
    )
    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module._check_database_compatibility(db_path)
    assert "missing required `engagement_id`" in str(exc.value)
    assert db_path.exists()


def test_check_raises_on_unopenable_file(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"not a sqlite database at all")
    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module._check_database_compatibility(db_path)
    assert "SQLite refused to open" in str(exc.value)
    assert db_path.exists(), "corrupt file must NOT be deleted"


def test_init_db_propagates_incompatible_error(isolate_settings):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        "CREATE TABLE projects (id INTEGER PRIMARY KEY);",
    )
    with pytest.raises(db_module.IncompatibleDatabaseError):
        db_module.init_db()
    assert db_path.exists()


def test_operational_error_passthrough_not_incompatibility(monkeypatch, isolate_settings):
    """`database is locked` must surface as OperationalError, not a mis-framed
    IncompatibleDatabaseError telling the operator to move the DB aside."""
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.touch()

    original_connect = sqlite3.connect

    class _LockedConnection:
        def __enter__(self):
            raise sqlite3.OperationalError("database is locked")

        def __exit__(self, *args):
            return False

    def _fake_connect(path, *args, **kwargs):
        if str(path) == str(db_path):
            return _LockedConnection()
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", _fake_connect)

    with pytest.raises(sqlite3.OperationalError) as exc:
        db_module._check_database_compatibility(db_path)
    assert "database is locked" in str(exc.value)
    assert db_path.exists()


def test_default_busy_timeout_stays_below_agent_client_read_timeout(monkeypatch):
    monkeypatch.delenv("VIGIL_DB_BUSY_TIMEOUT_MS", raising=False)
    assert db_module._resolve_busy_timeout_ms() == 8_000


def test_check_accepts_future_shared_table_without_engagement_id(isolate_settings):
    """A future non-engagement-scoped table with an ``assessment_`` or ``code_``
    prefix must NOT trigger a false-positive refuse-to-start unless it is added
    to the known engagement-scoped table allowlist."""
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        """
        CREATE TABLE assessment_tool_registry (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        );
        """,
    )
    db_module._check_database_compatibility(db_path)  # no raise


_LEGACY_CODE_ANALYSIS_QUEUE_SQL = """
CREATE TABLE code_analysis_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_agent TEXT NOT NULL DEFAULT '',
    lease_token TEXT NOT NULL DEFAULT '',
    repo_generation INTEGER NOT NULL DEFAULT 0,
    last_heartbeat_at TEXT,
    disposition TEXT NOT NULL DEFAULT '',
    analysis_notes TEXT NOT NULL DEFAULT '',
    skip_reason TEXT NOT NULL DEFAULT '',
    expansion_request_json TEXT NOT NULL DEFAULT '{}',
    batch_theme TEXT NOT NULL DEFAULT '',
    slot_types_json TEXT NOT NULL DEFAULT '[]',
    guidance_hypotheses_json TEXT NOT NULL DEFAULT '[]',
    cwe_coverage_json TEXT NOT NULL DEFAULT '[]',
    cross_file_triggers_json TEXT NOT NULL DEFAULT '[]',
    consumed_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
);
"""


def test_legacy_metadata_theme_is_not_elevated_to_service_owned_mode(
    isolate_settings,
):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_db_with_tables(
        db_path,
        _LEGACY_CODE_ANALYSIS_QUEUE_SQL
        + """
        INSERT INTO code_analysis_queue (
            engagement_id, file_id, priority, status, batch_theme
        ) VALUES (1, 1, 91, 'pending', 'metadata-refresh-review');
        """,
    )

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        row = connection.execute(
            "SELECT queue_mode, priority FROM code_analysis_queue WHERE id = 1"
        ).fetchone()
    assert row == ("initial", 91)


@pytest.mark.parametrize("schema_kind", ["fresh", "migrated"])
def test_reanalysis_history_preserves_engagement_delete_parity(
    isolate_settings, schema_kind
):
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    if schema_kind == "migrated":
        _write_db_with_tables(db_path, _LEGACY_CODE_ANALYSIS_QUEUE_SQL)
    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('queue-delete', 'example.com', 'in_progress', '/tmp/queue-delete')
            """
        ).lastrowid
        repo_id = connection.execute(
            """
            INSERT INTO code_repos (
                engagement_id, repo_key, name, repo_path, active_generation
            ) VALUES (?, 'repo', 'repo', '/tmp/repo', 1)
            """,
            (engagement_id,),
        ).lastrowid
        file_id = connection.execute(
            """
            INSERT INTO code_files (engagement_id, repo_id, file_path)
            VALUES (?, ?, 'src/parser.py')
            """,
            (engagement_id, repo_id),
        ).lastrowid
        predecessor_id = connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, priority, status, repo_generation
            ) VALUES (?, ?, 80, 'done', 1)
            """,
            (engagement_id, file_id),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO code_analysis_queue (
                engagement_id, file_id, priority, status, repo_generation,
                queue_mode, reanalysis_reason, reanalysis_of_queue_item_id
            ) VALUES (?, ?, 80, 'pending', 1, 'reanalysis', 'independent reread', ?)
            """,
            (engagement_id, file_id, predecessor_id),
        )
        connection.commit()

        connection.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
        connection.commit()
        assert connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue"
        ).fetchone()[0] == 0
        self_references = [
            row
            for row in connection.execute(
                "PRAGMA foreign_key_list(code_analysis_queue)"
            ).fetchall()
            if row[3] == "reanalysis_of_queue_item_id"
        ]
        assert self_references == []
