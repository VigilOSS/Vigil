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


def test_check_accepts_future_shared_table_without_engagement_id(isolate_settings):
    """A future non-engagement-scoped table with an ``assessment_`` or ``code_``
    prefix must NOT trigger a false-positive refuse-to-start. Only the real
    migration signal — a legacy ``run_id`` column — matters."""
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
