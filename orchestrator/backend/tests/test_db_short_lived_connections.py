"""Startup-owned SQLite handles close independently of garbage collection."""
from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from app import db


@pytest.fixture
def tracked_connections(monkeypatch):
    connect = sqlite3.connect
    connections = []

    def tracked_connect(*args, **kwargs):
        connection = connect(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    yield connections
    for connection in connections:
        connection.close()


def _assert_closed(connection):
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("schema", ["current", "legacy", "corrupt"])
def test_compatibility_check_closes_connection_on_every_exit(
    tmp_path, tracked_connections, schema
):
    path = tmp_path / "compatibility.sqlite3"
    if schema == "legacy":
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE projects (id INTEGER PRIMARY KEY)")
    elif schema == "corrupt":
        path.write_bytes(b"not a SQLite database")
    else:
        path.touch()
    previous_count = len(tracked_connections)

    if schema == "current":
        db._check_database_compatibility(path)
    else:
        with pytest.raises(db.IncompatibleDatabaseError):
            db._check_database_compatibility(path)

    assert len(tracked_connections) == previous_count + 1
    _assert_closed(tracked_connections[-1])


@pytest.mark.parametrize("migration_fails", [False, True])
def test_initialization_closes_connections_and_preserves_transaction_outcome(
    isolate_settings, monkeypatch, tracked_connections, migration_fails
):
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("CREATE TABLE lifecycle_probe (value TEXT NOT NULL)")

    def finish_migration(connection):
        connection.execute("INSERT INTO lifecycle_probe VALUES ('persisted')")
        if migration_fails:
            raise RuntimeError("migration failed")

    monkeypatch.setattr(db, "_run_data_migrations", finish_migration)
    previous_count = len(tracked_connections)
    previous_fingerprint = db._startup_database_fingerprint

    if migration_fails:
        with pytest.raises(RuntimeError, match="migration failed"):
            db.init_db()
        assert db._startup_database_fingerprint is previous_fingerprint
    else:
        db.init_db()
        assert db._startup_database_fingerprint.path == path.resolve()

    created_connections = tracked_connections[previous_count:]
    assert created_connections, "init_db did not open a connection"
    for connection in reversed(created_connections):
        _assert_closed(connection)
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute("SELECT value FROM lifecycle_probe").fetchall()
    assert rows == ([] if migration_fails else [("persisted",)])
