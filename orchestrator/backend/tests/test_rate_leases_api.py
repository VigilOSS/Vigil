"""Lossless retirement migration for aggregate-rate lease state."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from app import db as db_module


_LEGACY_SCHEMA = """
CREATE TABLE engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    engagement_root TEXT NOT NULL DEFAULT ''
);
CREATE TABLE assessment_rate_leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    lease_token TEXT NOT NULL UNIQUE,
    owner TEXT NOT NULL,
    effective_rate_rps REAL NOT NULL,
    aggregate_limit_rps REAL,
    override_reason TEXT,
    command_run_id INTEGER,
    expires_at TEXT NOT NULL,
    released_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_assessment_rate_leases_active
ON assessment_rate_leases(engagement_id, released_at, expires_at);
"""

_LEASE_VALUES = (
    41,
    1,
    "historical-lease",
    "recon-specialist",
    6.25,
    10.0,
    "historical approved burst",
    77,
    "2026-07-14T13:00:00Z",
    "2026-07-14T12:05:00Z",
    "2026-07-14T12:00:00Z",
    "2026-07-14T12:05:00Z",
)


def _write_legacy_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO engagements (id, key) VALUES (1, 'legacy-engagement')"
        )
        connection.execute(
            """
            INSERT INTO assessment_rate_leases (
                id, engagement_id, lease_token, owner, effective_rate_rps,
                aggregate_limit_rps, override_reason, command_run_id,
                expires_at, released_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _LEASE_VALUES,
        )


def _tables(path: Path) -> set[str]:
    with closing(sqlite3.connect(path)) as connection:
        return {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def test_populated_rate_lease_table_is_losslessly_archived_and_retired(
    isolate_settings,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)

    db_module.init_db()

    tables = _tables(path)
    assert "assessment_rate_leases" not in tables
    assert "assessment_rate_lease_history" in tables
    with closing(sqlite3.connect(path)) as connection:
        archived = connection.execute(
            """
            SELECT id, engagement_id, lease_token, owner, effective_rate_rps,
                   aggregate_limit_rps, override_reason, command_run_id,
                   expires_at, released_at, created_at, updated_at
            FROM assessment_rate_lease_history
            """
        ).fetchone()
        migration = connection.execute(
            """
            SELECT migrated_rows, warning_count, backup_path, report_json
            FROM schema_migrations
            WHERE migration_id = 'aggregate-rate-lease-retirement-v1'
            """
        ).fetchone()
        archive_foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(assessment_rate_lease_history)"
        ).fetchall()
    assert archived == _LEASE_VALUES
    assert archive_foreign_keys == []
    assert migration is not None
    assert migration[0:2] == (1, 0)
    backup = Path(migration[2])
    report = json.loads(migration[3])
    assert backup.is_file()
    assert report["backup_path"] == str(backup)
    assert report["backup_size_bytes"] == backup.stat().st_size
    assert report["backup_sha256"] == _sha256(backup)
    assert report["source_count"] == report["archive_count"] == 1
    assert report["source_sha256"] == report["archive_sha256"]
    assert report["postconditions"] == {
        "active_table_removed": True,
        "digest_equal": True,
        "row_count_equal": True,
    }
    assert "assessment_rate_leases" in _tables(backup)
    with closing(sqlite3.connect(backup)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_rate_lease_retirement_migration_is_idempotent(isolate_settings) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    db_module.init_db()
    backups = list(path.parent.glob(f"{path.name}.pre-rate-lease-retirement.*.bak"))

    db_module.init_db()

    assert list(path.parent.glob(f"{path.name}.pre-rate-lease-retirement.*.bak")) == backups
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE migration_id = 'aggregate-rate-lease-retirement-v1'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_rate_lease_history"
        ).fetchone()[0] == 1


def test_malformed_rate_lease_schema_stops_without_coercing_rows(
    isolate_settings,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "ALTER TABLE assessment_rate_leases ADD COLUMN unknown_evidence BLOB"
        )
        connection.execute(
            "UPDATE assessment_rate_leases SET unknown_evidence = x'00ff'"
        )

    with pytest.raises(RuntimeError, match="cannot retire malformed"):
        db_module.init_db()

    assert "assessment_rate_leases" in _tables(path)
    assert "assessment_rate_lease_history" not in _tables(path)
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute(
            "SELECT unknown_evidence FROM assessment_rate_leases"
        ).fetchone()[0] == b"\x00\xff"
    backup = next(
        path.parent.glob(f"{path.name}.pre-rate-lease-retirement.*.bak")
    )
    assert "assessment_rate_leases" in _tables(backup)


def test_rate_lease_api_surface_is_fully_retired(client) -> None:
    engagement_key = "2026-07-14-120000-rate-lease-api-retired"
    with db_module.get_connection() as connection:
        connection.execute(
            "INSERT INTO engagements (key, target, status, engagement_root) "
            "VALUES (?, ?, 'active', '/tmp/rate-lease-api-retired')",
            (engagement_key, "https://example.com"),
        )

    base = f"/engagements/{engagement_key}/assessment/rate-leases"
    assert client.get(base).status_code == 404
    assert not any(
        path.endswith("/assessment/rate-leases")
        for path in client.app.openapi()["paths"]
    )
