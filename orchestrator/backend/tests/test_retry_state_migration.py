"""Recoverable migration for the blocked-technique retry-state contract."""

from __future__ import annotations

import json
import shutil
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
CREATE TABLE assessment_blocked_techniques (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    technique_key TEXT NOT NULL,
    technique TEXT NOT NULL,
    target_kind TEXT NOT NULL DEFAULT '',
    target_ref TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    retry_state TEXT NOT NULL DEFAULT 'pending',
    evidence_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(engagement_id, technique_key),
    FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
);
"""


def _write_legacy_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO engagements (id, key) VALUES (1, 'legacy-engagement')"
        )
        connection.executemany(
            """
            INSERT INTO assessment_blocked_techniques (
                engagement_id, technique_key, technique, target_kind, target_ref,
                reason, retry_state, evidence_ref, notes, provenance_json
            ) VALUES (1, ?, 'SSRF', 'host', ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    "ssrf:valid",
                    "api.example.com",
                    "egress wall",
                    "no_retry",
                    "evidence/valid.txt",
                    "reviewed",
                    '{"source_name":"operator-a"}',
                ),
                (
                    "ssrf:prose",
                    "old.example.com",
                    "old free-text decision",
                    "probably never retry",
                    "evidence/legacy.txt",
                    "must be reviewed again",
                    '{"source_name":"legacy-agent"}',
                ),
            ),
        )


def _table_sql(path: Path, table: str) -> str:
    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
    assert row is not None
    return str(row[0])


def test_retry_state_migration_is_backed_up_constrained_and_historical(
    isolate_settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)

    db_module.init_db()

    table_sql = _table_sql(path, "assessment_blocked_techniques")
    assert "CHECK" in table_sql.upper()
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT technique_key, retry_state, reason, provenance_json
            FROM assessment_blocked_techniques ORDER BY id
            """
        ).fetchall()
        history = connection.execute(
            """
            SELECT technique_key, event_kind, from_retry_state, to_retry_state,
                   reason, evidence_ref, notes, provenance_json,
                   revalidation_context_json, legacy_payload_json
            FROM assessment_blocked_technique_history ORDER BY id
            """
        ).fetchall()
        report = connection.execute(
            """
            SELECT migrated_rows, warning_count, backup_path, report_json
            FROM schema_migrations
            WHERE migration_id = 'blocked-technique-retry-state-v1'
            """
        ).fetchone()

    assert rows == [
        (
            "ssrf:valid",
            "no_retry",
            "egress wall",
            '{"source_name":"operator-a"}',
        ),
        (
            "ssrf:prose",
            "pending",
            "old free-text decision",
            '{"source_name":"legacy-agent"}',
        ),
    ]
    assert [row[:4] for row in history] == [
        ("ssrf:valid", "migration", "no_retry", "no_retry"),
        ("ssrf:prose", "migration", "probably never retry", "pending"),
    ]
    assert history[1][4:9] == (
        "old free-text decision",
        "evidence/legacy.txt",
        "must be reviewed again",
        '{"source_name":"legacy-agent"}',
        "{}",
    )
    assert json.loads(history[1][9])["retry_state"] == "probably never retry"
    assert report is not None and report[0:2] == (2, 1)
    assert json.loads(report[3])["mappings"][1]["mapped_retry_state"] == "pending"

    backup = Path(report[2])
    assert backup.is_file()
    assert "CHECK" not in _table_sql(backup, "assessment_blocked_techniques").upper()
    with sqlite3.connect(backup) as connection:
        assert connection.execute(
            "SELECT retry_state FROM assessment_blocked_techniques WHERE technique_key = 'ssrf:prose'"
        ).fetchone()[0] == "probably never retry"
    assert any(
        "legacy-engagement" in record.message
        and "ssrf:prose" in record.message
        and "mapped to pending" in record.message
        for record in caplog.records
    )


def test_retry_state_migration_is_idempotent(isolate_settings) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    db_module.init_db()
    backups = list(path.parent.glob(f"{path.name}.pre-retry-state.*.bak"))

    db_module.init_db()

    assert list(path.parent.glob(f"{path.name}.pre-retry-state.*.bak")) == backups
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE migration_id = 'blocked-technique-retry-state-v1'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_blocked_technique_history"
        ).fetchone()[0] == 2


def test_failed_retry_state_migration_rolls_back_and_backup_can_be_restored(
    isolate_settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    original = db_module._migrate_blocked_technique_retry_state

    def fail_after_migration(connection, *, backup_path):
        original(connection, backup_path=backup_path)
        raise RuntimeError("simulated retry-state migration interruption")

    monkeypatch.setattr(
        db_module, "_migrate_blocked_technique_retry_state", fail_after_migration
    )
    with pytest.raises(RuntimeError, match="simulated retry-state migration interruption"):
        db_module.init_db()

    assert "CHECK" not in _table_sql(path, "assessment_blocked_techniques").upper()
    backup = next(path.parent.glob(f"{path.name}.pre-retry-state.*.bak"))
    assert "CHECK" not in _table_sql(backup, "assessment_blocked_techniques").upper()

    monkeypatch.setattr(
        db_module, "_migrate_blocked_technique_retry_state", original
    )
    db_module.close_thread_connection()
    shutil.copy2(backup, path)
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    db_module._startup_database_fingerprint = None
    db_module.init_db()

    assert "CHECK" in _table_sql(path, "assessment_blocked_techniques").upper()
