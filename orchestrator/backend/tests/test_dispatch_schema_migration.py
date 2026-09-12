"""Recoverable dispatch provenance and retired-column migration."""

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
CREATE TABLE assessment_dispatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    agent_id TEXT NOT NULL,
    agent_role TEXT NOT NULL,
    task TEXT,
    application_unit_id INTEGER,
    dispatched_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    model TEXT,
    reasoning TEXT,
    requested_model TEXT,
    actual_model TEXT,
    requested_reasoning TEXT,
    actual_reasoning TEXT,
    dispatch_mode TEXT,
    finding_slugs_json TEXT,
    skills TEXT,
    tier TEXT,
    vuln_classes TEXT,
    identity TEXT,
    skill_loaded TEXT,
    scope_host TEXT,
    permission TEXT,
    command_budget TEXT,
    output_schema TEXT,
    files_allowed_json TEXT,
    scope_path_prefix TEXT,
    UNIQUE(engagement_id, agent_id)
);
"""

_RETIRED = {
    "model",
    "reasoning",
    "skill_loaded",
    "scope_host",
    "permission",
    "command_budget",
    "output_schema",
    "files_allowed_json",
    "scope_path_prefix",
}


def _write_legacy_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO engagements (id, key) VALUES (1, 'legacy-engagement')"
        )
        connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, task, application_unit_id,
                dispatched_at, status, model, reasoning, requested_model,
                actual_model, requested_reasoning, skill_loaded, scope_host,
                permission, command_budget, output_schema, files_allowed_json,
                scope_path_prefix
            ) VALUES (1, 'legacy-agent', 'recon-specialist', 'legacy task', 42,
                      '2026-07-01T00:00:00Z', 'completed', 'legacy-model', 'high',
                      NULL, 'observed-model', NULL, 'surface-collection',
                      'example.com', 'authorized', '100', 'json', '["scans/"]',
                      '/api')
            """
        )


def _columns(path: Path) -> set[str]:
    with closing(sqlite3.connect(path)) as connection, connection:
        return {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(assessment_dispatches)"
            ).fetchall()
        }


def test_dispatch_migration_preserves_history_and_cuts_over_schema(
    isolate_settings,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)

    db_module.init_db()

    columns = _columns(path)
    assert not (_RETIRED & columns)
    assert "application_unit_id" in columns
    assert {
        "requested_model",
        "actual_model",
        "requested_reasoning",
        "actual_reasoning",
        "client_name",
        "requested_client",
        "launcher_effective_client",
        "provider_observed_client",
        "launcher_effective_model",
        "launcher_effective_reasoning",
        "launcher_effective_source",
        "source_revision",
        "operator_instruction_path",
        "operator_instruction_sha256",
        "specialist_instruction_path",
        "specialist_instruction_sha256",
        "instruction_identity_status",
        "instructions_stale",
    } <= columns
    with closing(sqlite3.connect(path)) as connection, connection:
        row = connection.execute(
            """
            SELECT requested_model, actual_model, requested_reasoning,
                   client_name, source_revision, instruction_identity_status,
                   requested_client, launcher_effective_client,
                   provider_observed_client, launcher_effective_model,
                   launcher_effective_reasoning, launcher_effective_source
            FROM assessment_dispatches WHERE agent_id = 'legacy-agent'
            """
        ).fetchone()
        history = connection.execute(
            """
            SELECT agent_id, legacy_payload_json
            FROM dispatch_column_migration_history
            """
        ).fetchone()
        report = connection.execute(
            """
            SELECT migrated_rows, warning_count, backup_path
            FROM schema_migrations
            WHERE migration_id = 'dispatch-provenance-and-fossils-v1'
            """
        ).fetchone()
    assert row == (
        "legacy-model",
        "observed-model",
        "high",
        "unknown",
        "unknown",
        "incomplete",
        "unknown",
        "unknown",
        "unknown",
        None,
        None,
        None,
    )
    assert history is not None and history[0] == "legacy-agent"
    preserved = json.loads(history[1])
    assert preserved == {
        "command_budget": "100",
        "files_allowed_json": '["scans/"]',
        "model": "legacy-model",
        "output_schema": "json",
        "permission": "authorized",
        "reasoning": "high",
        "scope_host": "example.com",
        "scope_path_prefix": "/api",
        "skill_loaded": "surface-collection",
    }
    assert report is not None and report[0:2] == (1, 0)
    backup = Path(report[2])
    assert backup.is_file()
    assert _RETIRED <= _columns(backup)
    with closing(sqlite3.connect(backup)) as connection, connection:
        assert connection.execute(
            "SELECT model, application_unit_id FROM assessment_dispatches"
        ).fetchone() == ("legacy-model", 42)


def test_dispatch_migration_is_idempotent(isolate_settings) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    db_module.init_db()
    backups = list(path.parent.glob(f"{path.name}.pre-dispatch-schema.*.bak"))

    db_module.init_db()

    assert list(path.parent.glob(f"{path.name}.pre-dispatch-schema.*.bak")) == backups
    with closing(sqlite3.connect(path)) as connection, connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE migration_id = 'dispatch-provenance-and-fossils-v1'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM dispatch_column_migration_history"
        ).fetchone()[0] == 1


@pytest.mark.parametrize("unobserved_model", [None, " \t"], ids=["null", "blank"])
def test_dispatch_migration_normalizes_unobserved_actual_model_idempotently(
    isolate_settings,
    unobserved_model: str | None,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute(
            "UPDATE assessment_dispatches SET actual_model = ?",
            (unobserved_model,),
        )

    db_module.init_db()
    db_module.init_db()

    with closing(sqlite3.connect(path)) as connection, connection:
        actual_model = connection.execute(
            "SELECT actual_model FROM assessment_dispatches WHERE agent_id = 'legacy-agent'"
        ).fetchone()[0]
    assert actual_model == "unknown"


def test_failed_dispatch_migration_rolls_back_and_backup_can_be_restored(
    isolate_settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    original = db_module._migrate_dispatch_schema

    def fail_after_migration(connection, *, backup_path):
        original(connection, backup_path=backup_path)
        raise RuntimeError("simulated dispatch migration interruption")

    monkeypatch.setattr(db_module, "_migrate_dispatch_schema", fail_after_migration)
    with pytest.raises(RuntimeError, match="simulated dispatch migration interruption"):
        db_module.init_db()

    assert _RETIRED <= _columns(path)
    backup = next(path.parent.glob(f"{path.name}.pre-dispatch-schema.*.bak"))
    assert _RETIRED <= _columns(backup)

    monkeypatch.setattr(db_module, "_migrate_dispatch_schema", original)
    db_module.close_thread_connection()
    shutil.copy2(backup, path)
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    db_module._startup_database_fingerprint = None
    db_module.init_db()

    assert not (_RETIRED & _columns(path))
