"""Behaviour pins for ``app.db`` schema plumbing (packet S16).

Two areas carried no direct coverage before this file:

* the AFTER UPDATE / AFTER DELETE arms of the ``assessment_command_runs`` and
  ``assessment_artifacts`` content-backed FTS5 triggers, and their
  drop-and-rebuild-on-column-drift guard, and
* the ``BEGIN IMMEDIATE`` / ``COMMIT`` / ``ROLLBACK``-and-reraise transaction
  that wraps each protected schema migration in ``init_db``.

Everything here asserts observable effects — rows visible through ``MATCH``,
the FTS table's own column set, and whether a failed migration leaves its
writes behind — so the surrounding plumbing can be rewritten without the
assertions moving.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module


COMMAND_RUN_FTS_COLUMNS = (
    "command",
    "tool_name",
    "tool_bin",
    "agent_name",
    "phase",
    "stdout_preview",
    "stderr_preview",
    "stdout_suppression_reason",
    "stderr_suppression_reason",
    "notes",
    "intent",
    "technique",
)
ARTIFACT_FTS_COLUMNS = (
    "relative_path",
    "kind",
    "media_type",
    "preview_text",
    "indexed_text",
    "related_finding_slug",
    "related_chain_key",
)


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_module.database_path()))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _seed_engagement(connection: sqlite3.Connection, key: str = "pin-s16") -> int:
    cursor = connection.execute(
        """
        INSERT INTO engagements (key, target, status, engagement_root)
        VALUES (?, 'acme.example', 'active', '/tmp/pin-s16')
        """,
        (key,),
    )
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


def _insert_command_run(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    run_uuid: str,
    command: str,
    notes: str = "",
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO assessment_command_runs (
            engagement_id, run_uuid, command, tool_name, tool_bin, agent_name,
            phase, started_at, completed_at, command_hash, notes, intent, technique
        ) VALUES (?, ?, ?, 'curl', '/usr/bin/curl', 'recon', 'discovery',
                  '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'hash', ?,
                  'enumerate', 'T1595')
        """,
        (engagement_id, run_uuid, command, notes),
    )
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


def _insert_artifact(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    relative_path: str,
    preview_text: str,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO assessment_artifacts (
            engagement_id, relative_path, kind, media_type, preview_text,
            indexed_text, related_finding_slug, related_chain_key
        ) VALUES (?, ?, 'capture', 'text/plain', ?, ?, 'SQLI-001', 'chain-a')
        """,
        (engagement_id, relative_path, preview_text, preview_text),
    )
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


def _match_rowids(
    connection: sqlite3.Connection, fts_table: str, expression: str
) -> list[int]:
    return [
        int(row[0])
        for row in connection.execute(
            f"SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ? ORDER BY rowid",
            (expression,),
        ).fetchall()
    ]


def _fts_columns(connection: sqlite3.Connection, fts_table: str) -> tuple[str, ...]:
    return tuple(
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({fts_table})").fetchall()
    )


# ──────────────────────────────────────────────────────────────
# Content-backed FTS5 trigger arms
# ──────────────────────────────────────────────────────────────


def test_command_runs_fts_declares_the_indexed_columns(isolate_settings):
    db_module.init_db()
    with _connect() as connection:
        assert (
            _fts_columns(connection, "assessment_command_runs_fts")
            == COMMAND_RUN_FTS_COLUMNS
        )


def test_command_runs_fts_tracks_insert_update_and_delete(isolate_settings):
    db_module.init_db()
    with _connect() as connection:
        engagement_id = _seed_engagement(connection)
        run_id = _insert_command_run(
            connection,
            engagement_id,
            run_uuid="run-1",
            command="nmap sorbet.example",
            notes="initial sweep",
        )

        # AFTER INSERT
        assert _match_rowids(connection, "assessment_command_runs_fts", "sorbet") == [
            run_id
        ]

        # AFTER UPDATE: the old text stops matching, the new text starts.
        connection.execute(
            "UPDATE assessment_command_runs SET command = ?, notes = ? WHERE id = ?",
            ("nmap tangerine.example", "second sweep", run_id),
        )
        assert _match_rowids(connection, "assessment_command_runs_fts", "sorbet") == []
        assert _match_rowids(
            connection, "assessment_command_runs_fts", "tangerine"
        ) == [run_id]
        assert _match_rowids(connection, "assessment_command_runs_fts", "second") == [
            run_id
        ]

        # AFTER DELETE
        connection.execute(
            "DELETE FROM assessment_command_runs WHERE id = ?", (run_id,)
        )
        assert (
            _match_rowids(connection, "assessment_command_runs_fts", "tangerine") == []
        )


def test_artifacts_fts_declares_the_indexed_columns(isolate_settings):
    db_module.init_db()
    with _connect() as connection:
        assert (
            _fts_columns(connection, "assessment_artifacts_fts")
            == ARTIFACT_FTS_COLUMNS
        )


def test_artifacts_fts_tracks_insert_update_and_delete(isolate_settings):
    db_module.init_db()
    with _connect() as connection:
        engagement_id = _seed_engagement(connection)
        artifact_id = _insert_artifact(
            connection,
            engagement_id,
            relative_path="captures/sorbet.txt",
            preview_text="sorbet response body",
        )

        assert _match_rowids(connection, "assessment_artifacts_fts", "sorbet") == [
            artifact_id
        ]

        connection.execute(
            """
            UPDATE assessment_artifacts
            SET relative_path = ?, preview_text = ?, indexed_text = ?
            WHERE id = ?
            """,
            (
                "captures/tangerine.txt",
                "tangerine response body",
                "tangerine response body",
                artifact_id,
            ),
        )
        assert _match_rowids(connection, "assessment_artifacts_fts", "sorbet") == []
        assert _match_rowids(connection, "assessment_artifacts_fts", "tangerine") == [
            artifact_id
        ]

        connection.execute(
            "DELETE FROM assessment_artifacts WHERE id = ?", (artifact_id,)
        )
        assert _match_rowids(connection, "assessment_artifacts_fts", "tangerine") == []


def _replace_with_legacy_fts(
    connection: sqlite3.Connection,
    *,
    fts_table: str,
    base_table: str,
    columns: tuple[str, ...],
) -> None:
    """Stand in a legacy virtual table whose column set predates the current one."""

    connection.execute(f"DROP TABLE IF EXISTS {fts_table}")
    for suffix in ("ai", "ad", "au"):
        connection.execute(f"DROP TRIGGER IF EXISTS {base_table}_{suffix}")
    connection.execute(
        f"CREATE VIRTUAL TABLE {fts_table} USING fts5("
        f"{', '.join(columns)}, content='{base_table}', content_rowid='id', "
        "tokenize='unicode61')"
    )


@pytest.mark.parametrize(
    "dropped_column",
    ["tool_bin", "intent"],
)
def test_command_runs_fts_rebuilds_on_column_drift(isolate_settings, dropped_column):
    db_module.init_db()
    with _connect() as connection:
        engagement_id = _seed_engagement(connection)
        run_id = _insert_command_run(
            connection,
            engagement_id,
            run_uuid="run-drift",
            command="nmap sorbet.example",
        )
        _replace_with_legacy_fts(
            connection,
            fts_table="assessment_command_runs_fts",
            base_table="assessment_command_runs",
            columns=tuple(
                name for name in COMMAND_RUN_FTS_COLUMNS if name != dropped_column
            ),
        )
        connection.commit()

    db_module.close_thread_connection()
    db_module.init_db()

    with _connect() as connection:
        assert (
            _fts_columns(connection, "assessment_command_runs_fts")
            == COMMAND_RUN_FTS_COLUMNS
        )
        # The pre-existing base row was re-indexed by the 'rebuild' command.
        assert _match_rowids(connection, "assessment_command_runs_fts", "sorbet") == [
            run_id
        ]


def test_artifacts_fts_rebuilds_on_column_drift(isolate_settings):
    db_module.init_db()
    with _connect() as connection:
        engagement_id = _seed_engagement(connection)
        artifact_id = _insert_artifact(
            connection,
            engagement_id,
            relative_path="captures/sorbet.txt",
            preview_text="sorbet response body",
        )
        _replace_with_legacy_fts(
            connection,
            fts_table="assessment_artifacts_fts",
            base_table="assessment_artifacts",
            columns=tuple(
                name for name in ARTIFACT_FTS_COLUMNS if name != "related_chain_key"
            ),
        )
        connection.commit()

    db_module.close_thread_connection()
    db_module.init_db()

    with _connect() as connection:
        assert (
            _fts_columns(connection, "assessment_artifacts_fts")
            == ARTIFACT_FTS_COLUMNS
        )
        assert _match_rowids(connection, "assessment_artifacts_fts", "sorbet") == [
            artifact_id
        ]


def test_command_runs_fts_untouched_when_column_set_matches(isolate_settings):
    """A virtual table carrying the guarded columns is left in place."""

    db_module.init_db()
    with _connect() as connection:
        engagement_id = _seed_engagement(connection)
        run_id = _insert_command_run(
            connection,
            engagement_id,
            run_uuid="run-keep",
            command="nmap sorbet.example",
        )
        connection.commit()

    db_module.close_thread_connection()
    db_module.init_db()

    with _connect() as connection:
        assert _match_rowids(connection, "assessment_command_runs_fts", "sorbet") == [
            run_id
        ]


# ──────────────────────────────────────────────────────────────
# Protected migration transaction
# ──────────────────────────────────────────────────────────────


class _MigrationExploded(RuntimeError):
    pass


def test_protected_migration_commits_on_success(isolate_settings):
    db_module.init_db()
    connection = sqlite3.connect(str(db_module.database_path()))
    try:
        connection.execute("CREATE TABLE pin_s16_protected (value TEXT)")
        connection.commit()
        connection.execute("INSERT INTO pin_s16_protected VALUES ('pending')")
        assert connection.in_transaction

        with db_module._protected_migration(connection):
            connection.execute("INSERT INTO pin_s16_protected VALUES ('migrated')")

        assert not connection.in_transaction
        values = [
            str(row[0])
            for row in connection.execute(
                "SELECT value FROM pin_s16_protected ORDER BY rowid"
            ).fetchall()
        ]
        assert values == ["pending", "migrated"]
    finally:
        connection.close()


def test_protected_migration_rolls_back_and_reraises(isolate_settings):
    db_module.init_db()
    connection = sqlite3.connect(str(db_module.database_path()))
    try:
        connection.execute("CREATE TABLE pin_s16_protected (value TEXT)")
        connection.commit()
        # Work already pending when the migration starts is committed first, so
        # it survives a rollback of the migration itself.
        connection.execute("INSERT INTO pin_s16_protected VALUES ('pending')")

        with pytest.raises(_MigrationExploded):
            with db_module._protected_migration(connection):
                connection.execute("INSERT INTO pin_s16_protected VALUES ('partial')")
                raise _MigrationExploded("migration failed")

        assert not connection.in_transaction
        values = [
            str(row[0])
            for row in connection.execute(
                "SELECT value FROM pin_s16_protected ORDER BY rowid"
            ).fetchall()
        ]
        assert values == ["pending"]
    finally:
        connection.close()
