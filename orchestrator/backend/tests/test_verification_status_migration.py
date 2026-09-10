"""One-time, recoverable migration to the shared verification-status axis."""
from __future__ import annotations

import shutil
import sqlite3
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
CREATE TABLE assessment_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    slug TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'active',
    verification_state TEXT NOT NULL DEFAULT 'unreviewed',
    verification_disposition TEXT NOT NULL DEFAULT 'none',
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_assessment_findings_verification
ON assessment_findings(engagement_id, verification_state, verification_disposition);
CREATE TABLE assessment_finding_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    from_workflow_status TEXT,
    to_workflow_status TEXT NOT NULL DEFAULT '',
    from_verification_state TEXT,
    to_verification_state TEXT,
    from_verification_disposition TEXT,
    to_verification_disposition TEXT,
    from_severity TEXT,
    to_severity TEXT NOT NULL DEFAULT '',
    reason_code TEXT NOT NULL DEFAULT '',
    reason_text TEXT NOT NULL DEFAULT '',
    artifact_ref TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


_PAIRS = (
    ("unreviewed", "none", "unreviewed", False),
    ("disputed", "none", "disputed", False),
    ("verified", "pending_runtime_proof", "pending_runtime_proof", False),
    ("verified", "blocked", "blocked", False),
    ("verified", "confirmed", "confirmed", False),
    ("verified", "downgraded", "downgraded", False),
    ("verified", "false_positive", "false_positive", False),
    ("verified", "none", "unreviewed", True),
    ("nonsense", "confirmed", "unreviewed", True),
)

_TRANSITION_PAIRS = (
    (None, None, "unreviewed", "none", None, "unreviewed", False),
    ("unreviewed", "none", "verified", "confirmed", "unreviewed", "confirmed", False),
    ("verified", "confirmed", "disputed", "none", "confirmed", "disputed", False),
    ("verified", "none", "verified", "confirmed", "unreviewed", "confirmed", True),
)


def _write_legacy_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO engagements (id, key) VALUES (1, 'legacy-engagement')"
        )
        connection.executemany(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, verification_state, verification_disposition
            ) VALUES (1, ?, ?, ?)
            """,
            [
                (f"VA-{index:03d}", state, disposition)
                for index, (state, disposition, _mapped, _warning) in enumerate(
                    _PAIRS, start=1
                )
            ],
        )
        connection.executemany(
            """
            INSERT INTO assessment_finding_transitions (
                engagement_id, finding_id, action,
                from_verification_state, from_verification_disposition,
                to_verification_state, to_verification_disposition
            ) VALUES (1, 1, 'legacy-event', ?, ?, ?, ?)
            """,
            [pair[:4] for pair in _TRANSITION_PAIRS],
        )


def _write_partial_current_transition_database(path: Path) -> None:
    """Write the interrupted/current shape that predates event versioning."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(_LEGACY_SCHEMA)
        connection.execute(
            "INSERT INTO engagements (id, key) VALUES (1, 'partial-current')"
        )
        connection.execute(
            """
            INSERT INTO assessment_findings (
                id, engagement_id, slug, verification_state,
                verification_disposition
            ) VALUES (1, 1, 'VA-001', 'verified', 'confirmed')
            """
        )
        connection.execute(
            "ALTER TABLE assessment_findings ADD COLUMN verification_status "
            "TEXT NOT NULL DEFAULT 'unreviewed'"
        )
        connection.execute(
            "UPDATE assessment_findings SET verification_status = 'confirmed'"
        )
        connection.execute("DROP INDEX idx_assessment_findings_verification")
        connection.execute(
            "ALTER TABLE assessment_findings DROP COLUMN verification_state"
        )
        connection.execute(
            "ALTER TABLE assessment_findings DROP COLUMN verification_disposition"
        )
        connection.execute(
            "ALTER TABLE assessment_finding_transitions "
            "ADD COLUMN from_verification_status TEXT"
        )
        connection.execute(
            "ALTER TABLE assessment_finding_transitions "
            "ADD COLUMN to_verification_status TEXT NOT NULL DEFAULT 'unreviewed'"
        )
        connection.execute(
            """
            INSERT INTO assessment_finding_transitions (
                id, engagement_id, finding_id, action,
                from_verification_status, to_verification_status
            ) VALUES (1, 1, 1, 'current-event', 'confirmed', 'disputed')
            """
        )
        for column_name in (
            "from_verification_state",
            "to_verification_state",
            "from_verification_disposition",
            "to_verification_disposition",
        ):
            connection.execute(
                "ALTER TABLE assessment_finding_transitions "
                f"DROP COLUMN {column_name}"
            )


def _columns(path: Path, table: str) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[1])
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }


def test_verification_status_migration_is_explicit_backed_up_and_historical(
    isolate_settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)

    db_module.init_db()

    columns = _columns(path, "assessment_findings")
    assert "verification_status" in columns
    assert "verification_state" not in columns
    assert "verification_disposition" not in columns
    with sqlite3.connect(path) as connection:
        mapped = connection.execute(
            "SELECT slug, verification_status FROM assessment_findings ORDER BY id"
        ).fetchall()
        history = connection.execute(
            """
            SELECT finding_id, legacy_state, legacy_disposition, mapped_status,
                   warning
            FROM finding_verification_migration_history
            ORDER BY finding_id
            """
        ).fetchall()
        reports = connection.execute(
            "SELECT migrated_rows, warning_count, backup_path FROM schema_migrations "
            "WHERE migration_id = 'finding-verification-status-v1'"
        ).fetchall()
    assert mapped == [
        (f"VA-{index:03d}", expected)
        for index, (_state, _disposition, expected, _warning) in enumerate(
            _PAIRS, start=1
        )
    ]
    assert [tuple(row[1:4]) for row in history] == [
        (state, disposition, expected)
        for state, disposition, expected, _warning in _PAIRS
    ]
    assert [bool(row[4]) for row in history] == [warning for *_rest, warning in _PAIRS]
    assert len(reports) == 1
    assert reports[0][0:2] == (
        len(_PAIRS) + len(_TRANSITION_PAIRS),
        sum(pair[3] for pair in _PAIRS) + sum(pair[6] for pair in _TRANSITION_PAIRS),
    )

    backups = list(path.parent.glob(f"{path.name}.pre-verification-status.*.bak"))
    assert len(backups) == 1
    assert Path(reports[0][2]) == backups[0].resolve()
    assert _columns(backups[0], "assessment_findings") >= {
        "verification_state",
        "verification_disposition",
    }
    assert _columns(backups[0], "assessment_finding_transitions") >= {
        "from_verification_state",
        "to_verification_state",
        "from_verification_disposition",
        "to_verification_disposition",
    }
    with sqlite3.connect(backups[0]) as backup_connection:
        assert backup_connection.execute(
            "SELECT COUNT(*) FROM assessment_findings"
        ).fetchone()[0] == len(_PAIRS)
    warnings = [record.message for record in caplog.records]
    assert any("legacy-engagement" in message and "VA-008" in message for message in warnings)
    assert any("legacy-engagement" in message and "VA-009" in message for message in warnings)
    assert any("transition=4" in message for message in warnings)


def test_repeated_startup_does_not_remigrate_or_duplicate_history(isolate_settings) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    db_module.init_db()
    first_backups = list(path.parent.glob(f"{path.name}.pre-verification-status.*.bak"))

    db_module.init_db()

    assert list(path.parent.glob(f"{path.name}.pre-verification-status.*.bak")) == first_backups
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations "
            "WHERE migration_id = 'finding-verification-status-v1'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_verification_migration_history"
        ).fetchone()[0] == len(_PAIRS)
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_transition_verification_migration_history"
        ).fetchone()[0] == len(_TRANSITION_PAIRS)


def test_legacy_transition_events_are_versioned_mapped_and_preserved(
    isolate_settings,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)

    db_module.init_db()

    columns = _columns(path, "assessment_finding_transitions")
    assert {"from_verification_status", "to_verification_status", "verification_event_version"} <= columns
    assert "from_verification_state" not in columns
    assert "to_verification_state" not in columns
    assert "from_verification_disposition" not in columns
    assert "to_verification_disposition" not in columns
    with sqlite3.connect(path) as connection:
        mapped = connection.execute(
            """
            SELECT from_verification_status, to_verification_status,
                   verification_event_version
            FROM assessment_finding_transitions ORDER BY id
            """
        ).fetchall()
        history = connection.execute(
            """
            SELECT legacy_from_state, legacy_from_disposition,
                   legacy_to_state, legacy_to_disposition,
                   mapped_from_status, mapped_to_status, warning
            FROM finding_transition_verification_migration_history
            ORDER BY transition_id
            """
        ).fetchall()
    assert mapped == [
        (mapped_from, mapped_to, 1)
        for *_legacy, mapped_from, mapped_to, _warning in _TRANSITION_PAIRS
    ]
    assert [tuple(row[:6]) for row in history] == [
        (*pair[:4], pair[4], pair[5]) for pair in _TRANSITION_PAIRS
    ]
    assert [bool(row[6]) for row in history] == [pair[6] for pair in _TRANSITION_PAIRS]


def test_partial_current_transition_schema_adds_version_without_overwriting_statuses(
    isolate_settings,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_partial_current_transition_database(path)

    db_module.init_db()
    db_module.init_db()

    with sqlite3.connect(path) as connection:
        transition = connection.execute(
            """
            SELECT from_verification_status, to_verification_status,
                   verification_event_version
            FROM assessment_finding_transitions WHERE id = 1
            """
        ).fetchone()
        history_count = connection.execute(
            "SELECT COUNT(*) FROM finding_transition_verification_migration_history"
        ).fetchone()[0]
    assert transition == ("confirmed", "disputed", 2)
    assert history_count == 0
    backups = list(path.parent.glob(f"{path.name}.pre-verification-status.*.bak"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as connection:
        assert connection.execute(
            """
            SELECT from_verification_status, to_verification_status
            FROM assessment_finding_transitions WHERE id = 1
            """
        ).fetchone() == ("confirmed", "disputed")


def test_failed_verification_migration_rolls_back_and_keeps_readable_backup(
    isolate_settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    original = db_module._migrate_finding_verification_status

    def fail_after_migration(connection, *, backup_path):
        original(connection, backup_path=backup_path)
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(db_module, "_migrate_finding_verification_status", fail_after_migration)

    with pytest.raises(RuntimeError, match="simulated interruption"):
        db_module.init_db()

    assert _columns(path, "assessment_findings") >= {
        "verification_state",
        "verification_disposition",
    }
    assert "verification_status" not in _columns(path, "assessment_findings")
    assert "from_verification_status" not in _columns(
        path, "assessment_finding_transitions"
    )
    backups = list(path.parent.glob(f"{path.name}.pre-verification-status.*.bak"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM assessment_findings"
        ).fetchone()[0] == len(_PAIRS)


def test_restored_backup_can_be_migrated_again(isolate_settings) -> None:
    path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_database(path)
    db_module.init_db()
    backup = next(path.parent.glob(f"{path.name}.pre-verification-status.*.bak"))
    db_module.close_thread_connection()
    shutil.copy2(backup, path)
    for suffix in ("-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)
    db_module._startup_database_fingerprint = None

    db_module.init_db()

    assert "verification_status" in _columns(path, "assessment_findings")
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_verification_migration_history"
        ).fetchone()[0] == len(_PAIRS)
