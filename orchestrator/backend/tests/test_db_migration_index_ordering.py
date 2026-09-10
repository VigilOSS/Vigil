"""Indexes must not be created over columns that only exist after migration.

``init_db`` runs ``_create_*_tables`` BEFORE ``_apply_additive_migrations``. On an
existing database the ``CREATE TABLE IF NOT EXISTS`` in those creators is a no-op,
so a column introduced later by the additive migration map is absent at that
point. An index over such a column therefore raises
``sqlite3.OperationalError: no such column`` and fails backend startup outright --
which is exactly what ``submission_ref`` did. These tests pin the ordering rather
than the single column, because the trap recurs every time a column is added.
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from app import db as db_module

# A pre-migration ``assessment_findings``: the columns the additive map adds are
# deliberately absent, which is what a long-lived engagement database looks like.
_LEGACY_SCHEMA = """
CREATE TABLE engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT ''
);
CREATE TABLE assessment_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    slug TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def _write_legacy_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(db_path)) as connection:
        connection.executescript(_LEGACY_SCHEMA)


def _columns(db_path: Path, table: str) -> set[str]:
    with sqlite3.connect(str(db_path)) as connection:
        return {
            row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }


def _indexes(db_path: Path, table: str) -> set[str]:
    with sqlite3.connect(str(db_path)) as connection:
        return {
            row[1] for row in connection.execute(f"PRAGMA index_list({table})").fetchall()
        }


def test_init_db_succeeds_against_a_pre_migration_findings_table(isolate_settings):
    """The reported startup crash: an index over a not-yet-migrated column."""
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_db(db_path)

    db_module.init_db()  # raised OperationalError: no such column: submission_ref

    columns = _columns(db_path, "assessment_findings")
    assert {"submission_ref", "submission_platform", "submission_url"} <= columns
    assert "verification_status" in columns
    assert "verification_state" not in columns
    assert "verification_disposition" not in columns


def test_every_findings_index_exists_after_migrating_a_legacy_database(isolate_settings):
    """Guards the CLASS: no findings index may be silently skipped on an upgrade.

    A column-existence guard around the index would also make startup succeed, but
    would leave the index quietly absent -- the silent-skip shape this codebase
    treats as worse than a loud failure. Assert every index db.py declares over
    ``assessment_findings`` is actually present once migration has run.
    """
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    _write_legacy_db(db_path)
    db_module.init_db()

    declared = set(
        re.findall(
            r"CREATE INDEX IF NOT EXISTS (\w+) \"\s*\"ON assessment_findings\(",
            Path(db_module.__file__).read_text(),
        )
    )
    assert declared, "no assessment_findings indexes parsed -- update this test"
    missing = declared - _indexes(db_path, "assessment_findings")
    assert not missing, f"declared but never created on an upgraded database: {sorted(missing)}"
