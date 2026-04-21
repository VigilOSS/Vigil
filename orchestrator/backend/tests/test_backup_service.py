"""Scheduled orchestrator DB backup service."""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module
from app.services import backup as backup_service


def test_run_backup_now_noop_when_live_db_missing(isolate_settings):
    assert not db_module.database_path().exists()
    result = backup_service.run_backup_now()
    assert result is None
    # No backup directory should be spawned just to hold emptiness.
    assert not backup_service.backups_dir().exists() or not list(
        backup_service.backups_dir().iterdir()
    )


def test_run_backup_now_writes_snapshot_of_live_db(client, isolate_settings):
    # client fixture runs init_db via the FastAPI lifespan. Seed a row.
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO engagements (key, target, status, engagement_root) "
            "VALUES (?, ?, ?, ?)",
            ("live-sample", "https://example.com", "in_progress", "/tmp/x"),
        )
        connection.commit()

    out = backup_service.run_backup_now()
    assert out is not None
    assert out.exists()

    with sqlite3.connect(str(out)) as connection:
        row = connection.execute(
            "SELECT key FROM engagements WHERE key = ?", ("live-sample",)
        ).fetchone()
    assert row == ("live-sample",)


def test_run_backup_now_rotates_to_max_copies(client, isolate_settings):
    # Produce a handful of snapshots with explicit timestamps so we can
    # deterministically assert prune order.
    timestamps = [f"20260417T12000{i}Z" for i in range(5)]
    for ts in timestamps:
        created = backup_service.run_backup_now(max_copies=3, timestamp=ts)
        assert created is not None

    remaining = [p.name for p in backup_service.list_backups()]
    # The two oldest must be gone; the three newest must survive.
    assert len(remaining) == 3
    for expected in timestamps[-3:]:
        assert any(expected in name for name in remaining)
    for pruned in timestamps[:2]:
        assert not any(pruned in name for name in remaining)


def test_prune_backups_is_noop_when_under_limit(isolate_settings):
    root = backup_service.backups_dir()
    root.mkdir(parents=True, exist_ok=True)
    for ts in ("20260101T000000Z", "20260102T000000Z"):
        (root / f"orchestrator.{ts}.sqlite3").write_bytes(b"stub")

    removed = backup_service.prune_backups(root, max_copies=5)
    assert removed == []
    assert len(backup_service.list_backups(root)) == 2


def test_prune_backups_rejects_invalid_limit(isolate_settings):
    root = backup_service.backups_dir()
    root.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError):
        backup_service.prune_backups(root, max_copies=0)


def test_scheduler_honors_disabled_env(isolate_settings, monkeypatch):
    monkeypatch.setenv(backup_service.SCHEDULER_DISABLED_ENV, "1")
    backup_service.stop_scheduler()
    backup_service.start_scheduler(interval_seconds=0.01, max_copies=3)
    # Disabled: no timer was installed.
    assert backup_service._scheduler_timer is None
    assert backup_service._scheduler_enabled is False


def test_scheduler_start_is_idempotent(isolate_settings, monkeypatch):
    # Force-enable inside the test process so we can verify idempotency.
    monkeypatch.delenv(backup_service.SCHEDULER_DISABLED_ENV, raising=False)
    backup_service.stop_scheduler()
    try:
        backup_service.start_scheduler(interval_seconds=86400, max_copies=3)
        first_timer = backup_service._scheduler_timer
        backup_service.start_scheduler(interval_seconds=86400, max_copies=3)
        assert backup_service._scheduler_timer is first_timer
    finally:
        backup_service.stop_scheduler()
