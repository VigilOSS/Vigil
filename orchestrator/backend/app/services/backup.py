"""Scheduled snapshot of ``orchestrator.sqlite3`` for disaster recovery.

Every 15 minutes a WAL-coherent snapshot is written to
``<data_dir>/backups/orchestrator.YYYYMMDDTHHMMSSZ.sqlite3``. The last 60
snapshots are retained (15 hours of continuous coverage at default cadence).

This complements the per-engagement snapshot taken by
``vigil engagement create``: that command protects against accidents during setup,
while the scheduled task protects against everything in between — operator
mistakes against a live DB, filesystem renames of engagement dirs that used
to trigger the sync cascade-delete, and general OS-level corruption.

Backups are sibling files next to the live DB, so they land on the same
volume. That's deliberate — they're for fast recovery from logical data
loss (accidental delete, cascade), not disk-failure disaster recovery. A
separate offsite rsync/borg is out of scope here.
"""
from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .. import db as db_module


SCHEDULER_DISABLED_ENV = "VIGIL_BACKUP_DISABLED"


DEFAULT_INTERVAL_SECONDS = 15 * 60
DEFAULT_MAX_COPIES = 60
BACKUP_PREFIX = "orchestrator."
BACKUP_SUFFIX = ".sqlite3"

_logger = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_timer: threading.Timer | None = None
_scheduler_enabled = False


def backups_dir(data_dir: Path | None = None) -> Path:
    from ..config import settings

    root = Path(data_dir) if data_dir is not None else settings.data_dir
    return root / "backups"


def _timestamp_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _backup_path(backups_root: Path, *, timestamp: str | None = None) -> Path:
    ts = timestamp or _timestamp_utc()
    return backups_root / f"{BACKUP_PREFIX}{ts}{BACKUP_SUFFIX}"


def list_backups(backups_root: Path | None = None) -> list[Path]:
    root = backups_root or backups_dir()
    if not root.exists():
        return []
    matches = [
        path
        for path in root.iterdir()
        if path.is_file()
        and path.name.startswith(BACKUP_PREFIX)
        and path.name.endswith(BACKUP_SUFFIX)
    ]
    matches.sort(key=lambda p: p.name)
    return matches


def prune_backups(backups_root: Path, max_copies: int) -> list[Path]:
    """Keep the newest ``max_copies`` snapshots, delete the rest. Returns
    the removed paths (useful for tests/logging)."""
    if max_copies < 1:
        raise ValueError("max_copies must be >= 1")
    all_backups = list_backups(backups_root)
    if len(all_backups) <= max_copies:
        return []
    to_remove = all_backups[: len(all_backups) - max_copies]
    removed: list[Path] = []
    for path in to_remove:
        try:
            path.unlink()
            removed.append(path)
        except OSError as exc:
            _logger.warning("Failed to prune backup %s: %s", path, exc)
    return removed


def run_backup_now(
    *,
    data_dir: Path | None = None,
    max_copies: int = DEFAULT_MAX_COPIES,
    timestamp: str | None = None,
) -> Path | None:
    """Take one snapshot and rotate old snapshots. Returns the new path, or
    ``None`` if the live DB is missing (fresh install, nothing to back up yet).
    """
    from ..config import settings

    live_db = (Path(data_dir) if data_dir is not None else settings.data_dir) / "orchestrator.sqlite3"
    if not live_db.exists():
        _logger.debug("Skipping scheduled backup — live DB not yet created at %s", live_db)
        return None

    backups_root = backups_dir(data_dir)
    backups_root.mkdir(parents=True, exist_ok=True)
    target = _backup_path(backups_root, timestamp=timestamp)

    tmp_target = target.with_name(target.name + ".partial")
    try:
        with sqlite3.connect(str(live_db)) as source, sqlite3.connect(str(tmp_target)) as dest:
            source.backup(dest)
        tmp_target.rename(target)
    except Exception as exc:
        _logger.warning("Scheduled backup to %s failed: %s", target, exc)
        if tmp_target.exists():
            try:
                tmp_target.unlink()
            except OSError:
                pass
        return None

    removed = prune_backups(backups_root, max_copies)
    if removed:
        _logger.info(
            "Wrote backup %s; rotated %d older snapshot(s).", target, len(removed)
        )
    else:
        _logger.info("Wrote backup %s.", target)
    return target


def start_scheduler(
    *,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    max_copies: int = DEFAULT_MAX_COPIES,
) -> None:
    """Install a daemon timer that runs :func:`run_backup_now` every
    ``interval_seconds``. Idempotent — second calls are no-ops.
    """
    global _scheduler_timer, _scheduler_enabled
    if os.environ.get(SCHEDULER_DISABLED_ENV, "").strip().lower() in {"1", "true", "yes"}:
        _logger.info(
            "Orchestrator DB backup scheduler disabled by %s env var.",
            SCHEDULER_DISABLED_ENV,
        )
        return
    with _scheduler_lock:
        if _scheduler_enabled:
            return
        _scheduler_enabled = True

        def _tick() -> None:
            global _scheduler_timer
            try:
                run_backup_now(max_copies=max_copies)
            except Exception as exc:  # pragma: no cover — belt + suspenders
                _logger.exception("Unhandled backup-scheduler error: %s", exc)
            with _scheduler_lock:
                if not _scheduler_enabled:
                    return
                _scheduler_timer = threading.Timer(interval_seconds, _tick)
                _scheduler_timer.daemon = True
                _scheduler_timer.start()

        _scheduler_timer = threading.Timer(interval_seconds, _tick)
        _scheduler_timer.daemon = True
        _scheduler_timer.start()
        _logger.info(
            "Orchestrator DB backup scheduler armed (interval=%ss, max_copies=%d).",
            interval_seconds,
            max_copies,
        )


def stop_scheduler() -> None:
    """Stop the scheduled timer. Safe to call when nothing is scheduled."""
    global _scheduler_timer, _scheduler_enabled
    with _scheduler_lock:
        _scheduler_enabled = False
        if _scheduler_timer is not None:
            _scheduler_timer.cancel()
            _scheduler_timer = None


# Used by tests only — mypy/IDEs can resolve shutil for the copy fallback path.
_ = shutil
_ = db_module
