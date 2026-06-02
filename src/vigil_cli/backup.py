from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .paths import resolve_orchestrator_data_dir

BACKUP_PREFIX = "orchestrator."
BACKUP_SUFFIX = ".sqlite3"


@dataclass(frozen=True, slots=True)
class BackupInfo:
    path: Path
    size: int
    modified_at: str


def data_dir(install_root: Path) -> Path:
    return resolve_orchestrator_data_dir(install_root)


def live_database(install_root: Path) -> Path:
    return data_dir(install_root) / "orchestrator.sqlite3"


def backups_dir(install_root: Path) -> Path:
    return data_dir(install_root) / "backups"


def create_backup(install_root: Path, *, timestamp: str | None = None) -> Path:
    source = live_database(install_root)
    if not source.exists():
        raise SystemExit(f"Orchestrator database not found: {source}")
    root = backups_dir(install_root)
    root.mkdir(parents=True, exist_ok=True)
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target, partial = _reserve_backup_paths(root, stamp)
    try:
        with sqlite3.connect(str(source)) as src, sqlite3.connect(str(partial)) as dst:
            src.backup(dst)
        partial.rename(target)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    return target


def list_backups(install_root: Path) -> list[BackupInfo]:
    root = backups_dir(install_root)
    if not root.exists():
        return []
    result: list[BackupInfo] = []
    for path in sorted(root.glob(f"{BACKUP_PREFIX}*{BACKUP_SUFFIX}")):
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result.append(BackupInfo(path=path.resolve(), size=stat.st_size, modified_at=modified))
    return result


def latest_backup(install_root: Path) -> BackupInfo | None:
    backups = list_backups(install_root)
    return backups[-1] if backups else None


def resolve_backup(install_root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.exists():
        return candidate.resolve()
    for item in list_backups(install_root):
        if item.path.name == value or item.path.stem == value:
            return item.path
    raise SystemExit(f"Backup not found: {value}")


def restore_backup(install_root: Path, backup: Path) -> Path:
    target = live_database(install_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not backup.exists():
        raise SystemExit(f"Backup not found: {backup}")
    partial = target.with_name(target.name + ".restore-partial")
    partial.unlink(missing_ok=True)
    shutil.copy2(backup, partial)
    try:
        with sqlite3.connect(str(partial)) as connection:
            result = connection.execute("PRAGMA quick_check").fetchone()
    except sqlite3.Error as exc:
        partial.unlink(missing_ok=True)
        raise SystemExit(f"Backup failed SQLite quick_check: {exc}") from exc
    if not result or result[0] != "ok":
        partial.unlink(missing_ok=True)
        raise SystemExit(f"Backup failed SQLite quick_check: {result[0] if result else 'no result'}")
    for path in (target, *_sqlite_sidecars(target)):
        path.unlink(missing_ok=True)
    partial.replace(target)
    for path in _sqlite_sidecars(target):
        path.unlink(missing_ok=True)
    return target


def _sqlite_sidecars(path: Path) -> tuple[Path, Path]:
    return (path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm"))


def _reserve_backup_paths(root: Path, stamp: str) -> tuple[Path, Path]:
    collision_index = 0
    while True:
        target = _backup_target(root, stamp, collision_index)
        partial = target.with_name(target.name + ".partial")
        try:
            with partial.open("xb"):
                pass
        except FileExistsError:
            collision_index += 1
            continue
        if target.exists():
            partial.unlink(missing_ok=True)
            collision_index += 1
            continue
        return target, partial


def _backup_target(root: Path, stamp: str, collision_index: int) -> Path:
    suffix = "" if collision_index == 0 else f"_{collision_index:04d}"
    return root / f"{BACKUP_PREFIX}{stamp}{suffix}{BACKUP_SUFFIX}"
