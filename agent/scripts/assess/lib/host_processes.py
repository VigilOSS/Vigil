"""Precise host-process ownership registry used by host-exec reconciliation."""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import signal
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from .client import AssessError


_REGISTRY_RELPATH = (".runtime", "host-processes")
_RUN_UUID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REGISTRY_DIRECTORY_MODE = 0o700
_REGISTRY_RECORD_MODE = 0o600
_MAX_REGISTRY_RECORD_BYTES = 64 * 1024
_MAX_PROCESS_ID = 2_147_483_647
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
)
_RECORD_OPEN_FLAGS = (
    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
)


@dataclass(frozen=True)
class ProcessOwnership:
    """In-memory proof binding one PID/process group to its start identity."""

    pid: int
    pgid: int
    process_identity: str


@dataclass(frozen=True)
class _LoadedRecord:
    data: dict[str, Any]
    device: int
    inode: int


def _registry_dir(engagement_dir: str | os.PathLike[str]) -> Path:
    path = Path(engagement_dir)
    for part in _REGISTRY_RELPATH:
        path /= part
    return path


def _validate_run_uuid(run_uuid: str) -> str:
    if not isinstance(run_uuid, str) or not _RUN_UUID_RE.fullmatch(run_uuid):
        raise AssessError(
            "run_uuid must contain 1-64 letters, numbers, underscores, or hyphens"
        )
    return run_uuid


def _validate_ownership(ownership: ProcessOwnership) -> None:
    if (
        type(ownership.pid) is not int
        or ownership.pid <= 0
        or ownership.pid > _MAX_PROCESS_ID
        or type(ownership.pgid) is not int
        or ownership.pgid != ownership.pid
        or not isinstance(ownership.process_identity, str)
        or not ownership.process_identity.strip()
    ):
        raise AssessError("process ownership is malformed or does not own its process group")


def _open_directory_nofollow(path: Path) -> int:
    """Open every directory component from the filesystem anchor without links."""
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise AssessError(f"host-process registry root must be absolute: {path}")
    parts = absolute.parts
    if any(part in {".", ".."} for part in parts[1:]):
        raise AssessError(f"host-process registry root is not normalized: {path}")

    descriptor = os.open(absolute.anchor, _DIRECTORY_OPEN_FLAGS)
    try:
        for part in parts[1:]:
            next_descriptor = os.open(
                part,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_registry_directory(
    engagement_dir: str | os.PathLike[str], *, create: bool
) -> int | None:
    """Open and pin the private registry without following its child symlinks."""
    current_fd = _open_directory_nofollow(Path(engagement_dir))
    try:
        for part in _REGISTRY_RELPATH:
            created = False
            if create:
                try:
                    os.mkdir(part, _REGISTRY_DIRECTORY_MODE, dir_fd=current_fd)
                    created = True
                except FileExistsError:
                    pass
            try:
                child_fd = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    return None
                raise
            try:
                child_stat = os.fstat(child_fd)
                if child_stat.st_uid != os.geteuid():
                    raise AssessError(
                        f"host-process registry component {part!r} is not owned by the current user"
                    )
                os.fchmod(child_fd, _REGISTRY_DIRECTORY_MODE)
                os.fsync(child_fd)
                if created:
                    os.fsync(current_fd)
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        result = current_fd
        current_fd = -1
        return result
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while persisting host-process ownership")
        offset += written


def _entry_identity(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return entry_stat.st_dev, entry_stat.st_ino


def _unlink_matching_entry(
    directory_fd: int,
    name: str,
    *,
    device: int,
    inode: int,
) -> bool:
    """Remove ``name`` only when the atomically captured entry is the expected inode."""
    quarantine = f".{name}.{secrets.token_hex(16)}.reap"
    try:
        os.rename(
            name,
            quarantine,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return False
    captured = _entry_identity(directory_fd, quarantine)
    if captured == (device, inode):
        os.unlink(quarantine, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True

    # The name changed after it was read. Restore the captured entry without
    # overwriting anything that may now occupy the original name.
    try:
        os.link(
            quarantine,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError:
        return False
    os.unlink(quarantine, dir_fd=directory_fd)
    os.fsync(directory_fd)
    return False


def _best_effort_unlink_matching_entry(
    directory_fd: int,
    name: str,
    *,
    device: int,
    inode: int,
) -> bool:
    try:
        return _unlink_matching_entry(
            directory_fd,
            name,
            device=device,
            inode=inode,
        )
    except OSError:
        return False


def _process_identity(pid: int) -> str | None:
    """Return an OS process-start token, or None when ownership is unverifiable."""
    proc_stat = Path(f"/proc/{int(pid)}/stat")
    try:
        raw = proc_stat.read_text(encoding="ascii")
        # comm is parenthesized and may contain spaces/parentheses; split after
        # the final ')' then field 22 (starttime) is rest index 19.
        rest = raw.rsplit(")", 1)[1].strip().split()
        return f"proc-start:{rest[19]}" if len(rest) > 19 else None
    except (OSError, IndexError):
        pass
    try:
        created_at = float(psutil.Process(int(pid)).create_time())
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        OSError,
        TypeError,
        ValueError,
        OverflowError,
    ):
        return None
    if not math.isfinite(created_at) or created_at <= 0:
        return None
    return f"psutil-create:{created_at.hex()}"


def _pid_exists(pid: int) -> bool | None:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, TypeError, ValueError, OverflowError):
        return None
    return True


def _process_group_id(pid: int) -> int | None:
    try:
        return int(os.getpgid(int(pid)))
    except (ProcessLookupError, PermissionError, OSError, TypeError, ValueError, OverflowError):
        return None


def _group_exists(pgid: int) -> bool | None:
    """Probe process-group liveness independently of its original leader."""
    try:
        os.killpg(int(pgid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, TypeError, ValueError, OverflowError):
        return None
    return True


def capture_process_ownership(pid: int) -> ProcessOwnership:
    """Capture the live process identity before mutable registry I/O."""
    identity = _process_identity(pid)
    if identity is None:
        raise AssessError(
            f"host process pid={pid} has no verifiable start identity; refusing an imprecise registry entry"
        )
    pgid = _process_group_id(pid)
    if pgid != int(pid):
        raise AssessError(
            f"host process pid={pid} does not own a verifiable process group "
            f"(expected pgid={pid}, observed {pgid}); refusing registry entry"
        )
    return ProcessOwnership(
        pid=int(pid),
        pgid=int(pgid),
        process_identity=identity,
    )


def register_process_ownership(
    engagement_dir: str | os.PathLike[str],
    *,
    run_uuid: str,
    ownership: ProcessOwnership,
) -> Path:
    """Persist a previously captured ownership token for crash recovery."""
    safe_run_uuid = _validate_run_uuid(run_uuid)
    _validate_ownership(ownership)
    payload = json.dumps(
        {
            "run_uuid": safe_run_uuid,
            "pid": ownership.pid,
            "pgid": ownership.pgid,
            "process_identity": ownership.process_identity,
            "created_at_epoch": time.time(),
        },
        indent=2,
    ).encode("utf-8")
    directory_fd = _open_registry_directory(engagement_dir, create=True)
    if directory_fd is None:  # pragma: no cover - create=True guarantees a descriptor
        raise AssessError("host-process registry could not be opened")
    final_name = f"{safe_run_uuid}.json"
    temporary_name = f".{safe_run_uuid}.{secrets.token_hex(16)}.tmp"
    temporary_fd: int | None = None
    temporary_identity: tuple[int, int] | None = None
    published = False
    completed = False
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            _REGISTRY_RECORD_MODE,
            dir_fd=directory_fd,
        )
        os.fchmod(temporary_fd, _REGISTRY_RECORD_MODE)
        opened_stat = os.fstat(temporary_fd)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise AssessError("host-process registry temporary entry is not a regular file")
        temporary_identity = opened_stat.st_dev, opened_stat.st_ino
        _write_all(temporary_fd, payload)
        os.fsync(temporary_fd)
        if _entry_identity(directory_fd, temporary_name) != temporary_identity:
            raise AssessError("host-process registry temporary entry changed during publication")
        os.link(
            temporary_name,
            final_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        published = True
        if _entry_identity(directory_fd, final_name) != temporary_identity:
            raise AssessError("host-process registry final entry changed during publication")
        os.fsync(directory_fd)
        if not _unlink_matching_entry(
            directory_fd,
            temporary_name,
            device=temporary_identity[0],
            inode=temporary_identity[1],
        ):
            raise AssessError("host-process registry temporary entry changed during cleanup")
        temporary_identity = None
        completed = True
        return _registry_dir(engagement_dir) / final_name
    except FileExistsError as exc:
        raise AssessError(
            f"host-process registry already contains run_uuid={safe_run_uuid!r}"
        ) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if not completed and published and temporary_identity is not None:
            _best_effort_unlink_matching_entry(
                directory_fd,
                final_name,
                device=temporary_identity[0],
                inode=temporary_identity[1],
            )
        if temporary_identity is not None:
            _best_effort_unlink_matching_entry(
                directory_fd,
                temporary_name,
                device=temporary_identity[0],
                inode=temporary_identity[1],
            )
        os.close(directory_fd)


def _register_process(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str, pid: int
) -> tuple[Path, ProcessOwnership]:
    ownership = capture_process_ownership(pid)
    path = register_process_ownership(
        engagement_dir,
        run_uuid=run_uuid,
        ownership=ownership,
    )
    return path, ownership


def register_process(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str, pid: int
) -> Path:
    path, _ownership = _register_process(
        engagement_dir,
        run_uuid=run_uuid,
        pid=pid,
    )
    return path


def register_owned_process(
    engagement_dir: str | os.PathLike[str],
    *,
    run_uuid: str,
    pid: int,
    ownership: ProcessOwnership | None = None,
) -> ProcessOwnership:
    """Register a process and retain the exact ownership proof in memory."""
    captured = ownership or capture_process_ownership(pid)
    if captured.pid != int(pid):
        raise AssessError("captured process ownership does not match the requested pid")
    register_process_ownership(
        engagement_dir, run_uuid=run_uuid, ownership=captured
    )
    return captured


def unregister_process(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str
) -> None:
    safe_run_uuid = _validate_run_uuid(run_uuid)
    directory_fd = _open_registry_directory(engagement_dir, create=False)
    if directory_fd is None:
        return
    try:
        try:
            os.unlink(f"{safe_run_uuid}.json", dir_fd=directory_fd)
        except FileNotFoundError:
            return
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _owned_group_matches(pid: int, pgid: int, identity: str) -> bool:
    current = _process_identity(pid)
    if current == identity:
        return _process_group_id(pid) == pgid
    # A session leader may exit before background children. The saved PGID
    # remains the owned group while it has members; a confirmed-absent leader
    # is safe to distinguish from a reused PID, whose identity is non-None.
    if current is None and _pid_exists(pid) is False:
        return _group_exists(pgid) is True
    return False


def _wait_for_owned_exit(pid: int, pgid: int, identity: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        group_exists = _group_exists(pgid)
        if group_exists is False:
            return True
        if group_exists is None:
            return False
        time.sleep(0.1)
    return False


def _terminate_owned_group(pid: int, pgid: int, identity: str) -> bool:
    """Signal only the process group whose leader identity was registered."""
    for sig, grace in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 1.0)):
        if not _owned_group_matches(pid, pgid, identity):
            return _pid_exists(pid) is False and _group_exists(pgid) is False
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return True
        except (PermissionError, OSError, TypeError, ValueError, OverflowError):
            return False
        if _wait_for_owned_exit(pid, pgid, identity, grace):
            return True
    return False


def terminate_owned_process(ownership: ProcessOwnership) -> bool:
    """Terminate only the process group still bound to ``ownership``."""
    return _terminate_owned_group(
        ownership.pid,
        ownership.pgid,
        ownership.process_identity,
    )


def _read_record(directory_fd: int, name: str) -> _LoadedRecord | None:
    if not name.endswith(".json"):
        return None
    run_uuid = name.removesuffix(".json")
    try:
        _validate_run_uuid(run_uuid)
    except AssessError:
        return None
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _RECORD_OPEN_FLAGS, dir_fd=directory_fd)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            return None
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(
                descriptor,
                min(8192, _MAX_REGISTRY_RECORD_BYTES + 1 - size),
            )
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_REGISTRY_RECORD_BYTES:
                return None
        record = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(record, dict):
        return None
    pid = record.get("pid")
    pgid = record.get("pgid")
    identity = record.get("process_identity")
    created_at = record.get("created_at_epoch")
    if (
        record.get("run_uuid") != run_uuid
        or type(pid) is not int
        or pid <= 0
        or pid > _MAX_PROCESS_ID
        or type(pgid) is not int
        or pgid != pid
        or not isinstance(identity, str)
        or not identity.strip()
        or isinstance(created_at, bool)
        or not isinstance(created_at, (int, float))
        or not math.isfinite(float(created_at))
        or float(created_at) <= 0
    ):
        return None
    return _LoadedRecord(
        data=record,
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
    )


def reap_registered_processes(
    engagement_dir: str | os.PathLike[str],
    *,
    max_age_seconds: int,
    dry_run: bool = False,
    now_epoch: float | None = None,
) -> dict[str, int]:
    summary = {
        "checked": 0,
        "still_recent": 0,
        "reaped": 0,
        "stale": 0,
        "unverifiable": 0,
        "failed": 0,
    }
    now = time.time() if now_epoch is None else float(now_epoch)
    try:
        directory_fd = _open_registry_directory(engagement_dir, create=False)
    except (AssessError, OSError):
        summary["unverifiable"] += 1
        return summary
    if directory_fd is None:
        return summary
    try:
        try:
            names = sorted(
                name for name in os.listdir(directory_fd) if name.endswith(".json")
            )
        except OSError:
            summary["unverifiable"] += 1
            return summary
        for name in names:
            loaded = _read_record(directory_fd, name)
            if loaded is None:
                summary["unverifiable"] += 1
                continue
            record = loaded.data
            age = now - float(record["created_at_epoch"])
            if age < max_age_seconds:
                summary["still_recent"] += 1
                continue
            summary["checked"] += 1
            pid = int(record["pid"])
            pgid = int(record["pgid"])
            expected = str(record["process_identity"])
            current = _process_identity(pid)
            if current is None:
                if _pid_exists(pid) is False:
                    group_exists = _group_exists(pgid)
                    if group_exists is False:
                        summary["stale"] += 1
                        if not dry_run and not _best_effort_unlink_matching_entry(
                            directory_fd,
                            name,
                            device=loaded.device,
                            inode=loaded.inode,
                        ):
                            summary["failed"] += 1
                        continue
                    if group_exists is None:
                        summary["unverifiable"] += 1
                        continue
                    # Leader exited but the owned group still has background
                    # children; continue into group termination below.
                else:
                    summary["unverifiable"] += 1
                    continue
            elif current != expected:
                summary["stale"] += 1
                if not dry_run and not _best_effort_unlink_matching_entry(
                    directory_fd,
                    name,
                    device=loaded.device,
                    inode=loaded.inode,
                ):
                    summary["failed"] += 1
                continue
            elif _process_group_id(pid) != pgid:
                summary["unverifiable"] += 1
                continue
            if dry_run:
                summary["reaped"] += 1
                continue
            if _terminate_owned_group(pid, pgid, expected):
                summary["reaped"] += 1
                if not _best_effort_unlink_matching_entry(
                    directory_fd,
                    name,
                    device=loaded.device,
                    inode=loaded.inode,
                ):
                    summary["failed"] += 1
            else:
                summary["failed"] += 1
        return summary
    finally:
        os.close(directory_fd)
