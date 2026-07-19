"""Precise host-process ownership registry used by host-exec reconciliation."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .client import AssessError


_REGISTRY_RELPATH = (".runtime", "host-processes")


def _registry_dir(engagement_dir: str | os.PathLike[str]) -> Path:
    path = Path(engagement_dir)
    for part in _REGISTRY_RELPATH:
        path /= part
    return path


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
        result = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(int(pid))],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    started = result.stdout.strip()
    return f"ps-start:{started}" if result.returncode == 0 and started else None


def _pid_exists(pid: int) -> bool | None:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _process_group_id(pid: int) -> int | None:
    try:
        return int(os.getpgid(int(pid)))
    except (ProcessLookupError, PermissionError, OSError):
        return None


def _group_exists(pgid: int) -> bool | None:
    """Probe process-group liveness independently of its original leader."""
    try:
        os.killpg(int(pgid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def register_process(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str, pid: int
) -> Path:
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
    directory = _registry_dir(engagement_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_uuid}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps(
            {
                "run_uuid": run_uuid,
                "pid": int(pid),
                "pgid": pgid,
                "process_identity": identity,
                "created_at_epoch": time.time(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    tmp.replace(path)
    return path


def unregister_process(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str
) -> None:
    try:
        (_registry_dir(engagement_dir) / f"{run_uuid}.json").unlink()
    except FileNotFoundError:
        pass


def registered_group_alive(
    engagement_dir: str | os.PathLike[str], *, run_uuid: str
) -> bool | None:
    """Return whether a registered process group still has any members.

    ``None`` preserves the registry when its record or OS liveness cannot be
    verified; orphan reconciliation can then surface the uncertainty instead
    of host-exec deleting the only ownership evidence.
    """
    record = _read_record(_registry_dir(engagement_dir) / f"{run_uuid}.json")
    if record is None:
        return None
    return _group_exists(int(record["pgid"]))


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
            return _pid_exists(pid) is False
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return True
        except (PermissionError, OSError):
            return False
        if _wait_for_owned_exit(pid, pgid, identity, grace):
            return True
    return False


def _read_record(path: Path) -> dict[str, Any] | None:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict):
        return None
    if (
        not isinstance(record.get("pid"), int)
        or not isinstance(record.get("pgid"), int)
        or not record.get("process_identity")
    ):
        return None
    return record


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
    directory = _registry_dir(engagement_dir)
    if not directory.is_dir():
        return summary
    for path in sorted(directory.glob("*.json")):
        record = _read_record(path)
        if record is None:
            summary["unverifiable"] += 1
            continue
        age = now - float(record.get("created_at_epoch") or 0)
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
                    if not dry_run:
                        path.unlink(missing_ok=True)
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
            if not dry_run:
                path.unlink(missing_ok=True)
            continue
        elif _process_group_id(pid) != pgid:
            summary["unverifiable"] += 1
            continue
        if dry_run:
            summary["reaped"] += 1
            continue
        if _terminate_owned_group(pid, pgid, expected):
            summary["reaped"] += 1
            path.unlink(missing_ok=True)
        else:
            summary["failed"] += 1
    return summary
