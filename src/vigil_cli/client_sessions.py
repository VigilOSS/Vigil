"""Retain release bindings for official client processes across application upgrades."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Iterator

from .application import application_provenance, application_root_for_workspace
from .install_fs import atomic_write_bytes, open_pinned_directory
from .paths import resolve_runtime_state_dir


def _unavailable_process_identity(pid: int) -> None:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    raise SystemExit(f"Cannot inspect the birth identity of live client PID {pid}; shared client files were not refreshed.")


def _process_identity(pid: int) -> str | None:
    """Bind a PID to its birth identity, so PID reuse does not revive a session."""
    if pid <= 0:
        return None
    proc = Path("/proc")
    if proc.is_dir():
        try:
            fields = (proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] == "Z":
                return None
            boot = (proc / "sys/kernel/random/boot_id").read_text().strip()
            return f"proc:{boot}:{fields[19]}"
        except (OSError, IndexError):
            _unavailable_process_identity(pid)
            return None
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat=", "-o", "lstart="], capture_output=True,
            text=True, check=False, timeout=5, env={**os.environ, "LC_ALL": "C", "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired):
        _unavailable_process_identity(pid)
        return None
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        _unavailable_process_identity(pid)
        return None
    state, _, birth = value.partition(" ")
    if state.startswith("Z"):
        return None
    if not birth.strip():
        _unavailable_process_identity(pid)
        return None
    return f"ps:{birth.strip()}"


def _registry_directory(workspace: Path) -> Path:
    return resolve_runtime_state_dir(workspace) / "client-sessions"


def active_client_sessions(workspace: Path) -> tuple[dict[str, Any], ...]:
    """Read live official starts without deleting their historical registry records."""
    directory = _registry_directory(workspace)
    pin = open_pinned_directory(directory, missing_ok=True)
    if pin is None:
        return ()
    rows: list[dict[str, Any]] = []
    identities: dict[int, str | None] = {}
    with pin:
        for name in sorted(os.listdir(pin.fd)):
            if not name.endswith(".json"):
                continue
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise SystemExit(f"Invalid client session registry entry: {directory / name}")
                with os.fdopen(descriptor, encoding="utf-8") as document:
                    descriptor = -1
                    row = json.load(document)
            except (ValueError, OSError) as exc:
                raise SystemExit(f"Cannot read client session registry: {directory / name}: {exc}") from exc
            finally:
                if descriptor != -1:
                    os.close(descriptor)
            if (not isinstance(row, dict) or row.get("schema_version") != 1
                    or not isinstance(row.get("pid"), int) or isinstance(row["pid"], bool)
                    or not isinstance(row.get("process_identity"), str)
                    or not isinstance(row.get("engagement"), str)
                    or not isinstance(row.get("application"), dict)
                    or any(not isinstance(row["application"].get(key), str)
                           for key in ("root", "version", "content_sha256"))):
                raise SystemExit(f"Invalid client session registry entry: {directory / name}")
            pid = row["pid"]
            if pid not in identities:
                identities[pid] = _process_identity(pid)
            if identities[pid] is not None and identities[pid] == row["process_identity"]:
                rows.append(row)
    return tuple(rows)


def guard_client_session_upgrade(
    workspace: Path, engagement: Path, application_root: Path | None = None,
) -> None:
    """Refuse to rebind shared client paths while another release uses them."""
    provenance = application_provenance(application_root or application_root_for_workspace(workspace))
    for session in active_client_sessions(workspace):
        if Path(session["engagement"]).resolve() != engagement.resolve():
            continue
        original = session["application"]
        if (original["version"], original["content_sha256"]) == (provenance["version"], provenance["content_sha256"]):
            continue
        raise SystemExit(
            f"engagement {engagement.name} has an active client session from release "
            f"{original['version']} ({session.get('client') or 'client'}, PID {session['pid']}). "
            "It can continue using its current prompts and helpers. When ready to adopt the update, "
            "save a handoff, exit that client, and start the engagement again. Pausing does not "
            "replace its inherited helper paths or instructions already in the conversation."
        )


def record_client_session(workspace: Path, engagement: Path, client: str, mode: str) -> dict[str, Any]:
    pid = os.getpid()
    identity = _process_identity(pid)
    if identity is None:
        raise SystemExit("Cannot establish the client process birth identity; refusing an untracked release binding.")
    provenance = application_provenance(application_root_for_workspace(workspace))
    row = {
        "schema_version": 1,
        "pid": pid,
        "process_identity": identity,
        "workspace": str(workspace.resolve()),
        "engagement": str(engagement.resolve()),
        "client": client,
        "mode": mode,
        "application": provenance,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    suffix = hashlib.sha256(f"{identity}:{provenance['content_sha256']}:{engagement.resolve()}".encode()).hexdigest()[:24]
    name = f"{pid}-{suffix}.json"
    directory = _registry_directory(workspace)
    pin = open_pinned_directory(directory, create=True)
    assert pin is not None
    with pin:
        atomic_write_bytes(pin.fd, name, (json.dumps(row, indent=2, sort_keys=True) + "\n").encode(),
                           mode=0o600, display=directory / name)
        pin.require_attached()
    return row


@contextmanager
def client_session_bootstrap(workspace: Path, engagement: Path) -> Iterator[None]:
    """Serialize release checks, shared-file refresh, and the official start receipt."""
    directory = _registry_directory(workspace)
    pin = open_pinned_directory(directory, create=True)
    assert pin is not None
    with pin:
        descriptor = os.open("bootstrap.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                             0o600, dir_fd=pin.fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SystemExit(f"Invalid client bootstrap lock: {directory / 'bootstrap.lock'}")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            pin.require_attached()
            guard_client_session_upgrade(workspace, engagement)
            yield
            pin.require_attached()
        finally:
            os.close(descriptor)
