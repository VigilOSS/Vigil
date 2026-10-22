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
import sys
from typing import Any, Iterator
import uuid

from .application import application_provenance, application_root_for_workspace
from .install_fs import atomic_write_bytes, open_pinned_directory
from .paths import resolve_runtime_state_dir
from .term import single_line


from .process_identity import _process_identity


def _registry_directory(workspace: Path) -> Path:
    return resolve_runtime_state_dir(workspace) / "client-sessions"


def historical_client_starts(workspace: Path) -> tuple[tuple[dict[str, Any], ...], bool]:
    """Read historical starts independently of process liveness; never repair records.

    This tolerant display projection must not replace the fail-closed active-session
    reader used by release upgrade guards.
    """
    rows: list[dict[str, Any]] = []
    incomplete = False
    for directory, launch in ((_registry_directory(workspace), False),
                              (resolve_runtime_state_dir(workspace) / "client-launches", True)):
        try:
            pin = open_pinned_directory(directory, missing_ok=True)
            if pin is None:
                continue
            with pin:
                for name in sorted(os.listdir(pin.fd)):
                    if not name.endswith(".json"):
                        continue
                    try:
                        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
                        with os.fdopen(descriptor, "rb") as document:
                            details = os.fstat(document.fileno())
                            if not stat.S_ISREG(details.st_mode) or details.st_size > 1024 * 1024:
                                raise ValueError("invalid historical record")
                            row = json.loads(document.read(1024 * 1024 + 1))
                        if not isinstance(row, dict) or row.get("schema_version") != 1:
                            raise ValueError("invalid historical record")
                        if not all(isinstance(row.get(key), str) for key in ("engagement", "client", "mode", "started_at")):
                            raise ValueError("invalid historical identity")
                        if launch:
                            if row.get("event") not in {"launch_requested", "workspace_opened"}:
                                raise ValueError("invalid launch event")
                        elif (not isinstance(row.get("pid"), int) or isinstance(row.get("pid"), bool)
                              or not isinstance(row.get("process_identity"), str)
                              or not isinstance(row.get("application"), dict)
                              or not all(isinstance(row["application"].get(key), str)
                                         for key in ("root", "version", "content_sha256"))):
                            raise ValueError("invalid historical session")
                        rows.append(row)
                    except (OSError, ValueError, RecursionError):
                        incomplete = True
                pin.require_attached()
        except (OSError, SystemExit):
            incomplete = True
    return tuple(rows), incomplete


def record_client_launch(workspace: Path, engagement: Path, client: str, mode: str,
                         *, event: str = "launch_requested") -> None:
    """Best-effort historical intent/open marker, not process or native readiness proof."""
    if event not in {"launch_requested", "workspace_opened"}:
        raise ValueError(f"Unsupported official client launch event: {event}")
    try:
        directory = resolve_runtime_state_dir(workspace) / "client-launches"
        row = {"schema_version": 1, "event": event, "engagement": str(engagement.resolve()),
               "client": client, "mode": mode, "started_at": datetime.now(timezone.utc).isoformat()}
        name = f"{uuid.uuid4().hex}.json"
        pin = open_pinned_directory(directory, create=True)
        assert pin is not None
        with pin:
            atomic_write_bytes(pin.fd, name, (json.dumps(row, sort_keys=True) + "\n").encode(),
                               mode=0o600, display=directory / name)
            pin.require_attached()
    except (OSError, SystemExit) as exc:
        print(f"Warning: could not record official client {event}: {exc}", file=sys.stderr)


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
def client_session_bootstrap(
    workspace: Path, engagement: Path, *, shared_files: bool = True, concurrent: bool = False,
) -> Iterator[bool]:
    """Serialize starts; retain shared configuration while its clients are alive.

    The yielded value permits shared-file refresh. Explicit maintenance retains
    the strict upgrade guard; official starts can join the retained release.
    Native projects do not consume the shared configuration or its release pin.
    """
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
            if shared_files and not concurrent:
                guard_client_session_upgrade(workspace, engagement)
            sessions: tuple[dict[str, Any], ...] = ()
            if concurrent or not shared_files:
                sessions = tuple(row for row in active_client_sessions(workspace)
                                 if Path(row["engagement"]).resolve() == engagement.resolve())
            shared = tuple(row for row in sessions if not (
                row.get("client") in {"opencode", "zcode"} and row.get("mode") in {"web", "code"}
            ))
            previous_root = os.environ.get("VIGIL_APPLICATION_DIR")
            try:
                if sessions:
                    clients = ", ".join(single_line(
                        f"{row.get('client') or 'client'} ({row.get('mode') or 'unknown mode'}, "
                        f"release {row['application']['version']}, PID {row['pid']})"
                    ) for row in sessions)
                    print(f"Warning: engagement {single_line(engagement.name)} already has active sessions: {clients}. "
                          "Starting another session; existing clients remain running.", file=sys.stderr, flush=True)
                if shared_files and shared:
                    retained = shared[0]["application"]
                    os.environ["VIGIL_APPLICATION_DIR"] = retained["root"]
                    print(f"Warning: reusing retained release {single_line(retained['version'])} and shared client "
                          "configuration without refreshing it. To adopt updated prompts and helpers for shared-config "
                          "clients, exit those clients and start again. Native project clients use separate contexts.",
                          file=sys.stderr, flush=True)
                yield not (shared_files and shared)
            finally:
                if shared_files and shared:
                    if previous_root is None:
                        os.environ.pop("VIGIL_APPLICATION_DIR", None)
                    else:
                        os.environ["VIGIL_APPLICATION_DIR"] = previous_root
            pin.require_attached()
        finally:
            os.close(descriptor)
