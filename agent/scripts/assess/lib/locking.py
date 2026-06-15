"""mkdir-based file locks — replaces lock logic in findings.sh and append_log_entry.sh.

Also hosts :func:`network_heavy_lock` (CR-9): a global "one network-heavy op at a
time" advisory lock that serializes DNS brutes / bulk liveness across BOTH the
host execution lane and the in-container lane. Because the engagement dir is
bind-mounted into the runtime container, a lockfile under it is a path both lanes
share; the canonical arbiter is the HOST-side dispatch (it launches both the
host subprocess and the ``docker exec``), so taking the lock there covers both.
"""
from __future__ import annotations

import fcntl
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator


class LockError(Exception):
    pass


# Env that marks a dedicated / Heavy-tier runtime where the serialization cap
# does NOT apply (operator-core.md: cap=1 is Standard/shared-tier only). When set
# truthy, :func:`network_heavy_lock` is a no-op.
_DEDICATED_RUNTIME_ENV = "VIGIL_DEDICATED_RUNTIME"

_NETWORK_HEAVY_LOCK_RELPATH = (".locks", "network-heavy.lock")


@contextmanager
def file_lock(lock_path: str, max_attempts: int = 200, interval: float = 0.05) -> Generator[str, None, None]:
    """Acquire a mkdir-based lock. Same protocol as the bash scripts."""
    attempts = 0
    while True:
        try:
            os.mkdir(lock_path)
            break
        except FileExistsError:
            attempts += 1
            if attempts >= max_attempts:
                raise LockError(f"Failed to acquire lock: {lock_path}")
            time.sleep(interval)
    try:
        yield lock_path
    finally:
        try:
            os.rmdir(lock_path)
        except OSError:
            pass


def _dedicated_runtime() -> bool:
    """True when the runtime is dedicated/Heavy-tier (lock is a no-op)."""
    raw = os.environ.get(_DEDICATED_RUNTIME_ENV, "").strip().lower()
    return raw not in ("", "0", "false", "no", "off")


def _holder_is_stale(fd: int) -> bool:
    """True when the PID recorded in the lockfile is no longer alive.

    Mirrors kali_nuclei.py's stale-holder reclaim so a crashed holder cannot wedge
    the global network lock forever. A PID owned by another user is treated as
    ALIVE (we can't safely force-release it). No recorded PID → holder crashed
    before writing one → stale.
    """
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        prior_raw = os.read(fd, 64).decode("ascii", errors="ignore").strip()
    except OSError:
        return False
    if not prior_raw:
        return True
    try:
        prior_pid = int(prior_raw)
    except ValueError:
        return True
    try:
        os.kill(prior_pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    except OSError:
        return True
    return False


@contextmanager
def network_heavy_lock(
    engagement_dir: str | os.PathLike[str],
    *,
    label: str,
    timeout_s: float = 0,
    blocking: bool = True,
) -> Generator[bool, None, None]:
    """Global "one network-heavy op at a time" lock spanning host + container (CR-9).

    A single ``fcntl.flock`` over ``<engagement_dir>/.locks/network-heavy.lock`` —
    a path both the host lane and the bind-mounted container lane see — so a host
    DNS brute and an in-container bulk httpx cannot run concurrently and reproduce
    the I-006 host-NIC starvation. The canonical arbiter is the host-side dispatch.

    Tier-gated: a NO-OP (yields immediately) when ``VIGIL_DEDICATED_RUNTIME`` is
    set, matching the operator-core policy that the cap=1 rule applies on
    Standard/shared tier only.

    Contention policy (the kali_nuclei lesson — a hard-fail killed the swarm):
    BLOCK up to ``timeout_s`` then PROCEED anyway with a one-line WARN. Never
    hard-fails the dispatch. ``timeout_s=0`` with ``blocking=True`` means block
    indefinitely (serialize fully). ``blocking=False`` tries once and proceeds-
    with-WARN on contention. A stale holder (dead PID) is reclaimed immediately.

    Yields True when the lock was actually held for the body, False when it
    proceeded WITHOUT the lock (dedicated tier no-op, or contention past timeout).

    Args:
        engagement_dir: engagement root (bind-mounted at /engagements in-container).
        label: short op label for the WARN line (e.g. ``'puredns brute'``).
        timeout_s: max seconds to wait on contention before proceeding-with-WARN;
            0 = wait indefinitely when ``blocking``.
        blocking: when False, never wait — proceed-with-WARN immediately on
            contention.
    """
    if _dedicated_runtime():
        yield False
        return

    lock_path = Path(engagement_dir)
    for part in _NETWORK_HEAVY_LOCK_RELPATH:
        lock_path = lock_path / part
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as exc:
        # Can't even create the lockfile — degrade to no-op rather than blocking
        # the dispatch on a filesystem quirk.
        print(
            f"WARN: network-heavy lock unavailable ({exc}); proceeding without "
            f"serialization for {label}.",
            file=sys.stderr,
        )
        yield False
        return

    acquired = False
    deadline = (time.monotonic() + timeout_s) if timeout_s > 0 else None
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if _holder_is_stale(fd):
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except BlockingIOError:
                        pass
                if not blocking:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                time.sleep(0.5)

        if acquired:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                os.write(fd, f"{os.getpid()}\n".encode("ascii"))
            except OSError:
                pass
        else:
            print(
                f"WARN: another network-heavy op holds the global lock past "
                f"{int(timeout_s)}s — proceeding with {label} anyway (serialization "
                "not guaranteed). Set VIGIL_DEDICATED_RUNTIME on a dedicated runtime "
                "to silence this.",
                file=sys.stderr,
            )

        yield acquired
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        try:
            os.close(fd)
        except OSError:
            pass
