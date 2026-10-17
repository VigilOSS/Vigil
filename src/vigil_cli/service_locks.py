"""Process locks for shared local services, independent of engagement lifetime."""
from __future__ import annotations

import fcntl
import hashlib
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .application import _application_cache
from .install_fs import open_pinned_directory

_held_locks = threading.local()


@contextmanager
def service_start_lock(identity: str) -> Iterator[None]:
    """Serialize discovery and creation without taking ownership of a service.

    Nested operations in this process/thread retain outer ownership. Other
    threads and processes still acquire the OS lock. Locks do not supervise a
    service or terminate another engagement's work.
    """
    key = (os.getpid(), identity)
    held = getattr(_held_locks, 'identities', None)
    if held is None:
        held = _held_locks.identities = set()
    if key in held:
        yield
        return
    directory = _application_cache() / "service-locks"
    name = hashlib.sha256(identity.encode()).hexdigest() + ".lock"
    pin = open_pinned_directory(directory, create=True)
    assert pin is not None
    with pin:
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=pin.fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise SystemExit(f"Invalid shared service lock: {directory / name}")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            pin.require_attached()
            held.add(key)
            try:
                yield
                pin.require_attached()
            finally:
                held.remove(key)
        finally:
            os.close(descriptor)
