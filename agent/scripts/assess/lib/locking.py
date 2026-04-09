"""mkdir-based file locks — replaces lock logic in findings.sh and append_log_entry.sh."""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Generator


class LockError(Exception):
    pass


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
