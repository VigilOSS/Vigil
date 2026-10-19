"""Birth identity for managed host processes; PID reuse never conveys ownership."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

def _unavailable_process_identity(pid: int) -> None:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass
    raise SystemExit(f"Cannot inspect the birth identity of live PID {pid}; process ownership cannot be established.")


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


