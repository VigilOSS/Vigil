"""Output preview, RSS rollup, scope/auth context helpers for kali runs.

Pure-ish I/O: read stdout/stderr files into a head+tail preview capped at
32KB, parse ``/proc/<pid>/status`` for the actual peak RSS (more accurate
than ``getrusage`` for a single child), and derive the scope-version /
auth-context audit fields from engagement files. Also owns the
``KaliResult`` dataclass that the orchestrator returns to callers.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional


@dataclasses.dataclass
class KaliResult:
    run_id: int | None
    status: str
    return_code: int | None
    stdout_path: str
    stderr_path: str
    duration_ms: int
    peak_rss_bytes: int | None
    stdout_preview: str
    stderr_preview: str
    timed_out: bool
    partial_results: bool


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope_version(engagement_dir: Path) -> str:
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return ""
    try:
        digest = hashlib.sha256(scope.read_bytes()).hexdigest()
    except OSError:
        return ""
    return digest[:16]


def _auth_context(engagement_dir: Path) -> str:
    auth = engagement_dir / "auth.json"
    if not auth.is_file():
        return "none"
    try:
        data = json.loads(auth.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "none"
    if not isinstance(data, dict):
        return "none"
    kind = data.get("kind") or data.get("mode") or "none"
    return str(kind) or "none"


def _peak_rss_kilobytes_to_bytes(peak_kb: int) -> int:
    # Linux exposes ru_maxrss in KB; macOS exposes it in bytes. Rather than
    # branch on platform, treat the number as KB on Linux (engagement runtime)
    # and fall back to "as reported" elsewhere. The audit field name uses
    # bytes so legacy MCP-era data stays consistent.
    if sys.platform == "linux":
        return peak_kb * 1024
    return peak_kb


def _read_proc_peak_rss(pid: int) -> Optional[int]:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("VmHWM:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _read_safely(path: Path, *, max_bytes: int = 32_768) -> str:
    """Return a preview of ``path`` capped at ``max_bytes``.

    For files smaller than ``max_bytes`` the full content is returned. For
    larger files we read ``head_budget`` bytes from the start and seek to the
    actual end-of-file for the tail — the previous implementation read
    ``max_bytes + 1`` bytes from the START and called the second half "tail",
    which silently lied about file content past the 32K mark (ISSUE-007).
    """
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size == 0:
        return ""
    head_budget = max_bytes // 2
    tail_budget = max_bytes - head_budget
    try:
        with path.open("rb") as fh:
            if size <= max_bytes:
                return fh.read().decode("utf-8", errors="replace")
            head = fh.read(head_budget)
            fh.seek(-tail_budget, os.SEEK_END)
            tail = fh.read(tail_budget)
    except OSError:
        return ""
    elided = size - len(head) - len(tail)
    return (
        f"{head.decode('utf-8', errors='replace')}\n"
        f"...\n[truncated {elided} bytes from middle of {size}-byte file]\n...\n"
        f"{tail.decode('utf-8', errors='replace')}"
    )
