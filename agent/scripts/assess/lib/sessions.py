"""Session path/ID helpers — replaces lib/session_workflows.sh."""
from __future__ import annotations

import json
import re
from pathlib import Path

_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_session_id(session_id: str) -> None:
    """Validate session ID format."""
    if not _SESSION_ID_RE.match(session_id):
        raise SystemExit(f"invalid session id: {session_id}")


def session_root_path(engagement_dir: str) -> str:
    return str(Path(engagement_dir) / "sessions")


def session_index_path(engagement_dir: str) -> str:
    return str(Path(session_root_path(engagement_dir)) / "index.json")


def session_dir_path(engagement_dir: str, session_id: str) -> str:
    validate_session_id(session_id)
    return str(Path(session_root_path(engagement_dir)) / session_id)


def ensure_session_index(engagement_dir: str) -> None:
    """Create sessions directory and index.json if they don't exist."""
    root = Path(session_root_path(engagement_dir))
    root.mkdir(parents=True, exist_ok=True)
    index = Path(session_index_path(engagement_dir))
    if not index.is_file():
        index.write_text("[]\n", encoding="utf-8")
