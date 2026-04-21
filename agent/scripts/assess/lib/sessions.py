"""Session path/ID helpers — replaces lib/session_workflows.sh."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

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


def _write_json_atomically(path: Path, payload: Any) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.rename(path)


def normalize_assignment_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    changed = False
    if "assigned_findings" in payload:
        raise SystemExit(
            "legacy assigned_findings is no longer supported; rewrite session assignments to assigned_targets"
        )
    raw_targets = payload.get("assigned_targets")
    if not isinstance(raw_targets, list):
        raw_targets = []
    normalized = [str(item) for item in raw_targets]
    if payload.get("assigned_targets") != normalized:
        payload["assigned_targets"] = normalized
        changed = True
    return payload, changed


def load_session_index(engagement_dir: str) -> list[dict[str, Any]]:
    ensure_session_index(engagement_dir)
    index_path = Path(session_index_path(engagement_dir))
    rows = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        rows = []
    changed = False
    normalized_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        normalized_row, row_changed = normalize_assignment_payload(dict(row))
        changed = changed or row_changed
        normalized_rows.append(normalized_row)
    if changed:
        _write_json_atomically(index_path, normalized_rows)
    return normalized_rows


def save_session_index(engagement_dir: str, rows: list[dict[str, Any]]) -> None:
    normalized_rows = []
    for row in rows:
        normalized_row = dict(row)
        normalized_rows.append(normalize_assignment_payload(normalized_row)[0])
    _write_json_atomically(Path(session_index_path(engagement_dir)), normalized_rows)


def write_assignment_file(session_dir: str | Path, payload: dict[str, Any]) -> None:
    assignment_path = Path(session_dir) / "assignment.json"
    normalized_payload = dict(payload)
    normalized_payload, _ = normalize_assignment_payload(normalized_payload)
    _write_json_atomically(assignment_path, normalized_payload)
