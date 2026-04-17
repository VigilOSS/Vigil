from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from fastapi import HTTPException, status

from .. import db
from ..config import settings
from ..models.engagement import Engagement
from ..models.engagement_session import EngagementSession


@dataclass(frozen=True, slots=True)
class EngagementView:
    id: int
    key: str
    target: str
    status: str
    engagement_root: str
    current_phase: str
    exploit_policy: str
    exploit_review_state: str
    approved_targets: list[str]
    created_at: str
    updated_at: str
    session_count: int


_sync_lock = Lock()
_last_sync_signature: tuple[tuple[str, int, int | None, int | None], ...] | None = None
_logger = logging.getLogger(__name__)


def engagements_root() -> Path:
    return settings.install_dir / "agent" / "engagements"


def _json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json_atomically(path: Path, payload: Any) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.rename(path)


def _normalize_target_list(payload: dict[str, Any], *, new_key: str, old_key: str) -> bool:
    changed = False
    raw_targets = payload.get(new_key)
    if not isinstance(raw_targets, list):
        raw_targets = payload.get(old_key)
    if not isinstance(raw_targets, list):
        raw_targets = []
    normalized = [str(item) for item in raw_targets]
    if payload.get(new_key) != normalized:
        payload[new_key] = normalized
        changed = True
    if old_key in payload:
        del payload[old_key]
        changed = True
    return changed


def _read_json_for_migration(path: Path, *, expected_type: type) -> Any:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"failed to read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, expected_type):
        raise RuntimeError(f"expected {expected_type.__name__} in {path}, got {type(payload).__name__}")
    return payload


def _normalize_assignment_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    changed = _normalize_target_list(payload, new_key="assigned_targets", old_key="assigned_findings")
    return payload, changed


def _migrate_scope_file(scope_path: Path) -> dict[str, Any]:
    scope = _read_json_for_migration(scope_path, expected_type=dict)
    changed = _normalize_target_list(scope, new_key="approved_targets", old_key="approved_findings")
    if changed:
        _write_json_atomically(scope_path, scope)
    return scope


def _migrate_session_artifacts(engagement_dir: Path) -> list[dict[str, Any]]:
    sessions_root = engagement_dir / "sessions"
    sessions_root.mkdir(parents=True, exist_ok=True)
    index_path = sessions_root / "index.json"
    if not index_path.exists():
        _write_json_atomically(index_path, [])
        rows: list[dict[str, Any]] = []
    else:
        rows = _read_json_for_migration(index_path, expected_type=list)
        changed = False
        normalized_rows: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                changed = True
                continue
            normalized_row, row_changed = _normalize_assignment_payload(dict(row))
            changed = changed or row_changed
            normalized_rows.append(normalized_row)
        rows = normalized_rows
        if changed:
            _write_json_atomically(index_path, rows)

    for session_dir in sorted(path for path in sessions_root.iterdir() if path.is_dir()):
        assignment_path = session_dir / "assignment.json"
        if not assignment_path.exists():
            continue
        assignment = _read_json_for_migration(assignment_path, expected_type=dict)
        _, changed = _normalize_assignment_payload(assignment)
        if changed:
            _write_json_atomically(assignment_path, assignment)

    return rows


def _manifest_for(engagement_dir: Path) -> dict[str, Any]:
    manifest_path = engagement_dir / "engagement.json"
    scope_path = engagement_dir / "scope.json"
    manifest = _json_file(manifest_path)
    scope = _migrate_scope_file(scope_path)
    key = engagement_dir.name
    target = str(manifest.get("target") or manifest.get("hostname") or scope.get("hostname") or key)
    status = str(scope.get("status") or "in_progress")
    return {
        "key": key,
        "target": target,
        "status": status,
        "scope": scope,
    }


def _session_payload(index_row: dict[str, Any], session_dir: Path) -> dict[str, str]:
    assigned_targets = index_row.get("assigned_targets")
    if not isinstance(assigned_targets, list):
        assigned_targets = []
    merged_at = index_row.get("merged_at")
    if not isinstance(merged_at, str):
        merged_at = None
    return {
        "status": str(index_row.get("status") or "active"),
        "merge_state": str(index_row.get("merge_state") or "pending"),
        "assigned_targets_json": json.dumps(assigned_targets, ensure_ascii=True),
        "session_path": str(session_dir),
        "merged_at": merged_at,
    }


def _safe_mtime_ns(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _engagements_signature() -> tuple[tuple[str, int, int | None, int | None], ...]:
    root = engagements_root()
    root.mkdir(parents=True, exist_ok=True)

    signature: list[tuple[str, int, int | None, int | None]] = []
    for engagement_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        scope_path = engagement_dir / "scope.json"
        scope_mtime_ns = _safe_mtime_ns(scope_path)
        if scope_mtime_ns is None:
            continue
        signature.append(
            (
                engagement_dir.name,
                scope_mtime_ns,
                _safe_mtime_ns(engagement_dir / "engagement.json"),
                _safe_mtime_ns(engagement_dir / "sessions" / "index.json"),
            )
        )
    return tuple(signature)


def sync_engagements() -> None:
    root = engagements_root()
    root.mkdir(parents=True, exist_ok=True)

    discovered_keys: set[str] = set()
    for engagement_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if not (engagement_dir / "scope.json").exists():
            continue
        discovered_keys.add(engagement_dir.name)
        try:
            manifest = _manifest_for(engagement_dir)
            index_rows = _migrate_session_artifacts(engagement_dir)

            engagement = db.get_engagement_by_key(manifest["key"])
            if engagement is None:
                engagement = db.create_engagement(
                    manifest["key"],
                    manifest["target"],
                    manifest["status"],
                    str(engagement_dir),
                )
            else:
                db.update_engagement_identity(
                    engagement.id,
                    manifest["target"],
                    manifest["status"],
                    str(engagement_dir),
                )
                engagement = db.get_engagement_by_id(engagement.id)
                assert engagement is not None

            seen_session_ids: set[str] = set()
            if isinstance(index_rows, list):
                for index_row in index_rows:
                    if not isinstance(index_row, dict):
                        continue
                    session_id = str(index_row.get("session_id") or "").strip()
                    if not session_id:
                        continue
                    seen_session_ids.add(session_id)
                    session_dir = engagement_dir / "sessions" / session_id
                    db.upsert_engagement_session(
                        engagement.id,
                        session_id,
                        **_session_payload(index_row, session_dir),
                    )

            for session in db.list_engagement_sessions_for_engagement(engagement.id):
                if session.session_id not in seen_session_ids:
                    db.delete_engagement_session(engagement.id, session.session_id)
        except RuntimeError as exc:
            _logger.warning("Skipping invalid engagement artifacts for %s: %s", engagement_dir, exc)
            continue

    # Sync is ADDITIVE only. A filesystem directory that vanished (renamed,
    # archived, accidentally rm'd, or temporarily moved for backup) used to
    # cascade-delete every engagement row — findings, probe runs, command
    # runs, code analysis, credentials — via the FK ON DELETE CASCADE chain.
    # Silent destruction of engagement history is never an acceptable
    # filesystem-drift response. Explicit deletion MUST go through the
    # `DELETE /api/engagements/{key}` endpoint with a confirm token.
    for engagement in db.list_engagements():
        if engagement.key not in discovered_keys:
            _logger.info(
                "Engagement %s (id=%s) has no filesystem directory under %s; "
                "retaining DB row. Use DELETE /api/engagements/%s to remove explicitly.",
                engagement.key,
                engagement.id,
                engagements_root(),
                engagement.key,
            )


def maybe_sync_engagements(force: bool = False) -> None:
    global _last_sync_signature

    signature = _engagements_signature()
    if not force and signature == _last_sync_signature:
        return

    with _sync_lock:
        signature = _engagements_signature()
        if not force and signature == _last_sync_signature:
            return
        sync_engagements()
        _last_sync_signature = signature


def _scope_details(engagement_root: Path) -> tuple[str, str, str, list[str]]:
    try:
        scope = _migrate_scope_file(engagement_root / "scope.json")
    except RuntimeError as exc:
        _logger.warning("Using persisted engagement identity for invalid scope at %s: %s", engagement_root, exc)
        return "unknown", "pause", "pending", []
    current_phase = str(scope.get("current_phase") or "unknown")
    exploit_policy = str(scope.get("exploit_policy") or "pause")
    exploit_review_state = str(scope.get("exploit_review_state") or "pending")
    approved_targets = scope.get("approved_targets")
    if not isinstance(approved_targets, list):
        approved_targets = []
    return current_phase, exploit_policy, exploit_review_state, [str(item) for item in approved_targets]


def _view_for(engagement: Engagement) -> EngagementView:
    current_phase, exploit_policy, exploit_review_state, approved_targets = _scope_details(Path(engagement.engagement_root))
    return EngagementView(
        id=engagement.id,
        key=engagement.key,
        target=engagement.target,
        status=engagement.status,
        engagement_root=engagement.engagement_root,
        current_phase=current_phase,
        exploit_policy=exploit_policy,
        exploit_review_state=exploit_review_state,
        approved_targets=approved_targets,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        session_count=len(db.list_engagement_sessions_for_engagement(engagement.id)),
    )


def list_engagements() -> list[EngagementView]:
    maybe_sync_engagements()
    return [_view_for(engagement) for engagement in db.list_engagements()]


def get_engagement_or_404(engagement_key: str) -> Engagement:
    maybe_sync_engagements()
    engagement = db.get_engagement_by_key(engagement_key)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")
    return engagement


def get_engagement_view_or_404(engagement_key: str) -> EngagementView:
    engagement = get_engagement_or_404(engagement_key)
    return _view_for(engagement)


def list_sessions_for_engagement(engagement_key: str) -> list[EngagementSession]:
    engagement = get_engagement_or_404(engagement_key)
    return db.list_engagement_sessions_for_engagement(engagement.id)
