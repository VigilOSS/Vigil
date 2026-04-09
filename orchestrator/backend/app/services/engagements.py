from __future__ import annotations

import json
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
    approved_findings: list[str]
    created_at: str
    updated_at: str
    session_count: int


_sync_lock = Lock()
_last_sync_signature: tuple[tuple[str, int, int | None, int | None], ...] | None = None


def engagements_root() -> Path:
    return settings.install_dir / "agent" / "engagements"


def _json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _manifest_for(engagement_dir: Path) -> dict[str, Any]:
    manifest_path = engagement_dir / "engagement.json"
    scope_path = engagement_dir / "scope.json"
    manifest = _json_file(manifest_path)
    scope = _json_file(scope_path)
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
    assigned_findings = index_row.get("assigned_findings")
    if not isinstance(assigned_findings, list):
        assigned_findings = []
    merged_at = index_row.get("merged_at")
    if not isinstance(merged_at, str):
        merged_at = None
    return {
        "status": str(index_row.get("status") or "active"),
        "merge_state": str(index_row.get("merge_state") or "pending"),
        "assigned_findings_json": json.dumps(assigned_findings, ensure_ascii=True),
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
        manifest = _manifest_for(engagement_dir)
        discovered_keys.add(manifest["key"])
        engagement = db.get_engagement_by_key(manifest["key"])
        if engagement is None:
            engagement = db.create_engagement(manifest["key"], manifest["target"], manifest["status"], str(engagement_dir))
        else:
            db.update_engagement_identity(engagement.id, manifest["target"], manifest["status"], str(engagement_dir))
            engagement = db.get_engagement_by_id(engagement.id)
            assert engagement is not None

        index_path = engagement_dir / "sessions" / "index.json"
        seen_session_ids: set[str] = set()
        if not index_path.exists():
            index_rows = []
        else:
            try:
                index_rows = json.loads(index_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                index_rows = []
        if isinstance(index_rows, list):
            for index_row in index_rows:
                if not isinstance(index_row, dict):
                    continue
                session_id = str(index_row.get("session_id") or "").strip()
                if not session_id:
                    continue
                seen_session_ids.add(session_id)
                session_dir = engagement_dir / "sessions" / session_id
                db.upsert_engagement_session(engagement.id, session_id, **_session_payload(index_row, session_dir))

        for session in db.list_engagement_sessions_for_engagement(engagement.id):
            if session.session_id not in seen_session_ids:
                db.delete_engagement_session(engagement.id, session.session_id)

    for engagement in db.list_engagements():
        if engagement.key not in discovered_keys:
            db.delete_engagement(engagement.id)


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
    scope = _json_file(engagement_root / "scope.json")
    current_phase = str(scope.get("current_phase") or "unknown")
    exploit_policy = str(scope.get("exploit_policy") or "pause")
    exploit_review_state = str(scope.get("exploit_review_state") or "pending")
    approved_findings = scope.get("approved_findings")
    if not isinstance(approved_findings, list):
        approved_findings = []
    return current_phase, exploit_policy, exploit_review_state, [str(item) for item in approved_findings]


def _view_for(engagement: Engagement) -> EngagementView:
    current_phase, exploit_policy, exploit_review_state, approved_findings = _scope_details(Path(engagement.engagement_root))
    return EngagementView(
        id=engagement.id,
        key=engagement.key,
        target=engagement.target,
        status=engagement.status,
        engagement_root=engagement.engagement_root,
        current_phase=current_phase,
        exploit_policy=exploit_policy,
        exploit_review_state=exploit_review_state,
        approved_findings=approved_findings,
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
