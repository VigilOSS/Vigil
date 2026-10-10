from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from fastapi import HTTPException, status

from .. import db
from ..config import settings
from ..models.engagement import Engagement
from ..models.engagement_session import EngagementSession
from .engagement_tracks import track_phases


@dataclass(frozen=True, slots=True)
class EngagementView:
    id: int
    key: str
    target: str
    status: str
    engagement_root: str
    current_phase: str
    code_phase: str | None
    track_phases: dict[str, str]
    exploit_policy: str
    exploit_review_state: str
    approved_targets: list[str]
    scope_hosts: list[str]
    scope_priority: int
    created_at: str
    updated_at: str
    session_count: int
    engagement_type: str | None = None
    customer: str | None = None
    platforms: list[str] | None = None
    tenant_reference_paths: list[str] | None = None
    out_of_scope: list[str] | None = None
    capture_policy: dict[str, Any] | None = None


AssignmentSignature = tuple[tuple[str, int | None], ...]
EngagementSignatureRow = tuple[
    str,
    int | None,
    int | None,
    int | None,
    AssignmentSignature,
    int | None,
]
EngagementsSignature = tuple[str, tuple[EngagementSignatureRow, ...]]
ListCacheKey = tuple[str, str | None, str | None, EngagementsSignature | None]


_sync_lock = Lock()
_list_cache_lock = Lock()
_last_sync_signature: EngagementsSignature | None = None
_last_sync_checked_at = 0.0
_SYNC_SIGNATURE_TTL_SECONDS = 1.0
_LIST_CACHE_TTL_SECONDS = 1.0
_list_cache: dict[ListCacheKey, tuple[float, tuple[EngagementView, ...]]] = {}
_logger = logging.getLogger(__name__)
_DELETED_ENGAGEMENTS_DIR = ".deleted-engagements"
_LEGACY_FINDING_PREFIX = "FINDING" + "-"


def engagements_root() -> Path:
    return settings.engagements_dir or settings.install_dir / "agent" / "engagements"


def _deleted_engagement_marker_path(engagement_key: str) -> Path:
    return engagements_root() / _DELETED_ENGAGEMENTS_DIR / f"{engagement_key}.json"


def mark_engagement_deleted(engagement: Engagement) -> None:
    marker_path = _deleted_engagement_marker_path(engagement.key)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomically(
        marker_path,
        {
            "key": engagement.key,
            "id": engagement.id,
            "engagement_root": engagement.engagement_root,
            "deleted_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    clear_list_engagements_cache()


def _json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json_atomically(path: Path, payload: Any) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.rename(path)


def _strip_legacy_finding_prefix(value: str) -> str:
    if value.startswith(_LEGACY_FINDING_PREFIX):
        return value[len(_LEGACY_FINDING_PREFIX) :]
    return value


def _normalize_target_list(payload: dict[str, Any], *, new_key: str, old_key: str) -> bool:
    changed = False
    raw_targets = payload.get(new_key)
    if not isinstance(raw_targets, list):
        raw_targets = payload.get(old_key)
    if not isinstance(raw_targets, list):
        raw_targets = []
    normalized = [_strip_legacy_finding_prefix(str(item)) for item in raw_targets]
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
    # ``engagement_type`` comes from scope.json (preferred) with a fallback to
    # engagement.json. None means "leave whatever the DB had", which preserves
    # the DEFAULT 'red' for fresh rows without overriding existing values.
    raw_type = scope.get("engagement_type") or manifest.get("engagement_type")
    engagement_type: str | None = str(raw_type) if raw_type else None
    status = str(scope.get("status") or "in_progress")
    phases = track_phases(scope)
    if len(phases) > 1 and status in {"in_progress", "completed"}:
        status = (
            "completed"
            if all(phase == "complete" for phase in phases.values())
            else "in_progress"
        )
    return {
        "key": key,
        "target": target,
        "status": status,
        "engagement_type": engagement_type,
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


def _engagements_signature() -> EngagementsSignature:
    root = engagements_root()
    root.mkdir(parents=True, exist_ok=True)

    signature: list[EngagementSignatureRow] = []
    for engagement_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if engagement_dir.name == _DELETED_ENGAGEMENTS_DIR:
            continue
        scope_path = engagement_dir / "scope.json"
        scope_mtime_ns = _safe_mtime_ns(scope_path)
        marker_mtime_ns = _safe_mtime_ns(_deleted_engagement_marker_path(engagement_dir.name))
        if scope_mtime_ns is None and marker_mtime_ns is None:
            continue
        sessions_root = engagement_dir / "sessions"
        assignment_signature = tuple(
            (
                session_dir.name,
                _safe_mtime_ns(session_dir / "assignment.json"),
            )
            for session_dir in sorted(path for path in sessions_root.iterdir() if path.is_dir())
        ) if sessions_root.exists() else tuple()
        signature.append(
            (
                engagement_dir.name,
                scope_mtime_ns,
                _safe_mtime_ns(engagement_dir / "engagement.json"),
                _safe_mtime_ns(engagement_dir / "sessions" / "index.json"),
                assignment_signature,
                marker_mtime_ns,
            )
        )
    return (str(root), tuple(signature))


def sync_engagements() -> None:
    root = engagements_root()
    root.mkdir(parents=True, exist_ok=True)

    discovered_keys: set[str] = set()
    for engagement_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        if engagement_dir.name == _DELETED_ENGAGEMENTS_DIR:
            continue
        if _deleted_engagement_marker_path(engagement_dir.name).exists():
            continue
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
                    engagement_type=manifest.get("engagement_type"),
                )
            else:
                db.update_engagement_identity(
                    engagement.id,
                    manifest["target"],
                    manifest["status"],
                    str(engagement_dir),
                    engagement_type=manifest.get("engagement_type"),
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
    global _last_sync_checked_at, _last_sync_signature

    now = time.monotonic()
    current_root = str(engagements_root())
    last_root = _last_sync_signature[0] if _last_sync_signature is not None else None
    if (
        not force
        and _last_sync_signature is not None
        and current_root == last_root
        and now - _last_sync_checked_at < _SYNC_SIGNATURE_TTL_SECONDS
    ):
        return

    with _sync_lock:
        now = time.monotonic()
        current_root = str(engagements_root())
        last_root = _last_sync_signature[0] if _last_sync_signature is not None else None
        if (
            not force
            and _last_sync_signature is not None
            and current_root == last_root
            and now - _last_sync_checked_at < _SYNC_SIGNATURE_TTL_SECONDS
        ):
            return
        signature = _engagements_signature()
        _last_sync_checked_at = now
        if not force and signature == _last_sync_signature:
            return
        sync_engagements()
        _last_sync_signature = signature
        clear_list_engagements_cache()


def _scope_details(
    engagement_root: Path,
) -> tuple[
    str,
    str | None,
    str,
    str,
    list[str],
    list[str],
    int,
    str | None,
    list[str],
    list[str],
    list[str],
    dict[str, str],
]:
    try:
        scope = _migrate_scope_file(engagement_root / "scope.json")
    except RuntimeError as exc:
        _logger.warning("Using persisted engagement identity for invalid scope at %s: %s", engagement_root, exc)
        return "unknown", None, "pause", "pending", [], [], 0, None, [], [], [], {}
    phases = track_phases(scope)
    current_phase = phases.get("web") or phases.get("code") or phases.get("blue") or phases.get("android") or phases.get("remediation") or "unknown"
    code_phase = phases.get("code") if "web" in phases else None
    exploit_policy = str(scope.get("exploit_policy") or "pause")
    exploit_review_state = str(scope.get("exploit_review_state") or "pending")
    approved_targets = scope.get("approved_targets")
    if not isinstance(approved_targets, list):
        approved_targets = []
    scope_hosts = _collect_scope_hosts(scope)
    raw_priority = scope.get("scope_priority", 0)
    try:
        scope_priority = int(raw_priority) if raw_priority is not None else 0
    except (TypeError, ValueError):
        scope_priority = 0
    raw_customer = scope.get("customer")
    customer = str(raw_customer) if isinstance(raw_customer, str) and raw_customer.strip() else None
    raw_platforms = scope.get("platforms")
    platforms = [str(item) for item in raw_platforms] if isinstance(raw_platforms, list) else []
    raw_tenant_refs = scope.get("tenant_reference_paths")
    tenant_reference_paths = [str(item) for item in raw_tenant_refs] if isinstance(raw_tenant_refs, list) else []
    out_of_scope = _collect_out_of_scope(scope)
    return (
        current_phase,
        code_phase,
        exploit_policy,
        exploit_review_state,
        [str(item) for item in approved_targets],
        scope_hosts,
        scope_priority,
        customer,
        platforms,
        tenant_reference_paths,
        out_of_scope,
        phases,
    )


def _collect_scope_hosts(scope: dict[str, Any]) -> list[str]:
    """Return the deduped, lowercased host-pattern list from scope.json.

    Mirrors the parsing that ``agent/scripts/proxy_addon.py`` does today so the
    backend is a faithful registry for the multi-engagement mitmproxy router.
    Reads from ``hosts`` / ``scope_hosts`` / ``scope`` lists plus a top-level
    ``hostname`` string.
    """
    raw: list[str] = []
    for key in ("hosts", "scope_hosts", "scope"):
        value = scope.get(key)
        if isinstance(value, list):
            raw.extend(value)
    hostname = scope.get("hostname")
    if isinstance(hostname, str) and hostname:
        raw.append(hostname)
    seen: set[str] = set()
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        normalized = item.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _capture_policy_details(engagement_root: Path) -> dict[str, Any]:
    """Return the per-engagement mitmproxy capture policy for the registry payload.

    Reads the ``capture-policy.json`` filesystem mirror that
    ``state_manager.set_capture_policy`` writes next to ``scope.json`` (the DB is
    the source of truth; the file is the durable mirror the proxy addon also
    falls back to). Reading the mirror here — rather than the DB — keeps the
    ``/engagements`` registry poll to a single DB connection (the proxy polls it
    frequently). Absent/invalid file → the default OFF policy.
    """
    # Local import mirrors coverage.py's deferred `from .. import engagements`
    # convention to keep the state_manager<->engagements relationship cycle-free.
    from .state_manager.http_flows import normalize_capture_policy

    raw = _json_file(engagement_root / "capture-policy.json")
    return normalize_capture_policy(raw if isinstance(raw, dict) else {})


def _collect_out_of_scope(scope: dict[str, Any]) -> list[str]:
    """Return the deduped, lowercased out-of-scope carve-out patterns.

    Mirrors ``_collect_scope_hosts`` so the backend is a faithful registry for
    the multi-engagement mitmproxy router's denylist. Reads only the dedicated
    ``out_of_scope`` list (a carve-out is never inferred from ``hosts``).
    """
    raw = scope.get("out_of_scope")
    if not isinstance(raw, list):
        return []
    seen: set[str] = set()
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        normalized = item.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _view_for(engagement: Engagement, *, session_count: int | None = None) -> EngagementView:
    (
        current_phase,
        code_phase,
        exploit_policy,
        exploit_review_state,
        approved_targets,
        scope_hosts,
        scope_priority,
        customer,
        platforms,
        tenant_reference_paths,
        out_of_scope,
        track_state,
    ) = _scope_details(Path(engagement.engagement_root))
    if engagement.engagement_type == "remediation":
        current_phase = "remediation"
        code_phase = None
        track_state.setdefault("remediation", "remediation")
    return EngagementView(
        id=engagement.id,
        key=engagement.key,
        target=engagement.target,
        status=engagement.status,
        engagement_root=engagement.engagement_root,
        current_phase=current_phase,
        code_phase=code_phase,
        track_phases=track_state,
        exploit_policy=exploit_policy,
        exploit_review_state=exploit_review_state,
        approved_targets=approved_targets,
        scope_hosts=scope_hosts,
        scope_priority=scope_priority,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        session_count=(
            session_count
            if session_count is not None
            else len(db.list_engagement_sessions_for_engagement(engagement.id))
        ),
        engagement_type=engagement.engagement_type,
        customer=customer,
        platforms=platforms,
        tenant_reference_paths=tenant_reference_paths,
        out_of_scope=out_of_scope,
        capture_policy=_capture_policy_details(Path(engagement.engagement_root)),
    )


def _list_cache_key(
    status_filter: str | None,
    engagement_type: str | None,
) -> ListCacheKey:
    return (str(settings.install_dir), status_filter, engagement_type, _last_sync_signature)


def _should_skip_registry_row(engagement: Engagement, *, status_filter: str | None) -> bool:
    if _deleted_engagement_marker_path(engagement.key).exists():
        return True
    if status_filter != "in_progress":
        return False
    return not (Path(engagement.engagement_root) / "scope.json").exists()


def _build_list_views(
    *,
    status_filter: str | None,
    engagement_type: str | None,
) -> tuple[EngagementView, ...]:
    return tuple(
        _view_for(engagement, session_count=session_count)
        for engagement, session_count in db.list_engagements_with_session_counts(
            status_filter=status_filter,
            engagement_type=engagement_type,
        )
        if not _should_skip_registry_row(engagement, status_filter=status_filter)
    )


def list_engagements(
    *,
    status_filter: str | None = None,
    engagement_type: str | None = None,
) -> list[EngagementView]:
    cache_key = _list_cache_key(status_filter, engagement_type)
    now = time.monotonic()
    cache_before_sync = status_filter == "in_progress"
    if cache_before_sync:
        with _list_cache_lock:
            cached = _list_cache.get(cache_key)
            if cached is not None and cached[0] > now:
                return list(cached[1])

    maybe_sync_engagements(force=not cache_before_sync)
    cache_key = _list_cache_key(status_filter, engagement_type)
    now = time.monotonic()
    with _list_cache_lock:
        cached = _list_cache.get(cache_key)
        if cached is not None and cached[0] > now:
            return list(cached[1])

    views = _build_list_views(status_filter=status_filter, engagement_type=engagement_type)
    if not views:
        maybe_sync_engagements(force=True)
        cache_key = _list_cache_key(status_filter, engagement_type)
        views = _build_list_views(status_filter=status_filter, engagement_type=engagement_type)

    with _list_cache_lock:
        cached = _list_cache.get(cache_key)
        if cached is not None and cached[0] > now:
            return list(cached[1])
        _list_cache.clear()
        _list_cache[cache_key] = (now + _LIST_CACHE_TTL_SECONDS, views)
        return list(views)


def clear_list_engagements_cache() -> None:
    with _list_cache_lock:
        _list_cache.clear()


def get_engagement_or_404(engagement_key: str) -> Engagement:
    maybe_sync_engagements()
    engagement = db.get_engagement_by_key(engagement_key)
    if engagement is None:
        maybe_sync_engagements(force=True)
        engagement = db.get_engagement_by_key(engagement_key)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")
    return engagement


def get_engagement_view_or_404(engagement_key: str) -> EngagementView:
    engagement = get_engagement_or_404(engagement_key)
    return _view_for(engagement)


def list_sessions_for_engagement(engagement_key: str) -> list[EngagementSession]:
    maybe_sync_engagements(force=True)
    engagement = get_engagement_or_404(engagement_key)
    return db.list_engagement_sessions_for_engagement(engagement.id)
