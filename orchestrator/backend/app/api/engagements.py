from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from .. import db
from ..services.engagements import (
    EngagementView,
    get_engagement_or_404,
    get_engagement_view_or_404,
    list_engagements,
    list_sessions_for_engagement,
    mark_engagement_deleted,
)

router = APIRouter(prefix="/engagements", tags=["engagements"])


class EngagementResponse(BaseModel):
    id: int
    key: str
    target: str
    status: str
    engagement_root: str
    current_phase: str
    code_phase: str | None = None
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
    platforms: list[str] = Field(default_factory=list)
    tenant_reference_paths: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    track_state: dict[str, dict[str, str | bool | None]] = Field(default_factory=dict)
    aggregate_complete: bool = False
    # Per-engagement mitmproxy capture policy (backend-owned durable state). The
    # shared proxy addon reads this off the registry payload so restarting it
    # never silently changes capture behavior; a capture-policy.json filesystem
    # mirror next to scope.json is the offline fallback.
    capture_policy: dict = Field(default_factory=dict)


class SessionResponse(BaseModel):
    id: int
    session_id: str
    session_path: str
    status: str
    merge_state: str
    assigned_targets: list[str]
    created_at: str
    updated_at: str
    merged_at: str | None


def _engagement_response(engagement: EngagementView) -> EngagementResponse:
    engagement_type = (engagement.engagement_type or "web").strip().lower()
    if engagement_type == "both":
        track_state = {
            "web": {
                "phase": engagement.current_phase,
                "complete": engagement.current_phase == "complete",
            },
            "code": {
                "phase": engagement.code_phase,
                "complete": engagement.code_phase == "complete",
            },
        }
    else:
        track = engagement_type if engagement_type in {"code", "blue", "android"} else "web"
        track_state = {
            track: {
                "phase": engagement.current_phase,
                "complete": engagement.current_phase == "complete",
            }
        }
    return EngagementResponse(
        id=engagement.id,
        key=engagement.key,
        target=engagement.target,
        status=engagement.status,
        engagement_root=engagement.engagement_root,
        current_phase=engagement.current_phase,
        code_phase=engagement.code_phase,
        exploit_policy=engagement.exploit_policy,
        exploit_review_state=engagement.exploit_review_state,
        approved_targets=engagement.approved_targets,
        scope_hosts=engagement.scope_hosts,
        scope_priority=engagement.scope_priority,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        session_count=engagement.session_count,
        engagement_type=engagement.engagement_type,
        customer=engagement.customer,
        platforms=list(engagement.platforms or []),
        tenant_reference_paths=list(engagement.tenant_reference_paths or []),
        out_of_scope=list(engagement.out_of_scope or []),
        track_state=track_state,
        aggregate_complete=all(
            bool(state["complete"]) for state in track_state.values()
        ),
        capture_policy=dict(engagement.capture_policy or {}),
    )


@router.get("", response_model=list[EngagementResponse])
def get_engagements(
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by engagement status (e.g. in_progress).",
    ),
    engagement_type: str | None = Query(
        default=None,
        description="Filter by engagement_type (case-sensitive, e.g. 'red' | 'blue' | 'web' | 'code').",
    ),
    customer: str | None = Query(
        default=None,
        description="Filter blue engagements by customer slug.",
    ),
    platform: str | None = Query(
        default=None,
        description="Filter blue engagements by platform tag.",
    ),
) -> list[EngagementResponse]:
    engagements = list_engagements(status_filter=status_filter, engagement_type=engagement_type)
    if customer:
        engagements = [
            engagement
            for engagement in engagements
            if engagement.customer == customer
        ]
    if platform:
        engagements = [
            engagement
            for engagement in engagements
            if platform in (engagement.platforms or [])
        ]
    return [_engagement_response(engagement) for engagement in engagements]


@router.get("/{engagement_key}", response_model=EngagementResponse)
def get_engagement(engagement_key: str) -> EngagementResponse:
    return _engagement_response(get_engagement_view_or_404(engagement_key))


class DeleteEngagementResponse(BaseModel):
    deleted: bool
    key: str
    id: int


@router.delete("/{engagement_key}", response_model=DeleteEngagementResponse)
def delete_engagement(engagement_key: str, confirm: str = "") -> DeleteEngagementResponse:
    """Explicitly delete an engagement and ALL its cascaded rows (findings,
    probe runs, command runs, code analysis, credentials). Requires
    ``?confirm=<engagement_key>`` so a mistyped or injected key cannot trigger
    deletion by accident — the caller must prove they know the key they are
    about to destroy.
    """
    engagement = get_engagement_or_404(engagement_key)
    if confirm != engagement_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "delete requires `?confirm=<engagement_key>` matching the path key; "
                "this prevents accidental cascade-delete of findings, probes, and "
                "command-run history"
            ),
        )
    mark_engagement_deleted(engagement)
    db.delete_engagement(engagement.id)
    return DeleteEngagementResponse(deleted=True, key=engagement.key, id=engagement.id)


@router.get("/{engagement_key}/sessions", response_model=list[SessionResponse])
def get_sessions(engagement_key: str) -> list[SessionResponse]:
    get_engagement_or_404(engagement_key)
    sessions = list_sessions_for_engagement(engagement_key)
    return [
        SessionResponse(
            id=session.id,
            session_id=session.session_id,
            session_path=session.session_path,
            status=session.status,
            merge_state=session.merge_state,
            assigned_targets=json.loads(session.assigned_targets_json or "[]"),
            created_at=session.created_at,
            updated_at=session.updated_at,
            merged_at=session.merged_at,
        )
        for session in sessions
    ]
