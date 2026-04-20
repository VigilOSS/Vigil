from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from .. import db
from ..services.engagements import (
    EngagementView,
    get_engagement_or_404,
    get_engagement_view_or_404,
    list_engagements,
    list_sessions_for_engagement,
)

router = APIRouter(prefix="/engagements", tags=["engagements"])


class EngagementResponse(BaseModel):
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
    return EngagementResponse(
        id=engagement.id,
        key=engagement.key,
        target=engagement.target,
        status=engagement.status,
        engagement_root=engagement.engagement_root,
        current_phase=engagement.current_phase,
        exploit_policy=engagement.exploit_policy,
        exploit_review_state=engagement.exploit_review_state,
        approved_targets=engagement.approved_targets,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
        session_count=engagement.session_count,
    )


@router.get("", response_model=list[EngagementResponse])
def get_engagements() -> list[EngagementResponse]:
    return [_engagement_response(engagement) for engagement in list_engagements()]


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
