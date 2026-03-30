from __future__ import annotations

import json

from fastapi import APIRouter
from pydantic import BaseModel

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
    approved_findings: list[str]
    active: bool
    created_at: str
    updated_at: str
    session_count: int


class SessionResponse(BaseModel):
    id: int
    session_id: str
    session_path: str
    status: str
    merge_state: str
    assigned_findings: list[str]
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
        approved_findings=engagement.approved_findings,
        active=engagement.active,
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
            assigned_findings=json.loads(session.assigned_findings_json or "[]"),
            created_at=session.created_at,
            updated_at=session.updated_at,
            merged_at=session.merged_at,
        )
        for session in sessions
    ]
