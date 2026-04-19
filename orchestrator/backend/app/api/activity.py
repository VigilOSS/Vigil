"""Per-engagement activity-log API.

Real bodies for the ``activity_entries`` side of plan §1d. ``events`` stays
the source of truth for structured state-change events; this router owns
the prose/narrative log that used to live in ``log.md``.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, status

from ..services import activity as activity_service
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster
from .intel_schemas import (
    ActivityEntryRecord,
    ActivityEntryRecordRequest,
    ListActivityEntriesResponse,
)


router = APIRouter(prefix="/engagements/{engagement_key}", tags=["activity"])


async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "activity.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


@router.get("/activity-entries", response_model=ListActivityEntriesResponse)
def list_activity_entries(
    engagement_key: str,
    q: str = Query(default="", max_length=1024),
    actor_kind: str = Query(default="", max_length=64),
    since: str = Query(default="", max_length=64),
    until: str = Query(default="", max_length=64),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> ListActivityEntriesResponse:
    engagement = get_engagement_or_404(engagement_key)
    result = activity_service.list_activity_entries(
        engagement.id,
        q=q,
        actor_kind=actor_kind,
        since=since or None,
        until=until or None,
        limit=limit,
        offset=offset,
    )
    return ListActivityEntriesResponse(
        total=result["total"],
        items=[ActivityEntryRecord(**item) for item in result["items"]],
    )


@router.post("/activity-entries", status_code=status.HTTP_201_CREATED)
async def create_activity_entry(
    engagement_key: str, request: ActivityEntryRecordRequest
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    record = activity_service.record_activity_entry(
        engagement.id,
        occurred_at=request.occurred_at,
        actor_kind=request.actor_kind,
        actor_name=request.actor_name,
        title=request.title,
        action=request.action,
        result=request.result,
        artifact_ref=request.artifact_ref,
        body_markdown=request.body_markdown,
        metadata=request.metadata,
    )
    await _broadcast(engagement.key, "activity_entry", record)
    return record
