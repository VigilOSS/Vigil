"""Per-engagement activity-log API.

Real bodies for the ``activity_entries`` side of plan §1d. ``events`` stays
the source of truth for structured state-change events; this router owns
the prose/narrative log that used to live in ``log.md`` and ``/activity``,
the merged newest-first feed of both (``services/activity_feed.py``).
"""
from __future__ import annotations

import functools
from typing import Any, Literal

import anyio
from fastapi import APIRouter, Query, status
from pydantic import BaseModel

from ..services import activity as activity_service
from ..services import activity_feed
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster
from .intel_schemas import (
    ActivityEntryRecord,
    ActivityEntryRecordRequest,
    ListActivityEntriesResponse,
)


router = APIRouter(prefix="/engagements/{engagement_key}", tags=["activity"])


class ActivityFeedActor(BaseModel):
    name: str
    kind: Literal["operator", "agent", "system"]


class ActivityFeedEntity(BaseModel):
    type: str
    key: str
    label: str
    # The record the chip opens, by type: finding ``finding_slug``; run
    # ``run_id``; http_variant ``request_variant_id``; surface ``surface_id``;
    # intel ``intel_type`` + ``intel_id``; chain ``chain_key`` + the
    # ``finding_slug`` whose record shows it; code_file ``code_file_id``,
    # ``repo_id``, ``file_path`` and ``result_id`` (null when unknown); file
    # ``file_name`` (an engagement root document). Null with
    # ``unlinked_reason`` when no record can be opened.
    ref: dict[str, str | int | None] | None = None
    unlinked_reason: str = ""


class ActivityFeedDispatch(BaseModel):
    agent_id: str
    role: str
    run_id: int | None = None


class ActivityFeedItem(BaseModel):
    id: str
    source: Literal["audit", "event"]
    source_id: int
    cursor: str
    occurred_at: str
    actor: ActivityFeedActor
    category: str
    kind: str
    summary: str
    entities: list[ActivityFeedEntity]
    dispatch: ActivityFeedDispatch | None = None
    # Verbatim stored fields (ADR 0019) for the row's disclosure.
    detail: dict[str, Any]


class ActivityFeedCategory(BaseModel):
    key: str
    label: str
    count: int
    default: bool


class ActivityFeedResponse(BaseModel):
    items: list[ActivityFeedItem]
    has_more: bool
    total: int
    categories: list[ActivityFeedCategory]


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


@router.get("/activity", response_model=ActivityFeedResponse)
def list_activity_feed(
    engagement_key: str,
    category: list[str] = Query(default=[], description="Repeat or comma-separate; default hides tool calls."),
    actor: str = Query(default="", max_length=16),
    q: str = Query(default="", max_length=1024),
    since: str = Query(default="", max_length=64),
    until: str = Query(default="", max_length=64),
    before: str = Query(default="", max_length=128),
    after: str = Query(default="", max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
) -> ActivityFeedResponse:
    """Audit-log entries merged with structured events, newest first."""
    engagement = get_engagement_or_404(engagement_key)
    categories = [part.strip() for value in category for part in value.split(",") if part.strip()]
    return ActivityFeedResponse(
        **activity_feed.list_activity_feed(
            engagement.id,
            categories=categories or None,
            actor=actor,
            q=q,
            since=since or None,
            until=until or None,
            before=before or None,
            after=after or None,
            limit=limit,
        )
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
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            activity_service.record_activity_entry,
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
    )
    await _broadcast(engagement.key, "activity_entry", record)
    return record
