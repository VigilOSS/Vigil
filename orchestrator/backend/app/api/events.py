from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from ..models.event import Event
from ..services.engagements import get_engagement_or_404
from ..services.events import create_event_for_engagement, list_events_for_engagement, summarize_events_for_engagement
from ..ws import broadcaster

router = APIRouter(prefix="/engagements/{engagement_key}/events", tags=["events"])


class CreateEventRequest(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    phase: str = Field(min_length=1, max_length=64)
    task_name: str = Field(min_length=1, max_length=128)
    agent_name: str = Field(min_length=1, max_length=128)
    summary: str = Field(min_length=1, max_length=512)


class EventResponse(BaseModel):
    id: int
    event_type: str
    phase: str
    task_name: str
    agent_name: str
    summary: str
    created_at: str


def _event_response(event: Event) -> EventResponse:
    return EventResponse(
        id=event.id,
        event_type=event.event_type,
        phase=event.phase,
        task_name=event.task_name,
        agent_name=event.agent_name,
        summary=event.summary,
        created_at=event.created_at,
    )


@router.post("", response_model=EventResponse, status_code=status.HTTP_201_CREATED)
async def create_event(engagement_key: str, request: CreateEventRequest) -> EventResponse:
    engagement = get_engagement_or_404(engagement_key)
    event = create_event_for_engagement(
        engagement.id,
        event_type=request.event_type,
        phase=request.phase,
        task_name=request.task_name,
        agent_name=request.agent_name,
        summary=request.summary,
    )
    response = _event_response(event)
    await broadcaster.publish(
        engagement.key,
        {
            "type": "event.created",
            "engagement_key": engagement.key,
            "event": response.model_dump(),
        },
    )
    return response


@router.get("", response_model=list[EventResponse])
def list_events(engagement_key: str) -> list[EventResponse]:
    engagement = get_engagement_or_404(engagement_key)
    return [_event_response(event) for event in list_events_for_engagement(engagement.id)]


@router.get("/summary")
def summarize_events(engagement_key: str) -> dict[str, dict[str, str] | None]:
    engagement = get_engagement_or_404(engagement_key)
    return summarize_events_for_engagement(engagement.id)
