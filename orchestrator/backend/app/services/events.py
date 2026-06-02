from __future__ import annotations

from dataclasses import dataclass
from fastapi import HTTPException, status

from .. import db
from ..models.event import Event


_AGENT_PHASE = {
    "recon-specialist": "recon",
    "source-analyzer": "recon",
    "vulnerability-analyst": "consume-test",
    "exploit-developer": "exploit",
    "osint-analyst": "exploit",
    "report-writer": "report",
}


@dataclass(frozen=True, slots=True)
class _ActivitySignal:
    """Minimal activity_entries projection used for timeline synthesis.

    PhaseWaterfall and TaskTimeline in the frontend expect ``phase.started``,
    ``task.started``, and ``task.completed`` rows to infer phase progression.
    Pre-refactor those were synthesised from ``artifact.updated task_name=log.md``
    events emitted by the old ``assess.py log`` (which also appended to
    ``log.md``). Now that ``log.md`` is gone and ``vigil assess log`` POSTs to
    ``activity_entries`` without writing a parallel event row, we synthesise
    the same signals from activity rows here.
    """

    engagement_id: int
    actor_name: str
    title: str
    occurred_at: str


def _engagement_or_404(engagement_id: int):
    engagement = db.get_engagement_by_id(engagement_id)
    if engagement is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")
    return engagement


def create_event_for_engagement(
    engagement_id: int,
    *,
    event_type: str,
    phase: str,
    task_name: str,
    agent_name: str,
    summary: str,
) -> Event:
    engagement = _engagement_or_404(engagement_id)
    return db.create_event(engagement.id, event_type, phase, task_name, agent_name, summary)


def _phase_for_actor(actor_name: str, title: str = "") -> str:
    if actor_name in _AGENT_PHASE:
        return _AGENT_PHASE[actor_name]
    if actor_name == "operator" and title == "Engagement start":
        return "recon"
    return "unknown"


def _load_activity_signals(engagement_id: int) -> list[_ActivitySignal]:
    """Fetch the fields from ``activity_entries`` we need for synthesis.

    Kept inline here rather than routed through ``services.activity`` so the
    timeline projection does not pay the cost of the FTS join / metadata
    deserialization that the API-shaped list helper does.
    """
    with db.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT engagement_id, actor_name, title, occurred_at
            FROM activity_entries
            WHERE engagement_id = ?
            ORDER BY occurred_at ASC, id ASC
            """,
            (engagement_id,),
        ).fetchall()
    return [
        _ActivitySignal(
            engagement_id=row["engagement_id"],
            actor_name=row["actor_name"] or "",
            title=row["title"] or "",
            occurred_at=row["occurred_at"] or "",
        )
        for row in rows
    ]


def _legacy_activity_signals(events: list[Event]) -> list[_ActivitySignal]:
    return [
        _ActivitySignal(
            engagement_id=event.engagement_id,
            actor_name=event.agent_name or "",
            title=event.summary or "",
            occurred_at=event.created_at or "",
        )
        for event in events
        if event.event_type == "artifact.updated" and event.task_name == "log.md"
    ]


def _project_timeline_events(
    events: list[Event], activity: list[_ActivitySignal]
) -> list[Event]:
    projected: list[Event] = []
    next_id = -1
    seen_phase_started: set[str] = {
        event.phase for event in events if event.event_type == "phase.started" and event.phase != "unknown"
    }

    for signal in activity:
        phase = _phase_for_actor(signal.actor_name, signal.title)
        if phase != "unknown" and phase not in seen_phase_started:
            projected.append(
                Event(
                    id=next_id,
                    engagement_id=signal.engagement_id,
                    event_type="phase.started",
                    phase=phase,
                    task_name=phase,
                    agent_name="operator",
                    summary=f"{phase} phase started",
                    created_at=signal.occurred_at,
                )
            )
            next_id -= 1
            seen_phase_started.add(phase)

        if signal.actor_name == "operator":
            continue

        normalized = signal.title.lower()
        if normalized.endswith(" start"):
            projected.append(
                Event(
                    id=next_id,
                    engagement_id=signal.engagement_id,
                    event_type="task.started",
                    phase=phase,
                    task_name=signal.actor_name,
                    agent_name=signal.actor_name,
                    summary=signal.title,
                    created_at=signal.occurred_at,
                )
            )
            next_id -= 1
        elif normalized.endswith(" summary") or normalized.endswith(" complete"):
            projected.append(
                Event(
                    id=next_id,
                    engagement_id=signal.engagement_id,
                    event_type="task.completed",
                    phase=phase,
                    task_name=signal.actor_name,
                    agent_name=signal.actor_name,
                    summary=signal.title,
                    created_at=signal.occurred_at,
                )
            )
            next_id -= 1

    return sorted([*events, *projected], key=lambda item: (item.created_at, item.id))


def list_events_for_engagement(engagement_id: int) -> list[Event]:
    engagement = _engagement_or_404(engagement_id)
    events = db.list_events_for_engagement(engagement.id)
    activity = _load_activity_signals(engagement.id)
    if not activity:
        activity = _legacy_activity_signals(events)
    return _project_timeline_events(events, activity)


def summarize_events_for_engagement(engagement_id: int) -> dict[str, dict[str, str] | None]:
    events = list_events_for_engagement(engagement_id)
    latest_phase = next((event for event in reversed(events) if event.event_type.startswith("phase.")), None)
    latest_task = next((event for event in reversed(events) if event.event_type.startswith("task.")), None)

    return {
        "latest_phase": (
            {
                "phase": latest_phase.phase,
                "event_type": latest_phase.event_type,
                "summary": latest_phase.summary,
            }
            if latest_phase
            else None
        ),
        "latest_task": (
            {
                "phase": latest_task.phase,
                "task_name": latest_task.task_name,
                "event_type": latest_task.event_type,
                "summary": latest_task.summary,
            }
            if latest_task
            else None
        ),
    }
