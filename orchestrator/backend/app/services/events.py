from __future__ import annotations

from dataclasses import dataclass
from sqlite3 import Connection
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


def _has_activity_signals(connection: Connection, engagement_id: int) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM activity_entries
        WHERE engagement_id = ?
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    return row is not None


def _phase_started_phases(connection: Connection, engagement_id: int) -> set[str]:
    rows = connection.execute(
        """
        SELECT DISTINCT phase
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'phase.started'
          AND phase != 'unknown'
        """,
        (engagement_id,),
    ).fetchall()
    return {str(row["phase"]) for row in rows if row["phase"]}


def _activity_signal_from_row(row) -> _ActivitySignal:
    return _ActivitySignal(
        engagement_id=row["engagement_id"],
        actor_name=row["actor_name"] or "",
        title=row["title"] or "",
        occurred_at=row["occurred_at"] or "",
    )


def _event_signal_from_row(row) -> _ActivitySignal:
    return _ActivitySignal(
        engagement_id=row["engagement_id"],
        actor_name=row["agent_name"] or "",
        title=row["summary"] or "",
        occurred_at=row["created_at"] or "",
    )


def _latest_activity_task_signal(
    connection: Connection, engagement_id: int
) -> _ActivitySignal | None:
    row = connection.execute(
        """
        SELECT engagement_id, actor_name, title, occurred_at
        FROM activity_entries
        WHERE engagement_id = ?
          AND actor_name != 'operator'
          AND (
            lower(title) LIKE '% start'
            OR lower(title) LIKE '% summary'
            OR lower(title) LIKE '% complete'
          )
        ORDER BY occurred_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    return _activity_signal_from_row(row) if row else None


def _latest_legacy_task_signal(
    connection: Connection, engagement_id: int
) -> _ActivitySignal | None:
    row = connection.execute(
        """
        SELECT engagement_id, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'artifact.updated'
          AND task_name = 'log.md'
          AND agent_name != 'operator'
          AND (
            lower(summary) LIKE '% start'
            OR lower(summary) LIKE '% summary'
            OR lower(summary) LIKE '% complete'
          )
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    return _event_signal_from_row(row) if row else None


def _first_activity_phase_signal(
    connection: Connection, engagement_id: int, phase: str, actor_names: tuple[str, ...]
) -> _ActivitySignal | None:
    params: list[str | int] = [engagement_id, *actor_names]
    actor_clause = ", ".join("?" for _ in actor_names)
    conditions = [f"actor_name IN ({actor_clause})"] if actor_names else []
    if phase == "recon":
        conditions.append("(actor_name = 'operator' AND title = 'Engagement start')")
    if not conditions:
        return None
    row = connection.execute(
        f"""
        SELECT engagement_id, actor_name, title, occurred_at
        FROM activity_entries
        WHERE engagement_id = ?
          AND ({' OR '.join(conditions)})
        ORDER BY occurred_at ASC, id ASC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()
    return _activity_signal_from_row(row) if row else None


def _first_legacy_phase_signal(
    connection: Connection, engagement_id: int, phase: str, actor_names: tuple[str, ...]
) -> _ActivitySignal | None:
    params: list[str | int] = [engagement_id, *actor_names]
    actor_clause = ", ".join("?" for _ in actor_names)
    conditions = [f"agent_name IN ({actor_clause})"] if actor_names else []
    if phase == "recon":
        conditions.append("(agent_name = 'operator' AND summary = 'Engagement start')")
    if not conditions:
        return None
    row = connection.execute(
        f"""
        SELECT engagement_id, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'artifact.updated'
          AND task_name = 'log.md'
          AND ({' OR '.join(conditions)})
        ORDER BY created_at ASC, id ASC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()
    return _event_signal_from_row(row) if row else None


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


def _task_event_from_signal(signal: _ActivitySignal | None) -> Event | None:
    if signal is None or signal.actor_name == "operator":
        return None
    normalized = signal.title.lower()
    if normalized.endswith("start"):
        event_type = "task.started"
    elif normalized.endswith("summary") or normalized.endswith("complete"):
        event_type = "task.completed"
    else:
        return None
    phase = _phase_for_actor(signal.actor_name, signal.title)
    return Event(
        id=-1,
        engagement_id=signal.engagement_id,
        event_type=event_type,
        phase=phase,
        task_name=signal.actor_name,
        agent_name=signal.actor_name,
        summary=signal.title,
        created_at=signal.occurred_at,
    )


def _phase_event_from_signal(signal: _ActivitySignal | None, phase: str) -> Event | None:
    if signal is None:
        return None
    return Event(
        id=-1,
        engagement_id=signal.engagement_id,
        event_type="phase.started",
        phase=phase,
        task_name=phase,
        agent_name="operator",
        summary=f"{phase} phase started",
        created_at=signal.occurred_at,
    )


def _phase_actor_groups() -> dict[str, tuple[str, ...]]:
    groups: dict[str, list[str]] = {}
    for actor_name, phase in _AGENT_PHASE.items():
        groups.setdefault(phase, []).append(actor_name)
    return {phase: tuple(actor_names) for phase, actor_names in groups.items()}


def _projected_phase_candidates(
    connection: Connection, engagement_id: int, *, use_activity: bool
) -> list[Event]:
    started_phases = _phase_started_phases(connection, engagement_id)
    candidates: list[Event] = []
    for phase, actor_names in _phase_actor_groups().items():
        if phase in started_phases:
            continue
        signal = (
            _first_activity_phase_signal(connection, engagement_id, phase, actor_names)
            if use_activity
            else _first_legacy_phase_signal(connection, engagement_id, phase, actor_names)
        )
        event = _phase_event_from_signal(signal, phase)
        if event is not None:
            candidates.append(event)
    return candidates


def _latest_event(candidates: list[Event | None]) -> Event | None:
    return max(
        (event for event in candidates if event is not None),
        key=lambda event: (event.created_at, event.id),
        default=None,
    )


def _latest_persisted_event(
    connection: Connection, engagement_id: int, prefix: str
) -> Event | None:
    row = connection.execute(
        """
        SELECT id, engagement_id, event_type, phase, task_name, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ? AND event_type LIKE ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (engagement_id, f"{prefix}%"),
    ).fetchone()
    return Event.from_row(row) if row else None


def list_events_for_engagement(engagement_id: int) -> list[Event]:
    engagement = _engagement_or_404(engagement_id)
    events = db.list_events_for_engagement(engagement.id)
    activity = _load_activity_signals(engagement.id)
    if not activity:
        activity = _legacy_activity_signals(events)
    return _project_timeline_events(events, activity)


def summarize_events_for_engagement(engagement_id: int) -> dict[str, dict[str, str] | None]:
    engagement = _engagement_or_404(engagement_id)
    with db.get_connection() as connection:
        use_activity = _has_activity_signals(connection, engagement.id)
        latest_projected_task = _task_event_from_signal(
            _latest_activity_task_signal(connection, engagement.id)
            if use_activity
            else _latest_legacy_task_signal(connection, engagement.id)
        )
        latest_phase = _latest_event(
            [
                _latest_persisted_event(connection, engagement.id, "phase."),
                *_projected_phase_candidates(
                    connection, engagement.id, use_activity=use_activity
                ),
            ]
        )
        latest_task = _latest_event(
            [
                _latest_persisted_event(connection, engagement.id, "task."),
                latest_projected_task,
            ]
        )

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
