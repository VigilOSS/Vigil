from __future__ import annotations

from dataclasses import dataclass, replace
from sqlite3 import Connection
from fastapi import HTTPException, status

from .. import db
from ..models.event import Event
from .timestamps import iso_utc, parse_utc


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

    The ``/events`` timeline (Overview "Latest activity") and its summary
    expect ``phase.started``, ``task.started``, and ``task.completed`` rows to
    infer phase progression.
    Pre-refactor those were synthesised from ``artifact.updated task_name=log.md``
    events emitted by the old ``assess.py log`` (which also appended to
    ``log.md``). Now that ``log.md`` is gone and ``vigil assess log`` POSTs to
    ``activity_entries`` without writing a parallel event row, we synthesise
    the same signals from activity rows here.
    """

    source_id: int
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


_TASK_TITLE_SQL = (
    "(lower({column}) LIKE '% start' OR lower({column}) LIKE '% summary' "
    "OR lower({column}) LIKE '% complete')"
)


def _limit_sql(limit: int | None) -> tuple[str, tuple[int, ...]]:
    return ("LIMIT ?", (int(limit),)) if limit is not None else ("", ())


def _load_activity_signals(engagement_id: int, *, limit: int | None = None) -> list[_ActivitySignal]:
    """Fetch the newest activity rows that project to ``task.*`` timeline rows.

    Kept inline here rather than routed through ``services.activity`` so the
    timeline projection does not pay the cost of the FTS join / metadata
    deserialization that the API-shaped list helper does. Ordering is by
    instant (``julianday``) because stored spellings mix SQLite and ISO-8601.
    """
    limit_sql, limit_params = _limit_sql(limit)
    with db.get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT id, engagement_id, actor_name, title, occurred_at
            FROM activity_entries
            WHERE engagement_id = ?
              AND actor_name != 'operator'
              AND {_TASK_TITLE_SQL.format(column="title")}
            ORDER BY julianday(occurred_at) DESC, id DESC
            {limit_sql}
            """,
            (engagement_id, *limit_params),
        ).fetchall()
    return [_activity_signal_from_row(row) for row in rows]


def _load_legacy_task_signals(
    connection: Connection, engagement_id: int, *, limit: int | None
) -> list[_ActivitySignal]:
    """Pre-``activity_entries`` engagements narrated through ``log.md`` events."""
    limit_sql, limit_params = _limit_sql(limit)
    rows = connection.execute(
        f"""
        SELECT id, engagement_id, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'artifact.updated'
          AND task_name = 'log.md'
          AND agent_name != 'operator'
          AND {_TASK_TITLE_SQL.format(column="summary")}
        ORDER BY julianday(created_at) DESC, id DESC
        {limit_sql}
        """,
        (engagement_id, *limit_params),
    ).fetchall()
    return [_event_signal_from_row(row) for row in rows]


def _load_stored_events(
    connection: Connection, engagement_id: int, *, limit: int | None
) -> list[Event]:
    limit_sql, limit_params = _limit_sql(limit)
    rows = connection.execute(
        f"""
        SELECT id, engagement_id, event_type, phase, task_name, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
        ORDER BY julianday(created_at) DESC, id DESC
        {limit_sql}
        """,
        (engagement_id, *limit_params),
    ).fetchall()
    return [Event.from_row(row) for row in rows]


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
        source_id=row["id"],
        engagement_id=row["engagement_id"],
        actor_name=row["actor_name"] or "",
        title=row["title"] or "",
        occurred_at=row["occurred_at"] or "",
    )


def _event_signal_from_row(row) -> _ActivitySignal:
    return _ActivitySignal(
        source_id=row["id"],
        engagement_id=row["engagement_id"],
        actor_name=row["agent_name"] or "",
        title=row["summary"] or "",
        occurred_at=row["created_at"] or "",
    )


def _latest_activity_task_signal(
    connection: Connection, engagement_id: int
) -> _ActivitySignal | None:
    row = connection.execute(
        f"""
        SELECT id, engagement_id, actor_name, title, occurred_at
        FROM activity_entries
        WHERE engagement_id = ?
          AND actor_name != 'operator'
          AND {_TASK_TITLE_SQL.format(column="title")}
        ORDER BY julianday(occurred_at) DESC, id DESC
        LIMIT 1
        """,
        (engagement_id,),
    ).fetchone()
    return _activity_signal_from_row(row) if row else None


def _latest_legacy_task_signal(
    connection: Connection, engagement_id: int
) -> _ActivitySignal | None:
    row = connection.execute(
        f"""
        SELECT id, engagement_id, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'artifact.updated'
          AND task_name = 'log.md'
          AND agent_name != 'operator'
          AND {_TASK_TITLE_SQL.format(column="summary")}
        ORDER BY julianday(created_at) DESC, id DESC
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
        SELECT id, engagement_id, actor_name, title, occurred_at
        FROM activity_entries
        WHERE engagement_id = ?
          AND ({' OR '.join(conditions)})
        ORDER BY julianday(occurred_at) ASC, id ASC
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
        SELECT id, engagement_id, agent_name, summary, created_at
        FROM events
        WHERE engagement_id = ?
          AND event_type = 'artifact.updated'
          AND task_name = 'log.md'
          AND ({' OR '.join(conditions)})
        ORDER BY julianday(created_at) ASC, id ASC
        LIMIT 1
        """,
        tuple(params),
    ).fetchone()
    return _event_signal_from_row(row) if row else None


def _projected_task_event(signal: _ActivitySignal) -> Event | None:
    normalized = signal.title.lower()
    if normalized.endswith(" start"):
        event_type = "task.started"
    elif normalized.endswith(" summary") or normalized.endswith(" complete"):
        event_type = "task.completed"
    else:
        return None
    return Event(
        id=_inferred_id(signal, "task"),
        engagement_id=signal.engagement_id,
        event_type=event_type,
        phase=_phase_for_actor(signal.actor_name, signal.title),
        task_name=signal.actor_name,
        agent_name=signal.actor_name,
        summary=signal.title,
        created_at=signal.occurred_at,
    )


def _inferred_id(signal: _ActivitySignal, kind: str) -> int:
    """Stable negative id for a projected row, whatever window is read.

    Each source row can yield one task row and one phase row; negative ids
    keep them distinct from stored events.
    """
    return -(2 * signal.source_id + (1 if kind == "phase" else 0))


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
        id=_inferred_id(signal, "task"),
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
        id=_inferred_id(signal, "phase"),
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


def _instant_key(event: Event) -> tuple[float, int]:
    parsed = parse_utc(str(event.created_at or "").strip())
    return (parsed.timestamp() if parsed is not None else float("-inf"), event.id)


def _latest_event(candidates: list[Event | None]) -> Event | None:
    return max(
        (event for event in candidates if event is not None),
        key=_instant_key,
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
        ORDER BY julianday(created_at) DESC, id DESC
        LIMIT 1
        """,
        (engagement_id, f"{prefix}%"),
    ).fetchone()
    return Event.from_row(row) if row else None


def list_events_for_engagement(engagement_id: int, *, limit: int | None = None) -> list[Event]:
    """Structured timeline, oldest first, optionally only the newest ``limit``.

    Stored events are joined by ``phase.started`` / ``task.*`` rows inferred
    from activity (or legacy ``log.md``) signals. Each source is bounded in
    SQL by the same ``limit`` before the merge, so a window never reads the
    whole history; timestamps come back as ISO-8601 UTC.
    """
    engagement = _engagement_or_404(engagement_id)
    with db.get_connection() as connection:
        stored = _load_stored_events(connection, engagement.id, limit=limit)
        use_activity = _has_activity_signals(connection, engagement.id)
        phases = _projected_phase_candidates(connection, engagement.id, use_activity=use_activity)
        signals = (
            None
            if use_activity
            else _load_legacy_task_signals(connection, engagement.id, limit=limit)
        )
    if signals is None:
        signals = _load_activity_signals(engagement.id, limit=limit)
    tasks = [event for event in map(_projected_task_event, signals) if event is not None]
    timeline = sorted([*stored, *phases, *tasks], key=_instant_key)
    if limit is not None:
        timeline = timeline[-limit:]
    return [replace(event, created_at=iso_utc(event.created_at)) for event in timeline]


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
