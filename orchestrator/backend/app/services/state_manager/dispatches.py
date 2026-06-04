from __future__ import annotations

import json
from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404

from . import _common
from ._common import (
    DispatchStatus,
    TERMINAL_DISPATCH_STATUSES as _TERMINAL_DISPATCH_STATUSES,
    _require_canonical_finding_slugs,
)
from .findings import _ensure_finding_slugs_exist



def _require_terminal_dispatch_status(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized not in _TERMINAL_DISPATCH_STATUSES:
        allowed = ", ".join(sorted(_TERMINAL_DISPATCH_STATUSES))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"closed_dispatch_status must be terminal ({allowed})",
        )
    return normalized

def _serialize_dispatch(row) -> dict[str, Any]:
    data = dict(row)
    for col in ("finding_slugs_json",):
        raw = data.pop(col, None) or ""
        key = col[: -len("_json")]
        if raw:
            try:
                data[key] = json.loads(raw)
            except json.JSONDecodeError:
                data[key] = None
        else:
            data[key] = None
    return data

def record_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    agent_role: str,
    task: str | None = None,
    scope_host: str | None = None,
    dispatched_at: str | None = None,
    status_value: str = DispatchStatus.IN_PROGRESS,
    model: str | None = None,
    reasoning: str | None = None,
    requested_model: str | None = None,
    actual_model: str | None = None,
    requested_reasoning: str | None = None,
    actual_reasoning: str | None = None,
    dispatch_mode: str | None = None,
    finding_slugs: list[str] | None = None,
    skills: str | None = None,
    tier: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (agent_id or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id is required")
    dispatched_value = dispatched_at or _common._utcnow_iso_dispatch()
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    findings_json = json.dumps(list(finding_slugs)) if finding_slugs is not None else None
    skills_value = (skills or "").strip() or None
    tier_value = (tier or "").strip() or None
    requested_model_value = requested_model if requested_model is not None else model
    requested_reasoning_value = requested_reasoning if requested_reasoning is not None else reasoning
    with _common.get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        existing = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"dispatch with agent_id={agent_id!r} already exists for this engagement",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, task, scope_host,
                dispatched_at, status, model, reasoning,
                requested_model, actual_model, requested_reasoning, actual_reasoning,
                dispatch_mode, finding_slugs_json, skills, tier
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                agent_id,
                agent_role,
                task,
                scope_host,
                dispatched_value,
                status_value,
                requested_model_value,
                requested_reasoning_value,
                requested_model_value,
                actual_model,
                requested_reasoning_value,
                actual_reasoning,
                dispatch_mode,
                findings_json,
                skills_value,
                tier_value,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    return _serialize_dispatch(row)

def update_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    status_value: str | None = None,
    completed_at: str | None = None,
    finding_slugs: list[str] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    with _common.get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        existing = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
        sets: list[str] = []
        values: list[Any] = []
        if status_value is not None:
            sets.append("status = ?")
            values.append(status_value)
        if completed_at is not None:
            sets.append("completed_at = ?")
            values.append(completed_at)
        if finding_slugs is not None:
            sets.append("finding_slugs_json = ?")
            values.append(json.dumps(list(finding_slugs)))
        if not sets:
            return _serialize_dispatch(existing)
        values.extend([engagement.id, agent_id])
        connection.execute(
            f"UPDATE assessment_dispatches SET {', '.join(sets)} WHERE engagement_id = ? AND agent_id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    assert row is not None
    return _serialize_dispatch(row)

def get_dispatch(engagement_id: int, agent_id: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
    return _serialize_dispatch(row)

def list_dispatches(
    engagement_id: int,
    *,
    role: str = "",
    status_value: str = "",
    since: str = "",
    task_q: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("agent_role = ?")
        params.append(role)
    if status_value:
        where.append("status = ?")
        params.append(status_value)
    if since:
        where.append("dispatched_at >= ?")
        params.append(since)
    if task_q:
        where.append("task LIKE ?")
        params.append(f"%{task_q}%")
    params.append(int(limit))
    params.append(max(int(offset), 0))
    query = (
        f"SELECT * FROM assessment_dispatches WHERE {' AND '.join(where)} "
        "ORDER BY dispatched_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_dispatch(row) for row in rows]

def _serialize_handoff(row) -> dict[str, Any]:
    data = dict(row)
    for col in (
        "finding_slugs_json",
        "coverage_gaps_json",
        "next_steps_json",
        "runtime_issues_json",
        "working_artifacts_json",
        "open_questions_json",
        "extras_json",
    ):
        raw = data.pop(col, None) or ""
        key = col[: -len("_json")]
        if raw:
            try:
                data[key] = json.loads(raw)
            except json.JSONDecodeError:
                data[key] = None
        else:
            data[key] = None
    return data

_HANDOFF_SUMMARY_MAX = 2000

def _register_handoff_artifacts(engagement_id: int, handoff: dict[str, Any]) -> None:
    artifacts = handoff.get("working_artifacts") or []
    if not isinstance(artifacts, list):
        return
    raw_slugs = handoff.get("finding_slugs") or []
    finding_slugs: list[str] = (
        [str(slug) for slug in raw_slugs if str(slug)] if isinstance(raw_slugs, list) else []
    )
    # The artifact row carries one related_finding_slug. The primary slug
    # (first in the handoff list, by specialist convention) gets the column;
    # multi-finding handoffs still find their artifact via indexed_text /
    # path LIKE searches in search_artifacts, so the column is the
    # canonical-link anchor rather than the only path back.
    related_finding_slug = finding_slugs[0] if finding_slugs else None
    producer_agent_id = str(handoff.get("agent_id") or "") or None
    producer_agent_role = str(handoff.get("agent_role") or "") or None
    for item in artifacts:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        _common._register_artifact_reference(
            engagement_id,
            str(item.get("path") or ""),
            kind=str(item.get("kind") or "handoff-artifact"),
            producer_agent_id=producer_agent_id,
            producer_agent_role=producer_agent_role,
            related_finding_slug=related_finding_slug,
        )

def record_handoff(
    engagement_id: int,
    *,
    agent_id: str,
    agent_role: str,
    summary: str,
    phase: str | None = None,
    confidence: str | None = None,
    finding_slugs: list[str] | None = None,
    coverage_gaps: list[dict[str, Any]] | None = None,
    next_steps: list[dict[str, Any]] | None = None,
    runtime_issues: list[dict[str, Any]] | None = None,
    working_artifacts: list[dict[str, Any]] | None = None,
    open_questions: list[str] | None = None,
    recommended_next_agent: str | None = None,
    handoff_status: str = "checkpointed",
    closed_dispatch_status: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (agent_id or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id is required")
    if not (summary or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="summary is required")
    if len(summary) > _HANDOFF_SUMMARY_MAX:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"summary exceeds {_HANDOFF_SUMMARY_MAX} characters",
        )
    closed_dispatch_status = _require_terminal_dispatch_status(closed_dispatch_status)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    created_at = _common._utcnow_iso_dispatch()
    with _common.get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        dispatch_row = connection.execute(
            "SELECT agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if dispatch_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"dispatch not found for handoff agent_id={agent_id!r}",
            )
        if str(dispatch_row["agent_role"]) != str(agent_role):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"agent_role mismatch: handoff agent_role={agent_role!r} does not match registered "
                    f"dispatch role={dispatch_row['agent_role']!r}"
                ),
            )
        existing = connection.execute(
            "SELECT id FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"handoff with agent_id={agent_id!r} already exists; PATCH to update",
            )
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatch_handoffs (
                engagement_id, agent_id, agent_role, phase, summary, confidence,
                finding_slugs_json, coverage_gaps_json, next_steps_json,
                runtime_issues_json, working_artifacts_json, open_questions_json,
                recommended_next_agent, handoff_status, handoff_version, last_checkpoint_at,
                closed_dispatch_status, extras_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                agent_id,
                agent_role,
                phase,
                summary,
                confidence,
                json.dumps(list(finding_slugs)) if finding_slugs is not None else None,
                json.dumps(list(coverage_gaps)) if coverage_gaps is not None else None,
                json.dumps(list(next_steps)) if next_steps is not None else None,
                json.dumps(list(runtime_issues)) if runtime_issues is not None else None,
                json.dumps(list(working_artifacts)) if working_artifacts is not None else None,
                json.dumps(list(open_questions)) if open_questions is not None else None,
                recommended_next_agent,
                handoff_status,
                1,
                created_at,
                closed_dispatch_status,
                json.dumps(extras) if extras is not None else None,
                created_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    serialized = _serialize_handoff(row)
    _register_handoff_artifacts(engagement.id, serialized)
    return serialized

def update_handoff(
    engagement_id: int,
    *,
    agent_id: str,
    summary: str | None = None,
    phase: str | None = None,
    confidence: str | None = None,
    finding_slugs: list[str] | None = None,
    coverage_gaps: list[dict[str, Any]] | None = None,
    next_steps: list[dict[str, Any]] | None = None,
    runtime_issues: list[dict[str, Any]] | None = None,
    working_artifacts: list[dict[str, Any]] | None = None,
    open_questions: list[str] | None = None,
    recommended_next_agent: str | None = None,
    handoff_status: str | None = None,
    closed_dispatch_status: str | None = None,
    extras: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    closed_dispatch_status = _require_terminal_dispatch_status(closed_dispatch_status)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    with _common.get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        dispatch_row = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if dispatch_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"dispatch not found for handoff agent_id={agent_id!r}",
            )
        existing = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="handoff not found")
        sets: list[str] = []
        values: list[Any] = []
        if summary is not None:
            if not summary.strip():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="summary cannot be empty")
            if len(summary) > _HANDOFF_SUMMARY_MAX:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"summary exceeds {_HANDOFF_SUMMARY_MAX} characters",
                )
            sets.append("summary = ?")
            values.append(summary)
        if phase is not None:
            sets.append("phase = ?")
            values.append(phase)
        if confidence is not None:
            sets.append("confidence = ?")
            values.append(confidence)
        if finding_slugs is not None:
            sets.append("finding_slugs_json = ?")
            values.append(json.dumps(list(finding_slugs)))
        if coverage_gaps is not None:
            sets.append("coverage_gaps_json = ?")
            values.append(json.dumps(list(coverage_gaps)))
        if next_steps is not None:
            sets.append("next_steps_json = ?")
            values.append(json.dumps(list(next_steps)))
        if runtime_issues is not None:
            sets.append("runtime_issues_json = ?")
            values.append(json.dumps(list(runtime_issues)))
        if working_artifacts is not None:
            sets.append("working_artifacts_json = ?")
            values.append(json.dumps(list(working_artifacts)))
        if open_questions is not None:
            sets.append("open_questions_json = ?")
            values.append(json.dumps(list(open_questions)))
        if recommended_next_agent is not None:
            sets.append("recommended_next_agent = ?")
            values.append(recommended_next_agent)
        if handoff_status is not None:
            sets.append("handoff_status = ?")
            values.append(handoff_status)
        if closed_dispatch_status is not None:
            sets.append("closed_dispatch_status = ?")
            values.append(closed_dispatch_status)
        if extras is not None:
            sets.append("extras_json = ?")
            values.append(json.dumps(extras))
        if not sets:
            return _serialize_handoff(existing)
        sets.append("handoff_version = COALESCE(handoff_version, 1) + 1")
        sets.append("last_checkpoint_at = ?")
        values.append(_common._utcnow_iso_dispatch())
        values.extend([engagement.id, agent_id])
        connection.execute(
            f"UPDATE assessment_dispatch_handoffs SET {', '.join(sets)} WHERE engagement_id = ? AND agent_id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    assert row is not None
    serialized = _serialize_handoff(row)
    _register_handoff_artifacts(engagement.id, serialized)
    return serialized

def get_handoff(engagement_id: int, agent_id: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="handoff not found")
    return _serialize_handoff(row)

def list_handoffs(
    engagement_id: int,
    *,
    role: str = "",
    since: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("agent_role = ?")
        params.append(role)
    if since:
        where.append("created_at >= ?")
        params.append(since)
    params.append(int(limit))
    query = (
        f"SELECT * FROM assessment_dispatch_handoffs WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_handoff(row) for row in rows]

def _serialize_decision(row) -> dict[str, Any]:
    data = dict(row)
    raw = data.pop("payload_json", None) or "{}"
    try:
        data["payload"] = json.loads(raw)
    except json.JSONDecodeError:
        data["payload"] = None
    raw_resolution = data.pop("resolution_json", None) or ""
    if raw_resolution:
        try:
            data["resolution"] = json.loads(raw_resolution)
        except json.JSONDecodeError:
            data["resolution"] = None
    else:
        data["resolution"] = None
    if "surfaced_to_user" in data:
        data["surfaced_to_user"] = bool(data["surfaced_to_user"])
    if "resolved" in data:
        data["resolved"] = bool(data["resolved"])
    return data

def record_decision(
    engagement_id: int,
    *,
    kind: str,
    payload: dict[str, Any],
    surfaced_to_user: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (kind or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="kind is required")
    created_at = _common._utcnow_iso_dispatch()
    with _common.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatch_decisions (
                engagement_id, kind, payload_json, surfaced_to_user, resolved,
                resolution_json, created_at
            ) VALUES (?, ?, ?, ?, 0, NULL, ?)
            """,
            (
                engagement.id,
                kind,
                json.dumps(payload or {}),
                1 if surfaced_to_user else 0,
                created_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    return _serialize_decision(row)

def list_decisions(
    engagement_id: int,
    *,
    kind: str = "",
    resolved: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if kind:
        where.append("kind = ?")
        params.append(kind)
    if resolved is not None:
        where.append("resolved = ?")
        params.append(1 if resolved else 0)
    params.append(int(limit))
    params.append(int(offset))
    query = (
        f"SELECT * FROM assessment_dispatch_decisions WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_decision(row) for row in rows]

def update_decision(
    engagement_id: int,
    *,
    decision_id: int,
    resolved: bool | None = None,
    resolution: dict[str, Any] | None = None,
    surfaced_to_user: bool | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE engagement_id = ? AND id = ?",
            (engagement.id, decision_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="decision not found")
        sets: list[str] = []
        values: list[Any] = []
        if resolved is not None:
            sets.append("resolved = ?")
            values.append(1 if resolved else 0)
        if resolution is not None:
            sets.append("resolution_json = ?")
            values.append(json.dumps(resolution))
        if surfaced_to_user is not None:
            sets.append("surfaced_to_user = ?")
            values.append(1 if surfaced_to_user else 0)
        if not sets:
            return _serialize_decision(existing)
        values.extend([engagement.id, decision_id])
        connection.execute(
            f"UPDATE assessment_dispatch_decisions SET {', '.join(sets)} WHERE engagement_id = ? AND id = ?",
            tuple(values),
        )
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE engagement_id = ? AND id = ?",
            (engagement.id, decision_id),
        ).fetchone()
    assert row is not None
    return _serialize_decision(row)
