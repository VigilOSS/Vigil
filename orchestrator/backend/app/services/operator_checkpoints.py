"""The operator's own durable checkpoint — references only, one intent note.

Every dispatched specialist writes an ``assessment_dispatch_handoffs`` row. The
operator wrote nothing for itself, so its state died with the session. This
service owns the missing row, and its governing constraint is truth-safety: the
record must be structurally incapable of carrying a NEW factual claim about the
target.

Two mechanisms enforce that, and neither is advisory:

1. Every caller-supplied field except ``intent_note`` is a REFERENCE to a row
   the backend already holds, and each reference is existence-checked inside the write
   transaction. A checkpoint pointing at a finding, dispatch, command run, or
   artifact that does not exist is itself a false claim, so the write is
   refused (400) naming the unknown ids rather than stored.
2. Both track phases (``current_phase`` and, where the engagement has a code
   track, ``code_phase``) are read from engagement state at write time;
   ``source`` and ``client_name`` are server-owned constants for new rows. The
   request model deliberately has no such fields, so a caller cannot assert
   them.

``intent_note`` is the single free-text block. It is "what I was about to do and
why" — unverified operator intent — and every renderer labels it as such. There
is deliberately no second free-text field (no ``supersede_reason``): the
correcting row's own ``intent_note`` carries the correction narrative.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from fastapi import HTTPException, status

from ..db import get_connection
from . import engagements as engagement_service
from .events import _engagement_or_404
from .state_manager._common import is_canonical_finding_slug


# Validation bounds, not redaction: over-long input is REFUSED with a clear
# error (see the API model), never silently truncated or dropped.
MAX_INTENT_NOTE_CHARS = 8000
MAX_REFERENCES = 200


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _json_list(raw: Any) -> list[Any]:
    try:
        decoded = json.loads(str(raw or "[]"))
    except json.JSONDecodeError:
        return []
    return decoded if isinstance(decoded, list) else []


def _serialize(row) -> dict[str, Any]:
    successor_version = (
        row["superseded_by_checkpoint_version"]
        if "superseded_by_checkpoint_version" in row.keys()
        else None
    )
    return {
        "id": int(row["id"]),
        "checkpoint_version": int(row["checkpoint_version"]),
        "superseded_by_id": (
            int(row["superseded_by_id"]) if row["superseded_by_id"] is not None else None
        ),
        "superseded_by_checkpoint_version": (
            int(successor_version) if successor_version is not None else None
        ),
        "current_phase": str(row["current_phase"]),
        "code_phase": (
            str(row["code_phase"]) if row["code_phase"] is not None else None
        ),
        "finding_slugs": _json_list(row["finding_slugs_json"]),
        "dispatch_agent_ids": _json_list(row["dispatch_agent_ids_json"]),
        "command_run_ids": _json_list(row["command_run_ids_json"]),
        "artifact_ids": _json_list(row["artifact_ids_json"]),
        "intent_note": str(row["intent_note"]),
        "source": str(row["source"]),
        "client_name": str(row["client_name"]),
        "created_at": str(row["created_at"]),
    }


def _dedupe(values: Iterable[Any]) -> list[Any]:
    """Preserve caller order while dropping exact repeats.

    A repeated reference is not new information, and collapsing it keeps the
    stored list a faithful set of pointers rather than a frequency table.
    """
    seen: set[Any] = set()
    ordered: list[Any] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _unknown_findings(connection, engagement_id: int, slugs: list[str]) -> list[str]:
    unknown: list[str] = []
    for slug in slugs:
        if not is_canonical_finding_slug(slug):
            unknown.append(slug)
            continue
        row = connection.execute(
            "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, slug),
        ).fetchone()
        if row is None:
            unknown.append(slug)
    return unknown


def _unknown_rows(
    connection,
    engagement_id: int,
    values: list[Any],
    *,
    table: str,
    column: str,
) -> list[Any]:
    unknown: list[Any] = []
    for value in values:
        row = connection.execute(
            f"SELECT 1 FROM {table} WHERE engagement_id = ? AND {column} = ?",
            (engagement_id, value),
        ).fetchone()
        if row is None:
            unknown.append(value)
    return unknown


def _track_phases(engagement) -> tuple[str, str | None]:
    """Read BOTH track phases from the canonical engagement view.

    ``get_engagement_view_or_404`` is the same reader the dashboard and resume
    brief resolve phases through, so a checkpoint can never disagree with the
    phase the rest of the backend reports.

    A dual-track engagement advances the web track (``current_phase``) and the
    code track (``code_phase``) independently, so recording only the first
    reports the position of a track the operator may not have been working —
    the checkpoint exists to carry that position across a context boundary, so
    naming the wrong one is worse than naming none. ``code_phase`` is ``None``
    for every engagement without a code track, web and code-only alike: a
    code-only engagement keeps its code-track phase in ``current_phase``, so it
    has one phase to record, not two.
    """

    view = engagement_service.get_engagement_view_or_404(engagement.key)
    return view.current_phase, view.code_phase


def record_checkpoint(
    engagement_id: int,
    *,
    intent_note: str,
    finding_slugs: list[str],
    dispatch_agent_ids: list[str],
    command_run_ids: list[int],
    artifact_ids: list[int],
) -> dict[str, Any]:
    """Append checkpoint N+1 and stamp the previous current row as superseded."""

    engagement = _engagement_or_404(engagement_id)
    phase, code_phase = _track_phases(engagement)
    findings = _dedupe(str(slug).strip() for slug in finding_slugs if str(slug).strip())
    agents = _dedupe(str(value).strip() for value in dispatch_agent_ids if str(value).strip())
    runs = _dedupe(int(value) for value in command_run_ids)
    artifacts = _dedupe(int(value) for value in artifact_ids)

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        unknown: list[str] = []
        unknown += [
            f"finding {slug}"
            for slug in _unknown_findings(connection, engagement.id, findings)
        ]
        unknown += [
            f"dispatch agent_id {value}"
            for value in _unknown_rows(
                connection,
                engagement.id,
                agents,
                table="assessment_dispatches",
                column="agent_id",
            )
        ]
        unknown += [
            f"command run {value}"
            for value in _unknown_rows(
                connection,
                engagement.id,
                runs,
                table="assessment_command_runs",
                column="id",
            )
        ]
        unknown += [
            f"artifact {value}"
            for value in _unknown_rows(
                connection,
                engagement.id,
                artifacts,
                table="assessment_artifacts",
                column="id",
            )
        ]
        if unknown:
            # A reference to a nonexistent row is itself a false claim; refuse rather than store.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "operator checkpoint references rows this engagement does "
                    "not have: " + "; ".join(unknown)
                ),
            )

        previous = connection.execute(
            """
            SELECT id, checkpoint_version FROM assessment_operator_checkpoints
            WHERE engagement_id = ? AND superseded_by_id IS NULL
            ORDER BY checkpoint_version DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()
        highest = connection.execute(
            "SELECT MAX(checkpoint_version) AS version "
            "FROM assessment_operator_checkpoints WHERE engagement_id = ?",
            (engagement.id,),
        ).fetchone()
        next_version = int((highest["version"] if highest else None) or 0) + 1
        cursor = connection.execute(
            """
            INSERT INTO assessment_operator_checkpoints (
                engagement_id, checkpoint_version, superseded_by_id, current_phase,
                code_phase, finding_slugs_json, dispatch_agent_ids_json,
                command_run_ids_json, artifact_ids_json, intent_note, source,
                client_name, created_at
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                next_version,
                phase,
                code_phase,
                _json_text(findings),
                _json_text(agents),
                _json_text(runs),
                _json_text(artifacts),
                intent_note,
                "operator",
                "unknown",
                _utcnow_iso(),
            ),
        )
        new_id = int(cursor.lastrowid)
        for row in previous:
            connection.execute(
                "UPDATE assessment_operator_checkpoints SET superseded_by_id = ? "
                "WHERE id = ? AND superseded_by_id IS NULL",
                (new_id, int(row["id"])),
            )
        record = connection.execute(
            """
            SELECT checkpoint.*, successor.checkpoint_version
                AS superseded_by_checkpoint_version
            FROM assessment_operator_checkpoints AS checkpoint
            LEFT JOIN assessment_operator_checkpoints AS successor
                ON successor.id = checkpoint.superseded_by_id
            WHERE checkpoint.id = ?
            """,
            (new_id,),
        ).fetchone()
        assert record is not None
        return _serialize(record)


def list_checkpoints(
    engagement_id: int,
    *,
    include_superseded: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Read the current checkpoint, or the whole supersession chain.

    ``total_count`` is the true number of checkpoints this engagement holds, so
    a bounded chain read still reports honest depth.
    """

    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        total = int(
            connection.execute(
                "SELECT COUNT(*) AS total FROM assessment_operator_checkpoints "
                "WHERE engagement_id = ?",
                (engagement.id,),
            ).fetchone()["total"]
        )
        if include_superseded:
            rows = connection.execute(
                """
                SELECT checkpoint.*, successor.checkpoint_version
                    AS superseded_by_checkpoint_version
                FROM assessment_operator_checkpoints AS checkpoint
                LEFT JOIN assessment_operator_checkpoints AS successor
                    ON successor.id = checkpoint.superseded_by_id
                WHERE checkpoint.engagement_id = ?
                ORDER BY checkpoint.checkpoint_version DESC, checkpoint.id DESC
                LIMIT ? OFFSET ?
                """,
                (engagement.id, int(limit), int(offset)),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT checkpoint.*, successor.checkpoint_version
                    AS superseded_by_checkpoint_version
                FROM assessment_operator_checkpoints AS checkpoint
                LEFT JOIN assessment_operator_checkpoints AS successor
                    ON successor.id = checkpoint.superseded_by_id
                WHERE checkpoint.engagement_id = ?
                    AND checkpoint.superseded_by_id IS NULL
                ORDER BY checkpoint.checkpoint_version DESC, checkpoint.id DESC
                """,
                (engagement.id,),
            ).fetchall()
    checkpoints = [_serialize(row) for row in rows]
    return {
        "checkpoints": checkpoints,
        "returned_count": len(checkpoints),
        "total_count": total,
    }


def current_checkpoint(engagement_id: int) -> dict[str, Any] | None:
    """The single current checkpoint, or ``None`` when the operator wrote none."""

    checkpoints = list_checkpoints(engagement_id)["checkpoints"]
    return checkpoints[0] if checkpoints else None
