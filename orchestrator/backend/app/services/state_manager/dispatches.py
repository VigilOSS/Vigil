from __future__ import annotations

import difflib
import json
import hashlib
import sqlite3
from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404

from . import _common
from ._common import (
    DispatchStatus,
    TERMINAL_DISPATCH_STATUSES as _TERMINAL_DISPATCH_STATUSES,
    _require_canonical_finding_slugs,
)
from .findings import _ensure_finding_slugs_exist, finding_mode_sql
from ..variant_scopes import (
    MAX_VARIANT_PARENT_FINDINGS,
    VARIANT_DISPATCH_ROLE,
    canonical_variant_parent_slugs,
    variant_parent_finding_set_digest,
)



def _json_list(value: Any) -> str:
    """Store one optional list column exactly as its creating writer stores it."""
    return json.dumps(list(value))


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

# Caller-asserted binding fields, in the order they read on the row. The
# `client_binding_` prefix is the alias every dispatch read projects them under
# (see `_DISPATCH_SELECT`), so this tuple drives both the SQL and the unpacking.
_CLIENT_BINDING_FIELDS: tuple[str, ...] = (
    "id",
    "binding_version",
    "asserted_client",
    "asserted_session_namespace",
    "asserted_client_handle",
    "provider_observed_handle",
    "note",
    "bound_at",
)

# Every dispatch read goes through this projection so the CURRENT client binding
# rides on the row itself. `agent list`, `agent get`, and the resume brief all
# read a serialized dispatch and would otherwise need one extra round trip per
# row to learn which live session — if any — the dispatch was bound to.
# `client_binding_count` is what makes a re-bind visible at a glance: a row with
# count 2 has a correction in its history worth reading.
_DISPATCH_SELECT = (
    "SELECT d.*, "
    + ", ".join(
        f"b.{field} AS client_binding_{field}" for field in _CLIENT_BINDING_FIELDS
    )
    + ", (SELECT COUNT(*) FROM assessment_dispatch_client_bindings c "
    "WHERE c.dispatch_id = d.id) AS client_binding_count "
    "FROM assessment_dispatches d "
    "LEFT JOIN assessment_dispatch_client_bindings b "
    "ON b.dispatch_id = d.id AND b.superseded_by_id IS NULL"
)

def _serialize_dispatch(row) -> dict[str, Any]:
    data = dict(row)
    # Old engagement databases may retain these retired columns. They are not
    # part of the dispatch contract and must not leak back into current rows.
    for retired in (
        "model",
        "reasoning",
        "scope_host",
        "scope_path_prefix",
    ):
        data.pop(retired, None)
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
    binding = {
        field: data.pop(f"client_binding_{field}", None)
        for field in _CLIENT_BINDING_FIELDS
    }
    data["client_binding_count"] = int(data.pop("client_binding_count", 0) or 0)
    # A dispatch with no binding is the normal state right after `agent start`,
    # not an error: the client has not been launched yet.
    data["client_binding"] = (
        _serialize_client_binding(binding, agent_id=str(data.get("agent_id") or ""))
        if binding["id"] is not None
        else None
    )
    return data


def _serialize_prompt_packet(row) -> dict[str, Any]:
    return {
        "schema": str(row["schema_version"]),
        "context": json.loads(str(row["context_json"])),
        "rendered_prompt": str(row["rendered_prompt"]),
        "sha256": str(row["sha256"]),
        "created_at": str(row["created_at"]),
    }

def _serialize_client_binding(values: Any, *, agent_id: str) -> dict[str, Any]:
    """One shape for a binding, read standalone or embedded on a dispatch row.

    ``superseded_by_id`` is absent from the embedded projection because the
    dispatch join selects only the CURRENT binding, whose pointer is NULL by
    definition — reading it with a default keeps one serializer for both paths.
    ``agent_id`` is passed in rather than stored: the bindings table addresses a
    dispatch by its durable ``dispatch_id``, while every operator-facing surface
    addresses it by ``agent_id``.
    """
    data = dict(values)
    return {
        **{field: data.get(field) for field in _CLIENT_BINDING_FIELDS},
        "agent_id": agent_id,
        "superseded_by_id": data.get("superseded_by_id"),
    }

def record_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    agent_role: str,
    task: str | None = None,
    application_unit_id: int | None = None,
    dispatched_at: str | None = None,
    status_value: str = DispatchStatus.IN_PROGRESS,
    requested_model: str | None = None,
    actual_model: str = "unknown",
    requested_reasoning: str | None = None,
    actual_reasoning: str = "unknown",
    launcher_effective_model: str | None = None,
    launcher_effective_reasoning: str | None = None,
    launcher_effective_source: str | None = None,
    client_name: str = "unknown",
    requested_client: str = "unknown",
    launcher_effective_client: str = "unknown",
    provider_observed_client: str = "unknown",
    source_revision: str = "unknown",
    operator_instruction_path: str | None = None,
    operator_instruction_sha256: str | None = None,
    specialist_instruction_path: str | None = None,
    specialist_instruction_sha256: str | None = None,
    instruction_identity_status: str = "incomplete",
    instructions_stale: bool | None = None,
    dispatch_mode: str | None = None,
    assessment_mode: str | None = None,
    finding_slugs: list[str] | None = None,
    skills: str | None = None,
    tier: str | None = None,
    vuln_classes: str | None = None,
    identity: str | None = None,
    prompt_packet: dict[str, Any] | None = None,
    continued_from_dispatch_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (agent_id or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="agent_id is required")
    dispatched_value = dispatched_at or _common._utcnow_iso_dispatch()
    completed_value = (
        _common._utcnow_iso_dispatch()
        if status_value in _TERMINAL_DISPATCH_STATUSES
        else None
    )
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    variant_parent_slugs: list[str] | None = None
    if agent_role == VARIANT_DISPATCH_ROLE:
        if finding_slugs is not None and not finding_slugs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "code-variant-hunter requires a non-empty immutable "
                    "finding_slugs parent scope"
                ),
            )
        if len(finding_slugs or []) > MAX_VARIANT_PARENT_FINDINGS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "code-variant-hunter finding_slugs exceeds the immutable scope cap "
                    f"of {MAX_VARIANT_PARENT_FINDINGS}"
                ),
            )
        if finding_slugs is not None:
            variant_parent_slugs = canonical_variant_parent_slugs(finding_slugs)
            if finding_slugs != variant_parent_slugs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "code-variant-hunter finding_slugs must be sorted and unique "
                        "because they define an immutable dispatch scope"
                    ),
                )
    findings_json = json.dumps(list(finding_slugs)) if finding_slugs is not None else None
    skills_value = (skills or "").strip() or None
    tier_value = (tier or "").strip() or None
    vuln_classes_value = (vuln_classes or "").strip() or None
    identity_value = (identity or "").strip() or None
    registration_sha256 = None
    if prompt_packet is not None:
        prompt_packet = dict(prompt_packet)
        packet_context = dict(prompt_packet["context"])
        packet_context.pop("_registration_sha256", None)
        prompt_packet["context"] = packet_context
        registration_input = {
            "agent_id": agent_id,
            "agent_role": agent_role,
            "task": task,
            "application_unit_id": application_unit_id,
            "dispatched_at": dispatched_at,
            "status_value": status_value,
            "requested_model": requested_model,
            "requested_reasoning": requested_reasoning,
            "client_name": client_name,
            "requested_client": requested_client,
            "launcher_effective_client": launcher_effective_client,
            "provider_observed_client": provider_observed_client,
            "source_revision": source_revision,
            "operator_instruction_path": operator_instruction_path,
            "operator_instruction_sha256": operator_instruction_sha256,
            "specialist_instruction_path": specialist_instruction_path,
            "specialist_instruction_sha256": specialist_instruction_sha256,
            "instruction_identity_status": instruction_identity_status,
            "instructions_stale": instructions_stale,
            "dispatch_mode": dispatch_mode,
            "assessment_mode": assessment_mode,
            "finding_slugs": finding_slugs,
            "skills_value": skills_value,
            "tier_value": tier_value,
            "vuln_classes_value": vuln_classes_value,
            "identity_value": identity_value,
            "continued_from_dispatch_id": continued_from_dispatch_id,
            "prompt_packet": prompt_packet,
        }
        registration_sha256 = hashlib.sha256(json.dumps(registration_input, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        packet_context["_registration_sha256"] = registration_sha256
    with _common.get_connection() as connection:
        if not connection.in_transaction:
            connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is not None:
            saved = connection.execute("SELECT * FROM assessment_dispatch_prompt_packets WHERE dispatch_id = ?", (existing["id"],)).fetchone()
            if registration_sha256 is not None and saved is not None and json.loads(saved["context_json"]).get("_registration_sha256") == registration_sha256:
                previous = connection.execute(f"{_DISPATCH_SELECT} WHERE d.id = ?", (existing["id"],)).fetchone()
                return {**_serialize_dispatch(previous), "prompt_packet": _serialize_prompt_packet(saved),
                        "idempotent_replay": True, "launch_required": False}
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"dispatch with agent_id={agent_id!r} already exists with different or uncaptured inputs; inspect it before choosing a fresh identity",
            )
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        if variant_parent_slugs is not None:
            # Import lazily because code_analysis imports the finding lifecycle
            # helpers from this package. Receipt-bearing authority is the only
            # dispatch path that needs the code-specific snapshot selector.
            from .. import code_analysis

            code_analysis.validate_variant_dispatch_parent_scope(
                connection,
                engagement.id,
                variant_parent_slugs,
            )
        if application_unit_id is not None:
            unit = connection.execute(
                "SELECT id FROM assessment_application_units "
                "WHERE id = ? AND engagement_id = ?",
                (application_unit_id, engagement.id),
            ).fetchone()
            if unit is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"application_unit_id={application_unit_id} does not identify "
                        "an application unit in this engagement"
                    ),
                )
        if continued_from_dispatch_id is not None:
            parent = connection.execute(
                "SELECT status FROM assessment_dispatches WHERE id = ? AND engagement_id = ?",
                (continued_from_dispatch_id, engagement.id),
            ).fetchone()
            if parent is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="continued_from_dispatch_id must name a dispatch in this engagement",
                )
            proof_owner = connection.execute(
                "SELECT 1 FROM assessment_proof_work w WHERE w.engagement_id=? AND "
                "(w.owner_dispatch_id=? OR EXISTS (SELECT 1 FROM assessment_proof_work_events e "
                "WHERE e.work_id=w.id AND ((e.action='claimed' AND json_extract(e.details_json,'$.dispatch_id')=?) "
                "OR (e.action='released' AND json_extract(e.details_json,'$.previous_dispatch_id')=?)))) LIMIT 1",
                (engagement.id, continued_from_dispatch_id, continued_from_dispatch_id, continued_from_dispatch_id),
            ).fetchone()
            if proof_owner:
                raise HTTPException(status_code=409, detail=(
                    'Proof owners cannot continue through ordinary dispatch; run vigil assess kali sweep-orphans, '
                    'inspect vigil assess command-run list and proof runs/jobs, wait or stop active work, '
                    'then proof-work reconcile, close the ended dispatch, proof-work release, and claim fresh work'
                ))
            if parent['status'] not in _common.TERMINAL_DISPATCH_STATUSES:
                raise HTTPException(status_code=409, detail=('Predecessor dispatch must be explicitly closed before continuation. After observing '
                        'native return and confirming execution ended, use vigil assess agent close <agent-id>; '
                        'for no final handoff use agent close <agent-id> --status failed '
                        '--reason <observed-return-and-execution-state>. Inspect kali sweep-orphans and '
                        'command-run list; wait or stop active execution first.'))
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, task, application_unit_id,
                requested_model, actual_model, requested_reasoning, actual_reasoning,
                launcher_effective_model, launcher_effective_reasoning,
                launcher_effective_source,
                client_name, requested_client, launcher_effective_client,
                provider_observed_client, source_revision,
                operator_instruction_path, operator_instruction_sha256,
                specialist_instruction_path, specialist_instruction_sha256,
                instruction_identity_status, instructions_stale,
                dispatched_at, completed_at, status,
                dispatch_mode, assessment_mode, finding_slugs_json, skills, tier,
                vuln_classes, identity, continued_from_dispatch_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                agent_id,
                agent_role,
                task,
                application_unit_id,
                requested_model,
                actual_model,
                requested_reasoning,
                actual_reasoning,
                launcher_effective_model,
                launcher_effective_reasoning,
                launcher_effective_source,
                client_name,
                requested_client,
                launcher_effective_client,
                provider_observed_client,
                source_revision,
                operator_instruction_path,
                operator_instruction_sha256,
                specialist_instruction_path,
                specialist_instruction_sha256,
                instruction_identity_status,
                instructions_stale,
                dispatched_value,
                completed_value,
                status_value,
                dispatch_mode,
                assessment_mode,
                findings_json,
                skills_value,
                tier_value,
                vuln_classes_value,
                identity_value,
                continued_from_dispatch_id,
            ),
        )
        if variant_parent_slugs is not None:
            connection.execute(
                """
                INSERT INTO code_variant_dispatch_scopes (
                    dispatch_id, engagement_id, parent_finding_slugs_json,
                    parent_finding_set_digest
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    int(cursor.lastrowid),
                    engagement.id,
                    json.dumps(variant_parent_slugs, separators=(",", ":")),
                    variant_parent_finding_set_digest(variant_parent_slugs),
                ),
            )
        if prompt_packet is not None:
            schema = str(prompt_packet["schema_version"])
            context = prompt_packet["context"]
            rendered = str(prompt_packet["rendered_prompt"])
            canonical_context = json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
            connection.execute(
                """
                INSERT INTO assessment_dispatch_prompt_packets (
                    engagement_id, dispatch_id, schema_version, context_json, rendered_prompt, sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (engagement.id, int(cursor.lastrowid), schema, canonical_context, rendered, digest),
            )
        row = connection.execute(
            f"{_DISPATCH_SELECT} WHERE d.id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    assert row is not None
    record = _serialize_dispatch(row)
    if prompt_packet is not None:
        record["prompt_packet"] = {
            "schema": str(prompt_packet["schema_version"]),
            "context": prompt_packet["context"],
            "rendered_prompt": str(prompt_packet["rendered_prompt"]),
            "sha256": hashlib.sha256(str(prompt_packet["rendered_prompt"]).encode("utf-8")).hexdigest(),
        }
    record["idempotent_replay"] = False
    record["launch_required"] = prompt_packet is not None and status_value == DispatchStatus.IN_PROGRESS
    return record


def get_dispatch_prompt_packet(engagement_id: int, agent_id: str) -> dict[str, Any]:
    with _common.get_connection() as connection:
        row = connection.execute(
            """
            SELECT p.* FROM assessment_dispatch_prompt_packets AS p
            JOIN assessment_dispatches AS d ON d.id = p.dispatch_id
            WHERE p.engagement_id = ? AND d.agent_id = ?
            """,
            (engagement_id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch prompt packet not found")
    return _serialize_prompt_packet(row)

def update_dispatch(
    engagement_id: int,
    *,
    agent_id: str,
    status_value: str | None = None,
    completed_at: str | None = None,
    finding_slugs: list[str] | None = None,
    actual_model: str | None = None,
    actual_reasoning: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    finding_slugs = _require_canonical_finding_slugs(finding_slugs)
    with _common.get_connection() as connection:
        _ensure_finding_slugs_exist(connection, engagement.id, finding_slugs)
        existing = connection.execute(
            f"{_DISPATCH_SELECT} WHERE d.engagement_id = ? AND d.agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
        if existing is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
        if finding_slugs is not None and str(existing["agent_role"]) == VARIANT_DISPATCH_ROLE:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "code-variant-hunter finding_slugs define the immutable parent-finding "
                    "scope and cannot be updated; record produced findings on the handoff"
                ),
            )
        effective_status = status_value or str(existing["status"] or "")
        if effective_status in _TERMINAL_DISPATCH_STATUSES:
            if completed_at is not None and not str(completed_at).strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="terminal dispatch completed_at must not be blank",
                )
            resolved_completed_at = (
                str(completed_at).strip()
                if completed_at is not None
                else str(existing["completed_at"] or "").strip()
                or _common._utcnow_iso_dispatch()
            )
        else:
            if completed_at is not None and str(completed_at).strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="in-progress dispatch must not have completed_at",
                )
            resolved_completed_at = None
        sets: list[str] = []
        values: list[Any] = []
        if status_value is not None:
            sets.append("status = ?")
            values.append(status_value)
        if effective_status in _TERMINAL_DISPATCH_STATUSES and (
            completed_at is not None or status_value is not None
        ):
            sets.append("completed_at = ?")
            values.append(resolved_completed_at)
        if finding_slugs is not None:
            sets.append("finding_slugs_json = ?")
            values.append(json.dumps(list(finding_slugs)))
        if actual_model is not None:
            sets.append("actual_model = ?")
            values.append(actual_model)
        if actual_reasoning is not None:
            sets.append("actual_reasoning = ?")
            values.append(actual_reasoning)
        if not sets:
            return _serialize_dispatch(existing)
        values.extend([engagement.id, agent_id])
        where = "engagement_id = ? AND agent_id = ?"
        if status_value is not None:
            # Dispatch status is a one-way lifecycle. Bind every status write to
            # the sole mutable state so a timeout abort cannot overwrite a
            # specialist that completed after the read above.
            where += " AND status = ?"
            values.append(DispatchStatus.IN_PROGRESS)
        connection.execute(
            f"UPDATE assessment_dispatches SET {', '.join(sets)} WHERE {where}",
            tuple(values),
        )
        row = connection.execute(
            f"{_DISPATCH_SELECT} WHERE d.engagement_id = ? AND d.agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    assert row is not None
    return _serialize_dispatch(row)

def get_dispatch(engagement_id: int, agent_id: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            f"{_DISPATCH_SELECT} WHERE d.engagement_id = ? AND d.agent_id = ?",
            (engagement.id, agent_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dispatch not found")
    return _serialize_dispatch(row)

def dispatch_mode_sql(mode: str | None, *, role_sql: str = 'd.agent_role') -> str:
    """Scope dispatch reads by durable proof assignment, then ordinary role.

    Proof memory belongs to the candidate's investigation, independently of its
    execution route. Claimed events retain that association after ownership is
    released or another worker claims the work. Callers use dispatch alias ``d``
    and trusted SQL expressions.
    """
    if mode not in {'code', 'web'}:
        return ''
    assignments = '''SELECT 1 FROM assessment_proof_work pw
        JOIN assessment_findings pf ON pf.id=pw.finding_id
        WHERE pw.engagement_id=d.engagement_id AND (
            pw.owner_dispatch_id=d.id OR EXISTS (
                SELECT 1 FROM assessment_proof_work_events pe
                WHERE pe.work_id=pw.id AND pe.action='claimed'
                  AND json_extract(pe.details_json, '$.dispatch_id')=d.id))'''
    role_match = "LIKE 'code-%'" if mode == 'code' else "NOT LIKE 'code-%'"
    return (f" AND (EXISTS ({assignments}{finding_mode_sql(mode, location_sql='pf.canonical_location')}) OR "
            f"(NOT EXISTS ({assignments}) AND {role_sql} {role_match}))")


def list_dispatches(
    engagement_id: int,
    *,
    role: str = "",
    role_prefix: str = "",
    exclude_role_prefix: str = "",
    mode: str | None = None,
    status_value: str = "",
    since: str = "",
    task_q: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    # `d.` qualifies every predicate: the client-binding join carries its own
    # engagement_id/id, so an unqualified column name here would be ambiguous.
    where = ["d.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("d.agent_role = ?")
        params.append(role)
    if role_prefix:
        where.append("d.agent_role LIKE ?")
        params.append(f"{role_prefix}%")
    if exclude_role_prefix:
        where.append("d.agent_role NOT LIKE ?")
        params.append(f"{exclude_role_prefix}%")
    if status_value:
        where.append("d.status = ?")
        params.append(status_value)
    if since:
        where.append("d.dispatched_at >= ?")
        params.append(since)
    if task_q:
        where.append("d.task LIKE ?")
        params.append(f"%{task_q}%")
    params.append(int(limit))
    params.append(max(int(offset), 0))
    query = (
        f"{_DISPATCH_SELECT} WHERE {' AND '.join(where)}{dispatch_mode_sql(mode)} "
        "ORDER BY d.dispatched_at DESC, d.id DESC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_dispatch(row) for row in rows]

def _dispatch_id_or_404(connection, engagement_id: int, agent_id: str) -> int:
    row = connection.execute(
        "SELECT id FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
        (engagement_id, agent_id),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"dispatch not found for agent_id={agent_id!r}",
        )
    return int(row["id"])

def _next_client_binding_id(connection) -> int:
    """The id the next appended binding will carry.

    AUTOINCREMENT's own rule, read rather than waited for: the next rowid is one
    past the high-water mark it keeps in ``sqlite_sequence``, which is never
    rewound even by an engagement cascade. Valid only inside the write lock.
    """
    row = connection.execute(
        """
        SELECT MAX(
            COALESCE((
                SELECT seq FROM sqlite_sequence
                WHERE name = 'assessment_dispatch_client_bindings'
            ), 0),
            COALESCE((SELECT MAX(id) FROM assessment_dispatch_client_bindings), 0)
        ) + 1
        """
    ).fetchone()
    return int(row[0])


def _retire_current_binding(connection, *, current_id: int, successor_id: int) -> None:
    """Stamp one current binding's successor, refusing a swap that matched nothing.

    The append-only trigger permits exactly this update: NULL -> NOT NULL. Binding
    it to `IS NULL` makes it a compare-and-swap, and a swap that matched no row
    means this binding was already retired by someone else — so the bind is
    refused rather than left to append a second current row.
    """
    cursor = connection.execute(
        "UPDATE assessment_dispatch_client_bindings SET superseded_by_id = ? "
        "WHERE id = ? AND superseded_by_id IS NULL",
        (successor_id, current_id),
    )
    if cursor.rowcount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"client binding {current_id} was already superseded by a "
                "concurrent bind; re-read the binding history and bind again"
            ),
        )


def record_dispatch_client_binding(
    engagement_id: int,
    *,
    agent_id: str,
    asserted_client: str,
    asserted_session_namespace: str,
    asserted_client_handle: str,
    note: str | None = None,
    bound_at: str | None = None,
) -> dict[str, Any]:
    """Append one client binding to a dispatch and supersede the previous one.

    Nothing is ever rewritten: a correction is a new version whose insert stamps
    the prior current row's ``superseded_by_id``, so the record of what was bound
    when survives the correction. Returns both halves of that transition —
    ``{"binding": <new>, "superseded": <prior or None>}`` — because "which
    binding did this replace" is the question a reader has next.
    """
    engagement = _engagement_or_404(engagement_id)
    bound_value = bound_at or _common._utcnow_iso_dispatch()
    note_value = (note or "").strip() or None
    with _common.get_connection() as connection:
        # Reading the current binding, deriving the next version and writing both
        # halves of the transition is one decision, so it takes the write lock for
        # the whole of it — the same serialization `adopt_queue_lease`,
        # `reset_stale_queue_items` and the lead binders open. Unserialized, two
        # binds that read the same current row each appended a row nothing had
        # retired, and every dispatch read joins on `superseded_by_id IS NULL`.
        connection.execute("BEGIN IMMEDIATE")
        dispatch_id = _dispatch_id_or_404(connection, engagement.id, agent_id)
        current = connection.execute(
            "SELECT * FROM assessment_dispatch_client_bindings "
            "WHERE dispatch_id = ? AND superseded_by_id IS NULL",
            (dispatch_id,),
        ).fetchone()
        if current is not None and (
            str(current["asserted_client"]) == asserted_client
            and str(current["asserted_session_namespace"]) == asserted_session_namespace
            and str(current["asserted_client_handle"]) == asserted_client_handle
        ):
            # Re-asserting the current binding carries no new information, and an
            # identical extra version would bury the real corrections in the
            # history this table exists to preserve. The caller asked for the
            # state that already holds, so it gets that binding back, marked.
            return {
                "binding": _serialize_client_binding(current, agent_id=agent_id),
                "superseded": None,
                "already_bound": True,
            }
        highest = connection.execute(
            "SELECT MAX(binding_version) AS version "
            "FROM assessment_dispatch_client_bindings WHERE dispatch_id = ?",
            (dispatch_id,),
        ).fetchone()
        next_version = int(highest["version"] or 0) + 1
        # `idx_dispatch_client_bindings_one_current` is checked per statement, so
        # the predecessor has to be retired BEFORE the successor row exists —
        # which means knowing the successor's id first. AUTOINCREMENT never reuses
        # one and this transaction holds the only write lock, so the next id is
        # knowable, and it is written explicitly rather than inferred afterwards.
        binding_id = _next_client_binding_id(connection)
        if current is not None:
            # The forward reference is legal only until COMMIT, by which point
            # the row it names exists. The pragma resets itself at that commit.
            connection.execute("PRAGMA defer_foreign_keys = ON")
            _retire_current_binding(
                connection, current_id=int(current["id"]), successor_id=binding_id
            )
        try:
            connection.execute(
                """
                INSERT INTO assessment_dispatch_client_bindings (
                    id, engagement_id, dispatch_id, binding_version, superseded_by_id,
                    asserted_client, asserted_session_namespace,
                    asserted_client_handle, note, bound_at
                ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
                """,
                (
                    binding_id,
                    engagement.id,
                    dispatch_id,
                    next_version,
                    asserted_client,
                    asserted_session_namespace,
                    asserted_client_handle,
                    note_value,
                    bound_value,
                ),
            )
        except sqlite3.IntegrityError as exc:
            # UNIQUE(dispatch_id, binding_version): a concurrent bind already
            # claimed this version. Re-read the history and bind again rather
            # than guessing which of the two writers the operator meant.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"a concurrent client binding already claimed version "
                    f"{next_version} for dispatch {agent_id!r}; re-read "
                    "the binding history and bind again"
                ),
            ) from exc
        rows = connection.execute(
            "SELECT * FROM assessment_dispatch_client_bindings "
            "WHERE dispatch_id = ? AND id IN (?, ?)",
            (dispatch_id, binding_id, int(current["id"]) if current else binding_id),
        ).fetchall()
    by_id = {
        int(row["id"]): _serialize_client_binding(row, agent_id=agent_id)
        for row in rows
    }
    return {
        "binding": by_id[binding_id],
        "superseded": by_id.get(int(current["id"])) if current is not None else None,
        "already_bound": False,
    }

def list_dispatch_client_bindings(
    engagement_id: int, agent_id: str
) -> list[dict[str, Any]]:
    """Every client binding recorded for one dispatch, oldest version first."""
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        dispatch_id = _dispatch_id_or_404(connection, engagement.id, agent_id)
        rows = connection.execute(
            "SELECT * FROM assessment_dispatch_client_bindings "
            "WHERE dispatch_id = ? ORDER BY binding_version ASC",
            (dispatch_id,),
        ).fetchall()
    return [_serialize_client_binding(row, agent_id=agent_id) for row in rows]

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

HANDOFF_SUMMARY_MAX_CHARS = 16384

# A role's retired spelling -> the role that replaced it. A dispatch keeps the
# role it was registered under; a handoff naming the current role of a retired
# spelling names that same dispatch role. The CLI mirror
# (`contract_registry.py:RENAMED_DISPATCH_ROLES`) registers new dispatches under
# the current role; `test_renamed_dispatch_roles_mirror.py` pins the two.
RENAMED_DISPATCH_ROLES: dict[str, str] = {"general": "blind-reviewer"}


def _current_dispatch_role(role: str) -> str:
    return RENAMED_DISPATCH_ROLES.get(role, role)

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
    agent_role: str | None,
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
    if len(summary) > HANDOFF_SUMMARY_MAX_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"summary exceeds {HANDOFF_SUMMARY_MAX_CHARS} characters",
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
        # The handoff's role is the dispatch's: ``agent_id`` names the dispatch,
        # and its registered role is the one every role-keyed read joins on. A
        # role the caller left out is filled from it, and the response says so;
        # a different role contradicts the dispatch the handoff names and is
        # refused, because one of the two identities is wrong. The current name
        # of a renamed role is the same role, so the stored spelling is kept.
        registered_role = str(dispatch_row["agent_role"])
        derived: list[dict[str, Any]] = []
        if agent_role and _current_dispatch_role(agent_role) != _current_dispatch_role(registered_role):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"handoff agent_role {agent_role!r} contradicts the role "
                    f"{registered_role!r} dispatch {agent_id!r} was registered "
                    "with; omit agent_role to have the registered role stored, or "
                    "name the dispatch this handoff belongs to"
                ),
            )
        if not agent_role:
            derived.append({
                "field": "agent_role",
                "value": registered_role,
                "derived_from": "dispatch",
                "detail": (
                    f"stored the registered dispatch role {registered_role!r}; "
                    "the handoff named none"
                ),
            })
        elif agent_role != registered_role:
            derived.append({
                "field": "agent_role",
                "value": registered_role,
                "derived_from": "dispatch",
                "detail": (
                    f"stored the registered dispatch role {registered_role!r}; "
                    f"{agent_role!r} is its current name"
                ),
            })
        agent_role = registered_role
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
    return {**serialized, "derived": derived}

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
    expected_handoff_version: int | None = None,
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
        if expected_handoff_version is not None and (existing["handoff_version"] or 1) != expected_handoff_version:
            raise HTTPException(status_code=409, detail="Handoff changed; read its current version before recovery")
        sets: list[str] = []
        values: list[Any] = []
        if summary is not None:
            if not summary.strip():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="summary cannot be empty")
            if len(summary) > HANDOFF_SUMMARY_MAX_CHARS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"summary exceeds {HANDOFF_SUMMARY_MAX_CHARS} characters",
                )
            sets.append("summary = ?")
            values.append(summary)
        # The remaining optional columns, in the order their SET fragments are
        # emitted — which is also the UPDATE's parameter order, so the rows are
        # not reorderable. `encode` is the stored form of a JSON-backed column.
        for column, value, encode in (
            ("phase", phase, None),
            ("confidence", confidence, None),
            ("finding_slugs_json", finding_slugs, _json_list),
            ("coverage_gaps_json", coverage_gaps, _json_list),
            ("next_steps_json", next_steps, _json_list),
            ("runtime_issues_json", runtime_issues, _json_list),
            ("working_artifacts_json", working_artifacts, _json_list),
            ("open_questions_json", open_questions, _json_list),
            ("recommended_next_agent", recommended_next_agent, None),
            ("handoff_status", handoff_status, None),
            ("closed_dispatch_status", closed_dispatch_status, None),
            ("extras_json", extras, json.dumps),
        ):
            if value is None:
                continue
            sets.append(f"{column} = ?")
            values.append(value if encode is None else encode(value))
        if not sets:
            return _serialize_handoff(existing)
        sets.append("handoff_version = COALESCE(handoff_version, 1) + 1")
        sets.append("last_checkpoint_at = ?")
        values.append(_common._utcnow_iso_dispatch())
        values.extend([engagement.id, agent_id])
        version_clause = ""
        if expected_handoff_version is not None:
            version_clause = " AND COALESCE(handoff_version, 1) = ?"
            values.append(expected_handoff_version)
        updated = connection.execute(
            f"UPDATE assessment_dispatch_handoffs SET {', '.join(sets)} WHERE engagement_id = ? AND agent_id = ?{version_clause}",
            tuple(values),
        )
        if updated.rowcount != 1:
            raise HTTPException(status_code=409, detail="Handoff changed; read its current version before recovery")
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

# Orderings `list_handoffs` accepts, keyed by its `sort` argument. `created`
# is the arrival order, and stays the default so every existing caller is
# unaffected. `checkpoint` ranks by the last checkpoint — the only timestamp
# `update_handoff` moves, `created_at` being immutable — and exists because the
# ordering has to happen BEFORE `limit` bites: a "most recently active handoffs"
# window built by re-sorting a creation-limited page can never contain an
# old-created row that just checkpointed, because the query already cut it.
# `last_checkpoint_at` is nullable (it post-dates the table; the migration
# backfills it from `created_at`), so COALESCE keeps a null row in creation
# order instead of sinking it below every populated row. Both columns are
# written as fixed-width second-precision `...Z` strings, so SQLite's BINARY
# text ordering over them is the chronological one.
_HANDOFF_SORTS = {
    "created": "h.created_at DESC, h.id DESC",
    "checkpoint": "COALESCE(h.last_checkpoint_at, h.created_at) DESC, h.id DESC",
}

def list_handoffs(
    engagement_id: int,
    *,
    role: str = "",
    role_prefix: str = "",
    exclude_role_prefix: str = "",
    mode: str | None = None,
    since: str = "",
    sort: str = "created",
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    order_by = _HANDOFF_SORTS.get((sort or "created").strip().lower())
    if order_by is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"invalid handoff sort: {sort} "
                f"(expected one of {', '.join(sorted(_HANDOFF_SORTS))})"
            ),
        )
    where = ["h.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if role:
        where.append("h.agent_role = ?")
        params.append(role)
    if role_prefix:
        where.append("h.agent_role LIKE ?")
        params.append(f"{role_prefix}%")
    if exclude_role_prefix:
        where.append("h.agent_role NOT LIKE ?")
        params.append(f"{exclude_role_prefix}%")
    if since:
        # `since` is a creation-time window regardless of `sort` — it is the
        # documented filter on the public read, so it keeps its own meaning.
        where.append("h.created_at >= ?")
        params.append(since)
    params.append(int(limit))
    params.append(max(int(offset), 0))
    query = (
        "SELECT h.* FROM assessment_dispatch_handoffs h LEFT JOIN assessment_dispatches d "
        "ON d.engagement_id=h.engagement_id AND d.agent_id=h.agent_id "
        f"WHERE {' AND '.join(where)}{dispatch_mode_sql(mode, role_sql='h.agent_role')} "
        f"ORDER BY {order_by} LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_handoff(row) for row in rows]

# The role a decision records when the write names no dispatch: Vigil's
# attribution default, the operator session.
OPERATOR_RECORDER = "operator"


def decision_recorded_by(row) -> dict[str, Any] | None:
    """``{"agent_id", "agent_role"}`` of the dispatch that recorded a decision row,
    ``agent_id`` None for the operator's; None for a row recorded before the
    recorder was stored."""
    keys = row.keys()
    role = row["recorded_by_role"] if "recorded_by_role" in keys else None
    if role is None:
        return None
    return {"agent_id": row["recorded_by_agent_id"], "agent_role": role}


def _decision_recorder(connection, engagement_id: int, agent_id: str | None) -> tuple[str | None, str]:
    """``(dispatch agent_id or None, role)`` for the recorder a decision write names.

    The role is the dispatch row's, never the caller's. No id (or ``operator``)
    is the operator session; an id that names no dispatch of this engagement is
    refused rather than stored as a recorder nobody can be.
    """
    named = (agent_id or "").strip()
    if not named or named == OPERATOR_RECORDER:
        return None, OPERATOR_RECORDER
    row = connection.execute(
        "SELECT agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
        (engagement_id, named),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"recorded_by_agent_id {named!r} names no recorded dispatch in this engagement; "
                "pass your dispatch agent_id from your packet's Runtime Identity, or omit it "
                "when the operator records the decision"
            ),
        )
    return named, str(row["agent_role"])


def _serialize_decision(row) -> dict[str, Any]:
    data = dict(row)
    data["recorded_by"] = decision_recorded_by(row)
    data.pop("recorded_by_agent_id", None)
    data.pop("recorded_by_role", None)
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

_QC_PAYLOAD_KEYS = frozenset(
    {"reviewer_dispatch_agent_id", "writer_dispatch_agent_id", "verdict", "failed_rows"}
)


def _qc_verdict_problems(
    connection, engagement_id: int, payload: dict[str, Any], *, label: str, subject_keys: frozenset[str],
) -> tuple[list[str], str | None]:
    """Shape and attribution shared by every report-writer QC verdict.

    Returns each problem the payload has, and the reviewer when the attribution
    names two distinct recorded report-writer dispatches (else None). A blocked
    verdict names each failed checklist row with the quoted text that failed it,
    so the writer receives the fix list; a pass names none. Every problem is
    collected, because nothing about the payload changes between refusals.
    """
    problems: list[str] = []
    allowed = _QC_PAYLOAD_KEYS | subject_keys
    unknown = sorted(set(payload) - allowed)
    if unknown:
        named = "; ".join(
            f"{key!r}"
            + (
                f" (did you mean {close[0]!r}?)"
                if (close := difflib.get_close_matches(key, sorted(allowed), n=1, cutoff=0.6))
                else ""
            )
            for key in unknown
        )
        problems.append(
            f"{label} payload has unknown fields: {named}. Its fields: {', '.join(sorted(allowed))}"
        )
    verdict = payload.get("verdict")
    rows = payload.get("failed_rows", [])
    if verdict not in {"pass", "blocked"}:
        problems.append(f"{label} verdict must be pass or blocked (got {verdict!r})")
    if not isinstance(rows, list) or any(
        not isinstance(row, dict)
        or set(row) != {"row", "quote"}
        or any(not isinstance(row[key], str) or not row[key].strip() for key in ("row", "quote"))
        for row in rows
    ):
        problems.append(f"{label} failed_rows entries need a checklist row and the quoted failing text")
    elif verdict == "blocked" and not rows:
        problems.append(f"a blocked {label} verdict names its failed_rows")
    elif verdict == "pass" and rows:
        problems.append(f"a passing {label} verdict has no failed_rows")
    if any(
        not isinstance(payload.get(key), str) or not payload[key].strip()
        for key in ("reviewer_dispatch_agent_id", "writer_dispatch_agent_id")
    ):
        problems.append(f"{label} requires reviewer and writer dispatch attribution")
        return problems, None
    reviewer = payload["reviewer_dispatch_agent_id"]
    writer = payload["writer_dispatch_agent_id"]
    if reviewer == writer:
        problems.append(f"{label} reviewer must be a dispatch separate from the writer")
    identities = connection.execute(
        "SELECT agent_id, agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id IN (?, ?)",
        (engagement_id, reviewer, writer),
    ).fetchall()
    roles = {row["agent_id"]: row["agent_role"] for row in identities}
    not_writers = [
        f"{side} {agent!r}"
        for side, agent in (("reviewer", reviewer), ("writer", writer))
        if roles.get(agent) != "report-writer"
    ]
    if not_writers:
        problems.append(
            f"{label} requires recorded report-writer dispatches for reviewer and writer; "
            f"{' and '.join(not_writers)} is not one"
        )
    return problems, (reviewer if reviewer != writer and not not_writers else None)


def _refuse_qc_problems(label: str, problems: list[str]) -> None:
    """One refusal naming every problem a QC verdict payload has."""
    if problems:
        raise HTTPException(
            status_code=422,
            detail=(
                problems[0]
                if len(problems) == 1
                else f"{label} verdict has {len(problems)} problems: " + "; ".join(problems)
            ),
        )


def _artifact_producers(artifact) -> set[str]:
    """Every agent recorded as registering one artifact row's path."""
    try:
        history = json.loads(artifact["producer_history_json"] or "[]")
    except (TypeError, ValueError):
        history = []
    producers = {
        agent for agent in (history if isinstance(history, list) else [])
        if isinstance(agent, str) and agent
    }
    producers.update(
        agent for agent in (artifact["producer_agent_id"], artifact["content_producer_agent_id"])
        if isinstance(agent, str) and agent
    )
    return producers


def _registered_producers(connection, engagement_id: int, slug: str) -> set[str]:
    """Every agent that registered a submission workspace linked to ``slug``.

    ``export submission --agent-id`` attributes each render's registration, so a
    dispatch that wrote any version of the workspace is in this set.
    """
    rows = connection.execute(
        """
        SELECT producer_agent_id, content_producer_agent_id, producer_history_json
        FROM assessment_artifacts
        WHERE engagement_id = ? AND kind = 'submission' AND related_finding_slug = ?
        """,
        (engagement_id, slug),
    ).fetchall()
    return set().union(*(_artifact_producers(row) for row in rows))


def _validate_submission_qc(connection, engagement_id: int, payload: dict[str, Any]) -> None:
    """An independent report-writer reviewed one triage packet of this finding."""
    from ..submission_versions import triage_packet_issue

    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="submission QC payload must be an object")
    problems, reviewer = _qc_verdict_problems(
        connection, engagement_id, payload, label="submission QC",
        subject_keys=frozenset({"finding_slug", "packet_id"}),
    )
    slug = payload.get("finding_slug")
    packet_id = payload.get("packet_id")
    if not isinstance(slug, str) or not slug.strip() or not isinstance(packet_id, str):
        problems.append("submission QC requires finding_slug and packet_id")
        _refuse_qc_problems("submission QC", problems)
    finding = connection.execute(
        "SELECT id, provenance_json FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
        (engagement_id, slug),
    ).fetchone()
    if finding is None:
        if not problems:
            raise HTTPException(status_code=404, detail="submission QC finding not found")
        problems.append(f"submission QC finding {slug!r} not found")
        _refuse_qc_problems("submission QC", problems)
    if reviewer is not None:
        if reviewer == _common._json_object(finding["provenance_json"]).get("agent_id"):
            problems.append("submission QC reviewer must differ from the finding author")
        if reviewer in _registered_producers(connection, engagement_id, slug):
            problems.append(
                "submission QC reviewer registered this finding's submission workspace; "
                "a report-writer that has not written it must review"
            )
        edited = connection.execute(
            """
            SELECT 1 FROM assessment_finding_transitions
            WHERE engagement_id = ? AND finding_id = ?
              AND (actor = ? OR json_extract(metadata_json, '$.dispatch_agent_id') = ?)
            LIMIT 1
            """,
            (engagement_id, int(finding["id"]), reviewer, reviewer),
        ).fetchone()
        if edited is not None:
            problems.append(
                "submission QC reviewer edited this finding; a dispatch that has not "
                "edited it must review"
            )
    issue = triage_packet_issue(engagement_id, slug, packet_id)
    if issue:
        problems.append(f"submission QC must review a triage packet of this finding: {issue}")
    _refuse_qc_problems("submission QC", problems)


def _report_disk_check(root, size_bytes: int, sha256: str) -> str | None:
    """Why report.md on disk is not ``size_bytes`` bytes hashing to ``sha256``."""
    from .. import artifact_index

    try:
        artifact_index.read_registered_artifact_bytes(
            root, "report.md", expected_size=size_bytes, expected_sha256=sha256,
        )
    except HTTPException as exc:
        return str(exc.detail)
    return None


def _observe_report_bytes(engagement, payload: Any) -> tuple[int, str, str | None] | None:
    """Read report.md against the reviewed digest before the write lock is taken.

    Hashing the whole report inside ``BEGIN IMMEDIATE`` held every other writer
    for the length of the read. Returns ``(size_bytes, sha256, problem)`` for the
    registration the read was checked against; the validator under the lock
    uses it only while the registration still names those bytes, and reads
    again otherwise.
    """
    from pathlib import Path

    if not isinstance(payload, dict):
        return None
    artifact_id = payload.get("artifact_id")
    sha256 = payload.get("sha256")
    if type(artifact_id) is not int or not isinstance(sha256, str) or len(sha256) != 64:
        return None
    with _common.get_connection() as connection:
        artifact = connection.execute(
            "SELECT relative_path, size_bytes, sha256 FROM assessment_artifacts "
            "WHERE engagement_id = ? AND id = ?",
            (engagement.id, artifact_id),
        ).fetchone()
    if artifact is None or artifact["relative_path"] != "report.md" or artifact["sha256"] != sha256:
        return None
    size_bytes = int(artifact["size_bytes"])
    root = Path(engagement.engagement_root).expanduser().resolve()
    return size_bytes, sha256, _report_disk_check(root, size_bytes, sha256)


def _validate_report_qc(
    connection,
    engagement,
    payload: dict[str, Any],
    *,
    observed: tuple[int, str, str | None] | None = None,
) -> None:
    """An independent report-writer reviewed the registered bytes of report.md."""
    from pathlib import Path

    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="report QC payload must be an object")
    problems, reviewer = _qc_verdict_problems(
        connection, engagement.id, payload, label="report QC",
        subject_keys=frozenset({"artifact_id", "sha256"}),
    )
    artifact_id = payload.get("artifact_id")
    sha256 = payload.get("sha256")
    if type(artifact_id) is not int or not isinstance(sha256, str) or len(sha256) != 64:
        problems.append("report QC requires artifact_id and the sha256 it reviewed")
        _refuse_qc_problems("report QC", problems)
    artifact = connection.execute(
        "SELECT * FROM assessment_artifacts WHERE engagement_id = ? AND id = ?",
        (engagement.id, artifact_id),
    ).fetchone()
    if artifact is None or artifact["relative_path"] != "report.md" or not artifact["present"]:
        problems.append("report QC must name the registered report.md artifact")
        _refuse_qc_problems("report QC", problems)
    if artifact["sha256"] != sha256:
        problems.append("report QC sha256 differs from the registered report.md")
    if not artifact["content_producer_agent_id"]:
        problems.append(
            "report QC needs report.md's current bytes registered by their writer: "
            "`vigil assess artifact register report.md --kind report --agent-id <writer dispatch>`, "
            "then review those bytes"
        )
    if reviewer is not None and reviewer in _artifact_producers(artifact):
        problems.append(
            "report QC reviewer registered report.md bytes; a report-writer that has not "
            "drafted it must review"
        )
    if artifact["sha256"] == sha256:
        size_bytes = int(artifact["size_bytes"])
        if observed is not None and observed[:2] == (size_bytes, sha256):
            problem = observed[2]
        else:
            problem = _report_disk_check(
                Path(engagement.engagement_root).expanduser().resolve(), size_bytes, sha256,
            )
        if problem is not None:
            problems.append(
                f"report.md on disk differs from its registration ({problem}); register "
                "its current bytes and review them"
            )
    _refuse_qc_problems("report QC", problems)


_REPRO_VOCABULARY = {
    "verdict": ("followed", "failed", "equivalent"),
    "proof_mode": ("live", "source", "fuzz"),
}


def _repro_payload_problems(payload: Any) -> list[str]:
    """Each way a repro_rehearsal payload is malformed, naming the field."""
    if not isinstance(payload, dict):
        return ["payload must be an object"]
    problems = [
        f"payload.{key} is required (a non-empty string)"
        for key in ("finding_slug", "verifier_dispatch_agent_id")
        if not isinstance(payload.get(key), str) or not payload[key].strip()
    ]
    for key, allowed in _REPRO_VOCABULARY.items():
        if payload.get(key) not in allowed:
            problems.append(
                f"payload.{key} must be one of: {', '.join(allowed)} "
                f"(got {payload.get(key)!r})"
            )
    runs = payload.get("runs_checked", [])
    if not isinstance(runs, list) or any(type(run_id) is not int or run_id < 1 for run_id in runs):
        problems.append("payload.runs_checked must be a list of positive integer command-run ids")
    return problems


#: Gate readers and approve+execute flows read only rows this predicate admits:
#: a decision recorded with ``supersedes`` replaces the row it names, which stays
#: readable by id and through ``include_superseded``.
CURRENT_DECISION_SQL = "superseded_by_id IS NULL"

#: Kinds whose gate state lives outside the decision row, so replacing the row
#: would leave the state it recorded in force. ``severity_variance`` attaches to
#: the current verification and is replaced by a fresh verification.
_UNSUPERSEDABLE_DECISION_KINDS: dict[str, str] = {
    "severity_variance": (
        "a severity_variance is attached to the finding's current verification, "
        "not held by its decision row; record the corrected reason on a fresh "
        "verification with `vigil assess finding verify <slug> ... "
        "--severity-variance-file <path>`"
    ),
}


def _check_supersedable(connection, engagement_id: int, kind: str, decision_id: int) -> None:
    """Refuse a supersession the new row cannot truthfully make."""
    if kind in _UNSUPERSEDABLE_DECISION_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"supersedes is refused for {kind}: {_UNSUPERSEDABLE_DECISION_KINDS[kind]}",
        )
    row = connection.execute(
        "SELECT id, kind, superseded_by_id FROM assessment_dispatch_decisions "
        "WHERE engagement_id = ? AND id = ?",
        (engagement_id, decision_id),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"supersedes names decision {decision_id}, which this engagement does not "
                "hold; read the row to correct with `vigil assess fetch "
                f"dispatch-decisions/{decision_id}`"
            ),
        )
    if row["kind"] != kind:
        raise HTTPException(
            status_code=422,
            detail=(
                f"supersedes names decision {decision_id}, a {row['kind']!r} row; a "
                f"{kind!r} row supersedes only a {kind!r} row. Record the correction "
                f"under `--kind {row['kind']}`"
            ),
        )
    if row["superseded_by_id"] is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"decision {decision_id} is already superseded by decision "
                f"{row['superseded_by_id']}; supersede {row['superseded_by_id']} instead"
            ),
        )


def record_decision(
    engagement_id: int,
    *,
    kind: str,
    payload: dict[str, Any],
    surfaced_to_user: bool = False,
    supersedes: int | None = None,
    recorded_by_agent_id: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not (kind or "").strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="kind is required")
    created_at = _common._utcnow_iso_dispatch()
    report_bytes = (
        _observe_report_bytes(engagement, payload) if kind == "report_qc_verdict" else None
    )
    with _common.get_connection() as connection:
        recorder_id, recorder_role = _decision_recorder(
            connection, engagement.id, recorded_by_agent_id
        )
        if recorder_id is not None:
            from ..code_analysis import FAMILY_EXCLUSION_DECISION_KIND

            if kind == FAMILY_EXCLUSION_DECISION_KIND:
                # The exclusion records a program's or the user's ruling and must be
                # surfaced to the user, which only the operator does.
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=(
                        f"{kind} not recorded: dispatch {recorder_id} ({recorder_role}) is a "
                        "specialist, and the exclusion records a program or user ruling the "
                        "operator surfaces to the user. Report the ruling in your handoff "
                        "(open_questions) for the operator to record"
                    ),
                )
        if supersedes is not None:
            _check_supersedable(connection, engagement.id, kind, supersedes)
        if kind == "claim_equivalence":
            connection.execute("BEGIN IMMEDIATE")
            from .findings import validate_claim_equivalence_decision

            validate_claim_equivalence_decision(connection, engagement.id, payload)
        if kind == "submission_qc_verdict":
            connection.execute("BEGIN IMMEDIATE")
            _validate_submission_qc(connection, engagement.id, payload)
        if kind == "severity_variance":
            connection.execute("BEGIN IMMEDIATE")
            from .proofs import attach_severity_variance

            payload = attach_severity_variance(connection, engagement.id, payload)
        if kind == "report_qc_verdict":
            connection.execute("BEGIN IMMEDIATE")
            _validate_report_qc(connection, engagement, payload, observed=report_bytes)
        if kind == "blind_triage_verdict":
            # Existing verdict rows retain their historical attribution. Every new
            # review names real dispatches; distinct IDs prove attribution, not
            # that native clients provided independent context windows.
            connection.execute("BEGIN IMMEDIATE")
            if any(
                not isinstance(payload.get(key), str) or not payload[key].strip()
                for key in ("finding_slug", "reviewer_dispatch_agent_id", "writer_dispatch_agent_id")
            ):
                raise HTTPException(status_code=422, detail="blind triage requires finding, reviewer and writer attribution")
            reviewer_id = payload["reviewer_dispatch_agent_id"]
            writer_id = payload["writer_dispatch_agent_id"]
            finding = connection.execute(
                "SELECT provenance_json FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
                (engagement.id, payload["finding_slug"]),
            ).fetchone()
            if finding is None:
                raise HTTPException(status_code=404, detail="blind triage finding not found")
            provenance = _common._json_object(finding["provenance_json"])
            if reviewer_id in {writer_id, provenance.get("agent_id")}:
                raise HTTPException(status_code=422, detail="blind triage reviewer must differ from the finding author and report writer")
            identities = connection.execute(
                "SELECT agent_id, agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id IN (?, ?)",
                (engagement.id, reviewer_id, writer_id),
            ).fetchall()
            roles = {row["agent_id"]: row["agent_role"] for row in identities}
            if roles.get(writer_id) != "report-writer":
                raise HTTPException(status_code=422, detail="blind triage requires a recorded report-writer dispatch")
            if reviewer_id not in roles or roles[reviewer_id] == "report-writer":
                raise HTTPException(status_code=422, detail="blind triage requires a recorded reviewer dispatch distinct from report writing")
        if kind == "repro_rehearsal":
            connection.execute("BEGIN IMMEDIATE")
            from .repro_currentness import reproduction_basis, reproduction_sha256

            problems = _repro_payload_problems(payload)
            if problems:
                raise HTTPException(
                    status_code=422,
                    detail="repro_rehearsal payload invalid: " + "; ".join(problems),
                )

            finding = connection.execute(
                "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
                (engagement.id, payload["finding_slug"]),
            ).fetchone()
            if finding is None:
                raise HTTPException(status_code=404, detail="reproduction finding not found")
            if payload["proof_mode"] == "fuzz" and not str(
                finding["canonical_location"] or ""
            ).startswith("file:"):
                raise HTTPException(status_code=422, detail="fuzz reproduction requires a file finding")
            if payload["proof_mode"] == "source" and reproduction_basis(
                connection, engagement.id, finding
            ) != "source":
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "source reproduction requires a source-derived file finding: "
                        "every current verification receipt must be a source_observation; "
                        "rehearse a finding with runtime receipts live or by fuzz"
                    ),
                )
            reviewer = connection.execute(
                "SELECT agent_role FROM assessment_dispatches WHERE engagement_id = ? AND agent_id = ?",
                (engagement.id, payload["verifier_dispatch_agent_id"]),
            ).fetchone()
            roles = {
                "live": "vulnerability-analyst",
                "source": "code-vuln-verifier",
                "fuzz": "code-fuzz-engineer",
            }
            if reviewer is None or reviewer["agent_role"] != roles[payload["proof_mode"]]:
                raise HTTPException(status_code=422, detail="reproduction requires a dispatch with the matching verifier role")
            provenance = json.loads(finding["provenance_json"] or "{}")
            if payload["verifier_dispatch_agent_id"] == provenance.get("agent_id"):
                raise HTTPException(status_code=422, detail="reproduction reviewer must be independent of the finding author")
            verdict = payload["verdict"]
            if verdict == "followed":
                if not str(payload.get("observed_outcome") or "").strip():
                    raise HTTPException(status_code=422, detail="successful reproduction needs the observed outcome")
                if payload["proof_mode"] in {"live", "fuzz"}:
                    run_ids = payload.get("runs_checked") or []
                    if not run_ids:
                        raise HTTPException(status_code=422, detail="live or fuzz reproduction needs checked command run IDs")
                    rows = connection.execute(
                        f"SELECT id, agent_name FROM assessment_command_runs WHERE engagement_id = ? AND status = 'completed' AND id IN ({','.join('?' for _ in run_ids)})",
                        (engagement.id, *run_ids),
                    ).fetchall()
                    if {int(row["id"]) for row in rows} != set(run_ids):
                        raise HTTPException(status_code=422, detail="reproduction command runs must be completed in this engagement")
                    if not any(row["agent_name"] == payload["verifier_dispatch_agent_id"] for row in rows):
                        raise HTTPException(status_code=422, detail="reproduction needs a completed run attributed to the cold verifier")
                    details = json.loads(finding["details_json"] or "{}")
                    authored_runs = details.get("repro_runs") or []
                    if not isinstance(authored_runs, list) or any(
                        type(run_id) not in {int, str}
                        or not str(run_id).strip().isdigit()
                        or int(run_id) < 1
                        for run_id in authored_runs
                    ):
                        raise HTTPException(status_code=422, detail="finding repro_runs contains an invalid command-run ID")
                    if not {int(run_id) for run_id in authored_runs}.issubset(set(run_ids)):
                        raise HTTPException(status_code=422, detail="reproduction check omits an authored repro_runs ID")
            elif verdict == "failed":
                if not str(payload.get("failed_step") or "").strip():
                    raise HTTPException(status_code=422, detail="failed reproduction needs the failed step")
            else:
                prior = connection.execute(
                    "SELECT payload_json FROM assessment_dispatch_decisions WHERE id = ? AND engagement_id = ? AND kind = 'repro_rehearsal' "
                    f"AND {CURRENT_DECISION_SQL}",
                    (payload.get("prior_decision_id"), engagement.id),
                ).fetchone()
                previous = json.loads(prior["payload_json"]) if prior else {}
                if (previous.get("finding_slug") != payload["finding_slug"]
                    or previous.get("verdict") != "followed"
                    or previous.get("verifier_dispatch_agent_id") == payload["verifier_dispatch_agent_id"]
                    or not str(payload.get("reason") or "").strip()):
                    raise HTTPException(status_code=422, detail="equivalence needs a prior successful check, a fresh reviewer, and a reason")
            payload = {**payload, "reproduction_sha256": reproduction_sha256(dict(finding))}
        cursor = connection.execute(
            """
            INSERT INTO assessment_dispatch_decisions (
                engagement_id, kind, payload_json, surfaced_to_user, resolved,
                resolution_json, created_at, supersedes_id, recorded_by_agent_id,
                recorded_by_role
            ) VALUES (?, ?, ?, ?, 0, NULL, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                kind,
                json.dumps(payload or {}),
                1 if surfaced_to_user else 0,
                created_at,
                supersedes,
                recorder_id,
                recorder_role,
            ),
        )
        if supersedes is not None:
            # Conditional on the row still being current, so two corrections
            # racing for one row cannot both claim it; the loser rolls back.
            stamped = connection.execute(
                "UPDATE assessment_dispatch_decisions SET superseded_by_id = ?, superseded_at = ? "
                f"WHERE engagement_id = ? AND id = ? AND {CURRENT_DECISION_SQL}",
                (cursor.lastrowid, created_at, engagement.id, supersedes),
            )
            if stamped.rowcount != 1:
                raise HTTPException(
                    status_code=409,
                    detail=f"decision {supersedes} was superseded concurrently; read it and retry",
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
    include_superseded: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if not include_superseded:
        where.append(CURRENT_DECISION_SQL)
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

def get_decision(engagement_id: int, *, decision_id: int) -> dict[str, Any]:
    """Read one dispatch decision by id.

    ``PATCH /dispatch-decisions/{id}`` already owned this path template; the read
    was list-only, so "show me decision 3056" fell through the SPA catch-all and
    came back as a 200 HTML page.
    """

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions WHERE engagement_id = ? AND id = ?",
            (engagement.id, decision_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="decision not found")
    return _serialize_decision(row)


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
        if existing["superseded_by_id"] is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"decision {decision_id} is superseded by decision "
                    f"{existing['superseded_by_id']}; act on {existing['superseded_by_id']}"
                ),
            )
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
