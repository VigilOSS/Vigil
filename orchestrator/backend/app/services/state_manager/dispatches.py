from __future__ import annotations

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
    with _common.get_connection() as connection:
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
                "SELECT 1 FROM assessment_dispatches WHERE id = ? AND engagement_id = ?",
                (continued_from_dispatch_id, engagement.id),
            ).fetchone()
            if parent is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="continued_from_dispatch_id must name a dispatch in this engagement",
                )
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
            # history this table exists to preserve.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"dispatch {agent_id!r} is already bound to this client handle "
                    f"at binding_version={int(current['binding_version'])}; bind a "
                    "different client, namespace, or handle to supersede it"
                ),
            )
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
        if kind == "claim_equivalence":
            connection.execute("BEGIN IMMEDIATE")
            from .findings import validate_claim_equivalence_decision

            validate_claim_equivalence_decision(connection, engagement.id, payload)
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
            provenance = json.loads(finding["provenance_json"] or "{}")
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
            from .repro_currentness import reproduction_sha256

            required = ("finding_slug", "verdict", "proof_mode", "verifier_dispatch_agent_id")
            if (
                not isinstance(payload, dict)
                or any(not isinstance(payload.get(key), str) or not payload[key].strip() for key in required)
                or payload.get("verdict") not in {"followed", "failed", "equivalent"}
                or payload.get("proof_mode") not in {"live", "source", "fuzz"}
                or not isinstance(payload.get("runs_checked", []), list)
                or any(type(run_id) is not int or run_id < 1 for run_id in payload.get("runs_checked", []))
            ):
                raise HTTPException(status_code=422, detail="invalid reproduction decision payload")

            finding = connection.execute(
                "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
                (engagement.id, payload["finding_slug"]),
            ).fetchone()
            if finding is None:
                raise HTTPException(status_code=404, detail="reproduction finding not found")
            if payload["proof_mode"] in {"source", "fuzz"} and not str(
                finding["canonical_location"] or ""
            ).startswith("file:"):
                raise HTTPException(status_code=422, detail="source or fuzz reproduction requires a file finding")
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
                    "SELECT payload_json FROM assessment_dispatch_decisions WHERE id = ? AND engagement_id = ? AND kind = 'repro_rehearsal'",
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
