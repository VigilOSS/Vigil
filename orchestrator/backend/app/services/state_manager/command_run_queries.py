"""Read models and search projections for the command-run audit ledger."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, status

from ..events import _engagement_or_404
from ..search import (
    fts_escape as _fts_escape_shared,
    expanded_fts_query,
    finding_aliases_in_text,
)
from . import _common


def _serialize_command_run(row, *, include_output: bool) -> dict[str, Any]:
    data = dict(row)
    try:
        data["argv"] = json.loads(data.pop("argv_json", None) or "[]")
    except json.JSONDecodeError:
        data["argv"] = []
    data["timed_out"] = bool(data.get("timed_out"))
    data["success"] = bool(data.get("success"))
    # Command-metadata fields — surfaced explicitly so callers don't rely on
    # sqlite3.Row dict coercion to include them. Default to None so rows
    # written before this migration (where dict(row) simply won't have the
    # key if the schema matched pre-ALTER) still serialize with a null
    # present. `destructive` is stored as 0/1 INTEGER; coerce back to a
    # Python bool for API consumers, preserving NULL.
    data["technique"] = data.get("technique")
    data["intent"] = data.get("intent")
    data["probe_kind"] = data.get("probe_kind")
    destructive_raw = data.get("destructive")
    if destructive_raw is None:
        data["destructive"] = None
    else:
        data["destructive"] = bool(destructive_raw)
    data["partial_results"] = bool(data.get("partial_results"))
    data["output_recovery_observed_at"] = data.get("output_recovery_observed_at")
    if not include_output:
        # Listings default to lightweight rows so a sub-agent fetching 50
        # records does not load 50 × 64 KiB of preview text into context.
        # Hashes, suppression reasons, artifact refs, and byte counts stay
        # so the caller can decide whether a follow-up command-run get is
        # warranted. The full preview is always available via that detail
        # endpoint or by passing include_output=true on the list call.
        stdout_len = len(data.get("stdout_preview") or "")
        stderr_len = len(data.get("stderr_preview") or "")
        data["stdout_preview"] = ""
        data["stderr_preview"] = ""
        data["stdout_preview_chars"] = stdout_len
        data["stderr_preview_chars"] = stderr_len
    return data


def _fts_escape(term: str) -> str:
    """Back-compat shim; real implementation lives in ``services.search``."""
    return _fts_escape_shared(term)


def list_command_runs(
    engagement_id: int,
    *,
    q: str = "",
    agent_name: str = "",
    phase: str = "",
    tool_name: str = "",
    tool_bin: str = "",
    target_host: str = "",
    auth_context: str = "",
    audit_source: str = "",
    route: str = "",
    success: bool | None = None,
    timed_out: bool | None = None,
    output_attention: bool = False,
    technique: str = "",
    probe_kind: str = "",
    destructive: bool | None = None,
    intent_q: str = "",
    sort: str = "",
    exact: bool = False,
    require_all: bool = False,
    show_matches: bool = False,
    limit: int = 100,
    offset: int = 0,
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)

    # Track WHERE filters as (clause, params) tuples so the distant-search
    # helper can drop the MATCH filter cleanly. Positional zip() against a
    # flat base_params list breaks when a filter takes >1 param.
    filters: list[tuple[str, list[Any]]] = [("r.engagement_id = ?", [engagement.id])]

    # ``q`` is a global FTS match across all content columns. ``intent_q`` is
    # a scoped FTS match against the intent column only — SQLite FTS5 uses
    # the ``column:term`` syntax for this. When both are provided the
    # queries are AND-combined via an additional MATCH (FTS5 supports two
    # MATCH clauses against the same virtual table via two JOINs; simpler
    # here is to merge them into a single MATCH term joined with AND).
    join_sql = ""
    match_terms: list[str] = []
    fts_term = expanded_fts_query(q, exact=exact, require_all=require_all) if q else ""
    if fts_term:
        match_terms.append(fts_term)
    intent_term = _fts_escape(intent_q) if intent_q else ""
    if intent_term:
        # Scope every escaped token to the intent column. ``_fts_escape``
        # returns space-separated quoted phrases (implicit AND); prefixing
        # each with ``intent:`` restricts the match to that column.
        scoped_tokens = [f"intent:{tok}" for tok in intent_term.split(" ") if tok]
        if scoped_tokens:
            match_terms.append(" ".join(scoped_tokens))
    match_filter: tuple[str, list[Any]] | None = None
    if match_terms:
        join_sql = "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id"
        match_filter = ("assessment_command_runs_fts MATCH ?", [" ".join(match_terms)])
        filters.append(match_filter)

    if agent_name:
        filters.append(("r.agent_name = ?", [agent_name]))
    if phase:
        filters.append(("r.phase = ?", [phase]))
    if tool_name:
        filters.append(("r.tool_name = ?", [tool_name]))
    if tool_bin:
        filters.append(("r.tool_bin = ?", [tool_bin]))
    if target_host:
        # Case-insensitive exact match against the parsed target_host column.
        # NULL-tolerant (LOWER(NULL) = NULL, which will not match the literal).
        filters.append(("LOWER(r.target_host) = ?", [target_host.strip().lower()]))
    if auth_context:
        filters.append(("r.auth_context = ?", [auth_context]))
    if audit_source:
        filters.append(("r.audit_source = ?", [audit_source]))
    if route:
        # Provenance-lane filter so host-side katana/httpx coverage is visible.
        # host-exec rows are stamped route='host_exec'; container/kali typed-verb
        # rows are stamped route='vigil assess kali/<tool>'. 'kali' is therefore a
        # prefix match, 'host_exec' an exact match, and any other value an exact
        # match against the stored route string.
        if route == "kali":
            # Transitional back-compat: rows recorded before the aith->vigil
            # rename are stamped route='aith assess kali/<tool>'. Match both
            # the new prefix and the old one so pre-rename rows still return.
            filters.append(
                (
                    "(r.route LIKE 'vigil assess kali/%' OR r.route LIKE 'aith assess kali/%')",
                    [],
                )
            )
        else:
            filters.append(("r.route = ?", [route]))
    if success is not None:
        filters.append(("r.success = ?", [1 if success else 0]))
    if timed_out is not None:
        filters.append(("r.timed_out = ?", [1 if timed_out else 0]))
    if output_attention:
        filters.append(
            (
                "("
                "r.output_retention_status IN "
                "('integrity_failure', 'measurement_conflict', 'partially_measured', "
                "'suppression_deferred', 'untrusted', 'preview_only', 'unmeasured') "
                "OR r.output_cleanup_status IN ('deferred', 'pending', 'warning') "
                "OR r.output_integrity_status IN ('pending', 'warning')"
                ")",
                [],
            )
        )
    if technique:
        filters.append(("r.technique = ?", [technique]))
    if probe_kind:
        filters.append(("r.probe_kind = ?", [probe_kind]))
    if destructive is not None:
        filters.append(("r.destructive = ?", [1 if destructive else 0]))

    base_where = [clause for clause, _ in filters]
    base_params: list[Any] = [param for _, params in filters for param in params]

    sort_value = (sort or "").strip().lower()
    if not sort_value:
        sort_value = "relevance" if match_terms else "recent"
    if sort_value not in {"relevance", "recent", "distant"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid command-run sort: {sort}",
        )

    if sort_value == "distant":
        return _list_distant_command_runs(
            engagement.id,
            q=q,
            filters=filters,
            match_filter=match_filter,
            match_terms=match_terms,
            limit=limit,
            offset=offset,
            include_output=include_output,
            show_matches=show_matches,
            exact=exact,
        )

    params = list(base_params)
    params.extend([int(limit), int(offset)])
    rank_select = (
        ", bm25(assessment_command_runs_fts) AS search_rank" if match_terms else ""
    )
    if sort_value == "relevance" and match_terms:
        order_sql = "ORDER BY search_rank ASC, r.created_at DESC, r.id DESC"
    else:
        order_sql = "ORDER BY r.created_at DESC, r.id DESC"
    query = (
        f"SELECT r.*{rank_select} FROM assessment_command_runs r {join_sql} "
        f"WHERE {' AND '.join(base_where)} "
        f"{order_sql} LIMIT ? OFFSET ?"
    )

    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [
        _serialize_command_run_with_matches(
            row,
            include_output=include_output,
            q=q,
            show_matches=show_matches,
            exact=exact,
        )
        for row in rows
    ]


def foreign_lane_target_facing_recency(
    engagement_id: int, *, current_agent: str
) -> dict[str, int | str | None]:
    """Return all-history foreign target-facing execution timing in one row.

    The advisory is intentionally non-enforcing, but it runs before every
    target-facing sync and async command. Keeping its target-facing predicate
    and count in the command-run service avoids replaying bounded list pages in
    each client execution path.
    """
    engagement = _engagement_or_404(engagement_id)
    query = """
        WITH foreign_target_facing_runs AS (
            SELECT
                r.id,
                CASE
                    WHEN r.started_at IS NOT NULL AND r.started_at != '' THEN r.started_at
                    ELSE r.created_at
                END AS activity_at
            FROM assessment_command_runs AS r
            WHERE r.engagement_id = ?
              AND COALESCE(r.agent_name, '') != ?
              AND CASE
                    WHEN json_valid(r.notes) THEN json_extract(r.notes, '$.target_facing')
                    ELSE 0
                  END = 1
        )
        SELECT
            COUNT(*) AS foreign_count,
            (
                SELECT activity_at
                FROM foreign_target_facing_runs
                WHERE julianday(activity_at) IS NOT NULL
                ORDER BY julianday(activity_at) DESC, id DESC
                LIMIT 1
            ) AS latest_started_at
        FROM foreign_target_facing_runs
    """
    with _common.get_connection() as connection:
        row = connection.execute(query, (engagement.id, current_agent)).fetchone()
    assert row is not None
    return {
        "foreign_count": int(row["foreign_count"]),
        "latest_started_at": row["latest_started_at"],
    }


def _list_distant_command_runs(
    engagement_id: int,
    *,
    q: str,
    filters: list[tuple[str, list[Any]]],
    match_filter: tuple[str, list[Any]] | None,
    match_terms: list[str],
    limit: int,
    offset: int,
    include_output: bool,
    show_matches: bool,
    exact: bool = False,
) -> list[dict[str, Any]]:
    """Return nonmatching rows in the same inferred command scope.

    This is a coverage-gap view: first find direct matches, infer scope from
    their structured fields, then list older/nonmatching command families in
    that scope.
    """

    distant_filters = [
        (clause, list(params))
        for clause, params in filters
        if (clause, params) != match_filter
    ]
    if not distant_filters:
        distant_filters = [("r.engagement_id = ?", [engagement_id])]
    distant_where = [clause for clause, _ in distant_filters]
    distant_params: list[Any] = [p for _, ps in distant_filters for p in ps]

    direct_rows: list[Any] = []
    direct_ids: list[int] = []
    if match_terms:
        base_where = [clause for clause, _ in filters]
        base_params = [p for _, ps in filters for p in ps]
        direct_query = (
            "SELECT r.* FROM assessment_command_runs r "
            "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id "
            f"WHERE {' AND '.join(base_where)} "
            "ORDER BY r.created_at DESC, r.id DESC LIMIT 200"
        )
        with _common.get_connection() as connection:
            direct_rows = connection.execute(
                direct_query, tuple(base_params)
            ).fetchall()
        direct_ids = [int(row["id"]) for row in direct_rows]

    if direct_ids:
        placeholders = ", ".join("?" for _ in direct_ids)
        distant_where.append(f"r.id NOT IN ({placeholders})")
        distant_params.extend(direct_ids)
        scope_clauses: list[str] = []
        for column in ("target_host", "tool_bin", "technique", "probe_kind", "phase"):
            values = sorted(
                {
                    str(row[column] or "")
                    for row in direct_rows
                    if str(row[column] or "").strip()
                }
            )
            if values:
                scope_placeholders = ", ".join("?" for _ in values)
                scope_clauses.append(f"r.{column} IN ({scope_placeholders})")
                distant_params.extend(values)
        if scope_clauses:
            distant_where.append("(" + " OR ".join(scope_clauses) + ")")
    elif match_terms:
        # No direct match means there is no safe inferred scope. Return no
        # distant rows rather than flooding resume output with unrelated runs.
        return []

    distant_params.extend([int(limit), int(offset)])
    query = (
        "SELECT r.* FROM assessment_command_runs r "
        f"WHERE {' AND '.join(distant_where)} "
        "ORDER BY r.created_at ASC, r.id ASC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(distant_params)).fetchall()
    return [
        _serialize_command_run_with_matches(
            row,
            include_output=include_output,
            q=q,
            show_matches=show_matches,
            exact=exact,
        )
        for row in rows
    ]


def _serialize_command_run_with_matches(
    row,
    *,
    include_output: bool,
    q: str,
    show_matches: bool,
    exact: bool = False,
) -> dict[str, Any]:
    data = _serialize_command_run(row, include_output=include_output)
    if show_matches:
        data["matches"] = _command_run_match_reasons(data, q, exact=exact)
    return data


def _command_run_match_reasons(
    row: dict[str, Any], q: str, *, exact: bool = False
) -> list[str]:
    reasons: list[str] = []
    # In exact mode the FTS query is the user's raw phrase only — alias
    # expansion never ran, so attributing the match to an alias would be
    # misleading. Plain-token reasons still apply because the input phrase
    # itself was searched.
    if not exact:
        aliases = finding_aliases_in_text(q)
        if aliases:
            for canonical, values in aliases.items():
                needle_values = {value.lower() for value in values}
                for field in (
                    "command",
                    "tool_name",
                    "tool_bin",
                    "agent_name",
                    "phase",
                    "notes",
                    "intent",
                    "technique",
                    "stdout_suppression_reason",
                    "stderr_suppression_reason",
                    "stdout_artifact_ref",
                    "stderr_artifact_ref",
                ):
                    value = str(row.get(field) or "").lower()
                    if value and any(needle in value for needle in needle_values):
                        reasons.append(f"finding_alias:{canonical}:{field}")
    plain_terms = [term.lower() for term in str(q or "").split() if len(term) >= 3]
    for field in (
        "command",
        "tool_name",
        "tool_bin",
        "agent_name",
        "phase",
        "notes",
        "intent",
        "technique",
    ):
        value = str(row.get(field) or "").lower()
        for term in plain_terms:
            if term in value:
                reasons.append(f"token:{term}:{field}")
                break
    return sorted(set(reasons))


def get_command_run(engagement_id: int, command_run_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(command_run_id)),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="command run not found"
        )
    return _serialize_command_run(row, include_output=True)
