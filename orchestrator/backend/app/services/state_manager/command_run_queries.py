"""Read models and search projections for the command-run audit ledger."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal, get_args
from urllib.parse import urlsplit

from fastapi import HTTPException, status

from ..events import _engagement_or_404
from ..search import (
    fts_escape as _fts_escape_shared,
    expanded_fts_query,
    finding_aliases_in_text,
)
from . import _common
from ..sql_like import like_contains, like_prefix


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
            """SELECT c.*, f.slug AS finding_slug
               FROM assessment_command_runs c
               LEFT JOIN assessment_findings f ON f.id = c.finding_id
                    AND f.engagement_id = c.engagement_id
               WHERE c.engagement_id = ? AND c.id = ?""",
            (engagement.id, int(command_run_id)),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="command run not found"
        )
    data = _serialize_command_run(row, include_output=True)
    data.update(
        _command_run_operator_fields(
            row, str(data.get("command") or ""), [str(arg) for arg in data["argv"]]
        )
    )
    return data


# ── Operator command ledger (paged list, facets, position) ──────────────
#
# ``list_command_runs`` above is the list contract ``vigil assess command-run
# list`` pages. The operator Commands view reads the ledger through the
# functions below instead: server paging with a visible total, facet and scope
# counts over the whole ledger, the one definition of "needs attention", and
# lean rows that drop the ``command``/``argv`` bulk (the point read keeps both).

COMMAND_LEDGER_PAGE_DEFAULT_LIMIT = 100
COMMAND_LEDGER_PAGE_MAX_LIMIT = 500
COMMAND_LEDGER_FACET_DEFAULT_LIMIT = 200
COMMAND_LEDGER_FACET_MAX_LIMIT = 5000
COMMAND_PREVIEW_CHARS = 240

_KNOWN_RUN_STATUSES = tuple(status.value for status in _common.CommandRunStatus)
_KNOWN_RUN_STATUSES_SQL = ", ".join(f"'{value}'" for value in _KNOWN_RUN_STATUSES)

# The lifecycle status a row shows: the durable ``status`` column, or — for rows
# written before it existed — the outcome inferred from ``timed_out``/``success``.
_RUN_STATUS_SQL = (
    f"(CASE WHEN r.status IN ({_KNOWN_RUN_STATUSES_SQL}) THEN r.status "
    "WHEN r.timed_out = 1 THEN 'timed_out' WHEN r.success = 1 THEN 'completed' "
    "ELSE 'failed' END)"
)
_RUN_TOOL_SQL = "COALESCE(NULLIF(r.tool_bin, ''), r.tool_name, '')"

# Status sort order, most urgent first: the operator UI's ``command`` status
# vocabulary order (frontend ``ui/statusTones.ts``). The rank counts down, so a
# descending sort leads with the most urgent and an ascending one with the least;
# a value outside the tuple ranks NULL and sorts last either way.
_RUN_STATUS_URGENCY: tuple[str, ...] = tuple(
    status.value
    for status in (
        _common.CommandRunStatus.FAILED,
        _common.CommandRunStatus.TIMED_OUT,
        _common.CommandRunStatus.KILLED,
        _common.CommandRunStatus.LOST,
        _common.CommandRunStatus.RUNNING,
        _common.CommandRunStatus.QUEUED,
        _common.CommandRunStatus.COMPLETED,
    )
)
assert sorted(_RUN_STATUS_URGENCY) == sorted(_KNOWN_RUN_STATUSES)
_RUN_STATUS_URGENCY_SQL = (
    f"(CASE {_RUN_STATUS_SQL} "
    + " ".join(
        f"WHEN '{value}' THEN {len(_RUN_STATUS_URGENCY) - index}"
        for index, value in enumerate(_RUN_STATUS_URGENCY)
    )
    + " END)"
)


def command_run_status(row: Any) -> str:
    """Python twin of ``_RUN_STATUS_SQL``."""
    value = str(row["status"] or "")
    if value in _KNOWN_RUN_STATUSES:
        return value
    if row["timed_out"]:
        return "timed_out"
    return "completed" if row["success"] else "failed"


# What a lifecycle status means for a run that has not plainly completed.
COMMAND_RUN_STATUS_MEANINGS: dict[str, str] = {
    "queued": "waiting to start",
    "running": "still running",
    "failed": "finished unsuccessfully",
    "timed_out": "stopped at its time limit",
    "killed": "stopped before it finished",
    "lost": "its runner stopped reporting",
}
_INCOMPLETE_OUTPUT_RETENTION = ("measurement_conflict", "partially_measured", "preview_only", "unmeasured")
_UNTRUSTED_OUTPUT_RETENTION = ("integrity_failure", "untrusted")
_UNSETTLED_OUTPUT_INTEGRITY = ("pending", "warning")
_UNSETTLED_OUTPUT_CLEANUP = ("deferred", "pending", "warning")


def _sql_values(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


# "Needs attention": the run did not plainly complete, is not marked
# successful, returned partial results, was superseded, or its output is
# unsettled, untrusted, suppressed or only partly measured.
# ``command_run_attention_reasons`` is the Python twin; both must agree.
_RUN_NEEDS_ATTENTION_SQL = (
    "("
    f"{_RUN_STATUS_SQL} != 'completed' OR COALESCE(r.success, 0) = 0 "
    "OR COALESCE(r.partial_results, 0) = 1 OR r.superseded_by_id IS NOT NULL "
    f"OR lower(COALESCE(r.output_integrity_status, '')) IN ({_sql_values(_UNSETTLED_OUTPUT_INTEGRITY)}) "
    "OR lower(COALESCE(r.output_retention_status, '')) IN "
    f"({_sql_values(_UNTRUSTED_OUTPUT_RETENTION + _INCOMPLETE_OUTPUT_RETENTION)}) "
    "OR lower(COALESCE(r.output_retention_status, '')) GLOB 'suppression_*' "
    f"OR lower(COALESCE(r.output_cleanup_status, '')) IN ({_sql_values(_UNSETTLED_OUTPUT_CLEANUP)})"
    ")"
)


def command_run_attention_reasons(row: Any) -> list[str]:
    """Why a run needs the operator's attention, in plain words; empty when it
    does not. Must agree with ``_RUN_NEEDS_ATTENTION_SQL``."""
    status_value = command_run_status(row)
    retention = str(row["output_retention_status"] or "").lower()
    integrity = str(row["output_integrity_status"] or "").lower()
    cleanup = str(row["output_cleanup_status"] or "").lower()
    reasons: list[str] = []
    if status_value != "completed":
        reasons.append(COMMAND_RUN_STATUS_MEANINGS[status_value])
    elif not row["success"]:
        reasons.append("not marked successful")
    if row["partial_results"]:
        reasons.append("partial results")
    if row["superseded_by_id"] is not None:
        reasons.append(f"superseded by #{row['superseded_by_id']}")
    if integrity in _UNSETTLED_OUTPUT_INTEGRITY:
        reasons.append(f"output integrity {integrity}")
    if (
        retention in _UNTRUSTED_OUTPUT_RETENTION
        or retention in _INCOMPLETE_OUTPUT_RETENTION
        or retention.startswith("suppression_")
    ):
        reasons.append(f"output {retention.replace('_', ' ')}")
    if cleanup in _UNSETTLED_OUTPUT_CLEANUP:
        reasons.append(f"output cleanup {cleanup}")
    return reasons


# ── Target a run hit ──
# The stored ``target_host`` (kali wrappers parse it for high-traffic verbs), or
# a best-effort inference: the first http(s) URL in the command, a common target
# flag, nmap's last positional argument, or a bare host name in argv.
_TARGET_URL_RE = re.compile(r"(https?://[^\s\"']+)", re.IGNORECASE)
_TARGET_FQDN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE
)
_TARGET_FLAGS = ("-u", "--url", "--target", "-t")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _url_host(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return value
    if not hostname:
        return value
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme.lower()):
        return f"{hostname}:{port}"
    return hostname


def _flag_target(value: str) -> str:
    return _url_host(value) if _TARGET_URL_RE.match(value) else value


def command_run_target(command: str, argv: list[str], tool_bin: str, target_host: str) -> tuple[str, str]:
    """``(target, source)`` with source ``stored``, ``inferred`` or ``none``."""
    stored = (target_host or "").strip()
    if stored:
        return stored, "stored"
    match = _TARGET_URL_RE.search(command or "")
    if match:
        return _url_host(match.group(1).rstrip("),.;'\"")), "inferred"
    lowered = [arg.lower() for arg in argv]
    for index, arg in enumerate(lowered):
        if arg in _TARGET_FLAGS and index + 1 < len(argv) and argv[index + 1]:
            return _flag_target(argv[index + 1]), "inferred"
        for flag in _TARGET_FLAGS:
            if arg.startswith(f"{flag}=") and len(arg) > len(flag) + 1:
                return _flag_target(argv[index][len(flag) + 1 :]), "inferred"
    if (tool_bin or "").lower() == "nmap":
        positional = next((arg for arg in reversed(argv[1:]) if not arg.startswith("-")), "")
        if positional:
            return positional, "inferred"
    for arg in argv[1:]:
        if not arg.startswith("-") and _TARGET_FQDN_RE.match(arg):
            return arg, "inferred"
    return "", "none"


def _command_run_operator_fields(row: Any, command: str, argv: list[str]) -> dict[str, Any]:
    reasons = command_run_attention_reasons(row)
    target, target_source = command_run_target(
        command, argv, str(row["tool_bin"] or ""), str(row["target_host"] or "")
    )
    return {
        "needs_attention": bool(reasons),
        "attention_reasons": reasons,
        "target": target,
        "target_source": target_source,
    }


_COMMAND_LEDGER_ROW_COLUMNS = f"""
    r.id, r.engagement_id, r.run_uuid, r.command, r.argv_json, r.tool_name, r.tool_bin,
    {_RUN_TOOL_SQL} AS tool, r.route, r.agent_name, r.phase, r.audit_source, r.status,
    r.return_code, r.timed_out, r.success, r.started_at, r.completed_at, r.duration_ms,
    r.command_hash, r.output_retention_status, r.output_cleanup_status,
    r.output_integrity_status, r.stdout_bytes, r.stderr_bytes, r.created_at,
    r.target_host, r.auth_context, r.superseded_by_id, r.timeout_seconds_requested,
    r.partial_results, r.finding_id, f.slug AS finding_slug, r.technique, r.intent,
    r.probe_kind, r.destructive
"""


def _command_ledger_row(row: Any) -> dict[str, Any]:
    data = dict(row)
    command = str(data.pop("command") or "")
    try:
        argv = json.loads(data.pop("argv_json") or "[]")
    except json.JSONDecodeError:
        argv = []
    argv = [str(arg) for arg in argv] if isinstance(argv, list) else []
    data["status"] = command_run_status(row)
    data["command_preview"] = command[:COMMAND_PREVIEW_CHARS]
    data["command_chars"] = len(command)
    for flag in ("timed_out", "success", "partial_results"):
        data[flag] = bool(data.get(flag))
    if data.get("destructive") is not None:
        data["destructive"] = bool(data["destructive"])
    data.update(_command_run_operator_fields(row, command, argv))
    return data


CommandLedgerSort = Literal[
    "created_at",
    "started_at",
    "completed_at",
    "duration_ms",
    "return_code",
    "status",
    "tool",
    "agent",
    "phase",
    "id",
]
# Public name -> (SQL expression, nullable). A nullable expression sorts its
# missing values last in both directions; anything else is rejected at the route.
_COMMAND_LEDGER_SORTS: dict[str, tuple[str, bool]] = {
    "created_at": ("r.created_at", False),
    "started_at": ("julianday(NULLIF(r.started_at, ''))", True),
    "completed_at": ("julianday(NULLIF(r.completed_at, ''))", True),
    "duration_ms": ("r.duration_ms", False),
    "return_code": ("r.return_code", True),
    "status": (_RUN_STATUS_URGENCY_SQL, True),
    "tool": (f"lower({_RUN_TOOL_SQL})", False),
    "agent": ("lower(COALESCE(r.agent_name, ''))", False),
    "phase": ("lower(COALESCE(r.phase, ''))", False),
    "id": ("r.id", False),
}
assert set(_COMMAND_LEDGER_SORTS) == set(get_args(CommandLedgerSort))

# Facet name -> SQL value. Technique and probe kind are the stored (trimmed)
# values; ``''`` is a run that declared none.
_COMMAND_LEDGER_FACETS: dict[str, str] = {
    "status": _RUN_STATUS_SQL,
    "tool": _RUN_TOOL_SQL,
    "agent": "COALESCE(r.agent_name, '')",
    "technique": "COALESCE(r.technique, '')",
    "probe_kind": "COALESCE(r.probe_kind, '')",
}

# Free search terms match any of these columns (case-insensitive substring), a
# run_uuid or command hash prefix, or ``#<id>``.
_COMMAND_SEARCH_COLUMNS = (
    "r.command",
    "r.tool_name",
    "r.tool_bin",
    "r.agent_name",
    "r.phase",
    "r.route",
    "r.target_host",
    "r.stdout_suppression_reason",
    "r.stderr_suppression_reason",
    "r.notes",
    "r.technique",
    "r.probe_kind",
    "r.intent",
)
COMMAND_SEARCH_SCOPES = (
    "tool",
    "agent",
    "phase",
    "rc",
    "status",
    "target",
    "hash",
    "technique",
    "probe",
    "intent",
    "destructive",
    "write",
)
_SEARCH_TOKEN_RE = re.compile(r'(\S+?:"[^"]*"|"[^"]*"|\S+)')
_RUN_ID_TERM_RE = re.compile(r"^#?(\d+)$")


@dataclass(frozen=True)
class CommandLedgerFilters:
    """Operator ledger filters. Multi-valued dimensions OR within themselves and
    AND across dimensions; ``scope="attention"`` keeps runs that need attention."""

    statuses: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    agents: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    probe_kinds: tuple[str, ...] = ()
    scope: Literal["all", "attention"] = "all"
    q: str = ""

    def facet_values(self) -> dict[str, tuple[str, ...]]:
        """Selected values per ``_COMMAND_LEDGER_FACETS`` name."""
        return {
            "status": self.statuses,
            "tool": self.tools,
            "agent": self.agents,
            "technique": self.techniques,
            "probe_kind": self.probe_kinds,
        }


def _command_search_clauses(q: str) -> tuple[list[str], list[Any]]:
    """The search box grammar: ``scope:value`` tokens (exact match, ``intent`` and
    ``target`` are substrings) and free terms; every token must match."""
    clauses: list[str] = []
    params: list[Any] = []
    for raw in _SEARCH_TOKEN_RE.findall(q or ""):
        token = raw
        if token.startswith('"') and token.endswith('"') and len(token) >= 2:
            token = token[1:-1]
            if token:
                _free_term(token.lower(), clauses, params)
            continue
        scope, separator, value = token.partition(":")
        scope = scope.lower()
        if separator and scope in COMMAND_SEARCH_SCOPES:
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            _scoped_term(scope, value.lower(), clauses, params)
            continue
        _free_term(token.lower(), clauses, params)
    return clauses, params


def _free_term(term: str, clauses: list[str], params: list[Any]) -> None:
    pattern = like_contains(term)
    alternatives = [f"{column} LIKE ? ESCAPE '\\'" for column in _COMMAND_SEARCH_COLUMNS]
    term_params: list[Any] = [pattern] * len(_COMMAND_SEARCH_COLUMNS)
    alternatives.append("r.run_uuid LIKE ? ESCAPE '\\'")
    term_params.append(like_prefix(term))
    id_match = _RUN_ID_TERM_RE.match(term)
    if id_match:
        alternatives.append("r.id = ?")
        term_params.append(int(id_match.group(1)))
    clauses.append("(" + " OR ".join(alternatives) + ")")
    params.extend(term_params)


def _scoped_term(scope: str, value: str, clauses: list[str], params: list[Any]) -> None:
    if scope == "tool":
        clauses.append("(lower(COALESCE(r.tool_bin, '')) = ? OR lower(COALESCE(r.tool_name, '')) = ?)")
        params.extend([value, value])
    elif scope in {"agent", "phase"}:
        column = "r.agent_name" if scope == "agent" else "r.phase"
        clauses.append(f"lower(COALESCE({column}, '')) = ?")
        params.append(value)
    elif scope == "rc":
        clauses.append(
            {
                "0": "(COALESCE(r.timed_out, 0) = 0 AND r.return_code = 0)",
                "!0": "(COALESCE(r.timed_out, 0) = 0 AND r.return_code IS NOT NULL AND r.return_code != 0)",
                "timeout": "r.timed_out = 1",
            }.get(value, "0")
        )
    elif scope == "status":
        if value in {"retained", "empty"}:
            clauses.append("lower(COALESCE(r.output_retention_status, '')) = ?")
        else:
            clauses.append(f"{_RUN_STATUS_SQL} = ?")
        params.append(value)
    elif scope == "target":
        # The inferred target comes from the command text, so a command
        # containing the value is the SQL superset of "its target contains it".
        pattern = like_contains(value)
        clauses.append(
            "(r.target_host LIKE ? ESCAPE '\\' OR "
            "(COALESCE(r.target_host, '') = '' AND r.command LIKE ? ESCAPE '\\'))"
        )
        params.extend([pattern, pattern])
    elif scope == "hash":
        clauses.append("lower(COALESCE(r.command_hash, '')) LIKE ? ESCAPE '\\'")
        params.append(like_prefix(value))
    elif scope in {"technique", "probe"}:
        column = "r.technique" if scope == "technique" else "r.probe_kind"
        clauses.append(f"lower(trim(COALESCE({column}, ''))) = ?")
        params.append(value)
    elif scope == "intent":
        clauses.append("lower(COALESCE(r.intent, '')) LIKE ? ESCAPE '\\'")
        params.append(like_contains(value))
    else:  # destructive / write: NULL (undeclared) never matches either way
        wanted = {"true": 1, "1": 1, "yes": 1, "false": 0, "0": 0, "no": 0}.get(value)
        if wanted is None:
            clauses.append("0")
        else:
            clauses.append("r.destructive = ?")
            params.append(wanted)


def _command_ledger_where(
    engagement_id: int,
    filters: CommandLedgerFilters,
    *,
    exclude: str | None = None,
    ignore_scope: bool = False,
) -> tuple[str, list[Any]]:
    clauses = ["r.engagement_id = ?"]
    params: list[Any] = [engagement_id]

    def any_of(expression: str, values: tuple[str, ...]) -> None:
        clauses.append(f"{expression} IN ({', '.join('?' for _ in values)})")
        params.extend(values)

    for name, values in filters.facet_values().items():
        if values and exclude != name:
            any_of(_COMMAND_LEDGER_FACETS[name], values)
    if filters.scope == "attention" and not ignore_scope:
        clauses.append(_RUN_NEEDS_ATTENTION_SQL)
    search_clauses, search_params = _command_search_clauses(filters.q)
    clauses.extend(search_clauses)
    params.extend(search_params)
    return " AND ".join(clauses), params


def _command_ledger_order(sort: str, direction: str) -> str:
    if sort not in _COMMAND_LEDGER_SORTS or direction not in {"asc", "desc"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported command-run sort")
    expression, nullable = _COMMAND_LEDGER_SORTS[sort]
    sql_direction = direction.upper()
    order = f"{expression} {sql_direction}, r.id {sql_direction}"
    return f"({expression}) IS NULL, {order}" if nullable else order


def _hydrate_command_ledger_rows(connection: Any, ids: list[int]) -> dict[int, dict[str, Any]]:
    if not ids:
        return {}
    rows = connection.execute(
        f"""
        SELECT {_COMMAND_LEDGER_ROW_COLUMNS}
        FROM assessment_command_runs AS r
        LEFT JOIN assessment_findings AS f ON f.id = r.finding_id AND f.engagement_id = r.engagement_id
        WHERE r.id IN ({', '.join('?' for _ in ids)})
        """,
        tuple(ids),
    ).fetchall()
    return {int(row["id"]): _command_ledger_row(row) for row in rows}


def page_command_runs(
    engagement_id: int,
    filters: CommandLedgerFilters,
    *,
    sort: str = "created_at",
    direction: str = "desc",
    limit: int = COMMAND_LEDGER_PAGE_DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """One page of the operator ledger plus the total matching the filters."""
    engagement = _engagement_or_404(engagement_id)
    order = _command_ledger_order(sort, direction)
    limit = max(1, min(int(limit), COMMAND_LEDGER_PAGE_MAX_LIMIT))
    offset = max(0, int(offset))
    where, params = _command_ledger_where(engagement.id, filters)
    with _common.get_connection() as connection:
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM assessment_command_runs AS r WHERE {where}", tuple(params)
            ).fetchone()[0]
        )
        page_ids = [
            int(row[0])
            for row in connection.execute(
                f"SELECT r.id FROM assessment_command_runs AS r WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        ]
        hydrated = _hydrate_command_ledger_rows(connection, page_ids)
    items = [hydrated[run_id] for run_id in page_ids if run_id in hydrated]
    return {
        "total": total,
        "offset": offset,
        "count": len(items),
        "has_more": offset + len(items) < total,
        "items": items,
    }


def command_run_position(
    engagement_id: int,
    command_run_id: int,
    filters: CommandLedgerFilters,
    *,
    sort: str = "created_at",
    direction: str = "desc",
) -> dict[str, Any]:
    """``{index, total, previous, next}``: where one run sits in the page order
    for these filters, with the rows either side (``index`` null when the run
    does not match the filters)."""
    engagement = _engagement_or_404(engagement_id)
    order = _command_ledger_order(sort, direction)
    where, params = _command_ledger_where(engagement.id, filters)
    with _common.get_connection() as connection:
        if connection.execute(
            "SELECT 1 FROM assessment_command_runs WHERE id = ? AND engagement_id = ?",
            (command_run_id, engagement.id),
        ).fetchone() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="command run not found")
        total = int(
            connection.execute(
                f"SELECT COUNT(*) FROM assessment_command_runs AS r WHERE {where}", tuple(params)
            ).fetchone()[0]
        )
        ranked = connection.execute(
            f"""
            WITH ranked AS (
                SELECT r.id AS id, ROW_NUMBER() OVER (ORDER BY {order}) - 1 AS position
                FROM assessment_command_runs AS r
                WHERE {where}
            ),
            target AS (SELECT position FROM ranked WHERE id = ?)
            SELECT ranked.id, ranked.position
            FROM ranked, target
            WHERE ranked.position BETWEEN target.position - 1 AND target.position + 1
            """,
            (*params, command_run_id),
        ).fetchall()
        positions = {int(row[0]): int(row[1]) for row in ranked}
        index = positions.get(command_run_id)
        hydrated = _hydrate_command_ledger_rows(
            connection, [run_id for run_id in positions if run_id != command_run_id]
        )

    def neighbour(step: int) -> dict[str, Any] | None:
        if index is None:
            return None
        return next(
            (hydrated[run_id] for run_id, pos in positions.items() if pos == index + step and run_id in hydrated),
            None,
        )

    return {"index": index, "total": total, "previous": neighbour(-1), "next": neighbour(1)}


def command_run_facets(
    engagement_id: int,
    filters: CommandLedgerFilters,
    *,
    facet_limit: int = COMMAND_LEDGER_FACET_DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Counts behind the Commands filters.

    ``total`` matches the page; each facet ignores its own filter (so a chip
    shows what selecting it would give) but honours the scope, search and the
    other facets; ``scope_totals`` is the "Needs attention N · All N" pair under
    every filter except the scope; ``engagement_totals`` ignores all filters.
    """
    engagement = _engagement_or_404(engagement_id)
    facet_limit = max(1, min(int(facet_limit), COMMAND_LEDGER_FACET_MAX_LIMIT))

    def count(connection: Any, where: str, params: list[Any]) -> int:
        return int(
            connection.execute(
                f"SELECT COUNT(*) FROM assessment_command_runs AS r WHERE {where}", tuple(params)
            ).fetchone()[0]
        )

    def scope_pair(connection: Any, where: str, params: list[Any]) -> dict[str, int]:
        row = connection.execute(
            f"SELECT COUNT(*), COALESCE(SUM({_RUN_NEEDS_ATTENTION_SQL}), 0) "
            f"FROM assessment_command_runs AS r WHERE {where}",
            tuple(params),
        ).fetchone()
        return {"attention": int(row[1] or 0), "all": int(row[0])}

    facets: dict[str, Any] = {}
    with _common.get_connection() as connection:
        where, params = _command_ledger_where(engagement.id, filters)
        total = count(connection, where, params)
        scope_where, scope_params = _command_ledger_where(engagement.id, filters, ignore_scope=True)
        scope_totals = scope_pair(connection, scope_where, scope_params)
        engagement_totals = scope_pair(connection, "r.engagement_id = ?", [engagement.id])
        for name, expression in _COMMAND_LEDGER_FACETS.items():
            facet_where, facet_params = _command_ledger_where(engagement.id, filters, exclude=name)
            rows = connection.execute(
                f"SELECT {expression} AS value, COUNT(*) AS total "
                f"FROM assessment_command_runs AS r WHERE {facet_where} GROUP BY value",
                tuple(facet_params),
            ).fetchall()
            facets[name] = _common._ranked_facet_values([(row["value"], int(row["total"])) for row in rows], facet_limit)
    return {
        "total": total,
        "scope_totals": scope_totals,
        "engagement_totals": engagement_totals,
        "facets": facets,
    }
