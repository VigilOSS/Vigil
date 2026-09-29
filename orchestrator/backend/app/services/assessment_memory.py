from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ..db import get_connection
from . import artifact_index, code_analysis, intel, operator_checkpoints, state_manager
from .events import _engagement_or_404
from .engagement_tracks import track_phases
from .search import canonical_finding_alias


def _read_scope(root: Path) -> dict[str, Any]:
    path = root / "scope.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _json_obj(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _finding_summary(row: Any) -> dict[str, Any]:
    details = _json_obj(row["details_json"] if "details_json" in row.keys() else "")
    return {
        "slug": row["slug"],
        "title": row["title"],
        "severity": row["severity"],
        "workflow_status": row["status"],
        "verification_status": row["verification_status"] or "unreviewed",
        "source_name": row["source_name"] or "",
        "evidence_ref": row["evidence_ref"] or "",
        "chain_required": bool(details.get("chain_required")),
        "chain_rationale": str(details.get("chain_rationale") or "")[:500],
        # Blocked-for-provisioning marker: a disposition='blocked' finding is held
        # OUT of the report and otherwise renders in the brief as a bare
        # active/verified line, so surface WHY it stalled via the required
        # block_reason. Empty for non-blocked findings; bounded so the brief stays
        # compact. Rendered by resume_brief._finding_line via the shared
        # finding_render.blocked_reason_summary helper. The compact projection
        # intentionally carries only the reason; full prerequisite metadata
        # remains available on the finding detail endpoint.
        "block_reason": str(details.get("block_reason") or "")[:300],
        "updated_at": row["updated_at"],
    }


def _limited_findings(
    connection,
    engagement_id: int,
    where_sql: str,
    params: tuple[Any, ...] = (),
    *,
    since: str = "",
    mode: str | None = None,
) -> list[dict[str, Any]]:
    extra_where = ""
    extra_params: tuple[Any, ...] = ()
    if since:
        extra_where = " AND updated_at >= ?"
        extra_params = (since,)
    rows = connection.execute(
        f"""
        SELECT slug, title, severity, status, verification_status,
               source_name, evidence_ref,
               details_json, updated_at
        FROM assessment_findings
        WHERE engagement_id = ? AND {where_sql}{extra_where}{_finding_mode_sql(mode)}
        ORDER BY updated_at DESC, id DESC
        LIMIT 12
        """,
        (engagement_id, *params, *extra_params),
    ).fetchall()
    return [_finding_summary(row) for row in rows]


_DECISION_RENDER_CAP = 10


def _recent_decisions(engagement_id: int, *, since: str = "") -> list[dict[str, Any]]:
    rows = state_manager.list_decisions(engagement_id, limit=10 if not since else 30)
    return _since_filter(rows, since=since, field="created_at")[:_DECISION_RENDER_CAP]


def _decision_count(connection, engagement_id: int, *, since: str = "") -> int:
    """Count the same decision window represented by ``recent_decisions``."""
    if not since:
        return _row_count(connection, "assessment_dispatch_decisions", engagement_id)
    rows = connection.execute(
        "SELECT created_at FROM assessment_dispatch_decisions WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    timestamps = [{"created_at": row["created_at"]} for row in rows]
    return len(_since_filter(timestamps, since=since, field="created_at"))


def _row_count(connection, table: str, engagement_id: int) -> int:
    """Absolute row count for one engagement-scoped table.

    The display lists above are capped, so the renderer needs the TRUE total to
    print an honest "showing N of M" instead of implying the cap is the depth.
    """
    row = connection.execute(
        f"SELECT COUNT(*) AS total FROM {table} WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()
    return int(row["total"]) if row is not None else 0


def _to_naive_utc(value: dt.datetime | None) -> dt.datetime | None:
    """Collapse an aware datetime to offset-naive UTC; pass naive through.

    Row timestamps are a mix: SQLite ``CURRENT_TIMESTAMP`` is offset-naive UTC
    (intel_* tables), while app-written columns are ISO-8601 with a ``Z``
    (offset-aware). A caller-supplied ``--since`` cutoff is likewise often
    ``...Z`` (the documented format). Comparing a naive row to an aware cutoff
    raises ``TypeError``, so normalize both to naive-UTC before comparing —
    correct because the naive DB timestamps are already UTC.
    """
    if value is not None and value.tzinfo is not None:
        return value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return value


def _since_filter(
    rows: list[dict[str, Any]],
    *,
    since: str,
    field: str,
) -> list[dict[str, Any]]:
    """Keep only rows whose ``field`` timestamp is at or after ``since``.

    Rows missing the field stay in the result so a malformed row never
    silently disappears; the caller can investigate. ``since=""`` is a
    no-op pass-through.
    """
    if not since:
        return rows
    cutoff = _to_naive_utc(_parse_iso(since))
    if cutoff is None:
        return rows
    kept: list[dict[str, Any]] = []
    for row in rows:
        ts_raw = row.get(field)
        if not ts_raw:
            kept.append(row)
            continue
        parsed = _to_naive_utc(_parse_iso(ts_raw))
        if parsed is None or parsed >= cutoff:
            kept.append(row)
    return kept


# Roles whose dispatches legitimately run longer than a normal recon/test
# pass. The default per-role threshold is consulted only when the caller
# does not pin --max-age-hours; an explicit override always wins.
_STALE_THRESHOLD_BY_ROLE: dict[str, float] = {
    "exploit-developer": 48.0,
    "report-writer": 48.0,
    "code-architect": 48.0,
    "code-vuln-hunter": 48.0,
    "code-variant-hunter": 48.0,
    "code-vuln-verifier": 48.0,
    "code-fuzz-engineer": 72.0,
}
_DEFAULT_STALE_THRESHOLD_HOURS = 24.0
_KNOWLEDGE_DRIFT_LIMIT = 10


def _stale_threshold_for(role: str | None, *, override: float | None) -> float:
    if override is not None:
        return float(override)
    return _STALE_THRESHOLD_BY_ROLE.get(str(role or ""), _DEFAULT_STALE_THRESHOLD_HOURS)


# A dispatch that lands on any terminal status with no
# handoff row at all is silent state-loss — there is no artifact explaining
# why it died, and (pre-fix) it was structurally invisible to this picture
# because the in-progress-only gate below excluded it before the handoff-gap
# check ever ran. `_TERMINAL_NO_HANDOFF_STATUSES` is the scope for the new
# `terminal_no_handoff` list; keep it in sync with the `agent.py`
# `_reconcile_stale` mirror (which reports the same rows read-only, since a
# handoff-less terminal dispatch has no ready/blocked handoff to close).
_TERMINAL_NO_HANDOFF_STATUSES = frozenset(
    {"completed", "blocked", "failed", "aborted"}
)

# The single NON-terminal dispatch status, and so the one the stale and
# handoff-gap checks apply to. Named beside the terminal set because one scan
# now walks every dispatch and splits it on exactly this distinction.
_IN_PROGRESS_STATUS = "in-progress"

# Every list this picture publishes is cut to this many rows, and the TRUE total
# rides alongside as `*_count` — the "capped list + absolute count" pattern used
# elsewhere in the brief (blocked_techniques_count). The detection scans below
# are deliberately NOT capped: the cut decides what an operator is shown, never
# what was measured.
_DISPATCH_LIST_RENDER_CAP = 10


def _dispatch_lifecycle_rows(connection, engagement_id: int) -> list[Any]:
    """Every dispatch of one engagement, worst-first, lifecycle columns only.

    Exhaustive on purpose. No row cap is honest here: "stale" is a per-role age
    threshold and "no handoff" is a join, so neither the worklists nor their
    counts can be derived from a page — and the page this read used to take
    (newest 1,000 by `dispatched_at`) cut the OLDEST rows, which is precisely
    what stale means. `agent.py:_reconcile_stale`, the command this picture must
    agree with, pages the same row set to exhaustion for the same reason.

    Ordered oldest-first because `_DISPATCH_LIST_RENDER_CAP`, not the scan, now
    decides which rows reach the operator: the ten longest-overdue dispatches
    are the ten worth showing, where newest-first would have shown the ten that
    only just crossed their threshold.

    Only the lifecycle columns are read, so exhaustive stays cheap — the full
    dispatch projection carries a client-binding join and the task prose that
    none of this needs.
    """
    return connection.execute(
        """
        SELECT agent_id, agent_role, dispatched_at, completed_at, status
        FROM assessment_dispatches
        WHERE engagement_id = ?
        ORDER BY dispatched_at ASC, id ASC
        """,
        (engagement_id,),
    ).fetchall()


def _handoff_status_by_agent(connection, engagement_id: int) -> dict[str, str]:
    """Handoff status for every agent of one engagement, keyed by ``agent_id``.

    Exhaustive for a harder reason than the dispatch scan: ABSENCE from this map
    is what the brief reports as a `handoff_gap`, so a partial map does not
    merely lose a row — it invents a gap for a specialist that had checkpointed.
    The scan it replaces was a top-1,000 page ordered by checkpoint, which put
    exactly the quietest live workers on the wrong side of the cut.

    `agent_id` is UNIQUE per engagement, so the key is total; presence is what
    the callers test, and the status is read only for a stale row's label.
    """
    return {
        str(row["agent_id"]): str(row["handoff_status"] or "")
        for row in connection.execute(
            "SELECT agent_id, handoff_status FROM assessment_dispatch_handoffs "
            "WHERE engagement_id = ?",
            (engagement_id,),
        )
    }


def _reconciled_agent_ids(connection, engagement_id: int) -> set[str]:
    """Agents whose empty-handed exit an operator has already adjudicated.

    A `dispatch_reconciliation` decision is the durable ruling that a worker
    genuinely produced no handoff, so its dispatch leaves the terminal worklist
    without anything fabricating a handoff for it.
    """
    rows = connection.execute(
        """
        SELECT payload_json
        FROM assessment_dispatch_decisions
        WHERE engagement_id = ? AND kind = 'dispatch_reconciliation'
        """,
        (engagement_id,),
    ).fetchall()
    agent_ids: set[str] = set()
    for row in rows:
        payload = _json_obj(row["payload_json"])
        if payload.get("agent_id"):
            agent_ids.add(str(payload["agent_id"]))
    return agent_ids


def _dispatch_in_mode(role: str | None, mode: str | None) -> bool:
    if mode not in {"web", "code"}:
        return True
    is_code = str(role or "").startswith("code-")
    return is_code if mode == "code" else not is_code


def _recent_dispatch_picture(
    engagement_id: int,
    *,
    max_age_hours: float | None,
    mode: str | None = None,
) -> dict[str, Any]:
    # Detection and its counts come from ONE connection, so the worklists and
    # the totals beside them describe the same instant: a handoff written
    # between two separate reads could otherwise erase a gap from the list while
    # leaving it in the count.
    with get_connection() as connection:
        lifecycle_rows = [
            row for row in _dispatch_lifecycle_rows(connection, engagement_id)
            if _dispatch_in_mode(row["agent_role"], mode)
        ]
        handoff_status_by_agent = _handoff_status_by_agent(connection, engagement_id)
        reconciled_agent_ids = _reconciled_agent_ids(connection, engagement_id)
        dispatch_total = len(lifecycle_rows)
        if mode in {"web", "code"}:
            role_filter = "LIKE 'code-%'" if mode == "code" else "NOT LIKE 'code-%'"
            handoff_total = int(connection.execute(
                f"SELECT COUNT(*) FROM assessment_dispatch_handoffs WHERE engagement_id = ? AND agent_role {role_filter}",
                (engagement_id,),
            ).fetchone()[0])
        else:
            handoff_total = _row_count(connection, "assessment_dispatch_handoffs", engagement_id)

    now = dt.datetime.now(dt.timezone.utc)
    stale: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    closable_handoffs: list[dict[str, Any]] = []
    # Terminal dispatch with no handoff row = silent state-loss: nothing durable
    # explains why the worker died. A `dispatch_reconciliation` decision takes an
    # honestly-empty worker off this worklist without fabricating a handoff.
    terminal_no_handoff: list[dict[str, Any]] = []
    for row in lifecycle_rows:
        agent_id = str(row["agent_id"] or "")
        agent_role = row["agent_role"]
        row_status = str(row["status"] or "")
        handoff_status = handoff_status_by_agent.get(agent_id)
        if row_status == _IN_PROGRESS_STATUS:
            if handoff_status in {"ready", "blocked"}:
                closable_handoffs.append(
                    {"agent_id": agent_id, "agent_role": agent_role,
                     "handoff_status": handoff_status}
                )
            # In-progress with no handoff = running but not yet checkpointed.
            if handoff_status is None:
                gaps.append(
                    {"agent_id": agent_id, "agent_role": agent_role, "reason": "no_handoff"}
                )
            started = _parse_iso(row["dispatched_at"])
            age_hours = ((now - started).total_seconds() / 3600.0) if started else None
            threshold = _stale_threshold_for(agent_role, override=max_age_hours)
            if age_hours is not None and age_hours >= threshold:
                stale.append(
                    {
                        "agent_id": agent_id,
                        "agent_role": agent_role,
                        "age_hours": round(age_hours, 2),
                        "handoff_status": handoff_status or "none",
                        "threshold_hours": threshold,
                    }
                )
        elif row_status in _TERMINAL_NO_HANDOFF_STATUSES:
            if handoff_status is not None or agent_id in reconciled_agent_ids:
                continue
            terminal_no_handoff.append(
                {
                    "agent_id": agent_id,
                    "agent_role": agent_role,
                    "status": row_status,
                    "completed_at": row["completed_at"],
                }
            )

    # The reported `stale_threshold_hours` is the override if set, else the
    # default — per-role thresholds applied per dispatch are also visible on
    # each stale entry's `threshold_hours`.
    reported_threshold = (
        float(max_age_hours) if max_age_hours is not None else _DEFAULT_STALE_THRESHOLD_HOURS
    )
    # Every list is cut to the render cap and every `*_count` beside it is the
    # engagement's TRUE total, so the renderer prints an honest "showing N of M"
    # and the operator is pointed at `reconcile-stale` (wired in
    # `_recommended_actions`) for the full list plus the action.
    #
    # The two display lists are fetched AT the cap rather than sliced down to it:
    # both orderings are the query's, so asking for more rows than are shown only
    # decides which rows get thrown away. "Latest handoffs" means most recently
    # CHECKPOINTED, not most recently created — `created_at` is immutable and
    # `update_handoff` moves only `last_checkpoint_at`, so a creation-ordered
    # query cuts a just-checkpointed old handoff out of the window entirely, and
    # no re-sort afterwards can recover a row the LIMIT already dropped.
    return {
        "recent_dispatches": state_manager.list_dispatches(
            engagement_id, limit=_DISPATCH_LIST_RENDER_CAP,
            role_prefix="code-" if mode == "code" else "",
            exclude_role_prefix="code-" if mode == "web" else "",
        ),
        "recent_dispatches_count": dispatch_total,
        "latest_handoffs": state_manager.list_handoffs(
            engagement_id, sort="checkpoint", limit=_DISPATCH_LIST_RENDER_CAP,
            role_prefix="code-" if mode == "code" else "",
            exclude_role_prefix="code-" if mode == "web" else "",
        ),
        "latest_handoffs_count": handoff_total,
        "stale_in_progress_dispatches": stale[:_DISPATCH_LIST_RENDER_CAP],
        "stale_in_progress_dispatches_count": len(stale),
        "handoff_gaps": gaps[:_DISPATCH_LIST_RENDER_CAP],
        "handoff_gaps_count": len(gaps),
        "closable_handoffs": closable_handoffs[:_DISPATCH_LIST_RENDER_CAP],
        "closable_handoffs_count": len(closable_handoffs),
        "terminal_no_handoff": terminal_no_handoff[:_DISPATCH_LIST_RENDER_CAP],
        "terminal_no_handoff_count": len(terminal_no_handoff),
        "stale_threshold_hours": reported_threshold,
        "stale_threshold_role_overrides": dict(_STALE_THRESHOLD_BY_ROLE) if max_age_hours is None else {},
    }


def _parse_iso(value: Any) -> dt.datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finding_mode_sql(mode: str | None) -> str:
    if mode == "code":
        return " AND canonical_location LIKE 'file:%'"
    if mode == "web":
        return " AND COALESCE(canonical_location, '') NOT LIKE 'file:%'"
    return ""


def _counts(connection, engagement_id: int, *, mode: str | None = None) -> dict[str, dict[str, int]]:
    rows = connection.execute(
        f"""
        SELECT status, verification_status, severity, source_name
        FROM assessment_findings
        WHERE engagement_id = ?{_finding_mode_sql(mode)}
        """,
        (engagement_id,),
    ).fetchall()
    workflow = Counter(str(row["status"] or "draft") for row in rows)
    verification = Counter(str(row["verification_status"] or "unreviewed") for row in rows)
    severity = Counter(str(row["severity"] or "info") for row in rows)
    source = Counter(str(row["source_name"] or "unknown") for row in rows)
    return {
        "workflow": dict(workflow),
        "verification_status": dict(verification),
        "severity": dict(severity),
        "source": dict(source),
    }


# A surface (and likewise a coverage item) is conclusively retired only when it
# is ``covered`` or ruled ``not_applicable`` — mirrors the depth-ledger rule in
# state_manager/depth_ledger.py. Everything else is still open work the operator
# should see on resume. ``discovered`` / ``partially-covered`` / ``deferred`` all
# want attention, ranked in that order (deferred = decided-skip, lowest).
_RETIRED_SURFACE_STATUSES = frozenset({"covered", "not_applicable"})
_RETIRED_COVERAGE_STATUSES = frozenset({"covered", "not_applicable", "not-applicable"})
_UNCOVERED_SURFACE_PRIORITY = {"discovered": 0, "partially-covered": 1, "deferred": 2}
_TOP_UNCOVERED_SURFACE_LIMIT = 6

# Free-text intel-note tags that mark a note "read me on resume". The brief
# surfaces these by title so coverage maps and read-first context are not lost
# in the plain-note pile (they are otherwise invisible to the brief).
_RESUME_NOTE_TAGS = frozenset({"coverage", "read-first"})
_RESUME_NOTE_LIMIT = 8

# "Do-today" attempt ledger surfacing (P1-C). The Attempts section pulls two
# already-persisted but previously resume-invisible signals so the operator
# reads what has been TRIED-AND-WALLED-OFF before re-dispatching the same
# surface: recorded blocked techniques and findings flagged roe_blocked in
# details_json. (Per-input probe coverage moved to its own Per-Input Coverage
# section — see _per_input_coverage_section.) Each list is bounded (pointers +
# counts, never bodies) consistent with the other sections.
_ATTEMPTS_ROW_LIMIT = 8
# The covering subset mirrors state_manager.coverage.PROBE_RESULT_STATUSES_
# COVERING; a probe run outside it (blocked / no-signal / attempted / error) is
# an attempt that did NOT establish coverage. Used by the Per-Input Coverage
# grid to mark a cell covering vs non-covering. Kept as a local literal (the
# brief must not depend on the coverage module) but pinned to the same values.
_PROBE_COVERING_STATUSES = ("tested", "signal")

# Per-Input Coverage grid (WS2). A generated per-(host × path × attack_family ×
# input_slot × auth_context) view over assessment_probe_runs — the queryable
# "which input was tested for which class, as which identity" surface that the
# named `--input-slot slot:name` convention produces. _FETCH scans a recent
# window to build cells; _ROW caps the cells returned (bounded like every other
# worklist). The absolute distinct-cell total is reported separately so a capped
# grid still signals true breadth.
_PER_INPUT_FETCH_LIMIT = 400
_PER_INPUT_ROW_LIMIT = 20


def _surfaces_section(connection, engagement_id: int) -> dict[str, Any]:
    """Surface coverage rollup for the resume brief (gap #1 root fix).

    Counts every recorded surface by status and by (status, surface_type), and
    samples the most actionable still-open surfaces. Counts are an absolute
    snapshot (like finding_counts), so they are NOT since-filtered.
    """
    rows = connection.execute(
        """
        SELECT status, surface_type, target_descriptor, source_name
        FROM assessment_surfaces
        WHERE engagement_id = ?
        ORDER BY updated_at DESC, id DESC
        """,
        (engagement_id,),
    ).fetchall()
    by_status: Counter = Counter()
    status_type: Counter = Counter()
    # (priority, recency_index, sample) so the most actionable + most recently
    # touched open surfaces sort to the front. Rows arrive updated_at DESC, so a
    # smaller index is more recent.
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    for index, row in enumerate(rows):
        status_value = str(row["status"] or "discovered")
        surface_type = str(row["surface_type"] or "unknown")
        by_status[status_value] += 1
        status_type[(status_value, surface_type)] += 1
        if status_value not in _RETIRED_SURFACE_STATUSES:
            candidates.append(
                (
                    _UNCOVERED_SURFACE_PRIORITY.get(status_value, 3),
                    index,
                    {
                        "status": status_value,
                        "surface_type": surface_type,
                        "target_descriptor": str(row["target_descriptor"] or ""),
                        "source_name": str(row["source_name"] or ""),
                    },
                )
            )
    candidates.sort(key=lambda item: (item[0], item[1]))
    open_count = sum(
        count for status_value, count in by_status.items()
        if status_value not in _RETIRED_SURFACE_STATUSES
    )
    return {
        "total": sum(by_status.values()),
        "open_count": open_count,
        "by_status": dict(by_status),
        "by_status_type": [
            {"status": status_value, "surface_type": surface_type, "count": count}
            for (status_value, surface_type), count in sorted(status_type.items())
        ],
        "top_uncovered": [item[2] for item in candidates[:_TOP_UNCOVERED_SURFACE_LIMIT]],
    }


def _work_buffer_section(connection, engagement_id: int) -> dict[str, Any]:
    """Pending work-buffer rollup keyed by gf-bucket cluster (gap #2).

    Reads the real dispatch queue (``assessment_work_items``) — the transient
    triage buffer folded into the backend ledger (ADR 0013) — rather than a
    coverage-item proxy. A row is pending work until it is claimed / done /
    skipped / deferred; rows carrying a ``terminal_reason`` are excluded. Keyed
    by ``cluster_key`` (the gf-bucket identity, e.g. ``gf:trust_surface``),
    falling back to ``type:<type>`` when unclustered. Counts are an absolute
    snapshot, NOT since-filtered. ``by_bucket`` is ordered by descending count.
    """
    rows = connection.execute(
        "SELECT cluster_key, type, status, terminal_reason "
        "FROM assessment_work_items WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    by_bucket: Counter = Counter()
    for row in rows:
        status_value = str(row["status"] or "pending").strip().lower()
        if status_value != "pending":
            continue
        if row["terminal_reason"]:
            continue
        key = row["cluster_key"] or f"type:{row['type'] or 'unknown'}"
        by_bucket[str(key)] += 1
    return {
        "pending_total": sum(by_bucket.values()),
        "by_bucket": dict(by_bucket.most_common()),
    }


def _resume_note_pointers(engagement_id: int, *, since: str) -> list[dict[str, Any]]:
    """Intel notes tagged ``coverage`` / ``read-first`` — projected as bounded
    pointers (id + title + matching tags + lead_status), not bodies, so the
    operator opens them via intel list/search. Bounded list, so since-filtered
    like the other intel worklists."""
    matches: list[dict[str, Any]] = []
    for row in intel.list_notes(engagement_id, include_superseded=False):
        tags = row.get("tags")
        if not isinstance(tags, list):
            continue
        tag_set = {str(tag).strip().lower() for tag in tags}
        hit = tag_set & _RESUME_NOTE_TAGS
        if not hit:
            continue
        matches.append(
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "tags": sorted(hit),
                "lead_status": row.get("lead_status") or "",
                "updated_at": row.get("updated_at"),
            }
        )
    return _since_filter(matches, since=since, field="updated_at")[:_RESUME_NOTE_LIMIT]


def _knowledge_drift_section(engagement_id: int) -> dict[str, Any]:
    """Project the existing unlinked-markdown detector into session start.

    Report readiness remains the detector owner. Resume carries a bounded,
    advisory-only view so accumulated prose is visible without becoming a new
    readiness gate. A detector failure is also explicit rather than falsely
    presenting an empty drift set.
    """
    try:
        readiness = state_manager.report_readiness(engagement_id)
    except Exception as exc:  # noqa: BLE001 - resume degrades for advisory data.
        return {
            "classification": "advisory",
            "detector_status": "unavailable",
            "detector_detail": str(exc)[:500],
            "unlinked_markdown_note_count": None,
            "unlinked_markdown_notes": [],
            "truncated": False,
        }
    advisories = readiness.get("advisories")
    rows = (
        [
            {
                "kind": "unlinked_markdown_note",
                "artifact_id": row.get("artifact_id"),
                "path": str(row.get("path") or "")[:500],
                "detail": str(row.get("detail") or "")[:1000],
            }
            for row in advisories
            if isinstance(row, dict) and row.get("kind") == "unlinked_markdown_note"
        ]
        if isinstance(advisories, list)
        else []
    )
    return {
        "classification": "advisory",
        "detector_status": "complete",
        "unlinked_markdown_note_count": len(rows),
        "unlinked_markdown_notes": rows[:_KNOWLEDGE_DRIFT_LIMIT],
        "truncated": len(rows) > _KNOWLEDGE_DRIFT_LIMIT,
    }


def _attempts_section(connection, engagement_id: int, *, since: str) -> dict[str, Any]:
    """Do-today attempt ledger (P1-C) — two already-persisted signals that the
    brief never surfaced, so a re-dispatch could unknowingly retry a walled-off
    surface.

    - ``blocked_techniques``: recent ``assessment_blocked_techniques`` rows
      (wires the previously CLI-less table into resume).
    - ``roe_blocked_findings``: findings whose ``details_json`` has
      ``roe_blocked`` set true (value-aware json_extract, mirroring the
      chain_required predicate). Projected as finding pointers.

    Per-input probe coverage (the old ``noncovering_probe_runs`` flat list) moved
    to :func:`_per_input_coverage_section`, which groups covering AND non-covering
    probes by (host × path × class × input × identity) — a richer view of the
    same rows, so the brief does not render probe data twice.

    Each list is bounded and, where the row carries a timestamp, since-filtered.
    Counts are the pre-truncation totals so a truncated list still signals depth.
    """
    blocked_rows = connection.execute(
        """
        SELECT id, technique_key, technique, target_kind, target_ref,
               reason, retry_state, evidence_ref, notes, updated_at
        FROM assessment_blocked_techniques
        WHERE engagement_id = ?
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, _ATTEMPTS_ROW_LIMIT * 3),
    ).fetchall()
    blocked_techniques = _since_filter(
        [
            {
                "id": row["id"],
                "technique_key": row["technique_key"],
                "technique": row["technique"],
                "target_kind": row["target_kind"] or "",
                "target_ref": row["target_ref"] or "",
                "reason": str(row["reason"] or "")[:300],
                "retry_state": row["retry_state"] or "",
                "evidence_ref": row["evidence_ref"] or "",
                "notes": str(row["notes"] or "")[:300],
                "updated_at": row["updated_at"],
            }
            for row in blocked_rows
        ],
        since=since,
        field="updated_at",
    )[:_ATTEMPTS_ROW_LIMIT]

    roe_blocked_findings = _limited_findings(
        connection,
        engagement_id,
        "json_extract(details_json,'$.roe_blocked') = 1",
        since=since,
    )

    # Counts are absolute totals (like finding_counts), not len() of the
    # truncated lists — so a list capped at _ATTEMPTS_ROW_LIMIT still signals the
    # true depth of walled-off work a re-dispatch must not blindly retry.
    blocked_total = connection.execute(
        "SELECT COUNT(*) FROM assessment_blocked_techniques WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()[0]
    roe_blocked_total = connection.execute(
        "SELECT COUNT(*) FROM assessment_findings "
        "WHERE engagement_id = ? AND json_extract(details_json,'$.roe_blocked') = 1",
        (engagement_id,),
    ).fetchone()[0]

    return {
        "blocked_techniques": blocked_techniques,
        "blocked_techniques_count": blocked_total,
        "roe_blocked_findings": roe_blocked_findings,
        "roe_blocked_findings_count": roe_blocked_total,
    }


def _per_input_coverage_section(
    connection, engagement_id: int, *, since: str, row_limit: int = _PER_INPUT_ROW_LIMIT
) -> dict[str, Any]:
    """Per-input coverage grid (WS2) — the generated, queryable answer to "which
    input was tested for which class, as which identity, and did it hit a wall".

    Groups ``assessment_probe_runs`` by
    ``(target_host, target_path, attack_family, input_slot, auth_context)`` and
    reports, per cell: the probe count, whether any probe was COVERING
    (tested/signal) vs only non-covering (attempted/blocked/no-signal/error), the
    latest ``result_status``, the latest non-null ``observed_http_status`` (the
    403/auth-wall signal — previously an orphan column read by nothing), and the
    latest non-empty ``lens``.

    Both covering and non-covering probes are included: the grid is a true
    coverage view (what WAS tested), not just a dead-ends ledger. It supersedes
    the old flat ``noncovering_probe_runs`` list in :func:`_attempts_section` — the
    same rows, grouped, so the brief never renders probe data twice.

    Bounded like every other worklist: a recent window of rows is scanned to build
    cells, the cell list is capped, and the ABSOLUTE distinct-cell total (not
    since-filtered) is reported so a capped grid still signals true breadth. The
    cell list itself is since-filtered — a cell only appears if it has a probe in
    the window — so a future ``--since`` cutoff yields no cells.
    """
    # ``row_limit <= 0`` is the ``--all-cells`` escape valve: it must see EVERY
    # probe run, not just the newest _PER_INPUT_FETCH_LIMIT. Capping the source
    # query unconditionally would silently drop older cells from the grid while
    # ``cells_count`` (uncapped, below) still reported them — sending operators
    # back to already-covered inputs. Only bound the fetch for the sampled path.
    fetch_sql = """
        SELECT id, attack_family, result_status, tool_name,
               target_host, target_path, input_slot, auth_context, lens,
               observed_http_status, evidence_ref, created_at
        FROM assessment_probe_runs
        WHERE engagement_id = ?
        ORDER BY created_at DESC, id DESC
    """
    if row_limit <= 0:
        rows = connection.execute(fetch_sql, (engagement_id,)).fetchall()
    else:
        rows = connection.execute(
            fetch_sql + "        LIMIT ?\n",
            (engagement_id, _PER_INPUT_FETCH_LIMIT),
        ).fetchall()
    probes = _since_filter(
        [
            {
                "id": row["id"],
                "attack_family": row["attack_family"] or "",
                "result_status": row["result_status"] or "",
                "tool_name": row["tool_name"] or "",
                "target_host": row["target_host"] or "",
                "target_path": row["target_path"] or "",
                "input_slot": row["input_slot"] or "",
                "auth_context": row["auth_context"] or "",
                "lens": row["lens"] or "",
                "observed_http_status": row["observed_http_status"],
                "evidence_ref": row["evidence_ref"] or "",
                "created_at": row["created_at"],
            }
            for row in rows
        ],
        since=since,
        field="created_at",
    )

    # Group into cells. Rows are DESC by created_at, so the FIRST time a cell key
    # is seen is its most-recent probe — dict insertion order is therefore
    # recency-of-latest-activity, and the "latest_*" fields take the first
    # (most-recent) non-empty value encountered.
    cells: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for probe in probes:
        key = (
            probe["target_host"],
            probe["target_path"],
            probe["attack_family"],
            probe["input_slot"],
            probe["auth_context"],
        )
        covering = probe["result_status"] in _PROBE_COVERING_STATUSES
        cell = cells.get(key)
        if cell is None:
            cell = {
                "target_host": probe["target_host"],
                "target_path": probe["target_path"],
                "attack_family": probe["attack_family"],
                "input_slot": probe["input_slot"],
                "auth_context": probe["auth_context"],
                "count": 0,
                "covering": False,
                "latest_status": probe["result_status"],
                "observed_http_status": None,
                "lens": "",
                "evidence_ref": "",
            }
            cells[key] = cell
        cell["count"] += 1
        if covering:
            cell["covering"] = True
        if cell["observed_http_status"] is None and probe["observed_http_status"] is not None:
            cell["observed_http_status"] = probe["observed_http_status"]
        if not cell["lens"] and probe["lens"]:
            cell["lens"] = probe["lens"]
        if not cell["evidence_ref"] and covering and probe["evidence_ref"]:
            cell["evidence_ref"] = probe["evidence_ref"]

    all_cells = list(cells.values())
    # ``row_limit <= 0`` returns every cell (the resume-brief ``--all-cells``
    # escape valve for the ~790-cell case); a positive limit caps the sample. The
    # absolute total below still reports true breadth regardless of the cap.
    cell_list = all_cells if row_limit <= 0 else all_cells[:row_limit]

    # NOT since-filtered, unlike the cell list above.
    total_cells = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT DISTINCT target_host, target_path, attack_family, input_slot, auth_context
            FROM assessment_probe_runs
            WHERE engagement_id = ?
        )
        """,
        (engagement_id,),
    ).fetchone()[0]

    return {"cells": cell_list, "cells_count": total_cells}


# A resumed session must see a code dispatch that stopped mid-file. Its lease is
# still held and its receipts are still current, so nothing in the finding,
# surface or dispatch sections reports it — and `reset-stale`, the obvious
# recovery, would throw those receipts away. Bounded like every other worklist:
# a capped list beside the absolute count.
_OPEN_LEASE_RENDER_CAP = 10


def _code_analysis_section(
    engagement_id: int, code_enabled: bool, current_code_phase: str
) -> dict[str, Any]:
    """Project the existing code gate, queue, and repository identities."""
    section = code_analysis.open_authoring_leases(
        engagement_id, limit=_OPEN_LEASE_RENDER_CAP
    )
    repos = code_analysis.list_code_repos(engagement_id)
    if not code_enabled and not repos:
        return section
    coverage = code_analysis.code_coverage_summary(engagement_id)
    confidence = coverage.get("confidence") or {}
    triggers = coverage.get("trigger_summary") or {}
    coverage_gate = coverage.get("gate") or {}
    coverage_by_classification = {}
    for classification, counts in (coverage.get("by_classification") or {}).items():
        if not isinstance(counts, dict):
            continue
        total = int(counts.get("count") or 0)
        analyzed = int(counts.get("analyzed") or 0)
        coverage_by_classification[str(classification)] = {
            "count": total,
            "analyzed": analyzed,
            "remaining": max(0, total - analyzed),
        }
    readiness_target = code_analysis.next_code_readiness_phase(current_code_phase)
    readiness = (
        code_analysis.code_readiness(
            engagement_id, target_phase=readiness_target
        )
        if readiness_target
        else None
    )
    section.update({
        "queue_count": int(confidence.get("active_queue_items") or 0),
        "coverage_by_classification": coverage_by_classification,
        "trigger_counts": {
            "pending": int(triggers.get("pending") or 0),
            "queued": int(triggers.get("queued") or 0),
        },
        "coverage_gate": {
            "passed": coverage_gate.get("passed") is True,
            "reasons": list(coverage_gate.get("reasons") or []),
        },
        "next_gate": None if readiness is None else {
            "target_phase": readiness_target,
            "transition_ready": readiness.get("transition_ready") is True,
            "blocker_codes": [
                str(row.get("code")) for row in readiness.get("blockers", [])
                if isinstance(row, dict) and row.get("code")
            ],
            "structural_debt_count": int(
                readiness.get("structural_debt_count") or 0
            ),
        },
        "reference_repos": [
            {"repo_id": row.get("id"), "repo_key": row.get("repo_key"),
             "repo_generation": row.get("active_generation")}
            for row in repos if row.get("repo_role") == "reference"
        ][:10],
        "reference_repos_count": sum(
            row.get("repo_role") == "reference" for row in repos
        ),
    })
    return section


def _cross_track_pointer(connection, engagement_id: int, *, mode: str, phases: dict[str, str]) -> dict[str, Any]:
    other = "code" if mode == "web" else "web"
    if other not in phases:
        return {}
    where = _finding_mode_sql(other)
    count = int(connection.execute(
        f"SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ?{where}",
        (engagement_id,),
    ).fetchone()[0])
    rows = connection.execute(
        f"""SELECT slug, title, severity, status FROM assessment_findings
            WHERE engagement_id = ?{where}
            ORDER BY updated_at DESC, id DESC LIMIT 5""",
        (engagement_id,),
    ).fetchall()
    return {
        "track": other,
        "phase": phases[other],
        "finding_count": count,
        "finding_pointers": [
            {"slug": row["slug"], "title": row["title"],
             "severity": row["severity"], "workflow_status": row["status"]}
            for row in rows
        ],
        "read_command": f"vigil assess resume-brief --mode {other}",
        "shared_unattributed_sections": [
            "attempts", "command_runs", "artifacts", "recent_decisions", "intel"
        ],
    }


def _credential_needs_section(connection, engagement_id: int) -> dict[str, Any]:
    """Bounded owner queue from unresolved dispatch decisions and blocked findings."""
    decisions = connection.execute(
        "SELECT id, payload_json FROM assessment_dispatch_decisions "
        "WHERE engagement_id = ? AND kind = 'dispatch_blocked' AND resolved = 0 "
        "ORDER BY created_at DESC, id DESC LIMIT 10",
        (engagement_id,),
    ).fetchall()
    findings = connection.execute(
        "SELECT slug, title, severity, details_json FROM assessment_findings "
        "WHERE engagement_id = ? AND verification_status = 'blocked' "
        "ORDER BY updated_at DESC, id DESC LIMIT 10",
        (engagement_id,),
    ).fetchall()
    count = connection.execute(
        "SELECT (SELECT COUNT(*) FROM assessment_dispatch_decisions WHERE engagement_id = ? "
        "AND kind = 'dispatch_blocked' AND resolved = 0) + "
        "(SELECT COUNT(*) FROM assessment_findings WHERE engagement_id = ? "
        "AND verification_status = 'blocked')",
        (engagement_id, engagement_id),
    ).fetchone()[0]
    items = []
    for row in decisions:
        payload = _json_obj(row["payload_json"])
        items.append({
            "source": "dispatch_decision", "id": row["id"],
            "identity": str(payload.get("identity") or "")[:128],
            "surface": str(payload.get("surface") or "")[:200],
            "need": str(payload.get("need") or payload.get("reason") or "")[:300],
        })
    for row in findings:
        details = _json_obj(row["details_json"])
        requirement = details.get("unblock_requirements") or {}
        items.append({
            "source": "finding", "slug": row["slug"],
            "severity": row["severity"],
            "identity": str(requirement.get("kind") or "")[:128],
            "surface": str(row["title"] or "")[:200],
            "need": str(requirement.get("description") or details.get("block_reason") or "")[:300],
            "requested_from": str(requirement.get("requested_from") or "")[:128],
        })
    return {"count": int(count), "items": items[:10]}


def _contradiction_reviews_section(connection, engagement_id: int) -> dict[str, Any]:
    predicate = (
        "links.engagement_id = ? AND links.link_kind = 'contradicts' "
        "AND links.target_kind = 'finding' AND links.retired_at IS NULL"
    )
    count = connection.execute(
        f"SELECT COUNT(*) FROM assessment_finding_links AS links WHERE {predicate}",
        (engagement_id,),
    ).fetchone()[0]
    rows = connection.execute(
        f"""
        SELECT links.id, COALESCE(target.slug, links.target_ref) AS target_slug,
               links.notes, source.slug AS source_slug
        FROM assessment_finding_links AS links
        JOIN assessment_findings AS source ON source.id = links.finding_id
        LEFT JOIN assessment_findings AS target
          ON target.id = links.target_id AND target.engagement_id = links.engagement_id
        WHERE {predicate}
        ORDER BY links.id DESC LIMIT 10
        """,
        (engagement_id,),
    ).fetchall()
    return {
        "count": int(count),
        "items": [
            {
                "link_id": row["id"], "source_slug": row["source_slug"],
                "target_slug": row["target_slug"], "notes": row["notes"],
            }
            for row in rows
        ],
    }


def build_resume_brief(
    engagement_id: int,
    *,
    mode: str | None = None,
    q: str = "",
    finding: str = "",
    agent_id: str = "",
    max_age_hours: float | None = None,
    since: str = "",
    per_input_limit: int = _PER_INPUT_ROW_LIMIT,
) -> dict[str, Any]:
    if since and _parse_iso(since) is None:
        # Silent fallback would hide the bug — the operator types
        # `--since today` and gets the full brief back, then assumes
        # nothing has changed. Refuse loudly.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"--since={since!r} is not a valid ISO datetime. "
                "Use a form like 2026-05-19T10:00:00Z or 2026-05-19."
            ),
        )
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root)
    scope = _read_scope(root)
    engagement_type = str(scope.get("engagement_type") or "web")
    phases = track_phases(scope)
    if mode is not None and mode not in phases:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"resume-brief mode {mode!r} is not enabled for this engagement",
        )
    canonical_finding = canonical_finding_alias(finding) if finding else ""
    search_terms = [term for term in (canonical_finding, q) if term]
    search_text = " ".join(search_terms)

    with get_connection() as connection:
        target_finding = None
        if canonical_finding:
            row = connection.execute(
                """
                SELECT slug, title, severity, status, verification_status,
                       source_name, evidence_ref,
                       details_json, updated_at
                FROM assessment_findings
                WHERE engagement_id = ? AND slug = ?
                """,
                (engagement_id, canonical_finding),
            ).fetchone()
            target_finding = _finding_summary(row) if row else None
        findings = {
            "active": _limited_findings(connection, engagement_id, "status IN ('active', 'exploited', 'reported')", since=since, mode=mode),
            "unreviewed": _limited_findings(
                connection,
                engagement_id,
                "verification_status = 'unreviewed' "
                "AND status NOT IN ('merged', 'false_positive')",
                since=since, mode=mode,
            ),
            "verified": _limited_findings(
                connection,
                engagement_id,
                "verification_status NOT IN ('unreviewed', 'disputed')",
                since=since, mode=mode,
            ),
            "killed": _limited_findings(connection, engagement_id, "status = 'false_positive'", since=since, mode=mode),
            "merged": _limited_findings(connection, engagement_id, "status = 'merged'", since=since, mode=mode),
            "chain_required": _limited_findings(
                connection,
                engagement_id,
                "json_extract(details_json,'$.chain_required') = 1",
                since=since, mode=mode,
            ),
        }
        counts = _counts(connection, engagement_id, mode=mode)
        cross_track = (
            _cross_track_pointer(connection, engagement_id, mode=mode, phases=phases)
            if mode in {"web", "code"} else {}
        )
        web_view = "web" in phases and mode != "code"
        surfaces_section = _surfaces_section(connection, engagement_id) if web_view else {}
        work_buffer_section = _work_buffer_section(connection, engagement_id) if web_view else {}
        attempts_section = _attempts_section(connection, engagement_id, since=since)
        credential_needs = _credential_needs_section(connection, engagement_id)
        contradiction_reviews = _contradiction_reviews_section(connection, engagement_id)
        per_input_coverage_section = (
            _per_input_coverage_section(connection, engagement_id, since=since, row_limit=per_input_limit)
            if web_view else {}
        )

    command_matches_all = (
        state_manager.list_command_runs(
            engagement_id,
            q=search_text,
            sort="relevance",
            show_matches=True,
            limit=10 if not since else 30,
            include_output=False,
        )
        if search_text
        else state_manager.list_command_runs(
            engagement_id,
            sort="recent",
            limit=10 if not since else 30,
            include_output=False,
        )
    )
    command_filtered = _since_filter(
        command_matches_all, since=since, field="created_at"
    )
    command_matches = command_filtered[:10]
    artifacts_all = artifact_index.search_artifacts(
        engagement_id,
        query=q,
        finding=canonical_finding or finding,
        limit=10 if not since else 30,
    )
    artifacts_filtered = _since_filter(
        artifacts_all, since=since, field="updated_at"
    )
    artifacts = artifacts_filtered[:10]
    command_fetch_limit = 10 if not since else 30
    artifact_fetch_limit = 10 if not since else 30
    command_page = {
        "returned_count": len(command_matches),
        "total_count": len(command_filtered),
        "total_is_lower_bound": len(command_matches_all) >= command_fetch_limit,
        "truncated": (
            len(command_matches) < len(command_filtered)
            or len(command_matches_all) >= command_fetch_limit
        ),
    }
    artifact_page = {
        "returned_count": len(artifacts),
        "total_count": len(artifacts_filtered),
        "total_is_lower_bound": len(artifacts_all) >= artifact_fetch_limit,
        "truncated": (
            len(artifacts) < len(artifacts_filtered)
            or len(artifacts_all) >= artifact_fetch_limit
        ),
    }
    open_high_cves = _since_filter(
        intel.list_open_high_cves(engagement_id), since=since, field="updated_at"
    )[:10]
    open_leads = _since_filter(
        intel.list_leads(engagement_id, open_only=True), since=since, field="updated_at"
    )[:10]
    # A lead bound into reviewed source is code work waiting on the operator,
    # and a stale binding is a line range that must be re-read before it is
    # trusted. Both are one integer each, so the pointer stays a pointer.
    lead_binding_counts = code_analysis.open_code_lead_binding_counts(engagement_id)
    intel_section = {
        # Aggregate counts are an absolute snapshot (like finding_counts), so
        # they are NOT since-filtered; the bounded lists below are.
        "summary": intel.intel_summary(engagement_id),
        "open_high_cves": open_high_cves,
        # Project a pointer (title + status), not the note body — keep the brief
        # compact; the operator opens the lead via intel list/search.
        "open_leads": [
            {
                "id": row.get("id"),
                "title": row.get("title"),
                "lead_status": row.get("lead_status"),
                "code_bindings": lead_binding_counts.get(
                    int(row.get("id") or 0), {}
                ).get("bindings", 0),
                "stale_code_bindings": lead_binding_counts.get(
                    int(row.get("id") or 0), {}
                ).get("stale", 0),
            }
            for row in open_leads
        ],
        # Notes the operator tagged coverage/read-first — surfaced by title so a
        # coverage map or read-first context is not lost in the plain-note pile.
        "read_first_notes": _resume_note_pointers(engagement_id, since=since),
    }
    dispatch_picture = _recent_dispatch_picture(engagement_id, max_age_hours=max_age_hours, mode=mode)
    current_code_phase = phases.get("code", "")
    code_analysis_section = (
        _code_analysis_section(engagement_id, "code" in phases, current_code_phase)
        if mode != "web" else {}
    )
    knowledge_drift = _knowledge_drift_section(engagement_id)
    recent_decisions = _recent_decisions(engagement_id, since=since)
    with get_connection() as connection:
        decision_total = _decision_count(connection, engagement_id, since=since)
    checkpoint = operator_checkpoints.current_checkpoint(engagement_id)
    shared_checkpoint: dict[str, Any] | None = None
    if mode in {"web", "code"} and {"web", "code"}.issubset(phases):
        if checkpoint:
            shared_checkpoint = {
                "checkpoint_version": checkpoint["checkpoint_version"],
                "read_command": "vigil assess operator-checkpoint show",
            }
        checkpoint = None
    if agent_id:
        dispatch_picture["selected_dispatch"] = state_manager.get_dispatch(engagement_id, agent_id)
        try:
            dispatch_picture["selected_handoff"] = state_manager.get_handoff(engagement_id, agent_id)
        except Exception:  # noqa: BLE001 - resume should degrade when handoff is absent.
            dispatch_picture["selected_handoff"] = None

    return {
        "engagement": {
            "id": engagement.id,
            "key": engagement.key,
            "root": str(root),
            "current_phase": phases.get(mode) if mode else (phases.get("web") or next(iter(phases.values()), "unknown")),
            "operator_mode": mode,
            "track_state": {name: {"phase": phase, "complete": phase == "complete"} for name, phase in phases.items()},
            "scope_status": scope.get("status") or engagement.status,
            "engagement_type": engagement_type,
            "host_count": len(scope.get("hosts") or []) if isinstance(scope.get("hosts"), list) else 0,
        },
        "query": {"q": q, "finding": canonical_finding or finding, "agent_id": agent_id, "since": since},
        "cross_track": cross_track,
        "finding_counts": counts,
        "surfaces": surfaces_section,
        "work_buffer": work_buffer_section,
        "attempts": attempts_section,
        "credential_needs": credential_needs,
        "contradiction_reviews": contradiction_reviews,
        "per_input_coverage": per_input_coverage_section,
        "target_finding": target_finding,
        "findings": findings,
        "recent_decisions": recent_decisions,
        "recent_decisions_count": decision_total,
        "operator_checkpoint": checkpoint,
        "shared_checkpoint": shared_checkpoint,
        "code_analysis": code_analysis_section,
        "dispatches": dispatch_picture,
        "command_runs": command_matches,
        "command_runs_page": command_page,
        "artifacts": artifacts,
        "artifacts_page": artifact_page,
        "intel": intel_section,
        "knowledge_drift": knowledge_drift,
        "recommended_next_actions": _recommended_actions(
            finding=canonical_finding or finding,
            agent_id=agent_id,
            artifacts=artifacts,
            command_matches=command_matches,
            stale_dispatches=dispatch_picture.get("stale_in_progress_dispatches") or [],
            stale_threshold_hours=max_age_hours if max_age_hours is not None else _DEFAULT_STALE_THRESHOLD_HOURS,
            open_code_leases=code_analysis_section.get("open_leases") or [],
            open_code_leads=intel_section["open_leads"],
        ),
    }


def _recommended_actions(
    *,
    finding: str,
    agent_id: str,
    artifacts: list[dict[str, Any]],
    command_matches: list[dict[str, Any]],
    stale_dispatches: list[dict[str, Any]],
    stale_threshold_hours: float = 24.0,
    open_code_leases: list[dict[str, Any]] | None = None,
    open_code_leads: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    max_actions = 8

    def add(
        reason: str,
        command: str,
        *,
        entity_kind: str = "",
        entity_id: str | int | None = None,
    ) -> None:
        if len(actions) >= max_actions:
            return
        action: dict[str, Any] = {"reason": reason, "command": command}
        if entity_kind:
            action["entity_kind"] = entity_kind
        if entity_id is not None and entity_id != "":
            action["entity_id"] = entity_id
        actions.append(action)

    if finding:
        add("inspect finding", f"vigil assess fetch findings/{finding}", entity_kind="finding", entity_id=finding)
        add("command coverage", f"vigil assess command-run list --q {finding} --show-matches", entity_kind="finding", entity_id=finding)
        add("artifact context", f"vigil assess artifact search --finding {finding}", entity_kind="finding", entity_id=finding)
    elif not command_matches:
        add("recent command coverage", "vigil assess command-run list --limit 20")
    if agent_id:
        add("handoff continuation", f"vigil assess agent render-handoff {agent_id}", entity_kind="agent", entity_id=agent_id)
    if open_code_leases:
        # Point at the read, not at a mutation: whether an open lease should be
        # adopted or reset depends on how much durable work it already holds.
        add(
            "open code-analysis lease",
            "vigil assess code-dispatch list --status processing",
        )
    if any(row.get("code_bindings") for row in open_code_leads or []):
        # Point at the read: whether a bound lead needs queueing, rebinding or
        # closing depends on what the binding already carries.
        add("open code-bound lead", "vigil assess code-lead list --lead-status open")
    if stale_dispatches:
        threshold_arg = (
            "" if abs(stale_threshold_hours - 24.0) < 1e-9
            else f" --max-age-hours {stale_threshold_hours:g}"
        )
        add(
            "stale dispatch lifecycle",
            f"vigil assess agent reconcile-stale --dry-run{threshold_arg}",
        )
    if not artifacts:
        add("refresh artifact index", "vigil assess artifact register <path> --finding <slug>")
    for row in command_matches[:3]:
        run_id = row.get("id")
        if run_id is not None:
            add(
                "inspect matching command run",
                f"vigil assess command-run get {run_id}",
                entity_kind="command_run",
                entity_id=run_id,
            )
    for row in artifacts[:3]:
        artifact_id = row.get("id")
        if artifact_id is not None:
            add(
                "inspect indexed artifact",
                f"vigil assess artifact get {artifact_id}",
                entity_kind="artifact",
                entity_id=artifact_id,
            )
    return actions
