from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ..db import get_connection
from . import artifact_index, intel, state_manager
from .events import _engagement_or_404
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
        "verification_state": row["verification_state"] or "unreviewed",
        "verification_disposition": row["verification_disposition"] or "none",
        "source_name": row["source_name"] or "",
        "evidence_ref": row["evidence_ref"] or "",
        "chain_required": bool(details.get("chain_required")),
        "chain_rationale": str(details.get("chain_rationale") or "")[:500],
        "updated_at": row["updated_at"],
    }


def _limited_findings(
    connection,
    engagement_id: int,
    where_sql: str,
    params: tuple[Any, ...] = (),
    *,
    since: str = "",
) -> list[dict[str, Any]]:
    extra_where = ""
    extra_params: tuple[Any, ...] = ()
    if since:
        extra_where = " AND updated_at >= ?"
        extra_params = (since,)
    rows = connection.execute(
        f"""
        SELECT slug, title, severity, status, verification_state,
               verification_disposition, source_name, evidence_ref,
               details_json, updated_at
        FROM assessment_findings
        WHERE engagement_id = ? AND {where_sql}{extra_where}
        ORDER BY updated_at DESC, id DESC
        LIMIT 12
        """,
        (engagement_id, *params, *extra_params),
    ).fetchall()
    return [_finding_summary(row) for row in rows]


def _recent_decisions(engagement_id: int, *, since: str = "") -> list[dict[str, Any]]:
    rows = state_manager.list_decisions(engagement_id, limit=10 if not since else 30)
    return _since_filter(rows, since=since, field="created_at")[:10]


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


def _stale_threshold_for(role: str | None, *, override: float | None) -> float:
    if override is not None:
        return float(override)
    return _STALE_THRESHOLD_BY_ROLE.get(str(role or ""), _DEFAULT_STALE_THRESHOLD_HOURS)


def _recent_dispatch_picture(
    engagement_id: int,
    *,
    max_age_hours: float | None,
) -> dict[str, Any]:
    dispatches = state_manager.list_dispatches(engagement_id, limit=25)
    handoffs = {row.get("agent_id"): row for row in state_manager.list_handoffs(engagement_id, limit=100)}
    now = dt.datetime.now(dt.timezone.utc)
    stale: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for row in dispatches:
        if row.get("status") != "in-progress":
            continue
        agent_id = row.get("agent_id")
        agent_role = row.get("agent_role")
        handoff = handoffs.get(agent_id)
        if not handoff:
            gaps.append({"agent_id": agent_id, "agent_role": agent_role, "reason": "no_handoff"})
        started = _parse_iso(row.get("dispatched_at"))
        age_hours = ((now - started).total_seconds() / 3600.0) if started else None
        threshold = _stale_threshold_for(agent_role, override=max_age_hours)
        if age_hours is not None and age_hours >= threshold:
            stale.append(
                {
                    "agent_id": agent_id,
                    "agent_role": agent_role,
                    "age_hours": round(age_hours, 2),
                    "handoff_status": (handoff or {}).get("handoff_status") or "none",
                    "threshold_hours": threshold,
                }
            )
    # The reported `stale_threshold_hours` is the override if set, else the
    # default — per-role thresholds applied per dispatch are also visible on
    # each stale entry's `threshold_hours`.
    reported_threshold = (
        float(max_age_hours) if max_age_hours is not None else _DEFAULT_STALE_THRESHOLD_HOURS
    )
    return {
        "recent_dispatches": dispatches[:10],
        "latest_handoffs": list(handoffs.values())[:10],
        "stale_in_progress_dispatches": stale,
        "handoff_gaps": gaps[:10],
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


def _counts(connection, engagement_id: int) -> dict[str, dict[str, int]]:
    rows = connection.execute(
        """
        SELECT status, verification_state, verification_disposition, severity, source_name
        FROM assessment_findings
        WHERE engagement_id = ?
        """,
        (engagement_id,),
    ).fetchall()
    workflow = Counter(str(row["status"] or "draft") for row in rows)
    verification = Counter(str(row["verification_state"] or "unreviewed") for row in rows)
    disposition = Counter(str(row["verification_disposition"] or "none") for row in rows)
    severity = Counter(str(row["severity"] or "info") for row in rows)
    source = Counter(str(row["source_name"] or "unknown") for row in rows)
    return {
        "workflow": dict(workflow),
        "verification_state": dict(verification),
        "verification_disposition": dict(disposition),
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

# "Do-today" attempt ledger surfacing (P1-C). The Attempts section pulls three
# already-persisted but previously resume-invisible signals so the operator
# reads what has been TRIED-AND-WALLED-OFF before re-dispatching the same
# surface: recorded blocked techniques, non-covering probe runs, and findings
# flagged roe_blocked in details_json. Each list is bounded (pointers + counts,
# never bodies) consistent with the other sections.
_ATTEMPTS_ROW_LIMIT = 8
# The covering subset mirrors state_manager.coverage.PROBE_RESULT_STATUSES_
# COVERING; a probe run outside it (blocked / no-signal / attempted / error) is
# an attempt that did NOT establish coverage — exactly what "what did I already
# try here" wants. Kept as a local literal (the brief must not depend on the
# coverage module) but pinned to the same two values.
_PROBE_COVERING_STATUSES = ("tested", "signal")


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
    """Pending coverage-item rollup ("work buffer") keyed by gf-bucket (gap #2).

    The gf-bucket → coverage bridge records one ``assessment_coverage_items``
    row per matched bucket, storing the canonical attack-class that the bucket
    maps to (``GF_BUCKET_TO_CLASS[bucket]``) in ``attack_family`` — so grouping
    by ``attack_family`` rolls up the pending work by bucket-derived class. A
    coverage item is pending until it is ``covered`` / ``not_applicable``.
    Counts are an absolute snapshot, NOT since-filtered. ``by_bucket`` is
    ordered by descending count.
    """
    rows = connection.execute(
        "SELECT attack_family, status FROM assessment_coverage_items WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    by_bucket: Counter = Counter()
    for row in rows:
        status_value = str(row["status"] or "pending").strip().lower()
        if status_value in _RETIRED_COVERAGE_STATUSES:
            continue
        by_bucket[str(row["attack_family"] or "unknown")] += 1
    return {
        "pending_total": sum(by_bucket.values()),
        "by_bucket": dict(by_bucket.most_common()),
    }


def _resume_note_pointers(engagement_id: int, *, since: str) -> list[dict[str, Any]]:
    """Intel notes tagged ``coverage`` / ``read-first`` — projected as bounded
    pointers (id + title + matching tags + lead_status), not bodies, so the
    operator opens them via list-intel/search. Bounded list, so since-filtered
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


def _attempts_section(connection, engagement_id: int, *, since: str) -> dict[str, Any]:
    """Do-today attempt ledger (P1-C) — three already-persisted signals that the
    brief never surfaced, so a re-dispatch could unknowingly retry a walled-off
    surface.

    - ``blocked_techniques``: recent ``assessment_blocked_techniques`` rows
      (wires the previously CLI-less table into resume).
    - ``noncovering_probe_runs``: ``assessment_probe_runs`` whose result_status
      is NOT in the covering subset (tested/signal) — i.e. blocked / no-signal /
      attempted / error attempts that established no coverage.
    - ``roe_blocked_findings``: findings whose ``details_json`` carries the
      ``roe_blocked`` free-text convention (mirrors the existing chain_required
      LIKE-filter). Projected as finding pointers.

    Each list is bounded and, where the row carries a timestamp, since-filtered.
    Counts are the pre-truncation totals so a truncated list still signals depth.
    """
    blocked_rows = connection.execute(
        """
        SELECT id, technique_key, technique, target_kind, target_ref,
               reason, retry_state, evidence_ref, updated_at
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
                "updated_at": row["updated_at"],
            }
            for row in blocked_rows
        ],
        since=since,
        field="updated_at",
    )[:_ATTEMPTS_ROW_LIMIT]

    placeholders = ", ".join("?" for _ in _PROBE_COVERING_STATUSES)
    probe_rows = connection.execute(
        f"""
        SELECT id, attack_family, result_status, tool_name, agent_name,
               target_host, target_path, signal_type, evidence_ref, created_at
        FROM assessment_probe_runs
        WHERE engagement_id = ?
          AND result_status NOT IN ({placeholders})
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        """,
        (engagement_id, *_PROBE_COVERING_STATUSES, _ATTEMPTS_ROW_LIMIT * 3),
    ).fetchall()
    noncovering_probe_runs = _since_filter(
        [
            {
                "id": row["id"],
                "attack_family": row["attack_family"] or "",
                "result_status": row["result_status"] or "",
                "tool_name": row["tool_name"] or "",
                "agent_name": row["agent_name"] or "",
                "target_host": row["target_host"] or "",
                "target_path": row["target_path"] or "",
                "signal_type": row["signal_type"] or "",
                "evidence_ref": row["evidence_ref"] or "",
                "created_at": row["created_at"],
            }
            for row in probe_rows
        ],
        since=since,
        field="created_at",
    )[:_ATTEMPTS_ROW_LIMIT]

    roe_blocked_findings = _limited_findings(
        connection,
        engagement_id,
        "details_json LIKE '%roe_blocked%'",
        since=since,
    )

    # Counts are absolute totals (like finding_counts), not len() of the
    # truncated lists — so a list capped at _ATTEMPTS_ROW_LIMIT still signals the
    # true depth of walled-off work a re-dispatch must not blindly retry.
    blocked_total = connection.execute(
        "SELECT COUNT(*) FROM assessment_blocked_techniques WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()[0]
    noncovering_total = connection.execute(
        f"SELECT COUNT(*) FROM assessment_probe_runs "
        f"WHERE engagement_id = ? AND result_status NOT IN ({placeholders})",
        (engagement_id, *_PROBE_COVERING_STATUSES),
    ).fetchone()[0]
    roe_blocked_total = connection.execute(
        "SELECT COUNT(*) FROM assessment_findings "
        "WHERE engagement_id = ? AND details_json LIKE '%roe_blocked%'",
        (engagement_id,),
    ).fetchone()[0]

    return {
        "blocked_techniques": blocked_techniques,
        "blocked_techniques_count": blocked_total,
        "noncovering_probe_runs": noncovering_probe_runs,
        "noncovering_probe_runs_count": noncovering_total,
        "roe_blocked_findings": roe_blocked_findings,
        "roe_blocked_findings_count": roe_blocked_total,
    }


def build_resume_brief(
    engagement_id: int,
    *,
    q: str = "",
    finding: str = "",
    agent_id: str = "",
    max_age_hours: float | None = None,
    since: str = "",
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
    canonical_finding = canonical_finding_alias(finding) if finding else ""
    search_terms = [term for term in (canonical_finding, q) if term]
    search_text = " ".join(search_terms)

    with get_connection() as connection:
        target_finding = None
        if canonical_finding:
            row = connection.execute(
                """
                SELECT slug, title, severity, status, verification_state,
                       verification_disposition, source_name, evidence_ref,
                       details_json, updated_at
                FROM assessment_findings
                WHERE engagement_id = ? AND slug = ?
                """,
                (engagement_id, canonical_finding),
            ).fetchone()
            target_finding = _finding_summary(row) if row else None
        findings = {
            "active": _limited_findings(connection, engagement_id, "status IN ('active', 'exploited', 'reported')", since=since),
            "unreviewed": _limited_findings(connection, engagement_id, "verification_state = 'unreviewed'", since=since),
            "verified": _limited_findings(connection, engagement_id, "verification_state = 'verified'", since=since),
            "killed": _limited_findings(connection, engagement_id, "status = 'false_positive'", since=since),
            "merged": _limited_findings(connection, engagement_id, "status = 'merged'", since=since),
            "chain_required": _limited_findings(
                connection,
                engagement_id,
                "details_json LIKE '%chain_required%'",
                since=since,
            ),
        }
        counts = _counts(connection, engagement_id)
        surfaces_section = _surfaces_section(connection, engagement_id)
        work_buffer_section = _work_buffer_section(connection, engagement_id)
        attempts_section = _attempts_section(connection, engagement_id, since=since)

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
    command_matches = _since_filter(command_matches_all, since=since, field="created_at")[:10]
    artifacts_all = artifact_index.search_artifacts(
        engagement_id,
        query=q,
        finding=canonical_finding or finding,
        limit=10 if not since else 30,
    )
    artifacts = _since_filter(artifacts_all, since=since, field="updated_at")[:10]
    open_high_cves = _since_filter(
        intel.list_open_high_cves(engagement_id), since=since, field="updated_at"
    )[:10]
    open_leads = _since_filter(
        intel.list_leads(engagement_id, open_only=True), since=since, field="updated_at"
    )[:10]
    intel_section = {
        # Aggregate counts are an absolute snapshot (like finding_counts), so
        # they are NOT since-filtered; the bounded lists below are.
        "summary": intel.intel_summary(engagement_id),
        "open_high_cves": open_high_cves,
        # Project a pointer (title + status), not the note body — keep the brief
        # compact; the operator opens the lead via list-intel/search.
        "open_leads": [
            {"id": row.get("id"), "title": row.get("title"), "lead_status": row.get("lead_status")}
            for row in open_leads
        ],
        # Notes the operator tagged coverage/read-first — surfaced by title so a
        # coverage map or read-first context is not lost in the plain-note pile.
        "read_first_notes": _resume_note_pointers(engagement_id, since=since),
    }
    dispatch_picture = _recent_dispatch_picture(engagement_id, max_age_hours=max_age_hours)
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
            "current_phase": scope.get("current_phase") or "unknown",
            "scope_status": scope.get("status") or engagement.status,
            "host_count": len(scope.get("hosts") or []) if isinstance(scope.get("hosts"), list) else 0,
        },
        "query": {"q": q, "finding": canonical_finding or finding, "agent_id": agent_id, "since": since},
        "finding_counts": counts,
        "surfaces": surfaces_section,
        "work_buffer": work_buffer_section,
        "attempts": attempts_section,
        "target_finding": target_finding,
        "findings": findings,
        "recent_decisions": _recent_decisions(engagement_id, since=since),
        "dispatches": dispatch_picture,
        "command_runs": command_matches,
        "artifacts": artifacts,
        "intel": intel_section,
        "recommended_next_actions": _recommended_actions(
            finding=canonical_finding or finding,
            agent_id=agent_id,
            artifacts=artifacts,
            command_matches=command_matches,
            stale_dispatches=dispatch_picture.get("stale_in_progress_dispatches") or [],
            stale_threshold_hours=max_age_hours if max_age_hours is not None else _DEFAULT_STALE_THRESHOLD_HOURS,
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
        add("command coverage", f"vigil assess list-command-runs --q {finding} --show-matches", entity_kind="finding", entity_id=finding)
        add("artifact context", f"vigil assess artifact search --finding {finding}", entity_kind="finding", entity_id=finding)
    elif not command_matches:
        add("recent command coverage", "vigil assess list-command-runs --limit 20")
    if agent_id:
        add("handoff continuation", f"vigil assess agent render-handoff {agent_id}", entity_kind="agent", entity_id=agent_id)
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
                f"vigil assess get-command-run {run_id}",
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
