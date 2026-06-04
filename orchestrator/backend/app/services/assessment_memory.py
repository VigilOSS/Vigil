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
