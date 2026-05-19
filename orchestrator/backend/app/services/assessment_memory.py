from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..db import get_connection
from . import artifact_index, state_manager
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


def _limited_findings(connection, engagement_id: int, where_sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    rows = connection.execute(
        f"""
        SELECT slug, title, severity, status, verification_state,
               verification_disposition, source_name, evidence_ref,
               details_json, updated_at
        FROM assessment_findings
        WHERE engagement_id = ? AND {where_sql}
        ORDER BY updated_at DESC, id DESC
        LIMIT 12
        """,
        (engagement_id, *params),
    ).fetchall()
    return [_finding_summary(row) for row in rows]


def _recent_decisions(engagement_id: int) -> list[dict[str, Any]]:
    return state_manager.list_decisions(engagement_id, limit=10)


def _recent_dispatch_picture(engagement_id: int) -> dict[str, Any]:
    dispatches = state_manager.list_dispatches(engagement_id, limit=25)
    handoffs = {row.get("agent_id"): row for row in state_manager.list_handoffs(engagement_id, limit=100)}
    now = dt.datetime.now(dt.timezone.utc)
    stale: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for row in dispatches:
        if row.get("status") != "in-progress":
            continue
        agent_id = row.get("agent_id")
        handoff = handoffs.get(agent_id)
        if not handoff:
            gaps.append({"agent_id": agent_id, "agent_role": row.get("agent_role"), "reason": "no_handoff"})
        started = _parse_iso(row.get("dispatched_at"))
        age_hours = ((now - started).total_seconds() / 3600.0) if started else None
        if age_hours is not None and age_hours >= 24:
            stale.append(
                {
                    "agent_id": agent_id,
                    "agent_role": row.get("agent_role"),
                    "age_hours": round(age_hours, 2),
                    "handoff_status": (handoff or {}).get("handoff_status") or "none",
                }
            )
    return {
        "recent_dispatches": dispatches[:10],
        "latest_handoffs": list(handoffs.values())[:10],
        "stale_in_progress_dispatches": stale,
        "handoff_gaps": gaps[:10],
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
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root)
    scope = _read_scope(root)
    canonical_finding = canonical_finding_alias(finding) if finding else ""
    search_text = canonical_finding or q

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
            "active": _limited_findings(connection, engagement_id, "status IN ('active', 'exploited', 'reported')"),
            "unreviewed": _limited_findings(connection, engagement_id, "verification_state = 'unreviewed'"),
            "verified": _limited_findings(connection, engagement_id, "verification_state = 'verified'"),
            "killed": _limited_findings(connection, engagement_id, "status = 'false_positive'"),
            "merged": _limited_findings(connection, engagement_id, "status = 'merged'"),
            "chain_required": _limited_findings(
                connection,
                engagement_id,
                "details_json LIKE '%chain_required%'",
            ),
        }
        counts = _counts(connection, engagement_id)

    command_matches = (
        state_manager.list_command_runs(
            engagement_id,
            q=search_text,
            sort="relevance",
            show_matches=True,
            limit=10,
            include_output=False,
        )
        if search_text
        else state_manager.list_command_runs(engagement_id, sort="recent", limit=10, include_output=False)
    )
    artifacts = artifact_index.search_artifacts(
        engagement_id,
        query=q,
        finding=canonical_finding or finding,
        limit=10,
    )
    dispatch_picture = _recent_dispatch_picture(engagement_id)
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
        "query": {"q": q, "finding": canonical_finding or finding, "agent_id": agent_id},
        "finding_counts": counts,
        "target_finding": target_finding,
        "findings": findings,
        "recent_decisions": _recent_decisions(engagement_id),
        "dispatches": dispatch_picture,
        "command_runs": command_matches,
        "artifacts": artifacts,
        "recommended_next_actions": _recommended_actions(
            finding=canonical_finding or finding,
            agent_id=agent_id,
            has_artifacts=bool(artifacts),
            has_command_matches=bool(command_matches),
            stale_dispatches=dispatch_picture.get("stale_in_progress_dispatches") or [],
        ),
    }


def _recommended_actions(
    *,
    finding: str,
    agent_id: str,
    has_artifacts: bool,
    has_command_matches: bool,
    stale_dispatches: list[dict[str, Any]],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    if finding:
        actions.append({"reason": "inspect finding", "command": f"aith assess fetch findings/{finding}"})
        actions.append({"reason": "command coverage", "command": f"aith assess list-command-runs --q {finding} --show-matches"})
        actions.append({"reason": "artifact context", "command": f"aith assess artifact search --finding {finding}"})
    elif not has_command_matches:
        actions.append({"reason": "recent command coverage", "command": "aith assess list-command-runs --limit 20"})
    if not has_artifacts:
        actions.append({"reason": "refresh artifact index", "command": "aith assess artifact sync"})
    if agent_id:
        actions.append({"reason": "handoff continuation", "command": f"aith assess agent render-handoff {agent_id}"})
    if stale_dispatches:
        actions.append({"reason": "stale dispatch lifecycle", "command": "aith assess agent reconcile-stale --dry-run"})
    return actions[:8]
