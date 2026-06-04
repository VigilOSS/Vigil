"""Cross-engagement dashboard projection.

Read-only aggregate over the single orchestrator SQLite DB that powers the
landing-page dashboard. Everything here is a projection — there are no
mutations and no per-engagement N+1 fan-out: the per-engagement severity
rollup is a SINGLE grouped query (``GROUP BY engagement_id, severity``)
joined back to the engagement metadata in Python.

Engagement identity/phase/customer come from ``list_engagements()`` (the
filesystem-backed ``EngagementView``: phase, engagement_type and customer
live in scope.json, not the DB), while the finding counts come from the DB.
The DB join key is the engagement ``id``; the view carries the same ``id``.

The finding exclusion idiom mirrors ``assessment_summary`` /
``state_manager.assessment_summary.assessment_summary`` exactly:
``status NOT IN ('merged', 'false_positive')`` so suppressed/merged findings
never inflate the totals or the donut.
"""
from __future__ import annotations

from typing import Any

from .. import db
from .engagements import EngagementView, list_engagements

# Mirror the per-engagement summary exclusion (merged/false_positive are
# suppressed everywhere a "live finding" count is shown). Kept as a module
# constant so the three queries below cannot drift from each other.
_LIVE_FINDING_PREDICATE = "status NOT IN ('merged', 'false_positive')"


def _severity_rollups_by_engagement(
    connection: Any,
) -> dict[int, dict[str, int]]:
    """Return ``{engagement_id: {severity: count}}`` over live findings.

    ONE grouped query across every engagement — NOT a per-engagement call.
    Engagements with zero live findings simply do not appear and are filled
    with an empty dict by the caller.
    """
    rows = connection.execute(
        f"""
        SELECT engagement_id, severity, COUNT(*) AS total
        FROM assessment_findings
        WHERE {_LIVE_FINDING_PREDICATE}
        GROUP BY engagement_id, severity
        """
    ).fetchall()
    rollups: dict[int, dict[str, int]] = {}
    for row in rows:
        rollups.setdefault(int(row["engagement_id"]), {})[str(row["severity"])] = int(row["total"])
    return rollups


def _finding_totals(connection: Any) -> dict[str, Any]:
    """Cross-engagement finding totals + by-severity (one grouped query)."""
    rows = connection.execute(
        f"""
        SELECT severity, COUNT(*) AS total
        FROM assessment_findings
        WHERE {_LIVE_FINDING_PREDICATE}
        GROUP BY severity
        ORDER BY severity ASC
        """
    ).fetchall()
    by_severity = {str(row["severity"]): int(row["total"]) for row in rows}
    return {
        "total": sum(by_severity.values()),
        "by_severity": by_severity,
    }


def _recent_activity(connection: Any, limit: int = 10) -> list[dict[str, Any]]:
    """Most-recent activity entries across all engagements.

    ``activity_entries`` carries ``engagement_id`` + an indexed
    ``occurred_at`` ordering, so the cross-engagement projection is a single
    JOIN-to-``engagements`` (for the human-facing key) with ``ORDER BY
    occurred_at DESC, id DESC LIMIT n`` — cheap and bounded. We surface the
    columns the per-engagement activity log already exposes (actor, title,
    action, result) plus the owning engagement key.
    """
    rows = connection.execute(
        """
        SELECT
            entries.id,
            engagements.key AS engagement_key,
            entries.actor_kind,
            entries.actor_name,
            entries.title,
            entries.action,
            entries.result,
            entries.occurred_at,
            entries.created_at
        FROM activity_entries AS entries
        JOIN engagements ON engagements.id = entries.engagement_id
        ORDER BY entries.occurred_at DESC, entries.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def _bump(counter: dict[str, int], key: str | None) -> None:
    label = key or "unknown"
    counter[label] = counter.get(label, 0) + 1


def dashboard_summary() -> dict[str, Any]:
    """Build the cross-engagement dashboard projection.

    ``list_engagements()`` is the single source of engagement identity (it
    folds in scope.json for phase/type/customer and triggers the filesystem
    sync). The DB queries below run once each, keyed by engagement id, so
    the whole projection is O(1) queries regardless of engagement count.
    """
    views: list[EngagementView] = list_engagements()

    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    for view in views:
        _bump(by_status, view.status)
        _bump(by_type, view.engagement_type)
        _bump(by_phase, view.current_phase)

    with db.get_connection() as connection:
        finding_totals = _finding_totals(connection)
        severity_by_engagement = _severity_rollups_by_engagement(connection)
        recent_activity = _recent_activity(connection)

    engagements: list[dict[str, Any]] = []
    for view in views:
        severities = severity_by_engagement.get(view.id, {})
        engagements.append(
            {
                "key": view.key,
                "target": view.target,
                "status": view.status,
                "current_phase": view.current_phase,
                "engagement_type": view.engagement_type,
                "customer": view.customer,
                "updated_at": view.updated_at,
                "finding_count": sum(severities.values()),
                "finding_severities": severities,
            }
        )
    # Newest-updated first. ``updated_at`` is an ISO-8601 / SQLite
    # CURRENT_TIMESTAMP string, so lexical descending order == chronological.
    engagements.sort(key=lambda row: row["updated_at"], reverse=True)

    return {
        "engagement_counts": {
            "total": len(views),
            "by_status": by_status,
            "by_type": by_type,
            "by_phase": by_phase,
        },
        "finding_totals": finding_totals,
        "engagements": engagements,
        "recent_activity": recent_activity,
    }
