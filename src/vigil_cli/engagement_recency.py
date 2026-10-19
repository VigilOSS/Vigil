"""Read-only, dependency-free projection of meaningful engagement activity.

The explicit source registry intentionally excludes mutable sync/index timestamps.
Missing tables are normal for older databases; remaining sources still contribute
and incomplete coverage is exposed to the picker. Never initialize a database or
use immutable=1 (which would hide committed WAL records).
"""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
from typing import Any

from .client_sessions import historical_client_starts
from .paths import resolve_orchestrator_data_dir


@dataclass(frozen=True, slots=True)
class EngagementRecency:
    latest_at: datetime | None
    source: str
    incomplete: bool


@dataclass(frozen=True, slots=True)
class ActivitySource:
    table: str
    timestamps: tuple[str, ...] = ("created_at",)
    parent: str = ""
    foreign_key: str = ""


# Only durable work clocks: never engagements.updated_at, file/index freshness,
# credential probes, environment lease heartbeats, or backend sync bookkeeping.
ACTIVITY_SOURCES = (
    *(ActivitySource(table) for table in (
        "events", "assessment_finding_transitions",
        "assessment_probe_runs", "assessment_request_observations",
        "assessment_artifacts", "assessment_submission_versions", "assessment_sent_reply_versions",
        "assessment_operator_checkpoints",
        "assessment_run_lifecycle_events", "assessment_run_obligation_events",
        "assessment_run_candidate_events", "assessment_run_tool_signals", "assessment_run_discovery_passes",
        "assessment_proof_receipts", "assessment_finding_proof_receipts", "assessment_finding_counterchecks",
        "assessment_finding_severity_variances", "assessment_blocked_technique_history",
        "assessment_oob_interactions", "assessment_credential_tests", "assessment_access_records",
        "code_analysis_results", "code_variant_check_receipts", "code_fuzz_decisions", "code_fuzz_campaign_receipts",
        "code_analysis_triggers",
    )),
    *(ActivitySource(table, ("created_at", "updated_at")) for table in (
        "assessment_findings", "assessment_proof_work", "remediation_cases",
    )),
    ActivitySource("activity_entries", ("occurred_at", "created_at")),
    ActivitySource("assessment_dispatch_decisions", ("created_at", "resolution_json:approved_at")),
    ActivitySource("assessment_dispatch_handoffs", ("created_at", "last_checkpoint_at")),
    ActivitySource("assessment_runs", ("created_at", "started_at", "finished_at")),
    ActivitySource("assessment_dispatches", ("dispatched_at", "completed_at")),
    ActivitySource("assessment_command_runs", ("started_at", "completed_at")),
    ActivitySource("code_analysis_queue", ("created_at", "completed_at")),
    ActivitySource("assessment_proof_work_events", parent="assessment_proof_work", foreign_key="work_id"),
    *(ActivitySource(table, parent="remediation_cases", foreign_key="case_id") for table in (
        "remediation_evidence", "remediation_approvals", "remediation_transitions",
        "remediation_deployments", "remediation_human_verifications",
    )),
)


def parse_activity_time(value: object) -> datetime | None:
    """Normalize ISO and SQLite UTC timestamps before comparing (never strings)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        timestamp = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return (timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None
                else timestamp.astimezone(timezone.utc))
    except (ValueError, OverflowError):
        return None


def engagement_recency(install_root: Path, engagement: Path, scope: Mapping[str, Any]) -> EngagementRecency:
    return engagement_recencies(install_root, {engagement: scope})[engagement]


def engagement_recencies(install_root: Path, scopes: Mapping[Path, Mapping[str, Any]]) -> dict[Path, EngagementRecency]:
    """Batch once per picker: one historical read and one bounded SQLite snapshot."""
    latest = {path: EngagementRecency(None, "unknown", False) for path in scopes}

    def observe(path: Path, value: object, owner: str) -> None:
        parsed = parse_activity_time(value)
        previous = latest[path]
        if parsed is not None and (previous.latest_at is None or parsed > previous.latest_at):
            latest[path] = EngagementRecency(parsed, owner, previous.incomplete)
        elif parsed is None and value not in (None, ""):
            latest[path] = EngagementRecency(previous.latest_at, previous.source, True)

    def unavailable() -> None:
        for path, previous in latest.items():
            latest[path] = EngagementRecency(previous.latest_at, previous.source, True)

    if not scopes:
        return latest
    resolved = {path.resolve(): path for path in scopes}
    for path, scope in scopes.items():
        observe(path, scope.get("created_at"), "created")
        observe(path, scope.get("phase_changed_at"), "phase")
        observe(path, scope.get("exploit_review_changed_at"), "approval")
        transitions = scope.get("track_transitions", [])
        if isinstance(transitions, list):
            for row in transitions:
                if isinstance(row, dict):
                    observe(path, row.get("at"), "phase")
    history, history_incomplete = historical_client_starts(install_root)
    if history_incomplete:
        unavailable()
    for row in history:
        matched = resolved.get(Path(row["engagement"]).resolve())
        if matched is not None:
            observe(matched, row["started_at"], row.get("event", "official_start"))

    try:
        database_path = resolve_orchestrator_data_dir(install_root) / "orchestrator.sqlite3"
        if not database_path.is_file():
            unavailable()
            return latest
        with closing(sqlite3.connect(database_path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as database:
            deadline = time.monotonic() + 1.0
            database.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)

            def utc_clock(value: object, field: str) -> str | None:
                if field:
                    try:
                        decoded = json.loads(value) if isinstance(value, str) else None
                        value = decoded.get(field) if isinstance(decoded, dict) else None
                    except (ValueError, TypeError):
                        unavailable()
                        return None
                parsed = parse_activity_time(value)
                if parsed is None and value not in (None, ""):
                    unavailable()
                # Fixed precision keeps MAX lexicographically chronological after
                # normalizing offsets, including submillisecond differences.
                return parsed.isoformat(timespec="microseconds") if parsed else None

            database.create_function("vigil_activity_utc", 2, utc_clock, deterministic=True)
            database.execute("PRAGMA query_only=ON")
            database.execute("BEGIN")
            tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            columns = {table: {row[1] for row in database.execute(f'PRAGMA table_info("{table}")')}
                       for table in {"engagements", *(item.table for item in ACTIVITY_SOURCES),
                                     *(item.parent for item in ACTIVITY_SOURCES if item.parent)} if table in tables}
            if not {"id", "key", "engagement_root"} <= columns.get("engagements", set()):
                unavailable()
                return latest
            owners = {}
            for owner, key, root in database.execute("SELECT id,key,engagement_root FROM engagements"):
                matched = resolved.get(Path(root).resolve()) if isinstance(root, str) else None
                if matched is not None and key == matched.name:
                    owners[owner] = matched
            if len(set(owners.values())) != len(scopes):
                unavailable()
            if not owners:
                return latest
            for item in ACTIVITY_SOURCES:
                available = columns.get(item.table, set())
                clocks = [clock for clock in item.timestamps if clock.partition(":")[0] in available]
                if len(clocks) != len(item.timestamps):
                    unavailable()
                if not clocks:
                    continue
                if item.parent:
                    if (item.foreign_key not in available or
                            not {"id", "engagement_id"} <= columns.get(item.parent, set())):
                        unavailable()
                        continue
                    joins = f' JOIN "{item.parent}" p ON p.id=t."{item.foreign_key}"'
                    owner_column = "p.engagement_id"
                elif "engagement_id" in available:
                    joins, owner_column = "", "t.engagement_id"
                else:
                    unavailable()
                    continue
                try:
                    expressions = []
                    for clock in clocks:
                        column, _, field = clock.partition(":")
                        expressions.append(f'MAX(vigil_activity_utc(t."{column}",\'{field}\'))')
                    selected = ",".join(expressions)
                    placeholders = ",".join("?" for _ in owners)
                    query = (f'SELECT {owner_column},{selected} FROM "{item.table}" t{joins} '
                             f'WHERE {owner_column} IN ({placeholders}) GROUP BY {owner_column}')
                    for row in database.execute(query, tuple(owners)):
                        for value in row[1:]:
                            observe(owners[row[0]], value, item.table)
                except sqlite3.Error:
                    unavailable()
                    if time.monotonic() > deadline:
                        break
    except (OSError, sqlite3.Error, ValueError, TypeError, SystemExit):
        unavailable()
    return latest
