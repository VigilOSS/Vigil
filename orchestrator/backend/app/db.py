from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from . import db_code_analysis_schema
from .code_snapshot import SOURCE_MANIFEST_VERSION, source_manifest_digest
from .config import settings
from .models.engagement import Engagement
from .models.engagement_session import EngagementSession
from .models.event import Event
from .retry_state import RETRY_STATES, map_legacy_retry_state


logger = logging.getLogger(__name__)

_VERIFICATION_STATUS_MIGRATION_ID = "finding-verification-status-v1"
_DISPATCH_SCHEMA_MIGRATION_ID = "dispatch-provenance-and-fossils-v1"
_RETRY_STATE_MIGRATION_ID = "blocked-technique-retry-state-v1"
_RUN_ACCOUNTING_MIGRATION_ID = "assessment-run-accounting-v1"
_RUN_ACCOUNTING_V2_MIGRATION_ID = "assessment-run-accounting-v2"
_RATE_LEASE_RETIREMENT_MIGRATION_ID = "aggregate-rate-lease-retirement-v1"
_RATE_LEASE_COLUMNS = (
    "id",
    "engagement_id",
    "lease_token",
    "owner",
    "effective_rate_rps",
    "aggregate_limit_rps",
    "override_reason",
    "command_run_id",
    "expires_at",
    "released_at",
    "created_at",
    "updated_at",
)
_RUN_ACCOUNTING_TABLES = frozenset(
    {
        "assessment_runs",
        "assessment_run_lifecycle_events",
        "assessment_run_sources",
        "assessment_run_source_reads",
        "assessment_run_obligations",
        "assessment_run_obligation_events",
        "assessment_run_candidates",
        "assessment_run_candidate_events",
        "assessment_run_comparisons",
        "assessment_proof_receipts",
        "assessment_finding_proof_receipts",
    }
)
_RUN_ACCOUNTING_V2_TABLES = frozenset(
    {
        "assessment_run_tool_signals",
        "assessment_run_discovery_passes",
        "assessment_run_code_receipt_links",
    }
)
_RUN_ACCOUNTING_RUN_COLUMNS = frozenset(
    {
        "run_purpose",
        "target_identity_json",
        "source_generations_json",
        "exclusions_json",
        "resumed_from_run_id",
        "started_at",
        "finished_at",
        "seal_json",
        "seal_sha256",
    }
)
_RETIRED_DISPATCH_COLUMNS = (
    "model",
    "reasoning",
    "skill_loaded",
    "scope_host",
    "permission",
    "command_budget",
    "output_schema",
    "files_allowed_json",
    "scope_path_prefix",
)
_VERIFICATION_STATUSES = frozenset(
    {
        "unreviewed",
        "disputed",
        "pending_runtime_proof",
        "blocked",
        "confirmed",
        "downgraded",
        "false_positive",
    }
)


@dataclass(frozen=True, slots=True)
class DatabaseFingerprint:
    path: Path
    device: int
    inode: int


def _resolve_busy_timeout_ms() -> int:
    """SQLite busy-timeout (ms) for short-lived connections.

    Matches the historical implicit sqlite3 default (5000 ms) but is now explicit
    and overridable via VIGIL_DB_BUSY_TIMEOUT_MS so the BEGIN IMMEDIATE wait can
    be tuned under multi-worker contention (E1). Invalid/negative values fall back
    to the default.
    """
    raw = os.environ.get("VIGIL_DB_BUSY_TIMEOUT_MS", "").strip()
    if raw:
        try:
            value = int(raw)
            if value >= 0:
                return value
        except ValueError:
            pass
    # Keep the default below AssessmentClient's 10 s read timeout. Exhausted
    # contention must reach the HTTP layer as a retryable 503; a longer SQLite
    # wait lets the client time out first and creates an ambiguous write result.
    return 8_000


_BUSY_TIMEOUT_MS = _resolve_busy_timeout_ms()
_thread_connections = threading.local()
_connection_generation = 0


_startup_database_fingerprint: DatabaseFingerprint | None = None
_LEGACY_FINDING_PREFIX = "FINDING" + "-"
_LEGACY_FINDING_REF_RE = re.compile(
    rf"\b{_LEGACY_FINDING_PREFIX}([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{{3}}[A-Z]?)\b"
)
_COVERAGE_STATUS_RANK = {
    "pending": 0,
    "queued": 1,
    "deferred": 2,
    "covered": 3,
    "not_applicable": 3,
    "blocked": 4,
}


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        row[1]
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def _database_needs_verification_status_migration(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with closing(sqlite3.connect(str(db_path))) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "assessment_findings" not in tables:
            return False
        finding_columns = _table_columns(connection, "assessment_findings")
        if "verification_status" not in finding_columns:
            return True
        if "assessment_finding_transitions" not in tables:
            return False
        transition_columns = _table_columns(
            connection, "assessment_finding_transitions"
        )
        return bool(
            {
                "from_verification_state",
                "to_verification_state",
                "from_verification_disposition",
                "to_verification_disposition",
            }.intersection(transition_columns)
            or not {
                "from_verification_status",
                "to_verification_status",
                "verification_event_version",
            }.issubset(transition_columns)
        )


def _database_needs_dispatch_schema_migration(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with closing(sqlite3.connect(str(db_path))) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if "assessment_dispatches" not in tables:
            return False
        columns = _table_columns(connection, "assessment_dispatches")
        return bool(columns.intersection(_RETIRED_DISPATCH_COLUMNS))


def _database_needs_retry_state_migration(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with closing(sqlite3.connect(str(db_path))) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' "
            "AND name = 'assessment_blocked_techniques'"
        ).fetchone()
    if row is None:
        return False
    table_sql = str(row[0] or "").lower()
    return "check" not in table_sql or "retry_state in" not in table_sql


def _database_needs_rate_lease_retirement(db_path: Path) -> bool:
    """Return whether the retired active lease table needs archival."""

    if not db_path.exists():
        return False
    with closing(sqlite3.connect(str(db_path))) as connection:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' "
            "AND name = 'assessment_rate_leases'"
        ).fetchone() is not None


def _database_run_accounting_migration_reasons(db_path: Path) -> tuple[str, ...]:
    """Describe Phase 2 run/proof schema that requires a protected upgrade."""

    if not db_path.exists():
        return ()
    with closing(sqlite3.connect(str(db_path))) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        anchors = {
            "assessment_runs",
            "assessment_proof_receipts",
            "assessment_finding_proof_receipts",
        }
        if not tables.intersection(anchors):
            return ()
        reasons = [
            f"missing_table:{table_name}"
            for table_name in sorted(_RUN_ACCOUNTING_TABLES - tables)
        ]
        if "assessment_runs" in tables:
            missing_columns = _RUN_ACCOUNTING_RUN_COLUMNS - _table_columns(
                connection, "assessment_runs"
            )
            reasons.extend(
                f"assessment_runs.missing_column:{column_name}"
                for column_name in sorted(missing_columns)
            )
            if connection.execute(
                "SELECT 1 FROM assessment_runs WHERE status = 'started' LIMIT 1"
            ).fetchone() is not None:
                reasons.append("assessment_runs.legacy_status:started")
        if "assessment_proof_receipts" in tables:
            proof_columns = _table_columns(connection, "assessment_proof_receipts")
            for column_name in ("command_run_id", "source_read_id"):
                if column_name not in proof_columns:
                    reasons.append(
                        f"assessment_proof_receipts.missing_column:{column_name}"
                    )
        if "assessment_finding_proof_receipts" in tables and "transition_id" not in _table_columns(
            connection, "assessment_finding_proof_receipts"
        ):
            reasons.append(
                "assessment_finding_proof_receipts.missing_column:transition_id"
            )
    return tuple(sorted(set(reasons)))


def _database_run_accounting_v2_migration_reasons(db_path: Path) -> tuple[str, ...]:
    """Describe additive automatic-signal schema requiring a protected upgrade."""

    if not db_path.exists():
        return ()
    with closing(sqlite3.connect(str(db_path))) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if not tables.intersection(_RUN_ACCOUNTING_TABLES):
            return ()
        reasons = [
            f"missing_table:{table_name}"
            for table_name in sorted(_RUN_ACCOUNTING_V2_TABLES - tables)
        ]
        if (
            "assessment_run_candidates" in tables
            and "originating_signal_id"
            not in _table_columns(connection, "assessment_run_candidates")
        ):
            reasons.append(
                "assessment_run_candidates.missing_column:originating_signal_id"
            )
        if (
            "assessment_run_code_receipt_links" in tables
            and "target_key"
            not in _table_columns(connection, "assessment_run_code_receipt_links")
        ):
            reasons.append(
                "assessment_run_code_receipt_links.missing_column:target_key"
            )
    return tuple(sorted(set(reasons)))


def _create_adjacent_migration_backup(db_path: Path, *, label: str) -> Path:
    """Create and verify a pre-migration snapshot before opening a writer."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_path = db_path.with_name(
        f"{db_path.name}.pre-{label}.{timestamp}.bak"
    )
    temporary_path = backup_path.with_suffix(backup_path.suffix + ".tmp")
    with closing(sqlite3.connect(str(db_path))) as source, closing(
        sqlite3.connect(str(temporary_path))
    ) as destination:
        source.backup(destination)
        quick_check = destination.execute("PRAGMA quick_check").fetchone()
        if quick_check is None or str(quick_check[0]).lower() != "ok":
            raise RuntimeError(
                f"pre-{label} database backup failed integrity check: {backup_path}"
            )
    temporary_path.replace(backup_path)
    return backup_path.resolve()


def _create_adjacent_verification_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(db_path, label="verification-status")


def _create_adjacent_dispatch_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(db_path, label="dispatch-schema")


def _create_adjacent_retry_state_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(db_path, label="retry-state")


def _create_adjacent_run_accounting_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(db_path, label="run-accounting")


def _create_adjacent_run_accounting_v2_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(db_path, label="run-accounting-v2")


def _create_adjacent_rate_lease_retirement_backup(db_path: Path) -> Path:
    return _create_adjacent_migration_backup(
        db_path, label="rate-lease-retirement"
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _verification_status_from_legacy_pair(
    state_value: Any, disposition_value: Any
) -> tuple[str, str]:
    state = str(state_value or "").strip().lower()
    disposition = str(disposition_value or "").strip().lower()
    explicit_pairs = {
        ("unreviewed", "none"): "unreviewed",
        ("disputed", "none"): "disputed",
        ("verified", "pending_runtime_proof"): "pending_runtime_proof",
        ("verified", "blocked"): "blocked",
        ("verified", "confirmed"): "confirmed",
        ("verified", "downgraded"): "downgraded",
        ("verified", "false_positive"): "false_positive",
    }
    mapped = explicit_pairs.get((state, disposition))
    if mapped is not None:
        return mapped, ""
    return (
        "unreviewed",
        f"invalid legacy verification pair state={state!r}, disposition={disposition!r}; "
        "mapped to unreviewed",
    )


def _create_migration_history_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            migration_id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            from_version TEXT NOT NULL,
            to_version TEXT NOT NULL,
            migrated_rows INTEGER NOT NULL,
            warning_count INTEGER NOT NULL,
            backup_path TEXT NOT NULL,
            report_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dispatch_column_migration_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_id TEXT NOT NULL,
            dispatch_id INTEGER NOT NULL,
            engagement_id INTEGER NOT NULL,
            agent_id TEXT NOT NULL,
            legacy_payload_json TEXT NOT NULL,
            migrated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(migration_id, dispatch_id),
            FOREIGN KEY(migration_id) REFERENCES schema_migrations(migration_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_verification_migration_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_id TEXT NOT NULL,
            finding_id INTEGER NOT NULL,
            legacy_state TEXT NOT NULL,
            legacy_disposition TEXT NOT NULL,
            mapped_status TEXT NOT NULL,
            warning TEXT NOT NULL DEFAULT '',
            migrated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(migration_id, finding_id),
            FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE CASCADE,
            FOREIGN KEY(migration_id) REFERENCES schema_migrations(migration_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_transition_verification_migration_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_id TEXT NOT NULL,
            transition_id INTEGER NOT NULL,
            finding_id INTEGER NOT NULL,
            legacy_from_state TEXT,
            legacy_from_disposition TEXT,
            legacy_to_state TEXT,
            legacy_to_disposition TEXT,
            mapped_from_status TEXT,
            mapped_to_status TEXT NOT NULL,
            warning TEXT NOT NULL DEFAULT '',
            migrated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(migration_id, transition_id),
            FOREIGN KEY(transition_id) REFERENCES assessment_finding_transitions(id)
                ON DELETE CASCADE,
            FOREIGN KEY(migration_id) REFERENCES schema_migrations(migration_id)
                ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_blocked_technique_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            blocked_technique_id INTEGER NOT NULL,
            technique_key TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            from_retry_state TEXT,
            to_retry_state TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            evidence_ref TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            provenance_json TEXT NOT NULL DEFAULT '{}',
            revalidation_context_json TEXT NOT NULL DEFAULT '{}',
            legacy_payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
        )
        """
    )


def _blocked_technique_table_sql(table_name: str) -> str:
    if table_name not in {
        "assessment_blocked_techniques",
        "assessment_blocked_techniques__retry_v1",
    }:
        raise ValueError(f"unsupported blocked-technique table name: {table_name}")
    allowed = ", ".join(f"'{value}'" for value in RETRY_STATES)
    return f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            technique_key TEXT NOT NULL,
            technique TEXT NOT NULL,
            target_kind TEXT NOT NULL DEFAULT '',
            target_ref TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            retry_state TEXT NOT NULL DEFAULT 'pending'
                CHECK (retry_state IN ({allowed})),
            evidence_ref TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            provenance_json TEXT NOT NULL DEFAULT '{{}}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, technique_key),
            FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
        )
    """


def _create_blocked_techniques_table(
    connection: sqlite3.Connection,
    *,
    table_name: str = "assessment_blocked_techniques",
) -> None:
    connection.execute(_blocked_technique_table_sql(table_name))


def _migrate_blocked_technique_retry_state(
    connection: sqlite3.Connection, *, backup_path: Path
) -> None:
    """Constrain retry state without promoting legacy prose into authority."""

    _create_migration_history_tables(connection)
    rows = connection.execute(
        """
        SELECT blocked.*, engagements.key AS engagement_key
        FROM assessment_blocked_techniques AS blocked
        LEFT JOIN engagements ON engagements.id = blocked.engagement_id
        ORDER BY blocked.id
        """
    ).fetchall()
    mappings: list[dict[str, Any]] = []
    warning_count = 0
    _create_blocked_techniques_table(
        connection, table_name="assessment_blocked_techniques__retry_v1"
    )
    for row in rows:
        mapped, warning = map_legacy_retry_state(row["retry_state"])
        payload = {
            key: row[key]
            for key in (
                "id",
                "engagement_id",
                "technique_key",
                "technique",
                "target_kind",
                "target_ref",
                "reason",
                "retry_state",
                "evidence_ref",
                "notes",
                "provenance_json",
                "created_at",
                "updated_at",
            )
        }
        connection.execute(
            """
            INSERT INTO assessment_blocked_techniques__retry_v1 (
                id, engagement_id, technique_key, technique, target_kind,
                target_ref, reason, retry_state, evidence_ref, notes,
                provenance_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["id"],
                payload["engagement_id"],
                payload["technique_key"],
                payload["technique"],
                payload["target_kind"],
                payload["target_ref"],
                payload["reason"],
                mapped,
                payload["evidence_ref"],
                payload["notes"],
                payload["provenance_json"],
                payload["created_at"],
                payload["updated_at"],
            ),
        )
        connection.execute(
            """
            INSERT INTO assessment_blocked_technique_history (
                engagement_id, blocked_technique_id, technique_key, event_kind,
                from_retry_state, to_retry_state, reason, evidence_ref, notes,
                provenance_json, revalidation_context_json, legacy_payload_json
            ) VALUES (?, ?, ?, 'migration', ?, ?, ?, ?, ?, ?, '{}', ?)
            """,
            (
                int(row["engagement_id"]),
                int(row["id"]),
                str(row["technique_key"]),
                str(row["retry_state"]),
                mapped,
                str(row["reason"]),
                str(row["evidence_ref"]),
                str(row["notes"]),
                str(row["provenance_json"]),
                json.dumps(payload, sort_keys=True),
            ),
        )
        mapping = {
            "engagement": str(row["engagement_key"] or ""),
            "technique_key": str(row["technique_key"]),
            "legacy_retry_state": str(row["retry_state"]),
            "mapped_retry_state": mapped,
            "warning": warning,
        }
        mappings.append(mapping)
        if warning:
            warning_count += 1
            logger.warning(
                "retry-state migration warning engagement=%s technique=%s: %s",
                row["engagement_key"],
                row["technique_key"],
                warning,
            )
    connection.execute("DROP TABLE assessment_blocked_techniques")
    connection.execute(
        "ALTER TABLE assessment_blocked_techniques__retry_v1 "
        "RENAME TO assessment_blocked_techniques"
    )
    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _RETRY_STATE_MIGRATION_ID,
            "free-text-retry-state",
            "retry-state-v1",
            len(rows),
            warning_count,
            str(backup_path),
            json.dumps(
                {"backup_path": str(backup_path), "mappings": mappings},
                sort_keys=True,
            ),
        ),
    )


def _migrate_finding_transition_verification_status(
    connection: sqlite3.Connection,
) -> list[dict[str, Any]]:
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    if "assessment_finding_transitions" not in tables:
        return []
    columns = _table_columns(connection, "assessment_finding_transitions")
    legacy_columns = {
        "from_verification_state",
        "to_verification_state",
        "from_verification_disposition",
        "to_verification_disposition",
    }
    has_legacy_columns = bool(legacy_columns.intersection(columns))
    if not has_legacy_columns and {
        "from_verification_status",
        "to_verification_status",
        "verification_event_version",
    }.issubset(columns):
        return []
    for column_name, definition in (
        ("from_verification_status", "TEXT"),
        ("to_verification_status", "TEXT NOT NULL DEFAULT 'unreviewed'"),
        ("verification_event_version", "INTEGER NOT NULL DEFAULT 2"),
    ):
        if column_name not in columns:
            connection.execute(
                "ALTER TABLE assessment_finding_transitions "
                f"ADD COLUMN {column_name} {definition}"
            )
    if not has_legacy_columns:
        # A partially upgraded database can already hold canonical transition
        # statuses while lacking only the event-version column. Adding that
        # column is sufficient; remapping from absent legacy columns would
        # overwrite preserved values with NULL/unreviewed.
        return []
    expression = {
        name: name if name in columns else "NULL"
        for name in legacy_columns
    }
    rows = connection.execute(
        f"""
        SELECT transitions.id, transitions.finding_id, findings.slug,
               engagements.key AS engagement_key,
               {expression['from_verification_state']} AS legacy_from_state,
               {expression['from_verification_disposition']} AS legacy_from_disposition,
               {expression['to_verification_state']} AS legacy_to_state,
               {expression['to_verification_disposition']} AS legacy_to_disposition
        FROM assessment_finding_transitions AS transitions
        LEFT JOIN assessment_findings AS findings ON findings.id = transitions.finding_id
        LEFT JOIN engagements ON engagements.id = transitions.engagement_id
        ORDER BY transitions.id
        """
    ).fetchall()
    report_rows: list[dict[str, Any]] = []
    for row in rows:
        legacy_from = (
            str(row["legacy_from_state"] or ""),
            str(row["legacy_from_disposition"] or ""),
        )
        if legacy_from == ("", ""):
            mapped_from, from_warning = None, ""
        else:
            mapped_from, from_warning = _verification_status_from_legacy_pair(
                *legacy_from
            )
        mapped_to, to_warning = _verification_status_from_legacy_pair(
            row["legacy_to_state"], row["legacy_to_disposition"]
        )
        warnings = "; ".join(
            value
            for value in (
                f"from: {from_warning}" if from_warning else "",
                f"to: {to_warning}" if to_warning else "",
            )
            if value
        )
        if warnings:
            logger.warning(
                "verification transition migration warning engagement=%s "
                "finding=%s transition=%s: %s",
                row["engagement_key"],
                row["slug"],
                row["id"],
                warnings,
            )
        connection.execute(
            """
            UPDATE assessment_finding_transitions
            SET from_verification_status = ?, to_verification_status = ?,
                verification_event_version = 1
            WHERE id = ?
            """,
            (mapped_from, mapped_to, int(row["id"])),
        )
        report_rows.append(
            {
                "transition_id": int(row["id"]),
                "finding_id": int(row["finding_id"]),
                "engagement": str(row["engagement_key"] or ""),
                "finding": str(row["slug"] or ""),
                "legacy_from_state": row["legacy_from_state"],
                "legacy_from_disposition": row["legacy_from_disposition"],
                "legacy_to_state": row["legacy_to_state"],
                "legacy_to_disposition": row["legacy_to_disposition"],
                "mapped_from_status": mapped_from,
                "mapped_to_status": mapped_to,
                "warning": warnings,
            }
        )
    for column_name in legacy_columns:
        if column_name in columns:
            connection.execute(
                "ALTER TABLE assessment_finding_transitions "
                f"DROP COLUMN {column_name}"
            )
    return report_rows


def _migrate_finding_verification_status(
    connection: sqlite3.Connection, *, backup_path: Path
) -> None:
    """Backfill finding/event status, preserve history, and rebuild the index."""

    _create_migration_history_tables(connection)
    columns = _table_columns(connection, "assessment_findings")
    migrate_findings = "verification_status" not in columns
    rows: list[sqlite3.Row] = []
    report_rows: list[dict[str, Any]] = []
    warning_count = 0
    if migrate_findings:
        legacy_state_column = "verification_state" in columns
        legacy_disposition_column = "verification_disposition" in columns
        connection.execute(
            "ALTER TABLE assessment_findings ADD COLUMN verification_status "
            "TEXT NOT NULL DEFAULT 'unreviewed'"
        )
        state_expression = (
            "findings.verification_state" if legacy_state_column else "''"
        )
        disposition_expression = (
            "findings.verification_disposition"
            if legacy_disposition_column
            else "''"
        )
        rows = connection.execute(
            f"""
            SELECT findings.id, findings.slug, engagements.key AS engagement_key,
                   {state_expression} AS legacy_state,
                   {disposition_expression} AS legacy_disposition
            FROM assessment_findings AS findings
            LEFT JOIN engagements ON engagements.id = findings.engagement_id
            ORDER BY findings.id
            """
        ).fetchall()
        for row in rows:
            mapped, warning = _verification_status_from_legacy_pair(
                row["legacy_state"], row["legacy_disposition"]
            )
            if mapped not in _VERIFICATION_STATUSES:
                raise RuntimeError(
                    f"verification migration produced invalid status: {mapped}"
                )
            connection.execute(
                "UPDATE assessment_findings SET verification_status = ? WHERE id = ?",
                (mapped, int(row["id"])),
            )
            report_rows.append(
                {
                    "engagement": str(row["engagement_key"] or ""),
                    "finding": str(row["slug"] or ""),
                    "legacy_state": str(row["legacy_state"] or ""),
                    "legacy_disposition": str(row["legacy_disposition"] or ""),
                    "verification_status": mapped,
                    "warning": warning,
                }
            )
            if warning:
                warning_count += 1
                logger.warning(
                    "verification migration warning engagement=%s finding=%s: %s",
                    row["engagement_key"],
                    row["slug"],
                    warning,
                )

        connection.execute("DROP INDEX IF EXISTS idx_assessment_findings_verification")
        if legacy_state_column:
            connection.execute(
                "ALTER TABLE assessment_findings DROP COLUMN verification_state"
            )
        if legacy_disposition_column:
            connection.execute(
                "ALTER TABLE assessment_findings DROP COLUMN verification_disposition"
            )
    transition_rows = _migrate_finding_transition_verification_status(connection)
    warning_count += sum(bool(row["warning"]) for row in transition_rows)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_findings_verification "
        "ON assessment_findings(engagement_id, verification_status)"
    )
    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(migration_id) DO UPDATE SET
            to_version = excluded.to_version,
            migrated_rows = schema_migrations.migrated_rows + excluded.migrated_rows,
            warning_count = schema_migrations.warning_count + excluded.warning_count,
            report_json = excluded.report_json
        """,
        (
            _VERIFICATION_STATUS_MIGRATION_ID,
            "verification-pair",
            "verification-status-v1",
            len(rows) + len(transition_rows),
            warning_count,
            str(backup_path),
            json.dumps(
                {
                    "finding_rows": report_rows,
                    "transition_rows": transition_rows,
                    "backup_path": str(backup_path),
                },
                sort_keys=True,
            ),
        ),
    )
    for row in rows:
        mapped, warning = _verification_status_from_legacy_pair(
            row["legacy_state"], row["legacy_disposition"]
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO finding_verification_migration_history (
                migration_id, finding_id, legacy_state, legacy_disposition,
                mapped_status, warning
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                _VERIFICATION_STATUS_MIGRATION_ID,
                int(row["id"]),
                str(row["legacy_state"] or ""),
                str(row["legacy_disposition"] or ""),
                mapped,
                warning,
            ),
        )
    for row in transition_rows:
        connection.execute(
            """
            INSERT OR IGNORE INTO finding_transition_verification_migration_history (
                migration_id, transition_id, finding_id,
                legacy_from_state, legacy_from_disposition,
                legacy_to_state, legacy_to_disposition,
                mapped_from_status, mapped_to_status, warning
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _VERIFICATION_STATUS_MIGRATION_ID,
                row["transition_id"],
                row["finding_id"],
                row["legacy_from_state"],
                row["legacy_from_disposition"],
                row["legacy_to_state"],
                row["legacy_to_disposition"],
                row["mapped_from_status"],
                row["mapped_to_status"],
                row["warning"],
            ),
        )


def _normalize_unobserved_dispatch_actual_identity(
    connection: sqlite3.Connection,
) -> None:
    columns = _table_columns(connection, "assessment_dispatches")
    for column in ("actual_model", "actual_reasoning"):
        if column in columns:
            connection.execute(
                f"UPDATE assessment_dispatches SET {column} = 'unknown' "
                f"WHERE {column} IS NULL OR "
                f"trim({column}, ' ' || char(9) || char(10) || char(11) || "
                "char(12) || char(13)) = ''"
            )


def _migrate_dispatch_schema(
    connection: sqlite3.Connection, *, backup_path: Path
) -> None:
    """Preserve retired dispatch data and add exact instruction provenance."""

    columns = _table_columns(connection, "assessment_dispatches")
    retired = [name for name in _RETIRED_DISPATCH_COLUMNS if name in columns]
    if not retired:
        return
    _create_migration_history_tables(connection)

    additions = {
        "requested_model": "TEXT",
        "actual_model": "TEXT NOT NULL DEFAULT 'unknown'",
        "requested_reasoning": "TEXT",
        "actual_reasoning": "TEXT NOT NULL DEFAULT 'unknown'",
        "launcher_effective_model": "TEXT",
        "launcher_effective_reasoning": "TEXT",
        "launcher_effective_source": "TEXT",
        "client_name": "TEXT NOT NULL DEFAULT 'unknown'",
        "requested_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "launcher_effective_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "provider_observed_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "source_revision": "TEXT NOT NULL DEFAULT 'unknown'",
        "operator_instruction_path": "TEXT",
        "operator_instruction_sha256": "TEXT",
        "specialist_instruction_path": "TEXT",
        "specialist_instruction_sha256": "TEXT",
        "instruction_identity_status": "TEXT NOT NULL DEFAULT 'incomplete'",
        "instructions_stale": "INTEGER",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(
                f"ALTER TABLE assessment_dispatches ADD COLUMN {name} {definition}"
            )
    _normalize_unobserved_dispatch_actual_identity(connection)
    if "model" in columns:
        connection.execute(
            "UPDATE assessment_dispatches SET requested_model = model "
            "WHERE requested_model IS NULL"
        )
    if "reasoning" in columns:
        connection.execute(
            "UPDATE assessment_dispatches SET requested_reasoning = reasoning "
            "WHERE requested_reasoning IS NULL"
        )

    select_columns = ", ".join(["id", "engagement_id", "agent_id", *retired])
    rows = connection.execute(
        f"SELECT {select_columns} FROM assessment_dispatches ORDER BY id"
    ).fetchall()
    report_rows: list[dict[str, Any]] = []
    for row in rows:
        legacy = {name: row[name] for name in retired}
        report_rows.append(
            {
                "dispatch_id": int(row["id"]),
                "engagement_id": int(row["engagement_id"]),
                "agent_id": str(row["agent_id"]),
                "legacy": legacy,
            }
        )

    for index_row in connection.execute(
        "PRAGMA index_list(assessment_dispatches)"
    ).fetchall():
        index_name = str(index_row[1])
        indexed_columns = {
            str(info[2])
            for info in connection.execute(f'PRAGMA index_info("{index_name}")')
        }
        if indexed_columns.intersection(retired) and not index_name.startswith(
            "sqlite_autoindex_"
        ):
            escaped = index_name.replace('"', '""')
            connection.execute(f'DROP INDEX "{escaped}"')
    for name in retired:
        connection.execute(f"ALTER TABLE assessment_dispatches DROP COLUMN {name}")

    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _DISPATCH_SCHEMA_MIGRATION_ID,
            "dispatch-legacy-columns",
            "dispatch-provenance-v1",
            len(rows),
            0,
            str(backup_path),
            json.dumps(
                {"retired_columns": retired, "rows": report_rows}, sort_keys=True
            ),
        ),
    )
    for row in report_rows:
        connection.execute(
            """
            INSERT INTO dispatch_column_migration_history (
                migration_id, dispatch_id, engagement_id, agent_id,
                legacy_payload_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                _DISPATCH_SCHEMA_MIGRATION_ID,
                row["dispatch_id"],
                row["engagement_id"],
                row["agent_id"],
                json.dumps(row["legacy"], sort_keys=True),
            ),
        )


def _has_unique_index_on_columns(
    connection: sqlite3.Connection, table_name: str, columns: tuple[str, ...]
) -> bool:
    for row in connection.execute(f"PRAGMA index_list({table_name})"):
        index_name = str(row[1])
        is_unique = bool(row[2])
        if not is_unique:
            continue
        indexed_columns = tuple(
            str(info[2])
            for info in connection.execute(f"PRAGMA index_info({index_name})")
        )
        if indexed_columns == columns:
            return True
    return False


def _append_notes(existing: str, incoming: str) -> str:
    if not incoming:
        return existing
    if not existing:
        return incoming
    if incoming in existing.splitlines():
        return existing
    return existing + "\n" + incoming


def _merge_coverage_status(statuses: list[str]) -> str:
    best_status = "pending"
    best_rank = _COVERAGE_STATUS_RANK[best_status]
    for status_value in statuses:
        normalized = str(status_value or "pending").strip().lower()
        rank = _COVERAGE_STATUS_RANK.get(normalized, 0)
        if rank > best_rank:
            best_status = normalized
            best_rank = rank
    return best_status


def _refresh_service_coverage_status(
    connection: sqlite3.Connection, engagement_id: int, service_id: int
) -> None:
    # Sibling of state_manager.coverage._refresh_service_coverage_status. They are
    # NOT merged on purpose: importing that one here would create a cycle
    # (db -> coverage -> events -> db), and this migration/dedupe-time copy must
    # tolerate arbitrary legacy status strings (raw .lower()) rather than validate
    # against the CoverageStatus enum (which raises). Keep the bucketing logic in sync.
    rows = connection.execute(
        "SELECT status FROM assessment_coverage_items WHERE engagement_id = ? AND service_id = ?",
        (engagement_id, service_id),
    ).fetchall()
    if not rows:
        return
    statuses = [str(row[0] or "pending").strip().lower() for row in rows]
    if all(status_value in {"covered", "not_applicable"} for status_value in statuses):
        coverage_status = "covered"
    elif any(status_value == "blocked" for status_value in statuses):
        coverage_status = "blocked"
    elif any(
        status_value in {"covered", "not_applicable", "deferred"}
        for status_value in statuses
    ):
        coverage_status = "partial"
    else:
        coverage_status = "pending"
    connection.execute(
        """
        UPDATE assessment_services
        SET coverage_status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND engagement_id = ?
        """,
        (coverage_status, service_id, engagement_id),
    )


def _dedupe_coverage_items(connection: sqlite3.Connection) -> None:
    duplicate_groups = connection.execute(
        """
        SELECT
            engagement_id,
            request_variant_id,
            service_id,
            auth_context,
            input_slot,
            attack_family
        FROM assessment_coverage_items
        GROUP BY
            engagement_id,
            COALESCE(request_variant_id, -1),
            COALESCE(service_id, -1),
            auth_context,
            input_slot,
            attack_family
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    affected_services: set[tuple[int, int]] = set()
    for (
        engagement_id,
        request_variant_id,
        service_id,
        auth_context,
        input_slot,
        attack_family,
    ) in duplicate_groups:
        rows = connection.execute(
            """
            SELECT id, status, notes
            FROM assessment_coverage_items
            WHERE engagement_id = ?
              AND request_variant_id IS ?
              AND service_id IS ?
              AND auth_context = ?
              AND input_slot = ?
              AND attack_family = ?
            ORDER BY id ASC
            """,
            (
                engagement_id,
                request_variant_id,
                service_id,
                auth_context,
                input_slot,
                attack_family,
            ),
        ).fetchall()
        if len(rows) < 2:
            continue
        keeper_id = int(rows[0][0])
        merged_status = _merge_coverage_status(
            [str(row[1] or "pending") for row in rows]
        )
        merged_notes = ""
        for row in rows:
            merged_notes = _append_notes(merged_notes, str(row[2] or ""))
        connection.execute(
            """
            UPDATE assessment_coverage_items
            SET status = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (merged_status, merged_notes, keeper_id),
        )
        for row in rows[1:]:
            duplicate_id = int(row[0])
            connection.execute(
                "UPDATE assessment_probe_runs SET coverage_item_id = ? WHERE coverage_item_id = ?",
                (keeper_id, duplicate_id),
            )
            connection.execute(
                "DELETE FROM assessment_coverage_items WHERE id = ?", (duplicate_id,)
            )
        if service_id is not None:
            affected_services.add((int(engagement_id), int(service_id)))
    for engagement_id, service_id in affected_services:
        _refresh_service_coverage_status(connection, engagement_id, service_id)


def _strip_legacy_finding_prefix(value: str) -> str:
    if value.startswith(_LEGACY_FINDING_PREFIX):
        return value[len(_LEGACY_FINDING_PREFIX) :]
    return value


def _normalize_legacy_finding_refs(
    value: str, slug_map: dict[tuple[int, str], str], engagement_id: int | None
) -> str:
    def replace(match: re.Match[str]) -> str:
        old_slug = match.group(0)
        if engagement_id is not None:
            mapped_slug = slug_map.get((engagement_id, old_slug))
            if mapped_slug is not None:
                return mapped_slug
        return match.group(1)

    return _LEGACY_FINDING_REF_RE.sub(replace, value)


def _strip_legacy_finding_prefixes(
    value,
    slug_map: dict[tuple[int, str], str] | None = None,
    engagement_id: int | None = None,
):
    if isinstance(value, str):
        normalized = _normalize_legacy_finding_refs(
            value, slug_map or {}, engagement_id
        )
        return normalized, normalized != value
    if isinstance(value, list):
        changed = False
        normalized_items = []
        for item in value:
            normalized_item, item_changed = _strip_legacy_finding_prefixes(
                item, slug_map, engagement_id
            )
            normalized_items.append(normalized_item)
            changed = changed or item_changed
        return normalized_items, changed
    if isinstance(value, dict):
        changed = False
        normalized_dict = {}
        for key, item in value.items():
            normalized_item, item_changed = _strip_legacy_finding_prefixes(
                item, slug_map, engagement_id
            )
            normalized_dict[key] = normalized_item
            changed = changed or item_changed
        return normalized_dict, changed
    return value, False


def _next_legacy_collision_slug(
    connection: sqlite3.Connection, engagement_id: int, preferred_slug: str, row_id: int
) -> str:
    candidate = f"{preferred_slug}-legacy-{row_id}"
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
        (engagement_id, candidate),
    ).fetchone():
        candidate = f"{preferred_slug}-legacy-{row_id}-{suffix}"
        suffix += 1
    return candidate


def _migrate_legacy_finding_slugs(
    connection: sqlite3.Connection,
) -> dict[tuple[int, str], str]:
    if not {"id", "engagement_id", "slug"}.issubset(
        _table_columns(connection, "assessment_findings")
    ):
        return {}

    slug_map: dict[tuple[int, str], str] = {}
    rows = connection.execute(
        """
        SELECT id, engagement_id, slug
        FROM assessment_findings
        WHERE slug LIKE ?
        ORDER BY engagement_id ASC, id ASC
        """,
        (f"{_LEGACY_FINDING_PREFIX}%",),
    ).fetchall()
    for row_id, engagement_id, old_slug in rows:
        if not isinstance(old_slug, str):
            continue
        normalized = _strip_legacy_finding_prefix(old_slug)
        collision = connection.execute(
            """
            SELECT 1
            FROM assessment_findings
            WHERE engagement_id = ?
              AND slug = ?
              AND id != ?
            """,
            (engagement_id, normalized, row_id),
        ).fetchone()
        if collision is not None:
            normalized = _next_legacy_collision_slug(
                connection, int(engagement_id), normalized, int(row_id)
            )
        if normalized != old_slug:
            connection.execute(
                "UPDATE assessment_findings SET slug = ? WHERE id = ?",
                (normalized, row_id),
            )
            slug_map[(int(engagement_id), old_slug)] = normalized
    return slug_map


def _migrate_legacy_finding_prefix_in_text_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    slug_map: dict[tuple[int, str], str],
) -> None:
    columns = _table_columns(connection, table_name)
    if column_name not in columns:
        return
    select_columns = (
        "id, engagement_id, " + column_name
        if "engagement_id" in columns
        else "id, " + column_name
    )
    rows = connection.execute(
        f"SELECT {select_columns} FROM {table_name} WHERE {column_name} LIKE ?",
        (f"{_LEGACY_FINDING_PREFIX}%",),
    ).fetchall()
    for row in rows:
        row_id = row[0]
        if "engagement_id" in columns:
            engagement_id = int(row[1])
            value = row[2]
        else:
            engagement_id = None
            value = row[1]
        if not isinstance(value, str):
            continue
        normalized = (
            slug_map.get((engagement_id, value), _strip_legacy_finding_prefix(value))
            if engagement_id is not None
            else _strip_legacy_finding_prefix(value)
        )
        if normalized != value:
            connection.execute(
                f"UPDATE {table_name} SET {column_name} = ? WHERE id = ?",
                (normalized, row_id),
            )


def _migrate_legacy_finding_prefix_in_json_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    slug_map: dict[tuple[int, str], str],
) -> None:
    columns = _table_columns(connection, table_name)
    if column_name not in columns:
        return
    select_columns = (
        "id, engagement_id, " + column_name
        if "engagement_id" in columns
        else "id, " + column_name
    )
    rows = connection.execute(
        f"SELECT {select_columns} FROM {table_name} WHERE {column_name} LIKE ?",
        (f"%{_LEGACY_FINDING_PREFIX}%",),
    ).fetchall()
    for row in rows:
        row_id = row[0]
        if "engagement_id" in columns:
            engagement_id = int(row[1])
            value = row[2]
        else:
            engagement_id = None
            value = row[1]
        if not isinstance(value, str):
            continue
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            continue
        normalized, changed = _strip_legacy_finding_prefixes(
            payload, slug_map, engagement_id
        )
        if changed:
            connection.execute(
                f"UPDATE {table_name} SET {column_name} = ? WHERE id = ?",
                (json.dumps(normalized, ensure_ascii=True), row_id),
            )


def _migrate_legacy_finding_slug_references(connection: sqlite3.Connection) -> None:
    slug_map = _migrate_legacy_finding_slugs(connection)
    for table_name, column_name in (
        ("assessment_finding_links", "target_ref"),
        ("assessment_attack_chain_links", "entity_ref"),
        ("code_analysis_results", "finding_slug"),
        ("intel_notes", "linked_finding_slug"),
    ):
        _migrate_legacy_finding_prefix_in_text_column(
            connection, table_name, column_name, slug_map
        )

    for table_name, column_name in (
        ("assessment_findings", "details_json"),
        ("assessment_findings", "provenance_json"),
        ("engagement_sessions", "assigned_targets_json"),
        ("assessment_finding_transitions", "metadata_json"),
    ):
        _migrate_legacy_finding_prefix_in_json_column(
            connection, table_name, column_name, slug_map
        )


class IncompatibleDatabaseError(RuntimeError):
    """Raised when the on-disk orchestrator DB does not match the current schema.

    Auto-reset was removed intentionally: the engagement database holds
    canonical findings, probe runs, command-run audit, and code analysis
    state. Silently unlinking it on a schema mismatch is unrecoverable
    data loss. Operators must triage an incompatibility explicitly.
    """


def _incompatible_message(db_path: Path, reason: str) -> str:
    return (
        f"Orchestrator database at {db_path} is incompatible with the current schema: {reason}.\n"
        "Refusing to start — auto-reset would delete engagement history (findings, probes, "
        "command runs, code analysis) with no backup.\n"
        "Resolve manually, in order of preference:\n"
        "  1. Investigate the schema drift and migrate the data in place.\n"
        f"  2. If the data is not needed, move the file aside yourself, e.g.:\n"
        f"       ts=$(date +%Y%m%dT%H%M%S)\n"
        f"       for s in '' '-shm' '-wal'; do\n"
        f"         [[ -f {db_path}$s ]] && mv {db_path}$s {db_path}.incompatible.$ts$s\n"
        f"       done\n"
        "     Then restart the orchestrator; it will initialise a fresh database.\n"
        "No files have been modified."
    )


_ENGAGEMENT_SCOPED_TABLES = {
    "engagement_sessions",
    "events",
    "assessment_targets",
    "assessment_services",
    "assessment_request_variants",
    "assessment_request_observations",
    "assessment_coverage_items",
    "assessment_work_items",
    "assessment_probe_runs",
    "assessment_surfaces",
    "assessment_findings",
    "assessment_finding_transitions",
    "assessment_finding_links",
    "assessment_attack_chains",
    "assessment_attack_chain_links",
    "assessment_credentials",
    "assessment_credential_tests",
    "assessment_access_records",
    "assessment_pivots",
    "assessment_tunnels",
    "assessment_blocked_techniques",
    "assessment_blocked_technique_history",
    "assessment_command_runs",
    "assessment_artifacts",
    "assessment_artifact_path_reservations",
    "assessment_jobs",
    "code_repos",
    "code_modules",
    "code_files",
    "code_analysis_queue",
    "code_analysis_results",
    "code_analysis_triggers",
    "code_variant_check_receipts",
    "code_variant_dispatch_scopes",
    "code_fuzz_decisions",
    "code_fuzz_campaign_receipts",
    "intel_tech_components",
    "intel_people",
    "intel_emails",
    "intel_domains",
    "intel_cves",
    "intel_dns_records",
    "intel_social_profiles",
    "intel_breach_records",
    "intel_org_facts",
    "intel_notes",
    "intel_search_index",
    "activity_entries",
    "assessment_dispatches",
    "assessment_dispatch_handoffs",
    "assessment_dispatch_decisions",
    "assessment_oob_probes",
    "assessment_oob_interactions",
}


def _check_database_compatibility(db_path: Path) -> None:
    """Raise :class:`IncompatibleDatabaseError` if the DB cannot safely serve
    the current schema. Never modifies the filesystem.

    Only known engagement-scoped tables must carry ``engagement_id``. A future
    shared, non-engagement-scoped table may still use an ``assessment_`` or
    ``code_`` prefix without tripping this check, but current scoped tables
    missing ``engagement_id`` would fail later CRUD and must refuse startup.
    """
    if not db_path.exists():
        return

    try:
        with closing(sqlite3.connect(str(db_path))) as connection, connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }

            legacy = {"projects", "runs", "users"} & tables
            if legacy:
                raise IncompatibleDatabaseError(
                    _incompatible_message(
                        db_path,
                        f"legacy pre-engagement tables present: {sorted(legacy)}",
                    )
                )

            scoped_tables = _ENGAGEMENT_SCOPED_TABLES & tables
            for table_name in scoped_tables:
                columns = _table_columns(connection, table_name)
                if "run_id" in columns:
                    raise IncompatibleDatabaseError(
                        _incompatible_message(
                            db_path,
                            f"{table_name} still has pre-engagement `run_id` column",
                        )
                    )
                if "engagement_id" not in columns:
                    raise IncompatibleDatabaseError(
                        _incompatible_message(
                            db_path,
                            f"{table_name} is missing required `engagement_id` column",
                        )
                    )
    except sqlite3.OperationalError:
        # `database is locked` and friends are transient — let the caller see
        # the raw OperationalError so uvicorn's retry/startup logic can
        # distinguish contention from real incompatibility. Converting this to
        # IncompatibleDatabaseError would tell the operator to move the DB
        # aside for what is actually a concurrent-access race.
        raise
    except sqlite3.DatabaseError as exc:
        raise IncompatibleDatabaseError(
            _incompatible_message(db_path, f"SQLite refused to open the file: {exc}")
        ) from exc


def database_path() -> Path:
    return settings.data_dir / "orchestrator.sqlite3"


def _database_fingerprint(db_path: Path) -> DatabaseFingerprint:
    stat_result = db_path.stat()
    return DatabaseFingerprint(
        path=db_path.resolve(), device=stat_result.st_dev, inode=stat_result.st_ino
    )


def _require_startup_database_fingerprint() -> DatabaseFingerprint:
    if _startup_database_fingerprint is None:
        raise RuntimeError(
            "Orchestrator database has not been initialized for this process"
        )
    return _startup_database_fingerprint


def _verify_database_fingerprint() -> Path:
    expected = _require_startup_database_fingerprint()
    db_path = database_path()
    if db_path.resolve() != expected.path:
        raise RuntimeError(
            f"Orchestrator database path changed after startup: expected {expected.path}, got {db_path.resolve()}"
        )
    if not db_path.exists():
        raise RuntimeError(
            f"Orchestrator database file disappeared after startup: {db_path}"
        )
    current = _database_fingerprint(db_path)
    if current.device != expected.device or current.inode != expected.inode:
        raise RuntimeError(
            f"Orchestrator database file changed after startup: expected dev/inode "
            f"{expected.device}/{expected.inode}, got {current.device}/{current.inode}"
        )
    return db_path


def database_cache_token() -> tuple[str, int, int, int]:
    fingerprint = _require_startup_database_fingerprint()
    return (
        str(fingerprint.path),
        fingerprint.device,
        fingerprint.inode,
        _connection_generation,
    )


def _require_fts5(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT sqlite_compileoption_used('ENABLE_FTS5')"
    ).fetchone()
    if not row or not row[0]:
        raise RuntimeError(
            "Orchestrator SQLite build lacks FTS5 support, which assessment_command_runs search requires. "
            "Rebuild the interpreter's SQLite with ENABLE_FTS5 or use a Python/SQLite distribution that ships it."
        )


def _create_core_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                engagement_type TEXT NULL DEFAULT 'red',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
    )
    # Additive migration for pre-existing DBs created before the
    # ``engagement_type`` column was introduced. New schema gets it via
    # CREATE TABLE above; existing rows stay NULL (no DEFAULT backfill —
    # the DEFAULT only applies on INSERT of new rows). Allowed values are
    # enforced in the Pydantic layer ('red' | 'web' | 'code' | 'both' |
    # 'android' | 'blue'); the schema stays free-form TEXT so the enum can
    # evolve without a rebuild.
    engagement_columns = _table_columns(connection, "engagements")
    if engagement_columns and "engagement_type" not in engagement_columns:
        connection.execute(
            "ALTER TABLE engagements ADD COLUMN engagement_type TEXT NULL DEFAULT 'red'"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_engagements_engagement_type "
        "ON engagements(engagement_type)"
    )
    # NOTE: Older dev databases may carry an ``engagement_token`` column
    # left over from a previous experiment. SQLite < 3.35 cannot DROP
    # COLUMN, and even with newer SQLite a rewrite would force every
    # operator to take downtime. The orchestrator simply stops reading
    # and writing the column; fresh DBs created from the schema above
    # never have it.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS engagement_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                session_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                merge_state TEXT NOT NULL DEFAULT 'pending',
                assigned_targets_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                merged_at TEXT,
                UNIQUE(engagement_id, session_id),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                phase TEXT NOT NULL,
                task_name TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_engagement_id "
        "ON events(engagement_id, id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_engagement_created "
        "ON events(engagement_id, created_at DESC, id DESC)"
    )


# Additive column spec for engagement_credentials (multi-identity session store,
# 2026-07). New freshness/liveness columns are appended here so an existing DB
# created before they existed upgrades cleanly via the same _table_columns
# pattern used for assessment_http_flows. All nullable — populated by upsert
# (created_at/last_seen_at) or by the liveness probe (liveness_verdict/
# last_probed_at); the age sweep tolerates NULL last_seen_at.
_CREDENTIAL_ADDITIVE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("principal_id", "TEXT NOT NULL DEFAULT ''"),
    ("mfa_factor", "TEXT NOT NULL DEFAULT ''"),
    ("created_at", "TEXT"),
    ("last_seen_at", "TEXT"),
    ("liveness_verdict", "TEXT"),
    ("last_probed_at", "TEXT"),
)


def _create_credentials_table(connection: sqlite3.Connection) -> None:
    """Centralized per-engagement credential store (replaces auth.json).

    One row per (engagement, identity_name). The named-identity model is
    preserved (cross-identity IDOR/BOLA depth needs ≥2 users), so the engagement
    key alone is not unique — identity_name is part of the key. ``is_active``
    marks the engagement's default identity (the one resolved when no
    ``--identity`` is requested); the service layer keeps at most one active row
    per engagement. Known auth material is stored in typed JSON columns; the
    ``raw_json`` column preserves the full captured/imported payload verbatim so
    sessions we don't fully model (custom token shapes, unusual headers) are
    never lost — the materializer applies what it understands and round-trips
    the rest. Rows cascade-delete with their engagement.
    """
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS engagement_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                identity_name TEXT NOT NULL,
                principal_id TEXT NOT NULL DEFAULT '',
                mfa_factor TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT 'manual',
                state TEXT NOT NULL DEFAULT 'missing',
                use_for_requests INTEGER NOT NULL DEFAULT 1,
                auth_context TEXT NOT NULL DEFAULT 'authenticated',
                is_active INTEGER NOT NULL DEFAULT 0,
                cookies_json TEXT NOT NULL DEFAULT '{}',
                headers_json TEXT NOT NULL DEFAULT '{}',
                tokens_json TEXT NOT NULL DEFAULT '{}',
                host_cookies_json TEXT NOT NULL DEFAULT '[]',
                raw_json TEXT NOT NULL DEFAULT '{}',
                notes TEXT NOT NULL DEFAULT '',
                expires_at TEXT,
                created_at TEXT,
                last_seen_at TEXT,
                liveness_verdict TEXT,
                last_probed_at TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, identity_name),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    # Additive migration for pre-existing DBs (mirrors the assessment_http_flows
    # pattern): ALTER-in any freshness/liveness column absent from an older
    # on-disk schema. Fresh DBs already have every column via CREATE TABLE above,
    # so this only backfills. All new columns are nullable (no backfill value):
    # created_at/last_seen_at populate on the next upsert, and the age-backstop
    # sweep skips rows whose last_seen_at is NULL (no false hard-delete of a row
    # that predates the column).
    credential_columns = _table_columns(connection, "engagement_credentials")
    if credential_columns:
        for column_name, column_ddl in _CREDENTIAL_ADDITIVE_COLUMNS:
            if column_name not in credential_columns:
                connection.execute(
                    f"ALTER TABLE engagement_credentials ADD COLUMN {column_name} {column_ddl}"
                )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_engagement_credentials_engagement "
        "ON engagement_credentials(engagement_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_engagement_credentials_active "
        "ON engagement_credentials(engagement_id, is_active DESC, identity_name)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS engagement_credential_aliases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            alias TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            scope_key TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, alias, scope_key),
            FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS engagement_credential_liveness (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            identity_name TEXT NOT NULL,
            scope_key TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            UNIQUE(engagement_id, identity_name, scope_key),
            FOREIGN KEY(engagement_id, identity_name)
                REFERENCES engagement_credentials(engagement_id, identity_name)
                ON DELETE CASCADE
        )
        """
    )
    # Ordering + the age-backstop sweep both scan by (engagement, last_seen_at).
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_engagement_credentials_last_seen "
        "ON engagement_credentials(engagement_id, last_seen_at DESC)"
    )


def _create_assessment_entity_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                identity TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'host',
                host TEXT,
                ip_address TEXT,
                hostname TEXT,
                notes TEXT NOT NULL DEFAULT '',
                discovered_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, identity),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                target_id INTEGER,
                endpoint TEXT NOT NULL,
                port INTEGER,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                service TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'discovered',
                coverage_status TEXT NOT NULL DEFAULT 'pending',
                banner TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                discovered_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, endpoint, protocol),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(target_id) REFERENCES assessment_targets(id) ON DELETE SET NULL
            )
            """
    )
    # Authoritative, freshness-aware host-liveness ledger. One row per
    # (engagement, host); httpx probes upsert it via `vigil assess ingest-httpx`.
    # reachability_class is the stored verdict (live/dead/blackholed/unknown);
    # the read projection degrades a stale verdict to 'stale' past the TTL so
    # a 2-hour-old "live" forces a re-probe rather than being trusted across
    # the shifting-egress boundary.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_host_liveness (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                status_code INTEGER,
                scheme TEXT NOT NULL DEFAULT '',
                final_url TEXT NOT NULL DEFAULT '',
                host_ip TEXT NOT NULL DEFAULT '',
                tech TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                webserver TEXT NOT NULL DEFAULT '',
                tls TEXT NOT NULL DEFAULT '',
                failed INTEGER NOT NULL DEFAULT 0,
                reachability_class TEXT NOT NULL DEFAULT 'unknown',
                probed_at TEXT,
                source TEXT NOT NULL DEFAULT '',
                source_run_id INTEGER,
                source_run_uuid TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, host),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(source_run_id) REFERENCES assessment_command_runs(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_host_liveness_class "
        "ON assessment_host_liveness(engagement_id, reachability_class)"
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_request_variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                scheme TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                method TEXT NOT NULL,
                normalized_path TEXT NOT NULL,
                path_template TEXT NOT NULL DEFAULT '',
                canonical_url TEXT NOT NULL DEFAULT '',
                -- Scorer-fact audit (CONCLUSION — no new column):
                -- the app-unit scorer's "static-asset" suppressor is
                -- DERIVABLE from existing columns and needs NO new
                -- raw_payload/observation fact. A variant is static-asset when
                -- content_type_family is an asset family (image/font/style/
                -- script/media) AND method == 'GET' AND the query/body/path
                -- schemas are empty (no params). The scorer computes this at
                -- score time from content_type_family + method + the *_schema_json
                -- columns below, so we deliberately do NOT add a column here.
                content_type_family TEXT NOT NULL DEFAULT 'unknown',
                query_schema_json TEXT NOT NULL DEFAULT '{}',
                body_schema_json TEXT NOT NULL DEFAULT '{}',
                path_schema_json TEXT NOT NULL DEFAULT '{}',
                cookie_schema_json TEXT NOT NULL DEFAULT '{}',
                header_schema_json TEXT NOT NULL DEFAULT '{}',
                params_schema_hash TEXT NOT NULL,
                body_schema_hash TEXT NOT NULL,
                discovery_source TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(
                    engagement_id,
                    scheme,
                    host,
                    port,
                    method,
                    normalized_path,
                    auth_context,
                    params_schema_hash,
                    body_schema_hash,
                    content_type_family
                ),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_request_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                request_variant_id INTEGER NOT NULL,
                observed_url TEXT NOT NULL,
                source_name TEXT NOT NULL DEFAULT '',
                response_status INTEGER,
                evidence_ref TEXT NOT NULL DEFAULT '',
                raw_payload TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_request_variants_seen "
        "ON assessment_request_variants(engagement_id, last_seen_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_request_observations_created "
        "ON assessment_request_observations(engagement_id, created_at DESC, id DESC)"
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_coverage_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                request_variant_id INTEGER,
                service_id INTEGER,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                input_slot TEXT NOT NULL,
                attack_family TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_probe_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                request_variant_id INTEGER,
                service_id INTEGER,
                coverage_item_id INTEGER,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                input_slot TEXT NOT NULL DEFAULT 'unknown',
                attack_family TEXT NOT NULL,
                payload_family TEXT NOT NULL DEFAULT '',
                payload_value_hash TEXT NOT NULL DEFAULT '',
                probe_key TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                -- result_status vocabulary.
                -- Column stays TEXT (forward-compatible: a new status can be
                -- added to PROBE_RESULT_STATUSES without a destructive
                -- migration). The 'tested' default is a well-formed outcome
                -- label ONLY — it is NOT silently promoted to "covered".
                -- Canonical vocabulary + the covering subset
                -- (tested/signal only) live in
                -- app.services.state_manager.coverage.PROBE_RESULT_STATUSES /
                -- PROBE_RESULT_STATUSES_COVERING, validated on every write.
                result_status TEXT NOT NULL DEFAULT 'tested',
                observed_http_status INTEGER,
                signal_type TEXT NOT NULL DEFAULT '',
                outcome_assertion TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                -- Target anchor. A raw/list-mode probe with a
                -- null request_variant_id still carries the host it tested, so
                -- it can be mapped to an app unit and its probe_key no longer
                -- collides with other null-FK probes (these columns are part of
                -- _probe_key in coverage.py). Path/port are often absent from
                -- kali argv, so they default empty/NULL.
                target_host TEXT NOT NULL DEFAULT '',
                target_path TEXT NOT NULL DEFAULT '',
                target_port INTEGER,
                -- Free-text lens/mindset the probe was run under (e.g. an attack
                -- persona or hypothesis label). Part of _probe_key in coverage.py
                -- so the SAME target probed under a DIFFERENT lens does not
                -- collide on UNIQUE(engagement_id, probe_key). NOT hard-enumerated.
                lens TEXT NOT NULL DEFAULT '',
                -- Optional finding this attempt supports/backfills. Nullable +
                -- ON DELETE SET NULL (mirrors coverage_item_id); NOT part of
                -- _probe_key, so a re-run of the same probe COALESCE-backfills it.
                finding_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, probe_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE CASCADE,
                FOREIGN KEY(coverage_item_id) REFERENCES assessment_coverage_items(id) ON DELETE SET NULL,
                FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE SET NULL
            )
            """
    )
    probe_columns = _table_columns(connection, "assessment_probe_runs")
    if probe_columns and "target_host" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN target_host TEXT NOT NULL DEFAULT ''"
        )
    if probe_columns and "target_path" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN target_path TEXT NOT NULL DEFAULT ''"
        )
    if probe_columns and "target_port" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN target_port INTEGER"
        )
    # lens: free-text mindset the probe ran under, part of
    # _probe_key so a different lens does not collide on UNIQUE(probe_key).
    # Additive, NOT NULL DEFAULT '' so legacy rows read back as the empty lens.
    if probe_columns and "lens" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN lens TEXT NOT NULL DEFAULT ''"
        )
    # finding_id: optional attempt→finding linkage. SQLite cannot ALTER a column
    # to add a REFERENCES constraint, so legacy DBs get a plain nullable INTEGER
    # (the application enforces the link); fresh DBs pick up the FK from CREATE.
    if probe_columns and "finding_id" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN finding_id INTEGER"
        )
    if probe_columns and "outcome_assertion" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_probe_runs "
            "ADD COLUMN outcome_assertion TEXT NOT NULL DEFAULT ''"
        )
    _dedupe_coverage_items(connection)
    connection.execute(
        """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_assessment_coverage_items_natural
            ON assessment_coverage_items(
                engagement_id,
                COALESCE(request_variant_id, -1),
                COALESCE(service_id, -1),
                auth_context,
                input_slot,
                attack_family
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_coverage_items_updated "
        "ON assessment_coverage_items(engagement_id, updated_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_coverage_items_status_updated "
        "ON assessment_coverage_items(engagement_id, status, updated_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_probe_runs_created "
        "ON assessment_probe_runs(engagement_id, created_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_probe_runs_finding "
        "ON assessment_probe_runs(engagement_id, finding_id)"
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_application_units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port_class TEXT NOT NULL DEFAULT 'web',
                path_prefix TEXT NOT NULL DEFAULT '/',
                deep_required INTEGER NOT NULL DEFAULT 0,
                depth_tier TEXT NOT NULL DEFAULT 'thin',
                structure_score INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL DEFAULT 0,
                suppressor_score INTEGER NOT NULL DEFAULT 0,
                total_score INTEGER NOT NULL DEFAULT 0,
                confidence TEXT NOT NULL DEFAULT 'low',
                evidence_json TEXT NOT NULL DEFAULT '{}',
                override TEXT,
                override_reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, host, port_class, path_prefix),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_application_units_host "
        "ON assessment_application_units(engagement_id, host)"
    )
    coverage_columns = _table_columns(connection, "assessment_coverage_items")
    if coverage_columns and "application_unit_id" not in coverage_columns:
        connection.execute(
            "ALTER TABLE assessment_coverage_items ADD COLUMN application_unit_id INTEGER "
            "REFERENCES assessment_application_units(id) ON DELETE SET NULL"
        )
    probe_columns_au = _table_columns(connection, "assessment_probe_runs")
    if probe_columns_au and "application_unit_id" not in probe_columns_au:
        connection.execute(
            "ALTER TABLE assessment_probe_runs ADD COLUMN application_unit_id INTEGER "
            "REFERENCES assessment_application_units(id) ON DELETE SET NULL"
        )


def _create_assessment_finding_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_surfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                surface_type TEXT NOT NULL,
                target_descriptor TEXT NOT NULL,
                source_name TEXT NOT NULL DEFAULT '',
                rationale TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'discovered',
                followup_condition TEXT NOT NULL DEFAULT '',
                framework_registration TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, surface_type, target_descriptor),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    # Additive migrations for deployments that predate the ``partially-covered``
    # lifecycle state (``followup_condition``) and the B5 architecture axis
    # (``framework_registration``). Both default to empty, so an upgraded row
    # means exactly what it meant before.
    surface_columns = _table_columns(connection, "assessment_surfaces")
    for column_name in ("followup_condition", "framework_registration"):
        if surface_columns and column_name not in surface_columns:
            connection.execute(
                f"ALTER TABLE assessment_surfaces ADD COLUMN {column_name} "
                "TEXT NOT NULL DEFAULT ''"
            )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                slug TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                status TEXT NOT NULL DEFAULT 'draft',
                verification_status TEXT NOT NULL DEFAULT 'unreviewed',
                defect_family TEXT NOT NULL DEFAULT '',
                root_cause_key TEXT NOT NULL DEFAULT '',
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                canonical_location TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                evidence_type TEXT,
                submission_status TEXT NOT NULL DEFAULT 'none',
                submission_platform TEXT NOT NULL DEFAULT '',
                submission_ref TEXT NOT NULL DEFAULT '',
                submission_url TEXT NOT NULL DEFAULT '',
                merged_into_finding_id INTEGER,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                row_version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, slug),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(merged_into_finding_id) REFERENCES assessment_findings(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_surfaces_status_updated "
        "ON assessment_surfaces(engagement_id, status, updated_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_surfaces_updated "
        "ON assessment_surfaces(engagement_id, updated_at DESC, id DESC)"
    )
    # Durable surface ↔ request-variant cross-link. Keyed on request_variant_id
    # (the value the backend hands back on a request-observation POST), NOT a
    # local cases.db work_item id — that local PK is ephemeral and the backend
    # has never seen it.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS surface_request_variant_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                surface_id INTEGER NOT NULL,
                request_variant_id INTEGER NOT NULL,
                relation TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(surface_id, request_variant_id, relation),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(surface_id) REFERENCES assessment_surfaces(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_surface_request_variant_links_surface "
        "ON surface_request_variant_links(engagement_id, surface_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_surface_request_variant_links_variant "
        "ON surface_request_variant_links(engagement_id, request_variant_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_findings_status_updated "
        "ON assessment_findings(engagement_id, status, updated_at DESC, id DESC)"
    )
    # NOTE: indexes over additively-migrated columns (verification_status,
    # submission_ref) are NOT created here. On an
    # existing database ``CREATE TABLE IF NOT EXISTS`` above is a no-op, so those
    # columns do not exist yet -- they are added by ``_apply_additive_migrations``,
    # which runs later. See ``_create_post_migration_indexes``.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_finding_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                from_workflow_status TEXT,
                to_workflow_status TEXT NOT NULL DEFAULT '',
                from_verification_status TEXT,
                to_verification_status TEXT NOT NULL DEFAULT 'unreviewed',
                verification_event_version INTEGER NOT NULL DEFAULT 2,
                from_severity TEXT,
                to_severity TEXT NOT NULL DEFAULT '',
                from_canonical_location TEXT,
                to_canonical_location TEXT,
                details_before_json TEXT,
                details_after_json TEXT,
                notes_before_json TEXT,
                notes_after_json TEXT,
                reason_code TEXT NOT NULL DEFAULT '',
                reason_text TEXT NOT NULL DEFAULT '',
                artifact_ref TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_finding_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                link_kind TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id INTEGER,
                target_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                retired_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE CASCADE
            )
            """
    )
    finding_link_columns = _table_columns(connection, "assessment_finding_links")
    if finding_link_columns and "retired_at" not in finding_link_columns:
        connection.execute(
            "ALTER TABLE assessment_finding_links ADD COLUMN retired_at TEXT"
        )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                chain_key TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                severity TEXT NOT NULL DEFAULT 'info',
                narrative TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, chain_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_attack_chain_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                chain_id INTEGER NOT NULL,
                relation TEXT NOT NULL,
                entity_kind TEXT NOT NULL,
                entity_id INTEGER,
                entity_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(chain_id) REFERENCES assessment_attack_chains(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                credential_key TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'password',
                principal TEXT NOT NULL DEFAULT '',
                secret TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'discovered',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                -- Named identity this credential is replayable AS. Links a stored credential to the
                -- credential-store identity (user_a/user_b/admin) so "which identity ran which
                -- probe" is recordable and cross-identity access-control depth
                -- is real. Additive + free-text; empty when no identity is set.
                identity TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, credential_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    credential_columns = _table_columns(connection, "assessment_credentials")
    if credential_columns and "identity" not in credential_columns:
        connection.execute(
            "ALTER TABLE assessment_credentials ADD COLUMN identity TEXT NOT NULL DEFAULT ''"
        )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_credential_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                credential_id INTEGER NOT NULL,
                service_id INTEGER,
                target_ref TEXT NOT NULL DEFAULT '',
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                outcome TEXT NOT NULL DEFAULT 'untested',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(credential_id) REFERENCES assessment_credentials(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_access_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                access_key TEXT NOT NULL,
                credential_id INTEGER,
                service_id INTEGER,
                principal TEXT NOT NULL DEFAULT '',
                access_level TEXT NOT NULL DEFAULT '',
                target_ref TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, access_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(credential_id) REFERENCES assessment_credentials(id) ON DELETE SET NULL,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_pivots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                pivot_key TEXT NOT NULL,
                access_record_id INTEGER,
                source_ref TEXT NOT NULL DEFAULT '',
                destination_ref TEXT NOT NULL DEFAULT '',
                technique TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'draft',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, pivot_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(access_record_id) REFERENCES assessment_access_records(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_tunnels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                tunnel_key TEXT NOT NULL,
                pivot_id INTEGER,
                tunnel_type TEXT NOT NULL DEFAULT '',
                source_endpoint TEXT NOT NULL DEFAULT '',
                destination_endpoint TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'draft',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, tunnel_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(pivot_id) REFERENCES assessment_pivots(id) ON DELETE SET NULL
            )
            """
    )
    _create_blocked_techniques_table(connection)


def _create_command_runs_table_and_fts(connection: sqlite3.Connection) -> None:
    # assessment_command_runs is the source of truth for every Kali
    # command executed during an engagement. A shadow FTS5 virtual table
    # plus three sync triggers provide keyword search.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_command_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                run_uuid TEXT NOT NULL UNIQUE,
                command TEXT NOT NULL,
                argv_json TEXT NOT NULL DEFAULT '[]',
                tool_name TEXT NOT NULL,
                tool_bin TEXT NOT NULL DEFAULT '',
                route TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                audit_source TEXT NOT NULL DEFAULT 'header',
                status TEXT NOT NULL DEFAULT 'completed',
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                output_recovery_observed_at TEXT,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                command_hash TEXT NOT NULL,
                stdout_sha256 TEXT NOT NULL DEFAULT '',
                stderr_sha256 TEXT NOT NULL DEFAULT '',
                stdout_preview TEXT NOT NULL DEFAULT '',
                stderr_preview TEXT NOT NULL DEFAULT '',
                output_retention_status TEXT NOT NULL DEFAULT 'retained',
                stdout_suppression_reason TEXT NOT NULL DEFAULT '',
                stderr_suppression_reason TEXT NOT NULL DEFAULT '',
                stdout_artifact_ref TEXT NOT NULL DEFAULT '',
                stderr_artifact_ref TEXT NOT NULL DEFAULT '',
                stdout_bytes INTEGER NOT NULL DEFAULT 0,
                stderr_bytes INTEGER NOT NULL DEFAULT 0,
                output_cleanup_warning TEXT NOT NULL DEFAULT '',
                output_cleanup_status TEXT NOT NULL DEFAULT 'not_required',
                output_integrity_warning TEXT NOT NULL DEFAULT '',
                output_integrity_status TEXT NOT NULL DEFAULT 'unverified',
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
                technique TEXT,
                intent TEXT,
                probe_kind TEXT,
                destructive INTEGER,
                stdout_path TEXT,
                stderr_path TEXT,
                stdout_spill_device INTEGER,
                stdout_spill_inode INTEGER,
                stderr_spill_device INTEGER,
                stderr_spill_inode INTEGER,
                peak_rss_bytes INTEGER,
                cpu_user_seconds REAL,
                cpu_system_seconds REAL,
                working_dir TEXT,
                scope_version TEXT,
                auth_context TEXT,
                target_host TEXT NOT NULL DEFAULT '',
                superseded_by_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE SET NULL,
                timeout_seconds_requested INTEGER,
                partial_results INTEGER NOT NULL DEFAULT 0,
                -- Optional link to the finding this command produced/supports.
                -- Nullable + ON DELETE SET NULL so the audit row survives the
                -- finding's deletion (a command run is durable evidence in its
                -- own right); back-compat default NULL for rows written before
                -- the writer threaded finding_id.
                finding_id INTEGER REFERENCES assessment_findings(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    # Additive migration for existing deployments of the pre-tool_bin,
    # pre-audit_source schema. Safe to run on fresh DBs (CREATE TABLE
    # above already includes the columns, so _table_columns returns them
    # and the ALTER is skipped).
    cmdrun_columns = _table_columns(connection, "assessment_command_runs")
    if cmdrun_columns and "run_uuid" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN run_uuid TEXT"
        )
        connection.execute(
            """
                UPDATE assessment_command_runs
                SET run_uuid = 'legacy-' || id
                WHERE run_uuid IS NULL OR run_uuid = ''
                """
        )
        cmdrun_columns = _table_columns(connection, "assessment_command_runs")
    if cmdrun_columns and "tool_bin" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN tool_bin TEXT NOT NULL DEFAULT ''"
        )
    if cmdrun_columns and "audit_source" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN audit_source TEXT NOT NULL DEFAULT 'header'"
        )
    # Command-metadata additive migrations — all NULLable so pre-rollout
    # rows stay valid and agents that don't yet set the fields continue
    # writing without a schema error. Re-check columns after each ALTER
    # in case the first ALTER mutated the cached list.
    if cmdrun_columns and "technique" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN technique TEXT"
        )
    if cmdrun_columns and "intent" not in cmdrun_columns:
        connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN intent TEXT")
    if cmdrun_columns and "probe_kind" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN probe_kind TEXT"
        )
    if cmdrun_columns and "destructive" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN destructive INTEGER"
        )
    # Command-run cutover migrations: pre-exec lifecycle, output spill paths,
    # resource snapshot, scope/auth context, dedup linkage, and the
    # agent-supplied timeout. All NULL/safe-default so legacy rows
    # continue to validate.
    #
    # Note: there is no schema-version mechanism. Round 9 dropped the
    # ``strace_path`` column entirely; existing DBs that still carry the
    # column keep it as a vestigial NULL TEXT (SQLite does not reliably
    # support DROP COLUMN). Fresh DBs created against this schema do not
    # have it. Code paths must not read or write the field either way.
    if cmdrun_columns and "status" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"
        )
    if cmdrun_columns and "stdout_path" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN stdout_path TEXT"
        )
    if cmdrun_columns and "stderr_path" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN stderr_path TEXT"
        )
    if cmdrun_columns and "peak_rss_bytes" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN peak_rss_bytes INTEGER"
        )
    if cmdrun_columns and "cpu_user_seconds" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN cpu_user_seconds REAL"
        )
    if cmdrun_columns and "cpu_system_seconds" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN cpu_system_seconds REAL"
        )
    if cmdrun_columns and "working_dir" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN working_dir TEXT"
        )
    if cmdrun_columns and "scope_version" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN scope_version TEXT"
        )
    if cmdrun_columns and "auth_context" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN auth_context TEXT"
        )
    # C30: target_host is the parsed target from argv for high-traffic verbs
    # (httpx, nuclei, ffuf, sqlmap). Unhandled verbs leave it empty; FTS
    # search via --q still finds those rows.
    if cmdrun_columns and "target_host" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN target_host TEXT NOT NULL DEFAULT ''"
        )
    # SQLite cannot ALTER a column to add a REFERENCES constraint, but the
    # FK is non-load-bearing — the application enforces the link, the
    # constraint is an integrity belt. Legacy rows simply have a plain
    # INTEGER column; new schema gets the REFERENCES via CREATE TABLE.
    if cmdrun_columns and "superseded_by_id" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN superseded_by_id INTEGER"
        )
    # Round 9 dropped ``strace_path``; we deliberately do NOT re-add the
    # column on legacy DBs (SQLite cannot DROP COLUMN reliably, so a
    # vestigial NULL column on existing files is the migration). Fresh DBs
    # created against the new schema simply do not have the column.
    if cmdrun_columns and "timeout_seconds_requested" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN timeout_seconds_requested INTEGER"
        )
    if cmdrun_columns and "partial_results" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN partial_results INTEGER NOT NULL DEFAULT 0"
        )
    if cmdrun_columns and "output_cleanup_warning" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN output_cleanup_warning TEXT NOT NULL DEFAULT ''"
        )
    if cmdrun_columns and "output_cleanup_status" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN output_cleanup_status TEXT NOT NULL DEFAULT 'not_required'"
        )
    if cmdrun_columns and "output_integrity_warning" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN output_integrity_warning TEXT NOT NULL DEFAULT ''"
        )
    if cmdrun_columns and "output_integrity_status" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN output_integrity_status TEXT NOT NULL DEFAULT 'unverified'"
        )
    if cmdrun_columns and "output_recovery_observed_at" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN output_recovery_observed_at TEXT"
        )
    if cmdrun_columns:
        # Old terminal rows have no trustworthy server commit clock. Pending
        # cleanup/integrity work needs one so the reconciler can age it without
        # trusting client-supplied completed_at. Migration time is the first
        # server-owned instant available, so start their grace period now.
        connection.execute(
            """
            UPDATE assessment_command_runs
            SET output_recovery_observed_at = CURRENT_TIMESTAMP
            WHERE status NOT IN ('queued', 'running')
              AND (
                    output_cleanup_status = 'pending'
                    OR output_integrity_status = 'pending'
                  )
              AND (
                    output_recovery_observed_at IS NULL
                    OR TRIM(output_recovery_observed_at) = ''
                  )
            """
        )
        # Older non-host finalizers could persist a preview while leaving the
        # pre-exec ``empty`` placeholder intact when the wrapper omitted byte
        # totals. The preview proves output was observed, but not its full size.
        # Repair only that contradiction; rows with no preview remain ambiguous
        # and must not acquire invented totals, hashes, or an unmeasured label.
        connection.execute(
            """
            UPDATE assessment_command_runs
            SET output_retention_status = 'preview_only'
            WHERE status NOT IN ('queued', 'running')
              AND output_retention_status = 'empty'
              AND (
                    COALESCE(stdout_preview, '') <> ''
                    OR COALESCE(stderr_preview, '') <> ''
                  )
            """
        )
    for stream in ("stdout", "stderr"):
        for suffix in ("device", "inode"):
            column = f"{stream}_spill_{suffix}"
            if cmdrun_columns and column not in cmdrun_columns:
                connection.execute(
                    f"ALTER TABLE assessment_command_runs ADD COLUMN {column} INTEGER"
                )
    # Optional finding linkage. As with superseded_by_id above, SQLite cannot
    # ALTER a column to add a REFERENCES constraint, so legacy DBs get a plain
    # nullable INTEGER (the application enforces the link); fresh DBs pick up the
    # REFERENCES ... ON DELETE SET NULL from CREATE TABLE.
    if cmdrun_columns and "finding_id" not in cmdrun_columns:
        connection.execute(
            "ALTER TABLE assessment_command_runs ADD COLUMN finding_id INTEGER"
        )
    if not _has_unique_index_on_columns(
        connection, "assessment_command_runs", ("run_uuid",)
    ):
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_assessment_command_runs_run_uuid "
            "ON assessment_command_runs(run_uuid) WHERE run_uuid IS NOT NULL"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_created "
        "ON assessment_command_runs(engagement_id, created_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_agent "
        "ON assessment_command_runs(engagement_id, agent_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_phase "
        "ON assessment_command_runs(engagement_id, phase)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_tool "
        "ON assessment_command_runs(engagement_id, tool_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_hash "
        "ON assessment_command_runs(engagement_id, command_hash)"
    )
    # Command runs are queried by finding for the "commands behind this finding"
    # view; index the linkage (engagement-scoped, NULLs skipped by the planner).
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_command_runs_finding "
        "ON assessment_command_runs(engagement_id, finding_id)"
    )
    # Chip-filter indexes for the four command-metadata fields. Scoped by
    # engagement_id so they stay useful in per-engagement queries (which
    # is every query the UI and CLI issue). Partial NULL handling is
    # left to SQLite defaults — the planner skips NULL rows naturally
    # when the filter value is concrete.
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_acr_technique "
        "ON assessment_command_runs(engagement_id, technique)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_acr_probe_kind "
        "ON assessment_command_runs(engagement_id, probe_kind)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_acr_destructive "
        "ON assessment_command_runs(engagement_id, destructive)"
    )
    # status powers the in-flight Commands tab and the dedup-window
    # check that ignores already-finalized rows.
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_acr_status "
        "ON assessment_command_runs(engagement_id, status, created_at DESC)"
    )
    # If the FTS schema predates tool_bin, drop the table and its triggers so
    # CREATE VIRTUAL TABLE / CREATE TRIGGER below rebuild with the current
    # column set. CREATE TRIGGER IF NOT EXISTS would silently keep stale
    # trigger bodies that reference a now-dropped column set.
    fts_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_command_runs_fts)"
        ).fetchall()
    }
    existing_cmdrun_count = connection.execute(
        "SELECT COUNT(*) FROM assessment_command_runs"
    ).fetchone()[0]
    rebuild_command_runs_fts = not fts_columns and existing_cmdrun_count > 0
    if fts_columns and "tool_bin" not in fts_columns:
        connection.execute("DROP TABLE IF EXISTS assessment_command_runs_fts")
        for trigger in (
            "assessment_command_runs_ai",
            "assessment_command_runs_ad",
            "assessment_command_runs_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        rebuild_command_runs_fts = existing_cmdrun_count > 0
        fts_columns = set()
    # Shape-change guard for the command-metadata FTS5 additions
    # (`intent`, `technique`). Mirrors the tool_bin precedent: when the
    # existing virtual table lacks the new column, drop+recreate so the
    # CREATE VIRTUAL TABLE IF NOT EXISTS below rebuilds with the current
    # column set. probe_kind/destructive are filter axes only — not in
    # FTS — so they are deliberately NOT included in this check.
    if fts_columns and "intent" not in fts_columns:
        connection.execute("DROP TABLE IF EXISTS assessment_command_runs_fts")
        for trigger in (
            "assessment_command_runs_ai",
            "assessment_command_runs_ad",
            "assessment_command_runs_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        rebuild_command_runs_fts = existing_cmdrun_count > 0
    connection.execute(
        """
            CREATE VIRTUAL TABLE IF NOT EXISTS assessment_command_runs_fts
            USING fts5(
                command,
                tool_name,
                tool_bin,
                agent_name,
                phase,
                stdout_preview,
                stderr_preview,
                stdout_suppression_reason,
                stderr_suppression_reason,
                notes,
                intent,
                technique,
                content='assessment_command_runs',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_command_runs_ai
            AFTER INSERT ON assessment_command_runs BEGIN
                INSERT INTO assessment_command_runs_fts(
                    rowid, command, tool_name, tool_bin, agent_name, phase,
                    stdout_preview, stderr_preview,
                    stdout_suppression_reason, stderr_suppression_reason, notes,
                    intent, technique
                )
                VALUES (
                    new.id, new.command, new.tool_name, new.tool_bin, new.agent_name, new.phase,
                    new.stdout_preview, new.stderr_preview,
                    new.stdout_suppression_reason, new.stderr_suppression_reason, new.notes,
                    new.intent, new.technique
                );
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_command_runs_ad
            AFTER DELETE ON assessment_command_runs BEGIN
                INSERT INTO assessment_command_runs_fts(
                    assessment_command_runs_fts, rowid, command, tool_name, tool_bin, agent_name, phase,
                    stdout_preview, stderr_preview,
                    stdout_suppression_reason, stderr_suppression_reason, notes,
                    intent, technique
                )
                VALUES (
                    'delete', old.id, old.command, old.tool_name, old.tool_bin, old.agent_name, old.phase,
                    old.stdout_preview, old.stderr_preview,
                    old.stdout_suppression_reason, old.stderr_suppression_reason, old.notes,
                    old.intent, old.technique
                );
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_command_runs_au
            AFTER UPDATE ON assessment_command_runs BEGIN
                INSERT INTO assessment_command_runs_fts(
                    assessment_command_runs_fts, rowid, command, tool_name, tool_bin, agent_name, phase,
                    stdout_preview, stderr_preview,
                    stdout_suppression_reason, stderr_suppression_reason, notes,
                    intent, technique
                )
                VALUES (
                    'delete', old.id, old.command, old.tool_name, old.tool_bin, old.agent_name, old.phase,
                    old.stdout_preview, old.stderr_preview,
                    old.stdout_suppression_reason, old.stderr_suppression_reason, old.notes,
                    old.intent, old.technique
                );
                INSERT INTO assessment_command_runs_fts(
                    rowid, command, tool_name, tool_bin, agent_name, phase,
                    stdout_preview, stderr_preview,
                    stdout_suppression_reason, stderr_suppression_reason, notes,
                    intent, technique
                )
                VALUES (
                    new.id, new.command, new.tool_name, new.tool_bin, new.agent_name, new.phase,
                    new.stdout_preview, new.stderr_preview,
                    new.stdout_suppression_reason, new.stderr_suppression_reason, new.notes,
                    new.intent, new.technique
                );
            END
            """
    )
    if rebuild_command_runs_fts:
        connection.execute(
            "INSERT INTO assessment_command_runs_fts(assessment_command_runs_fts) VALUES ('rebuild')"
        )


def _create_artifacts_table_and_fts(connection: sqlite3.Connection) -> None:
    # assessment_artifacts indexes engagement-local files while keeping
    # large/raw bytes on disk. Rows carry previews, hashes, producer
    # metadata, and optional entity links so resume/report flows can
    # discover artifacts without scraping arbitrary paths into prompts.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                relative_path TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT '',
                media_type TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                sha256 TEXT NOT NULL DEFAULT '',
                preview_text TEXT NOT NULL DEFAULT '',
                indexed_text TEXT NOT NULL DEFAULT '',
                sensitive INTEGER NOT NULL DEFAULT 0,
                present INTEGER NOT NULL DEFAULT 1,
                verified_device INTEGER,
                verified_inode INTEGER,
                integrity_status TEXT NOT NULL DEFAULT 'unverified',
                producer_agent_id TEXT,
                producer_agent_role TEXT,
                producer_command_run_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE SET NULL,
                related_finding_slug TEXT,
                related_chain_key TEXT,
                related_surface_id INTEGER,
                related_request_variant_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_indexed_at TEXT,
                UNIQUE(engagement_id, relative_path)
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_engagement_path "
        "ON assessment_artifacts(engagement_id, relative_path)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_finding "
        "ON assessment_artifacts(engagement_id, related_finding_slug)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_present "
        "ON assessment_artifacts(engagement_id, present)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_artifact_path_reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            relative_path TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            command_run_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, relative_path)
        )
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_artifacts_block_reserved_insert
        BEFORE INSERT ON assessment_artifacts
        WHEN EXISTS (
            SELECT 1 FROM assessment_artifact_path_reservations r
            WHERE r.engagement_id = NEW.engagement_id
              AND r.relative_path = NEW.relative_path
        )
        BEGIN
            SELECT RAISE(ABORT, 'artifact path is reserved from indexing');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_artifacts_block_reserved_update
        BEFORE UPDATE OF engagement_id, relative_path ON assessment_artifacts
        WHEN EXISTS (
            SELECT 1 FROM assessment_artifact_path_reservations r
            WHERE r.engagement_id = NEW.engagement_id
              AND r.relative_path = NEW.relative_path
        )
        BEGIN
            SELECT RAISE(ABORT, 'artifact path is reserved from indexing');
        END
        """
    )
    artifact_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_artifacts)"
        ).fetchall()
    }
    if "scratch" not in artifact_columns:
        connection.execute(
            "ALTER TABLE assessment_artifacts ADD COLUMN scratch INTEGER NOT NULL DEFAULT 0"
        )
    if "verified_device" not in artifact_columns:
        connection.execute(
            "ALTER TABLE assessment_artifacts ADD COLUMN verified_device INTEGER"
        )
    if "verified_inode" not in artifact_columns:
        connection.execute(
            "ALTER TABLE assessment_artifacts ADD COLUMN verified_inode INTEGER"
        )
    if "integrity_status" not in artifact_columns:
        connection.execute(
            "ALTER TABLE assessment_artifacts ADD COLUMN integrity_status TEXT NOT NULL DEFAULT 'unverified'"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_scratch "
        "ON assessment_artifacts(engagement_id, scratch)"
    )
    artifact_fts_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_artifacts_fts)"
        ).fetchall()
    }
    existing_artifact_count = connection.execute(
        "SELECT COUNT(*) FROM assessment_artifacts"
    ).fetchone()[0]
    rebuild_artifacts_fts = not artifact_fts_columns and existing_artifact_count > 0
    expected_artifact_fts_columns = {
        "relative_path",
        "kind",
        "media_type",
        "preview_text",
        "indexed_text",
        "related_finding_slug",
        "related_chain_key",
    }
    if artifact_fts_columns and not expected_artifact_fts_columns.issubset(
        artifact_fts_columns
    ):
        connection.execute("DROP TABLE IF EXISTS assessment_artifacts_fts")
        for trigger in (
            "assessment_artifacts_ai",
            "assessment_artifacts_ad",
            "assessment_artifacts_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        rebuild_artifacts_fts = existing_artifact_count > 0
    connection.execute(
        """
            CREATE VIRTUAL TABLE IF NOT EXISTS assessment_artifacts_fts
            USING fts5(
                relative_path,
                kind,
                media_type,
                preview_text,
                indexed_text,
                related_finding_slug,
                related_chain_key,
                content='assessment_artifacts',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_artifacts_ai
            AFTER INSERT ON assessment_artifacts BEGIN
                INSERT INTO assessment_artifacts_fts(
                    rowid, relative_path, kind, media_type, preview_text,
                    indexed_text, related_finding_slug, related_chain_key
                )
                VALUES (
                    new.id, new.relative_path, new.kind, new.media_type, new.preview_text,
                    new.indexed_text, new.related_finding_slug, new.related_chain_key
                );
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_artifacts_ad
            AFTER DELETE ON assessment_artifacts BEGIN
                INSERT INTO assessment_artifacts_fts(
                    assessment_artifacts_fts, rowid, relative_path, kind, media_type, preview_text,
                    indexed_text, related_finding_slug, related_chain_key
                )
                VALUES (
                    'delete', old.id, old.relative_path, old.kind, old.media_type, old.preview_text,
                    old.indexed_text, old.related_finding_slug, old.related_chain_key
                );
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS assessment_artifacts_au
            AFTER UPDATE ON assessment_artifacts BEGIN
                INSERT INTO assessment_artifacts_fts(
                    assessment_artifacts_fts, rowid, relative_path, kind, media_type, preview_text,
                    indexed_text, related_finding_slug, related_chain_key
                )
                VALUES (
                    'delete', old.id, old.relative_path, old.kind, old.media_type, old.preview_text,
                    old.indexed_text, old.related_finding_slug, old.related_chain_key
                );
                INSERT INTO assessment_artifacts_fts(
                    rowid, relative_path, kind, media_type, preview_text,
                    indexed_text, related_finding_slug, related_chain_key
                )
                VALUES (
                    new.id, new.relative_path, new.kind, new.media_type, new.preview_text,
                    new.indexed_text, new.related_finding_slug, new.related_chain_key
                );
            END
            """
    )
    if rebuild_artifacts_fts:
        connection.execute(
            "INSERT INTO assessment_artifacts_fts(assessment_artifacts_fts) VALUES ('rebuild')"
        )


def _create_submission_version_tables(connection: sqlite3.Connection) -> None:
    """Create the append-only records behind immutable submission exports.

    This is an additive table creation, not a data migration: existing finding
    rows are not rewritten and therefore no migration backup is required.
    """

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_submission_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE RESTRICT,
            version_number INTEGER NOT NULL CHECK(version_number >= 1),
            status TEXT NOT NULL CHECK(status IN ('staging', 'complete', 'failed')),
            platform TEXT NOT NULL CHECK(platform IN ('bugcrowd', 'hackerone', 'direct')),
            package_format TEXT NOT NULL CHECK(package_format IN ('markdown', 'zip')),
            actor_surface TEXT NOT NULL CHECK(actor_surface IN ('vigil-assess', 'web-ui')),
            relative_path TEXT NOT NULL,
            staging_relative_path TEXT NOT NULL,
            media_type TEXT NOT NULL,
            size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
            sha256 TEXT NOT NULL,
            submission_sha256 TEXT NOT NULL,
            source_finding_row_version INTEGER NOT NULL CHECK(source_finding_row_version >= 1),
            source_finding_updated_at TEXT NOT NULL,
            attachment_ids_json TEXT NOT NULL DEFAULT '[]',
            manifest_json TEXT NOT NULL DEFAULT '{}',
            sources_json TEXT NOT NULL DEFAULT '{}',
            request_sha256 TEXT NOT NULL,
            artifact_id INTEGER REFERENCES assessment_artifacts(id) ON DELETE SET NULL,
            failure_reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            UNIQUE(engagement_id, finding_id, version_number),
            UNIQUE(engagement_id, finding_id, request_sha256)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_submission_versions_finding "
        "ON assessment_submission_versions(engagement_id, finding_id, version_number DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_submission_versions_status "
        "ON assessment_submission_versions(engagement_id, status)"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_submission_versions_immutable_update
        BEFORE UPDATE ON assessment_submission_versions
        WHEN OLD.status = 'complete'
        BEGIN
            SELECT RAISE(ABORT, 'completed submission versions are immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_submission_versions_immutable_delete
        BEFORE DELETE ON assessment_submission_versions
        WHEN OLD.status = 'complete'
          AND EXISTS (SELECT 1 FROM engagements WHERE id = OLD.engagement_id)
        BEGIN
            SELECT RAISE(ABORT, 'completed submission versions are immutable');
        END
        """
    )


def _create_sent_reply_version_tables(connection: sqlite3.Connection) -> None:
    """Create immutable exact-byte records for operator-marked sent replies.

    Existing sent reply entries live inside finding ``details_json`` and are left
    untouched.  The absence of a row here is therefore an explicit legacy state,
    never an invitation to reconstruct bytes from mutable authored content.
    """

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_sent_reply_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE RESTRICT,
            reply_sequence INTEGER NOT NULL CHECK(reply_sequence >= 1),
            body_bytes BLOB NOT NULL,
            size_bytes INTEGER NOT NULL CHECK(size_bytes >= 1),
            sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
            renderer_identity TEXT NOT NULL CHECK(length(renderer_identity) >= 1),
            renderer_version TEXT NOT NULL CHECK(length(renderer_version) >= 1),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, finding_id, reply_sequence)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_sent_reply_versions_finding "
        "ON assessment_sent_reply_versions(engagement_id, finding_id, reply_sequence)"
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_sent_reply_versions_immutable_update
        BEFORE UPDATE ON assessment_sent_reply_versions
        BEGIN
            SELECT RAISE(ABORT, 'sent reply versions are immutable');
        END
        """
    )
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_sent_reply_versions_immutable_delete
        BEFORE DELETE ON assessment_sent_reply_versions
        WHEN EXISTS (SELECT 1 FROM engagements WHERE id = OLD.engagement_id)
        BEGIN
            SELECT RAISE(ABORT, 'sent reply versions are immutable');
        END
        """
    )


def _create_jobs_table(connection: sqlite3.Connection) -> None:
    # assessment_jobs tracks long-running dtach-supervised workers spawned
    # by `vigil assess kali job start`. parent_command_run_id links the
    # pre-exec command audit owned by that async job; SET NULL on cascade
    # so cleaning up an orphaned command-run does not destroy the job
    # record we still need for forensics.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                parent_command_run_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE SET NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                started_at TEXT,
                ended_at TEXT,
                exit_code INTEGER,
                dtach_socket_path TEXT,
                stdout_path TEXT,
                stderr_path TEXT,
                audit_metadata_json TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_jobs_engagement "
        "ON assessment_jobs(engagement_id, status, created_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_jobs_command_run "
        "ON assessment_jobs(parent_command_run_id)"
    )


def _sqlite_rows_digest(
    connection: sqlite3.Connection, table_name: str, columns: tuple[str, ...]
) -> tuple[int, str]:
    """Return a deterministic, type-preserving digest for a SQLite row set."""

    column_sql = ", ".join(columns)
    rows = connection.execute(
        f"SELECT {column_sql} FROM {table_name} ORDER BY id"
    )
    digest = hashlib.sha256()
    row_count = 0
    for row in rows:
        row_count += 1
        for value in row:
            if value is None:
                encoded = b"n"
            elif isinstance(value, bytes):
                encoded = b"b" + value
            elif isinstance(value, bool):
                encoded = b"i" + str(int(value)).encode("ascii")
            elif isinstance(value, int):
                encoded = b"i" + str(value).encode("ascii")
            elif isinstance(value, float):
                encoded = b"f" + value.hex().encode("ascii")
            else:
                encoded = b"s" + str(value).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return row_count, digest.hexdigest()


def _migrate_rate_lease_history(
    connection: sqlite3.Connection, *, backup_path: Path
) -> None:
    """Archive every retired aggregate-lease value, verify, then drop its surface.

    The legacy table is accepted only in its known schema. Unknown columns or
    missing fields stop the transaction instead of coercing historical evidence.
    The archive intentionally has no foreign-key actions: later lifecycle cleanup
    must not rewrite the preserved engagement/command identifiers.
    """

    actual_columns = tuple(
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(assessment_rate_leases)"
        ).fetchall()
    )
    if actual_columns != _RATE_LEASE_COLUMNS:
        raise RuntimeError(
            "cannot retire malformed assessment_rate_leases schema: "
            f"expected {_RATE_LEASE_COLUMNS!r}, observed {actual_columns!r}"
        )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_rate_lease_history (
            id INTEGER PRIMARY KEY,
            engagement_id INTEGER NOT NULL,
            lease_token TEXT NOT NULL,
            owner TEXT NOT NULL,
            effective_rate_rps REAL NOT NULL,
            aggregate_limit_rps REAL,
            override_reason TEXT,
            command_run_id INTEGER,
            expires_at TEXT NOT NULL,
            released_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            archived_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    archive_columns = tuple(
        str(row[1])
        for row in connection.execute(
            "PRAGMA table_info(assessment_rate_lease_history)"
        ).fetchall()
    )
    expected_archive_columns = (*_RATE_LEASE_COLUMNS, "archived_at")
    if archive_columns != expected_archive_columns:
        raise RuntimeError(
            "cannot retire aggregate leases into malformed archive schema: "
            f"expected {expected_archive_columns!r}, observed {archive_columns!r}"
        )

    source_count, source_digest = _sqlite_rows_digest(
        connection, "assessment_rate_leases", _RATE_LEASE_COLUMNS
    )
    column_sql = ", ".join(_RATE_LEASE_COLUMNS)
    connection.execute(
        f"INSERT OR IGNORE INTO assessment_rate_lease_history ({column_sql}) "
        f"SELECT {column_sql} FROM assessment_rate_leases"
    )
    archive_count, archive_digest = _sqlite_rows_digest(
        connection, "assessment_rate_lease_history", _RATE_LEASE_COLUMNS
    )
    if source_count != archive_count or source_digest != archive_digest:
        raise RuntimeError(
            "aggregate-rate lease archive verification failed: "
            f"source count/digest={source_count}/{source_digest}, "
            f"archive count/digest={archive_count}/{archive_digest}"
        )

    connection.execute("DROP INDEX IF EXISTS idx_assessment_rate_leases_active")
    connection.execute("DROP TABLE assessment_rate_leases")
    active_table_removed = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'assessment_rate_leases'"
    ).fetchone() is None
    if not active_table_removed:
        raise RuntimeError("aggregate-rate lease retirement did not remove active table")

    backup_size = backup_path.stat().st_size
    backup_sha256 = _file_sha256(backup_path)
    _create_migration_history_tables(connection)
    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, ?, 0, ?, ?)
        ON CONFLICT(migration_id) DO UPDATE SET
            migrated_rows = excluded.migrated_rows,
            warning_count = excluded.warning_count,
            backup_path = excluded.backup_path,
            report_json = excluded.report_json
        """,
        (
            _RATE_LEASE_RETIREMENT_MIGRATION_ID,
            "aggregate-rate-leases-active",
            "aggregate-rate-lease-history-archive",
            source_count,
            str(backup_path),
            json.dumps(
                {
                    "archive_count": archive_count,
                    "archive_sha256": archive_digest,
                    "archive_table": "assessment_rate_lease_history",
                    "backup_path": str(backup_path),
                    "backup_sha256": backup_sha256,
                    "backup_size_bytes": backup_size,
                    "legacy_table": "assessment_rate_leases",
                    "postconditions": {
                        "active_table_removed": active_table_removed,
                        "digest_equal": source_digest == archive_digest,
                        "row_count_equal": source_count == archive_count,
                    },
                    "source_count": source_count,
                    "source_sha256": source_digest,
                },
                sort_keys=True,
            ),
        ),
    )


# Additive column spec for assessment_http_flows. New table columns are
# appended here (name -> column DDL fragment) so an existing DB created before a
# column existed upgrades cleanly via the same _table_columns pattern used for
# assessment_command_runs / assessment_probe_runs. Fresh DBs get every column
# via CREATE TABLE below; this list only backfills older on-disk schemas.
_HTTP_FLOW_ADDITIVE_COLUMNS: tuple[tuple[str, str], ...] = (
    (
        "request_variant_id",
        "INTEGER REFERENCES assessment_request_variants(id) ON DELETE SET NULL",
    ),
    ("method", "TEXT NOT NULL DEFAULT ''"),
    ("scheme", "TEXT NOT NULL DEFAULT ''"),
    ("host", "TEXT NOT NULL DEFAULT ''"),
    ("port", "INTEGER"),
    ("url", "TEXT NOT NULL DEFAULT ''"),
    ("path", "TEXT NOT NULL DEFAULT ''"),
    ("response_status", "INTEGER"),
    ("request_content_type", "TEXT NOT NULL DEFAULT ''"),
    ("response_content_type", "TEXT NOT NULL DEFAULT ''"),
    ("content_type_family", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("auth_context", "TEXT NOT NULL DEFAULT 'anonymous'"),
    ("request_body_sha256", "TEXT NOT NULL DEFAULT ''"),
    ("response_body_sha256", "TEXT NOT NULL DEFAULT ''"),
    ("request_body_bytes", "INTEGER NOT NULL DEFAULT 0"),
    ("response_body_bytes", "INTEGER NOT NULL DEFAULT 0"),
    ("request_body_truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("response_body_truncated", "INTEGER NOT NULL DEFAULT 0"),
    ("request_body_capture_status", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("response_body_capture_status", "TEXT NOT NULL DEFAULT 'unknown'"),
    ("request_body_capture_error", "TEXT NOT NULL DEFAULT ''"),
    ("response_body_capture_error", "TEXT NOT NULL DEFAULT ''"),
    ("request_body_artifact_path", "TEXT"),
    ("response_body_artifact_path", "TEXT"),
    # Header maps are small and load-bearing for HAR export/import (which the
    # named column set could not otherwise reconstruct). Stored as JSON objects,
    # NOT raw bodies — raw bodies stay engagement-local artifacts per the plan.
    ("request_headers_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("response_headers_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("redaction_status", "TEXT NOT NULL DEFAULT 'none'"),
    ("host_mismatch", "INTEGER NOT NULL DEFAULT 0"),
    ("url_authority", "TEXT NOT NULL DEFAULT ''"),
    ("host_header", "TEXT NOT NULL DEFAULT ''"),
    ("sni", "TEXT NOT NULL DEFAULT ''"),
    ("timing_ms", "INTEGER"),
    ("started_at", "TEXT"),
)


def _create_http_flow_tables(connection: sqlite3.Connection) -> None:
    # assessment_http_flows is the canonical, compact, searchable full-flow
    # record written by the mitmproxy addon (Phase 5). Raw request/response
    # bodies stay on disk as engagement-local artifacts; the row carries only
    # the artifact relative_path + sha256 + byte counts + truncation flags plus
    # the (small) header maps needed to reconstruct a HAR entry. flow_uid is a
    # stable per-flow id supplied by the addon; INSERT OR IGNORE on
    # UNIQUE(engagement_id, flow_uid) makes ingest idempotent under retries.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_http_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                request_variant_id INTEGER REFERENCES assessment_request_variants(id) ON DELETE SET NULL,
                flow_uid TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT '',
                scheme TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                port INTEGER,
                url TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                response_status INTEGER,
                request_content_type TEXT NOT NULL DEFAULT '',
                response_content_type TEXT NOT NULL DEFAULT '',
                content_type_family TEXT NOT NULL DEFAULT 'unknown',
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                request_body_sha256 TEXT NOT NULL DEFAULT '',
                response_body_sha256 TEXT NOT NULL DEFAULT '',
                request_body_bytes INTEGER NOT NULL DEFAULT 0,
                response_body_bytes INTEGER NOT NULL DEFAULT 0,
                request_body_truncated INTEGER NOT NULL DEFAULT 0,
                response_body_truncated INTEGER NOT NULL DEFAULT 0,
                request_body_capture_status TEXT NOT NULL DEFAULT 'unknown',
                response_body_capture_status TEXT NOT NULL DEFAULT 'unknown',
                request_body_capture_error TEXT NOT NULL DEFAULT '',
                response_body_capture_error TEXT NOT NULL DEFAULT '',
                request_body_artifact_path TEXT,
                response_body_artifact_path TEXT,
                request_headers_json TEXT NOT NULL DEFAULT '{}',
                response_headers_json TEXT NOT NULL DEFAULT '{}',
                redaction_status TEXT NOT NULL DEFAULT 'none',
                host_mismatch INTEGER NOT NULL DEFAULT 0,
                url_authority TEXT NOT NULL DEFAULT '',
                host_header TEXT NOT NULL DEFAULT '',
                sni TEXT NOT NULL DEFAULT '',
                timing_ms INTEGER,
                started_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, flow_uid)
            )
            """
    )
    # Additive migration for pre-existing DBs (mirrors the assessment_command_runs
    # pattern): ALTER-in any column absent from an older on-disk schema.
    http_flow_columns = _table_columns(connection, "assessment_http_flows")
    if http_flow_columns:
        for column_name, column_ddl in _HTTP_FLOW_ADDITIVE_COLUMNS:
            if column_name not in http_flow_columns:
                connection.execute(
                    f"ALTER TABLE assessment_http_flows ADD COLUMN {column_name} {column_ddl}"
                )
    for column, direction in (
        ("created_at", "DESC"),
        ("host", ""),
        ("method", ""),
        ("response_status", ""),
        ("content_type_family", ""),
        ("auth_context", ""),
    ):
        suffix = f" {direction}" if direction else ""
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS idx_assessment_http_flows_{column} "
            f"ON assessment_http_flows(engagement_id, {column}{suffix}, id DESC)"
        )

    # Per-engagement capture policy. Dedicated table (keyed UNIQUE by
    # engagement_id) rather than a column on engagements, so the row survives
    # the filesystem→DB engagement identity re-sync that rewrites engagement
    # columns, and mirrors the engagement_credentials per-engagement typed-state
    # pattern. Full-flow metadata recording and both body sides are OFF by
    # default, so restarting the shared proxy never silently expands capture.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_capture_policy (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL UNIQUE REFERENCES engagements(id) ON DELETE CASCADE,
                enabled INTEGER NOT NULL DEFAULT 0,
                capture_request_bodies INTEGER NOT NULL DEFAULT 0,
                capture_response_bodies INTEGER NOT NULL DEFAULT 0,
                max_body_bytes INTEGER NOT NULL DEFAULT 102400,
                content_type_allow_json TEXT NOT NULL DEFAULT '[]',
                content_type_deny_json TEXT NOT NULL DEFAULT '[]',
                redaction_profile TEXT NOT NULL DEFAULT 'none',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
    )


def _apply_additive_migrations(connection: sqlite3.Connection) -> None:

    # Migrate secret_locator → secret in assessment_credentials
    cred_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_credentials)"
        ).fetchall()
    }
    if "secret_locator" in cred_columns and "secret" not in cred_columns:
        connection.execute(
            "ALTER TABLE assessment_credentials RENAME COLUMN secret_locator TO secret"
        )

    session_columns = _table_columns(connection, "engagement_sessions")
    if (
        "assigned_findings_json" in session_columns
        and "assigned_targets_json" not in session_columns
    ):
        connection.execute(
            "ALTER TABLE engagement_sessions RENAME COLUMN assigned_findings_json TO assigned_targets_json"
        )

    finding_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_findings)"
        ).fetchall()
    }
    finding_column_defaults = {
        "defect_family": "TEXT NOT NULL DEFAULT ''",
        "root_cause_key": "TEXT NOT NULL DEFAULT ''",
        "auth_context": "TEXT NOT NULL DEFAULT 'anonymous'",
        "canonical_location": "TEXT NOT NULL DEFAULT ''",
        "source_name": "TEXT NOT NULL DEFAULT ''",
        "summary": "TEXT NOT NULL DEFAULT ''",
        "details_json": "TEXT NOT NULL DEFAULT '{}'",
        "provenance_json": "TEXT NOT NULL DEFAULT '{}'",
        # C44: evidence_type categorizes confirmation mode for findings.
        # Nullable; no backfill (existing rows stay NULL). New findings
        # may carry: network-confirmed | code-inferred | theoretical |
        # informational. Report-writer treats NULL as 'unknown' and falls
        # back to its existing details-content inspection.
        "evidence_type": "TEXT",
        # External bug-bounty / program submission state, ORTHOGONAL to the
        # workflow_status (report-inclusion) axis. Existing rows backfill to the
        # 'none' default; new findings track submitted/accepted/needs_info/
        # rejected/duplicate independently of workflow_status.
        "submission_status": "TEXT NOT NULL DEFAULT 'none'",
        # The submission axis's IDENTITY. A status with no referent cannot be
        # joined back to the external report it describes, so `duplicate` records
        # that a duplicate exists while making the thing it duplicates
        # unrecoverable. Additive; legacy rows backfill to '' and stay writable.
        "submission_platform": "TEXT NOT NULL DEFAULT ''",
        "submission_ref": "TEXT NOT NULL DEFAULT ''",
        "submission_url": "TEXT NOT NULL DEFAULT ''",
        "merged_into_finding_id": "INTEGER",
        "last_seen_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "row_version": "INTEGER NOT NULL DEFAULT 1",
        "evidence_artifact_id": "INTEGER REFERENCES assessment_artifacts(id) ON DELETE SET NULL",
    }
    for column_name, definition in finding_column_defaults.items():
        if column_name not in finding_columns:
            connection.execute(
                f"ALTER TABLE assessment_findings ADD COLUMN {column_name} {definition}"
            )

    # Transition-ledger history columns. All nullable and additive: a legacy row
    # simply has no recorded before/after for the axis, which is honest — the
    # ledger cannot invent history it never captured. ``details_*``/``notes_*``
    # make a clobbering details or notes write recoverable (there was previously
    # no record of the prior value anywhere); ``*_canonical_location`` records an
    # audited relocation.
    transition_columns = _table_columns(connection, "assessment_finding_transitions")
    if transition_columns:
        for column_name in (
            "from_canonical_location",
            "to_canonical_location",
            "details_before_json",
            "details_after_json",
            "notes_before_json",
            "notes_after_json",
        ):
            if column_name not in transition_columns:
                connection.execute(
                    "ALTER TABLE assessment_finding_transitions "
                    f"ADD COLUMN {column_name} TEXT"
                )

    if finding_columns:
        # The obsolete one-axis ``status='confirmed'`` value predates the
        # workflow/verification split. Keep its workflow repair separate from
        # verification migration: verification is now mapped ONLY from the two
        # legacy verification columns, never inferred from workflow state.
        connection.execute(
            """
                UPDATE assessment_findings
                SET status = CASE status
                    WHEN 'confirmed' THEN 'active'
                    ELSE status
                END
                WHERE status = 'confirmed'
                """
        )

    chain_columns = _table_columns(connection, "assessment_attack_chains")
    if chain_columns and "evidence_artifact_id" not in chain_columns:
        connection.execute(
            "ALTER TABLE assessment_attack_chains ADD COLUMN "
            "evidence_artifact_id INTEGER REFERENCES assessment_artifacts(id) ON DELETE SET NULL"
        )

    # Migrate code_repos: add lsp_config_json if missing
    repo_columns = {
        row[1] for row in connection.execute("PRAGMA table_info(code_repos)").fetchall()
    }
    legacy_repos_need_generation_backfill = (
        bool(repo_columns) and "active_generation" not in repo_columns
    )
    snapshot_columns_added = False
    for col_name, col_def in {
        "lsp_config_json": "TEXT NOT NULL DEFAULT '{}'",
        "active_generation": "INTEGER NOT NULL DEFAULT 0",
        "source_origin_path": "TEXT NOT NULL DEFAULT ''",
        "source_kind": "TEXT NOT NULL DEFAULT 'legacy'",
        "snapshot_manifest_path": "TEXT NOT NULL DEFAULT ''",
        "snapshot_digest": "TEXT NOT NULL DEFAULT ''",
        "source_review_identity_digest": "TEXT NOT NULL DEFAULT ''",
        "source_manifest_version": "TEXT NOT NULL DEFAULT 'v1'",
        "source_manifest_digest": "TEXT NOT NULL DEFAULT ''",
        "source_snapshot_quality": "TEXT NOT NULL DEFAULT 'legacy-unverified'",
        "worktree_dirty": "INTEGER",
        "structural_index_schema": "TEXT NOT NULL DEFAULT ''",
        "structural_index_generation": "INTEGER",
        "structural_index_manifest_path": "TEXT NOT NULL DEFAULT ''",
        "structural_degraded_files": "INTEGER NOT NULL DEFAULT 0",
        "structural_degraded_file_paths_json": "TEXT NOT NULL DEFAULT '[]'",
        "structural_artifact_truncated_files": "INTEGER NOT NULL DEFAULT 0",
        "structural_artifact_truncated_file_paths_json": "TEXT NOT NULL DEFAULT '[]'",
        "structural_analysis_status_counts_json": "TEXT NOT NULL DEFAULT '{}'",
        "threat_model_generation": "INTEGER",
        "pending_refresh_token": "TEXT NOT NULL DEFAULT ''",
        "pending_refresh_json": "TEXT NOT NULL DEFAULT '{}'",
        # Every repository ingested before roles existed was ingested to be
        # reviewed, so the column default backfills them to 'analysis' and the
        # migration cannot change what an existing engagement's state means.
        "repo_role": "TEXT NOT NULL DEFAULT 'analysis'",
    }.items():
        if repo_columns and col_name not in repo_columns:
            connection.execute(
                f"ALTER TABLE code_repos ADD COLUMN {col_name} {col_def}"
            )
            snapshot_columns_added = (
                snapshot_columns_added or col_name == "source_manifest_digest"
            )
    if legacy_repos_need_generation_backfill:
        # Repositories created before refresh generations existed are already
        # authoritative snapshots. Generation zero is reserved for an
        # uncommitted first refresh, so preserve legacy visibility as gen 1.
        connection.execute("UPDATE code_repos SET active_generation = 1")

    file_history_columns = {
        "retired_at": "TEXT",
        "retirement_reason": "TEXT",
        "replacement_repo_generation": "INTEGER",
    }
    file_columns = _table_columns(connection, "code_files")
    for col_name, col_def in file_history_columns.items():
        if file_columns and col_name not in file_columns:
            connection.execute(
                f"ALTER TABLE code_files ADD COLUMN {col_name} {col_def}"
            )
    file_columns = _table_columns(connection, "code_files")

    if repo_columns:
        connection.execute(
            "UPDATE code_repos SET source_origin_path = repo_path WHERE source_origin_path = ''"
        )
        connection.execute(
            "UPDATE code_repos SET source_manifest_version = ? "
            "WHERE source_manifest_version = ''",
            (SOURCE_MANIFEST_VERSION,),
        )
        if snapshot_columns_added:
            rows = connection.execute(
                "SELECT id FROM code_repos WHERE active_generation > 0"
            ).fetchall()
            for row in rows:
                file_rows = connection.execute(
                    """
                    SELECT file_path, file_hash, language
                    FROM code_files
                    WHERE repo_id = ? AND retired_at IS NULL
                    """,
                    (int(row[0]),),
                ).fetchall()
                connection.execute(
                    "UPDATE code_repos SET source_manifest_digest = ? WHERE id = ?",
                    (
                        source_manifest_digest(
                            {
                                "file_path": file_row[0],
                                "file_hash": file_row[1],
                                "language": file_row[2],
                            }
                            for file_row in file_rows
                        ),
                        int(row[0]),
                    ),
                )

        # Upgrades can preserve only the source generation that is still
        # represented by the live repository row. Older rows deleted by a
        # previous release are deliberately not reconstructed.
        connection.execute(
            """
            INSERT OR IGNORE INTO code_source_generations (
                engagement_id, repo_id, repo_generation,
                source_manifest_version, source_manifest_digest,
                source_review_identity_digest, snapshot_manifest_path,
                snapshot_digest, source_snapshot_quality, repo_path,
                source_origin_path, source_kind, commit_hash, branch,
                worktree_dirty, promoted_at
            )
            SELECT engagement_id, id, active_generation,
                   source_manifest_version, source_manifest_digest,
                   source_review_identity_digest, snapshot_manifest_path,
                   snapshot_digest, source_snapshot_quality, repo_path,
                   source_origin_path, source_kind, commit_hash, branch,
                   worktree_dirty, COALESCE(created_at, CURRENT_TIMESTAMP)
            FROM code_repos
            WHERE active_generation > 0
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO code_source_generation_files (
                engagement_id, repo_id, repo_generation, file_id, file_path,
                file_hash, language, loc, header_snippet, git_churn_score,
                has_past_cve_fix
            )
            SELECT files.engagement_id, files.repo_id, repos.active_generation,
                   files.id, files.file_path, files.file_hash, files.language,
                   files.loc, files.header_snippet, files.git_churn_score,
                   files.has_past_cve_fix
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE repos.active_generation > 0 AND files.retired_at IS NULL
            """
        )

    result_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(code_analysis_results)"
        ).fetchall()
    }
    if result_columns and "audit_metadata_json" not in result_columns:
        connection.execute(
            "ALTER TABLE code_analysis_results ADD COLUMN audit_metadata_json TEXT NOT NULL DEFAULT '{}'"
        )

    # Migrate code_analysis_queue: add file-direct queue columns
    queue_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(code_analysis_queue)"
        ).fetchall()
    }
    queue_new_columns = {
        "batch_theme": "TEXT NOT NULL DEFAULT ''",
        "slot_types_json": "TEXT NOT NULL DEFAULT '[]'",
        "guidance_hypotheses_json": "TEXT NOT NULL DEFAULT '[]'",
        "cwe_coverage_json": "TEXT NOT NULL DEFAULT '[]'",
        "cross_file_triggers_json": "TEXT NOT NULL DEFAULT '[]'",
        # C50: separate "analyzed and found clean" from "deliberately
        # skipped" so code-coverage can distinguish 100% completion from
        # silent deferral. Operators tag skips with a structured reason
        # (test-fixture, generated-code, minified, out-of-scope-language).
        "skip_reason": "TEXT NOT NULL DEFAULT ''",
        "lease_token": "TEXT NOT NULL DEFAULT ''",
        "repo_generation": "INTEGER NOT NULL DEFAULT 0",
        "last_heartbeat_at": "TEXT",
        # B9: the lease identities an adopted attempt inherited, oldest first.
        # Adoption hands a still-open attempt to a replacement agent instead of
        # discarding what the dead lease recorded, so those identities stay
        # valid authors of this attempt's receipts. '[]' for every row that was
        # never adopted, which is why the owner-chain predicate is inert there.
        "adopted_leases_json": "TEXT NOT NULL DEFAULT '[]'",
        "queue_mode": "TEXT NOT NULL DEFAULT 'initial'",
        "reanalysis_reason": "TEXT NOT NULL DEFAULT ''",
        "reanalysis_of_queue_item_id": "INTEGER",
        "source_superseded_at": "TEXT",
        "source_supersession_reason": "TEXT NOT NULL DEFAULT ''",
        "replacement_repo_generation": "INTEGER",
    }
    for col_name, col_def in queue_new_columns.items():
        if queue_columns and col_name not in queue_columns:
            connection.execute(
                f"ALTER TABLE code_analysis_queue ADD COLUMN {col_name} {col_def}"
            )
    if queue_columns:
        connection.execute(
            """
            UPDATE code_analysis_queue
            SET queue_mode = 'trigger'
            WHERE queue_mode = 'initial'
              AND (
                  batch_theme = 'cross-file-trigger'
                  OR trim(cross_file_triggers_json) NOT IN ('', '[]')
              )
            """
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_analysis_queue_file_generation_status "
        "ON code_analysis_queue(engagement_id, file_id, repo_generation, status, id)"
    )

    # Migrate code_analysis_results: add cwe_coverage and cross_file_triggers
    if result_columns and "cwe_coverage_json" not in result_columns:
        connection.execute(
            "ALTER TABLE code_analysis_results ADD COLUMN cwe_coverage_json TEXT NOT NULL DEFAULT '[]'"
        )
    if result_columns and "cross_file_triggers_json" not in result_columns:
        connection.execute(
            "ALTER TABLE code_analysis_results ADD COLUMN cross_file_triggers_json TEXT NOT NULL DEFAULT '[]'"
        )
    for col_name, col_def in {
        "receipt_kind": "TEXT NOT NULL DEFAULT 'file'",
        "callable_refs_json": "TEXT NOT NULL DEFAULT '[]'",
        "reviewed_spans_json": "TEXT NOT NULL DEFAULT '[]'",
        "receipt_binding_status": "TEXT NOT NULL DEFAULT 'legacy_unbound'",
        "lease_token": "TEXT NOT NULL DEFAULT ''",
        "repo_generation": "INTEGER NOT NULL DEFAULT 0",
        "evidence_ref": "TEXT NOT NULL DEFAULT ''",
        "result_fingerprint": "TEXT NOT NULL DEFAULT ''",
        "supersedes_result_id": "INTEGER REFERENCES code_analysis_results(id) ON DELETE RESTRICT",
        "superseded_at": "TEXT",
        "source_superseded_at": "TEXT",
        "source_supersession_reason": "TEXT NOT NULL DEFAULT ''",
        "replacement_repo_generation": "INTEGER",
    }.items():
        if result_columns and col_name not in result_columns:
            connection.execute(
                f"ALTER TABLE code_analysis_results ADD COLUMN {col_name} {col_def}"
            )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_code_analysis_results_idempotent "
        "ON code_analysis_results(queue_item_id, lease_token, result_fingerprint) "
        "WHERE queue_item_id IS NOT NULL AND lease_token != '' AND result_fingerprint != ''"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_code_analysis_results_supersedes "
        "ON code_analysis_results(supersedes_result_id) "
        "WHERE supersedes_result_id IS NOT NULL"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_analysis_results_lease_function "
        "ON code_analysis_results(queue_item_id, lease_token, function_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_analysis_results_binding_status "
        "ON code_analysis_results(engagement_id, repo_generation, receipt_binding_status)"
    )

    trigger_columns = _table_columns(connection, "code_analysis_triggers")
    for col_name, col_def in {
        "repo_id": "INTEGER NOT NULL DEFAULT 0",
        "repo_generation": "INTEGER NOT NULL DEFAULT 0",
        "source_manifest_digest": "TEXT NOT NULL DEFAULT ''",
        "source_superseded_at": "TEXT",
        "source_supersession_reason": "TEXT NOT NULL DEFAULT ''",
        "replacement_repo_generation": "INTEGER",
    }.items():
        if trigger_columns and col_name not in trigger_columns:
            connection.execute(
                f"ALTER TABLE code_analysis_triggers ADD COLUMN {col_name} {col_def}"
            )
    if trigger_columns:
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET repo_id = COALESCE((
                    SELECT files.repo_id
                    FROM code_files AS files
                    WHERE files.id = code_analysis_triggers.source_file_id
                      AND files.engagement_id = code_analysis_triggers.engagement_id
                ), 0),
                repo_generation = COALESCE((
                    SELECT queue.repo_generation
                    FROM code_analysis_queue AS queue
                    WHERE queue.id = code_analysis_triggers.source_queue_item_id
                      AND queue.engagement_id = code_analysis_triggers.engagement_id
                ), (
                    SELECT repos.active_generation
                    FROM code_files AS files
                    JOIN code_repos AS repos ON repos.id = files.repo_id
                    WHERE files.id = code_analysis_triggers.source_file_id
                      AND files.engagement_id = code_analysis_triggers.engagement_id
                ), 0),
                source_manifest_digest = COALESCE((
                    SELECT generations.source_manifest_digest
                    FROM code_source_generations AS generations
                    WHERE generations.engagement_id = code_analysis_triggers.engagement_id
                      AND generations.repo_id = COALESCE((
                          SELECT files.repo_id FROM code_files AS files
                          WHERE files.id = code_analysis_triggers.source_file_id
                      ), 0)
                      AND generations.repo_generation = COALESCE((
                          SELECT queue.repo_generation
                          FROM code_analysis_queue AS queue
                          WHERE queue.id = code_analysis_triggers.source_queue_item_id
                      ), 0)
                ), '')
            WHERE repo_generation = 0
            """
        )

    # Migrate code_files: add structural metadata columns from tree-sitter index
    file_columns = _table_columns(connection, "code_files")
    structural_columns = {
        "total_functions": "INTEGER NOT NULL DEFAULT 0",
        "total_entry_points": "INTEGER NOT NULL DEFAULT 0",
        "total_sinks": "INTEGER NOT NULL DEFAULT 0",
        "total_exports": "INTEGER NOT NULL DEFAULT 0",
        "structural_analysis_status": "TEXT NOT NULL DEFAULT 'pending'",
        "structural_analysis_mode": "TEXT NOT NULL DEFAULT ''",
        "structural_degradation_reason": "TEXT NOT NULL DEFAULT ''",
        "structural_source_size": "INTEGER NOT NULL DEFAULT 0",
        "structural_bytes_scanned": "INTEGER NOT NULL DEFAULT 0",
        "structural_unavailable_dimensions_json": "TEXT NOT NULL DEFAULT '[]'",
        "structural_artifact_truncated": "INTEGER NOT NULL DEFAULT 0",
        "structural_truncated_dimensions_json": "TEXT NOT NULL DEFAULT '[]'",
        "structural_signal_counts_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for col_name, col_def in structural_columns.items():
        if file_columns and col_name not in file_columns:
            connection.execute(
                f"ALTER TABLE code_files ADD COLUMN {col_name} {col_def}"
            )

    variant_receipt_columns = _table_columns(connection, "code_variant_check_receipts")
    for col_name in ("dispatch_agent_id", "dispatch_agent_role"):
        if variant_receipt_columns and col_name not in variant_receipt_columns:
            connection.execute(
                f"ALTER TABLE code_variant_check_receipts "
                f"ADD COLUMN {col_name} TEXT NOT NULL DEFAULT ''"
            )


def _create_intel_tables(connection: sqlite3.Connection) -> None:
    # ── Intel Tables ───────────────────────────────────────────
    # Per-engagement intel replaces the legacy `intel.md` scratch pad.
    # Every table is engagement-scoped, carries UNIQUE(engagement_id,
    # <natural key>), created_at/updated_at, provenance_json, and CASCADE
    # on engagement delete. Naming mirrors the existing `assessment_*`
    # convention so helpers/FTS triggers/cascade tests can reuse the same
    # pattern.
    #
    # FTS design decision: the unified `intel_search_fts` virtual table
    # is backed by a **dedicated shadow table** `intel_search_index`
    # rather than a SQL view.  SQLite FTS5 external-content triggers
    # are already per-source-table; driving them from a view would
    # duplicate every trigger across 10 underlying tables and still
    # require a shadow rowid to stay stable across view updates.
    # A single shadow table is simpler, keeps rowids stable, and lets
    # state_manager helpers make a single write per intel insert/
    # update/delete that keeps the FTS index in sync automatically.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_tech_components (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                component TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_tech_components(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, component, version),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_people (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                organization TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_people(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, name),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                address TEXT NOT NULL,
                role_hint TEXT NOT NULL DEFAULT '',
                linked_person_id INTEGER,
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_emails(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, address),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(linked_person_id) REFERENCES intel_people(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                identity TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'subdomain',
                value TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                live_status TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_domains(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, identity, kind),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_cves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                affected_component TEXT NOT NULL DEFAULT '',
                affected_version_range TEXT NOT NULL DEFAULT '',
                cvss_score REAL,
                cvss_vector TEXT NOT NULL DEFAULT '',
                cwe_id TEXT NOT NULL DEFAULT '',
                poc_available INTEGER NOT NULL DEFAULT 0,
                source_name TEXT NOT NULL DEFAULT '',
                validation_status TEXT NOT NULL DEFAULT 'unverified',
                linked_finding_slug TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_cves(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, cve_id, affected_component),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    # Additive migration for existing deployments — adds details_json so
    # validation_status='attempted_blocked' rows can persist their
    # ``block_reason`` and any future structured detail field.
    cve_columns = _table_columns(connection, "intel_cves")
    if cve_columns and "details_json" not in cve_columns:
        connection.execute(
            "ALTER TABLE intel_cves ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}'"
        )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                record_type TEXT NOT NULL,
                name TEXT NOT NULL,
                value TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_dns_records(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, record_type, name, value),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_social_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                subject_kind TEXT NOT NULL,
                subject_ref TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL,
                handle TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_social_profiles(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, subject_kind, subject_ref, platform, handle),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_breach_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                breach_name TEXT NOT NULL,
                breach_date TEXT NOT NULL DEFAULT '',
                data_types TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                superseded_by_id INTEGER REFERENCES intel_breach_records(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, subject, breach_name),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_org_facts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                fact_key TEXT NOT NULL,
                fact_value TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                authored_by TEXT NOT NULL DEFAULT 'unknown',
                scope TEXT NOT NULL DEFAULT 'engagement',
                validity_context TEXT NOT NULL DEFAULT 'unreviewed; revalidate before relying on this interpretation',
                superseded_by_id INTEGER REFERENCES intel_org_facts(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, fact_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body_markdown TEXT NOT NULL DEFAULT '',
                source_agent TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                source_name TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                authored_by TEXT NOT NULL DEFAULT 'unknown',
                scope TEXT NOT NULL DEFAULT 'engagement',
                validity_context TEXT NOT NULL DEFAULT 'unreviewed; revalidate before relying on this interpretation',
                superseded_by_id INTEGER REFERENCES intel_notes(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, title),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )

    authored_context_columns = {
        "authored_by": "TEXT NOT NULL DEFAULT 'unknown'",
        "scope": "TEXT NOT NULL DEFAULT 'engagement'",
        "validity_context": (
            "TEXT NOT NULL DEFAULT 'unreviewed; revalidate before relying on this interpretation'"
        ),
    }
    for table_name in ("intel_org_facts", "intel_notes"):
        columns = _table_columns(connection, table_name)
        for column_name, definition in authored_context_columns.items():
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
                )

    # Additive migration: lead lifecycle. A note with a non-NULL lead_status is
    # a tracked *lead* (an actionable hypothesis/thread); NULL means a plain
    # reference note. Existing rows stay NULL — correct, so no pre-existing note
    # becomes a phantom lead.
    note_columns = _table_columns(connection, "intel_notes")
    if note_columns and "lead_status" not in note_columns:
        connection.execute("ALTER TABLE intel_notes ADD COLUMN lead_status TEXT")

    # Shadow table for unified FTS across every intel_* source table.
    # Service helpers (to be built in Phase B1) write one row here per
    # intel_* insert/update/delete, keyed by (entity_type, source_id),
    # and the three FTS triggers below keep intel_search_fts in sync
    # with the shadow content. This is the "shadow table" branch of
    # the view-vs-shadow decision documented at the top of this block.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS intel_search_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                entity_type TEXT NOT NULL,
                source_id INTEGER NOT NULL,
                key TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                source_name TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, entity_type, source_id),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_intel_search_index_engagement_entity "
        "ON intel_search_index(engagement_id, entity_type)"
    )


def _create_code_lead_binding_table(connection: sqlite3.Connection) -> None:
    """The seam between a tracked intel lead and the reviewed source.

    Created after both the code-analysis schema and
    ``_create_intel_tables`` because it is the only table whose parents span
    the two subsystems. A lead stays one row in ``intel_notes`` — this table
    adds *where to look*, never a second lead identity.

    ``repo_generation`` + ``file_hash`` are what stop a line range from
    silently drifting onto different code: a refresh that leaves the bytes
    identical carries the binding forward, and any other refresh stamps it
    superseded so the lines are re-read before they are trusted again.
    """
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_lead_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                note_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                line_start INTEGER,
                line_end INTEGER,
                prior_art_ref TEXT NOT NULL DEFAULT '',
                rationale TEXT NOT NULL DEFAULT '',
                bound_by TEXT NOT NULL DEFAULT '',
                unbound_at TEXT,
                unbound_reason TEXT NOT NULL DEFAULT '',
                source_superseded_at TEXT,
                source_supersession_reason TEXT NOT NULL DEFAULT '',
                replacement_repo_generation INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, note_id, file_id),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(note_id) REFERENCES intel_notes(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_lead_bindings_engagement_repo "
        "ON code_lead_bindings(engagement_id, repo_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_lead_bindings_note "
        "ON code_lead_bindings(engagement_id, note_id)"
    )


def _create_activity_table(connection: sqlite3.Connection) -> None:

    # Activity log narrative table replaces the legacy `log.md` scratch
    # pad. Every row is engagement-scoped and CASCADEs on engagement
    # delete. The existing `events` table stays for structured state
    # transitions — this table holds prose.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS activity_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                actor_kind TEXT NOT NULL DEFAULT 'operator',
                actor_name TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL DEFAULT '',
                artifact_ref TEXT NOT NULL DEFAULT '',
                body_markdown TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_activity_entries_engagement_occurred "
        "ON activity_entries(engagement_id, occurred_at DESC, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_activity_entries_actor "
        "ON activity_entries(engagement_id, actor_kind, actor_name)"
    )


def _retire_duplicate_current_client_bindings(
    connection: sqlite3.Connection,
) -> None:
    """Collapse pre-existing fan-out before the uniqueness guard can be built.

    A database written by the unserialized binder may already hold two rows with
    a NULL ``superseded_by_id`` for one dispatch, which is the state the index
    below refuses. The highest ``binding_version`` is the operator's latest
    assertion and stays current; every earlier current row is retired *to* it,
    which is the same NULL -> NOT NULL stamp the append-only trigger permits, so
    nothing is rewritten or lost.
    """
    duplicates = connection.execute(
        """
        SELECT dispatch_id
        FROM assessment_dispatch_client_bindings
        WHERE superseded_by_id IS NULL
        GROUP BY dispatch_id
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    for (dispatch_id,) in duplicates:
        survivor = connection.execute(
            """
            SELECT id FROM assessment_dispatch_client_bindings
            WHERE dispatch_id = ? AND superseded_by_id IS NULL
            ORDER BY binding_version DESC, id DESC LIMIT 1
            """,
            (dispatch_id,),
        ).fetchone()
        connection.execute(
            """
            UPDATE assessment_dispatch_client_bindings SET superseded_by_id = ?
            WHERE dispatch_id = ? AND superseded_by_id IS NULL AND id != ?
            """,
            (int(survivor[0]), dispatch_id, int(survivor[0])),
        )


def _create_dispatch_tables(connection: sqlite3.Connection) -> None:

    # Dispatch tracking lives in the orchestrator. Three
    # tables — dispatches (the audit row of who was dispatched), handoffs
    # (the structured payload the agent returned to the operator), and
    # decisions (scope/egress/dispatch-blocked checkpoints surfaced to the
    # user). Constraint enforcement on status/confidence/kind lives in the
    # Pydantic layer so we can evolve enums without a schema rebuild.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_dispatches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                agent_id TEXT NOT NULL,
                agent_role TEXT NOT NULL,
                task TEXT,
                application_unit_id INTEGER REFERENCES assessment_application_units(id) ON DELETE SET NULL,
                dispatched_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                requested_model TEXT,
                actual_model TEXT NOT NULL DEFAULT 'unknown',
                requested_reasoning TEXT,
                actual_reasoning TEXT NOT NULL DEFAULT 'unknown',
                launcher_effective_model TEXT,
                launcher_effective_reasoning TEXT,
                launcher_effective_source TEXT,
                client_name TEXT NOT NULL DEFAULT 'unknown',
                requested_client TEXT NOT NULL DEFAULT 'unknown',
                launcher_effective_client TEXT NOT NULL DEFAULT 'unknown',
                provider_observed_client TEXT NOT NULL DEFAULT 'unknown',
                source_revision TEXT NOT NULL DEFAULT 'unknown',
                operator_instruction_path TEXT,
                operator_instruction_sha256 TEXT,
                specialist_instruction_path TEXT,
                specialist_instruction_sha256 TEXT,
                instruction_identity_status TEXT NOT NULL DEFAULT 'incomplete',
                instructions_stale INTEGER,
                dispatch_mode TEXT,
                finding_slugs_json TEXT,
                skills TEXT,
                tier TEXT,
                vuln_classes TEXT,
                identity TEXT,
                continued_from_dispatch_id INTEGER REFERENCES assessment_dispatches(id) ON DELETE SET NULL,
                UNIQUE(engagement_id, agent_id)
            )
            """
    )
    # Additive migration for pre-existing DBs created before the `skills`
    # column was introduced. New schema gets it via CREATE TABLE above.
    dispatch_columns = _table_columns(connection, "assessment_dispatches")
    if dispatch_columns and "skills" not in dispatch_columns:
        connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN skills TEXT")
    if dispatch_columns and "requested_model" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN requested_model TEXT"
        )
    if dispatch_columns and "actual_model" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN actual_model "
            "TEXT NOT NULL DEFAULT 'unknown'"
        )
    if dispatch_columns and "requested_reasoning" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN requested_reasoning TEXT"
        )
    if dispatch_columns and "actual_reasoning" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN actual_reasoning "
            "TEXT NOT NULL DEFAULT 'unknown'"
        )
    if dispatch_columns:
        _normalize_unobserved_dispatch_actual_identity(connection)
    # Blue-engagement tier tag ('L1' | 'L2' | 'L3' | 'L4'). Enforced in
    # the Pydantic layer; stored as free-form TEXT so the enum can evolve
    # without a schema rebuild. Existing rows stay NULL.
    if dispatch_columns and "tier" not in dispatch_columns:
        connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN tier TEXT")
    if dispatch_columns and "application_unit_id" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN application_unit_id INTEGER "
            "REFERENCES assessment_application_units(id) ON DELETE SET NULL"
        )
    provenance_columns = {
        "client_name": "TEXT NOT NULL DEFAULT 'unknown'",
        "requested_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "launcher_effective_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "provider_observed_client": "TEXT NOT NULL DEFAULT 'unknown'",
        "launcher_effective_model": "TEXT",
        "launcher_effective_reasoning": "TEXT",
        "launcher_effective_source": "TEXT",
        "source_revision": "TEXT NOT NULL DEFAULT 'unknown'",
        "operator_instruction_path": "TEXT",
        "operator_instruction_sha256": "TEXT",
        "specialist_instruction_path": "TEXT",
        "specialist_instruction_sha256": "TEXT",
        "instruction_identity_status": "TEXT NOT NULL DEFAULT 'incomplete'",
        "instructions_stale": "INTEGER",
    }
    for _col, _definition in provenance_columns.items():
        if dispatch_columns and _col not in dispatch_columns:
            connection.execute(
                f"ALTER TABLE assessment_dispatches ADD COLUMN {_col} {_definition}"
            )
    for _col in ("vuln_classes", "identity"):
        if dispatch_columns and _col not in dispatch_columns:
            connection.execute(
                f"ALTER TABLE assessment_dispatches ADD COLUMN {_col} TEXT"
            )
    if dispatch_columns and "continued_from_dispatch_id" not in dispatch_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatches ADD COLUMN continued_from_dispatch_id "
            "INTEGER REFERENCES assessment_dispatches(id) ON DELETE SET NULL"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatches_engagement_at "
        "ON assessment_dispatches(engagement_id, dispatched_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatches_engagement_role "
        "ON assessment_dispatches(engagement_id, agent_role)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatches_engagement_status "
        "ON assessment_dispatches(engagement_id, status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatches_engagement_tier "
        "ON assessment_dispatches(engagement_id, tier)"
    )

    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_dispatch_prompt_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                dispatch_id INTEGER NOT NULL UNIQUE REFERENCES assessment_dispatches(id) ON DELETE CASCADE,
                schema_version TEXT NOT NULL,
                context_json TEXT NOT NULL,
                rendered_prompt TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """
    )

    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_variant_dispatch_scopes (
                dispatch_id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                parent_finding_slugs_json TEXT NOT NULL,
                parent_finding_set_digest TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, dispatch_id),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(dispatch_id) REFERENCES assessment_dispatches(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE INDEX IF NOT EXISTS idx_variant_dispatch_scopes_engagement
            ON code_variant_dispatch_scopes(engagement_id, dispatch_id)
            """
    )

    # Which live client session a dispatch is actually running as. `agent start`
    # writes the dispatch row BEFORE the operator launches the client, so the
    # handle does not exist yet and can never be a column on that row; it arrives
    # post-launch through `agent bind-client-handle`.
    #
    # Every value here is CALLER-ASSERTED — the operator read the handle out of
    # their client and typed it. Nothing attests it, which is why the columns say
    # `asserted_` and why `provider_observed_handle` exists and stays 'unknown':
    # the same closed-to-attestation shape `assessment_dispatches`
    # `provider_observed_client` uses, so the absence of a measured handle is
    # visible rather than merely missing.
    #
    # Storage is append-only: a correction is a NEW row (version N+1) that stamps
    # the previous current row's `superseded_by_id`, matching the ledger idiom used
    # by operator checkpoints, submission versions, and finding transitions.
    # Overwriting the wrong handle in place would erase the record of what was
    # bound when — and that record is the whole point of binding at all.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_dispatch_client_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                dispatch_id INTEGER NOT NULL
                    REFERENCES assessment_dispatches(id) ON DELETE CASCADE,
                binding_version INTEGER NOT NULL CHECK(binding_version >= 1),
                superseded_by_id INTEGER
                    REFERENCES assessment_dispatch_client_bindings(id),
                asserted_client TEXT NOT NULL,
                asserted_session_namespace TEXT NOT NULL,
                asserted_client_handle TEXT NOT NULL,
                provider_observed_handle TEXT NOT NULL DEFAULT 'unknown',
                note TEXT,
                bound_at TEXT NOT NULL,
                UNIQUE(dispatch_id, binding_version)
            )
            """
    )
    _retire_duplicate_current_client_bindings(connection)
    # UNIQUE, and partial on exactly the predicate every dispatch read joins on:
    # one dispatch has at most one CURRENT binding. The append-only triggers below
    # guard a row's content, and nothing guarded the count — so an unserialized
    # bind that raced another could leave two rows with a NULL `superseded_by_id`
    # and fan the dispatch itself out across `agent list`, `agent get` and the
    # resume brief. It replaces the non-unique two-column index of the same shape.
    connection.execute("DROP INDEX IF EXISTS idx_dispatch_client_bindings_current")
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_client_bindings_one_current "
        "ON assessment_dispatch_client_bindings(dispatch_id) "
        "WHERE superseded_by_id IS NULL"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispatch_client_bindings_engagement "
        "ON assessment_dispatch_client_bindings(engagement_id, dispatch_id)"
    )
    # Append-only enforced in the schema, not only in the service: the ONLY
    # permitted update is stamping a NULL `superseded_by_id`. Rewriting an
    # already-superseded pointer, or editing any other column, is refused.
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_dispatch_client_bindings_append_only_update
        BEFORE UPDATE ON assessment_dispatch_client_bindings
        WHEN NOT (
            OLD.superseded_by_id IS NULL
            AND NEW.superseded_by_id IS NOT NULL
            AND NEW.id = OLD.id
            AND NEW.engagement_id = OLD.engagement_id
            AND NEW.dispatch_id = OLD.dispatch_id
            AND NEW.binding_version = OLD.binding_version
            AND NEW.asserted_client = OLD.asserted_client
            AND NEW.asserted_session_namespace = OLD.asserted_session_namespace
            AND NEW.asserted_client_handle = OLD.asserted_client_handle
            AND NEW.provider_observed_handle = OLD.provider_observed_handle
            -- ``IS``, not ``=``: `note` is NULL on most bindings, and
            -- ``NULL = NULL`` is NULL, which would leave the guard unable to
            -- decide and let the edit through.
            AND NEW.note IS OLD.note
            AND NEW.bound_at = OLD.bound_at
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'dispatch client bindings are append-only; bind again to supersede instead of editing'
            );
        END
        """
    )
    # The engagement-cascade carve-out mirrors the operator-checkpoint triggers:
    # deleting the engagement still cascades, but nothing else may delete a row.
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_dispatch_client_bindings_append_only_delete
        BEFORE DELETE ON assessment_dispatch_client_bindings
        WHEN EXISTS (SELECT 1 FROM engagements WHERE id = OLD.engagement_id)
        BEGIN
            SELECT RAISE(ABORT, 'dispatch client bindings are append-only');
        END
        """
    )

    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_dispatch_handoffs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                agent_id TEXT NOT NULL,
                agent_role TEXT NOT NULL,
                phase TEXT,
                summary TEXT NOT NULL,
                confidence TEXT,
                finding_slugs_json TEXT,
                coverage_gaps_json TEXT,
                next_steps_json TEXT,
                runtime_issues_json TEXT,
                working_artifacts_json TEXT,
                open_questions_json TEXT,
                recommended_next_agent TEXT,
                handoff_status TEXT NOT NULL DEFAULT 'checkpointed',
                handoff_version INTEGER NOT NULL DEFAULT 1,
                last_checkpoint_at TEXT,
                closed_dispatch_status TEXT,
                extras_json TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(engagement_id, agent_id)
            )
            """
    )
    handoff_columns = _table_columns(connection, "assessment_dispatch_handoffs")
    if handoff_columns and "handoff_status" not in handoff_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatch_handoffs ADD COLUMN handoff_status TEXT NOT NULL DEFAULT 'checkpointed'"
        )
    if handoff_columns and "handoff_version" not in handoff_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatch_handoffs ADD COLUMN handoff_version INTEGER NOT NULL DEFAULT 1"
        )
    if handoff_columns and "last_checkpoint_at" not in handoff_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatch_handoffs ADD COLUMN last_checkpoint_at TEXT"
        )
        connection.execute(
            "UPDATE assessment_dispatch_handoffs SET last_checkpoint_at = created_at WHERE last_checkpoint_at IS NULL"
        )
    if handoff_columns and "closed_dispatch_status" not in handoff_columns:
        connection.execute(
            "ALTER TABLE assessment_dispatch_handoffs ADD COLUMN closed_dispatch_status TEXT"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_handoffs_engagement_at "
        "ON assessment_dispatch_handoffs(engagement_id, created_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_handoffs_engagement_status "
        "ON assessment_dispatch_handoffs(engagement_id, handoff_status)"
    )

    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_dispatch_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                surfaced_to_user INTEGER NOT NULL DEFAULT 0,
                resolved INTEGER NOT NULL DEFAULT 0,
                resolution_json TEXT,
                created_at TEXT NOT NULL
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_decisions_engagement_kind "
        "ON assessment_dispatch_decisions(engagement_id, kind)"
    )

    # The operator's own durable checkpoint. Every dispatched specialist writes
    # an ``assessment_dispatch_handoffs`` row; the operator wrote nothing, so its
    # state died with the session. This table is that missing row — and it is
    # deliberately built so it CANNOT hold a new factual claim about the target:
    # every column except ``intent_note`` is a reference to a row the backend
    # already holds (phases, finding slugs, dispatch agent ids, command-run ids,
    # artifact ids), and both phases are server-derived at write time rather
    # than caller-supplied. ``intent_note`` is the single free-text block and is
    # rendered everywhere as UNVERIFIED operator intent, never as evidence.
    #
    # ``current_phase`` and ``code_phase`` are the two INDEPENDENT engagement
    # tracks (``scope.json.current_phase`` / ``scope.json.code_phase``), not one
    # value spelled two ways. ``code_phase`` is NULL for every engagement that
    # has no code track, which is also what a row written before the column
    # existed reads back as — honest in both cases, because neither has a
    # code-track position to report.
    #
    # Storage is append-only: a correction is a NEW row (version N+1) that stamps
    # the previous current row's ``superseded_by_id``, matching the ledger idiom
    # used by submission versions, sent-reply versions, and finding transitions.
    # Mutating a wrong entry in place would erase the wrong claim, which is
    # itself state-truth loss; superseding keeps the correction visible.
    #
    # Why not ``assessment_dispatch_decisions``: its ``payload_json`` is
    # unstructured, so a checkpoint written there could hold any assertion about
    # the target as though verified, nothing validates that referenced ids exist,
    # and it is a flat per-decision ledger with no single current row per
    # engagement. This table is the opposite on all three axes by construction.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_operator_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
                checkpoint_version INTEGER NOT NULL CHECK(checkpoint_version >= 1),
                superseded_by_id INTEGER REFERENCES assessment_operator_checkpoints(id),
                current_phase TEXT NOT NULL,
                code_phase TEXT,
                finding_slugs_json TEXT NOT NULL DEFAULT '[]',
                dispatch_agent_ids_json TEXT NOT NULL DEFAULT '[]',
                command_run_ids_json TEXT NOT NULL DEFAULT '[]',
                artifact_ids_json TEXT NOT NULL DEFAULT '[]',
                intent_note TEXT NOT NULL,
                source TEXT NOT NULL,
                client_name TEXT NOT NULL DEFAULT 'unknown',
                created_at TEXT NOT NULL,
                UNIQUE(engagement_id, checkpoint_version)
            )
            """
    )
    # Additive migration for deployments whose table predates the code track.
    # Nullable with no default, so every existing row keeps its web phase and
    # reports no code-track position rather than inheriting a fabricated one.
    # The append-only trigger enumerates every column, so a body written before
    # ``code_phase`` existed cannot guard it; drop the stale trigger here and
    # let the CREATE TRIGGER below rebuild it against the current column set
    # (the same drop-on-shape-change guard the command-run FTS triggers use).
    checkpoint_columns = _table_columns(connection, "assessment_operator_checkpoints")
    if checkpoint_columns and "code_phase" not in checkpoint_columns:
        connection.execute(
            "ALTER TABLE assessment_operator_checkpoints ADD COLUMN code_phase TEXT"
        )
        connection.execute(
            "DROP TRIGGER IF EXISTS assessment_operator_checkpoints_append_only_update"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_operator_checkpoints_engagement_current "
        "ON assessment_operator_checkpoints(engagement_id, superseded_by_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_operator_checkpoints_engagement_version "
        "ON assessment_operator_checkpoints(engagement_id, checkpoint_version DESC)"
    )
    # Append-only enforced in the schema, not only in the service: the ONLY
    # permitted update is stamping a NULL ``superseded_by_id``. Rewriting an
    # already-superseded pointer, or editing any other column, is refused.
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_operator_checkpoints_append_only_update
        BEFORE UPDATE ON assessment_operator_checkpoints
        WHEN NOT (
            OLD.superseded_by_id IS NULL
            AND NEW.superseded_by_id IS NOT NULL
            AND NEW.id = OLD.id
            AND NEW.engagement_id = OLD.engagement_id
            AND NEW.checkpoint_version = OLD.checkpoint_version
            AND NEW.current_phase = OLD.current_phase
            -- ``IS``, not ``=``: ``code_phase`` is NULL on every single-track
            -- and every pre-migration row, and ``NULL = NULL`` is NULL, which
            -- would leave the guard unable to decide and let the edit through.
            AND NEW.code_phase IS OLD.code_phase
            AND NEW.finding_slugs_json = OLD.finding_slugs_json
            AND NEW.dispatch_agent_ids_json = OLD.dispatch_agent_ids_json
            AND NEW.command_run_ids_json = OLD.command_run_ids_json
            AND NEW.artifact_ids_json = OLD.artifact_ids_json
            AND NEW.intent_note = OLD.intent_note
            AND NEW.source = OLD.source
            AND NEW.client_name = OLD.client_name
            AND NEW.created_at = OLD.created_at
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'operator checkpoints are append-only; record a new checkpoint instead of editing one'
            );
        END
        """
    )
    # The engagement-cascade carve-out mirrors the sent-reply-version triggers:
    # deleting the engagement still cascades, but nothing else may delete a row.
    connection.execute(
        """
        CREATE TRIGGER IF NOT EXISTS assessment_operator_checkpoints_append_only_delete
        BEFORE DELETE ON assessment_operator_checkpoints
        WHEN EXISTS (SELECT 1 FROM engagements WHERE id = OLD.engagement_id)
        BEGIN
            SELECT RAISE(ABORT, 'operator checkpoints are append-only');
        END
        """
    )


def _create_verification_evidence_tables(connection: sqlite3.Connection) -> None:
    """Shared run/proof identities used by code, web, and blue workflows."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_uuid TEXT NOT NULL,
            run_kind TEXT NOT NULL,
            run_purpose TEXT NOT NULL DEFAULT 'proof',
            producer_dispatch_id INTEGER NOT NULL
                REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            status TEXT NOT NULL DEFAULT 'queued',
            target_identity_json TEXT NOT NULL DEFAULT '{}',
            source_generations_json TEXT NOT NULL DEFAULT '[]',
            exclusions_json TEXT NOT NULL DEFAULT '[]',
            resumed_from_run_id INTEGER REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            started_at TEXT,
            finished_at TEXT,
            seal_json TEXT,
            seal_sha256 TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, run_uuid)
        )
        """
    )
    run_columns = _table_columns(connection, "assessment_runs")
    run_column_additions = {
        "run_purpose": "TEXT NOT NULL DEFAULT 'proof'",
        "target_identity_json": "TEXT NOT NULL DEFAULT '{}'",
        "source_generations_json": "TEXT NOT NULL DEFAULT '[]'",
        "exclusions_json": "TEXT NOT NULL DEFAULT '[]'",
        "resumed_from_run_id": "INTEGER REFERENCES assessment_runs(id) ON DELETE RESTRICT",
        "started_at": "TEXT",
        "finished_at": "TEXT",
        "seal_json": "TEXT",
        "seal_sha256": "TEXT NOT NULL DEFAULT ''",
    }
    for column_name, column_definition in run_column_additions.items():
        if run_columns and column_name not in run_columns:
            connection.execute(
                f"ALTER TABLE assessment_runs ADD COLUMN {column_name} {column_definition}"
            )
    # ``started`` was the Phase 2 name for an unsealed active proof run. Phase 3
    # distinguishes queued from running; preserving it as a public alias would
    # leave two names for the same durable state.
    connection.execute(
        "UPDATE assessment_runs SET status = 'running', "
        "started_at = COALESCE(started_at, created_at) WHERE status = 'started'"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_runs_dispatch "
        "ON assessment_runs(engagement_id, producer_dispatch_id, created_at DESC)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_lifecycle_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            from_status TEXT,
            to_status TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_lifecycle "
        "ON assessment_run_lifecycle_events(engagement_id, run_id, id)"
    )
    # Add one truthful baseline event for Phase 2 rows. This is a migration
    # write, never a GET-side repair, so status reads remain side-effect free.
    connection.execute(
        """
        INSERT INTO assessment_run_lifecycle_events (
            engagement_id, run_id, from_status, to_status, reason, created_at
        )
        SELECT runs.engagement_id, runs.id, NULL, runs.status,
               'migrated Phase 2 run state', runs.created_at
        FROM assessment_runs AS runs
        WHERE NOT EXISTS (
            SELECT 1 FROM assessment_run_lifecycle_events AS events
            WHERE events.run_id = runs.id
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            target_key TEXT NOT NULL,
            declared_root TEXT NOT NULL,
            path TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            byte_size INTEGER NOT NULL,
            line_count INTEGER NOT NULL,
            encoding TEXT NOT NULL,
            inventory_status TEXT NOT NULL,
            exclusion_reason TEXT NOT NULL DEFAULT '',
            parser_status TEXT NOT NULL,
            parser_error TEXT NOT NULL DEFAULT '',
            identity_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, target_key, declared_root, path)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_sources_page "
        "ON assessment_run_sources(engagement_id, run_id, target_key, path, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_source_reads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            source_id INTEGER NOT NULL REFERENCES assessment_run_sources(id) ON DELETE RESTRICT,
            dispatch_id INTEGER NOT NULL REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            attempt INTEGER NOT NULL,
            byte_start INTEGER NOT NULL,
            byte_end INTEGER NOT NULL,
            line_start INTEGER NOT NULL,
            line_end INTEGER NOT NULL,
            proof_receipt_id INTEGER REFERENCES assessment_proof_receipts(id) ON DELETE RESTRICT,
            read_fingerprint TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, read_fingerprint)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_source_reads_page "
        "ON assessment_run_source_reads(engagement_id, run_id, source_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_obligations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            identity_key TEXT NOT NULL,
            obligation_kind TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_key TEXT NOT NULL,
            hard INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'open',
            resolution TEXT NOT NULL DEFAULT '',
            proof_receipt_ids_json TEXT NOT NULL DEFAULT '[]',
            record_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, identity_key)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_obligations_page "
        "ON assessment_run_obligations(engagement_id, run_id, status, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_obligation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            obligation_id INTEGER NOT NULL REFERENCES assessment_run_obligations(id) ON DELETE RESTRICT,
            from_status TEXT,
            to_status TEXT NOT NULL,
            resolution TEXT NOT NULL DEFAULT '',
            proof_receipt_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_obligation_history "
        "ON assessment_run_obligation_events(engagement_id, run_id, obligation_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            identity_key TEXT NOT NULL,
            target_key TEXT NOT NULL,
            source_id INTEGER REFERENCES assessment_run_sources(id) ON DELETE RESTRICT,
            source_anchor TEXT NOT NULL,
            vulnerability_family TEXT NOT NULL,
            hypothesis TEXT NOT NULL,
            originating_result_id INTEGER REFERENCES code_analysis_results(id) ON DELETE RESTRICT,
            originating_signal_id INTEGER,
            dispatch_id INTEGER NOT NULL REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            proof_receipt_ids_json TEXT NOT NULL DEFAULT '[]',
            state TEXT NOT NULL DEFAULT 'open',
            finding_slug TEXT NOT NULL DEFAULT '',
            record_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, identity_key)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_candidates_page "
        "ON assessment_run_candidates(engagement_id, run_id, state, id)"
    )
    candidate_columns = _table_columns(connection, "assessment_run_candidates")
    if candidate_columns and "originating_signal_id" not in candidate_columns:
        connection.execute(
            "ALTER TABLE assessment_run_candidates ADD COLUMN originating_signal_id INTEGER"
        )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_candidate_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            candidate_id INTEGER NOT NULL REFERENCES assessment_run_candidates(id) ON DELETE RESTRICT,
            from_state TEXT,
            to_state TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            proof_receipt_ids_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_tool_signals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            identity_key TEXT NOT NULL,
            signal_kind TEXT NOT NULL,
            dispatch_id INTEGER NOT NULL REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            target_key TEXT NOT NULL,
            source_id INTEGER REFERENCES assessment_run_sources(id) ON DELETE RESTRICT,
            source_anchor TEXT NOT NULL,
            vulnerability_family TEXT NOT NULL,
            hypothesis TEXT NOT NULL,
            observed_signature TEXT NOT NULL,
            exact_input_sha256 TEXT NOT NULL DEFAULT '',
            command_run_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE RESTRICT,
            proof_receipt_ids_json TEXT NOT NULL,
            candidate_id INTEGER NOT NULL REFERENCES assessment_run_candidates(id) ON DELETE RESTRICT,
            record_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, identity_key)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_tool_signals_page "
        "ON assessment_run_tool_signals(engagement_id, run_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_discovery_passes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            identity_key TEXT NOT NULL,
            dispatch_id INTEGER NOT NULL REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            frontier_identity_sha256 TEXT NOT NULL,
            terminal_reason TEXT NOT NULL,
            candidate_identity_keys_json TEXT NOT NULL,
            candidate_delta INTEGER NOT NULL,
            proof_receipt_ids_json TEXT NOT NULL,
            record_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, identity_key)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_discovery_passes_page "
        "ON assessment_run_discovery_passes(engagement_id, run_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_code_receipt_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            receipt_kind TEXT NOT NULL,
            receipt_id INTEGER NOT NULL,
            target_key TEXT NOT NULL,
            obligation_id INTEGER NOT NULL
                REFERENCES assessment_run_obligations(id) ON DELETE RESTRICT,
            candidate_ids_json TEXT NOT NULL,
            signal_ids_json TEXT NOT NULL,
            proof_receipt_ids_json TEXT NOT NULL,
            obligation_status TEXT NOT NULL,
            record_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, receipt_kind, receipt_id, obligation_id)
        )
        """
    )
    if "target_key" not in _table_columns(
        connection, "assessment_run_code_receipt_links"
    ):
        connection.execute(
            "ALTER TABLE assessment_run_code_receipt_links "
            "ADD COLUMN target_key TEXT NOT NULL DEFAULT ''"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_code_receipts_page "
        "ON assessment_run_code_receipt_links(engagement_id, run_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_run_comparisons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            baseline_run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            selection TEXT NOT NULL,
            target_compatible INTEGER NOT NULL,
            source_compatible INTEGER NOT NULL,
            comparison_json TEXT NOT NULL,
            comparison_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(run_id, baseline_run_id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_run_comparisons "
        "ON assessment_run_comparisons(engagement_id, run_id, id DESC)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_proof_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id) ON DELETE RESTRICT,
            producer_dispatch_id INTEGER NOT NULL
                REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            evidence_kind TEXT NOT NULL,
            expected_result TEXT NOT NULL DEFAULT '',
            observed_result TEXT NOT NULL DEFAULT '',
            artifact_id INTEGER REFERENCES assessment_artifacts(id) ON DELETE SET NULL,
            source_read_id INTEGER
                REFERENCES assessment_run_source_reads(id) ON DELETE RESTRICT,
            command_run_id INTEGER REFERENCES assessment_command_runs(id) ON DELETE RESTRICT,
            artifact_relative_path TEXT NOT NULL DEFAULT '',
            evidence_sha256 TEXT NOT NULL,
            recorded_health TEXT NOT NULL DEFAULT 'healthy',
            redaction_status TEXT NOT NULL DEFAULT 'raw',
            derivative_of_receipt_id INTEGER
                REFERENCES assessment_proof_receipts(id) ON DELETE RESTRICT,
            tombstone_reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    proof_receipt_columns = _table_columns(connection, "assessment_proof_receipts")
    if proof_receipt_columns and "source_read_id" not in proof_receipt_columns:
        connection.execute(
            "ALTER TABLE assessment_proof_receipts "
            "ADD COLUMN source_read_id INTEGER "
            "REFERENCES assessment_run_source_reads(id) ON DELETE RESTRICT"
        )
    if proof_receipt_columns and "command_run_id" not in proof_receipt_columns:
        connection.execute(
            "ALTER TABLE assessment_proof_receipts "
            "ADD COLUMN command_run_id INTEGER "
            "REFERENCES assessment_command_runs(id) ON DELETE RESTRICT"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_proof_receipts_run "
        "ON assessment_proof_receipts(engagement_id, run_id, id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_proof_receipts_derivative "
        "ON assessment_proof_receipts(engagement_id, derivative_of_receipt_id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_finding_proof_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE CASCADE,
            transition_id INTEGER NOT NULL
                REFERENCES assessment_finding_transitions(id) ON DELETE RESTRICT,
            proof_receipt_id INTEGER NOT NULL
                REFERENCES assessment_proof_receipts(id) ON DELETE RESTRICT,
            relation TEXT NOT NULL DEFAULT 'verification',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(finding_id, proof_receipt_id, relation)
        )
        """
    )
    proof_link_columns = _table_columns(
        connection, "assessment_finding_proof_receipts"
    )
    if "transition_id" not in proof_link_columns:
        connection.execute(
            "ALTER TABLE assessment_finding_proof_receipts "
            "ADD COLUMN transition_id INTEGER "
            "REFERENCES assessment_finding_transitions(id) ON DELETE RESTRICT"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_finding_proof_receipts_finding "
        "ON assessment_finding_proof_receipts(engagement_id, finding_id, id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_finding_proof_receipts_transition "
        "ON assessment_finding_proof_receipts"
        "(engagement_id, finding_id, transition_id, id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_finding_counterchecks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE CASCADE,
            transition_id INTEGER NOT NULL
                REFERENCES assessment_finding_transitions(id) ON DELETE RESTRICT,
            verifier_dispatch_id INTEGER NOT NULL
                REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
            method TEXT NOT NULL,
            expected_result TEXT NOT NULL,
            observed_result TEXT NOT NULL,
            falsified_claim TEXT NOT NULL,
            completed INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_finding_countercheck_receipts (
            countercheck_id INTEGER NOT NULL
                REFERENCES assessment_finding_counterchecks(id) ON DELETE CASCADE,
            proof_receipt_id INTEGER NOT NULL
                REFERENCES assessment_proof_receipts(id) ON DELETE RESTRICT,
            PRIMARY KEY(countercheck_id, proof_receipt_id)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_finding_counterchecks_finding "
        "ON assessment_finding_counterchecks(engagement_id, finding_id, id DESC)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_finding_severity_variances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE CASCADE,
            transition_id INTEGER NOT NULL
                REFERENCES assessment_finding_transitions(id) ON DELETE RESTRICT,
            normal_band TEXT NOT NULL,
            chosen_severity TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            proof_receipt_id INTEGER NOT NULL
                REFERENCES assessment_proof_receipts(id) ON DELETE RESTRICT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_finding_severity_variances_finding "
        "ON assessment_finding_severity_variances(engagement_id, finding_id, id DESC)"
    )


def _migrate_run_accounting_schema(
    connection: sqlite3.Connection,
    *,
    backup_path: Path,
    reasons: tuple[str, ...],
) -> None:
    """Upgrade the Phase 2 run/proof ledger and record its preservation report."""

    tables_before = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    preserved_counts = {
        table_name: int(
            connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        )
        for table_name in sorted(_RUN_ACCOUNTING_TABLES.intersection(tables_before))
    }
    status_mappings: list[dict[str, Any]] = []
    if "assessment_runs" in tables_before:
        status_mappings = [
            {
                "run_id": int(row["id"]),
                "run_uuid": str(row["run_uuid"]),
                "from_status": "started",
                "to_status": "running",
            }
            for row in connection.execute(
                "SELECT id, run_uuid FROM assessment_runs "
                "WHERE status = 'started' ORDER BY id"
            ).fetchall()
        ]

    _create_verification_evidence_tables(connection)
    _create_migration_history_tables(connection)
    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (
            _RUN_ACCOUNTING_MIGRATION_ID,
            "phase-2-run-proof-ledger",
            "phase-3-run-accounting-v1",
            len(status_mappings),
            str(backup_path),
            json.dumps(
                {
                    "backup_path": str(backup_path),
                    "preserved_counts": preserved_counts,
                    "reasons": list(reasons),
                    "status_mappings": status_mappings,
                },
                sort_keys=True,
            ),
        ),
    )


def _migrate_run_accounting_v2_schema(
    connection: sqlite3.Connection,
    *,
    backup_path: Path,
    reasons: tuple[str, ...],
) -> None:
    """Add automatic-signal accounting without rewriting the v1 ledger."""

    tables_before = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    preserved_counts = {
        table_name: int(
            connection.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        )
        for table_name in sorted(
            (_RUN_ACCOUNTING_TABLES | _RUN_ACCOUNTING_V2_TABLES).intersection(
                tables_before
            )
        )
    }
    _create_verification_evidence_tables(connection)
    _create_migration_history_tables(connection)
    connection.execute(
        """
        INSERT INTO schema_migrations (
            migration_id, from_version, to_version, migrated_rows,
            warning_count, backup_path, report_json
        ) VALUES (?, ?, ?, 0, 0, ?, ?)
        """,
        (
            _RUN_ACCOUNTING_V2_MIGRATION_ID,
            "phase-3-run-accounting-v1",
            "phase-3-run-accounting-v2",
            str(backup_path),
            json.dumps(
                {
                    "backup_path": str(backup_path),
                    "preserved_counts": preserved_counts,
                    "reasons": list(reasons),
                },
                sort_keys=True,
            ),
        ),
    )


def _create_oob_correlation_tables(connection: sqlite3.Connection) -> None:
    # OAST (out-of-band) auto-correlation. ``vigil oob mint`` records a probe
    # with a unique random ``nonce`` subdomain label; that label IS the
    # correlation token routed through the shared interactsh/frp transport
    # (see src/vigil_cli/oob.py). ``vigil oob poll`` parses the
    # interactsh-client log, extracts the nonce from each callback host, and
    # records the matching interaction here so a blind callback auto-maps to
    # the payload that caused it. The interaction child table keeps one row
    # per observed callback (a single probe can fire multiple times).
    #
    # Constraint enforcement on status / probe_kind / protocol lives in the
    # Pydantic layer so the enums can evolve without a schema rebuild.
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_oob_probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                target_url TEXT NOT NULL DEFAULT '',
                param TEXT NOT NULL DEFAULT '',
                technique TEXT NOT NULL DEFAULT '',
                probe_kind TEXT NOT NULL DEFAULT '',
                request_hash TEXT NOT NULL DEFAULT '',
                oob_domain TEXT NOT NULL DEFAULT '',
                client_name TEXT NOT NULL DEFAULT '',
                client_payload_host TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    probe_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(assessment_oob_probes)"
        ).fetchall()
    }
    if "client_name" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_oob_probes ADD COLUMN client_name TEXT NOT NULL DEFAULT ''"
        )
    if "client_payload_host" not in probe_columns:
        connection.execute(
            "ALTER TABLE assessment_oob_probes ADD COLUMN client_payload_host TEXT NOT NULL DEFAULT ''"
        )
    connection.execute(
        "UPDATE assessment_oob_probes SET status = 'expired', updated_at = CURRENT_TIMESTAMP "
        "WHERE status = 'pending' AND (client_name = '' OR client_payload_host = '')"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_oob_probes_engagement_status "
        "ON assessment_oob_probes(engagement_id, status)"
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS assessment_oob_interactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                probe_id INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT '',
                remote_address TEXT NOT NULL DEFAULT '',
                query_type TEXT NOT NULL DEFAULT '',
                raw_request TEXT NOT NULL DEFAULT '',
                interaction_hash TEXT NOT NULL,
                observed_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(probe_id, interaction_hash),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(probe_id) REFERENCES assessment_oob_probes(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_oob_interactions_probe "
        "ON assessment_oob_interactions(probe_id)"
    )


def _create_intel_and_activity_fts(connection: sqlite3.Connection) -> None:

    # FTS5 virtual tables + rebuild-on-drift guard follow the same pattern
    # as assessment_command_runs_fts in _create_command_runs_table_and_fts.
    intel_fts_columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(intel_search_fts)").fetchall()
    }
    existing_intel_search_count = connection.execute(
        "SELECT COUNT(*) FROM intel_search_index"
    ).fetchone()[0]
    rebuild_intel_search_fts = not intel_fts_columns and existing_intel_search_count > 0
    expected_intel_fts_columns = {"key", "body", "source_name", "entity_type"}
    if intel_fts_columns and not expected_intel_fts_columns.issubset(intel_fts_columns):
        connection.execute("DROP TABLE IF EXISTS intel_search_fts")
        for trigger in (
            "intel_search_index_ai",
            "intel_search_index_ad",
            "intel_search_index_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        rebuild_intel_search_fts = existing_intel_search_count > 0
    connection.execute(
        """
            CREATE VIRTUAL TABLE IF NOT EXISTS intel_search_fts
            USING fts5(
                key,
                body,
                source_name,
                entity_type,
                content='intel_search_index',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS intel_search_index_ai
            AFTER INSERT ON intel_search_index BEGIN
                INSERT INTO intel_search_fts(rowid, key, body, source_name, entity_type)
                VALUES (new.id, new.key, new.body, new.source_name, new.entity_type);
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS intel_search_index_ad
            AFTER DELETE ON intel_search_index BEGIN
                INSERT INTO intel_search_fts(intel_search_fts, rowid, key, body, source_name, entity_type)
                VALUES ('delete', old.id, old.key, old.body, old.source_name, old.entity_type);
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS intel_search_index_au
            AFTER UPDATE ON intel_search_index BEGIN
                INSERT INTO intel_search_fts(intel_search_fts, rowid, key, body, source_name, entity_type)
                VALUES ('delete', old.id, old.key, old.body, old.source_name, old.entity_type);
                INSERT INTO intel_search_fts(rowid, key, body, source_name, entity_type)
                VALUES (new.id, new.key, new.body, new.source_name, new.entity_type);
            END
            """
    )
    if rebuild_intel_search_fts:
        connection.execute(
            "INSERT INTO intel_search_fts(intel_search_fts) VALUES ('rebuild')"
        )

    activity_fts_columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(activity_entries_fts)"
        ).fetchall()
    }
    existing_activity_count = connection.execute(
        "SELECT COUNT(*) FROM activity_entries"
    ).fetchone()[0]
    rebuild_activity_fts = not activity_fts_columns and existing_activity_count > 0
    expected_activity_fts_columns = {
        "title",
        "action",
        "result",
        "body_markdown",
        "actor_name",
    }
    if activity_fts_columns and not expected_activity_fts_columns.issubset(
        activity_fts_columns
    ):
        connection.execute("DROP TABLE IF EXISTS activity_entries_fts")
        for trigger in (
            "activity_entries_ai",
            "activity_entries_ad",
            "activity_entries_au",
        ):
            connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
        rebuild_activity_fts = existing_activity_count > 0
    connection.execute(
        """
            CREATE VIRTUAL TABLE IF NOT EXISTS activity_entries_fts
            USING fts5(
                title,
                action,
                result,
                body_markdown,
                actor_name,
                content='activity_entries',
                content_rowid='id',
                tokenize='unicode61'
            )
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS activity_entries_ai
            AFTER INSERT ON activity_entries BEGIN
                INSERT INTO activity_entries_fts(rowid, title, action, result, body_markdown, actor_name)
                VALUES (new.id, new.title, new.action, new.result, new.body_markdown, new.actor_name);
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS activity_entries_ad
            AFTER DELETE ON activity_entries BEGIN
                INSERT INTO activity_entries_fts(activity_entries_fts, rowid, title, action, result, body_markdown, actor_name)
                VALUES ('delete', old.id, old.title, old.action, old.result, old.body_markdown, old.actor_name);
            END
            """
    )
    connection.execute(
        """
            CREATE TRIGGER IF NOT EXISTS activity_entries_au
            AFTER UPDATE ON activity_entries BEGIN
                INSERT INTO activity_entries_fts(activity_entries_fts, rowid, title, action, result, body_markdown, actor_name)
                VALUES ('delete', old.id, old.title, old.action, old.result, old.body_markdown, old.actor_name);
                INSERT INTO activity_entries_fts(rowid, title, action, result, body_markdown, actor_name)
                VALUES (new.id, new.title, new.action, new.result, new.body_markdown, new.actor_name);
            END
            """
    )
    if rebuild_activity_fts:
        connection.execute(
            "INSERT INTO activity_entries_fts(activity_entries_fts) VALUES ('rebuild')"
        )


def _run_data_migrations(connection: sqlite3.Connection) -> None:

    # Intel supersede migration: each intel_* row may be marked stale when
    # a newer record displaces it. Report-writer filters on
    # superseded_by_id IS NULL so historical rows stay queryable for
    # audit but never appear in the report. Idempotent: re-runs skip
    # tables that already carry the columns.
    #
    # Wrapped in ``BEGIN IMMEDIATE`` + commit/rollback so the 20 ALTER
    # statements either all succeed or all roll back. Mid-loop failure
    # (disk full, FK constraint mismatch on ALTER REFERENCES) used to
    # leave the schema split-brain — half the intel_* tables carrying the
    # supersede columns and half not — which made downstream code paths
    # unsafe to run.
    _INTEL_SUPERSEDE_TABLES: tuple[str, ...] = (
        "intel_tech_components",
        "intel_people",
        "intel_emails",
        "intel_domains",
        "intel_cves",
        "intel_dns_records",
        "intel_social_profiles",
        "intel_breach_records",
        "intel_org_facts",
        "intel_notes",
    )
    # Flush any implicit Python-sqlite3 transaction before starting an
    # explicit BEGIN IMMEDIATE — Python's sqlite3 driver opens a deferred
    # txn on first DML, and a manual BEGIN inside that txn raises
    # ``cannot start a transaction within a transaction``. Committing
    # first releases the implicit txn cleanly.
    if connection.in_transaction:
        connection.commit()
    connection.execute("BEGIN IMMEDIATE")
    try:
        for intel_table in _INTEL_SUPERSEDE_TABLES:
            intel_columns = _table_columns(connection, intel_table)
            if intel_columns and "superseded_by_id" not in intel_columns:
                connection.execute(
                    f"ALTER TABLE {intel_table} ADD COLUMN superseded_by_id INTEGER REFERENCES {intel_table}(id) ON DELETE SET NULL"
                )
            if intel_columns and "superseded_at" not in intel_columns:
                connection.execute(
                    f"ALTER TABLE {intel_table} ADD COLUMN superseded_at TEXT"
                )
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    # ── End Intel Tables ──────────────────────────────────────

    _migrate_legacy_finding_slug_references(connection)


def _create_assessment_work_items_table(connection: sqlite3.Connection) -> None:
    """Engagement-scoped work buffer — the transient queue of captured/ingested
    HTTP requests awaiting triage and probing. Folds the former per-engagement
    ``cases.db`` ``work_items`` table into the backend ledger (ADR 0013).

    Keeps a denormalized request/response snapshot (refreshed on every re-ingest
    by the service-layer UPSERT) so the dispatcher ``fetch`` returns a flat,
    replayable row without a join, while carrying REAL foreign keys to the
    request-variant / service / coverage-item so referential integrity is
    enforced. ``UNIQUE(engagement_id, queue_key)`` is the idempotent-upsert key.
    """
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS assessment_work_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            queue_key TEXT NOT NULL,
            request_variant_id INTEGER,
            service_id INTEGER,
            coverage_item_id INTEGER,
            application_unit_id INTEGER,
            auth_context TEXT NOT NULL DEFAULT 'anonymous',
            method TEXT NOT NULL DEFAULT 'GET',
            url TEXT NOT NULL,
            url_path TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            query_params TEXT NOT NULL DEFAULT '{}',
            body_params TEXT NOT NULL DEFAULT '{}',
            path_params TEXT NOT NULL DEFAULT '{}',
            cookie_params TEXT NOT NULL DEFAULT '{}',
            headers TEXT NOT NULL DEFAULT '',
            body TEXT,
            content_type TEXT NOT NULL DEFAULT '',
            content_length INTEGER NOT NULL DEFAULT 0,
            request_body_truncated INTEGER NOT NULL DEFAULT 0,
            response_status INTEGER NOT NULL DEFAULT 0,
            response_headers TEXT NOT NULL DEFAULT '',
            response_size INTEGER NOT NULL DEFAULT 0,
            response_snippet TEXT,
            response_truncated INTEGER NOT NULL DEFAULT 0,
            type TEXT NOT NULL DEFAULT 'unknown',
            source TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            assigned_agent TEXT,
            retry_count INTEGER NOT NULL DEFAULT 0,
            consumed_at TEXT,
            params_key_sig TEXT NOT NULL DEFAULT '',
            priority_score INTEGER NOT NULL DEFAULT 0,
            priority_reason TEXT,
            cluster_key TEXT,
            terminal_reason TEXT,
            classifier_version TEXT,
            signals TEXT,
            selected_by TEXT,
            triage_rationale TEXT,
            live_status TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, queue_key),
            FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
            FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE,
            FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE SET NULL,
            FOREIGN KEY(coverage_item_id) REFERENCES assessment_coverage_items(id) ON DELETE SET NULL,
            FOREIGN KEY(application_unit_id) REFERENCES assessment_application_units(id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_priority "
        "ON assessment_work_items(engagement_id, status, priority_score DESC, cluster_key, id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_status_type "
        "ON assessment_work_items(engagement_id, status, type)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_host "
        "ON assessment_work_items(engagement_id, host, status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_consumed "
        "ON assessment_work_items(engagement_id, status, consumed_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_source "
        "ON assessment_work_items(engagement_id, source)"
    )
    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(assessment_work_items)")
    }
    if "application_unit_id" not in columns:
        connection.execute(
            "ALTER TABLE assessment_work_items ADD COLUMN application_unit_id INTEGER "
            "REFERENCES assessment_application_units(id) ON DELETE SET NULL"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_work_items_unit_pending "
        "ON assessment_work_items(engagement_id, application_unit_id, status, type, id)"
    )


def _create_post_migration_indexes(connection: sqlite3.Connection) -> None:
    """Indexes whose columns only exist after ``_apply_additive_migrations``.

    ``_create_*_tables`` runs before the additive migrations, and on an existing
    database its ``CREATE TABLE IF NOT EXISTS`` is a no-op -- so a column added by
    migration is absent at that point and ``CREATE INDEX`` over it raises
    ``sqlite3.OperationalError: no such column`` and fails startup outright. Any
    index over a key in the additive-migration column maps therefore belongs here,
    after the columns are guaranteed to exist.
    """

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_findings_verification "
        "ON assessment_findings(engagement_id, verification_status)"
    )
    # The submission axis is only joinable to the external program when the
    # report's own identifier is indexed beside the engagement.
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_assessment_findings_submission_ref "
        "ON assessment_findings(engagement_id, submission_ref)"
    )


_REMEDIATION_CASE_TABLE_SQL = """
        CREATE TABLE {if_not_exists}{table} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            source_type TEXT NOT NULL,
            source_key TEXT NOT NULL,
            title TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'intake',
            worktree_path TEXT,
            worktree_branch TEXT,
            worktree_revision TEXT,
            base_branch TEXT,
            base_revision TEXT,
            review_policy_json TEXT,
            verification_requirements_json TEXT,
            verification_plan TEXT NOT NULL DEFAULT '',
            baseline_json TEXT NOT NULL DEFAULT '{{}}',
            release_plan_json TEXT NOT NULL DEFAULT '{{}}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, source_type, source_key)
        )
"""


def _create_remediation_finding_links(connection: sqlite3.Connection) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS remediation_case_findings (
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(case_id, finding_id)
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS idx_remediation_case_findings_finding ON remediation_case_findings(finding_id, case_id)")


def _database_needs_remediation_finding_link_migration(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with closing(sqlite3.connect(str(db_path))) as connection:
        table = connection.execute("SELECT sql FROM sqlite_master WHERE name='remediation_cases'").fetchone()
        return "linked_finding_slug" in _table_columns(connection, "remediation_cases") or bool(
            table and "CHECK(source_type IN" in table[0]
        )


def _migrate_remediation_finding_links(db_path: Path) -> None:
    # Disabling FK actions prevents rebuilding the parent from cascading into
    # its immutable ledgers. The transaction and final check preserve integrity.
    with closing(sqlite3.connect(str(db_path))) as connection, connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN IMMEDIATE")
        columns = _table_columns(connection, "remediation_cases")
        sequence = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='remediation_cases'").fetchone()
        linked_rows = []
        for row in connection.execute("SELECT c.*,e.key AS owner_key FROM remediation_cases c JOIN engagements e ON e.id=c.engagement_id ORDER BY c.id"):
            slug = row["linked_finding_slug"] if "linked_finding_slug" in columns else None
            key = row["linked_finding_engagement_key"] if "linked_finding_engagement_key" in columns else None
            if not slug and not key:
                continue
            matches = connection.execute(
                "SELECT f.id FROM assessment_findings f JOIN engagements e ON e.id=f.engagement_id WHERE e.key=? AND f.slug=?",
                (key or row["owner_key"], slug),
            ).fetchall()
            if len(matches) != 1:
                raise RuntimeError(f"Cannot migrate remediation case {row['id']}: unresolved finding {key or row['owner_key']!r}/{slug!r}")
            linked_rows.append((row["id"], matches[0]["id"]))
        connection.execute(_REMEDIATION_CASE_TABLE_SQL.format(if_not_exists="", table="remediation_cases_next"))
        next_columns = _table_columns(connection, "remediation_cases_next")
        unknown_columns = columns - next_columns - {"linked_finding_slug", "linked_finding_engagement_key"}
        if unknown_columns:
            raise RuntimeError(f"Cannot migrate remediation cases with unknown columns: {sorted(unknown_columns)!r}")
        shared_columns = sorted(columns & next_columns)
        names = ",".join(shared_columns)
        connection.execute(f"INSERT INTO remediation_cases_next({names}) SELECT {names} FROM remediation_cases")
        connection.execute("DROP TABLE remediation_cases")
        connection.execute("ALTER TABLE remediation_cases_next RENAME TO remediation_cases")
        if sequence is not None:
            updated = connection.execute("UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='remediation_cases'", (sequence["seq"],))
            if not updated.rowcount:
                connection.execute("INSERT INTO sqlite_sequence(name,seq) VALUES('remediation_cases',?)", (sequence["seq"],))
        _create_remediation_finding_links(connection)
        connection.executemany("INSERT INTO remediation_case_findings(case_id,finding_id) VALUES(?,?)", linked_rows)
        failures = connection.execute("PRAGMA foreign_key_check").fetchall()
        if failures:
            raise RuntimeError(f"Remediation finding migration failed foreign-key validation: {failures!r}")


def _create_remediation_tables(connection: sqlite3.Connection) -> None:
    connection.execute(_REMEDIATION_CASE_TABLE_SQL.format(if_not_exists="IF NOT EXISTS ", table="remediation_cases"))
    _create_remediation_finding_links(connection)
    connection.executescript("""
        CREATE INDEX IF NOT EXISTS idx_remediation_cases_queue
            ON remediation_cases(engagement_id, status, updated_at DESC);
        CREATE TABLE IF NOT EXISTS remediation_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            method TEXT NOT NULL,
            environment TEXT,
            command TEXT NOT NULL DEFAULT '',
            observed TEXT NOT NULL,
            proved TEXT NOT NULL,
            outcome TEXT,
            artifact_path TEXT,
            artifact_sha256 TEXT,
            revision TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remediation_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            reviewer TEXT NOT NULL,
            review_digest TEXT NOT NULL,
            approved_revision TEXT NOT NULL,
            evidence_cutoff_id INTEGER NOT NULL DEFAULT 0,
            approval_method TEXT NOT NULL DEFAULT 'ui',
            owner_instruction TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remediation_transitions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            from_status TEXT NOT NULL,
            to_status TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remediation_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            approval_id INTEGER REFERENCES remediation_approvals(id),
            workflow TEXT NOT NULL,
            run_id TEXT NOT NULL,
            environment TEXT NOT NULL,
            expected_revision TEXT NOT NULL,
            observed_revision TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remediation_human_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            deployment_id INTEGER NOT NULL REFERENCES remediation_deployments(id) ON DELETE CASCADE,
            actor TEXT NOT NULL,
            result TEXT NOT NULL CHECK(result IN ('passed', 'failed', 'blocked')),
            observed_revision TEXT NOT NULL,
            notes TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS remediation_environment_leases (
            scope TEXT NOT NULL,
            environment TEXT NOT NULL,
            case_id INTEGER NOT NULL REFERENCES remediation_cases(id) ON DELETE CASCADE,
            revision TEXT NOT NULL,
            actor TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            released_at TEXT,
            released_by TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_environment_owner
            ON remediation_environment_leases(scope, environment) WHERE released_at IS NULL;
    """)
    for column in ("base_branch", "base_revision", "review_policy_json", "verification_requirements_json"):
        if column not in _table_columns(connection, "remediation_cases"):
            connection.execute(f"ALTER TABLE remediation_cases ADD COLUMN {column} TEXT")
    for column in ("execution", "executed_revision", "executed_directory", "shared_environment", "environment_token", "runtime_revision"):
        if column not in _table_columns(connection, "remediation_evidence"):
            connection.execute(f"ALTER TABLE remediation_evidence ADD COLUMN {column} TEXT")
    for column in ("observed_revision", "confirmed_at", "confirmed_by"):
        if column not in _table_columns(connection, "remediation_environment_leases"):
            connection.execute(f"ALTER TABLE remediation_environment_leases ADD COLUMN {column} TEXT")
    if "worktree_branch" not in _table_columns(connection, "remediation_cases"):
        connection.execute("ALTER TABLE remediation_cases ADD COLUMN worktree_branch TEXT")
    if "baseline_json" not in _table_columns(connection, "remediation_cases"):
        connection.execute("ALTER TABLE remediation_cases ADD COLUMN baseline_json TEXT NOT NULL DEFAULT '{}'")
    if "release_plan_json" not in _table_columns(connection, "remediation_cases"):
        connection.execute("ALTER TABLE remediation_cases ADD COLUMN release_plan_json TEXT NOT NULL DEFAULT '{}'")
    if "evidence_cutoff_id" not in _table_columns(connection, "remediation_approvals"):
        connection.execute("ALTER TABLE remediation_approvals ADD COLUMN evidence_cutoff_id INTEGER NOT NULL DEFAULT 0")
    if "approval_method" not in _table_columns(connection, "remediation_approvals"):
        connection.execute("ALTER TABLE remediation_approvals ADD COLUMN approval_method TEXT NOT NULL DEFAULT 'ui'")
    if "owner_instruction" not in _table_columns(connection, "remediation_approvals"):
        connection.execute("ALTER TABLE remediation_approvals ADD COLUMN owner_instruction TEXT")
    if "outcome" not in _table_columns(connection, "remediation_evidence"):
        connection.execute("ALTER TABLE remediation_evidence ADD COLUMN outcome TEXT")
    if "environment" not in _table_columns(connection, "remediation_evidence"):
        connection.execute("ALTER TABLE remediation_evidence ADD COLUMN environment TEXT")
    if "approval_id" not in _table_columns(connection, "remediation_deployments"):
        connection.execute("ALTER TABLE remediation_deployments ADD COLUMN approval_id INTEGER REFERENCES remediation_approvals(id)")


def init_db() -> None:
    global _connection_generation, _startup_database_fingerprint

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db_path = database_path()
    _check_database_compatibility(db_path)
    if _database_needs_remediation_finding_link_migration(db_path):
        _create_adjacent_migration_backup(db_path, label="remediation-finding-links")
        _migrate_remediation_finding_links(db_path)
    verification_backup = (
        _create_adjacent_verification_backup(db_path)
        if _database_needs_verification_status_migration(db_path)
        else None
    )
    dispatch_backup = (
        _create_adjacent_dispatch_backup(db_path)
        if _database_needs_dispatch_schema_migration(db_path)
        else None
    )
    retry_state_backup = (
        _create_adjacent_retry_state_backup(db_path)
        if _database_needs_retry_state_migration(db_path)
        else None
    )
    rate_lease_retirement_backup = (
        _create_adjacent_rate_lease_retirement_backup(db_path)
        if _database_needs_rate_lease_retirement(db_path)
        else None
    )
    run_accounting_migration_reasons = _database_run_accounting_migration_reasons(
        db_path
    )
    run_accounting_backup = (
        _create_adjacent_run_accounting_backup(db_path)
        if run_accounting_migration_reasons
        else None
    )
    run_accounting_v2_migration_reasons = (
        _database_run_accounting_v2_migration_reasons(db_path)
    )
    run_accounting_v2_backup = (
        _create_adjacent_run_accounting_v2_backup(db_path)
        if run_accounting_v2_migration_reasons
        else None
    )
    with closing(sqlite3.connect(str(db_path))) as connection, connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        # WAL mode lets readers (including `sqlite3 .backup` snapshots and the
        # 15-minute backend backup task) run concurrently with writers without
        # taking an exclusive lock. Without this, the rollback-journal default
        # causes backups to collide with active writes and return SQLITE_BUSY.
        connection.execute("PRAGMA journal_mode = WAL")
        _require_fts5(connection)
        _create_core_tables(connection)
        _create_remediation_tables(connection)
        _create_credentials_table(connection)
        _create_assessment_entity_tables(connection)
        _create_assessment_work_items_table(connection)
        _create_assessment_finding_tables(connection)
        _create_command_runs_table_and_fts(connection)
        _create_artifacts_table_and_fts(connection)
        _create_submission_version_tables(connection)
        _create_sent_reply_version_tables(connection)
        _create_http_flow_tables(connection)
        _create_jobs_table(connection)
        db_code_analysis_schema.create_tables(connection)
        _apply_additive_migrations(connection)
        if verification_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_finding_verification_status(
                    connection, backup_path=verification_backup
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        else:
            _create_migration_history_tables(connection)
        if dispatch_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_dispatch_schema(connection, backup_path=dispatch_backup)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if retry_state_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_blocked_technique_retry_state(
                    connection, backup_path=retry_state_backup
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if rate_lease_retirement_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_rate_lease_history(
                    connection, backup_path=rate_lease_retirement_backup
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        _create_post_migration_indexes(connection)
        _create_intel_tables(connection)
        _create_code_lead_binding_table(connection)
        _create_activity_table(connection)
        _create_dispatch_tables(connection)
        if run_accounting_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_run_accounting_schema(
                    connection,
                    backup_path=run_accounting_backup,
                    reasons=run_accounting_migration_reasons,
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        elif run_accounting_v2_backup is None:
            _create_verification_evidence_tables(connection)
        if run_accounting_v2_backup is not None:
            if connection.in_transaction:
                connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            try:
                _migrate_run_accounting_v2_schema(
                    connection,
                    backup_path=run_accounting_v2_backup,
                    reasons=run_accounting_v2_migration_reasons,
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        _create_oob_correlation_tables(connection)
        _create_intel_and_activity_fts(connection)
        _run_data_migrations(connection)

        connection.commit()

    _startup_database_fingerprint = _database_fingerprint(db_path)
    _connection_generation += 1


_READINESS_SUBSYSTEM_TABLES: tuple[tuple[str, frozenset[str]], ...] = (
    (
        "assessment_schema",
        frozenset(
            {
                "engagements",
                "assessment_dispatches",
                "assessment_findings",
                "assessment_sent_reply_versions",
            }
        ),
    ),
    (
        "code_analysis_schema",
        frozenset(
            {
                "code_repos",
                "code_files",
                "code_analysis_queue",
                "code_variant_check_receipts",
                "code_variant_dispatch_scopes",
                "code_fuzz_decisions",
                "code_fuzz_campaign_receipts",
            }
        ),
    ),
)


def database_readiness_flags(connection: sqlite3.Connection) -> dict[str, bool]:
    """Return schema-level readiness for assessment vs code-analysis subsystems.

    These checks confirm ``init_db`` created the durable tables backing each
    API router; they are not HTTP-level router probes.

    Returns keys like ``assessment_schema_ready`` and ``code_analysis_schema_ready``.
    """
    names = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    flags: dict[str, bool] = {}
    for prefix, required in _READINESS_SUBSYSTEM_TABLES:
        flags[f"{prefix}_ready"] = required.issubset(names)
    return flags


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    db_path = _verify_database_fingerprint()
    connection = _connection_for_thread(db_path)
    depth = getattr(_thread_connections, "depth", 0)
    _thread_connections.depth = depth + 1
    try:
        yield connection
        if depth == 0:
            connection.commit()
    except BaseException:
        if depth == 0:
            connection.rollback()
        raise
    finally:
        _thread_connections.depth = depth


def _connection_for_thread(db_path: Path) -> sqlite3.Connection:
    cached = getattr(_thread_connections, "connection", None)
    cached_path = getattr(_thread_connections, "path", None)
    cached_generation = getattr(_thread_connections, "generation", None)
    if (
        cached is not None
        and cached_path == db_path
        and cached_generation == _connection_generation
    ):
        return cached
    if cached is not None:
        try:
            cached.close()
        except sqlite3.Error:
            pass
    connection = sqlite3.connect(str(db_path), cached_statements=512)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    # E1: the DB is WAL (single writer, concurrent readers). Set the busy-timeout
    # explicitly rather than relying on Python's implicit 5 s default so the wait
    # a concurrent writer takes on the BEGIN IMMEDIATE lock is documented and
    # tunable. Under multi-worker uvicorn (E1) several processes contend for the
    # single write lock; this gives the loser room to wait while remaining below
    # the agent client's read timeout so exhausted contention is returned as 503.
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    _thread_connections.connection = connection
    _thread_connections.path = db_path
    _thread_connections.generation = _connection_generation
    _thread_connections.depth = 0
    return connection


def close_thread_connection() -> None:
    connection = getattr(_thread_connections, "connection", None)
    if connection is not None:
        try:
            connection.close()
        except sqlite3.Error:
            pass
    _thread_connections.connection = None
    _thread_connections.path = None
    _thread_connections.generation = None
    _thread_connections.depth = 0


def create_engagement(
    key: str,
    target: str,
    status: str,
    engagement_root: str,
    engagement_type: str | None = None,
) -> Engagement:
    with get_connection() as connection:
        if engagement_type is None:
            cursor = connection.execute(
                """
                INSERT INTO engagements (key, target, status, engagement_root)
                VALUES (?, ?, ?, ?)
                """,
                (key, target, status, engagement_root),
            )
        else:
            cursor = connection.execute(
                """
                INSERT INTO engagements (key, target, status, engagement_root, engagement_type)
                VALUES (?, ?, ?, ?, ?)
                """,
                (key, target, status, engagement_root, engagement_type),
            )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return Engagement.from_row(row)


def update_engagement_root(engagement_id: int, engagement_root: str) -> Engagement:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE engagements
            SET engagement_root = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (engagement_root, engagement_id),
        )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        ).fetchone()
        assert row is not None
        return Engagement.from_row(row)


def update_engagement_identity(
    engagement_id: int,
    target: str,
    status: str,
    engagement_root: str,
    *,
    engagement_type: str | None = None,
) -> Engagement:
    """Update the mutable identity columns on an engagement row.

    ``engagement_type`` is opt-in: callers that don't have a manifest value
    handy (e.g. legacy sync paths) skip it and the column is left untouched.
    When passed, it joins the existing target/status/engagement_root diff
    guard so a no-op call still avoids bumping ``updated_at``.
    """
    with get_connection() as connection:
        if engagement_type is None:
            connection.execute(
                """
                UPDATE engagements
                SET target = ?, status = ?, engagement_root = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND (target != ? OR status != ? OR engagement_root != ?)
                """,
                (
                    target,
                    status,
                    engagement_root,
                    engagement_id,
                    target,
                    status,
                    engagement_root,
                ),
            )
        else:
            connection.execute(
                """
                UPDATE engagements
                SET target = ?,
                    status = ?,
                    engagement_root = ?,
                    engagement_type = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND (
                      target != ?
                      OR status != ?
                      OR engagement_root != ?
                      OR COALESCE(engagement_type, '') != ?
                  )
                """,
                (
                    target,
                    status,
                    engagement_root,
                    engagement_type,
                    engagement_id,
                    target,
                    status,
                    engagement_root,
                    engagement_type,
                ),
            )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        ).fetchone()
        assert row is not None
        return Engagement.from_row(row)


def list_engagements() -> list[Engagement]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            ORDER BY id ASC
            """,
        ).fetchall()
    return [Engagement.from_row(row) for row in rows]


def list_engagements_with_session_counts(
    *,
    status_filter: str | None = None,
    engagement_type: str | None = None,
) -> list[tuple[Engagement, int]]:
    where: list[str] = []
    params: list[Any] = []
    if status_filter:
        where.append("e.status = ?")
        params.append(status_filter)
    if engagement_type:
        where.append("e.engagement_type = ?")
        params.append(engagement_type)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""

    with get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT
                e.id,
                e.key,
                e.target,
                e.status,
                e.engagement_root,
                e.engagement_type,
                e.created_at,
                e.updated_at,
                COUNT(s.id) AS session_count
            FROM engagements e
            LEFT JOIN engagement_sessions s
              ON s.engagement_id = e.id
            {where_sql}
            GROUP BY
                e.id,
                e.key,
                e.target,
                e.status,
                e.engagement_root,
                e.engagement_type,
                e.created_at,
                e.updated_at
            ORDER BY e.id ASC
            """,
            params,
        ).fetchall()
    return [(Engagement.from_row(row), int(row["session_count"] or 0)) for row in rows]


def get_engagement_by_id(engagement_id: int) -> Engagement | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        ).fetchone()
    return Engagement.from_row(row) if row else None


def get_engagement_by_key(key: str) -> Engagement | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE key = ?
            """,
            (key,),
        ).fetchone()
    return Engagement.from_row(row) if row else None


# ---------------------------------------------------------------------------
# Engagement credentials (centralized auth store — replaces auth.json)
# ---------------------------------------------------------------------------

# Age backstops (multi-identity session store, 2026-07). Mirrors the
# host_liveness TTL-on-read pattern (command_runs._HOST_LIVENESS_TTL_SECONDS):
# a lazy sweep runs at the start of every credential read. Age NEVER marks a
# session `dead` (only a failed liveness probe does) — it soft-flags `stale`
# (LLM must re-probe) then hard-deletes.
_CRED_STALE_TTL_SECONDS = 8 * 3600  # 8h since last_seen -> stale
_CRED_HARD_DELETE_TTL_SECONDS = 5 * 24 * 3600  # 5 days since last_seen -> delete


def _parse_cred_timestamp(value: Any) -> datetime | None:
    """Parse a credential timestamp to an aware UTC datetime, or None.

    Tolerates both the canonical capture/upsert format written here
    (``YYYY-MM-DDTHH:MM:SSZ``) and the SQLite ``CURRENT_TIMESTAMP`` default
    (``YYYY-MM-DD HH:MM:SS``) that older ``updated_at`` values carry, so the age
    sweep never trips on a legacy timestamp shape.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _sweep_credential_age(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    now: datetime | None = None,
) -> None:
    """Lazy age-backstop sweep, run at the start of every credential read.

    ``now - last_seen_at > 8h`` and state not already ``dead`` -> persist
    ``stale`` (advisory; the row stays listed so the LLM re-probes it, and the
    runtime identity injector still REPLAYS it with a warning — only a
    proven-dead probe verdict blocks replay).
    ``> 5 days`` -> hard-DELETE the row. Rows with a NULL/unparseable
    ``last_seen_at`` (predate the column) are left untouched — no backstop
    rather than a false purge. Operates on the caller's (thread-local)
    connection so it commits with the surrounding read.
    """
    now_dt = now or datetime.now(timezone.utc)
    rows = connection.execute(
        "SELECT id, last_seen_at, state FROM engagement_credentials "
        "WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    to_delete: list[tuple[int]] = []
    to_stale: list[tuple[int]] = []
    for row in rows:
        seen = _parse_cred_timestamp(row["last_seen_at"])
        if seen is None:
            continue
        age = (now_dt - seen).total_seconds()
        if age > _CRED_HARD_DELETE_TTL_SECONDS:
            to_delete.append((row["id"],))
        elif (
            age > _CRED_STALE_TTL_SECONDS
            and row["state"] != "dead"
            and row["state"] != "stale"
        ):
            to_stale.append((row["id"],))
    if to_delete:
        connection.executemany(
            "DELETE FROM engagement_credentials WHERE id = ?", to_delete
        )
    if to_stale:
        connection.executemany(
            "UPDATE engagement_credentials SET state = 'stale' WHERE id = ?", to_stale
        )


def touch_credential_use(
    engagement_id: int,
    identity_name: str,
    *,
    now: datetime | None = None,
) -> None:
    """Refresh ``last_seen_at`` because the identity was USED, not written.

    The age backstop (:func:`_sweep_credential_age`) measures ``now -
    last_seen_at``, but before this existed only a WRITE (capture / import /
    live probe) ever moved ``last_seen_at``. An identity that was being
    replayed on every request therefore still flipped to ``stale`` at exactly
    ``_CRED_STALE_TTL_SECONDS`` — the backstop fired against actively-used
    sessions, which is the opposite of what an age backstop is for.

    A resolve-for-replay is a use, so it refreshes the clock. ``updated_at`` is
    deliberately NOT moved: it means "material last changed", and a use changes
    nothing. ``dead`` rows are never touched — a proven-dead session must age
    out to the hard-delete backstop rather than be kept alive by reads.
    """
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_connection() as connection:
        connection.execute(
            "UPDATE engagement_credentials SET last_seen_at = ? "
            "WHERE engagement_id = ? AND identity_name = ? AND state != 'dead'",
            (stamp, engagement_id, identity_name),
        )


def _credential_row_to_material(row: sqlite3.Row) -> dict[str, Any]:
    """Project a credentials row to the identity-material dict consumers expect.

    The shape mirrors the legacy per-identity auth.json material (cookies /
    headers / tokens / host_cookies / mode / state / auth_context / …) so the
    runtime materializer and CLI are source-agnostic. ``raw_json`` is merged
    UNDER the typed columns so any verbatim-preserved extras (custom fields)
    survive, while the typed columns remain authoritative.
    """

    def _loads(value: str, fallback: Any) -> Any:
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return fallback

    raw = _loads(row["raw_json"], {})
    material: dict[str, Any] = raw if isinstance(raw, dict) else {}
    material.update(
        {
            "identity_name": row["identity_name"],
            "principal_id": row["principal_id"],
            "mfa_factor": row["mfa_factor"],
            "mode": row["mode"],
            "state": row["state"],
            "use_for_requests": bool(row["use_for_requests"]),
            "auth_context": row["auth_context"],
            "is_active": bool(row["is_active"]),
            "cookies": _loads(row["cookies_json"], {}),
            "headers": _loads(row["headers_json"], {}),
            "tokens": _loads(row["tokens_json"], {}),
            "host_cookies": _loads(row["host_cookies_json"], []),
            "notes": row["notes"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "last_seen_at": row["last_seen_at"],
            "liveness_verdict": row["liveness_verdict"],
            "last_probed_at": row["last_probed_at"],
            "updated_at": row["updated_at"],
        }
    )
    return material


def _material_matches_host(material: dict[str, Any], host: str) -> bool:
    """True if the identity is USABLE at ``host`` — mirrors the replay injection
    path (kali ``_identity_header_pairs``) so ``--host`` lists exactly the
    sessions replay would actually carry there:

    * a ``host_cookies`` bucket matches when its host equals ``host`` OR ``host``
      is a subdomain of it (a parent-domain cookie is sent to the subdomain);
    * ``headers`` or a bearer token (``token``/``bearer``/``tokens[...]``) are
      injected on ANY host — so a bearer/JWT identity (no cookie bucket) is usable
      everywhere, and must list for every host;
    * flat ``cookies`` are a fallback ONLY for identities that carry no per-host
      buckets at all (manual/legacy) — the same bleed-avoidance rule replay uses.
    """
    target = (host or "").strip().rstrip(".").lower()
    if not target:
        return True
    raw = material.get("host_cookies")
    buckets = raw if isinstance(raw, list) else []
    usable_bucket_exists = False
    for bucket in buckets:
        if not isinstance(bucket, dict):
            continue
        bhost = str(bucket.get("host", "")).strip().rstrip(".").lower()
        cookies = bucket.get("cookies")
        if not bhost or not isinstance(cookies, dict) or not cookies:
            continue
        usable_bucket_exists = True
        if target == bhost or target.endswith("." + bhost):
            return True
    # Host-agnostic material: replay injects these on any request host.
    headers = material.get("headers")
    if isinstance(headers, dict) and any(str(k).strip() for k in headers):
        return True
    for key in ("token", "bearer"):
        if isinstance(material.get(key), str) and material[key].strip():
            return True
    tokens = material.get("tokens")
    if isinstance(tokens, dict) and any(
        isinstance(v, str) and v.strip() for v in tokens.values()
    ):
        return True
    # Flat-cookie fallback: only when NO per-host buckets exist (else bleed).
    if not usable_bucket_exists:
        cookies = material.get("cookies")
        if isinstance(cookies, dict) and any(str(v).strip() for v in cookies.values()):
            return True
    return False


def list_credentials(
    engagement_id: int,
    *,
    host: str | None = None,
    include_dead: bool = False,
) -> list[dict[str, Any]]:
    """List an engagement's credential identities, freshest first.

    Applies the lazy age-backstop sweep first (stale-flag / hard-delete). Rows in
    state ``dead`` are excluded unless ``include_dead``; ``stale`` rows are NOT
    excluded (the LLM must re-probe them). When ``host`` is given, only sessions
    with a matching host_cookies bucket are returned (subdomain-aware). Ordered by
    ``last_seen_at`` DESC (falling back to ``updated_at``), then identity_name.
    """
    with get_connection() as connection:
        _sweep_credential_age(connection, engagement_id)
        rows = connection.execute(
            "SELECT * FROM engagement_credentials WHERE engagement_id = ? "
            "ORDER BY COALESCE(last_seen_at, updated_at) DESC, identity_name",
            (engagement_id,),
        ).fetchall()
    materials = [_credential_row_to_material(row) for row in rows]
    for material in materials:
        material["liveness_observations"] = list_credential_liveness(
            engagement_id, str(material["identity_name"])
        )
    if not include_dead:
        materials = [m for m in materials if m.get("state") != "dead"]
    if host:
        materials = [m for m in materials if _material_matches_host(m, host)]
    return materials


def get_credential(
    engagement_id: int, identity_name: str, *, touch: bool = False
) -> dict[str, Any] | None:
    """Read one identity's material.

    ``touch=True`` marks this read as a USE and refreshes ``last_seen_at`` (see
    :func:`touch_credential_use`) so an actively-replayed identity cannot age
    into ``stale``. The age sweep still runs FIRST, against the previous use
    time, so a genuine 8h gap is still flagged for re-probing before the new
    use resets the clock. Plain reads (listing, display) leave the clock alone.
    """
    with get_connection() as connection:
        _sweep_credential_age(connection, engagement_id)
        row = connection.execute(
            "SELECT * FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (engagement_id, identity_name),
        ).fetchone()
    if not row:
        return None
    if touch:
        touch_credential_use(engagement_id, identity_name)
        with get_connection() as connection:
            refreshed = connection.execute(
                "SELECT * FROM engagement_credentials "
                "WHERE engagement_id = ? AND identity_name = ?",
                (engagement_id, identity_name),
            ).fetchone()
        row = refreshed or row
    material = _credential_row_to_material(row)
    material["liveness_observations"] = list_credential_liveness(
        engagement_id, identity_name
    )
    return material


def get_active_credential(
    engagement_id: int, *, touch: bool = False
) -> dict[str, Any] | None:
    """Return the active identity's material, or the first USABLE one if none is
    explicitly active, or None when the engagement has no live credentials.

    The no-active fallback is restricted to ``use_for_requests`` rows so an
    unreviewed opt-in identity (e.g. a discovered secret minted
    ``use_for_requests=0``) is never replayed by default; an explicitly activated
    row (``is_active=1``) is always returned regardless of that flag.

    ``touch=True`` records the read as a USE (see :func:`get_credential`)."""
    with get_connection() as connection:
        _sweep_credential_age(connection, engagement_id)
        row = connection.execute(
            "SELECT * FROM engagement_credentials "
            "WHERE engagement_id = ? AND state != 'dead' "
            "AND (is_active = 1 OR use_for_requests = 1) "
            "ORDER BY is_active DESC, identity_name LIMIT 1",
            (engagement_id,),
        ).fetchone()
    if row is None:
        return None
    if touch:
        touch_credential_use(engagement_id, str(row["identity_name"]))
        with get_connection() as connection:
            refreshed = connection.execute(
                "SELECT * FROM engagement_credentials WHERE id = ?", (row["id"],)
            ).fetchone()
        row = refreshed or row
    return _credential_row_to_material(row)


def upsert_credential(
    engagement_id: int,
    identity_name: str,
    *,
    principal_id: str,
    mfa_factor: str,
    mode: str,
    state: str,
    use_for_requests: bool,
    auth_context: str,
    cookies: dict[str, Any],
    headers: dict[str, Any],
    tokens: dict[str, Any],
    host_cookies: list[Any],
    raw: dict[str, Any],
    notes: str,
    expires_at: str | None,
    make_active: bool,
) -> dict[str, Any]:
    """Insert or replace one identity's credential material.

    UNIQUE(engagement_id, identity_name) makes this idempotent. When
    ``make_active`` is set, all other identities for the engagement are
    deactivated so at most one row is active.

    ``created_at`` is set to ``now`` on INSERT and PRESERVED on CONFLICT (a
    refresh of the same derived identity does not reset its first-capture time);
    ``last_seen_at`` is set to ``now`` on both paths and drives the age backstop.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_connection() as connection:
        if make_active:
            connection.execute(
                "UPDATE engagement_credentials SET is_active = 0 WHERE engagement_id = ?",
                (engagement_id,),
            )
        connection.execute(
            """
            INSERT INTO engagement_credentials (
                engagement_id, identity_name, principal_id, mfa_factor, mode, state, use_for_requests,
                auth_context, is_active, cookies_json, headers_json, tokens_json,
                host_cookies_json, raw_json, notes, expires_at,
                created_at, last_seen_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, identity_name) DO UPDATE SET
                principal_id = excluded.principal_id,
                mfa_factor = excluded.mfa_factor,
                mode = excluded.mode,
                state = excluded.state,
                use_for_requests = excluded.use_for_requests,
                auth_context = excluded.auth_context,
                is_active = CASE WHEN ? THEN 1 ELSE engagement_credentials.is_active END,
                cookies_json = excluded.cookies_json,
                headers_json = excluded.headers_json,
                tokens_json = excluded.tokens_json,
                host_cookies_json = excluded.host_cookies_json,
                raw_json = excluded.raw_json,
                notes = excluded.notes,
                expires_at = excluded.expires_at,
                last_seen_at = excluded.last_seen_at,
                updated_at = excluded.updated_at
            """,
            (
                engagement_id,
                identity_name,
                principal_id,
                mfa_factor,
                mode,
                state,
                1 if use_for_requests else 0,
                auth_context,
                1 if make_active else 0,
                json.dumps(cookies),
                json.dumps(headers),
                json.dumps(tokens),
                json.dumps(host_cookies),
                json.dumps(raw),
                notes,
                expires_at,
                now,
                now,
                now,
                1 if make_active else 0,
            ),
        )
    result = get_credential(engagement_id, identity_name)
    assert result is not None  # just written
    return result


def set_credential_alias(
    engagement_id: int, alias: str, principal_id: str, scope_key: str = ""
) -> None:
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO engagement_credential_aliases "
            "(engagement_id, alias, principal_id, scope_key, updated_at) "
            "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(engagement_id, alias, scope_key) DO UPDATE SET "
            "principal_id=excluded.principal_id, updated_at=excluded.updated_at",
            (engagement_id, alias.strip(), principal_id.strip(), scope_key.strip()),
        )


def record_credential_liveness(
    engagement_id: int,
    identity_name: str,
    *,
    scope_key: str,
    verdict: str,
    observed_at: str,
    ttl_seconds: int,
    source: str,
    reason: str = "",
) -> dict[str, Any] | None:
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        observed = datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    observed = observed.astimezone(timezone.utc)
    observed_at = observed.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (observed + timedelta(seconds=max(int(ttl_seconds), 1))).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    with get_connection() as connection:
        exists = connection.execute(
            "SELECT 1 FROM engagement_credentials WHERE engagement_id=? AND identity_name=?",
            (engagement_id, identity_name),
        ).fetchone()
        if not exists:
            return None
        connection.execute(
            "INSERT INTO engagement_credential_liveness "
            "(engagement_id, identity_name, scope_key, verdict, observed_at, expires_at, source, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(engagement_id, identity_name, scope_key) DO UPDATE SET "
            "verdict=excluded.verdict, observed_at=excluded.observed_at, "
            "expires_at=excluded.expires_at, source=excluded.source, reason=excluded.reason "
            "WHERE excluded.observed_at >= engagement_credential_liveness.observed_at",
            (
                engagement_id,
                identity_name,
                scope_key.strip(),
                verdict,
                observed_at,
                expires_at,
                source,
                reason,
            ),
        )
    return get_credential(engagement_id, identity_name)


def list_credential_liveness(
    engagement_id: int, identity_name: str
) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT scope_key, verdict, observed_at, expires_at, source, reason "
            "FROM engagement_credential_liveness WHERE engagement_id=? AND identity_name=? "
            "ORDER BY observed_at DESC, scope_key",
            (engagement_id, identity_name),
        ).fetchall()
    now = datetime.now(timezone.utc)
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            expiry = datetime.fromisoformat(
                str(row["expires_at"]).replace("Z", "+00:00")
            )
        except ValueError:
            expiry = now
        item["fresh"] = expiry > now
        result.append(item)
    return result


def resolve_credential_alias(
    engagement_id: int, alias: str, scope_key: str, *, touch: bool = True
) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_connection() as connection:
        row = connection.execute(
            "SELECT c.identity_name FROM engagement_credential_aliases a "
            "JOIN engagement_credentials c ON c.engagement_id=a.engagement_id "
            "AND c.principal_id=a.principal_id "
            "JOIN engagement_credential_liveness l ON l.engagement_id=c.engagement_id "
            "AND l.identity_name=c.identity_name AND l.scope_key=a.scope_key "
            "WHERE a.engagement_id=? AND a.alias=? AND a.scope_key=? "
            "AND c.state != 'dead' AND l.verdict='live' AND l.expires_at>? "
            "ORDER BY l.observed_at DESC, COALESCE(c.last_seen_at,c.updated_at) DESC LIMIT 1",
            (engagement_id, alias.strip(), scope_key.strip(), now),
        ).fetchone()
    # An alias resolve is normally a resolve-for-replay, so it counts as a USE.
    # ``touch=False`` is for the read-only inspection path, which must not refresh
    # the clock the stale flag and the purge backstop key off.
    return (
        get_credential(engagement_id, row["identity_name"], touch=touch)
        if row
        else None
    )


def set_liveness(
    engagement_id: int,
    identity_name: str,
    verdict: str,
    probed_at: str | None,
) -> dict[str, Any] | None:
    """Record a liveness-probe result for one identity.

    Sets ``liveness_verdict`` and ``last_probed_at``, and reconciles ``state``:
    ``verdict == 'dead'`` -> ``state='dead'`` (only a proven-dead probe kills a
    session; a 401/403 on a scanned endpoint is an authz finding, not a dead
    session); ``verdict == 'live'`` -> ``state='available'`` (a live probe clears
    an age-backstop ``stale`` mark, and revives a session probed with
    ``--include-dead``); ``unknown`` leaves ``state`` untouched (never a false
    verdict). Returns the updated material, or None when no such identity exists.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_connection() as connection:
        if verdict == "dead":
            connection.execute(
                "UPDATE engagement_credentials "
                "SET liveness_verdict = ?, last_probed_at = ?, state = 'dead', "
                "updated_at = ? "
                "WHERE engagement_id = ? AND identity_name = ?",
                (verdict, probed_at, now, engagement_id, identity_name),
            )
        elif verdict == "live":
            connection.execute(
                "UPDATE engagement_credentials "
                "SET liveness_verdict = ?, last_probed_at = ?, state = 'available', "
                "last_seen_at = ?, updated_at = ? "
                "WHERE engagement_id = ? AND identity_name = ?",
                (verdict, probed_at, now, now, engagement_id, identity_name),
            )
        else:
            connection.execute(
                "UPDATE engagement_credentials "
                "SET liveness_verdict = ?, last_probed_at = ?, updated_at = ? "
                "WHERE engagement_id = ? AND identity_name = ?",
                (verdict, probed_at, now, engagement_id, identity_name),
            )
    return get_credential(engagement_id, identity_name)


def set_active_identity(engagement_id: int, identity_name: str) -> bool:
    """Mark one identity active (others inactive). Returns False if absent."""
    with get_connection() as connection:
        exists = connection.execute(
            "SELECT 1 FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (engagement_id, identity_name),
        ).fetchone()
        if exists is None:
            return False
        connection.execute(
            "UPDATE engagement_credentials SET is_active = 0 WHERE engagement_id = ?",
            (engagement_id,),
        )
        connection.execute(
            "UPDATE engagement_credentials SET is_active = 1 "
            "WHERE engagement_id = ? AND identity_name = ?",
            (engagement_id, identity_name),
        )
    return True


def quarantine_credential(
    engagement_id: int, identity_name: str
) -> dict[str, Any] | None:
    """Disable replay for one identity without deleting its evidence material."""
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE engagement_credentials "
            "SET use_for_requests = 0, is_active = 0, updated_at = ? "
            "WHERE engagement_id = ? AND identity_name = ?",
            (
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                engagement_id,
                identity_name,
            ),
        )
    if cursor.rowcount == 0:
        return None
    return get_credential(engagement_id, identity_name)


def delete_credential(engagement_id: int, identity_name: str) -> None:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (engagement_id, identity_name),
        )


def delete_all_credentials(engagement_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM engagement_credentials WHERE engagement_id = ?",
            (engagement_id,),
        )


def delete_engagement(engagement_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        )


def delete_engagement_session(engagement_id: int, session_id: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM engagement_sessions
            WHERE engagement_id = ? AND session_id = ?
            """,
            (engagement_id, session_id),
        )


def update_engagement_status(engagement_id: int, status: str) -> Engagement:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE engagements
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, engagement_id),
        )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, engagement_type, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        ).fetchone()
        assert row is not None
        return Engagement.from_row(row)


def create_event(
    engagement_id: int,
    event_type: str,
    phase: str,
    task_name: str,
    agent_name: str,
    summary: str,
) -> Event:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (engagement_id, event_type, phase, task_name, agent_name, summary)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, event_type, phase, task_name, agent_name, summary),
        )
        row = connection.execute(
            """
            SELECT id, engagement_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return Event.from_row(row)


def list_events_for_engagement(engagement_id: int) -> list[Event]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, engagement_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE engagement_id = ?
            ORDER BY id ASC
            """,
            (engagement_id,),
        ).fetchall()
    return [Event.from_row(row) for row in rows]


def get_latest_event_for_engagement(engagement_id: int, prefix: str) -> Event | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, engagement_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE engagement_id = ? AND event_type LIKE ?
            ORDER BY created_at DESC, id DESC
            LIMIT 1
            """,
            (engagement_id, f"{prefix}%"),
        ).fetchone()
    return Event.from_row(row) if row else None


def upsert_engagement_session(
    engagement_id: int,
    session_id: str,
    *,
    session_path: str,
    status: str,
    merge_state: str,
    assigned_targets_json: str,
    merged_at: str | None,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO engagement_sessions (
                engagement_id, session_id, session_path, status, merge_state, assigned_targets_json, merged_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, session_id) DO UPDATE SET
                session_path = excluded.session_path,
                status = excluded.status,
                merge_state = excluded.merge_state,
                assigned_targets_json = excluded.assigned_targets_json,
                merged_at = excluded.merged_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                engagement_id,
                session_id,
                session_path,
                status,
                merge_state,
                assigned_targets_json,
                merged_at,
            ),
        )


def list_engagement_sessions_for_engagement(
    engagement_id: int,
) -> list[EngagementSession]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, engagement_id, session_id, session_path, status, merge_state, assigned_targets_json, created_at, updated_at, merged_at
            FROM engagement_sessions
            WHERE engagement_id = ?
            ORDER BY id ASC
            """,
            (engagement_id,),
        ).fetchall()
    return [EngagementSession.from_row(row) for row in rows]
