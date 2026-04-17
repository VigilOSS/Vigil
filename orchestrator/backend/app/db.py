from __future__ import annotations

import gc
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import settings
from .models.event import Event
from .models.engagement_session import EngagementSession
from .models.engagement import Engagement


@dataclass(frozen=True, slots=True)
class DatabaseFingerprint:
    path: Path
    device: int
    inode: int


_startup_database_fingerprint: DatabaseFingerprint | None = None


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}


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
    "assessment_command_runs",
    "code_repos",
    "code_modules",
    "code_files",
    "code_analysis_queue",
    "code_analysis_results",
    "code_analysis_triggers",
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
        with sqlite3.connect(str(db_path)) as connection:
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
                        db_path, f"legacy pre-engagement tables present: {sorted(legacy)}"
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
    return DatabaseFingerprint(path=db_path.resolve(), device=stat_result.st_dev, inode=stat_result.st_ino)


def _require_startup_database_fingerprint() -> DatabaseFingerprint:
    if _startup_database_fingerprint is None:
        raise RuntimeError("Orchestrator database has not been initialized for this process")
    return _startup_database_fingerprint


def _verify_database_fingerprint() -> Path:
    expected = _require_startup_database_fingerprint()
    db_path = database_path()
    if db_path.resolve() != expected.path:
        raise RuntimeError(
            f"Orchestrator database path changed after startup: expected {expected.path}, got {db_path.resolve()}"
        )
    if not db_path.exists():
        raise RuntimeError(f"Orchestrator database file disappeared after startup: {db_path}")
    current = _database_fingerprint(db_path)
    if current.device != expected.device or current.inode != expected.inode:
        raise RuntimeError(
            f"Orchestrator database file changed after startup: expected dev/inode "
            f"{expected.device}/{expected.inode}, got {current.device}/{current.inode}"
        )
    return db_path


def _require_fts5(connection: sqlite3.Connection) -> None:
    row = connection.execute("SELECT sqlite_compileoption_used('ENABLE_FTS5')").fetchone()
    if not row or not row[0]:
        raise RuntimeError(
            "Orchestrator SQLite build lacks FTS5 support, which assessment_command_runs search requires. "
            "Rebuild the interpreter's SQLite with ENABLE_FTS5 or use a Python/SQLite distribution that ships it."
        )


def init_db() -> None:
    global _startup_database_fingerprint

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db_path = database_path()
    _check_database_compatibility(db_path)
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        # WAL mode lets readers (including `sqlite3 .backup` snapshots and the
        # 15-minute backend backup task) run concurrently with writers without
        # taking an exclusive lock. Without this, the rollback-journal default
        # causes backups to collide with active writes and return SQLITE_BUSY.
        connection.execute("PRAGMA journal_mode = WAL")
        _require_fts5(connection)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
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
                result_status TEXT NOT NULL DEFAULT 'tested',
                observed_http_status INTEGER,
                signal_type TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, probe_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE CASCADE,
                FOREIGN KEY(coverage_item_id) REFERENCES assessment_coverage_items(id) ON DELETE SET NULL
            )
            """
        )
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, surface_type, target_descriptor),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
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
                verification_state TEXT NOT NULL DEFAULT 'unreviewed',
                verification_disposition TEXT NOT NULL DEFAULT 'none',
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
                merged_into_finding_id INTEGER,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, slug),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(merged_into_finding_id) REFERENCES assessment_findings(id) ON DELETE SET NULL
            )
            """
        )
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
                from_verification_state TEXT,
                to_verification_state TEXT NOT NULL DEFAULT '',
                from_verification_disposition TEXT,
                to_verification_disposition TEXT NOT NULL DEFAULT '',
                from_severity TEXT,
                to_severity TEXT NOT NULL DEFAULT '',
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE CASCADE
            )
            """
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, credential_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
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
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_blocked_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                technique_key TEXT NOT NULL,
                technique TEXT NOT NULL,
                target_kind TEXT NOT NULL DEFAULT '',
                target_ref TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                retry_state TEXT NOT NULL DEFAULT 'pending',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, technique_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        # assessment_command_runs is the source of truth for every Kali MCP
        # command executed during an engagement. A shadow FTS5 virtual table
        # plus three sync triggers provide keyword search. A later change can
        # add assessment_command_run_chunks (cols: command_run_id, seq,
        # chunk_text, embedding_blob, indexed_at) for embedding search without
        # touching the source rows.
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
                return_code INTEGER,
                timed_out INTEGER NOT NULL DEFAULT 0,
                success INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
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
                indexed_for_embeddings_at TEXT,
                notes TEXT NOT NULL DEFAULT '',
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
        if cmdrun_columns and "tool_bin" not in cmdrun_columns:
            connection.execute(
                "ALTER TABLE assessment_command_runs ADD COLUMN tool_bin TEXT NOT NULL DEFAULT ''"
            )
        if cmdrun_columns and "audit_source" not in cmdrun_columns:
            connection.execute(
                "ALTER TABLE assessment_command_runs ADD COLUMN audit_source TEXT NOT NULL DEFAULT 'header'"
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
        # If the FTS schema predates tool_bin, drop it so CREATE VIRTUAL
        # TABLE below rebuilds with the new column set. Old triggers are
        # re-created as CREATE TRIGGER IF NOT EXISTS — but they reference
        # the old fts table, so force a clean slate on any shape mismatch.
        fts_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_command_runs_fts)").fetchall()
        }
        if fts_columns and "tool_bin" not in fts_columns:
            connection.execute("DROP TABLE IF EXISTS assessment_command_runs_fts")
            for trigger in ("assessment_command_runs_ai", "assessment_command_runs_ad", "assessment_command_runs_au"):
                connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
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
                    stdout_suppression_reason, stderr_suppression_reason, notes
                )
                VALUES (
                    new.id, new.command, new.tool_name, new.tool_bin, new.agent_name, new.phase,
                    new.stdout_preview, new.stderr_preview,
                    new.stdout_suppression_reason, new.stderr_suppression_reason, new.notes
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
                    stdout_suppression_reason, stderr_suppression_reason, notes
                )
                VALUES (
                    'delete', old.id, old.command, old.tool_name, old.tool_bin, old.agent_name, old.phase,
                    old.stdout_preview, old.stderr_preview,
                    old.stdout_suppression_reason, old.stderr_suppression_reason, old.notes
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
                    stdout_suppression_reason, stderr_suppression_reason, notes
                )
                VALUES (
                    'delete', old.id, old.command, old.tool_name, old.tool_bin, old.agent_name, old.phase,
                    old.stdout_preview, old.stderr_preview,
                    old.stdout_suppression_reason, old.stderr_suppression_reason, old.notes
                );
                INSERT INTO assessment_command_runs_fts(
                    rowid, command, tool_name, tool_bin, agent_name, phase,
                    stdout_preview, stderr_preview,
                    stdout_suppression_reason, stderr_suppression_reason, notes
                )
                VALUES (
                    new.id, new.command, new.tool_name, new.tool_bin, new.agent_name, new.phase,
                    new.stdout_preview, new.stderr_preview,
                    new.stdout_suppression_reason, new.stderr_suppression_reason, new.notes
                );
            END
            """
        )
        # ── Code Analysis Tables ──────────────────────────────────
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_repos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_key TEXT NOT NULL,
                name TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT '',
                repo_path TEXT NOT NULL,
                total_files INTEGER NOT NULL DEFAULT 0,
                analyzable_files INTEGER NOT NULL DEFAULT 0,
                total_loc INTEGER NOT NULL DEFAULT 0,
                commit_hash TEXT NOT NULL DEFAULT '',
                branch TEXT NOT NULL DEFAULT '',
                analysis_status TEXT NOT NULL DEFAULT 'ingested',
                threat_model_json TEXT NOT NULL DEFAULT '{}',
                git_churn_json TEXT NOT NULL DEFAULT '{}',
                lsp_config_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                module_key TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                trust_boundary TEXT NOT NULL DEFAULT '',
                file_count INTEGER NOT NULL DEFAULT 0,
                critical_file_count INTEGER NOT NULL DEFAULT 0,
                analysis_status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_id, module_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT '',
                loc INTEGER NOT NULL DEFAULT 0,
                file_hash TEXT NOT NULL DEFAULT '',
                classification TEXT NOT NULL DEFAULT 'unclassified',
                role TEXT NOT NULL DEFAULT '',
                slot_types_json TEXT NOT NULL DEFAULT '[]',
                analysis_priority INTEGER NOT NULL DEFAULT 0,
                analysis_status TEXT NOT NULL DEFAULT 'unclassified',
                analysis_depth TEXT NOT NULL DEFAULT 'none',
                skip_reason TEXT NOT NULL DEFAULT '',
                variant_check_status TEXT NOT NULL DEFAULT 'pending',
                module_id INTEGER,
                git_churn_score INTEGER NOT NULL DEFAULT 0,
                has_past_cve_fix INTEGER NOT NULL DEFAULT 0,
                header_snippet TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_id, file_path),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE,
                FOREIGN KEY(module_id) REFERENCES code_modules(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_analysis_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 50,
                status TEXT NOT NULL DEFAULT 'pending',
                assigned_agent TEXT NOT NULL DEFAULT '',
                disposition TEXT NOT NULL DEFAULT '',
                analysis_notes TEXT NOT NULL DEFAULT '',
                expansion_request_json TEXT NOT NULL DEFAULT '{}',
                batch_theme TEXT NOT NULL DEFAULT '',
                slot_types_json TEXT NOT NULL DEFAULT '[]',
                guidance_hypotheses_json TEXT NOT NULL DEFAULT '[]',
                cwe_coverage_json TEXT NOT NULL DEFAULT '[]',
                cross_file_triggers_json TEXT NOT NULL DEFAULT '[]',
                consumed_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                queue_item_id INTEGER,
                file_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                function_name TEXT NOT NULL DEFAULT '',
                hypothesis TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '',
                disposition TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'medium',
                finding_slug TEXT NOT NULL DEFAULT '',
                cwe_id TEXT NOT NULL DEFAULT '',
                slot_type TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                audit_metadata_json TEXT NOT NULL DEFAULT '{}',
                cwe_coverage_json TEXT NOT NULL DEFAULT '[]',
                cross_file_triggers_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS code_analysis_triggers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_queue_item_id INTEGER,
                source_file_id INTEGER,
                target_file_id INTEGER,
                target_file_path TEXT NOT NULL DEFAULT '',
                vuln_class TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                resolved_queue_item_id INTEGER,
                resolution_note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(source_queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE CASCADE,
                FOREIGN KEY(source_file_id) REFERENCES code_files(id) ON DELETE SET NULL,
                FOREIGN KEY(target_file_id) REFERENCES code_files(id) ON DELETE SET NULL,
                FOREIGN KEY(resolved_queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE SET NULL
            )
            """
        )
        # ── End Code Analysis Tables ──────────────────────────────

        # Migrate secret_locator → secret in assessment_credentials
        cred_columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_credentials)").fetchall()}
        if "secret_locator" in cred_columns and "secret" not in cred_columns:
            connection.execute("ALTER TABLE assessment_credentials RENAME COLUMN secret_locator TO secret")

        session_columns = _table_columns(connection, "engagement_sessions")
        if "assigned_findings_json" in session_columns and "assigned_targets_json" not in session_columns:
            connection.execute("ALTER TABLE engagement_sessions RENAME COLUMN assigned_findings_json TO assigned_targets_json")

        finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_findings)").fetchall()}
        finding_column_defaults = {
            "verification_state": "TEXT NOT NULL DEFAULT 'unreviewed'",
            "verification_disposition": "TEXT NOT NULL DEFAULT 'none'",
            "defect_family": "TEXT NOT NULL DEFAULT ''",
            "root_cause_key": "TEXT NOT NULL DEFAULT ''",
            "auth_context": "TEXT NOT NULL DEFAULT 'anonymous'",
            "canonical_location": "TEXT NOT NULL DEFAULT ''",
            "source_name": "TEXT NOT NULL DEFAULT ''",
            "summary": "TEXT NOT NULL DEFAULT ''",
            "details_json": "TEXT NOT NULL DEFAULT '{}'",
            "provenance_json": "TEXT NOT NULL DEFAULT '{}'",
            "merged_into_finding_id": "INTEGER",
            "last_seen_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        }
        for column_name, definition in finding_column_defaults.items():
            if column_name not in finding_columns:
                connection.execute(f"ALTER TABLE assessment_findings ADD COLUMN {column_name} {definition}")

        if finding_columns:
            connection.execute(
                """
                UPDATE assessment_findings
                SET verification_state = CASE status
                    WHEN 'draft' THEN 'unreviewed'
                    WHEN 'merged' THEN 'unreviewed'
                    WHEN 'false_positive' THEN 'verified'
                    ELSE 'verified'
                END
                WHERE status IN ('draft', 'merged', 'false_positive', 'confirmed', 'exploited', 'reported', 'blocked')
                  AND (verification_state = '' OR verification_state = 'unreviewed')
                """
            )
            connection.execute(
                """
                UPDATE assessment_findings
                SET verification_disposition = CASE status
                    WHEN 'confirmed' THEN 'confirmed'
                    WHEN 'exploited' THEN 'confirmed'
                    WHEN 'reported' THEN 'confirmed'
                    WHEN 'blocked' THEN 'confirmed'
                    WHEN 'false_positive' THEN 'false_positive'
                    ELSE 'none'
                END
                WHERE status IN ('draft', 'merged', 'false_positive', 'confirmed', 'exploited', 'reported', 'blocked')
                  AND (verification_disposition = '' OR verification_disposition = 'none')
                """
            )
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

        # Migrate code_repos: add lsp_config_json if missing
        repo_columns = {row[1] for row in connection.execute("PRAGMA table_info(code_repos)").fetchall()}
        if repo_columns and "lsp_config_json" not in repo_columns:
            connection.execute("ALTER TABLE code_repos ADD COLUMN lsp_config_json TEXT NOT NULL DEFAULT '{}'")

        result_columns = {row[1] for row in connection.execute("PRAGMA table_info(code_analysis_results)").fetchall()}
        if result_columns and "audit_metadata_json" not in result_columns:
            connection.execute("ALTER TABLE code_analysis_results ADD COLUMN audit_metadata_json TEXT NOT NULL DEFAULT '{}'")

        # Migrate code_analysis_queue: add file-direct queue columns
        queue_columns = {row[1] for row in connection.execute("PRAGMA table_info(code_analysis_queue)").fetchall()}
        queue_new_columns = {
            "batch_theme": "TEXT NOT NULL DEFAULT ''",
            "slot_types_json": "TEXT NOT NULL DEFAULT '[]'",
            "guidance_hypotheses_json": "TEXT NOT NULL DEFAULT '[]'",
            "cwe_coverage_json": "TEXT NOT NULL DEFAULT '[]'",
            "cross_file_triggers_json": "TEXT NOT NULL DEFAULT '[]'",
        }
        for col_name, col_def in queue_new_columns.items():
            if queue_columns and col_name not in queue_columns:
                connection.execute(f"ALTER TABLE code_analysis_queue ADD COLUMN {col_name} {col_def}")

        # Migrate code_analysis_results: add cwe_coverage and cross_file_triggers
        if result_columns and "cwe_coverage_json" not in result_columns:
            connection.execute("ALTER TABLE code_analysis_results ADD COLUMN cwe_coverage_json TEXT NOT NULL DEFAULT '[]'")
        if result_columns and "cross_file_triggers_json" not in result_columns:
            connection.execute("ALTER TABLE code_analysis_results ADD COLUMN cross_file_triggers_json TEXT NOT NULL DEFAULT '[]'")

        # Migrate code_files: add structural metadata columns from tree-sitter index
        file_columns = _table_columns(connection, "code_files")
        structural_columns = {
            "total_functions": "INTEGER NOT NULL DEFAULT 0",
            "total_entry_points": "INTEGER NOT NULL DEFAULT 0",
            "total_sinks": "INTEGER NOT NULL DEFAULT 0",
            "total_exports": "INTEGER NOT NULL DEFAULT 0",
        }
        for col_name, col_def in structural_columns.items():
            if file_columns and col_name not in file_columns:
                connection.execute(f"ALTER TABLE code_files ADD COLUMN {col_name} {col_def}")

        connection.commit()

    _startup_database_fingerprint = _database_fingerprint(db_path)


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    db_path = _verify_database_fingerprint()
    connection = sqlite3.connect(str(db_path), cached_statements=0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()
        gc.collect()


def create_engagement(key: str, target: str, status: str, engagement_root: str) -> Engagement:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES (?, ?, ?, ?)
            """,
            (key, target, status, engagement_root),
        )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, created_at, updated_at
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
            SELECT id, key, target, status, engagement_root, created_at, updated_at
            FROM engagements
            WHERE id = ?
            """,
            (engagement_id,),
        ).fetchone()
        assert row is not None
        return Engagement.from_row(row)


def update_engagement_identity(engagement_id: int, target: str, status: str, engagement_root: str) -> Engagement:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE engagements
            SET target = ?, status = ?, engagement_root = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND (target != ? OR status != ? OR engagement_root != ?)
            """,
            (target, status, engagement_root, engagement_id, target, status, engagement_root),
        )
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, created_at, updated_at
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
            SELECT id, key, target, status, engagement_root, created_at, updated_at
            FROM engagements
            ORDER BY id ASC
            """,
        ).fetchall()
    return [Engagement.from_row(row) for row in rows]


def get_engagement_by_id(engagement_id: int) -> Engagement | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, key, target, status, engagement_root, created_at, updated_at
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
            SELECT id, key, target, status, engagement_root, created_at, updated_at
            FROM engagements
            WHERE key = ?
            """,
            (key,),
        ).fetchone()
    return Engagement.from_row(row) if row else None


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
            SELECT id, key, target, status, engagement_root, created_at, updated_at
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
            ORDER BY id DESC
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
            (engagement_id, session_id, session_path, status, merge_state, assigned_targets_json, merged_at),
        )


def list_engagement_sessions_for_engagement(engagement_id: int) -> list[EngagementSession]:
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
