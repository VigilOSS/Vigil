from __future__ import annotations

import gc
import json
import re
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
_LEGACY_FINDING_PREFIX = "FINDING" + "-"
_LEGACY_FINDING_REF_RE = re.compile(rf"\b{_LEGACY_FINDING_PREFIX}([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{{3}}[A-Z]?)\b")
_COVERAGE_STATUS_RANK = {
    "pending": 0,
    "queued": 1,
    "deferred": 2,
    "covered": 3,
    "not_applicable": 3,
    "blocked": 4,
}


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}


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


def _refresh_service_coverage_status(connection: sqlite3.Connection, engagement_id: int, service_id: int) -> None:
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
    elif any(status_value in {"covered", "not_applicable", "deferred"} for status_value in statuses):
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
            (engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
        ).fetchall()
        if len(rows) < 2:
            continue
        keeper_id = int(rows[0][0])
        merged_status = _merge_coverage_status([str(row[1] or "pending") for row in rows])
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
            connection.execute("DELETE FROM assessment_coverage_items WHERE id = ?", (duplicate_id,))
        if service_id is not None:
            affected_services.add((int(engagement_id), int(service_id)))
    for engagement_id, service_id in affected_services:
        _refresh_service_coverage_status(connection, engagement_id, service_id)


def _strip_legacy_finding_prefix(value: str) -> str:
    if value.startswith(_LEGACY_FINDING_PREFIX):
        return value[len(_LEGACY_FINDING_PREFIX) :]
    return value


def _normalize_legacy_finding_refs(value: str, slug_map: dict[tuple[int, str], str], engagement_id: int | None) -> str:
    def replace(match: re.Match[str]) -> str:
        old_slug = match.group(0)
        if engagement_id is not None:
            mapped_slug = slug_map.get((engagement_id, old_slug))
            if mapped_slug is not None:
                return mapped_slug
        return match.group(1)

    return _LEGACY_FINDING_REF_RE.sub(replace, value)


def _strip_legacy_finding_prefixes(value, slug_map: dict[tuple[int, str], str] | None = None, engagement_id: int | None = None):
    if isinstance(value, str):
        normalized = _normalize_legacy_finding_refs(value, slug_map or {}, engagement_id)
        return normalized, normalized != value
    if isinstance(value, list):
        changed = False
        normalized_items = []
        for item in value:
            normalized_item, item_changed = _strip_legacy_finding_prefixes(item, slug_map, engagement_id)
            normalized_items.append(normalized_item)
            changed = changed or item_changed
        return normalized_items, changed
    if isinstance(value, dict):
        changed = False
        normalized_dict = {}
        for key, item in value.items():
            normalized_item, item_changed = _strip_legacy_finding_prefixes(item, slug_map, engagement_id)
            normalized_dict[key] = normalized_item
            changed = changed or item_changed
        return normalized_dict, changed
    return value, False


def _next_legacy_collision_slug(connection: sqlite3.Connection, engagement_id: int, preferred_slug: str, row_id: int) -> str:
    candidate = f"{preferred_slug}-legacy-{row_id}"
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
        (engagement_id, candidate),
    ).fetchone():
        candidate = f"{preferred_slug}-legacy-{row_id}-{suffix}"
        suffix += 1
    return candidate


def _migrate_legacy_finding_slugs(connection: sqlite3.Connection) -> dict[tuple[int, str], str]:
    if not {"id", "engagement_id", "slug"}.issubset(_table_columns(connection, "assessment_findings")):
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
            normalized = _next_legacy_collision_slug(connection, int(engagement_id), normalized, int(row_id))
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
    select_columns = "id, engagement_id, " + column_name if "engagement_id" in columns else "id, " + column_name
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
        normalized = slug_map.get((engagement_id, value), _strip_legacy_finding_prefix(value)) if engagement_id is not None else _strip_legacy_finding_prefix(value)
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
    select_columns = "id, engagement_id, " + column_name if "engagement_id" in columns else "id, " + column_name
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
        normalized, changed = _strip_legacy_finding_prefixes(payload, slug_map, engagement_id)
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
        _migrate_legacy_finding_prefix_in_text_column(connection, table_name, column_name, slug_map)

    for table_name, column_name in (
        ("assessment_findings", "details_json"),
        ("assessment_findings", "provenance_json"),
        ("engagement_sessions", "assigned_targets_json"),
        ("assessment_finding_transitions", "metadata_json"),
    ):
        _migrate_legacy_finding_prefix_in_json_column(connection, table_name, column_name, slug_map)


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
    "assessment_artifacts",
    "assessment_jobs",
    "code_repos",
    "code_modules",
    "code_files",
    "code_analysis_queue",
    "code_analysis_results",
    "code_analysis_triggers",
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
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, surface_type, target_descriptor),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )
        # Additive migration for existing deployments that predate the
        # ``partially-covered`` lifecycle state and its companion
        # ``followup_condition`` column.
        surface_columns = _table_columns(connection, "assessment_surfaces")
        if surface_columns and "followup_condition" not in surface_columns:
            connection.execute(
                "ALTER TABLE assessment_surfaces ADD COLUMN followup_condition TEXT NOT NULL DEFAULT ''"
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
                evidence_type TEXT,
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
        # assessment_command_runs is the source of truth for every Kali
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
                status TEXT NOT NULL DEFAULT 'completed',
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
                technique TEXT,
                intent TEXT,
                probe_kind TEXT,
                destructive INTEGER,
                stdout_path TEXT,
                stderr_path TEXT,
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
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN run_uuid TEXT")
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
            connection.execute(
                "ALTER TABLE assessment_command_runs ADD COLUMN intent TEXT"
            )
        if cmdrun_columns and "probe_kind" not in cmdrun_columns:
            connection.execute(
                "ALTER TABLE assessment_command_runs ADD COLUMN probe_kind TEXT"
            )
        if cmdrun_columns and "destructive" not in cmdrun_columns:
            connection.execute(
                "ALTER TABLE assessment_command_runs ADD COLUMN destructive INTEGER"
            )
        # Wave-1 cutover migrations: pre-exec lifecycle, output spill paths,
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
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN stdout_path TEXT")
        if cmdrun_columns and "stderr_path" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN stderr_path TEXT")
        if cmdrun_columns and "peak_rss_bytes" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN peak_rss_bytes INTEGER")
        if cmdrun_columns and "cpu_user_seconds" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN cpu_user_seconds REAL")
        if cmdrun_columns and "cpu_system_seconds" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN cpu_system_seconds REAL")
        if cmdrun_columns and "working_dir" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN working_dir TEXT")
        if cmdrun_columns and "scope_version" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN scope_version TEXT")
        if cmdrun_columns and "auth_context" not in cmdrun_columns:
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN auth_context TEXT")
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
            connection.execute("ALTER TABLE assessment_command_runs ADD COLUMN superseded_by_id INTEGER")
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
        # If the FTS schema predates tool_bin, drop it so CREATE VIRTUAL
        # TABLE below rebuilds with the new column set. Old triggers are
        # re-created as CREATE TRIGGER IF NOT EXISTS — but they reference
        # the old fts table, so force a clean slate on any shape mismatch.
        fts_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_command_runs_fts)").fetchall()
        }
        existing_cmdrun_count = connection.execute("SELECT COUNT(*) FROM assessment_command_runs").fetchone()[0]
        rebuild_command_runs_fts = not fts_columns and existing_cmdrun_count > 0
        if fts_columns and "tool_bin" not in fts_columns:
            connection.execute("DROP TABLE IF EXISTS assessment_command_runs_fts")
            for trigger in ("assessment_command_runs_ai", "assessment_command_runs_ad", "assessment_command_runs_au"):
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
            for trigger in ("assessment_command_runs_ai", "assessment_command_runs_ad", "assessment_command_runs_au"):
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
        artifact_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_artifacts)").fetchall()
        }
        if "scratch" not in artifact_columns:
            connection.execute(
                "ALTER TABLE assessment_artifacts ADD COLUMN scratch INTEGER NOT NULL DEFAULT 0"
            )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_assessment_artifacts_scratch "
            "ON assessment_artifacts(engagement_id, scratch)"
        )
        artifact_fts_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(assessment_artifacts_fts)").fetchall()
        }
        existing_artifact_count = connection.execute("SELECT COUNT(*) FROM assessment_artifacts").fetchone()[0]
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
        if artifact_fts_columns and not expected_artifact_fts_columns.issubset(artifact_fts_columns):
            connection.execute("DROP TABLE IF EXISTS assessment_artifacts_fts")
            for trigger in ("assessment_artifacts_ai", "assessment_artifacts_ad", "assessment_artifacts_au"):
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
        # assessment_jobs tracks long-running dtach-supervised workers spawned
        # by `aith assess kali job start`. parent_command_run_id links the
        # synchronous audit row that initiated the job; SET NULL on cascade
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
                skip_reason TEXT NOT NULL DEFAULT '',
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
            # C44: evidence_type categorizes confirmation mode for findings.
            # Nullable; no backfill (existing rows stay NULL). New findings
            # may carry: network-confirmed | code-inferred | theoretical |
            # informational. Report-writer treats NULL as 'unknown' and falls
            # back to its existing details-content inspection.
            "evidence_type": "TEXT",
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
            # C50: separate "analyzed and found clean" from "deliberately
            # skipped" so code-coverage can distinguish 100% completion from
            # silent deferral. Operators tag skips with a structured reason
            # (test-fixture, generated-code, minified, out-of-scope-language).
            "skip_reason": "TEXT NOT NULL DEFAULT ''",
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

        # ── Intel Tables ───────────────────────────────────────────
        # Per-engagement intel replaces the legacy `intel.md` scratch pad.
        # Every table is engagement-scoped, carries UNIQUE(engagement_id,
        # <natural key>), created_at/updated_at, provenance_json, and CASCADE
        # on engagement delete. Naming mirrors the existing `assessment_*`
        # convention so helpers/FTS triggers/cascade tests can reuse the
        # pattern at db.py:668-838.
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
                superseded_by_id INTEGER REFERENCES intel_notes(id) ON DELETE SET NULL,
                superseded_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, title),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
        )

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
                scope_host TEXT,
                dispatched_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL,
                model TEXT,
                reasoning TEXT,
                requested_model TEXT,
                actual_model TEXT,
                requested_reasoning TEXT,
                actual_reasoning TEXT,
                dispatch_mode TEXT,
                finding_slugs_json TEXT,
                skills TEXT,
                tier TEXT,
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
            connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN requested_model TEXT")
            connection.execute("UPDATE assessment_dispatches SET requested_model = model WHERE requested_model IS NULL")
        if dispatch_columns and "actual_model" not in dispatch_columns:
            connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN actual_model TEXT")
        if dispatch_columns and "requested_reasoning" not in dispatch_columns:
            connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN requested_reasoning TEXT")
            connection.execute("UPDATE assessment_dispatches SET requested_reasoning = reasoning WHERE requested_reasoning IS NULL")
        if dispatch_columns and "actual_reasoning" not in dispatch_columns:
            connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN actual_reasoning TEXT")
        # Blue-engagement tier tag ('L1' | 'L2' | 'L3' | 'L4'). Enforced in
        # the Pydantic layer; stored as free-form TEXT so the enum can evolve
        # without a schema rebuild. Existing rows stay NULL.
        if dispatch_columns and "tier" not in dispatch_columns:
            connection.execute("ALTER TABLE assessment_dispatches ADD COLUMN tier TEXT")
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
            connection.execute("ALTER TABLE assessment_dispatch_handoffs ADD COLUMN last_checkpoint_at TEXT")
            connection.execute(
                "UPDATE assessment_dispatch_handoffs SET last_checkpoint_at = created_at WHERE last_checkpoint_at IS NULL"
            )
        if handoff_columns and "closed_dispatch_status" not in handoff_columns:
            connection.execute("ALTER TABLE assessment_dispatch_handoffs ADD COLUMN closed_dispatch_status TEXT")
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

        # FTS5 virtual tables + rebuild-on-drift guard follow the pattern
        # at db.py:724-801 for assessment_command_runs_fts.
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
            for row in connection.execute("PRAGMA table_info(activity_entries_fts)").fetchall()
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
        if activity_fts_columns and not expected_activity_fts_columns.issubset(activity_fts_columns):
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

        connection.commit()

    _startup_database_fingerprint = _database_fingerprint(db_path)


_READINESS_SUBSYSTEM_TABLES: tuple[tuple[str, frozenset[str]], ...] = (
    ("assessment_schema", frozenset({"engagements", "assessment_dispatches", "assessment_findings"})),
    ("code_analysis_schema", frozenset({"code_repos", "code_files", "code_analysis_queue"})),
)


def database_readiness_flags(connection: sqlite3.Connection) -> dict[str, bool]:
    """Return schema-level readiness for assessment vs code-analysis subsystems.

    These checks confirm ``init_db`` created the durable tables backing each
    API router; they are not HTTP-level router probes.

    Returns keys like ``assessment_schema_ready`` and ``code_analysis_schema_ready``.
    """
    names = {
        str(row[0])
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    flags: dict[str, bool] = {}
    for prefix, required in _READINESS_SUBSYSTEM_TABLES:
        flags[f"{prefix}_ready"] = required.issubset(names)
    return flags


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
                (target, status, engagement_root, engagement_id, target, status, engagement_root),
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
