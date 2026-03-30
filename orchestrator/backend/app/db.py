from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings
from .models.event import Event
from .models.engagement_session import EngagementSession
from .models.engagement import Engagement


def _table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    return {row[1] for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()}


def _database_requires_reset(db_path: Path) -> bool:
    if not db_path.exists():
        return False

    try:
        with sqlite3.connect(str(db_path)) as connection:
            tables = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            }

            if {"projects", "runs", "users"} & tables:
                return True

            engagement_scoped_tables = {"engagement_sessions", "events"}
            engagement_scoped_tables.update(
                table_name for table_name in tables if table_name.startswith("assessment_")
            )
            for table_name in engagement_scoped_tables:
                if table_name not in tables:
                    continue
                columns = _table_columns(connection, table_name)
                if "run_id" in columns or "engagement_id" not in columns:
                    return True
    except sqlite3.DatabaseError:
        return True

    return False


def _reset_incompatible_database(db_path: Path) -> None:
    if not _database_requires_reset(db_path):
        return

    for suffix in ("", "-shm", "-wal"):
        candidate = Path(f"{db_path}{suffix}")
        if candidate.exists():
            candidate.unlink()


def database_path() -> Path:
    return settings.data_dir / "orchestrator.sqlite3"


def init_db() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db_path = database_path()
    _reset_incompatible_database(db_path)
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
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
                assigned_findings_json TEXT NOT NULL DEFAULT '[]',
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
                secret_locator TEXT NOT NULL DEFAULT '',
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
        finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(assessment_findings)").fetchall()}
        finding_column_defaults = {
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
        connection.commit()


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    init_db()
    db_path = database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


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
            """,
            (target, status, engagement_root, engagement_id),
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
    assigned_findings_json: str,
    merged_at: str | None,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO engagement_sessions (
                engagement_id, session_id, session_path, status, merge_state, assigned_findings_json, merged_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, session_id) DO UPDATE SET
                session_path = excluded.session_path,
                status = excluded.status,
                merge_state = excluded.merge_state,
                assigned_findings_json = excluded.assigned_findings_json,
                merged_at = excluded.merged_at,
                updated_at = CURRENT_TIMESTAMP
            """,
            (engagement_id, session_id, session_path, status, merge_state, assigned_findings_json, merged_at),
        )


def list_engagement_sessions_for_engagement(engagement_id: int) -> list[EngagementSession]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, engagement_id, session_id, session_path, status, merge_state, assigned_findings_json, created_at, updated_at, merged_at
            FROM engagement_sessions
            WHERE engagement_id = ?
            ORDER BY id ASC
            """,
            (engagement_id,),
        ).fetchall()
    return [EngagementSession.from_row(row) for row in rows]
