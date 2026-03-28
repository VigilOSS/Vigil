from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import settings
from .models.event import Event
from .models.project import Project
from .models.run import Run
from .models.user import User


class UsernameAlreadyExistsError(Exception):
    pass


def database_path() -> Path:
    return settings.data_dir / "orchestrator.sqlite3"


def init_db() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(database_path())) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(sessions)").fetchall()
        }
        if "expires_at" not in columns:
            connection.execute(
                "ALTER TABLE sessions ADD COLUMN expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                slug TEXT NOT NULL,
                root_path TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, slug),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                engagement_root TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                phase TEXT NOT NULL,
                task_name TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                identity TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'host',
                host TEXT,
                ip_address TEXT,
                hostname TEXT,
                notes TEXT NOT NULL DEFAULT '',
                discovered_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_id, identity),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, endpoint, protocol),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(target_id) REFERENCES assessment_targets(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_request_variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                    run_id,
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
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_request_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                request_variant_id INTEGER NOT NULL,
                observed_url TEXT NOT NULL,
                source_name TEXT NOT NULL DEFAULT '',
                response_status INTEGER,
                evidence_ref TEXT NOT NULL DEFAULT '',
                raw_payload TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_coverage_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                request_variant_id INTEGER,
                service_id INTEGER,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                input_slot TEXT NOT NULL,
                attack_family TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_id, request_variant_id, service_id, auth_context, input_slot, attack_family),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(request_variant_id) REFERENCES assessment_request_variants(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_probe_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, probe_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
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
                run_id INTEGER NOT NULL,
                surface_type TEXT NOT NULL,
                target_descriptor TEXT NOT NULL,
                source_name TEXT NOT NULL DEFAULT '',
                rationale TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'discovered',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_id, surface_type, target_descriptor),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, slug),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(merged_into_finding_id) REFERENCES assessment_findings(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_finding_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                finding_id INTEGER NOT NULL,
                link_kind TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id INTEGER,
                target_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(finding_id) REFERENCES assessment_findings(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                chain_key TEXT NOT NULL,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                severity TEXT NOT NULL DEFAULT 'info',
                narrative TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(run_id, chain_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_attack_chain_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                chain_id INTEGER NOT NULL,
                relation TEXT NOT NULL,
                entity_kind TEXT NOT NULL,
                entity_id INTEGER,
                entity_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(chain_id) REFERENCES assessment_attack_chains(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, credential_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_credential_tests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                credential_id INTEGER NOT NULL,
                service_id INTEGER,
                target_ref TEXT NOT NULL DEFAULT '',
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                outcome TEXT NOT NULL DEFAULT 'untested',
                evidence_ref TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(credential_id) REFERENCES assessment_credentials(id) ON DELETE CASCADE,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_access_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, access_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(credential_id) REFERENCES assessment_credentials(id) ON DELETE SET NULL,
                FOREIGN KEY(service_id) REFERENCES assessment_services(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_pivots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, pivot_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(access_record_id) REFERENCES assessment_access_records(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_tunnels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, tunnel_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                FOREIGN KEY(pivot_id) REFERENCES assessment_pivots(id) ON DELETE SET NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessment_blocked_techniques (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
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
                UNIQUE(run_id, technique_key),
                FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
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


def create_user(username: str, password_hash: str, salt: str) -> User:
    with get_connection() as connection:
        try:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, salt),
            )
        except sqlite3.IntegrityError as exc:
            raise UsernameAlreadyExistsError(username) from exc
        row = connection.execute(
            "SELECT id, username, password_hash, salt, created_at FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return User.from_row(row)


def get_user_by_username(username: str) -> User | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, username, password_hash, salt, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    return User.from_row(row) if row else None


def get_user_by_id(user_id: int) -> User | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, username, password_hash, salt, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    return User.from_row(row) if row else None


def create_session(user_id: int, token: str, expires_at: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (?, ?, ?)
            """,
            (token, user_id, expires_at),
        )


def get_user_by_token(token: str, now_utc: str) -> User | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT u.id, u.username, u.password_hash, u.salt, u.created_at
            FROM sessions AS s
            JOIN users AS u ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (token, now_utc),
        ).fetchone()
    return User.from_row(row) if row else None


def create_project(user_id: int, name: str, slug: str, root_path: str) -> Project:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO projects (user_id, name, slug, root_path)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, name, slug, root_path),
        )
        row = connection.execute(
            """
            SELECT id, user_id, name, slug, root_path, created_at
            FROM projects
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return Project.from_row(row)


def get_project_by_user_and_slug(user_id: int, slug: str) -> Project | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, user_id, name, slug, root_path, created_at
            FROM projects
            WHERE user_id = ? AND slug = ?
            """,
            (user_id, slug),
        ).fetchone()
    return Project.from_row(row) if row else None


def list_projects_for_user(user_id: int) -> list[Project]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, user_id, name, slug, root_path, created_at
            FROM projects
            WHERE user_id = ?
            ORDER BY id ASC
            """,
            (user_id,),
        ).fetchall()
    return [Project.from_row(row) for row in rows]


def get_project_by_id(project_id: int) -> Project | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, user_id, name, slug, root_path, created_at
            FROM projects
            WHERE id = ?
            """,
            (project_id,),
        ).fetchone()
    return Project.from_row(row) if row else None


def delete_project(project_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM projects
            WHERE id = ?
            """,
            (project_id,),
        )


def create_run(project_id: int, target: str, status: str, engagement_root: str) -> Run:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO runs (project_id, target, status, engagement_root)
            VALUES (?, ?, ?, ?)
            """,
            (project_id, target, status, engagement_root),
        )
        row = connection.execute(
            """
            SELECT id, project_id, target, status, engagement_root, created_at, updated_at
            FROM runs
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return Run.from_row(row)


def update_run_engagement_root(run_id: int, engagement_root: str) -> Run:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE runs
            SET engagement_root = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (engagement_root, run_id),
        )
        row = connection.execute(
            """
            SELECT id, project_id, target, status, engagement_root, created_at, updated_at
            FROM runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        return Run.from_row(row)


def list_runs_for_project(project_id: int) -> list[Run]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, project_id, target, status, engagement_root, created_at, updated_at
            FROM runs
            WHERE project_id = ?
            ORDER BY id ASC
            """,
            (project_id,),
        ).fetchall()
    return [Run.from_row(row) for row in rows]


def get_run_by_id(run_id: int) -> Run | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, project_id, target, status, engagement_root, created_at, updated_at
            FROM runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
    return Run.from_row(row) if row else None


def delete_run(run_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            DELETE FROM runs
            WHERE id = ?
            """,
            (run_id,),
        )


def update_run_status(run_id: int, status: str) -> Run:
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE runs
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (status, run_id),
        )
        row = connection.execute(
            """
            SELECT id, project_id, target, status, engagement_root, created_at, updated_at
            FROM runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        return Run.from_row(row)


def create_event(
    run_id: int,
    event_type: str,
    phase: str,
    task_name: str,
    agent_name: str,
    summary: str,
) -> Event:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (run_id, event_type, phase, task_name, agent_name, summary)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, event_type, phase, task_name, agent_name, summary),
        )
        row = connection.execute(
            """
            SELECT id, run_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return Event.from_row(row)


def list_events_for_run(run_id: int) -> list[Event]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, run_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE run_id = ?
            ORDER BY id ASC
            """,
            (run_id,),
        ).fetchall()
    return [Event.from_row(row) for row in rows]


def get_latest_event_for_run(run_id: int, prefix: str) -> Event | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, run_id, event_type, phase, task_name, agent_name, summary, created_at
            FROM events
            WHERE run_id = ? AND event_type LIKE ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (run_id, f"{prefix}%"),
        ).fetchone()
    return Event.from_row(row) if row else None
