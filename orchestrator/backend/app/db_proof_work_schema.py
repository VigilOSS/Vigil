"""Additive proof-work schema: scheduling never replaces finding lifecycle truth."""
from __future__ import annotations

import sqlite3


def create_tables(connection: sqlite3.Connection) -> None:
    statements = (
        '''CREATE TABLE IF NOT EXISTS assessment_proof_work (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES assessment_findings(id),
            binding_digest TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            route TEXT NOT NULL CHECK(route IN ('code', 'web')),
            objective TEXT NOT NULL,
            target_hosts_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'prepared'
                CHECK(status IN ('prepared','claimed','blocked','finished','stale','resolved')),
            approved INTEGER NOT NULL DEFAULT 0,
            owner_dispatch_id INTEGER REFERENCES assessment_dispatches(id),
            blocker TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(engagement_id, finding_id, binding_digest)
        )''',
        '''CREATE TABLE IF NOT EXISTS assessment_proof_work_runs (
            work_id INTEGER NOT NULL REFERENCES assessment_proof_work(id) ON DELETE CASCADE,
            run_id INTEGER NOT NULL REFERENCES assessment_runs(id),
            PRIMARY KEY(work_id, run_id)
        )''',
        '''CREATE TABLE IF NOT EXISTS assessment_proof_work_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            work_id INTEGER NOT NULL REFERENCES assessment_proof_work(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE INDEX IF NOT EXISTS idx_proof_work_engagement
            ON assessment_proof_work(engagement_id, id)''',
    )
    # executescript() commits the caller's transaction. init_db() owns one
    # BEGIN IMMEDIATE across additive schema creation, so execute each complete
    # statement without crossing that serialization boundary.
    for statement in statements:
        connection.execute(statement)
