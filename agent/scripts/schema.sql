-- schema.sql — Case collection pipeline database schema
-- Usage: sqlite3 cases.db < scripts/schema.sql

PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Request identity
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    url_path TEXT NOT NULL,

    -- Structured parameters (pre-extracted by producers)
    query_params TEXT,
    body_params TEXT,
    path_params TEXT,
    cookie_params TEXT,

    -- Request content
    headers TEXT,
    body TEXT,
    content_type TEXT,
    content_length INTEGER,

    -- Response summary
    response_status INTEGER,
    response_headers TEXT,
    response_size INTEGER,
    response_snippet TEXT,

    -- Classification and routing
    type TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL,

    -- State management
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_agent TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    consumed_at TEXT,

    -- Dedup signature: hash of sorted query/body param KEYS (not values)
    params_key_sig TEXT,

    UNIQUE(method, url_path, params_key_sig)
);

CREATE INDEX IF NOT EXISTS idx_consume ON cases(status, type);
CREATE INDEX IF NOT EXISTS idx_source ON cases(source);
CREATE INDEX IF NOT EXISTS idx_created ON cases(created_at);

CREATE TABLE IF NOT EXISTS work_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Canonical backend identity when available
    queue_key TEXT NOT NULL,
    request_variant_id INTEGER,
    service_id INTEGER,
    coverage_item_id INTEGER,
    auth_context TEXT NOT NULL DEFAULT 'anonymous',

    -- Request identity and replay context
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    url_path TEXT NOT NULL,

    -- Structured parameters (pre-extracted by producers)
    query_params TEXT,
    body_params TEXT,
    path_params TEXT,
    cookie_params TEXT,

    -- Request content
    headers TEXT,
    body TEXT,
    content_type TEXT,
    content_length INTEGER,

    -- Response summary
    response_status INTEGER,
    response_headers TEXT,
    response_size INTEGER,
    response_snippet TEXT,

    -- Classification and routing
    type TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL,

    -- Transient buffer state only
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_agent TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TEXT DEFAULT (datetime('now')),
    consumed_at TEXT,

    -- Dedup signature: hash of sorted query/body param KEYS
    params_key_sig TEXT,

    -- Signal-first dispatch metadata (db_insert_work_item writes these inline at ingest;
    -- classify-work re-applies them when classify_buckets._BUCKETS is intentionally changed)
    priority_score INTEGER NOT NULL DEFAULT 0,
    priority_reason TEXT,
    cluster_key TEXT,
    terminal_reason TEXT,

    UNIQUE(queue_key)
);

CREATE INDEX IF NOT EXISTS idx_work_items_consume ON work_items(status, type);
CREATE INDEX IF NOT EXISTS idx_work_items_source ON work_items(source);
CREATE INDEX IF NOT EXISTS idx_work_items_created ON work_items(created_at);
CREATE INDEX IF NOT EXISTS idx_work_items_priority ON work_items(status, priority_score DESC, cluster_key);

-- The per-host aggregate view (`work_items_per_host`) is owned by
-- `agent/scripts/assess/lib/db.py:_apply_work_items_per_host_view`, NOT by
-- this file. It is purely derived state (no rows) and the host-extraction
-- expression evolved across releases (port strip, IPv6 bracket strip), so
-- defining it in two places creates drift. db.py drops and recreates the
-- view on every `db_init()` so both fresh engagements and legacy engagement
-- DBs end up with the same definition. Look there if you need to change
-- the view shape or host extraction logic.
