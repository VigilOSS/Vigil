"""Tests for the work-buffer priority/cluster pipeline.

Covers the schema migration that adds `priority_score`, `priority_reason`,
`cluster_key`, and `terminal_reason`, plus the `classify-work`, `list-clusters`,
and the `dispatch fetch-by-priority` / `dispatch defer-cluster` CLI
subcommands. We import each command module directly through a helper (mirroring
the pattern used by `test_agent_script_regressions.py`) so the tests exercise
the real argparse-driven `run` entry point without paying the subprocess cost.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_db_module():
    return _load_script_module(
        "test_work_buffer_db_module",
        "agent/scripts/assess/lib/db.py",
    )


def _load_classify_module():
    return _load_script_module(
        "test_classify_work_module",
        "agent/scripts/assess/commands/classify_work.py",
    )


def _load_list_clusters_module():
    return _load_script_module(
        "test_list_clusters_module",
        "agent/scripts/assess/commands/list_clusters.py",
    )


def _load_dispatch_module():
    return _load_script_module(
        "test_dispatch_module",
        "agent/scripts/assess/commands/dispatch.py",
    )


def _make_fresh_db(tmp_path: Path, name: str = "cases.db") -> Path:
    db_path = tmp_path / name
    db_path.touch()
    db_module = _load_db_module()
    db_module.db_init(str(db_path))
    return db_path


def _insert_work_item(
    db_path: Path,
    *,
    queue_key: str,
    url_path: str,
    url: str | None = None,
    method: str = "GET",
    case_type: str = "api",
    status: str = "pending",
    query_params: dict | None = None,
    body_params: dict | None = None,
    source: str = "test",
    priority_score: int = 0,
    cluster_key: str | None = None,
    terminal_reason: str | None = None,
) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.execute(
            """INSERT INTO work_items
            (queue_key, method, url, url_path, query_params, body_params,
             type, source, status, priority_score, cluster_key, terminal_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                queue_key,
                method,
                url or f"https://target.example{url_path}",
                url_path,
                json.dumps(query_params or {}),
                json.dumps(body_params or {}),
                case_type,
                source,
                status,
                priority_score,
                cluster_key,
                terminal_reason,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def _run_classify(db_path: Path, batch: int = 500):
    module = _load_classify_module()
    module.run(SimpleNamespace(db_path=str(db_path), batch=batch))


def _run_list_clusters(db_path: Path, status: str = "pending", limit: int = 100):
    module = _load_list_clusters_module()
    module.run(SimpleNamespace(db_path=str(db_path), status=status, limit=limit))


def _run_dispatch(
    db_path: Path,
    action: str,
    extra: list[str] | None = None,
    reason: str = "",
):
    module = _load_dispatch_module()
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action=action,
            extra=extra or [],
            reason=reason,
        )
    )


def test_schema_migration_adds_priority_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "old.db"
    db_path.touch()
    conn = sqlite3.connect(str(db_path))
    try:
        # Build a work_items table that mirrors the schema before the
        # signal-first dispatch columns shipped. The migration should add the
        # four columns without touching existing rows.
        conn.execute(
            """CREATE TABLE work_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                queue_key TEXT NOT NULL,
                request_variant_id INTEGER,
                service_id INTEGER,
                coverage_item_id INTEGER,
                auth_context TEXT NOT NULL DEFAULT 'anonymous',
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                url_path TEXT NOT NULL,
                query_params TEXT,
                body_params TEXT,
                path_params TEXT,
                cookie_params TEXT,
                headers TEXT,
                body TEXT,
                content_type TEXT,
                content_length INTEGER,
                response_status INTEGER,
                response_headers TEXT,
                response_size INTEGER,
                response_snippet TEXT,
                type TEXT NOT NULL DEFAULT 'unknown',
                source TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                assigned_agent TEXT,
                retry_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                consumed_at TEXT,
                params_key_sig TEXT,
                UNIQUE(queue_key)
            )"""
        )
        conn.execute(
            "INSERT INTO work_items (queue_key, method, url, url_path, source, type) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("legacy:1", "GET", "https://target.example/", "/", "legacy", "api"),
        )
        conn.commit()
    finally:
        conn.close()

    db_module = _load_db_module()
    db_module.db_init(str(db_path))

    conn = sqlite3.connect(str(db_path))
    try:
        columns = {row[1]: row for row in conn.execute("PRAGMA table_info(work_items)").fetchall()}
        for name in ("priority_score", "priority_reason", "cluster_key", "terminal_reason"):
            assert name in columns, f"missing migrated column {name}"

        # priority_score has NOT NULL DEFAULT 0; existing rows should reflect that
        # and the nullable columns should come back as NULL rather than empty strings.
        row = conn.execute(
            "SELECT priority_score, priority_reason, cluster_key, terminal_reason "
            "FROM work_items WHERE queue_key = ?",
            ("legacy:1",),
        ).fetchone()
        assert row == (0, None, None, None)

        # The priority index is created as part of schema.sql for fresh DBs; the
        # migration path must also leave it present so fetch-by-priority can rely
        # on the ordering.
        indexes = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='work_items'"
        ).fetchall()}
        assert "idx_work_items_priority" in indexes
    finally:
        conn.close()


def test_classify_work_assigns_ssrf_bucket(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="v:1",
        url_path="/api",
        url="https://target.example/api?url=http://evil.example",
        query_params={"url": "http://evil.example"},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT cluster_key, priority_score, priority_reason, terminal_reason "
            "FROM work_items WHERE queue_key = ?",
            ("v:1",),
        ).fetchone()
    finally:
        conn.close()

    assert row[0] == "gf:ssrf"
    assert row[1] >= 40
    assert row[2] is not None and "gf:ssrf" in row[2]
    assert row[3] is None

    summary = json.loads(capsys.readouterr().out)
    assert summary["classified"] == 1
    assert summary["updated"] == 1
    assert summary["by_cluster"].get("gf:ssrf") == 1


def test_classify_work_assigns_salesforce_overlay(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="sf:1",
        url_path="/aura",
        url="https://target.example/aura?controller=executeActions",
        query_params={"executeActions": "1"},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT cluster_key, priority_score, priority_reason FROM work_items WHERE queue_key = ?",
            ("sf:1",),
        ).fetchone()
    finally:
        conn.close()

    assert row[0] == "overlay:salesforce"
    assert row[1] == 18
    assert row[2] == "overlay:salesforce"

    summary = json.loads(capsys.readouterr().out)
    assert summary["by_cluster"].get("overlay:salesforce") == 1


def test_classify_work_deterministic(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="v:1",
        url_path="/account/profile",
        query_params={"id": "42", "url": "http://x"},
    )
    _insert_work_item(
        db_path,
        queue_key="v:2",
        url_path="/admin/debug",
        query_params={"cmd": "id"},
    )

    _run_classify(db_path)
    first = capsys.readouterr().out

    conn = sqlite3.connect(str(db_path))
    try:
        first_rows = conn.execute(
            "SELECT queue_key, cluster_key, priority_score, priority_reason, terminal_reason "
            "FROM work_items ORDER BY queue_key"
        ).fetchall()
    finally:
        conn.close()

    # Re-running should be a no-op because classify-work only touches rows with
    # priority_score=0 AND cluster_key IS NULL. We assert both the output
    # summary and the stored rows are unchanged.
    _run_classify(db_path)
    second = capsys.readouterr().out

    conn = sqlite3.connect(str(db_path))
    try:
        second_rows = conn.execute(
            "SELECT queue_key, cluster_key, priority_score, priority_reason, terminal_reason "
            "FROM work_items ORDER BY queue_key"
        ).fetchall()
    finally:
        conn.close()

    assert first_rows == second_rows
    first_summary = json.loads(first)
    second_summary = json.loads(second)
    assert first_summary["classified"] == 2
    assert second_summary["classified"] == 0
    assert second_summary["updated"] == 0


def test_classify_work_inert_type_terminates(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="img:1",
        url_path="/static/logo.png",
        case_type="image",
        status="skipped",
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT status, terminal_reason, cluster_key, priority_score "
            "FROM work_items WHERE queue_key = ?",
            ("img:1",),
        ).fetchone()
    finally:
        conn.close()

    assert row[0] == "skipped"
    assert row[1] == "inert_type"
    assert row[2] == "type:image"
    assert row[3] == 0


def test_classify_work_path_fallback(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="v:1",
        url_path="/about/company/history",
        query_params={},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT cluster_key, priority_score, priority_reason FROM work_items WHERE queue_key = ?",
            ("v:1",),
        ).fetchone()
    finally:
        conn.close()

    assert row[0] == "path:/about/company"
    assert row[1] == 0
    assert row[2] is None


def test_fetch_by_priority_orders_correctly(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    seeds = [
        ("low", 5, "path:/misc"),
        ("ssrf-top", 45, "gf:ssrf"),
        ("rce-top", 50, "gf:rce"),
        ("sqli", 40, "gf:sqli"),
        ("redirect", 25, "gf:redirect"),
        ("zero", 0, "path:/x"),
    ]
    for key, score, cluster in seeds:
        _insert_work_item(
            db_path,
            queue_key=key,
            url_path=f"/{key}",
            priority_score=score,
            cluster_key=cluster,
        )

    _run_dispatch(db_path, "fetch-by-priority", ["5", "priority-agent"])

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert [row["queue_key"] for row in payload] == [
        "rce-top",
        "ssrf-top",
        "sqli",
        "redirect",
        "low",
    ]
    for row in payload:
        assert row["status"] == "processing"
        assert row["assigned_agent"] == "priority-agent"


def test_fetch_by_priority_skips_terminal(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="keep",
        url_path="/keep",
        priority_score=30,
        cluster_key="gf:idor",
    )
    _insert_work_item(
        db_path,
        queue_key="drop",
        url_path="/drop",
        priority_score=99,
        cluster_key="gf:xss",
        terminal_reason="low-signal",
    )

    _run_dispatch(db_path, "fetch-by-priority", ["10", "priority-agent"])

    payload = json.loads(capsys.readouterr().out)
    assert [row["queue_key"] for row in payload] == ["keep"]


def test_defer_cluster_flips_status(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    for idx in range(3):
        _insert_work_item(
            db_path,
            queue_key=f"xss:{idx}",
            url_path=f"/search{idx}",
            priority_score=20,
            cluster_key="gf:xss",
        )
    _insert_work_item(
        db_path,
        queue_key="other",
        url_path="/else",
        priority_score=35,
        cluster_key="gf:idor",
    )

    _run_dispatch(db_path, "defer-cluster", ["gf:xss"], reason="low-signal")
    output = capsys.readouterr().out
    assert "Deferred 3 pending item(s)" in output
    assert "gf:xss" in output

    conn = sqlite3.connect(str(db_path))
    try:
        xss_rows = conn.execute(
            "SELECT status, terminal_reason FROM work_items WHERE cluster_key = ?",
            ("gf:xss",),
        ).fetchall()
        other = conn.execute(
            "SELECT status, terminal_reason FROM work_items WHERE cluster_key = ?",
            ("gf:idor",),
        ).fetchone()
    finally:
        conn.close()

    assert xss_rows == [("skipped", "low-signal")] * 3
    assert other == ("pending", None)


def test_defer_cluster_rejects_empty_reason(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="xss:1",
        url_path="/search",
        priority_score=20,
        cluster_key="gf:xss",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_dispatch(db_path, "defer-cluster", ["gf:xss"], reason="")

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert "--reason is required" in stderr

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT status, terminal_reason FROM work_items WHERE cluster_key = ?",
            ("gf:xss",),
        ).fetchone()
    finally:
        conn.close()
    assert row == ("pending", None)


def test_list_clusters_orders_by_max_priority(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    # gf:rce — single high-priority row
    _insert_work_item(
        db_path,
        queue_key="rce:1",
        url_path="/exec/run",
        priority_score=50,
        cluster_key="gf:rce",
    )
    # gf:ssrf — two rows at weight 45
    for idx in range(2):
        _insert_work_item(
            db_path,
            queue_key=f"ssrf:{idx}",
            url_path=f"/proxy/{idx}",
            priority_score=45,
            cluster_key="gf:ssrf",
        )
    # path fallback — zero priority
    _insert_work_item(
        db_path,
        queue_key="about:1",
        url_path="/about",
        priority_score=0,
        cluster_key="path:/about",
    )

    _run_list_clusters(db_path)
    payload = json.loads(capsys.readouterr().out)

    assert payload["status"] == "pending"
    assert payload["cluster_count"] == 3
    keys = [entry["cluster_key"] for entry in payload["clusters"]]
    assert keys == ["gf:rce", "gf:ssrf", "path:/about"]

    ssrf_entry = payload["clusters"][1]
    assert ssrf_entry["count"] == 2
    assert ssrf_entry["max_priority_score"] == 45
    assert ssrf_entry["avg_priority_score"] == 45.0
    assert len(ssrf_entry["sample_urls"]) == 2
