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


def _run_list_clusters(
    db_path: Path,
    status: str = "pending",
    limit: int = 100,
    host: str = "",
):
    module = _load_list_clusters_module()
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            status=status,
            limit=limit,
            host=host,
        )
    )


def _run_dispatch(
    db_path: Path,
    action: str,
    extra: list[str] | None = None,
    reason: str = "",
    by: str = "status",
):
    module = _load_dispatch_module()
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action=action,
            extra=extra or [],
            reason=reason,
            by=by,
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


def test_classify_work_ignores_non_pending_consumable_rows(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="done:rce",
        url_path="/api/run",
        status="done",
        query_params={"cmd": "id"},
    )
    _insert_work_item(
        db_path,
        queue_key="pending:rce",
        url_path="/api/run",
        query_params={"cmd": "id"},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        rows = {
            row[0]: row[1:]
            for row in conn.execute(
                "SELECT queue_key, status, cluster_key, priority_score, priority_reason "
                "FROM work_items ORDER BY queue_key"
            ).fetchall()
        }
    finally:
        conn.close()

    assert rows["done:rce"] == ("done", None, 0, None)
    assert rows["pending:rce"] == ("pending", "gf:rce", 50, "gf:rce")
    summary = json.loads(capsys.readouterr().out)
    assert summary["classified"] == 1


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


def test_fetch_by_priority_auto_routes_by_type(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    seeds = [
        ("api-rce", "api", 50, "gf:rce"),
        ("js-ssrf", "javascript", 45, "gf:ssrf"),
        ("unknown-high", "unknown", 99, "path:/unknown"),
        ("page-low", "page", 5, "path:/page"),
    ]
    for key, case_type, score, cluster in seeds:
        _insert_work_item(
            db_path,
            queue_key=key,
            url_path=f"/{key}",
            case_type=case_type,
            priority_score=score,
            cluster_key=cluster,
        )

    _run_dispatch(db_path, "fetch-by-priority", ["10", "auto"])

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert [row["queue_key"] for row in payload] == [
        "api-rce",
        "js-ssrf",
        "page-low",
    ]
    assert [row["assigned_agent"] for row in payload] == [
        "vulnerability-analyst",
        "source-analyzer",
        "source-analyzer",
    ]


def test_fetch_by_priority_known_agent_filters_to_routed_types(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="api-low",
        url_path="/api/low",
        case_type="api",
        priority_score=10,
        cluster_key="path:/api",
    )
    _insert_work_item(
        db_path,
        queue_key="js-high",
        url_path="/static/app.js",
        case_type="javascript",
        priority_score=50,
        cluster_key="path:/static/app.js",
    )

    _run_dispatch(db_path, "fetch-by-priority", ["10", "vulnerability-analyst-1"])

    payload = json.loads(capsys.readouterr().out)
    assert [row["queue_key"] for row in payload] == ["api-low"]
    assert payload[0]["assigned_agent"] == "vulnerability-analyst-1"


def test_fetch_by_priority_rejects_unroutable_agent_name(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="api",
        url_path="/api",
        case_type="api",
        priority_score=10,
        cluster_key="path:/api",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_dispatch(db_path, "fetch-by-priority", ["10", "priority-agent"])

    assert excinfo.value.code == 1
    assert "not a routed agent" in capsys.readouterr().err


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

    _run_dispatch(db_path, "fetch-by-priority", ["10", "auto"])

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


def test_dispatch_peek_returns_pending_rows_without_claiming(
    tmp_path: Path, capsys
) -> None:
    db_path = _make_fresh_db(tmp_path)
    for idx in range(3):
        _insert_work_item(
            db_path,
            queue_key=f"api:{idx}",
            url_path=f"/api/users/{idx}",
            case_type="api",
            priority_score=50 - idx,
        )
    # Adjacent type that should not appear in peek output for `api`.
    _insert_work_item(
        db_path,
        queue_key="form:1",
        url_path="/login",
        case_type="form",
        priority_score=99,
    )

    _run_dispatch(db_path, "peek", ["api", "5"])
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 3
    assert all(row["type"] == "api" for row in rows)
    # Peek must not flip status.
    conn = sqlite3.connect(str(db_path))
    try:
        statuses = {
            row[0]
            for row in conn.execute(
                "SELECT status FROM work_items WHERE type = 'api'"
            ).fetchall()
        }
    finally:
        conn.close()
    assert statuses == {"pending"}


def test_dispatch_defer_items_flips_specific_ids(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    ids: list[int] = []
    for idx in range(4):
        ids.append(
            _insert_work_item(
                db_path,
                queue_key=f"api:{idx}",
                url_path=f"/api/users/{idx}",
                case_type="api",
                priority_score=10,
            )
        )

    targets = f"{ids[0]},{ids[2]}"
    _run_dispatch(db_path, "defer-items", [targets], reason="manual triage")

    conn = sqlite3.connect(str(db_path))
    try:
        rows = {
            row[0]: (row[1], row[2])
            for row in conn.execute(
                "SELECT id, status, terminal_reason FROM work_items"
            ).fetchall()
        }
    finally:
        conn.close()

    assert rows[ids[0]] == ("skipped", "manual triage")
    assert rows[ids[2]] == ("skipped", "manual triage")
    assert rows[ids[1]] == ("pending", None)
    assert rows[ids[3]] == ("pending", None)


def test_dispatch_defer_items_rejects_empty_reason(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    item_id = _insert_work_item(
        db_path,
        queue_key="api:1",
        url_path="/api/users/1",
        case_type="api",
    )
    with pytest.raises(SystemExit):
        _run_dispatch(db_path, "defer-items", [str(item_id)], reason="")
    stderr = capsys.readouterr().err
    assert "--reason is required" in stderr


def test_dispatch_stats_by_host_groups_by_url_host(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="a:1",
        url_path="/a",
        url="https://example.test/a",
        case_type="api",
    )
    _insert_work_item(
        db_path,
        queue_key="a:2",
        url_path="/b",
        url="https://example.test/b",
        case_type="api",
    )
    _insert_work_item(
        db_path,
        queue_key="b:1",
        url_path="/x",
        url="https://other.example/x",
        case_type="api",
    )

    _run_dispatch(db_path, "stats", by="host")
    out = capsys.readouterr().out
    assert "example.test|pending|2" in out
    assert "other.example|pending|1" in out


def test_dispatch_stats_by_cluster_includes_max_priority(
    tmp_path: Path, capsys
) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="x:1",
        url_path="/x",
        cluster_key="gf:rce",
        priority_score=50,
    )
    _insert_work_item(
        db_path,
        queue_key="x:2",
        url_path="/y",
        cluster_key="gf:rce",
        priority_score=20,
    )

    _run_dispatch(db_path, "stats", by="cluster")
    out = capsys.readouterr().out
    assert "gf:rce|pending|2|max_priority=50" in out


def test_list_clusters_filters_by_host(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="a:1",
        url_path="/a",
        url="https://example.test/a",
        cluster_key="gf:rce",
        priority_score=50,
    )
    _insert_work_item(
        db_path,
        queue_key="b:1",
        url_path="/x",
        url="https://other.example/x",
        cluster_key="gf:xss",
        priority_score=30,
    )

    _run_list_clusters(db_path, host="example.test")
    payload = json.loads(capsys.readouterr().out)
    keys = [entry["cluster_key"] for entry in payload["clusters"]]
    assert keys == ["gf:rce"]
    assert payload["host_filter"] == "example.test"


# ---------------------------------------------------------------------------
# 1D.2 — per-host URL budget regression coverage
# ---------------------------------------------------------------------------


def _load_classify_lib_module():
    return _load_script_module(
        "test_classify_lib_module",
        "agent/scripts/assess/lib/classify.py",
    )


def _load_ingest_module():
    return _load_script_module(
        "test_ingest_endpoints_module",
        "agent/scripts/assess/commands/ingest_endpoints.py",
    )


def _bulk_insert_for_host(
    db_path: Path,
    *,
    host: str,
    n_pending: int,
    n_deferred: int = 0,
    case_type: str = "page",
    queue_prefix: str = "host",
) -> None:
    """Seed the work_items table with rows split between pending and deferred.

    Mirrors the pattern the ingestion path produces — pending rows look like
    a normal admit, while deferred rows carry the budget-exceeded cluster_key
    and terminal_reason. Used to drive the budget-decision tests below
    without paying the cost of stubbing the full ingestion HTTP roundtrip.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        for idx in range(n_pending):
            conn.execute(
                """INSERT INTO work_items
                (queue_key, method, url, url_path, type, source, status, priority_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"{queue_prefix}-pending:{idx}",
                    "GET",
                    f"https://{host}/p{idx}",
                    f"/p{idx}",
                    case_type,
                    "test",
                    "pending",
                    0,
                ),
            )
        for idx in range(n_deferred):
            conn.execute(
                """INSERT INTO work_items
                (queue_key, method, url, url_path, type, source, status,
                 cluster_key, terminal_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"{queue_prefix}-defer:{idx}",
                    "GET",
                    f"https://{host}/d{idx}",
                    f"/d{idx}",
                    case_type,
                    "test",
                    "deferred",
                    "deferred:per-host-budget-exceeded",
                    "per-host-budget-exceeded",
                ),
            )
        conn.commit()
    finally:
        conn.close()


def test_per_host_budget_caps_content_rich_at_1000(tmp_path: Path) -> None:
    """A typical content-rich host caps at 1000 active rows. The 1001st URL
    must defer with cluster_key='deferred:per-host-budget-exceeded' rather
    than admit."""
    classify_lib = _load_classify_lib_module()
    db_path = _make_fresh_db(tmp_path)

    # Default content-rich tier returns 1000.
    assert classify_lib.per_host_budget("example.test") == classify_lib.PER_HOST_BUDGET_CONTENT_RICH
    assert classify_lib.PER_HOST_BUDGET_CONTENT_RICH == 1000

    _bulk_insert_for_host(
        db_path,
        host="example.test",
        n_pending=1000,
        queue_prefix="content",
    )

    # The view should report the host at exactly 1000 active rows.
    assert classify_lib.host_active_count(str(db_path), "example.test") == 1000

    # Now the budget gate replicates the ingest decision: the next URL would
    # exceed the budget, so it must be inserted as deferred.
    ingest = _load_ingest_module()
    ingest._insert_budget_exceeded_work_item(
        db_path=str(db_path),
        method="GET",
        url="https://example.test/over1001",
        url_path="/over1001",
        query_params={},
        body_params={},
        path_params={},
        cookie_params={},
        case_type="page",
        source="test",
        params_sig="",
        auth_context="anonymous",
        host="example.test",
        budget=1000,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        pending = conn.execute(
            "SELECT COUNT(*) FROM work_items WHERE status='pending' AND url LIKE 'https://example.test/%'"
        ).fetchone()[0]
        deferred = conn.execute(
            "SELECT COUNT(*), MAX(cluster_key), MAX(terminal_reason) "
            "FROM work_items WHERE status='deferred' AND url LIKE 'https://example.test/%'"
        ).fetchone()
    finally:
        conn.close()

    assert pending == 1000
    assert deferred[0] == 1
    assert deferred[1] == "deferred:per-host-budget-exceeded"
    assert deferred[2] == "per-host-budget-exceeded"


def test_per_host_budget_api_tier_at_200(tmp_path: Path) -> None:
    """An ``api.*`` host caps at 200 because its surface is method × parameter
    rather than URL × URL. The classifier is purely hostname-driven so the
    test passes without reading any sitemap or recon intel."""
    classify_lib = _load_classify_lib_module()
    db_path = _make_fresh_db(tmp_path)

    # api.* matches the API-tier rule.
    assert classify_lib.per_host_budget("api.example.test") == classify_lib.PER_HOST_BUDGET_API_TIER
    assert classify_lib.PER_HOST_BUDGET_API_TIER == 200

    # *.api.* also matches.
    assert classify_lib.per_host_budget("staging.api.example.test") == classify_lib.PER_HOST_BUDGET_API_TIER

    _bulk_insert_for_host(
        db_path,
        host="api.example.test",
        n_pending=200,
        queue_prefix="api",
    )

    assert classify_lib.host_active_count(str(db_path), "api.example.test") == 200


def test_per_host_budget_sitemap_at_2000(tmp_path: Path) -> None:
    """A sitemap-bearing host raises the budget to 2000 because the sitemap
    declares the canonical surface and we must not truncate below it. The
    sitemap-bearing flag is supplied by the operator at ingestion time
    (``--sitemap-host`` flag or backend intel lookup)."""
    classify_lib = _load_classify_lib_module()

    sitemap_hosts = {"docs.example.test"}
    assert classify_lib.per_host_budget(
        "docs.example.test", sitemap_hosts=sitemap_hosts
    ) == classify_lib.PER_HOST_BUDGET_SITEMAP_BEARING
    assert classify_lib.PER_HOST_BUDGET_SITEMAP_BEARING == 2000

    # Sitemap-bearing wins over API-tier when both apply: the sitemap is the
    # canonical surface declaration, so honor it.
    assert classify_lib.per_host_budget(
        "api.example.test", sitemap_hosts={"api.example.test"}
    ) == classify_lib.PER_HOST_BUDGET_SITEMAP_BEARING


def test_per_host_budget_override_via_dispatch_context(tmp_path: Path) -> None:
    """The operator passes ``--budget-override host:N`` to override the
    default. The override beats every heuristic rule (API-tier, sitemap-
    bearing, and content-rich) so the operator can both raise and lower the
    cap on a specific host without rewriting the heuristic table."""
    classify_lib = _load_classify_lib_module()

    # parse_budget_overrides handles the operator-side flag parsing and
    # normalizes hostnames.
    overrides = classify_lib.parse_budget_overrides(
        ["EXAMPLE.test:5000", "api.example.test:50"]
    )
    assert overrides == {"example.test": 5000, "api.example.test": 50}

    # Override raises a content-rich host above its 1000 default.
    assert classify_lib.per_host_budget("example.test", overrides=overrides) == 5000
    # Override LOWERS an API-tier host below its 200 default.
    assert classify_lib.per_host_budget("api.example.test", overrides=overrides) == 50

    # Sitemap-bearing AND override → override still wins.
    assert classify_lib.per_host_budget(
        "example.test",
        sitemap_hosts={"example.test"},
        overrides=overrides,
    ) == 5000

    # Bad override input fails fast.
    with pytest.raises(ValueError):
        classify_lib.parse_budget_overrides(["malformed-no-colon"])
    with pytest.raises(ValueError):
        classify_lib.parse_budget_overrides(["host.test:notanumber"])


def test_work_items_per_host_view_aggregates_across_statuses(tmp_path: Path) -> None:
    """The work_items_per_host view sums active/pending/done/deferred counts
    by host so the classify-work output and ingest budget gate share the same
    source of truth."""
    db_path = _make_fresh_db(tmp_path)
    _bulk_insert_for_host(
        db_path,
        host="alpha.example.test",
        n_pending=3,
        n_deferred=2,
        queue_prefix="alpha",
    )
    _bulk_insert_for_host(
        db_path,
        host="beta.example.test",
        n_pending=1,
        queue_prefix="beta",
    )

    conn = sqlite3.connect(str(db_path))
    try:
        rows = {
            row[0]: {
                "active": row[1],
                "pending": row[2],
                "done": row[3],
                "deferred": row[4],
            }
            for row in conn.execute(
                "SELECT host, active_count, pending_count, done_count, deferred_count "
                "FROM work_items_per_host ORDER BY host"
            ).fetchall()
        }
    finally:
        conn.close()

    assert rows["alpha.example.test"]["active"] == 3
    assert rows["alpha.example.test"]["pending"] == 3
    assert rows["alpha.example.test"]["deferred"] == 2
    assert rows["beta.example.test"]["active"] == 1
    assert rows["beta.example.test"]["pending"] == 1


def test_classify_work_emits_per_host_budget_signal(tmp_path: Path, capsys) -> None:
    """``classify-work`` includes a ``per_host_budget`` summary in its JSON
    output so the operator sees which hosts are at-budget without separately
    reading the view."""
    db_path = _make_fresh_db(tmp_path)
    # Seed an api-tier host at its 200 cap.
    _bulk_insert_for_host(
        db_path,
        host="api.example.test",
        n_pending=200,
        n_deferred=5,
        queue_prefix="apicap",
    )

    _run_classify(db_path)
    summary = json.loads(capsys.readouterr().out)

    per_host = {entry["host"]: entry for entry in summary["per_host_budget"]}
    assert "api.example.test" in per_host
    api_entry = per_host["api.example.test"]
    assert api_entry["budget"] == 200
    assert api_entry["active_count"] == 200
    assert api_entry["at_budget"] is True
    assert api_entry["budget_deferred_count"] == 5
