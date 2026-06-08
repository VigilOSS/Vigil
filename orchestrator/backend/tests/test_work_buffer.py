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
from types import ModuleType, SimpleNamespace

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
        "agent/scripts/assess/commands/dispatch/__init__.py",
    )


def _load_proxy_addon_module():
    mitmproxy = ModuleType("mitmproxy")
    http = ModuleType("mitmproxy.http")
    http.HTTPFlow = object  # type: ignore[attr-defined]
    mitmproxy.http = http  # type: ignore[attr-defined]
    mitmproxy.ctx = SimpleNamespace(
        log=SimpleNamespace(
            info=lambda *_args, **_kwargs: None,
            warn=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        ),
        options=SimpleNamespace(
            engagements_root="", engagement_dir="", registry_poll_seconds=30
        ),
    )
    sys.modules.setdefault("mitmproxy", mitmproxy)
    sys.modules.setdefault("mitmproxy.http", http)
    return _load_script_module(
        "test_proxy_addon_module",
        "agent/scripts/proxy_addon.py",
    )


def _make_collector_with_engagement(module, root: Path, *, key: str = "eng-1"):
    """Helper for tests that need a CaseCollector preloaded with a single
    engagement entry pointing at ``root/<key>``. Returns ``(collector, entry)``.
    """
    engagement_dir = root / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    collector = module.CaseCollector()
    collector.engagements_root = root
    entry = module.EngagementEntry(
        key=key,
        root=engagement_dir,
        scope_patterns=[],
        scope_priority=0,
        updated_at="",
    )
    collector.registry = {key: entry}
    return collector, entry


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


def _run_classify(db_path: Path, batch: int = 500, extra_args: list[str] | None = None):
    module = _load_classify_module()
    extras = extra_args or []
    reclassify_all = "--reclassify-all" in extras
    reclaim_skipped = "--reclaim-skipped" in extras
    only_unscored = "--only-unscored" in extras  # deprecated alias, kept for back-compat
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            batch=batch,
            reclassify_all=reclassify_all,
            reclaim_skipped=reclaim_skipped,
            only_unscored=only_unscored,
        )
    )


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
    reason_tag: str = "",
):
    module = _load_dispatch_module()
    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            action=action,
            extra=extra or [],
            reason=reason,
            by=by,
            reason_tag=reason_tag,
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
        for name in (
            "priority_score",
            "priority_reason",
            "cluster_key",
            "terminal_reason",
            "signals",
            "selected_by",
            "triage_rationale",
            "live_status",
            "request_body_truncated",
            "response_truncated",
        ):
            assert name in columns, f"missing migrated column {name}"

        # priority_score has NOT NULL DEFAULT 0; existing rows should reflect that
        # and the nullable columns should come back as NULL rather than empty strings.
        row = conn.execute(
            "SELECT priority_score, priority_reason, cluster_key, terminal_reason, "
            "signals, selected_by, triage_rationale, live_status "
            "FROM work_items WHERE queue_key = ?",
            ("legacy:1",),
        ).fetchone()
        assert row == (0, None, None, None, None, None, None, None)

        # The priority index is created as part of schema.sql for fresh DBs; the
        # migration path must also leave it present so fetch-by-priority can rely
        # on the ordering.
        indexes = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='work_items'"
        ).fetchall()}
        assert "idx_work_items_priority" in indexes
    finally:
        conn.close()


def test_db_exec_returning_commits_and_returns_dict_rows(tmp_path: Path) -> None:
    """db_exec_returning runs an UPDATE ... RETURNING, commits, and returns the
    mutated rows as dicts (the contract _fetch relies on)."""
    db_module = _load_db_module()
    db_path = tmp_path / "ret.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT, note TEXT)")
        conn.execute("INSERT INTO t (id, status, note) VALUES (1, 'pending', 'a')")
        conn.execute("INSERT INTO t (id, status, note) VALUES (2, 'pending', 'b')")
        conn.commit()
    finally:
        conn.close()

    rows = db_module.db_exec_returning(
        str(db_path),
        "UPDATE t SET status = 'done' WHERE status = 'pending' RETURNING *",
    )
    assert isinstance(rows, list)
    assert all(isinstance(r, dict) for r in rows)
    assert sorted(r["id"] for r in rows) == [1, 2]
    assert {r["status"] for r in rows} == {"done"}

    # The mutation must be durably committed: a fresh connection sees 'done'.
    conn = sqlite3.connect(str(db_path))
    try:
        persisted = {r[0]: r[1] for r in conn.execute("SELECT id, status FROM t").fetchall()}
    finally:
        conn.close()
    assert persisted == {1: "done", 2: "done"}


def test_db_exec_returning_empty_match_returns_empty_list(tmp_path: Path) -> None:
    """A RETURNING statement that matches no rows returns []."""
    db_module = _load_db_module()
    db_path = tmp_path / "ret_empty.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT)")
        conn.commit()
    finally:
        conn.close()

    rows = db_module.db_exec_returning(
        str(db_path),
        "UPDATE t SET status = 'done' WHERE status = 'pending' RETURNING *",
    )
    assert rows == []


def test_db_connect_yields_row_factory_and_supports_explicit_txn(tmp_path: Path) -> None:
    """db_connect yields a Row-factory connection the caller can drive a
    BEGIN IMMEDIATE transaction on, and closes it on exit."""
    db_module = _load_db_module()
    db_path = tmp_path / "conn.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, status TEXT)")
        conn.execute("INSERT INTO t (id, status) VALUES (1, 'pending')")
        conn.commit()
    finally:
        conn.close()

    captured = {}
    with db_module.db_connect(str(db_path)) as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM t WHERE id = 1").fetchone()
        # Row factory => mapping access by column name works.
        assert row["status"] == "pending"
        c.execute("UPDATE t SET status = 'processing' WHERE id = 1")
        c.commit()
        captured["conn"] = c

    # Connection is closed after the context manager exits.
    import pytest as _pytest

    with _pytest.raises(sqlite3.ProgrammingError):
        captured["conn"].execute("SELECT 1")

    # The committed change is visible to a fresh connection.
    conn = sqlite3.connect(str(db_path))
    try:
        assert conn.execute("SELECT status FROM t WHERE id = 1").fetchone()[0] == "processing"
    finally:
        conn.close()


def test_db_connect_closes_connection_on_exception(tmp_path: Path) -> None:
    """An exception inside the with-block still closes the connection."""
    db_module = _load_db_module()
    db_path = tmp_path / "conn_exc.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        conn.commit()
    finally:
        conn.close()

    leaked = {}
    with __import__("pytest").raises(RuntimeError):
        with db_module.db_connect(str(db_path)) as c:
            leaked["conn"] = c
            raise RuntimeError("boom")

    with __import__("pytest").raises(sqlite3.ProgrammingError):
        leaked["conn"].execute("SELECT 1")


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


def test_upload_rows_prefer_upload_fields_over_generic_lfi(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="upload:1",
        url_path="/api/users/avatar",
        method="POST",
        case_type="upload",
        body_params={"file": "avatar.png"},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT cluster_key, priority_score, priority_reason "
            "FROM work_items WHERE queue_key = ?",
            ("upload:1",),
        ).fetchone()
    finally:
        conn.close()

    assert row[0] == "gf:upload_fields"
    assert row[1] == 40
    assert row[2] == "gf:lfi+gf:upload_fields"


def _classify_one(db_path: Path, queue_key: str):
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(
            "SELECT cluster_key, priority_score, priority_reason, terminal_reason "
            "FROM work_items WHERE queue_key = ?",
            (queue_key,),
        ).fetchone()
    finally:
        conn.close()


def test_classify_idor_path_embedded_numeric_id(tmp_path: Path) -> None:
    """A numeric object id in the URL path (no query/body param) buckets as idor."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="idor:path-num",
        url_path="/api/users/1024/profile",
    )
    _run_classify(db_path)
    row = _classify_one(db_path, "idor:path-num")
    assert row[0] == "gf:idor"
    assert row[1] == 35
    assert row[2] is not None and "gf:idor" in row[2]
    assert row[3] is None


def test_classify_idor_path_embedded_uuid(tmp_path: Path) -> None:
    """A UUID object id in the URL path buckets as idor."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="idor:path-uuid",
        url_path="/files/550e8400-e29b-41d4-a716-446655440000",
    )
    _run_classify(db_path)
    row = _classify_one(db_path, "idor:path-uuid")
    assert row[0] == "gf:idor"
    assert row[1] == 35


def test_classify_idor_expanded_param_key_workspace(tmp_path: Path) -> None:
    """A tenant/workspace scoping key (cross-tenant BOLA) buckets as idor."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="idor:workspace",
        url_path="/api/list",
        query_params={"workspace_id": "acme"},
    )
    _run_classify(db_path)
    row = _classify_one(db_path, "idor:workspace")
    assert row[0] == "gf:idor"
    assert row[1] == 35
    assert row[2] is not None and "gf:idor" in row[2]


def test_classify_non_object_path_is_not_idor(tmp_path: Path) -> None:
    """A static, id-free path stays in the path: fallback — no spurious idor."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="static:about",
        url_path="/about/company/history",
    )
    _run_classify(db_path)
    row = _classify_one(db_path, "static:about")
    assert row[0] == "path:/about/company"
    assert row[1] == 0
    assert row[2] is None


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

    # Re-running classify-work with the safe default predicate must not
    # touch already-scored rows — otherwise an operator running it as a
    # routine "refresh" would silently overwrite manual triage. Re-running
    # with --reclassify-all is the explicit opt-in that re-applies the
    # current bucket table to every pending row.
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
    # Default predicate is narrow: scored rows are skipped on re-run.
    assert second_summary["classified"] == 0
    assert second_summary["updated"] == 0

    # --reclassify-all re-applies the bucket table to every pending row
    # (the deliberate path for picking up _BUCKETS edits without resetting).
    _run_classify(db_path, extra_args=["--reclassify-all"])
    third = capsys.readouterr().out
    third_summary = json.loads(third)
    assert third_summary["classified"] == 2
    assert third_summary["updated"] == 2

    # Deprecated --only-unscored alias still works as a no-op when every row
    # is already scored, so older runbooks/CI do not break mid-cutover.
    _run_classify(db_path, extra_args=["--only-unscored"])
    fourth = capsys.readouterr().out
    fourth_summary = json.loads(fourth)
    assert fourth_summary["classified"] == 0
    assert fourth_summary["updated"] == 0


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


def test_classify_work_reclaim_skipped_unstrands_now_non_inert_rows(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="map:1",
        url_path="/static/app.js.map",
        case_type="sourcemap",
        status="skipped",
        terminal_reason="inert_type",
        cluster_key="type:sourcemap",
    )
    _insert_work_item(
        db_path,
        queue_key="img:1",
        url_path="/static/logo.png",
        case_type="image",
        status="skipped",
        terminal_reason="inert_type",
    )

    _run_classify(db_path)
    capsys.readouterr()
    conn = sqlite3.connect(str(db_path))
    try:
        before = conn.execute(
            "SELECT status FROM work_items WHERE queue_key = ?", ("map:1",)
        ).fetchone()[0]
    finally:
        conn.close()
    assert before == "skipped", "default predicate must not touch the stranded row"

    _run_classify(db_path, extra_args=["--reclaim-skipped"])
    summary = json.loads(capsys.readouterr().out)
    conn = sqlite3.connect(str(db_path))
    try:
        rows = {
            r[0]: r[1:]
            for r in conn.execute(
                "SELECT queue_key, status, terminal_reason FROM work_items"
            ).fetchall()
        }
    finally:
        conn.close()
    assert rows["map:1"][0] == "pending"
    assert rows["map:1"][1] is None
    assert rows["img:1"][0] == "skipped"
    assert rows["img:1"][1] == "inert_type"
    assert summary["reclaimed_to_pending"] == 1


def test_classify_type_marks_archive_extensions_inert() -> None:
    module = _load_classify_lib_module()

    assert module.classify_type("GET", "/backup.zip", "", "") == "archive"
    assert module.classify_type("GET", "/exports/site.tar.gz", "", "") == "archive"


def test_classify_type_marks_sourcemaps_before_generic_data_content_types() -> None:
    module = _load_classify_lib_module()

    assert (
        module.classify_type("GET", "/static/app.js.map", "application/json", "")
        == "sourcemap"
    )
    assert (
        module.classify_type("GET", "/static/app.css.map", "text/plain", "")
        == "sourcemap"
    )


def test_classify_type_bare_host_root() -> None:
    module = _load_classify_lib_module()

    # Bare scheme://host[/] with no path/query/content-type → host_root.
    assert module.classify_type("GET", "/", "", "") == "host_root"
    assert module.classify_type("GET", "", "", "") == "host_root"
    # A query gives param signal → not a bare host_root.
    assert module.classify_type("GET", "/?next=x", "", "") != "host_root"
    # A content-type means we know it's a rendered page, not a bare root.
    assert module.classify_type("GET", "/", "text/html", "") == "page"
    # Real paths are unaffected.
    assert module.classify_type("GET", "/api/users", "", "") == "api"


def test_classify_work_host_root_is_seed_not_skipped(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="v:hr",
        url_path="/",
        case_type="host_root",
        query_params={},
    )

    _run_classify(db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT cluster_key, priority_score, terminal_reason, status "
            "FROM work_items WHERE queue_key = ?",
            ("v:hr",),
        ).fetchone()
    finally:
        conn.close()

    # Stable, greppable cluster; zero priority; NOT terminal/skipped (it is a
    # Phase-2 crawl seed, must stay pending to be crawled — not silently dropped).
    assert row[0] == "type:host_root"
    assert row[1] == 0
    assert row[2] is None
    assert row[3] == "pending"


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
        ("unknown-trust", "unknown", 35, "gf:trust_surface"),
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
        "unknown-trust",
        "page-low",
    ]
    assert [row["assigned_agent"] for row in payload] == [
        "vulnerability-analyst",
        "source-analyzer",
        "vulnerability-analyst",
        "source-analyzer",
    ]


def test_db_insert_inline_classifies_unknown_trust_surface(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)
    db_module = _load_db_module()

    db_module.db_insert_work_item(
        str(db_path),
        queue_key="unknown:trust",
        method="GET",
        url="https://target.example/oauth/callback",
        url_path="/oauth/callback",
        query_params="{}",
        body_params="{}",
        path_params="{}",
        case_type="unknown",
        source="test",
        params_key_sig="",
    )

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT type, status, priority_score, cluster_key, priority_reason "
            "FROM work_items WHERE queue_key = ?",
            ("unknown:trust",),
        ).fetchone()
    finally:
        conn.close()

    assert row == ("unknown", "pending", 35, "gf:trust_surface", "gf:trust_surface")


def test_proxy_insert_uses_shared_inline_classification(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    engagements_root = tmp_path / "engagements"
    engagements_root.mkdir()
    collector, entry = _make_collector_with_engagement(module, engagements_root)

    case_type = collector._classify_type("GET", "/oauth/callback", "", {})
    assert case_type == "unknown"
    collector._insert_case(
        entry,
        queue_key="variant:1:unknown",
        request_variant_id=1,
        service_id=None,
        auth_context="anonymous",
        method="GET",
        url="https://target.example/oauth/callback",
        url_path="/oauth/callback",
        params={
            "query_params": "{}",
            "body_params": "{}",
            "path_params": "{}",
            "cookie_params": "{}",
        },
        headers="{}",
        body=None,
        content_type="",
        content_length=0,
        request_body_truncated=False,
        response_status=200,
        response_headers="{}",
        response_size=0,
        response_snippet=None,
        response_truncated=False,
        case_type=case_type,
        params_key_sig="",
    )

    conn = sqlite3.connect(str(entry.root / "cases.db"))
    try:
        row = conn.execute(
            "SELECT type, status, priority_score, cluster_key, priority_reason "
            "FROM work_items WHERE queue_key = ?",
            ("variant:1:unknown",),
        ).fetchone()
    finally:
        conn.close()

    assert row == ("unknown", "pending", 35, "gf:trust_surface", "gf:trust_surface")


def test_proxy_insert_reuses_open_db_connection(tmp_path: Path, monkeypatch) -> None:
    module = _load_proxy_addon_module()
    engagements_root = tmp_path / "engagements"
    engagements_root.mkdir()
    collector, entry = _make_collector_with_engagement(module, engagements_root)
    # Pre-populate the cached DB handle on the entry; _insert_case must reuse it
    # rather than re-opening cases.db per call.
    cached_connection = object()
    entry.db = cached_connection
    seen: dict[str, object] = {}

    def fake_insert(_db_path: str, **kwargs) -> None:
        seen["connection"] = kwargs.get("connection")

    monkeypatch.setattr(module, "db_insert_work_item", fake_insert)
    collector._insert_case(
        entry,
        queue_key="variant:1:unknown",
        request_variant_id=1,
        service_id=None,
        auth_context="anonymous",
        method="GET",
        url="https://target.example/oauth/callback",
        url_path="/oauth/callback",
        params={
            "query_params": "{}",
            "body_params": "{}",
            "path_params": "{}",
            "cookie_params": "{}",
        },
        headers="{}",
        body=None,
        content_type="",
        content_length=0,
        request_body_truncated=False,
        response_status=200,
        response_headers="{}",
        response_size=0,
        response_snippet=None,
        response_truncated=False,
        case_type="unknown",
        params_key_sig="",
    )

    assert seen["connection"] is cached_connection


def test_apply_body_policy_flags_truncation() -> None:
    """`_apply_body_policy` must surface truncation explicitly so cases.db
    rows never silently misrepresent a partial body as complete. The
    response_snippet path lives directly in `CaseCollector.response` and
    is exercised in the proxy_addon routing tests; this nails the
    request side.
    """
    module = _load_proxy_addon_module()
    collector = module.CaseCollector()
    big = b"x" * (module.BODY_TRUNCATE + 100)
    body, truncated = collector._apply_body_policy(big, "application/json")
    assert truncated is True
    assert body is not None and len(body) == module.BODY_TRUNCATE

    small = b'{"ok":true}'
    body, truncated = collector._apply_body_policy(small, "application/json")
    assert truncated is False
    assert body == small.decode()

    # Binary types and unsaveable content types return (None, False) so
    # the proxy doesn't accidentally label a "we never tried" body as
    # "truncated".
    body, truncated = collector._apply_body_policy(b"\x89PNG", "image/png")
    assert (body, truncated) == (None, False)
    body, truncated = collector._apply_body_policy(b"some bytes", "application/zip")
    assert (body, truncated) == (None, False)


def test_proxy_insert_persists_truncation_flags(tmp_path: Path) -> None:
    """End-to-end through `_insert_case` → `db_insert_work_item` →
    `work_items`. Catches a regression where the flags are accepted as
    kwargs but never written to the row.
    """
    module = _load_proxy_addon_module()
    engagements_root = tmp_path / "engagements"
    engagements_root.mkdir()
    collector, entry = _make_collector_with_engagement(module, engagements_root)

    collector._insert_case(
        entry,
        queue_key="variant:1:unknown",
        request_variant_id=1,
        service_id=None,
        auth_context="anonymous",
        method="POST",
        url="https://target.example/api/large",
        url_path="/api/large",
        params={
            "query_params": "{}",
            "body_params": "{}",
            "path_params": "{}",
            "cookie_params": "{}",
        },
        headers="{}",
        body="x" * module.BODY_TRUNCATE,
        content_type="application/json",
        content_length=module.BODY_TRUNCATE + 5000,
        request_body_truncated=True,
        response_status=200,
        response_headers="{}",
        response_size=module.RESPONSE_SNIPPET_BYTES * 4,
        response_snippet="y" * module.RESPONSE_SNIPPET_BYTES,
        response_truncated=True,
        case_type="unknown",
        params_key_sig="",
    )

    import sqlite3 as _sqlite
    conn = _sqlite.connect(str(entry.root / "cases.db"))
    try:
        row = conn.execute(
            "SELECT request_body_truncated, response_truncated, "
            "content_length, response_size "
            "FROM work_items WHERE queue_key = ?",
            ("variant:1:unknown",),
        ).fetchone()
    finally:
        conn.close()

    assert row == (1, 1, module.BODY_TRUNCATE + 5000, module.RESPONSE_SNIPPET_BYTES * 4)


def test_fetch_by_priority_vuln_agent_routes_scored_unknown_only(
    tmp_path: Path, capsys
) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="unknown-trust",
        url_path="/oauth/callback",
        case_type="unknown",
        priority_score=35,
        cluster_key="gf:trust_surface",
    )
    _insert_work_item(
        db_path,
        queue_key="unknown-path",
        url_path="/misc/path",
        case_type="unknown",
        priority_score=99,
        cluster_key="path:/misc/path",
    )

    _run_dispatch(db_path, "fetch-by-priority", ["10", "vulnerability-analyst-1"])

    payload = json.loads(capsys.readouterr().out)
    assert [row["queue_key"] for row in payload] == ["unknown-trust"]
    assert payload[0]["assigned_agent"] == "vulnerability-analyst-1"


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


def _classify_buckets():
    import sys as _sys
    from pathlib import Path as _Path
    scripts = _Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in _sys.path:
        _sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb
    return cb


def test_classify_matched_buckets_single(tmp_path: Path) -> None:
    """S14: classify_from_fields exposes a machine-readable matched_buckets list."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="api",
        url_path="/api/users/1024/profile",
    )
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["matched_buckets"] == ["idor"]


def test_classify_matched_buckets_multiple(tmp_path: Path) -> None:
    """S14: a URL matching TWO buckets surfaces BOTH in matched_buckets, not just
    the winner — this is what lets the 2b bridge mint two class-typed items."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="api",
        url_path="/api/fetch",
        query_params=json.dumps({"id": "10", "url": "http://internal/"}),
    )
    matched = assignment["matched_buckets"]
    assert "idor" in matched
    assert "ssrf" in matched
    cb2 = _import_vuln_taxonomy()
    classes = {cb2.GF_BUCKET_TO_CLASS.get(b) for b in matched}
    assert "idor" in classes
    assert "ssrf" in classes


def _import_vuln_taxonomy():
    import sys as _sys
    from pathlib import Path as _Path
    scripts = _Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in _sys.path:
        _sys.path.insert(0, str(scripts))
    import assess.lib.vuln_taxonomy as vt
    return vt


def _run_ingest_bridge(monkeypatch, tmp_path, lines, *, variant_id=501):
    """Run ingest-endpoints over `lines` with a fake backend, capturing the
    class-typed coverage-items the 2b bridge POSTs."""
    module = _load_script_module(
        "test_ingest_endpoints_bridge",
        "agent/scripts/assess/commands/ingest_endpoints.py",
    )
    db_path = _make_fresh_db(tmp_path)

    monkeypatch.setattr(
        module,
        "load_config",
        lambda flag: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda _eng: "anonymous")

    coverage_posts: list[dict] = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def post(self, endpoint, payload):
            if endpoint == "request-observations":
                return {"request_variant": {"id": variant_id}, "service": {"id": 9}}
            if endpoint == "coverage-items":
                coverage_posts.append(payload)
                return {"id": len(coverage_posts), **payload}
            return {}

        def close(self):
            pass

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    endpoints_file = tmp_path / "endpoints.txt"
    endpoints_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    module.run(SimpleNamespace(
        db_path=str(db_path),
        source="recon",
        input_file=str(endpoints_file),
        engagement_dir=str(tmp_path),
        egress_blocked_hosts=None,
    ))
    return coverage_posts


def test_ingest_bridges_single_gf_bucket_to_coverage_item(monkeypatch, tmp_path):
    """2b: an endpoint classifying to the idor bucket POSTs a class-typed
    coverage_item with attack_family='idor' (additive to the generic baseline)."""
    posts = _run_ingest_bridge(
        monkeypatch,
        tmp_path,
        ['{"url": "https://shop.example.com/api/users/1024/profile", "method": "GET"}'],
    )
    families = {p["attack_family"] for p in posts}
    assert "idor" in families
    idor_post = next(p for p in posts if p["attack_family"] == "idor")
    assert idor_post["request_variant_id"] == 501


def test_ingest_bridges_two_buckets_to_two_coverage_items(monkeypatch, tmp_path):
    """2b/S14: a URL matching TWO gf buckets (idor + ssrf) yields TWO class-typed
    coverage_items — not just the cluster winner."""
    posts = _run_ingest_bridge(
        monkeypatch,
        tmp_path,
        ['{"url": "https://shop.example.com/api/fetch", "method": "GET", '
         '"query_params": {"id": "10", "url": "http://internal/"}}'],
    )
    families = {p["attack_family"] for p in posts}
    assert "idor" in families
    assert "ssrf" in families


def test_reason_tag_helpers_round_trip():
    cb = _classify_buckets()
    assert cb.tagged_terminal_reason("blackholed", "akamai 403") == "skipped:blackholed | akamai 403"
    assert cb.tagged_terminal_reason("duplicate", "") == "skipped:duplicate"
    assert cb.tagged_terminal_reason("", "plain text") == "plain text"
    assert cb.reason_tag_of("skipped:blackholed | akamai 403") == "blackholed"
    assert cb.reason_tag_of("inert_type") == "inert_type"
    assert cb.reason_tag_of("") == ""
    assert cb.reason_tag_of("egress-blocked: some prose") == "untagged"  # legacy free-text


def test_defer_cluster_reason_tag_stamps_structured_reason(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(db_path, queue_key="x:1", url_path="/s", cluster_key="gf:sqli")

    _run_dispatch(db_path, "defer-cluster", ["gf:sqli"], reason="akamai 403 wall",
                  reason_tag="blackholed")

    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute(
            "SELECT status, terminal_reason FROM work_items WHERE cluster_key = ?",
            ("gf:sqli",),
        ).fetchone()
    finally:
        conn.close()
    assert row == ("skipped", "skipped:blackholed | akamai 403 wall")


def test_dispatch_stats_by_reason_surfaces_untagged(tmp_path: Path, capsys) -> None:
    db_path = _make_fresh_db(tmp_path)
    # A tagged defer and an untagged (legacy free-text) defer.
    _insert_work_item(db_path, queue_key="a", url_path="/a", cluster_key="gf:sqli")
    _insert_work_item(db_path, queue_key="b", url_path="/b", cluster_key="gf:lfi")
    _run_dispatch(db_path, "defer-cluster", ["gf:sqli"], reason="wall", reason_tag="blackholed")
    _run_dispatch(db_path, "defer-cluster", ["gf:lfi"], reason="just dropped it")

    _run_dispatch(db_path, "stats", by="reason")
    out = capsys.readouterr().out
    assert "blackholed|1" in out
    assert "untagged|1" in out   # the un-reasoned drop is now visible


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


# The per-host budget tests (caps_content_rich_at_1000,
# api_tier_at_1000, sitemap_at_2000, override_via_dispatch_context) and the
# classify-work per_host_budget signal test were removed when the budget gate
# was deleted in the mid-engagement refactor — the silent 4,300-URL deferral
# bug they protected against no longer exists because all URLs now ingest
# (low-signal types stamp `status='skipped'`). The view tests below still
# exercise `work_items_per_host` directly so the view's port-stripping and
# IPv6 handling remain regression-protected.


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


def test_work_items_per_host_view_strips_explicit_port(tmp_path: Path) -> None:
    """B6 regression: URLs with an explicit port collapse onto the same host
    row as their portless siblings.

    The view used to extract host as ``example.com:8443`` while host
    aggregation lookups looked up the host via ``urlparse(url).hostname``
    (which never carries a port), silently disabling per-host counting for
    explicit-port URLs. The fix strips the port in the view's host
    expression so both forms aggregate on ``example.com``.
    """
    db_path = _make_fresh_db(tmp_path)

    conn = sqlite3.connect(str(db_path))
    try:
        # Same host with and without explicit port; uppercase variants too,
        # to confirm the lower() keeps working.
        conn.executemany(
            "INSERT INTO work_items (queue_key, method, url, url_path, type, source, status, priority_score) "
            "VALUES (?, 'GET', ?, '/x', 'page', 'test', 'pending', 0)",
            [
                ("p:1", "https://example.com:8443/api"),
                ("p:2", "https://example.com/other"),
                ("p:3", "https://EXAMPLE.com:9000/x"),
                ("p:4", "https://other.example/path"),
            ],
        )
        conn.commit()
        rows = list(
            conn.execute(
                "SELECT host, active_count FROM work_items_per_host ORDER BY host"
            )
        )
    finally:
        conn.close()

    rollup = dict(rows)
    assert rollup == {"example.com": 3, "other.example": 1}, rollup


def test_work_items_per_host_view_preserves_ipv6_literal(tmp_path: Path) -> None:
    db_path = _make_fresh_db(tmp_path)

    conn = sqlite3.connect(str(db_path))
    try:
        conn.executemany(
            "INSERT INTO work_items (queue_key, method, url, url_path, type, source, status, priority_score) "
            "VALUES (?, 'GET', ?, '/x', 'page', 'test', 'pending', 0)",
            [
                ("ipv6:1", "https://[2001:db8::1]:8443/api"),
                ("ipv6:2", "https://[2001:db8::1]/other"),
                ("ipv6:3", "https://[2001:db8::2]/x"),
            ],
        )
        conn.commit()
        rows = list(
            conn.execute(
                "SELECT host, active_count FROM work_items_per_host ORDER BY host"
            )
        )
    finally:
        conn.close()

    rollup = dict(rows)
    assert rollup == {"2001:db8::1": 2, "2001:db8::2": 1}, rollup


def test_egress_script_logic_handles_dead_hosts_and_empty_input() -> None:
    """B4/B5/B9 regression: the egress reputation bash script

    - drops the ``|| echo 000`` fallback that caused curl-failure to print
      ``"000\\n000"`` and break the comparison;
    - guards against zero alive hosts so the percentage calculation does
      not divide by zero;
    - excludes 000-status hosts from the alive-sample total so dead hosts
      are not counted as blocked.

    We exercise the script in-process by feeding canned curl exit codes
    through a small bash translation of the same logic. This ensures the
    reference doc's script is shape-correct without needing to spawn the
    runtime container.
    """
    import subprocess

    # Faithful translation of the bash conditional in
    # web-recon/SKILL.md and cdn-ip-blocking.md. The harness substitutes
    # codes for the curl call.
    def run(codes: list[str]) -> tuple[int, str]:
        codes_str = " ".join(codes) if codes else ""
        script = f"""
set -e
codes="{codes_str}"
blocked=0; total=0
for code in $codes; do
  case "$code" in
    000) ;;
    403) blocked=$((blocked+1)); total=$((total+1)) ;;
    *)   total=$((total+1)) ;;
  esac
done
if [ "$total" -eq 0 ]; then
  echo "egress check skipped: no live hosts to sample"
  exit 0
fi
pct=$((blocked * 100 / total))
echo "egress_block_pct=$pct (blocked=$blocked alive=$total)"
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip()

    # All hosts dead — must skip cleanly, no division by zero.
    rc, out = run(["000", "000", "000"])
    assert rc == 0
    assert "egress check skipped" in out

    # Mixed dead/alive — dead excluded; only the 403 counts as blocked.
    rc, out = run(["000", "200", "403"])
    assert rc == 0
    assert "egress_block_pct=50 (blocked=1 alive=2)" in out

    # All 403 against alive hosts — 100% block rate.
    rc, out = run(["403", "403", "403"])
    assert rc == 0
    assert "egress_block_pct=100 (blocked=3 alive=3)" in out

    # Zero hosts (empty input) — must skip cleanly.
    rc, out = run([])
    assert rc == 0
    assert "egress check skipped" in out


def test_stamp_liveness_marks_claimed_rows(monkeypatch, tmp_path):
    """_stamp_liveness stamps live_status (verdict@age) from the ledger onto
    claimed rows, persists to cases.db, and is silent when there's no data."""
    import sqlite3 as _sql
    from types import SimpleNamespace
    module = _load_dispatch_module()

    conn = _sql.connect(":memory:")
    conn.row_factory = _sql.Row
    conn.execute("CREATE TABLE work_items (id INTEGER PRIMARY KEY, url TEXT, live_status TEXT)")
    conn.execute("INSERT INTO work_items (id, url, live_status) VALUES (1, 'https://a.example.com/x', NULL)")
    conn.execute("INSERT INTO work_items (id, url, live_status) VALUES (2, 'https://b.example.com/y', NULL)")
    conn.commit()
    result = [{"id": 1, "url": "https://a.example.com/x"}, {"id": 2, "url": "https://b.example.com/y"}]

    class _FakeClient:
        def __init__(self, *a, **k): pass
        def get(self, endpoint):
            assert endpoint.startswith("host-liveness?host=")
            return [{"host": "a.example.com", "reachability_class": "live", "age_seconds": 540}]
        def close(self): pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module.work_items, "AssessmentClient", _FakeClient)
    module._stamp_liveness(conn, result, SimpleNamespace(base_url="http://x", engagement_key="eng"))

    # a got stamped (540s -> 9m); b had no ledger row -> untouched.
    assert result[0]["live_status"] == "live@9m"
    assert "live_status" not in result[1]
    db_a = conn.execute("SELECT live_status FROM work_items WHERE id = 1").fetchone()[0]
    db_b = conn.execute("SELECT live_status FROM work_items WHERE id = 2").fetchone()[0]
    assert db_a == "live@9m" and db_b is None


def test_stamp_liveness_best_effort_skips(monkeypatch, tmp_path):
    """No cfg, or a backend error, must not raise (the fetch still succeeds)."""
    import sqlite3 as _sql
    from types import SimpleNamespace
    module = _load_dispatch_module()
    conn = _sql.connect(":memory:")
    conn.execute("CREATE TABLE work_items (id INTEGER PRIMARY KEY, url TEXT, live_status TEXT)")
    result = [{"id": 1, "url": "https://a.example.com/x"}]

    module._stamp_liveness(conn, result, None)            # no cfg → no-op
    assert "live_status" not in result[0]

    class _Boom:
        def __init__(self, *a, **k): raise RuntimeError("backend down")
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False
    monkeypatch.setattr(module.work_items, "AssessmentClient", _Boom)
    module._stamp_liveness(conn, result, SimpleNamespace(base_url="http://x", engagement_key="eng"))
    assert "live_status" not in result[0]   # swallowed, no raise


def test_work_buffer_cli_wires_reason_tag_and_by_reason(tmp_path, capsys):
    """Drive the REAL `vigil assess work-buffer` argparse (not a hand-built
    namespace) — proves --reason-tag and --by reason are wired into the
    operator-facing verb, not just the legacy dispatch register."""
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.cli as cli

    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(db_path, queue_key="x", url_path="/s", cluster_key="gf:sqli")

    cli.main(["work-buffer", str(db_path), "defer-cluster", "gf:sqli",
              "--reason", "akamai 403", "--reason-tag", "blackholed"])
    conn = sqlite3.connect(str(db_path))
    try:
        tr = conn.execute(
            "SELECT terminal_reason FROM work_items WHERE cluster_key='gf:sqli'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert tr == "skipped:blackholed | akamai 403"

    cli.main(["work-buffer", str(db_path), "stats", "--by", "reason"])
    assert "blackholed|1" in capsys.readouterr().out


def test_work_buffer_action_help_is_action_specific(tmp_path, capsys):
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.cli as cli

    db_path = _make_fresh_db(tmp_path)

    with pytest.raises(SystemExit) as exc:
        cli.main(["work-buffer", str(db_path), "peek", "url", "--help"])

    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Usage: vigil assess work-buffer <cases.db> peek <type> [limit]" in captured.out
    assert "defer-cluster" not in captured.out


def test_work_buffer_cli_defer_items_reason_tag(tmp_path):
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    import assess.cli as cli
    db_path = _make_fresh_db(tmp_path)
    iid = _insert_work_item(db_path, queue_key="y", url_path="/y", cluster_key="gf:lfi")
    cli.main(["work-buffer", str(db_path), "defer-items", str(iid),
              "--reason", "dup", "--reason-tag", "duplicate"])
    conn = sqlite3.connect(str(db_path))
    try:
        tr = conn.execute("SELECT terminal_reason FROM work_items WHERE id=?", (iid,)).fetchone()[0]
    finally:
        conn.close()
    assert tr == "skipped:duplicate | dup"


def test_host_root_seed_does_not_block_consumption_gate(tmp_path):
    module = _load_script_module("test_scope_cov_module", "agent/scripts/assess/lib/coverage_checks.py")
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(db_path, queue_key="hr", url_path="/", url="https://seed.example.com/", case_type="host_root")
    _insert_work_item(db_path, queue_key="api", url_path="/api/x", url="https://real.example.com/api/x", case_type="api")
    by_host = module._load_work_items_by_host(Path(db_path))
    seed = by_host.get("seed.example.com", {})
    real = by_host.get("real.example.com", {})
    assert seed.get("pending", 0) == 1
    assert seed.get("pending_without_terminal_reason", 0) == 0   # seed excluded
    assert real.get("pending_without_terminal_reason", 0) == 1
    assert module._consumption_satisfied(seed, "active") is True     # gate passes for seed-only host
    assert module._consumption_satisfied(real, "active") is False    # still fails for real uncovered work


def test_stamp_liveness_clamps_negative_age(monkeypatch):
    import sqlite3 as _sql
    from types import SimpleNamespace
    module = _load_dispatch_module()
    conn = _sql.connect(":memory:")
    conn.execute("CREATE TABLE work_items (id INTEGER PRIMARY KEY, url TEXT, live_status TEXT)")
    result = [{"id": 1, "url": "https://a.example.com/x"}]

    class _C:
        def __init__(self, *a, **k): pass
        def get(self, e): return [{"host": "a.example.com", "reachability_class": "live", "age_seconds": -999.0}]
        def close(self): pass
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            self.close()
            return False

    monkeypatch.setattr(module.work_items, "AssessmentClient", _C)
    module._stamp_liveness(conn, result, SimpleNamespace(base_url="x", engagement_key="e"))
    assert result[0]["live_status"] == "live"   # negative age → no nonsense @-NNNm suffix




def test_s13_nested_versioned_api_doc_paths_classify_as_api_spec() -> None:
    """S13: the API-doc classifier must match nested/versioned doc paths, not
    only top-level ones — a missed spec means its whole endpoint inventory is
    never ingested."""
    module = _load_classify_lib_module()
    nested = [
        "/api/swagger.json",
        "/v2/openapi.json",
        "/docs/openapi.json",
        "/docs/swagger.yaml",
        "/api/v1/api-docs",
    ]
    for path in nested:
        assert module.classify_type("GET", path, "", "") == "api-spec", path
    assert module.classify_type("GET", "/openapi.json", "", "") == "api-spec"
    assert module.classify_type("GET", "/swagger-ui.html", "", "") == "api-spec"
    assert module.classify_type("GET", "/myopenapi", "", "") != "api-spec"
    assert module.classify_type("GET", "/swaggerings/x", "", "") != "api-spec"


def test_s15_sourcemap_not_in_inert_set() -> None:
    """S15: sourcemap is no longer terminally inert."""
    cb = _classify_buckets()
    assert "sourcemap" not in cb.INERT_TYPES
    db = _load_db_module()
    assert "sourcemap" not in db._SKIP_TYPES


def test_s15_sourcemap_classifies_to_secret_surface_not_inert(tmp_path: Path) -> None:
    """S15: a sourcemap row classifies to a real, non-inert secret/JS surface
    that downstream analysis can act on (kept pending, no inert terminal_reason)."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="sm:1",
        url_path="/static/app.js.map",
        case_type="sourcemap",
    )
    _run_classify(db_path)
    row = _classify_one(db_path, "sm:1")
    assert row[0] == "gf:interestingext"
    assert row[1] > 0
    assert row[2] == "gf:interestingext"
    assert row[3] is None

    conn = sqlite3.connect(str(db_path))
    try:
        status = conn.execute(
            "SELECT status FROM work_items WHERE queue_key = ?", ("sm:1",)
        ).fetchone()[0]
    finally:
        conn.close()
    assert status == "pending"


def test_s20_admin_fragment_is_segment_anchored_not_substring() -> None:
    """S20: `/administration-guide` must NOT match the `/admin` risk fragment,
    while `/admin` and `/admin/...` still do."""
    cb = _classify_buckets()
    assert cb.fragment_in_path("/admin", "/administration-guide") is False
    assert cb.fragment_in_path("/admin", "/admin") is True
    assert cb.fragment_in_path("/admin", "/admin/users") is True
    assert cb.fragment_in_path("/admin", "/v1/admin?x=1") is True
    assert cb.fragment_in_path(".env", "/.environment") is False
    assert cb.fragment_in_path(".env", "/app/.env") is True
    assert cb.fragment_in_path(".config", "/app.configuration") is False
    assert cb.fragment_in_path("/proxy/", "/proxy/fetch") is True
    assert cb.fragment_in_path("/proxy/", "/proxyfoo") is False


def test_s20_administration_guide_does_not_bucket_as_debug_logic(tmp_path: Path) -> None:
    """End-to-end S20: a `/administration-guide` doc page no longer falls into
    the `/admin` (debug_logic) bucket — it lands in the path fallback."""
    db_path = _make_fresh_db(tmp_path)
    _insert_work_item(
        db_path,
        queue_key="adminguide",
        url_path="/administration-guide/getting-started",
    )
    _insert_work_item(
        db_path,
        queue_key="realadmin",
        url_path="/admin/users",
    )
    _run_classify(db_path)
    guide = _classify_one(db_path, "adminguide")
    real = _classify_one(db_path, "realadmin")
    assert not str(guide[0]).startswith("gf:")
    assert real[0] == "gf:debug_logic"


def test_s12_ingest_endpoints_admits_ip_localhost_ipv6_and_skips_malformed(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """S12: IP / localhost / bracketed-IPv6 endpoint lines now ingest (they used
    to pass through schemeless and fail the POST), template/fuzz lines WARN
    instead of dropping silently, and a genuinely malformed line is skipped with
    a WARN rather than failing the POST."""
    module = _load_ingest_module()
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")
    db_path = engagement_dir / "cases.db"
    db_path.touch()
    _load_db_module().db_init(str(db_path))

    input_file = tmp_path / "endpoints.txt"
    input_file.write_text(
        "\n".join(
            [
                "10.0.0.5/admin",
                "127.0.0.1:8080/api/login",
                "localhost/dashboard",
                "[::1]:8080/health",
                "https://app.example.com/x",
                "/relative/only",
                "GET FUZZ/path",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda _eng_dir: "anonymous")

    posted_hosts: list[str] = []

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def post(self, endpoint, payload):
            posted_hosts.append(payload.get("target_hostname"))
            return {"request_variant": {"id": 100 + len(posted_hosts)}}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            db_path=str(db_path),
            source="recon",
            input_file=str(input_file),
            engagement_dir=str(engagement_dir),
            egress_blocked_hosts=None,
        )
    )

    captured = capsys.readouterr()
    assert "10.0.0.5" in posted_hosts
    assert "127.0.0.1" in posted_hosts
    assert "localhost" in posted_hosts
    assert "::1" in posted_hosts
    assert "app.example.com" in posted_hosts

    conn = sqlite3.connect(str(db_path))
    try:
        ingested = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
    finally:
        conn.close()
    assert ingested == 5

    assert "malformed endpoint line" in captured.err
    assert "template/fuzz-marker" in captured.err
    assert "Skipped" in captured.err
