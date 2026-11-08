"""Coverage retains every file without one SQL parameter per corpus entry."""
from __future__ import annotations

import sqlite3

import pytest

from app import db
from app.services import code_analysis
from app.services import code_analysis_support as support
from test_code_queue_path_scope import _seed


def _copy_files(connection, count, *, module_id=None):
    original = dict(connection.execute("SELECT * FROM code_files LIMIT 1").fetchone())
    columns = [column for column in original if column != "id"]
    query = (
        "INSERT INTO code_files (" + ",".join(columns) + ") VALUES ("
        + ",".join("?" for _ in columns) + ")"
    )
    for index in range(count):
        row = dict(original, file_path=f"acme/module-{index}/config.php", module_id=module_id)
        connection.execute(query, [row[column] for column in columns])
    return int(original["engagement_id"]), int(original["repo_id"])


@pytest.mark.parametrize("projection", ["summary", "families", "top_level", "structural_gaps", "selected_files", "variant_scope"])
def test_coverage_preserves_corpus_beyond_sql_variable_limit(client, isolate_settings, projection):
    _seed(client, isolate_settings, f"2026-11-08-acme-sql-{projection}")
    with db.get_connection() as connection:
        engagement_id, _ = _copy_files(connection, 200)
        file_ids = [int(row[0]) for row in connection.execute("SELECT id FROM code_files")]

    def read():
        if projection == "summary":
            return code_analysis.code_coverage_summary(engagement_id)
        if projection == "families":
            return code_analysis.code_coverage_cwe_detail(engagement_id)
        with db.get_connection() as connection:
            if projection == "variant_scope":
                return code_analysis._load_variant_receipt_projection(
                    connection, engagement_id,
                    file_rows=[dict(row) for row in connection.execute("SELECT * FROM code_files")],
                    restrict_to_files=True,
                )
            if projection == "selected_files":
                return support._get_file_rows(connection, engagement_id, set(file_ids))
            if projection == "top_level":
                return support._current_top_level_spans(connection, engagement_id, file_ids)
            return support.structural_review_gaps(
                connection, engagement_id, file_ids,
                support._current_result_receipt_sql(
                    "results", "result_queue", "result_files", "result_repos",
                    allow_processing=False
                ),
            )

    with db.get_connection() as connection:
        previous = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 128)
    try:
        actual = read()
    finally:
        with db.get_connection() as connection:
            connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous)
    assert actual == read()


def test_module_rollup_work_is_bounded_by_module_not_engagement(client, isolate_settings):
    _seed(client, isolate_settings, "2026-11-08-acme-rollup")
    with db.get_connection() as connection:
        row = connection.execute("SELECT engagement_id, repo_id FROM code_files LIMIT 1").fetchone()
        engagement_id, repo_id = int(row[0]), int(row[1])
        modules = [int(connection.execute(
            "INSERT INTO code_modules (engagement_id, repo_id, module_key, name) VALUES (?, ?, ?, ?)",
            (engagement_id, repo_id, key, key),
        ).lastrowid) for key in ("acme-selected", "acme-other")]
        connection.execute("UPDATE code_files SET module_id=?", (modules[0],))

        def rollup_steps():
            steps = []
            connection.set_progress_handler(lambda: steps.append(1) or 0, 100)
            try:
                support._sync_module_rollup(connection, engagement_id, modules[0])
            finally:
                connection.set_progress_handler(None, 0)
            return len(steps)

        before = rollup_steps()
        _copy_files(connection, 2000, module_id=modules[1])
        after = rollup_steps()
        module = dict(connection.execute("SELECT * FROM code_modules WHERE id=?", (modules[0],)).fetchone())
        assert module["file_count"] == 5
        assert module["analysis_status"] == "queued"
        assert after <= before + 10, (before, after)


def test_existing_database_gets_bounded_module_rollups(client, isolate_settings):
    _seed(client, isolate_settings, "2026-11-08-acme-module-upgrade")
    with db.get_connection() as connection:
        before = connection.execute("SELECT COUNT(*) FROM code_files").fetchone()[0]
        connection.execute("DROP INDEX IF EXISTS idx_code_files_module_rollup")
    db.init_db()
    with db.get_connection() as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT analysis_status, COUNT(*) FROM code_files "
            "WHERE engagement_id=? AND module_id=? AND retired_at IS NULL GROUP BY analysis_status",
            (1, 1),
        ).fetchall()
        assert any("module_id=?" in str(row[3]) for row in plan), [tuple(row) for row in plan]
        assert connection.execute("SELECT COUNT(*) FROM code_files").fetchone()[0] == before


@pytest.mark.parametrize("action", ["claim", "queue"])
def test_queue_operation_rolls_up_each_affected_module_once(client, isolate_settings, monkeypatch, action):
    from contextlib import contextmanager
    base, file_ids, _ = _seed(client, isolate_settings, "2026-11-08-acme-claim-modules")
    with db.get_connection() as connection:
        row = connection.execute("SELECT engagement_id, repo_id FROM code_files LIMIT 1").fetchone()
        module_id = connection.execute(
            "INSERT INTO code_modules (engagement_id, repo_id, module_key, name) VALUES (?, ?, ?, ?)",
            (row[0], row[1], "acme-batch", "Acme batch"),
        ).lastrowid
        connection.execute("UPDATE code_files SET module_id=?", (module_id,))
    statements = []
    get_connection = code_analysis.get_connection

    @contextmanager
    def traced_connection():
        with get_connection() as connection:
            connection.set_trace_callback(statements.append)
            try:
                yield connection
            finally:
                connection.set_trace_callback(None)

    monkeypatch.setattr(code_analysis, "get_connection", traced_connection)
    if action == "claim":
        response = client.post(base + "/analysis-queue/fetch", json={"limit": 5, "agent_name": "acme-hunter"})
        assert response.status_code == 200, response.text
        assert len(response.json()) == 5
    else:
        response = client.post(base + "/analysis-queue", json={"items": [
            {"file_id": file_id, "priority": 50, "batch_theme": "acme-wave"}
            for file_id in file_ids.values()
        ]})
        assert response.status_code == 201, response.text
        assert response.json()["updated"] == 5
    updates = [statement for statement in statements if statement.strip().startswith("UPDATE code_modules")]
    assert len(updates) == 1, updates
    with db.get_connection() as connection:
        module = connection.execute("SELECT file_count, analysis_status FROM code_modules WHERE id=?", (module_id,)).fetchone()
    assert tuple(module) == (5, "in_progress" if action == "claim" else "queued")
