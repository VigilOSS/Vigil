"""Per-file trigger and per-finding decision lookups seek; they never walk the table.

Cross-file triggers are synced per reviewed file and carried forward per
reanalysis, and the submission views read the latest QC / blind-triage decision
per finding. Each of those lookups ran over every trigger or every decision of
its kind, so a large code engagement (tens of thousands of triggers) or a long
submission history paid table size x calls. The step counts below are SQLite VM
steps from a progress handler: deterministic, and proportional to rows visited.
"""
from __future__ import annotations

import json
import re
import sqlite3

import pytest

from app import db as db_module
from app.services import code_analysis
from app.services import code_analysis_support as support
from app.services import submission_versions
from test_code_queue_path_scope import _seed


def _steps(connection, call) -> tuple[int, object]:
    steps: list[int] = []
    connection.set_progress_handler(lambda: steps.append(1) or 0, 100)
    try:
        result = call()
    finally:
        connection.set_progress_handler(None, 0)
    return len(steps), result


def _plan(connection, sql: str, parameters=()) -> list[str]:
    return [str(row[3]) for row in connection.execute("EXPLAIN QUERY PLAN " + sql, parameters).fetchall()]


def _trigger_lines(plans: list[list[str]]) -> list[str]:
    return [
        line
        for plan in plans
        for line in plan
        if re.match(r"^(?:SCAN|SEARCH) (?:code_analysis_triggers|triggers|t)\b", line)
    ]


def _add_unrelated_triggers(connection, engagement_id: int, template: dict, start: int, count: int) -> None:
    """Pending triggers aimed at other files of the same engagement."""
    columns = [column for column in template if column != "id"]
    connection.executemany(
        f"INSERT INTO code_analysis_triggers ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
        [
            [
                {
                    "target_file_id": None,
                    "target_file_path": f"acme/elsewhere-{index}.py",
                    "resolved_queue_item_id": None,
                    "status": "pending",
                }.get(column, template[column])
                for column in columns
            ]
            for index in range(start, start + count)
        ],
    )


@pytest.fixture
def trigger_engagement(client, isolate_settings):
    key = "2026-11-14-acme-trigger-scale"
    _base, file_ids, item_ids = _seed(client, isolate_settings, key)
    with db_module.get_connection() as connection:
        source = connection.execute(
            "SELECT * FROM code_files WHERE id = ?", (file_ids["src/auth/login.py"],)
        ).fetchone()
        engagement_id = int(source["engagement_id"])
        repo = connection.execute(
            "SELECT active_generation FROM code_repos WHERE id = ?", (int(source["repo_id"]),)
        ).fetchone()
        connection.execute(
            """
            INSERT INTO code_analysis_triggers (
                engagement_id, source_queue_item_id, source_file_id, target_file_id,
                target_file_path, vuln_class, reason, status, repo_id, repo_generation
            ) VALUES (?, ?, ?, ?, ?, 'sqli', 'Acme caller passes raw input', 'pending', ?, ?)
            """,
            (
                engagement_id,
                item_ids["src/auth/login.py"],
                int(source["id"]),
                file_ids["src/billing/refund.py"],
                "src/billing/refund.py",
                int(source["repo_id"]),
                int(repo["active_generation"]),
            ),
        )
        template = dict(
            connection.execute("SELECT * FROM code_analysis_triggers ORDER BY id DESC LIMIT 1").fetchone()
        )
    return engagement_id, file_ids, item_ids, template


def test_trigger_sync_for_one_file_does_not_grow_with_other_files_triggers(trigger_engagement):
    engagement_id, file_ids, _item_ids, template = trigger_engagement
    target = file_ids["src/billing/refund.py"]
    with db_module.get_connection() as connection:
        connection.execute("SAVEPOINT acme_scale")
        try:
            _add_unrelated_triggers(connection, engagement_id, template, 0, 300)
            small, _ = _steps(connection, lambda: support._sync_trigger_status_for_file(connection, engagement_id, target))
            _add_unrelated_triggers(connection, engagement_id, template, 300, 2700)
            large, _ = _steps(connection, lambda: support._sync_trigger_status_for_file(connection, engagement_id, target))
            status = connection.execute(
                "SELECT status FROM code_analysis_triggers WHERE id = ?", (int(template["id"]),)
            ).fetchone()[0]
        finally:
            connection.execute("ROLLBACK TO acme_scale")
            connection.execute("RELEASE acme_scale")

    assert status == "pending"
    # Ten times the unrelated triggers must not cost ten times the work.
    assert large <= 2 * small + 10, (small, large)


def test_trigger_carry_forward_does_not_grow_with_other_files_triggers(trigger_engagement):
    engagement_id, _file_ids, item_ids, template = trigger_engagement
    attempt = item_ids["src/billing/refund.py"]
    with db_module.get_connection() as connection:
        connection.execute("SAVEPOINT acme_scale")
        try:
            _add_unrelated_triggers(connection, engagement_id, template, 0, 300)

            def carry():
                return code_analysis._carry_trigger_bindings_forward(
                    connection, engagement_id, predecessor_id=attempt, successor_id=attempt
                )

            small, carried_small = _steps(connection, carry)
            _add_unrelated_triggers(connection, engagement_id, template, 300, 2700)
            large, carried_large = _steps(connection, carry)
        finally:
            connection.execute("ROLLBACK TO acme_scale")
            connection.execute("RELEASE acme_scale")

    assert carried_small == carried_large == []
    assert large <= 2 * small + 10, (small, large)


@pytest.mark.parametrize(
    ("parent_delete", "column"),
    [
        ("DELETE FROM code_analysis_queue WHERE id = 1", "resolved_queue_item_id"),
        ("DELETE FROM code_files WHERE id = 1", "target_file_id"),
    ],
)
def test_parent_delete_seeks_set_null_trigger_children(
    client, isolate_settings, parent_delete: str, column: str
) -> None:
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        plan = _plan(connection, parent_delete)

    assert any(
        line.startswith("SEARCH code_analysis_triggers") and f"({column}=?)" in line for line in plan
    ), plan


def _seed_decisions(connection, engagement_id: int, start: int, count: int) -> None:
    connection.executemany(
        "INSERT INTO assessment_dispatch_decisions (engagement_id, kind, payload_json, created_at) "
        "VALUES (?, ?, ?, '2026-11-14T00:00:00Z')",
        [
            (
                engagement_id,
                ("submission_qc_verdict", "blind_triage_verdict")[index % 2],
                json.dumps({"finding_slug": f"VA-{1000 + index}", "verdict": "pass"}),
            )
            for index in range(start, start + count)
        ],
    )


def test_latest_decision_per_finding_seeks_by_slug(trigger_engagement):
    engagement_id = trigger_engagement[0]
    with db_module.get_connection() as connection:
        connection.execute("SAVEPOINT acme_decisions")
        try:
            _seed_decisions(connection, engagement_id, 0, 400)

            def latest(slug: str):
                return submission_versions._latest_decision(
                    engagement_id, "submission_qc_verdict", slug, connection
                )

            small, found_small = _steps(connection, lambda: latest("VA-1000"))
            missing_small, _ = _steps(connection, lambda: latest("VA-NONE"))
            _seed_decisions(connection, engagement_id, 400, 3600)
            large, found_large = _steps(connection, lambda: latest("VA-1000"))
            missing_large, missing = _steps(connection, lambda: latest("VA-NONE"))
            newest = latest("VA-4998")
        finally:
            connection.execute("ROLLBACK TO acme_decisions")
            connection.execute("RELEASE acme_decisions")

    assert found_small is not None and found_large is not None
    assert json.loads(found_large["payload_json"])["finding_slug"] == "VA-1000"
    assert missing is None
    assert json.loads(newest["payload_json"])["finding_slug"] == "VA-4998"
    assert large <= 2 * small + 10, (small, large)
    assert missing_large <= 2 * missing_small + 10, (missing_small, missing_large)


def test_existing_database_gains_the_lookup_indexes_on_startup(client, isolate_settings) -> None:
    db_path = db_module.database_path()

    def lookup_indexes() -> set[str]:
        with sqlite3.connect(str(db_path)) as connection:
            return {
                str(row[1])
                for table in ("code_analysis_triggers", "assessment_dispatch_decisions")
                for row in connection.execute(f"PRAGMA index_list({table})").fetchall()
                if not str(row[1]).startswith("sqlite_autoindex")
            }

    fresh = lookup_indexes()
    assert len(fresh) >= 5, fresh
    with sqlite3.connect(str(db_path)) as connection:
        for name in fresh - {"idx_decisions_engagement_kind"}:
            connection.execute(f"DROP INDEX {name}")
    db_module.close_thread_connection()
    db_module._startup_database_fingerprint = None

    db_module.init_db()

    assert lookup_indexes() == fresh
