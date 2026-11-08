"""Current review projections do not repeatedly search retained attempt history."""

from __future__ import annotations

import pytest

from app import db
from app.services import code_analysis_support as support
from test_code_analysis_api import _owned, _record_fixture_source_receipt
from test_code_queue_path_scope import _seed


@pytest.fixture
def completed_review(client, isolate_settings):
    key = "2026-11-08-acme-terminal-history"
    base, _, _ = _seed(client, isolate_settings, key)
    response = client.post(
        base + "/analysis-queue/fetch", json={"limit": 1, "agent_name": "acme-reviewer"}
    )
    assert response.status_code == 200, response.text
    claim = response.json()[0]
    _record_fixture_source_receipt(client, key, claim)
    response = client.post(
        base + "/analysis-queue/done",
        json=_owned(
            claim,
            item_ids=[claim["id"]],
            disposition="clean",
            notes="Acme source reviewed",
            cwe_coverage=[
                {"family": family, "effort": 80}
                for family in claim["applicable_vuln_classes"]
            ],
        ),
    )
    assert response.status_code == 200, response.text
    with db.get_connection() as connection:
        queue = dict(
            connection.execute(
                "SELECT * FROM code_analysis_queue WHERE id=?", (claim["id"],)
            ).fetchone()
        )
        yield connection, queue


def _append_attempt(connection, previous):
    row = dict(
        previous,
        queue_mode="reanalysis",
        reanalysis_reason="Acme source re-review",
        reanalysis_of_queue_item_id=previous["id"],
    )
    columns = [name for name in row if name != "id"]
    row["id"] = connection.execute(
        "INSERT INTO code_analysis_queue ("
        + ",".join(columns)
        + ") VALUES ("
        + ",".join("?" for _ in columns)
        + ")",
        [row[name] for name in columns],
    ).lastrowid
    for previous_receipt in connection.execute(
        "SELECT * FROM code_analysis_results WHERE queue_item_id=?", (previous["id"],)
    ).fetchall():
        receipt = dict(previous_receipt, queue_item_id=row["id"])
        receipt_columns = [name for name in receipt if name != "id"]
        receipt_id = connection.execute(
            "INSERT INTO code_analysis_results ("
            + ",".join(receipt_columns)
            + ") VALUES ("
            + ",".join("?" for _ in receipt_columns)
            + ")",
            [receipt[name] for name in receipt_columns],
        ).lastrowid
        for previous_link in connection.execute(
            "SELECT * FROM code_analysis_result_callables WHERE result_id=?",
            (receipt["id"],),
        ).fetchall():
            link = dict(previous_link, result_id=receipt_id)
            link_columns = list(link)
            connection.execute(
                "INSERT INTO code_analysis_result_callables ("
                + ",".join(link_columns)
                + ") VALUES ("
                + ",".join("?" for _ in link_columns)
                + ")",
                [link[name] for name in link_columns],
            )
    return row


def _project(connection, engagement_id):
    return connection.execute(
        "SELECT files.id, ("
        + support._CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL
        + ") AS reviewed, ("
        + support._CURRENT_ACCOUNTED_FILE_EXISTS_SQL
        + ") AS accounted FROM code_files AS files WHERE files.engagement_id=? ORDER BY files.id",
        (engagement_id,),
    ).fetchall()


def test_terminal_review_projection_searches_latest_attempt_once_per_file(
    completed_review,
):
    connection, queue = completed_review

    def measured():
        steps = []
        connection.set_progress_handler(lambda: steps.append(1) or 0, 100)
        try:
            rows = _project(connection, queue["engagement_id"])
        finally:
            connection.set_progress_handler(None, 0)
        return len(steps), [tuple(row) for row in rows]

    baseline_steps, expected = measured()
    assert sum(row[1] for row in expected) == 1
    attempts = 400
    for _ in range(attempts):
        queue = _append_attempt(connection, queue)
    steps, actual = measured()
    assert actual == expected
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE file_id=?",
            (queue["file_id"],),
        ).fetchone()[0]
        == attempts + 1
    )
    assert steps <= baseline_steps + attempts * 5, (baseline_steps, steps)


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("clean", (1, 1)),
        ("pending", (0, 0)),
        ("processing", (0, 0)),
        ("error", (0, 0)),
        ("needs_context", (0, 0)),
        ("skipped", (0, 1)),
        ("unexplained_skip", (0, 0)),
        ("suspicious", (1, 1)),
        ("wrong_lease", (0, 0)),
        ("stale_receipt", (0, 0)),
        ("superseded_receipt", (0, 0)),
        ("unbound_finding", (0, 0)),
        ("unclaimed", (0, 0)),
        ("incomplete", (0, 0)),
        ("stale_generation", (0, 0)),
        ("overlapping_active", (0, 0)),
        ("superseded_latest", (1, 1)),
        ("other_generation_latest", (1, 1)),
    ],
)
def test_terminal_review_projection_preserves_currentness_and_receipt_gates(
    completed_review, case, expected
):
    connection, original = completed_review
    latest = _append_attempt(connection, original)
    item_id = latest["id"]
    if case in {"pending", "processing", "error", "needs_context"}:
        connection.execute(
            "UPDATE code_analysis_queue SET status=? WHERE id=?", (case, item_id)
        )
    elif case in {"skipped", "unexplained_skip"}:
        connection.execute(
            "UPDATE code_analysis_queue SET disposition='skipped', skip_reason=? WHERE id=?",
            ("Acme generated file" if case == "skipped" else "", item_id),
        )
    elif case in {"suspicious", "wrong_lease", "stale_receipt", "superseded_receipt"}:
        connection.execute(
            "UPDATE code_analysis_queue SET disposition='suspicious' WHERE id=?",
            (item_id,),
        )
        connection.execute(
            "UPDATE code_analysis_results SET disposition='suspicious' WHERE queue_item_id=?",
            (item_id,),
        )
        if case == "wrong_lease":
            connection.execute(
                "UPDATE code_analysis_results SET lease_token='other-acme-lease' WHERE queue_item_id=?",
                (item_id,),
            )
        elif case == "stale_receipt":
            connection.execute(
                "UPDATE code_analysis_results SET repo_generation=repo_generation+1 WHERE queue_item_id=?",
                (item_id,),
            )
        elif case == "superseded_receipt":
            connection.execute(
                "UPDATE code_analysis_results SET superseded_at='2026-11-08T00:00:00Z' WHERE queue_item_id=?",
                (item_id,),
            )
    elif case == "unbound_finding":
        connection.execute(
            "UPDATE code_analysis_queue SET disposition='finding' WHERE id=?",
            (item_id,),
        )
    elif case == "unclaimed":
        connection.execute(
            "UPDATE code_analysis_queue SET assigned_agent='' WHERE id=?", (item_id,)
        )
    elif case == "incomplete":
        connection.execute(
            "UPDATE code_analysis_queue SET completed_at=NULL WHERE id=?", (item_id,)
        )
    elif case == "stale_generation":
        connection.execute(
            "UPDATE code_repos SET active_generation=active_generation+1"
        )
    elif case == "overlapping_active":
        connection.execute(
            "UPDATE code_analysis_queue SET status='processing' WHERE id=?",
            (original["id"],),
        )
    elif case == "superseded_latest":
        connection.execute(
            "UPDATE code_analysis_queue SET source_superseded_at='2026-11-08T00:00:00Z' WHERE id=?",
            (item_id,),
        )
    elif case == "other_generation_latest":
        connection.execute(
            "UPDATE code_analysis_queue SET repo_generation=repo_generation+1 WHERE id=?",
            (item_id,),
        )
    rows = _project(connection, original["engagement_id"])
    actual = next(
        (int(row["reviewed"]), int(row["accounted"]))
        for row in rows
        if row["id"] == original["file_id"]
    )
    assert actual == expected
