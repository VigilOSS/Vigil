"""File status projection scales linearly with retained reanalysis history."""

from __future__ import annotations

import pytest

from app import db
from app.services import code_analysis_support as support
from test_code_analysis_api import _record_fixture_source_receipt
from test_code_queue_path_scope import _seed


@pytest.mark.parametrize("latest_status", ["done", "processing"])
def test_file_status_reuses_current_attempt_with_large_receipt_history(
    client, isolate_settings, latest_status
):
    key = "2026-11-08-acme-attempt-rollup"
    base, _, _ = _seed(client, isolate_settings, key)
    claimed = client.post(
        base + "/analysis-queue/fetch", json={"limit": 1, "agent_name": "acme-reviewer"}
    )
    assert claimed.status_code == 200, claimed.text
    claim = claimed.json()[0]
    _record_fixture_source_receipt(client, key, claim)
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET status='done', disposition='clean' WHERE id=?",
            (claim["id"],),
        )
        queue = dict(
            connection.execute(
                "SELECT * FROM code_analysis_queue WHERE id=?", (claim["id"],)
            ).fetchone()
        )
        receipt = dict(
            connection.execute(
                "SELECT * FROM code_analysis_results WHERE queue_item_id=?",
                (claim["id"],),
            ).fetchone()
        )
        queue_columns = [name for name in queue if name != "id"]
        receipt_columns = [name for name in receipt if name != "id"]
        queue_insert = (
            "INSERT INTO code_analysis_queue ("
            + ",".join(queue_columns)
            + ") VALUES ("
            + ",".join("?" for _ in queue_columns)
            + ")"
        )
        receipt_insert = (
            "INSERT INTO code_analysis_results ("
            + ",".join(receipt_columns)
            + ") VALUES ("
            + ",".join("?" for _ in receipt_columns)
            + ")"
        )

        def project():
            instructions = []
            connection.set_progress_handler(lambda: instructions.append(1) or 0, 100)
            try:
                support._sync_file_analysis_status(
                    connection, int(queue["engagement_id"]), int(queue["file_id"])
                )
            finally:
                connection.set_progress_handler(None, 0)
            status = connection.execute(
                "SELECT analysis_status FROM code_files WHERE id=?", (queue["file_id"],)
            ).fetchone()[0]
            return len(instructions), status

        baseline_steps, _ = project()
        history_count = 400
        previous = int(queue["id"])
        for _ in range(history_count):
            queue["queue_mode"] = "reanalysis"
            queue["reanalysis_reason"] = "Acme repeated source review"
            queue["reanalysis_of_queue_item_id"] = previous
            latest = connection.execute(
                queue_insert, [queue[name] for name in queue_columns]
            ).lastrowid
            receipt["queue_item_id"] = latest
            connection.execute(
                receipt_insert, [receipt[name] for name in receipt_columns]
            )
            previous = int(latest)
        connection.execute(
            "UPDATE code_analysis_queue SET status=? WHERE id=?",
            (latest_status, previous),
        )
        steps, actual_status = project()
        assert actual_status == (
            "analyzed" if latest_status == "done" else "in_progress"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM code_analysis_results WHERE file_id=?",
                (queue["file_id"],),
            ).fetchone()[0]
            == history_count + 1
        )
        # Retained attempts can cost a linear scan, but every historical receipt
        # must not independently rescan that history to find the same current row.
        assert steps <= baseline_steps + history_count * 3, (baseline_steps, steps)
