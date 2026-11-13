"""Structural review proof work grows with the receipts it reads, not receipts x files."""
from __future__ import annotations

import json

from app import db
from app.services import code_analysis_support as support
from test_code_analysis_api import _owned
from test_code_queue_path_scope import _seed


def _insert_copy(connection, table: str, row: dict[str, object]) -> int:
    columns = [column for column in row if column != "id"]
    cursor = connection.execute(
        f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
        [row[column] for column in columns],
    )
    return int(cursor.lastrowid)


def _clone_reviewed_file(connection, file_row, queue_row, result_row, index: int) -> int:
    file_id = _insert_copy(
        connection, "code_files", dict(file_row, file_path=f"acme/clone-{index}/login.py")
    )
    token = f"acme-clone-lease-{index}"
    queue_id = _insert_copy(
        connection, "code_analysis_queue", dict(queue_row, file_id=file_id, lease_token=token)
    )
    spans = [dict(span, file_id=file_id) for span in json.loads(result_row["reviewed_spans_json"])]
    _insert_copy(
        connection,
        "code_analysis_results",
        dict(
            result_row,
            queue_item_id=queue_id,
            file_id=file_id,
            lease_token=token,
            supersedes_result_id=None,
            reviewed_spans_json=json.dumps(spans),
        ),
    )
    return file_id


def test_reviewed_span_proof_is_linear_in_current_receipts(client, isolate_settings):
    key = "2026-11-13-acme-span-scale"
    base, _, _ = _seed(client, isolate_settings, key)
    claim = client.post(
        base + "/analysis-queue/fetch", json={"limit": 1, "agent_name": "acme-reviewer"}
    ).json()[0]
    recorded = client.post(
        base + "/analysis-results",
        json=_owned(
            claim,
            queue_item_id=claim["id"],
            disposition="clean",
            evidence="Acme reviewed the exact current source.",
            reviewed_spans=[{"file_id": claim["file_id"], "start_line": 1, "end_line": 20}],
        ),
    )
    assert recorded.status_code == 201, recorded.text
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE code_analysis_queue SET status='done', disposition='clean' WHERE id=?",
            (claim["id"],),
        )
        file_row = dict(
            connection.execute("SELECT * FROM code_files WHERE id=?", (claim["file_id"],)).fetchone()
        )
        queue_row = dict(
            connection.execute("SELECT * FROM code_analysis_queue WHERE id=?", (claim["id"],)).fetchone()
        )
        result_row = dict(
            connection.execute(
                "SELECT * FROM code_analysis_results WHERE queue_item_id=?", (claim["id"],)
            ).fetchone()
        )
        engagement_id = int(file_row["engagement_id"])
        receipt = support._current_result_receipt_sql(
            "results", "result_queue", "result_files", "result_repos", allow_processing=False
        )
        reviewed = [int(claim["file_id"])]

        def proof_steps() -> tuple[int, tuple[set[int], set[int]]]:
            steps: list[int] = []
            connection.set_progress_handler(lambda: steps.append(1) or 0, 100)
            try:
                gaps = support.structural_review_gaps(connection, engagement_id, reviewed, receipt)
            finally:
                connection.set_progress_handler(None, 0)
            return len(steps), gaps

        for index in range(150):
            reviewed.append(_clone_reviewed_file(connection, file_row, queue_row, result_row, index))
        small, small_gaps = proof_steps()
        for index in range(150, 600):
            reviewed.append(_clone_reviewed_file(connection, file_row, queue_row, result_row, index))
        large, (owing, unproven) = proof_steps()

    # Each clone owes structural proof and its own reviewed span discharges it.
    assert small_gaps == (set(reviewed[:151]), set())
    assert owing == set(reviewed) and unproven == set()
    # Four times the receipts must cost about four times the work. Driving the span
    # file lookup from the engagement index once per receipt grows it ~16x instead.
    assert large <= 6 * small, (small, large)
