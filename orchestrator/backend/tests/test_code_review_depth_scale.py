"""Review depth reads each prompt packet once, not once per review row joined to it."""
from __future__ import annotations

import sqlite3

from app.services import code_analysis_support as support
from test_code_analysis_api import db_module
from test_code_review_depth import _dispatch, _seed


def _counting_json_functions(
    connection: sqlite3.Connection, contexts: set[str], parsed: list[str]
) -> None:
    """Shadow the JSON built-ins, counting each parse of a prompt packet's context.

    Every other call (the review predicates read JSON too) is answered by the
    real built-in on a side connection and is not counted.
    """
    builtin = sqlite3.connect(":memory:")

    def json_valid(value):
        if value in contexts:
            parsed.append(value)
        return builtin.execute("SELECT json_valid(?)", (value,)).fetchone()[0]

    def json_extract(value, path):
        if value in contexts:
            parsed.append(value)
        return builtin.execute("SELECT json_extract(?, ?)", (value, path)).fetchone()[0]

    connection.create_function("json_valid", 1, json_valid)
    connection.create_function("json_extract", 2, json_extract)


def test_review_depth_parses_each_packet_once_however_many_reviews_ran_under_it(
    client, isolate_settings
):
    key = "2026-11-14-review-depth-scale"
    _base, ids = _seed(client, isolate_settings, key)
    # Most first passes ran as `hunter-1`; giving that agent a dispatch whose
    # packet says deep makes the per-row form parse that packet once per joined
    # review row.
    _dispatch(
        client,
        key,
        "hunter-1",
        dispatch_mode="item-iterating",
        prompt_packet={
            "schema": "dispatch-prompt/v1",
            "context": {"hunt_scope": "deep", "target": "src"},
            "rendered_prompt": "## Dispatch Mindset\nhunt_scope: deep\n",
        },
    )
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.row_factory = sqlite3.Row
        engagement_id = int(
            connection.execute(
                "SELECT engagement_id FROM code_files WHERE id = ?", (ids["src/api.py"],)
            ).fetchone()[0]
        )
        under_packets = connection.execute(
            "SELECT COUNT(*) FROM code_analysis_queue WHERE engagement_id = ?"
            " AND assigned_agent IN ('hunter-1', 'code-hunter-scoped')",
            (engagement_id,),
        ).fetchone()[0]
        contexts = {
            str(row[0])
            for row in connection.execute(
                "SELECT context_json FROM assessment_dispatch_prompt_packets"
                " WHERE engagement_id = ?",
                (engagement_id,),
            )
        }
        packets = len(contexts)
        assert packets == 2 and under_packets >= 7

        parsed: list[str] = []
        _counting_json_functions(connection, contexts, parsed)
        rows = {
            int(row["file_id"]): dict(row)
            for row in connection.execute(
                support._review_depth_sql(), support.review_depth_params(engagement_id)
            )
        }

    # The depth verdict is unchanged: a pass under the deep packet is deep.
    for path in ("src/views.py", "src/auth.py", "src/api.py", "src/clean.py", "lib/low.py"):
        assert rows[ids[path]]["deep_passes"] == rows[ids[path]]["review_passes"] == 1, path
    # The deep-manual dispatch and the reanalysis stay deep; the trigger
    # requeue under `hunter-2` (no packet) stays wide.
    assert rows[ids["src/export.py"]]["deep_passes"] == 1
    assert rows[ids["src/parser.py"]]["deep_passes"] == 2
    assert rows[ids["src/util.py"]]["review_passes"] == 2
    assert rows[ids["src/util.py"]]["deep_passes"] == 1
    # One validity check and one extraction per packet, independent of the
    # number of review rows that ran under it.
    assert len(parsed) <= 2 * packets, (len(parsed), under_packets)
