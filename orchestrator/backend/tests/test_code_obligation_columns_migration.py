"""An engagement database from before trigger origins and context tags upgrades.

`code_analysis_triggers.origin` and `code_files.context_tags_json` arrive through
the additive migration map. A long-lived database without them must start, keep
its rows, and read them as what they were: every trigger it holds was a
reviewer's cross-file hypothesis, and no file in it recorded context tags.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing

from app import db as db_module
from test_code_analysis_api import (
    _claim_file_for_analysis,
    _owned,
)
from test_code_depth_floor_triggers import _seed


def _columns(table: str) -> set[str]:
    with closing(sqlite3.connect(str(db_module.database_path()))) as connection:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}


def test_a_database_without_origin_or_context_tag_columns_upgrades_in_place(
    client, isolate_settings
):
    key = "2026-11-14-acme-obligation-columns"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    raised = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="parse() hands the raw body to the Acme helper.",
        cross_file_triggers=[{
            "file_path": "src/helpers.py", "vuln_class": "web-app-injection",
            "reason": "The helper may build a query from the raw body.",
        }],
    ))
    assert raised.status_code == 201, raised.text
    with closing(sqlite3.connect(str(db_module.database_path()))) as connection, connection:
        connection.execute("ALTER TABLE code_analysis_triggers DROP COLUMN origin")
        connection.execute("ALTER TABLE code_files DROP COLUMN context_tags_json")
    assert "origin" not in _columns("code_analysis_triggers")
    assert "context_tags_json" not in _columns("code_files")

    db_module.init_db()

    assert "origin" in _columns("code_analysis_triggers")
    assert "context_tags_json" in _columns("code_files")
    (trigger,) = client.get(f"{base}/triggers?status=pending").json()["items"]
    assert (trigger["origin"], trigger["target_file_path"]) == ("cross_file", "src/helpers.py")
    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert coverage["trigger_summary"]["pending"] == 1
    assert coverage["trigger_summary"]["depth_floor_pending"] == 0
    unrecorded = coverage["gate"]["context_tags_unrecorded"]
    assert unrecorded["by_classification"] == {"critical": 1, "low": 1}
    stored = client.get(f"{base}/files/{parser['id']}").json()
    assert stored["context_tags"] == [] and stored["context_tags_recorded"] is False


def test_a_database_without_insert_attribution_or_first_claim_upgrades_in_place(
    client, isolate_settings
):
    """An old row's claim is its recorded `consumed_at`; no old row reads as requeue-inserted."""
    key = "2026-11-15-acme-queue-attribution-columns"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    with closing(sqlite3.connect(str(db_module.database_path()))) as connection, connection:
        consumed_at = connection.execute(
            "SELECT consumed_at FROM code_analysis_queue WHERE id = ?", (claim["id"],)
        ).fetchone()[0]
        directed = connection.execute(
            "INSERT INTO code_analysis_queue (engagement_id, file_id, priority, status, "
            "repo_generation, queue_mode, inserted_by) "
            "SELECT engagement_id, file_id, priority, 'pending', repo_generation, 'trigger', "
            "'requeue-triggers' FROM code_analysis_queue WHERE id = ?",
            (claim["id"],),
        ).lastrowid
        connection.execute("ALTER TABLE code_analysis_queue DROP COLUMN inserted_by")
        connection.execute("ALTER TABLE code_analysis_queue DROP COLUMN first_claimed_at")
    assert consumed_at
    assert {"inserted_by", "first_claimed_at"}.isdisjoint(_columns("code_analysis_queue"))

    db_module.init_db()

    assert {"inserted_by", "first_claimed_at"} <= _columns("code_analysis_queue")
    with closing(sqlite3.connect(str(db_module.database_path()))) as connection:
        rows = {
            row[0]: (row[1], row[2])
            for row in connection.execute(
                "SELECT id, inserted_by, first_claimed_at FROM code_analysis_queue"
            )
        }
    assert rows[claim["id"]] == ("", consumed_at)
    assert rows[directed] == ("", None)
    withdrawn = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [directed], "reason": "Acme: a row recorded before attribution.",
    }).json()
    assert withdrawn["withdrawn"] == []
    (refused,) = withdrawn["refused"]
    assert "before inserts were attributed" in refused["reason"]
