"""Lost closeout responses are reconciled without repeating writes or audits."""

from __future__ import annotations

import sqlite3

import pytest

from app import db
from app.api import code_analysis as api
from test_code_analysis_api import _owned, _record_fixture_source_receipt
from test_code_queue_path_scope import _seed


def _claim(client, isolate_settings):
    base, _, _ = _seed(client, isolate_settings, "2026-11-08-acme-closeout-replay")
    response = client.post(
        base + "/analysis-queue/fetch", json={"limit": 1, "agent_name": "acme-reviewer"}
    )
    assert response.status_code == 200, response.text
    claim = response.json()[0]
    payload = _owned(
        claim,
        item_ids=[claim["id"]],
        disposition="clean",
        notes="Acme source reviewed",
        cwe_coverage=[
            {"family": family, "effort": 80}
            for family in claim["applicable_vuln_classes"]
        ],
    )
    return base, claim, payload


def test_exact_closeout_retry_returns_already_applied_without_new_audit(
    client, isolate_settings
):
    base, claim, payload = _claim(client, isolate_settings)
    _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)
    first = client.post(base + "/analysis-queue/done", json=payload)
    assert first.status_code == 200, first.text
    with db.get_connection() as connection:
        completed_at = connection.execute(
            "SELECT completed_at FROM code_analysis_queue WHERE id=?", (claim["id"],)
        ).fetchone()[0]
        audit_count = connection.execute(
            "SELECT COUNT(*) FROM activity_entries WHERE title='code-dispatch done'"
        ).fetchone()[0]
    retry = client.post(base + "/analysis-queue/done", json=payload)
    assert retry.status_code == 200, retry.text
    assert retry.json()["already_applied"] is True
    assert retry.json()["updated"] == 0
    assert retry.json()["coverage_integrity"] == first.json()["coverage_integrity"]
    with db.get_connection() as connection:
        assert (
            connection.execute(
                "SELECT completed_at FROM code_analysis_queue WHERE id=?",
                (claim["id"],),
            ).fetchone()[0]
            == completed_at
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM activity_entries WHERE title='code-dispatch done'"
            ).fetchone()[0]
            == audit_count
        )


@pytest.mark.parametrize("changed", ["notes", "lease", "coverage", "generation"])
def test_closeout_retry_refuses_changed_identity_or_payload(
    client, isolate_settings, changed
):
    base, claim, payload = _claim(client, isolate_settings)
    _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)
    assert client.post(base + "/analysis-queue/done", json=payload).status_code == 200
    if changed == "notes":
        payload["notes"] = "A different review"
    elif changed == "lease":
        payload["lease_token"] = "another-acme-lease"
    elif changed == "coverage":
        payload["cwe_coverage"][0]["effort"] = 81
    else:
        with db.get_connection() as connection:
            connection.execute(
                "UPDATE code_repos SET active_generation=active_generation+1"
            )
    response = client.post(base + "/analysis-queue/done", json=payload)
    assert response.status_code == 409, response.text


@pytest.mark.parametrize("operation", ["analysis", "done"])
def test_code_mutation_and_activity_become_visible_together(
    client, isolate_settings, monkeypatch, operation
):
    base, claim, payload = _claim(client, isolate_settings)
    if operation == "done":
        _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)
    observed = []
    original = api._audit_code_mutation

    def audit(eid, **kwargs):
        with db.get_connection() as current:
            other = sqlite3.connect(str(db.database_path()))
            try:
                if operation == "done":
                    visible = other.execute(
                        "SELECT status FROM code_analysis_queue WHERE id=?",
                        (claim["id"],),
                    ).fetchone()[0]
                    observed.append((current.in_transaction, visible))
                else:
                    visible = other.execute(
                        "SELECT COUNT(*) FROM code_analysis_results WHERE queue_item_id=?",
                        (claim["id"],),
                    ).fetchone()[0]
                    observed.append((current.in_transaction, visible))
            finally:
                other.close()
        original(eid, **kwargs)

    monkeypatch.setattr(api, "_audit_code_mutation", audit)
    if operation == "done":
        response = client.post(base + "/analysis-queue/done", json=payload)
        expected = [(True, "processing")]
    else:
        response = client.post(
            base + "/analysis-results",
            json=_owned(
                claim,
                queue_item_id=claim["id"],
                disposition="clean",
                evidence="Acme source observation",
            ),
        )
        expected = [(True, 0)]
    assert response.status_code in {200, 201}, response.text
    assert observed == expected


def test_failed_activity_discards_partial_audit_without_losing_closeout(
    client, isolate_settings, monkeypatch
):
    base, claim, payload = _claim(client, isolate_settings)
    _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)

    def partial_failure(eid, **_kwargs):
        with db.get_connection() as connection:
            connection.execute(
                "INSERT INTO activity_entries(engagement_id,title) VALUES(?, 'Acme partial audit')",
                (eid,),
            )
        raise RuntimeError("Acme activity unavailable")

    monkeypatch.setattr(api.activity_service, "record_activity_entry", partial_failure)
    response = client.post(base + "/analysis-queue/done", json=payload)
    assert response.status_code == 200, response.text
    with db.get_connection() as connection:
        assert (
            connection.execute(
                "SELECT status FROM code_analysis_queue WHERE id=?", (claim["id"],)
            ).fetchone()[0]
            == "done"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM activity_entries WHERE title='Acme partial audit'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM events WHERE event_type='code_analysis.audit_failed'"
            ).fetchone()[0]
            == 1
        )


def test_concurrent_exact_closeout_reconciles_one_commit(
    client, isolate_settings, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from app.services import code_analysis

    base, claim, payload = _claim(client, isolate_settings)
    _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)
    before_lock = Barrier(2)
    original = code_analysis._require_queue_generation

    def synchronized(connection, eid, rows, *, action, **kwargs):
        if action == "complete":
            before_lock.wait(timeout=3)
        return original(connection, eid, rows, action=action, **kwargs)

    monkeypatch.setattr(code_analysis, "_require_queue_generation", synchronized)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: client.post(base + "/analysis-queue/done", json=payload),
                range(2),
            )
        )
    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    assert sorted(r.json()["updated"] for r in responses) == [0, 1]
    with db.get_connection() as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM activity_entries WHERE title='code-dispatch done'"
            ).fetchone()[0]
            == 1
        )


def test_completed_closeout_reconciliation_does_not_wait_for_another_writer(
    client, isolate_settings, monkeypatch
):
    base, claim, payload = _claim(client, isolate_settings)
    _record_fixture_source_receipt(client, "2026-11-08-acme-closeout-replay", claim)
    assert client.post(base + "/analysis-queue/done", json=payload).status_code == 200
    original = db._connection_for_thread

    def no_wait(path):
        connection = original(path)
        connection.execute("PRAGMA busy_timeout=0")
        return connection

    monkeypatch.setattr(db, "_connection_for_thread", no_wait)
    with db.get_connection() as other_writer:
        other_writer.execute("BEGIN IMMEDIATE")
        response = client.post(base + "/analysis-queue/done", json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["already_applied"] is True
