"""`code-dispatch withdraw` takes back a directed attempt nobody has claimed.

A `requeue-triggers` batch sent by mistake leaves one pending directed row per
file, which suspends the file's earlier verdict and binds its triggers as
`queued`, where `resolve-triggers` cannot reach them. Withdrawing the row
removes the unclaimed attempt, so the earlier review is the file's current
verdict again, and returns its triggers to `pending` with the reason. A row a
lease has claimed, a completed one, or one that is not a directed attempt is
refused with the reason, and the rest of the batch still withdraws.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _close_queue_item,
    _network_input_coverage,
    _owned,
    _queue_file,
)
from test_code_depth_floor_triggers import _close, _floor_triggers, _seed


def _requeued(client, isolate_settings, key):
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": trigger["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    (outcome,) = requeued.json()["outcomes"]
    assert outcome["outcome"] == "inserted"
    return base, repo, parser, claim, trigger, int(outcome["queue_item_id"])


def _file(client, base, repo, parser):
    rows = client.get(f"{base}/files?repo_id={repo['id']}&limit=100").json()["items"]
    return next(row for row in rows if row["id"] == parser["id"])


def test_withdrawing_a_directed_attempt_restores_the_earlier_verdict(client, isolate_settings):
    key = "2026-11-14-acme-withdraw"
    base, repo, parser, claim, trigger, directed = _requeued(client, isolate_settings, key)
    assert _file(client, base, repo, parser)["analysis_status"] == "queued"
    assert _floor_triggers(client, base, status="queued")[0]["id"] == trigger["id"]

    withdrawn = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [directed], "reason": "Acme: requeued by mistake; the family cannot occur here.",
    })

    assert withdrawn.status_code == 200, withdrawn.text
    body = withdrawn.json()
    assert body["refused"] == []
    (row,) = body["withdrawn"]
    assert row["queue_item_id"] == directed
    assert row["file_path"] == parser["file_path"]
    assert row["predecessor_queue_item_id"] == claim["id"]
    assert row["returned_trigger_ids"] == [trigger["id"]]
    assert row["file_analysis_status"] == "analyzed"
    assert _file(client, base, repo, parser)["analysis_status"] == "analyzed"
    listed = client.get(f"{base}/analysis-queue?current_only=true&limit=50").json()["items"]
    assert directed not in {item["id"] for item in listed}
    (pending,) = _floor_triggers(client, base)
    assert pending["id"] == trigger["id"]
    assert "requeued by mistake" in pending["resolution_note"]

    resolved = client.post(f"{base}/triggers/resolve", json={
        "items": [{"id": trigger["id"]}],
        "resolution_status": "not_applicable",
        "resolution_note": "The Acme parser makes no outbound request.",
    })
    assert resolved.json()["resolved"] == 1


def test_a_claimed_completed_or_undirected_row_is_refused_and_the_rest_withdraws(
    client, isolate_settings
):
    key = "2026-11-14-acme-withdraw-refused"
    base, repo, parser, claim, trigger, directed = _requeued(client, isolate_settings, key)
    other_key = "2026-11-14-acme-withdraw-claimed"
    other_base, _r, _p, _c, _t, claimed_directed = _requeued(client, isolate_settings, other_key)
    leased = client.post(
        f"{other_base}/analysis-queue/fetch", json={"limit": 1, "agent_name": "code-vuln-hunter"}
    )
    assert [item["id"] for item in leased.json()] == [claimed_directed]

    refused = client.post(f"{other_base}/analysis-queue/withdraw", json={
        "item_ids": [claimed_directed], "reason": "Acme: wrong batch.",
    }).json()
    assert refused["withdrawn"] == []
    (entry,) = refused["refused"]
    assert entry["queue_item_id"] == claimed_directed
    assert "processing" in entry["reason"] and "code-vuln-hunter" in entry["reason"]

    mixed = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [claim["id"], directed, 999999], "reason": "Acme: wrong batch.",
    }).json()

    assert [row["queue_item_id"] for row in mixed["withdrawn"]] == [directed]
    reasons = {row["queue_item_id"]: row["reason"] for row in mixed["refused"]}
    assert set(reasons) == {claim["id"], 999999}
    assert "done" in reasons[claim["id"]]
    assert "no queue item" in reasons[999999]


def test_an_initial_attempt_is_not_a_directed_one(client, isolate_settings):
    key = "2026-11-14-acme-withdraw-initial"
    base, _repo, parser = _seed(client, isolate_settings, key)
    assert _queue_file(client, key, int(parser["id"]), 90).status_code == 201
    queue = client.get(f"{base}/analysis-queue?current_only=true&limit=50").json()["items"]
    initial = next(item for item in queue if item["file_id"] == parser["id"])

    refused = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [initial["id"]], "reason": "Acme",
    }).json()

    (entry,) = refused["refused"]
    assert "initial" in entry["reason"] and "requeue-triggers" in entry["reason"]


def test_a_directed_attempt_claimed_and_released_is_not_withdrawn(client, isolate_settings):
    """Release clears the lease fields; the first-claim record survives it."""
    key = "2026-11-15-acme-withdraw-released"
    base, _repo, _parser, _claim, _trigger, directed = _requeued(client, isolate_settings, key)
    (leased,) = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": "code-vuln-hunter"}
    ).json()
    assert leased["id"] == directed
    released = client.post(f"{base}/analysis-queue/release", json={
        "item_id": directed, "agent_name": leased["agent_name"],
        "lease_token": leased["lease_token"], "reason": "Acme: handing it back",
    })
    assert released.status_code == 200, released.text

    refused = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [directed], "reason": "Acme: wrong batch.",
    }).json()

    assert refused["withdrawn"] == []
    (entry,) = refused["refused"]
    assert "claimed before" in entry["reason"]


def test_a_trigger_merged_into_a_required_re_review_cannot_be_withdrawn(
    client, isolate_settings
):
    """A metadata-refresh re-review a requeue merged into stays owed."""
    key = "2026-11-15-acme-withdraw-refresh"
    base, _repo, parser = _seed(client, isolate_settings, key)
    helper = next(
        row for row in client.get(f"{base}/files?limit=50").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(default_effort=80))
    helper_claim = _claim_file_for_analysis(client, key, int(helper["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        helper_claim, queue_item_id=helper_claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
        cross_file_triggers=[{
            "file_path": "src/parser.py", "vuln_class": "path-traversal",
            "reason": "Acme: the helper hands the parser a caller-chosen path.",
        }],
    ))
    assert receipt.status_code == 201, receipt.text
    assert _close_queue_item(
        client, key, helper_claim, disposition="clean", notes="Acme helper review",
        cwe_coverage=[
            {"family": "algorithmic-dos", "effort": 20},
            {"family": "error-handling", "effort": 20},
        ],
    ).status_code == 200
    (cross,) = [
        row for row in client.get(f"{base}/triggers?status=pending").json()["items"]
        if row["origin"] == "cross_file"
    ]
    reclassified = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": int(parser["id"]), "classification": "critical", "role": "parser",
        "slot_types": ["NETWORK-INPUT", "FILE-CONTENT"], "analysis_priority": 90,
    }]})
    assert reclassified.status_code == 200, reclassified.text
    (refresh,) = [
        row for row in client.get(
            f"{base}/analysis-queue?current_only=true&limit=50"
        ).json()["items"]
        if row["file_id"] == parser["id"] and row["status"] == "pending"
    ]
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": cross["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    (outcome,) = requeued.json()["outcomes"]
    assert outcome["queue_item_id"] == refresh["id"]

    refused = client.post(f"{base}/analysis-queue/withdraw", json={
        "item_ids": [refresh["id"]], "reason": "Acme: wrong batch.",
    }).json()

    assert refused["withdrawn"] == []
    (entry,) = refused["refused"]
    assert "requeue-triggers" in entry["reason"]
    queue = client.get(f"{base}/analysis-queue?current_only=true&limit=50").json()["items"]
    (kept,) = [row for row in queue if row["id"] == refresh["id"]]
    assert kept["status"] == "pending"
    # The re-review still answers for every family, not only the carried one.
    assert kept["queue_mode"] == "metadata-refresh"


def test_resolving_a_queued_trigger_names_the_withdraw_that_frees_it(client, isolate_settings):
    key = "2026-11-15-acme-withdraw-resolve-queued"
    base, _repo, parser, _claim, trigger, directed = _requeued(client, isolate_settings, key)

    for selector in ({"id": trigger["id"]}, {"file_path": parser["file_path"], "vuln_class": "ssrf"}):
        body = client.post(f"{base}/triggers/resolve", json={
            "items": [selector], "resolution_status": "not_applicable",
            "resolution_note": "The Acme parser makes no outbound request.",
        }).json()

        assert body["resolved"] == 0
        (queued,) = body["queued"]
        assert (queued["trigger_id"], queued["queue_item_id"]) == (trigger["id"], directed)
        assert f"withdraw {directed}" in body["detail"]
