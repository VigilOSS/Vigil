"""Cross-file trigger resolutions follow the review that discharges them."""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _classify_file,
    _close_queue_item,
    _fetch_queue,
    _network_input_coverage,
    _publish_structural_callables,
    _queue_file,
    _record_fixture_source_receipt,
    _seed_repo_files,
)


def _seed_files(client, isolate_settings, key):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    _classify_file(client, key, int(parser["id"]), "critical", 100)
    _classify_file(client, key, int(helper["id"]), "high", 79)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", repo, parser, helper


def _seed_parser_trigger(client, isolate_settings, key):
    """Review the parser and record one trigger on the helper it delegates to."""
    base, repo, parser, helper = _seed_files(client, isolate_settings, key)
    _record_parser_trigger(client, key, base, parser)
    return base, repo, helper


def _record_parser_trigger(client, key, base, parser, vuln_class="web-app-injection"):
    assert _queue_file(client, key, parser["id"], 100).status_code == 201
    item = _fetch_queue(client, key).json()[0]
    recorded = client.post(f"{base}/analysis-results", json={
        "queue_item_id": item["id"], "file_id": parser["id"], "agent_name": "code-vuln-hunter",
        "lease_token": item["lease_token"],
        "reviewed_spans": [{"file_id": parser["id"], "start_line": 1, "end_line": int(parser["loc"])}],
        "hypothesis": "Shared helper may carry taint.", "evidence": "parse delegates to helper.",
        "disposition": "clean", "confidence": "medium", "notes": "helper follow-up",
        "cross_file_triggers": [{"file_path": "src/helpers.py", "reason": "shared parser helper",
                                 "vuln_class": vuln_class}],
    })
    assert recorded.status_code == 201, recorded.text
    closed = _close_queue_item(client, key, item, disposition="clean", notes="Reviewed parser",
                               cwe_coverage=_network_input_coverage(default_effort=80))
    assert closed.status_code == 200, closed.text


def _review(client, key, claim, *, effort=60, overrides=None):
    _record_fixture_source_receipt(client, key, claim)
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Reviewed helper",
        cwe_coverage=_network_input_coverage(default_effort=effort, overrides=overrides),
    )
    assert closed.status_code == 200, closed.text


def test_completed_reanalysis_keeps_trigger_resolved(client, isolate_settings):
    key = "2026-11-13-acme-reanalysis-trigger"
    base, repo, helper = _seed_parser_trigger(client, isolate_settings, key)
    requeue = client.post(f"{base}/analysis-queue/requeue", json={"items": [{
        "file_path": "src/helpers.py", "priority": 79, "reason": "shared parser helper",
        "trigger_context": {"vuln_class": "web-app-injection"}}]})
    assert requeue.status_code == 201 and requeue.json()["inserted"] == 1, requeue.text
    _review(client, key, _fetch_queue(client, key, agent_name="follow-up-hunter").json()[0])
    cov = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert cov["trigger_summary"]["resolved"] == 1 and cov["gate"]["passed"] is True, cov

    successor = _claim_file_for_reanalysis(client, key, int(helper["id"]), reason="Acme added depth")
    # The successor now owns the obligation its predecessor discharged.
    during = client.get(f"{base}/triggers").json()["items"]
    assert [(t["status"], t["resolved_queue_item_id"]) for t in during] == [
        ("queued", successor["id"])
    ]
    assert any(
        entry.get("source") == "code_analysis_trigger"
        and entry.get("trigger_id") == during[0]["id"]
        for entry in successor["cross_file_triggers"]
    ), successor["cross_file_triggers"]
    _review(client, key, successor)

    after = client.get(f"{base}/triggers").json()["items"]
    assert [(t["status"], t["resolved_queue_item_id"]) for t in after] == [
        ("resolved", successor["id"])
    ]
    cov = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert cov["trigger_summary"]["pending"] == 0
    assert cov["gate"]["passed"] is True, cov["gate"]["reasons"]


def _requeue_trigger(client, base, trigger_id):
    requeue = client.post(f"{base}/analysis-queue/requeue", json={"items": [
        {"trigger_id": trigger_id}
    ]})
    assert requeue.status_code == 201, requeue.text
    [trigger] = client.get(f"{base}/triggers").json()["items"]
    return requeue.json(), trigger


def test_requeue_resolves_trigger_a_later_review_already_covers(client, isolate_settings):
    """A review claimed after the trigger that scored its class discharges it."""
    key = "2026-11-13-acme-trigger-covered"
    base, repo, helper = _seed_parser_trigger(client, isolate_settings, key)
    # Queued plainly, so the packet does not carry the trigger; the review still
    # scores the trigger's class (web-app-injection) with real effort.
    covering = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79)
    assert not covering["cross_file_triggers"]
    _review(client, key, covering)
    [pending] = client.get(f"{base}/triggers").json()["items"]
    assert pending["status"] == "pending"

    outcome, _trigger = _requeue_trigger(client, base, pending["id"])
    assert outcome["inserted"] == 0 and outcome["already_completed"] == 1
    assert outcome["resolved_trigger_ids"] == [pending["id"]]

    [resolved] = client.get(f"{base}/triggers").json()["items"]
    assert resolved["status"] == "resolved"
    assert resolved["resolved_queue_item_id"] == covering["id"]
    assert f"queue item {covering['id']}" in resolved["resolution_note"]
    queue = client.get(f"{base}/analysis-queue").json()["items"]
    assert [row["id"] for row in queue if row["file_id"] == helper["id"]] == [covering["id"]]
    cov = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert cov["trigger_summary"]["pending"] == 0
    assert cov["gate"]["passed"] is True, cov["gate"]["reasons"]

    # The covering review keeps the obligation only while it stays current: a
    # reanalysis carries the resolution to its successor rather than dropping it.
    successor = _claim_file_for_reanalysis(client, key, int(helper["id"]), reason="Acme recheck")
    [carried] = client.get(f"{base}/triggers").json()["items"]
    assert (carried["status"], carried["resolved_queue_item_id"]) == ("queued", successor["id"])
    # The carry keeps the resolution history and names where it moved.
    assert resolved["resolution_note"] in carried["resolution_note"]
    assert f"queue item {successor['id']}" in carried["resolution_note"]
    activity = client.get(
        f"/engagements/{key}/activity-entries", params={"q": "code-dispatch"}
    ).json()["items"]
    [audited] = [row for row in activity if row["title"] == "code-dispatch reanalyze"]
    assert audited["metadata"]["carried_triggers"] == [{
        "trigger_id": pending["id"],
        "from_queue_item_id": covering["id"],
        "to_queue_item_id": successor["id"],
    }]
    _review(client, key, successor)
    [closed] = client.get(f"{base}/triggers").json()["items"]
    assert (closed["status"], closed["resolved_queue_item_id"]) == ("resolved", successor["id"])


def _assert_requeued_not_resolved(client, base, helper, pending, outcome, trigger):
    assert trigger["status"] == "queued", (trigger, outcome)
    assert outcome["inserted"] == 1, outcome
    assert outcome["resolved_trigger_ids"] == [], outcome
    queue = client.get(f"{base}/analysis-queue").json()["items"]
    [requeued] = [
        row for row in queue
        if row["file_id"] == helper["id"] and row["id"] == trigger["resolved_queue_item_id"]
    ]
    assert any(
        entry.get("trigger_id") == pending["id"] for entry in requeued["cross_file_triggers"]
    ), requeued


def test_review_marking_the_trigger_class_not_applicable_does_not_discharge_it(
    client, isolate_settings
):
    key = "2026-11-13-acme-trigger-na"
    base, _repo, parser, helper = _seed_files(client, isolate_settings, key)
    _record_parser_trigger(client, key, base, parser, vuln_class="ssrf")
    claim = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79,
                                     agent_name="helper-hunter")
    assert not claim["cross_file_triggers"]
    _review(client, key, claim, overrides={"ssrf": {
        "effort": 0, "disposition": "not_applicable", "notes": "Acme helper: the family cannot occur here.",
    }})
    [pending] = client.get(f"{base}/triggers").json()["items"]
    assert pending["status"] == "pending"

    outcome, trigger = _requeue_trigger(client, base, pending["id"])
    _assert_requeued_not_resolved(client, base, helper, pending, outcome, trigger)


def test_review_that_never_scored_the_trigger_class_does_not_discharge_it(
    client, isolate_settings
):
    key = "2026-11-13-acme-trigger-other-class"
    base, _repo, parser, helper = _seed_files(client, isolate_settings, key)
    # The review scores its own families with real effort, none of them sqli.
    _record_parser_trigger(client, key, base, parser, vuln_class="sqli")
    _review(client, key, _claim_file_for_analysis(client, key, int(helper["id"]), priority=79))
    [pending] = client.get(f"{base}/triggers").json()["items"]

    outcome, trigger = _requeue_trigger(client, base, pending["id"])
    _assert_requeued_not_resolved(client, base, helper, pending, outcome, trigger)


def test_review_leased_before_the_trigger_existed_does_not_discharge_it(
    client, isolate_settings
):
    key = "2026-11-13-acme-trigger-early-lease"
    base, _repo, parser, helper = _seed_files(client, isolate_settings, key)
    # Lane B holds the helper lease before lane A raises the trigger; its
    # receipts land after lane A's, so receipt order alone reads as "later".
    claim = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79,
                                     agent_name="helper-hunter")
    _record_parser_trigger(client, key, base, parser, vuln_class="ssrf")
    _review(client, key, claim)
    [pending] = client.get(f"{base}/triggers").json()["items"]
    assert pending["status"] == "pending"

    outcome, trigger = _requeue_trigger(client, base, pending["id"])
    _assert_requeued_not_resolved(client, base, helper, pending, outcome, trigger)


def _record_helper_triggers(client, key, base, parser, item, triggers):
    """Record one parser result on *item* raising each (vuln_class, reason) on the helper."""
    recorded = client.post(f"{base}/analysis-results", json={
        "queue_item_id": item["id"], "file_id": parser["id"], "agent_name": "parser-hunter",
        "lease_token": item["lease_token"],
        "reviewed_spans": [{"file_id": parser["id"], "start_line": 1, "end_line": int(parser["loc"])}],
        "hypothesis": "Helper builds URL and path.", "evidence": "parse passes host to helper.",
        "disposition": "clean", "confidence": "medium", "notes": "helper follow-up",
        "cross_file_triggers": [
            {"file_path": "src/helpers.py", "reason": reason, "vuln_class": vuln_class}
            for vuln_class, reason in triggers
        ],
    })
    assert recorded.status_code == 201, recorded.text


def _triggers_by_class(client, base):
    return {t["vuln_class"]: t for t in client.get(f"{base}/triggers").json()["items"]}


def _auto_resolve_one_of_two_sibling_triggers(client, isolate_settings, key):
    """Raise ssrf and path-traversal on the helper; a later review scores only ssrf.

    The requeue of ssrf resolves it against that review and inserts a trigger
    attempt for the owed path-traversal sibling.
    """
    base, repo, parser, helper = _seed_files(client, isolate_settings, key)
    assert _queue_file(client, key, parser["id"], 100).status_code == 201
    [item] = _fetch_queue(client, key, agent_name="parser-hunter").json()
    _record_helper_triggers(client, key, base, parser, item, [
        ("ssrf", "outbound URL built in helper"),
        ("path-traversal", "path joined in helper"),
    ])
    closed = _close_queue_item(client, key, item, disposition="clean", notes="Reviewed parser",
                               cwe_coverage=_network_input_coverage(default_effort=80))
    assert closed.status_code == 200, closed.text
    # Claimed after both triggers; scores ssrf with effort, path-traversal N/A.
    covering = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79,
                                        agent_name="helper-hunter")
    _review(client, key, covering,
            overrides={"path-traversal": {
        "effort": 0, "disposition": "not_applicable", "notes": "Acme helper: the family cannot occur here.",
    }})
    triggers = _triggers_by_class(client, base)
    assert {t["status"] for t in triggers.values()} == {"pending"}

    requeue = client.post(f"{base}/analysis-queue/requeue",
                          json={"items": [{"trigger_id": triggers["ssrf"]["id"]}]})
    assert requeue.status_code == 201, requeue.text
    return base, repo, helper, covering, requeue.json()


def test_auto_resolved_trigger_stays_resolved_when_its_sibling_requeues(
    client, isolate_settings
):
    """The sibling's new trigger attempt is added depth, not a reopened verdict."""
    key = "2026-11-13-acme-trigger-sibling"
    base, repo, helper, covering, outcome = _auto_resolve_one_of_two_sibling_triggers(
        client, isolate_settings, key
    )
    after = _triggers_by_class(client, base)
    assert outcome["resolved_trigger_ids"] == [after["ssrf"]["id"]], outcome
    assert outcome["inserted"] == 1, outcome
    assert (after["ssrf"]["status"], after["ssrf"]["resolved_queue_item_id"]) == (
        "resolved", covering["id"]
    ), after["ssrf"]
    assert after["path-traversal"]["status"] == "queued", after["path-traversal"]
    assert after["path-traversal"]["resolved_queue_item_id"] != covering["id"]
    cov = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert cov["trigger_summary"]["resolved"] == 1, cov["trigger_summary"]
    assert cov["trigger_summary"]["pending"] == 0, cov["trigger_summary"]


def test_reanalysis_carries_a_resolution_bound_to_an_earlier_attempt(
    client, isolate_settings
):
    """A reanalysis owes every resolution still in force on the file, not only its
    predecessor's: the ssrf trigger rests on the review before the sibling attempt."""
    key = "2026-11-13-acme-trigger-sibling-reanalysis"
    base, _repo, helper, covering, _outcome = _auto_resolve_one_of_two_sibling_triggers(
        client, isolate_settings, key
    )
    [sibling_attempt] = _fetch_queue(client, key, agent_name="helper-hunter").json()
    _review(client, key, sibling_attempt)
    resolved = _triggers_by_class(client, base)
    assert {(t["status"], t["resolved_queue_item_id"]) for t in resolved.values()} == {
        ("resolved", covering["id"]), ("resolved", sibling_attempt["id"]),
    }, resolved

    successor = _claim_file_for_reanalysis(client, key, int(helper["id"]), reason="Acme recheck")
    during = _triggers_by_class(client, base)
    assert {(t["status"], t["resolved_queue_item_id"]) for t in during.values()} == {
        ("queued", successor["id"])
    }, during
    carried_ids = {
        entry.get("trigger_id")
        for entry in successor["cross_file_triggers"]
        if entry.get("source") == "code_analysis_trigger"
    }
    assert carried_ids == {t["id"] for t in during.values()}, successor["cross_file_triggers"]
    _review(client, key, successor)
    after = _triggers_by_class(client, base)
    assert {(t["status"], t["resolved_queue_item_id"]) for t in after.values()} == {
        ("resolved", successor["id"])
    }, after


def test_trigger_resolved_by_its_carried_attempt_survives_a_later_sibling_requeue(
    client, isolate_settings
):
    key = "2026-11-13-acme-trigger-carried-sibling"
    base, _repo, parser, helper = _seed_files(client, isolate_settings, key)
    assert _queue_file(client, key, parser["id"], 100).status_code == 201
    [parser_item] = _fetch_queue(client, key, agent_name="parser-hunter").json()
    _record_helper_triggers(client, key, base, parser, parser_item, [("ssrf", "url")])
    [first] = client.get(f"{base}/triggers").json()["items"]
    outcome, _trigger = _requeue_trigger(client, base, first["id"])
    assert outcome["inserted"] == 1, outcome
    [carrying] = _fetch_queue(client, key, agent_name="helper-hunter").json()
    _review(client, key, carrying)
    assert _triggers_by_class(client, base)["ssrf"]["status"] == "resolved"

    _record_helper_triggers(client, key, base, parser, parser_item, [("path-traversal", "path")])
    closed = _close_queue_item(client, key, parser_item, disposition="clean",
                               notes="Reviewed parser",
                               cwe_coverage=_network_input_coverage(default_effort=80))
    assert closed.status_code == 200, closed.text
    sibling = _triggers_by_class(client, base)["path-traversal"]
    requeue = client.post(f"{base}/analysis-queue/requeue",
                          json={"items": [{"trigger_id": sibling["id"]}]})
    assert requeue.status_code == 201, requeue.text
    assert requeue.json()["inserted"] == 1, requeue.json()

    after = _triggers_by_class(client, base)
    assert (after["ssrf"]["status"], after["ssrf"]["resolved_queue_item_id"]) == (
        "resolved", carrying["id"]
    ), after["ssrf"]
    assert after["path-traversal"]["status"] == "queued", after["path-traversal"]


def test_requeue_resolution_note_names_how_the_review_addressed_the_trigger(
    client, isolate_settings
):
    """A carried trigger and a covered class resolve the same way but for different
    reasons; each note says which one this was."""
    from app import db as db_module
    from app.services.code_analysis_support import trigger_review_basis

    key = "2026-11-13-acme-trigger-note-basis"
    base, _repo, parser, helper = _seed_files(client, isolate_settings, key)
    _record_parser_trigger(client, key, base, parser, vuln_class="ssrf")
    [trigger] = client.get(f"{base}/triggers").json()["items"]
    _outcome, _queued = _requeue_trigger(client, base, trigger["id"])
    [carrying] = _fetch_queue(client, key, agent_name="helper-hunter").json()
    # The review marks the class not applicable, so only the carried row addressed it.
    _review(client, key, carrying, overrides={"ssrf": {
        "effort": 0, "disposition": "not_applicable", "notes": "Acme helper: the family cannot occur here.",
    }})
    with db_module.get_connection() as connection:
        engagement_id = int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (key,)
        ).fetchone()["id"])
        assert trigger_review_basis(
            connection, engagement_id, trigger["id"], carrying["id"]
        ) == "carried"
        # Reopen it unbound, as an operator correction leaves it, so the next
        # requeue resolves it against the review that carried it.
        connection.execute(
            "UPDATE code_analysis_triggers SET status = 'pending', resolved_queue_item_id = NULL, "
            "resolution_note = '' WHERE id = ?",
            (trigger["id"],),
        )
    outcome, carried = _requeue_trigger(client, base, trigger["id"])
    assert outcome["resolved_trigger_ids"] == [trigger["id"]], outcome
    assert (carried["status"], carried["resolved_queue_item_id"]) == ("resolved", carrying["id"])

    covered_key = "2026-11-13-acme-trigger-note-covered"
    covered_base, _repo, covered_parser, covered_helper = _seed_files(
        client, isolate_settings, covered_key
    )
    _record_parser_trigger(client, covered_key, covered_base, covered_parser, vuln_class="ssrf")
    covering = _claim_file_for_analysis(client, covered_key, int(covered_helper["id"]), priority=79)
    _review(client, covered_key, covering)
    [pending] = client.get(f"{covered_base}/triggers").json()["items"]
    with db_module.get_connection() as connection:
        covered_engagement_id = int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (covered_key,)
        ).fetchone()["id"])
        assert trigger_review_basis(
            connection, covered_engagement_id, pending["id"], covering["id"]
        ) == "covered"
    _outcome, covered = _requeue_trigger(client, covered_base, pending["id"])
    assert covered["status"] == "resolved"

    assert f"queue item {carrying['id']}" in carried["resolution_note"]
    assert f"queue item {covering['id']}" in covered["resolution_note"]
    carried_reason = carried["resolution_note"].split(":", 1)[1]
    covered_reason = covered["resolution_note"].split(":", 1)[1]
    assert carried_reason != covered_reason, (carried_reason, covered_reason)


def test_requeue_inserts_nothing_for_a_target_whose_every_trigger_it_resolved(
    client, isolate_settings
):
    """A trigger row copied from list-triggers carries its reason; once the
    covering review resolves the trigger, that reason is no work of its own."""
    key = "2026-11-15-acme-trigger-echo"
    base, repo, helper = _seed_parser_trigger(client, isolate_settings, key)
    covering = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79)
    _review(client, key, covering)
    [pending] = client.get(f"{base}/triggers").json()["items"]

    requeue = client.post(f"{base}/analysis-queue/requeue", json={"items": [{
        "trigger_id": pending["id"], "reason": pending["reason"],
        "trigger_context": {"vuln_class": pending["vuln_class"]},
    }]})

    assert requeue.status_code == 201, requeue.text
    outcome = requeue.json()
    assert outcome["inserted"] == 0 and outcome["already_completed"] == 1, outcome
    assert outcome["reopened_terminal_files"] == 0
    [target] = outcome["outcomes"]
    assert target["resolved_trigger_ids"] == [pending["id"]]
    assert str(pending["id"]) in target["detail"]
    queue = client.get(f"{base}/analysis-queue").json()["items"]
    assert [row["id"] for row in queue if row["file_id"] == helper["id"]] == [covering["id"]]


def test_requeue_still_inserts_new_free_text_context_beside_a_resolved_trigger(
    client, isolate_settings
):
    """Context the caller names by file, not by the resolved trigger, is new work."""
    key = "2026-11-15-acme-trigger-new-context"
    base, repo, helper = _seed_parser_trigger(client, isolate_settings, key)
    covering = _claim_file_for_analysis(client, key, int(helper["id"]), priority=79)
    _review(client, key, covering)
    [pending] = client.get(f"{base}/triggers").json()["items"]

    requeue = client.post(f"{base}/analysis-queue/requeue", json={"items": [
        {"trigger_id": pending["id"]},
        {"file_path": "src/helpers.py", "priority": 79, "reason": "Acme token reaches eval",
         "trigger_context": {"vuln_class": "code-injection"}},
    ]})

    assert requeue.status_code == 201, requeue.text
    outcome = requeue.json()
    assert outcome["inserted"] == 1, outcome
    assert outcome["resolved_trigger_ids"] == [pending["id"]]


def test_list_triggers_takes_all_and_names_every_status_it_refuses(client, isolate_settings):
    from app.services.code_analysis_support import _TRIGGER_STATUSES

    key = "2026-11-15-acme-trigger-status-filter"
    base, _repo, _helper = _seed_parser_trigger(client, isolate_settings, key)

    every = client.get(f"{base}/triggers", params={"status": "all"})
    assert every.status_code == 200, every.text
    assert every.json()["items"] == client.get(f"{base}/triggers").json()["items"]

    refused = client.get(f"{base}/triggers", params={"status": "accepted_gap"})
    assert refused.status_code == 400
    detail = refused.json()["detail"]
    assert "accepted_gap" in detail and "all" in detail
    for name in _TRIGGER_STATUSES:
        assert name in detail
