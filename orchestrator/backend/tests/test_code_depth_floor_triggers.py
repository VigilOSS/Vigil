"""A critical or high file closed below its review-depth floor owes Phase 2B work.

The closeout is never refused for its effort numbers (ADR 0001 decision 3):
they are the reviewer's own record. Each applicable family a critical or high
closeout leaves at effort 0, or below the tier's floor, becomes a pending
`depth_floor` trigger on the file itself, which the existing trigger machinery
carries: `requeue-triggers` turns it into a directed reanalysis attempt, and
`resolve-triggers` records why another pass would not move it. Until one of
those happens the coverage gate and code readiness name it.
"""
from __future__ import annotations

import sqlite3

from app import db as db_module
from app.services import code_analysis
from test_code_analysis_api import (
    _owned,
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _classify_file,
    _close_queue_item,
    _network_input_coverage,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    _seed_repo_files,
)


def _seed(client, isolate_settings, key, tier="critical"):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    _classify_file(
        client, key, int(parser["id"]), tier, {"critical": 90, "high": 60, "medium": 30}[tier]
    )
    _classify_file(client, key, int(helper["id"]), "low", 10)
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", repo, parser


def _close(client, key, claim, coverage):
    receipt = _record_fixture_source_receipt(client, key, claim)
    claim["_receipt_id"] = receipt["id"]
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review", cwe_coverage=coverage
    )
    assert closed.status_code == 200, closed.text
    return closed.json()


def _floor_triggers(client, base, status="pending"):
    rows = client.get(f"{base}/triggers?status={status}").json()["items"]
    return [row for row in rows if row["origin"] == "depth_floor"]


def test_a_shallow_critical_closeout_raises_depth_floor_triggers(client, isolate_settings):
    key = "2026-11-14-acme-depth-floor"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    coverage = _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    )
    # One family left out entirely: the backend records it at effort 0.
    coverage = [entry for entry in coverage if entry["family"] != "open-redirect"]

    body = _close(client, key, claim, coverage)

    raised = {row["family"]: row for row in body["depth_floor_triggers"]["raised"]}
    assert set(raised) == {"ssrf", "open-redirect"}
    assert (raised["ssrf"]["effort"], raised["ssrf"]["threshold"]) == (30, 70)
    assert raised["open-redirect"]["effort"] == 0
    triggers = {row["vuln_class"]: row for row in _floor_triggers(client, base)}
    assert set(triggers) == {"ssrf", "open-redirect"}
    for row in triggers.values():
        assert row["source_file_id"] == row["target_file_id"] == int(parser["id"])
        assert row["source_queue_item_id"] == claim["id"]

    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert gate["gate"]["passed"] is False
    assert any("depth-floor" in reason for reason in gate["gate"]["reasons"])
    assert gate["trigger_summary"]["depth_floor_pending"] == 2
    readiness = client.get(
        f"{base}/readiness?target_phase=verify-variant"
    ).json()
    kinds = {blocker["code"] for blocker in readiness["blockers"]}
    assert "depth_floor_triggers" in kinds


def test_a_closeout_at_the_floor_or_on_a_medium_file_raises_none(client, isolate_settings):
    key = "2026-11-14-acme-depth-floor-met"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    coverage = _network_input_coverage(
        default_effort=70,
        overrides={"ssrf": {
                "effort": 0, "disposition": "not_applicable",
                "notes": "The Acme parser makes no outbound request.",
            }},
    )
    assert _close(client, key, claim, coverage).get("depth_floor_triggers") is None
    assert _floor_triggers(client, base) == []

    medium_key = "2026-11-14-acme-depth-floor-medium"
    medium_base, _repo, medium = _seed(client, isolate_settings, medium_key, tier="medium")
    medium_claim = _claim_file_for_analysis(client, medium_key, int(medium["id"]))
    shallow = _network_input_coverage(default_effort=5)
    assert _close(client, medium_key, medium_claim, shallow).get("depth_floor_triggers") is None
    assert _floor_triggers(client, medium_base) == []


def test_a_requeued_depth_floor_trigger_resolves_when_its_attempt_meets_the_floor(
    client, isolate_settings
):
    key = "2026-11-14-acme-depth-floor-requeue"
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
    assert requeued.json()["inserted"] == 1
    fetched = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": "code-vuln-hunter"}
    )
    assert fetched.status_code == 200, fetched.text
    (attempt,) = fetched.json()
    assert any(
        entry.get("trigger_id") == trigger["id"]
        for entry in attempt["cross_file_triggers"]
    )
    # The directed pass names only the family it was sent for; the families the
    # earlier review covered are not re-raised by this closeout.
    body = _close(client, key, attempt, [{"family": "ssrf", "effort": 75}])

    assert body.get("depth_floor_triggers") is None
    assert _floor_triggers(client, base) == []
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert not any("depth-floor" in reason for reason in gate["reasons"])


def test_a_resolved_depth_floor_trigger_is_not_raised_again(client, isolate_settings):
    key = "2026-11-14-acme-depth-floor-resolved"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    shallow = _network_input_coverage(default_effort=80, overrides={"ssrf": {"effort": 30}})
    _close(client, key, claim, shallow)
    (trigger,) = _floor_triggers(client, base)

    resolved = client.post(f"{base}/triggers/resolve", json={
        "items": [{"trigger_id": trigger["id"]}],
        "resolution_status": "not_applicable",
        "resolution_note": "The Acme parser never builds an outbound URL; another pass adds nothing.",
    })
    assert resolved.status_code == 200, resolved.text
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert not any("depth-floor" in reason for reason in gate["reasons"])

    again = _claim_file_for_reanalysis(client, key, int(parser["id"]), reason="Acme recheck")
    body = _close(client, key, again, shallow)

    report = body["depth_floor_triggers"]
    assert "raised" not in report
    assert [(row["family"], row["trigger_id"], row["status"]) for row in report["settled"]] == [
        ("ssrf", trigger["id"], "not_applicable"),
    ]
    assert _floor_triggers(client, base) == []


def test_a_completed_row_correction_rejudges_the_floor(client, isolate_settings):
    """`code-record analysis --supersede` rewrites the done row's coverage, so the
    floor is judged again against the corrected record."""
    key = "2026-11-14-acme-depth-floor-correction"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)

    corrected = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], supersedes=claim["_receipt_id"],
        disposition="clean", evidence="Acme corrective pass over the same source",
        cwe_coverage=_network_input_coverage(default_effort=80),
    ))

    assert corrected.status_code == 201, corrected.text
    report = corrected.json()["depth_floor_triggers"]
    assert [(row["family"], row["trigger_id"]) for row in report["resolved"]] == [
        ("ssrf", trigger["id"]),
    ]
    assert _floor_triggers(client, base) == []
    (resolved,) = [
        row for row in _floor_triggers(client, base, status="resolved")
        if row["id"] == trigger["id"]
    ]
    assert resolved["resolved_queue_item_id"] == claim["id"]


def _floor_rows(client, base):
    return [
        (row["id"], row["vuln_class"], row["status"])
        for row in client.get(f"{base}/triggers").json()["items"]
        if row["origin"] == "depth_floor"
    ]


def test_requeue_sends_a_directed_pass_when_the_current_review_stayed_below_the_floor(
    client, isolate_settings
):
    """A review that scored the family, but below the floor, has not answered
    the trigger: `requeue-triggers` must send the directed pass, not resolve it."""
    key = "2026-11-14-acme-depth-floor-requeue-short"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    again = _claim_file_for_reanalysis(client, key, int(parser["id"]), reason="Acme deeper")
    body = _close(client, key, again, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 40}}
    ))
    assert [
        (row["family"], row["trigger_id"]) for row in body["depth_floor_triggers"]["still_pending"]
    ] == [("ssrf", trigger["id"])]

    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": trigger["id"]}]}
    )

    assert requeued.status_code == 201, requeued.text
    payload = requeued.json()
    assert payload["resolved_trigger_ids"] == []
    assert payload["inserted"] == 1
    assert _floor_rows(client, base) == [(trigger["id"], "ssrf", "queued")]


def test_a_correction_that_reaches_the_floor_stays_resolved_across_later_syncs(
    client, isolate_settings
):
    """The status sync re-derives every bound trigger; a `--supersede` correction
    that brought the family to the floor is a basis it must keep."""
    key = "2026-11-14-acme-depth-floor-correction-sync"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    corrected = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], supersedes=claim["_receipt_id"],
        disposition="clean", evidence="Acme corrective pass over the same source",
        cwe_coverage=_network_input_coverage(default_effort=80),
    ))
    assert corrected.status_code == 201, corrected.text

    with db_module.get_connection() as connection:
        engagement = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (key,)
        ).fetchone()
        code_analysis._sync_trigger_status_for_file(
            connection, int(engagement["id"]), int(parser["id"])
        )
        connection.commit()

    assert _floor_rows(client, base) == [(trigger["id"], "ssrf", "resolved")]
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert not any("depth-floor" in reason for reason in gate["reasons"])


def test_a_directed_pass_below_the_floor_keeps_its_trigger_owed_and_dry_run_agrees(
    client, isolate_settings
):
    """A short directed pass leaves the one trigger owed: it is neither resolved
    by the queue row having carried it nor replaced by a fresh trigger, and the
    dry run reports exactly what the real close then records."""
    key = "2026-11-14-acme-depth-floor-short-directed"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": trigger["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    (attempt,) = client.post(
        f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": "code-vuln-hunter"}
    ).json()
    _record_fixture_source_receipt(client, key, attempt)
    short = [{"family": "ssrf", "effort": 40}]

    dry = _close_queue_item(
        client, key, attempt, disposition="clean", notes="Acme review",
        cwe_coverage=short, dry_run=True,
    )
    real = _close_queue_item(
        client, key, attempt, disposition="clean", notes="Acme review", cwe_coverage=short,
    )

    assert dry.status_code == 200, dry.text
    assert real.status_code == 200, real.text
    report = real.json()["depth_floor_triggers"]
    assert dry.json()["depth_floor_triggers"] == report
    assert "raised" not in report and "resolved" not in report
    assert [(row["family"], row["trigger_id"]) for row in report["still_pending"]] == [
        ("ssrf", trigger["id"]),
    ]
    assert _floor_rows(client, base) == [(trigger["id"], "ssrf", "pending")]


def test_reviewed_at_sufficient_depth_settles_only_depth_floor_triggers(
    client, isolate_settings
):
    """The operator's judgement that the file was read at depth despite the
    recorded effort settles a depth-floor trigger with its reason; it says
    nothing about a cross-file hypothesis, which keeps its own statuses."""
    key = "2026-11-14-acme-depth-floor-sufficient"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    hypothesis = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="parse() hands the raw body to the Acme helper.",
        cross_file_triggers=[{
            "file_path": "src/helpers.py", "vuln_class": "web-app-injection",
            "reason": "The helper may build a query from the raw body.",
        }],
    ))
    assert hypothesis.status_code == 201, hypothesis.text
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (floor_trigger,) = _floor_triggers(client, base)
    complete = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "depth_floor_triggers" in {blocker["code"] for blocker in complete["blockers"]}
    (cross_file,) = [
        row for row in client.get(f"{base}/triggers?status=pending").json()["items"]
        if row["origin"] == "cross_file"
    ]

    refused = client.post(f"{base}/triggers/resolve", json={
        "items": [{"trigger_id": cross_file["id"]}],
        "resolution_status": "reviewed_at_sufficient_depth",
        "resolution_note": "Acme helper read in full.",
    })
    assert refused.status_code == 200, refused.text
    assert refused.json()["resolved"] == 0
    assert refused.json()["not_resolved"] == [str(cross_file["id"])]
    assert "depth_floor" in refused.json()["detail"]

    resolved = client.post(f"{base}/triggers/resolve", json={
        "items": [{"trigger_id": floor_trigger["id"]}],
        "resolution_status": "reviewed_at_sufficient_depth",
        "resolution_note": "Every outbound fetch in the Acme parser was traced; effort was under-recorded.",
    })

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["resolved"] == 1
    assert _floor_rows(client, base) == [
        (floor_trigger["id"], "ssrf", "reviewed_at_sufficient_depth"),
    ]
    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert not any("depth-floor" in reason for reason in coverage["gate"]["reasons"])
    assert coverage["trigger_summary"]["reviewed_at_sufficient_depth"] == 1
    complete = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "depth_floor_triggers" not in {blocker["code"] for blocker in complete["blockers"]}


def test_a_family_the_closeout_marks_not_applicable_never_raises_a_trigger(
    client, isolate_settings
):
    """A browser bundle owes the server-side slot families on paper; the review
    that says one cannot occur there settles it, even beside a receipt that
    scored it low."""
    key = "2026-11-14-acme-depth-floor-not-applicable"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    scored = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Acme bundle: fetch() calls only same-origin API paths.",
        cwe_coverage=[{"family": "ssrf", "effort": 10}],
    ))
    assert scored.status_code == 201, scored.text
    claim["_receipt_id"] = scored.json()["id"]
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme browser bundle review",
        cwe_coverage=_network_input_coverage(
            default_effort=80,
            overrides={"ssrf": {
                "effort": 0, "disposition": "not_applicable",
                "notes": "The Acme parser makes no outbound request.",
            }},
        ),
    )

    assert closed.status_code == 200, closed.text
    assert closed.json().get("depth_floor_triggers") is None
    assert _floor_triggers(client, base) == []
    with db_module.get_connection() as connection:
        engagement = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (key,)
        ).fetchone()
        code_analysis._sync_trigger_status_for_file(
            connection, int(engagement["id"]), int(parser["id"])
        )
        connection.commit()
    assert _floor_triggers(client, base) == []


def test_a_close_recorded_before_depth_floor_triggers_is_an_advisory_not_a_blocker(
    client, isolate_settings
):
    """A close an older backend recorded has its below-floor families and no
    trigger. Raising them retroactively turned one engagement's history into
    hundreds of blocking re-reviews, so they are named instead: grouped by tier
    and family with sample paths and the reads and verbs that act on them, and
    the gate does not block on them. A startup does not raise them."""
    key = "2026-11-14-acme-depth-floor-untriggered"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    with sqlite3.connect(str(db_module.database_path())) as connection:
        # The close as an older backend recorded it: no depth-floor trigger.
        connection.execute("DELETE FROM code_analysis_triggers WHERE origin = 'depth_floor'")
    db_module.close_thread_connection()

    db_module.init_db()

    assert _floor_triggers(client, base) == []
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert not any("depth-floor" in reason for reason in gate["reasons"])
    untriggered = gate["untriggered_depth_shortfalls"]
    assert untriggered["total"] == 1
    (group,) = untriggered["groups"]
    assert (group["classification"], group["family"], group["file_count"]) == (
        "critical", "ssrf", 1,
    )
    assert parser["file_path"] in group["sample_file_paths"]
    assert "reanalyze" in untriggered["detail"] and "not_applicable" in untriggered["detail"]
    readiness = client.get(f"{base}/readiness?target_phase=complete").json()
    assert "depth_floor_triggers" not in {b["code"] for b in readiness["blockers"]}
    assert readiness["untriggered_depth_shortfalls"]["total"] == 1
    # The grouped pointer names the read that lists every row, and that read does.
    assert untriggered["rows_omitted"] == 1
    assert "--cwe-matrix" in untriggered["full_list"]
    detailed = client.get(f"{base}/coverage?detail=cwe&repo_id={repo['id']}").json()
    listed = detailed["gate"]["untriggered_depth_shortfalls"]
    assert listed["rows_omitted"] == 0
    assert [(row["file_path"], row["family"]) for row in listed["rows"]] == [
        (parser["file_path"], "ssrf"),
    ]


def test_a_later_review_marking_the_family_not_applicable_settles_its_trigger_for_good(
    client, isolate_settings
):
    key = "2026-11-14-acme-depth-floor-not-applicable-later"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    again = _claim_file_for_reanalysis(client, key, int(parser["id"]), reason="Acme recheck")
    scored = client.post(f"{base}/analysis-results", json=_owned(
        again, queue_item_id=again["id"], disposition="clean",
        evidence="Acme bundle: only same-origin fetches.",
        cwe_coverage=[{"family": "ssrf", "effort": 10}],
    ))
    assert scored.status_code == 201, scored.text
    closed = _close_queue_item(
        client, key, again, disposition="clean", notes="Acme browser bundle review",
        cwe_coverage=_network_input_coverage(
            default_effort=80,
            overrides={"ssrf": {
                "effort": 0, "disposition": "not_applicable",
                "notes": "The Acme parser makes no outbound request.",
            }},
        ),
    )
    assert closed.status_code == 200, closed.text
    with db_module.get_connection() as connection:
        engagement = connection.execute("SELECT id FROM engagements WHERE key = ?", (key,)).fetchone()
        code_analysis._sync_trigger_status_for_file(connection, int(engagement["id"]), int(parser["id"]))
        connection.commit()

    assert _floor_rows(client, base) == [(trigger["id"], "ssrf", "resolved")]


# The keys `code-dispatch resolve-triggers` forwards from each row it reads.
_RESOLVE_ITEM_KEYS = ("trigger_id", "id", "file_path", "target_file_path", "repo_id", "vuln_class")


def _as_resolve_item(row):
    return {key: row[key] for key in _RESOLVE_ITEM_KEYS if row.get(key) not in (None, "")}


def test_list_triggers_rows_resolve_unchanged(client, isolate_settings):
    """`list-triggers` prints rows carrying `id`; `resolve-triggers` takes them as they are."""
    key = "2026-11-14-acme-depth-floor-round-trip"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}, "file-upload": {"effort": 20}}
    ))
    rows = _floor_triggers(client, base)
    assert {row["vuln_class"] for row in rows} == {"ssrf", "file-upload"}

    resolved = client.post(f"{base}/triggers/resolve", json={
        "items": [_as_resolve_item(row) for row in rows],
        "resolution_status": "reviewed_at_sufficient_depth",
        "resolution_note": "Every Acme parser fetch and upload path was traced.",
    })

    assert resolved.status_code == 200, resolved.text
    assert (resolved.json()["resolved"], resolved.json()["not_resolved"]) == (2, [])
    assert _floor_triggers(client, base) == []
    by_path = client.post(f"{base}/triggers/resolve", json={
        "items": [{"target_file_path": parser["file_path"]}],
        "resolution_status": "not_applicable",
        "resolution_note": "Acme: nothing left pending on the parser.",
    }).json()
    assert by_path["not_resolved"] == [parser["file_path"]]
    assert "selector" not in by_path.get("detail", "")
    unselected = client.post(f"{base}/triggers/resolve", json={
        "items": [{}],
        "resolution_status": "reviewed_at_sufficient_depth",
        "resolution_note": "Acme: an item without a selector.",
    }).json()
    assert unselected["not_resolved"] == ["item[0]"]
    assert "no selector" in unselected["detail"]
    assert "depth_floor" not in unselected["detail"]


def test_the_harness_reads_a_closeout_not_applicable_family_as_answered(
    client, isolate_settings
):
    """The effort harness, the depth-floor trigger and the untriggered pointer agree:
    a family the closeout marks not applicable is answered whatever a receipt scored."""
    key = "2026-11-14-acme-depth-floor-na-harness"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    scored = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Acme bundle: fetch() calls only same-origin API paths.",
        cwe_coverage=[{"family": "ssrf", "effort": 10}],
    ))
    assert scored.status_code == 201, scored.text
    claim["_receipt_id"] = scored.json()["id"]
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme browser bundle review",
        cwe_coverage=_network_input_coverage(default_effort=80, overrides={"ssrf": {
            "effort": 0, "disposition": "not_applicable",
            "notes": "The Acme bundle runs in the browser; it never fetches server-side.",
        }}),
    )
    assert closed.status_code == 200, closed.text
    assert _floor_triggers(client, base) == []

    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    gap_families = {
        group["family"] for group in (gate.get("effort_gaps") or {}).get("groups", [])
    }
    assert "ssrf" not in gap_families
    assert gate.get("untriggered_depth_shortfalls") is None
    readiness = client.get(f"{base}/readiness?target_phase=complete").json()
    assert readiness.get("untriggered_depth_shortfalls") is None


def test_a_critical_closeout_says_why_a_family_is_not_applicable(client, isolate_settings):
    """On a critical/high file a not-applicable family settles a depth-floor
    trigger, so the closeout must say why, and the trigger keeps that reason."""
    key = "2026-11-14-acme-depth-floor-na-notes"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=80, overrides={"ssrf": {"effort": 30}}
    ))
    (trigger,) = _floor_triggers(client, base)
    again = _claim_file_for_reanalysis(client, key, int(parser["id"]), reason="Acme recheck")
    again["_receipt_id"] = _record_fixture_source_receipt(client, key, again)["id"]
    blank = _network_input_coverage(default_effort=80, overrides={
        "ssrf": {"effort": 0, "disposition": "not_applicable", "notes": "  "},
        "file-upload": {"effort": 0, "disposition": "not_applicable"},
    })

    for dry_run in (True, False):
        refused = _close_queue_item(
            client, key, again, disposition="clean", notes="Acme review",
            cwe_coverage=blank, dry_run=dry_run,
        )
        assert refused.status_code == 400, refused.text
        assert "file-upload" in refused.text and "ssrf" in refused.text
        assert "notes" in refused.text

    why = "The Acme parser never builds an outbound URL; every fetch target is a constant."
    closed = _close_queue_item(
        client, key, again, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(default_effort=80, overrides={
            "ssrf": {"effort": 0, "disposition": "not_applicable", "notes": why},
        }),
    )
    assert closed.status_code == 200, closed.text
    (settled,) = [
        row for row in client.get(f"{base}/triggers?status=resolved").json()["items"]
        if row["id"] == trigger["id"]
    ]
    assert why in settled["resolution_note"]


def test_a_medium_closeout_may_mark_a_family_not_applicable_without_notes(
    client, isolate_settings
):
    key = "2026-11-14-acme-depth-floor-na-medium"
    _base, _repo, medium = _seed(client, isolate_settings, key, tier="medium")
    claim = _claim_file_for_analysis(client, key, int(medium["id"]))
    _close(client, key, claim, _network_input_coverage(
        default_effort=40, overrides={"ssrf": {"effort": 0, "disposition": "not_applicable"}},
    ))


def test_a_receipt_marking_a_family_not_applicable_on_a_critical_file_owes_notes(
    client, isolate_settings
):
    """A receipt's not-applicable entry answers the family like the closeout's, so
    the closeout's notes rule holds for it too."""
    key = "2026-11-15-acme-depth-floor-receipt-na"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))

    refused = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
        cwe_coverage=[{"family": "ssrf", "effort": 0, "disposition": "not_applicable"}],
    ))
    assert refused.status_code == 400, refused.text
    assert "ssrf" in refused.text and "notes" in refused.text

    recorded = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
        cwe_coverage=[{
            "family": "ssrf", "effort": 0, "disposition": "not_applicable",
            "notes": "The Acme parser never builds an outbound URL.",
        }],
    ))
    assert recorded.status_code == 201, recorded.text


def test_a_family_the_closeout_leaves_out_is_answered_by_a_receipt_that_scored_it(
    client, isolate_settings
):
    """The closeout's effort-0 placeholder gives way to a receipt's score, so the
    family is neither an effort gap nor a depth_floor trigger."""
    key = "2026-11-15-acme-depth-floor-receipt-scored"
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
        cwe_coverage=[{"family": "open-redirect", "effort": 80}],
    ))
    assert receipt.status_code == 201, receipt.text
    claim["_receipt_id"] = receipt.json()["id"]
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=[
            entry for entry in _network_input_coverage(default_effort=80)
            if entry["family"] != "open-redirect"
        ],
    )

    assert closed.status_code == 200, closed.text
    body = closed.json()
    assert body["unreviewed_families_recorded"]["families"] == ["open-redirect"]
    assert body.get("depth_floor_triggers") is None
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    assert "open-redirect" not in {
        group["family"] for group in (gate.get("effort_gaps") or {}).get("groups", [])
    }
