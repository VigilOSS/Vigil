"""A tag or tier change recomputes a reviewed file's obligations; it reopens nothing.

A file's review identity is its slot types and language: a change to either
reopens the review. Context tags only map to review families
(`CONTEXT_TAG_VULN_CLASSES` and the families `client-bundle` makes optional)
and the tier only sets the depth floor, so a tag or tier change leaves the
review, its coverage and its trigger history as they are: a family the change
makes owed that the review on record left below the floor is raised as a
depth_floor trigger for that family alone, and a floor trigger it stops owing
is superseded and named. The role is descriptive metadata. Trigger history is
never deleted: a reopen supersedes the reopened review's own triggers and
keeps them readable.
"""
from __future__ import annotations

import re

from app import db as db_module
from test_code_analysis_api import (
    _append_repo_files,
    _claim_file_for_analysis,
    _classify_file,
    _close_queue_item,
    _create_code_parent_finding,
    _network_input_coverage,
    _owned,
    _register_variant_dispatch,
    _seed_repo_files,
    _source_hash,
    _variant_receipt_payload,
    _verify_code_finding,
)
from test_code_depth_floor_triggers import _floor_triggers, _seed


def _classification(parser, **extra):
    return {
        "file_id": int(parser["id"]), "classification": "critical", "role": "parser",
        "slot_types": ["NETWORK-INPUT"], "analysis_priority": 90, **extra,
    }


def _reviewed_with_history(client, isolate_settings, key, *, ssrf_effort=30):
    """A critical file closed with a cross-file trigger and a settled depth floor."""
    base, repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
        cross_file_triggers=[{
            "file_path": "src/helpers.py", "vuln_class": "ssrf",
            "reason": "Acme: re-check the downstream URL construction.",
        }],
    ))
    assert receipt.status_code == 201, receipt.text
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": ssrf_effort}}
        ),
    )
    assert closed.status_code == 200, closed.text
    if ssrf_effort < 70:
        (floor,) = _floor_triggers(client, base)
        settled = client.post(f"{base}/triggers/resolve", json={
            "items": [{"trigger_id": floor["id"]}],
            "resolution_status": "not_applicable",
            "resolution_note": "Acme parser builds no outbound URL.",
        })
        assert settled.status_code == 200, settled.text
    return base, repo, parser, claim


def _trigger_history(client, base):
    rows = client.get(f"{base}/triggers?include_superseded=true&limit=500").json()["items"]
    return {
        int(row["id"]): (row["status"], row["resolution_note"], row["vuln_class"])
        for row in rows
    }


def _file(client, base, parser):
    return client.get(f"{base}/files/{parser['id']}").json()


def _current_attempts(client, base, parser):
    rows = client.get(f"{base}/analysis-queue?current_only=true&limit=50").json()["items"]
    return [(row["id"], row["status"]) for row in rows if row["file_id"] == parser["id"]]


def test_tagging_reviewed_files_client_bundle_keeps_their_review_and_trigger_history(
    client, isolate_settings
):
    """The e2e reclassify: every field unchanged except `client-bundle` added."""
    key = "2026-11-15-acme-tag-only-reclassify"
    base, repo, parser, claim = _reviewed_with_history(client, isolate_settings, key)
    history = _trigger_history(client, base)
    assert {status for status, _note, _family in history.values()} == {
        "pending", "not_applicable",
    }
    attempts = _current_attempts(client, base, parser)
    assert _file(client, base, parser)["analysis_status"] == "analyzed"

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["client-bundle"]),
    ]})

    assert response.status_code == 200, response.text
    stored = _file(client, base, parser)
    assert stored["context_tags"] == ["client-bundle"]
    assert stored["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts
    after = _trigger_history(client, base)
    assert {trigger_id: after[trigger_id] for trigger_id in history} == history
    # The browser families the tag makes required, which the review on record
    # never scored, are owed for those families alone.
    added = {trigger_id: row for trigger_id, row in after.items() if trigger_id not in history}
    assert {(status, family) for status, _note, family in added.values()} == {
        ("pending", "injection"), ("pending", "prototype-pollution"),
        ("pending", "secrets-exposure"),
    }
    (change,) = response.json()["obligation_changes"]
    assert change["required_families_added"] == [
        "injection", "prototype-pollution", "secrets-exposure",
    ]
    assert "ssrf" in change["optional_families_added"]
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    gap_families = {
        group["family"] for group in (gate.get("effort_gaps") or {}).get("groups", [])
    }
    assert "ssrf" not in gap_families
    assert {"injection", "prototype-pollution", "secrets-exposure"} <= gap_families


def test_re_recording_an_unchanged_classification_keeps_a_reviewed_file_analyzed(
    client, isolate_settings
):
    key = "2026-11-15-acme-unchanged-reclassify"
    base, _repo, parser, _claim = _reviewed_with_history(client, isolate_settings, key)
    history = _trigger_history(client, base)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser),
    ]})

    assert response.status_code == 200, response.text
    assert response.json()["obligation_changes"] == []
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    assert _trigger_history(client, base) == history


def test_a_tag_that_makes_a_family_required_raises_a_trigger_for_that_family_only(
    client, isolate_settings
):
    key = "2026-11-15-acme-tag-adds-family"
    base, _repo, parser, claim = _reviewed_with_history(
        client, isolate_settings, key, ssrf_effort=80
    )
    assert _floor_triggers(client, base) == []
    attempts = _current_attempts(client, base, parser)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["authentication"]),
    ]})

    assert response.status_code == 200, response.text
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts
    raised = {row["vuln_class"]: row for row in _floor_triggers(client, base)}
    # web-app-auth was already required and reviewed at 80.
    assert set(raised) == {"auth-bypass", "rate-limit"}
    for row in raised.values():
        assert row["source_queue_item_id"] == claim["id"]
        assert "authentication" in row["reason"]
    (change,) = response.json()["obligation_changes"]
    assert change["file_id"] == parser["id"]
    assert change["required_families_added"] == ["auth-bypass", "rate-limit"]
    assert sorted(
        entry["family"] for entry in change["depth_floor_triggers"]["raised"]
    ) == ["auth-bypass", "rate-limit"]


def test_a_tag_that_makes_a_pending_floor_family_optional_retires_that_trigger(
    client, isolate_settings
):
    key = "2026-11-15-acme-tag-optional-floor"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": 30}}
        ),
    )
    assert closed.status_code == 200, closed.text
    (floor,) = _floor_triggers(client, base)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["client-bundle"]),
    ]})

    assert response.status_code == 200, response.text
    assert {row["vuln_class"] for row in _floor_triggers(client, base)} == {
        "injection", "prototype-pollution", "secrets-exposure",
    }
    (kept,) = [
        row for row in client.get(
            f"{base}/triggers?include_superseded=true&limit=50"
        ).json()["items"]
        if row["id"] == floor["id"]
    ]
    assert kept["status"] == "pending"
    (change,) = response.json()["obligation_changes"]
    assert change["optional_families_added"] and "ssrf" in change["optional_families_added"]
    assert change["depth_floor_triggers_retired"] == [floor["id"]]


def test_a_review_identity_change_supersedes_trigger_history_instead_of_deleting_it(
    client, isolate_settings
):
    key = "2026-11-15-acme-identity-reopen"
    base, _repo, parser, claim = _reviewed_with_history(client, isolate_settings, key)
    with db_module.get_connection() as connection:
        before = {
            int(row["id"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM code_analysis_triggers ORDER BY id"
            ).fetchall()
        }

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, slot_types=["NETWORK-INPUT", "FILE-CONTENT"]),
    ]})

    assert response.status_code == 200, response.text
    assert _file(client, base, parser)["analysis_status"] == "queued"
    with db_module.get_connection() as connection:
        after = {
            int(row["id"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM code_analysis_triggers ORDER BY id"
            ).fetchall()
        }
    assert set(after) == set(before)
    for trigger_id, row in after.items():
        assert row["status"] == before[trigger_id]["status"]
        assert row["resolution_note"] == before[trigger_id]["resolution_note"]
    floor_rows = [row for row in after.values() if row["origin"] == "depth_floor"]
    assert floor_rows and all(row["source_superseded_at"] for row in floor_rows)
    assert {row["source_supersession_reason"] for row in floor_rows} == {
        "file_review_reopened"
    }
    # The reviewer's hypothesis about another file is still owed.
    cross = [row for row in after.values() if row["origin"] == "cross_file"]
    assert cross and all(row["source_superseded_at"] is None for row in cross)
    assert all(row["status"] == "pending" for row in cross)


def test_a_single_file_tag_patch_recomputes_obligations_without_reopening(
    client, isolate_settings
):
    key = "2026-11-15-acme-tag-patch"
    base, _repo, parser, claim = _reviewed_with_history(
        client, isolate_settings, key, ssrf_effort=80
    )
    attempts = _current_attempts(client, base, parser)

    patched = client.patch(
        f"{base}/files/{parser['id']}", json={"context_tags_json": ["authentication"]}
    )

    assert patched.status_code == 200, patched.text
    assert patched.json()["obligation_change"]["required_families_added"] == [
        "auth-bypass", "rate-limit",
    ]
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts
    assert {row["vuln_class"] for row in _floor_triggers(client, base)} == {
        "auth-bypass", "rate-limit",
    }


def test_file_accounting_blockers_name_sample_paths_and_the_exact_full_list(
    client, isolate_settings
):
    """A readiness blocker that counts files says which ones and how to list them all."""
    key = "2026-11-15-acme-blocker-paths"
    base, repo, parser = _seed(client, isolate_settings, key)
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_files SET classification = 'unclassified' WHERE file_path = ?",
            ("src/helpers.py",),
        )

    for target, code, gap in (
        ("hunt", "files_unclassified", "unclassified"),
        ("hunt", "admitted_files_unqueued", "unqueued"),
        ("verify-variant", "admitted_files_unaccounted", "unaccounted"),
    ):
        readiness = client.get(f"{base}/readiness?target_phase={target}").json()
        (blocker,) = [row for row in readiness["blockers"] if row["code"] == code]
        listed = client.get(
            f"{base}/files?accounting={gap}&repo_id={repo['id']}&limit=100"
        ).json()
        assert blocker["sample_paths"] == sorted(row["file_path"] for row in listed["items"])
        assert blocker["omitted"] == 0
        assert f"accounting={gap}" in blocker["full_list"]
        assert str(listed["total"]) in blocker["message"]


def _admit_extra_files(client, key, repo, count):
    """Admit *count* more Acme python files to the repo's current generation."""
    _append_repo_files(client, key, int(repo["id"]), [
        {
            "file_path": f"src/acme_{index:02d}.py", "language": "python", "loc": 20,
            "file_hash": _source_hash(f"acme-extra-{index}"), "header_snippet": "",
            "git_churn_score": 0, "has_past_cve_fix": False,
        }
        for index in range(count)
    ])
    return [
        row for row in client.get(
            f"/engagements/{key}/assessment/code/files?repo_id={repo['id']}&limit=1000"
        ).json()["items"]
        if row["file_path"].startswith("src/acme_")
    ]


def test_a_tag_only_classification_keeps_every_files_role_and_slot_types(
    client, isolate_settings
):
    """Omitting role and slot_types keeps them; it never reads as a review-identity change."""
    key = "2026-11-15-acme-tag-only-many"
    base, repo, parser = _seed(client, isolate_settings, key)
    extras = _admit_extra_files(client, key, repo, 12)
    parser = next(
        row for row in client.get(f"{base}/files?limit=100").json()["items"]
        if row["file_path"] == "src/parser.py"
    )
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    assert _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(default_effort=80),
    ).status_code == 200
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    recorded = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        {
            "file_id": int(row["id"]), "classification": "high", "role": f"handler-{index}",
            "slot_types": ["URL-COMPONENT"], "analysis_priority": 60,
        }
        for index, row in enumerate(extras)
    ]})
    assert recorded.status_code == 200, recorded.text
    attempts = _current_attempts(client, base, parser)
    history = _trigger_history(client, base)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        {"file_id": int(parser["id"]), "classification": "critical",
         "analysis_priority": 90, "context_tags": ["authentication"]},
        *(
            {"file_id": int(row["id"]), "classification": "high",
             "analysis_priority": 60, "context_tags": []}
            for row in extras
        ),
    ]})

    assert response.status_code == 200, response.text
    body = response.json()
    stored = _file(client, base, parser)
    assert (stored["role"], stored["slot_types"]) == ("parser", ["NETWORK-INPUT"])
    assert stored["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts
    after = _trigger_history(client, base)
    assert {trigger_id: after[trigger_id] for trigger_id in history} == history
    for index, row in enumerate(extras):
        kept = _file(client, base, row)
        assert (kept["role"], kept["slot_types"]) == (f"handler-{index}", ["URL-COMPONENT"])
    derived = {(entry["file_id"], entry["field"]): entry for entry in body["derived"]}
    for row, role in [(parser, "parser"), *((r, f"handler-{i}") for i, r in enumerate(extras))]:
        assert derived[(int(row["id"]), "role")]["value"] == role
        assert derived[(int(row["id"]), "slot_types")]["derived_from"] == "stored"
    (change,) = body["obligation_changes"]
    assert change["required_families_added"] == ["auth-bypass", "rate-limit"]


def test_a_patch_that_nulls_role_slot_types_or_tags_keeps_the_stored_values(
    client, isolate_settings
):
    key = "2026-11-15-acme-patch-nulls"
    base, _repo, parser, _claim = _reviewed_with_history(
        client, isolate_settings, key, ssrf_effort=80
    )
    tagged = client.patch(
        f"{base}/files/{parser['id']}", json={"context_tags_json": ["authentication"]}
    )
    assert tagged.status_code == 200, tagged.text
    attempts = _current_attempts(client, base, parser)

    patched = client.patch(f"{base}/files/{parser['id']}", json={
        "role": None, "slot_types_json": None, "context_tags_json": None,
    })

    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert (body["role"], body["slot_types"], body["context_tags"]) == (
        "parser", ["NETWORK-INPUT"], ["authentication"],
    )
    assert {entry["field"] for entry in body["derived"]} == {
        "role", "slot_types", "context_tags",
    }
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts


def test_a_role_relabel_records_metadata_and_keeps_the_review(client, isolate_settings):
    """The role is descriptive and never read for an obligation."""
    key = "2026-11-15-acme-role-relabel"
    base, _repo, parser, _claim = _reviewed_with_history(client, isolate_settings, key)
    attempts = _current_attempts(client, base, parser)
    history = _trigger_history(client, base)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, role="request_parser"),
    ]})
    patched = client.patch(f"{base}/files/{parser['id']}", json={"role": "wire_parser"})

    assert response.status_code == 200, response.text
    assert response.json()["obligation_changes"] == []
    assert patched.status_code == 200, patched.text
    stored = _file(client, base, parser)
    assert stored["role"] == "wire_parser"
    assert stored["analysis_status"] == "analyzed"
    assert _current_attempts(client, base, parser) == attempts
    assert _trigger_history(client, base) == history
    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json()


def test_a_tier_raise_measures_the_review_on_record_at_the_new_floor(
    client, isolate_settings
):
    key = "2026-11-15-acme-tier-raise"
    base, repo, parser = _seed(client, isolate_settings, key, tier="high")
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": 60}}
        ),
    )
    assert closed.status_code == 200, closed.text
    assert _floor_triggers(client, base) == []
    attempts = _current_attempts(client, base, parser)

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser),
    ]})

    assert response.status_code == 200, response.text
    stored = _file(client, base, parser)
    assert (stored["classification"], stored["analysis_status"]) == ("critical", "analyzed")
    assert _current_attempts(client, base, parser) == attempts
    (raised,) = _floor_triggers(client, base)
    assert raised["vuln_class"] == "ssrf"
    assert raised["source_queue_item_id"] == claim["id"]
    assert "high" in raised["reason"] and "critical" in raised["reason"]
    (change,) = response.json()["obligation_changes"]
    assert (change["previous_classification"], change["classification"]) == (
        "high", "critical",
    )
    assert [entry["family"] for entry in change["depth_floor_triggers"]["raised"]] == ["ssrf"]
    assert client.get(f"{base}/analysis-results?file_id={parser['id']}").json()


def test_a_tier_drop_retires_the_floor_triggers_the_new_tier_does_not_owe(
    client, isolate_settings
):
    key = "2026-11-15-acme-tier-drop"
    base, _repo, parser, _claim = _reviewed_with_history(client, isolate_settings, key)
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE code_analysis_triggers SET status = 'pending', resolution_note = '' "
            "WHERE origin = 'depth_floor'"
        )
    (floor,) = _floor_triggers(client, base)
    attempts = _current_attempts(client, base, parser)

    high = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="high", analysis_priority=60),
    ]})
    assert high.status_code == 200, high.text
    # ssrf at 30 is still below the high floor of 50: the trigger stays owed.
    assert [row["id"] for row in _floor_triggers(client, base)] == [floor["id"]]

    medium = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="medium", analysis_priority=30),
    ]})

    assert medium.status_code == 200, medium.text
    assert _floor_triggers(client, base) == []
    assert _current_attempts(client, base, parser) == attempts
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    (change,) = medium.json()["obligation_changes"]
    assert change["depth_floor_triggers_retired"] == [floor["id"]]
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT status, source_superseded_at, source_supersession_reason "
            "FROM code_analysis_triggers WHERE id = ?", (floor["id"],),
        ).fetchone()
    assert row["status"] == "pending" and row["source_superseded_at"]
    assert row["source_supersession_reason"] == "tier_floor_lowered"


def test_promoting_a_skip_closed_file_to_an_unskippable_tier_reopens_its_review(
    client, isolate_settings
):
    """A skipped closeout cannot stand on a tier `done skipped` refuses."""
    key = "2026-11-15-acme-skip-promoted"
    base, _repo, _parser = _seed(client, isolate_settings, key)
    helper = next(
        row for row in client.get(f"{base}/files?limit=50").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    claim = _claim_file_for_analysis(client, key, int(helper["id"]))
    skipped = _close_queue_item(
        client, key, claim, disposition="skipped", skip_reason="generated-code",
        notes="Acme generated stub",
    )
    assert skipped.status_code == 200, skipped.text

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": int(helper["id"]), "classification": "high", "role": "helper",
        "slot_types": ["NETWORK-INPUT"], "analysis_priority": 60,
    }]})

    assert response.status_code == 200, response.text
    assert _file(client, base, helper)["analysis_status"] == "queued"


def test_a_tag_change_that_retires_every_queued_trigger_withdraws_the_unclaimed_requeue(
    client, isolate_settings
):
    key = "2026-11-15-acme-requeue-withdrawn"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    assert _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": 30}}
        ),
    ).status_code == 200
    (floor,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": floor["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    directed = int(requeued.json()["outcomes"][0]["queue_item_id"])

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["client-bundle"]),
    ]})

    assert response.status_code == 200, response.text
    (change,) = response.json()["obligation_changes"]
    assert change["depth_floor_triggers_retired"] == [floor["id"]]
    (withdrawn,) = change["requeue_withdrawn"]
    assert withdrawn["queue_item_id"] == directed
    # The trigger it carried was retired, so it stays retired: nothing returns.
    assert withdrawn["returned_trigger_ids"] == []
    assert withdrawn["retired_trigger_ids"] == [floor["id"]]
    assert _current_attempts(client, base, parser) == [(claim["id"], "done")]
    assert _file(client, base, parser)["analysis_status"] == "analyzed"
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "analysis_queue_active" not in {row["code"] for row in readiness["blockers"]}
    activity = client.get(
        f"/engagements/{key}/activity-entries", params={"q": "code-record classify"}
    ).json()["items"]
    (entry,) = [
        row for row in activity
        if row["title"] == "code-record classify" and row["metadata"]["obligation_changes"]
    ]
    (audited,) = entry["metadata"]["obligation_changes"]
    assert audited["requeue_withdrawn"][0]["queue_item_id"] == directed


def test_a_claimed_requeue_is_kept_and_named_when_its_trigger_retires(
    client, isolate_settings
):
    key = "2026-11-15-acme-requeue-kept"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    assert _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": 30}}
        ),
    ).status_code == 200
    (floor,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": floor["id"]}]}
    )
    directed = int(requeued.json()["outcomes"][0]["queue_item_id"])
    fetched = client.post(f"{base}/analysis-queue/fetch", json={
        "limit": 1, "agent_name": "code-vuln-hunter", "item_ids": [directed],
    })
    assert fetched.status_code == 200 and fetched.json(), fetched.text

    response = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["client-bundle"]),
    ]})

    assert response.status_code == 200, response.text
    (change,) = response.json()["obligation_changes"]
    assert "requeue_withdrawn" not in change
    (kept,) = change["requeue_kept"]
    assert kept["queue_item_id"] == directed and "processing" in kept["reason"]
    assert (directed, "processing") in _current_attempts(client, base, parser)


def test_coverage_counts_the_floor_triggers_a_reclassification_retired(
    client, isolate_settings
):
    key = "2026-11-15-acme-retired-count"
    base, repo, parser, _claim = _reviewed_with_history(
        client, isolate_settings, key, ssrf_effort=80
    )
    added = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=["authentication"]),
    ]})
    assert added.status_code == 200, added.text
    assert len(_floor_triggers(client, base)) == 2

    removed = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, context_tags=[]),
    ]})

    assert removed.status_code == 200, removed.text
    summary = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["trigger_summary"]
    assert summary["depth_floor_retired"] == 2
    assert summary["depth_floor_pending"] == 0


def _shallow_review(client, key, base, parser, *, ssrf_effort):
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    receipt = client.post(f"{base}/analysis-results", json=_owned(
        claim, queue_item_id=claim["id"], disposition="clean",
        evidence="Fixture reviewed the exact current source.",
    ))
    assert receipt.status_code == 201, receipt.text
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme review",
        cwe_coverage=_network_input_coverage(
            default_effort=80, overrides={"ssrf": {"effort": ssrf_effort}}
        ),
    )
    assert closed.status_code == 200, closed.text
    return claim


def _floor_trigger_row(trigger_id):
    with db_module.get_connection() as connection:
        return dict(connection.execute(
            "SELECT status, resolved_queue_item_id, resolution_note, source_superseded_at, "
            "source_supersession_reason FROM code_analysis_triggers WHERE id = ?",
            (trigger_id,),
        ).fetchone())


def test_coverage_and_readiness_name_the_files_a_tier_drop_retired_floor_triggers_on(
    client, isolate_settings
):
    """A lowered tier legitimately lowers the floor; the retirement is never silent."""
    key = "2026-11-15-acme-retired-files"
    base, repo, parser = _seed(client, isolate_settings, key)
    _shallow_review(client, key, base, parser, ssrf_effort=10)
    (floor,) = _floor_triggers(client, base)

    dropped = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="medium", analysis_priority=30),
    ]})

    assert dropped.status_code == 200, dropped.text
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    retired = gate["depth_floor_retired_files"]
    assert retired["count"] == 1 and retired["triggers"] == 1
    assert retired["by_reason"] == {"tier_floor_lowered": 1}
    assert retired["sample"] == [{
        "file_path": "src/parser.py", "classification": "medium", "families": ["ssrf"],
        "reasons": ["tier_floor_lowered"], "trigger_ids": [floor["id"]],
    }]
    assert retired["omitted"] == 0
    # The full list is an exact read: the same triggers, nothing else.
    (route,) = re.findall(r"'(code/triggers\?[^']+)'", retired["full_list"])
    listed = client.get(f"/engagements/{key}/assessment/{route}").json()
    assert [row["id"] for row in listed["items"]] == [floor["id"]]
    assert listed["items"][0]["source_supersession_reason"] == "tier_floor_lowered"
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    engagement_wide = client.get(f"{base}/coverage").json()["gate"]["depth_floor_retired_files"]
    assert readiness["depth_floor_retired_files"] == engagement_wide
    assert engagement_wide["sample"] == retired["sample"]


def test_the_classify_audit_names_the_dispatch_or_operator_that_classified(
    client, isolate_settings
):
    key = "2026-11-15-acme-classify-actor"
    base, _repo, parser = _seed(client, isolate_settings, key)
    _shallow_review(client, key, base, parser, ssrf_effort=10)
    architect = client.post(f"/engagements/{key}/assessment/dispatches", json={
        "agent_id": "acme-architect", "agent_role": "code-architect",
        "task": "Classify the Acme repository.",
    })
    assert architect.status_code == 201, architect.text

    by_dispatch = client.post(f"{base}/files/bulk-classify", json={
        "classifications": [_classification(parser, classification="high", analysis_priority=60)],
        "recorded_by_agent_id": "acme-architect",
    })
    by_operator = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="medium", analysis_priority=30),
    ]})
    unknown = client.post(f"{base}/files/bulk-classify", json={
        "classifications": [_classification(parser, classification="low", analysis_priority=10)],
        "recorded_by_agent_id": "acme-nobody",
    })
    patched = client.patch(f"{base}/files/{parser['id']}", json={
        "classification": "high", "analysis_priority": 60,
        "recorded_by_agent_id": "acme-architect",
    })

    assert by_dispatch.status_code == 200, by_dispatch.text
    assert by_dispatch.json()["recorded_by"] == {
        "agent_id": "acme-architect", "agent_role": "code-architect",
    }
    assert by_operator.status_code == 200, by_operator.text
    assert by_operator.json()["recorded_by"] == {"agent_id": None, "agent_role": "operator"}
    assert unknown.status_code == 422, unknown.text
    assert "acme-nobody" in unknown.text
    assert patched.status_code == 200, patched.text
    assert patched.json()["recorded_by"]["agent_id"] == "acme-architect"
    assert _file(client, base, parser)["classification"] == "high"
    activity = client.get(
        f"/engagements/{key}/activity-entries", params={"q": "code-record classify"}
    ).json()["items"]
    audited = sorted(
        (row["id"], row["actor_name"], row["metadata"].get("recorded_by"))
        for row in activity if row["title"] == "code-record classify"
    )
    # The fixture's own classifications, then the three accepted writes above.
    assert [(actor, recorder) for _id, actor, recorder in audited[-3:]] == [
        ("acme-architect", {"agent_id": "acme-architect", "agent_role": "code-architect"}),
        ("operator", {"agent_id": None, "agent_role": "operator"}),
        ("acme-architect", {"agent_id": "acme-architect", "agent_role": "code-architect"}),
    ]


def test_a_tier_drop_under_a_pending_requeue_measures_the_review_before_it(
    client, isolate_settings
):
    key = "2026-11-15-acme-requeue-tier-drop"
    base, _repo, parser = _seed(client, isolate_settings, key)
    claim = _shallow_review(client, key, base, parser, ssrf_effort=60)
    (floor,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": floor["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    directed = int(requeued.json()["outcomes"][0]["queue_item_id"])

    high = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="high", analysis_priority=60),
    ]})

    assert high.status_code == 200, high.text
    (change,) = high.json()["obligation_changes"]
    # ssrf at 60 meets the high floor of 50 on the review the requeue suspended.
    assert change["depth_floor_triggers_retired_reasons"] == {
        str(floor["id"]): "tier_floor_lowered",
    }
    assert [entry["queue_item_id"] for entry in change["requeue_withdrawn"]] == [directed]
    assert _current_attempts(client, base, parser) == [(claim["id"], "done")]
    assert _file(client, base, parser)["analysis_status"] == "analyzed"


def test_withdrawing_an_emptied_requeue_leaves_its_retired_triggers_retired(
    client, isolate_settings
):
    key = "2026-11-15-acme-requeue-retired-kept"
    base, _repo, parser = _seed(client, isolate_settings, key)
    _shallow_review(client, key, base, parser, ssrf_effort=10)
    (floor,) = _floor_triggers(client, base)
    requeued = client.post(
        f"{base}/analysis-queue/requeue", json={"items": [{"trigger_id": floor["id"]}]}
    )
    assert requeued.status_code == 201, requeued.text
    before = _floor_trigger_row(floor["id"])
    assert before["status"] == "queued"

    medium = client.post(f"{base}/files/bulk-classify", json={"classifications": [
        _classification(parser, classification="medium", analysis_priority=30),
    ]})

    assert medium.status_code == 200, medium.text
    (change,) = medium.json()["obligation_changes"]
    (withdrawn,) = change["requeue_withdrawn"]
    assert withdrawn["returned_trigger_ids"] == []
    assert withdrawn["retired_trigger_ids"] == [floor["id"]]
    after = _floor_trigger_row(floor["id"])
    assert after["status"] == "queued"
    assert after["resolution_note"] == before["resolution_note"]
    assert after["source_supersession_reason"] == "tier_floor_lowered"
    assert after["source_superseded_at"]


def _variant_checked_parser(client, isolate_settings, key):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(row for row in files if row["file_path"] == "src/parser.py")
    _classify_file(client, key, int(parser["id"]), "critical", 100)
    _create_code_parent_finding(client, key, int(repo["id"]), slug="AC-701")
    _verify_code_finding(client, key, int(repo["id"]), "AC-701")
    dispatch = _register_variant_dispatch(client, key, agent_id="acme-variant", finding_slugs=["AC-701"])
    base = f"/engagements/{key}/assessment/code"
    recorded = client.post(f"{base}/variant-checks", json=_variant_receipt_payload(
        client, key, int(repo["id"]), parser, dispatch, parent_finding_slugs=["AC-701"],
    ))
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["current"] is True
    return base, parser, recorded.json()


def test_a_variant_check_receipt_stays_current_across_role_and_tier_changes(
    client, isolate_settings
):
    """The receipt proves the file's bytes were checked against the parent set;
    the role label and the tier set review order, never receipt eligibility."""
    base, parser, receipt = _variant_checked_parser(
        client, isolate_settings, "2026-11-15-acme-variant-relabel"
    )

    relabeled = client.patch(f"{base}/files/{parser['id']}", json={"role": "acme-relabel"})
    lowered = client.patch(
        f"{base}/files/{parser['id']}", json={"classification": "high", "analysis_priority": 60}
    )

    assert relabeled.status_code == 200, relabeled.text
    assert lowered.status_code == 200, lowered.text
    stored = _file(client, base, parser)
    assert (stored["role"], stored["classification"]) == ("acme-relabel", "high")
    assert stored["variant_check_status"] == "done"
    current = client.get(f"{base}/variant-checks?file_id={parser['id']}").json()
    assert [(row["id"], row["current"]) for row in current] == [(receipt["id"], True)]
    # The receipt keeps the labels it was recorded under.
    assert (current[0]["role"], current[0]["classification"]) == (
        receipt["role"], receipt["classification"],
    )
