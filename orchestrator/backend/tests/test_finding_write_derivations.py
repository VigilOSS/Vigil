"""Finding writes fill what the rest of the payload already says, and say so.

A value the service can compute from what the caller wrote (the CVSS score of a
vector, a block or kill reason the verify rationale states, the downgraded
verdict a lower band on a live finding is) is filled in instead of refused, and
every fill is named on the write envelope's ``derived`` list so the caller sees
exactly what was stored on its behalf. Where the caller authored both halves of
a pair and they disagree, the write is still refused: a derivation never
overrides what was written.
"""
from __future__ import annotations

import json

import pytest

from app import db as db_module
from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_change_policy import _RUNTIME_PLAN, _receipt, _record
from tests.test_verification_status_contract import BASE, _seed, _verify_with_proof

_HIGH_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
_CRITICAL_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0


def _derived(response) -> dict[str, dict]:
    body = response.json()
    assert isinstance(body["derived"], list), body
    return {entry["field"]: entry for entry in body["derived"]}


def _details(client, slug: str) -> dict:
    return client.get(f"{BASE}/findings/{slug}").json()["details"]


def _latest_transition(client, slug: str) -> dict:
    latest = client.get(f"{BASE}/findings/{slug}/transitions").json()[0]
    return client.get(f"{BASE}/findings/{slug}/transitions/{latest['id']}").json()


def _counter_check(receipt_id: int) -> dict:
    return {
        "method": "authorization-dominance source proof",
        "expected_result": "an unguarded path reaches the read",
        "observed_result": "every path is dominated by the Acme tenant guard",
        "falsified_claim": "a path bypasses tenant authorization",
        "completed": True,
        "proof_receipt_ids": [receipt_id],
    }


@pytest.fixture
def seeded(client, isolate_settings):
    _seed(client, isolate_settings)


# --- cvss_score from cvss_vector ------------------------------------------------


def test_record_with_only_a_vector_stores_its_computed_score(client, seeded):
    response = client.post(f"{BASE}/findings", json={
        "slug": "VA-601", "title": "VA-601 finding", "severity": "high",
        "workflow_status": "active", "verification_status": "unreviewed",
        "canonical_location": "https://example.test/VA-601", "summary": "s",
        "source_name": "hunter-a", "provenance": {"agent_id": "HUNT-A"},
        "details": {"evidence": "e", "impact": "i", "cvss_vector": _HIGH_VECTOR},
    })

    assert response.status_code == 201, response.text
    assert _derived(response)["details.cvss_score"]["value"] == 7.5
    assert _derived(response)["details.cvss_score"]["derived_from"] == "details.cvss_vector"
    assert _details(client, "VA-601")["cvss_score"] == 7.5
    assert "details.cvss_score" in json.loads(
        _latest_transition(client, "VA-601")["metadata_json"]
    )["derived"]


def test_a_vector_only_patch_that_contradicts_the_stored_score_is_refused(client, seeded):
    # The stored score is a value someone recorded; a vector that computes to a
    # different one contradicts it, so the write names both instead of
    # overwriting either.
    _record(client, "VA-602", details={
        "evidence": "e", "impact": "i", "cvss_score": 7.5, "cvss_vector": _HIGH_VECTOR,
    })

    response = client.patch(f"{BASE}/findings/VA-602", json={
        "details": {"cvss_vector": _CRITICAL_VECTOR},
    })

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "7.5" in detail and "10.0" in detail
    assert _details(client, "VA-602")["cvss_score"] == 7.5


def test_a_vector_and_score_patch_rescores_the_finding(client, seeded):
    _record(client, "VA-605", details={
        "evidence": "e", "impact": "i", "cvss_score": 7.5, "cvss_vector": _HIGH_VECTOR,
    })

    response = client.patch(f"{BASE}/findings/VA-605", json={
        "details": {"cvss_vector": _CRITICAL_VECTOR, "cvss_score": 10.0},
    })

    assert response.status_code == 200, response.text
    assert _details(client, "VA-605")["cvss_score"] == 10.0


def test_a_patch_that_changes_nothing_derives_nothing(client, seeded):
    _record(client, "VA-603", details={
        "evidence": "e", "impact": "i", "cvss_score": 7.5, "cvss_vector": _HIGH_VECTOR,
    })

    response = client.patch(f"{BASE}/findings/VA-603", json={
        "details": {"cvss_vector": _HIGH_VECTOR, "impact": "wider"},
    })

    assert response.status_code == 200, response.text
    assert response.json()["derived"] == []


def test_an_authored_score_that_disagrees_with_an_authored_vector_is_still_refused(
    client, seeded
):
    _record(client, "VA-604")

    response = client.patch(f"{BASE}/findings/VA-604", json={
        "details": {"cvss_score": 9.8, "cvss_vector": _HIGH_VECTOR},
    })

    assert response.status_code == 400, response.text
    assert "computes to 7.5" in response.json()["detail"]


# --- kill / withdrawal reasons ---------------------------------------------------


def test_a_kill_without_kill_details_takes_its_reason_from_the_rationale(client, seeded):
    _record(client, "VA-611")
    receipt_id = _receipt(client, "VA-611", "kill")

    response = client.post(f"{BASE}/findings/VA-611/verify", json={
        "verification_status": "false_positive",
        "reason_text": "The Acme tenant guard dominates every path.",
        "counter_check": _counter_check(receipt_id),
    })

    assert response.status_code == 200, response.text
    assert response.json()["finding"]["verification_status"] == "false_positive"
    derived = _derived(response)
    assert derived["details.kill_reason"]["value"] == "The Acme tenant guard dominates every path."
    assert derived["details.kill_reason"]["derived_from"] == "reason_text"
    assert _details(client, "VA-611")["kill_reason"] == "The Acme tenant guard dominates every path."


def test_withdrawn_without_withdrawal_reason_takes_it_from_the_rationale(client, seeded):
    _record(client, "VA-624")
    submitted = client.patch(f"{BASE}/findings/VA-624", json={
        "submission_status": "submitted", "submission_ref": "ACME-624",
    })
    assert submitted.status_code == 200, submitted.text

    response = client.patch(f"{BASE}/findings/VA-624", json={
        "submission_status": "withdrawn",
        "reason_text": "Duplicate of an Acme-internal report.",
    })

    assert response.status_code == 200, response.text
    assert _derived(response)["details.withdrawal_reason"]["derived_from"] == "reason_text"
    assert _details(client, "VA-624")["withdrawal_reason"] == "Duplicate of an Acme-internal report."


# --- verify rationale from the structured check --------------------------------


def _transition_reason(client, slug: str) -> str:
    return _latest_transition(client, slug)["reason_text"]


def test_pending_runtime_proof_without_a_reason_states_the_plan(client, seeded):
    _record(client, "VA-631")

    response = client.post(f"{BASE}/findings/VA-631/verify", json={
        "verification_status": "pending_runtime_proof", "next_test": _RUNTIME_PLAN,
    })

    assert response.status_code == 200, response.text
    assert _derived(response)["reason_text"]["derived_from"] == "next_test.hypothesis"
    assert _RUNTIME_PLAN["hypothesis"] in _transition_reason(client, "VA-631")


def test_confirmed_without_a_reason_states_the_confirm_check(client, seeded):
    _record(client, "VA-632")
    receipt_id = _receipt(client, "VA-632", "confirm")
    check = completed_confirm_check(receipt_id)

    response = client.post(f"{BASE}/findings/VA-632/verify", json={
        "verification_status": "confirmed",
        "proof_receipt_ids": [receipt_id], "confirm_check": check,
    })

    assert response.status_code == 200, response.text
    assert _derived(response)["reason_text"]["derived_from"] == "confirm_check"
    assert check["observed_result"] in _transition_reason(client, "VA-632")


def test_blocked_without_a_reason_states_the_block_reason(client, seeded):
    _record(client, "VA-633")

    response = client.post(f"{BASE}/findings/VA-633/verify", json={
        "verification_status": "blocked",
        "details": {"block_reason": "Awaiting the Acme staging window."},
    })

    assert response.status_code == 200, response.text
    assert _transition_reason(client, "VA-633") == "Awaiting the Acme staging window."


def test_disputed_still_requires_a_reason(client, seeded):
    _record(client, "VA-634")

    response = client.post(f"{BASE}/findings/VA-634/verify", json={
        "verification_status": "disputed",
    })

    assert response.status_code == 400, response.text
    assert "reason_text" in response.json()["detail"]


def test_leaving_a_held_terminal_verdict_still_requires_a_reason(client, seeded):
    _record(client, "VA-635")
    assert _verify_with_proof(client, "VA-635").status_code == 200

    response = client.post(f"{BASE}/findings/VA-635/verify", json={
        "verification_status": "pending_runtime_proof", "next_test": _RUNTIME_PLAN,
    })

    assert response.status_code == 400, response.text
    assert "reason_text" in response.json()["detail"]
    assert client.get(f"{BASE}/findings/VA-635").json()["verification_status"] == "confirmed"


def test_a_write_that_derives_nothing_reports_an_empty_list(client, seeded):
    _record(client, "VA-636")

    response = client.patch(f"{BASE}/findings/VA-636", json={"summary": "revised"})

    assert response.status_code == 200, response.text
    assert response.json()["derived"] == []
    assert response.json()["advisories"] == []
    with db_module.get_connection() as connection:
        metadata = connection.execute(
            "SELECT metadata_json FROM assessment_finding_transitions "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    assert "derived" not in json.loads(metadata or "{}")


# --- refusals name the field that is actually missing ----------------------------


def test_a_lower_band_confirm_without_a_confirm_check_names_the_confirm_check(client, seeded):
    """confirmed with a lower new_severity is recorded as downgraded; what it
    lacks is the confirm_check, not a reason the check would have stated."""
    _record(client, "VA-641")
    receipt_id = _receipt(client, "VA-641", "lower")

    response = client.post(f"{BASE}/findings/VA-641/verify", json={
        "verification_status": "confirmed", "new_severity": "low",
        "proof_receipt_ids": [receipt_id],
    })

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "confirm_check" in detail
    assert "downgraded" in detail and "new_severity" in detail
    assert not detail.startswith("reason_text is required")


def test_a_blocked_reason_over_the_block_reason_cap_names_reason_text(client, seeded):
    _record(client, "VA-642")

    response = client.post(f"{BASE}/findings/VA-642/verify", json={
        "verification_status": "blocked", "reason_text": "x" * 600,
    })

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "reason_text" in detail and "500" in detail and "details.block_reason" in detail


# --- a killed verdict revived states why ----------------------------------------


def _kill(client, slug: str) -> None:
    receipt_id = _receipt(client, slug, "kill")
    killed = client.post(f"{BASE}/findings/{slug}/verify", json={
        "verification_status": "false_positive",
        "reason_text": "The Acme tenant guard dominates every path.",
        "counter_check": _counter_check(receipt_id),
    })
    assert killed.status_code == 200, killed.text


def test_reviving_a_killed_finding_requires_a_written_reason(client, seeded):
    _record(client, "VA-643")
    _kill(client, "VA-643")
    receipt_id = _receipt(client, "VA-643", "revive")
    body = {
        "verification_status": "confirmed",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id),
    }

    refused = client.post(f"{BASE}/findings/VA-643/verify", json=body)

    assert refused.status_code == 400, refused.text
    assert "reason_text" in refused.json()["detail"]
    assert "false_positive" in refused.json()["detail"]
    assert client.get(f"{BASE}/findings/VA-643").json()["verification_status"] == "false_positive"

    revived = client.post(f"{BASE}/findings/VA-643/verify", json={
        **body, "reason_text": "A second Acme tenant reproduces the cross-org read.",
    })
    assert revived.status_code == 200, revived.text
    assert revived.json()["finding"]["verification_status"] == "confirmed"


@pytest.mark.parametrize("workflow_status", ["draft", "active"])
def test_reopening_a_killed_finding_requires_a_written_reason(
    client, seeded, workflow_status
):
    """A patch reopen is the other door out of a kill, so it states why too.

    Without this, a reopen with no reason clears the false_positive verdict and
    a reasonless confirm then revives the finding, so nothing records what the
    kill got wrong.
    """
    slug = f"VA-64{6 if workflow_status == 'draft' else 7}"
    _record(client, slug)
    _kill(client, slug)

    refused = client.patch(
        f"{BASE}/findings/{slug}", json={"workflow_status": workflow_status}
    )

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "--reason" in detail and "what the kill got wrong" in detail
    assert client.get(f"{BASE}/findings/{slug}").json()["verification_status"] == "false_positive"

    reopened = client.patch(f"{BASE}/findings/{slug}", json={
        "workflow_status": workflow_status,
        "reason_text": "The Acme tenant guard is bypassed by the legacy export route.",
    })
    assert reopened.status_code == 200, reopened.text
    assert _transition_reason(client, slug) == (
        "The Acme tenant guard is bypassed by the legacy export route."
    )


# --- the ledger and the audit log record what was stored -------------------------


def test_variance_fills_are_named_on_the_transition_ledger(client, seeded):
    _record(client, "VA-644", details={
        "evidence": "e", "impact": "i", "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    })
    receipt_id = _receipt(client, "VA-644", "variance")

    response = client.post(f"{BASE}/findings/VA-644/verify", json={
        "verification_status": "confirmed",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id),
        "severity_variance": {"reason": "Contractual exposure for Acme justifies high."},
    })

    assert response.status_code == 200, response.text
    envelope = {entry["field"] for entry in response.json()["derived"]}
    ledger = set(json.loads(_latest_transition(client, "VA-644")["metadata_json"])["derived"])
    assert "severity_variance.actor" in envelope
    assert envelope == ledger


def test_the_verify_audit_entry_records_the_stored_verdict_and_reason(client, seeded):
    _record(client, "VA-645")
    receipt_id = _receipt(client, "VA-645", "audit")

    response = client.post(f"{BASE}/findings/VA-645/verify", json={
        "verification_status": "confirmed", "new_severity": "low",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id),
    })

    assert response.status_code == 200, response.text
    with db_module.get_connection() as connection:
        entry = connection.execute(
            "SELECT action, result, metadata_json FROM activity_entries "
            "WHERE title = 'finding-verify' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert "verification_status=downgraded" in entry["action"]
    assert entry["result"] == _transition_reason(client, "VA-645")
    assert json.loads(entry["metadata_json"])["verification_status"] == "downgraded"


# --- a derived reason comes from this write, never an earlier verdict's details ---


def test_a_new_blocked_episode_does_not_reuse_an_earlier_block_reason(client, seeded):
    _record(client, "VA-651")
    first = client.post(f"{BASE}/findings/VA-651/verify", json={
        "verification_status": "blocked", "reason_text": "Need the Acme admin account.",
    })
    assert first.status_code == 200, first.text
    unblocked = client.post(f"{BASE}/findings/VA-651/verify", json={
        "verification_status": "pending_runtime_proof", "reason_text": "Account granted.",
        "next_test": _RUNTIME_PLAN,
    })
    assert unblocked.status_code == 200, unblocked.text

    refused = client.post(f"{BASE}/findings/VA-651/verify", json={
        "verification_status": "blocked",
    })

    assert refused.status_code == 400, refused.text
    assert "reason_text" in refused.json()["detail"]
    assert client.get(f"{BASE}/findings/VA-651").json()["verification_status"] == (
        "pending_runtime_proof"
    )

    reblocked = client.post(f"{BASE}/findings/VA-651/verify", json={
        "verification_status": "blocked", "reason_text": "Acme staging VPN is down.",
    })
    assert reblocked.status_code == 200, reblocked.text
    assert _details(client, "VA-651")["block_reason"] == "Acme staging VPN is down."
    assert _derived(reblocked)["details.block_reason"]["derived_from"] == "reason_text"
    assert _transition_reason(client, "VA-651") == "Acme staging VPN is down."


def test_a_blocked_revision_without_a_reason_is_refused(client, seeded):
    _record(client, "VA-652")
    first = client.post(f"{BASE}/findings/VA-652/verify", json={
        "verification_status": "blocked", "reason_text": "Need the Acme admin account.",
    })
    assert first.status_code == 200, first.text

    refused = client.post(f"{BASE}/findings/VA-652/verify", json={
        "verification_status": "blocked",
    })
    assert refused.status_code == 400, refused.text
    assert "reason_text" in refused.json()["detail"]

    revised = client.post(f"{BASE}/findings/VA-652/verify", json={
        "verification_status": "blocked", "reason_text": "Still waiting on Acme IT.",
    })
    assert revised.status_code == 200, revised.text
    # The block itself is unchanged; the revision's reason is its own.
    assert _details(client, "VA-652")["block_reason"] == "Need the Acme admin account."
    assert _transition_reason(client, "VA-652") == "Still waiting on Acme IT."


def test_a_rekill_states_its_own_counter_check_not_the_earlier_kill(client, seeded):
    _record(client, "VA-653")
    _kill(client, "VA-653")
    revived = client.post(f"{BASE}/findings/VA-653/verify", json={
        "verification_status": "pending_runtime_proof",
        "reason_text": "The legacy Acme export route bypasses the guard.",
        "next_test": _RUNTIME_PLAN,
    })
    assert revived.status_code == 200, revived.text
    receipt_id = _receipt(client, "VA-653", "rekill")
    check = {**_counter_check(receipt_id),
             "observed_result": "the legacy export route also checks the tenant",
             "falsified_claim": "the legacy export route skips tenant authorization"}

    rekilled = client.post(f"{BASE}/findings/VA-653/verify", json={
        "verification_status": "false_positive", "counter_check": check,
    })

    assert rekilled.status_code == 200, rekilled.text
    reason = _transition_reason(client, "VA-653")
    assert "the legacy export route also checks the tenant" in reason
    assert "dominates every path" not in reason
    stored = _details(client, "VA-653")["kill_reason"]
    assert "the legacy export route also checks the tenant" in stored
    assert _derived(rekilled)["details.kill_reason"]["derived_from"] == "counter_check"



def test_a_rekill_names_the_stored_kill_reason_it_replaced(client, seeded):
    _record(client, "VA-654")
    _kill(client, "VA-654")
    revived = client.post(f"{BASE}/findings/VA-654/verify", json={
        "verification_status": "pending_runtime_proof",
        "reason_text": "The legacy Acme export route bypasses the guard.",
        "next_test": _RUNTIME_PLAN,
    })
    assert revived.status_code == 200, revived.text
    receipt_id = _receipt(client, "VA-654", "rekill")

    rekilled = client.post(f"{BASE}/findings/VA-654/verify", json={
        "verification_status": "false_positive", "counter_check": _counter_check(receipt_id),
    })

    assert rekilled.status_code == 200, rekilled.text
    entry = _derived(rekilled)["details.kill_reason"]
    assert entry["derived_from"] == "counter_check"
    assert "replaced" in entry["detail"]
    assert "The Acme tenant guard dominates every path." in entry["detail"]
    assert "was not supplied" not in entry["detail"]


def test_a_kill_reason_written_after_the_revival_states_the_rekill(client, seeded):
    _record(client, "VA-655")
    _kill(client, "VA-655")
    revived = client.post(f"{BASE}/findings/VA-655/verify", json={
        "verification_status": "pending_runtime_proof",
        "reason_text": "The legacy Acme export route bypasses the guard.",
        "next_test": _RUNTIME_PLAN,
    })
    assert revived.status_code == 200, revived.text
    written = client.patch(f"{BASE}/findings/VA-655", json={
        "details": {"kill_reason": "The legacy export route also checks the Acme tenant."},
    })
    assert written.status_code == 200, written.text
    receipt_id = _receipt(client, "VA-655", "rekill")

    rekilled = client.post(f"{BASE}/findings/VA-655/verify", json={
        "verification_status": "false_positive", "counter_check": _counter_check(receipt_id),
    })

    assert rekilled.status_code == 200, rekilled.text
    assert _details(client, "VA-655")["kill_reason"] == (
        "The legacy export route also checks the Acme tenant."
    )
    assert "details.kill_reason" not in _derived(rekilled)


def test_a_block_reason_written_after_the_unblock_states_the_reblock(client, seeded):
    _record(client, "VA-656")
    first = client.post(f"{BASE}/findings/VA-656/verify", json={
        "verification_status": "blocked", "reason_text": "Need the Acme admin account.",
    })
    assert first.status_code == 200, first.text
    unblocked = client.post(f"{BASE}/findings/VA-656/verify", json={
        "verification_status": "pending_runtime_proof", "reason_text": "Account granted.",
        "next_test": _RUNTIME_PLAN,
    })
    assert unblocked.status_code == 200, unblocked.text
    written = client.patch(f"{BASE}/findings/VA-656", json={
        "details": {"block_reason": "Acme staging VPN is down."},
    })
    assert written.status_code == 200, written.text

    reblocked = client.post(f"{BASE}/findings/VA-656/verify", json={
        "verification_status": "blocked", "reason_text": "Blocked again after the grant.",
    })

    assert reblocked.status_code == 200, reblocked.text
    assert _details(client, "VA-656")["block_reason"] == "Acme staging VPN is down."
    assert "details.block_reason" not in _derived(reblocked)


def test_a_reblock_names_the_stored_block_reason_it_replaced(client, seeded):
    _record(client, "VA-657")
    first = client.post(f"{BASE}/findings/VA-657/verify", json={
        "verification_status": "blocked", "reason_text": "Need the Acme admin account.",
    })
    assert first.status_code == 200, first.text
    unblocked = client.post(f"{BASE}/findings/VA-657/verify", json={
        "verification_status": "pending_runtime_proof", "reason_text": "Account granted.",
        "next_test": _RUNTIME_PLAN,
    })
    assert unblocked.status_code == 200, unblocked.text

    reblocked = client.post(f"{BASE}/findings/VA-657/verify", json={
        "verification_status": "blocked", "reason_text": "Acme staging VPN is down.",
    })

    assert reblocked.status_code == 200, reblocked.text
    entry = _derived(reblocked)["details.block_reason"]
    assert "replaced" in entry["detail"]
    assert "Need the Acme admin account." in entry["detail"]


# --- merge never carries the source's verdict rationale ---------------------------


def _merge(client, source: str, target: str):
    merged = client.post(f"{BASE}/findings/merge", json={
        "source_slug": source, "target_slug": target, "reason": "Same Acme tenant bypass.",
        "source_name": "operator",
    })
    assert merged.status_code == 200, merged.text
    return merged.json()


def test_a_merged_target_states_its_own_kill_not_the_sources(client, seeded):
    _record(client, "VA-661")
    _record(client, "VA-662", canonical_location="https://example.test/VA-662-orders")
    receipt_id = _receipt(client, "VA-661", "kill")
    killed = client.post(f"{BASE}/findings/VA-661/verify", json={
        "verification_status": "false_positive",
        "reason_text": "The Acme tenant guard dominates every path.",
        "counter_check": _counter_check(receipt_id),
        "details": {"kill_check": 3},
    })
    assert killed.status_code == 200, killed.text

    merged = _merge(client, "VA-661", "VA-662")

    for key in ("kill_reason", "kill_check"):
        assert key not in merged["target"]["details"], merged["target"]["details"]
    # The source row keeps its own verdict rationale; nothing is lost.
    assert merged["source"]["details"]["kill_reason"] == (
        "The Acme tenant guard dominates every path."
    )
    assert merged["source"]["details"]["kill_check"] == 3

    target_receipt = _receipt(client, "VA-662", "kill")
    check = {**_counter_check(target_receipt),
             "observed_result": "the orders route checks the Acme tenant",
             "falsified_claim": "the orders route skips tenant authorization"}
    target_killed = client.post(f"{BASE}/findings/VA-662/verify", json={
        "verification_status": "false_positive", "counter_check": check,
    })

    assert target_killed.status_code == 200, target_killed.text
    stored = _details(client, "VA-662")["kill_reason"]
    assert "the orders route checks the Acme tenant" in stored
    assert "dominates every path" not in stored
    assert _derived(target_killed)["details.kill_reason"]["derived_from"] == "counter_check"


def test_a_merged_target_states_its_own_block_not_the_sources(client, seeded):
    _record(client, "VA-663")
    _record(client, "VA-664", canonical_location="https://example.test/VA-664-orders")
    blocked = client.post(f"{BASE}/findings/VA-663/verify", json={
        "verification_status": "blocked", "reason_text": "Need the Acme admin account.",
        "details": {"unblock_requirements": {"kind": "account",
                                             "description": "an Acme org-admin account"}},
    })
    assert blocked.status_code == 200, blocked.text

    merged = _merge(client, "VA-663", "VA-664")

    for key in ("block_reason", "unblock_requirements"):
        assert key not in merged["target"]["details"], merged["target"]["details"]
    assert merged["source"]["details"]["block_reason"] == "Need the Acme admin account."

    refused = client.post(f"{BASE}/findings/VA-664/verify", json={
        "verification_status": "blocked",
    })
    assert refused.status_code == 400, refused.text

    target_blocked = client.post(f"{BASE}/findings/VA-664/verify", json={
        "verification_status": "blocked", "reason_text": "Acme staging VPN is down.",
    })
    assert target_blocked.status_code == 200, target_blocked.text
    assert _details(client, "VA-664")["block_reason"] == "Acme staging VPN is down."


def test_a_merged_target_does_not_take_the_sources_withdrawal_reason(client, seeded):
    _record(client, "VA-665")
    _record(client, "VA-666", canonical_location="https://example.test/VA-666-orders")
    submitted = client.patch(f"{BASE}/findings/VA-665", json={
        "submission_status": "submitted", "submission_ref": "ACME-665",
    })
    assert submitted.status_code == 200, submitted.text
    withdrawn = client.patch(f"{BASE}/findings/VA-665", json={
        "submission_status": "withdrawn", "reason_text": "Duplicate of an Acme-internal report.",
    })
    assert withdrawn.status_code == 200, withdrawn.text

    merged = _merge(client, "VA-665", "VA-666")

    assert "withdrawal_reason" not in merged["target"]["details"], merged["target"]["details"]
    assert merged["source"]["details"]["withdrawal_reason"] == (
        "Duplicate of an Acme-internal report."
    )
