"""A terminal verify is a fresh verification event, so it carries fresh evidence.

Re-asserting the status a finding already holds is no exception: a receiptless
``confirmed`` on a confirmed finding would otherwise settle a pending claim review
and carry a re-band or an invalidating CVSS change past the change policy. The
evidenced upgrade path, operator authority and every non-terminal same-status
write stay open.
"""
from __future__ import annotations

import pytest

from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_change_policy import (
    _RUNTIME_PLAN,
    _audit,
    _confirmed,
    _put_in_status,
    _receipt,
    _record,
)
from tests.test_verification_status_contract import BASE, ENGAGEMENT_KEY, _seed

_HIGHER_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"  # 10.0 critical
_KILL_DETAILS = {"kill_reason": "The tenant guard dominates every path.", "kill_check": 1}


def _finding(client, slug: str) -> dict:
    return client.get(f"{BASE}/findings/{slug}").json()


def _intel_note(client) -> int:
    response = client.post(f"/engagements/{ENGAGEMENT_KEY}/intel/notes", json={
        "title": "Acme deployment config",
        "body_markdown": "Deployment config read outside the sealed snapshot.",
    })
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def _transition_count(client, slug: str) -> int:
    return len(client.get(f"{BASE}/findings/{slug}/transitions").json())


def _held(client, isolate_settings, slug: str, status: str) -> None:
    _seed(client, isolate_settings)
    _record(client, slug)
    _put_in_status(client, slug, status)


@pytest.mark.parametrize(
    ("status", "extra"),
    [
        ("confirmed", {}),
        ("downgraded", {"new_severity": "medium"}),
        ("false_positive", {"details": _KILL_DETAILS}),
    ],
)
def test_receiptless_reassert_of_a_held_terminal_status_is_refused(
    client, isolate_settings, status, extra
):
    slug = f"VA-90{['confirmed', 'downgraded', 'false_positive'].index(status)}"
    _held(client, isolate_settings, slug, status)
    before, transitions = _finding(client, slug), _transition_count(client, slug)

    response = client.post(f"{BASE}/findings/{slug}/verify", json={
        "verification_status": status, "reason_text": "re-assert", **extra})

    assert response.status_code == 400, response.text
    assert "proof_receipt_ids" in response.json()["detail"]
    after = _finding(client, slug)
    assert after["verification_status"] == before["verification_status"]
    assert after["row_version"] == before["row_version"]
    assert _transition_count(client, slug) == transitions


def test_receiptless_reassert_leaves_a_pending_claim_review_pending(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-910")
    patched = client.patch(f"{BASE}/findings/VA-910", json={
        "details": {"impact": "Attacker reads every Acme tenant's orders."}})
    assert patched.status_code == 200, patched.text
    assert patched.json()["verification_effect"] == "claim_review"

    response = client.post(f"{BASE}/findings/VA-910/verify", json={
        "verification_status": "confirmed", "reason_text": "re-assert"})

    assert response.status_code == 400, response.text
    assert _audit(client, "VA-910")["claim_review_pending"] is True


def test_receiptless_reassert_cannot_reband(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-911")

    response = client.post(f"{BASE}/findings/VA-911/verify", json={
        "verification_status": "confirmed", "reason_text": "re-band",
        "new_severity": "critical"})

    assert response.status_code == 400, response.text
    assert _finding(client, "VA-911")["severity"] == "high"


def test_receiptless_reassert_cannot_carry_an_invalidating_cvss_change(
    client, isolate_settings
):
    _confirmed(client, isolate_settings, "VA-912")

    response = client.post(f"{BASE}/findings/VA-912/verify", json={
        "verification_status": "confirmed", "reason_text": "vector",
        "details": {"cvss_vector": _HIGHER_VECTOR, "cvss_score": 10.0}})

    assert response.status_code == 400, response.text
    after = _finding(client, "VA-912")
    assert after["verification_status"] == "confirmed"
    assert after["details"].get("cvss_vector") is None


def test_fresh_evidence_re_bands_an_already_confirmed_finding(client, isolate_settings):
    """The phase-5 upgrade path: one evidenced write re-bands and re-attests."""
    _confirmed(client, isolate_settings, "VA-913")
    receipt_id = _receipt(client, "VA-913", "upgrade")

    response = client.post(f"{BASE}/findings/VA-913/verify", json={
        "verification_status": "confirmed", "reason_text": "impact is wider",
        "new_severity": "critical", "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id)})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding"]["severity"] == "critical"
    assert [r["id"] for r in body["proof_receipts"]] == [receipt_id]


def test_fresh_counter_check_re_bands_a_killed_finding(client, isolate_settings):
    _held(client, isolate_settings, "VA-914", "false_positive")
    receipt_id = _receipt(client, "VA-914", "re-kill")

    response = client.post(f"{BASE}/findings/VA-914/verify", json={
        "verification_status": "false_positive", "reason_text": "the guard dominates",
        "new_severity": "low", "details": _KILL_DETAILS,
        "counter_check": {
            "method": "authorization-dominance source proof",
            "expected_result": "an unguarded path reaches the read",
            "observed_result": "every path is dominated by the tenant guard",
            "falsified_claim": "a path bypasses tenant authorization",
            "completed": True,
            "proof_receipt_ids": [receipt_id],
        }})

    assert response.status_code == 200, response.text
    assert response.json()["finding"]["severity"] == "low"


def test_operator_authority_reasserts_a_held_terminal_status(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-915")
    intel_id = _intel_note(client)

    response = client.post(f"{BASE}/findings/VA-915/verify", json={
        "verification_status": "confirmed", "source_name": "operator",
        "reason_text": "The deployment config exposes the route in production.",
        "operator_authority": True, "operator_authority_intel_id": intel_id})

    assert response.status_code == 200, response.text
    assert response.json()["operator_authority"]["intel_id"] == intel_id


@pytest.mark.parametrize(
    ("held", "request_body"),
    [
        ("confirmed", {"verification_status": "blocked", "reason_text": "lost the tenant",
                       "details": {"block_reason": "The second Acme tenant was revoked."}}),
        ("blocked", {"verification_status": "blocked", "reason_text": "still waiting",
                     "details": {"block_reason": "A second Acme tenant account is required."}}),
        ("pending_runtime_proof", {"verification_status": "pending_runtime_proof",
                                   "reason_text": "revised plan", "next_test": _RUNTIME_PLAN}),
        ("disputed", {"verification_status": "pending_runtime_proof",
                      "reason_text": "source accepted", "next_test": _RUNTIME_PLAN}),
        ("pending_runtime_proof", {"verification_status": "disputed",
                                   "reason_text": "two lanes disagree"}),
    ],
)
def test_receiptless_non_terminal_verify_writes_stay_open(
    client, isolate_settings, held, request_body
):
    _held(client, isolate_settings, "VA-916", held)

    response = client.post(f"{BASE}/findings/VA-916/verify", json=request_body)

    assert response.status_code == 200, response.text
    assert response.json()["finding"]["verification_status"] == request_body[
        "verification_status"
    ]
