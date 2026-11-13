"""A claim edit is reviewed by a dispatch that did not make it.

The finding author is excluded from equivalence review, and so is every dispatch
that edited the claim under review since the last verification; an edit with no
attributed dispatch excludes only the author.
"""
from __future__ import annotations

from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_change_policy import _audit, _confirmed, _receipt
from tests.test_verification_status_contract import BASE


def _dispatch(client, agent_id: str) -> None:
    response = client.post(f"{BASE}/dispatches", json={
        "agent_id": agent_id, "agent_role": "vulnerability-analyst", "task": "claim review"})
    assert response.status_code == 201, response.text


def _edit(client, slug: str, summary: str, editor: str | None = None) -> None:
    body = {"summary": summary}
    if editor is not None:
        body["dispatch_agent_id"] = editor
    response = client.patch(f"{BASE}/findings/{slug}", json=body)
    assert response.status_code == 200, response.text
    assert response.json()["verification_effect"] == "claim_review"


def _decide(client, slug: str, verifier: str):
    audit = _audit(client, slug)
    return client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": {
            "finding_slug": slug, "verdict": "equivalent",
            "claim_transition_id": audit["claim_transition_id"],
            "new_claim_sha256": audit["current_claim_sha256"],
            "verifier_dispatch_agent_id": verifier,
            "reason": "Same boundary, action and observed outcome.",
        }})


def test_the_editing_dispatch_cannot_rule_its_own_edit_equivalent(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-920")  # authored by HUNT-A, proven by VERIFY-B
    _edit(client, "VA-920", "Any anonymous caller reads every Acme tenant's orders.", "VERIFY-B")

    response = _decide(client, "VA-920", "VERIFY-B")

    assert response.status_code == 400, response.text
    assert "edited" in response.json()["detail"]
    assert _audit(client, "VA-920")["claim_review_pending"] is True


def test_an_earlier_editor_of_the_pending_claim_is_also_excluded(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-921")
    _dispatch(client, "VERIFY-C")
    _edit(client, "VA-921", "Anonymous callers read Acme tenant orders.", "VERIFY-B")
    _edit(client, "VA-921", "Anonymous callers read every Acme tenant order.", "VERIFY-C")

    assert _decide(client, "VA-921", "VERIFY-B").status_code == 400
    assert _audit(client, "VA-921")["claim_review_pending"] is True


def test_an_independent_dispatch_settles_the_edit(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-922")
    _dispatch(client, "VERIFY-C")
    _edit(client, "VA-922", "A clearer statement of the same Acme bypass.", "VERIFY-B")

    response = _decide(client, "VA-922", "VERIFY-C")

    assert response.status_code == 201, response.text
    assert _audit(client, "VA-922")["claim_review_pending"] is False


def test_an_unattributed_edit_excludes_only_the_author(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-923")
    _edit(client, "VA-923", "A clearer statement of the same Acme bypass.")

    assert _decide(client, "VA-923", "HUNT-A").status_code == 400
    response = _decide(client, "VA-923", "VERIFY-B")
    assert response.status_code == 201, response.text
    assert _audit(client, "VA-923")["claim_review_pending"] is False


def test_editors_before_the_latest_verification_are_not_excluded(client, isolate_settings):
    """A fresh verification attests the claim as it stands, so it ends the edit window."""
    _confirmed(client, isolate_settings, "VA-924")
    _dispatch(client, "VERIFY-C")
    _edit(client, "VA-924", "Anonymous callers read Acme tenant orders.", "VERIFY-B")
    receipt_id = _receipt(client, "VA-924", "re-verify")
    reverified = client.post(f"{BASE}/findings/VA-924/verify", json={
        "verification_status": "confirmed", "reason_text": "fresh proof of the edited claim",
        "proof_receipt_ids": [receipt_id], "confirm_check": completed_confirm_check(receipt_id)})
    assert reverified.status_code == 200, reverified.text
    _edit(client, "VA-924", "Anonymous callers read every Acme tenant order.", "VERIFY-C")

    response = _decide(client, "VA-924", "VERIFY-B")

    assert response.status_code == 201, response.text


def test_an_unattributed_edit_source_name_does_not_exclude_a_dispatch(client, isolate_settings):
    """Only a validated dispatch attribution names an editor; free-text source_name does not."""
    _confirmed(client, isolate_settings, "VA-925")
    edited = client.patch(f"{BASE}/findings/VA-925", json={
        "summary": "A clearer statement of the same Acme bypass.", "source_name": "VERIFY-B"})
    assert edited.status_code == 200, edited.text
    assert edited.json()["verification_effect"] == "claim_review"

    response = _decide(client, "VA-925", "VERIFY-B")

    assert response.status_code == 201, response.text
    assert _audit(client, "VA-925")["claim_review_pending"] is False
