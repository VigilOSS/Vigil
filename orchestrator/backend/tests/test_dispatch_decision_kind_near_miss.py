"""Decision kinds are open text, except near misses of a gated kind.

A gated kind's row is what a backend gate reads, so a row stored under another
spelling would satisfy nothing and leave the gate it was meant for silently
open. A spelling that differs from a gated kind only in case and separators is
that kind, so it is stored under the canonical name and the response says so;
a true misspelling is refused with the kind it most likely meant.
"""
from __future__ import annotations

import pytest

from tests.test_dispatch_decisions_api import BASE, _seed
from tests.test_finding_change_policy import _audit, _confirmed
from tests.test_verification_status_contract import BASE as FINDING_BASE


@pytest.mark.parametrize(
    ("kind", "canonical"),
    [
        ("coverage-completeness-deferral", "coverage_completeness_deferral"),
        ("Coverage_Completeness_Deferral", "coverage_completeness_deferral"),
        ("coveragecompletenessdeferral", "coverage_completeness_deferral"),
        (" coverage completeness deferral ", "coverage_completeness_deferral"),
    ],
)
def test_a_gated_kind_spelled_with_other_case_or_separators_is_stored_canonically(
    client, isolate_settings, kind, canonical
):
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": kind, "payload": {"note": "Acme checkpoint"}})

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["kind"] == canonical
    assert body["derived"] == [{
        "field": "kind",
        "value": canonical,
        "derived_from": "kind",
        "detail": f"stored the gated kind {canonical!r} for the spelling {kind!r}",
    }]
    assert [row["kind"] for row in client.get(f"{BASE}/dispatch-decisions").json()] == [canonical]


def test_an_exact_kind_derives_nothing(client, isolate_settings):
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "coverage_completeness_deferral", "payload": {"note": "Acme checkpoint"}})

    assert response.status_code == 201, response.text
    assert response.json()["derived"] == []


@pytest.mark.parametrize(
    ("kind", "canonical"),
    [
        ("claim_equivalance", "claim_equivalence"),
        ("blind_triage_verdicts", "blind_triage_verdict"),
        ("depth_deferal", "depth_deferral"),
        ("submission_qc_verdit", "submission_qc_verdict"),
        ("Report-QC-Verdct", "report_qc_verdict"),
    ],
)
def test_a_misspelled_gated_kind_is_refused_with_the_kind_it_meant(
    client, isolate_settings, kind, canonical
):
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": kind, "payload": {"note": "Acme checkpoint"}})

    assert response.status_code == 422, response.text
    assert f"did you mean '{canonical}'?" in response.json()["detail"]
    assert client.get(f"{BASE}/dispatch-decisions").json() == []


def test_a_folded_gated_kind_runs_that_kind_s_payload_validation(client, isolate_settings):
    """The canonical kind's gate applies, so a folded spelling cannot skip it."""
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "Repro-Rehearsal", "payload": {"note": "Acme checkpoint"}})

    assert response.status_code == 422, response.text
    assert "repro_rehearsal payload invalid" in response.json()["detail"]
    assert client.get(f"{BASE}/dispatch-decisions").json() == []


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        ("pass1_qa_verdict", {"note": "Acme checkpoint"}),
        ("pass1-qa-verdict", {"note": "Acme checkpoint"}),
        ("pass1_qa_verdicts", {"note": "Acme checkpoint"}),
        ("Pass1QAVerdict", {"note": "Acme checkpoint"}),
        ("pass1_qa_verdict", {"finding_slug": "VA-001", "verdict": "pass"}),
    ],
)
def test_the_ungated_checklist_kind_and_its_near_misses_name_the_gated_kind(
    client, isolate_settings, kind, payload
):
    """Following the refusal leads to an accepted kind, never to another refusal."""
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={"kind": kind, "payload": payload})

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "submission_qc_verdict" in detail
    assert client.get(f"{BASE}/dispatch-decisions").json() == []


@pytest.mark.parametrize(
    "kind",
    [
        "scope_decision",
        "egress_decision",
        "dispatch_blocked",
        "license_decision",
        "coverage_completeness_deferral",
        "acme_custom_checkpoint",
    ],
)
def test_open_kinds_are_still_recorded(client, isolate_settings, kind):
    _seed(client, isolate_settings)

    response = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": kind, "payload": {"note": "Acme checkpoint"}})

    assert response.status_code == 201, response.text
    assert response.json()["kind"] == kind


def test_a_misspelled_claim_equivalence_leaves_the_review_pending(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-810")
    assert client.patch(f"{FINDING_BASE}/findings/VA-810", json={
        "summary": "Object authorization is missing for Acme invoices."}).status_code == 200
    audit = _audit(client, "VA-810")
    assert audit["claim_review_pending"] is True

    recorded = client.post(f"{FINDING_BASE}/dispatch-decisions", json={
        "kind": "claim_equivalnce", "payload": {
            "finding_slug": "VA-810", "verdict": "equivalent",
            "claim_transition_id": audit["claim_transition_id"],
            "new_claim_sha256": audit["current_claim_sha256"],
            "verifier_dispatch_agent_id": "VERIFY-B", "reason": "same claim",
        }})

    assert recorded.status_code == 422, recorded.text
    assert "'claim_equivalence'" in recorded.json()["detail"]
    assert _audit(client, "VA-810")["claim_review_pending"] is True


def test_a_claim_equivalence_spelled_with_dashes_clears_the_review(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-811")
    assert client.patch(f"{FINDING_BASE}/findings/VA-811", json={
        "summary": "Object authorization is missing for Acme invoices."}).status_code == 200
    audit = _audit(client, "VA-811")
    assert audit["claim_review_pending"] is True

    recorded = client.post(f"{FINDING_BASE}/dispatch-decisions", json={
        "kind": "Claim-Equivalence", "payload": {
            "finding_slug": "VA-811", "verdict": "equivalent",
            "claim_transition_id": audit["claim_transition_id"],
            "new_claim_sha256": audit["current_claim_sha256"],
            "verifier_dispatch_agent_id": "VERIFY-B", "reason": "same claim",
        }})

    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["kind"] == "claim_equivalence"
    assert _audit(client, "VA-811")["claim_review_pending"] is False
