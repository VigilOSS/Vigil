"""Closed vocabularies accept their own words in any case or separator.

``Blocked``, ``pending-runtime-proof``, ``in_progress`` and ``network_confirmed``
name exactly one canonical value each, so they fold to it before the vocabulary
is checked; a word outside the vocabulary is still refused.
"""
from __future__ import annotations

import pytest

from app.api.assessment_operator import BlindTriageVerdictPayload, ReproRehearsalPayload
from tests.test_finding_change_policy import _RUNTIME_PLAN, _record
from tests.test_verification_status_contract import BASE, _finding_payload, _seed


@pytest.fixture
def seeded(client, isolate_settings):
    _seed(client, isolate_settings)


@pytest.mark.parametrize(
    ("status", "extra", "stored"),
    [
        ("Blocked", {"reason_text": "No Acme tenant account."}, "blocked"),
        ("Pending-Runtime-Proof", {"next_test": _RUNTIME_PLAN}, "pending_runtime_proof"),
        (" DISPUTED ", {"reason_text": "Two lanes disagree."}, "disputed"),
    ],
)
def test_a_verification_status_folds_to_its_canonical_spelling(
    client, seeded, status, extra, stored
):
    _record(client, "VA-801")

    response = client.post(f"{BASE}/findings/VA-801/verify", json={
        "verification_status": status, **extra,
    })

    assert response.status_code == 200, response.text
    assert response.json()["finding"]["verification_status"] == stored


def test_an_unknown_verification_status_is_still_refused(client, seeded):
    _record(client, "VA-802")

    response = client.post(f"{BASE}/findings/VA-802/verify", json={
        "verification_status": "verified", "reason_text": "r",
    })

    assert response.status_code == 422, response.text


def test_an_evidence_type_folds_hyphen_and_underscore(client, seeded):
    response = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-803", evidence_type="Network_Confirmed"),
    )

    assert response.status_code == 201, response.text
    assert response.json()["finding"]["evidence_type"] == "network-confirmed"


def test_a_dispatch_status_folds_its_separator(client, seeded):
    response = client.post(f"{BASE}/dispatches", json={
        "agent_id": "FOLD-A", "agent_role": "vulnerability-analyst",
        "task": "Acme fold check.", "status": "in_progress",
    })

    assert response.status_code == 201, response.text
    assert response.json()["status"] == "in-progress"


def test_decision_verdicts_fold_their_case():
    assert BlindTriageVerdictPayload.model_validate({
        "finding_slug": "VA-001", "packet_id": "0" * 64,
        "reviewer_dispatch_agent_id": "TRIAGE-A", "writer_dispatch_agent_id": "WRITER-A",
        "verdict": "accept@p2",
    }).verdict == "Accept@P2"
    folded = ReproRehearsalPayload.model_validate({
        "finding_slug": "VA-001", "verdict": "Followed", "proof_mode": "LIVE",
        "verifier_dispatch_agent_id": "VERIFY-B",
    })
    assert (folded.verdict, folded.proof_mode) == ("followed", "live")


@pytest.mark.parametrize("typed", ["VA-7", "va_007", "VA07"])
def test_a_short_or_misspelled_slug_names_the_canonical_one(client, seeded, typed):
    _record(client, "VA-007")

    response = client.patch(f"{BASE}/findings/{typed}", json={"summary": "revised"})

    assert response.status_code == 400, response.text
    assert "did you mean VA-007" in response.json()["detail"]
