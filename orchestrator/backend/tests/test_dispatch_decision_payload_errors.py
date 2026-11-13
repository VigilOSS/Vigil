"""A refused decision payload names the field that failed and what it accepts."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services import state_manager
from tests.test_verification_status_contract import BASE, ENGAGEMENT_KEY, _seed


@pytest.fixture
def seeded(client, isolate_settings):
    _seed(client, isolate_settings)


def _decide(client, kind: str, payload: dict):
    return client.post(f"{BASE}/dispatch-decisions", json={"kind": kind, "payload": payload})


_REPRO = {
    "finding_slug": "VA-001",
    "verdict": "followed",
    "proof_mode": "live",
    "verifier_dispatch_agent_id": "VERIFY-B",
}


@pytest.mark.parametrize(
    ("change", "named"),
    [
        ({"proof_mode": None}, ["proof_mode", "live, source, fuzz"]),
        ({"verdict": "passed"}, ["verdict", "followed, failed, equivalent"]),
        ({"runs_checked": ["five"]}, ["runs_checked", "integer"]),
        ({"verifier_dispatch_agent_id": " "}, ["verifier_dispatch_agent_id"]),
    ],
)
def test_a_malformed_repro_rehearsal_names_the_field(client, seeded, change, named):
    payload = {key: value for key, value in {**_REPRO, **change}.items() if value is not None}

    response = _decide(client, "repro_rehearsal", payload)

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert isinstance(detail, str), detail
    assert "payload." in detail, detail
    for text in named:
        assert text in detail, detail


def test_a_refused_vocabulary_word_is_echoed_as_sent(client, seeded):
    """The model folds case before checking the word; the refusal quotes what the
    caller wrote, so the caller can find it in its own payload."""
    response = _decide(client, "repro_rehearsal", {**_REPRO, "verdict": "  Passed"})

    assert response.status_code == 422, response.text
    assert "(got '  Passed')" in response.json()["detail"]


def test_an_unknown_qc_verdict_field_is_named(client, seeded):
    response = _decide(client, "submission_qc_verdict", {
        "finding_slug": "VA-001", "packet_id": 1,
        "reviewer_dispatch_agent_id": "QC-A", "writer_dispatch_agent_id": "WRITER-A",
        "verdcit": "pass",
    })

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "'verdcit'" in detail and "verdict" in detail, detail


def test_a_repro_rehearsal_reaching_the_recorder_unvalidated_names_the_field(seeded):
    """The recorder holds the same shape for any caller, not only the API."""
    with db_module.get_connection() as connection:
        engagement_id = int(connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()["id"])
    with pytest.raises(HTTPException) as refused:
        state_manager.record_decision(
            engagement_id, kind="repro_rehearsal",
            payload={**_REPRO, "proof_mode": "runtime"},
        )

    assert refused.value.status_code == 422
    assert "proof_mode" in refused.value.detail
    assert "live, source, fuzz" in refused.value.detail
