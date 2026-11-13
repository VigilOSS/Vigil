"""A refused confirm_check or counter_check names every problem in one answer.

The request model refuses a missing field; the service refuses what the model
lets through (a blank field, an incomplete check, receipts that are not this
verification's decision receipts). Naming one problem per refusal costs the
verifier a round trip for each, so the service collects them all.
"""
from __future__ import annotations

import pytest

from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_change_policy import _receipt, _record
from tests.test_verification_status_contract import BASE, _seed


@pytest.fixture
def seeded(client, isolate_settings):
    _seed(client, isolate_settings)


def test_a_counter_check_refusal_names_every_problem(client, seeded):
    _record(client, "VA-701")
    receipt_id = _receipt(client, "VA-701", "kill")

    refused = client.post(f"{BASE}/findings/VA-701/verify", json={
        "verification_status": "false_positive",
        "reason_text": "The Acme tenant guard dominates every path.",
        "proof_receipt_ids": [receipt_id],
        "counter_check": {
            "method": " ",
            "expected_result": "an unguarded path reaches the read",
            "observed_result": " ",
            "falsified_claim": " ",
            "completed": True,
            "proof_receipt_ids": [receipt_id],
        },
    })

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    for name in ("method", "observed_result", "falsified_claim"):
        assert f"counter_check.{name} is required" in detail, detail
    assert client.get(f"{BASE}/findings/VA-701").json()["verification_status"] == "unreviewed"


def test_a_confirm_check_refusal_names_every_problem(client, seeded):
    _record(client, "VA-702")
    receipt_id = _receipt(client, "VA-702", "confirm")
    check = {
        **completed_confirm_check(receipt_id),
        "method": " ",
        "attempted_falsification": " ",
        "completed": False,
    }

    refused = client.post(f"{BASE}/findings/VA-702/verify", json={
        "verification_status": "confirmed",
        "reason_text": "The Acme export returns another tenant's rows.",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": check,
    })

    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert "confirm_check must be completed" in detail, detail
    for name in ("method", "attempted_falsification"):
        assert f"confirm_check.{name} is required" in detail, detail
