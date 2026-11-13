"""A pending claim review names the exact decision that clears it.

The readiness blocker is what an operator reads when the report refuses, so it
carries the `agent decision --kind claim_equivalence` invocation with the
finding slug, claim transition id and current claim digest already filled in.
Re-verification is the alternative, not the instruction.
"""
from __future__ import annotations

import json

from tests.test_finding_change_policy import _audit, _confirmed
from tests.test_verification_status_contract import BASE


def test_claim_review_blocker_carries_the_filled_in_decision_command(
    client, isolate_settings
):
    _confirmed(client, isolate_settings, "VA-830")
    edited = client.patch(f"{BASE}/findings/VA-830", json={
        "summary": "Object authorization is missing for Acme invoice exports."})
    assert edited.status_code == 200, edited.text
    audit = _audit(client, "VA-830")
    assert audit["claim_review_pending"] is True

    readiness = client.get(f"{BASE}/report-readiness").json()
    blocker = next(
        item for item in readiness["blockers"]
        if item["kind"] == "finding_claim_review_pending" and item["slug"] == "VA-830"
    )
    detail = blocker["detail"]
    prefix = "vigil assess agent decision --kind claim_equivalence --payload-json '"
    assert prefix in detail
    payload = json.loads(detail.split(prefix, 1)[1].split("'", 1)[0])
    assert payload["finding_slug"] == "VA-830"
    assert payload["claim_transition_id"] == audit["claim_transition_id"]
    assert payload["new_claim_sha256"] == audit["current_claim_sha256"]
    assert blocker["claim_transition_id"] == audit["claim_transition_id"]
    assert blocker["current_claim_sha256"] == audit["current_claim_sha256"]
    assert detail.index(prefix) < detail.index("fresh proof receipts")
