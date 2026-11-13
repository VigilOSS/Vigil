"""An in-band rating correction on a verified finding is a claim review, not a re-verify.

``downgraded`` records a band that moved, so a same-band downgrade is refused. The
refusal routes the correction by what it would do to the verdict: an impact or
score revision inside the band raises a claim review that an independent
``claim_equivalence`` decision settles; a correction that sets a band the finding
lacked invalidates the verdict and needs fresh proof.
"""
from __future__ import annotations

import re

import pytest

from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_change_policy import (
    _BASE_VECTOR,
    _audit,
    _blocker_kinds,
    _confirmed,
    _receipt,
)
from tests.test_verification_status_contract import BASE

_IMPACT_DOWN = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5, still high
_SCORED = {"evidence": "request transcript", "impact": "data disclosure", "cvss_score": 8.2}


def _same_band_downgrade(client, slug: str):
    receipt_id = _receipt(client, slug, "same-band")
    refused = client.post(f"{BASE}/findings/{slug}/verify", json={
        "verification_status": "downgraded", "new_severity": "high",
        "reason_text": "integrity impact was overstated",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id),
    })
    assert refused.status_code == 400, refused.text
    return refused.json()["detail"]


def _suggested_detail_keys(detail: str) -> set[str]:
    match = re.search(r"--details-inline '(\{[^']*\})'", detail)
    assert match, detail
    return set(re.findall(r'"(\w+)":', match.group(1)))


def _settle_by_equivalence(client, slug: str) -> None:
    audit = _audit(client, slug)
    assert audit["claim_review_pending"] is True
    recorded = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": {
            "finding_slug": slug, "verdict": "equivalent",
            "claim_transition_id": audit["claim_transition_id"],
            "new_claim_sha256": audit["current_claim_sha256"],
            "verifier_dispatch_agent_id": "VERIFY-B",
            "reason": "same preconditions, action and outcome; the impact was overstated",
        }})
    assert recorded.status_code == 201, recorded.text
    assert _audit(client, slug)["claim_review_pending"] is False
    assert "finding_claim_review_pending" not in _blocker_kinds(client, slug)
    assert client.get(f"{BASE}/findings/{slug}").json()["verification_status"] == "confirmed"


@pytest.mark.parametrize(
    ("details", "suggested_keys", "correction"),
    [
        ({**_SCORED, "cvss_vector": _BASE_VECTOR}, {"cvss_score", "cvss_vector"},
         {"cvss_score": 7.5, "cvss_vector": _IMPACT_DOWN}),
        (_SCORED, {"cvss_score"}, {"cvss_score": 7.5}),
    ],
    ids=["scored-with-vector", "scored-without-vector"],
)
def test_the_refusal_routes_an_in_band_correction_through_claim_review(
    client, isolate_settings, details, suggested_keys, correction
):
    _confirmed(client, isolate_settings, "VA-801", details=details)

    detail = _same_band_downgrade(client, "VA-801")

    assert "vigil assess agent decision --kind claim_equivalence" in detail, detail
    assert _suggested_detail_keys(detail) == suggested_keys
    patched = client.patch(f"{BASE}/findings/VA-801", json={"details": correction})
    assert patched.status_code == 200, patched.text
    assert patched.json()["verification_effect"] == "claim_review"
    _settle_by_equivalence(client, "VA-801")


def test_adding_the_vector_a_scored_finding_lacks_invalidates(client, isolate_settings):
    """Why the score-only finding is not told to patch a vector in."""
    _confirmed(client, isolate_settings, "VA-802", details=_SCORED)
    patched = client.patch(f"{BASE}/findings/VA-802", json={
        "details": {"cvss_score": 7.5, "cvss_vector": _IMPACT_DOWN}})
    assert patched.status_code == 200, patched.text
    assert patched.json()["verification_effect"] == "invalidate"
    assert "cvss.vector" in patched.json()["changed_axes"]


def test_an_unscored_verified_finding_is_routed_to_fresh_verification(
    client, isolate_settings
):
    """Scoring a finding that had no score sets a band, which invalidates."""
    _confirmed(client, isolate_settings, "VA-803")

    detail = _same_band_downgrade(client, "VA-803")

    assert "vigil assess finding verify VA-803 --status confirmed" in detail, detail
    keys = _suggested_detail_keys(detail)
    patched = client.patch(f"{BASE}/findings/VA-803", json={"details": {
        key: {"cvss_score": 7.5, "cvss_vector": _IMPACT_DOWN}[key] for key in keys}})
    assert patched.status_code == 200, patched.text
    assert patched.json()["verification_effect"] == "invalidate"

