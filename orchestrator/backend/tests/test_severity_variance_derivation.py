"""A severity that departs from its CVSS band is attributed, not refused (ADR 0046).

Only the variance ``reason`` is a human judgment. The CVSS band, the chosen
severity, the verifying dispatch and the decision receipt are the verification's
own, so the backend fills each one the caller leaves out and names it on the
envelope's ``derived`` list; an authored value must agree with it. A verdict with
no variance at all is recorded, with an advisory that readiness repeats.
"""
from __future__ import annotations

import pytest

from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation
from tests.test_report_readiness_harness import (
    BASE,
    ENGAGEMENT_KEY,
    _ensure_dispatch,
    _readiness,
    _reportable_finding,
    _write_engagement,
)

_MEDIUM_DETAILS = {
    "cvss_score": 5.3,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "steps_to_reproduce": ["step one", "step two"],
    "remediation": "Fix it",
    "impact": "High contractual impact for Acme",
    "evidence": "Captured request in linked artifact",
}


@pytest.fixture
def unverified(client, isolate_settings):
    """A high-severity finding whose CVSS score sits in the medium band."""
    eng = _write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    _reportable_finding(
        client, eng, slug="SV-001", verification_status="unreviewed",
        details=dict(_MEDIUM_DETAILS),
    )
    return "SV-001"


def _receipt(client, slug: str) -> int:
    _ensure_dispatch(client, "VERIFY-1", "code-vuln-verifier")
    run = client.post(f"{BASE}/assessment-runs", json={
        "run_uuid": f"severity-variance-{slug}", "run_kind": "code",
        "producer_dispatch_agent_id": "VERIFY-1",
    })
    assert run.status_code == 201, run.text
    linked = client.post(f"{BASE}/findings/{slug}/links", json={
        "link_kind": "proof_run", "target_kind": "assessment_run",
        "target_id": run.json()["id"],
    })
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(client, f"{BASE}/proof-receipts", json={
        "run_id": run.json()["id"], "evidence_kind": "source_observation",
        "expected_result": "medium is the normal CVSS band",
        "observed_result": "contractual impact justifies high severity",
    })
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}", json={"status": "completed"}
    )
    assert completed.status_code == 200, completed.text
    return int(receipt.json()["id"])


def _confirm(client, slug: str, receipt_id: int, **extra):
    return client.post(f"{BASE}/findings/{slug}/verify", json={
        "verification_status": "confirmed",
        "reason_text": "independently verified",
        "proof_receipt_ids": [receipt_id],
        "confirm_check": completed_confirm_check(receipt_id),
        **extra,
    })


def test_an_unattributed_band_departure_is_recorded_with_an_advisory(client, unverified):
    response = _confirm(client, unverified, _receipt(client, unverified))

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding"]["verification_status"] == "confirmed"
    assert body["severity_variance"] is None
    advisory = next(a for a in body["advisories"] if a["kind"] == "severity_cvss_band_departure")
    assert "medium" in advisory["detail"] and "--severity-variance-file" in advisory["detail"]
    readiness = _readiness(client)
    assert any(
        row["kind"] == "severity_cvss_mismatch" and row["slug"] == unverified
        for row in readiness["advisories"]
    )
    assert not any(row.get("slug") == unverified and row["kind"] == "severity_cvss_mismatch"
                   for row in readiness["blockers"])


def test_a_reason_only_variance_fills_the_rest_from_the_verification(client, unverified):
    receipt_id = _receipt(client, unverified)

    response = _confirm(client, unverified, receipt_id, severity_variance={
        "reason": "Contractual exposure for Acme justifies high.",
    })

    assert response.status_code == 200, response.text
    body = response.json()
    variance = body["severity_variance"]
    assert (variance["normal_band"], variance["chosen_severity"]) == ("medium", "high")
    assert variance["actor"] == "VERIFY-1"
    assert variance["proof_receipt_id"] == receipt_id
    derived = {entry["field"] for entry in body["derived"]}
    assert {
        "severity_variance.normal_band", "severity_variance.chosen_severity",
        "severity_variance.actor", "severity_variance.proof_receipt_id",
    } <= derived
    assert not any(a["kind"] == "severity_cvss_band_departure" for a in body["advisories"])
    assert any(
        row["kind"] == "severity_cvss_band_divergence" and row["slug"] == unverified
        for row in _readiness(client)["advisories"]
    )


def test_an_authored_variance_field_that_disagrees_is_refused(client, unverified):
    response = _confirm(client, unverified, _receipt(client, unverified), severity_variance={
        "reason": "Contractual exposure for Acme justifies high.", "normal_band": "low",
    })

    assert response.status_code == 400, response.text
    assert "normal_band medium" in response.json()["detail"]


def test_an_authored_variance_actor_other_than_the_verifier_is_refused(client, unverified):
    """The actor is the verifying dispatch: a variance cannot name someone else
    as the person who approved the departure."""
    response = _confirm(client, unverified, _receipt(client, unverified), severity_variance={
        "reason": "Contractual exposure for Acme justifies high.",
        "actor": "ACME-LEAD-NOT-A-DISPATCH",
    })

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "actor" in detail and "VERIFY-1" in detail


def test_an_authored_variance_actor_may_name_the_verifier_by_agent_or_dispatch_id(
    client, unverified
):
    receipt_id = _receipt(client, unverified)
    dispatch_id = next(
        row["id"] for row in client.get(f"{BASE}/dispatches").json()
        if row["agent_id"] == "VERIFY-1"
    )

    response = _confirm(client, unverified, receipt_id, severity_variance={
        "reason": "Contractual exposure for Acme justifies high.",
        "actor": str(dispatch_id),
    })

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["severity_variance"]["actor"] == "VERIFY-1"
    # The stored spelling differs from the authored one, so the envelope says so.
    assert any(
        entry["field"] == "severity_variance.actor" and entry["value"] == "VERIFY-1"
        for entry in body["derived"]
    )


# -- a reason attached to the current verification ---------------------------


def _decide(client, payload: dict):
    return client.post(
        f"{BASE}/dispatch-decisions", json={"kind": "severity_variance", "payload": payload}
    )


def test_a_reason_attaches_to_the_current_verification_without_fresh_proof(client, unverified):
    receipt_id = _receipt(client, unverified)
    assert _confirm(client, unverified, receipt_id).status_code == 200

    response = _decide(client, {
        "finding_slug": unverified,
        "reason": "Contractual exposure for Acme justifies high.",
    })

    assert response.status_code == 201, response.text
    payload = response.json()["payload"]
    assert (payload["normal_band"], payload["chosen_severity"]) == ("medium", "high")
    assert payload["actor"] == "VERIFY-1"
    assert payload["proof_receipt_id"] == receipt_id
    advisories = _readiness(client)["advisories"]
    assert any(
        row["kind"] == "severity_cvss_band_divergence" and row["slug"] == unverified
        and "Contractual exposure" in row["detail"]
        for row in advisories
    )
    assert not any(
        row["kind"] == "severity_cvss_mismatch" and row["slug"] == unverified
        for row in advisories
    )
    audit = client.get(f"{BASE}/findings/{unverified}").json()["verification_audit"]
    latest = audit["severity_variances"][0]
    assert latest["reason"] == "Contractual exposure for Acme justifies high."
    assert latest["proof_receipt_id"] == receipt_id


@pytest.mark.parametrize(
    ("payload", "named"),
    [
        ({"reason": "r", "normal_band": "low"}, "normal_band"),
        ({"reason": "r", "actor": "ACME-LEAD-NOT-A-DISPATCH"}, "actor"),
        ({"reason": ""}, "reason"),
        ({"reason": "r", "proof_receipt": 1}, "proof_receipt"),
    ],
)
def test_a_reason_only_variance_refuses_what_contradicts_the_verification(
    client, unverified, payload, named
):
    receipt_id = _receipt(client, unverified)
    assert _confirm(client, unverified, receipt_id).status_code == 200

    response = _decide(client, {"finding_slug": unverified, **payload})

    assert response.status_code == 422, response.text
    assert named in response.json()["detail"]
    assert client.get(f"{BASE}/dispatch-decisions?kind=severity_variance").json() == []


def test_a_reason_only_variance_needs_a_band_departure_on_a_verified_finding(
    client, unverified
):
    unverified_response = _decide(client, {"finding_slug": unverified, "reason": "r"})
    assert unverified_response.status_code == 422, unverified_response.text
    assert "verification" in unverified_response.json()["detail"]

    receipt_id = _receipt(client, unverified)
    variance = {"reason": "Contractual exposure for Acme justifies high."}
    assert _confirm(client, unverified, receipt_id, severity_variance=variance).status_code == 200
    again = _decide(client, {"finding_slug": unverified, "reason": "A second reason."})
    assert again.status_code == 409, again.text
    assert "Contractual exposure" in again.json()["detail"]
