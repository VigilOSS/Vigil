from __future__ import annotations

import json

import pytest

from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-08-verification-status"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (("HUNT-A", "hunter-a"), ("VERIFY-B", "vulnerability-analyst")):
        response = client.post(
            f"{BASE}/dispatches",
            json={"agent_id": agent_id, "agent_role": role, "task": role},
        )
        assert response.status_code == 201, response.text


def _finding_payload(slug: str, **overrides) -> dict:
    payload = {
        "slug": slug,
        "title": f"{slug} finding",
        "severity": "high",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "root_cause_key": f"root-{slug}",
        "auth_context": "anonymous",
        "canonical_location": f"https://example.test/{slug}",
        "summary": "Object authorization is missing.",
        "source_name": "hunter-a",
        "details": {"evidence": "request transcript", "impact": "data disclosure"},
        "provenance": {"agent_id": "HUNT-A"},
    }
    payload.update(overrides)
    return payload


def _verify_with_proof(client, slug: str, verification_status: str = "confirmed"):
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"verification-status-{slug}-{verification_status}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "VERIFY-B",
        },
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/{slug}/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": run.json()["id"],
        },
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{BASE}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "an authorization bypass is impossible",
            "observed_result": "an unguarded path reaches the protected read",
        },
    )
    assert receipt.status_code == 201, receipt.text
    finished = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert finished.status_code == 200, finished.text
    payload = {
        "verification_status": verification_status,
        "reason_text": "independent proof",
        "proof_receipt_ids": [receipt.json()["id"]],
        "confirm_check": completed_confirm_check(receipt.json()["id"]),
    }
    if verification_status == "downgraded":
        payload["new_severity"] = "medium"
    return client.post(f"{BASE}/findings/{slug}/verify", json=payload)


def test_api_uses_only_the_seven_value_verification_status_contract(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)

    created = client.post(f"{BASE}/findings", json=_finding_payload("VA-001"))

    assert created.status_code == 201, created.text
    finding = created.json()["finding"]
    assert finding["verification_status"] == "unreviewed"
    assert "verification_state" not in finding
    assert "verification_disposition" not in finding

    listing = client.get(f"{BASE}/findings", params={"verification_status": "unreviewed"})
    assert listing.status_code == 200, listing.text
    assert [row["slug"] for row in listing.json()] == ["VA-001"]

    summary = client.get(f"{BASE}/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["finding_verification_statuses"] == {"unreviewed": 1}
    assert "finding_verification_states" not in summary.json()
    assert "finding_verification_dispositions" not in summary.json()

    invalid = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-002", verification_status="unresolved"),
    )
    assert invalid.status_code == 422, invalid.text

    for legacy_field, value in (
        ("verification_state", "verified"),
        ("verification_disposition", "confirmed"),
    ):
        legacy = client.post(
            f"{BASE}/findings",
            json={**_finding_payload("VA-003"), legacy_field: value},
        )
        assert legacy.status_code == 422, legacy.text


def test_verification_endpoint_and_history_emit_only_versioned_status(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-010")).status_code == 201

    verified = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={
            "verification_status": "blocked",
            "reason_text": "The required account was not provisioned.",
            "source_name": "verifier-b",
            "details": {"block_reason": "no finance-admin test account"},
        },
    )

    assert verified.status_code == 200, verified.text
    assert verified.json()["finding"]["verification_status"] == "blocked"
    transitions = client.get(f"{BASE}/findings/VA-010/transitions")
    assert transitions.status_code == 200, transitions.text
    latest = transitions.json()[0]
    assert latest["to_verification_status"] == "blocked"
    assert latest["verification_event_version"] == 2
    assert "to_verification_state" not in latest
    assert "to_verification_disposition" not in latest

    legacy = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={"disposition": "confirmed", "reason_text": "legacy alias"},
    )
    assert legacy.status_code == 422, legacy.text


@pytest.mark.parametrize(
    "material_patch",
    (
        pytest.param({"defect_family": "authentication"}, id="defect-family"),
        pytest.param({"details": {"cwe_id": "CWE-639"}}, id="cwe-id"),
    ),
)
def test_material_edits_invalidate_verification_but_notes_and_title_wording_do_not(
    client, isolate_settings, material_patch
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-020"),
    )
    assert created.status_code == 201, created.text
    verified = _verify_with_proof(client, "VA-020")
    assert verified.status_code == 200, verified.text

    notes = client.patch(
        f"{BASE}/findings/VA-020",
        json={"notes": "Verifier follow-up note."},
    )
    assert notes.status_code == 200, notes.text
    assert notes.json()["finding"]["verification_status"] == "confirmed"

    wording = client.patch(
        f"{BASE}/findings/VA-020",
        json={"title": "Clearer wording for the same authorization defect."},
    )
    assert wording.status_code == 200, wording.text
    assert wording.json()["finding"]["verification_status"] == "confirmed"

    material = client.patch(
        f"{BASE}/findings/VA-020",
        json=material_patch,
    )
    assert material.status_code == 200, material.text
    assert material.json()["finding"]["verification_status"] == "unreviewed"
    assert material.json()["finding"]["verification_invalidated"] is True

    transitions = client.get(f"{BASE}/findings/VA-020/transitions").json()
    assert transitions[0]["action"] == "verification_invalidated"
    assert transitions[0]["from_verification_status"] == "confirmed"
    assert transitions[0]["to_verification_status"] == "unreviewed"


def test_summary_edit_keeps_verdict_but_requires_claim_equivalence_review(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-023")).status_code == 201
    verified = _verify_with_proof(client, "VA-023")
    assert verified.status_code == 200, verified.text

    edited = client.patch(
        f"{BASE}/findings/VA-023",
        json={"summary": "The same object authorization defect exposes invoices."},
    )

    assert edited.status_code == 200, edited.text
    assert edited.json()["finding"]["verification_status"] == "confirmed"
    assert edited.json()["finding"]["verification_invalidated"] is False
    current = client.get(f"{BASE}/findings/VA-023").json()
    assert current["verification_audit"]["claim_review_pending"] is True
    assert len(current["verification_audit"]["current_claim_sha256"]) == 64
    pending_id = current["verification_audit"]["claim_transition_id"]
    transition = client.get(f"{BASE}/findings/VA-023/transitions/{pending_id}").json()
    assert transition["action"] == "claim_review_pending"
    assert json.loads(transition["metadata_json"])["summary_before"] == "Object authorization is missing."


def test_record_again_with_revised_summary_requires_claim_review(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-028")).status_code == 201
    assert _verify_with_proof(client, "VA-028").status_code == 200

    revised = client.post(
        f"{BASE}/findings",
        json=_finding_payload(
            "VA-028",
            summary="The same object authorization defect exposes invoices.",
        ),
    )

    assert revised.status_code == 201, revised.text
    assert revised.json()["finding"]["verification_status"] == "confirmed"
    audit = client.get(f"{BASE}/findings/VA-028").json()["verification_audit"]
    assert audit["claim_review_pending"] is True
    transition = client.get(
        f"{BASE}/findings/VA-028/transitions/{audit['claim_transition_id']}"
    ).json()
    assert transition["action"] == "claim_review_pending"


def test_record_again_with_changed_defect_invalidates_verification(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-029")).status_code == 201
    assert _verify_with_proof(client, "VA-029").status_code == 200

    revised = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-029", defect_family="authentication"),
    )

    assert revised.status_code == 201, revised.text
    assert revised.json()["finding"]["verification_status"] == "unreviewed"
    transition = client.get(f"{BASE}/findings/VA-029/transitions").json()[0]
    assert transition["action"] == "verification_invalidated"


def test_empty_summary_patch_is_noop_for_claim_review(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-030")).status_code == 201
    assert _verify_with_proof(client, "VA-030").status_code == 200

    edited = client.patch(
        f"{BASE}/findings/VA-030",
        json={"summary": "", "notes": "Editorial pass found no summary change."},
    )

    assert edited.status_code == 200, edited.text
    current = client.get(f"{BASE}/findings/VA-030").json()
    assert current["summary"] == "Object authorization is missing."
    assert current["verification_audit"]["claim_review_pending"] is False


def test_same_band_cvss_reduction_keeps_confirmed_and_audits_scores(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    finding = _finding_payload("VA-024")
    finding["details"].update({
        "cvss_score": 8.2,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    })
    assert client.post(f"{BASE}/findings", json=finding).status_code == 201
    verified = _verify_with_proof(client, "VA-024")
    assert verified.status_code == 200, verified.text

    changed = client.patch(
        f"{BASE}/findings/VA-024",
        json={"details": {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        }},
    )

    assert changed.status_code == 200, changed.text
    assert changed.json()["finding"]["verification_status"] == "confirmed"
    metadata = json.loads(changed.json()["transition"]["metadata_json"])
    assert metadata["cvss_score_before"] == 8.2
    assert metadata["cvss_score_after"] == 7.5


def test_claim_equivalence_decision_is_bound_to_current_claim_and_independent_dispatch(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    assert client.post(f"{BASE}/findings", json=_finding_payload("VA-025")).status_code == 201
    assert _verify_with_proof(client, "VA-025").status_code == 200
    edited = client.patch(
        f"{BASE}/findings/VA-025",
        json={"summary": "A clearer statement of the same authorization bypass."},
    )
    assert edited.status_code == 200, edited.text
    audit = client.get(f"{BASE}/findings/VA-025").json()["verification_audit"]
    payload = {
        "finding_slug": "VA-025",
        "verdict": "equivalent",
        "claim_transition_id": audit["claim_transition_id"],
        "new_claim_sha256": audit["current_claim_sha256"],
        "verifier_dispatch_agent_id": "VERIFY-B",
        "reason": "The authorization boundary and observed outcome are unchanged.",
    }
    malformed = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": {**payload, "reason": {"text": "same"}}},
    )
    assert malformed.status_code == 400, malformed.text
    stale = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": {**payload, "new_claim_sha256": "0" * 64}},
    )
    assert stale.status_code == 409, stale.text
    self_review = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": {**payload, "verifier_dispatch_agent_id": "HUNT-A"}},
    )
    assert self_review.status_code == 400, self_review.text
    writer = client.post(
        f"{BASE}/dispatches",
        json={"agent_id": "WRITER-C", "agent_role": "report-writer", "task": "Edit prose"},
    )
    assert writer.status_code == 201, writer.text
    unqualified = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": {**payload, "verifier_dispatch_agent_id": "WRITER-C"}},
    )
    assert unqualified.status_code == 400, unqualified.text
    accepted = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": payload},
    )
    assert accepted.status_code == 201, accepted.text
    assert client.get(f"{BASE}/findings/VA-025").json()["verification_audit"]["claim_review_pending"] is False
    challenged = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": {
            **payload, "verdict": "changed", "reason": "The revised scope overstates the observed read.",
        }},
    )
    assert challenged.status_code == 201, challenged.text
    assert client.get(f"{BASE}/findings/VA-025").json()["verification_audit"]["claim_review_pending"] is True
    repeated_accept = client.post(
        f"{BASE}/dispatch-decisions",
        json={"kind": "claim_equivalence", "payload": payload},
    )
    assert repeated_accept.status_code == 409, repeated_accept.text


def test_inbound_contradiction_surfaces_review_cue_without_resetting_verdict(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    for slug in ("VA-026", "VA-027"):
        assert client.post(f"{BASE}/findings", json=_finding_payload(slug)).status_code == 201
    assert _verify_with_proof(client, "VA-026").status_code == 200

    linked = client.post(
        f"{BASE}/findings/VA-027/links",
        json={
            "link_kind": "contradicts", "target_kind": "finding",
            "target_ref": "VA-026", "notes": "The second tenant check returned 403.",
        },
    )
    assert linked.status_code == 200, linked.text
    earlier = client.get(f"{BASE}/findings/VA-026")
    assert earlier.status_code == 200, earlier.text
    assert earlier.json()["verification_status"] == "confirmed"
    assert earlier.json()["verification_audit"]["contradiction_reviews"] == [{
        "source_slug": "VA-027", "link_id": linked.json()["id"],
        "notes": "The second tenant check returned 403.",
    }]


@pytest.mark.parametrize("verification_status", ("confirmed", "downgraded"))
def test_replace_removing_material_details_invalidates_verification(
    client, isolate_settings, verification_status
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-021"),
    )
    assert created.status_code == 201, created.text
    verified = _verify_with_proof(client, "VA-021", verification_status)
    assert verified.status_code == 200, verified.text

    replaced = client.patch(
        f"{BASE}/findings/VA-021",
        json={
            "details": {"remediation": "Enforce object ownership."},
            "details_mode": "replace",
            "expected_row_version": verified.json()["finding"]["row_version"],
        },
    )

    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["finding"]["details"] == {
        "remediation": "Enforce object ownership."
    }
    assert replaced.json()["finding"]["verification_status"] == "unreviewed"
    assert replaced.json()["finding"]["verification_invalidated"] is True
    transitions = client.get(f"{BASE}/findings/VA-021/transitions").json()
    assert transitions[0]["action"] == "verification_invalidated"
    assert transitions[0]["from_verification_status"] == verification_status
    assert transitions[0]["to_verification_status"] == "unreviewed"


@pytest.mark.parametrize("verification_status", ("confirmed", "downgraded"))
def test_claim_retraction_invalidates_terminal_verification_and_attributes_the_actor(
    client, isolate_settings, verification_status
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-022"),
    )
    assert created.status_code == 201, created.text
    verified = _verify_with_proof(client, "VA-022", verification_status)
    assert verified.status_code == 200, verified.text

    retracted = client.patch(
        f"{BASE}/findings/VA-022",
        json={
            "summary": "Authorization is enforced for tenant invoice reads.",
            "details": {
                "correction_history": [
                    {
                        "field": "summary",
                        "retracted_claim": "Object authorization is missing.",
                        "replacement_claim": (
                            "Authorization is enforced for tenant invoice reads."
                        ),
                    }
                ]
            },
            "reason_code": "claim_retracted",
            "reason_text": "The original claim exceeded the captured proof.",
            "source_name": "retraction-operator",
            "expected_row_version": verified.json()["finding"]["row_version"],
        },
    )

    assert retracted.status_code == 200, retracted.text
    assert retracted.json()["finding"]["verification_status"] == "unreviewed"
    assert retracted.json()["finding"]["verification_invalidated"] is True
    transition = retracted.json()["transition"]
    assert transition["action"] == "verification_invalidated"
    assert transition["actor"] == "retraction-operator"
    assert transition["reason_code"] == "claim_retracted"
    assert transition["from_verification_status"] == verification_status
    assert transition["to_verification_status"] == "unreviewed"

    activity = client.get(
        f"/engagements/{ENGAGEMENT_KEY}/activity-entries",
        params={"q": "finding-update"},
    )
    assert activity.status_code == 200, activity.text
    update_rows = [
        row for row in activity.json()["items"] if row["title"] == "finding-update"
    ]
    assert len(update_rows) == 1
    assert update_rows[0]["actor_name"] == "retraction-operator"
