from __future__ import annotations

from tests.proof_fixtures import post_artifact_backed_source_observation
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-08-verification-status"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (("HUNT-A", "hunter-a"), ("VERIFY-B", "verifier-b")):
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


def test_material_edits_invalidate_verification_but_notes_and_wording_do_not(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    created = client.post(
        f"{BASE}/findings",
        json=_finding_payload("VA-020"),
    )
    assert created.status_code == 201, created.text
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": "verification-status-material-edit",
            "run_kind": "shared",
            "producer_dispatch_agent_id": "VERIFY-B",
        },
    )
    assert run.status_code == 201, run.text
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
    verified = client.post(
        f"{BASE}/findings/VA-020/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent proof",
            "proof_receipt_ids": [receipt.json()["id"]],
        },
    )
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
        json={"defect_family": "authentication"},
    )
    assert material.status_code == 200, material.text
    assert material.json()["finding"]["verification_status"] == "unreviewed"
    assert material.json()["finding"]["verification_invalidated"] is True

    transitions = client.get(f"{BASE}/findings/VA-020/transitions").json()
    assert transitions[0]["action"] == "verification_invalidated"
    assert transitions[0]["from_verification_status"] == "confirmed"
    assert transitions[0]["to_verification_status"] == "unreviewed"
