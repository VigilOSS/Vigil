from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from app import db
from app.services.state_manager import findings
from tests.proof_fixtures import completed_confirm_check
from tests.test_finding_code_snapshot_provenance import (
    _ENGAGEMENT_KEY, _dispatch, _finding_payload, _info_severity_variance,
    _record, _seed_repo, _verification_receipt,
)


@pytest.fixture
def verification(client, isolate_settings):
    return _prepare_verification(client, isolate_settings)


def _prepare_verification(client, isolate_settings):
    binding = _seed_repo(client, isolate_settings)
    _dispatch(client, "acme-hunter")
    assert _record(client, _finding_payload("VA-701", binding,
                   author_agent_id="acme-hunter")).status_code == 201
    _dispatch(client, "acme-verifier", role="code-vuln-verifier")
    receipt = _verification_receipt(client, "acme-verifier", "VA-701")
    payload = {
        "verification_status": "confirmed", "reason_text": "Acme independent source check",
        "source_name": "code-vuln-verifier", "notes": "Acme verification checkpoint",
        "proof_receipt_ids": [receipt], "confirm_check": completed_confirm_check(receipt),
        "severity_variance": _info_severity_variance(receipt),
    }
    return f"/engagements/{_ENGAGEMENT_KEY}/assessment/findings/VA-701", payload


def test_exact_verification_retry_returns_original_event_without_reappending(client, verification):
    base, payload = verification
    first = client.post(base + "/verify", json=payload)
    assert first.status_code == 200, first.text
    replay = client.post(base + "/verify", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["already_applied"] is True
    assert replay.json()["transition"]["id"] == first.json()["transition"]["id"]
    assert replay.json()["finding"]["row_version"] == first.json()["finding"]["row_version"]
    assert replay.json()["finding"]["notes"].count(payload["notes"]) == 1


@pytest.mark.parametrize("changed", [{"notes": "different checkpoint"},
                                    {"source_name": "different actor"},
                                    {"reason_text": "different claim check"}])
def test_changed_verification_request_cannot_reuse_previous_proof(client, verification, changed):
    base, payload = verification
    first = client.post(base + "/verify", json=payload)
    assert first.status_code == 200, first.text
    refused = client.post(base + "/verify", json={**payload, **changed})
    assert refused.status_code in {400, 409}, refused.text
    assert client.get(base).json()["row_version"] == first.json()["finding"]["row_version"]


def test_post_verification_edit_prevents_old_request_replay(client, verification):
    base, payload = verification
    assert client.post(base + "/verify", json=payload).status_code == 200
    assert client.patch(base, json={"notes": "Later Acme checkpoint", "notes_mode": "append"}).status_code == 200
    refused = client.post(base + "/verify", json=payload)
    assert refused.status_code in {400, 409}, refused.text


def test_concurrent_exact_verifications_commit_only_one_event(client, verification, monkeypatch):
    base, payload = verification
    barrier = threading.Barrier(2)
    original = findings.patch_finding

    def simultaneous(*args, **kwargs):
        barrier.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(findings, "patch_finding", simultaneous)
    with ThreadPoolExecutor(max_workers=2) as workers:
        responses = list(workers.map(lambda _: client.post(base + "/verify", json=payload), range(2)))
    assert [response.status_code for response in responses] == [200, 200], [r.text for r in responses]
    assert len({response.json()["transition"]["id"] for response in responses}) == 1
    with db.get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM assessment_finding_transitions WHERE action='verified_confirmed'").fetchone()[0]
    assert count == 1


def test_exact_verification_replay_emits_one_mutation_activity(client, verification):
    base, payload = verification
    assert client.post(base + "/verify", json=payload).status_code == 200
    assert client.post(base + "/verify", json=payload).status_code == 200
    with db.get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM activity_entries WHERE title='finding-verify'").fetchone()[0]
    assert count == 1


def test_lost_postcommit_artifact_completion_is_resumed(client, verification, monkeypatch):
    base, payload = verification
    payload = {**payload, "artifact_ref": "tools/acme-verification.txt"}
    original = findings._common._register_artifact_reference
    calls = []

    def interrupted(*args, **kwargs):
        calls.append(kwargs.get("kind"))
        if len(calls) == 1:
            raise RuntimeError("Acme postcommit interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(findings._common, "_register_artifact_reference", interrupted)
    with pytest.raises(RuntimeError, match="Acme postcommit interruption"):
        client.post(base + "/verify", json=payload)
    retry = client.post(base + "/verify", json=payload)
    assert retry.status_code == 200, retry.text
    assert retry.json()["already_applied"] is True
    assert len(calls) == 2


def test_downgraded_verification_retry_preserves_original_band_transition(client, verification):
    base, payload = verification
    current = client.get(base).json()
    assert client.patch(base, json={"severity": "high", "expected_row_version": current["row_version"]}).status_code == 200
    payload = {**payload, "verification_status": "downgraded", "new_severity": "info"}
    first = client.post(base + "/verify", json=payload)
    assert first.status_code == 200, first.text
    replay = client.post(base + "/verify", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["already_applied"] is True
    assert replay.json()["transition"]["id"] == first.json()["transition"]["id"]
    assert replay.json()["transition"]["from_severity"] == "high"
    assert replay.json()["transition"]["to_severity"] == "info"


def test_source_generation_change_prevents_old_verification_replay(client, verification):
    from tests.test_finding_code_snapshot_provenance import _advance_repo
    base, payload = verification
    first = client.post(base + "/verify", json=payload)
    assert first.status_code == 200, first.text
    _advance_repo(first.json()["finding"]["provenance"]["code_snapshot"])
    refused = client.post(base + "/verify", json=payload)
    assert refused.status_code == 409, refused.text


def test_repeated_blocked_checkpoint_has_one_replayable_decision(client, verification):
    base, _ = verification
    payload = {"verification_status": "blocked", "source_name": "code-vuln-verifier",
               "reason_text": "Acme account unavailable", "details": {"block_reason": "Acme test account missing"}}
    assert client.post(base + "/verify", json=payload).status_code == 200
    payload = {**payload, "reason_text": "Acme account still unavailable after provisioning check"}
    checkpoint = client.post(base + "/verify", json=payload)
    assert checkpoint.status_code == 200, checkpoint.text
    replay = client.post(base + "/verify", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["already_applied"] is True
    assert replay.json()["transition"]["id"] == checkpoint.json()["transition"]["id"]
