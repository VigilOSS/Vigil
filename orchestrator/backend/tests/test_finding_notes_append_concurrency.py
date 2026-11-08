"""Implicit note appends merge under the canonical writer, without stale fields."""
import pytest

from app.services.state_manager import findings
from tests.test_finding_verification_replay import _prepare_verification


@pytest.fixture
def verification(client, isolate_settings):
    return _prepare_verification(client, isolate_settings)


def _interleave(client, monkeypatch, base, action):
    original = findings.create_finding
    entered = []
    committed = []

    def writer(*args, **kwargs):
        if kwargs.get("code_snapshot_write_mode") == "patch" and not entered:
            entered.append(True)
            response = action()
            assert response.status_code == 200, response.text
            committed.append(response.json()["finding"])
        return original(*args, **kwargs)

    monkeypatch.setattr(findings, "create_finding", writer)
    return committed


@pytest.mark.parametrize("other", ["notes", "material", "verification"])
def test_implicit_append_keeps_the_latest_writer_state(client, verification, monkeypatch, other):
    base, verification_payload = verification
    before = client.get(base).json()
    if other == "verification":
        def action():
            return client.post(base + "/verify", json=verification_payload)
    elif other == "material":
        def action():
            return client.patch(base, json={
                    "title": "Acme revised finding", "severity": "high",
                    "canonical_location": "file:src/other.c:37", "notes": "Other material writer",
                    "summary": "Acme revised summary", "evidence_ref": "findings.md",
                    "details": {"impact": "Acme revised impact"},
                    "provenance": {"artifact": "tools/acme-provenance.txt"},
                    "submission_ref": "ACME-42",
                    "expected_row_version": before["row_version"],
                })
    else:
        def action():
            return client.patch(base, json={"notes": "Other notes writer"})
    committed = _interleave(client, monkeypatch, base, action)
    appended = client.patch(base, json={"notes": "Acme appended checkpoint", "notes_mode": "append"})
    assert appended.status_code == 200, appended.text
    record = client.get(base).json()
    for field in (
        "title", "severity", "canonical_location", "summary", "evidence_ref",
        "details", "provenance", "submission_ref", "source_name",
        "workflow_status", "verification_status",
    ):
        assert appended.json()["finding"][field] == committed[0][field], field
    assert "Acme appended checkpoint" in record["notes"]
    if other == "verification":
        assert record["verification_status"] == "confirmed"
        assert verification_payload["notes"] in record["notes"]
        assert len(record["proof_receipts"]) == 1
    elif other == "material":
        assert record["title"] == "Acme revised finding"
        assert record["severity"] == "high"
        assert record["canonical_location"] == "file:src/other.c:37"
        assert "Other material writer" in record["notes"]
    else:
        assert "Other notes writer" in record["notes"]
    transition = appended.json()["transition"]
    assert transition["notes_after_json"] == record["notes"]
    assert "Acme appended checkpoint" not in transition["notes_before_json"]


@pytest.mark.parametrize("payload_kind", ["explicit-cas", "material", "retract"])
def test_noncommutative_patch_keeps_its_concurrency_guard(client, verification, monkeypatch, payload_kind):
    base, _ = verification
    before = client.get(base).json()
    def action():
        return client.patch(base, json={"title": "Acme current title", "expected_row_version": before["row_version"]})
    _interleave(client, monkeypatch, base, action)
    payload = {"notes": "Acme attempted guarded note"}
    if payload_kind == "explicit-cas":
        payload["expected_row_version"] = before["row_version"]
    elif payload_kind == "material":
        payload["title"] = "Acme stale title"
    else:
        payload["reason_code"] = "claim_retracted"
    response = client.patch(base, json=payload)
    assert response.status_code == 409, response.text
    record = client.get(base).json()
    assert record["title"] == "Acme current title"
    assert "Acme attempted guarded note" not in record["notes"]


def test_append_projects_current_proof_health_after_releasing_writer(client, verification, monkeypatch):
    from app import db
    from app.services.state_manager import proofs
    base, payload = verification
    assert client.post(base + "/verify", json=payload).status_code == 200
    original = proofs.artifact_index.registered_snapshot_evidence_health
    observed = []

    def attest(*args, **kwargs):
        with db.get_connection() as connection:
            observed.append(connection.in_transaction)
        return original(*args, **kwargs)

    monkeypatch.setattr(proofs.artifact_index, "registered_snapshot_evidence_health", attest)
    response = client.patch(base, json={"notes": "Acme proof-bearing checkpoint"})
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["proof_receipts"][0]["evidence_health"] == "healthy"
    assert observed and not any(observed), observed


def test_append_attests_the_captured_decision_when_another_verifier_commits(client, verification, monkeypatch):
    base, payload = verification
    confirmed = client.post(base + "/verify", json=payload)
    assert confirmed.status_code == 200, confirmed.text
    captured_ids = [record["id"] for record in confirmed.json()["proof_receipts"]]
    original = findings._apply_live_evidence_health
    entered = []

    def next_decision(connection, engagement_id, records):
        if not entered:
            entered.append(True)
            blocked = client.post(base + "/verify", json={
                "verification_status": "blocked", "source_name": "code-vuln-verifier",
                "reason_text": "Acme provisioning state changed",
                "details": {"block_reason": "Acme account unavailable"},
            })
            assert blocked.status_code == 200, blocked.text
        return original(connection, engagement_id, records)

    monkeypatch.setattr(findings, "_apply_live_evidence_health", next_decision)
    response = client.patch(base, json={"notes": "Acme captured-decision checkpoint"})
    assert response.status_code == 200, response.text
    record = response.json()["finding"]
    assert record["verification_status"] == "confirmed"
    assert [row["id"] for row in record["proof_receipts"]] == captured_ids
    assert client.get(base).json()["verification_status"] == "blocked"


def test_append_reports_live_integrity_failure_in_captured_proof(client, verification, monkeypatch):
    from pathlib import Path
    from app import db
    base, payload = verification
    confirmed = client.post(base + "/verify", json=payload)
    assert confirmed.status_code == 200, confirmed.text
    receipt_id = payload["proof_receipt_ids"][0]
    with db.get_connection() as connection:
        row = connection.execute(
            "SELECT engagements.engagement_root, artifacts.relative_path "
            "FROM assessment_proof_receipts AS receipts "
            "JOIN assessment_artifacts AS artifacts ON artifacts.id=receipts.artifact_id "
            "JOIN engagements ON engagements.id=artifacts.engagement_id WHERE receipts.id=?",
            (receipt_id,),
        ).fetchone()
    artifact = Path(row["engagement_root"]) / row["relative_path"]
    original = findings._apply_live_evidence_health

    def changed(connection, engagement_id, records):
        artifact.write_text("Acme evidence changed after note commit", encoding="utf-8")
        return original(connection, engagement_id, records)

    monkeypatch.setattr(findings, "_apply_live_evidence_health", changed)
    response = client.patch(base, json={"notes": "Acme integrity checkpoint"})
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["proof_receipts"][0]["evidence_health"] == "stale"


def test_implicit_append_does_not_rewrite_a_stored_location(client, verification):
    from app import db
    base, _ = verification
    with db.get_connection() as connection:
        repo_path = connection.execute("SELECT repo_path FROM code_repos LIMIT 1").fetchone()[0]
        location = f"file:{repo_path}/src/parser.c:35"
        connection.execute(
            "UPDATE assessment_findings SET canonical_location=?, row_version=row_version+1 WHERE slug='VA-701'",
            (location,),
        )
    appended = client.patch(base, json={"notes": "Acme legacy-location checkpoint"})
    assert appended.status_code == 200, appended.text
    assert appended.json()["finding"]["canonical_location"] == location


def test_claim_retraction_with_notes_still_invalidates_verification(client, verification):
    base, payload = verification
    assert client.post(base + "/verify", json=payload).status_code == 200
    response = client.patch(base, json={
        "notes": "Acme claim withdrawn", "reason_code": "claim_retracted",
        "reason_text": "Acme evidence does not support this claim",
    })
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["verification_status"] == "unreviewed"
    assert response.json()["verification_invalidated"] is True


def test_notes_append_does_not_clear_existing_claim_review(client, verification):
    base, payload = verification
    assert client.post(base + "/verify", json=payload).status_code == 200
    changed = client.patch(base, json={"details": {"impact": "Acme revised impact claim"}})
    assert changed.status_code == 200, changed.text
    before = client.get(base).json()
    assert before["verification_audit"]["claim_review_pending"] is True
    response = client.patch(base, json={"notes": "Acme administrative checkpoint"})
    assert response.status_code == 200, response.text
    after = client.get(base).json()
    assert after["verification_audit"]["claim_review_pending"] is True
    assert after["verification_status"] == before["verification_status"]
    assert [r["id"] for r in after["proof_receipts"]] == [r["id"] for r in before["proof_receipts"]]


def _merge_targets(client, base):
    from tests.test_finding_code_snapshot_provenance import _finding_payload, _record
    binding = client.get(base).json()["provenance"]["code_snapshot"]
    targets = []
    for slug, path in (("VA-702", "src/other.c"), ("VA-703", "src/bound.c")):
        response = _record(client, _finding_payload(
            slug, binding, location=f"file:{path}:37", author_agent_id="acme-hunter",
        ))
        assert response.status_code == 201, response.text
        targets.append(response.json()["finding"]["id"])
    return targets



def _merge_source(client, base):
    target_base = base.replace("VA-701", "VA-702")
    source = client.get(base).json()
    target = client.get(target_base).json()
    return client.post(base.rsplit("/findings/", 1)[0] + "/findings/merge", json={
        "source_slug": "VA-701", "target_slug": "VA-702",
        "reason": "Acme independent review identified the same root cause",
        "source_name": "operator",
        "expected_source_row_version": source["row_version"],
        "expected_target_row_version": target["row_version"],
    })


def test_implicit_append_keeps_already_merged_source_and_target_intact(client, verification):
    base, _ = verification
    target, _ = _merge_targets(client, base)
    merged = _merge_source(client, base)
    assert merged.status_code == 200, merged.text
    target_before = client.get(base.replace("VA-701", "VA-702")).json()
    response = client.patch(base, json={"notes": "Acme archived-source checkpoint"})
    assert response.status_code == 200, response.text
    finding = response.json()["finding"]
    assert finding["workflow_status"] == "merged"
    assert finding["merged_into_finding_id"] == target
    assert "Acme archived-source checkpoint" in finding["notes"]
    target_after = client.get(base.replace("VA-701", "VA-702")).json()
    assert target_after["row_version"] == target_before["row_version"]
    assert target_after["notes"] == target_before["notes"]


@pytest.mark.parametrize("already_merged", [False, True])
def test_implicit_append_refuses_a_merge_boundary_changed_after_validation(
    client, verification, monkeypatch, already_merged,
):
    from app import db
    base, _ = verification
    first_target, second_target = _merge_targets(client, base)
    if already_merged:
        with db.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_findings SET status='merged', merged_into_finding_id=?, "
                "row_version=row_version+1 WHERE slug='VA-701'", (first_target,),
            )
    original = findings.create_finding
    entered = []

    def merge_between_validation_and_writer(*args, **kwargs):
        if kwargs.get("code_snapshot_write_mode") == "patch" and not entered:
            entered.append(True)
            with db.get_connection() as connection:
                connection.execute(
                    "UPDATE assessment_findings SET status='merged', merged_into_finding_id=?, "
                    "row_version=row_version+1 WHERE slug='VA-701'", (second_target,),
                )
        return original(*args, **kwargs)

    monkeypatch.setattr(findings, "create_finding", merge_between_validation_and_writer)
    response = client.patch(base, json={"notes": "Acme stale merge checkpoint"})
    assert response.status_code == 409, response.text
    assert "changed since it was loaded" in response.json()["detail"]
    current = client.get(base).json()
    assert current["workflow_status"] == "merged"
    assert current["merged_into_finding_id"] == second_target
    assert "Acme stale merge checkpoint" not in current["notes"]


def test_actual_merge_after_validation_refuses_late_notes_without_changing_either_record(
    client, verification, monkeypatch,
):
    base, _ = verification
    _merge_targets(client, base)
    original = findings.create_finding
    merged_records = {}
    merged_history = {}

    def merge_between_validation_and_writer(*args, **kwargs):
        if kwargs.get("code_snapshot_write_mode") == "patch" and not merged_records:
            merged = _merge_source(client, base)
            assert merged.status_code == 200, merged.text
            for slug in ("VA-701", "VA-702"):
                path = base.replace("VA-701", slug)
                merged_records[slug] = client.get(path).json()
                merged_history[slug] = client.get(path + "/transitions").json()
        return original(*args, **kwargs)

    monkeypatch.setattr(findings, "create_finding", merge_between_validation_and_writer)
    response = client.patch(base, json={"notes": "Acme late checkpoint after actual merge"})
    assert response.status_code == 409, response.text
    for slug in ("VA-701", "VA-702"):
        path = base.replace("VA-701", slug)
        record = client.get(path).json()
        for field in ("notes", "row_version", "workflow_status", "verification_status", "proof_receipts"):
            assert record[field] == merged_records[slug][field], (slug, field)
        assert client.get(path + "/transitions").json() == merged_history[slug]
