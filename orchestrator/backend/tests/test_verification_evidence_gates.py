from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from app import db as db_module
from app.services import state_manager

from tests.proof_fixtures import (
    RUNTIME_PROOF_PLAN,
    completed_confirm_check,
    post_artifact_backed_source_observation,
)
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-08-verification-evidence"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for agent_id, role in (
        ("HUNT-1", "vulnerability-analyst"),
        ("VERIFY-1", "code-vuln-verifier"),
    ):
        response = client.post(
            f"{BASE}/dispatches",
            json={"agent_id": agent_id, "agent_role": role, "task": role},
        )
        assert response.status_code == 201, response.text


def _finding(client, slug: str, **overrides) -> dict:
    payload = {
        "slug": slug,
        "title": f"{slug} authorization defect",
        "severity": "medium",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "defect_family": "access-control",
        "root_cause_key": f"root-{slug}",
        "canonical_location": f"https://example.test/{slug}",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "hunter observation", "impact": "data disclosure"},
        "provenance": {"agent_id": "HUNT-1"},
    }
    payload.update(overrides)
    response = client.post(f"{BASE}/findings", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["finding"]


def _legacy_authorless_finding(slug: str) -> dict:
    with db_module.get_connection() as connection:
        engagement = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()
        assert engagement is not None
        cursor = connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status, verification_status,
                defect_family, root_cause_key, canonical_location, source_name,
                summary, details_json, provenance_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(engagement["id"]),
                slug,
                f"{slug} legacy authorless finding",
                "medium",
                "active",
                "unreviewed",
                "access-control",
                f"root-{slug}",
                f"https://example.test/{slug}",
                "renamed-hunter-label",
                "Imported from a database created before author provenance.",
                json.dumps({"evidence": "legacy", "impact": "data disclosure"}),
                "{}",
            ),
        )
        finding_id = int(cursor.lastrowid)
    return {"id": finding_id, "row_version": 1}


def _receipt(
    client, agent_id: str, suffix: str, *,
    kind: str = "source_observation", finding_slug: str | None = None,
) -> dict:
    run = client.post(
        f"{BASE}/assessment-runs",
        json={
            "run_uuid": f"run-{suffix}",
            "run_kind": "code",
            "producer_dispatch_agent_id": agent_id,
        },
    )
    assert run.status_code == 201, run.text
    if finding_slug is not None:
        linked = client.post(
            f"{BASE}/findings/{finding_slug}/links",
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
            "evidence_kind": kind,
            "expected_result": "authorization guard dominates the data read",
            "observed_result": "a path bypasses the guard and reaches the data read",
        },
    )
    assert receipt.status_code == 201, receipt.text
    finished = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert finished.status_code == 200, finished.text
    return receipt.json()


def test_terminal_verification_requires_healthy_independent_proof(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-001")

    missing = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={"verification_status": "confirmed", "reason_text": "reviewed"},
    )
    assert missing.status_code == 400, missing.text
    assert "proof_receipt" in missing.json()["detail"]

    hunter_receipt = _receipt(client, "HUNT-1", "hunter", finding_slug="VA-001")
    not_independent = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "self-review",
            "proof_receipt_ids": [hunter_receipt["id"]],
        },
    )
    assert not_independent.status_code == 400, not_independent.text
    assert "independent" in not_independent.json()["detail"]

    verifier_receipt = _receipt(client, "VERIFY-1", "verifier", finding_slug="VA-001")
    unchecked = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent source-path proof",
            "proof_receipt_ids": [verifier_receipt["id"]],
        },
    )
    assert unchecked.status_code == 400, unchecked.text
    assert "confirm_check" in unchecked.json()["detail"]
    incomplete = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "unsettled source-path proof",
            "proof_receipt_ids": [verifier_receipt["id"]],
            "confirm_check": {**completed_confirm_check(verifier_receipt["id"]), "completed": False},
        },
    )
    assert incomplete.status_code == 400, incomplete.text
    mismatched = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "unrelated falsification evidence",
            "proof_receipt_ids": [verifier_receipt["id"]],
            "confirm_check": completed_confirm_check(hunter_receipt["id"]),
        },
    )
    assert mismatched.status_code == 400, mismatched.text
    assert "decision proof receipts" in mismatched.json()["detail"]
    unrelated_receipt = _receipt(client, "VERIFY-1", "unrelated-check")
    unrelated_check = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "The check cites unrelated verifier work.",
            "proof_receipt_ids": [verifier_receipt["id"], unrelated_receipt["id"]],
            "confirm_check": completed_confirm_check(unrelated_receipt["id"]),
        },
    )
    assert unrelated_check.status_code == 400, unrelated_check.text
    assert "finding-linked" in unrelated_check.json()["detail"]
    confirmed = client.post(
        f"{BASE}/findings/VA-001/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "independent source-path proof",
            "proof_receipt_ids": [verifier_receipt["id"]],
            "confirm_check": {
                "method": "Replay with a second tenant",
                "attempted_falsification": "Check whether object ownership stops the read",
                "expected_result": "The second tenant receives a denial",
                "observed_result": "The second tenant receives the object",
                "proof_receipt_ids": [verifier_receipt["id"]],
                "completed": True,
            },
        },
    )
    assert confirmed.status_code == 200, confirmed.text
    finding = confirmed.json()["finding"]
    assert finding["verification_status"] == "confirmed"
    assert [row["id"] for row in finding["proof_receipts"]] == [verifier_receipt["id"]]
    transition = client.get(f"{BASE}/findings/VA-001/transitions").json()[0]
    assert json.loads(transition["metadata_json"])["confirm_check"]["attempted_falsification"] == "Check whether object ownership stops the read"


def test_terminal_verification_requires_receipt_run_linked_to_finding(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-099")
    verifier_receipt = _receipt(client, "VERIFY-1", "unlinked-verifier")
    payload = {
        "verification_status": "confirmed",
        "reason_text": "Independent source-path proof",
        "proof_receipt_ids": [verifier_receipt["id"]],
        "confirm_check": completed_confirm_check(verifier_receipt["id"]),
    }

    unlinked = client.post(f"{BASE}/findings/VA-099/verify", json=payload)
    assert unlinked.status_code == 400, unlinked.text
    assert "proof_run" in unlinked.json()["detail"]

    unknown_run = client.post(
        f"{BASE}/findings/VA-099/links",
        json={
            "link_kind": "proof_run", "target_kind": "assessment_run",
            "target_id": 999999,
        },
    )
    assert unknown_run.status_code == 404, unknown_run.text

    linked = client.post(
        f"{BASE}/findings/VA-099/links",
        json={
            "link_kind": "proof_run",
            "target_kind": "assessment_run",
            "target_id": verifier_receipt["run_id"],
        },
    )
    assert linked.status_code == 200, linked.text
    retired = client.patch(
        f"{BASE}/findings/VA-099/links/{linked.json()['id']}",
        json={"retired": True},
    )
    assert retired.status_code == 200, retired.text
    assert client.post(f"{BASE}/findings/VA-099/verify", json=payload).status_code == 400
    reactivated = client.patch(
        f"{BASE}/findings/VA-099/links/{linked.json()['id']}",
        json={"retired": False},
    )
    assert reactivated.status_code == 200, reactivated.text
    confirmed = client.post(f"{BASE}/findings/VA-099/verify", json=payload)
    assert confirmed.status_code == 200, confirmed.text


def test_terminal_verification_cannot_invent_missing_author_identity(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _legacy_authorless_finding("VA-003")

    # Missing historical attribution does not make the record unreadable.
    readable = client.get(f"{BASE}/findings/VA-003")
    assert readable.status_code == 200, readable.text
    assert readable.json()["provenance"] == {}

    hunter_receipt = _receipt(client, "HUNT-1", "legacy-self-review", finding_slug="VA-003")
    response = client.post(
        f"{BASE}/findings/VA-003/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "self-review under a different label",
            "source_name": "independent-looking-label",
            # Verification-time metadata cannot retroactively establish who
            # authored the finding being reviewed.
            "provenance": {"agent_id": "VERIFY-1"},
            "proof_receipt_ids": [hunter_receipt["id"]],
        },
    )

    assert response.status_code == 400, response.text
    assert "author" in response.json()["detail"]
    unchanged = client.get(f"{BASE}/findings/VA-003").json()
    assert unchanged["verification_status"] == "unreviewed"
    assert unchanged["provenance"] == {}


def test_relocation_cannot_retrofit_missing_author_identity(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    finding = _legacy_authorless_finding("VA-004")

    response = client.put(
        f"{BASE}/findings/VA-004/canonical-location",
        json={
            "canonical_location": "https://example.test/relocated/VA-004",
            "reason_text": "reviewed relocation",
            "source_name": "independent-looking-label",
            "expected_row_version": finding["row_version"],
            "provenance": {"agent_id": "VERIFY-1"},
        },
    )

    assert response.status_code == 400, response.text
    assert "immutable" in response.json()["detail"]
    unchanged = client.get(f"{BASE}/findings/VA-004").json()
    assert unchanged["canonical_location"].endswith("/VA-004")
    assert unchanged["provenance"] == {}


def test_merge_cannot_replace_unknown_target_author_with_source_author(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _legacy_authorless_finding("VA-005")
    _finding(
        client,
        "VA-006",
        provenance={"agent_id": "VERIFY-1"},
        source_name="code-vuln-verifier",
    )

    merged = client.post(
        f"{BASE}/findings/merge",
        json={
            "source_slug": "VA-006",
            "target_slug": "VA-005",
            "reason": "same root cause",
            "source_name": "operator",
        },
    )
    assert merged.status_code == 200, merged.text

    hunter_receipt = _receipt(client, "HUNT-1", "merged-unknown-self-review", finding_slug="VA-005")
    response = client.post(
        f"{BASE}/findings/VA-005/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "target author remained unknown",
            "proof_receipt_ids": [hunter_receipt["id"]],
        },
    )

    assert response.status_code == 400, response.text
    assert "author" in response.json()["detail"]


def test_finding_record_cannot_bypass_terminal_verification_gate(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)

    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-002",
            "title": "unaudited terminal verdict",
            "severity": "medium",
            "verification_status": "confirmed",
            "source_name": "vulnerability-analyst",
            "provenance": {"agent_id": "HUNT-1"},
        },
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"][0]
    assert detail["loc"] == ["body", "verification_status"]
    assert "unreviewed" in detail["msg"]


def test_false_positive_requires_completed_structured_countercheck(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-010")
    receipt = _receipt(client, "VERIFY-1", "fp", finding_slug="VA-010")

    prose_only = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "not reproducible",
            "details": {"kill_reason": "not reproducible", "kill_check": 1},
            "proof_receipt_ids": [receipt["id"]],
        },
    )
    assert prose_only.status_code == 400, prose_only.text
    assert "counter_check" in prose_only.json()["detail"]

    unavailable = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "account unavailable",
            "details": {
                "kill_reason": "The required account was unavailable.",
                "kill_check": 1,
                "required_followup": ["Provision the second account and rerun the replay."],
            },
            "counter_check": {
                "method": "cross-tenant replay",
                "expected_result": "other tenant data is returned",
                "observed_result": "no second tenant account was available",
                "falsified_claim": "cross-tenant access is possible",
                "completed": False,
                "proof_receipt_ids": [receipt["id"]],
            },
        },
    )
    assert unavailable.status_code == 400, unavailable.text
    assert "blocked" in unavailable.json()["detail"]
    assert "pending_runtime_proof" in unavailable.json()["detail"]

    decisive = client.post(
        f"{BASE}/findings/VA-010/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "completed negative control falsified the claim",
            "details": {
                "kill_reason": "All source paths are dominated by the tenant guard.",
                "kill_check": 1,
            },
            "counter_check": {
                "method": "authorization-dominance source proof",
                "expected_result": "an unguarded path reaches the sensitive read",
                "observed_result": "all paths are dominated by the tenant guard",
                "falsified_claim": "a path bypasses tenant authorization",
                "completed": True,
                "proof_receipt_ids": [receipt["id"]],
            },
        },
    )
    assert decisive.status_code == 200, decisive.text
    assert decisive.json()["finding"]["verification_status"] == "false_positive"
    assert decisive.json()["counter_check"]["completed"] is True

    detail_response = client.get(f"{BASE}/findings/VA-010")
    assert detail_response.status_code == 200, detail_response.text
    audit = detail_response.json()["verification_audit"]
    assert audit["counter_check_total"] == 1
    assert audit["severity_variance_total"] == 0
    assert audit["truncated"] is False
    assert audit["counter_checks"] == [
        {
            "id": decisive.json()["counter_check"]["id"],
            "transition_id": decisive.json()["transition"]["id"],
            "verifier_dispatch_id": decisive.json()["counter_check"][
                "verifier_dispatch_id"
            ],
            "method": "authorization-dominance source proof",
            "expected_result": "an unguarded path reaches the sensitive read",
            "observed_result": "all paths are dominated by the tenant guard",
            "falsified_claim": "a path bypasses tenant authorization",
            "completed": True,
            "proof_receipt_ids": [receipt["id"]],
            "created_at": audit["counter_checks"][0]["created_at"],
        }
    ]

    history_response = client.get(
        f"{BASE}/findings/VA-010/transitions", params={"limit": 1}
    )
    assert history_response.status_code == 200, history_response.text
    transition = history_response.json()[0]
    assert transition["id"] == decisive.json()["transition"]["id"]
    assert transition["verification_audit"]["counter_checks"] == audit[
        "counter_checks"
    ]
    assert transition["verification_audit"]["severity_variances"] == []


def test_missing_raw_evidence_blocks_only_a_dependent_terminal_decision(
    client, isolate_settings
) -> None:
    from app import db as db_module

    _seed(client, isolate_settings)
    _finding(client, "VA-020")
    receipt = _receipt(client, "VERIFY-1", "missing", finding_slug="VA-020")
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_receipts SET recorded_health = 'tombstoned' WHERE id = ?",
            (receipt["id"],),
        )

    blocked = client.post(
        f"{BASE}/findings/VA-020/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "depends on missing receipt",
            "proof_receipt_ids": [receipt["id"]],
        },
    )
    assert blocked.status_code == 409, blocked.text
    assert "evidence" in blocked.json()["detail"]

    # An unrelated holding decision does not claim proof and remains writable.
    pending = client.post(
        f"{BASE}/findings/VA-020/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "next_test": RUNTIME_PROOF_PLAN,
            "reason_text": "fresh proof is required",
        },
    )
    assert pending.status_code == 200, pending.text


def test_fresh_reverification_supersedes_old_receipt_health_dependency(
    client, isolate_settings
) -> None:
    from app import db as db_module

    _seed(client, isolate_settings)
    _finding(client, "VA-021")
    old_receipt = _receipt(client, "VERIFY-1", "old-decision", finding_slug="VA-021")
    original = client.post(
        f"{BASE}/findings/VA-021/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "initial independent proof",
            "proof_receipt_ids": [old_receipt["id"]],
            "confirm_check": completed_confirm_check(old_receipt["id"]),
        },
    )
    assert original.status_code == 200, original.text

    fresh_receipt = _receipt(client, "VERIFY-1", "fresh-decision", finding_slug="VA-021")
    refreshed = client.post(
        f"{BASE}/findings/VA-021/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "fresh independent proof supersedes the old decision",
            "proof_receipt_ids": [fresh_receipt["id"]],
            "confirm_check": completed_confirm_check(fresh_receipt["id"]),
        },
    )
    assert refreshed.status_code == 200, refreshed.text

    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_receipts "
            "SET recorded_health = 'tombstoned' WHERE id = ?",
            (old_receipt["id"],),
        )

    detail = client.get(f"{BASE}/findings/VA-021")
    assert detail.status_code == 200, detail.text
    assert [row["id"] for row in detail.json()["proof_receipts"]] == [
        fresh_receipt["id"]
    ]
    readiness = client.get(f"{BASE}/report-readiness")
    assert readiness.status_code == 200, readiness.text
    assert not any(
        blocker["kind"].startswith("finding_proof_evidence_")
        and blocker.get("slug") == "VA-021"
        for blocker in readiness.json()["blockers"]
    )

    history = client.get(f"{BASE}/findings/VA-021/transitions").json()
    by_transition = {row["id"]: row for row in history}
    assert by_transition[original.json()["transition"]["id"]][
        "verification_audit"
    ]["proof_receipt_ids"] == [old_receipt["id"]]
    assert by_transition[refreshed.json()["transition"]["id"]][
        "verification_audit"
    ]["proof_receipt_ids"] == [fresh_receipt["id"]]


def test_cvss_band_departure_requires_attributed_variance_event(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(
        client,
        "VA-030",
        severity="high",
        details={
            "evidence": "source proof",
            "impact": "limited disclosure",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "severity_band_rationale": "legacy free text is not an approval",
        },
    )
    receipt = _receipt(client, "VERIFY-1", "variance", finding_slug="VA-030")

    missing = client.post(
        f"{BASE}/findings/VA-030/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "business impact supports high",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )
    assert missing.status_code == 400, missing.text
    assert "severity_variance" in missing.json()["detail"]
    assert '"normal_band":"medium"' in missing.json()["detail"]
    assert '"chosen_severity":"high"' in missing.json()["detail"]
    assert f'"proof_receipt_id":{receipt["id"]}' in missing.json()["detail"]

    accepted = client.post(
        f"{BASE}/findings/VA-030/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "business impact supports high",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
            "severity_variance": {
                "normal_band": "medium",
                "chosen_severity": "high",
                "actor": "code-vuln-verifier",
                "reason": "The exposed records trigger a contractual incident.",
                "proof_receipt_id": receipt["id"],
            },
        },
    )
    assert accepted.status_code == 200, accepted.text
    variance = accepted.json()["severity_variance"]
    assert variance["normal_band"] == "medium"
    assert variance["chosen_severity"] == "high"
    assert variance["actor"] == "code-vuln-verifier"

    detail_response = client.get(f"{BASE}/findings/VA-030")
    assert detail_response.status_code == 200, detail_response.text
    audit = detail_response.json()["verification_audit"]
    assert audit["counter_check_total"] == 0
    assert audit["severity_variance_total"] == 1
    assert audit["truncated"] is False
    assert audit["severity_variances"] == [
        {
            "id": variance["id"],
            "transition_id": accepted.json()["transition"]["id"],
            "normal_band": "medium",
            "chosen_severity": "high",
            "actor": "code-vuln-verifier",
            "reason": "The exposed records trigger a contractual incident.",
            "proof_receipt_id": receipt["id"],
            "created_at": audit["severity_variances"][0]["created_at"],
        }
    ]

    history_response = client.get(
        f"{BASE}/findings/VA-030/transitions", params={"limit": 1}
    )
    assert history_response.status_code == 200, history_response.text
    transition = history_response.json()[0]
    assert transition["id"] == accepted.json()["transition"]["id"]
    assert transition["verification_audit"]["counter_checks"] == []
    assert transition["verification_audit"]["severity_variances"] == audit[
        "severity_variances"
    ]


def _engagement_id() -> int:
    with db_module.get_connection() as connection:
        row = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()
    assert row is not None
    return int(row["id"])


def _intel_note(client, title: str) -> int:
    response = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/intel/notes",
        json={
            "title": title,
            "body_markdown": "Deployment config read outside the sealed snapshot.",
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["id"])


def test_a_confirmed_verification_re_bands_and_re_attests_in_one_write(
    client, isolate_settings
) -> None:
    """A terminal verdict carries its own band, so a re-band keeps the verdict.

    ``finding update --severity`` is an INVALIDATE axis, so a program re-band
    through it destroys the verdict the verifier just earned and leaves an
    operator holding no dispatch unable to restore it.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-040")
    receipt = _receipt(client, "VERIFY-1", "reband", finding_slug="VA-040")

    response = client.post(
        f"{BASE}/findings/VA-040/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Program calibration bands this class at high.",
            "new_severity": "high",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert response.status_code == 200, response.text
    finding = response.json()["finding"]
    assert finding["verification_status"] == "confirmed"
    assert finding["severity"] == "high"
    transition = client.get(f"{BASE}/findings/VA-040/transitions").json()[0]
    assert transition["from_severity"] == "medium"
    assert transition["to_severity"] == "high"
    assert json.loads(transition["metadata_json"])["previous_severity"] == "medium"


def test_new_severity_outside_a_terminal_verdict_names_the_update_verb(
    client, isolate_settings
) -> None:
    """A non-terminal status records no fresh attestation, so it cannot re-band."""
    _seed(client, isolate_settings)
    _finding(client, "VA-041")

    response = client.post(
        f"{BASE}/findings/VA-041/verify",
        json={
            "verification_status": "disputed",
            "reason_text": "The band looks wrong but nothing was re-tested.",
            "new_severity": "low",
        },
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "confirmed, downgraded, false_positive" in detail
    assert "vigil assess finding update VA-041 --severity low" in detail


def test_a_same_band_downgrade_refusal_names_the_cvss_correction_route(
    client, isolate_settings
) -> None:
    """``downgraded`` means the band moved; an in-band rating fix has its own route."""
    _seed(client, isolate_settings)
    _finding(
        client,
        "VA-042",
        severity="medium",
        details={
            "evidence": "hunter observation",
            "impact": "data disclosure",
            "cvss_score": 5.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        },
    )
    receipt = _receipt(client, "VERIFY-1", "sameband", finding_slug="VA-042")

    response = client.post(
        f"{BASE}/findings/VA-042/verify",
        json={
            "verification_status": "downgraded",
            "reason_text": "The rating is wrong but the band is right.",
            "new_severity": "medium",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "vigil assess finding update VA-042 --details-inline" in detail
    assert "cvss_score" in detail and "cvss_vector" in detail
    assert "vigil assess finding verify VA-042 --status confirmed" in detail
    assert "in that order" in detail


def test_a_downgrade_cannot_raise_the_band_it_is_recording(
    client, isolate_settings
) -> None:
    """``downgraded`` names a direction, so the upward refusal is the verdict's own.

    Pinned here because the refusal had no coverage at all: the production string
    was the only copy in the tree, so an edit that dropped the comparison would
    have turned a band ESCALATION recorded as a downgrade into a silent 200.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-044", severity="high")
    receipt = _receipt(client, "VERIFY-1", "down-up", finding_slug="VA-044")

    response = client.post(
        f"{BASE}/findings/VA-044/verify",
        json={
            "verification_status": "downgraded",
            "reason_text": "The retest widened the impact.",
            "new_severity": "critical",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert response.status_code == 400, response.text
    assert "higher than the current severity" in response.json()["detail"]
    stored = client.get(f"{BASE}/findings/VA-044").json()
    assert stored["severity"] == "high"
    assert stored["verification_status"] == "unreviewed"


def test_a_confirmed_verdict_cannot_lower_the_band_behind_the_downgrade_route(
    client, isolate_settings
) -> None:
    """A band that moved DOWN is a downgrade whichever status is being written.

    ``confirmed`` re-bands upward on purpose — a program calibration that raises
    the class is still a confirmation. Downward it is the ``downgraded`` verdict
    by definition, and routing it through ``confirmed`` instead reaches the same
    lower band while the ledger row reads ``verified_confirmed``: no
    ``verified_downgraded`` transition, so nothing that reads the history for
    band movements sees it. ``cvss_score`` is optional at record time, so the
    CVSS-band variance gate is not covering this: with no score stored there is
    no band to depart from and the write lands unattributed.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-045", severity="high")
    receipt = _receipt(client, "VERIFY-1", "confirm-down", finding_slug="VA-045")

    response = client.post(
        f"{BASE}/findings/VA-045/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Reproduced, but the blast radius is smaller than filed.",
            "new_severity": "info",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert "vigil assess finding verify VA-045 --status downgraded" in detail
    stored = client.get(f"{BASE}/findings/VA-045").json()
    assert stored["severity"] == "high"
    assert stored["verification_status"] == "unreviewed"

    # Same evidence, honest disposition: the lower band is reachable, and the
    # ledger says a band moved.
    accepted = client.post(
        f"{BASE}/findings/VA-045/verify",
        json={
            "verification_status": "downgraded",
            "reason_text": "Reproduced, but the blast radius is smaller than filed.",
            "new_severity": "info",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["finding"]["severity"] == "info"
    transition = client.get(f"{BASE}/findings/VA-045/transitions").json()[0]
    assert transition["action"] == "verified_downgraded"
    assert json.loads(transition["metadata_json"])["previous_severity"] == "high"


# --- operator authority -------------------------------------------------------
#
# The operator holds no dispatch, so every receipt route is closed to them: a
# fact that settles a finding but lies OUTSIDE the sealed snapshot (a deployment
# config, a vendor statement) had no verdict lever at all, and the finding kept a
# rating its own evidence contradicted. ADR 0019 lets the operator weaken a gate
# over their own engagement; it must be visible, so the waiver is stamped and
# every verdict projection carries it.

_OPERATOR_REASON = "The deployment config disables the affected route in production."


def _operator_authority_verdict(slug: str, intel_id: int, **overrides) -> dict:
    payload = {
        "slug": slug,
        "verification_status": "downgraded",
        "reason_code": "operator_authority",
        "reason_text": _OPERATOR_REASON,
        "source_name": "operator",
        "evidence_ref": "",
        "notes": "",
        "details": None,
        "provenance": None,
        "artifact_ref": "",
        "new_severity": "low",
        "operator_authority": True,
        "operator_authority_intel_id": intel_id,
    }
    payload.update(overrides)
    return state_manager.verify_finding(_engagement_id(), **payload)


def test_an_operator_authority_verdict_records_without_a_proof_receipt(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-050")
    intel_id = _intel_note(client, "Acme deployment config disables the affected route")

    result = _operator_authority_verdict("VA-050", intel_id)

    stamp = result["finding"]["provenance"]["operator_authority"]
    assert stamp["kind"] == "out_of_snapshot"
    assert stamp["intel_id"] == intel_id
    assert stamp["reason"] == _OPERATOR_REASON
    assert stamp["at"]
    assert result["finding"]["verification_status"] == "downgraded"
    assert result["finding"]["severity"] == "low"
    assert result["operator_authority"] == stamp
    assert result["proof_receipts"] == []

    detail = client.get(f"{BASE}/findings/VA-050")
    assert detail.status_code == 200, detail.text
    audit = detail.json()["verification_audit"]
    assert audit["operator_authority"] == stamp
    assert audit["proof_receipt_total"] == 0
    transition = client.get(f"{BASE}/findings/VA-050/transitions").json()[0]
    assert json.loads(transition["metadata_json"])["operator_authority"] == stamp


def test_operator_authority_requires_a_resolvable_intel_row(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-051")

    with pytest.raises(HTTPException) as exc:
        _operator_authority_verdict("VA-051", 4242)

    assert exc.value.status_code == 400
    assert "4242" in exc.value.detail
    assert "intel" in exc.value.detail
    assert client.get(f"{BASE}/findings/VA-051").json()["verification_status"] == "unreviewed"


def test_operator_authority_requires_a_reason_and_a_terminal_status(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings)
    _finding(client, "VA-052")
    intel_id = _intel_note(client, "Acme vendor statement for VA-052")

    with pytest.raises(HTTPException) as blank:
        _operator_authority_verdict("VA-052", intel_id, reason_text="   ")
    assert blank.value.status_code == 400
    assert "reason" in blank.value.detail

    with pytest.raises(HTTPException) as non_terminal:
        _operator_authority_verdict(
            "VA-052", intel_id, verification_status="disputed", new_severity=None
        )
    assert non_terminal.value.status_code == 400
    assert "terminal" in non_terminal.value.detail
    assert client.get(f"{BASE}/findings/VA-052").json()["verification_status"] == "unreviewed"


def test_an_authored_operator_authority_stamp_is_not_a_waiver(
    client, isolate_settings
) -> None:
    """The stamp is the server's record of a resolved intel row and a reason.

    Accepting one from the request body would make the whole gate forgeable by
    anybody who can write provenance.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-053")

    hand_written = {
        "kind": "out_of_snapshot",
        "intel_id": 1,
        "at": "2026-01-01T00:00:00Z",
        "reason": "hand-written",
    }

    forged = client.post(
        f"{BASE}/findings/VA-053/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "Stamped by hand.",
            "provenance": {"operator_authority": hand_written},
        },
    )
    assert forged.status_code >= 400, forged.text
    assert "--operator-authority" in forged.text

    with pytest.raises(HTTPException) as exc:
        state_manager.verify_finding(
            _engagement_id(),
            slug="VA-053",
            verification_status="confirmed",
            reason_code="",
            reason_text="Stamped by hand.",
            source_name="operator",
            evidence_ref="",
            notes="",
            details=None,
            provenance={"operator_authority": hand_written},
            artifact_ref="",
        )
    assert exc.value.status_code == 400
    assert "--operator-authority" in exc.value.detail
    assert client.get(f"{BASE}/findings/VA-053").json()["verification_status"] == "unreviewed"


def test_an_authored_superseded_stamp_cannot_fabricate_a_waiver_that_never_was(
    client, isolate_settings
) -> None:
    """The superseded record grants no authority, which is exactly why it matters.

    Nothing reads it as a live waiver, so a forged one cannot clear a gate — it
    fabricates HISTORY instead, telling every later reader of ``provenance``
    that a waiver was granted and replaced when neither happened. Both stamps
    are written by the funnel, so neither is authorable.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-056")
    hand_written = {
        "kind": "out_of_snapshot",
        "intel_id": 1,
        "at": "2026-01-01T00:00:00Z",
        "reason": "a waiver nobody granted",
    }

    forged = client.patch(
        f"{BASE}/findings/VA-056",
        json={"provenance": {"superseded_operator_authority": hand_written}},
    )
    assert forged.status_code >= 400, forged.text

    intel_id = _intel_note(client, "Acme deployment config for VA-056")
    with pytest.raises(HTTPException) as riding_along:
        _operator_authority_verdict(
            "VA-056",
            intel_id,
            provenance={"superseded_operator_authority": hand_written},
        )
    assert riding_along.value.status_code == 400
    assert "superseded_operator_authority" in riding_along.value.detail

    stored = client.get(f"{BASE}/findings/VA-056").json()["provenance"]
    assert "superseded_operator_authority" not in stored
    assert "operator_authority" not in stored


@pytest.mark.parametrize(
    "key", ["operator_authority", "superseded_operator_authority"]
)
def test_a_relocation_cannot_author_either_operator_authority_stamp(
    client, isolate_settings, key: str
) -> None:
    """The relocation route is a provenance door, so it owes the same refusal.

    ``relocate_finding`` merges caller provenance onto the stored object and
    writes it, so without this guard the waiver is forgeable by anybody who can
    move a finding: a stamp citing an intel id that need not exist, with a reason
    nobody gave, reaching ``verification_audit.operator_authority`` on the read.
    Relocation invalidates the verdict, so the LIVE forgery cannot carry a report
    — but the forged ``superseded`` record is durable, and both are history a
    reader is asked to trust.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-057")
    hand_written = {
        "kind": "out_of_snapshot",
        "intel_id": 9999,
        "at": "2026-01-01T00:00:00Z",
        "reason": "a waiver no relocation was ever granted",
    }

    forged = client.put(
        f"{BASE}/findings/VA-057/canonical-location",
        json={
            "canonical_location": "https://example.test/VA-057/moved",
            "reason_text": "Runtime proof relocated the defect server-side.",
            "source_name": "operator",
            "expected_row_version": 1,
            "provenance": {key: hand_written},
        },
    )

    assert forged.status_code == 400, forged.text
    assert key in forged.text
    assert "--operator-authority" in forged.text
    stored = client.get(f"{BASE}/findings/VA-057").json()
    assert key not in stored["provenance"]
    assert stored["verification_audit"]["operator_authority"] is None
    # The refusal is the whole write: the location it carried stays put.
    assert stored["canonical_location"] == "https://example.test/VA-057"


def test_a_relocation_that_authors_no_stamp_still_relocates(
    client, isolate_settings
) -> None:
    """The guard reads the two stamp keys and nothing else on this route."""
    _seed(client, isolate_settings)
    _finding(client, "VA-058")

    moved = client.put(
        f"{BASE}/findings/VA-058/canonical-location",
        json={
            "canonical_location": "https://example.test/VA-058/moved",
            "reason_text": "Runtime proof relocated the defect server-side.",
            "source_name": "operator",
            "expected_row_version": 1,
            "provenance": {"evidence_quote": "the handler reads the raw id"},
        },
    )

    assert moved.status_code == 200, moved.text
    stored = client.get(f"{BASE}/findings/VA-058").json()
    assert stored["canonical_location"] == "https://example.test/VA-058/moved"
    assert stored["provenance"]["evidence_quote"] == "the handler reads the raw id"


def test_no_finding_provenance_door_accepts_an_authored_waiver(
    client, isolate_settings
) -> None:
    """Every route that writes a finding's provenance refuses both stamps.

    A guard on one door and not another is not a guard: the waiver's value is
    that a reader can trust it was granted, so the refusal has to hold on each
    route that can reach ``assessment_findings.provenance_json`` — create, patch,
    verify and the audited relocation. The link and root-cause routes take their
    own provenance and write the LINK row, which no verdict projection reads;
    they are exercised here so the boundary is checked rather than assumed.
    """
    _seed(client, isolate_settings)
    hand_written = {
        "kind": "out_of_snapshot",
        "intel_id": 9999,
        "intel_type": "note",
        "at": "2026-01-01T00:00:00Z",
        "reason": "a waiver nobody granted",
    }

    for slug, key in (
        ("VA-061", "operator_authority"),
        ("VA-064", "superseded_operator_authority"),
    ):
        created = client.post(
            f"{BASE}/findings",
            json={
                "slug": slug,
                "title": "Authored waiver on create",
                "severity": "medium",
                "workflow_status": "active",
                "verification_status": "unreviewed",
                "canonical_location": f"https://example.test/{slug}",
                "source_name": "vulnerability-analyst",
                "details": {"evidence": "e", "impact": "i"},
                "provenance": {"agent_id": "HUNT-1", key: hand_written},
            },
        )
        assert created.status_code == 400, created.text
        assert key in created.text

    _finding(client, "VA-062")
    doors = {
        "patch": lambda key: client.patch(
            f"{BASE}/findings/VA-062",
            json={"provenance": {key: hand_written}},
        ),
        "verify": lambda key: client.post(
            f"{BASE}/findings/VA-062/verify",
            json={
                "verification_status": "confirmed",
                "reason_text": "Stamped by hand.",
                "provenance": {key: hand_written},
            },
        ),
        "relocate": lambda key: client.put(
            f"{BASE}/findings/VA-062/canonical-location",
            json={
                "canonical_location": "https://example.test/VA-062/moved",
                "reason_text": "Runtime proof relocated the defect server-side.",
                "source_name": "operator",
                "expected_row_version": 1,
                "provenance": {key: hand_written},
            },
        ),
    }
    for door, call in doors.items():
        for key in ("operator_authority", "superseded_operator_authority"):
            response = call(key)
            assert response.status_code == 400, f"{door}/{key}: {response.text}"
            assert key in response.text, f"{door}/{key}: {response.text}"

    # The link doors write the link row's own provenance, so they are not a
    # route to a finding's waiver. Named here so the claim is tested.
    _finding(client, "VA-063")
    linked = client.post(
        f"{BASE}/findings/VA-062/links",
        json={
            "link_kind": "related",
            "target_kind": "finding",
            "target_ref": "VA-063",
            "provenance": {"operator_authority": hand_written},
        },
    )
    assert linked.status_code == 200, linked.text
    rooted = client.put(
        f"{BASE}/findings/VA-062/root-cause",
        json={
            "root_cause_slug": "VA-063",
            "root_cause_effect": "eliminates_finding",
            "source_name": "operator",
            "provenance": {"operator_authority": hand_written},
        },
    )
    assert rooted.status_code == 200, rooted.text

    stored = client.get(f"{BASE}/findings/VA-062").json()
    assert "operator_authority" not in stored["provenance"]
    assert "superseded_operator_authority" not in stored["provenance"]
    assert stored["verification_audit"]["operator_authority"] is None
    assert stored["canonical_location"] == "https://example.test/VA-062"


# The other three service-stamped blocks. The request model declares all five so
# that a STORED row validates against the same vocabulary, and the attestation is
# additionally read back off an incoming payload to mark a copied binding — so the
# schema admits them and the service has to say which a caller may assert.

_FORGED_SERVICE_STAMPS = {
    "code_snapshot_attestation": {
        "finding_slug": "VA-OTHER",
        "recorded_by": "someone-else",
        "write_mode": "forged",
        "agent_id": "VERIFY-1",
        "dispatch_id": 1,
        "command_run_id": 99999,
        "at": "2026-01-01T00:00:00Z",
    },
    "superseded_code_snapshot": {
        "slug": "VA-OTHER",
        "code_snapshot": {
            "repo_id": 1,
            "repo_generation": 1,
            "source_manifest_digest": "d" * 64,
        },
        "reason": "a source review nobody performed",
        "at": "2026-01-01T00:00:00Z",
    },
    "original_canonical_location": "file:src/elsewhere.c:1",
}


@pytest.mark.parametrize("key", sorted(_FORGED_SERVICE_STAMPS))
def test_no_finding_provenance_door_accepts_an_authored_service_stamp(
    client, isolate_settings, key: str
) -> None:
    """The waiver keys are not the only stamps a reader is asked to trust.

    ``code_snapshot_attestation`` is the record of WHO asserted a binding and
    under which audited work — the block ``code_snapshot_attestation_status``
    reads to call a binding attested, unattested or copied, and report readiness
    blocks on the last two. ``superseded_code_snapshot`` asserts which bytes were
    reviewed before an audited relocation. ``original_canonical_location`` is the
    location as AUTHORED, kept so a normalisation cannot rewrite the audit trail;
    an authored one plants an as-authored location nobody wrote. Each is written
    by the service, so each owes the same refusal on every door.
    """
    _seed(client, isolate_settings)
    forged = _FORGED_SERVICE_STAMPS[key]

    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-065",
            "title": "Authored service stamp on create",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/VA-065",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "e", "impact": "i"},
            "provenance": {"agent_id": "HUNT-1", key: forged},
        },
    )
    assert created.status_code == 400, created.text
    assert key in created.text
    assert client.get(f"{BASE}/findings/VA-065").status_code == 404

    _finding(client, "VA-066")
    doors = {
        "patch": lambda: client.patch(
            f"{BASE}/findings/VA-066",
            json={"provenance": {key: forged}},
        ),
        "verify": lambda: client.post(
            f"{BASE}/findings/VA-066/verify",
            json={
                "verification_status": "confirmed",
                "reason_text": "Stamped by hand.",
                "provenance": {key: forged},
            },
        ),
        "relocate": lambda: client.put(
            f"{BASE}/findings/VA-066/canonical-location",
            json={
                "canonical_location": "https://example.test/VA-066/moved",
                "reason_text": "Runtime proof relocated the defect server-side.",
                "source_name": "operator",
                "expected_row_version": 1,
                "provenance": {key: forged},
            },
        ),
    }
    for door, call in doors.items():
        response = call()
        assert response.status_code == 400, f"{door}: {response.text}"
        assert key in response.text, f"{door}: {response.text}"

    stored = client.get(f"{BASE}/findings/VA-066").json()
    assert key not in stored["provenance"]
    assert stored["verification_status"] == "unreviewed"
    assert stored["canonical_location"] == "https://example.test/VA-066"


def test_only_the_door_that_restamps_an_attestation_lets_one_ride_a_binding(
    client, isolate_settings
) -> None:
    """The copy-detection exception belongs to the funnel that restamps, and only it.

    ``finding record`` reads an incoming attestation to mark a binding copied from
    another finding, then writes its OWN over the top, so nothing authored
    survives there. The relocation never stamps an attestation, so the same
    payload would be stored verbatim — the exception is a property of the door,
    not of the payload.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-070")
    riding_along = {
        "code_snapshot": {
            "repo_id": 1,
            "repo_generation": 1,
            "source_manifest_digest": "d" * 64,
        },
        "code_snapshot_attestation": _FORGED_SERVICE_STAMPS[
            "code_snapshot_attestation"
        ],
    }

    forged = client.put(
        f"{BASE}/findings/VA-070/canonical-location",
        json={
            "canonical_location": "https://example.test/VA-070/moved",
            "reason_text": "Runtime proof relocated the defect server-side.",
            "source_name": "operator",
            "expected_row_version": 1,
            "provenance": riding_along,
        },
    )

    assert forged.status_code == 400, forged.text
    assert "code_snapshot_attestation" in forged.text
    stored = client.get(f"{BASE}/findings/VA-070").json()
    assert "code_snapshot_attestation" not in stored["provenance"]
    assert stored["canonical_location"] == "https://example.test/VA-070"


def test_every_caller_assertable_provenance_key_still_round_trips(
    client, isolate_settings
) -> None:
    """The refusal is scoped to the stamps, and over-refusing is the other failure.

    ``provenance`` answers "who recorded this, and from what", and the authoring
    half of that vocabulary is the operator-visible evidence the report renders
    beside each finding. A guard that swept it up would make the record
    unwritable, so the accepted set is pinned next to the refused one.
    """
    _seed(client, isolate_settings)
    authored = {
        "agent_id": "HUNT-1",
        "agent_name": "vulnerability-analyst",
        "artifact": "artifacts/acme-orders-replay.har",
        "artifact_ref": "artifacts/acme-orders-replay.har#entry-12",
        "captured_at": "2026-01-01T00:00:00Z",
        "evidence_quote": "GET /api/orders/4711 -> 200 {\"tenant\":\"acme\"}",
        "reported_by": "acme-researcher",
        "reviewed_by": "ir-lead",
        "verified_by": "code-vuln-verifier",
    }

    created = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-067",
            "title": "Caller-assertable provenance round trip",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/VA-067",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "e", "impact": "i"},
            "provenance": authored,
        },
    )

    assert created.status_code == 201, created.text
    assert created.json()["finding"]["provenance"] == authored


def test_an_authored_command_run_citation_must_name_a_run_in_this_engagement(
    client, isolate_settings
) -> None:
    """The citation is a pointer into the audit trail, so it resolves at write time.

    ``details.repro_runs`` and ``details.replay_commands`` already refuse an id
    that names nothing — an id that points at a transcript nobody can fetch.
    ``provenance.command_run_id`` is the same kind of claim about the run this
    write was performed under, and it is folded into the code-snapshot
    attestation, so an unresolvable one puts a run id on the record that no
    reader can follow.
    """
    _seed(client, isolate_settings)

    refused = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-068",
            "title": "Unresolvable command-run citation",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/VA-068",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "e", "impact": "i"},
            "provenance": {"agent_id": "HUNT-1", "command_run_id": 99999},
        },
    )

    assert refused.status_code == 400, refused.text
    assert "99999" in refused.text
    assert "command-run" in refused.text
    assert client.get(f"{BASE}/findings/VA-068").status_code == 404

    run = client.post(
        f"{BASE}/command-runs",
        json={
            "run_uuid": "provenance-citation-run",
            "command": "curl -sS https://example.test/api/orders/4711",
            "tool_name": "curl",
            "agent_name": "vulnerability-analyst",
            "phase": "exploit",
            "status": "completed",
            "return_code": 0,
            "started_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:01Z",
            "stdout": "{\"tenant\":\"acme\"}",
        },
    )
    assert run.status_code == 201, run.text

    accepted = client.post(
        f"{BASE}/findings",
        json={
            "slug": "VA-069",
            "title": "Resolvable command-run citation",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.test/VA-069",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "e", "impact": "i"},
            "provenance": {
                "agent_id": "HUNT-1",
                "command_run_id": int(run.json()["id"]),
            },
        },
    )

    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["finding"]["provenance"]["command_run_id"] == int(
        run.json()["id"]
    )

    # The maintenance doors resolve it too: a citation that only has to survive
    # the create is a citation a later patch can replace with anything.
    patched = client.patch(
        f"{BASE}/findings/VA-069",
        json={"provenance": {"command_run_id": 99999}},
    )
    assert patched.status_code == 400, patched.text
    relocated = client.put(
        f"{BASE}/findings/VA-069/canonical-location",
        json={
            "canonical_location": "https://example.test/VA-069/moved",
            "reason_text": "Runtime proof relocated the defect server-side.",
            "source_name": "operator",
            "expected_row_version": 1,
            "provenance": {"command_run_id": 99999},
        },
    )
    assert relocated.status_code == 400, relocated.text
    stored = client.get(f"{BASE}/findings/VA-069").json()
    assert stored["provenance"]["command_run_id"] == int(run.json()["id"])
    assert stored["canonical_location"] == "https://example.test/VA-069"


def test_a_dispatch_verified_verdict_supersedes_an_earlier_operator_stamp(
    client, isolate_settings
) -> None:
    """A stale stamp would read as though the CURRENT verdict were operator-granted."""
    _seed(client, isolate_settings)
    _finding(client, "VA-054")
    intel_id = _intel_note(client, "Acme deployment config for VA-054")
    stamp = _operator_authority_verdict("VA-054", intel_id)["operator_authority"]
    receipt = _receipt(client, "VERIFY-1", "after-operator", finding_slug="VA-054")

    confirmed = client.post(
        f"{BASE}/findings/VA-054/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "The verifier reproduced it after all.",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )

    assert confirmed.status_code == 200, confirmed.text
    provenance = confirmed.json()["finding"]["provenance"]
    assert "operator_authority" not in provenance
    assert provenance["superseded_operator_authority"] == stamp
    audit = client.get(f"{BASE}/findings/VA-054").json()["verification_audit"]
    assert audit["operator_authority"] is None


def test_the_verify_route_records_an_operator_authority_verdict(
    client, isolate_settings
) -> None:
    """End to end: the operator holds no dispatch and still records the correction."""
    _seed(client, isolate_settings)
    _finding(client, "VA-055", severity="high")
    intel_id = _intel_note(client, "Acme deployment config disables the route for VA-055")

    response = client.post(
        f"{BASE}/findings/VA-055/verify",
        json={
            "verification_status": "downgraded",
            "reason_text": _OPERATOR_REASON,
            "new_severity": "low",
            "source_name": "operator",
            "operator_authority": True,
            "operator_authority_intel_id": intel_id,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding"]["verification_status"] == "downgraded"
    assert body["finding"]["severity"] == "low"
    assert body["operator_authority"]["intel_id"] == intel_id
    assert body["proof_receipts"] == []


def test_the_exploit_candidate_rows_carry_the_authority_behind_each_verdict(
    client, isolate_settings
) -> None:
    """``candidate_reason`` reads ``verified_<severity>`` either way.

    The approval gate authorizes live exploitation off these rows, so a verdict
    the operator reached on their own out-of-snapshot evidence has to arrive
    marked. The band stays at or above ``medium`` on purpose: a candidate
    downgraded below it leaves the queue entirely, and a stamp asserted over a
    finding that is not in the queue asserts nothing.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-059", severity="critical")
    _finding(client, "VA-060", severity="high")
    intel_id = _intel_note(client, "Acme deployment config narrows VA-059 to high")
    attested = _operator_authority_verdict("VA-059", intel_id, new_severity="high")
    receipt = _receipt(client, "VERIFY-1", "candidate-receipt", finding_slug="VA-060")
    proven = client.post(
        f"{BASE}/findings/VA-060/verify",
        json={
            "verification_status": "confirmed",
            "reason_text": "The verifier reproduced it.",
            "proof_receipt_ids": [receipt["id"]],
            "confirm_check": completed_confirm_check(receipt["id"]),
        },
    )
    assert proven.status_code == 200, proven.text

    candidates = client.get(f"{BASE}/exploit-candidates")
    assert candidates.status_code == 200, candidates.text
    rows = {str(row["slug"]): row for row in candidates.json()}

    assert rows["VA-059"]["candidate_reason"] == "verified_high"
    assert rows["VA-060"]["candidate_reason"] == "verified_high"
    # Same reason string, and only the stamp tells the two verdicts apart.
    assert (
        rows["VA-059"]["operator_authority"]
        == attested["finding"]["provenance"]["operator_authority"]
    )
    assert rows["VA-059"]["operator_authority"]["intel_id"] == intel_id
    assert rows["VA-059"]["operator_authority"]["reason"] == _OPERATOR_REASON
    # Delivered on every candidate, so None reads as "receipt-backed" rather
    # than "this projection does not carry it".
    assert rows["VA-060"]["operator_authority"] is None


def test_a_false_positive_verdict_may_re_band_as_it_kills(client, isolate_settings) -> None:
    """A kill that re-bands records both in one attested write.

    `finding update --severity` on a killed finding is refused outright (the
    change policy keeps a killed finding killed), so without this the band a
    refuted `critical` finding is left at cannot be corrected at all.
    """
    _seed(client, isolate_settings)
    _finding(client, "VA-043", severity="critical")
    receipt = _receipt(client, "VERIFY-1", "kill-reband", finding_slug="VA-043")

    response = client.post(
        f"{BASE}/findings/VA-043/verify",
        json={
            "verification_status": "false_positive",
            "reason_text": "The guard dominates every path; the claim does not hold.",
            "new_severity": "info",
            "details": {
                "kill_reason": "The authorization guard dominates the data read.",
                "kill_check": 4,
            },
            "proof_receipt_ids": [receipt["id"]],
            "counter_check": {
                "method": "Re-walked every path into the data read.",
                "expected_result": "a path reaches the read without the guard",
                "observed_result": "every path passes the guard first",
                "falsified_claim": "an unguarded path reaches the protected read",
                "completed": True,
                "proof_receipt_ids": [receipt["id"]],
            },
        },
    )

    assert response.status_code == 200, response.text
    finding = response.json()["finding"]
    assert finding["verification_status"] == "false_positive"
    assert finding["severity"] == "info"
