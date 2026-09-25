from __future__ import annotations

import json

from app import db as db_module

from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation
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
