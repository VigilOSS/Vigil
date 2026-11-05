"""Every write to a verified finding resolves its verdict through one change policy.

Cosmetic edits keep the verdict, claim wording raises an independent claim review,
and technical changes invalidate it. The same change has the same effect whether it
arrives through a patch, a re-record, a merge, a relocation or a relationship write.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from tests.proof_fixtures import post_artifact_backed_source_observation
from tests.test_verification_status_contract import (
    BASE,
    _finding_payload,
    _seed,
    _verify_with_proof,
)

# Each vector computes exactly the paired score; the write-time pair check rejects
# any fixture that does not.
_BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 8.2 high
_RUNTIME_PLAN = {
    "hypothesis": "GET /orders/{id} returns another tenant's order.",
    "confirm_if": "Tenant B receives tenant A's order.",
    "falsify_if": "Tenant B receives 403.",
    "route_hint": "live",
}


def _record(client, slug: str, **overrides):
    response = client.post(f"{BASE}/findings", json=_finding_payload(slug, **overrides))
    assert response.status_code == 201, response.text
    return response.json()["finding"]


def _confirmed(client, isolate_settings, slug: str, status: str = "confirmed", **overrides):
    _seed(client, isolate_settings)
    _record(client, slug, **overrides)
    verified = _verify_with_proof(client, slug, status)
    assert verified.status_code == 200, verified.text
    return verified.json()["finding"]


def _receipt(client, slug: str, tag: str) -> int:
    run = client.post(
        f"{BASE}/assessment-runs",
        json={"run_uuid": f"change-policy-{slug}-{tag}", "run_kind": "shared",
              "producer_dispatch_agent_id": "VERIFY-B"},
    )
    assert run.status_code == 201, run.text
    linked = client.post(
        f"{BASE}/findings/{slug}/links",
        json={"link_kind": "proof_run", "target_kind": "assessment_run",
              "target_id": run.json()["id"]},
    )
    assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{BASE}/proof-receipts",
        json={"run_id": run.json()["id"], "evidence_kind": "source_observation",
              "expected_result": "the guard holds", "observed_result": "the guard holds"},
    )
    assert receipt.status_code == 201, receipt.text
    finished = client.patch(
        f"{BASE}/assessment-runs/{run.json()['id']}", json={"status": "completed"}
    )
    assert finished.status_code == 200, finished.text
    return int(receipt.json()["id"])


def _put_in_status(client, slug: str, status: str) -> None:
    if status in {"confirmed", "downgraded"}:
        response = _verify_with_proof(client, slug, status)
    elif status == "false_positive":
        receipt_id = _receipt(client, slug, "kill")
        response = client.post(f"{BASE}/findings/{slug}/verify", json={
            "verification_status": "false_positive",
            "reason_text": "the tenant guard dominates every path",
            "details": {"kill_reason": "The tenant guard dominates every path.", "kill_check": 1},
            "counter_check": {
                "method": "authorization-dominance source proof",
                "expected_result": "an unguarded path reaches the read",
                "observed_result": "every path is dominated by the tenant guard",
                "falsified_claim": "a path bypasses tenant authorization",
                "completed": True,
                "proof_receipt_ids": [receipt_id],
            },
        })
    elif status == "pending_runtime_proof":
        response = client.post(f"{BASE}/findings/{slug}/verify", json={
            "verification_status": status, "reason_text": "source accepted",
            "next_test": _RUNTIME_PLAN,
        })
    elif status == "blocked":
        response = client.post(f"{BASE}/findings/{slug}/verify", json={
            "verification_status": status, "reason_text": "no second tenant",
            "details": {"block_reason": "A second Acme tenant account is required."},
        })
    else:
        assert status == "disputed"
        response = client.post(f"{BASE}/findings/{slug}/verify", json={
            "verification_status": status, "reason_text": "two lanes disagree",
        })
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["verification_status"] == status


def _latest_transition(client, slug: str) -> dict:
    latest = client.get(f"{BASE}/findings/{slug}/transitions").json()[0]
    return client.get(f"{BASE}/findings/{slug}/transitions/{latest['id']}").json()


def _change_policy(transition: dict) -> dict:
    return json.loads(transition["metadata_json"])["change_policy"]


def _audit(client, slug: str) -> dict:
    return client.get(f"{BASE}/findings/{slug}").json()["verification_audit"]


def _blocker_kinds(client, slug: str) -> set[str]:
    readiness = client.get(f"{BASE}/report-readiness").json()
    return {b["kind"] for b in readiness.get("blockers", []) if b.get("slug") == slug}


# --- root-cause relationships ---------------------------------------------------


def test_root_cause_set_retarget_and_clear_keep_a_confirmed_child(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-300")
    for slug in ("VA-301", "VA-302"):
        _record(client, slug)
    base = f"{BASE}/findings/VA-300/root-cause"

    for operation, request in (
        ("set", lambda: client.put(base, json={
            "root_cause_slug": "VA-301", "root_cause_effect": "eliminates_attack_path"})),
        ("retarget", lambda: client.put(base, json={
            "root_cause_slug": "VA-302", "root_cause_effect": "eliminates_attack_path"})),
        ("clear", lambda: client.delete(base)),
    ):
        response = request()
        assert response.status_code == 200, (operation, response.text)
        assert response.json()["verification_effect"] == "keep", operation
        assert response.json()["verification_invalidated"] is False, operation
        assert response.json()["changed_axes"] == ["root_cause_link"], operation
        finding = client.get(f"{BASE}/findings/VA-300").json()
        assert finding["verification_status"] == "confirmed", operation
        assert finding["verification_audit"]["claim_review_pending"] is False, operation
        transition = _latest_transition(client, "VA-300")
        assert transition["action"] == "relationship_recorded", operation
        assert transition["to_verification_status"] == "confirmed", operation
        assert _change_policy(transition)["axes"] == [
            {"axis": "root_cause_link", "effect": "keep"}
        ], operation
        assert json.loads(transition["metadata_json"])["relationship_change"], operation


def test_eliminates_finding_root_cause_requires_claim_review(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-305")
    _record(client, "VA-306")

    linked = client.put(f"{BASE}/findings/VA-305/root-cause", json={
        "root_cause_slug": "VA-306", "root_cause_effect": "eliminates_finding",
    })

    assert linked.status_code == 200, linked.text
    assert linked.json()["verification_effect"] == "claim_review"
    finding = client.get(f"{BASE}/findings/VA-305").json()
    assert finding["verification_status"] == "confirmed"
    assert finding["verification_audit"]["claim_review_pending"] is True
    assert _latest_transition(client, "VA-305")["action"] == "claim_review_pending"
    assert "finding_claim_review_pending" in _blocker_kinds(client, "VA-305")


# --- merge ---------------------------------------------------------------------


@pytest.mark.parametrize("source_workflow", ["reported", "exploited"])
def test_merge_with_progressed_source_keeps_the_target_verdict(
    client, isolate_settings, source_workflow
):
    _confirmed(client, isolate_settings, "VA-310")
    _record(client, "VA-311", workflow_status=source_workflow)

    merged = client.post(f"{BASE}/findings/merge", json={
        "source_slug": "VA-311", "target_slug": "VA-310", "reason": "same defect",
    })

    assert merged.status_code == 200, merged.text
    body = merged.json()
    assert body["target"]["verification_status"] == "confirmed"
    assert body["target"]["workflow_status"] == source_workflow
    assert body["verification_effect"] == "keep"
    assert body["verification_invalidated"] is False
    assert "workflow_status" in body["changed_axes"]
    metadata = json.loads(_latest_transition(client, "VA-310")["metadata_json"])
    assert "workflow_status" in metadata["changed_axes"]
    assert metadata["change_policy"]["effect"] == "keep"


def test_merge_with_stronger_source_summary_requires_claim_review(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-312")
    _record(client, "VA-313", workflow_status="exploited",
            summary="Object authorization is missing on every tenant read.")

    merged = client.post(f"{BASE}/findings/merge", json={
        "source_slug": "VA-313", "target_slug": "VA-312", "reason": "same defect",
    })

    assert merged.status_code == 200, merged.text
    assert merged.json()["verification_effect"] == "claim_review"
    target = client.get(f"{BASE}/findings/VA-312").json()
    assert target["verification_status"] == "confirmed"
    assert target["summary"] == "Object authorization is missing on every tenant read."
    assert target["verification_audit"]["claim_review_pending"] is True


def test_merge_with_higher_source_severity_warns_and_keeps_the_target(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-314", details={
        "evidence": "request transcript", "impact": "data disclosure",
        "cvss_score": 8.2, "cvss_vector": _BASE_VECTOR, "cwe_id": "CWE-639",
    })
    _record(client, "VA-315", severity="critical", details={
        "evidence": "request transcript", "impact": "data disclosure",
        "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-285",
    })

    merged = client.post(f"{BASE}/findings/merge", json={
        "source_slug": "VA-315", "target_slug": "VA-314", "reason": "same defect",
    })

    assert merged.status_code == 200, merged.text
    body = merged.json()
    target = body["target"]
    assert target["verification_status"] == "confirmed"
    assert target["severity"] == "high"
    assert target["details"]["cvss_score"] == 8.2
    assert target["details"]["cvss_vector"] == _BASE_VECTOR
    assert target["details"]["cwe_id"] == "CWE-639"
    warnings = "\n".join(body["warnings"])
    assert "vigil assess finding update VA-314 --severity critical" in warnings
    assert "9.8" in warnings
    assert "CWE-285" in warnings


def test_merge_never_fills_a_technical_detail_the_target_lacks(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-316")
    _record(client, "VA-317", details={
        "evidence": "request transcript", "impact": "data disclosure", "cwe_id": "CWE-639",
    })

    merged = client.post(f"{BASE}/findings/merge", json={
        "source_slug": "VA-317", "target_slug": "VA-316", "reason": "same defect",
    })

    assert merged.status_code == 200, merged.text
    assert "cwe_id" not in merged.json()["target"]["details"]
    assert merged.json()["target"]["verification_status"] == "confirmed"
    assert any("CWE-639" in warning for warning in merged.json()["warnings"])


# --- patch axes ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "vector", "expected_status", "expected_axis"),
    [
        pytest.param(8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
                     "confirmed", "cvss.impact", id="impact-up"),
        pytest.param(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                     "confirmed", "cvss.impact", id="impact-down"),
        pytest.param(7.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                     "unreviewed", "cvss.exploitability", id="privileges-required"),
        pytest.param(7.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                     "unreviewed", "cvss.exploitability", id="user-interaction"),
        pytest.param(7.1, "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                     "unreviewed", "cvss.exploitability", id="attack-vector"),
        pytest.param(9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                     "unreviewed", "cvss.band", id="impact-crosses-band"),
    ],
)
def test_cvss_metric_edits_within_the_band(
    client, isolate_settings, score, vector, expected_status, expected_axis
):
    _confirmed(client, isolate_settings, "VA-320", details={
        "evidence": "request transcript", "impact": "data disclosure",
        "cvss_score": 8.2, "cvss_vector": _BASE_VECTOR,
    })

    patched = client.patch(f"{BASE}/findings/VA-320", json={
        "details": {"cvss_score": score, "cvss_vector": vector},
    })

    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["finding"]["verification_status"] == expected_status
    assert expected_axis in body["changed_axes"]
    expected_effect = "claim_review" if expected_status == "confirmed" else "invalidate"
    assert body["verification_effect"] == expected_effect
    assert body["finding"]["verification_invalidated"] is (expected_status == "unreviewed")
    if expected_status == "confirmed":
        assert _audit(client, "VA-320")["claim_review_pending"] is True


def test_filling_evidence_ref_keeps_the_verdict_and_replacing_it_requires_review(
    client, isolate_settings
):
    _confirmed(client, isolate_settings, "VA-325")

    filled = client.patch(f"{BASE}/findings/VA-325", json={"evidence_ref": "evidence/acme.json"})

    assert filled.status_code == 200, filled.text
    assert filled.json()["verification_effect"] == "keep"
    assert filled.json()["changed_axes"] == ["evidence_ref.fill"]
    assert filled.json()["finding"]["verification_status"] == "confirmed"
    assert _audit(client, "VA-325")["claim_review_pending"] is False

    replaced = client.patch(
        f"{BASE}/findings/VA-325", json={"evidence_ref": "evidence/acme-replay.json"}
    )

    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["verification_effect"] == "claim_review"
    assert replaced.json()["finding"]["verification_status"] == "confirmed"
    assert _audit(client, "VA-325")["claim_review_pending"] is True


def test_title_edit_raises_no_claim_review_blocker(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-326")

    retitled = client.patch(f"{BASE}/findings/VA-326", json={"title": "Acme invoice IDOR"})

    assert retitled.status_code == 200, retitled.text
    assert retitled.json()["verification_effect"] == "keep"
    assert _audit(client, "VA-326")["claim_review_pending"] is False
    assert "finding_claim_review_pending" not in _blocker_kinds(client, "VA-326")
    rerecorded = client.post(
        f"{BASE}/findings", json=_finding_payload("VA-326", title="Acme invoice IDOR again")
    )
    assert rerecorded.status_code == 201, rerecorded.text
    assert _audit(client, "VA-326")["claim_review_pending"] is False


@pytest.mark.parametrize(
    "patch",
    [
        pytest.param({"severity": "critical"}, id="severity"),
        pytest.param({"canonical_location": "https://example.test/VA-330/v2"}, id="location"),
        pytest.param({"details": {"cwe_id": "CWE-285"}}, id="cwe"),
    ],
)
def test_technical_edit_on_a_killed_finding_is_refused(client, isolate_settings, patch):
    _seed(client, isolate_settings)
    _record(client, "VA-330")
    _put_in_status(client, "VA-330", "false_positive")
    before = client.get(f"{BASE}/findings/VA-330").json()

    refused = client.patch(f"{BASE}/findings/VA-330", json=patch)

    assert refused.status_code == 409, refused.text
    assert "reopen" in refused.json()["detail"]
    after = client.get(f"{BASE}/findings/VA-330").json()
    assert after["row_version"] == before["row_version"]
    assert (after["workflow_status"], after["verification_status"]) == (
        "false_positive", "false_positive",
    )


def test_killed_finding_accepts_keep_edits_and_refuses_relocation(client, isolate_settings):
    _seed(client, isolate_settings)
    _record(client, "VA-331")
    _put_in_status(client, "VA-331", "false_positive")

    filled = client.patch(f"{BASE}/findings/VA-331", json={"evidence_ref": "evidence/kill.json"})
    assert filled.status_code == 200, filled.text
    assert (filled.json()["finding"]["workflow_status"],
            filled.json()["finding"]["verification_status"]) == ("false_positive", "false_positive")

    current = client.get(f"{BASE}/findings/VA-331").json()
    relocated = client.put(f"{BASE}/findings/VA-331/canonical-location", json={
        "canonical_location": "https://example.test/elsewhere",
        "reason_text": "moved", "expected_row_version": current["row_version"],
    })
    assert relocated.status_code == 409, relocated.text
    assert "reopen" in relocated.json()["detail"]


@pytest.mark.parametrize("status", ["confirmed", "downgraded"])
def test_reopening_a_verified_finding_to_draft_invalidates_it(client, isolate_settings, status):
    _confirmed(client, isolate_settings, "VA-335", status)

    reopened = client.patch(f"{BASE}/findings/VA-335", json={
        "workflow_status": "draft", "reason_text": "new evidence disproves the verdict",
    })

    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["finding"]["verification_status"] == "unreviewed"
    assert reopened.json()["finding"]["workflow_status"] == "draft"
    assert reopened.json()["finding"]["verification_invalidated"] is True
    assert reopened.json()["verification_effect"] == "invalidate"
    transition = _latest_transition(client, "VA-335")
    assert transition["action"] == "verification_invalidated"
    assert transition["reason_code"] == "finding_reopened"
    assert transition["reason_text"] == "new evidence disproves the verdict"
    assert {"axis": "reopen", "effect": "invalidate"} in _change_policy(transition)["axes"]


@pytest.mark.parametrize(
    ("status", "patch", "effect", "outcome"),
    [
        pytest.param(None, {"severity": "critical"}, "invalidate", "keep", id="unreviewed-severity"),
        pytest.param("blocked", {"summary": "Reworded."}, "claim_review", "keep", id="blocked-summary"),
        pytest.param("confirmed", {"summary": "Reworded."}, "claim_review", "claim_review",
                     id="confirmed-summary"),
        pytest.param("confirmed", {"severity": "critical"}, "invalidate", "invalidate",
                     id="confirmed-severity"),
    ],
)
def test_transition_records_what_the_write_did_to_the_verdict(
    client, isolate_settings, status, patch, effect, outcome
):
    """The audit carries the classified effect and the verdict outcome separately.

    An unreviewed draft has no verdict a severity edit could invalidate, so its
    history must not read as an invalidation; the outcome matches the write
    response's verification_effect.
    """
    _seed(client, isolate_settings)
    _record(client, "VA-336")
    if status is not None:
        _put_in_status(client, "VA-336", status)

    response = client.patch(f"{BASE}/findings/VA-336", json=patch)

    assert response.status_code == 200, response.text
    assert response.json()["verification_effect"] == outcome
    policy = _change_policy(_latest_transition(client, "VA-336"))
    assert (policy["effect"], policy["outcome"]) == (effect, outcome)


# --- one effect everywhere -----------------------------------------------------

_STATUSES = ["confirmed", "downgraded", "pending_runtime_proof", "blocked", "disputed"]


def _matrix_operation(client, operation: str) -> None:
    slug = "VA-340"
    # A re-record re-asserts the stored band; a downgraded finding is no longer high.
    severity = client.get(f"{BASE}/findings/{slug}").json()["severity"]
    if operation == "patch-technical":
        response = client.patch(f"{BASE}/findings/{slug}", json={"auth_context": "member"})
    elif operation == "record-technical":
        response = client.post(f"{BASE}/findings", json=_finding_payload(
            slug, severity=severity, auth_context="member"))
    elif operation == "relocate":
        current = client.get(f"{BASE}/findings/{slug}").json()
        response = client.put(f"{BASE}/findings/{slug}/canonical-location", json={
            "canonical_location": "https://example.test/VA-340/moved",
            "reason_text": "runtime proof moved the boundary",
            "expected_row_version": current["row_version"],
        })
    elif operation == "patch-wording":
        response = client.patch(f"{BASE}/findings/{slug}", json={
            "summary": "Object authorization is missing for invoice reads."})
    elif operation == "record-wording":
        response = client.post(f"{BASE}/findings", json=_finding_payload(
            slug, severity=severity,
            summary="Object authorization is missing for invoice reads."))
    elif operation == "patch-cosmetic":
        response = client.patch(f"{BASE}/findings/{slug}", json={
            "title": "Acme invoice IDOR", "notes": "editorial pass"})
    elif operation == "root-cause":
        _record(client, "VA-341")
        response = client.put(f"{BASE}/findings/{slug}/root-cause", json={
            "root_cause_slug": "VA-341", "root_cause_effect": "eliminates_attack_path"})
    else:
        assert operation == "merge"
        _record(client, "VA-342", workflow_status="reported")
        response = client.post(f"{BASE}/findings/merge", json={
            "source_slug": "VA-342", "target_slug": slug, "reason": "duplicate"})
    assert response.status_code in {200, 201}, (operation, response.text)


@pytest.mark.parametrize("status", _STATUSES)
@pytest.mark.parametrize(
    ("operation", "outcome"),
    [
        ("patch-technical", "invalidate"),
        ("record-technical", "invalidate"),
        ("relocate", "invalidate"),
        ("patch-wording", "claim_review"),
        ("record-wording", "claim_review"),
        ("patch-cosmetic", "keep"),
        ("root-cause", "keep"),
        ("merge", "keep"),
    ],
)
def test_one_effect_for_each_status_and_operation(
    client, isolate_settings, status, operation, outcome
):
    _seed(client, isolate_settings)
    _record(client, "VA-340")
    _put_in_status(client, "VA-340", status)

    _matrix_operation(client, operation)

    finding = client.get(f"{BASE}/findings/VA-340").json()
    expected_status = "unreviewed" if outcome == "invalidate" else status
    assert finding["verification_status"] == expected_status
    review_applies = outcome == "claim_review" and status in {"confirmed", "downgraded"}
    assert finding["verification_audit"]["claim_review_pending"] is review_applies
    transition = _latest_transition(client, "VA-340")
    assert _change_policy(transition)["effect"] == outcome


# --- digest migration ------------------------------------------------------------


def _legacy_claim_sha256(row: dict) -> str:
    """The claim digest every pre-versioned decision and binding recorded."""
    details = {k: v for k, v in row["details"].items() if k != "correction_history"}
    claim = {
        "title": row["title"], "summary": row["summary"], "severity": row["severity"],
        "defect_family": row["defect_family"], "root_cause_key": row["root_cause_key"],
        "auth_context": row["auth_context"], "canonical_location": row["canonical_location"],
        "evidence_ref": row["evidence_ref"] or "", "details": details,
    }
    encoded = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_legacy_equivalence_decision_survives_the_digest_version(client, isolate_settings):
    from app import db

    _confirmed(client, isolate_settings, "VA-350")
    assert client.patch(f"{BASE}/findings/VA-350", json={
        "summary": "Object authorization is missing for Acme invoices."}).status_code == 200
    audit = _audit(client, "VA-350")
    assert audit["claim_review_pending"] is True
    row = client.get(f"{BASE}/findings/VA-350").json()
    legacy = _legacy_claim_sha256(row)
    assert legacy != audit["current_claim_sha256"]
    with db.get_connection() as connection:
        engagement_id = connection.execute(
            "SELECT engagement_id FROM assessment_findings WHERE slug = 'VA-350'"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO assessment_dispatch_decisions (engagement_id, kind, payload_json, created_at) "
            "VALUES (?, 'claim_equivalence', ?, '2026-10-01T00:00:00Z')",
            (engagement_id, json.dumps({
                "finding_slug": "VA-350", "verdict": "equivalent",
                "claim_transition_id": audit["claim_transition_id"],
                "new_claim_sha256": legacy, "verifier_dispatch_agent_id": "VERIFY-B",
                "reason": "same claim",
            })),
        )

    assert _audit(client, "VA-350")["claim_review_pending"] is False
    assert "finding_claim_review_pending" not in _blocker_kinds(client, "VA-350")


def test_new_equivalence_decision_records_its_digest_version(client, isolate_settings):
    _confirmed(client, isolate_settings, "VA-351")
    assert client.patch(f"{BASE}/findings/VA-351", json={
        "summary": "Object authorization is missing for Acme invoices."}).status_code == 200
    audit = _audit(client, "VA-351")
    recorded = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": {
            "finding_slug": "VA-351", "verdict": "equivalent",
            "claim_transition_id": audit["claim_transition_id"],
            "new_claim_sha256": audit["current_claim_sha256"],
            "verifier_dispatch_agent_id": "VERIFY-B", "reason": "same claim",
        },
    })
    assert recorded.status_code == 201, recorded.text
    assert recorded.json()["payload"]["claim_digest_version"] == audit["claim_digest_version"]
    assert _audit(client, "VA-351")["claim_review_pending"] is False

    retitled = client.patch(f"{BASE}/findings/VA-351", json={"title": "Acme invoice IDOR"})
    assert retitled.status_code == 200, retitled.text
    assert _audit(client, "VA-351")["claim_review_pending"] is False


def test_legacy_proof_work_binding_stays_current(client, isolate_settings):
    from app import db

    _seed(client, isolate_settings)
    _record(client, "VA-352")
    _put_in_status(client, "VA-352", "pending_runtime_proof")
    prepared = client.post(f"{BASE}/proof-work", json={
        "finding_slug": "VA-352", "route": "code", "objective": "Replay the Acme read",
        "target_hosts": [],
    })
    assert prepared.status_code in {200, 201}, prepared.text
    work = prepared.json()
    assert work["current"] is True
    row = client.get(f"{BASE}/findings/VA-352").json()
    legacy_binding = {
        key: value for key, value in work["binding"].items() if key != "claim_digest_version"
    }
    legacy_binding["finding_claim_sha256"] = _legacy_claim_sha256(row)
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_proof_work SET binding_json = ? WHERE id = ?",
            (json.dumps(legacy_binding, sort_keys=True, separators=(",", ":")), work["id"]),
        )

    listed = client.get(f"{BASE}/proof-work/{work['id']}").json()
    assert listed["current"] is True
    reprepared = client.post(f"{BASE}/proof-work", json={
        "finding_slug": "VA-352", "route": "code", "objective": "Replay the Acme read",
        "target_hosts": [],
    })
    assert reprepared.status_code in {200, 201}, reprepared.text
    assert reprepared.json()["id"] == work["id"]
