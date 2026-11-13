"""Decision readers outside the decision service skip superseded rows.

Each case writes a row, supersedes it with a row that names a different
subject, and asserts the reader no longer sees the superseded subject. The
superseded row is stamped directly so the case does not depend on the
kind-specific recording validators.
"""
from __future__ import annotations

import importlib
import json

import pytest
from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-11-14-120000-supersede-readers"


@pytest.fixture
def engagement_id(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _superseded_pair(engagement_id: int, kind: str, old: dict, new: dict) -> tuple[int, int]:
    with state_manager.get_connection() as connection:
        ids = []
        for payload in (old, new):
            cursor = connection.execute(
                "INSERT INTO assessment_dispatch_decisions (engagement_id, kind, payload_json, "
                "surfaced_to_user, resolved, created_at) VALUES (?, ?, ?, 1, 0, "
                "strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
                (engagement_id, kind, json.dumps(payload)),
            )
            ids.append(int(cursor.lastrowid))
        connection.execute(
            "UPDATE assessment_dispatch_decisions SET supersedes_id = ? WHERE id = ?",
            (ids[0], ids[1]),
        )
        connection.execute(
            "UPDATE assessment_dispatch_decisions SET superseded_by_id = ?, "
            "superseded_at = 'now' WHERE id = ?",
            (ids[1], ids[0]),
        )
    return ids[0], ids[1]


def test_depth_ledger_skips_superseded_depth_deferrals(engagement_id):
    depth_ledger = importlib.import_module("app.services.state_manager.depth_ledger")
    _superseded_pair(
        engagement_id,
        "depth_deferral",
        {"host": "old.example.com", "vuln_classes": ["xss"], "reason": "x"},
        {"host": "new.example.com", "vuln_classes": ["xss"], "reason": "corrected"},
    )
    rows = depth_ledger._active_depth_deferrals(engagement_id)
    assert [row["payload"]["host"] for row in rows] == ["new.example.com"]


def test_vendor_saas_scope_decision_reader_skips_superseded_rows(engagement_id):
    state_manager.record_service(
        engagement_id, endpoint="acme.my.salesforce.com", protocol="tcp", port=None,
        service="", state="up", coverage_status="pending", banner="", notes="",
        discovered_by="test", target_identity=None,
    )
    _superseded_pair(
        engagement_id,
        "scope_decision",
        {"host": "acme.my.salesforce.com", "choice": "in_scope"},
        {"host": "other.my.salesforce.com", "choice": "in_scope"},
    )
    pending = state_manager.vendor_saas_hosts_pending_decision(engagement_id)
    assert [row["host"] for row in pending] == ["acme.my.salesforce.com"]


def test_egress_status_skips_a_superseded_connectivity_check(engagement_id):
    old, _ = _superseded_pair(
        engagement_id,
        "egress_decision",
        {"subtype": "connectivity_check", "blocked_pct": 90, "sampled": 10},
        {"subtype": "other", "note": "corrected: the sample was mis-scoped"},
    )
    assert state_manager.egress_block_status(engagement_id)["blocked_pct"] == 0


def test_packet_review_reader_skips_superseded_verdicts(engagement_id):
    submission_versions = importlib.import_module("app.services.submission_versions")
    _superseded_pair(
        engagement_id,
        "blind_triage_verdict",
        {"finding_slug": "VA-001", "verdict": "Accept@P2"},
        {"finding_slug": "VA-002", "verdict": "Accept@P2"},
    )
    assert submission_versions._latest_decision(engagement_id, "blind_triage_verdict", "VA-001") is None


def _stamp_superseded(old_id: int, new_id: int) -> None:
    with state_manager.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_dispatch_decisions SET supersedes_id = ? WHERE id = ?",
            (old_id, new_id),
        )
        connection.execute(
            "UPDATE assessment_dispatch_decisions SET superseded_by_id = ?, "
            "superseded_at = 'now' WHERE id = ?",
            (new_id, old_id),
        )


def _raw_decision(engagement_id: int, kind: str, payload: dict, created_at: str) -> int:
    with state_manager.get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO assessment_dispatch_decisions (engagement_id, kind, payload_json, "
            "surfaced_to_user, resolved, created_at) VALUES (?, ?, ?, 1, 0, ?)",
            (engagement_id, kind, json.dumps(payload), created_at),
        )
        return int(cursor.lastrowid)


# -- claim_equivalence -------------------------------------------------------


def _pending_claim_edit(client, isolate_settings, slug: str) -> dict:
    from tests.test_claim_equivalence_editor_independence import _edit
    from tests.test_finding_change_policy import _audit, _confirmed

    finding = _confirmed(client, isolate_settings, slug)  # authored by HUNT-A, proven by VERIFY-B
    _edit(client, slug, "A clearer statement of the same Acme bypass.")
    audit = _audit(client, slug)
    assert audit["claim_review_pending"] is True
    return {"engagement_id": int(finding["engagement_id"]), **audit}


def _claim_payload(slug: str, audit: dict, verdict: str) -> dict:
    return {
        "finding_slug": slug, "verdict": verdict,
        "claim_transition_id": audit["claim_transition_id"],
        "new_claim_sha256": audit["current_claim_sha256"],
        "verifier_dispatch_agent_id": "VERIFY-B",
        "reason": "Same boundary, action and observed outcome.",
    }


def test_a_superseded_equivalent_verdict_no_longer_clears_the_claim_review(
    client, isolate_settings
):
    from tests.test_finding_change_policy import _audit, _blocker_kinds
    from tests.test_verification_status_contract import BASE

    audit = _pending_claim_edit(client, isolate_settings, "VA-940")
    equivalent = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": _claim_payload("VA-940", audit, "equivalent")})
    assert equivalent.status_code == 201, equivalent.text
    assert _audit(client, "VA-940")["claim_review_pending"] is False

    replacement = _raw_decision(
        audit["engagement_id"], "claim_equivalence",
        {"finding_slug": "VA-999", "verdict": "equivalent"}, "2026-11-14T12:00:00.000Z",
    )
    _stamp_superseded(int(equivalent.json()["id"]), replacement)

    assert _audit(client, "VA-940")["claim_review_pending"] is True
    assert "finding_claim_review_pending" in _blocker_kinds(client, "VA-940")


def test_the_superseding_claim_verdict_is_the_one_read(client, isolate_settings):
    from tests.test_finding_change_policy import _audit
    from tests.test_verification_status_contract import BASE

    audit = _pending_claim_edit(client, isolate_settings, "VA-941")
    equivalent = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": _claim_payload("VA-941", audit, "equivalent")})
    assert equivalent.status_code == 201, equivalent.text
    changed = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "supersedes": equivalent.json()["id"],
        "payload": _claim_payload("VA-941", audit, "changed")})
    assert changed.status_code == 201, changed.text

    assert _audit(client, "VA-941")["claim_review_pending"] is True
    # The changed verdict is current: equivalence now needs a new claim edit.
    again = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "claim_equivalence", "payload": _claim_payload("VA-941", audit, "equivalent")})
    assert again.status_code == 409, again.text


# -- report_qc_verdict -------------------------------------------------------


def _registered_report(client, isolate_settings) -> dict:
    from tests.test_submission_qc_verdict import _register_report
    from tests.test_submission_versions_api import _seed_reportable_finding

    _seed_reportable_finding(client, isolate_settings)
    return _register_report(client, isolate_settings)


def _report_qc(client) -> dict:
    from tests.test_submission_qc_verdict import BASE

    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    return response.json()["report_qc"]


def test_a_superseded_passing_report_qc_verdict_does_not_satisfy_the_gate(
    client, isolate_settings
):
    from tests.test_submission_qc_verdict import _record, _report_payload

    artifact = _registered_report(client, isolate_settings)
    passed = _record(client, "report_qc_verdict", _report_payload(client, artifact))
    assert passed.status_code == 201, passed.text
    assert _report_qc(client)["status"] == "current"

    # The superseding row carries an earlier timestamp, so a reader that ordered
    # without the currency predicate would still pick the superseded pass.
    blocked = _raw_decision(
        int(artifact["engagement_id"]), "report_qc_verdict",
        _report_payload(client, artifact, verdict="blocked",
                        failed_rows=[{"row": "Executive summary", "quote": "TBD"}]),
        "2000-01-01T00:00:00.000Z",
    )
    _stamp_superseded(int(passed.json()["id"]), blocked)

    state = _report_qc(client)
    assert state["status"] == "blocked", state
    assert state["decision_id"] == blocked


def test_the_superseding_report_qc_verdict_is_the_one_read(client, isolate_settings):
    from tests.test_submission_qc_verdict import BASE, _record, _report_payload

    artifact = _registered_report(client, isolate_settings)
    blocked = _record(client, "report_qc_verdict", _report_payload(
        client, artifact, verdict="blocked",
        failed_rows=[{"row": "Executive summary", "quote": "TBD"}]))
    assert blocked.status_code == 201, blocked.text
    passed = client.post(f"{BASE}/dispatch-decisions", json={
        "kind": "report_qc_verdict", "supersedes": blocked.json()["id"],
        "payload": _report_payload(client, artifact)})
    assert passed.status_code == 201, passed.text

    state = _report_qc(client)
    assert state["status"] == "current", state
    assert state["decision_id"] == passed.json()["id"]
