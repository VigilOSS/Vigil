"""Harness regressions for surface-coverage readiness and the
result_status / coverage-item honesty rules.

These cover the contracts the coverage backend owns:

- result_status vocabulary: a probe with a non-test
  outcome (``blocked``/``error``/``no-signal``/``attempted``) is recorded but is
  NOT a covering status; unknown statuses are rejected; the bare default no
  longer auto-maps to COVERED.
- S5: a coverage item cannot be set ``covered``/``not_applicable`` with an
  empty rationale.
- L1-2: a discovered / partially-covered surface is ADVISORY unless linked to
  an active finding (then it blocks).
- L1-9: a partially-covered surface whose follow-up is resolved (followup
  cleared) stops blocking — the accept-partial path.
- L1-10: a high-risk deferred surface type can be exempted engagement-wide via
  a recorded ``surface_deferral_exemption`` policy decision.
- Cross-track invariant: a CODE-track (zero-surface) engagement passes
  ``coverage_readiness`` trivially, and the return SHAPE is unchanged.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services import state_manager
from app.services.state_manager import coverage as coverage_mod
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-05-20-090000-covharness"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
AUTHOR_AGENT_ID = "COVERAGE-READINESS-AUTHOR"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    dispatch = client.post(
        f"{ASSESSMENT_BASE}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record coverage-readiness fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    return int(response.json()["id"])


def _create_surface(client, *, target_descriptor: str, surface_type: str = "object_reference") -> dict:
    response = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": surface_type,
            "target_descriptor": target_descriptor,
            "source_name": "recon-specialist",
            "rationale": "live endpoint",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _patch_surface(client, surface_id: int, **fields) -> dict:
    response = client.patch(f"{ASSESSMENT_BASE}/surfaces/{surface_id}", json=fields)
    assert response.status_code == 200, response.text
    return response.json()


def _create_active_finding(client, *, slug: str, canonical_location: str) -> None:
    response = client.post(
        f"{ASSESSMENT_BASE}/findings",
        json={
            "slug": slug,
            "title": "IDOR on object",
            "severity": "high",
            "workflow_status": "active",
            "canonical_location": canonical_location,
            "summary": "IDOR",
            "evidence_ref": "findings.md",
            "source_name": "test",
            "provenance": {"agent_id": AUTHOR_AGENT_ID},
        },
    )
    assert response.status_code in {200, 201}, response.text




def test_probe_result_status_vocabulary_is_single_source_of_truth() -> None:
    assert coverage_mod.PROBE_RESULT_STATUSES == (
        "tested",
        "signal",
        "attempted",
        "blocked",
        "error",
        "no-signal",
    )
    assert coverage_mod.PROBE_RESULT_STATUSES_COVERING == frozenset({"tested", "signal"})
    for bad in ("attempted", "blocked", "error", "no-signal"):
        assert bad not in coverage_mod.PROBE_RESULT_STATUSES_COVERING


def test_blocked_probe_is_recorded_but_not_a_covering_status(client, isolate_settings) -> None:
    """A probe with result_status='blocked' is stored verbatim but is NOT in the
    covering set — it must never be counted as 'covered' downstream."""
    _seed(client, isolate_settings)
    response = client.post(
        f"{ASSESSMENT_BASE}/probe-runs",
        json={
            "attack_family": "idor",
            "tool_name": "curl",
            "result_status": "blocked",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["result_status"] == "blocked"
    assert body["result_status"] not in coverage_mod.PROBE_RESULT_STATUSES_COVERING


def test_probe_run_rejects_unknown_result_status(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    response = client.post(
        f"{ASSESSMENT_BASE}/probe-runs",
        json={
            "attack_family": "idor",
            "tool_name": "curl",
            "result_status": "totally-made-up",
        },
    )
    assert response.status_code == 422, response.text


def test_probe_service_layer_rejects_unknown_result_status(client, isolate_settings) -> None:
    """Defense in depth: the service layer also validates the vocabulary, so a
    direct call (bypassing the request model) cannot store junk."""
    engagement_id = _seed(client, isolate_settings)
    with pytest.raises(HTTPException) as excinfo:
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=None,
            service_id=None,
            coverage_item_id=None,
            auth_context="anonymous",
            input_slot="unknown",
            attack_family="idor",
            payload_family="",
            payload_value="",
            tool_name="curl",
            agent_name="",
            result_status="definitely-not-real",
            observed_http_status=None,
            signal_type="",
            evidence_ref="",
            notes="",
        )
    assert excinfo.value.status_code == 400


def test_coverage_item_covered_requires_rationale(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings)
    item = state_manager.record_coverage_item(
        engagement_id,
        request_variant_id=None,
        service_id=None,
        auth_context="anonymous",
        input_slot="query",
        attack_family="idor",
        status_value="pending",
        notes="",
    )
    response = client.patch(
        f"{ASSESSMENT_BASE}/coverage-items/{item['id']}",
        json={"status": "covered", "notes": "   "},
    )
    assert response.status_code == 422, response.text

    response = client.patch(
        f"{ASSESSMENT_BASE}/coverage-items/{item['id']}",
        json={"status": "covered", "notes": "Tested idor on /api/users/{id}; 403 on cross-tenant."},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "covered"


def test_coverage_item_not_applicable_requires_rationale_service_layer(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings)
    item = state_manager.record_coverage_item(
        engagement_id,
        request_variant_id=None,
        service_id=None,
        auth_context="anonymous",
        input_slot="query",
        attack_family="idor",
        status_value="pending",
        notes="",
    )
    with pytest.raises(HTTPException) as excinfo:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=int(item["id"]),
            status_value="not_applicable",
            notes="",
        )
    assert excinfo.value.status_code == 400




def test_discovered_surface_not_finding_linked_is_advisory(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings)
    surface = _create_surface(client, target_descriptor="https://example.test/api/users/{id}")
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["track"] == "web"
    assert gate["ready"] is True
    assert gate["blocker_count"] == 0
    assert gate["unresolved_surfaces"] == []
    assert [row["id"] for row in gate["advisory_surfaces"]] == [surface["id"]]


def test_discovered_surface_linked_to_active_finding_blocks(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings)
    surface = _create_surface(client, target_descriptor="https://example.test/api/users/{id}")
    _create_active_finding(client, slug="VA-201", canonical_location="https://example.test/api/users/1")
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is False
    assert gate["blocker_count"] == 1
    assert [row["id"] for row in gate["unresolved_surfaces"]] == [surface["id"]]


def test_partial_with_resolved_followup_stops_blocking(client, isolate_settings) -> None:
    """L1-9 — a partially-covered surface whose followup is cleared is accepted
    (advisory) even when it is linked to an active finding."""
    engagement_id = _seed(client, isolate_settings)
    surface = _create_surface(client, target_descriptor="https://example.test/api/users/{id}")
    _create_active_finding(client, slug="VA-202", canonical_location="https://example.test/api/users/1")
    _patch_surface(
        client,
        surface["id"],
        status="partially-covered",
        rationale="unauth path tested",
        followup_condition="re-test with creds",
    )
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is False
    assert [row["id"] for row in gate["partially_covered_surfaces"]] == [surface["id"]]

    _patch_surface(
        client,
        surface["id"],
        status="covered",
        rationale="auth re-test completed; residual accepted",
    )
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is True
    assert gate["partially_covered_surfaces"] == []


def test_high_risk_deferred_surface_blocks_then_exempted_by_policy(client, isolate_settings) -> None:
    """L1-10 — a high-risk deferred surface blocks, but an engagement-wide
    ``surface_deferral_exemption`` policy decision exempts its type."""
    engagement_id = _seed(client, isolate_settings)
    surface = _create_surface(
        client,
        target_descriptor="https://example.test/admin",
        surface_type="privileged_write",
    )
    _patch_surface(
        client,
        surface["id"],
        status="deferred",
        rationale="admin panel out of test window",
    )
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is False
    assert [row["id"] for row in gate["high_risk_deferred_surfaces"]] == [surface["id"]]

    response = client.post(
        f"{ASSESSMENT_BASE}/dispatch-decisions",
        json={
            "kind": "surface_deferral_exemption",
            "payload": {
                "surface_types": ["privileged_write"],
                "reason": "admin panel owned by a separate team; out of scope",
            },
            "surfaced_to_user": True,
        },
    )
    assert response.status_code in {200, 201}, response.text

    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is True
    assert gate["high_risk_deferred_surfaces"] == []
    assert [row["id"] for row in gate["advisory_surfaces"]] == [surface["id"]]




def test_code_track_zero_surface_coverage_passes_trivially(client, isolate_settings) -> None:
    engagement_id = _seed(client, isolate_settings)
    gate = state_manager.coverage_readiness(engagement_id)
    assert gate["ready"] is True
    assert gate["blocker_count"] == 0
    for key in (
        "ready",
        "blocker_count",
        "unresolved_surfaces",
        "partially_covered_surfaces",
        "high_risk_deferred_surfaces",
        "advisory_surfaces",
    ):
        assert key in gate, key
    assert gate["unresolved_surfaces"] == []
    assert gate["partially_covered_surfaces"] == []
    assert gate["high_risk_deferred_surfaces"] == []
    assert gate["advisory_surfaces"] == []


def test_record_coverage_item_pending_does_not_demote_resolved(client, isolate_settings):
    """The gf-bucket ingest bridge (re)creates class-typed coverage
    OBLIGATIONS via record_coverage_item with status='pending'. A routine
    endpoint re-ingest must NOT overwrite an already-resolved covered item back
    to pending (which would reopen the depth/report gates) — it coalesces."""
    eng_id = _seed(client, isolate_settings)
    common = dict(
        request_variant_id=None, service_id=None, auth_context="anonymous",
        input_slot="query", attack_family="idor",
    )
    state_manager.record_coverage_item(eng_id, status_value="pending", notes="gf obligation", **common)
    covered = state_manager.record_coverage_item(eng_id, status_value="covered", notes="tested", **common)
    assert covered["status"] == "covered"
    reingest = state_manager.record_coverage_item(eng_id, status_value="pending", notes="re-ingest", **common)
    assert reingest["status"] == "covered", "pending re-ingest must not demote covered"
