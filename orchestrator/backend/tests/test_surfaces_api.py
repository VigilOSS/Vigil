"""Tests for the surface PATCH-by-id endpoint and its CLI helper.

Covers ``PATCH /engagements/{key}/assessment/surfaces/{id}`` and the
``state_manager.update_surface`` helper. The tests exercise:

- Valid lifecycle transitions (``discovered`` → ``covered`` /
  ``not_applicable`` / ``deferred``).
- Rationale appending so the audit trail accumulates context across
  successive resolutions.
- 404 on unknown surface ids and 400 on payloads with no effective
  changes or invalid status values.
"""
from __future__ import annotations

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120100-surfaces"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _create_surface(client) -> dict:
    payload = {
        "surface_type": "object_reference",
        "target_descriptor": "https://example.test/api/users/{id}",
        "source_name": "surface-collector",
        "rationale": "GET handler with numeric id parameter",
        "evidence_ref": "scans/katana.txt:14",
    }
    response = client.post(f"{ASSESSMENT_BASE}/surfaces", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_patch_surface_resolves_to_covered_with_rationale(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]
    assert created["status"] == "discovered"

    patched = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "covered",
            "rationale": "vulnerability-analyst confirmed coverage on parameter id",
        },
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["id"] == surface_id
    assert body["status"] == "covered"
    assert "vulnerability-analyst confirmed" in body["rationale"]
    # Original rationale is retained because update_surface appends.
    assert "GET handler with numeric id parameter" in body["rationale"]


def test_patch_surface_rejects_unknown_id(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/9999",
        json={"status": "covered", "rationale": "nope"},
    )
    assert response.status_code == 404, response.text


def test_patch_surface_rejects_empty_payload(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={},
    )
    assert response.status_code == 400, response.text


def test_patch_surface_rejects_invalid_status(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "bogus"},
    )
    # Pydantic Literal rejects upstream, returning 422.
    assert response.status_code == 422, response.text


def test_patch_surface_supports_deferred_and_not_applicable(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    deferred = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "deferred", "rationale": "low-signal cluster, revisit"},
    )
    assert deferred.status_code == 200
    assert deferred.json()["status"] == "deferred"

    not_applicable = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "not_applicable",
            "rationale": "no input vector after retest",
        },
    )
    assert not_applicable.status_code == 200
    final_body = not_applicable.json()
    assert final_body["status"] == "not_applicable"
    # All three rationales accumulate in the audit trail.
    assert "GET handler" in final_body["rationale"]
    assert "low-signal cluster" in final_body["rationale"]
    assert "no input vector after retest" in final_body["rationale"]


def test_patch_surface_rejects_empty_source_name(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"source_name": ""},
    )
    # Pydantic min_length=1 rejects upstream with 422.
    assert response.status_code == 422, response.text


def test_patch_surface_rejects_empty_evidence_ref(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"evidence_ref": ""},
    )
    assert response.status_code == 422, response.text


def test_patch_surface_blocks_regression_to_discovered_from_covered(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    covered = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered", "rationale": "vulnerability-analyst confirmed"},
    )
    assert covered.status_code == 200

    regress = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "discovered", "rationale": "operator changed mind"},
    )
    assert regress.status_code == 409, regress.text
    assert "discovered" in regress.json()["detail"]


def test_patch_surface_blocks_regression_to_discovered_from_not_applicable(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    na = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "not_applicable", "rationale": "no input vector"},
    )
    assert na.status_code == 200

    regress = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "discovered", "rationale": "re-found"},
    )
    assert regress.status_code == 409, regress.text


def test_patch_surface_allows_not_applicable_to_covered(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    na = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "not_applicable", "rationale": "looked irrelevant"},
    )
    assert na.status_code == 200

    promote = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered", "rationale": "actually relevant on retest"},
    )
    assert promote.status_code == 200, promote.text
    assert promote.json()["status"] == "covered"


def test_patch_surface_allows_deferred_to_anything(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    deferred = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "deferred", "rationale": "park it"},
    )
    assert deferred.status_code == 200

    rediscovered = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "discovered", "rationale": "back on the queue"},
    )
    assert rediscovered.status_code == 200, rediscovered.text


def test_patch_surface_requires_rationale_when_changing_status(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered"},
    )
    assert response.status_code == 400, response.text
    assert "rationale" in response.json()["detail"].lower()


def test_patch_surface_requires_non_blank_rationale_when_changing_status(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered", "rationale": "   "},
    )
    assert response.status_code == 400, response.text


def test_patch_surface_dedups_rationale_substring(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    first = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "covered",
            "rationale": "vulnerability-analyst confirmed coverage on parameter id",
        },
    )
    assert first.status_code == 200
    rationale_after_first = first.json()["rationale"]

    # Submit a substring of the just-appended rationale: should NOT
    # double-append.
    retry = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"rationale": "vulnerability-analyst confirmed"},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["rationale"] == rationale_after_first


def test_patch_surface_allows_rationale_only_update_when_status_unchanged(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"rationale": "extra audit note appended later"},
    )
    assert response.status_code == 200, response.text
    assert "extra audit note" in response.json()["rationale"]


# ──────────────────────────────────────────────────────────────
# N7 — partially-covered transitions
# ──────────────────────────────────────────────────────────────


def test_patch_surface_resolves_to_partially_covered_with_followup(client, isolate_settings):
    """N7 — discovered → partially-covered with rationale + followup_condition lands the
    new lifecycle state and persists the follow-up condition."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "unauth path tested; admin path still pending auth",
            "followup_condition": "needs auth re-test once credentials are issued",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "partially-covered"
    assert body["followup_condition"] == "needs auth re-test once credentials are issued"


def test_patch_surface_partially_covered_requires_followup_condition(client, isolate_settings):
    """N7 — backend rejects partially-covered without followup_condition."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "partial coverage but no follow-up named",
        },
    )
    assert response.status_code == 400, response.text
    assert "followup_condition" in response.json()["detail"]


def test_patch_surface_promotes_partially_covered_to_covered_clears_followup(
    client, isolate_settings
):
    """N7 — partially-covered → covered clears followup_condition."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    intermediate = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "unauth path tested",
            "followup_condition": "needs auth re-test",
        },
    )
    assert intermediate.status_code == 200
    assert intermediate.json()["followup_condition"] == "needs auth re-test"

    promote = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered", "rationale": "auth re-test confirmed coverage"},
    )
    assert promote.status_code == 200, promote.text
    final_body = promote.json()
    assert final_body["status"] == "covered"
    assert final_body["followup_condition"] == ""


def test_patch_surface_partially_covered_to_deferred(client, isolate_settings):
    """N7 — partially-covered → deferred is allowed (de-prioritize the follow-up)."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "auth path stalled",
            "followup_condition": "credentials never issued",
        },
    )
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "deferred", "rationale": "park until next engagement"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "deferred"


def test_patch_surface_covered_to_partially_covered_allowed(client, isolate_settings):
    """N7 — covered → partially-covered is regression-with-purpose; allowed when a
    follow-up is required (e.g., regression after deploy invalidated the prior coverage)."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "covered", "rationale": "vulnerability-analyst confirmed"},
    )
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "deploy invalidated prior coverage",
            "followup_condition": "re-test after deploy stabilizes",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "partially-covered"
    assert body["followup_condition"] == "re-test after deploy stabilizes"


def test_patch_surface_partially_covered_to_discovered_blocked(client, isolate_settings):
    """N7 — partially-covered → discovered is blocked (audit context loss)."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "auth path pending",
            "followup_condition": "needs creds",
        },
    )
    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={"status": "discovered", "rationale": "regress to undecided"},
    )
    assert response.status_code == 409, response.text
