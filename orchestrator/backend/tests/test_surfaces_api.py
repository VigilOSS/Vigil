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
