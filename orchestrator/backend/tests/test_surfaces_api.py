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
OTHER_ENGAGEMENT_KEY = "2026-04-17-120200-surfaces-other"
OTHER_ASSESSMENT_BASE = f"/engagements/{OTHER_ENGAGEMENT_KEY}/assessment"
AUTHOR_AGENT_ID = "SURFACE-FIXTURE-AUTHOR"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    dispatch = client.post(
        f"{ASSESSMENT_BASE}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record surface-linked fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


def _seed_other_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=OTHER_ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{OTHER_ENGAGEMENT_KEY}")
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


def _create_surface_with_descriptor(client, descriptor: str) -> dict:
    payload = {
        "surface_type": "object_reference",
        "target_descriptor": descriptor,
        "source_name": "surface-collector",
        "rationale": "candidate parameter",
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


def test_list_surfaces_is_bounded_and_paginates(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    created = [
        _create_surface_with_descriptor(client, f"https://example.test/api/{idx}")
        for idx in range(3)
    ]

    response = client.get(f"{ASSESSMENT_BASE}/surfaces?limit=2&offset=1")

    assert response.status_code == 200, response.text
    rows = response.json()
    assert len(rows) == 2
    assert [row["id"] for row in rows] == [created[1]["id"], created[0]["id"]]


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


def test_administratively_closed_surface_remains_an_uncovered_obligation(
    client, isolate_settings
):
    """Administrative queue cleanup is explicit and never earns coverage."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)

    closed = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{created['id']}",
        json={
            "status": "administratively-closed",
            "rationale": "bulk closeout; no specialist evidence",
        },
    )

    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "administratively-closed"
    brief = client.get(f"{ASSESSMENT_BASE}/resume-brief")
    assert brief.status_code == 200, brief.text
    surfaces = brief.json()["surfaces"]
    assert surfaces["by_status"]["administratively-closed"] == 1
    assert surfaces["open_count"] == 1
    assert surfaces["top_uncovered"][0]["status"] == "administratively-closed"
    readiness = client.get(f"{ASSESSMENT_BASE}/coverage-readiness")
    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["blocker_count"] == 0
    assert readiness.json()["advisory_surfaces"][0]["status"] == (
        "administratively-closed"
    )


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


def _create_request_variant(client, url: str) -> int:
    response = client.post(
        f"{ASSESSMENT_BASE}/request-observations",
        json={"url": url, "discovery_source": "recon"},
    )
    assert response.status_code == 201, response.text
    return response.json()["request_variant"]["id"]


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


def test_partially_covered_surface_not_finding_linked_is_advisory(client, isolate_settings):
    """L1-2/L1-9 — a partially-covered surface with an OPEN follow-up but NO
    linked active finding is ADVISORY, not a hard coverage blocker. It is
    surfaced in ``advisory_surfaces`` so the operator still sees it, but it does
    not flip ``ready`` to False (which would block forever with no escape)."""
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

    coverage = client.get(f"{ASSESSMENT_BASE}/coverage-readiness")
    assert coverage.status_code == 200, coverage.text
    coverage_body = coverage.json()
    assert coverage_body["ready"] is True
    assert coverage_body["blocker_count"] == 0
    assert coverage_body["partially_covered_surfaces"] == []
    assert [row["id"] for row in coverage_body["advisory_surfaces"]] == [surface_id]


def test_partially_covered_surface_linked_to_active_finding_blocks(client, isolate_settings):
    """L1-2 — a partially-covered surface DOES block when it is linked to an
    active (reportable) finding on the same host: the finding makes the residual
    follow-up load-bearing."""
    _seed_engagement(client, isolate_settings)
    created = _create_surface(client)
    surface_id = created["id"]

    finding = {
        "slug": "VA-101",
        "title": "IDOR on users endpoint",
        "severity": "high",
        "workflow_status": "active",
        "canonical_location": "https://example.test/api/users/1",
        "summary": "IDOR",
        "evidence_ref": "findings.md",
        "source_name": "test",
        "provenance": {"agent_id": AUTHOR_AGENT_ID},
    }
    resp = client.post(f"{ASSESSMENT_BASE}/findings", json=finding)
    assert resp.status_code in {200, 201}, resp.text

    response = client.patch(
        f"{ASSESSMENT_BASE}/surfaces/{surface_id}",
        json={
            "status": "partially-covered",
            "rationale": "unauth path tested; admin path still pending auth",
            "followup_condition": "needs auth re-test once credentials are issued",
        },
    )
    assert response.status_code == 200, response.text

    coverage = client.get(f"{ASSESSMENT_BASE}/coverage-readiness")
    assert coverage.status_code == 200, coverage.text
    coverage_body = coverage.json()
    assert coverage_body["ready"] is False
    assert coverage_body["blocker_count"] == 1
    assert coverage_body["partially_covered_surfaces"][0]["id"] == surface_id

    report = client.get(f"{ASSESSMENT_BASE}/report-readiness")
    assert report.status_code == 200, report.text
    assert report.json()["ready"] is False


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


# ──────────────────────────────────────────────────────────────
# surface_request_variant_links — durable surface <-> request-variant link
# ──────────────────────────────────────────────────────────────


def test_create_surface_request_variant_link_success(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)
    variant_id = _create_request_variant(client, "https://example.test/api/users/1")

    response = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": surface["id"],
            "request_variant_id": variant_id,
            "relation": "primary-endpoint",
            "evidence_ref": "scans/katana.txt:14",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["surface_id"] == surface["id"]
    assert body["request_variant_id"] == variant_id
    assert body["relation"] == "primary-endpoint"
    assert body["evidence_ref"] == "scans/katana.txt:14"


def test_create_surface_request_variant_link_404_on_bad_surface_id(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    variant_id = _create_request_variant(client, "https://example.test/api/users/2")

    response = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": 9999, "request_variant_id": variant_id},
    )
    assert response.status_code == 404, response.text
    assert "surface" in response.json()["detail"].lower()


def test_create_surface_request_variant_link_404_on_bad_request_variant_id(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)

    response = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": surface["id"], "request_variant_id": 9999},
    )
    assert response.status_code == 404, response.text
    assert "request_variant" in response.json()["detail"].lower()


def test_list_surface_request_variant_links_by_surface(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)
    other_surface = _create_surface_with_descriptor(client, "https://example.test/api/other")
    variant_a = _create_request_variant(client, "https://example.test/api/users/3")
    variant_b = _create_request_variant(client, "https://example.test/api/users/4")

    for variant_id in (variant_a, variant_b):
        response = client.post(
            f"{ASSESSMENT_BASE}/surface-request-variant-links",
            json={"surface_id": surface["id"], "request_variant_id": variant_id},
        )
        assert response.status_code == 201, response.text
    # Link belonging to a different surface must not leak into the list below.
    response = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": other_surface["id"], "request_variant_id": variant_a},
    )
    assert response.status_code == 201, response.text

    listed = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}"
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 2
    assert {row["request_variant_id"] for row in rows} == {variant_a, variant_b}
    assert all(row["surface_id"] == surface["id"] for row in rows)


def test_list_surface_request_variant_links_by_request_variant(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    surface_a = _create_surface(client)
    surface_b = _create_surface_with_descriptor(client, "https://example.test/api/another")
    variant_id = _create_request_variant(client, "https://example.test/api/users/5")
    other_variant_id = _create_request_variant(client, "https://example.test/api/users/6")

    for surface in (surface_a, surface_b):
        response = client.post(
            f"{ASSESSMENT_BASE}/surface-request-variant-links",
            json={"surface_id": surface["id"], "request_variant_id": variant_id},
        )
        assert response.status_code == 201, response.text
    # Link belonging to a different request_variant must not leak into the list below.
    response = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": surface_a["id"], "request_variant_id": other_variant_id},
    )
    assert response.status_code == 201, response.text

    listed = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-request-variant/{variant_id}"
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 2
    assert {row["surface_id"] for row in rows} == {surface_a["id"], surface_b["id"]}
    assert all(row["request_variant_id"] == variant_id for row in rows)


def test_create_surface_request_variant_link_upsert_updates_evidence_ref(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)
    variant_id = _create_request_variant(client, "https://example.test/api/users/7")

    first = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": surface["id"],
            "request_variant_id": variant_id,
            "relation": "primary-endpoint",
            "evidence_ref": "scans/katana-v1.txt:1",
        },
    )
    assert first.status_code == 201, first.text
    first_id = first.json()["id"]

    second = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": surface["id"],
            "request_variant_id": variant_id,
            "relation": "primary-endpoint",
            "evidence_ref": "scans/katana-v2.txt:9",
        },
    )
    assert second.status_code == 201, second.text
    assert second.json()["id"] == first_id
    assert second.json()["evidence_ref"] == "scans/katana-v2.txt:9"

    listed = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}"
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    # The upsert must not create a second row for the same
    # (surface_id, request_variant_id, relation) key.
    assert len(rows) == 1
    assert rows[0]["evidence_ref"] == "scans/katana-v2.txt:9"


def test_create_surface_request_variant_link_distinct_relations_create_separate_rows(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)
    variant_id = _create_request_variant(client, "https://example.test/api/users/8")

    for relation in ("primary-endpoint", "related"):
        response = client.post(
            f"{ASSESSMENT_BASE}/surface-request-variant-links",
            json={
                "surface_id": surface["id"],
                "request_variant_id": variant_id,
                "relation": relation,
            },
        )
        assert response.status_code == 201, response.text

    listed = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}"
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 2
    assert {row["relation"] for row in rows} == {"primary-endpoint", "related"}


def test_create_surface_request_variant_link_empty_evidence_ref_does_not_clobber(
    client, isolate_settings
):
    """The upsert uses COALESCE(NULLIF(excluded.evidence_ref, ''), ...) — a
    re-post with no evidence_ref (the CLI/ingest default) must not erase a
    previously-recorded one."""
    _seed_engagement(client, isolate_settings)
    surface = _create_surface(client)
    variant_id = _create_request_variant(client, "https://example.test/api/users/9")

    first = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": surface["id"],
            "request_variant_id": variant_id,
            "relation": "primary-endpoint",
            "evidence_ref": "scans/katana.txt:14",
        },
    )
    assert first.status_code == 201, first.text
    first_id = first.json()["id"]

    second = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": surface["id"],
            "request_variant_id": variant_id,
            "relation": "primary-endpoint",
            # evidence_ref omitted -> defaults to "" on the wire.
        },
    )
    assert second.status_code == 201, second.text
    assert second.json()["id"] == first_id
    assert second.json()["evidence_ref"] == "scans/katana.txt:14"

    listed = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}"
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["evidence_ref"] == "scans/katana.txt:14"


# ──────────────────────────────────────────────────────────────
# surface_request_variant_links — cross-engagement scoping
# ──────────────────────────────────────────────────────────────


def test_create_surface_request_variant_link_404_on_foreign_surface_id(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    _seed_other_engagement(client, isolate_settings)

    foreign_surface = _create_surface(client)  # belongs to ENGAGEMENT_KEY
    # A request_variant_id that is genuinely VALID under OTHER_ENGAGEMENT_KEY,
    # so the 404 below is attributable to the surface_id check alone, not a
    # coincidental failure on both ids.
    own_variant = client.post(
        f"{OTHER_ASSESSMENT_BASE}/request-observations",
        json={"url": "https://example-other.test/api/users/10", "discovery_source": "recon"},
    )
    assert own_variant.status_code == 201, own_variant.text
    own_variant_id = own_variant.json()["request_variant"]["id"]

    response = client.post(
        f"{OTHER_ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": foreign_surface["id"], "request_variant_id": own_variant_id},
    )
    assert response.status_code == 404, response.text
    assert "surface" in response.json()["detail"].lower()


def test_create_surface_request_variant_link_404_on_foreign_request_variant_id(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    _seed_other_engagement(client, isolate_settings)

    foreign_variant_id = _create_request_variant(
        client, "https://example.test/api/users/11"
    )  # belongs to ENGAGEMENT_KEY

    other_surface = client.post(
        f"{OTHER_ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example-other.test/api/users/{id}",
            "source_name": "surface-collector",
            "rationale": "candidate parameter",
            "evidence_ref": "scans/katana.txt:1",
        },
    )
    assert other_surface.status_code == 201, other_surface.text

    response = client.post(
        f"{OTHER_ASSESSMENT_BASE}/surface-request-variant-links",
        json={
            "surface_id": other_surface.json()["id"],
            "request_variant_id": foreign_variant_id,
        },
    )
    assert response.status_code == 404, response.text
    assert "request_variant" in response.json()["detail"].lower()


def test_list_surface_request_variant_links_by_surface_does_not_leak_across_engagements(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    _seed_other_engagement(client, isolate_settings)

    surface = _create_surface(client)  # ENGAGEMENT_KEY
    variant_id = _create_request_variant(client, "https://example.test/api/users/12")
    link = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": surface["id"], "request_variant_id": variant_id},
    )
    assert link.status_code == 201, link.text

    # Same surface_id queried under the OTHER engagement must not see the
    # ENGAGEMENT_KEY link — engagement scoping, not a global table scan.
    leaked = client.get(
        f"{OTHER_ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}"
    )
    assert leaked.status_code == 200, leaked.text
    assert leaked.json() == []

    # Sanity: the link IS visible under its own engagement.
    own = client.get(f"{ASSESSMENT_BASE}/surface-request-variant-links/by-surface/{surface['id']}")
    assert own.status_code == 200, own.text
    assert len(own.json()) == 1


def test_list_surface_request_variant_links_by_request_variant_does_not_leak_across_engagements(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    _seed_other_engagement(client, isolate_settings)

    surface = _create_surface(client)  # ENGAGEMENT_KEY
    variant_id = _create_request_variant(client, "https://example.test/api/users/13")
    link = client.post(
        f"{ASSESSMENT_BASE}/surface-request-variant-links",
        json={"surface_id": surface["id"], "request_variant_id": variant_id},
    )
    assert link.status_code == 201, link.text

    leaked = client.get(
        f"{OTHER_ASSESSMENT_BASE}/surface-request-variant-links/by-request-variant/{variant_id}"
    )
    assert leaked.status_code == 200, leaked.text
    assert leaked.json() == []

    own = client.get(
        f"{ASSESSMENT_BASE}/surface-request-variant-links/by-request-variant/{variant_id}"
    )
    assert own.status_code == 200, own.text
    assert len(own.json()) == 1
