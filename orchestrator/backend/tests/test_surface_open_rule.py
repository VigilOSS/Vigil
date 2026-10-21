"""One owner for "an open surface".

A surface is retired only when it is ``covered`` or ruled ``not_applicable``.
Every other status is open work — including ``administratively-closed``, which
never earns coverage. The summary badge counts by this rule, publishes the open
statuses, and every surface row says whether it is open, so the UI never
re-derives the rule and the rail and the page cannot disagree.
"""
from __future__ import annotations

from app.services.state_manager.coverage_readiness import (
    OPEN_SURFACE_STATUSES,
    SURFACE_STATUSES,
    SurfaceStatus,
)
from tests.test_surfaces_api import ASSESSMENT_BASE, _create_surface_with_descriptor, _seed_engagement


def test_open_statuses_are_everything_but_covered_and_not_applicable():
    assert OPEN_SURFACE_STATUSES == SURFACE_STATUSES - {
        SurfaceStatus.COVERED,
        SurfaceStatus.NOT_APPLICABLE,
    }


def test_summary_and_rows_share_the_open_rule(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    updates = {
        "discovered": None,
        "covered": {"status": "covered", "rationale": "tested both tenants"},
        "not_applicable": {"status": "not_applicable", "rationale": "static page"},
        "deferred": {"status": "deferred", "rationale": "rate limited"},
        "partially-covered": {
            "status": "partially-covered",
            "rationale": "anonymous only",
            "followup_condition": "retest as member",
        },
        "administratively-closed": {
            "status": "administratively-closed",
            "rationale": "bulk closeout",
        },
    }
    for index, (status_value, patch) in enumerate(updates.items()):
        surface = _create_surface_with_descriptor(client, f"https://shop.acme.example/s/{index}")
        if patch is not None:
            response = client.patch(f"{ASSESSMENT_BASE}/surfaces/{surface['id']}", json=patch)
            assert response.status_code == 200, response.text
            assert response.json()["open"] is (status_value in OPEN_SURFACE_STATUSES)

    rows = client.get(f"{ASSESSMENT_BASE}/surfaces").json()
    assert {row["status"]: row["open"] for row in rows} == {
        "discovered": True,
        "covered": False,
        "not_applicable": False,
        "deferred": True,
        "partially-covered": True,
        "administratively-closed": True,
    }
    summary = client.get(f"{ASSESSMENT_BASE}/summary").json()
    assert summary["open_surface_count"] == sum(row["open"] for row in rows) == 4
    assert summary["open_surface_statuses"] == sorted(OPEN_SURFACE_STATUSES)
