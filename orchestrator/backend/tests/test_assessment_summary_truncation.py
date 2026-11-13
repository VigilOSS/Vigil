"""``GET /assessment/summary`` says which of its bounded lists it cut short.

The summary carries several top-N lists (``top_findings``, ``attack_chains``,
...) beside its exact totals. A reader holding only the list cannot tell "these
are all of them" from "these are the first eight", so each list states its
bound, whether rows were left out, and the route that serves the whole set.
"""
from __future__ import annotations

import importlib

from tests.test_engagements_api import write_engagement

summary_module = importlib.import_module("app.services.state_manager.assessment_summary")
KEY = "2026-03-30-120000-example"
BASE = f"/engagements/{KEY}/assessment"

_BOUNDED_LISTS = {
    "top_surfaces": (8, "surfaces"),
    "top_findings": (10, "findings"),
    "recent_probes": (10, "probe-runs"),
    "open_coverage_items": (12, "coverage-items"),
    "attack_chains": (8, "attack-chains"),
    "service_coverage_gaps": (10, "services"),
}


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"])
    assert client.get(f"/engagements/{KEY}").status_code == 200
    summary_module.clear_assessment_summary_cache()


def _summary(client) -> dict:
    summary_module.clear_assessment_summary_cache()
    response = client.get(f"{BASE}/summary")
    assert response.status_code == 200, response.text
    return response.json()


def _record_finding(client, index: int) -> None:
    slug = f"VA-{index:03d}"
    author = f"SOURCE-{slug}"
    dispatch = client.post(
        f"{BASE}/dispatches",
        json={"agent_id": author, "agent_role": "vulnerability-analyst", "task": f"record {slug}"},
    )
    assert dispatch.status_code == 201, dispatch.text
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": f"Acme finding {index}",
            "severity": "low",
            "workflow_status": "active",
            "canonical_location": f"https://example.com/item/{index}",
            "summary": f"Acme finding {index}",
            "source_name": "test",
            "provenance": {"agent_id": author},
        },
    )
    assert response.status_code in {200, 201}, response.text


def test_every_bounded_list_states_its_bound_and_full_route(client, isolate_settings):
    _seed(client, isolate_settings)
    truncation = _summary(client)["list_truncation"]
    assert truncation == {
        name: {"limit": limit, "truncated": False, "full_route": route}
        for name, (limit, route) in _BOUNDED_LISTS.items()
    }


def test_a_list_at_its_bound_is_not_truncated_and_one_past_it_is(client, isolate_settings):
    _seed(client, isolate_settings)
    for index in range(8):
        response = client.post(
            f"{BASE}/attack-chains",
            json={"chain_key": f"chain-{index}", "title": f"Acme chain {index}"},
        )
        assert response.status_code == 201, response.text

    exact = _summary(client)
    assert len(exact["attack_chains"]) == 8
    assert exact["list_truncation"]["attack_chains"]["truncated"] is False

    response = client.post(
        f"{BASE}/attack-chains", json={"chain_key": "chain-8", "title": "Acme chain 8"}
    )
    assert response.status_code == 201, response.text
    over = _summary(client)
    assert len(over["attack_chains"]) == 8
    assert over["attack_chain_count"] == 9
    assert over["list_truncation"]["attack_chains"] == {
        "limit": 8,
        "truncated": True,
        "full_route": "attack-chains",
    }


def test_top_findings_reports_truncation_past_its_bound(client, isolate_settings):
    _seed(client, isolate_settings)
    for index in range(11):
        _record_finding(client, index)

    payload = _summary(client)
    assert len(payload["top_findings"]) == 10
    assert payload["finding_count"] == 11
    assert payload["list_truncation"]["top_findings"]["truncated"] is True
    assert payload["list_truncation"]["top_surfaces"]["truncated"] is False
