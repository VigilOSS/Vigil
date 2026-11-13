"""Code-analysis list/fetch routes refuse query keys they do not declare.

FastAPI drops an undeclared query param, so ``triggers?state=pending`` would
answer with every trigger: unrelated rows presented as the filtered answer.
Every GET route declared in ``app.api.code_analysis`` refuses an unknown key
with 400, names it, and lists what the route accepts, read off the route's own
signature by the shared `reject_unknown_query_params` dependency.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute

from app.api import code_analysis
from app.api.query_params import reject_unknown_query_params
from test_code_analysis_api import write_engagement

ENGAGEMENT_KEY = "2026-11-13-code-query-params"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment/code"


@pytest.fixture
def engagement(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], ENGAGEMENT_KEY)
    return client


@pytest.mark.parametrize(
    ("endpoint", "unknown"),
    [
        ("triggers?state=pending", "state"),
        ("analysis-queue?status=pending&agent=hunter-1", "agent"),
        ("coverage/by-path?pathprefix=src", "pathprefix"),
        ("coverage?repo=1", "repo"),
        ("readiness?target_phase=hunt&phase=hunt", "phase"),
        ("analysis-results?disposition=clean&verdict=clean", "verdict"),
        ("files?repoid=1", "repoid"),
    ],
)
def test_undeclared_query_key_is_refused(engagement, endpoint, unknown):
    response = engagement.get(f"{BASE}/{endpoint}")
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    route = endpoint.partition("?")[0]
    assert detail.startswith(f"code/{route} does not accept query params: {unknown}.")


def test_declared_keys_are_accepted(engagement):
    assert engagement.get(f"{BASE}/triggers?status=pending").status_code == 200
    assert engagement.get(f"{BASE}/coverage/by-path?depth=1").status_code == 200
    assert engagement.get(f"{BASE}/files?repo_id=1&limit=5").status_code == 200
    assert engagement.get(f"{BASE}/readiness?target_phase=hunt").status_code == 200


def test_every_code_analysis_get_route_refuses_undeclared_keys():
    get_routes = [
        route
        for route in code_analysis.router.routes
        if isinstance(route, APIRoute)
        and "GET" in route.methods
        and route.endpoint.__module__ == code_analysis.__name__
    ]
    assert get_routes
    unguarded = [
        route.path
        for route in get_routes
        if not any(
            sub.call is reject_unknown_query_params for sub in route.dependant.dependencies
        )
    ]
    assert unguarded == []
