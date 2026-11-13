"""Assessment list/fetch routes refuse query keys they do not declare.

FastAPI drops an undeclared query param, so without a refusal
``coverage-items?application_unit_id=7`` answers with every coverage item:
unrelated rows presented as the filtered answer. Every GET route the app mounts
refuses an unknown key with 400, names it, and lists what the route accepts —
read off the route's own signature, aliases and sub-dependencies included. The
SPA fallback is the one exception: it serves browser deep links, whose query
string belongs to the frontend's own router.
"""
from __future__ import annotations

import pytest
from fastapi.routing import APIRoute, iter_route_contexts

from app.api.query_params import reject_unknown_query_params
from app.main import app, frontend_app
from tests.test_engagements_api import write_engagement

ENGAGEMENT_KEY = "2026-11-12-093000-query-params"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


@pytest.fixture
def engagement(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return client


@pytest.mark.parametrize(
    ("endpoint", "unknown"),
    [
        ("coverage-items?application_unit_id=7", "application_unit_id"),
        ("probe-runs?target_hots=app.example.com", "target_hots"),
        ("application-units?host=app.example.com", "host"),
        ("findings?severity=high&sevrity=low", "sevrity"),
        ("findings/count?state=active", "state"),
        ("coverage-readiness/by-family?unit=7", "unit"),
        ("work-items?status=pending&queue=web", "queue"),
    ],
)
def test_undeclared_query_key_is_refused(engagement, endpoint, unknown):
    response = engagement.get(f"{BASE}/{endpoint}")
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    route = endpoint.partition("?")[0]
    assert detail.startswith(f"{route} does not accept query params: {unknown}.")


def test_refusal_lists_every_declared_key_including_aliases(engagement):
    response = engagement.get(f"{BASE}/coverage-items?application_unit_id=7")
    detail = response.json()["detail"]
    accepted = detail.split("Accepted: ", 1)[1].split(", ")
    assert accepted == sorted([
        "attack_family", "auth_context", "input_slot", "limit", "offset",
        "request_variant_id", "service_id", "status", "target_host",
    ])


def test_declared_keys_and_sub_dependency_keys_are_accepted(engagement):
    assert engagement.get(f"{BASE}/coverage-items?status=covered&limit=5").status_code == 200
    assert engagement.get(f"{BASE}/findings?severity=high&view=summary").status_code == 200
    assert engagement.get(f"{BASE}/findings/count?holding=true").status_code == 200
    assert engagement.get(f"{BASE}/application-units").status_code == 200


def _mounted_routes(routes):
    """Every route the app serves, descending into included routers."""
    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            yield from _mounted_routes(included.routes)
        else:
            yield route


def test_every_mounted_get_route_refuses_undeclared_keys():
    get_routes = [
        route
        for route in _mounted_routes(app.routes)
        if isinstance(route, APIRoute)
        and "GET" in route.methods
        and route.endpoint is not frontend_app
    ]
    assert len(get_routes) > 150
    unguarded = [
        f"{route.endpoint.__module__}:{route.path}"
        for route in get_routes
        if not any(
            sub.call is reject_unknown_query_params for sub in route.dependant.dependencies
        )
    ]
    assert unguarded == []


@pytest.mark.parametrize(
    ("endpoint", "unknown"),
    [
        ("assessment/dispatches?rol=hunter", "rol"),
        ("assessment/proof-work?state=open", "state"),
        ("intel/search?q=acme&type=domain", "type"),
        ("activity-entries?actor=operator", "actor"),
    ],
)
def test_routes_outside_the_assessment_router_refuse_undeclared_keys(
    engagement, endpoint, unknown
):
    response = engagement.get(f"/engagements/{ENGAGEMENT_KEY}/{endpoint}")
    assert response.status_code == 400, response.text
    assert f"does not accept query params: {unknown}." in response.json()["detail"]


def test_a_path_param_is_never_accepted_as_a_query_key(engagement):
    # engagement_key is the path's own; as a query key it is unknown, not ignored.
    response = engagement.get(f"{BASE}/dispatches?engagement_key=other")
    assert response.status_code == 400, response.text
    assert response.json()["detail"].startswith(
        "dispatches does not accept query params: engagement_key."
    )

    refused = engagement.get(f"{BASE}/proof-work?limit=1")
    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert detail.startswith("proof-work does not accept query params: limit.")
    assert detail.endswith("Accepted: (none)")


def test_every_get_route_is_registered_at_its_full_path():
    """A route registered relative to an including router's prefix reads that
    prefix's path params as query params, and refusals would label it by the
    relative path; every GET route carries its full path itself."""
    misregistered = [
        f"{context.original_route.endpoint.__module__}:{context.path}"
        for context in iter_route_contexts(app.routes)
        if isinstance(context.original_route, APIRoute)
        and "GET" in context.original_route.methods
        and context.original_route.endpoint is not frontend_app
        and context.original_route.path != context.path
    ]
    assert misregistered == []
