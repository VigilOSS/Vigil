"""`vigil assess fetch` can tell an operator which routes exist.

`fetch` is the generic read escape hatch, and it required an endpoint name with
no way to discover one: an operator who did not already know that repository
records live at `code/repos/<repo-id>` had nothing to ask. The catalog is one
declared registry — the argument help, the discovery listing, and the paginated
marker all read from it, so no second copy can drift out of date.
"""
from __future__ import annotations

import typing
from types import SimpleNamespace

import pytest

from assess.commands import fetch
from assess.lib.intel_types import INTEL_TYPES


def _catalog_text(capsys) -> str:
    fetch.run(
        SimpleNamespace(
            endpoint=None,
            list_routes=True,
            engagement_dir=None,
            as_json=False,
            compact=False,
            paginate=False,
            jq="",
        )
    )
    return capsys.readouterr().out


def test_list_routes_names_the_code_repository_routes(capsys) -> None:
    listing = _catalog_text(capsys)

    assert "code/repos" in listing
    assert "code/repos/<repo-id>" in listing


def test_the_repository_route_advertises_the_public_churn_field(capsys) -> None:
    # The stored column is `git_churn_json`; the response field is `git_churn`.
    # Naming the internal column sent operators looking for a key that is never
    # in the payload.
    listing = _catalog_text(capsys)

    assert "git_churn" in listing
    assert "git_churn_json" not in listing


def test_every_intel_type_is_discoverable_from_the_type_registry(capsys) -> None:
    listing = _catalog_text(capsys)

    for _schema, segment in INTEL_TYPES.values():
        assert f"intel/{segment}" in listing, segment


def test_paginated_routes_are_marked_from_the_paging_tables(capsys) -> None:
    listing = _catalog_text(capsys)

    for line in listing.splitlines():
        route = line.strip().split(" ", 1)[0]
        if route in fetch._PAGED_ASSESSMENT_ENDPOINTS:
            assert "--paginate" in line, line


_ASSESSMENT_PREFIX = "/engagements/{engagement_key}/assessment/"

# One sentinel route per router that serves assessment reads. `assessment.py`
# carries `assessment_operator` and `assessment_proof_work` through its own
# nested `include_router`, so mounting those two again here only duplicates
# their operation ids; what the invariant needs is proof that they ARRIVE. A
# router that stops being reachable — or an include FastAPI stops resolving —
# now fails this file loudly instead of quietly shrinking the ground the
# registration check below walks. The operator router is the one that mattered:
# `dispatch-decisions` survived a sweep of thirteen unregistered routes.
_ROUTER_SENTINEL_ROUTES = (
    "findings",             # app.api.assessment
    "code/files",           # app.api.code_analysis
    "dispatch-decisions",   # app.api.assessment_operator
    "proof-work",           # app.api.assessment_proof_work
)


def _backend_assessment_get_routes() -> dict[str, dict[str, dict]]:
    """``{route: {query parameter: JSON schema}}`` for every assessment GET.

    The routers are the authority on which reads bound their page and how far a
    caller may widen it. Mounting them on a throwaway app and reading the
    generated OpenAPI document resolves nested ``include_router`` calls — which
    is how the operator and proof-work routers arrive — and reports each
    ``Query()`` constraint without reaching into FastAPI internals.
    ``test_the_paging_invariant_can_see_every_router_that_serves_reads`` holds
    that reachability to account. The assess suite runs on the backend venv, so
    the routers are importable here.
    """
    from fastapi import FastAPI

    from app.api.assessment import router as assessment_router
    from app.api.code_analysis import router as code_analysis_router

    probe = FastAPI()
    probe.include_router(assessment_router)
    probe.include_router(code_analysis_router)
    routes: dict[str, dict[str, dict]] = {}
    for path, operations in probe.openapi()["paths"].items():
        operation = operations.get("get")
        if operation is None or not path.startswith(_ASSESSMENT_PREFIX):
            continue
        routes[path[len(_ASSESSMENT_PREFIX):]] = {
            parameter["name"]: parameter.get("schema", {})
            for parameter in operation.get("parameters", ())
        }
    return routes


def _backend_assessment_list_limits() -> dict[str, tuple[object, object]]:
    """``{route: (default limit, maximum limit)}`` for every paged backend read."""
    limits: dict[str, tuple[object, object]] = {}
    for route, schemas in _backend_assessment_get_routes().items():
        limit = schemas.get("limit")
        if limit is None or "offset" not in schemas:
            continue
        maximum = limit.get("maximum")
        if maximum is None:
            maximum = next(
                (
                    option["maximum"]
                    for option in limit.get("anyOf", ())
                    if option.get("maximum") is not None
                ),
                None,
            )
        limits[route] = (limit.get("default"), maximum)
    return limits


def test_the_paging_invariant_can_see_every_router_that_serves_reads() -> None:
    """An invariant is worth exactly the surface it covers.

    A router missing from the probe makes its bounded routes structurally
    invisible to the registration check below, which reports success over
    ground it never walked. Naming one route per router turns that from a
    silent gap into a failure.
    """
    routes = _backend_assessment_get_routes()

    for sentinel in _ROUTER_SENTINEL_ROUTES:
        assert sentinel in routes, sentinel


def _catalog_assessment_routes() -> list[str]:
    """Catalog collection routes, as backend path names.

    A ``<placeholder>`` in the PATH marks a point read with no page to bound;
    one in the query string (``artifacts/search?q=<text>``) is still a
    collection, so the path is what decides.
    """
    paths = (
        route.partition("?")[0].strip("/") for route, _purpose in fetch._FETCH_ROUTES
    )
    return [
        path
        for path in paths
        if "<" not in path and not fetch._is_engagement_scoped(path)
    ]


def test_every_bounded_backend_list_route_is_registered_for_paging() -> None:
    """The converse of ``test_paginated_routes_are_marked_from_the_paging_tables``.

    That test only proves the catalog does not PROMISE paging it cannot deliver.
    The expensive direction is the other one: a catalog route whose backend
    bounds the page by default and that ``fetch`` has not registered returns one
    truncated page, and ``--paginate`` is read after the unregistered
    short-circuit, so the flag does nothing and the command says nothing. The
    backend's own ``Query(default=...)`` is the only honest trigger for the
    invariant, so it is asserted against the live route table rather than a
    second hand-kept list.
    """
    backend_limits = _backend_assessment_list_limits()
    unpageable = [
        f"{route} (backend default limit {backend_limits[route][0]})"
        for route in _catalog_assessment_routes()
        if route in backend_limits
        and backend_limits[route][0] is not None
        and fetch._route_page_cap(route) is None
    ]

    assert not unpageable, (
        "catalog routes the backend bounds by default that `fetch` cannot page: "
        + ", ".join(sorted(unpageable))
    )


def test_registered_page_caps_match_the_backend_maxima() -> None:
    """A mirrored ceiling that drifts above the backend's is a 422 on every page.

    One that drifts below silently stops ``--paginate`` short of the rows, which
    is the defect the registration was added to end.
    """
    backend_limits = _backend_assessment_list_limits()
    registered = (
        *fetch._PAGED_ASSESSMENT_ENDPOINTS,
        *fetch._PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS,
    )

    for route in registered:
        assert route in backend_limits, route
        assert fetch._route_page_cap(route) == backend_limits[route][1], route


def test_the_catalog_prints_each_paged_routes_backend_ceiling(capsys) -> None:
    """``--help`` documented no ceiling and the caps are not one number.

    ``code/files`` stops at 10000, the assessment lists at 5000,
    ``code/variant-checks`` at 500 and the fuzz history reads at 100, so a
    single figure in the flag help would be wrong for most routes. The catalog
    already reads the paging tables, so each route carries its own.
    """
    listing = _catalog_text(capsys)

    for line in listing.splitlines():
        route = line.strip().split(" ", 1)[0]
        cap = fetch._route_page_cap(route.partition("?")[0].strip("/"))
        if cap is None:
            continue
        assert "[--paginate" in line, line
        assert str(cap) in line, line


def test_the_catalog_names_every_code_file_sort_the_backend_accepts(capsys) -> None:
    """``code/files`` now REFUSES an unknown query param instead of ignoring it.

    A mistyped filter used to come back as a full unfiltered page — a wrong
    answer rather than an empty one — which is why six classification lanes
    filtered the whole corpus client-side. With the route refusing, the catalog
    is the only place an operator learns the accepted spelling, so a sort column
    added to the backend enum and not named here is a 400 they cannot explain.
    The live ``Literal`` is the authority. The assess suite runs on the backend
    venv, so it is importable here.
    """
    from app.api.code_analysis import CodeFileSort, CodeSortOrder

    line = next(
        row
        for row in _catalog_text(capsys).splitlines()
        if row.strip().startswith("code/files ")
    )

    for column in typing.get_args(CodeFileSort):
        assert column in line, column
    for direction in typing.get_args(CodeSortOrder):
        assert direction in line, direction


def test_the_paginate_help_names_the_per_route_backend_ceiling() -> None:
    parser = _fetch_parser()
    paginate_help = next(
        action.help for action in parser._actions if action.dest == "paginate"
    )

    assert "limit" in paginate_help
    assert "422" in paginate_help


def test_the_endpoint_help_points_at_the_catalog_instead_of_listing_routes() -> None:
    parser = _fetch_parser()
    endpoint_help = next(
        action.help for action in parser._actions if action.dest == "endpoint"
    )

    assert "--list-routes" in endpoint_help


def test_a_missing_endpoint_names_the_discovery_flag(capsys) -> None:
    with pytest.raises(SystemExit):
        fetch.run(
            SimpleNamespace(
                endpoint=None,
                list_routes=False,
                engagement_dir=None,
                as_json=False,
                compact=False,
                paginate=False,
                jq="",
            )
        )

    assert "--list-routes" in capsys.readouterr().err


def test_catalog_is_deterministic(capsys) -> None:
    first = _catalog_text(capsys)
    second = _catalog_text(capsys)

    assert first == second


def _fetch_parser():
    import argparse

    parser = argparse.ArgumentParser()
    fetch.register(parser.add_subparsers())
    return parser._subparsers._group_actions[0].choices["fetch"]
