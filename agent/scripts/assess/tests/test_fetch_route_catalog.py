"""`vigil assess fetch` can tell an operator which routes exist.

`fetch` is the generic read escape hatch, and it required an endpoint name with
no way to discover one: an operator who did not already know that repository
records live at `code/repos/<repo-id>` had nothing to ask. The catalog is one
declared registry — the argument help, the discovery listing, and the paginated
marker all read from it, so no second copy can drift out of date.
"""
from __future__ import annotations

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
