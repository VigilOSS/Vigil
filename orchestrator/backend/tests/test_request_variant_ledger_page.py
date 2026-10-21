"""Operator HTTP inventory reads: request-variant page, facets, position, point read,
and per-variant observations.

``GET /request-variants`` and ``GET /request-observations`` stay the bare lists
``vigil assess fetch`` pages. The HTTP view reads these routes instead, so a
search, a method count or a variant's observation count always covers the WHOLE
inventory — never the newest window the browser happened to load.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app import db as db_module

ENGAGEMENT_KEY = "2026-10-20-request-variant-page"
OTHER_KEY = "2026-10-20-request-variant-other"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _engagement(client, isolate_settings, key: str) -> None:
    engagement_dir: Path = isolate_settings["engagements_dir"] / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "HTTP inventory", "targets": ["https://shop.acme.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{key}").status_code == 200


def _observe(client, base: str, **payload) -> dict:
    response = client.post(f"{base}/request-observations", json={"auto_generate_coverage": False, **payload})
    assert response.status_code == 201, response.text
    return response.json()["request_variant"]


def _set_last_seen(variant_id: int, value: str) -> None:
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            "UPDATE assessment_request_variants SET last_seen_at = ? WHERE id = ?", (value, variant_id)
        )


@pytest.fixture
def inventory(client, isolate_settings) -> dict[str, dict]:
    _engagement(client, isolate_settings, ENGAGEMENT_KEY)
    _engagement(client, isolate_settings, OTHER_KEY)
    variants: dict[str, dict] = {}
    for status_code in (200, 200, 403):
        variants["orders"] = _observe(
            client,
            BASE,
            url="https://shop.acme.example/orders?id=1",
            method="GET",
            auth_context="member",
            query_schema={"order_id": "int"},
            discovery_source="crawl",
            response_status=status_code,
        )
    variants["users"] = _observe(
        client,
        BASE,
        url="https://api.acme.example/v1/users",
        method="POST",
        body_schema={"email": "string"},
        discovery_source="proxy",
        response_status=201,
    )
    variants["settings"] = _observe(
        client,
        BASE,
        url="https://admin.acme.example/settings",
        method="GET",
        auth_context="member",
        discovery_source="proxy",
    )
    variants["asset"] = _observe(
        client,
        BASE,
        url="https://shop.acme.example/assets/app.js",
        method="GET",
        content_type_family="script",
        discovery_source="crawl",
    )
    _observe(
        client,
        f"/engagements/{OTHER_KEY}/assessment",
        url="https://shop.acme.example/orders?id=1",
        method="GET",
        query_schema={"order_id": "int"},
    )
    _set_last_seen(variants["orders"]["id"], "2026-10-20 10:00:04")
    _set_last_seen(variants["users"]["id"], "2026-10-20 10:00:03")
    _set_last_seen(variants["settings"]["id"], "2026-10-20 10:00:02")
    _set_last_seen(variants["asset"]["id"], "2026-10-20 10:00:01")
    return variants


def _page(client, **params) -> dict:
    response = client.get(f"{BASE}/request-variants/page", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_page_covers_the_whole_inventory_with_observation_counts(client, inventory):
    page = _page(client, limit=2)
    assert page["total"] == 4 and page["count"] == 2 and page["has_more"] is True
    assert [row["id"] for row in page["items"]] == [inventory["orders"]["id"], inventory["users"]["id"]]
    orders = page["items"][0]
    assert orders["observation_count"] == 3
    assert orders["last_observed_at"]
    assert orders["normalized_path"] == "/orders"
    assert _page(client, limit=2, offset=2)["has_more"] is False


def test_method_facet_counts_the_whole_inventory(client, inventory):
    response = client.get(f"{BASE}/request-variants/facets", params={"method": "POST"})
    assert response.status_code == 200, response.text
    facets = response.json()
    assert facets["total"] == 1
    assert facets["engagement_total"] == 4
    methods = {entry["value"]: entry["count"] for entry in facets["facets"]["method"]["values"]}
    # The method facet ignores its own filter.
    assert methods == {"GET": 3, "POST": 1}
    sources = {entry["value"]: entry["count"] for entry in facets["facets"]["source"]["values"]}
    assert sources == {"proxy": 1}

    narrowed = client.get(f"{BASE}/request-variants/facets", params={"q": "shop.acme"}).json()
    assert {entry["value"]: entry["count"] for entry in narrowed["facets"]["method"]["values"]} == {"GET": 2}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("/settings", ["settings"]),
        ("admin.acme.example", ["settings"]),
        ("order_id", ["orders"]),
        ("email", ["users"]),
        ("shop.acme assets", ["asset"]),
        ("nothing-matches-this", []),
    ],
)
def test_search_matches_path_host_and_parameters(client, inventory, query, expected):
    page = _page(client, q=query)
    assert [row["id"] for row in page["items"]] == [inventory[name]["id"] for name in expected]
    assert page["total"] == len(expected)


def test_filters_and_sorts(client, inventory):
    member = _page(client, auth_context="member", method="GET")
    assert [row["id"] for row in member["items"]] == [inventory["orders"]["id"], inventory["settings"]["id"]]

    by_host = _page(client, sort="host", dir="asc")
    assert [row["host"] for row in by_host["items"]] == [
        "admin.acme.example",
        "api.acme.example",
        "shop.acme.example",
        "shop.acme.example",
    ]
    by_observations = _page(client, sort="observations", dir="desc")
    assert by_observations["items"][0]["id"] == inventory["orders"]["id"]
    assert client.get(f"{BASE}/request-variants/page", params={"sort": "notes"}).status_code == 422


def test_position_walks_the_page_order(client, inventory):
    params = {"method": "GET"}
    order = [row["id"] for row in _page(client, **params)["items"]]
    response = client.get(f"{BASE}/request-variants/{order[1]}/position", params=params)
    assert response.status_code == 200, response.text
    position = response.json()
    assert position["index"] == 1 and position["total"] == 3
    assert position["previous"]["id"] == order[0] and position["next"]["id"] == order[2]
    assert position["next"]["observation_count"] == 1

    outside = client.get(
        f"{BASE}/request-variants/{inventory['users']['id']}/position", params=params
    ).json()
    assert outside == {"index": None, "total": 3, "previous": None, "next": None}


def test_point_read_and_observations_list(client, inventory):
    variant_id = inventory["orders"]["id"]
    detail = client.get(f"{BASE}/request-variants/{variant_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["observation_count"] == 3

    first = client.get(f"{BASE}/request-variants/{variant_id}/observations", params={"limit": 2}).json()
    assert first["total"] == 3 and first["count"] == 2 and first["has_more"] is True
    assert all(item["request_variant_id"] == variant_id for item in first["items"])
    rest = client.get(
        f"{BASE}/request-variants/{variant_id}/observations", params={"limit": 2, "offset": 2}
    ).json()
    statuses = [item["response_status"] for item in first["items"] + rest["items"]]
    assert sorted(statuses) == [200, 200, 403]
    ids = [item["id"] for item in first["items"] + rest["items"]]
    assert ids == sorted(ids, reverse=True)

    other_variant = client.get(f"/engagements/{OTHER_KEY}/assessment/request-variants").json()[0]["id"]
    assert client.get(f"{BASE}/request-variants/{other_variant}").status_code == 404
    assert client.get(f"{BASE}/request-variants/{other_variant}/observations").status_code == 404
    assert client.get(f"{BASE}/request-variants/{other_variant}/position").status_code == 404


def test_existing_lists_are_unchanged(client, inventory):
    variants = client.get(f"{BASE}/request-variants").json()
    observations = client.get(f"{BASE}/request-observations").json()
    assert isinstance(variants, list) and len(variants) == 4
    assert isinstance(observations, list) and len(observations) == 6
