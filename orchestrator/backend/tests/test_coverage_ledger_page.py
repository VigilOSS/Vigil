"""Operator coverage-ledger reads: paged list, facets, reason rollup, item detail.

``GET /coverage-items`` stays the bare-list contract ``vigil assess fetch`` pages;
these routes serve the operator UI instead. They must page the WHOLE ledger with a
visible total (never a recency slice), count facets server-side, and derive each
item's latest reason the same way everywhere it appears — the rollup, the row,
the reason filter and the detail must agree, or "why is this blocked" lies.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import db as db_module

ENGAGEMENT_KEY = "2026-09-30-coverage-ledger-page"
OTHER_KEY = "2026-09-30-coverage-ledger-other"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"

BLOCKED_REASON = "Needs a second tenant account; only one Acme tenant is provisioned."
DEFERRED_REASON = "Deferred until the Acme rate-limit window resets."
COVERED_REASON = "Swapped order ids across tenants; every read returned 403."


def _engagement(client, isolate_settings, key: str) -> None:
    engagement_dir: Path = isolate_settings["engagements_dir"] / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "engagement_name": "Coverage ledger",
                "targets": ["https://shop.acme.example", "https://api.acme.example"],
            }
        ),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{key}").status_code == 200


def _observe(client, base: str, **payload) -> dict:
    response = client.post(f"{base}/request-observations", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _item(items: list[dict], *, host_url: str, slot: str) -> dict:
    return next(
        item
        for item in items
        if item["input_slot"] == slot and (item.get("canonical_url") or "").startswith(host_url)
    )


def _patch(client, item_id: int, status_value: str, notes: str) -> None:
    response = client.patch(
        f"{BASE}/coverage-items/{item_id}",
        json={"status": status_value, "notes": notes},
    )
    assert response.status_code == 200, response.text


@pytest.fixture
def ledger(client, isolate_settings):
    """Two hosts, request-variant and service-bound items, every status shape.

    shop.acme.example GET /orders?id=   (member)    endpoint, query, service items
    api.acme.example  POST /v1/users    (anonymous) endpoint, body, service items
    plus one gf-bridge item (idor on the shop variant) created with a provenance note.
    """
    _engagement(client, isolate_settings, ENGAGEMENT_KEY)
    shop = _observe(
        client,
        BASE,
        url="https://shop.acme.example/orders?id=1",
        method="GET",
        auth_context="member",
        query_schema={"id": "int"},
        discovery_source="crawl",
        work_item={"case_type": "api", "status": "pending"},
    )
    api = _observe(
        client,
        BASE,
        url="https://api.acme.example/v1/users",
        method="POST",
        auth_context="anonymous",
        body_schema={"email": "string"},
        discovery_source="crawl",
    )
    gf = client.post(
        f"{BASE}/coverage-items",
        json={
            "request_variant_id": shop["request_variant"]["id"],
            "auth_context": "member",
            "input_slot": "path:id",
            "attack_family": "idor",
            "status_value": "pending",
            "notes": "gf bucket 'idor' matched at ingest",
        },
    )
    assert gf.status_code == 201, gf.text

    items = client.get(f"{BASE}/coverage-items").json()
    shop_query = _item(items, host_url="https://shop.acme.example", slot="query")
    shop_endpoint = _item(items, host_url="https://shop.acme.example", slot="endpoint")
    api_body = _item(items, host_url="https://api.acme.example", slot="body")
    api_endpoint = _item(items, host_url="https://api.acme.example", slot="endpoint")
    api_service = next(
        item for item in items
        if item["service_id"] == api["service"]["id"] and item["input_slot"] == "service"
    )

    _patch(client, shop_query["id"], "blocked", BLOCKED_REASON)
    _patch(client, api_body["id"], "blocked", BLOCKED_REASON)
    _patch(client, api_endpoint["id"], "deferred", "First look: gateway returns 429.")
    _patch(client, api_endpoint["id"], "deferred", DEFERRED_REASON)
    _patch(client, shop_endpoint["id"], "covered", COVERED_REASON)
    _patch(client, api_service["id"], "blocked", "Service refuses TLS from the test egress.")

    # Deterministic recency: id order == updated order, newest last.
    with db_module.get_connection() as connection:
        rows = connection.execute(
            "SELECT id FROM assessment_coverage_items ORDER BY id"
        ).fetchall()
        for index, row in enumerate(rows):
            connection.execute(
                "UPDATE assessment_coverage_items SET updated_at = ? WHERE id = ?",
                (f"2026-09-30 10:{index:02d}:00", row["id"]),
            )
    return {
        "client": client,
        "items": client.get(f"{BASE}/coverage-items").json(),
        "shop": shop,
        "api": api,
        "gf_id": gf.json()["id"],
        "shop_query_id": shop_query["id"],
        "shop_endpoint_id": shop_endpoint["id"],
        "api_body_id": api_body["id"],
        "api_endpoint_id": api_endpoint["id"],
        "api_service_id": api_service["id"],
    }


def _page(client, query: str = "") -> dict:
    response = client.get(f"{BASE}/coverage-items/page{('?' + query) if query else ''}")
    assert response.status_code == 200, response.text
    return response.json()


def _ids(payload: dict) -> list[int]:
    return [item["id"] for item in payload["items"]]


# ── page ──────────────────────────────────────────────────────────────


def test_page_reports_the_whole_ledger_total_and_pages_newest_first(ledger) -> None:
    client = ledger["client"]
    every = sorted(item["id"] for item in ledger["items"])

    first = _page(client, "limit=3")
    assert first["total"] == len(every)
    assert first["offset"] == 0
    assert first["count"] == 3
    assert first["has_more"] is True
    assert _ids(first) == sorted(every, reverse=True)[:3]

    rest = _page(client, "limit=3&offset=3")
    assert rest["total"] == len(every)
    assert _ids(rest) == sorted(every, reverse=True)[3:6]

    tail = _page(client, f"limit=500&offset={len(every) - 1}")
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_page_rows_carry_latest_reason_without_the_full_note_log(ledger) -> None:
    rows = {row["id"]: row for row in _page(ledger["client"], "limit=500")["items"]}

    deferred = rows[ledger["api_endpoint_id"]]
    assert deferred["latest_reason"] == DEFERRED_REASON
    assert deferred["created_from"] == "Auto-generated from request observation"
    assert "notes" not in deferred

    # Created and never touched: provenance only, so there is no reason yet.
    gf = rows[ledger["gf_id"]]
    assert gf["latest_reason"] is None
    assert gf["created_from"] == "gf bucket 'idor' matched at ingest"


def test_repeatable_filters_compose(ledger) -> None:
    client = ledger["client"]
    open_ids = set(_ids(_page(client, "status=blocked&status=deferred&limit=500")))
    assert open_ids == {
        ledger["shop_query_id"],
        ledger["api_body_id"],
        ledger["api_endpoint_id"],
        ledger["api_service_id"],
    }
    narrowed = _page(client, "status=blocked&status=deferred&auth_context=member")
    assert set(_ids(narrowed)) == {ledger["shop_query_id"]}
    assert narrowed["total"] == 1

    by_method = set(_ids(_page(client, "method=post&limit=500")))
    assert ledger["api_body_id"] in by_method
    # Service-bound items carry no request method.
    assert ledger["api_service_id"] not in by_method

    assert set(_ids(_page(client, "attack_family=idor"))) == {ledger["gf_id"]}
    assert set(_ids(_page(client, "input_slot=path:id"))) == {ledger["gf_id"]}


def test_host_filter_matches_request_variant_and_service_hosts(ledger) -> None:
    """The ledger groups a service-bound item under its target host, so the
    host filter must find it there too — not only request-variant rows."""
    client = ledger["client"]
    api_rows = _page(client, "host=API.acme.example&limit=500")
    ids = set(_ids(api_rows))
    assert ledger["api_service_id"] in ids
    assert {ledger["api_body_id"], ledger["api_endpoint_id"]} <= ids
    assert ledger["shop_query_id"] not in ids
    assert all(row["item_host"] == "api.acme.example" for row in api_rows["items"])

    both = _page(client, "host=api.acme.example&host=shop.acme.example&limit=500")
    assert both["total"] == len(ledger["items"])
    assert _page(client, "host=nowhere.example")["total"] == 0


def test_search_matches_notes_url_and_family_and_treats_wildcards_literally(ledger) -> None:
    client = ledger["client"]
    assert set(_ids(_page(client, "q=second%20tenant&limit=500"))) == {
        ledger["shop_query_id"],
        ledger["api_body_id"],
    }
    # Every term must match: notes term AND URL term.
    assert set(_ids(_page(client, "q=second%20/orders"))) == {ledger["shop_query_id"]}
    assert set(_ids(_page(client, "q=IDOR"))) == {ledger["gf_id"]}
    assert _page(client, "q=%25")["total"] == 0
    assert _page(client, "q=_")["total"] == 0


def test_reason_filters_select_exactly_the_rolled_up_items(ledger) -> None:
    client = ledger["client"]
    blocked = _page(client, "reason=" + BLOCKED_REASON.replace(" ", "%20").replace(";", "%3B"))
    assert set(_ids(blocked)) == {ledger["shop_query_id"], ledger["api_body_id"]}

    # The deferred item's FIRST reason is history, not its latest reason.
    assert _page(client, "reason=First%20look%3A%20gateway%20returns%20429.")["total"] == 0

    missing = _page(
        client,
        "reason_missing=true&created_from=gf%20bucket%20%27idor%27%20matched%20at%20ingest",
    )
    assert set(_ids(missing)) == {ledger["gf_id"]}
    assert _page(client, "reason=line%0Abreak")["total"] == 0


def test_sort_maps_to_an_allowlist_and_rejects_anything_else(ledger) -> None:
    client = ledger["client"]
    by_url = _page(client, "sort=url&dir=asc&limit=500")["items"]
    urls = [row["canonical_url"] or row["service_endpoint"] for row in by_url]
    request_urls = [url for url in urls if url and url.startswith("https://")]
    assert request_urls == sorted(request_urls)

    by_host = _page(client, "sort=host&dir=desc&limit=500")["items"]
    hosts = [row["item_host"] for row in by_host]
    assert hosts == sorted(hosts, reverse=True)

    for bad in ("sort=notes", "sort=updated_at%3B%20DROP%20TABLE%20x", "dir=sideways", "limit=501", "limit=0"):
        response = client.get(f"{BASE}/coverage-items/page?{bad}")
        assert response.status_code == 422, (bad, response.text)


@pytest.mark.parametrize("direction", ["desc", "asc"])
def test_status_sort_ranks_by_urgency_with_unknown_values_last(ledger, direction: str) -> None:
    """Status sorts by the UI's urgency order, not alphabetically: descending is
    most urgent first, ascending least urgent first, ties by id in the same
    direction, and a stored value outside the vocabulary last either way.
    Position walks the same order."""
    client = ledger["client"]
    extra = client.post(
        f"{BASE}/coverage-items",
        json={
            "request_variant_id": ledger["shop"]["request_variant"]["id"],
            "auth_context": "member",
            "input_slot": "path:id",
            "attack_family": "xss",
            "status_value": "pending",
        },
    )
    assert extra.status_code == 201, extra.text
    ids = sorted(_ids(_page(client, "limit=500")))
    stored = ["covered", "legacy_hold", "pending", "not_applicable", "queued", "blocked", "deferred", "pending"]
    assert len(ids) == len(stored)
    with db_module.get_connection() as connection:
        for item_id, value in zip(ids, stored):
            connection.execute("UPDATE assessment_coverage_items SET status = ? WHERE id = ?", (value, item_id))
    shown = dict(zip(ids, stored))

    urgency = ["blocked", "deferred", "pending", "queued", "covered", "not_applicable"]

    def key(item_id: int) -> tuple[bool, int, int]:
        value = shown[item_id]
        rank = urgency.index(value) if value in urgency else len(urgency)
        if direction == "desc":
            return value not in urgency, rank, -item_id
        return value not in urgency, -rank, item_id

    expected = sorted(ids, key=key)

    query = f"sort=status&dir={direction}"
    rows = _page(client, f"{query}&limit=500")["items"]
    assert _ids({"items": rows}) == expected
    assert [row["status"] for row in rows] == [shown[item_id] for item_id in expected]
    paged = [item_id for offset in range(0, len(ids), 3) for item_id in _ids(_page(client, f"{query}&limit=3&offset={offset}"))]
    assert paged == expected

    for index, row in enumerate(rows):
        position = _position(client, row["id"], query)
        assert position["index"] == index
        assert position["total"] == len(rows)
        assert position["previous"] == (rows[index - 1] if index > 0 else None)
        assert position["next"] == (rows[index + 1] if index + 1 < len(rows) else None)


def test_page_is_scoped_to_its_engagement(ledger, isolate_settings) -> None:
    client = ledger["client"]
    _engagement(client, isolate_settings, OTHER_KEY)
    other = client.get(f"/engagements/{OTHER_KEY}/assessment/coverage-items/page").json()
    assert other["total"] == 0
    assert other["items"] == []


def test_legacy_list_keeps_its_bare_list_shape(ledger) -> None:
    rows = ledger["client"].get(f"{BASE}/coverage-items?limit=2").json()
    assert isinstance(rows, list)
    assert len(rows) == 2
    assert "notes" in rows[0]



# ── position ──────────────────────────────────────────────────────────


def _position(client, item_id: int, query: str = "") -> dict:
    response = client.get(f"{BASE}/coverage-items/{item_id}/position{('?' + query) if query else ''}")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    "query",
    ["", "sort=url&dir=asc", "sort=host&dir=desc", "sort=method&dir=asc", "status=blocked&status=deferred&sort=status&dir=asc"],
)
def test_position_places_an_item_between_its_page_order_neighbours(ledger, query: str) -> None:
    """Record navigation walks the same order the paged grid shows, across any
    block boundary, so each item's neighbours are the page rows beside it."""
    client = ledger["client"]
    rows = _page(client, f"{query}&limit=500" if query else "limit=500")["items"]
    for index, row in enumerate(rows):
        position = _position(client, row["id"], query)
        assert position["index"] == index
        assert position["total"] == len(rows)
        assert position["previous"] == (rows[index - 1] if index > 0 else None)
        assert position["next"] == (rows[index + 1] if index + 1 < len(rows) else None)


def test_position_of_an_item_outside_the_filters_has_no_index(ledger) -> None:
    client = ledger["client"]
    blocked_total = _page(client, "status=blocked")["total"]
    assert _position(client, ledger["gf_id"], "status=blocked") == {
        "index": None,
        "total": blocked_total,
        "previous": None,
        "next": None,
    }


def test_position_rejects_unknown_sorts_and_is_scoped(ledger, isolate_settings) -> None:
    client = ledger["client"]
    assert client.get(f"{BASE}/coverage-items/{ledger['gf_id']}/position?sort=notes").status_code == 422
    assert client.get(f"{BASE}/coverage-items/999999/position").status_code == 404
    _engagement(client, isolate_settings, OTHER_KEY)
    response = client.get(f"/engagements/{OTHER_KEY}/assessment/coverage-items/{ledger['gf_id']}/position")
    assert response.status_code == 404

# ── facets ────────────────────────────────────────────────────────────


def _facet(payload: dict, name: str) -> dict:
    return {entry["value"]: entry["count"] for entry in payload["facets"][name]["values"]}


def test_facets_count_the_whole_ledger_and_exclude_their_own_dimension(ledger) -> None:
    client = ledger["client"]
    unfiltered = client.get(f"{BASE}/coverage-items/facets").json()
    total = len(ledger["items"])
    assert unfiltered["total"] == total
    assert sum(unfiltered["status_totals"].values()) == total
    assert unfiltered["status_totals"]["blocked"] == 3
    assert _facet(unfiltered, "host") == {"shop.acme.example": 4, "api.acme.example": 3}

    filtered = client.get(f"{BASE}/coverage-items/facets?status=blocked&host=api.acme.example").json()
    assert filtered["total"] == 2
    # Status counts ignore the status filter but honour the host filter.
    assert _facet(filtered, "status") == _facet(
        client.get(f"{BASE}/coverage-items/facets?host=api.acme.example").json(), "status"
    )
    assert sum(_facet(filtered, "status").values()) == 3
    # Host counts ignore the host filter but honour the status filter.
    assert _facet(filtered, "host") == {"shop.acme.example": 1, "api.acme.example": 2}
    # Family counts honour both.
    assert sum(_facet(filtered, "attack_family").values()) == 2
    # The engagement-wide status bar never moves with filters.
    assert filtered["status_totals"] == unfiltered["status_totals"]
    # Service-bound items have no method; the facet names that bucket "".
    assert _facet(unfiltered, "method")[""] == 2


def test_facet_values_beyond_the_limit_are_counted_not_dropped(ledger) -> None:
    payload = ledger["client"].get(f"{BASE}/coverage-items/facets?facet_limit=1").json()
    host = payload["facets"]["host"]
    assert len(host["values"]) == 1
    assert host["distinct"] == 2
    assert host["values"] == [{"value": "shop.acme.example", "count": 4}]
    assert host["omitted_count"] == 3


# ── reasons ───────────────────────────────────────────────────────────


def test_reason_rollup_groups_latest_reasons_per_status(ledger) -> None:
    client = ledger["client"]
    payload = client.get(f"{BASE}/coverage-items/reasons?status=blocked&status=deferred&status=pending").json()
    groups = {group["status"]: group for group in payload["statuses"]}
    assert set(groups) == {"blocked", "deferred", "pending"}

    blocked = {(entry["reason"], entry["created_from"]): entry["count"] for entry in groups["blocked"]["reasons"]}
    assert blocked == {
        (BLOCKED_REASON, None): 2,
        ("Service refuses TLS from the test egress.", None): 1,
    }
    assert groups["blocked"]["count"] == 3
    assert groups["deferred"]["reasons"] == [
        {"reason": DEFERRED_REASON, "created_from": None, "count": 1}
    ]
    # Never-touched items roll up by what created them.
    pending = {(entry["reason"], entry["created_from"]): entry["count"] for entry in groups["pending"]["reasons"]}
    assert pending[(None, "gf bucket 'idor' matched at ingest")] == 1
    assert payload["total"] == sum(group["count"] for group in payload["statuses"])


def test_reason_rollup_is_filter_aware(ledger) -> None:
    payload = ledger["client"].get(
        f"{BASE}/coverage-items/reasons?status=blocked&host=shop.acme.example"
    ).json()
    assert payload["total"] == 1
    assert payload["statuses"][0]["reasons"] == [
        {"reason": BLOCKED_REASON, "created_from": None, "count": 1}
    ]


def test_every_rolled_up_reason_filters_back_to_its_count(ledger) -> None:
    """Rollup and reason filter share one definition of "latest reason"."""
    client = ledger["client"]
    with db_module.get_connection() as connection:
        # Tricky note shapes: trailing blank lines, an interior blank line,
        # and a reason that is a suffix of another reason.
        connection.execute(
            "UPDATE assessment_coverage_items SET notes = ? WHERE id = ?",
            ("Auto-generated from request observation\n\nretry later\n\n  \n", ledger["gf_id"]),
        )
        connection.execute(
            "UPDATE assessment_coverage_items SET notes = ?, status = 'blocked' WHERE id = ?",
            ("Auto-generated from request observation\nplease retry later", ledger["shop_endpoint_id"]),
        )
    payload = client.get(f"{BASE}/coverage-items/reasons").json()
    seen = 0
    for group in payload["statuses"]:
        for entry in group["reasons"]:
            params: dict[str, str] = {"status": group["status"], "limit": "500"}
            if entry["reason"] is None:
                params["reason_missing"] = "true"
                params["created_from"] = entry["created_from"]
            else:
                params["reason"] = entry["reason"]
            page = client.get(f"{BASE}/coverage-items/page", params=params).json()
            assert page["total"] == entry["count"], entry
            for row in page["items"]:
                assert row["latest_reason"] == entry["reason"]
            seen += entry["count"]
    assert seen == len(ledger["items"])
    rows = {row["id"]: row for row in _page(client, "limit=500")["items"]}
    assert rows[ledger["gf_id"]]["latest_reason"] == "retry later"
    assert rows[ledger["shop_endpoint_id"]]["latest_reason"] == "please retry later"


# ── detail ────────────────────────────────────────────────────────────


def test_detail_explains_the_item(ledger) -> None:
    client = ledger["client"]
    shop = ledger["shop"]
    item_id = ledger["shop_query_id"]
    work_item_id = shop["work_item"]["id"]
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_work_items SET coverage_item_id = ?, status = 'skipped', retry_count = 2, "
            "terminal_reason = 'coverage item blocked', triage_rationale = 'needs second tenant' WHERE id = ?",
            (item_id, work_item_id),
        )
    probe = client.post(
        f"{BASE}/probe-runs",
        json={
            "coverage_item_id": item_id,
            "request_variant_id": shop["request_variant"]["id"],
            "attack_family": "parameter-review",
            "tool_name": "manual",
            "auth_context": "member",
            "input_slot": "query",
            "result_status": "blocked",
            "evidence_ref": "scans/orders-idor.txt",
            "target_host": "shop.acme.example",
            "target_path": "/orders",
            "no_drain": True,
        },
    )
    assert probe.status_code == 201, probe.text
    for key, kind, ref, retry_state in (
        ("bt-host", "host", "shop.acme.example", "no_retry"),
        ("bt-endpoint", "endpoint", "GET https://shop.acme.example/orders", "blocked_on_dependency"),
        ("bt-path", "endpoint", "/orders", "pending"),
        ("bt-wildcard", "host", "*.acme.example", "retryable"),
        ("bt-other", "host", "api.acme.example", "pending"),
        ("bt-finding", "finding", "VA-001", "pending"),
    ):
        created = client.post(
            f"{BASE}/blocked-techniques",
            json={
                "technique_key": key,
                "technique": "IDOR",
                "target_kind": kind,
                "target_ref": ref,
                "reason": f"{key} reason",
                "retry_state": retry_state,
            },
        )
        assert created.status_code == 201, created.text

    detail = client.get(f"{BASE}/coverage-items/{item_id}").json()
    assert detail["item"]["id"] == item_id
    assert detail["item"]["status"] == "blocked"
    assert detail["item"]["item_host"] == "shop.acme.example"
    assert detail["item"]["latest_reason"] == BLOCKED_REASON
    assert detail["note_lines"] == [
        {"text": "Auto-generated from request observation", "provenance": True},
        {"text": BLOCKED_REASON, "provenance": False},
    ]
    assert detail["work_items"]["total"] == 1
    work = detail["work_items"]["items"][0]
    assert work["id"] == work_item_id
    assert work["retry_count"] == 2
    assert work["terminal_reason"] == "coverage item blocked"
    assert work["triage_rationale"] == "needs second tenant"
    assert detail["probe_runs"]["total"] == 1
    assert detail["probe_runs"]["items"][0]["result_status"] == "blocked"
    assert detail["request_variant"]["id"] == shop["request_variant"]["id"]
    assert detail["request_variant"]["method"] == "GET"
    assert detail["service"] is None

    related = {row["technique_key"]: row for row in detail["blocked_techniques"]}
    assert set(related) == {"bt-host", "bt-endpoint", "bt-path", "bt-wildcard"}
    assert related["bt-wildcard"]["relation"] == "host"
    assert related["bt-host"]["relation"] == "host"
    assert related["bt-endpoint"]["relation"] == "endpoint"
    assert related["bt-path"]["relation"] == "endpoint"
    assert related["bt-endpoint"]["retry_state"] == "blocked_on_dependency"


def test_detail_of_a_service_bound_item_uses_its_target_host(ledger) -> None:
    detail = ledger["client"].get(f"{BASE}/coverage-items/{ledger['api_service_id']}").json()
    assert detail["item"]["item_host"] == "api.acme.example"
    assert detail["service"]["id"] == ledger["api"]["service"]["id"]
    assert detail["request_variant"] is None


def test_detail_is_scoped_and_404s(ledger, isolate_settings) -> None:
    client = ledger["client"]
    assert client.get(f"{BASE}/coverage-items/999999").status_code == 404
    _engagement(client, isolate_settings, OTHER_KEY)
    response = client.get(f"/engagements/{OTHER_KEY}/assessment/coverage-items/{ledger['gf_id']}")
    assert response.status_code == 404
