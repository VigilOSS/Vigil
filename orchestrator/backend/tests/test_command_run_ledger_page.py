"""Operator command ledger: server page, facets, attention scope, search, position.

``GET /command-runs`` stays the list ``vigil assess command-run list`` pages. The
Commands view reads ``/command-runs/page`` instead: the whole ledger with a visible
total (never a silently capped window), facet and scope counts computed by the
server, one owner of the "needs attention" rule, lean rows without the duplicated
``command``/``argv`` bulk, and a ``position`` read so Previous/Next walk exactly
the order the grid shows.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module
from tests.test_command_runs_api import ENGAGEMENT_KEY, _base_payload, _post, _write_engagement


BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _record(client, **overrides) -> dict:
    response = _post(client, _base_payload(**overrides))
    assert response.status_code == 201, response.text
    return response.json()


def _update(run_id: int, **columns) -> None:
    assignments = ", ".join(f"{column} = ?" for column in columns)
    with sqlite3.connect(str(db_module.database_path())) as connection:
        connection.execute(
            f"UPDATE assessment_command_runs SET {assignments} WHERE id = ?",
            (*columns.values(), run_id),
        )


@pytest.fixture
def ledger(client, isolate_settings) -> dict[str, dict]:
    _write_engagement(isolate_settings["engagements_dir"])
    runs: dict[str, dict] = {}
    runs["curl_ok"] = _record(
        client,
        command="curl -s https://shop.acme.example/health",
        argv=["curl", "-s", "https://shop.acme.example/health"],
        tool_name="execute_command",
        run_uuid="aa11bb22cc33dd44",
    )
    runs["nmap_failed"] = _record(
        client,
        command="nmap -sV api.acme.example",
        argv=["nmap", "-sV", "api.acme.example"],
        return_code=1,
        success=False,
        status="failed",
        run_uuid="bb22cc33dd44ee55",
        technique="RECON",
        probe_kind="fingerprint",
    )
    runs["httpx_preview"] = _record(
        client,
        command="httpx -l hosts.txt -json",
        argv=["httpx", "-l", "hosts.txt", "-json"],
        tool_name="execute_command",
        run_uuid="cc33dd44ee55ff66",
        technique="RECON",
        probe_kind="fingerprint",
    )
    runs["script_superseded"] = _record(
        client,
        command="bash -lc 'set -euo pipefail; curl -sk https://api.acme.example/v1/users'",
        argv=["bash", "-lc", "set -euo pipefail; curl -sk https://api.acme.example/v1/users"],
        tool_name="execute_command",
        agent_name="web-specialist",
        phase="exploit",
        run_uuid="dd44ee55ff660011",
        technique="BOLA",
        probe_kind="exploit",
    )
    runs["sqlmap_timeout"] = _record(
        client,
        command="sqlmap --batch -u https://shop.acme.example/orders?id=1",
        argv=["sqlmap", "--batch", "-u", "https://shop.acme.example/orders?id=1"],
        tool_name="execute_command",
        agent_name="web-specialist",
        phase="exploit",
        return_code=None,
        timed_out=True,
        success=False,
        status="timed_out",
        run_uuid="ee55ff6600112233",
        technique="SQLI",
        probe_kind="payload",
    )
    _update(runs["httpx_preview"]["id"], output_retention_status="preview_only")
    _update(runs["script_superseded"]["id"], superseded_by_id=runs["curl_ok"]["id"])
    return runs


def _page(client, **params) -> dict:
    response = client.get(f"{BASE}/command-runs/page", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_page_reports_the_whole_ledger_with_lean_rows(client, ledger):
    page = _page(client, limit=2)
    assert page["total"] == 5
    assert page["count"] == 2 and page["has_more"] is True
    # Newest first by default.
    assert [row["id"] for row in page["items"]] == [
        ledger["sqlmap_timeout"]["id"],
        ledger["script_superseded"]["id"],
    ]
    row = page["items"][1]
    assert "command" not in row and "argv" not in row
    assert row["command_preview"].startswith("bash -lc 'set -euo pipefail; curl")
    assert row["command_chars"] == len(ledger["script_superseded"]["command"])
    assert row["tool"] == "curl"
    assert row["target"] == "api.acme.example" and row["target_source"] == "inferred"

    rest = _page(client, limit=2, offset=4)
    assert rest["count"] == 1 and rest["has_more"] is False

    # The point read keeps both the command text and argv.
    detail = client.get(f"{BASE}/command-runs/{row['id']}").json()
    assert detail["command"] == ledger["script_superseded"]["command"]
    assert detail["argv"][0] == "bash"
    assert detail["needs_attention"] is True
    assert detail["attention_reasons"] == [f"superseded by #{ledger['curl_ok']['id']}"]


def test_needs_attention_is_one_server_rule(client, ledger):
    every_row = _page(client, limit=500)["items"]
    reasons = {row["id"]: row["attention_reasons"] for row in every_row}
    assert reasons[ledger["curl_ok"]["id"]] == []
    assert reasons[ledger["nmap_failed"]["id"]] == ["finished unsuccessfully"]
    assert reasons[ledger["httpx_preview"]["id"]] == ["output preview only"]
    assert reasons[ledger["sqlmap_timeout"]["id"]] == ["stopped at its time limit"]
    for row in every_row:
        assert row["needs_attention"] is bool(row["attention_reasons"])

    attention = _page(client, scope="attention", limit=500)
    assert attention["total"] == 4
    assert {row["id"] for row in attention["items"]} == {
        row["id"] for row in every_row if row["needs_attention"]
    }


def test_facets_count_the_whole_ledger_and_ignore_their_own_filter(client, ledger):
    response = client.get(
        f"{BASE}/command-runs/facets", params={"status": "failed", "scope": "attention"}
    )
    assert response.status_code == 200, response.text
    facets = response.json()
    assert facets["total"] == 1
    assert facets["scope_totals"] == {"attention": 1, "all": 1}
    assert facets["engagement_totals"] == {"attention": 4, "all": 5}
    status_counts = {entry["value"]: entry["count"] for entry in facets["facets"]["status"]["values"]}
    # Status ignores its own filter but honours the attention scope.
    assert status_counts == {"failed": 1, "completed": 2, "timed_out": 1}
    tool_counts = {entry["value"]: entry["count"] for entry in facets["facets"]["tool"]["values"]}
    assert tool_counts == {"nmap": 1}

    tools = client.get(f"{BASE}/command-runs/facets").json()["facets"]["tool"]["values"]
    assert {entry["value"]: entry["count"] for entry in tools} == {
        "curl": 2,
        "nmap": 1,
        "httpx": 1,
        "sqlmap": 1,
    }


def test_filters_by_tool_agent_and_status(client, ledger):
    curl = _page(client, tool="curl")
    assert {row["id"] for row in curl["items"]} == {
        ledger["curl_ok"]["id"],
        ledger["script_superseded"]["id"],
    }
    web = _page(client, agent="web-specialist", status=["timed_out", "failed"])
    assert [row["id"] for row in web["items"]] == [ledger["sqlmap_timeout"]["id"]]


def _facet_counts(facets: dict, name: str) -> dict[str, int]:
    return {entry["value"]: entry["count"] for entry in facets["facets"][name]["values"]}


def test_filters_by_technique_and_probe_kind(client, ledger):
    recon = _page(client, technique="RECON")
    assert {row["id"] for row in recon["items"]} == {
        ledger["nmap_failed"]["id"],
        ledger["httpx_preview"]["id"],
    }
    assert recon["total"] == 2
    either = _page(client, technique=["RECON", "SQLI"], probe_kind="payload")
    assert [row["id"] for row in either["items"]] == [ledger["sqlmap_timeout"]["id"]]
    # The blank value selects runs that declared no technique / probe kind.
    undeclared = _page(client, technique="", probe_kind="")
    assert [row["id"] for row in undeclared["items"]] == [ledger["curl_ok"]["id"]]


def test_technique_and_probe_kind_facets_ignore_only_their_own_filter(client, ledger):
    unfiltered = client.get(f"{BASE}/command-runs/facets").json()
    assert _facet_counts(unfiltered, "technique") == {"": 1, "RECON": 2, "BOLA": 1, "SQLI": 1}
    assert _facet_counts(unfiltered, "probe_kind") == {
        "": 1,
        "fingerprint": 2,
        "exploit": 1,
        "payload": 1,
    }
    assert unfiltered["facets"]["technique"]["distinct"] == 4

    response = client.get(
        f"{BASE}/command-runs/facets",
        params={"technique": "RECON", "scope": "attention"},
    )
    assert response.status_code == 200, response.text
    facets = response.json()
    assert facets["total"] == 2
    # Technique ignores its own filter but honours the attention scope.
    assert _facet_counts(facets, "technique") == {"RECON": 2, "BOLA": 1, "SQLI": 1}
    # Every other facet honours the technique filter.
    assert _facet_counts(facets, "probe_kind") == {"fingerprint": 2}
    assert _facet_counts(facets, "tool") == {"nmap": 1, "httpx": 1}

    by_kind = client.get(f"{BASE}/command-runs/facets", params={"probe_kind": "exploit"}).json()
    assert _facet_counts(by_kind, "technique") == {"BOLA": 1}
    assert _facet_counts(by_kind, "probe_kind")["fingerprint"] == 2


def test_position_honours_technique_and_probe_kind(client, ledger):
    params = {"technique": ["RECON", "BOLA"], "probe_kind": ["fingerprint", "exploit"]}
    order = [row["id"] for row in _page(client, limit=500, **params)["items"]]
    assert len(order) == 3
    position = client.get(f"{BASE}/command-runs/{order[1]}/position", params=params).json()
    assert position["index"] == 1 and position["total"] == 3
    assert position["previous"]["id"] == order[0] and position["next"]["id"] == order[2]
    outside = client.get(
        f"{BASE}/command-runs/{ledger['sqlmap_timeout']['id']}/position", params=params
    ).json()
    assert outside["index"] is None


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("dd44ee55", ["script_superseded"]),
        ("tool:sqlmap", ["sqlmap_timeout"]),
        ("rc:!0", ["nmap_failed"]),
        ("rc:timeout", ["sqlmap_timeout"]),
        ("status:failed", ["nmap_failed"]),
        ("target:api.acme.example", ["script_superseded", "nmap_failed"]),
        ("agent:web-specialist orders", ["sqlmap_timeout"]),
        ("hosts.txt", ["httpx_preview"]),
        ("bogus:value", []),
    ],
)
def test_search_runs_server_side(client, ledger, query, expected):
    page = _page(client, q=query)
    assert [row["id"] for row in page["items"]] == [ledger[name]["id"] for name in expected]
    assert page["total"] == len(expected)


def test_search_matches_a_run_id(client, ledger):
    run_id = ledger["httpx_preview"]["id"]
    page = _page(client, q=f"#{run_id}")
    assert [row["id"] for row in page["items"]] == [run_id]


def test_position_walks_the_page_order(client, ledger):
    params = {"scope": "attention"}
    order = [row["id"] for row in _page(client, limit=500, **params)["items"]]
    middle = order[1]
    response = client.get(f"{BASE}/command-runs/{middle}/position", params=params)
    assert response.status_code == 200, response.text
    position = response.json()
    assert position["index"] == 1 and position["total"] == len(order)
    assert position["previous"]["id"] == order[0]
    assert position["next"]["id"] == order[2]
    assert "command" not in position["next"]

    outside = client.get(
        f"{BASE}/command-runs/{ledger['curl_ok']['id']}/position", params=params
    ).json()
    assert outside["index"] is None and outside["previous"] is None and outside["next"] is None

    sorted_order = [row["id"] for row in _page(client, sort="tool", dir="asc", limit=500)["items"]]
    first = client.get(
        f"{BASE}/command-runs/{sorted_order[0]}/position", params={"sort": "tool", "dir": "asc"}
    ).json()
    assert first["index"] == 0 and first["previous"] is None
    assert first["next"]["id"] == sorted_order[1]


@pytest.mark.parametrize("direction", ["desc", "asc"])
def test_status_sort_ranks_by_urgency_and_position_walks_it(client, ledger, direction):
    """Status sorts by the UI's urgency order, not alphabetically: descending is
    most urgent first, ascending least urgent first, ties by id in the same
    direction. A legacy row ranks by the status it shows. Position agrees."""
    for index in range(3):
        _record(client, command=f"curl -s https://shop.acme.example/p{index}", run_uuid=f"ff{index:014d}")
    ids = sorted(row["id"] for row in _page(client, limit=500)["items"])
    stored = ["completed", "queued", "lost", "failed", "running", "killed", "legacy", "failed"]
    assert len(ids) == len(stored)
    for run_id, value in zip(ids, stored):
        _update(run_id, status=value, timed_out=int(value == "legacy"), success=0)
    shown = dict(zip(ids, [value if value != "legacy" else "timed_out" for value in stored]))

    urgency = ["failed", "timed_out", "killed", "lost", "running", "queued", "completed"]
    if direction == "desc":
        expected = sorted(ids, key=lambda run_id: (urgency.index(shown[run_id]), -run_id))
    else:
        expected = sorted(ids, key=lambda run_id: (-urgency.index(shown[run_id]), run_id))

    params = {"sort": "status", "dir": direction}
    rows = _page(client, limit=500, **params)["items"]
    assert [row["id"] for row in rows] == expected
    assert [row["status"] for row in rows] == [shown[run_id] for run_id in expected]
    paged = [row["id"] for offset in range(0, len(ids), 3) for row in _page(client, limit=3, offset=offset, **params)["items"]]
    assert paged == expected

    for index, run_id in enumerate(expected):
        response = client.get(f"{BASE}/command-runs/{run_id}/position", params=params)
        assert response.status_code == 200, response.text
        position = response.json()
        assert position["index"] == index and position["total"] == len(expected)
        assert (position["previous"] or {}).get("id") == (expected[index - 1] if index else None)
        assert (position["next"] or {}).get("id") == (expected[index + 1] if index + 1 < len(expected) else None)


def test_unknown_sort_and_missing_run_are_rejected(client, ledger):
    assert client.get(f"{BASE}/command-runs/page", params={"sort": "command"}).status_code == 422
    assert client.get(f"{BASE}/command-runs/999999/position").status_code == 404


def test_existing_list_contract_is_unchanged(client, ledger):
    rows = client.get(f"{BASE}/command-runs").json()
    assert isinstance(rows, list) and len(rows) == 5
    assert all("command" in row and "argv" in row for row in rows)


def test_attention_sql_and_python_rule_agree_on_every_shape():
    """The SQL scope filter and the reasons shown beside a status are twins."""
    import itertools

    from app.services.state_manager import command_run_queries as queries

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE assessment_command_runs (id INTEGER PRIMARY KEY, status TEXT, "
        "timed_out INTEGER, success INTEGER, partial_results INTEGER, superseded_by_id INTEGER, "
        "output_integrity_status TEXT, output_retention_status TEXT, output_cleanup_status TEXT)"
    )
    shapes = itertools.product(
        ["completed", "failed", "running", "lost", "", "legacy"],
        [0, 1],
        [0, 1, None],
        [0, 1],
        [None, 7],
        ["", "verified", "pending", "WARNING"],
        ["retained", "preview_only", "suppression_pending", "untrusted", "artifact", None],
        ["not_required", "deferred", "complete"],
    )
    connection.executemany(
        "INSERT INTO assessment_command_runs (status, timed_out, success, partial_results, "
        "superseded_by_id, output_integrity_status, output_retention_status, output_cleanup_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        list(shapes),
    )
    rows = connection.execute(
        f"SELECT r.*, {queries._RUN_NEEDS_ATTENTION_SQL} AS sql_flag, "
        f"{queries._RUN_STATUS_SQL} AS sql_status FROM assessment_command_runs AS r"
    ).fetchall()
    assert len(rows) > 1000
    for row in rows:
        assert bool(row["sql_flag"]) is bool(queries.command_run_attention_reasons(row)), dict(row)
        assert row["sql_status"] == queries.command_run_status(row), dict(row)
