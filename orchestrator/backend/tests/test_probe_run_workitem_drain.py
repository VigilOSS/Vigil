"""A3: POST /probe-runs work-buffer drain + opt-in surface resolve.

Recording a probe with ``work_item_ids`` marks those ``assessment_work_items``
rows ``done`` in the SAME transaction as the probe insert, so "remaining work"
bucket counts (``/work-items/stats``) decrement as probes land. Unknown ids are
skipped rather than crashing the probe write. The opt-in ``resolve_surface_id``
advances a mapped surface to ``partially-covered``; omitting it leaves surface
state untouched (recording never auto-mutates it).
"""
import json

ENGAGEMENT_KEY = "2026-07-08-000000-probedrain"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    eng = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "Drain", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _make_work_item(client, url: str, case_type: str = "api") -> int:
    """Derive one pending work item from a request-observation; return its id."""
    resp = client.post(
        f"{BASE}/request-observations",
        json={
            "url": url,
            "method": "GET",
            "query_schema": {"q": "string"},
            "discovery_source": "test",
            "work_item": {"case_type": case_type, "status": "pending"},
        },
    )
    assert resp.status_code == 201, resp.text
    return int(resp.json()["work_item"]["id"])


def _pending_count(client) -> int:
    stats = client.get(f"{BASE}/work-items/stats").json()
    return {row["status"]: row["count"] for row in stats["status"]}.get("pending", 0)


def _probe_payload(**overrides) -> dict:
    base = {
        "attack_family": "idor",
        "tool_name": "manual",
        "target_host": "app.example",
        "target_path": "/api/a",
        "auth_context": "member",
        "input_slot": "path:id",
        "result_status": "tested",
        "evidence_ref": "scans/idor.txt",
    }
    base.update(overrides)
    return base


def test_probe_run_drains_work_items(client, isolate_settings):
    _seed(client, isolate_settings)
    a = _make_work_item(client, "https://app.example/api/a")
    b = _make_work_item(client, "https://app.example/api/b")
    assert _pending_count(client) == 2

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload(work_item_ids=[a, b]))
    assert resp.status_code == 201, resp.text
    assert resp.json()["work_items_done"]["affected"] == 2

    # The two ids are now done → pending count dropped to 0.
    assert _pending_count(client) == 0
    done_rows = client.get(f"{BASE}/work-items?status=done").json()
    assert {row["id"] for row in done_rows} == {a, b}


def test_probe_run_unknown_work_item_id_is_skipped(client, isolate_settings):
    _seed(client, isolate_settings)
    a = _make_work_item(client, "https://app.example/api/only")

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            attack_family="sqli",
            target_path="/api/only",
            input_slot="query:q",
            evidence_ref="scans/sqli.txt",
            work_item_ids=[a, 999999],
        ),
    )
    # A stale id neither 4xxs nor rolls back the probe write — only the real id
    # drains (mirrors POST /work-items/done).
    assert resp.status_code == 201, resp.text
    assert resp.json()["work_items_done"]["affected"] == 1
    assert _pending_count(client) == 0


def test_probe_run_without_work_item_ids_leaves_buffer(client, isolate_settings):
    _seed(client, isolate_settings)
    _make_work_item(client, "https://app.example/api/a")
    assert _pending_count(client) == 1

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload())
    assert resp.status_code == 201, resp.text
    # No drain requested → buffer untouched, no drain summary on the response.
    assert "work_items_done" not in resp.json()
    assert _pending_count(client) == 1


def _make_surface(client, descriptor: str) -> int:
    resp = client.post(
        f"{BASE}/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": descriptor,
            "source_name": "test",
            "rationale": "seed",
            "evidence_ref": "",
            "status": "discovered",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "discovered"
    return int(body["id"])


def test_probe_run_opt_in_resolves_surface(client, isolate_settings):
    _seed(client, isolate_settings)
    sid = _make_surface(client, "app.example/api/orders/{id}")

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(target_path="/api/orders/1", resolve_surface_id=sid),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["surface_resolved"]["status"] == "partially-covered"


def test_probe_run_without_resolve_surface_leaves_surface_untouched(client, isolate_settings):
    _seed(client, isolate_settings)
    sid = _make_surface(client, "app.example/api/carts/{id}")

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload(target_path="/api/carts/1"))
    assert resp.status_code == 201, resp.text
    # No opt-in → no surface mutation, no resolve summary on the response.
    assert "surface_resolved" not in resp.json()
    surfaces = client.get(f"{BASE}/surfaces").json()
    by_id = {row["id"]: row for row in surfaces}
    assert by_id[sid]["status"] == "discovered"
