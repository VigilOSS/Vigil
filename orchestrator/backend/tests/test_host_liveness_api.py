"""host_liveness store: upsert, keep-newest dedupe, freshness TTL overlay, filters."""
import json
from pathlib import Path

ENGAGEMENT_KEY = "2026-05-29-130000-liveness"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    eng = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "Liveness", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _post(client, rows):
    return client.post(f"{BASE}/host-liveness", json={"rows": rows})


def test_upsert_and_read_round_trip(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = _post(client, [
        {"host": "a.example.com", "status_code": 200, "scheme": "https",
         "host_ip": "1.2.3.4", "reachability_class": "live", "probed_at": "2999-01-01T00:00:00Z"},
        {"host": "b.example.com", "failed": True, "reachability_class": "blackholed",
         "probed_at": "2999-01-01T00:00:00Z"},
    ])
    assert resp.status_code == 200, resp.text
    assert resp.json()["upserted"] == 2

    rows = {r["host"]: r for r in client.get(f"{BASE}/host-liveness").json()}
    assert rows["a.example.com"]["reachability_class"] == "live"
    assert rows["b.example.com"]["reachability_class"] == "blackholed"
    assert "age_seconds" in rows["a.example.com"]


def test_host_is_normalized_and_filterable(client, isolate_settings):
    _seed(client, isolate_settings)
    # scheme + port + path should normalize down to the bare host key.
    _post(client, [{"host": "https://c.example.com:8443/login", "reachability_class": "live",
                    "probed_at": "2999-01-01T00:00:00Z"}])
    rows = client.get(f"{BASE}/host-liveness?host=c.example.com").json()
    assert len(rows) == 1
    assert rows[0]["host"] == "c.example.com"


def test_keep_newest_probe_wins(client, isolate_settings):
    _seed(client, isolate_settings)
    _post(client, [{"host": "d.example.com", "reachability_class": "live",
                    "probed_at": "2999-01-02T00:00:00Z"}])
    # An OLDER probe must NOT overwrite the newer verdict.
    _post(client, [{"host": "d.example.com", "reachability_class": "blackholed",
                    "probed_at": "2999-01-01T00:00:00Z"}])
    rows = client.get(f"{BASE}/host-liveness?host=d.example.com").json()
    assert rows[0]["reachability_class"] == "live"
    # A NEWER probe does overwrite.
    _post(client, [{"host": "d.example.com", "reachability_class": "blackholed",
                    "probed_at": "2999-01-03T00:00:00Z"}])
    rows = client.get(f"{BASE}/host-liveness?host=d.example.com").json()
    assert rows[0]["reachability_class"] == "blackholed"


def test_stale_overlay_degrades_old_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    # An ancient probe stored as 'live' must READ as 'stale' (past the TTL),
    # while the stored value is preserved for audit.
    _post(client, [{"host": "e.example.com", "reachability_class": "live",
                    "probed_at": "2020-01-01T00:00:00Z"}])
    rows = client.get(f"{BASE}/host-liveness?host=e.example.com").json()
    assert rows[0]["reachability_class"] == "stale"
    assert rows[0]["stored_reachability_class"] == "live"
    # fresh_only drops the stale row entirely.
    fresh = client.get(f"{BASE}/host-liveness?host=e.example.com&fresh_only=true").json()
    assert fresh == []


def test_rejects_stale_as_stored_class(client, isolate_settings):
    _seed(client, isolate_settings)
    # 'stale' is a read-time overlay, never an accepted stored class.
    resp = _post(client, [{"host": "f.example.com", "reachability_class": "stale"}])
    assert resp.status_code == 422


def _engagement_id(client) -> int:
    return client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"]


def test_coverage_rollup_splits_by_reachability(client, isolate_settings):
    _seed(client, isolate_settings)
    from app.services import state_manager

    eid = _engagement_id(client)
    with state_manager.get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO assessment_services (engagement_id, endpoint, port, protocol) "
            "VALUES (?, 'reachable.example.com:443', 443, 'tcp')", (eid,))
        svc_live = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO assessment_services (engagement_id, endpoint, port, protocol) "
            "VALUES (?, 'black.example.com:443', 443, 'tcp')", (eid,))
        svc_black = cur.lastrowid
        # 2 coverage items on the reachable host, 1 on the blackholed host.
        # Vary attack_family so each row is distinct under the natural-key index.
        for i, svc in enumerate((svc_live, svc_live, svc_black)):
            conn.execute(
                "INSERT INTO assessment_coverage_items "
                "(engagement_id, service_id, auth_context, input_slot, attack_family, status) "
                "VALUES (?, ?, 'anonymous', 'service', ?, 'pending')", (eid, svc, f"fam{i}"))

    _post(client, [
        {"host": "reachable.example.com", "reachability_class": "live", "probed_at": "2999-01-01T00:00:00Z"},
        {"host": "black.example.com", "reachability_class": "blackholed", "probed_at": "2999-01-01T00:00:00Z"},
    ])

    rollup = client.get(f"{BASE}/summary").json()["coverage_by_reachability"]
    assert rollup["total"] == 3
    assert rollup["reachable"] == 2
    assert rollup["blackholed"] == 1
    assert rollup["unprobed"] == 0
