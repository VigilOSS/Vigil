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
