"""Per-session liveness-persist route (WS4).

`POST /engagements/{key}/credentials/{identity}/liveness` records an LLM-owned
probe verdict and reconciles session state through `db.set_liveness`:
  * dead    -> state=dead   (only a proven-dead probe kills a session)
  * live    -> state=available (clears an age-backstop `stale` mark)
  * unknown -> state untouched (never a false verdict)
404 when the identity is absent; 422 for a verdict outside {live,dead,unknown}.
"""
from __future__ import annotations

from test_engagements_api import write_engagement

KEY = "2026-03-30-120000-example"


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], KEY)
    assert client.get("/engagements").status_code == 200


def _put_identity(client, name="user_a", state=None):
    payload = {"cookies": {"sid": "abc"}, "make_active": True}
    if state is not None:
        payload["state"] = state
    return client.put(f"/engagements/{KEY}/credentials/{name}", json=payload)


def test_liveness_dead_marks_state_dead(client, isolate_settings):
    _seed(client, isolate_settings)
    _put_identity(client)
    resp = client.post(
        f"/engagements/{KEY}/credentials/user_a/liveness",
        json={"verdict": "dead", "probed_at": "2026-07-03T12:00:00Z"},
    )
    assert resp.status_code == 200
    mat = resp.json()
    assert mat["liveness_verdict"] == "dead"
    assert mat["state"] == "dead"
    assert mat["last_probed_at"] == "2026-07-03T12:00:00Z"
    # A dead session is hidden from the default list, visible with include_dead.
    default_listing = client.get(f"/engagements/{KEY}/credentials").json()
    assert "user_a" not in default_listing["identities"]
    dead_listing = client.get(
        f"/engagements/{KEY}/credentials", params={"include_dead": "true"}
    ).json()
    assert "user_a" in dead_listing["identities"]


def test_liveness_live_sets_available_and_clears_stale(client, isolate_settings):
    _seed(client, isolate_settings)
    # Seed the identity into a `stale` state (as the age backstop would).
    _put_identity(client, state="stale")
    got = client.get(f"/engagements/{KEY}/credentials/user_a").json()
    assert got["state"] == "stale"
    resp = client.post(
        f"/engagements/{KEY}/credentials/user_a/liveness",
        json={"verdict": "live", "probed_at": "2026-07-03T12:00:00Z"},
    )
    assert resp.status_code == 200
    mat = resp.json()
    assert mat["liveness_verdict"] == "live"
    assert mat["state"] == "available"  # a live probe cleared the stale mark


def test_liveness_unknown_leaves_state_untouched(client, isolate_settings):
    _seed(client, isolate_settings)
    _put_identity(client)  # state=available
    resp = client.post(
        f"/engagements/{KEY}/credentials/user_a/liveness",
        json={"verdict": "unknown", "probed_at": None},
    )
    assert resp.status_code == 200
    mat = resp.json()
    assert mat["liveness_verdict"] == "unknown"
    # unknown never marks a session dead and never invents a live verdict.
    assert mat["state"] == "available"
    # Typed liveness records when the unknown observation occurred even though
    # it deliberately leaves the credential lifecycle state unchanged.
    assert mat["last_probed_at"]


def test_liveness_404_for_unknown_identity(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(
        f"/engagements/{KEY}/credentials/ghost/liveness",
        json={"verdict": "live", "probed_at": None},
    )
    assert resp.status_code == 404


def test_liveness_422_for_bad_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    _put_identity(client)
    resp = client.post(
        f"/engagements/{KEY}/credentials/user_a/liveness",
        json={"verdict": "alive-probably", "probed_at": None},
    )
    assert resp.status_code == 422


def test_liveness_verdict_is_case_insensitive(client, isolate_settings):
    _seed(client, isolate_settings)
    _put_identity(client)
    resp = client.post(
        f"/engagements/{KEY}/credentials/user_a/liveness",
        json={"verdict": "DEAD", "probed_at": None},
    )
    assert resp.status_code == 200
    assert resp.json()["state"] == "dead"
