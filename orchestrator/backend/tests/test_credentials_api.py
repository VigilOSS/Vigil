from __future__ import annotations

from test_engagements_api import write_engagement

KEY = "2026-03-30-120000-example"


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], KEY)
    # Force the engagement into the backend DB.
    assert client.get("/engagements").status_code == 200


def test_empty_engagement_has_no_identities(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.get(f"/engagements/{KEY}/credentials")
    assert resp.status_code == 200
    body = resp.json()
    assert body["identities"] == {}
    # resolve with no identities returns (None, {}) so callers keep legacy behavior
    resolved = client.get(f"/engagements/{KEY}/credentials/resolve").json()
    assert resolved["identity_name"] is None
    assert resolved["material"] == {}


def test_put_and_get_identity_roundtrip(client, isolate_settings):
    _seed(client, isolate_settings)
    payload = {
        "mode": "manual",
        "cookies": {"sid": "abc"},
        "headers": {"Authorization": "Bearer xyz"},
        "make_active": True,
    }
    put = client.put(f"/engagements/{KEY}/credentials/user_a", json=payload)
    assert put.status_code == 200
    material = put.json()
    assert material["cookies"] == {"sid": "abc"}
    assert material["headers"]["Authorization"] == "Bearer xyz"
    assert material["state"] == "available"  # derived from material presence
    assert material["is_active"] is True

    got = client.get(f"/engagements/{KEY}/credentials/user_a").json()
    assert got["cookies"] == {"sid": "abc"}

    listing = client.get(f"/engagements/{KEY}/credentials").json()
    assert set(listing["identities"]) == {"user_a"}
    assert listing["active_identity"] == "user_a"


def test_multi_identity_and_activation(client, isolate_settings):
    _seed(client, isolate_settings)
    client.put(
        f"/engagements/{KEY}/credentials/user_a",
        json={"cookies": {"sid": "a"}, "make_active": True},
    )
    client.put(
        f"/engagements/{KEY}/credentials/user_b",
        json={"cookies": {"sid": "b"}},
    )
    # default resolve picks the active (user_a)
    resolved = client.get(f"/engagements/{KEY}/credentials/resolve").json()
    assert resolved["identity_name"] == "user_a"
    assert resolved["material"]["cookies"] == {"sid": "a"}

    # activate user_b -> resolve flips
    act = client.post(f"/engagements/{KEY}/credentials/user_b/activate")
    assert act.status_code == 200
    resolved = client.get(f"/engagements/{KEY}/credentials/resolve").json()
    assert resolved["identity_name"] == "user_b"

    # explicit identity resolve
    resolved_a = client.get(
        f"/engagements/{KEY}/credentials/resolve", params={"identity": "user_a"}
    ).json()
    assert resolved_a["material"]["cookies"] == {"sid": "a"}

    # unknown identity resolves to (name, {}) — caller warns, intent recorded
    ghost = client.get(
        f"/engagements/{KEY}/credentials/resolve", params={"identity": "ghost"}
    ).json()
    assert ghost["identity_name"] == "ghost"
    assert ghost["material"] == {}


def test_capture_merges_cookies_across_calls(client, isolate_settings):
    _seed(client, isolate_settings)
    # First capture on the scope host.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.com",
            "scope_host": "example.com",
            "cookies": {"sid": "1"},
        },
    )
    # Second capture adds another cookie on a subdomain in scope.
    mat = client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "app.example.com",
            "scope_host": "example.com",
            "cookies": {"csrf": "2"},
            "headers": {"Authorization": "Bearer t"},
        },
    ).json()
    assert mat["mode"] == "proxy_capture"
    # Flat cookies include both in-scope hosts.
    assert mat["cookies"] == {"sid": "1", "csrf": "2"}
    assert mat["headers"]["Authorization"] == "Bearer t"
    assert mat["state"] == "available"
    # First capture made it the (only) identity and active.
    assert mat["is_active"] is True


def test_raw_json_preserves_unmodeled_fields(client, isolate_settings):
    _seed(client, isolate_settings)
    mat = client.put(
        f"/engagements/{KEY}/credentials/default",
        json={"cookies": {"sid": "a"}, "notes": "n", "custom_weird_field": {"x": 1}},
    ).json()
    # Unmodeled field survives via raw_json round-trip.
    got = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert got.get("custom_weird_field") == {"x": 1}
    assert mat["notes"] == "n"


def test_capture_preserves_existing_raw_json_extras(client, isolate_settings):
    # PR #40: a proxy capture (cookies/headers only) must NOT wipe previously
    # imported/edited raw_json extras — a benign cookie refresh used to reset the
    # raw column to {} and silently drop custom token/session shapes.
    _seed(client, isolate_settings)
    client.put(
        f"/engagements/{KEY}/credentials/default",
        json={"cookies": {"sid": "a"}, "custom_weird_field": {"x": 1}},
    )
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.com",
            "scope_host": "example.com",
            "cookies": {"csrf": "2"},
        },
    )
    got = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert got.get("custom_weird_field") == {"x": 1}  # raw extras preserved
    assert got["cookies"].get("csrf") == "2"           # capture delta still applied


def test_delete_one_and_all(client, isolate_settings):
    _seed(client, isolate_settings)
    client.put(f"/engagements/{KEY}/credentials/user_a", json={"cookies": {"s": "a"}})
    client.put(f"/engagements/{KEY}/credentials/user_b", json={"cookies": {"s": "b"}})
    assert client.delete(f"/engagements/{KEY}/credentials/user_a").status_code == 204
    listing = client.get(f"/engagements/{KEY}/credentials").json()
    assert set(listing["identities"]) == {"user_b"}
    assert client.delete(f"/engagements/{KEY}/credentials").status_code == 204
    listing = client.get(f"/engagements/{KEY}/credentials").json()
    assert listing["identities"] == {}


def test_credentials_404_for_unknown_engagement(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.get("/engagements/nope/credentials").status_code == 404
