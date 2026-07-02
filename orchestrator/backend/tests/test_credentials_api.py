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


def test_resolve_identity_uses_single_row_lookup(client, isolate_settings, monkeypatch):
    _seed(client, isolate_settings)
    client.put(
        f"/engagements/{KEY}/credentials/user_a",
        json={"cookies": {"sid": "a"}, "make_active": True},
    )
    client.put(
        f"/engagements/{KEY}/credentials/user_b",
        json={"cookies": {"sid": "b"}},
    )

    from app.services import credentials as creds_service

    def fail_list_credentials(_engagement_id):
        raise AssertionError("resolve should not list every credential row")

    monkeypatch.setattr(creds_service.db, "list_credentials", fail_list_credentials)

    resolved = client.get(f"/engagements/{KEY}/credentials/resolve")
    assert resolved.status_code == 200
    assert resolved.json()["identity_name"] == "user_a"

    explicit = client.get(
        f"/engagements/{KEY}/credentials/resolve", params={"identity": "user_b"}
    )
    assert explicit.status_code == 200
    assert explicit.json()["material"]["cookies"] == {"sid": "b"}


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


def test_liveness_signature_round_trips(client, isolate_settings):
    # `material.liveness` is the operator-set session-liveness signature consumed by
    # `vigil auth status --probe` / assess auth-status. It is NOT a modeled column, so
    # it must survive verbatim through upsert_material -> raw_json -> row_to_material
    # (same passthrough as material.csrf). Lock the contract: if `liveness` were ever
    # added to _MODELED_KEYS or otherwise mangled, this fails.
    _seed(client, isolate_settings)
    signature = {"expect_status": 200, "authed_marker": "Sign out", "dead_marker": "Log in"}
    put = client.put(
        f"/engagements/{KEY}/credentials/default",
        json={"cookies": {"sid": "a"}, "liveness": signature},
    ).json()
    assert put.get("liveness") == signature
    got = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert got.get("liveness") == signature


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


# ---------------------------------------------------------------------------
# Logout / deletion-cookie guard (the bug: a logout Set-Cookie wiped the store)
# ---------------------------------------------------------------------------

def test_capture_logout_deleted_value_does_not_wipe_stored_cookie(client, isolate_settings):
    """A logout Set-Cookie with value 'deleted' must never overwrite a live session.

    Regression for: CMS F5/APM sends Set-Cookie: MRHSession=deleted on logout,
    which used to wipe the stored MRHSession for ALL concurrent engagements.
    """
    _seed(client, isolate_settings)
    # 1. Seed a live session.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "abc123valid", "F5_ST": "ST2of2id9876"},
        },
    )
    # Confirm the live session is stored.
    before = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert before["cookies"]["MRHSession"] == "abc123valid"
    assert before["cookies"]["F5_ST"] == "ST2of2id9876"

    # 2. Simulate a logout — backend receives deletion-value cookies.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "deleted", "F5_ST": "deleted"},
        },
    )

    # 3. The stored session must be unchanged — logout is a no-op at the store.
    after = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert after["cookies"]["MRHSession"] == "abc123valid", (
        "logout 'deleted' value must not overwrite stored live cookie"
    )
    assert after["cookies"]["F5_ST"] == "ST2of2id9876", (
        "logout 'deleted' value must not overwrite stored live cookie"
    )


def test_capture_empty_value_does_not_wipe_stored_cookie(client, isolate_settings):
    """A cookie with empty value (RFC 6265 deletion) is also treated as a no-op."""
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "alive-session"},
        },
    )
    # Empty-value capture (simulates Max-Age=0 / Expires-past that proxy already stripped).
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": ""},
        },
    )
    after = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert after["cookies"]["MRHSession"] == "alive-session", (
        "empty-value cookie must not wipe a stored live cookie"
    )


def test_capture_fresh_login_cookie_updates_stored_value(client, isolate_settings):
    """A fresh non-deletion Set-Cookie (real login) must update the stored value."""
    _seed(client, isolate_settings)
    # Seed old session.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "old-session"},
        },
    )
    # New login delivers a fresh valid cookie.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "brand-new-session"},
        },
    )
    after = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert after["cookies"]["MRHSession"] == "brand-new-session", (
        "a fresh valid cookie value must replace the old one"
    )


def test_capture_mixed_deletion_and_live_cookies(client, isolate_settings):
    """Mixed payload: only live (non-deletion) cookies in the delta are applied."""
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "live", "other": "value"},
        },
    )
    # Delta contains one deletion and one new live cookie.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "deleted", "new_cookie": "fresh"},
        },
    )
    after = client.get(f"/engagements/{KEY}/credentials/default").json()
    # MRHSession must not be overwritten.
    assert after["cookies"]["MRHSession"] == "live"
    # The new live cookie must be added.
    assert after["cookies"]["new_cookie"] == "fresh"


def test_capture_quoted_empty_cookie_does_not_wipe_stored(client, isolate_settings):
    """A QUOTED-empty logout cookie (MRHSession="") is a deletion sentinel.

    Its surrounding DQUOTEs must be stripped before the deletion check so the
    unquoted-empty value is recognized and the live session is preserved.
    """
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "alive-session"},
        },
    )
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": '""'},  # quoted-empty logout
        },
    )
    after = client.get(f"/engagements/{KEY}/credentials/default").json()
    assert after["cookies"]["MRHSession"] == "alive-session", (
        "quoted-empty logout cookie must not wipe a stored live cookie"
    )


def test_capture_quoted_live_cookie_stored_dequoted(client, isolate_settings):
    """A live quoted cookie value must be STORED without its surrounding quotes
    so a later injection does not double-quote it."""
    _seed(client, isolate_settings)
    mat = client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"sid": '"abc123"'},
        },
    ).json()
    assert mat["cookies"]["sid"] == "abc123", "quoted value must be stored dequoted"


def test_capture_flat_cookies_union_across_hosts(client, isolate_settings):
    """The flat ``cookies`` view must UNION across every captured host bucket so a
    multi-host session is never undercounted, even when each capture passes a
    different (captured) scope_host.
    """
    _seed(client, isolate_settings)
    # Capture on host A with its own scope_host.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "a.example.com",
            "scope_host": "a.example.com",
            "cookies": {"sid_a": "1"},
        },
    )
    # Capture on an UNRELATED host B with scope_host=B — the legacy scope-filtered
    # flat view would have dropped host A's cookie here.
    mat = client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "identity_name": "default",
            "host": "b.other.com",
            "scope_host": "b.other.com",
            "cookies": {"sid_b": "2"},
        },
    ).json()
    # Both hosts' cookies are present in the flat view (union, no undercount).
    assert mat["cookies"] == {"sid_a": "1", "sid_b": "2"}
    # host_cookies remains the authoritative per-host source of truth.
    hosts = {b["host"] for b in mat["host_cookies"]}
    assert hosts == {"a.example.com", "b.other.com"}
