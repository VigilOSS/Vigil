from __future__ import annotations

from test_engagements_api import write_engagement

KEY = "2026-03-30-120000-example"


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], KEY)
    # Force the engagement into the backend DB.
    assert client.get("/engagements").status_code == 200


# A capture's identity is DERIVED server-side from session-anchor material, so
# there is no operator-facing "default" identity name after a capture. These
# helpers resolve the opaque derived name(s) the way a real consumer does — by
# listing. A stable session-hint cookie (name in the hint set) keeps repeated
# captures of one login coalescing to a single derived identity.
STABLE_SID = "sess-value-abcdef0123456789"


def _identity_names(client):
    listing = client.get(f"/engagements/{KEY}/credentials").json()
    return sorted(listing["identities"])


def _sole_identity(client):
    listing = client.get(f"/engagements/{KEY}/credentials").json()
    names = list(listing["identities"])
    assert len(names) == 1, f"expected exactly one identity, got {names}"
    return names[0], listing["identities"][names[0]]


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
    # Two captures of the SAME login (same session-anchor cookie + bearer) across
    # two hosts must coalesce to ONE derived identity and merge their cookies.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.com",
            "scope_host": "example.com",
            "cookies": {"sid": STABLE_SID},
            "headers": {"Authorization": "Bearer t"},
        },
    )
    # Second capture adds another cookie on a subdomain — same anchor -> refresh.
    mat = client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "app.example.com",
            "scope_host": "example.com",
            "cookies": {"sid": STABLE_SID, "csrf": "2"},
            "headers": {"Authorization": "Bearer t"},
        },
    ).json()
    assert mat["mode"] == "proxy_capture"
    # Flat cookies include both in-scope hosts.
    assert mat["cookies"] == {"sid": STABLE_SID, "csrf": "2"}
    assert mat["headers"]["Authorization"] == "Bearer t"
    assert mat["state"] == "available"
    # First capture made it the (only) identity and active.
    assert mat["is_active"] is True
    # Same login -> exactly one derived identity row (append-only did not fork).
    assert len(_identity_names(client)) == 1


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
    # Establish the derived identity via a capture, then attach a custom field.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.com",
            "scope_host": "example.com",
            "cookies": {"sid": STABLE_SID},
        },
    )
    name, _ = _sole_identity(client)
    client.put(
        f"/engagements/{KEY}/credentials/{name}",
        json={"cookies": {"sid": STABLE_SID}, "custom_weird_field": {"x": 1}},
    )
    # A later refresh of the same login (same anchor) must preserve the extras.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.com",
            "scope_host": "example.com",
            "cookies": {"sid": STABLE_SID, "csrf": "2"},
        },
    )
    got = client.get(f"/engagements/{KEY}/credentials/{name}").json()
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

def test_capture_logout_deleted_value_is_a_noop(client, isolate_settings):
    """A logout capture (all cookies value 'deleted') must never overwrite a live
    session AND must not mint a spurious identity.

    Regression for: CMS F5/APM sends Set-Cookie: MRHSession=deleted on logout,
    which used to wipe the stored MRHSession. Now the deletion filter empties the
    delta -> no session anchor -> the capture derives no identity and is a no-op.
    """
    _seed(client, isolate_settings)
    # 1. Seed a live session (MRHSession is a session-hint cookie -> anchor).
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "abc123valid-session", "F5_ST": "ST2of2id9876"},
        },
    )
    name, before = _sole_identity(client)
    assert before["cookies"]["MRHSession"] == "abc123valid-session"
    assert before["cookies"]["F5_ST"] == "ST2of2id9876"

    # 2. Simulate a logout — deletion-value cookies only.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "deleted", "F5_ST": "deleted"},
        },
    )

    # 3. The stored session is unchanged and no new identity was minted.
    assert _identity_names(client) == [name]
    after = client.get(f"/engagements/{KEY}/credentials/{name}").json()
    assert after["cookies"]["MRHSession"] == "abc123valid-session", (
        "logout 'deleted' value must not overwrite stored live cookie"
    )
    assert after["cookies"]["F5_ST"] == "ST2of2id9876", (
        "logout 'deleted' value must not overwrite stored live cookie"
    )


def test_capture_empty_value_is_a_noop(client, isolate_settings):
    """A cookie with empty value (RFC 6265 deletion) is also a no-op."""
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "alive-session-value"},
        },
    )
    name, _ = _sole_identity(client)
    # Empty-value capture (simulates Max-Age=0 / Expires-past).
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": ""},
        },
    )
    assert _identity_names(client) == [name]
    after = client.get(f"/engagements/{KEY}/credentials/{name}").json()
    assert after["cookies"]["MRHSession"] == "alive-session-value", (
        "empty-value cookie must not wipe a stored live cookie"
    )


def test_capture_fresh_login_appends_new_identity(client, isolate_settings):
    """A different session-anchor value is a DIFFERENT login -> a new identity row
    (append-only, multi-identity). The old row is not overwritten.

    This is the core redesign behavior (Scenario A): logout-then-login on one host
    holds both sessions simultaneously for cross-account IDOR/BOLA testing.
    """
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "old-session-value-1"},
        },
    )
    old_name, _ = _sole_identity(client)
    # New login delivers a fresh valid session cookie (distinct value).
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "brand-new-session-value-2"},
        },
    )
    names = _identity_names(client)
    assert len(names) == 2, "a distinct session anchor must append a new identity"
    old = client.get(f"/engagements/{KEY}/credentials/{old_name}").json()
    assert old["cookies"]["MRHSession"] == "old-session-value-1", (
        "the older distinct session must NOT be clobbered by a new login"
    )
    values = {
        client.get(f"/engagements/{KEY}/credentials/{n}").json()["cookies"]["MRHSession"]
        for n in names
    }
    assert values == {"old-session-value-1", "brand-new-session-value-2"}


def test_capture_mixed_deletion_and_live_within_one_identity(client, isolate_settings):
    """Within one login (stable anchor cookie), a per-cookie deletion in the delta
    must NOT evict a stored cookie, while a genuinely-new live cookie is added."""
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "keep-me-16chars-xx", "F5_ST": "tokenvalue-16chars"},
        },
    )
    name, _ = _sole_identity(client)
    # Same anchor (MRHSession unchanged) -> refresh; F5_ST deletion is filtered.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {
                "MRHSession": "keep-me-16chars-xx",
                "F5_ST": "deleted",
                "new_cookie": "fresh",
            },
        },
    )
    assert _identity_names(client) == [name]
    after = client.get(f"/engagements/{KEY}/credentials/{name}").json()
    assert after["cookies"]["MRHSession"] == "keep-me-16chars-xx"
    # F5_ST deletion in the delta must not evict the stored value.
    assert after["cookies"]["F5_ST"] == "tokenvalue-16chars"
    # The new live cookie is added within the same identity.
    assert after["cookies"]["new_cookie"] == "fresh"


def test_capture_quoted_empty_cookie_is_a_noop(client, isolate_settings):
    """A QUOTED-empty logout cookie (MRHSession="") is a deletion sentinel.

    Its surrounding DQUOTEs must be stripped before the deletion check so the
    unquoted-empty value is recognized and the live session is preserved.
    """
    _seed(client, isolate_settings)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": "alive-session-value"},
        },
    )
    name, _ = _sole_identity(client)
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "example.cms.gov",
            "scope_host": "example.cms.gov",
            "cookies": {"MRHSession": '""'},  # quoted-empty logout
        },
    )
    assert _identity_names(client) == [name]
    after = client.get(f"/engagements/{KEY}/credentials/{name}").json()
    assert after["cookies"]["MRHSession"] == "alive-session-value", (
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
    multi-host session (one login, same anchor) is never undercounted, even when
    each capture passes a different (captured) scope_host.
    """
    _seed(client, isolate_settings)
    # Capture on host A — shared session cookie (the anchor) + a host-A-only cookie.
    client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "a.example.com",
            "scope_host": "a.example.com",
            "cookies": {"sid": STABLE_SID, "a_only": "a-value-16chars-xxxx"},
        },
    )
    # Capture on an UNRELATED host B with scope_host=B — same anchor -> one
    # identity. The legacy scope-filtered flat view would have dropped host A here.
    mat = client.post(
        f"/engagements/{KEY}/credentials/capture",
        json={
            "host": "b.other.com",
            "scope_host": "b.other.com",
            "cookies": {"sid": STABLE_SID, "b_only": "b-value-16chars-xxxx"},
        },
    ).json()
    # One derived identity spans both hosts.
    assert len(_identity_names(client)) == 1
    # Both hosts' cookies are present in the flat view (union, no undercount).
    assert mat["cookies"] == {
        "sid": STABLE_SID,
        "a_only": "a-value-16chars-xxxx",
        "b_only": "b-value-16chars-xxxx",
    }
    # host_cookies remains the authoritative per-host source of truth.
    hosts = {b["host"] for b in mat["host_cookies"]}
    assert hosts == {"a.example.com", "b.other.com"}
