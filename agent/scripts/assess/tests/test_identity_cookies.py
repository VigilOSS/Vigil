"""Identity host-cookie jar projection (I-22).

The credential store keeps captured cookies in per-host buckets
(``host_cookies = [{"host": ..., "cookies": {...}}, ...]``). The flat ``cookies``
view is scoped to the engagement's PRIMARY scope host at capture time, so a
cookie-session app on a DIFFERENT host (an F5 APM / SiteMinder portal, a sibling
subdomain with its own JSESSIONID) gets sent the flat (mismatched/empty) cookie
view and reads the request as "session stale" — a fail-closed false negative.

The read side now projects the request-host-scoped bucket into the injected
``Cookie:`` header the way a browser sends it, and WARNs when an identity carries
captured host_cookies that this run is not using.
"""
from __future__ import annotations

from assess.lib import auth, identity, kali


def _material(**over):
    # Two NON-overlapping buckets (portal vs sibling api) so the exact-host
    # selection is unambiguous — neither is a parent domain of the other.
    base = {
        "mode": "proxy_capture",
        "cookies": {"flat": "1"},  # scope-flat view (primary host)
        "host_cookies": [
            {"host": "portal.example.com", "cookies": {"JSESSIONID": "PORTAL"}},
            {"host": "api.example.com", "cookies": {"apikey": "K"}},
        ],
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# identity.host_cookies_for — browser-faithful per-host selection
# --------------------------------------------------------------------------- #

def test_host_cookies_for_exact_host() -> None:
    got = identity.host_cookies_for(_material(), "portal.example.com")
    assert got == {"JSESSIONID": "PORTAL"}


def test_host_cookies_for_parent_domain_cookie_sent_to_subdomain() -> None:
    # A cookie set on example.com is sent to app.example.com (browser semantics).
    mat = {"host_cookies": [{"host": "example.com", "cookies": {"root": "R"}}]}
    assert identity.host_cookies_for(mat, "app.example.com") == {"root": "R"}


def test_host_cookies_for_exact_overlays_parent_on_collision() -> None:
    mat = _material(host_cookies=[
        {"host": "example.com", "cookies": {"k": "parent"}},
        {"host": "app.example.com", "cookies": {"k": "exact"}},
    ])
    assert identity.host_cookies_for(mat, "app.example.com")["k"] == "exact"


def test_host_cookies_for_no_match_returns_empty() -> None:
    assert identity.host_cookies_for(_material(), "unrelated.test") == {}


def test_host_cookie_hosts_lists_buckets() -> None:
    assert set(identity.host_cookie_hosts(_material())) == {"portal.example.com", "api.example.com"}
    assert identity.host_cookie_hosts({"cookies": {"a": "b"}}) == []


# --------------------------------------------------------------------------- #
# _identity_header_pairs — host-scoped Cookie header alongside the Bearer
# --------------------------------------------------------------------------- #

def test_pairs_inject_host_scoped_cookie_and_bearer() -> None:
    mat = _material(tokens={"access_token": "tok"})
    pairs = kali._identity_header_pairs(mat, request_host="portal.example.com")
    headers = dict(pairs)
    # The portal session rides as a Cookie header.
    assert "JSESSIONID=PORTAL" in headers["Cookie"]
    assert headers["Authorization"] == "Bearer tok"


def test_pairs_overlay_host_cookies_on_flat_view() -> None:
    pairs = kali._identity_header_pairs(_material(), request_host="portal.example.com")
    cookie = dict(pairs)["Cookie"]
    # Flat view is still present (back-compat) and the host bucket is added.
    assert "flat=1" in cookie
    assert "JSESSIONID=PORTAL" in cookie


def test_pairs_without_host_cookies_unchanged() -> None:
    pairs = kali._identity_header_pairs({"cookies": {"s": "b"}}, request_host="x.test")
    assert dict(pairs)["Cookie"] == "s=b"


# --------------------------------------------------------------------------- #
# _apply_identity_material — injects per request host + warns on unused buckets
# --------------------------------------------------------------------------- #

def test_apply_injects_portal_session_for_portal_target() -> None:
    cmd = ["curl", "-s", "https://portal.example.com/my.policy"]
    applied = kali._apply_identity_material(cmd, "curl", _material())
    assert applied is True
    joined = " ".join(cmd)
    assert "Cookie: " in joined
    assert "JSESSIONID=PORTAL" in joined


def test_apply_warns_when_host_cookies_unused_for_request_host(capsys) -> None:
    # The identity has buckets for portal/example.com but the run targets a host
    # with NO matching bucket — warn so the session-stale risk is visible.
    cmd = ["curl", "-s", "https://nomatch.test/x"]
    applied = kali._apply_identity_material(cmd, "curl", _material())
    assert applied is True
    err = capsys.readouterr().err
    assert "host_cookies" in err
    assert "nomatch.test" in err


def test_apply_no_warn_when_bucket_matches(capsys) -> None:
    cmd = ["curl", "-s", "https://portal.example.com/x"]
    kali._apply_identity_material(cmd, "curl", _material())
    assert "carries captured host_cookies" not in capsys.readouterr().err


def test_apply_non_injectable_tool_returns_false() -> None:
    # nmap takes no -H; identity must not be stamped (matches existing contract).
    cmd = ["nmap", "-sV", "portal.example.com"]
    assert kali._apply_identity_material(cmd, "nmap", _material()) is False


# --------------------------------------------------------------------------- #
# auth_runtime_snapshot — host_cookies count as session material (no false stale)
# --------------------------------------------------------------------------- #

def test_snapshot_treats_host_cookies_as_available_session(monkeypatch) -> None:
    from assess.lib import creds_client

    monkeypatch.setattr(
        creds_client, "active_material",
        lambda _eng: {
            "mode": "proxy_capture",
            "cookies": {},  # flat view empty (capture host != primary scope)
            "headers": {},
            "host_cookies": [{"host": "portal.example.com", "cookies": {"JSESSIONID": "P"}}],
        },
    )
    snap = auth.auth_runtime_snapshot("/eng")
    assert snap["host_cookies"]  # surfaced
    assert snap["state"] == "available"
    assert snap["active_use"] is True
    assert snap["auth_context"] != "anonymous"


def test_snapshot_no_session_material_still_missing(monkeypatch) -> None:
    from assess.lib import creds_client

    monkeypatch.setattr(
        creds_client, "active_material",
        lambda _eng: {"mode": "manual", "cookies": {}, "headers": {}, "host_cookies": []},
    )
    snap = auth.auth_runtime_snapshot("/eng")
    assert snap["state"] == "missing"
