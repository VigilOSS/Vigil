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


def test_pairs_use_host_bucket_alone_not_flat_union() -> None:
    # When the request host HAS a matching bucket, ONLY that bucket's cookies ride
    # the request. The flat ``cookies`` view is a cross-host UNION, so blending it
    # in would leak another host's uniquely-named session cookie into this request.
    cookie = dict(kali._identity_header_pairs(_material(), request_host="portal.example.com"))["Cookie"]
    assert "JSESSIONID=PORTAL" in cookie
    # api.example.com's cookie must NOT ride a portal request (cross-host leak).
    assert "apikey" not in cookie
    # the standalone flat view is not blended when a bucket matched.
    assert "flat=1" not in cookie


def test_pairs_fall_back_to_flat_when_no_bucket_matches() -> None:
    # A host with no matching bucket falls back to the flat view (manual/legacy
    # identities, or a host we never captured a bucket for).
    cookie = dict(kali._identity_header_pairs(_material(), request_host="unrelated.test")).get("Cookie", "")
    assert cookie == "flat=1"


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
    # Honesty (#3): material present ("available") is NOT proof the session is live.
    # The snapshot never probes, so it must report liveness as "unknown" — never a
    # false "fresh"/"live". A live verdict requires `auth-status --probe`.
    assert snap["liveness"] == "unknown"


def test_snapshot_no_session_material_still_missing(monkeypatch) -> None:
    from assess.lib import creds_client

    monkeypatch.setattr(
        creds_client, "active_material",
        lambda _eng: {"mode": "manual", "cookies": {}, "headers": {}, "host_cookies": []},
    )
    snap = auth.auth_runtime_snapshot("/eng")
    assert snap["state"] == "missing"
    assert snap["liveness"] == "unknown"


# --------------------------------------------------------------------------- #
# CSRF double-submit — opt-in, method-gated (#4)
# --------------------------------------------------------------------------- #

def _csrf_material(**over):
    base = {
        "cookies": {"PORTAL-XSRF-TOKEN": "tok123", "SESSION": "s"},
        "csrf": {"cookie": "PORTAL-XSRF-TOKEN", "header": "PORTAL-X-CSRF-TOKEN"},
    }
    base.update(over)
    return base


def test_request_is_state_changing_detects_methods_and_body() -> None:
    sch = kali._request_is_state_changing
    assert sch(["curl", "-X", "POST", "u"]) is True
    assert sch(["curl", "-XPUT", "u"]) is True
    assert sch(["curl", "--request", "DELETE", "u"]) is True
    assert sch(["curl", "--request=PATCH", "u"]) is True
    assert sch(["curl", "-d", "a=1", "u"]) is True
    assert sch(["curl", "--data-raw", "x", "u"]) is True
    assert sch(["curl", "--json", "{}", "u"]) is True
    # Read-only / unclassifiable → False (fail-safe: no CSRF header).
    assert sch(["curl", "-s", "u"]) is False
    assert sch(["curl", "-X", "GET", "u"]) is False
    assert sch(["curl", "-I", "u"]) is False
    # -G/--get sends a GET with -d moved to the query string → NOT state-changing.
    assert sch(["curl", "-G", "-d", "a=1", "u"]) is False
    assert sch(["curl", "--get", "--data-urlencode", "q=x", "u"]) is False
    # An explicit safe verb is authoritative even with a -d body attached.
    assert sch(["curl", "-X", "GET", "-d", "a=1", "u"]) is False
    assert sch(["curl", "-XHEAD", "-d", "a=1", "u"]) is False
    # An explicit state-changing verb still wins even alongside -G.
    assert sch(["curl", "-X", "POST", "-G", "-d", "a=1", "u"]) is True


def test_csrf_header_absent_on_get() -> None:
    pairs = kali._identity_header_pairs(_csrf_material(), request_host="", state_changing=False)
    headers = dict(pairs)
    assert "PORTAL-X-CSRF-TOKEN" not in headers
    assert "PORTAL-XSRF-TOKEN=tok123" in headers["Cookie"]  # cookie still rides


def test_csrf_header_present_on_post_from_named_cookie() -> None:
    pairs = kali._identity_header_pairs(_csrf_material(), request_host="", state_changing=True)
    assert dict(pairs)["PORTAL-X-CSRF-TOKEN"] == "tok123"


def test_csrf_missing_named_cookie_no_header_no_crash() -> None:
    mat = _csrf_material(cookies={"SESSION": "s"})  # the named XSRF cookie is absent
    pairs = kali._identity_header_pairs(mat, request_host="", state_changing=True)
    assert "PORTAL-X-CSRF-TOKEN" not in dict(pairs)


def test_csrf_other_cookie_mapping_no_header() -> None:
    # csrf maps a cookie name that this request's cookie view does not carry.
    mat = _csrf_material(csrf={"cookie": "NOT-PRESENT", "header": "X-CSRF"})
    pairs = kali._identity_header_pairs(mat, request_host="", state_changing=True)
    assert "X-CSRF" not in dict(pairs)


def test_csrf_mapping_absent_unchanged_behavior() -> None:
    mat = {"cookies": {"SESSION": "s"}}  # no csrf mapping at all
    pairs = kali._identity_header_pairs(mat, request_host="", state_changing=True)
    assert dict(pairs) == {"Cookie": "SESSION=s"}


def test_csrf_pre_existing_header_not_overwritten() -> None:
    mat = _csrf_material(headers={"PORTAL-X-CSRF-TOKEN": "operator-set"})
    pairs = kali._identity_header_pairs(mat, request_host="", state_changing=True)
    values = [v for n, v in pairs if n.lower() == "portal-x-csrf-token"]
    assert values == ["operator-set"]  # single, mirror of the Authorization guard


def test_apply_injects_csrf_on_post() -> None:
    cmd = ["curl", "-X", "POST", "-d", "x=1", "https://portal.example.com/api/write"]
    assert kali._apply_identity_material(cmd, "curl", _csrf_material()) is True
    assert "PORTAL-X-CSRF-TOKEN: tok123" in " ".join(cmd)


def test_apply_no_csrf_on_get() -> None:
    cmd = ["curl", "-s", "https://portal.example.com/api/read"]
    kali._apply_identity_material(cmd, "curl", _csrf_material())
    assert "PORTAL-X-CSRF-TOKEN" not in " ".join(cmd)


# --------------------------------------------------------------------------- #
# auth-status --probe liveness classifier (#3) — deterministic and operator-
# configured (material.liveness = {expect_status, authed_marker, dead_marker}).
# Pure, unit-tested in isolation and kept byte-identical to the vigil_cli.auth
# mirror; there is NO auto-detection of where a site handles auth.
# --------------------------------------------------------------------------- #

def test_classify_liveness_unknown_without_signature() -> None:
    from assess.commands import auth_status

    # No liveness config (None or empty) -> unknown, and it names the shape to set.
    verdict, reason = auth_status._classify_liveness(200, "Sign out", None)
    assert verdict == "unknown"
    assert "material.liveness" in reason
    assert auth_status._classify_liveness(200, "Sign out", {})[0] == "unknown"


def test_classify_liveness_unknown_on_transport_error() -> None:
    from assess.commands import auth_status

    # status None (transport error) wins even with a signature present.
    assert auth_status._classify_liveness(None, None, {"authed_marker": "Sign out"})[0] == "unknown"


def test_classify_liveness_dead_cases() -> None:
    from assess.commands import auth_status

    cl = auth_status._classify_liveness
    # dead_marker present in haystack.
    assert cl(200, "Please sign in", {"dead_marker": "sign in"})[0] == "dead"
    # authed_marker absent from haystack.
    assert cl(200, "anonymous page", {"authed_marker": "Sign out"})[0] == "dead"
    # expect_status mismatch (marker present, status wrong).
    assert cl(302, "Sign out", {"authed_marker": "Sign out", "expect_status": 200})[0] == "dead"


def test_classify_liveness_live_when_all_checks_pass() -> None:
    from assess.commands import auth_status

    cl = auth_status._classify_liveness
    assert cl(200, "Welcome — Sign out", {"authed_marker": "Sign out", "expect_status": 200})[0] == "live"
    # marker-only configs each stand alone.
    assert cl(200, "Sign out", {"authed_marker": "Sign out"})[0] == "live"
    assert cl(200, "welcome home", {"dead_marker": "Log in"})[0] == "live"
    assert cl(200, "anything", {"expect_status": 200})[0] == "live"


def test_classify_liveness_markers_case_sensitive() -> None:
    from assess.commands import auth_status

    # Case-sensitive substring: "sign out" != "Sign out".
    assert auth_status._classify_liveness(200, "sign out", {"authed_marker": "Sign out"})[0] == "dead"


def test_classify_liveness_mirror_parity_with_cli() -> None:
    """The assess classifier and the vigil_cli.auth classifier are two copies of
    ONE rule; they MUST return identical ``(verdict, reason)`` for identical
    inputs. (The functions are kept byte-identical; this pins that behaviourally.)
    """
    import sys
    from pathlib import Path

    repo_src = Path(__file__).resolve().parents[4] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

    from assess.commands import auth_status
    from vigil_cli import auth as cli_auth

    cases = [
        (200, "Welcome — Sign out", {"authed_marker": "Sign out", "expect_status": 200}),
        (302, "Location: /my.policy", {"authed_marker": "Sign out", "expect_status": 200}),
        (200, "Please log in", {"dead_marker": "log in"}),
        (200, "body", None),
        (200, "body", {}),
        (None, None, {"authed_marker": "x"}),
        (500, "Sign out", {"authed_marker": "Sign out", "expect_status": 200}),
        (200, "Sign out", {"authed_marker": "Sign out"}),
        (200, "anon", {"authed_marker": "Sign out"}),
        (200, "sign out", {"authed_marker": "Sign out"}),  # case-sensitivity
        (200, "x", {"expect_status": True}),  # bool is not a real int status
    ]
    for status, hay, cfg in cases:
        assert cli_auth._classify_liveness(status, hay, cfg) == \
            auth_status._classify_liveness(status, hay, cfg), (status, hay, cfg)
