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

from datetime import datetime, timedelta, timezone

import pytest
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


def test_pairs_omit_cookies_when_buckets_exist_but_none_match() -> None:
    # An identity WITH per-host buckets, targeting a host that matches NONE of them,
    # must NOT fall back to the flat ``cookies`` view: that flat view is a
    # display-only UNION across every captured host, so injecting it here would
    # bleed an unrelated host's session cookies onto this target (cross-host bleed).
    # No matching bucket → no Cookie header at all.
    cookie = dict(kali._identity_header_pairs(_material(), request_host="unrelated.test")).get("Cookie", "")
    assert cookie == ""


def test_pairs_omit_realistic_union_flat_view_on_host_mismatch() -> None:
    # Mirror how the backend actually builds the flat ``cookies`` view: a UNION of
    # every captured host bucket. A run against a host with no matching bucket must
    # send NEITHER host's session cookie — the whole point of the P1 fix.
    mat = {
        "cookies": {"JSESSIONID": "PORTAL", "apikey": "K"},  # realistic cross-host union
        "host_cookies": [
            {"host": "portal.example.com", "cookies": {"JSESSIONID": "PORTAL"}},
            {"host": "api.example.com", "cookies": {"apikey": "K"}},
        ],
    }
    pairs = dict(kali._identity_header_pairs(mat, request_host="victim.test"))
    assert "Cookie" not in pairs  # no cross-host session cookie rides an unrelated target


def test_pairs_without_host_cookies_unchanged() -> None:
    # A manual/legacy identity with NO per-host buckets still falls back to the
    # flat view — that flat view is the identity's only (single-host) session.
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
    # The identity has buckets for portal/api.example.com but the run targets a
    # host with NO matching bucket. Its only material is those per-host cookies, so
    # nothing rides this request (the cross-host flat union is correctly omitted)
    # and _apply_identity_material returns False — but the session-stale WARN must
    # STILL fire so the operator knows the session did not ride, and no unrelated
    # host's cookie leaks onto the target.
    cmd = ["curl", "-s", "https://nomatch.test/x"]
    applied = kali._apply_identity_material(cmd, "curl", _material())
    assert applied is False
    # No cross-host cookie leaked into the argv.
    assert "Cookie:" not in " ".join(cmd)
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


def test_prepare_browser_identity_material_only_stamps_when_materialized(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        kali,
        "resolve_identity",
        lambda _eng, requested: (
            requested,
            {"headers": {"X-App": "yes"}, "cookies": {"sid": "abc"}},
        ),
    )
    auth_context, prepared = kali.prepare_browser_identity_material(
        tmp_path, "member", "https://app.example.com/account"
    )
    assert auth_context == "member"
    assert prepared["headers"] == {"X-App": "yes"}
    assert prepared["cookies"] == [
        {"name": "sid", "value": "abc", "domain": "app.example.com", "path": "/"}
    ]

    monkeypatch.setattr(kali, "resolve_identity", lambda *_args: ("empty", {}))
    context, prepared = kali.prepare_browser_identity_material(
        tmp_path, "empty", "https://app.example.com"
    )
    assert context == "anonymous"
    assert prepared["headers"] == {}
    assert prepared["cookies"] == []
    assert prepared["storage_state"] is None
    # The refusal must carry a reason the operator can act on.
    assert "vigil assess auth list" in str(prepared["refusal_detail"])


def test_prepare_execution_command_refuses_missing_requested_identity(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        kali,
        "resolve_identity",
        lambda _eng, requested: (requested, {}),
    )

    with pytest.raises(
        kali.scope_lib.ScopePolicyError,
        match="requested identity 'ghost'.*refusing to run anonymously",
    ):
        kali.prepare_execution_command(
            ["curl", "https://app.example.com/account"],
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="ghost",
        )


def test_prepare_browser_identity_stamps_replayable_external_storage_state(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        kali,
        "resolve_identity",
        lambda _eng, requested: (
            requested,
            {"state": "available", "use_for_requests": True},
        ),
    )

    auth_context, prepared = kali.prepare_browser_identity_material(
        tmp_path,
        "member",
        "https://app.example.com",
        external_state_applied=True,
    )

    assert auth_context == "member"
    assert prepared == {"headers": {}, "cookies": [], "storage_state": None}


@pytest.mark.parametrize(
    "disabled",
    [
        {"use_for_requests": False},
        {"state": "dead"},
        # An operator-set marker is a deliberate signal: only the age-advisory
        # `stale` state widened, not every non-`available` state.
        {"state": "revoked"},
    ],
)
def test_disabled_identity_material_is_never_injected_or_audit_stamped(
    monkeypatch, tmp_path, disabled
) -> None:
    material = {
        "headers": {"Authorization": "Bearer secret"},
        "cookies": {"sid": "abc"},
        **disabled,
    }
    monkeypatch.setattr(
        kali,
        "resolve_identity",
        lambda _eng, requested: (requested, material),
    )
    cmd = ["curl", "https://app.example.com/account"]
    with pytest.raises(
        kali.scope_lib.ScopePolicyError,
        match="requested identity 'member'.*refusing to run anonymously",
    ):
        kali.prepare_execution_command(
            cmd,
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="member",
        )
    assert cmd == ["curl", "https://app.example.com/account"]
    context, prepared = kali.prepare_browser_identity_material(
        tmp_path, "member", "https://app.example.com/account"
    )
    assert context == "anonymous"
    assert prepared["headers"] == {}
    assert prepared["cookies"] == []
    assert prepared["storage_state"] is None
    assert str(prepared["refusal_detail"]).strip()


def test_scoped_alias_is_propagated_to_command_and_browser_resolution(
    monkeypatch, tmp_path
) -> None:
    calls = []

    def resolve(_engagement, requested, *, scope_key=""):
        calls.append((requested, scope_key))
        return requested, {
            "state": "available",
            "headers": {"Authorization": "Bearer scoped"},
        }

    monkeypatch.setattr(kali, "resolve_identity", resolve)
    cmd = ["curl", "https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd,
        tool_name="curl",
        engagement_dir=tmp_path,
        identity="member",
        identity_scope="billing",
    )
    assert auth_context == "member"
    browser_context, _prepared = kali.prepare_browser_identity_material(
        tmp_path,
        "member",
        "https://app.example.com/account",
        scope_key="billing",
    )
    assert browser_context == "member"
    assert calls == [("member", "billing"), ("member", "billing")]


# --------------------------------------------------------------------------- #
# Identity staleness is ADVISORY, and a refusal must say why
# --------------------------------------------------------------------------- #

def _aged_material(**over):
    material = {
        "identity_name": "member",
        "headers": {"Authorization": "Bearer secret"},
        "last_seen_at": (
            datetime.now(timezone.utc) - timedelta(hours=9)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    material.update(over)
    return material


def test_stale_identity_is_replayed_with_a_warning_not_refused(
    monkeypatch, tmp_path, capsys
) -> None:
    """`stale` is an age flag, not a verdict — replay it and warn.

    Refusing it deadlocked the store: the flag is set purely by age, and the
    documented recovery (`auth status --probe`) runs through this same
    injector, so the flag blocked the probe that would clear it.
    """
    material = _aged_material(state="stale")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    cmd = ["curl", "https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd, tool_name="curl", engagement_dir=tmp_path, identity="member"
    )

    assert auth_context == "member"
    assert "Authorization: Bearer secret" in cmd
    err = capsys.readouterr().err
    assert "state 'stale'" in err
    assert "auth status --probe --identity member" in err


def test_stale_identity_is_replayed_by_the_browser_path_too(
    monkeypatch, tmp_path, capsys
) -> None:
    material = _aged_material(state="stale")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    context, prepared = kali.prepare_browser_identity_material(
        tmp_path, "member", "https://app.example.com/account"
    )

    assert context == "member"
    assert prepared["headers"] == {"Authorization": "Bearer secret"}
    assert "state 'stale'" in capsys.readouterr().err


def test_liveness_probe_may_replay_a_probe_dead_identity(
    monkeypatch, tmp_path
) -> None:
    """The probe is the recovery mechanism, so it must run on the dead state.

    `db.set_liveness` documents that a `live` verdict "revives a session probed
    with --include-dead"; that is unreachable if the probe itself is refused.
    Only this one caller passes `identity_probe`.
    """
    material = _aged_material(state="dead")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    cmd = ["curl", "https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd,
        tool_name="curl",
        engagement_dir=tmp_path,
        identity="member",
        identity_probe=True,
    )

    assert auth_context == "member"
    assert "Authorization: Bearer secret" in cmd


def test_identity_refusal_names_state_age_and_the_recovery_command(
    monkeypatch, tmp_path
) -> None:
    material = _aged_material(state="dead")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["curl", "https://app.example.com/account"],
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="member",
        )

    message = str(excinfo.value)
    assert "'dead'" in message                       # the state
    assert "ago)" in message                         # the age
    assert (                                         # the exact recovery command
        "vigil assess auth status --probe --identity member --probe-url"
        in message
    )


def test_quarantined_identity_refusal_explains_the_quarantine(
    monkeypatch, tmp_path
) -> None:
    material = _aged_material(state="available", use_for_requests=False)
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["curl", "https://app.example.com/account"],
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="member",
        )

    message = str(excinfo.value)
    assert "quarantined" in message
    assert "vigil assess auth list" in message


def test_missing_identity_refusal_points_at_the_listing_command(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, {})
    )

    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["curl", "https://app.example.com/account"],
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="ghost",
        )

    message = str(excinfo.value)
    assert "was not found in the credential store" in message
    assert "vigil assess auth list" in message


def test_operator_flagged_state_refusal_names_the_state_and_the_probe(
    monkeypatch, tmp_path
) -> None:
    material = _aged_material(state="revoked")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["curl", "https://app.example.com/account"],
            tool_name="curl",
            engagement_dir=tmp_path,
            identity="member",
        )

    message = str(excinfo.value)
    assert "state 'revoked'" in message
    assert "only the age-advisory 'stale' state is replayed" in message
    assert "auth status --probe --identity member" in message


def test_liveness_probe_may_re_test_any_flagged_state(monkeypatch, tmp_path) -> None:
    """The recovery mechanism must run against whatever state it recovers from."""
    material = _aged_material(state="revoked")
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, material)
    )

    cmd = ["curl", "https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd,
        tool_name="curl",
        engagement_dir=tmp_path,
        identity="member",
        identity_probe=True,
    )

    assert auth_context == "member"
    assert "Authorization: Bearer secret" in cmd
