"""Multi-identity session store — derived-identity coalescing, host-filtered
listing, age backstops, and probe-driven liveness (2026-07 redesign).

The capture path DERIVES an opaque ``cap-<sha1>`` identity from a capture's
session-anchor material so the same login refreshes one row while a genuinely
distinct login appends a new row (append-only, multi-identity). These tests lock
that behavior plus the age-backstop sweep (8h -> stale, 5d -> hard-delete) and
the dead-only semantics of set_liveness, at both the pure-function and DB layers.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timedelta, timezone

from test_engagements_api import write_engagement

from app import db
from app.services import credentials as creds

KEY = "2026-03-30-121000-multi-id"

# The opaque hash fallback name: `cap-` + exactly 10 lowercase hex chars.
_BARE_HASH_RE = re.compile(r"^cap-[0-9a-f]{10}$")


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], KEY)
    assert client.get("/engagements").status_code == 200
    return db.get_engagement_by_key(KEY).id


def _jwt(payload: dict) -> str:
    def seg(obj: dict) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(payload)}.sigsigsig"


# ---------------------------------------------------------------------------
# derive_capture_identity — pure function
# ---------------------------------------------------------------------------

def test_derive_hint_cookie_is_stable_and_value_sensitive():
    a = creds.derive_capture_identity({"sid": "AAA-session-1234"}, {}, {})
    a2 = creds.derive_capture_identity({"sid": "AAA-session-1234"}, {}, {})
    b = creds.derive_capture_identity({"sid": "BBB-session-5678"}, {}, {})
    assert a is not None and a.startswith("cap-")
    assert a == a2          # same anchor -> same identity (coalesce)
    assert a != b           # distinct anchor -> distinct identity (append)


def test_derive_ignores_non_anchor_cookies():
    # A rotating anti-CSRF / stickiness cookie must NOT change the identity when a
    # session-hint cookie is present (this is why reloads coalesce, no churn).
    base = creds.derive_capture_identity({"sid": "AAA-session-1234"}, {}, {})
    churned = creds.derive_capture_identity(
        {"sid": "AAA-session-1234", "csrf": "rotates-every-request", "AWSALB": "x" * 40},
        {},
        {},
    )
    assert base == churned


def test_derive_recognizes_provider_prefixed_session_cookie_as_the_anchor():
    base = creds.derive_capture_identity(
        {
            "acme_session": "stable-session-bearer",
            "csrf_token": "first-rotating-value",
            "AWSALB": "a" * 40,
        },
        {},
        {},
    )
    refreshed = creds.derive_capture_identity(
        {
            "acme_session": "stable-session-bearer",
            "csrf_token": "second-rotating-value",
            "AWSALB": "b" * 40,
        },
        {},
        {},
    )

    assert base == refreshed


def test_derive_shared_high_entropy_cookie_does_not_merge_accounts():
    # Same AWSALB (shared stickiness), different sid -> must stay distinct.
    one = creds.derive_capture_identity(
        {"sid": "USER-ONE-session", "AWSALB": "SHARED" + "z" * 34}, {}, {}
    )
    two = creds.derive_capture_identity(
        {"sid": "USER-TWO-session", "AWSALB": "SHARED" + "z" * 34}, {}, {}
    )
    assert one != two


def test_derive_fallback_high_entropy_when_no_hint():
    # No hint cookie -> fall back to cookies with len(value) >= 16.
    got = creds.derive_capture_identity({"weirdauth": "z" * 20}, {}, {})
    assert got is not None and got.startswith("cap-")
    # Short, non-hint cookie only -> no anchor.
    assert creds.derive_capture_identity({"short": "abc"}, {}, {}) is None


def test_derive_none_for_anonymous_capture():
    # Consent cookie only (short, non-hint) -> anonymous/pre-login -> no identity.
    assert creds.derive_capture_identity({"cookie_consent": "yes"}, {}, {}) is None
    assert creds.derive_capture_identity({}, {}, {}) is None


def test_derive_jwt_sub_coalesces_across_token_refresh():
    # Two DIFFERENT raw JWTs with the same `sub` -> same identity (refresh
    # coalesces), while a different `sub` appends.
    t1 = _jwt({"sub": "user-42", "iat": 1, "exp": 100})
    t2 = _jwt({"sub": "user-42", "iat": 999, "exp": 9999})  # refreshed token
    t3 = _jwt({"sub": "user-99", "iat": 1, "exp": 100})
    assert t1 != t2
    a = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t1}"}, {})
    b = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t2}"}, {})
    c = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t3}"}, {})
    assert a is not None and a == b and a != c


def test_derive_jwt_same_sub_different_issuer_stays_distinct():
    # Same `sub` minted by two DIFFERENT issuers (multi-tenant / multi-app) is NOT
    # the same principal: coalescing would share one identity row and let the
    # globally-stored Authorization header from issuer B replay against issuer A.
    a = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'user-1', 'iss': 'https://a.idp'})}"}, {}
    )
    b = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'user-1', 'iss': 'https://b.idp'})}"}, {}
    )
    assert a is not None and b is not None and a != b


def test_derive_jwt_same_sub_same_issuer_coalesces_across_refresh():
    # A real token refresh keeps the SAME issuer, so the identity still coalesces
    # (the issuer fold must never split a legitimate refresh of one login).
    t1 = _jwt({"sub": "user-1", "iss": "https://a.idp", "iat": 1})
    t2 = _jwt({"sub": "user-1", "iss": "https://a.idp", "iat": 999})
    a = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t1}"}, {})
    b = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t2}"}, {})
    assert a is not None and a == b


def test_derive_jwt_same_sub_and_issuer_different_audience_stays_distinct():
    a = creds.derive_capture_identity(
        {},
        {
            "Authorization": f"Bearer {_jwt({'sub': 'user-1', 'iss': 'https://idp', 'aud': 'app-a'})}"
        },
        {},
    )
    b = creds.derive_capture_identity(
        {},
        {
            "Authorization": f"Bearer {_jwt({'sub': 'user-1', 'iss': 'https://idp', 'aud': 'app-b'})}"
        },
        {},
    )
    assert a is not None and b is not None and a != b


def test_derive_jwt_audience_list_order_does_not_split_refresh():
    t1 = _jwt(
        {"sub": "user-1", "iss": "https://idp", "aud": ["api", "account"], "iat": 1}
    )
    t2 = _jwt(
        {"sub": "user-1", "iss": "https://idp", "aud": ["account", "api"], "iat": 2}
    )
    a = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t1}"}, {})
    b = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t2}"}, {})
    assert a is not None and a == b


def test_derive_contextless_jwt_scopes_by_normalized_capture_host():
    token = _jwt({"sub": "user-1"})
    first = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {token}"}, {}, host="APP-A.Example."
    )
    same_host = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {token}"}, {}, host="app-a.example"
    )
    other_host = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {token}"}, {}, host="app-b.example"
    )

    assert first is not None and first == same_host and first != other_host


def test_derive_bearer_from_tokens_bag():
    got = creds.derive_capture_identity(
        {}, {}, {"access_token": _jwt({"sub": "tok-user"})}
    )
    hdr = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'tok-user'})}"}, {}
    )
    assert got is not None and got == hdr


def test_derive_raw_bearer_when_not_a_jwt():
    a = creds.derive_capture_identity({}, {"Authorization": "Bearer opaque-token-1"}, {})
    b = creds.derive_capture_identity({}, {"Authorization": "Bearer opaque-token-2"}, {})
    assert a is not None and a != b


def test_derive_logout_only_cookies_is_none():
    # Deletion-value cookies are filtered before deriving -> pure logout = no-op.
    assert creds.derive_capture_identity({"sid": "deleted"}, {}, {}) is None
    assert creds.derive_capture_identity({"MRHSession": ""}, {}, {}) is None


# ---------------------------------------------------------------------------
# Human-readable principal labels (B3b) — derive a readable `cap-<claim>` name
# from a JWT sub/uid/user_id/email principal instead of the opaque hash.
# ---------------------------------------------------------------------------

def test_derive_jwt_sub_yields_human_label_not_bare_hash():
    # (a) A `sub` claim surfaces as a readable label, not `cap-<sha1>`.
    name = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'acme-user'})}"}, {}
    )
    assert name == "cap-acme-user"
    assert not _BARE_HASH_RE.match(name)  # decisively not the opaque hash


def test_derive_email_claim_is_sanitized_and_readable():
    # An email principal is sanitized (lowercase, `@`->`_`) and stays readable;
    # a disambiguating hash is appended only because sanitization is lossy.
    name = creds.derive_capture_identity(
        {}, {}, {"access_token": _jwt({"email": "User@Example.com"})}
    )
    assert name.startswith("cap-user_example.com")
    assert "User" not in name and "@" not in name  # sanitized, never raw
    assert not _BARE_HASH_RE.match(name)


def test_derive_same_principal_is_stable_across_refresh():
    # (b) Two DIFFERENT raw JWTs with the same principal -> same readable name,
    # so a token refresh REFRESHES one row (label is durable, not cookie-bound).
    t1 = _jwt({"sub": "acct-alice", "iat": 1, "exp": 100})
    t2 = _jwt({"sub": "acct-alice", "iat": 999, "exp": 9999})
    assert t1 != t2
    a = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t1}"}, {})
    b = creds.derive_capture_identity({}, {"Authorization": f"Bearer {t2}"}, {})
    assert a == b == "cap-acct-alice"
    # Stable even when the co-captured session cookie rotates: the name derives
    # from the durable claim, never the rotating cookie.
    with_cookie = creds.derive_capture_identity(
        {"sid": "rotates-every-login"}, {"Authorization": f"Bearer {t1}"}, {}
    )
    assert with_cookie == "cap-acct-alice"


def test_derive_distinct_principals_get_distinct_names():
    # (c) Different principals -> different readable names (multi-identity).
    alice = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'alice'})}"}, {}
    )
    bob = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'bob'})}"}, {}
    )
    assert alice == "cap-alice"
    assert bob == "cap-bob"
    assert alice != bob


def test_derive_lossy_collision_disambiguated_by_hash():
    # Two DISTINCT principals whose claims sanitize to the SAME label must NOT
    # collapse into one identity (never a wrong cross-account merge).
    one = creds.derive_capture_identity(
        {}, {}, {"access_token": _jwt({"sub": "a+tag@identity.example"})}
    )
    two = creds.derive_capture_identity(
        {}, {}, {"access_token": _jwt({"sub": "a_tag@identity.example"})}
    )
    assert one.startswith("cap-a_tag_identity.example")
    assert two.startswith("cap-a_tag_identity.example")
    assert one != two  # disambiguating hash keeps distinct principals distinct


def test_derive_case_only_principals_stay_distinct():
    # Labels are forced lowercase; if the backend treats `sub` case-sensitively,
    # `ADMIN` and `admin` are two accounts and must NOT collapse to one identity.
    lower = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'admin'})}"}, {}
    )
    upper = creds.derive_capture_identity(
        {}, {"Authorization": f"Bearer {_jwt({'sub': 'ADMIN'})}"}, {}
    )
    assert lower == "cap-admin"                 # already lowercase -> clean
    assert upper.startswith("cap-admin-")       # case-folded -> disambiguated
    assert lower != upper


def test_derive_no_claim_keeps_bare_hash_fallback():
    # (d) No identifiable principal keeps the opaque `cap-<sha1>` fallback:
    # cookie-only session, and a raw (non-JWT) opaque bearer.
    cookie_only = creds.derive_capture_identity({"sid": "AAA-session-1234"}, {}, {})
    assert _BARE_HASH_RE.match(cookie_only)
    raw_bearer = creds.derive_capture_identity(
        {}, {"Authorization": "Bearer opaque-not-a-jwt"}, {}
    )
    assert _BARE_HASH_RE.match(raw_bearer)


def test_derive_anchorless_flow_still_mints_nothing():
    # (e) Anchor-less / pre-login / pure-logout captures mint nothing.
    assert creds.derive_capture_identity({}, {}, {}) is None
    assert creds.derive_capture_identity({"cookie_consent": "yes"}, {}, {}) is None
    assert creds.derive_capture_identity({"sid": "deleted"}, {}, {}) is None


# ---------------------------------------------------------------------------
# Capture -> multi-identity rows (via the service, DB-backed)
# ---------------------------------------------------------------------------

def _capture(eng_id, host, cookies, headers=None, tokens=None):
    return creds.capture_material(
        eng_id,
        None,
        host=host,
        cookies=cookies,
        headers=headers or {},
        tokens=tokens or {},
        scope_host=host,
    )


def test_two_distinct_sids_one_host_make_two_rows(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _capture(eng, "app.example.com", {"sid": "ACCOUNT-A-session-1"})
    _capture(eng, "app.example.com", {"sid": "ACCOUNT-B-session-2"})
    rows = db.list_credentials(eng)
    assert len(rows) == 2
    # First captured session is the active one; a later append does not steal it.
    active = [r for r in rows if r["is_active"]]
    assert len(active) == 1


def test_reload_same_login_refreshes_one_row_and_bumps_last_seen(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    first = _capture(eng, "app.example.com", {"sid": "AAA-session", "csrf": "v1-rotating"})
    name = first["identity_name"]
    created = first["created_at"]
    assert created is not None
    # Backdate last_seen_at within the fresh window (2h < 8h stale TTL) so the
    # bump is observable AND the age sweep leaves the row in place (a genuine
    # refresh-in-place, not a delete+reinsert).
    old = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE engagement_credentials SET last_seen_at = ? WHERE identity_name = ?",
            (old, name),
        )
    second = _capture(eng, "app.example.com", {"sid": "AAA-session", "csrf": "v2-rotating"})
    assert second["identity_name"] == name           # same login -> same row
    assert len(db.list_credentials(eng, include_dead=True)) == 1
    assert second["last_seen_at"] != old              # bumped
    assert second["created_at"] == created            # first-capture time preserved


def test_logout_then_login_appends(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _capture(eng, "app.example.com", {"sid": "SESSION-ONE"})
    # Logout: deletion cookies -> no-op.
    assert _capture(eng, "app.example.com", {"sid": "deleted"}) == {}
    assert len(db.list_credentials(eng)) == 1
    # New login: distinct sid -> append.
    _capture(eng, "app.example.com", {"sid": "SESSION-TWO"})
    assert len(db.list_credentials(eng)) == 2


def test_shared_stickiness_cookie_no_false_merge(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    shared = "AWSALB" + "z" * 40
    _capture(eng, "app.example.com", {"sid": "ACCT-A", "AWSALB": shared})
    _capture(eng, "app.example.com", {"sid": "ACCT-B", "AWSALB": shared})
    assert len(db.list_credentials(eng)) == 2


def test_anonymous_capture_creates_nothing(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    assert _capture(eng, "app.example.com", {"cookie_consent": "yes"}) == {}
    assert db.list_credentials(eng) == []


def test_jwt_same_sub_two_raw_tokens_one_row(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _capture(eng, "api.example.com", {}, headers={"Authorization": f"Bearer {_jwt({'sub': 'u1', 'iat': 1})}"})
    _capture(eng, "api.example.com", {}, headers={"Authorization": f"Bearer {_jwt({'sub': 'u1', 'iat': 2})}"})
    assert len(db.list_credentials(eng)) == 1


def test_jwt_different_audiences_keep_separate_bearer_rows(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    token_a = _jwt({"sub": "u1", "iss": "https://idp", "aud": "app-a"})
    token_b = _jwt({"sub": "u1", "iss": "https://idp", "aud": "app-b"})

    first = _capture(
        eng,
        "app-a.example.com",
        {},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    second = _capture(
        eng,
        "app-b.example.com",
        {},
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert first["identity_name"] != second["identity_name"]
    rows = {row["identity_name"]: row for row in db.list_credentials(eng)}
    assert len(rows) == 2
    assert rows[first["identity_name"]]["headers"]["Authorization"] == f"Bearer {token_a}"
    assert rows[second["identity_name"]]["headers"]["Authorization"] == f"Bearer {token_b}"


def test_contextless_jwt_keeps_separate_bearers_per_capture_host(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    token_a = _jwt({"sub": "u1", "iat": 1})
    token_b = _jwt({"sub": "u1", "iat": 2})

    first = _capture(
        eng,
        "app-a.example.com",
        {},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    second = _capture(
        eng,
        "app-b.example.com",
        {},
        headers={"Authorization": f"Bearer {token_b}"},
    )

    assert first["identity_name"] != second["identity_name"]
    rows = {row["identity_name"]: row for row in db.list_credentials(eng)}
    assert len(rows) == 2
    assert rows[first["identity_name"]]["headers"]["Authorization"] == f"Bearer {token_a}"
    assert rows[second["identity_name"]]["headers"]["Authorization"] == f"Bearer {token_b}"


def test_capture_names_row_after_principal_and_refresh_coalesces(client, isolate_settings):
    # A JWT-principal capture names the stored row readably; a refreshed token
    # for the same principal REFRESHES that one row (append-in-place dedup).
    eng = _seed(client, isolate_settings)
    first = _capture(
        eng, "api.example.com", {},
        headers={"Authorization": f"Bearer {_jwt({'sub': 'acme-user', 'iat': 1})}"},
    )
    assert first["identity_name"].startswith("cap-acme-user-host")
    second = _capture(
        eng, "api.example.com", {},
        headers={"Authorization": f"Bearer {_jwt({'sub': 'acme-user', 'iat': 2})}"},
    )
    assert second["identity_name"] == first["identity_name"]
    rows = db.list_credentials(eng, include_dead=True)
    assert len(rows) == 1
    assert rows[0]["identity_name"] == first["identity_name"]


def test_capture_distinct_principals_make_two_named_rows(client, isolate_settings):
    # Two different principals append as two distinct, readably-named rows —
    # this is the account-A vs account-B distinction for IDOR/BOLA testing.
    eng = _seed(client, isolate_settings)
    alice = _capture(
        eng,
        "api.example.com",
        {},
        headers={"Authorization": f"Bearer {_jwt({'sub': 'alice'})}"},
    )
    bob = _capture(
        eng,
        "api.example.com",
        {},
        headers={"Authorization": f"Bearer {_jwt({'sub': 'bob'})}"},
    )
    names = {r["identity_name"] for r in db.list_credentials(eng)}
    assert names == {alice["identity_name"], bob["identity_name"]}
    assert alice["identity_name"].startswith("cap-alice-host")
    assert bob["identity_name"].startswith("cap-bob-host")


# ---------------------------------------------------------------------------
# Host-filtered listing
# ---------------------------------------------------------------------------

def test_list_host_filter(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _capture(eng, "app.example.com", {"sid": "ON-APP-EXAMPLE"})
    _capture(eng, "shop.other.com", {"sid": "ON-SHOP-OTHER"})
    all_rows = db.list_credentials(eng)
    assert len(all_rows) == 2
    only_example = db.list_credentials(eng, host="app.example.com")
    assert len(only_example) == 1
    assert only_example[0]["cookies"]["sid"] == "ON-APP-EXAMPLE"
    # Subdomain-aware: a request host that is a subdomain of a captured bucket host
    # still resolves that session (parent-domain cookie is sent to the subdomain).
    _capture(eng, "example.com", {"sid": "PARENT-DOMAIN"})
    sub = db.list_credentials(eng, host="deep.example.com")
    assert any(r["cookies"]["sid"] == "PARENT-DOMAIN" for r in sub)


def test_list_host_filter_shows_host_agnostic_bearer_identity(client, isolate_settings):
    """A bearer/JWT identity carries no cookie bucket, but replay injects its
    Authorization header on ANY host — so `auth list --host X` must show it for
    every host (list must match what replay would actually use). This is the
    SPA/JWT IDOR case."""
    eng = _seed(client, isolate_settings)
    _capture(eng, "app.example.com", {"sid": "COOKIE-SESSION"})
    _capture(eng, "api.example.com", {}, headers={"Authorization": f"Bearer {_jwt({'sub': 'svc'})}"})
    # The cookie session lists only for its host; the bearer identity lists for BOTH
    # its capture host and an unrelated host (host-agnostic).
    on_app = db.list_credentials(eng, host="app.example.com")
    assert len(on_app) == 2  # cookie session + host-agnostic bearer
    on_unrelated = db.list_credentials(eng, host="unrelated.test")
    assert len(on_unrelated) == 1  # only the bearer identity, not the cookie session
    assert on_unrelated[0]["headers"].get("Authorization", "").startswith("Bearer ")


def test_host_filtered_load_preserves_global_active_identity(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    active = _capture(eng, "app.example.com", {"sid": "GLOBAL-ACTIVE"})
    other = _capture(eng, "shop.example.com", {"sid": "HOST-MATCHING-OTHER"})

    listing = creds.load_identities(eng, host="shop.example.com")

    assert set(listing["identities"]) == {other["identity_name"]}
    assert listing["active_identity"] == active["identity_name"]


# ---------------------------------------------------------------------------
# Age backstops (8h -> stale, 5d -> hard-delete)
# ---------------------------------------------------------------------------

def _backdate(eng, name, dt):
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE engagement_credentials SET last_seen_at = ? "
            "WHERE engagement_id = ? AND identity_name = ?",
            (dt.strftime("%Y-%m-%dT%H:%M:%SZ"), eng, name),
        )


def test_age_sweep_flags_stale_then_hard_deletes(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "AGING-SESSION"})
    name = mat["identity_name"]
    now = datetime.now(timezone.utc)

    # 9h old -> stale on next read (not dead, still listed).
    _backdate(eng, name, now - timedelta(hours=9))
    rows = db.list_credentials(eng)
    assert len(rows) == 1
    assert rows[0]["state"] == "stale"

    # 6 days old -> hard-deleted on next read.
    _backdate(eng, name, now - timedelta(days=6))
    assert db.list_credentials(eng, include_dead=True) == []


def test_age_sweep_leaves_fresh_untouched(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "FRESH-SESSION"})
    rows = db.list_credentials(eng)
    assert rows[0]["state"] == "available"
    assert mat["state"] == "available"


def test_resolve_for_replay_refreshes_last_seen_so_an_in_use_identity_never_ages_out(
    client, isolate_settings
):
    """An identity that is actively being replayed must not hit the age backstop.

    ``last_seen_at`` used to move only on a WRITE (capture / import / live
    probe), so a session that was being injected into every request still
    flipped to ``stale`` at exactly the 8h TTL. A resolve-for-replay is a USE
    and now resets the clock.
    """
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "IN-CONSTANT-USE"})
    name = mat["identity_name"]
    now = datetime.now(timezone.utc)

    # Last WRITE was 7h59m ago — still inside the TTL, about to cross it.
    _backdate(eng, name, now - timedelta(hours=7, minutes=59))

    resolved_name, material = creds.resolve_identity(eng, name)
    assert resolved_name == name
    assert material["state"] == "available"

    # Seven hours after that USE the row must still be available. Without the
    # touch its last_seen_at is still the 7h59m-old write, so the sweep would
    # see ~15h and flag it stale while it was being used every minute.
    with db.get_connection() as conn:
        db._sweep_credential_age(conn, eng, now=now + timedelta(hours=7))
    assert db.get_credential(eng, name)["state"] == "available"


def test_plain_listing_is_not_a_use_and_does_not_reset_the_age_clock(
    client, isolate_settings
):
    """Only a resolve-for-replay counts as a USE; listing must not keep rows alive."""
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "ONLY-LISTED"})
    name = mat["identity_name"]
    stale_seen = (datetime.now(timezone.utc) - timedelta(hours=7, minutes=59)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=7, minutes=59))

    db.list_credentials(eng)
    db.get_credential(eng, name)

    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT last_seen_at FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (eng, name),
        ).fetchone()
    assert row["last_seen_at"] == stale_seen


def test_touch_credential_use_never_revives_a_probe_dead_session(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "PROVEN-DEAD"})
    name = mat["identity_name"]
    db.set_liveness(eng, name, "dead", "2026-07-03T10:00:00Z")
    dead_seen = (datetime.now(timezone.utc) - timedelta(days=4)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(days=4))

    db.touch_credential_use(eng, name)

    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT last_seen_at FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (eng, name),
        ).fetchone()
    assert row["last_seen_at"] == dead_seen


def test_age_sweep_never_marks_dead(client, isolate_settings):
    # 9h old but probe-proven dead must STAY dead (age never overrides a probe).
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "DEAD-SESSION"})
    name = mat["identity_name"]
    db.set_liveness(eng, name, "dead", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=9))
    row = db.list_credentials(eng, include_dead=True)[0]
    assert row["state"] == "dead"  # not downgraded to stale


# ---------------------------------------------------------------------------
# set_liveness — dead-only state semantics + default dead exclusion
# ---------------------------------------------------------------------------

def test_set_liveness_dead_sets_state_and_hides_by_default(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "TO-KILL"})
    name = mat["identity_name"]
    probed = "2026-07-03T10:00:00Z"
    updated = db.set_liveness(eng, name, "dead", probed)
    assert updated["state"] == "dead"
    assert updated["liveness_verdict"] == "dead"
    assert updated["last_probed_at"] == probed
    # Dead excluded by default, surfaced with include_dead.
    assert db.list_credentials(eng) == []
    assert len(db.list_credentials(eng, include_dead=True)) == 1


def test_get_active_credential_skips_probe_dead_active_identity(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    active = _capture(eng, "app.example.com", {"sid": "ACTIVE-THEN-DEAD"})
    fallback = _capture(eng, "app.example.com", {"sid": "FALLBACK-STILL-LIVE"})

    db.set_liveness(eng, active["identity_name"], "dead", "2026-07-03T10:00:00Z")

    resolved = db.get_active_credential(eng)
    assert resolved is not None
    assert resolved["identity_name"] == fallback["identity_name"]
    assert resolved["state"] == "available"


def test_set_liveness_live_refreshes_last_seen_before_age_sweep(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "STALE-BUT-LIVE"})
    name = mat["identity_name"]
    probed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    old_seen = (datetime.now(timezone.utc) - timedelta(hours=9)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=9))

    updated = db.set_liveness(eng, name, "live", probed)

    assert updated["state"] == "available"
    assert updated["liveness_verdict"] == "live"
    assert updated["last_probed_at"] == probed
    assert updated["last_seen_at"] != old_seen
    assert db.get_credential(eng, name)["state"] == "available"


def test_set_liveness_non_dead_does_not_change_state(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    mat = _capture(eng, "app.example.com", {"sid": "STAYS-ALIVE"})
    name = mat["identity_name"]
    for verdict in ("live", "stale", "unknown"):
        updated = db.set_liveness(eng, name, verdict, "2026-07-03T10:00:00Z")
        assert updated["liveness_verdict"] == verdict
        assert updated["state"] == "available", (
            f"verdict {verdict!r} must never set state=dead"
        )


def test_set_liveness_unknown_identity_returns_none(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    assert db.set_liveness(eng, "cap-nope", "live", "2026-07-03T10:00:00Z") is None


def _put_capability(eng: int, name: str, principal: str, *, mfa_factor: str = ""):
    return creds.upsert_material(
        eng,
        name,
        {
            "principal_id": principal,
            "mfa_factor": mfa_factor,
            "cookies": {"sid": name},
        },
    )


def test_principal_and_mfa_factor_round_trip(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    row = _put_capability(eng, "cap-old", "user-42", mfa_factor="totp")
    assert row["principal_id"] == "user-42"
    assert row["mfa_factor"] == "totp"


def test_alias_resolves_freshest_live_capability_for_principal_and_scope(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-old", "user-42")
    _put_capability(eng, "cap-new", "user-42")
    db.set_credential_alias(eng, "member", "user-42", "billing")
    now = datetime.now(timezone.utc)
    db.record_credential_liveness(
        eng, "cap-old", scope_key="billing", verdict="live",
        observed_at=(now - timedelta(minutes=2)).isoformat(), ttl_seconds=86400, source="probe",
    )
    db.record_credential_liveness(
        eng, "cap-new", scope_key="billing", verdict="live",
        observed_at=(now - timedelta(minutes=1)).isoformat(), ttl_seconds=86400, source="keepalive",
    )
    name, material = creds.resolve_identity(eng, "member", scope_key="billing")
    assert name == "cap-new"
    assert material["principal_id"] == "user-42"
    assert material["liveness_observations"][0]["source"] == "keepalive"


def test_literal_identity_name_beats_alias(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "member", "literal-principal")
    _put_capability(eng, "cap-aliased", "aliased-principal")
    db.set_credential_alias(eng, "member", "aliased-principal", "")
    db.record_credential_liveness(
        eng, "cap-aliased", scope_key="", verdict="live",
        observed_at="2026-07-15T11:00:00Z", ttl_seconds=86400, source="probe",
    )
    name, material = creds.resolve_identity(eng, "member", scope_key="")
    assert name == "member"
    assert material["principal_id"] == "literal-principal"


def test_scoped_liveness_ttl_never_crosses_scope_or_uses_expired_live(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-billing", "user-42")
    db.set_credential_alias(eng, "member", "user-42", "billing")
    db.record_credential_liveness(
        eng, "cap-billing", scope_key="reports", verdict="live",
        observed_at="2026-07-15T11:00:00Z", ttl_seconds=86400, source="probe",
    )
    assert creds.resolve_identity(eng, "member", scope_key="billing") == ("member", {})
    db.record_credential_liveness(
        eng, "cap-billing", scope_key="billing", verdict="live",
        observed_at="2000-01-01T00:00:00Z", ttl_seconds=1, source="probe",
    )
    assert creds.resolve_identity(eng, "member", scope_key="billing") == ("member", {})


def test_alias_and_scoped_liveness_api(client, isolate_settings):
    _seed(client, isolate_settings)
    put = client.put(
        f"/engagements/{KEY}/credentials/cap-member",
        json={"principal_id": "user-42", "mfa_factor": "webauthn", "cookies": {"sid": "abc"}},
    )
    assert put.status_code == 200
    assert put.json()["mfa_factor"] == "webauthn"
    alias = client.put(
        f"/engagements/{KEY}/credentials/aliases/member",
        json={"principal_id": "user-42", "scope_key": "billing"},
    )
    assert alias.status_code == 200
    live = client.post(
        f"/engagements/{KEY}/credentials/cap-member/liveness",
        json={
            "verdict": "live",
            "probed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope_key": "billing",
            "ttl_seconds": 300,
            "source": "auth-status",
        },
    )
    assert live.status_code == 200
    resolved = client.get(
        f"/engagements/{KEY}/credentials/resolve",
        params={"identity": "member", "scope": "billing"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["identity_name"] == "cap-member"


def test_credential_refresh_preserves_durable_principal_and_mfa(client, isolate_settings):
    _seed(client, isolate_settings)
    initial = client.put(
        f"/engagements/{KEY}/credentials/cap-member",
        json={
            "principal_id": "jwt:sub:user-42",
            "mfa_factor": "webauthn",
            "cookies": {"sid": "old"},
        },
    )
    assert initial.status_code == 200

    refreshed = client.put(
        f"/engagements/{KEY}/credentials/cap-member",
        json={"cookies": {"sid": "refreshed"}},
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["principal_id"] == "jwt:sub:user-42"
    assert refreshed.json()["mfa_factor"] == "webauthn"


def test_older_unscoped_liveness_cannot_overwrite_newer_verdict(client, isolate_settings):
    _seed(client, isolate_settings)
    put = client.put(
        f"/engagements/{KEY}/credentials/cap-member",
        json={"principal_id": "user-42", "cookies": {"sid": "abc"}},
    )
    assert put.status_code == 200
    now = datetime.now(timezone.utc).replace(microsecond=0)
    newer = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    older = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    live = client.post(
        f"/engagements/{KEY}/credentials/cap-member/liveness",
        json={"verdict": "live", "probed_at": newer, "ttl_seconds": 600},
    )
    assert live.status_code == 200
    delayed_dead = client.post(
        f"/engagements/{KEY}/credentials/cap-member/liveness",
        json={"verdict": "dead", "probed_at": older, "ttl_seconds": 600},
    )
    assert delayed_dead.status_code == 200
    assert delayed_dead.json()["state"] == "available"
    unscoped = next(
        row
        for row in delayed_dead.json()["liveness_observations"]
        if row["scope_key"] == ""
    )
    assert unscoped["verdict"] == "live"
    assert unscoped["observed_at"] == newer


def test_liveness_timestamps_are_normalized_to_utc(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-member", "user-42")
    db.record_credential_liveness(
        eng,
        "cap-member",
        scope_key="billing",
        verdict="live",
        observed_at="2026-07-15T12:00:00+05:00",
        ttl_seconds=60,
        source="probe",
    )
    row = db.list_credential_liveness(eng, "cap-member")[0]
    assert row["observed_at"] == "2026-07-15T07:00:00Z"
    assert row["expires_at"] == "2026-07-15T07:01:00Z"


def _credential_with_hosts(eng: int, name: str, *hosts: str):
    return creds.upsert_material(
        eng,
        name,
        {
            "cookies": {"sid": name},
            "host_cookies": [
                {"host": host, "cookies": {"sid": name}} for host in hosts
            ],
        },
    )


def _force_legacy_liveness_projection(
    eng: int,
    name: str,
    *,
    state: str,
    verdict: str,
    probed_at: str,
) -> None:
    """Model a pre-scoped-liveness singleton projection left in the database."""
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE engagement_credentials "
            "SET state=?, liveness_verdict=?, last_probed_at=? "
            "WHERE engagement_id=? AND identity_name=?",
            (state, verdict, probed_at, eng, name),
        )


def _recent_liveness_times() -> tuple[str, str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return tuple(
        (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for minutes in (10, 5, 1)
    )


def test_unscoped_list_projects_newer_live_for_identity_with_one_defensible_host(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _credential_with_hosts(eng, "cap-chat", "chat.example.test")
    legacy_dead_at, scoped_live_at, _ = _recent_liveness_times()
    _force_legacy_liveness_projection(
        eng,
        "cap-chat",
        state="available",
        verdict="dead",
        probed_at=legacy_dead_at,
    )
    db.record_credential_liveness(
        eng,
        "cap-chat",
        scope_key="https://chat.example.test",
        verdict="live",
        observed_at=scoped_live_at,
        ttl_seconds=3600,
        source="auth-status",
    )

    material = creds.load_identities(eng)["identities"]["cap-chat"]

    assert material["state"] == "available"
    assert material["liveness_verdict"] == "live"
    assert material["last_probed_at"] == scoped_live_at


def test_unscoped_list_reports_unknown_when_multiple_hosts_have_conflicting_proof(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _credential_with_hosts(
        eng, "cap-multi", "chat.example.test", "api.example.test"
    )
    legacy_dead_at, chat_live_at, api_dead_at = _recent_liveness_times()
    _force_legacy_liveness_projection(
        eng,
        "cap-multi",
        state="available",
        verdict="dead",
        probed_at=legacy_dead_at,
    )
    db.record_credential_liveness(
        eng,
        "cap-multi",
        scope_key="https://chat.example.test",
        verdict="live",
        observed_at=chat_live_at,
        ttl_seconds=3600,
        source="auth-status",
    )
    db.record_credential_liveness(
        eng,
        "cap-multi",
        scope_key="https://api.example.test",
        verdict="dead",
        observed_at=api_dead_at,
        ttl_seconds=3600,
        source="auth-status",
    )

    material = creds.load_identities(eng)["identities"]["cap-multi"]

    assert material["state"] == "available"
    assert material["liveness_verdict"] == "unknown"
    assert material["last_probed_at"] is None


def test_host_scoped_list_uses_only_newest_matching_origin_and_isolates_identities(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _credential_with_hosts(
        eng, "cap-multi", "chat.example.test", "api.example.test"
    )
    _credential_with_hosts(eng, "cap-other", "chat.example.test")
    older_dead_at, newer_live_at, other_dead_at = _recent_liveness_times()
    db.record_credential_liveness(
        eng,
        "cap-multi",
        scope_key="http://chat.example.test",
        verdict="dead",
        observed_at=older_dead_at,
        ttl_seconds=3600,
        source="auth-status",
    )
    db.record_credential_liveness(
        eng,
        "cap-multi",
        scope_key="https://chat.example.test",
        verdict="live",
        observed_at=newer_live_at,
        ttl_seconds=3600,
        source="auth-status",
    )
    db.record_credential_liveness(
        eng,
        "cap-other",
        scope_key="https://chat.example.test",
        verdict="dead",
        observed_at=other_dead_at,
        ttl_seconds=3600,
        source="auth-status",
    )

    identities = creds.load_identities(
        eng, host="chat.example.test"
    )["identities"]

    assert identities["cap-multi"]["liveness_verdict"] == "live"
    assert identities["cap-multi"]["last_probed_at"] == newer_live_at
    assert identities["cap-other"]["liveness_verdict"] == "dead"
    assert identities["cap-other"]["last_probed_at"] == other_dead_at


def test_include_dead_list_keeps_newest_compatible_dead_proof_dead(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _credential_with_hosts(eng, "cap-dead", "chat.example.test")
    older_live_at, newer_dead_at, _ = _recent_liveness_times()
    _force_legacy_liveness_projection(
        eng,
        "cap-dead",
        state="dead",
        verdict="live",
        probed_at=older_live_at,
    )
    db.record_credential_liveness(
        eng,
        "cap-dead",
        scope_key="https://chat.example.test",
        verdict="dead",
        observed_at=newer_dead_at,
        ttl_seconds=3600,
        source="auth-status",
    )

    material = creds.load_identities(
        eng, include_dead=True
    )["identities"]["cap-dead"]

    assert material["state"] == "dead"
    assert material["liveness_verdict"] == "dead"
    assert material["last_probed_at"] == newer_dead_at


def test_available_unscoped_list_drops_unqualified_dead_after_scoped_live_expires(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-flat", "user-42")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    legacy_dead_at = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    scoped_live_at = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _force_legacy_liveness_projection(
        eng,
        "cap-flat",
        state="available",
        verdict="dead",
        probed_at=legacy_dead_at,
    )
    db.record_credential_liveness(
        eng,
        "cap-flat",
        scope_key="https://chat.example.test",
        verdict="live",
        observed_at=scoped_live_at,
        ttl_seconds=1,
        source="auth-status",
    )

    material = creds.load_identities(eng)["identities"]["cap-flat"]

    assert material["state"] == "available"
    assert material["liveness_verdict"] == "unknown"
    assert material["last_probed_at"] is None


def test_available_unscoped_list_drops_unqualified_dead_without_typed_observation(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-flat", "user-42")
    legacy_dead_at, _, _ = _recent_liveness_times()
    _force_legacy_liveness_projection(
        eng,
        "cap-flat",
        state="available",
        verdict="dead",
        probed_at=legacy_dead_at,
    )

    material = creds.load_identities(eng)["identities"]["cap-flat"]

    assert material["state"] == "available"
    assert material["liveness_verdict"] == "unknown"
    assert material["last_probed_at"] is None


def test_explicit_dead_unscoped_list_preserves_legacy_dead_projection(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    _put_capability(eng, "cap-flat-dead", "user-42")
    legacy_dead_at, _, _ = _recent_liveness_times()
    _force_legacy_liveness_projection(
        eng,
        "cap-flat-dead",
        state="dead",
        verdict="dead",
        probed_at=legacy_dead_at,
    )

    material = creds.load_identities(
        eng, include_dead=True
    )["identities"]["cap-flat-dead"]

    assert material["state"] == "dead"
    assert material["liveness_verdict"] == "dead"
    assert material["last_probed_at"] == legacy_dead_at
