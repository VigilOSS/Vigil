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
from datetime import datetime, timedelta, timezone

from test_engagements_api import write_engagement

from app import db
from app.services import credentials as creds

KEY = "2026-03-30-121000-multi-id"


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
