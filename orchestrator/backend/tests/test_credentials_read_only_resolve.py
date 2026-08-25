"""Read-only credential inspection must not record a USE.

``resolve_identity`` is the resolve-for-replay path, so a hit refreshes
``last_seen_at`` and an identity being injected into live traffic cannot age into
``stale``. ``auth status`` without ``--probe`` reads the same record purely to
DISPLAY it, and it reached the same resolver — so periodic inspection kept an
unused, unprobed session looking fresh forever and printed a misleading age,
defeating the 8h stale flag and the 5d purge that back the liveness design.

These tests lock the honest split at every layer the request crosses: the service
resolver, the alias branch underneath it, and the HTTP query parameter the CLI
client sets.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_engagements_api import write_engagement

from app import db
from app.services import credentials as creds

KEY = "2026-03-30-123000-readonly-resolve"


def _seed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"], KEY)
    assert client.get("/engagements").status_code == 200
    return db.get_engagement_by_key(KEY).id


def _capture(eng_id, host, cookies):
    return creds.capture_material(
        eng_id,
        None,
        host=host,
        cookies=cookies,
        headers={},
        tokens={},
        scope_host=host,
    )


def _backdate(eng, name, dt):
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE engagement_credentials SET last_seen_at = ? "
            "WHERE engagement_id = ? AND identity_name = ?",
            (dt.strftime("%Y-%m-%dT%H:%M:%SZ"), eng, name),
        )


def _last_seen(eng, name):
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT last_seen_at FROM engagement_credentials "
            "WHERE engagement_id = ? AND identity_name = ?",
            (eng, name),
        ).fetchone()
    return row["last_seen_at"]


def _put_capability(eng, name, principal):
    return creds.upsert_material(
        eng, name, {"principal_id": principal, "cookies": {"sid": name}}
    )


def _alias(eng, name, principal, alias, scope_key):
    db.set_credential_alias(eng, alias, principal, scope_key)
    db.record_credential_liveness(
        eng,
        name,
        scope_key=scope_key,
        verdict="live",
        observed_at=datetime.now(timezone.utc).isoformat(),
        ttl_seconds=86400,
        source="probe",
    )


# ---------------------------------------------------------------------------
# service layer
# ---------------------------------------------------------------------------

def test_named_resolve_without_record_use_leaves_the_age_clock_alone(
    client, isolate_settings
):
    eng = _seed(client, isolate_settings)
    name = _capture(eng, "app.example.com", {"sid": "ONLY-INSPECTED"})["identity_name"]
    aged = timedelta(hours=7, minutes=59)
    _backdate(eng, name, datetime.now(timezone.utc) - aged)
    before = _last_seen(eng, name)

    resolved, material = creds.resolve_identity(eng, name, record_use=False)

    assert resolved == name
    assert material["cookies"] == {"sid": "ONLY-INSPECTED"}
    assert _last_seen(eng, name) == before

    # ...and the age backstop still fires, which is the whole point: a status
    # loop must not be able to hold a session out of the stale sweep.
    with db.get_connection() as conn:
        db._sweep_credential_age(
            conn, eng, now=datetime.now(timezone.utc) + timedelta(minutes=2)
        )
    assert db.get_credential(eng, name)["state"] == "stale"


def test_active_resolve_without_record_use_leaves_the_age_clock_alone(
    client, isolate_settings
):
    # `auth status` with no --identity resolves the ACTIVE row instead; the
    # no-name branch is a different db call and needs its own lock.
    eng = _seed(client, isolate_settings)
    name = _capture(eng, "app.example.com", {"sid": "ACTIVE-INSPECTED"})["identity_name"]
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=3))
    before = _last_seen(eng, name)

    resolved, material = creds.resolve_identity(eng, None, record_use=False)

    assert resolved == name and material
    assert _last_seen(eng, name) == before


def test_alias_resolve_without_record_use_leaves_the_age_clock_alone(
    client, isolate_settings
):
    # The alias branch resolves through `resolve_credential_alias`, which used to
    # touch unconditionally — a read-only status on an ALIAS would otherwise still
    # reset the clock of the row it selected.
    eng = _seed(client, isolate_settings)
    name = "cap-aliased-read"
    _put_capability(eng, name, "user-42")
    _alias(eng, name, "user-42", "member", "billing")
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=3))
    before = _last_seen(eng, name)

    resolved, material = creds.resolve_identity(
        eng, "member", scope_key="billing", record_use=False
    )

    assert resolved == name and material
    assert _last_seen(eng, name) == before


def test_resolve_for_replay_still_records_a_use(client, isolate_settings):
    # The default is the replay contract and must be untouched: a real injection
    # (kali exec --identity, the browser path, `auth status --probe`) resets the
    # clock so an in-use session cannot age out mid-engagement.
    eng = _seed(client, isolate_settings)
    name = _capture(eng, "app.example.com", {"sid": "IN-USE"})["identity_name"]
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=7, minutes=59))
    before = _last_seen(eng, name)

    creds.resolve_identity(eng, name)

    assert _last_seen(eng, name) != before


def test_alias_resolve_for_replay_still_records_a_use(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    name = "cap-aliased-replay"
    _put_capability(eng, name, "user-42")
    _alias(eng, name, "user-42", "member", "billing")
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=3))
    before = _last_seen(eng, name)

    resolved, _material = creds.resolve_identity(eng, "member", scope_key="billing")

    assert resolved == name
    assert _last_seen(eng, name) != before


# ---------------------------------------------------------------------------
# HTTP surface — the query parameter the assess client sets
# ---------------------------------------------------------------------------

def test_resolve_route_honors_record_use_false(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    name = _capture(eng, "app.example.com", {"sid": "HTTP-INSPECTED"})["identity_name"]
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=3))
    before = _last_seen(eng, name)

    resp = client.get(
        f"/engagements/{KEY}/credentials/resolve",
        params={"identity": name, "record_use": "false"},
    )

    assert resp.status_code == 200
    assert resp.json()["identity_name"] == name
    assert _last_seen(eng, name) == before


def test_resolve_route_records_a_use_by_default(client, isolate_settings):
    eng = _seed(client, isolate_settings)
    name = _capture(eng, "app.example.com", {"sid": "HTTP-REPLAYED"})["identity_name"]
    _backdate(eng, name, datetime.now(timezone.utc) - timedelta(hours=3))
    before = _last_seen(eng, name)

    resp = client.get(
        f"/engagements/{KEY}/credentials/resolve", params={"identity": name}
    )

    assert resp.status_code == 200
    assert _last_seen(eng, name) != before
