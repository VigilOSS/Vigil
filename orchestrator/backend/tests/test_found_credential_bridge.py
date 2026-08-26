"""Tests for the WS7 found-credential bridge (multi-identity session store).

Recording a *discovered* credential (``status == 'discovered'`` — a genuine find,
not an operator-supplied known cred) auto-bridges it, in ``state_manager
.record_credential``, to:

1. a conservative **candidate finding** (severity left ``info`` for the LLM to
   confirm), referencing the credential — idempotent on re-record; and
2. iff the secret is a **session artifact** (a bearer/JWT or a ``name=value``
   session cookie), a **minted replayable identity** in the engagement credential
   store, cross-linked back onto the credential row's ``identity`` column.

A plain login password mints NO session. An operator-known credential (any status
other than ``discovered``) is recorded exactly as before — no finding, no mint.
"""
from __future__ import annotations

import base64
import json

from app import db
from app.services import credentials as credential_store
from app.services import state_manager
from tests.test_engagements_api import write_engagement


def _seed(client, isolate_settings, key: str) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=key)
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _make_jwt(payload: dict) -> str:
    def _seg(obj: dict) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_seg({'alg': 'none', 'typ': 'JWT'})}.{_seg(payload)}.sig"


def _obj(value) -> dict:
    """Parse a *_json column value (JSON string on the read path) to a dict."""
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _credential_findings(eng_id: int) -> list[dict]:
    return [
        f
        for f in state_manager.list_findings(eng_id)
        if str(f.get("canonical_location", "")).startswith("credential:")
    ]


def test_discovered_password_flags_finding_no_mint(client, isolate_settings):
    key = "2026-07-03-000001-disc-pw"
    eng_id = _seed(client, isolate_settings, key)

    record = state_manager.record_credential(
        eng_id,
        credential_key="leaked-admin-login",
        kind="password",
        principal="admin@target.example",
        secret="hunter2",
        source_name="exploit-developer",
        status_value="discovered",
        notes="",
        provenance={"source": "response-body"},
    )

    # Intel row recorded; a plain password is NOT a session -> no minted identity.
    assert record["status"] == "discovered"
    assert record["identity"] == ""
    identities = credential_store.load_identities(eng_id)["identities"]
    assert identities == {}

    # A single candidate finding was flagged, conservatively severity-rated,
    # referencing the credential.
    findings = _credential_findings(eng_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "info"
    assert finding["workflow_status"] == "draft"
    assert _obj(finding["details_json"])["discovered_credential"]["credential_key"] == "leaked-admin-login"
    assert _obj(finding["details_json"])["discovered_credential"]["session_minted"] is False
    # Credential row cross-links back to its originating finding via provenance.
    assert _obj(record["provenance_json"])["candidate_finding_slug"] == finding["slug"]


def test_discovered_session_cookie_mints_identity(client, isolate_settings):
    key = "2026-07-03-000002-disc-cookie"
    eng_id = _seed(client, isolate_settings, key)

    record = state_manager.record_credential(
        eng_id,
        credential_key="leaked-session-cookie",
        kind="session_cookie",
        principal="victim@target.example",
        secret="sessionid=ABCDEF0123456789ABCDEF",
        source_name="vulnerability-analyst",
        status_value="discovered",
        notes="",
        provenance={},
    )

    # A replayable identity was minted and cross-linked onto the credential row.
    minted = record["identity"]
    assert minted, "expected a minted identity name on the credential row"
    identities = credential_store.load_identities(eng_id)["identities"]
    assert minted in identities
    assert identities[minted]["cookies"].get("sessionid") == "ABCDEF0123456789ABCDEF"

    # Candidate finding flagged and marked as session-minting.
    findings = _credential_findings(eng_id)
    assert len(findings) == 1
    assert _obj(findings[0]["details_json"])["discovered_credential"]["session_minted"] is True
    assert _obj(findings[0]["details_json"])["discovered_credential"]["minted_identity"] == minted
    assert _obj(record["provenance_json"])["minted_identity"] == minted


def test_discovered_identity_is_opt_in_not_default_resolved(client, isolate_settings):
    # A minted discovered secret is UNREVIEWED — it must not be replayed by
    # default. It is stored not-usable-for-requests and, since nothing is active,
    # default resolution (get_active_credential) must decline it rather than fall
    # back to the first non-dead row. It stays selectable by explicit --identity.
    key = "2026-07-03-000009-disc-optin"
    eng_id = _seed(client, isolate_settings, key)

    record = state_manager.record_credential(
        eng_id,
        credential_key="leaked-session-cookie",
        kind="session_cookie",
        principal="victim@target.example",
        secret="sessionid=ABCDEF0123456789ABCDEF",
        source_name="vulnerability-analyst",
        status_value="discovered",
        notes="",
        provenance={},
    )
    minted = record["identity"]
    assert minted

    # Stored opt-in (not usable for requests) and never the default resolution.
    stored = db.get_credential(eng_id, minted)
    assert stored is not None
    assert stored["use_for_requests"] is False
    assert db.get_active_credential(eng_id) is None

    # Explicit activation makes it the resolved identity again.
    assert db.set_active_identity(eng_id, minted) is True
    active = db.get_active_credential(eng_id)
    assert active is not None and active["identity_name"] == minted


def test_discovered_bearer_jwt_mints_identity(client, isolate_settings):
    key = "2026-07-03-000003-disc-jwt"
    eng_id = _seed(client, isolate_settings, key)

    token = _make_jwt({"sub": "user-42", "role": "admin"})
    record = state_manager.record_credential(
        eng_id,
        credential_key="leaked-bearer",
        kind="jwt",
        principal="user-42",
        secret=token,
        source_name="exploit-developer",
        status_value="discovered",
        notes="",
        provenance={},
    )

    minted = record["identity"]
    assert minted
    identities = credential_store.load_identities(eng_id)["identities"]
    assert minted in identities
    # Bearer is replayable via an Authorization header.
    assert identities[minted]["headers"].get("Authorization") == f"Bearer {token}"
    findings = _credential_findings(eng_id)
    assert len(findings) == 1
    assert _obj(findings[0]["details_json"])["discovered_credential"]["session_minted"] is True


def test_rerecording_same_credential_no_duplicate(client, isolate_settings):
    key = "2026-07-03-000004-disc-dedup"
    eng_id = _seed(client, isolate_settings, key)

    for _ in range(3):
        state_manager.record_credential(
            eng_id,
            credential_key="leaked-session-cookie",
            kind="session_cookie",
            principal="victim@target.example",
            secret="sessionid=ABCDEF0123456789ABCDEF",
            source_name="vulnerability-analyst",
            status_value="discovered",
            notes="",
            provenance={},
        )

    # Re-recording the same discovered credential neither duplicates the finding
    # nor appends a second minted identity.
    assert len(_credential_findings(eng_id)) == 1
    assert len(credential_store.load_identities(eng_id)["identities"]) == 1
    assert len(state_manager.list_credentials(eng_id)) == 1


def test_operator_known_credential_no_bridge(client, isolate_settings):
    key = "2026-07-03-000005-known-cred"
    eng_id = _seed(client, isolate_settings, key)

    record = state_manager.record_credential(
        eng_id,
        credential_key="operator-supplied",
        kind="session_cookie",
        principal="tester@target.example",
        # A session-shaped secret, but status is NOT 'discovered' -> no bridge.
        secret="sessionid=ABCDEF0123456789ABCDEF",
        source_name="operator",
        status_value="valid",
        notes="provided by client",
        provenance={},
    )

    assert record["identity"] == ""
    assert _credential_findings(eng_id) == []
    assert credential_store.load_identities(eng_id)["identities"] == {}
