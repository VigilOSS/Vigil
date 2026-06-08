"""Tests for the credential->identity link (depth-gate Wave 4 / identity).

A credential can be associated to a named auth.json identity (user_a/user_b/
admin) via an additive ``identity`` column so "which identity ran which probe"
is recordable. The column is additive + free-text and defaults empty.
"""
from __future__ import annotations


from app.services import state_manager
from tests.test_engagements_api import write_engagement


def _seed(client, isolate_settings, key: str) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=key)
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def test_credential_records_identity(client, isolate_settings):
    key = "2026-06-09-210000-cred-id"
    _seed(client, isolate_settings, key)
    resp = client.post(
        f"/engagements/{key}/assessment/credentials",
        json={
            "credential_key": "rock-user-a",
            "kind": "password",
            "principal": "user_a@rock.example.com",
            "secret": "s3cr3t",
            "identity": "user_a",
        },
    )
    assert resp.status_code == 201, resp.text
    record = resp.json()
    assert record["identity"] == "user_a"

    creds = client.get(f"/engagements/{key}/assessment/credentials").json()
    assert any(c["identity"] == "user_a" for c in creds)


def test_credential_identity_defaults_empty(client, isolate_settings):
    key = "2026-06-09-210001-cred-id-empty"
    eng_id = _seed(client, isolate_settings, key)
    record = state_manager.record_credential(
        eng_id,
        credential_key="legacy-cred",
        kind="password",
        principal="admin",
        secret="x",
        source_name="",
        status_value="discovered",
        notes="",
        provenance={},
    )
    assert record["identity"] == ""
