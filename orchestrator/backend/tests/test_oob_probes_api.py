"""Tests for the OAST (out-of-band) auto-correlation API.

Covers the engagement-scoped probe + interaction endpoints that back
``aith oob mint`` / ``aith oob poll``:

- ``POST /assessment/oob-probes`` records a probe keyed on its unique nonce
  (idempotent re-mint returns the existing row).
- ``POST /assessment/oob-probes/interactions`` correlates an observed
  callback to its probe by nonce, flips ``pending`` → ``fired``, dedupes
  identical callbacks, and reports ``matched=False`` for unknown nonces
  (instead of 404) so a mixed poll never aborts on a stray callback.
- ``GET /assessment/oob-probes`` and ``GET /assessment/oob-probes/{nonce}``
  list probes (with interaction counts) and fetch one with its history.

These are the verifiable API surface; the live interactsh round-trip
(frp + container) is exercised separately and marked ``integration``.
"""
from __future__ import annotations

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-05-30-120100-oob"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _mint_probe(client, *, nonce="abc123def456ghij", **overrides) -> dict:
    payload = {
        "nonce": nonce,
        "target_url": "https://shop.test/api/import?url=",
        "param": "url",
        "technique": "ssrf",
        "probe_kind": "blind-ssrf",
        "request_hash": "deadbeef",
        "oob_domain": "researcher.example",
    }
    payload.update(overrides)
    response = client.post(f"{ASSESSMENT_BASE}/oob-probes", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_record_probe_persists_metadata_and_defaults_pending(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client)
    assert probe["nonce"] == "abc123def456ghij"
    assert probe["technique"] == "ssrf"
    assert probe["target_url"] == "https://shop.test/api/import?url="
    assert probe["status"] == "pending"
    assert probe["id"] >= 1


def test_record_probe_is_idempotent_on_nonce(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    first = _mint_probe(client)
    # Re-mint with the same nonce but different (ignored) metadata: same row.
    second = _mint_probe(client, technique="cmdi", target_url="https://other.test/")
    assert second["id"] == first["id"]
    assert second["technique"] == "ssrf"  # original metadata retained
    assert second["target_url"] == first["target_url"]


def test_record_probe_rejects_unknown_engagement(client, isolate_settings):
    response = client.post(
        "/engagements/2026-01-01-000000-missing/assessment/oob-probes",
        json={"nonce": "whatever123"},
    )
    assert response.status_code == 404, response.text


def test_correlate_interaction_rejects_unknown_engagement(client, isolate_settings):
    response = client.post(
        "/engagements/2026-01-01-000000-missing/assessment/oob-probes/interactions",
        json={"nonce": "whatever123", "protocol": "dns", "remote_address": "203.0.113.1"},
    )
    assert response.status_code == 404, response.text


def test_correlate_interaction_matches_and_flips_status(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client)
    response = client.post(
        f"{ASSESSMENT_BASE}/oob-probes/interactions",
        json={
            "nonce": probe["nonce"],
            "protocol": "dns",
            "remote_address": "203.0.113.9",
            "query_type": "A",
            "raw_request": "[researcher.example] Received DNS interaction (A) from 203.0.113.9",
            "observed_at": "2026-05-30 12:00:00",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["matched"] is True
    assert body["duplicate"] is False
    assert body["probe"]["status"] == "fired"
    assert body["interaction"]["protocol"] == "dns"
    assert body["interaction"]["remote_address"] == "203.0.113.9"


def test_correlate_interaction_dedupes_identical_callback(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client)
    payload = {
        "nonce": probe["nonce"],
        "protocol": "http",
        "remote_address": "198.51.100.4",
        "raw_request": "exact same line",
        "observed_at": "2026-05-30 12:00:01",
    }
    first = client.post(f"{ASSESSMENT_BASE}/oob-probes/interactions", json=payload)
    assert first.status_code == 200
    assert first.json()["duplicate"] is False

    second = client.post(f"{ASSESSMENT_BASE}/oob-probes/interactions", json=payload)
    assert second.status_code == 200
    assert second.json()["duplicate"] is True

    fetched = client.get(f"{ASSESSMENT_BASE}/oob-probes/{probe['nonce']}")
    assert fetched.status_code == 200
    assert len(fetched.json()["interactions"]) == 1


def test_correlate_unknown_nonce_reports_unmatched_not_404(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.post(
        f"{ASSESSMENT_BASE}/oob-probes/interactions",
        json={
            "nonce": "neverminted0000",
            "protocol": "dns",
            "remote_address": "203.0.113.50",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["matched"] is False
    assert body["probe"] is None
    assert body["interaction"] is None


def test_list_probes_embeds_interaction_count(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    probe = _mint_probe(client)
    _mint_probe(client, nonce="secondnonce99999", technique="blind-xss")
    client.post(
        f"{ASSESSMENT_BASE}/oob-probes/interactions",
        json={"nonce": probe["nonce"], "protocol": "dns", "remote_address": "203.0.113.1", "observed_at": "2026-05-30 13:00:00"},
    )

    listed = client.get(f"{ASSESSMENT_BASE}/oob-probes")
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    assert len(rows) == 2
    by_nonce = {row["nonce"]: row for row in rows}
    assert by_nonce[probe["nonce"]]["interaction_count"] == 1
    assert by_nonce[probe["nonce"]]["last_interaction_at"] == "2026-05-30 13:00:00"
    assert by_nonce["secondnonce99999"]["interaction_count"] == 0


def test_list_probes_status_filter(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    fired = _mint_probe(client)
    _mint_probe(client, nonce="stillpending0001")
    client.post(
        f"{ASSESSMENT_BASE}/oob-probes/interactions",
        json={"nonce": fired["nonce"], "protocol": "dns", "remote_address": "203.0.113.2"},
    )

    pending = client.get(f"{ASSESSMENT_BASE}/oob-probes", params={"status": "pending"})
    assert pending.status_code == 200
    pending_nonces = {row["nonce"] for row in pending.json()}
    assert "stillpending0001" in pending_nonces
    assert fired["nonce"] not in pending_nonces

    fired_list = client.get(f"{ASSESSMENT_BASE}/oob-probes", params={"status": "fired"})
    assert {row["nonce"] for row in fired_list.json()} == {fired["nonce"]}


def test_get_probe_by_unknown_nonce_404(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.get(f"{ASSESSMENT_BASE}/oob-probes/does-not-exist")
    assert response.status_code == 404, response.text


def test_record_probe_rejects_extra_field(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.post(
        f"{ASSESSMENT_BASE}/oob-probes",
        json={"nonce": "abc123", "bogus_field": "x"},
    )
    assert response.status_code == 422, response.text


def test_record_probe_rejects_empty_nonce(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.post(f"{ASSESSMENT_BASE}/oob-probes", json={"nonce": ""})
    assert response.status_code == 422, response.text
