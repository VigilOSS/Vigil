"""Contract tests for the per-engagement activity-entries API (plan §1d).

Covers:
  - POST /activity-entries → 201 + returned row.
  - GET /activity-entries (plain list, ``q`` FTS filter, ``actor_kind`` +
    ``since`` filters).
  - extra="forbid" violations → 422.
  - The FTS virtual table round-trips ``body_markdown``.

Cascade-delete coverage lives in ``test_engagement_cascade_intel.py``.

These tests run against the final Phase B1 product.
"""
from __future__ import annotations

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120100-activity"
BASE = f"/engagements/{ENGAGEMENT_KEY}/activity-entries"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _items(response) -> list[dict]:
    assert response.status_code == 200, response.text
    payload = response.json()
    # The list envelope wraps items under ``items`` — see
    # ``ListActivityEntriesResponse`` in ``app/api/intel_schemas.py``.
    assert isinstance(payload, dict), payload
    assert "items" in payload, payload
    return payload["items"]


def test_activity_entry_post_and_list(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "occurred_at": "2026-04-17T12:30:00Z",
        "actor_kind": "operator",
        "actor_name": "alex",
        "title": "Ran nmap recon",
        "action": "nmap -sV target.example.com",
        "result": "Found 22, 80, 443 open",
        "artifact_ref": "artifacts/nmap.txt",
        "body_markdown": "## Recon\nTop ports 22/80/443.",
        "metadata": {"tool": "nmap", "duration_s": 31},
    }

    created = client.post(BASE, json=payload)
    assert created.status_code == 201, created.text
    row = created.json()
    assert row["title"] == "Ran nmap recon"
    assert row["actor_kind"] == "operator"
    assert row["actor_name"] == "alex"
    assert row["id"] > 0
    assert row["engagement_id"] > 0

    listing = _items(client.get(BASE))
    assert len(listing) == 1
    assert listing[0]["title"] == "Ran nmap recon"


def test_activity_entry_extra_forbid_returns_422(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    bad = client.post(
        BASE,
        json={"title": "x", "action": "y", "not_a_field": "should-reject"},
    )
    assert bad.status_code == 422, bad.text


def test_activity_entries_filter_by_actor_kind(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    client.post(BASE, json={"actor_kind": "operator", "title": "Op ran triage"})
    client.post(BASE, json={"actor_kind": "agent", "title": "Agent scanned"})
    client.post(BASE, json={"actor_kind": "hook", "title": "Hook fired"})

    all_items = _items(client.get(BASE))
    assert len(all_items) == 3

    ops = _items(client.get(BASE, params={"actor_kind": "operator"}))
    assert len(ops) == 1
    assert ops[0]["actor_kind"] == "operator"

    agents = _items(client.get(BASE, params={"actor_kind": "agent"}))
    assert len(agents) == 1
    assert agents[0]["actor_kind"] == "agent"


def test_activity_entries_fts_searches_body_markdown(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    client.post(
        BASE,
        json={
            "actor_kind": "agent",
            "actor_name": "osint-analyst",
            "title": "Subdomain enumeration",
            "body_markdown": "Ran amass; found 12 subdomains on api.example.com",
        },
    )
    client.post(
        BASE,
        json={
            "actor_kind": "agent",
            "actor_name": "nmap-runner",
            "title": "Port sweep",
            "body_markdown": "Scanned CIDR 10.0.0.0/24 with nmap",
        },
    )

    amass = _items(client.get(BASE, params={"q": "amass"}))
    assert len(amass) == 1
    assert amass[0]["title"] == "Subdomain enumeration"

    nmap = _items(client.get(BASE, params={"q": "nmap"}))
    assert len(nmap) == 1
    assert nmap[0]["title"] == "Port sweep"

    # Non-matching query → no items.
    empty = _items(client.get(BASE, params={"q": "definitely-no-match-xyz12345"}))
    assert empty == []


def test_activity_entries_since_filter_excludes_older_rows(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    early = client.post(
        BASE,
        json={
            "occurred_at": "2026-01-01T00:00:00Z",
            "actor_kind": "operator",
            "title": "Kickoff",
        },
    )
    assert early.status_code == 201, early.text
    late = client.post(
        BASE,
        json={
            "occurred_at": "2026-04-17T12:00:00Z",
            "actor_kind": "operator",
            "title": "Midpoint",
        },
    )
    assert late.status_code == 201, late.text

    filtered = _items(client.get(BASE, params={"since": "2026-03-01T00:00:00Z"}))
    titles = {row["title"] for row in filtered}
    assert "Midpoint" in titles, filtered
    assert "Kickoff" not in titles, filtered


def test_activity_entries_list_unknown_engagement_returns_404(client, isolate_settings):
    response = client.get("/engagements/does-not-exist/activity-entries")
    assert response.status_code == 404

    post = client.post(
        "/engagements/does-not-exist/activity-entries",
        json={"title": "x"},
    )
    assert post.status_code == 404
