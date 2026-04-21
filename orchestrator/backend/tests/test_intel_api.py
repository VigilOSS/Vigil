"""Contract tests for the per-engagement intel API (plan §1d).

For every POST + GET under ``/engagements/{key}/intel`` we assert:
  - POST with a valid payload returns 201 + the full row state_manager
    produced (id, engagement_id, server-stamped created_at/updated_at,
    plus the request fields round-tripped).
  - Repeating the POST with the same natural key UPSERTs — one row in the
    list, and the second response reflects the updated fields.
  - POST with an ``extra="forbid"`` violation returns 422 (the
    ``intel_schemas`` models are the single-source contract).
  - The GET list returns the created row.
  - ``/intel/summary`` counts reflect the inserts.
  - ``/intel/search?q=...`` finds the row after insert (FTS round-trip).
  - ``/intel/by-url?url=...`` returns intel_domains + assessment_services
    hits where applicable.

The engagement-cascade-delete coverage lives in
``test_engagement_cascade_intel.py`` — see that file for the
"every intel_* table empties when the engagement is deleted" assertion.

These tests run against the final Phase B1 product. While B1 is in flight
the endpoints return 501 and every body assertion below will fail; rerun
after B1's helpers land.
"""
from __future__ import annotations

from typing import Any

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120000-example"
INTEL_BASE = f"/engagements/{ENGAGEMENT_KEY}/intel"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    # Trigger filesystem discovery + engagement row creation.
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


def _summary(client) -> dict[str, int]:
    response = client.get(f"{INTEL_BASE}/summary")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "counts" in payload, payload
    return payload["counts"]


def _assert_present_in_search(client, query: str, entity_type: str | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"q": query}
    if entity_type:
        params["entity_type"] = entity_type
    response = client.get(f"{INTEL_BASE}/search", params=params)
    assert response.status_code == 200, response.text
    hits = response.json()
    assert isinstance(hits, list), hits
    return hits


# ──────────────────────────────────────────────────────────────
# tech-components
# ──────────────────────────────────────────────────────────────


def test_tech_component_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "component": "nginx",
        "version": "1.25.0",
        "source_name": "wappalyzer",
        "confidence": "high",
        "evidence_ref": "artifacts/wapplyzer.json",
        "notes": "Observed on edge.",
        "provenance": {"agent_name": "osint-analyst"},
    }

    before = _summary(client).get("tech_components", 0)

    created = client.post(f"{INTEL_BASE}/tech-components", json=payload)
    assert created.status_code == 201, created.text
    row = created.json()
    assert row["component"] == "nginx"
    assert row["version"] == "1.25.0"
    assert row["source_name"] == "wappalyzer"
    assert row["id"] > 0
    assert row["engagement_id"] > 0

    listing = client.get(f"{INTEL_BASE}/tech-components")
    assert listing.status_code == 200, listing.text
    items = listing.json()
    assert len(items) == 1
    assert items[0]["component"] == "nginx"

    # UPSERT: same natural key (component, version) → single row, updates applied.
    payload["notes"] = "Observed on edge + api."
    payload["confidence"] = "confirmed"
    upsert = client.post(f"{INTEL_BASE}/tech-components", json=payload)
    assert upsert.status_code == 201, upsert.text
    assert upsert.json()["notes"] == "Observed on edge + api."
    assert upsert.json()["confidence"] == "confirmed"

    listing = client.get(f"{INTEL_BASE}/tech-components")
    assert listing.status_code == 200, listing.text
    assert len(listing.json()) == 1, "UPSERT must not create a duplicate row"

    # extra="forbid" violation → 422
    bad = client.post(
        f"{INTEL_BASE}/tech-components",
        json={**payload, "bogus_field": "should-reject"},
    )
    assert bad.status_code == 422, bad.text

    # summary counts
    assert _summary(client).get("tech_components", 0) == before + 1

    # FTS search hit
    hits = _assert_present_in_search(client, "nginx")
    assert any(hit.get("entity_type") == "tech_component" for hit in hits), hits


# ──────────────────────────────────────────────────────────────
# people + emails
# ──────────────────────────────────────────────────────────────


def test_person_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "name": "Jane Doe",
        "role": "Security Lead",
        "organization": "acme Inc.",
        "email": "jane@acme.example",
        "source_name": "linkedin",
        "notes": "Public profile.",
        "provenance": {"agent_name": "osint-analyst"},
    }

    created = client.post(f"{INTEL_BASE}/people", json=payload)
    assert created.status_code == 201, created.text
    row = created.json()
    assert row["name"] == "Jane Doe"

    listing = client.get(f"{INTEL_BASE}/people")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    # UPSERT on name
    payload["role"] = "CISO"
    upsert = client.post(f"{INTEL_BASE}/people", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["role"] == "CISO"
    assert len(client.get(f"{INTEL_BASE}/people").json()) == 1

    bad = client.post(f"{INTEL_BASE}/people", json={**payload, "junk": 1})
    assert bad.status_code == 422

    assert _summary(client).get("people", 0) == 1
    assert _assert_present_in_search(client, "Jane")


def test_email_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "address": "admin@example.com",
        "role_hint": "administrator",
        "source_name": "hunter.io",
        "notes": "From public leak list.",
    }

    created = client.post(f"{INTEL_BASE}/emails", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["address"] == "admin@example.com"

    listing = client.get(f"{INTEL_BASE}/emails")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["role_hint"] = "root"
    upsert = client.post(f"{INTEL_BASE}/emails", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["role_hint"] == "root"
    assert len(client.get(f"{INTEL_BASE}/emails").json()) == 1

    bad = client.post(f"{INTEL_BASE}/emails", json={**payload, "extra": "x"})
    assert bad.status_code == 422

    assert _summary(client).get("emails", 0) == 1
    assert _assert_present_in_search(client, "admin@example.com")


# ──────────────────────────────────────────────────────────────
# domains — covers /by-url too
# ──────────────────────────────────────────────────────────────


def test_domain_post_get_upsert_and_by_url(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "identity": "api.example.com",
        "kind": "subdomain",
        "value": "10.0.0.1",
        "source_name": "amass",
        "live_status": "up",
        "notes": "Discovered via passive DNS.",
        "provenance": {"agent_name": "osint-analyst"},
    }

    created = client.post(f"{INTEL_BASE}/domains", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["identity"] == "api.example.com"

    listing = client.get(f"{INTEL_BASE}/domains")
    assert listing.status_code == 200
    assert any(row["identity"] == "api.example.com" for row in listing.json())

    payload["live_status"] = "tested"
    upsert = client.post(f"{INTEL_BASE}/domains", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["live_status"] == "tested"
    assert len([r for r in client.get(f"{INTEL_BASE}/domains").json() if r["identity"] == "api.example.com"]) == 1

    bad = client.post(f"{INTEL_BASE}/domains", json={**payload, "not_a_field": True})
    assert bad.status_code == 422

    # Cross-table /by-url merge: seed an assessment_services row via
    # request-observations so by-url returns both intel_domains and
    # assessment_services hits for the same host.
    ingest = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/request-observations",
        json={"url": "https://api.example.com/health", "discovery_source": "recon"},
    )
    assert ingest.status_code == 201, ingest.text

    response = client.get(
        f"{INTEL_BASE}/by-url",
        params={"url": "https://api.example.com/health"},
    )
    assert response.status_code == 200, response.text
    merged = response.json()
    assert any(d["identity"] == "api.example.com" for d in merged.get("domains", [])), merged
    assert isinstance(merged.get("services"), list), merged
    # At least one of the cross-table sections must have hits; by-url is
    # advertised as a merged view and should never return completely empty
    # sections when intel_domains already matches.
    assert (
        merged["domains"] or merged["services"] or merged["surfaces"] or merged["request_variants"]
    ), merged

    assert _assert_present_in_search(client, "api.example.com")


# ──────────────────────────────────────────────────────────────
# cves
# ──────────────────────────────────────────────────────────────


def test_cve_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "cve_id": "CVE-2024-12345",
        "affected_component": "nginx",
        "affected_version_range": "<1.25.1",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-20",
        "poc_available": True,
        "validation_status": "version_match",
        "source_name": "nvd",
        "notes": "Affects edge nginx on the hostname.",
    }

    created = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["cve_id"] == "CVE-2024-12345"

    listing = client.get(f"{INTEL_BASE}/cves")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["validation_status"] = "exploited"
    upsert = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["validation_status"] == "exploited"
    assert len(client.get(f"{INTEL_BASE}/cves").json()) == 1

    bad = client.post(f"{INTEL_BASE}/cves", json={**payload, "x": 1})
    assert bad.status_code == 422

    bad_score = client.post(
        f"{INTEL_BASE}/cves",
        json={**payload, "cvss_score": 42.0},
    )
    assert bad_score.status_code == 422

    assert _summary(client).get("cves", 0) == 1
    assert _assert_present_in_search(client, "CVE-2024-12345")


# ──────────────────────────────────────────────────────────────
# dns-records
# ──────────────────────────────────────────────────────────────


def test_dns_record_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "record_type": "A",
        "name": "edge.example.com",
        "value": "203.0.113.10",
        "first_seen": "2026-01-01",
        "last_seen": "2026-04-17",
        "source_name": "securitytrails",
        "notes": "Primary A record.",
    }

    created = client.post(f"{INTEL_BASE}/dns-records", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "edge.example.com"

    listing = client.get(f"{INTEL_BASE}/dns-records")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["last_seen"] = "2026-04-17T12:00:00Z"
    upsert = client.post(f"{INTEL_BASE}/dns-records", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["last_seen"].startswith("2026-04-17")
    assert len(client.get(f"{INTEL_BASE}/dns-records").json()) == 1

    bad = client.post(f"{INTEL_BASE}/dns-records", json={**payload, "mystery": 1})
    assert bad.status_code == 422

    assert _summary(client).get("dns_records", 0) == 1
    assert _assert_present_in_search(client, "edge.example.com")


# ──────────────────────────────────────────────────────────────
# social-profiles
# ──────────────────────────────────────────────────────────────


def test_social_profile_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "subject_kind": "person",
        "subject_ref": "Jane Doe",
        "platform": "linkedin",
        "handle": "jane-doe",
        "url": "https://linkedin.com/in/jane-doe",
        "source_name": "linkedin-scrape",
        "notes": "Public profile.",
    }

    created = client.post(f"{INTEL_BASE}/social-profiles", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["platform"] == "linkedin"

    listing = client.get(f"{INTEL_BASE}/social-profiles")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["notes"] = "Confirmed active."
    upsert = client.post(f"{INTEL_BASE}/social-profiles", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["notes"] == "Confirmed active."
    assert len(client.get(f"{INTEL_BASE}/social-profiles").json()) == 1

    bad = client.post(f"{INTEL_BASE}/social-profiles", json={**payload, "z": 1})
    assert bad.status_code == 422

    assert _summary(client).get("social_profiles", 0) == 1
    assert _assert_present_in_search(client, "jane-doe")


# ──────────────────────────────────────────────────────────────
# breach-records
# ──────────────────────────────────────────────────────────────


def test_breach_record_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "subject": "admin@example.com",
        "breach_name": "Collection#1",
        "breach_date": "2019-01-01",
        "data_types": "email,password",
        "source_name": "haveibeenpwned",
        "notes": "Exposed in public paste.",
    }

    created = client.post(f"{INTEL_BASE}/breach-records", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["breach_name"] == "Collection#1"

    listing = client.get(f"{INTEL_BASE}/breach-records")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["notes"] = "Confirmed reuse."
    upsert = client.post(f"{INTEL_BASE}/breach-records", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["notes"] == "Confirmed reuse."
    assert len(client.get(f"{INTEL_BASE}/breach-records").json()) == 1

    bad = client.post(f"{INTEL_BASE}/breach-records", json={**payload, "zz": 1})
    assert bad.status_code == 422

    assert _summary(client).get("breach_records", 0) == 1
    assert _assert_present_in_search(client, "Collection")


# ──────────────────────────────────────────────────────────────
# org-facts
# ──────────────────────────────────────────────────────────────


def test_org_fact_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "fact_key": "Founded",
        "fact_value": "2014",
        "source_name": "opencorporates",
        "notes": "Public record.",
    }

    created = client.post(f"{INTEL_BASE}/org-facts", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["fact_key"] == "Founded"

    listing = client.get(f"{INTEL_BASE}/org-facts")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["fact_value"] = "2013"
    upsert = client.post(f"{INTEL_BASE}/org-facts", json=payload)
    assert upsert.status_code == 201
    assert upsert.json()["fact_value"] == "2013"
    assert len(client.get(f"{INTEL_BASE}/org-facts").json()) == 1

    bad = client.post(f"{INTEL_BASE}/org-facts", json={**payload, "x": "y"})
    assert bad.status_code == 422

    assert _summary(client).get("org_facts", 0) == 1
    assert _assert_present_in_search(client, "Founded")


# ──────────────────────────────────────────────────────────────
# notes
# ──────────────────────────────────────────────────────────────


def test_note_post_get_upsert_and_extra_forbid(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    payload = {
        "title": "Recon summary",
        "body_markdown": "## Recon\n- Found login at /admin",
        "source_agent": "osint-analyst",
        "tags": ["recon", "auth"],
        "source_name": "osint-analyst",
    }

    created = client.post(f"{INTEL_BASE}/notes", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["title"] == "Recon summary"

    listing = client.get(f"{INTEL_BASE}/notes")
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    payload["body_markdown"] = "## Recon\n- Found login at /admin\n- Found /api"
    upsert = client.post(f"{INTEL_BASE}/notes", json=payload)
    assert upsert.status_code == 201
    assert "/api" in upsert.json()["body_markdown"]
    assert len(client.get(f"{INTEL_BASE}/notes").json()) == 1

    bad = client.post(f"{INTEL_BASE}/notes", json={**payload, "nope": 1})
    assert bad.status_code == 422

    assert _summary(client).get("notes", 0) == 1
    assert _assert_present_in_search(client, "Recon")


# ──────────────────────────────────────────────────────────────
# /intel/credentials alias
# ──────────────────────────────────────────────────────────────


def test_intel_credentials_alias_is_readable(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    response = client.get(f"{INTEL_BASE}/credentials")
    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


# ──────────────────────────────────────────────────────────────
# summary counts increment across multiple types
# ──────────────────────────────────────────────────────────────


def test_summary_counts_increment_across_types(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    before = _summary(client)

    posts = [
        ("/tech-components", {"component": "postgres", "version": "15.2"}),
        ("/people", {"name": "John Roe"}),
        ("/emails", {"address": "j@example.com"}),
        ("/domains", {"identity": "db.example.com", "kind": "subdomain"}),
        ("/cves", {"cve_id": "CVE-2025-0001"}),
        ("/dns-records", {"record_type": "TXT", "name": "_dmarc.example.com"}),
        ("/social-profiles", {"subject_kind": "org", "platform": "github", "handle": "example"}),
        ("/breach-records", {"subject": "j@example.com", "breach_name": "Leak-X"}),
        ("/org-facts", {"fact_key": "HQ", "fact_value": "NYC"}),
        ("/notes", {"title": "Kickoff notes"}),
    ]
    for path, body in posts:
        resp = client.post(f"{INTEL_BASE}{path}", json=body)
        assert resp.status_code == 201, f"{path}: {resp.text}"

    after = _summary(client)
    # Every type we posted must have a strictly larger count than before.
    for key in (
        "tech_components",
        "people",
        "emails",
        "domains",
        "cves",
        "dns_records",
        "social_profiles",
        "breach_records",
        "org_facts",
        "notes",
    ):
        assert after.get(key, 0) > before.get(key, 0), (key, before, after)


# ──────────────────────────────────────────────────────────────
# search respects entity_type filter
# ──────────────────────────────────────────────────────────────


def test_intel_search_entity_type_filter(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "Apache Tomcat", "version": "9.0.80"},
    )
    client.post(f"{INTEL_BASE}/people", json={"name": "Apache Maintainer"})

    tech_hits = _assert_present_in_search(client, "Apache", entity_type="tech_component")
    assert all(hit.get("entity_type") == "tech_component" for hit in tech_hits), tech_hits

    person_hits = _assert_present_in_search(client, "Apache", entity_type="person")
    assert all(hit.get("entity_type") == "person" for hit in person_hits), person_hits


# ──────────────────────────────────────────────────────────────
# unknown engagement key returns 404 on every route
# ──────────────────────────────────────────────────────────────


def test_unknown_engagement_returns_404(client, isolate_settings):
    base = "/engagements/does-not-exist/intel"
    assert client.get(f"{base}/summary").status_code == 404
    assert client.get(f"{base}/tech-components").status_code == 404
    assert client.post(f"{base}/notes", json={"title": "x"}).status_code == 404
