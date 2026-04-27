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
# N8 — CVE validation_status enum extension
# ──────────────────────────────────────────────────────────────


def test_cve_validation_status_accepts_poc_available_unverified(client, isolate_settings):
    """N8 — `poc_available_unverified` is a valid validation_status."""
    _seed_engagement(client, isolate_settings)
    payload = {
        "cve_id": "CVE-2024-99001",
        "affected_component": "openssl",
        "poc_available": True,
        "validation_status": "poc_available_unverified",
        "source_name": "github-osint",
    }
    response = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["validation_status"] == "poc_available_unverified"


def test_cve_validation_status_attempted_blocked_requires_block_reason(
    client, isolate_settings
):
    """N8 — validation_status='attempted_blocked' requires details.block_reason."""
    _seed_engagement(client, isolate_settings)
    payload = {
        "cve_id": "CVE-2024-99002",
        "affected_component": "rails",
        "validation_status": "attempted_blocked",
        # No details / no block_reason — must reject.
    }
    response = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert response.status_code == 422, response.text
    body = response.text.lower()
    assert "block_reason" in body


def test_cve_validation_status_attempted_blocked_persists_block_reason(
    client, isolate_settings
):
    """N8 — `attempted_blocked` with details.block_reason is accepted and the block_reason
    round-trips."""
    _seed_engagement(client, isolate_settings)
    payload = {
        "cve_id": "CVE-2024-99003",
        "affected_component": "wordpress",
        "validation_status": "attempted_blocked",
        "details": {"block_reason": "WAF intercepted the PoC at the edge"},
    }
    response = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["validation_status"] == "attempted_blocked"
    assert body["details"]["block_reason"] == "WAF intercepted the PoC at the edge"


def test_cve_validation_status_rejects_old_dropped_value(client, isolate_settings):
    """N8 — values outside the new six-member enum are rejected."""
    _seed_engagement(client, isolate_settings)
    payload = {
        "cve_id": "CVE-2024-99004",
        "affected_component": "spring",
        "validation_status": "made-up-status",
    }
    response = client.post(f"{INTEL_BASE}/cves", json=payload)
    assert response.status_code == 422


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


# ──────────────────────────────────────────────────────────────
# update + supersede + listing filter behavior
# ──────────────────────────────────────────────────────────────


def test_update_intel_patches_existing_row_and_rejects_unknown_field(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "vendor-saas-platform", "version": "1.0.0", "source_name": "wappalyzer"},
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    patched = client.patch(
        f"{INTEL_BASE}/tech-components/{intel_id}",
        json={"payload": {"confidence": "confirmed", "notes": "Re-fingerprinted"}},
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["id"] == intel_id
    assert body["confidence"] == "confirmed"
    assert body["notes"] == "Re-fingerprinted"

    # unknown field surfaces as a structured error rather than silently dropping.
    bad = client.patch(
        f"{INTEL_BASE}/tech-components/{intel_id}",
        json={"payload": {"version_label": "x"}},
    )
    assert bad.status_code == 400, bad.text


def test_supersede_intel_marks_old_row_and_filters_from_list(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "vendor-saas-platform", "version": "1.0.0", "source_name": "wappalyzer"},
    )
    assert created.status_code == 201, created.text
    old_id = created.json()["id"]

    superseded = client.post(
        f"{INTEL_BASE}/tech-components/{old_id}/supersede",
        json={
            "payload": {
                "component": "vendor-saas-platform",
                "version": "2.0.0",
                "source_name": "vulnerability-analyst",
                "confidence": "confirmed",
            },
            "rationale": "Banner re-fingerprinted; version bumped",
        },
    )
    assert superseded.status_code == 201, superseded.text
    body = superseded.json()
    assert body["current"]["version"] == "2.0.0"
    new_id = body["current"]["id"]
    assert new_id != old_id
    assert body["superseded"]["superseded_by_id"] == new_id
    assert body["superseded"]["superseded_at"]
    assert "[superseded-by id=" in body["superseded"]["notes"]

    # Default list endpoint includes both rows so the UI can render
    # historical state distinctly.
    listing = client.get(f"{INTEL_BASE}/tech-components")
    assert listing.status_code == 200
    items = listing.json()
    ids = {row["id"] for row in items}
    assert ids == {old_id, new_id}

    # The old row is still queryable but flagged.
    old_row = next(row for row in items if row["id"] == old_id)
    assert old_row["superseded_by_id"] == new_id


def test_supersede_intel_collision_with_natural_key_returns_409(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "vendor-saas-platform", "version": "1.0.0", "source_name": "wappalyzer"},
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    # Same natural key (component, version) → service helper raises 409.
    collision = client.post(
        f"{INTEL_BASE}/tech-components/{intel_id}/supersede",
        json={
            "payload": {"component": "vendor-saas-platform", "version": "1.0.0"},
            "rationale": "Wrong call — should have been update-intel",
        },
    )
    assert collision.status_code == 409, collision.text


def test_update_intel_unknown_id_returns_404(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    response = client.patch(
        f"{INTEL_BASE}/tech-components/9999",
        json={"payload": {"notes": "ghost"}},
    )
    assert response.status_code == 404, response.text


# ──────────────────────────────────────────────────────────────
# include_superseded query param + canonical_id wire shape
# ──────────────────────────────────────────────────────────────


def test_list_intel_include_superseded_false_filters_old_rows(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "filter-test", "version": "1.0.0"},
    )
    assert created.status_code == 201, created.text
    old_id = created.json()["id"]

    superseded = client.post(
        f"{INTEL_BASE}/tech-components/{old_id}/supersede",
        json={"payload": {"component": "filter-test", "version": "2.0.0"}},
    )
    assert superseded.status_code == 201, superseded.text
    new_id = superseded.json()["current"]["id"]

    # Default (include_superseded=true) returns both rows.
    listing = client.get(f"{INTEL_BASE}/tech-components")
    assert listing.status_code == 200
    ids = {row["id"] for row in listing.json()}
    assert ids == {old_id, new_id}

    # Explicit include_superseded=false drops the historical row.
    filtered = client.get(
        f"{INTEL_BASE}/tech-components",
        params={"include_superseded": "false"},
    )
    assert filtered.status_code == 200, filtered.text
    filtered_ids = {row["id"] for row in filtered.json()}
    assert filtered_ids == {new_id}


def test_list_intel_canonical_id_walks_to_leaf(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    first = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "canonical-test", "version": "1.0.0"},
    )
    a_id = first.json()["id"]
    second = client.post(
        f"{INTEL_BASE}/tech-components/{a_id}/supersede",
        json={"payload": {"component": "canonical-test", "version": "2.0.0"}},
    )
    b_id = second.json()["current"]["id"]
    third = client.post(
        f"{INTEL_BASE}/tech-components/{b_id}/supersede",
        json={"payload": {"component": "canonical-test", "version": "3.0.0"}},
    )
    c_id = third.json()["current"]["id"]

    rows = client.get(f"{INTEL_BASE}/tech-components").json()
    by_id = {row["id"]: row for row in rows}
    assert by_id[a_id]["canonical_id"] == c_id
    assert by_id[b_id]["canonical_id"] == c_id
    assert by_id[c_id]["canonical_id"] == c_id


# ──────────────────────────────────────────────────────────────
# supersede payload validation (P1 #4)
# ──────────────────────────────────────────────────────────────


def test_supersede_intel_missing_natural_key_returns_400(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "missing-key-test", "version": "1.0.0"},
    )
    intel_id = created.json()["id"]

    # Omit ``component`` (the natural key) — service must surface 400, not 500.
    bad = client.post(
        f"{INTEL_BASE}/tech-components/{intel_id}/supersede",
        json={"payload": {"version": "2.0.0", "notes": "no component"}},
    )
    assert bad.status_code == 400, bad.text
    assert "component" in bad.json().get("detail", "").lower()


def test_supersede_intel_dns_record_missing_compound_key_returns_400(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/dns-records",
        json={"record_type": "A", "name": "alpha.example.com"},
    )
    intel_id = created.json()["id"]

    # Compound natural key (record_type, name) — omitting either must surface 400.
    missing_name = client.post(
        f"{INTEL_BASE}/dns-records/{intel_id}/supersede",
        json={"payload": {"record_type": "A"}},
    )
    assert missing_name.status_code == 400, missing_name.text


# ──────────────────────────────────────────────────────────────
# supersede cycle guard (P1 #6)
# ──────────────────────────────────────────────────────────────


def test_supersede_intel_self_collision_returns_409(client, isolate_settings):
    """Self-supersede via natural-key collision must surface 409."""
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "self-test", "version": "1.0.0"},
    )
    intel_id = created.json()["id"]

    self_collide = client.post(
        f"{INTEL_BASE}/tech-components/{intel_id}/supersede",
        json={"payload": {"component": "self-test", "version": "1.0.0"}},
    )
    assert self_collide.status_code == 409, self_collide.text


def test_supersede_intel_cycle_returns_409(client, isolate_settings):
    """Supersede A->B then B->A would close a cycle; must surface 409."""
    _seed_engagement(client, isolate_settings)

    a = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "cycle-test", "version": "1.0.0"},
    )
    a_id = a.json()["id"]
    ab = client.post(
        f"{INTEL_BASE}/tech-components/{a_id}/supersede",
        json={"payload": {"component": "cycle-test", "version": "2.0.0"}},
    )
    b_id = ab.json()["current"]["id"]

    # Attempting to point B back at A's natural key would already collide on
    # natural key (would re-upsert into A) and surface 409 anyway. The cycle
    # guard catches the harder case where the new payload has its OWN natural
    # key but the resulting row already supersedes back to the target.
    # Re-superseding A -> B via a payload that resolves to B's existing id
    # would close the loop — but since record_fn upserts and natural key
    # uniquely maps to one row, the explicit cycle requires a 3-row chain.
    abc = client.post(
        f"{INTEL_BASE}/tech-components/{b_id}/supersede",
        json={"payload": {"component": "cycle-test", "version": "3.0.0"}},
    )
    c_id = abc.json()["current"]["id"]

    # A->B->C exists. Now try to supersede C with A's natural key — that
    # would resolve to A, which is already superseded by B which is
    # already superseded by C: i.e., A already transitively supersedes
    # back to C from C's perspective once we link C->A.
    # Since record_fn upserts on (component, version) the only way to land
    # on A's id from new payload is to re-use A's natural key:
    cycle_attempt = client.post(
        f"{INTEL_BASE}/tech-components/{c_id}/supersede",
        json={"payload": {"component": "cycle-test", "version": "1.0.0"}},
    )
    assert cycle_attempt.status_code == 409, cycle_attempt.text


# ──────────────────────────────────────────────────────────────
# 404 differentiation (P3 #10)
# ──────────────────────────────────────────────────────────────


def test_supersede_404_messages_differ_for_engagement_type_id(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "diff-404-test", "version": "1.0.0"},
    )
    intel_id = created.json()["id"]

    # Unknown engagement.
    unknown_engagement = client.patch(
        "/engagements/no-such-engagement/intel/tech-components/1",
        json={"payload": {"notes": "x"}},
    )
    assert unknown_engagement.status_code == 404
    engagement_detail = unknown_engagement.json().get("detail", "").lower()

    # Unknown intel type segment.
    unknown_type = client.patch(
        f"{INTEL_BASE}/no-such-type/{intel_id}",
        json={"payload": {"notes": "x"}},
    )
    assert unknown_type.status_code == 404
    type_detail = unknown_type.json().get("detail", "")

    # Unknown intel id within a known type.
    unknown_id = client.patch(
        f"{INTEL_BASE}/tech-components/9999999",
        json={"payload": {"notes": "x"}},
    )
    assert unknown_id.status_code == 404
    id_detail = unknown_id.json().get("detail", "")

    # All three must use distinct detail messages so the caller can tell
    # which dimension was wrong without parsing the URL.
    details = {engagement_detail, type_detail.lower(), id_detail.lower()}
    assert len(details) == 3, details
    assert "engagement" in engagement_detail
    assert "no-such-type" in type_detail
    assert "9999999" in id_detail
