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
AUTHOR_AGENT_ID = "INTEL-CREDENTIAL-AUTHOR"


def _seed_engagement(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    # Trigger filesystem discovery + engagement row creation.
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    dispatch = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record intel credential fixture findings",
        },
    )
    assert dispatch.status_code == 201, dispatch.text


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
        "organization": "Acme Corp.",
        "email": "jane@acme-corp.example",
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


def test_update_cve_attempted_blocked_persists_details_block_reason(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/cves",
        json={
            "cve_id": "CVE-2024-99005",
            "affected_component": "tomcat",
            "validation_status": "poc_available_unverified",
        },
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    missing_reason = client.patch(
        f"{INTEL_BASE}/cves/{intel_id}",
        json={"payload": {"validation_status": "attempted_blocked"}},
    )
    assert missing_reason.status_code == 400, missing_reason.text
    assert "block_reason" in missing_reason.text

    patched = client.patch(
        f"{INTEL_BASE}/cves/{intel_id}",
        json={
            "payload": {
                "validation_status": "attempted_blocked",
                "details": {"block_reason": "Exploit path blocked by upstream WAF"},
            }
        },
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["validation_status"] == "attempted_blocked"
    assert body["details"]["block_reason"] == "Exploit path blocked by upstream WAF"


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


def test_authored_knowledge_has_explicit_scope_validity_and_attribution(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    defaulted = client.post(
        f"{INTEL_BASE}/org-facts",
        json={
            "fact_key": "service_significance",
            "fact_value": "billing system",
            "source_name": "operator",
        },
    )
    assert defaulted.status_code == 201, defaulted.text
    assert defaulted.json()["provenance"] == {}
    assert defaulted.json()["authored_by"] == "operator"
    assert defaulted.json()["scope"] == "engagement"
    assert defaulted.json()["validity_context"] == (
        "unreviewed; revalidate before relying on this interpretation"
    )

    explicit = client.post(
        f"{INTEL_BASE}/notes",
        json={
            "title": "Identity boundary",
            "body_markdown": "Billing admins can view invoices for their own org.",
            "source_agent": "vulnerability-analyst",
            "authored_by": "vulnerability-analyst",
            "scope": "host:billing.example.com identity:billing-admin",
            "validity_context": "observed in source snapshot generation 7",
            "provenance": {"agent_name": "vulnerability-analyst"},
        },
    )
    assert explicit.status_code == 201, explicit.text
    assert explicit.json()["provenance"] == {"agent_name": "vulnerability-analyst"}
    assert explicit.json()["authored_by"] == "vulnerability-analyst"
    assert explicit.json()["scope"] == "host:billing.example.com identity:billing-admin"
    assert explicit.json()["validity_context"] == (
        "observed in source snapshot generation 7"
    )

    patched = client.patch(
        f"{INTEL_BASE}/notes/{explicit.json()['id']}",
        json={"payload": {"provenance": {"agent_name": "reviewer"}}},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["provenance"] == {"agent_name": "reviewer"}
    assert patched.json()["authored_by"] == "vulnerability-analyst"
    assert patched.json()["scope"] == "host:billing.example.com identity:billing-admin"
    assert patched.json()["validity_context"] == (
        "observed in source snapshot generation 7"
    )


def test_authored_context_additive_migration_preserves_legacy_intel(
    isolate_settings,
):
    import sqlite3

    from app import db as db_module

    db_module.init_db()
    db_module.close_thread_connection()
    path = db_module.database_path()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO engagements (id, key, target, status, engagement_root) "
            "VALUES (1, 'legacy', 'https://example.com', 'active', '/tmp/legacy')"
        )
        connection.execute(
            "INSERT INTO intel_org_facts "
            "(engagement_id, fact_key, fact_value, provenance_json) "
            "VALUES (1, 'ownership', 'Example Holdings', '{\"source\":\"archive\"}')"
        )
        connection.execute(
            "INSERT INTO intel_notes "
            "(engagement_id, title, body_markdown, provenance_json) "
            "VALUES (1, 'Legacy note', 'preserve me', '{\"source\":\"operator\"}')"
        )
        for table in ("intel_org_facts", "intel_notes"):
            for column in ("authored_by", "scope", "validity_context"):
                connection.execute(f"ALTER TABLE {table} DROP COLUMN {column}")

    db_module.init_db()

    with sqlite3.connect(path) as connection:
        fact = connection.execute(
            "SELECT fact_value, provenance_json, authored_by, scope, validity_context "
            "FROM intel_org_facts WHERE fact_key = 'ownership'"
        ).fetchone()
        note = connection.execute(
            "SELECT body_markdown, provenance_json, authored_by, scope, validity_context "
            "FROM intel_notes WHERE title = 'Legacy note'"
        ).fetchone()
    assert fact == (
        "Example Holdings",
        '{"source":"archive"}',
        "unknown",
        "engagement",
        "unreviewed; revalidate before relying on this interpretation",
    )
    assert note == (
        "preserve me",
        '{"source":"operator"}',
        "unknown",
        "engagement",
        "unreviewed; revalidate before relying on this interpretation",
    )


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


def test_supersede_note_with_rationale_appends_to_body_markdown(client, isolate_settings):
    # Regression: `supersede-intel note --rationale` 500'd because the rationale
    # was appended to a `notes` column that intel_notes does not have (its free
    # text is body_markdown). The note type must append to body_markdown; every
    # other intel type keeps using its `notes` column (covered above).
    _seed_engagement(client, isolate_settings)
    created = client.post(
        f"{INTEL_BASE}/notes",
        json={"title": "Lead v1", "body_markdown": "## Lead\n- initial", "source_agent": "operator"},
    )
    assert created.status_code == 201, created.text
    old_id = created.json()["id"]

    # A DIFFERENT title is a supersede (same title would upsert in place -> 409).
    superseded = client.post(
        f"{INTEL_BASE}/notes/{old_id}/supersede",
        json={
            "payload": {
                "title": "Lead v2",
                "body_markdown": "## Lead\n- refined",
                "source_agent": "operator",
            },
            "rationale": "Re-scoped after source-map pass",
        },
    )
    assert superseded.status_code == 201, superseded.text  # regression: previously 500
    body = superseded.json()
    new_id = body["current"]["id"]
    assert new_id != old_id
    old = body["superseded"]
    assert old["superseded_by_id"] == new_id
    assert old["superseded_at"]
    # The rationale landed in body_markdown (the column that exists), not `notes`.
    assert "[superseded-by id=" in old["body_markdown"]
    assert "Re-scoped after source-map pass" in old["body_markdown"]


def test_note_lead_status_lifecycle(client, isolate_settings):
    """A note with lead_status is a tracked lead; list_leads(open_only) is the
    worklist; PATCH to a terminal status drops it; bad status is 422; the migration
    is idempotent."""
    import sqlite3

    from app import db as db_module
    from app.services import intel as intel_service

    _seed_engagement(client, isolate_settings)

    # Plain reference note — not a lead.
    ref = client.post(f"{INTEL_BASE}/notes", json={"title": "Reference: tech stack"})
    assert ref.status_code == 201, ref.text
    assert ref.json().get("lead_status") in (None, "")

    # A tracked lead.
    lead = client.post(
        f"{INTEL_BASE}/notes",
        json={
            "title": "Lead: Axis SSRF untested",
            "body_markdown": "Axis 1.x AdminService reachable; SSRF not yet attempted.",
            "lead_status": "open",
        },
    )
    assert lead.status_code == 201, lead.text
    assert lead.json()["lead_status"] == "open"
    lead_id = lead.json()["id"]

    # Invalid status rejected on POST (Pydantic Literal) and on PATCH/supersede
    # (service-level _validate_lead_status, since those bypass the Literal).
    bad = client.post(f"{INTEL_BASE}/notes", json={"title": "x", "lead_status": "bogus"})
    assert bad.status_code == 422, bad.text
    bad_patch = client.patch(
        f"{INTEL_BASE}/notes/{lead_id}", json={"payload": {"lead_status": "bogus"}}
    )
    assert bad_patch.status_code == 400, bad_patch.text

    # FTS round-trip (lead body indexed).
    assert _assert_present_in_search(client, "Axis")

    with sqlite3.connect(str(db_module.database_path())) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()[0]

    # Worklist = the open lead only (reference note excluded).
    open_titles = [r["title"] for r in intel_service.list_leads(engagement_id, open_only=True)]
    assert open_titles == ["Lead: Axis SSRF untested"], open_titles

    # Disposition it -> drops from the worklist but remains queryable.
    patched = client.patch(
        f"{INTEL_BASE}/notes/{lead_id}",
        json={"payload": {"lead_status": "resolved"}},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["lead_status"] == "resolved"
    assert intel_service.list_leads(engagement_id, open_only=True) == []
    all_titles = [r["title"] for r in intel_service.list_leads(engagement_id, open_only=False)]
    assert all_titles == ["Lead: Axis SSRF untested"], all_titles

    # Migration is idempotent — re-running init_db() does not error or duplicate.
    db_module.init_db()
    with sqlite3.connect(str(db_module.database_path())) as connection:
        cols = {row[1] for row in connection.execute("PRAGMA table_info(intel_notes)").fetchall()}
    assert "lead_status" in cols


# ──────────────────────────────────────────────────────────────
# /intel/credentials alias
# ──────────────────────────────────────────────────────────────


def test_intel_credentials_alias_is_readable(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    response = client.get(f"{INTEL_BASE}/credentials")
    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list)


def test_intel_credentials_alias_applies_limit_and_offset(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    assessment_base = f"/engagements/{ENGAGEMENT_KEY}/assessment"
    for index in range(3):
        created = client.post(
            f"{assessment_base}/credentials",
            json={
                "credential_key": f"opaque-{index}",
                "kind": "token",
                "principal": f"principal-{index}",
                "provenance": {"agent_id": AUTHOR_AGENT_ID},
            },
        )
        assert created.status_code == 201, created.text

    page = client.get(
        f"{INTEL_BASE}/credentials", params={"limit": 1, "offset": 1}
    )

    assert page.status_code == 200, page.text
    assert [row["credential_key"] for row in page.json()] == ["opaque-1"]


def test_typed_intel_list_applies_limit_and_offset_in_the_api(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    for index in range(3):
        response = client.post(
            f"{INTEL_BASE}/notes",
            json={"title": f"Paged note {index}", "body_markdown": f"body {index}"},
        )
        assert response.status_code == 201, response.text

    page = client.get(f"{INTEL_BASE}/notes", params={"limit": 1, "offset": 1})

    assert page.status_code == 200, page.text
    assert [row["title"] for row in page.json()] == ["Paged note 1"]


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


def test_intel_search_filters_by_lead_status_and_provenance(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    for title, lead_status, run_id in (
        ("Open lead", "open", "run-alpha"),
        ("Closed lead", "resolved", "run-beta"),
    ):
        response = client.post(
            f"{INTEL_BASE}/notes",
            json={
                "title": title,
                "lead_status": lead_status,
                "provenance": {"run_id": run_id},
            },
        )
        assert response.status_code == 201, response.text

    response = client.get(
        f"{INTEL_BASE}/search",
        params={"lead_status": "open", "provenance": "run-alpha"},
    )
    assert response.status_code == 200, response.text
    assert [hit["record"]["title"] for hit in response.json()] == ["Open lead"]

    invalid = client.get(f"{INTEL_BASE}/search", params={"lead_status": "typo"})
    assert invalid.status_code == 422, invalid.text


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


def test_update_intel_natural_key_collision_returns_409(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    first = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "vendor-saas-platform", "version": "1.0.0", "source_name": "wappalyzer"},
    )
    assert first.status_code == 201, first.text
    second = client.post(
        f"{INTEL_BASE}/tech-components",
        json={"component": "vendor-saas-platform", "version": "2.0.0", "source_name": "manual"},
    )
    assert second.status_code == 201, second.text
    second_id = second.json()["id"]

    collision = client.patch(
        f"{INTEL_BASE}/tech-components/{second_id}",
        json={"payload": {"version": "1.0.0"}},
    )
    assert collision.status_code == 409, collision.text
    assert "natural key" in collision.text

    rows = client.get(f"{INTEL_BASE}/tech-components").json()
    by_id = {row["id"]: row for row in rows}
    assert by_id[second_id]["version"] == "2.0.0"
    assert by_id[second_id]["source_name"] == "manual"


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

    # Same natural key (component, version) -> service helper raises 409
    # without first upserting the target row.
    collision = client.post(
        f"{INTEL_BASE}/tech-components/{intel_id}/supersede",
        json={
            "payload": {
                "component": "vendor-saas-platform",
                "version": "1.0.0",
                "source_name": "should-not-be-written",
            },
            "rationale": "Wrong call — should have been update-intel",
        },
    )
    assert collision.status_code == 409, collision.text
    row = client.get(f"{INTEL_BASE}/tech-components").json()[0]
    assert row["id"] == intel_id
    assert row["source_name"] == "wappalyzer"
    assert row["superseded_by_id"] is None


def test_supersede_cve_requires_full_natural_key(client, isolate_settings):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/cves",
        json={
            "cve_id": "CVE-2025-1111",
            "affected_component": "openssl",
            "source_name": "nvd",
        },
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    missing_component = client.post(
        f"{INTEL_BASE}/cves/{intel_id}/supersede",
        json={
            "payload": {
                "cve_id": "CVE-2025-1111",
                "source_name": "operator-review",
            },
            "rationale": "Should not create an empty-component replacement",
        },
    )
    assert missing_component.status_code == 400, missing_component.text
    assert "affected_component" in missing_component.text

    rows = client.get(f"{INTEL_BASE}/cves").json()
    assert len(rows) == 1
    assert rows[0]["id"] == intel_id
    assert rows[0]["affected_component"] == "openssl"
    assert rows[0]["superseded_by_id"] is None


def test_supersede_cve_attempted_blocked_persists_details_block_reason(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)

    created = client.post(
        f"{INTEL_BASE}/cves",
        json={
            "cve_id": "CVE-2025-2222",
            "affected_component": "spring",
            "validation_status": "version_match",
        },
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    superseded = client.post(
        f"{INTEL_BASE}/cves/{intel_id}/supersede",
        json={
            "payload": {
                "cve_id": "CVE-2025-2222",
                "affected_component": "spring-cloud-gateway",
                "validation_status": "attempted_blocked",
                "details": {"block_reason": "Exploit route requires unavailable admin role"},
            },
            "rationale": "Component scope refined during exploit review",
        },
    )
    assert superseded.status_code == 201, superseded.text
    body = superseded.json()
    assert body["current"]["validation_status"] == "attempted_blocked"
    assert (
        body["current"]["details"]["block_reason"]
        == "Exploit route requires unavailable admin role"
    )
    assert body["superseded"]["superseded_by_id"] == body["current"]["id"]


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

    # Compound natural key (record_type, name, value) — omitting any part
    # must surface 400.
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


# ──────────────────────────────────────────────────────────────
# CR-29 — `superseded_by_id` is a server-managed field, never a record input
# ──────────────────────────────────────────────────────────────

# (endpoint segment, minimal valid record payload) per intel type. Mirrors the
# natural-key minimums of the per-type request models in app.api.intel_schemas.
_CR29_MINIMAL_PAYLOADS: dict[str, dict[str, Any]] = {
    "tech-components": {"component": "nginx"},
    "people": {"name": "Jane Operator"},
    "emails": {"address": "jane@example.com"},
    "domains": {"identity": "api.example.com"},
    "cves": {"cve_id": "CVE-2024-0001"},
    "dns-records": {"record_type": "A", "name": "api.example.com"},
    "social-profiles": {"subject_kind": "person", "platform": "github"},
    "breach-records": {"subject": "jane@example.com", "breach_name": "ExampleLeak"},
    "org-facts": {"fact_key": "hq_city"},
    "notes": {"title": "CR-29 regression note"},
}


def test_record_intel_rejects_superseded_by_id_on_every_type(client, isolate_settings):
    """Adopting CR-29 option (b): supersession is a server-managed op via
    ``supersede-intel`` only. A record-time payload carrying ``superseded_by_id``
    must be rejected (extra="forbid" → 422) for every intel type, so an agent
    cannot manually point one row at another and forge a supersession chain."""
    _seed_engagement(client, isolate_settings)
    for segment, payload in _CR29_MINIMAL_PAYLOADS.items():
        # Baseline: the minimal payload itself is accepted.
        ok = client.post(f"{INTEL_BASE}/{segment}", json=payload)
        assert ok.status_code == 201, f"{segment} baseline: {ok.text}"
        # Same payload + the server-managed field → rejected, never silently
        # honored on the write path.
        bad = client.post(
            f"{INTEL_BASE}/{segment}",
            json={**payload, "superseded_by_id": 1},
        )
        assert bad.status_code == 422, f"{segment} must reject superseded_by_id: {bad.text}"


def test_intel_record_schemas_omit_superseded_by_id():
    """Anti-drift guard for CR-29. The bundled ``agent/schemas/intel-*.schema.json``
    record schemas are hand-maintained mirrors of the ``extra="forbid"`` POST
    request models (their ``$comment`` names the orchestrator as source of truth).
    Re-declaring ``superseded_by_id`` as a writable property is exactly the drift
    that let the CLI validator pass a payload the backend then 422s. Assert the
    field is absent from every record schema so the two cannot diverge again."""
    import json
    from pathlib import Path

    schema_dir = Path(__file__).resolve().parents[3] / "agent" / "schemas"
    schema_files = sorted(schema_dir.glob("intel-*.schema.json"))
    assert schema_files, f"no intel schemas found under {schema_dir}"
    offenders = []
    for schema_file in schema_files:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        if "superseded_by_id" in schema.get("properties", {}):
            offenders.append(schema_file.name)
    assert not offenders, (
        "superseded_by_id is server-managed (supersede-intel); it must not be a "
        f"record-schema property. Offending schemas: {offenders}"
    )


def test_intel_record_schemas_share_auditable_provenance_vocabulary():
    import json
    from pathlib import Path

    schema_dir = Path(__file__).resolve().parents[3] / "agent" / "schemas"
    for schema_file in sorted(schema_dir.glob("intel-*.schema.json")):
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        provenance = schema["properties"]["provenance"]["properties"]
        assert provenance["command_run_id"]["type"] == "integer", schema_file.name
        assert provenance["notes"]["type"] == "string", schema_file.name
        snapshot = provenance["code_snapshot"]
        assert snapshot["additionalProperties"] is False, schema_file.name
        assert snapshot["required"] == [
            "repo_id",
            "repo_generation",
            "source_manifest_digest",
        ], schema_file.name
        if schema_file.name in {
            "intel-note.schema.json",
            "intel-org-fact.schema.json",
        }:
            assert {
                "authored_by",
                "scope",
                "validity_context",
            } <= schema["properties"].keys(), schema_file.name


# ──────────────────────────────────────────────────────────────
# supersede --to-existing (I-15)
# ──────────────────────────────────────────────────────────────


def _post_tech(client, component: str, version: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"component": component, "version": version}
    payload.update(extra)
    response = client.post(f"{INTEL_BASE}/tech-components", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_supersede_to_existing_sets_fk_without_mutating_canonical(client, isolate_settings):
    """I-15: --to-existing points the stale row at an EXISTING same-type
    canonical row, setting ``superseded_by_id`` WITHOUT re-upserting — so the
    canonical's own fields are never overwritten."""
    _seed_engagement(client, isolate_settings)
    canonical = _post_tech(client, "nginx", "1.25.0", source_name="canon", notes="keep me")
    stale = _post_tech(client, "nginx", "1.25", source_name="stale")
    assert canonical["id"] != stale["id"]

    resp = client.post(
        f"{INTEL_BASE}/tech-components/{stale['id']}/supersede",
        json={"to_existing_id": canonical["id"], "rationale": "duplicate banner"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    # Stale row now defers to the canonical, with the rationale appended.
    assert body["superseded"]["id"] == stale["id"]
    assert body["superseded"]["superseded_by_id"] == canonical["id"]
    assert body["superseded"]["superseded_at"]
    assert "[superseded-by id=" in body["superseded"]["notes"]
    assert "duplicate banner" in body["superseded"]["notes"]

    # Canonical returned as "current" and its own fields are untouched.
    assert body["current"]["id"] == canonical["id"]
    assert body["current"]["component"] == "nginx"
    assert body["current"]["version"] == "1.25.0"
    assert body["current"]["notes"] == "keep me"
    assert body["current"].get("superseded_by_id") is None

    # No re-upsert happened: still exactly the two original rows (the audit
    # listing keeps superseded rows), and the stale row's canonical_id chases to
    # the canonical leaf while the canonical stays its own leaf.
    listing = client.get(f"{INTEL_BASE}/tech-components")
    assert listing.status_code == 200, listing.text
    rows = {row["id"]: row for row in listing.json()}
    assert set(rows) == {canonical["id"], stale["id"]}
    assert rows[stale["id"]]["canonical_id"] == canonical["id"]
    assert rows[canonical["id"]]["canonical_id"] == canonical["id"]


def test_supersede_to_existing_rejects_self(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    row = _post_tech(client, "redis", "7.2")
    resp = client.post(
        f"{INTEL_BASE}/tech-components/{row['id']}/supersede",
        json={"to_existing_id": row["id"]},
    )
    assert resp.status_code == 400, resp.text
    assert "itself" in resp.json()["detail"]


def test_supersede_to_existing_rejects_missing_target(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    row = _post_tech(client, "redis", "7.2")
    resp = client.post(
        f"{INTEL_BASE}/tech-components/{row['id']}/supersede",
        json={"to_existing_id": 999999},
    )
    assert resp.status_code == 404, resp.text
    assert "999999" in resp.json()["detail"]


def test_supersede_to_existing_rejects_replacement_payload(client, isolate_settings):
    """--to-existing and a replacement payload are mutually exclusive."""
    _seed_engagement(client, isolate_settings)
    canonical = _post_tech(client, "nginx", "1.25.0")
    stale = _post_tech(client, "nginx", "1.25")
    resp = client.post(
        f"{INTEL_BASE}/tech-components/{stale['id']}/supersede",
        json={
            "to_existing_id": canonical["id"],
            "payload": {"component": "nginx", "version": "1.25"},
        },
    )
    assert resp.status_code == 400, resp.text
    assert "payload" in resp.json()["detail"].lower()


def test_supersede_to_existing_rejects_cycle(client, isolate_settings):
    """If B already supersedes into A, pointing A --to-existing B closes a
    loop (A -> B -> A) and must be rejected."""
    _seed_engagement(client, isolate_settings)
    b_row = _post_tech(client, "nginx", "1.24")
    # Payload supersede B -> A: creates the canonical A (nginx 1.25).
    a_created = client.post(
        f"{INTEL_BASE}/tech-components/{b_row['id']}/supersede",
        json={"payload": {"component": "nginx", "version": "1.25"}, "rationale": "re-fingerprint"},
    )
    assert a_created.status_code == 201, a_created.text
    a_id = a_created.json()["current"]["id"]

    resp = client.post(
        f"{INTEL_BASE}/tech-components/{a_id}/supersede",
        json={"to_existing_id": b_row["id"]},
    )
    assert resp.status_code == 409, resp.text
    assert "cycle" in resp.json()["detail"].lower()
