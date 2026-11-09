"""Pinned behaviour of the intel type tables and the per-run child list routes.

These assert the CURRENT observable behaviour of the intel type tables, the
intel record/list round trip and the per-run child list routes, so a
consolidation of the duplicated per-type literals in
``app/services/intel.py`` (one registry instead of six parallel dicts plus a
tenth copy of each natural key inside the ``record_*`` helpers) cannot move
any mapping, any UPSERT key or any route bound without failing here.
"""
from __future__ import annotations

from typing import Any

from app.services import intel as intel_service
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-05-02-093000-acme"


# The six per-type mappings as they stand today. Every one of these is a
# different question asked of the same ten intel families, which is exactly
# why they are pinned together.
EXPECTED_LIST_TABLES = {
    "tech_component": "intel_tech_components",
    "person": "intel_people",
    "email": "intel_emails",
    "domain": "intel_domains",
    "cve": "intel_cves",
    "dns_record": "intel_dns_records",
    "social_profile": "intel_social_profiles",
    "breach_record": "intel_breach_records",
    "org_fact": "intel_org_facts",
    "note": "intel_notes",
}

EXPECTED_TABLE_BY_TYPE = {
    "tech-component": "intel_tech_components",
    "person": "intel_people",
    "email": "intel_emails",
    "domain": "intel_domains",
    "cve": "intel_cves",
    "dns-record": "intel_dns_records",
    "social-profile": "intel_social_profiles",
    "breach-record": "intel_breach_records",
    "org-fact": "intel_org_facts",
    "note": "intel_notes",
}

EXPECTED_FTS_ENTITY_TYPE = {
    "tech-component": "tech_component",
    "person": "person",
    "email": "email",
    "domain": "domain",
    "cve": "cve",
    "dns-record": "dns_record",
    "social-profile": "social_profile",
    "breach-record": "breach_record",
    "org-fact": "org_fact",
    "note": "note",
}

EXPECTED_NATURAL_KEY_FIELDS = {
    "tech-component": ("component", "version"),
    "person": ("name",),
    "email": ("address",),
    "domain": ("identity", "kind"),
    "cve": ("cve_id", "affected_component"),
    "dns-record": ("record_type", "name", "value"),
    "social-profile": ("subject_kind", "subject_ref", "platform", "handle"),
    "breach-record": ("subject", "breach_name"),
    "org-fact": ("fact_key",),
    "note": ("title",),
}

EXPECTED_RATIONALE_COLUMN = {
    "tech-component": "notes",
    "person": "notes",
    "email": "notes",
    "domain": "notes",
    "cve": "notes",
    "dns-record": "notes",
    "social-profile": "notes",
    "breach-record": "notes",
    "org-fact": "notes",
    "note": "body_markdown",
}

EXPECTED_SUMMARY_PLURAL = {
    "tech_component": "tech_components",
    "person": "people",
    "email": "emails",
    "domain": "domains",
    "cve": "cves",
    "dns_record": "dns_records",
    "social_profile": "social_profiles",
    "breach_record": "breach_records",
    "org_fact": "org_facts",
    "note": "notes",
}

EXPECTED_RESOLUTION_TITLE_FIELDS = {
    "tech_component": ("component",),
    "person": ("name",),
    "email": ("address",),
    "domain": ("identity",),
    "cve": ("cve_id",),
    "dns_record": ("name",),
    "social_profile": ("handle", "url"),
    "breach_record": ("breach_name", "subject"),
    "org_fact": ("fact_key",),
    "note": ("title",),
}


def test_intel_type_tables_are_exactly_as_declared() -> None:
    assert intel_service._LIST_TABLES == EXPECTED_LIST_TABLES
    assert list(intel_service._LIST_TABLES) == list(EXPECTED_LIST_TABLES)
    assert intel_service._ENTITY_TO_TABLE == EXPECTED_LIST_TABLES
    assert intel_service._INTEL_TABLE_BY_TYPE == EXPECTED_TABLE_BY_TYPE
    assert list(intel_service._INTEL_TABLE_BY_TYPE) == list(EXPECTED_TABLE_BY_TYPE)
    assert intel_service._INTEL_FTS_ENTITY_TYPE == EXPECTED_FTS_ENTITY_TYPE
    assert intel_service._INTEL_NATURAL_KEY_FIELDS == EXPECTED_NATURAL_KEY_FIELDS
    assert intel_service._INTEL_RATIONALE_COLUMN == EXPECTED_RATIONALE_COLUMN
    assert intel_service._SUMMARY_PLURAL == EXPECTED_SUMMARY_PLURAL
    assert list(intel_service._SUMMARY_PLURAL) == list(EXPECTED_SUMMARY_PLURAL)
    assert (
        intel_service._INTEL_RESOLUTION_TITLE_FIELDS
        == EXPECTED_RESOLUTION_TITLE_FIELDS
    )


def test_intel_updatable_fields_cover_every_type() -> None:
    assert set(intel_service._INTEL_UPDATABLE_FIELDS) == set(EXPECTED_TABLE_BY_TYPE)


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text


# One minimal payload per family, keyed by the family's API plural, with the
# natural-key fields set so the upsert path is the one exercised.
RECORD_CASES: dict[str, dict[str, Any]] = {
    "tech-components": {"component": "nginx", "version": "1.24.0", "notes": "pin"},
    "people": {"name": "Ada Acme", "role": "admin"},
    "emails": {"address": "ada@acme.example", "role_hint": "admin"},
    "domains": {"identity": "api.acme.example", "kind": "subdomain"},
    "cves": {"cve_id": "CVE-2024-0001", "affected_component": "nginx", "poc_available": True},
    "dns-records": {"record_type": "A", "name": "api.acme.example", "value": "10.0.0.1"},
    "social-profiles": {"subject_kind": "person", "subject_ref": "Ada Acme", "platform": "x", "handle": "@ada"},
    "breach-records": {"subject": "ada@acme.example", "breach_name": "AcmeLeak"},
    "org-facts": {"fact_key": "hq", "fact_value": "Springfield"},
    "notes": {"title": "pin note", "body_markdown": "body"},
}


def test_every_intel_family_upserts_on_its_natural_key(client, isolate_settings) -> None:
    """A repeated POST on the same natural key updates rather than inserts.

    This is what proves each family's conflict columns are the ones declared
    in ``_INTEL_NATURAL_KEY_FIELDS``: get them wrong and the second POST
    either raises or produces a second row.
    """

    _seed(client, isolate_settings)
    base = f"/engagements/{ENGAGEMENT_KEY}/intel"
    for plural, payload in RECORD_CASES.items():
        first = client.post(f"{base}/{plural}", json=payload)
        assert first.status_code == 201, (plural, first.text)
        second = client.post(f"{base}/{plural}", json=payload)
        assert second.status_code == 201, (plural, second.text)
        assert second.json()["id"] == first.json()["id"], plural
        listing = client.get(f"{base}/{plural}")
        assert listing.status_code == 200, (plural, listing.text)
        assert len(listing.json()) == 1, (plural, listing.json())

    summary = client.get(f"{base}/summary")
    assert summary.status_code == 200, summary.text
    counts = summary.json()["counts"]
    assert counts == {plural: 1 for plural in EXPECTED_SUMMARY_PLURAL.values()}


def test_cve_poc_available_is_a_bool_on_record_and_list(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    base = f"/engagements/{ENGAGEMENT_KEY}/intel"
    created = client.post(f"{base}/cves", json=RECORD_CASES["cves"])
    assert created.status_code == 201, created.text
    assert created.json()["poc_available"] is True
    listing = client.get(f"{base}/cves")
    assert listing.status_code == 200, listing.text
    assert listing.json()[0]["poc_available"] is True


def test_every_intel_family_is_searchable_under_its_entity_type(client, isolate_settings) -> None:
    """The FTS shadow row lands under the family's ``entity_type``."""

    _seed(client, isolate_settings)
    base = f"/engagements/{ENGAGEMENT_KEY}/intel"
    for plural, payload in RECORD_CASES.items():
        assert client.post(f"{base}/{plural}", json=payload).status_code == 201, plural
    for entity_type in EXPECTED_FTS_ENTITY_TYPE.values():
        response = client.get(f"{base}/search", params={"q": "acme", "entity_type": entity_type})
        assert response.status_code == 200, (entity_type, response.text)
        for hit in response.json():
            assert hit["entity_type"] == entity_type, hit


RUN_CHILD_SUFFIXES = (
    "sources",
    "source-reads",
    "dispatches",
    "proof-receipts",
    "commands",
    "observed-events",
    "decision-history",
    "obligations",
    "candidates",
    "tool-signals",
    "discovery-passes",
    "code-receipts",
    "comparisons",
)


def test_run_child_list_routes_share_one_pagination_contract(client, isolate_settings) -> None:
    """All thirteen /assessment-runs/{id}/<child> routes bound limit the same way."""

    from app.main import app

    spec = app.openapi()
    for suffix in RUN_CHILD_SUFFIXES:
        path = f"/engagements/{{engagement_key}}/assessment/assessment-runs/{{run_id}}/{suffix}"
        assert path in spec["paths"], path
        params = {
            param["name"]: param
            for param in spec["paths"][path]["get"]["parameters"]
        }
        assert set(params) == {"engagement_key", "run_id", "limit", "offset"}, (suffix, sorted(params))
        limit = params["limit"]["schema"]
        offset = params["offset"]["schema"]
        assert limit["default"] == 100, (suffix, limit)
        assert limit["minimum"] == 1, (suffix, limit)
        assert limit["maximum"] == 1000, (suffix, limit)
        assert offset["default"] == 0, (suffix, offset)
        assert offset["minimum"] == 0, (suffix, offset)


# Minimal payloads: only the natural-key / required fields. What the record
# comes back with for every omitted field is the request model's declared
# default travelling through the create handler, which is the behaviour a
# handler rewritten to forward the model wholesale must reproduce exactly.
MINIMAL_CASES: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "tech-components": (
        {"component": "nginx", "version": "1.24.0"},
        {
            "source_name": "",
            "confidence": "",
            "evidence_ref": "",
            "notes": "",
            "provenance": {},
        },
    ),
    "people": (
        {"name": "Ada Acme"},
        {"role": "", "organization": "", "email": "", "source_name": "", "notes": "", "provenance": {}},
    ),
    "emails": (
        {"address": "ada@acme.example"},
        {"role_hint": "", "linked_person_id": None, "source_name": "", "notes": "", "provenance": {}},
    ),
    "domains": (
        {"identity": "api.acme.example"},
        {"kind": "subdomain", "value": "", "source_name": "", "live_status": "", "notes": "", "provenance": {}},
    ),
    "cves": (
        {"cve_id": "CVE-2024-0002"},
        {
            "affected_component": "",
            "affected_version_range": "",
            "cvss_score": None,
            "cvss_vector": "",
            "cwe_id": "",
            "poc_available": False,
            "source_name": "",
            "validation_status": "unverified",
            "linked_finding_slug": "",
            "notes": "",
            "details": {},
            "provenance": {},
        },
    ),
    "dns-records": (
        {"record_type": "A", "name": "api.acme.example"},
        {"value": "", "first_seen": "", "last_seen": "", "source_name": "", "notes": "", "provenance": {}},
    ),
    "social-profiles": (
        {"platform": "x", "subject_kind": "person"},
        {"subject_ref": "", "handle": "", "url": "", "source_name": "", "notes": "", "provenance": {}},
    ),
    "breach-records": (
        {"subject": "ada@acme.example", "breach_name": "AcmeLeak"},
        {"breach_date": "", "data_types": "", "source_name": "", "notes": "", "provenance": {}},
    ),
}


def test_minimal_intel_post_stores_the_declared_defaults(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    base = f"/engagements/{ENGAGEMENT_KEY}/intel"
    for plural, (payload, expected) in MINIMAL_CASES.items():
        response = client.post(f"{base}/{plural}", json=payload)
        assert response.status_code == 201, (plural, response.text)
        record = response.json()
        for field, value in expected.items():
            assert record[field] == value, (plural, field, record[field], value)
        for field, value in payload.items():
            assert record[field] == value, (plural, field, record[field], value)
