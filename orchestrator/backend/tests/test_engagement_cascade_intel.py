"""Engagement cascade-delete coverage for every new intel_* + activity_entries table.

Deleting an engagement via ``DELETE /engagements/{key}?confirm={key}`` must
remove every row in every engagement-scoped intel table plus
``activity_entries`` and ``intel_search_index``. The DB schema declares
``FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE``
on each; this test seeds one row in each via the API (so B1's service
helpers are exercised the same way production does) and then verifies
every table empties after the delete.

Pairs with ``test_engagement_deletion.py`` (which owns the legacy
findings-survive-filesystem-drift guarantees).
"""
from __future__ import annotations

import sqlite3
from typing import Iterable

from app import db as db_module

from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120300-cascade"
INTEL_BASE = f"/engagements/{ENGAGEMENT_KEY}/intel"
ACTIVITY_BASE = f"/engagements/{ENGAGEMENT_KEY}/activity-entries"


INTEL_TABLES: tuple[str, ...] = (
    "intel_tech_components",
    "intel_people",
    "intel_emails",
    "intel_domains",
    "intel_cves",
    "intel_dns_records",
    "intel_social_profiles",
    "intel_breach_records",
    "intel_org_facts",
    "intel_notes",
)


def _seed_engagement(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _count_rows(engagement_id: int, tables: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    with sqlite3.connect(str(db_module.database_path())) as connection:
        for table in tables:
            row = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchone()
            counts[table] = int(row[0])
    return counts


def _seed_one_row_per_intel_table(client) -> None:
    """Seed one row in each intel_* table via the public API.

    Each payload uses the minimum required natural-key fields so B1's
    service helpers upsert cleanly. If this list falls out of sync with
    the ``intel_schemas`` request models the corresponding POST returns
    422 and this helper aborts loudly.
    """
    payloads = [
        ("/tech-components", {"component": "seed-tech", "version": "0.0.1"}),
        ("/people", {"name": "Seed Person"}),
        ("/emails", {"address": "seed@example.com"}),
        ("/domains", {"identity": "seed.example.com", "kind": "subdomain"}),
        ("/cves", {"cve_id": "CVE-2026-00001"}),
        ("/dns-records", {"record_type": "A", "name": "seed.example.com"}),
        ("/social-profiles", {"subject_kind": "org", "platform": "github", "handle": "seed"}),
        ("/breach-records", {"subject": "seed@example.com", "breach_name": "Seed-Leak"}),
        ("/org-facts", {"fact_key": "SeedFact", "fact_value": "SeedValue"}),
        ("/notes", {"title": "Seed note"}),
    ]
    for path, body in payloads:
        response = client.post(f"{INTEL_BASE}{path}", json=body)
        assert response.status_code == 201, f"seed {path}: {response.text}"


def test_engagement_delete_cascades_every_intel_and_activity_table(client, isolate_settings):
    engagement_id = _seed_engagement(client, isolate_settings)

    _seed_one_row_per_intel_table(client)
    activity = client.post(
        ACTIVITY_BASE,
        json={
            "actor_kind": "operator",
            "title": "Seed activity",
            "action": "seed",
            "body_markdown": "Seed narrative",
        },
    )
    assert activity.status_code == 201, activity.text

    # Sanity: every table has at least one row before the delete.
    counts_before = _count_rows(
        engagement_id,
        [*INTEL_TABLES, "intel_search_index", "activity_entries"],
    )
    for table, count in counts_before.items():
        assert count >= 1, f"{table} was not seeded (count={count})"

    # Explicit cascade delete via the public endpoint.
    response = client.delete(
        f"/engagements/{ENGAGEMENT_KEY}",
        params={"confirm": ENGAGEMENT_KEY},
    )
    assert response.status_code == 200, response.text
    assert response.json()["deleted"] is True

    counts_after = _count_rows(
        engagement_id,
        [*INTEL_TABLES, "intel_search_index", "activity_entries"],
    )
    for table, count in counts_after.items():
        assert count == 0, f"{table} still has {count} rows after cascade delete"

    # The engagement row itself is gone.
    assert db_module.get_engagement_by_key(ENGAGEMENT_KEY) is None
