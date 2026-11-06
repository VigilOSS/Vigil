"""``GET /finding-links`` is a list route, so it has to page like one.

It took no ``limit`` and no ``offset`` at all, which made it the one catalogued
read a generic pager could not walk: a caller could ask for the whole collection
or nothing, and a bounded page was unreachable. The default stays the route
ceiling so the operator views, which read the collection whole, keep seeing every
relationship.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ENGAGEMENT_KEY = "2026-10-08-finding-links-paging"
AUTHOR_AGENT_ID = "LINK-PAGING-AUTHOR"
LINK_COUNT = 7


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _finding(slug: str) -> dict:
    return {
        "slug": slug,
        "title": f"Access-control gap at /{slug.lower()}",
        "severity": "medium",
        "workflow_status": "active",
        "defect_family": "access-control",
        "root_cause_key": f"missing-object-authz-{slug.lower()}",
        "canonical_location": f"https://app.example/{slug.lower()}",
        "summary": "Another member's record is readable.",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        "provenance": {"agent_id": AUTHOR_AGENT_ID},
    }


@pytest.fixture
def linked(client, isolate_settings):
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Links", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    assert client.post(
        f"{_base()}/dispatches",
        json={
            "agent_id": AUTHOR_AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Record link-paging fixture findings",
        },
    ).status_code == 201
    for index in range(LINK_COUNT + 1):
        created = client.post(f"{_base()}/findings", json=_finding(f"VA-{index:03d}"))
        assert created.status_code == 201, created.text
    for index in range(1, LINK_COUNT + 1):
        linked_row = client.post(
            f"{_base()}/findings/VA-{index:03d}/links",
            json={
                "link_kind": "related",
                "target_kind": "finding",
                "target_ref": "VA-000",
                "notes": "Same missing control, different object.",
            },
        )
        assert linked_row.status_code in (200, 201), linked_row.text
    return client


def test_finding_links_defaults_to_the_whole_collection(linked) -> None:
    """The operator views read this route whole; a smaller default would drop rows.

    The fixture's related links are joined by the evidence link each recorded
    finding mints, so the floor is the related set and the assertion is that
    nothing is withheld rather than an exact fixture count.
    """
    rows = linked.get(f"{_base()}/finding-links").json()

    assert len({row["id"] for row in rows}) == len(rows)
    assert (
        len([row for row in rows if row["link_kind"] == "related"]) == LINK_COUNT
    )


def test_finding_links_can_be_walked_a_page_at_a_time(linked) -> None:
    whole = linked.get(f"{_base()}/finding-links").json()

    walked: list[dict] = []
    offset = 0
    while True:
        page = linked.get(
            f"{_base()}/finding-links", params={"limit": 2, "offset": offset}
        ).json()
        assert len(page) <= 2
        walked.extend(page)
        if len(page) < 2:
            break
        offset += len(page)

    assert [row["id"] for row in walked] == [row["id"] for row in whole]


def test_finding_links_offset_past_the_end_is_an_empty_page(linked) -> None:
    total = len(linked.get(f"{_base()}/finding-links").json())

    assert (
        linked.get(
            f"{_base()}/finding-links", params={"limit": 2, "offset": total}
        ).json()
        == []
    )


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"offset": -1}, {"limit": 100000}],
)
def test_finding_links_refuses_an_out_of_range_window(linked, params) -> None:
    assert linked.get(f"{_base()}/finding-links", params=params).status_code == 422
