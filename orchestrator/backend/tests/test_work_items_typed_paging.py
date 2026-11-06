"""``GET /work-items?type=`` accepted an ``offset`` and then dropped it.

The route declares ``limit`` and ``offset`` for the whole collection, but its
typed branch called ``peek_work_items(..., limit=limit)`` without the offset, so
every page of a typed read came back as the same first rows. A reader that
trusted the parameter silently re-processed page one; a pager that advanced on a
full page looped forever.

The window now rides the typed read's own total order — priority first, ``id``
as the tie-break — so paging preserves the ordering that makes it a work queue
rather than re-sorting it into an id dump.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ENGAGEMENT_KEY = "2026-10-08-work-items-paging"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
ITEM_COUNT = 7


@pytest.fixture
def buffered(client, isolate_settings):
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Paging", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for index in range(ITEM_COUNT):
        created = client.post(
            f"{BASE}/request-observations",
            json={
                "url": f"https://app.example/api/resource-{index}",
                "method": "GET",
                "query_schema": {"q": "string"},
                "discovery_source": "test",
                "work_item": {
                    "case_type": "api",
                    # Deliberately NOT distinct: the tie-break is what makes a
                    # window stable, so most rows share a priority.
                    "priority_score": 10 if index % 3 else 20,
                    "priority_reason": "api endpoint",
                },
            },
        )
        assert created.status_code == 201, created.text
    return client


def _typed_page(client, **params) -> list[dict]:
    response = client.get(f"{BASE}/work-items", params={"type": "api", **params})
    assert response.status_code == 200, response.text
    return response.json()


def test_a_typed_read_can_be_walked_a_page_at_a_time(buffered) -> None:
    whole = _typed_page(buffered)
    assert len(whole) == ITEM_COUNT

    walked: list[dict] = []
    offset = 0
    # Bounded on purpose. A read that drops the offset hands back the same full
    # page forever, so an honest pager over it never terminates — exactly the
    # loop an operator script would hang in. The bound turns that into a
    # failure that names how far it got instead of a test that never returns.
    for _ in range(ITEM_COUNT + 2):
        page = _typed_page(buffered, limit=2, offset=offset)
        assert len(page) <= 2
        walked.extend(page)
        if len(page) < 2:
            break
        offset += len(page)
    else:
        raise AssertionError(
            f"paging never reached the end: read {len(walked)} rows from "
            f"{ITEM_COUNT} items, so a full page kept coming back"
        )

    assert [row["id"] for row in walked] == [row["id"] for row in whole]


def test_a_typed_page_advances_instead_of_repeating_the_first_rows(buffered) -> None:
    first = _typed_page(buffered, limit=3, offset=0)
    second = _typed_page(buffered, limit=3, offset=3)

    assert [row["id"] for row in first] != [row["id"] for row in second]
    assert not {row["id"] for row in first} & {row["id"] for row in second}


def test_a_typed_offset_past_the_end_is_an_empty_page(buffered) -> None:
    assert _typed_page(buffered, limit=3, offset=ITEM_COUNT) == []


def test_the_typed_window_keeps_the_priority_ordering(buffered) -> None:
    """Paging a work queue must not silently re-sort it by id."""
    whole = _typed_page(buffered)

    scores = [int(row["priority_score"]) for row in whole]
    assert scores == sorted(scores, reverse=True)
    # Within one priority the id tie-break is what makes the window stable.
    for score in set(scores):
        ids = [int(row["id"]) for row in whole if int(row["priority_score"]) == score]
        assert ids == sorted(ids)
