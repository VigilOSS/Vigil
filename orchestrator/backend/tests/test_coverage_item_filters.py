"""Server-side filtering on ``GET /coverage-items`` (I-160c).

The route took ``limit``/``offset`` and nothing else, while ``/probe-runs`` two
routes below already filtered on five axes — so every coverage read auto-paged
the whole table and narrowed client-side. An unknown filter VALUE must return
``[]``: returning everything is the "measured nothing looks like measured
everything" shape this register is full of.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ENGAGEMENT_KEY = "2026-08-23-coverage-filters"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


@pytest.fixture
def seeded(client, isolate_settings):
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Coverage", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    for attack_family, auth_context, input_slot, status_value in (
        ("idor", "anonymous", "path:id", "pending"),
        ("idor", "member", "path:id", "covered"),
        ("ssrf", "anonymous", "query:url", "pending"),
    ):
        created = client.post(
            f"{BASE}/coverage-items",
            json={
                "attack_family": attack_family,
                "auth_context": auth_context,
                "input_slot": input_slot,
                "status_value": status_value,
                "notes": "seeded",
            },
        )
        assert created.status_code == 201, created.text
    return client


def _families(rows: list[dict]) -> list[str]:
    return sorted(row["attack_family"] for row in rows)


def test_each_filter_narrows_the_result_set(seeded) -> None:
    assert _families(seeded.get(f"{BASE}/coverage-items").json()) == ["idor", "idor", "ssrf"]
    assert _families(
        seeded.get(f"{BASE}/coverage-items?attack_family=idor").json()
    ) == ["idor", "idor"]
    assert _families(
        seeded.get(f"{BASE}/coverage-items?auth_context=member").json()
    ) == ["idor"]
    assert _families(
        seeded.get(f"{BASE}/coverage-items?input_slot=query:url").json()
    ) == ["ssrf"]
    assert _families(
        seeded.get(f"{BASE}/coverage-items?status=covered").json()
    ) == ["idor"]


def test_filters_compose(seeded) -> None:
    rows = seeded.get(
        f"{BASE}/coverage-items?attack_family=idor&auth_context=anonymous"
    ).json()

    assert len(rows) == 1
    assert rows[0]["auth_context"] == "anonymous"


@pytest.mark.parametrize(
    "query",
    [
        "attack_family=not-a-family",
        "auth_context=not-an-identity",
        "input_slot=header:Nope",
        "status=not-a-status",
        "target_host=nowhere.example",
    ],
)
def test_an_unknown_filter_value_fails_closed(seeded, query) -> None:
    """Never everything: a value nothing matches must narrow to nothing."""
    assert seeded.get(f"{BASE}/coverage-items?{query}").json() == []
