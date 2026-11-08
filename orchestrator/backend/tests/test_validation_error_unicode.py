"""Validation errors and activity responses preserve authored Unicode values."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from app.db import get_connection
from app.main import app
from app.services import activity as activity_service
from tests.test_activity_api import BASE, ENGAGEMENT_KEY, _seed_engagement


def _post_json(payload: dict) -> httpx.Response:
    async def request():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://acme.example"
        ) as client:
            return await client.post(
                BASE,
                content=json.dumps(payload, ensure_ascii=True).encode("ascii"),
                headers={"content-type": "application/json"},
            )

    return asyncio.run(request())


@pytest.mark.parametrize("text", ["Acme \ud800 observation", "Acme \udfff observation"])
def test_unpaired_surrogate_validation_returns_422_with_exact_rejected_input(
    client, isolate_settings, text
):
    _seed_engagement(client, isolate_settings)
    response = _post_json(
        {
            "actor_kind": "operator",
            "actor_name": "Acme operator",
            "title": text,
            "action": "Read Acme source",
        }
    )
    assert response.status_code == 422, response.text
    assert response.headers["content-type"] == "application/json"
    assert int(response.headers["content-length"]) == len(response.content)
    (error,) = response.json()["detail"]
    assert error["type"] == "string_unicode"
    assert error["loc"] == ["body", "title"]
    assert error["input"] == text
    assert client.get(BASE).json()["items"] == []


def test_nested_invalid_input_surrogates_round_trip_without_double_encoding(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    nested = {"notes": ["Acme \ud800", {"detail": "\udfff"}]}
    response = _post_json({"title": "Acme observation", "unexpected": nested})
    assert response.status_code == 422, response.text
    body = response.json()
    assert isinstance(body, dict)
    (error,) = body["detail"]
    assert error["type"] == "extra_forbidden"
    assert error["loc"] == ["body", "unexpected"]
    assert error["input"] == nested
    assert client.get(BASE).json()["items"] == []


def test_ordinary_validation_keeps_its_utf8_error_representation(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    text = "Acme café 😀"
    response = _post_json({"title": "Acme observation", "unexpected": text})
    assert response.status_code == 422, response.text
    (error,) = response.json()["detail"]
    assert error["type"] == "extra_forbidden"
    assert error["input"] == text
    assert text.encode("utf-8") in response.content


def test_valid_activity_unicode_still_round_trips_verbatim(client, isolate_settings):
    _seed_engagement(client, isolate_settings)
    payload = {
        "actor_kind": "operator",
        "actor_name": "Acme operator",
        "title": "Acme café 😀",
        "action": "Read source — résumé",
        "body_markdown": "## Acme\nA café observation: 😀",
        "metadata": {"note": "Acme café 😀"},
    }
    response = client.post(
        BASE,
        content=json.dumps(payload, ensure_ascii=True).encode("ascii"),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 201, response.text
    for key, value in payload.items():
        assert response.json()[key] == value
    (listed,) = client.get(BASE).json()["items"]
    for key, value in payload.items():
        assert listed[key] == value
    feed_response = client.get(f"/engagements/{ENGAGEMENT_KEY}/activity")
    assert feed_response.status_code == 200
    (feed_item,) = feed_response.json()["items"]
    assert feed_item["detail"]["metadata"] == payload["metadata"]
    assert payload["title"].encode("utf-8") in feed_response.content


def test_activity_metadata_surrogates_return_success_after_one_durable_write(
    client, isolate_settings
):
    _seed_engagement(client, isolate_settings)
    metadata = {"nested": ["Acme \ud800", {"low": "\udfff"}]}
    response = _post_json(
        {"title": "Acme metadata observation", "metadata": metadata}
    )
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT id, metadata_json FROM activity_entries"
        ).fetchall()
    assert len(rows) == 1
    assert json.loads(rows[0]["metadata_json"]) == metadata
    assert response.status_code == 201, response.text
    assert response.json()["id"] == rows[0]["id"]
    assert response.json()["metadata"] == metadata


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_activity_metadata_keeps_existing_nonfinite_number_json_representation(
    client, isolate_settings, number
):
    _seed_engagement(client, isolate_settings)
    response = _post_json(
        {"title": "Acme numeric observation", "metadata": {"value": number}}
    )
    assert response.status_code == 201, response.text
    assert response.json()["metadata"] == {"value": None}
    (listed,) = client.get(BASE).json()["items"]
    assert listed["metadata"] == {"value": None}
    feed = client.get(f"/engagements/{ENGAGEMENT_KEY}/activity")
    assert feed.status_code == 200
    (feed_item,) = feed.json()["items"]
    assert feed_item["detail"]["metadata"] == {"value": None}


@pytest.mark.parametrize("suffix", ["activity-entries", "activity"])
def test_existing_activity_metadata_surrogates_remain_readable(
    client, isolate_settings, suffix
):
    _seed_engagement(client, isolate_settings)
    metadata = {"nested": ["Acme \ud800", {"low": "\udfff"}]}
    with get_connection() as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?", (ENGAGEMENT_KEY,)
        ).fetchone()["id"]
    record = activity_service.record_activity_entry(
        engagement_id, title="Acme metadata observation", metadata=metadata
    )

    async def request():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://acme.example"
        ) as raw:
            return await raw.get(f"/engagements/{ENGAGEMENT_KEY}/{suffix}")

    response = asyncio.run(request())
    assert response.status_code == 200, response.text
    (row,) = response.json()["items"]
    if suffix == "activity":
        assert row["source_id"] == record["id"]
        assert row["detail"]["metadata"] == metadata
    else:
        assert row["id"] == record["id"]
        assert row["metadata"] == metadata
