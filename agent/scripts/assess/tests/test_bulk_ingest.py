from __future__ import annotations

import pytest

from assess.lib.bulk_ingest import (
    DEFAULT_BULK_WRITE_SIZE,
    post_coverage_items_bulk,
    post_request_observations_bulk,
)
from assess.lib.client import AssessError


def _observation_receipt(row_id: int = 1) -> dict:
    return {
        "request_variant": {"id": row_id},
        "request_observation": {"id": row_id},
    }


def test_coverage_items_bulk_chunks_at_backend_cap() -> None:
    calls: list[tuple[str, int]] = []

    class Client:
        def post(self, endpoint: str, payload: dict) -> dict:
            calls.append((endpoint, len(payload["items"])))
            records = [
                {
                    "id": index,
                    "request_variant_id": item.get("request_variant_id"),
                    "service_id": item.get("service_id"),
                    "auth_context": item.get("auth_context", "anonymous"),
                    "input_slot": item.get("input_slot", "endpoint"),
                    "attack_family": item["attack_family"],
                }
                for index, item in enumerate(payload["items"], start=1)
            ]
            return {"count": len(records), "records": records}

    items = [{"attack_family": "idor"} for _ in range(DEFAULT_BULK_WRITE_SIZE + 1)]

    post_coverage_items_bulk(Client(), items, warn_prefix="test")

    assert calls == [
        ("coverage-items/bulk", DEFAULT_BULK_WRITE_SIZE),
        ("coverage-items/bulk", 1),
    ]


def test_coverage_items_bulk_validation_error_falls_back_per_row() -> None:
    calls: list[tuple[str, int | str]] = []

    class Client:
        def post(self, endpoint: str, payload: dict) -> dict:
            if endpoint == "coverage-items/bulk":
                calls.append((endpoint, len(payload["items"])))
                raise AssessError("HTTP 422 validation error:\nbad coverage")
            calls.append((endpoint, str(payload["attack_family"])))
            return {
                "id": len(calls),
                "request_variant_id": payload.get("request_variant_id"),
                "service_id": payload.get("service_id"),
                "auth_context": payload.get("auth_context", "anonymous"),
                "input_slot": payload.get("input_slot", "endpoint"),
                **payload,
            }

    post_coverage_items_bulk(
        Client(),
        [{"attack_family": "idor"}, {"attack_family": "ssrf"}],
        warn_prefix="test",
    )

    assert calls == [
        ("coverage-items/bulk", 2),
        ("coverage-items", "idor"),
        ("coverage-items", "ssrf"),
    ]


def test_request_observations_bulk_validation_error_returns_per_row_outcomes() -> None:
    calls: list[tuple[str, str]] = []

    class Client:
        def post(self, endpoint: str, payload: dict) -> dict:
            if endpoint == "request-observations/bulk":
                calls.append((endpoint, "bulk"))
                raise AssessError("HTTP 422 validation error:\nbad observation")
            url = str(payload["url"])
            calls.append((endpoint, url))
            if "bad" in url:
                raise AssessError("HTTP 422 validation error:\nurl too long")
            row_id = len(calls)
            return {
                "request_variant": {"id": row_id, "method": "GET"},
                "request_observation": {
                    "id": row_id,
                    "request_variant_id": row_id,
                    "observed_url": url,
                },
            }

    results = post_request_observations_bulk(
        Client(),
        [
            {"url": "https://ok.example/one"},
            {"url": "https://bad.example/two"},
            {"url": "https://ok.example/three"},
        ],
        warn_prefix="test",
        fallback_individual=True,
    )

    assert calls == [
        ("request-observations/bulk", "bulk"),
        ("request-observations", "https://ok.example/one"),
        ("request-observations", "https://bad.example/two"),
        ("request-observations", "https://ok.example/three"),
    ]
    assert isinstance(results[0], dict)
    assert isinstance(results[1], AssessError)
    assert isinstance(results[2], dict)


def test_request_observations_bulk_rejects_receipt_without_matching_count() -> None:
    class Client:
        def post(self, _endpoint: str, _payload: dict) -> dict:
            return {"records": [_observation_receipt()]}

    with pytest.raises(AssessError, match="request observations.*may have committed") as exc:
        post_request_observations_bulk(
            Client(),
            [{"method": "GET", "url": "https://target.example/one"}],
            warn_prefix="test",
        )

    assert "do not retry automatically" in str(exc.value)


def test_coverage_items_bulk_rejects_malformed_success_receipt() -> None:
    class Client:
        def post(self, _endpoint: str, _payload: dict) -> dict:
            return {"message": "accepted"}

    with pytest.raises(AssessError, match="coverage items.*may have committed") as exc:
        post_coverage_items_bulk(
            Client(),
            [{"attack_family": "idor"}],
            warn_prefix="test",
        )

    assert "do not retry automatically" in str(exc.value)


def test_the_client_chunk_size_never_exceeds_the_backend_bulk_cap():
    """The chunk size is only safe while the backend still accepts it.

    Every bulk writer chunks at ``DEFAULT_BULK_WRITE_SIZE`` and the backend caps
    each request at ``MAX_BULK_ASSESSMENT_WRITE_ITEMS``. If the cap drops below
    the chunk, every oversized batch 422s — and for artifact registration that
    turns a whole chunk into an outcome the caller has to reconcile by hand. The
    assess suite runs on the backend venv, so the cap is importable here.
    """
    from app.api.assessment import MAX_BULK_ASSESSMENT_WRITE_ITEMS

    assert DEFAULT_BULK_WRITE_SIZE <= MAX_BULK_ASSESSMENT_WRITE_ITEMS
