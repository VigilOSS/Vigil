from __future__ import annotations

from assess.lib.bulk_ingest import (
    DEFAULT_BULK_WRITE_SIZE,
    post_coverage_items_bulk,
    post_request_observations_bulk,
)
from assess.lib.client import AssessError


def test_coverage_items_bulk_chunks_at_backend_cap() -> None:
    calls: list[tuple[str, int]] = []

    class Client:
        def post(self, endpoint: str, payload: dict) -> dict:
            calls.append((endpoint, len(payload["items"])))
            return {"count": len(payload["items"]), "records": []}

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
            return {"id": len(calls), **payload}

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
            return {"request_variant": {"id": len(calls)}}

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
