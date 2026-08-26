"""Regression: `dispatch requeue` must stamp a terminal (inert) row `skipped`,
not let the backend default it to `pending`. A requeued image/video/font/archive
carries a `terminal_reason`; without an explicit status it would resurface in
pending stats and be claimed by typed fetches despite being skip-worthy.
"""
from __future__ import annotations

import io
import json

from assess.commands.dispatch import work_items


class _CaptureClient:
    def __init__(self):
        self.items: list[dict] = []

    def post(self, endpoint: str, payload: dict):
        assert endpoint == "work-items/bulk"
        self.items.extend(payload["items"])
        return {"count": len(payload["items"])}


def _run_requeue(monkeypatch, rows):
    stdin = io.StringIO("\n".join(json.dumps(r) for r in rows) + "\n")
    monkeypatch.setattr("sys.stdin", stdin)
    client = _CaptureClient()
    work_items._requeue(client)
    return {item["queue_key"]: item for item in client.items}


def test_requeue_stamps_terminal_row_skipped(monkeypatch):
    rows = [
        {
            "queue_key": "variant:1:baseline",
            "request_variant_id": 1,
            "type": "image",
            "url": "https://t.test/logo.png",
            "url_path": "/logo.png",
        },
        {
            "queue_key": "variant:2:baseline",
            "request_variant_id": 2,
            "type": "page",
            "url": "https://t.test/app",
            "url_path": "/app",
        },
    ]
    by_key = _run_requeue(monkeypatch, rows)

    inert = by_key["variant:1:baseline"]
    assert inert["terminal_reason"] == "inert_type"
    assert inert["status"] == "skipped"

    normal = by_key["variant:2:baseline"]
    assert not normal["terminal_reason"]
    assert normal["status"] == "pending"
