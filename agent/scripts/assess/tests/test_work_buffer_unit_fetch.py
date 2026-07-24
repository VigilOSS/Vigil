from __future__ import annotations

import argparse
import json

from assess.commands import work_buffer
from assess.commands.dispatch import work_items


class _Client:
    def __init__(self) -> None:
        self.endpoint = ""
        self.payload = {}

    def post(self, endpoint, payload):
        self.endpoint = endpoint
        self.payload = payload
        return {
            "claimed": [{"id": 7, "application_unit_id": 3}],
            "unit": {"id": 3, "path_prefix": "/api"},
            "selection": "highest-ev-unsatisfied",
            "effective_limit": 8,
            "effective_limit_source": "depth-tier-and-saturation",
        }


def test_fetch_by_unit_posts_optional_narrowing_and_renders_claims(capsys):
    client = _Client()
    work_items._fetch_by_unit(
        client,
        unit_id=None,
        path="/api",
        work_class="api",
        limit=None,
        agent="auto",
    )
    assert client.endpoint == "work-items/fetch-by-unit"
    assert client.payload == {
        "unit_id": None,
        "path": "/api",
        "work_class": "api",
        "limit": None,
        "agent": "auto",
    }
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["unit"]["id"] == 3
    assert rendered["claimed"][0]["application_unit_id"] == 3


def test_status_filter_default_does_not_narrow_host_stats():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    work_buffer.register(subparsers)

    stats = parser.parse_args(["work-buffer", "stats", "--by", "host"])
    filtered = parser.parse_args(
        ["work-buffer", "stats", "--by", "host", "--status", "pending"]
    )

    assert stats.cluster_status == ""
    assert filtered.cluster_status == "pending"
