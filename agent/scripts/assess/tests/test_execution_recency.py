from __future__ import annotations

import importlib
from datetime import datetime, timezone


def test_foreign_lane_recency_uses_aggregate_and_reports_without_enforcement(capsys):
    module = importlib.import_module("assess.lib.execution_recency")

    class _Client:
        def __init__(self) -> None:
            self.endpoints: list[str] = []

        def get(self, endpoint: str):
            self.endpoints.append(endpoint)
            return {
                "foreign_count": 2,
                "latest_started_at": "2026-09-10T11:59:30Z",
            }

    client = _Client()
    module.emit_foreign_lane_recency(
        client,
        current_agent="same-agent",
        now=datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc),
    )

    err = capsys.readouterr().err
    assert client.endpoints == [
        "command-runs/foreign-lane-recency?agent_name=same-agent"
    ]
    assert "2 foreign-lane target-facing command(s) recorded (all history)" in err
    assert "latest 30s ago" in err
    assert "advisory only; no reservation or rate enforcement" in err


def test_foreign_lane_recency_malformed_rows_fail_open(capsys):
    module = importlib.import_module("assess.lib.execution_recency")

    class _Client:
        def get(self, _endpoint: str):
            raise RuntimeError("backend unavailable")

    module.emit_foreign_lane_recency(_Client(), current_agent="agent-a")

    assert "advisory unavailable" in capsys.readouterr().err


def test_foreign_lane_recency_uses_one_bounded_request_for_large_history(capsys):
    module = importlib.import_module("assess.lib.execution_recency")

    class _Client:
        def __init__(self) -> None:
            self.endpoints: list[str] = []

        def get(self, endpoint: str):
            self.endpoints.append(endpoint)
            return {
                "foreign_count": 1_000_000,
                "latest_started_at": "2026-09-10T11:59:30Z",
            }

    client = _Client()
    module.emit_foreign_lane_recency(client, current_agent="same agent/a")

    assert client.endpoints == [
        "command-runs/foreign-lane-recency?agent_name=same+agent%2Fa"
    ]
    err = capsys.readouterr().err
    assert "1000000 foreign-lane target-facing command(s) recorded (all history)" in err
    assert "advisory only; no reservation or rate enforcement" in err
