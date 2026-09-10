from __future__ import annotations

import importlib
from datetime import datetime, timezone


def test_foreign_lane_recency_pages_all_history_and_reports_without_enforcement(capsys):
    module = importlib.import_module("assess.lib.execution_recency")

    class _Client:
        def __init__(self) -> None:
            self.offsets: list[int] = []

        def get(self, endpoint: str):
            assert endpoint.startswith("command-runs?")
            offset = int(endpoint.split("offset=", 1)[1].split("&", 1)[0])
            self.offsets.append(offset)
            if offset == 0:
                return [
                    {
                        "agent_name": "same-agent",
                        "started_at": "2026-09-10T12:00:00Z",
                        "notes": '{"target_facing":true}',
                    },
                    *[
                        {
                            "agent_name": "unrelated",
                            "started_at": "2026-09-09T12:00:00Z",
                            "notes": '{"target_facing":false}',
                        }
                        for _ in range(999)
                    ],
                ]
            if offset == 1000:
                return [
                    {
                        "agent_name": "other-a",
                        "started_at": "2026-09-10T11:59:30Z",
                        "notes": '{"target_facing":true}',
                    },
                    {
                        "agent_name": "other-b",
                        "started_at": "2026-09-10T11:58:00Z",
                        "notes": '{"target_facing":true}',
                    },
                ]
            return []

    client = _Client()
    module.emit_foreign_lane_recency(
        client,
        current_agent="same-agent",
        now=datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc),
    )

    err = capsys.readouterr().err
    assert client.offsets == [0, 1000]
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


def test_foreign_lane_recency_stops_at_page_cap_and_labels_sample(
    monkeypatch, capsys
):
    module = importlib.import_module("assess.lib.execution_recency")
    monkeypatch.setattr(module, "_MAX_PAGES", 2)

    class _Client:
        def __init__(self) -> None:
            self.offsets: list[int] = []

        def get(self, endpoint: str):
            offset = int(endpoint.split("offset=", 1)[1].split("&", 1)[0])
            self.offsets.append(offset)
            return [
                {
                    "id": offset + index,
                    "agent_name": "other-agent",
                    "started_at": "2026-09-10T11:59:30Z",
                    "notes": '{"target_facing":true}',
                }
                for index in range(module._PAGE_SIZE)
            ]

    client = _Client()
    module.emit_foreign_lane_recency(client, current_agent="same-agent")

    assert client.offsets == [0, 1000]
    err = capsys.readouterr().err
    assert "2000 foreign-lane target-facing command(s) recorded" in err
    assert "bounded history sample; older rows not counted" in err
    assert "advisory only; no reservation or rate enforcement" in err
