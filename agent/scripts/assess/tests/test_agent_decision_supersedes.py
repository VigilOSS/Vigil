"""`agent decision --supersedes <id>` sends the row it corrects to the backend."""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import agent
from assess.commands.dispatch import agent as dispatch_agent


class _Client:
    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def record_decision(self, body):
        self.bodies.append(body)
        return {"id": 12, **body}

    def close(self):
        pass


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    return parser.parse_args(["agent", "decision", *argv])


def test_supersedes_is_an_integer_decision_id():
    args = _parse(["--kind", "coverage_deferral", "--supersedes", "5463", "--reason", "x"])
    assert args.decision_supersedes == 5463
    with pytest.raises(SystemExit):
        _parse(["--kind", "coverage_deferral", "--supersedes", "five", "--reason", "x"])


def test_supersedes_reaches_the_decision_body(monkeypatch, capsys):
    client = _Client()
    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _args: (client, None))
    args = _parse([
        "--kind", "coverage_deferral",
        "--supersedes", "5463",
        "--payload-json", json.dumps({
            "hosts": ["api.example.com"],
            "deferred_objectives": ["directory_fuzz"],
            "reason": "corrected objective",
        }),
    ])
    dispatch_agent._record_decision(args)
    (body,) = client.bodies
    assert body["supersedes"] == 5463
    assert "supersedes" not in body["payload"]


def test_a_decision_without_supersedes_sends_none(monkeypatch, capsys):
    client = _Client()
    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _args: (client, None))
    dispatch_agent._record_decision(_parse(["--kind", "phase_step_deferral", "--reason", "x"]))
    (body,) = client.bodies
    assert "supersedes" not in body
