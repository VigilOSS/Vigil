"""`agent decision --agent-id <id>` names the dispatch recording the decision.

The backend records that dispatch, with its own role, as the row's recorder; a
decision written without one is the operator's.
"""
from __future__ import annotations

import argparse

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


def _record(monkeypatch, argv: list[str]) -> dict:
    client = _Client()
    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _args: (client, None))
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    dispatch_agent._record_decision(parser.parse_args(["agent", "decision", *argv]))
    (body,) = client.bodies
    return body


def test_agent_id_names_the_recording_dispatch(monkeypatch, capsys):
    body = _record(monkeypatch, [
        "--kind", "dispatch_blocked", "--reason", "Acme runtime lacks massdns",
        "--agent-id", "rs-acme-1",
    ])
    assert body["recorded_by_agent_id"] == "rs-acme-1"
    assert "agent_id" not in body["payload"]


def test_a_decision_without_agent_id_names_no_recorder(monkeypatch, capsys):
    monkeypatch.setenv("AGENT_NAME", "recon-specialist")
    monkeypatch.setenv("VIGIL_AGENT_NAME", "recon-specialist")
    body = _record(monkeypatch, ["--kind", "dispatch_blocked", "--reason", "x"])
    # Attribution env is a role label, not dispatch identity: it is never sent.
    assert "recorded_by_agent_id" not in body
