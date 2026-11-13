"""`agent done` on a ready or blocked handoff closes it the way `agent close` does.

`agent done` is the raw dispatch-status PATCH; `agent close` consumes the
specialist's final handoff and writes the dispatch_closed_from_handoff decision
row the audit ledger reads. Refusing the raw form and asking the caller to
re-run with `close` cost a round trip for nothing, so an implicit `done` on a
closable handoff routes through `close` and says so. An explicit --status stays
the raw recovery write.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from assess.commands import agent


class _Client:
    def __init__(self, handoffs: dict[str, dict | None], dispatch_slugs=()):
        self.handoffs = handoffs
        self.dispatch_slugs = list(dispatch_slugs)
        self.updates: list[tuple[str, dict]] = []
        self.decisions: list[dict] = []

    def get_handoff(self, agent_id):
        return self.handoffs.get(agent_id)

    def get_dispatch(self, agent_id):
        return {
            "agent_id": agent_id,
            "agent_role": "vulnerability-analyst",
            "status": "in-progress",
            "finding_slugs": list(self.dispatch_slugs),
        }

    def update_dispatch(self, agent_id, patch):
        self.updates.append((agent_id, patch))
        return {"agent_id": agent_id, **patch}

    def record_decision(self, payload):
        self.decisions.append(payload)
        return {"id": len(self.decisions), **payload}

    def close(self):
        pass


def _install(monkeypatch, client):
    raw: list[list[str]] = []
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda args: (client, None))
    monkeypatch.setattr(
        agent.dispatch, "_update_dispatch_status", lambda args, ids: raw.append(list(ids))
    )
    return raw


def _args(*ids, status=None, finding_slugs=None):
    return SimpleNamespace(
        extra=list(ids), agent_id=None, dispatch_status=status,
        completed_at=None, finding_slugs=finding_slugs,
    )


@pytest.mark.parametrize(
    ("handoff_status", "closed_status"), [("ready", "completed"), ("blocked", "blocked")]
)
def test_done_routes_a_closable_handoff_through_close(
    handoff_status, closed_status, monkeypatch, capsys
):
    client = _Client({"VERIFY-1": {"agent_id": "VERIFY-1", "handoff_status": handoff_status,
                                   "handoff_version": 3}})
    raw = _install(monkeypatch, client)

    agent._done(_args("VERIFY-1"))

    assert raw == []
    assert [agent_id for agent_id, _ in client.updates] == ["VERIFY-1"]
    assert client.updates[0][1]["status"] == closed_status
    assert [d["kind"] for d in client.decisions] == ["dispatch_closed_from_handoff"]
    assert client.decisions[0]["payload"]["handoff_version"] == 3
    routed = [line for line in capsys.readouterr().err.splitlines() if "agent close VERIFY-1" in line]
    assert len(routed) == 1 and handoff_status in routed[0]


def test_done_batch_routes_only_the_closable_ids(monkeypatch, capsys):
    client = _Client({
        "VA-1": {"agent_id": "VA-1", "handoff_status": "ready"},
        "VA-2": {"agent_id": "VA-2", "handoff_status": "checkpointed"},
    })
    raw = _install(monkeypatch, client)

    agent._done(_args("VA-1", "VA-2"))

    assert [agent_id for agent_id, _ in client.updates] == ["VA-1"]
    assert raw == [["VA-2"]]


def test_done_routed_close_keeps_the_finding_slugs_it_was_given(monkeypatch, capsys):
    client = _Client(
        {"VA-1": {"agent_id": "VA-1", "handoff_status": "ready", "finding_slugs": ["VA-010"]}},
        dispatch_slugs=["VA-001"],
    )
    _install(monkeypatch, client)

    agent._done(_args("VA-1", finding_slugs="VA-020"))

    assert client.updates[0][1]["finding_slugs"] == ["VA-001", "VA-010", "VA-020"]


def test_done_allows_explicit_status_for_recovery(monkeypatch, capsys):
    client = _Client({"VERIFY-1": {"agent_id": "VERIFY-1", "handoff_status": "ready"}})
    raw = _install(monkeypatch, client)

    agent._done(_args("VERIFY-1", status="completed"))

    assert raw == [["VERIFY-1"]]
    assert client.decisions == []
    assert "dispatch_closed_from_handoff" in capsys.readouterr().err
