"""A ready handoff must be closed with its decision ledger entry."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from assess.commands import agent


class _Client:
    def get_handoff(self, agent_id):
        return {"agent_id": agent_id, "handoff_status": "ready"}

    def close(self):
        pass


def test_done_refuses_ready_handoff_without_explicit_status(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda args: (_Client(), None))
    monkeypatch.setattr(agent.dispatch, "_update_dispatch_status", lambda args, ids: calls.append(ids))
    args = SimpleNamespace(extra=["VERIFY-1"], agent_id=None, dispatch_status=None)

    with pytest.raises(SystemExit) as exc:
        agent._done(args)

    assert exc.value.code == 1
    assert calls == []
    assert "agent close VERIFY-1" in capsys.readouterr().err


def test_done_allows_explicit_status_for_recovery(monkeypatch):
    calls = []
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda args: (_Client(), None))
    monkeypatch.setattr(agent.dispatch, "_update_dispatch_status", lambda args, ids: calls.append(ids))
    args = SimpleNamespace(extra=["VERIFY-1"], agent_id=None, dispatch_status="completed")

    agent._done(args)

    assert calls == [["VERIFY-1"]]
