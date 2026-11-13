"""An identical rebind is answered as already bound, and the CLI says nothing was written.

The backend returns the current binding with ``already_bound: true`` instead of
a conflict when the operator re-asserts the handle a dispatch is already bound
to. The JSON alone reads like a fresh write, so the verb names the no-op.
"""
from __future__ import annotations

import argparse

from assess.commands import agent, dispatch


class _Client:
    def __init__(self, response: dict) -> None:
        self.response = response

    def post(self, endpoint: str, payload: dict) -> dict:
        return self.response

    def close(self) -> None:
        pass


def test_identical_rebind_reports_that_nothing_was_written(monkeypatch, capsys) -> None:
    client = _Client({
        "binding": {"agent_id": "acme-hunter-1", "binding_version": 2,
                    "asserted_client": "claude", "asserted_client_handle": "acme-handle"},
        "superseded": None,
        "already_bound": True,
    })
    monkeypatch.setattr(dispatch, "_client_for", lambda _args: (client, object()))
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())

    agent.run(parser.parse_args([
        "agent", "bind-client-handle", "acme-hunter-1", "--client", "claude",
        "--session-namespace", "acme-scope", "--handle", "acme-handle",
    ]))

    err = capsys.readouterr().err
    assert "already bound" in err
    assert "v2" in err
    assert "nothing written" in err
