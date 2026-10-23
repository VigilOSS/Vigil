"""`agent bind-client-handle` connects a backend dispatch row to a live session.

`agent start` records the dispatch; the operator launches the client separately,
so at start time there is no session handle to record. This verb is the
post-launch half: it asserts which client, which session namespace, and which
handle the dispatch is actually running as, without ever becoming a precondition
for starting a dispatch.
"""
from __future__ import annotations

import argparse
import json
import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from assess.commands import agent
from assess.commands import dispatch
from assess.lib import contracts


class _StubClient:
    """Records the exact request bodies the verb sends; no backend, no HTTP."""

    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.closed = False
        self.response = response or {
            "binding": {
                "id": 7,
                "agent_id": "code-hunter-3",
                "binding_version": 1,
                "asserted_client": "claude",
                "asserted_session_namespace": "/Users/op/vigil/engagements/acme",
                "asserted_client_handle": "01JQZ4S8K2A0",
                "provider_observed_handle": "unknown",
                "note": None,
                "superseded_by_id": None,
                "bound_at": "2026-09-16T09:10:00Z",
            },
            "superseded": None,
        }

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return self.response

    def close(self) -> None:
        self.closed = True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    agent.register(sub)
    return parser


def _run(monkeypatch, argv: list[str], stub: _StubClient) -> None:
    monkeypatch.setattr(
        dispatch, "_client_for", lambda _args: (stub, object()), raising=True
    )
    agent.run(_parser().parse_args(argv))


def test_bind_client_handle_posts_the_asserted_triplet(monkeypatch, capsys) -> None:
    stub = _StubClient()
    _run(
        monkeypatch,
        [
            "agent",
            "bind-client-handle",
            "code-hunter-3",
            "--client",
            "claude",
            "--session-namespace",
            "/Users/op/vigil/engagements/acme",
            "--handle",
            "01JQZ4S8K2A0",
        ],
        stub,
    )

    assert stub.posts == [
        (
            "dispatches/code-hunter-3/client-bindings",
            {
                "asserted_client": "claude",
                "asserted_session_namespace": "/Users/op/vigil/engagements/acme",
                "asserted_client_handle": "01JQZ4S8K2A0",
            },
        )
    ]
    assert stub.closed
    printed = json.loads(capsys.readouterr().out.strip())
    assert printed["binding"]["binding_version"] == 1
    assert printed["binding"]["provider_observed_handle"] == "unknown"


def test_bind_client_handle_sends_an_optional_note_for_a_correction(
    monkeypatch, capsys
) -> None:
    stub = _StubClient()
    _run(
        monkeypatch,
        [
            "agent",
            "bind-client-handle",
            "code-hunter-3",
            "--client",
            "codex",
            "--session-namespace",
            "acme-workspace",
            "--handle",
            "conv_7f31",
            "--note",
            "relaunched after the claude session died",
        ],
        stub,
    )

    _endpoint, payload = stub.posts[0]
    assert payload["note"] == "relaunched after the claude session died"
    capsys.readouterr()


def test_bind_client_handle_requires_the_whole_identity(capsys) -> None:
    """A partial binding identifies no session, so argparse refuses it."""
    for argv in (
        ["agent", "bind-client-handle", "code-hunter-3", "--client", "claude"],
        [
            "agent",
            "bind-client-handle",
            "code-hunter-3",
            "--session-namespace",
            "ns",
            "--handle",
            "h",
        ],
    ):
        with pytest.raises(SystemExit) as exc:
            _parser().parse_args(argv)
        assert exc.value.code == 2
        capsys.readouterr()


def test_agent_start_names_the_bind_as_the_step_after_launching(
    monkeypatch, tmp_path, capsys
) -> None:
    """The one moment the operator holds both the dispatch id and the session.

    Naming the bind in `agent start`'s own Next action is what makes the verb
    discoverable without spending a line of prompt on it.
    """
    engagement_dir = tmp_path / "engagements" / "acme"
    engagement_dir.mkdir(parents=True)
    stub = _StubClient()
    def record_dispatch(payload):
        packet = dict(payload['prompt_packet'])
        packet['sha256'] = hashlib.sha256(packet['rendered_prompt'].encode()).hexdigest()
        return {'id': 11, 'status': 'in-progress', **payload, 'prompt_packet': packet, 'launch_required': True}
    stub.record_dispatch = record_dispatch
    stub.list_dispatches = lambda **_filters: []  # type: ignore[method-assign]
    monkeypatch.setattr(
        dispatch,
        "_client_for",
        lambda _args: (
            stub,
            SimpleNamespace(
                engagement_dir=str(engagement_dir),
                agent_root=str(tmp_path / "agent"),
            ),
        ),
        raising=True,
    )

    agent.run(
        _parser().parse_args(
            [
                "agent",
                "start",
                "--agent-id",
                "recon-9",
                "--role",
                "recon-specialist",
                "--task",
                "enumerate subdomains",
                "--dispatch-mode",
                "item-iterating",
                "--model",
                "claude-opus-4-8",
                "--reasoning",
                "high",
                "--no-target-traffic",
            ]
        )
    )

    out = capsys.readouterr().out
    assert "agent bind-client-handle recon-9" in out


def test_agent_start_never_asks_for_a_client_handle() -> None:
    """The handle does not exist at `agent start` time; it must stay post-launch."""
    with pytest.raises(SystemExit):
        _parser().parse_args(
            [
                "agent",
                "start",
                "--role",
                "code-vuln-hunter",
                "--task",
                "hunt",
                "--handle",
                "01JQZ4S8K2A0",
            ]
        )


def test_contract_states_the_binding_is_asserted_not_observed() -> None:
    rendered = contracts.render_contract("agent bind-client-handle")

    assert "asserted" in rendered.lower()
    assert "provider_observed_handle" in rendered
    assert "agent bind-client-handle" in contracts.contract_names()
    # Discoverable from the parent contract too — an operator who reads
    # `contract agent` must learn the verb exists.
    assert "bind-client-handle" in contracts.render_contract("agent")
