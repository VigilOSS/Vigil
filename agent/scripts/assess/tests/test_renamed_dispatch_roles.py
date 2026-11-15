"""A dispatch role's retired spelling resolves to the role that replaced it.

The blind packet reviewer was registered as `general`, which is also the name
of OpenCode's built-in default subagent, so a native launch by that name ran
the built-in instead of the role. The role is `blind-reviewer` now. Requests
that still name the old spelling resolve to it with a warning, and a
continuation of a dispatch stored under it registers the current role: the
packet tells the specialist to read `agent/agents/<role>.md`, and only the
current name has a prompt there.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from types import SimpleNamespace

from assess.commands import agent
from assess.lib.contract_registry import DISPATCH_MODES_BY_ROLE, RENAMED_DISPATCH_ROLES
from assess.lib.contracts import current_dispatch_role

AGENT_ROOT = Path(__file__).resolve().parents[3]


def _parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    return parser.parse_args(["agent", *argv])


def test_every_retired_spelling_resolves_to_a_registered_role() -> None:
    assert RENAMED_DISPATCH_ROLES
    for retired, current in RENAMED_DISPATCH_ROLES.items():
        assert retired not in DISPATCH_MODES_BY_ROLE, retired
        assert current in DISPATCH_MODES_BY_ROLE, current
        assert (AGENT_ROOT / "agents" / f"{current}.md").is_file(), current
        assert current_dispatch_role(retired) == current
        assert current_dispatch_role(current) == current


def test_agent_start_with_the_retired_spelling_registers_the_current_role(capsys) -> None:
    args = _parse(
        "start", "--role", "general", "--task", "Judge the packet",
        "--dispatch-mode", "deep-manual", "--no-target-traffic",
    )

    payload = agent.dispatch._build_register_payload(args)  # noqa: SLF001

    assert payload["agent_role"] == "blind-reviewer"
    assert payload["agent_id"].startswith("blind-reviewer-")
    err = capsys.readouterr().err
    assert "'general'" in err and "'blind-reviewer'" in err


def test_agent_start_with_the_current_role_warns_nothing(capsys) -> None:
    args = _parse(
        "start", "--agent-id", "acme-review", "--role", "blind-reviewer",
        "--task", "Judge the packet", "--dispatch-mode", "deep-manual", "--no-target-traffic",
    )

    payload = agent.dispatch._build_register_payload(args)  # noqa: SLF001

    assert payload["agent_role"] == "blind-reviewer"
    assert "blind-reviewer" not in capsys.readouterr().err


class _Client:
    def __init__(self, prior: dict, packet: dict) -> None:
        self.writes: list[dict] = []
        self._prior = prior
        self._packet = packet

    def get_dispatch(self, _agent_id):
        return self._prior

    def get(self, endpoint):
        return self._packet if endpoint.endswith("prompt-packet") else {}

    def record_dispatch(self, payload):
        self.writes.append(payload)
        packet = dict(payload.get("prompt_packet") or {})
        packet["sha256"] = hashlib.sha256(packet.get("rendered_prompt", "").encode()).hexdigest()
        return {"id": 9, **payload, "status": "in-progress", "prompt_packet": packet,
                "launch_required": True, "idempotent_replay": False}

    def close(self):
        pass


def test_continuing_a_dispatch_stored_under_the_retired_spelling_registers_the_current_role(
    monkeypatch, tmp_path, capsys
) -> None:
    prior = {"id": 3, "agent_id": "acme-review-prior", "agent_role": "general",
             "status": "failed", "dispatch_mode": "deep-manual"}
    text = "## Runtime Identity\nagent_id: acme-review-prior\n"
    packet = {"context": {"traffic_declaration": {"no_target_traffic": True, "rate_budget": None}},
              "rendered_prompt": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
    client = _Client(prior, packet)
    cfg = SimpleNamespace(engagement_dir=str(tmp_path), agent_root=str(AGENT_ROOT))
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda _: (client, cfg))
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_: [])
    monkeypatch.setattr(agent, "_establish_authorized_phase", lambda *_, **__: None)

    agent._continue(SimpleNamespace(extra=["acme-review-prior"], task="Judge the repaired packet",
                                    agent_id="acme-review-next", assessment_mode=None))

    written = client.writes[0]
    assert written["agent_role"] == "blind-reviewer"
    assert "agent/agents/blind-reviewer.md" in written["prompt_packet"]["rendered_prompt"]
    err = capsys.readouterr().err
    assert "'general'" in err and "'blind-reviewer'" in err
