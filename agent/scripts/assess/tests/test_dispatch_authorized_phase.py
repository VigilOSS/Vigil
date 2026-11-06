"""A dispatch packet can never ship without a resolved `authorized_phase`.

Three lanes in one wave received `authorized_phase: not supplied` because every
optional prompt-context key renders that same generic placeholder. The code role
files make an absent phase a hard stop before reading source, so the lanes
resolved the ambiguity three different ways — one of them silently ran the
strictly less privileged branch and emitted no receipts at all.

`agent start` therefore establishes the phase itself from durable scope state and
echoes what it stamped; when scope state cannot supply one the packet says
MALFORMED in a way the role gate names, instead of a soft "not supplied" that
reads like ordinary missing context.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import agent

REPO_ROOT = Path(__file__).resolve().parents[4]


class _Client:
    def __init__(self) -> None:
        self.writes: list[dict] = []

    def record_dispatch(self, payload):
        self.writes.append(payload)
        packet = dict(payload.get("prompt_packet") or {})
        packet["sha256"] = hashlib.sha256(packet.get("rendered_prompt", "").encode()).hexdigest()
        return {"id": 11, **payload, "status": "in-progress", "prompt_packet": packet,
                "launch_required": True, "idempotent_replay": False}

    def close(self) -> None:
        pass


def _start_args(monkeypatch, tmp_path, *, role="code-vuln-hunter", mode="code", scope=None,
                prompt_context=None):
    if scope is not None:
        (tmp_path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    args = parser.parse_args(["agent", "start", "--agent-id", "acme-lane", "--role", role,
                              "--task", "Review the assigned batch", "--no-target-traffic"])
    args.engagement_dir = str(tmp_path)
    args.allow_duplicate = True
    args.prompt_context = prompt_context
    client = _Client()
    cfg = SimpleNamespace(engagement_dir=str(tmp_path), agent_root=str(tmp_path))
    monkeypatch.setattr(agent.dispatch, "_build_register_payload", lambda _: {
        "agent_id": "acme-lane", "agent_role": role, "task": args.task, "assessment_mode": mode,
    })
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda _: (client, cfg))
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_, **__: [])
    monkeypatch.setattr(agent, "_require_proof_variant_parent_set", lambda *_: None)
    return args, client


def test_start_establishes_the_phase_from_scope_state_and_echoes_what_it_stamped(
    monkeypatch, tmp_path, capsys
):
    args, client = _start_args(
        monkeypatch, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
    )
    agent._start(args)
    captured = capsys.readouterr()
    packet = client.writes[0]["prompt_packet"]

    assert packet["context"]["authorized_phase"] == "hunt"
    assert "authorized_phase: hunt" in packet["rendered_prompt"]
    assert f"authorized_phase: {agent._UNSET_AUTHORIZED_PHASE}" not in packet["rendered_prompt"]
    # The operator must be able to see what was stamped without opening the packet.
    assert "authorized_phase" in captured.err and "hunt" in captured.err
    assert json.loads(captured.out.splitlines()[0])["authorized_phase"] == "hunt"


def test_an_unestablishable_phase_renders_as_malformed_not_as_ordinary_missing_context(
    monkeypatch, tmp_path, capsys
):
    args, client = _start_args(monkeypatch, tmp_path)
    agent._start(args)
    captured = capsys.readouterr()
    packet = client.writes[0]["prompt_packet"]

    assert packet["context"]["authorized_phase"] == agent._UNSET_AUTHORIZED_PHASE
    assert f"authorized_phase: {agent._UNSET_AUTHORIZED_PHASE}" in packet["rendered_prompt"]
    assert "authorized_phase: not supplied" not in packet["rendered_prompt"]
    assert "authorized_phase" in captured.err


def test_an_explicitly_authored_phase_is_never_restamped_from_scope_state(
    monkeypatch, tmp_path, capsys
):
    args, client = _start_args(
        monkeypatch, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        prompt_context={"authorized_phase": "verify-variant"},
    )
    agent._start(args)
    capsys.readouterr()
    packet = client.writes[0]["prompt_packet"]
    assert packet["context"]["authorized_phase"] == "verify-variant"
    assert "authorized_phase: verify-variant" in packet["rendered_prompt"]


def test_an_off_roster_phase_is_advised_rather_than_refused(monkeypatch, tmp_path, capsys):
    args, client = _start_args(
        monkeypatch, tmp_path, prompt_context={"authorized_phase": "phase-2b"},
    )
    agent._start(args)
    err = capsys.readouterr().err
    assert client.writes[0]["prompt_packet"]["context"]["authorized_phase"] == "phase-2b"
    assert "phase-2b" in err


@pytest.mark.parametrize("source", [
    "agent/shared-constraints-code.md",
    "agent/agents/code-variant-hunter.md",
])
def test_the_malformed_phase_marker_is_named_where_the_code_roles_gate_on_it(source):
    """The gate and the renderer must use the same token, or the stop is unreachable.

    The role gate is the only thing that converts the marker into a refusal, so
    the token the CLI renders is pinned against the prompt sources that name it.
    """
    assert agent._UNSET_AUTHORIZED_PHASE in (REPO_ROOT / source).read_text(encoding="utf-8")


def test_a_hunter_lane_with_no_queue_lease_is_flagged_as_receiptless(monkeypatch, tmp_path, capsys):
    """No lease means `code-record analysis` is unreachable for every file read.

    A lane dispatched without queue items or a lane file read ~22 files in full
    and carried no receipts, so `code-coverage` reported them unreviewed and a
    later wave re-read them.
    """
    args, client = _start_args(
        monkeypatch, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
    )
    agent._start(args)
    err = capsys.readouterr().err
    assert "non-covering" in err
    assert "code-record analysis" in err
    assert client.writes


def test_a_hunter_lane_holding_queue_items_is_not_flagged_as_receiptless(
    monkeypatch, tmp_path, capsys
):
    args, _client = _start_args(
        monkeypatch, tmp_path,
        scope={"engagement_type": "code", "current_phase": "hunt"},
        prompt_context={"queue_item_ids": [44]},
    )
    monkeypatch.setattr(agent, "_backend_queue_manifest", lambda *_, **__: ["Queue manifest"])
    monkeypatch.setattr(
        agent, "_code_source_identity_lines",
        lambda *_, **__: ["repo_id: 7", "repo_generation: 3"],
    )
    agent._start(args)
    assert "non-covering" not in capsys.readouterr().err


@pytest.mark.parametrize(("scope", "mode", "role", "expected"), [
    ({"engagement_type": "code", "current_phase": "hunt"}, "code", "code-vuln-hunter",
     ("hunt", "code")),
    ({"engagement_type": "both", "current_phase": "verify", "code_phase": "verify-variant"},
     "code", "code-variant-hunter", ("verify-variant", "code")),
    ({"engagement_type": "both", "current_phase": "verify", "code_phase": "verify-variant"},
     "web", "vulnerability-analyst", ("verify", "web")),
    ({"engagement_type": "blue", "current_phase": "investigate"}, "", "investigator",
     ("investigate", "blue")),
    ({"tracks": {"code": {"phase": "fuzz"}}}, "", "code-fuzz-engineer", ("fuzz", "code")),
    # Two live tracks and a role that belongs to neither: guessing a track here
    # would stamp one track's phase onto the other's work.
    ({"engagement_type": "both", "current_phase": "verify"}, "", "recon-specialist", ("", "")),
    # A finished track authorizes nothing.
    ({"engagement_type": "code", "current_phase": "complete"}, "code", "code-vuln-hunter",
     ("", "")),
    # Legacy two-track scope whose code phase was never repaired.
    ({"engagement_type": "both", "current_phase": "verify"}, "code", "code-vuln-hunter",
     ("", "")),
])
def test_the_stamped_phase_comes_from_this_dispatchs_own_track(
    tmp_path, scope, mode, role, expected
):
    (tmp_path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    assert agent._scope_track_phase(tmp_path, assessment_mode=mode, agent_role=role) == expected


def test_an_unreadable_scope_file_stamps_nothing(tmp_path):
    (tmp_path / "scope.json").write_text("{not json", encoding="utf-8")
    assert agent._scope_track_phase(tmp_path, assessment_mode="code", agent_role="code-vuln-hunter") == ("", "")
