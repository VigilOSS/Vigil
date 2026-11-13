"""A receipt-bearing variant hunter gets its receipt authority from the helpers.

The backend binds every ``code-record variant-check`` receipt to the numeric
row id of a code-variant-hunter dispatch and to the parent set frozen on it.
The packet is rendered and captured before ``record_dispatch`` assigns that
row id, so no packet can carry it. The packet therefore renders the frozen
parent set from the registration itself, and the receipt command resolves the
dispatch id from the agent_id every specialist already has in its Runtime
Identity, so neither value depends on the operator copying it by hand.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from _fake_client import StubClient

from assess.commands import agent, code_record_variant_check
from assess.lib.client import AssessError


def _context(**overrides):
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields["authorized_phase"] = "verify-variant"
    fields.update(overrides)
    return fields


def _render(tmp_path: Path, payload: dict) -> str:
    args = argparse.Namespace(prompt_context=_context(), prompt_context_json=None,
                              no_target_traffic=True, rate_budget=None)
    return agent._dispatch_prompt(
        payload, engagement_dir=tmp_path, agent_root=tmp_path, source_identity=[], args=args,
    )


def test_receipt_bearing_variant_packet_renders_the_frozen_parent_set_and_binding(tmp_path):
    prompt = _render(tmp_path, {
        "agent_id": "acme-variant-1", "agent_role": "code-variant-hunter",
        "task": "Scan for variants", "finding_slugs": ["CH-001", "CH-004"],
    })

    section = prompt.split("## Variant Receipt Authority\n", 1)[1].split("\n## ", 1)[0]
    lines = section.splitlines()
    assert 'parent_finding_slugs: ["CH-001", "CH-004"]' in lines
    # The dispatch id cannot be in the packet; the binding command that
    # supplies it from this dispatch's own agent_id is.
    assert "--agent-id acme-variant-1" in section
    assert prompt.index("## Runtime Identity") < prompt.index("## Variant Receipt Authority")
    assert prompt.index("## Variant Receipt Authority") < prompt.index("## Authority\n")


def test_discovery_variant_packet_carries_no_receipt_authority(tmp_path):
    prompt = _render(tmp_path, {
        "agent_id": "acme-variant-2", "agent_role": "code-variant-hunter", "task": "Seed search",
    })
    assert "## Variant Receipt Authority" not in prompt


def _receipt(**overrides) -> dict[str, object]:
    payload: dict[str, object] = {
        "file_id": 42,
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": "a" * 64,
        "file_sha256": "b" * 64,
        "parent_finding_slugs": ["CH-001", "CH-004"],
        "status": "completed",
        "evidence_ref": "artifacts/variant-checks/src_parser_c.json",
        "rationale": "Checked each parent pattern against every candidate match in this file.",
    }
    payload.update(overrides)
    return payload


def _install(monkeypatch, *, dispatches: dict[str, dict]):
    posted: list[tuple[str, dict]] = []

    class _Client(StubClient):
        def get(self, endpoint):
            agent_id = endpoint.removeprefix("dispatches/")
            if endpoint.startswith("dispatches/") and agent_id in dispatches:
                return dispatches[agent_id]
            raise AssessError(f"HTTP 404 for {endpoint}")

        def post(self, endpoint, body):
            posted.append((endpoint, body))
            return {"id": 91, **body, "current_file_id": body["file_id"]}

    monkeypatch.setattr(code_record_variant_check, "AssessmentClient", _Client)
    monkeypatch.setattr(
        code_record_variant_check, "load_config",
        lambda *_a, **_k: SimpleNamespace(base_url="http://example.test", engagement_key="eng"),
    )
    return posted


def _run(monkeypatch, receipt: dict, **args):
    monkeypatch.setattr(code_record_variant_check.sys, "stdin", io.StringIO(json.dumps(receipt)))
    code_record_variant_check.run(SimpleNamespace(receipt_json="-", engagement_dir="/unused", **args))


def test_agent_id_binds_the_receipt_to_that_dispatch_row(monkeypatch, capsys):
    posted = _install(monkeypatch, dispatches={
        "acme-variant-1": {"id": 17, "agent_id": "acme-variant-1", "agent_role": "code-variant-hunter"},
    })

    _run(monkeypatch, _receipt(), agent_id="acme-variant-1")

    assert posted == [("code/variant-checks", {**_receipt(), "dispatch_id": 17})]
    assert json.loads(capsys.readouterr().out)["dispatch_id"] == 17


def test_a_receipt_dispatch_id_that_disagrees_with_agent_id_is_refused(monkeypatch, capsys):
    posted = _install(monkeypatch, dispatches={
        "acme-variant-1": {"id": 17, "agent_id": "acme-variant-1", "agent_role": "code-variant-hunter"},
    })

    with pytest.raises(SystemExit):
        _run(monkeypatch, _receipt(dispatch_id=18), agent_id="acme-variant-1")

    assert posted == []
    assert "17" in capsys.readouterr().err


def test_an_unknown_agent_id_is_refused_before_the_write(monkeypatch, capsys):
    posted = _install(monkeypatch, dispatches={})

    with pytest.raises(AssessError) as refused:
        _run(monkeypatch, _receipt(), agent_id="acme-missing")

    assert posted == []
    assert "acme-missing" in str(refused.value)
    assert "Runtime Identity" in str(refused.value)


def test_a_receipt_without_dispatch_id_or_agent_id_names_both_ways(monkeypatch, capsys):
    posted = _install(monkeypatch, dispatches={})

    with pytest.raises(SystemExit):
        _run(monkeypatch, _receipt())

    assert posted == []
    err = capsys.readouterr().err
    assert "dispatch_id" in err and "--agent-id" in err


def test_agent_id_flag_is_registered_on_the_leaf():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    code_record_variant_check.register(sub)
    args = parser.parse_args(["variant-check", "receipt.json", "--agent-id", "acme-variant-1"])
    assert args.agent_id == "acme-variant-1"


# The two other packet-rendering paths: a continuation of a scoped variant
# dispatch and a swarm of them carry the same receipt authority as `agent start`.

class _RecordingClient(StubClient):
    def __init__(self) -> None:
        self.writes: list[dict] = []

    def list_dispatches(self, **_filters) -> list[dict]:
        return []

    def record_dispatch(self, payload: dict) -> dict:
        self.writes.append(payload)
        packet = dict(payload.get("prompt_packet") or {})
        packet["sha256"] = hashlib.sha256(packet.get("rendered_prompt", "").encode()).hexdigest()
        return {"id": 7, **payload, "status": "in-progress", "prompt_packet": packet,
                "launch_required": True, "idempotent_replay": False}


def _section(prompt: str) -> str:
    return prompt.split("## Variant Receipt Authority\n", 1)[1].split("\n## ", 1)[0]


def _wire_dispatch(monkeypatch, tmp_path, client):
    cfg = SimpleNamespace(engagement_dir=str(tmp_path), agent_root=str(tmp_path))
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda _args: (client, cfg))
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_a: [])
    monkeypatch.setattr(agent, "_require_proof_variant_parent_set", lambda *_a: None)
    monkeypatch.setattr(agent, "_require_registered_role", lambda *_a: None)


_IDENTITY = ["repo_id: 7", "repo_generation: 3", "source_manifest_digest: " + "a" * 64]


def test_a_continued_variant_dispatch_carries_the_receipt_authority(monkeypatch, tmp_path):
    client = _RecordingClient()
    _wire_dispatch(monkeypatch, tmp_path, client)
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_a, **_k: list(_IDENTITY))
    prior = {"id": 3, "agent_id": "acme-variant-1", "agent_role": "code-variant-hunter",
             "status": "failed", "assessment_mode": "code",
             "finding_slugs": ["CH-001", "CH-004"]}
    context = {"authorized_phase": "verify-variant", "source_identity": list(_IDENTITY),
               "traffic_declaration": {"no_target_traffic": True, "rate_budget": None}}
    client.get_dispatch = lambda _agent_id: prior
    client.get = lambda _endpoint: {"context": context, "rendered_prompt": "Original scope",
                                    "sha256": "b" * 64}
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    args = parser.parse_args(["agent", "continue", "acme-variant-1",
                              "--task", "Finish the remaining candidate files"])
    args.engagement_dir = str(tmp_path)
    args.agent_id = "acme-variant-2"

    agent._continue(args)

    section = _section(client.writes[0]["prompt_packet"]["rendered_prompt"])
    assert 'parent_finding_slugs: ["CH-001", "CH-004"]' in section.splitlines()
    assert "--agent-id acme-variant-2" in section


def test_each_swarm_worker_packet_carries_its_own_receipt_binding(monkeypatch, tmp_path):
    client = _RecordingClient()
    _wire_dispatch(monkeypatch, tmp_path, client)
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_a, **_k: [])
    items = tmp_path / "files.txt"
    items.write_text("src/a.c\nsrc/b.c\n", encoding="utf-8")
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    args = parser.parse_args([
        "agent", "start-swarm", "--role", "code-variant-hunter", "--assessment-mode", "code",
        "--task", "Scan the assigned files for the parent patterns",
        "--finding-slugs", "CH-001,CH-004", "--workers", "2", "--batch-size", "1",
        "--items-file", str(items), "--no-target-traffic",
    ])
    args.engagement_dir = str(tmp_path)

    agent._start_swarm(args)

    assert len(client.writes) == 2
    for write in client.writes:
        section = _section(write["prompt_packet"]["rendered_prompt"])
        assert 'parent_finding_slugs: ["CH-001", "CH-004"]' in section.splitlines()
        assert f"--agent-id {write['agent_id']}" in section
