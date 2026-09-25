"""Proof-bearing variant dispatches must name their parent findings."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import agent


def test_verify_variant_rotation_requires_finding_slugs_before_dispatch(
    monkeypatch, tmp_path, capsys
):
    (tmp_path / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "verify"}),
        encoding="utf-8",
    )
    payload = {
        "agent_id": "variant-1",
        "agent_role": "vulnerability-analyst",
        "dispatch_mode": "variant-rotation",
        "task": "Hunt siblings of confirmed finding",
    }

    class _Client:
        def close(self):
            pass

        def record_dispatch(self, _payload):
            raise AssertionError("must reject before writing a dispatch")

    monkeypatch.setattr(agent.dispatch, "_build_register_payload", lambda _args: payload)
    monkeypatch.setattr(
        agent.dispatch, "_client_for", lambda _args: (
            _Client(),
            SimpleNamespace(engagement_dir=str(tmp_path), agent_root=str(tmp_path)),
        ),
    )
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_args: [])
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_args, **_kwargs: [])
    with pytest.raises(SystemExit) as exc:
        agent._start(SimpleNamespace(dry_run=False, allow_duplicate=True, emit_prompt=False))
    assert exc.value.code == 1
    assert "--finding-slugs" in capsys.readouterr().err


def test_exploratory_fuzzer_rotation_keeps_unscoped_dispatch(tmp_path):
    (tmp_path / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "verify"}),
        encoding="utf-8",
    )
    agent._require_proof_variant_parent_set(
        {"agent_role": "fuzzer", "dispatch_mode": "variant-rotation"}, tmp_path
    )


def test_code_verify_variant_requires_parent_finding_slugs(tmp_path, capsys):
    (tmp_path / "scope.json").write_text(
        json.dumps({"engagement_type": "code", "current_phase": "verify-variant"}),
        encoding="utf-8",
    )
    payload = {"agent_role": "code-variant-hunter"}
    with pytest.raises(SystemExit) as exc:
        agent._require_proof_variant_parent_set(payload, tmp_path)
    assert exc.value.code == 1
    assert "--finding-slugs" in capsys.readouterr().err
    agent._require_proof_variant_parent_set(
        {**payload, "finding_slugs": ["parent-finding"]}, tmp_path
    )
