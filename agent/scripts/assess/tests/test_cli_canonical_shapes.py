"""Regression contracts for CLI shapes that previously contradicted their help."""
from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import agent, artifact
from assess.lib import contracts


REPO_ROOT = Path(__file__).resolve().parents[4]


def _artifact_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    artifact.register(sub)
    return parser


def test_artifact_search_uses_q_for_free_text() -> None:
    args = _artifact_parser().parse_args(
        ["artifact", "search", "--q", "device fingerprint"]
    )

    assert args.query == "device fingerprint"


def test_artifact_search_rejects_positional_query_with_q_guidance(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        _artifact_parser().parse_args(
            ["artifact", "search", "device fingerprint"]
        )

    assert exc.value.code == 2
    assert "--q" in capsys.readouterr().err


def test_canonical_contracts_have_one_cli_shape() -> None:
    artifact_contract = contracts.render_contract("artifact")
    link_contract = contracts.render_contract("finding link")
    agent_contract = contracts.render_contract("agent")
    start_contract = contracts.render_contract("agent start")

    assert "artifact search --q" in artifact_contract
    assert "search: --q" in artifact_contract
    assert "artifact search VA-047" not in artifact_contract
    assert "--reason" in link_contract
    assert "--note" not in link_contract
    assert "<db_path>" not in agent_contract
    assert "work-buffer cases.db" not in agent_contract
    assert "does not spawn" in start_contract.lower()


def test_operator_prompt_does_not_advertise_local_work_buffer_database() -> None:
    prompt_sources = (
        REPO_ROOT / "agent" / "shared-constraints.md",
        REPO_ROOT / "agent" / "operator-core.md",
        REPO_ROOT / "agent" / "operator-core-blue.md",
    )

    for path in prompt_sources:
        text = path.read_text(encoding="utf-8")
        assert "work-buffer <db>" not in text, path
        assert "work-buffer <db_path>" not in text, path
        assert "work-buffer cases.db" not in text, path


class _DispatchClient:
    def record_dispatch(self, payload: dict) -> dict:
        return {"id": 7, **payload, "status": "in-progress"}

    def close(self) -> None:
        pass


def test_agent_start_output_explains_record_then_launch_flow(
    monkeypatch, capsys, tmp_path
) -> None:
    args = SimpleNamespace(
        agent_id="analyst-1",
        agent_role="vulnerability-analyst",
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_build_register_payload",
        lambda _args: {
            "agent_id": "analyst-1",
            "agent_role": "vulnerability-analyst",
        },
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_client_for",
        lambda _args: (
            _DispatchClient(),
            SimpleNamespace(engagement_dir=str(tmp_path)),
        ),
    )
    monkeypatch.setattr(agent, "_warn_missing_native_wrapper", lambda *_args: None)

    agent._start(args)

    out = capsys.readouterr().out.lower()
    assert "does not spawn" in out
    assert "launch the specialist" in out
