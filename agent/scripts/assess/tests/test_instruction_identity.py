from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import agent
from assess.lib.instruction_identity import build_dispatch_instruction_identity


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _agent_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    agent.register(parser.add_subparsers())
    return parser


def _fixture_tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    source_root = tmp_path / "source"
    install_root = tmp_path / "install"
    agent_root = install_root / "agent"
    engagement_dir = agent_root / "engagements" / "eng-1"
    source_root.mkdir()
    engagement_dir.mkdir(parents=True)
    (agent_root / ".codex" / "agents").mkdir(parents=True)
    (source_root / "agent" / ".codex" / "agents").mkdir(parents=True)
    (install_root / ".vigil-install-meta.json").write_text(
        json.dumps(
            {
                "source_sha": "a" * 40,
                "source_root": str(source_root),
            }
        ),
        encoding="utf-8",
    )
    return source_root, agent_root, engagement_dir


def test_dispatch_instruction_identity_hashes_exact_installed_files(
    tmp_path: Path,
) -> None:
    source_root, agent_root, engagement_dir = _fixture_tree(tmp_path)
    operator_bytes = b"installed operator instructions\n"
    specialist_bytes = b"installed specialist instructions\n"
    (agent_root / "AGENTS.md").write_bytes(operator_bytes)
    (agent_root / ".codex" / "agents" / "recon-specialist.toml").write_bytes(
        specialist_bytes
    )
    (source_root / "agent" / "AGENTS.md").write_bytes(operator_bytes)
    (
        source_root / "agent" / ".codex" / "agents" / "recon-specialist.toml"
    ).write_bytes(specialist_bytes)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_type": "web"}), encoding="utf-8"
    )

    identity, warnings = build_dispatch_instruction_identity(
        agent_root=agent_root,
        engagement_dir=engagement_dir,
        agent_role="recon-specialist",
        client_name="codex",
    )

    assert identity == {
        "client_name": "codex",
        "source_revision": "a" * 40,
        "operator_instruction_path": "agent/AGENTS.md",
        "operator_instruction_sha256": _sha256(operator_bytes),
        "specialist_instruction_path": (
            "agent/.codex/agents/recon-specialist.toml"
        ),
        "specialist_instruction_sha256": _sha256(specialist_bytes),
        "instruction_identity_status": "verified",
        "instructions_stale": False,
    }
    assert warnings == []


def test_dispatch_instruction_identity_uses_blue_operator_and_reports_staleness(
    tmp_path: Path,
) -> None:
    source_root, agent_root, engagement_dir = _fixture_tree(tmp_path)
    (agent_root / "AGENTS-blue.md").write_text("installed blue\n", encoding="utf-8")
    (agent_root / ".codex" / "agents" / "recon-specialist.toml").write_text(
        "installed specialist\n", encoding="utf-8"
    )
    (source_root / "agent" / "AGENTS-blue.md").write_text(
        "newer blue\n", encoding="utf-8"
    )
    (
        source_root / "agent" / ".codex" / "agents" / "recon-specialist.toml"
    ).write_text("installed specialist\n", encoding="utf-8")
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_type": "blue"}), encoding="utf-8"
    )

    identity, warnings = build_dispatch_instruction_identity(
        agent_root=agent_root,
        engagement_dir=engagement_dir,
        agent_role="recon-specialist",
        client_name="codex",
    )

    assert identity["operator_instruction_path"] == "agent/AGENTS-blue.md"
    assert identity["instruction_identity_status"] == "verified"
    assert identity["instructions_stale"] is True
    assert any("installed instructions differ" in warning for warning in warnings)


def test_dispatch_instruction_identity_never_guesses_unknown_client_wrapper(
    tmp_path: Path,
) -> None:
    source_root, agent_root, engagement_dir = _fixture_tree(tmp_path)
    (agent_root / "AGENTS.md").write_text("operator\n", encoding="utf-8")
    (source_root / "agent" / "AGENTS.md").write_text(
        "operator\n", encoding="utf-8"
    )
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")

    identity, warnings = build_dispatch_instruction_identity(
        agent_root=agent_root,
        engagement_dir=engagement_dir,
        agent_role="recon-specialist",
        client_name=None,
    )

    assert identity["client_name"] == "unknown"
    assert identity["specialist_instruction_path"] is None
    assert identity["specialist_instruction_sha256"] is None
    assert identity["instruction_identity_status"] == "incomplete"
    assert identity["instructions_stale"] is None
    assert any("client identity is unavailable" in warning for warning in warnings)


def test_dispatch_instruction_identity_retains_known_client_without_specialist_wrapper(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root, agent_root, engagement_dir = _fixture_tree(tmp_path)
    operator_bytes = b"operator\n"
    (agent_root / "AGENTS.md").write_bytes(operator_bytes)
    (source_root / "agent" / "AGENTS.md").write_bytes(operator_bytes)
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CLIENT_NAME", "kimi")

    identity, warnings = build_dispatch_instruction_identity(
        agent_root=agent_root,
        engagement_dir=engagement_dir,
        agent_role="recon-specialist",
    )

    assert identity["client_name"] == "kimi"
    assert identity["operator_instruction_sha256"] == _sha256(operator_bytes)
    assert identity["specialist_instruction_path"] is None
    assert identity["instruction_identity_status"] == "incomplete"
    assert any("does not install a specialist wrapper" in warning for warning in warnings)


def test_agent_start_overwrites_forged_provenance_and_marks_observed_model_unknown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _source_root, agent_root, engagement_dir = _fixture_tree(tmp_path)
    operator_bytes = b"trusted operator\n"
    specialist_bytes = b"trusted specialist\n"
    (agent_root / "AGENTS.md").write_bytes(operator_bytes)
    (agent_root / ".codex" / "agents" / "recon-specialist.toml").write_bytes(
        specialist_bytes
    )
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VIGIL_CLIENT_NAME", "codex")
    payload = {
        "agent_id": "recon-1",
        "agent_role": "recon-specialist",
        "source_revision": "forged",
        "operator_instruction_sha256": "0" * 64,
        "actual_model": "caller-forged-model",
        "actual_reasoning": "caller-forged-reasoning",
    }

    warnings = agent._attach_dispatch_provenance(
        payload,
        SimpleNamespace(
            agent_root=str(agent_root),
            engagement_dir=str(engagement_dir),
        ),
    )

    assert payload["source_revision"] == "a" * 40
    assert payload["operator_instruction_sha256"] == _sha256(operator_bytes)
    assert payload["specialist_instruction_sha256"] == _sha256(specialist_bytes)
    assert payload["actual_model"] == "unknown"
    assert payload["actual_reasoning"] == "unknown"
    assert any("provider-observed model identity" in warning for warning in warnings)


@pytest.mark.parametrize("field", ["--actual-model", "--actual-reasoning"])
def test_agent_cli_rejects_caller_attested_actual_identity(field: str) -> None:
    with pytest.raises(SystemExit) as exc:
        _agent_parser().parse_args(
            [
                "agent",
                "start",
                "--agent-id",
                "recon-1",
                "--role",
                "recon-specialist",
                field,
                "forged",
            ]
        )

    assert exc.value.code == 2
