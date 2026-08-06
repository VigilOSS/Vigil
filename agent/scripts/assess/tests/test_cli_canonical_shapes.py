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


def _agent_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    agent.register(sub)
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


def test_host_exec_contract_exposes_the_authoritative_cli_shapes() -> None:
    contract = contracts.get_contract("host-exec")

    assert contract is not None
    assert contract.name == "host-exec"
    assert contract.schema_name == "argparse + HostExecRecord/CommandRunFinalize"
    assert contract.preferred_invocations == (
        "vigil assess host-exec --tool <tool> --intent '<why>' --technique <technique> --phase <phase> -- <command> [args...]",
        "vigil assess host-exec --from-json <request.json>",
    )
    rendered = contracts.render_contract("host-exec")
    assert "--require-audit" in rendered
    assert "--allow-destructive" in rendered
    assert "--finding" in rendered


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


class _CodeDispatchClient(_DispatchClient):
    def __init__(self, repos: list[dict]) -> None:
        self.repos = repos
        self.recorded = False

    def get(self, endpoint: str):
        assert endpoint == "code/repos"
        return self.repos

    def record_dispatch(self, payload: dict) -> dict:
        self.recorded = True
        return super().record_dispatch(payload)


def test_agent_start_code_role_renders_backend_derived_source_identity(
    monkeypatch, capsys, tmp_path
) -> None:
    digest = "a" * 64
    client = _CodeDispatchClient(
        [
            {
                "id": 17,
                "repo_key": "example-17",
                "name": "example",
                "repo_path": "/sealed/example/source",
                "active_generation": 3,
                "source_manifest_digest": digest,
                "structural_index_schema": "structural-index/v5",
                "structural_index_manifest_path": "/sealed/example/index/manifest.json",
                "lsp_config": {
                    "ctags": {
                        "available": True,
                        "repo_generation": 3,
                        "source_manifest_digest": digest,
                        "tags_path": "/sealed/example/ctags/tags",
                    }
                },
            }
        ]
    )
    args = SimpleNamespace(
        agent_id="code-hunter-1",
        agent_role="code-vuln-hunter",
        code_repo_id=None,
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_build_register_payload",
        lambda _args: {
            "agent_id": "code-hunter-1",
            "agent_role": "code-vuln-hunter",
        },
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_client_for",
        lambda _args: (
            client,
            SimpleNamespace(engagement_dir=str(tmp_path)),
        ),
    )
    monkeypatch.setattr(agent, "_warn_missing_native_wrapper", lambda *_args: None)

    agent._start(args)

    assert client.recorded is True
    output = capsys.readouterr().out
    assert output.index("## Runtime Identity") < output.index("## Code Source Identity")
    assert "repo_id: 17" in output
    assert "repo_key: example-17" in output
    assert "repo_generation: 3" in output
    assert f"source_manifest_digest: {digest}" in output
    assert "snapshot_path: /sealed/example/source" in output
    assert "structural_index_schema: structural-index/v5" in output
    assert "structural_index_manifest_path: /sealed/example/index/manifest.json" in output
    assert "ctags_path: /sealed/example/ctags/tags" in output
    assert "pass it the Runtime Identity and Code Source Identity blocks above" in output


def test_agent_start_code_repo_selector_parses() -> None:
    args = _agent_parser().parse_args(
        [
            "agent",
            "start",
            "--agent-id",
            "code-hunter-1",
            "--role",
            "code-vuln-hunter",
            "--code-repo-id",
            "17",
        ]
    )

    assert args.code_repo_id == 17


def test_agent_start_code_role_requires_repo_selection_before_recording(
    monkeypatch, capsys, tmp_path
) -> None:
    digest = "b" * 64
    repos = [
        {
            "id": repo_id,
            "repo_key": f"repo-{repo_id}",
            "repo_path": f"/sealed/repo-{repo_id}/source",
            "active_generation": 1,
            "source_manifest_digest": digest,
            "structural_index_schema": "structural-index/v5",
            "structural_index_manifest_path": f"/sealed/repo-{repo_id}/manifest.json",
            "lsp_config": {},
        }
        for repo_id in (17, 18)
    ]
    client = _CodeDispatchClient(repos)
    args = SimpleNamespace(
        agent_id="code-hunter-1",
        agent_role="code-vuln-hunter",
        code_repo_id=None,
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_build_register_payload",
        lambda _args: {
            "agent_id": "code-hunter-1",
            "agent_role": "code-vuln-hunter",
        },
    )
    monkeypatch.setattr(
        agent.dispatch,
        "_client_for",
        lambda _args: (
            client,
            SimpleNamespace(engagement_dir=str(tmp_path)),
        ),
    )

    with pytest.raises(SystemExit) as excinfo:
        agent._start(args)

    assert excinfo.value.code == 1
    assert client.recorded is False
    assert "pass --code-repo-id" in capsys.readouterr().err
