"""Regression contracts for CLI shapes that previously contradicted their help."""
from __future__ import annotations

import argparse
import functools
import inspect
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from assess import cli
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


# --------------------------------------------------------------------------- #
# Contract-registry parity with the real argparse tree
#
# `vigil assess contract <verb>` and `vigil assess list-commands` are the only
# two discovery surfaces an agent has, and BOTH derive from `_CONTRACTS`. A verb
# that reaches neither is invisible: the agent either guesses the write shape or
# declines to record legitimate state. So every leaf that can WRITE must resolve
# through the registry, and the only exemptions are named read-only verbs.
# --------------------------------------------------------------------------- #


@functools.lru_cache(maxsize=1)
def _root_parser() -> argparse.ArgumentParser:
    """The real `vigil assess` root parser, with every subcommand registered.

    `cli.main` builds the parser inline and immediately parses, so there is no
    builder to call. Intercepting the root parser's own `parse_args` is the one
    way to reflect the ACTUAL registered tree — reconstructing it here would
    just be a second copy of `cli.py` that can drift from it.
    """
    captured: dict[str, argparse.ArgumentParser] = {}
    real_parse_args = argparse.ArgumentParser.parse_args

    def _capture(self, args=None, namespace=None):
        if self.prog == "vigil assess":
            captured["parser"] = self
            raise SystemExit(0)
        return real_parse_args(self, args, namespace)

    with mock.patch.object(argparse.ArgumentParser, "parse_args", _capture):
        with pytest.raises(SystemExit):
            cli.main([])

    parser = captured.get("parser")
    assert parser is not None, "failed to capture the `vigil assess` root parser"
    return parser


def _leaf_commands(
    parser: argparse.ArgumentParser, path: tuple[str, ...] = ()
) -> list[tuple[str, argparse.ArgumentParser]]:
    """Every executable leaf in the tree as ("<verb> <action> ...", parser)."""
    subparser_actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if not subparser_actions:
        return [(" ".join(path), parser)] if path else []
    leaves: list[tuple[str, argparse.ArgumentParser]] = []
    for action in subparser_actions:
        for name, subparser in action.choices.items():
            leaves.extend(_leaf_commands(subparser, path + (name,)))
    return leaves


# A call that changes durable state: a backend row write, an activity/decision
# write, or a write to a canonical engagement file (scope.json, a scans/ or
# notes/ artifact). Scanning the handler's whole MODULE is deliberate — helper
# functions do most of the writing, and over-matching only costs an allowlist
# entry while under-matching would let a state-writing verb stay invisible.
_MUTATING_CALL_RE = re.compile(
    r"""\bclient\.(?:post|put|patch|delete)\b
      | \bpost_event\b
      | \bpost_engagement\b
      | \brecord_decision\b
      | \bupdate_decision\b
      | \bmutate_scope\b
      | \.write_text\(
      | \.write_bytes\(
      | \bopen\([^)]*["'][wa]
    """,
    re.VERBOSE,
)

# Leaves whose module ALSO contains a mutating call but which are themselves
# read-only, so they need no write contract of their own. Keep this list tiny
# and justified: anything NOT listed here that can write must resolve through
# `get_contract`, which is what makes a newly-added state-writing verb fail.
_READ_ONLY_LEAVES: dict[str, str] = {
    # The read side of `block-technique`; both live in block_technique.py, and
    # the `block-technique` contract already lists this verb as a preferred
    # invocation, so the pair is documented in one place.
    "list-blocked-techniques": "read side of `block-technique` (same module)",
}


def _leaf_module_source(parser: argparse.ArgumentParser) -> str:
    handler = parser.get_default("func")
    module = sys.modules.get(getattr(handler, "__module__", "") or "")
    if module is None:
        return ""
    try:
        return inspect.getsource(module)
    except OSError:  # pragma: no cover - source is always available in-tree
        return ""


def _state_writing_leaves() -> list[str]:
    return sorted(
        name
        for name, parser in _leaf_commands(_root_parser())
        if _MUTATING_CALL_RE.search(_leaf_module_source(parser))
    )


def test_every_state_writing_verb_resolves_through_the_contract_registry() -> None:
    undiscoverable = [
        name
        for name in _state_writing_leaves()
        if name not in _READ_ONLY_LEAVES and contracts.get_contract(name) is None
    ]

    assert not undiscoverable, (
        "these verbs can write durable state but resolve to no contract, so "
        "`vigil assess contract <verb>` returns 'Unknown contract' and "
        "`list-commands` never surfaces them: " + ", ".join(undiscoverable)
    )


def test_read_only_allowlist_stays_minimal_and_current() -> None:
    # An entry is only justified while the verb is (a) still registered and
    # (b) still sharing a module with a writer. Otherwise it is dead weight
    # hiding a verb that should be carrying its own contract.
    leaves = dict(_leaf_commands(_root_parser()))
    for name in _READ_ONLY_LEAVES:
        assert name in leaves, f"{name!r} is allowlisted but no longer registered"
        assert _MUTATING_CALL_RE.search(_leaf_module_source(leaves[name])), (
            f"{name!r} no longer shares a module with a writer — drop the "
            "allowlist entry"
        )


def test_registered_kali_verbs_match_the_kali_verb_registry() -> None:
    # KALI_VERBS drives the `--kali-only` expansion, the collapsed dispatcher's
    # phase union, and `contract kali <verb>`. A verb registered in cli.py but
    # missing here (as `sweep` was) is invisible to all three.
    registered = {
        name.split(" ", 1)[1]
        for name, _parser in _leaf_commands(_root_parser())
        if name.startswith("kali ")
    }
    # `kali job <action>` is one registry entry (`job`) with its own action tree.
    registered = {verb.split(" ", 1)[0] for verb in registered}

    assert registered == set(contracts.KALI_VERBS)


@pytest.mark.parametrize(
    "name",
    [
        "artifact register",
        "artifact mark-scratch",
        "auth status",
        "exploit approve",
        "fixture observe",
        "gau js-endpoints",
        "http import-har",
        "http policy set",
        "ingest endpoints",
        "kali job start",
        "resolve coverage-item",
    ],
)
def test_inline_documented_namespace_action_resolves_to_its_parent(name: str) -> None:
    # These parents document every action inline and TELL the reader to run
    # `contract <parent> <action>`; returning "Unknown contract" there made the
    # parent's own pointer a dead end.
    parent = name.rsplit(" ", 1)[0] if name.startswith("kali job") else name.split(" ")[0]
    contract = contracts.get_contract(name)

    assert contract is not None, f"contract lookup for {name!r} returned None"
    assert contract.name == parent


def test_details_writing_contracts_publish_the_allowed_details_keys() -> None:
    # `details` is validated under additionalProperties:false, so an unknown key
    # is rejected outright. Both verbs that write it must print the vocabulary.
    for name in ("finding record", "finding update"):
        rendered = contracts.render_contract(name)
        assert "Allowed details keys" in rendered, name
        for key in ("attacker_trace", "cvss_vector", "repro_runs"):
            assert f"  - {key}" in rendered, f"{key} missing from {name} contract"
