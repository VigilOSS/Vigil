"""Native OpenCode discovery contracts verified on 1.18.10 and 1.19.3.

The native config loader scans plugin(s)/*.{ts,js}; merely writing a valid
JavaScript module with another suffix does not register a lifecycle adapter.
"""
import json
from pathlib import Path

import pytest
import yaml

from vigil_cli import assessment_clients


ROOT = Path(__file__).resolve().parents[1]


def test_prepared_assessment_hook_is_discoverable_by_native_opencode(tmp_path, monkeypatch):
    engagement = tmp_path / "private/engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(assessment_clients, "agent_root", lambda _: ROOT / "agent")
    monkeypatch.setattr(assessment_clients, "application_provenance", lambda _: {
        "root": str(ROOT), "version": "1.0.0", "content_sha256": "a" * 64,
    })
    monkeypatch.setattr(assessment_clients, "session_cli_directory", lambda _: tmp_path / "helper")
    monkeypatch.setattr(assessment_clients, "_tools", lambda _: {
        name: "/bin/true" for name in ("uv", "bash", "jq", "node")
    })
    monkeypatch.setattr(assessment_clients, "resolve_orchestrator_base_url", lambda *_: "http://127.0.0.1:9")

    workspace, _ = assessment_clients.prepare_workspace(
        tmp_path / "private", engagement, "opencode", "code", native_version="1.18.10",
    )
    discovered = [
        path for directory in ("plugin", "plugins") for suffix in ("ts", "js")
        for path in (workspace / ".opencode" / directory).glob(f"*.{suffix}")
    ]
    assert len(discovered) == 1
    assert discovered[0].read_bytes() == (ROOT / "agent/.opencode/plugin/project-dispatch.js").read_bytes()
    runtime = workspace / ".opencode/vigil-assessment-runtime.mjs"
    assert runtime.read_bytes() == (ROOT / "agent/.opencode/plugin/assessment-hooks.js").read_bytes()


def _frontmatter(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    return yaml.safe_load(text.split("\n---\n", 1)[0][4:])


@pytest.mark.parametrize("tree", ["agent/.opencode/agent", "agent/.opencode/assessment/agents"])
def test_specialists_cannot_block_an_unattended_run_on_a_question(tree):
    """OpenCode never auto-answers the question tool, so a specialist that asks
    one stalls its dispatch; only the operator talks to the user."""
    wrappers = sorted((ROOT / tree).glob("*.md"))
    assert wrappers, f"render the client trees first: {tree}"
    for wrapper in wrappers:
        frontmatter = _frontmatter(wrapper)
        question = (frontmatter.get("permission") or {}).get("question")
        if frontmatter["mode"] == "primary":
            assert question is None, wrapper
        else:
            assert frontmatter["mode"] == "subagent", wrapper
            assert question == "deny", wrapper


def test_staged_specialists_keep_the_question_denial(tmp_path, monkeypatch):
    """Native discovery reads the staged forwarding roles, not the rendered tree."""
    engagement = tmp_path / "private/engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(assessment_clients, "agent_root", lambda _: ROOT / "agent")
    monkeypatch.setattr(assessment_clients, "application_provenance", lambda _: {
        "root": str(ROOT), "version": "1.0.0", "content_sha256": "a" * 64,
    })
    monkeypatch.setattr(assessment_clients, "session_cli_directory", lambda _: tmp_path / "helper")
    monkeypatch.setattr(assessment_clients, "_tools", lambda _: {
        name: "/bin/true" for name in ("uv", "bash", "jq", "node")
    })
    monkeypatch.setattr(assessment_clients, "resolve_orchestrator_base_url", lambda *_: "http://127.0.0.1:9")
    workspace, _ = assessment_clients.prepare_workspace(
        tmp_path / "private", engagement, "opencode", "web", native_version="opencode v2.3.0",
    )
    staged = sorted((workspace / ".opencode/agents").glob("*.md"))
    assert {path.name for path in staged} == {
        path.name for path in (ROOT / "agent/.opencode/assessment/agents").glob("*.md")}
    for wrapper in staged:
        frontmatter = _frontmatter(wrapper)
        rendered = _frontmatter(ROOT / "agent/.opencode/assessment/agents" / wrapper.name)
        assert frontmatter == rendered, wrapper


def _discovered_plugins(opencode_dir: Path) -> list[Path]:
    return [path for directory in ("plugin", "plugins") for suffix in ("ts", "js")
            for path in (opencode_dir / directory).glob(f"*.{suffix}")]


def test_standard_engagement_plugin_is_discovered_once(tmp_path):
    """Both OpenCode majors scan plugin/ and plugins/; OpenCode 2 rejects a
    second module with the same plugin id."""
    from vigil_cli import client_rosters, engagements

    agent_root = tmp_path / "agent"
    (agent_root / ".opencode/plugin").mkdir(parents=True)
    (agent_root / ".opencode/plugin/standard-hooks.js").write_text("// hook v2\n")
    (agent_root / ".opencode/agent").mkdir()
    engagement = tmp_path / "engagement"
    engagement.mkdir()
    engagements._write_opencode_config(agent_root, engagement)
    assert [path.read_text() for path in _discovered_plugins(engagement / ".opencode")] == ["// hook v2\n"]

    stale = engagement / ".opencode/plugins/standard-hooks.js"
    stale.parent.mkdir(exist_ok=True)
    stale.write_text("// hook v1\n")
    client_rosters.ensure_opencode_plugin(agent_root, engagement / ".opencode")
    assert [path.read_text() for path in _discovered_plugins(engagement / ".opencode")] == ["// hook v2\n"]


def test_built_in_subagents_cannot_block_an_unattended_run_on_a_question(tmp_path):
    """The project-wide allow overrides the built-in general/explore deny of the
    question tool, so the engagement config restores it."""
    from vigil_cli import engagements

    engagement = tmp_path / "engagement"
    engagement.mkdir()
    config = engagements._load_opencode_config(engagement)
    for name in ("general", "explore"):
        assert config["agent"][name]["permission"]["question"] == "deny"


@pytest.mark.parametrize("agent", ["acme", {"general": "acme", "explore": {"permission": "deny"}}])
def test_question_denial_keeps_a_hand_edited_non_object_value(tmp_path, agent):
    from vigil_cli import engagements

    engagement = tmp_path / "engagement"
    engagement.mkdir()
    (engagement / "opencode.json").write_text(json.dumps({"agent": agent}))
    assert engagements._load_opencode_config(engagement)["agent"] == agent


def test_assessment_built_in_subagents_cannot_block_on_a_question(tmp_path, monkeypatch):
    engagement = tmp_path / "private/engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(assessment_clients, "agent_root", lambda _: ROOT / "agent")
    monkeypatch.setattr(assessment_clients, "application_provenance", lambda _: {
        "root": str(ROOT), "version": "1.0.0", "content_sha256": "a" * 64,
    })
    monkeypatch.setattr(assessment_clients, "session_cli_directory", lambda _: tmp_path / "helper")
    monkeypatch.setattr(assessment_clients, "_tools", lambda _: {
        name: "/bin/true" for name in ("uv", "bash", "jq", "node")
    })
    monkeypatch.setattr(assessment_clients, "resolve_orchestrator_base_url", lambda *_: "http://127.0.0.1:9")
    workspace, _ = assessment_clients.prepare_workspace(
        tmp_path / "private", engagement, "opencode", "web", native_version="opencode v2.3.0",
    )
    config = json.loads((workspace / ".opencode/opencode.json").read_text())
    for name in ("general", "explore"):
        assert config["agent"][name]["permission"]["question"] == "deny"
