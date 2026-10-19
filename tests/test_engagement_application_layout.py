"""Application assets never share ownership with private engagement/tenant state."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tomllib

import pytest

from vigil_cli import blue, engagements, remediation_sessions


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (application / "orchestrator").mkdir(parents=True)
    agent = application / "agent"
    (agent / "references" / "tenants").mkdir(parents=True)
    (agent / "AGENTS.md").write_text("application web prompt\n")
    (agent / "operator-core-code.md").write_text("application code prompt\n")
    (agent / "references" / "tenants" / "_template-gws.md").write_text("application tenant template\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    return application, workspace


def test_engagement_prompt_uses_application_assets(layout):
    application, workspace = layout
    assert engagements.engagement_mode_prompt(workspace, "code") == application / "agent/operator-core-code.md"


def test_engagement_create_uses_application_assets_in_fresh_workspace(layout, monkeypatch):
    application, workspace = layout
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "codex")
    created = engagements.create_engagement(
        engagements.CreateEngagementOptions(install_root=workspace, engagement_type="code", name="Acme"),
        contact_backend=False,
    )
    assert created.path.parent == workspace / "engagements"
    pointer = (created.path / "AGENTS.md").read_text()
    assert str(application / "agent/operator-core-code.md") in pointer
    assert f"Install root: {workspace}" in pointer
    assert not (workspace / "agent").exists()


@pytest.mark.parametrize("adopted", [False, True])
def test_blue_tenant_init_reads_application_template_and_writes_private_path(layout, adopted):
    application, workspace = layout
    destination_root = workspace / ("agent/references/tenants" if adopted else "tenant-references")
    if adopted:
        destination_root.mkdir(parents=True)
        (destination_root / "_template-gws.md").write_text("obsolete copied template\n")
    blue._cmd_tenant_init(argparse.Namespace(customer="acme", platform="gws", force=False), workspace)
    destination = destination_root / "acme-workspace.md"
    assert destination.read_text() == "application tenant template\n"
    assert not (application / "agent/references/tenants/acme-workspace.md").exists()
    assert blue._discover_blue_customers(workspace)[0]["tenant_reference_paths"] == [str(destination)]


def test_remediation_route_resolves_roles_from_application_not_workspace(layout):
    application, workspace = layout
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    context = remediation_sessions.route_context(workspace, engagement, {"repository": str(workspace / "source")}, ["SEC-123"])
    assert context["instructions"] == str(application / "agent/remediation-developer.md")
    assert context["essentials"] == str(application / "agent/operator-core-remediation.md")
    assert Path(context["pending_input"]).is_relative_to(engagement)


def test_launcher_pins_release_helper_and_private_workspace(layout, monkeypatch):
    from vigil_cli import application as application_module

    application, workspace = layout
    helper_bin = application / "bin"
    helper_bin.mkdir()
    helper = helper_bin / "vigil"
    helper.write_text("#!/bin/sh\nprintf 'http://matched-release.example\\n'\n")
    helper.chmod(0o755)
    client_bin = workspace / "bin"
    client_bin.mkdir()
    client = client_bin / "codex"
    client.write_text('#!/bin/sh\nprintf "%s\\n" "$ORCHESTRATOR_BASE_URL" "$VIGIL_APPLICATION_DIR" "$VIGIL_INSTALL_DIR"\n')
    client.chmod(0o755)
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(application_module, "session_cli_directory", lambda *_: helper_bin)
    monkeypatch.setenv("PATH", f"{client_bin}:/usr/bin:/bin")
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False, workspace_root=workspace)

    result = subprocess.run([str(engagement / "start_codex.sh")], text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["http://matched-release.example", str(application), str(workspace)]


def test_tenant_init_refuses_an_application_owned_destination(layout, monkeypatch):
    application, workspace = layout
    monkeypatch.setattr(blue, "tenant_references_root", lambda *_: application / "agent/references/tenants")
    with pytest.raises(SystemExit, match="application"):
        blue._cmd_tenant_init(argparse.Namespace(customer="acme", platform="gws", force=False), workspace)
    assert not (application / "agent/references/tenants/acme-workspace.md").exists()


def test_remediation_environment_pins_application_and_helpers(layout, monkeypatch):
    from vigil_cli import application as application_module

    application, workspace = layout
    helper_bin = application / "bin"
    monkeypatch.setattr(application_module, "session_cli_directory", lambda *_: helper_bin)
    environment = remediation_sessions._environment(workspace / "engagements/acme", "acme")
    assert environment["VIGIL_APPLICATION_DIR"] == str(application)
    assert environment["PATH"].split(":")[0] == str(helper_bin)
    assert environment["VIGIL_SESSION_ENGAGEMENT_DIR"] == str(workspace / "engagements/acme")


def test_remediation_command_overlays_retain_each_release(layout, monkeypatch):
    application, workspace = layout
    engagement = workspace / "engagements/acme"
    first_source = application / "agent/.claude/commands/vigil-remediate.md"
    first_source.parent.mkdir(parents=True)
    first_source.write_text("first release\n")
    first = remediation_sessions._command_overlay(workspace, engagement)
    second_application = application.parent / "application-next"
    (second_application / "orchestrator").mkdir(parents=True)
    second_source = second_application / "agent/.claude/commands/vigil-remediate.md"
    second_source.parent.mkdir(parents=True)
    second_source.write_text("next release\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(second_application))
    second = remediation_sessions._command_overlay(workspace, engagement)
    assert first != second
    assert (first / ".claude/commands/vigil-remediate.md").resolve() == first_source
    assert (second / ".claude/commands/vigil-remediate.md").resolve() == second_source


def test_explicit_pointer_repair_updates_legacy_default_web_to_application(layout):
    application, workspace = layout
    copied_agent = workspace / "agent"
    copied_agent.mkdir()
    (copied_agent / "AGENTS.md").write_text("old copied prompt\n")
    engagement = copied_agent / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "active"}))
    engagements._write_prompt_wrappers(copied_agent, engagement, "codex", engagement_type="web")
    assert engagements.repair_engagement_operator_pointers(workspace) == ("acme",)
    assert str(application / "agent/AGENTS.md") in (engagement / "AGENTS.md").read_text()


def test_start_refreshes_only_selected_generated_entrypoints_for_current_release(layout, monkeypatch):
    application, workspace = layout
    copied_agent = workspace / "agent"
    copied_agent.mkdir()
    (copied_agent / "operator-core-code.md").write_text("old copied prompt\n")
    engagement = copied_agent / "engagements/acme"
    other = copied_agent / "engagements/other"
    for directory in (engagement, other):
        directory.mkdir(parents=True)
        (directory / "scope.json").write_text(json.dumps({"engagement_type": "code", "current_phase": "hunt"}))
        engagements._write_prompt_wrappers(copied_agent, directory, "codex", engagement_type="code")
        engagements._write_launchers(copied_agent, directory, "codex", skip_permissions=False)
    original_other = (other / "start_codex.sh").read_bytes(), (other / "AGENTS.md").read_bytes()
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    launched = []
    monkeypatch.setattr(engagements.os, "execv", lambda *args: launched.append(args))

    engagements.start_engagement(workspace, engagement, "codex", [])

    assert launched
    from vigil_cli.client_sessions import historical_client_starts
    starts, _ = historical_client_starts(workspace)
    assert any(row.get("event") == "launch_requested" and row["client"] == "codex" for row in starts)
    assert str(application / "agent/operator-core-code.md") in (engagement / "AGENTS.md").read_text()
    assert f"VIGIL_INSTALL_DIR={workspace}" in (engagement / "start_codex.sh").read_text()
    assert f"VIGIL_APPLICATION_DIR={application}" in (engagement / "start_codex.sh").read_text()
    assert original_other == ((other / "start_codex.sh").read_bytes(), (other / "AGENTS.md").read_bytes())


def test_start_refuses_cross_release_refresh_while_original_session_is_alive(layout, monkeypatch):
    application, workspace = layout
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "code", "current_phase": "hunt"}))
    engagements._write_prompt_wrappers(application / "agent", engagement, "codex", engagement_type="code", workspace_root=workspace)
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False, workspace_root=workspace)
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *_: None)
    engagements.start_engagement(workspace, engagement, "codex", [])
    original = (engagement / "start_codex.sh").read_bytes(), (engagement / "AGENTS.md").read_bytes()
    next_application = application.parent / "application-next"
    (next_application / "orchestrator").mkdir(parents=True)
    (next_application / "agent").mkdir()
    (next_application / "agent/operator-core-code.md").write_text("new release prompt\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(next_application))

    with pytest.raises(SystemExit, match="active.*release|end.*session"):
        engagements.start_engagement(workspace, engagement, "codex", [])

    assert original == ((engagement / "start_codex.sh").read_bytes(), (engagement / "AGENTS.md").read_bytes())


def test_opencode_rejected_upgrade_start_preserves_active_session_config(layout, monkeypatch):
    from vigil_cli import main as main_module
    from vigil_cli import assessment_clients, client_sessions

    application, workspace = layout
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "code", "current_phase": "hunt"}))
    engagements._write_prompt_wrappers(application / "agent", engagement, "codex", engagement_type="code", workspace_root=workspace)
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False, workspace_root=workspace)
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *_: None)
    (engagement / "opencode.json").write_text('{"model":"operator-selected-model","compaction":{"auto":true}}\n')
    client_sessions.record_client_session(workspace, engagement, "opencode", "code")
    original = (engagement / "opencode.json").read_bytes()
    next_application = application.parent / "application-next"
    (next_application / "orchestrator").mkdir(parents=True)
    (next_application / "agent").mkdir()
    (next_application / "agent/operator-core-code.md").write_text("next release\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(next_application))
    monkeypatch.setattr(assessment_clients.shutil, "which", lambda *_: "/usr/bin/client")
    native_run = assessment_clients.subprocess.run
    monkeypatch.setattr(assessment_clients.subprocess, "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "1.19.3\n", "")
        if argv[0] == "/usr/bin/client" else native_run(argv, **kwargs))
    monkeypatch.setattr(assessment_clients, "prepare_workspace",
        lambda *a, **kw: pytest.fail("Cross-release retention must be checked before preparing workspace files"))

    with pytest.raises(SystemExit, match="active.*release|end.*session"):
        main_module.main(["--root", str(workspace), "engagement", "start", "acme", "--client", "opencode", "--thinking", "max", "--skip-preflight"])

    assert (engagement / "opencode.json").read_bytes() == original


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_official_start_preserves_operator_settings_and_custom_hooks(layout, monkeypatch, client):
    application, workspace = layout
    agent = application / "agent"
    (agent / ".codex").mkdir()
    (agent / ".codex/config.toml").write_text('model = "canonical-model"\n[[hooks.SessionEnd]]\n[[hooks.SessionEnd.hooks]]\ntype = "command"\ncommand = "bash scripts/hooks/session-end.sh"\n')
    (agent / ".claude").mkdir()
    (agent / ".claude/settings.json").write_text(json.dumps({"hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": "bash scripts/hooks/session-end.sh"}]}]}}))
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "code", "current_phase": "hunt"}))
    engagements._write_prompt_wrappers(agent, engagement, "both", engagement_type="code", workspace_root=workspace)
    engagements._write_launchers(agent, engagement, "both", skip_permissions=False, workspace_root=workspace)
    (engagement / ".codex").mkdir()
    original_codex = '# operator comment\nmodel = "operator-model"\n[mcp_servers.acme]\ncommand = "acme-mcp"\n[[hooks.SessionEnd]]\n[[hooks.SessionEnd.hooks]]\ntype = "command"\ncommand = "bash /old/application/agent/scripts/hooks/session-end.sh"\n[[hooks.SessionEnd.hooks]]\ntype = "command"\ncommand = "acme-custom-hook"\n'
    (engagement / ".codex/config.toml").write_text(original_codex)
    (engagement / ".claude").mkdir()
    (engagement / ".claude/settings.json").write_text(json.dumps({"model": "operator-model", "env": {"ACME_SETTING": "retain"}, "hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": "bash /old/application/agent/scripts/hooks/session-end.sh"}, {"type": "command", "command": "acme-custom-hook"}]}]}}))
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *_: None)

    engagements.start_engagement(workspace, engagement, client, [])

    codex_text = (engagement / ".codex/config.toml").read_text()
    codex_config = tomllib.loads(codex_text)
    assert codex_config["model"] == "operator-model"
    assert codex_config["mcp_servers"]["acme"]["command"] == "acme-mcp"
    assert "# operator comment" in codex_text
    assert "acme-custom-hook" in codex_text
    assert str(agent / "scripts/hooks/session-end.sh") in codex_text
    claude_config = json.loads((engagement / ".claude/settings.json").read_text())
    assert claude_config["model"] == "operator-model"
    assert claude_config["env"]["ACME_SETTING"] == "retain"
    commands = [hook["command"] for entry in claude_config["hooks"]["SessionEnd"] for hook in entry["hooks"]]
    assert "acme-custom-hook" in commands
    assert f"bash {agent}/scripts/hooks/session-end.sh" in commands


@pytest.mark.parametrize("cli_directory", ["cli", "src"])
def test_goose_launcher_uses_release_proxy_not_obsolete_workspace_code(layout, monkeypatch, cli_directory):
    from vigil_cli import application as application_module

    application, workspace = layout
    helper_bin = application / "bin"
    helper_bin.mkdir()
    helper = helper_bin / "vigil"
    helper.write_text("#!/bin/sh\nprintf 'http://backend.example\\n'\n")
    helper.chmod(0o755)
    proxy = application / cli_directory / "vigil_cli/goose_reasoning_proxy.py"
    proxy.parent.mkdir(parents=True)
    proxy.write_text('print("LISTENING http://127.0.0.1:19999", flush=True)\n')
    stale = workspace / "src/vigil_cli/goose_reasoning_proxy.py"
    stale.parent.mkdir(parents=True)
    stale.write_text('print("LISTENING http://127.0.0.1:18888", flush=True)\n')
    client_bin = workspace / "bin"
    client_bin.mkdir()
    client = client_bin / "goose"
    client.write_text('#!/bin/sh\nprintf "%s\\n" "$OPENAI_HOST"\n')
    client.chmod(0o755)
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    monkeypatch.setattr(application_module, "session_cli_directory", lambda *_: helper_bin)
    monkeypatch.setenv("PATH", f"{client_bin}:/usr/bin:/bin:/usr/local/bin")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-test-key")
    monkeypatch.delenv("VIGIL_GOOSE_REASONING_PROXY", raising=False)
    engagements._write_launchers(application / "agent", engagement, "codex", skip_permissions=False, workspace_root=workspace)

    result = subprocess.run([str(engagement / "start_goose.sh")], text=True, capture_output=True, check=False)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "http://127.0.0.1:19999"


@pytest.mark.parametrize("custom_hints", [False, True])
def test_upgrade_start_rebinds_goose_prompt_with_matching_router_and_retains_additions(layout, monkeypatch, custom_hints):
    application, workspace = layout
    old_agent = workspace / "agent"
    old_agent.mkdir()
    (old_agent / "operator-core-code.md").write_text("obsolete copied code prompt\n")
    engagement = old_agent / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "code", "current_phase": "hunt"}))
    engagements._write_prompt_wrappers(old_agent, engagement, "codex", engagement_type="code", workspace_root=workspace)
    engagements._write_launchers(old_agent, engagement, "codex", skip_permissions=False, workspace_root=workspace)
    engagements._write_goose_config(old_agent, engagement)
    if custom_hints:
        with (engagement / ".goosehints").open("a") as document:
            document.write("\n## Acme operator addition\nRetain this exact custom content.\n")
    monkeypatch.setattr(engagements.os, "chdir", lambda *_: None)
    monkeypatch.setattr(engagements.os, "execv", lambda *_: None)

    engagements.start_engagement(workspace, engagement, "goose", [])

    router = (engagement / "AGENTS.md").read_text()
    hints = (engagement / ".goosehints").read_text()
    assert str(application / "agent/operator-core-code.md") in router
    assert hints.startswith(router)
    assert str(old_agent / "operator-core-code.md") not in hints
    assert f"VIGIL_APPLICATION_DIR={application}" in (engagement / "start_goose.sh").read_text()
    if custom_hints:
        assert hints.endswith("\n## Acme operator addition\nRetain this exact custom content.\n")


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_start_config_refresh_preserves_custom_arguments_and_pipelines(layout, client):
    from vigil_cli import client_rosters

    application, workspace = layout
    agent = application / "agent"
    custom_command = "bash /old/application/agent/scripts/hooks/session-end.sh --acme-option | acme-notify"
    source_dir = agent / f".{client}"
    source_dir.mkdir()
    destination = workspace / "engagements/acme" / f".{client}"
    destination.mkdir(parents=True)
    if client == "codex":
        (source_dir / "config.toml").write_text('[[hooks.SessionEnd]]\n[[hooks.SessionEnd.hooks]]\ntype = "command"\ncommand = "bash scripts/hooks/session-end.sh"\n')
        config_path = destination / "config.toml"
        config_path.write_text('[[hooks.SessionEnd]]\n[[hooks.SessionEnd.hooks]]\ntype = "command"\ncommand = ' + json.dumps(custom_command) + '\n')
        client_rosters.ensure_codex_config(agent, destination, preserve_existing=True)
        assert tomllib.loads(config_path.read_text())["hooks"]["SessionEnd"][0]["hooks"][0]["command"] == custom_command
    else:
        (source_dir / "settings.json").write_text(json.dumps({"hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": "bash scripts/hooks/session-end.sh"}]}]}}))
        config_path = destination / "settings.json"
        config_path.write_text(json.dumps({"hooks": {"SessionEnd": [{"hooks": [{"type": "command", "command": custom_command}]}]}}))
        client_rosters.ensure_claude_settings(agent, destination, preserve_existing=True)
        assert json.loads(config_path.read_text())["hooks"]["SessionEnd"][0]["hooks"][0]["command"] == custom_command


def test_start_config_refresh_preserves_operator_authored_compact_prompt(layout, monkeypatch):
    from vigil_cli import client_rosters

    application, workspace = layout
    source_dir = application / "agent/.codex"
    source_dir.mkdir()
    (source_dir / "config.toml").write_text('compact_prompt = "__VIGIL_RENDER_COMPACT_PROMPT__"\n')
    codex_dir = workspace / "engagements/acme/.codex"
    codex_dir.mkdir(parents=True)
    config_path = codex_dir / "config.toml"
    original = 'compact_prompt = "Acme custom compaction instructions"\n# operator annotation\n'
    config_path.write_text(original)
    monkeypatch.setattr(client_rosters, "_render_codex_compact_prompt", lambda *_, **__: "canonical compaction instructions")

    client_rosters.ensure_codex_config(application / "agent", codex_dir, preserve_existing=True)

    assert config_path.read_text() == original
