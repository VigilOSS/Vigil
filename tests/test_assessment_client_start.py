"""Native client starts prepare a bounded workspace without a false GUI receipt."""
from contextlib import nullcontext
import json
from pathlib import Path
import re
import shlex
from types import SimpleNamespace

import pytest

from vigil_cli import engagements
from vigil_cli import main as cli
from vigil_cli import client_sessions

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_BOOTSTRAP = client_sessions.client_session_bootstrap


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(ROOT))
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    root = tmp_path / "private"
    engagement = root / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"status": "in_progress",
        "engagement_type": "offensive", "tracks": {"web": {"phase": "recon"},
        "code": {"phase": "ingest"}}}))
    monkeypatch.setattr(client_sessions, "client_session_bootstrap", lambda *_, **_kw: nullcontext())
    receipts = []
    monkeypatch.setattr(client_sessions, "record_client_session", lambda *args: receipts.append(args))
    monkeypatch.setattr(engagements, "repair_engagement_client_entrypoints",
        lambda *args, **kwargs: SimpleNamespace(reconciled=()))
    monkeypatch.setattr(engagements, "set_active_engagement", lambda *_: None)
    return root, engagement, receipts


def test_zcode_start_cli_accepts_the_native_client_without_backend_work(context, monkeypatch):
    root, engagement, _ = context
    monkeypatch.setattr(cli, "_resolve_current_or_selected_engagement", lambda *a, **kw: engagement)
    calls = []
    monkeypatch.setattr(cli, "start_engagement", lambda *a, **kw: calls.append((a, kw)))
    outcome = 0
    try:
        cli.main(["--root", str(root), "engagement", "start", "acme", "--client", "zcode",
                  "--mode", "code", "--skip-preflight"])
    except SystemExit as exc:
        outcome = exc.code
    assert outcome == 0
    assert calls[0][0][2] == "zcode"


def test_zcode_start_prepares_two_mode_bound_workspaces_and_no_pid_receipt(context, monkeypatch):
    root, engagement, receipts = context
    from vigil_cli import remediation_clients
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda: (Path("/Applications/ZCode.app"), "3.15.3"))
    calls = []
    monkeypatch.setattr(engagements.subprocess, "run", lambda *a, **kw: calls.append((a, kw)) or SimpleNamespace(returncode=0))
    outcome = None
    try:
        engagements.start_engagement(root, engagement, "zcode", [], "code")
        engagements.start_engagement(root, engagement, "zcode", [], "web")
    except SystemExit as exc:
        outcome = str(exc)
    assert outcome is None, outcome
    workspaces = [Path(call[0][0][-1]) for call in calls]
    assert len(set(workspaces)) == 2
    assert receipts == []
    history, _ = client_sessions.historical_client_starts(root)
    assert [(row["client"], row["mode"], row["event"]) for row in sorted(history, key=lambda row: row["started_at"])] == [
        ("zcode", "code", "workspace_opened"), ("zcode", "web", "workspace_opened")]
    for workspace, mode in zip(workspaces, ("code", "web")):
        selected = json.loads((workspace / ".vigil-current-context.json").read_text())
        binding = json.loads(Path(selected["binding_path"]).read_text())
        assert binding["mode"] == mode
        assert binding["engagement_dir"] == str(engagement)
        assert Path(binding["vigil_cli"]).is_file()
        assert (workspace / "AGENTS.md").read_text().startswith(engagements._SPECIALIST_STOP_SIGN)


def test_zcode_project_address_is_stable_when_native_build_changes(context, monkeypatch):
    from vigil_cli import remediation_clients
    root, engagement, _ = context
    versions = iter(("3.15.3", "3.16.0"))
    monkeypatch.setattr(remediation_clients, "_zcode_application",
                        lambda: (Path("/Applications/ZCode.app"), next(versions)))
    opened = []
    monkeypatch.setattr(engagements.subprocess, "run", lambda argv, **_:
                        opened.append(Path(argv[-1])) or SimpleNamespace(returncode=0))
    engagements.start_engagement(root, engagement, "zcode", [], "code")
    engagements.start_engagement(root, engagement, "zcode", [], "code")
    assert opened == [engagement / "clients/zcode/code"] * 2
    assert len(list((engagement / "client-context").glob("*/zcode"))) == 2


def test_native_project_start_does_not_rebind_shared_client_files(context, monkeypatch):
    from vigil_cli import remediation_clients
    root, engagement, _ = context
    monkeypatch.setattr(client_sessions, "client_session_bootstrap", ORIGINAL_BOOTSTRAP)
    def shared_guard(*_):
        raise SystemExit("Shared files are in use by another release")
    monkeypatch.setattr(client_sessions, "guard_client_session_upgrade", shared_guard)
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda:
                        (Path("/Applications/ZCode.app"), "3.15.3"))
    monkeypatch.setattr(engagements.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    outcome = None
    try:
        engagements.start_engagement(root, engagement, "zcode", [], "code")
    except SystemExit as exc:
        outcome = str(exc)
    assert outcome is None
    assert (engagement / "clients/zcode/code/AGENTS.md").is_file()


def test_zcode_refuses_unsupported_mode_before_preparing_context(context):
    root, engagement, _ = context
    (engagement / "scope.json").write_text('{"engagement_type":"blue","status":"in_progress"}')
    with pytest.raises(SystemExit, match="web|code"):
        engagements.start_engagement(root, engagement, "zcode", [], "blue")


@pytest.mark.parametrize("terminal", [True, False])
def test_zcode_launch_separates_setup_paths_and_copyable_prompt(context, monkeypatch, capsys, terminal):
    from vigil_cli import remediation_clients, term

    root, engagement, _ = context
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(term, "is_terminal", lambda _stream: terminal)
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda: (Path("/Applications/ZCode.app"), "3.15.3"))
    opened = []
    monkeypatch.setattr(engagements.subprocess, "run", lambda argv, **_kwargs:
                        opened.append(argv) or SimpleNamespace(returncode=0))
    engagements.start_engagement(root, engagement, "zcode", ["Investigate Acme"], "code")
    output = capsys.readouterr().out
    workspace = Path(opened[0][-1])
    assert "Plugin setup" in output
    assert output.count(str(workspace)) == 1
    assert "<PATH>/plugin/marketplace.json" in output
    plugin = json.loads((workspace / "plugin/.zcode-plugin/plugin.json").read_text())
    assert plugin["name"] in output
    prompt = output.split("Paste into a new task\n\n", 1)[1].strip()
    assert engagements.SOURCE_TRUST_CONFIRMATION in prompt
    assert json.dumps(str(engagement / "source")) in prompt
    assert "Investigate Acme" in prompt
    assert "\n\n" in prompt
    if terminal:
        assert "Continue in ZCode" in output
        assert str(workspace) in [line.strip() for line in output.splitlines()]
    else:
        assert f"workspace: {workspace}\nengagement: acme\nclient: zcode\nmode: code\n" in output


def test_zcode_no_autoprompt_still_explains_how_to_begin(context, monkeypatch, capsys):
    from vigil_cli import remediation_clients

    root, engagement, _ = context
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda: (Path("/Applications/ZCode.app"), "3.15.3"))
    monkeypatch.setattr(engagements.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    engagements.start_engagement(root, engagement, "zcode", [], "web", no_autoprompt=True)
    assert "Start a new task in this project and follow AGENTS.md." in capsys.readouterr().out


def test_zcode_opening_prompt_resolves_its_project_instructions_and_helper(context, monkeypatch, capsys):
    from vigil_cli import remediation_clients

    root, engagement, _ = context
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda: (Path("/Applications/ZCode.app"), "3.15.3"))
    opened = []
    monkeypatch.setattr(engagements.subprocess, "run", lambda argv, **_kwargs:
                        opened.append(argv) or SimpleNamespace(returncode=0))
    engagements.start_engagement(root, engagement, "zcode", [], "code")
    workspace = Path(opened[0][-1])
    output = capsys.readouterr().out
    prompt = output.split("Paste into a new task\n\n", 1)[1].strip()
    assert "./AGENTS.md" in prompt
    assert "./bin/vigil engagement client-check" in prompt
    assert "./.vigil-client-project.json" in prompt
    assert "acme" in prompt and "code" in prompt and "ZCode" in prompt
    assert (workspace / "AGENTS.md").is_file()
    assert (workspace / "bin/vigil").is_file()


@pytest.mark.parametrize("width", [60, 80, 100])
def test_zcode_start_has_compact_formatted_setup(context, monkeypatch, capsys, width):
    from vigil_cli import remediation_clients, term
    root, engagement, _ = context
    monkeypatch.setenv("COLUMNS", str(width))
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(term, "is_terminal", lambda _stream: True)
    monkeypatch.setattr(remediation_clients, "_zcode_application", lambda: (Path("/Applications/ZCode.app"), "3.15.3"))
    monkeypatch.setattr(engagements.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    engagements.start_engagement(root, engagement, "zcode", [], "code")
    output = capsys.readouterr().out
    setup = output.split("Paste into a new task\n\n", 1)[0]
    assert len(setup.splitlines()) <= 28
    assert "• Engagement" in setup
    assert "<PATH>" in setup


@pytest.mark.parametrize("client", ["zcode", "opencode"])
@pytest.mark.parametrize("mode", ["web", "code"])
def test_generated_router_shell_commands_preserve_helper_path_with_spaces(context, client, mode):
    from vigil_cli.assessment_clients import prepare_workspace

    root, engagement, _ = context
    spaced = root.with_name("Acme private workspace")
    root.rename(spaced)
    workspace, binding = prepare_workspace(spaced, spaced / "engagements" / engagement.name, client, mode)
    snippets = re.findall(r"`([^`\n]+)`", (workspace / "AGENTS.md").read_text())
    commands = [shlex.split(snippet) for snippet in snippets if " engagement " in snippet]
    assert commands
    for arguments in commands:
        assert arguments[0] == binding["vigil_cli"]
        assert arguments[1] == "engagement"


@pytest.mark.parametrize("arguments", [["investigate Acme"], ["--prompt", "investigate Acme"],
                                       ["--prompt=investigate Acme"]])
def test_opencode_start_merges_opening_and_user_focus_once(context, monkeypatch, arguments):
    from vigil_cli import assessment_clients as clients
    root, engagement, receipts = context
    original = clients.shutil.which
    monkeypatch.setattr(clients.shutil, "which", lambda name: "/native/opencode" if name == "opencode" else original(name))
    monkeypatch.setattr(clients.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="1.18.10", stderr=""))
    calls = []
    monkeypatch.chdir(ROOT)
    monkeypatch.setattr(clients.os, "execve", lambda path, argv, env: calls.append((path, argv, env)))
    engagements.start_engagement(root, engagement, "opencode", arguments, "web")
    _, argv, environment = calls[0]
    prompts = [argv[index + 1] for index, argument in enumerate(argv) if argument == "--prompt"]
    prompts.extend(argument.split("=", 1)[1] for argument in argv if argument.startswith("--prompt="))
    assert len(prompts) == 1
    assert "investigate Acme" in prompts[0]
    assert environment["VIGIL_OPERATOR_MODE"] == "web"
    workspace = Path(environment["VIGIL_CLIENT_CONTEXT"]).parent
    assert environment["OPENCODE_DISABLE_PROJECT_CONFIG"] == "1"
    assert environment["OPENCODE_CONFIG_DIR"] == str(workspace / ".opencode")
    configuration = json.loads((workspace / ".opencode/opencode.json").read_text())
    binding = json.loads((workspace / ".vigil-client-context.json").read_text())
    assert configuration["instructions"] == [str(Path(binding["project"]) / "AGENTS.md")]
    assert Path.cwd() == Path(binding["project"])
    assert receipts[0][2:] == ("opencode", "web")
    history, _ = client_sessions.historical_client_starts(root)
    assert [(row["client"], row["event"]) for row in history] == [("opencode", "launch_requested")]
