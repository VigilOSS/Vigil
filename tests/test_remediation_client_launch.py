from __future__ import annotations

import argparse
import json
import os
import plistlib
import shlex
import shutil
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_cli import install_fs
from vigil_cli import remediation_sessions as sessions
from vigil_cli.client_sessions import historical_client_starts
from vigil_cli.remediation import register_remediation_parser
from vigil_cli.remediation_clients import _prepare_zcode_plugin


@pytest.fixture
def launch(tmp_path, monkeypatch):
    # System applications are not fixtures; exercise only each test's temporary app.
    actual_is_file = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda path: False if str(path) ==
        '/Applications/ZCode.app/Contents/Info.plist' else actual_is_file(path))

    root = tmp_path / "release"
    (root / "orchestrator").mkdir(parents=True)
    for client in ("opencode", "zcode"):
        command = root / f"agent/.{client}/commands/vigil-remediate.md"
        command.parent.mkdir(parents=True)
        command.write_text("---\ndescription: Defensive remediation\n---\nRead the profile. $ARGUMENTS\n")
    plugin = root / "agent/.zcode/.zcode-plugin/plugin.json"
    plugin.parent.mkdir()
    plugin.write_text('{"name":"vigil-remediation"}')
    (root / "agent/.zcode/marketplace.json").write_text('{"plugins":[]}')
    (root / "agent/.zcode/hooks").mkdir()
    (root / "agent/.zcode/hooks/hooks.json").write_text('{}')
    (root / "agent/.zcode/hooks/remediation-context.mjs").write_text("// context hook\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(root))
    repository = tmp_path / "Acme $(touch marker); repository"
    repository.mkdir()
    engagement = tmp_path / "engagement"
    project = {"repository": str(repository), "_profile_path": str(repository / "PROJECT.md"),
               "remediation": {"hook_policy": "inherit"}}
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        output = "opencode v2.3.0" if argv == ["opencode", "--version"] else "--prompt text"
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(sessions.subprocess, "run", run)
    # Remediation finds the installed client by name before probing it.
    original_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda name, *args, **kwargs:
                        "/native/opencode" if name == "opencode" else original_which(name, *args, **kwargs))
    return SimpleNamespace(root=root, engagement=engagement, repository=repository,
                           project=project, calls=calls, sessions=sessions)


def start(launch, client, **options):
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client=client,
                              session_id=None)
    for key, value in options.items():
        setattr(args, key, value)
    return launch.sessions.run_session_command(args, launch.root, launch.engagement, launch.project)


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_parser_accepts_repository_context_clients(client):
    parser = argparse.ArgumentParser()
    register_remediation_parser(parser.add_subparsers(dest="command"))
    assert parser.parse_args(["remediation", "-k", "acme", "start", "--client", client]).client == client


def test_opencode_starts_native_tui_with_release_command_and_preserves_configuration(launch, monkeypatch):
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", json.dumps({"model": "zai-coding-plan/selected", "permission": "ask"}))
    assert start(launch, "opencode") == 0
    argv, options = launch.calls[-1]
    assert argv[:3] == ["opencode", "--standalone", "--prompt"]
    assert options["cwd"] == launch.repository
    config = json.loads(options["env"]["OPENCODE_CONFIG_CONTENT"])
    assert config["model"] == "zai-coding-plan/selected"
    assert config["permission"] == "ask"
    assert config["command"]["vigil-remediate"]["template"] == "Read the profile. $ARGUMENTS\n"
    assert options["env"]["VIGIL_CLIENT_NAME"] == "opencode"
    # An update prompt over the TUI would take the next keystroke as consent to upgrade.
    assert options["env"]["OPENCODE_DISABLE_AUTOUPDATE"] == "1"
    starts, _ = historical_client_starts(launch.root)
    assert [(row["client"], row["mode"], row["event"]) for row in starts] == [("opencode", "remediation", "launch_requested")]
    assert str(launch.project["_profile_path"]) in argv[3]
    assert list(launch.repository.iterdir()) == []
    assert not launch.engagement.exists()


@pytest.mark.parametrize("version", ["opencode v2.3.0\n", "2.3.0\n"])
def test_opencode_2_runs_its_own_server_so_the_remediation_command_applies(launch, monkeypatch, version):
    # A background service would not see this launch's OPENCODE_CONFIG_CONTENT,
    # so the /vigil-remediate command exists only in a standalone session.
    def run(argv, **options):
        launch.calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, version if argv[-1] == "--version" else "  --prompt string", "")

    monkeypatch.setattr(launch.sessions.subprocess, "run", run)
    assert start(launch, "opencode") == 0
    argv, options = launch.calls[-1]
    assert argv[:3] == ["opencode", "--standalone", "--prompt"]
    assert str(launch.project["_profile_path"]) in argv[3]
    config = json.loads(options["env"]["OPENCODE_CONFIG_CONTENT"])
    assert config["command"]["vigil-remediate"]["template"] == "Read the profile. $ARGUMENTS\n"


def test_opencode_keeps_repository_claude_context_discoverable(launch, monkeypatch):
    # OpenCode's Claude Code switches also skip the repository's own CLAUDE.md and
    # .claude/skills, so remediation leaves that compatibility as the owner set it.
    for name in ("OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT",
                 "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"):
        monkeypatch.delenv(name, raising=False)
    assert start(launch, "opencode") == 0
    environment = launch.calls[-1][1]["env"]
    assert not {"OPENCODE_DISABLE_CLAUDE_CODE", "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT",
                "OPENCODE_DISABLE_CLAUDE_CODE_SKILLS"} & set(environment)


def test_opencode_accepts_help_written_to_stderr(launch, monkeypatch):
    def run(argv, **options):
        launch.calls.append((argv, options))
        if argv == ["opencode", "--version"]:
            return subprocess.CompletedProcess(argv, 0, "opencode v2.3.0\n", "")
        if argv == ["opencode", "--help"]:
            return subprocess.CompletedProcess(argv, 0, "", "Options:\n  --prompt  prompt to use\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(launch.sessions.subprocess, "run", run)
    assert start(launch, "opencode") == 0
    assert launch.calls[-1][0][:3] == ["opencode", "--standalone", "--prompt"]


@pytest.mark.parametrize("client", ["opencode", "zcode"])
@pytest.mark.parametrize("option,value,message", [
    ("session_id", "existing", "--session-id"),
    ("hook_policy", "disabled", "hook_policy"),
])
def test_unsupported_session_policy_fails_before_probe_or_mutation(launch, client, option, value, message):
    options = {}
    if option == "hook_policy":
        launch.project["remediation"][option] = value
    else:
        options[option] = value
    with pytest.raises(SystemExit, match=message):
        start(launch, client, **options)
    assert launch.calls == []
    assert not launch.engagement.exists()


@pytest.mark.parametrize("version,help_output", [("0.9.0", "--prompt text"), ("1.18.10", "--prompt text"),
                                                  ("opencode v2.2.0", "--prompt text"),
                                                  ("opencode v3.0.0", "--prompt text"),
                                                  ("opencode v2.3.0", "--model text")])
def test_opencode_refuses_an_unsupported_release_or_missing_prompt_before_launch(launch, monkeypatch, version, help_output):
    def run(argv, **options):
        launch.calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, version if argv[-1] == "--version" else help_output, "")
    monkeypatch.setattr(launch.sessions.subprocess, "run", run)
    with pytest.raises(SystemExit, match="OpenCode"):
        start(launch, "opencode")
    assert all(argv[-1] in ("--version", "--help") for argv, _ in launch.calls)
    assert not launch.engagement.exists()


@pytest.mark.parametrize("version", ["opencode v2.3", "opencode 2.3.0 (update 2.4.0 available)", ""])
def test_opencode_with_an_unreadable_version_starts_with_the_supported_flags(launch, monkeypatch, version):
    def run(argv, **options):
        launch.calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, version if argv[-1] == "--version" else "--prompt text", "")
    monkeypatch.setattr(launch.sessions.subprocess, "run", run)
    assert start(launch, "opencode") == 0
    assert launch.calls[-1][0][:3] == ["opencode", "--standalone", "--prompt"]


def test_missing_opencode_reports_installation_requirement(launch, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: None)
    with pytest.raises(SystemExit, match="OpenCode CLI is required"):
        start(launch, "opencode")
    assert launch.calls == []


@pytest.mark.parametrize("probe", [["opencode", "--version"], ["opencode", "--help"]])
def test_opencode_probe_timeout_is_bounded(launch, monkeypatch, probe):
    """A timed-out --version is an unreadable version, which proceeds as every
    start does; the --help probe is the capability check, so its timeout refuses."""
    def timeout(argv, **kwargs):
        launch.calls.append((argv, kwargs))
        if argv == probe:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "opencode v2.3.0" if argv[-1] == "--version" else "--prompt text", "")

    monkeypatch.setattr(launch.sessions.subprocess, "run", timeout)
    if probe[-1] == "--help":
        with pytest.raises(SystemExit, match="timed out"):
            start(launch, "opencode")
    else:
        assert start(launch, "opencode") == 0
    assert all(options.get("timeout") is not None for argv, options in launch.calls if argv[-1] in ("--version", "--help"))


def test_zcode_prepares_context_plugin_and_opens_repository_without_false_session_receipt(launch, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "platform", "darwin")
    app = tmp_path / "Applications/ZCode.app"
    info = app / "Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.1"}))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert start(launch, "zcode") == 0
    argv, options = launch.calls[-1]
    assert argv == ["open", "-a", str(app), str(launch.repository)]
    starts, _ = historical_client_starts(launch.root)
    assert [(row["client"], row["event"]) for row in starts] == [("zcode", "workspace_opened")]
    assert options["cwd"] == launch.repository
    context_paths = list(launch.engagement.glob("remediation/client-context/*/zcode/vigil-context.json"))
    assert len(context_paths) == 1
    context = json.loads(context_paths[0].read_text())
    assert context["repository"] == str(launch.repository)
    assert context["engagement_key"] == "acme"
    assert context["agent_root"] == str(launch.root / "agent")
    assert not (launch.engagement / "remediation/sessions").exists()
    assert list(launch.repository.iterdir()) == []
    assert "enable" in capsys.readouterr().out.lower()


def test_zcode_missing_app_fails_without_preparing_plugin(launch, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(SystemExit, match="ZCode"):
        start(launch, "zcode")
    assert not launch.engagement.exists()


def test_zcode_node_probe_timeout_is_actionable_and_bounded(launch, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    app = tmp_path / "Applications/ZCode.app"
    info = app / "Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.1"}))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    def timeout(argv, **kwargs):
        launch.calls.append((argv, kwargs))
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

    monkeypatch.setattr(launch.sessions.subprocess, "run", timeout)
    with pytest.raises(SystemExit, match="timed out"):
        start(launch, "zcode")
    assert launch.calls[0][1].get("timeout") is not None
    assert not launch.engagement.exists()


@pytest.mark.parametrize("configuration", ['[]', '{"command": []}', '{'])
def test_opencode_invalid_runtime_configuration_fails_without_launch(launch, monkeypatch, configuration):
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", configuration)
    with pytest.raises(SystemExit, match="OPENCODE_CONFIG_CONTENT"):
        start(launch, "opencode")
    assert all(argv[-1] in ("--version", "--help") for argv, _ in launch.calls)


def test_opencode_runtime_command_collision_preserves_owner_configuration(launch, monkeypatch):
    configuration = '{"command":{"vigil-remediate":{"template":"owner command"}}}'
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", configuration)
    with pytest.raises(SystemExit, match="collision"):
        start(launch, "opencode")
    assert launch.sessions.os.environ["OPENCODE_CONFIG_CONTENT"] == configuration


def test_zcode_invalid_metadata_is_actionable_not_an_uncaught_exception(launch, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    info = tmp_path / "Applications/ZCode.app/Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps(["invalid metadata"]))
    with pytest.raises(SystemExit, match="metadata"):
        start(launch, "zcode")
    assert launch.calls == []


def test_zcode_preparation_refuses_symlinked_remediation_directory(launch, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    info = tmp_path / "Applications/ZCode.app/Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.1"}))
    outside = tmp_path / "outside"
    outside.mkdir()
    launch.engagement.mkdir()
    (launch.engagement / "remediation").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SystemExit, match="safely prepare"):
        start(launch, "zcode")
    assert list(outside.iterdir()) == []
    assert [argv for argv, _ in launch.calls] == [["node", "--version"]]


def test_route_exposes_actual_client_capability_limits(launch):
    result = launch.sessions.route_context(launch.root, launch.engagement, launch.project, ["ACME-123"])
    assert result.get("session_capabilities") == {
        "claude": {"native_binding": True, "exact_join": True, "background_launch": True},
        "opencode": {"native_binding": False, "exact_join": False, "background_launch": False},
        "zcode": {"native_binding": False, "exact_join": False, "background_launch": False},
    }


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_route_rejects_unsupported_coordinator_before_pending_mutation(launch, client):
    args = argparse.Namespace(remediation_command="route", client=client, references=["ACME-123", "ACME-124"], engagement_key="acme")
    with pytest.raises(SystemExit, match="one case"):
        launch.sessions.run_session_command(args, launch.root, launch.engagement, launch.project)
    assert not launch.engagement.exists()


def test_prepared_plugins_have_distinct_context_bound_native_identity(launch):
    first = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    second = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme-other", install_root=launch.root)
    first_name = json.loads((first / ".zcode-plugin/plugin.json").read_text())["name"]
    second_name = json.loads((second / ".zcode-plugin/plugin.json").read_text())["name"]
    assert first_name != second_name
    for plugin, name in ((first, first_name), (second, second_name)):
        assert json.loads((plugin / "marketplace.json").read_text())["plugins"][0]["name"] == name


def test_prepared_plugin_rejects_nonregular_collision_before_reading(launch, monkeypatch):
    root = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    target = root / "vigil-context.json"
    target.unlink()
    os.mkfifo(target)
    real_open = os.open
    def checked_open(path, flags, *args, **kwargs):
        if str(path) == target.name and not (flags & os.O_CREAT):
            assert flags & os.O_NONBLOCK, "Existing plugin entry can block before file-type validation"
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", checked_open)
    real_fdopen = os.fdopen
    def fdopen(descriptor, *args, **kwargs):
        assert stat.S_ISREG(os.fstat(descriptor).st_mode), "Nonregular collision reached potentially blocking read"
        return real_fdopen(descriptor, *args, **kwargs)
    monkeypatch.setattr(os, "fdopen", fdopen)
    with pytest.raises(SystemExit, match="collision"):
        _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)


def test_concurrent_plugin_preparation_publishes_same_complete_context(launch):
    def prepare(_):
        return _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    with ThreadPoolExecutor(max_workers=8) as executor:
        roots = list(executor.map(prepare, range(16)))
    assert len(set(roots)) == 1
    assert json.loads((roots[0] / "vigil-context.json").read_text())["engagement_key"] == "acme"


def test_interrupted_plugin_preparation_can_retry_without_partial_published_file(launch, monkeypatch):
    original_write = install_fs.os.write
    calls = 0
    def interrupted(descriptor, data):
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(descriptor, data[:3])
        raise OSError("simulated interrupted write")
    monkeypatch.setattr(install_fs.os, "write", interrupted)
    with pytest.raises(SystemExit, match="safely prepare"):
        _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    monkeypatch.setattr(install_fs.os, "write", original_write)
    root = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    assert json.loads((root / ".zcode-plugin/plugin.json").read_text())["name"].startswith("vigil-remediation-")


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_plugin_collision_preserves_operator_data(launch, tmp_path, kind):
    root = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    target = root / "vigil-context.json"
    operator = tmp_path / "owner-context.json"
    operator.write_text("owner context")
    if kind == "file":
        target.write_text("owner context")
    else:
        target.unlink()
        target.symlink_to(operator)
    with pytest.raises(SystemExit, match="collision|safely prepare"):
        _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    assert target.read_text() == "owner context"
    assert operator.read_text() == "owner context"


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_route_selects_actual_client_and_deduplicates_same_case(launch, client):
    parser = argparse.ArgumentParser()
    launch.sessions.register_session_parsers(parser.add_subparsers(dest="remediation_command"))
    args = parser.parse_args(["route", "--client", client, "ACME-123", "https://tracker.example.com/browse/ACME-123"])
    result = launch.sessions.route_context(launch.root, launch.engagement, launch.project, args.references, client=args.client)
    assert result["client"] == client
    assert result["role"] == "developer"
    assert result["session_capabilities"][client] == {"native_binding": False, "exact_join": False, "background_launch": False}


@pytest.mark.parametrize("version", ["3.6.4", "3.14.2", "2.99.0", "4.0.0"])
def test_zcode_refuses_unsupported_release_before_node_probe_or_plugin_preparation(launch, monkeypatch, tmp_path, version):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    info = tmp_path / "Applications/ZCode.app/Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": version}))
    with pytest.raises(SystemExit, match="ZCode 3.14.3"):
        start(launch, "zcode")
    assert launch.calls == []
    assert not launch.engagement.exists()


def test_zcode_nondefault_private_root_is_explicit_in_context_and_bootstrap(launch, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    info = tmp_path / "Applications/ZCode.app/Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.1"}))
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(tmp_path / "stale GUI root"))
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="zcode", session_id=None)
    root = tmp_path / "private root's $(marker)"
    assert launch.sessions.run_session_command(args, root, launch.engagement, launch.project) == 0
    context = json.loads(next(launch.engagement.glob("remediation/client-context/*/zcode/vigil-context.json")).read_text())
    assert context.get("install_root") == str(root)
    output = capsys.readouterr().out
    assert f"vigil --root {shlex.quote(str(root))} remediation -k acme route --client zcode" in output


def test_plugin_lock_creation_lookup_race_retries_on_attached_directory(launch, monkeypatch):
    original_open = os.open
    injected = False
    def open_with_race(path, flags, *args, **kwargs):
        nonlocal injected
        if path == ".prepare.lock" and flags & os.O_CREAT and not injected:
            injected = True
            raise FileNotFoundError("simulated lock creation lookup race")
        return original_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", open_with_race)
    root = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    assert json.loads((root / "vigil-context.json").read_text())["engagement_key"] == "acme"
    assert injected
