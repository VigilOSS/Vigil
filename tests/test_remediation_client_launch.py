from __future__ import annotations

import argparse
import json
import plistlib
import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture
def launch(tmp_path, monkeypatch):
    from vigil_cli import remediation_sessions as sessions

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
        output = "1.18.10" if argv == ["opencode", "--version"] else "--prompt text"
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(sessions.subprocess, "run", run)
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
    from vigil_cli.remediation import register_remediation_parser

    parser = argparse.ArgumentParser()
    register_remediation_parser(parser.add_subparsers(dest="command"))
    assert parser.parse_args(["remediation", "-k", "acme", "start", "--client", client]).client == client


def test_opencode_starts_native_tui_with_release_command_and_preserves_configuration(launch, monkeypatch):
    monkeypatch.setenv("OPENCODE_CONFIG_CONTENT", json.dumps({"model": "zai-coding-plan/selected", "permission": "ask"}))
    assert start(launch, "opencode") == 0
    argv, options = launch.calls[-1]
    assert argv[:2] == ["opencode", "--prompt"]
    assert options["cwd"] == launch.repository
    config = json.loads(options["env"]["OPENCODE_CONFIG_CONTENT"])
    assert config["model"] == "zai-coding-plan/selected"
    assert config["permission"] == "ask"
    assert config["command"]["vigil-remediate"]["template"] == "Read the profile. $ARGUMENTS\n"
    assert options["env"]["VIGIL_CLIENT_NAME"] == "opencode"
    assert str(launch.project["_profile_path"]) in argv[2]
    assert list(launch.repository.iterdir()) == []
    assert not launch.engagement.exists()


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


@pytest.mark.parametrize("version,help_output", [("0.9.0", "--prompt text"), ("2.0.0", "--prompt text"), ("1.18.10", "--model text")])
def test_opencode_refuses_unverified_version_or_missing_prompt_before_launch(launch, monkeypatch, version, help_output):
    def run(argv, **options):
        launch.calls.append((argv, options))
        return subprocess.CompletedProcess(argv, 0, version if argv[-1] == "--version" else help_output, "")
    monkeypatch.setattr(launch.sessions.subprocess, "run", run)
    with pytest.raises(SystemExit, match="OpenCode"):
        start(launch, "opencode")
    assert all(argv[-1] in ("--version", "--help") for argv, _ in launch.calls)
    assert not launch.engagement.exists()


def test_missing_opencode_reports_installation_requirement(launch, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError
    monkeypatch.setattr(launch.sessions.subprocess, "run", missing)
    with pytest.raises(SystemExit, match="OpenCode"):
        start(launch, "opencode")


def test_zcode_prepares_context_plugin_and_opens_repository_without_false_session_receipt(launch, monkeypatch, tmp_path, capsys):
    import sys
    from pathlib import Path

    monkeypatch.setattr(sys, "platform", "darwin")
    app = tmp_path / "Applications/ZCode.app"
    info = app / "Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "3.15.1"}))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert start(launch, "zcode") == 0
    argv, options = launch.calls[-1]
    assert argv == ["open", "-a", str(app), "--args", "--open-workspace", str(launch.repository)]
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
    import sys
    from pathlib import Path
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    with pytest.raises(SystemExit, match="ZCode"):
        start(launch, "zcode")
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
    import sys
    from pathlib import Path
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    info = tmp_path / "Applications/ZCode.app/Contents/Info.plist"
    info.parent.mkdir(parents=True)
    info.write_bytes(plistlib.dumps(["invalid metadata"]))
    with pytest.raises(SystemExit, match="metadata"):
        start(launch, "zcode")
    assert launch.calls == []


def test_zcode_preparation_refuses_symlinked_remediation_directory(launch, monkeypatch, tmp_path):
    import sys
    from pathlib import Path
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
    from vigil_cli.remediation_clients import _prepare_zcode_plugin

    first = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    second = _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme-other", install_root=launch.root)
    first_name = json.loads((first / ".zcode-plugin/plugin.json").read_text())["name"]
    second_name = json.loads((second / ".zcode-plugin/plugin.json").read_text())["name"]
    assert first_name != second_name
    for plugin, name in ((first, first_name), (second, second_name)):
        assert json.loads((plugin / "marketplace.json").read_text())["plugins"][0]["name"] == name


def test_prepared_plugin_rejects_nonregular_collision_before_reading(launch, monkeypatch):
    import os
    from vigil_cli.remediation_clients import _prepare_zcode_plugin

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
        import stat
        assert stat.S_ISREG(os.fstat(descriptor).st_mode), "Nonregular collision reached potentially blocking read"
        return real_fdopen(descriptor, *args, **kwargs)
    monkeypatch.setattr(os, "fdopen", fdopen)
    with pytest.raises(SystemExit, match="collision"):
        _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)


def test_concurrent_plugin_preparation_publishes_same_complete_context(launch):
    from concurrent.futures import ThreadPoolExecutor
    from vigil_cli.remediation_clients import _prepare_zcode_plugin

    def prepare(_):
        return _prepare_zcode_plugin(launch.root / "agent", launch.engagement, launch.repository, launch.project, "acme", install_root=launch.root)
    with ThreadPoolExecutor(max_workers=8) as executor:
        roots = list(executor.map(prepare, range(16)))
    assert len(set(roots)) == 1
    assert json.loads((roots[0] / "vigil-context.json").read_text())["engagement_key"] == "acme"


def test_interrupted_plugin_preparation_can_retry_without_partial_published_file(launch, monkeypatch):
    from vigil_cli import install_fs
    from vigil_cli.remediation_clients import _prepare_zcode_plugin

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
    from vigil_cli.remediation_clients import _prepare_zcode_plugin

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
    import sys
    from pathlib import Path
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
    import sys
    from pathlib import Path
    import shlex
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
    import os
    from vigil_cli.remediation_clients import _prepare_zcode_plugin
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
