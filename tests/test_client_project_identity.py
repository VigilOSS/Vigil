"""Project identity survives GUI shells without selecting application code from CWD."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from vigil_cli import main as cli
from vigil_cli.assessment_clients import prepare_workspace

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ("VIGIL_CLIENT_CONTEXT", "VIGIL_CLIENT_NAME", "VIGIL_REQUESTED_CLIENT",
            "VIGIL_SESSION_ENGAGEMENT_DIR", "ENGAGEMENT_DIR", "ENGAGEMENT_KEY",
            "VIGIL_OPERATOR_MODE", "VIGIL_INSTALL_DIR", "VIGIL_DIR")


@pytest.fixture(params=["zcode", "opencode"])
def project(tmp_path, monkeypatch, request):
    for name in IDENTITY:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(ROOT))
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    install = tmp_path / "Acme private"
    engagement = install / "engagements/acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "offensive", "hosts": ["app.example.com"],
        "tracks": {"web": {"phase": "recon"}, "code": {"phase": "hunt"}}}))
    workspace, binding = prepare_workspace(install, engagement, request.param, "code")
    monkeypatch.chdir(workspace)
    return install, engagement, workspace, binding


@pytest.mark.parametrize("nested", [False, True])
def test_bare_mode_discovers_project_identity(project, monkeypatch, capsys, nested):
    install, engagement, workspace, binding = project
    if nested:
        (workspace / "notes").mkdir()
        monkeypatch.chdir(workspace / "notes")
    cli.main(["engagement", "mode", "--json"])
    state = json.loads(capsys.readouterr().out)
    assert state["mode"] == "code"
    assert state["client"] == binding["client"]
    assert state["selection_source"] == "session"
    assert all(f"--client {binding['client']}" in row["start_command"]
               for row in state["tracks"].values())
    assert all(name not in os.environ for name in IDENTITY)


def test_project_identity_reaches_assess_without_changing_application(project, monkeypatch):
    install, engagement, workspace, binding = project
    captured = {}
    monkeypatch.setattr(cli.os, "execvpe", lambda executable, argv, env:
                        captured.update(executable=executable, argv=argv, env=env))
    cli.main(["assess", "contract", "finding"])
    env = captured["env"]
    assert env["VIGIL_CLIENT_NAME"] == binding["client"]
    assert env["VIGIL_OPERATOR_MODE"] == "code"
    assert env["VIGIL_SESSION_ENGAGEMENT_DIR"] == str(engagement)
    assert env["VIGIL_INSTALL_DIR"] == str(install)
    assert env["VIGIL_APPLICATION_DIR"] == str(ROOT)
    assert env["VIGIL_CLIENT_CONTEXT"] == str(workspace / ".vigil-client-context.json")
    assert captured["argv"][1:3] == ["--engagement-dir", str(engagement)]


@pytest.mark.parametrize("child_flag", ["-h", "--help"])
def test_forwarded_child_help_preserves_project_identity(project, monkeypatch, child_flag):
    _, engagement, _, binding = project
    captured = {}
    monkeypatch.setattr(cli.os, "execvpe", lambda executable, argv, env:
                        captured.update(argv=argv, env=env))
    cli.main(["assess", "kali", "exec", "--", "acme-tool", child_flag])
    assert captured["env"]["VIGIL_CLIENT_NAME"] == binding["client"]
    assert captured["argv"][1:3] == ["--engagement-dir", str(engagement)]
    assert captured["argv"][-3:] == ["--", "acme-tool", child_flag]


@pytest.mark.parametrize("selector", ["root", "root-abbreviation", "root-abbreviation-inline", "mode", "client", "engagement"])
def test_conflicting_identity_has_actionable_recovery(project, monkeypatch, selector):
    install, engagement, workspace, binding = project
    args = ["engagement", "mode", "--json"]
    if selector.startswith("root"):
        flag = "--root" if selector == "root" else "--roo"
        args = ([f"{flag}={install.parent / 'other'}", *args] if selector.endswith("inline")
                else [flag, str(install.parent / "other"), *args])
    elif selector == "mode":
        monkeypatch.setenv("VIGIL_OPERATOR_MODE", "web")
    elif selector == "client":
        monkeypatch.setenv("VIGIL_CLIENT_NAME", "claude")
    else:
        monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(install / "engagements/other"))
    with pytest.raises(SystemExit, match="project.*identity|Project.*identity"):
        cli.main(args)


def test_modified_project_binding_is_reported_before_inspection(project):
    _, _, workspace, binding = project
    binding["mode"] = "web"
    (workspace / ".vigil-client-context.json").write_text(json.dumps(binding))
    with pytest.raises(SystemExit, match="project.*context|Project.*context"):
        cli.main(["engagement", "mode", "--json"])


@pytest.mark.parametrize("mode", [[], {}])
def test_malformed_project_mode_has_actionable_recovery(project, mode):
    _, _, workspace, binding = project
    binding["mode"] = mode
    (workspace / ".vigil-client-context.json").write_text(json.dumps(binding))
    with pytest.raises(SystemExit, match="project context"):
        cli.main(["engagement", "mode", "--json"])


def test_help_still_works_with_modified_project_context(project, capsys):
    _, _, workspace, _ = project
    (workspace / ".vigil-client-context.json").write_text("invalid")
    with pytest.raises(SystemExit) as stopped:
        cli.main(["engagement", "mode", "--help"])
    assert stopped.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_unbound_mode_explains_selection_and_requests_client(project, monkeypatch, capsys):
    install, engagement, _, _ = project
    monkeypatch.chdir(engagement)
    cli.main(["--root", str(install), "engagement", "mode"])
    output = capsys.readouterr().out
    assert "session binding" in output
    assert "--client" in output
    cli.main(["--root", str(install), "engagement", "mode", "--json"])
    state = json.loads(capsys.readouterr().out)
    assert state["client"] is None
    assert state["selection_source"] == "unselected"
    assert all(row["start_command"] is None for row in state["tracks"].values())


def test_bound_helper_identity_selects_recovery_client_outside_project(project, monkeypatch, capsys):
    install, engagement, workspace, binding = project
    monkeypatch.chdir(engagement)
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engagement))
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "code")
    monkeypatch.setenv("VIGIL_CLIENT_NAME", binding["client"])
    cli.main(["--root", str(install), "engagement", "mode", "--json"])
    state = json.loads(capsys.readouterr().out)
    assert state["client"] == binding["client"]
    assert all(f"--client {binding['client']}" in row["start_command"]
               for row in state["tracks"].values())


@pytest.mark.parametrize("operation", ["mode", "scope"])
def test_real_cli_uses_project_identity_without_a_launch(project, operation):
    _, engagement, workspace, binding = project
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    arguments = (["engagement", "mode", "--json"] if operation == "mode"
                 else ["assess", "scope", "explain", "https://app.example.com", "--json"])
    result = subprocess.run([sys.executable, "-m", "vigil_cli.main", *arguments],
                            cwd=workspace, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    if operation == "mode":
        state = json.loads(result.stdout)
        assert state["mode"] == "code"
        assert state["client"] == binding["client"]
    else:
        assert json.loads(result.stdout)[0]["admitted"] is True


def test_bare_client_check_uses_project_workflow(project, monkeypatch, capsys):
    from vigil_cli import client_checks
    _, engagement, _, binding = project
    captured = {}
    monkeypatch.setattr(client_checks, "collect_client_checks", lambda client, **kwargs:
                        captured.update(client=client, **kwargs) or [])
    cli.main(["engagement", "client-check", "--client", binding["client"], "--json"])
    capsys.readouterr()
    assert captured["engagement"] == engagement
    assert captured["mode"] == "code"


def test_client_check_defaults_to_verified_project_client(project, monkeypatch, capsys):
    from vigil_cli import client_checks
    _, engagement, _, binding = project
    captured = {}
    monkeypatch.setattr(client_checks, "collect_client_checks", lambda client, **kwargs:
                        captured.update(client=client, **kwargs) or [])
    cli.main(["engagement", "client-check", "--json"])
    capsys.readouterr()
    assert captured["client"] == binding["client"]
    assert captured["engagement"] == engagement
    assert captured["mode"] == "code"


def test_client_check_outside_project_requests_a_client(project, monkeypatch, capsys):
    _, engagement, _, _ = project
    monkeypatch.chdir(engagement)
    with pytest.raises(SystemExit) as outcome:
        cli.main(["engagement", "client-check", "--json"])
    assert outcome.value.code == 2
    assert "--client" in capsys.readouterr().err


def test_explicit_context_diagnostics_keep_their_own_mode_filter(project, monkeypatch, capsys):
    from vigil_cli import client_checks
    install, engagement, workspace, binding = project
    monkeypatch.setenv("VIGIL_CLIENT_CONTEXT", str(workspace / ".vigil-client-context.json"))
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engagement))
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "web")
    captured = {}
    monkeypatch.setattr(client_checks, "collect_client_checks", lambda client, **kwargs:
                        captured.update(**kwargs) or [])
    cli.main(["--root", str(install), "engagement", "client-check", "--client", binding["client"], "--json"])
    capsys.readouterr()
    assert captured["mode"] is None


@pytest.mark.parametrize("inspection", ["explicit-key", "outside-project"])
def test_diagnostic_mode_default_requires_implicit_project_selection(project, monkeypatch, capsys, inspection):
    from vigil_cli import client_checks
    install, engagement, _, binding = project
    key = [engagement.name] if inspection == "explicit-key" else []
    if inspection == "outside-project":
        monkeypatch.chdir(engagement)
        monkeypatch.setenv("VIGIL_OPERATOR_MODE", "web")
    captured = {}
    monkeypatch.setattr(client_checks, "collect_client_checks", lambda client, **kwargs:
                        captured.update(**kwargs) or [])
    cli.main(["--root", str(install), "engagement", "client-check", *key,
              "--client", binding["client"], "--json"])
    capsys.readouterr()
    assert captured["mode"] is None


def test_explicit_assessment_selector_remains_authoritative(project, monkeypatch):
    _, _, _, _ = project
    captured = {}
    monkeypatch.setattr(cli.os, "execvpe", lambda executable, argv, env: captured.update(argv=argv))
    cli.main(["assess", "--engagement-dir=/tmp/acme-explicit", "contract", "finding"])
    assert captured["argv"][1:] == ["--engagement-dir=/tmp/acme-explicit", "contract", "finding"]


@pytest.mark.parametrize("damage", ["marker-link", "helper", "foreign-owner"])
def test_project_discovery_rejects_unverified_assets(project, damage):
    install, engagement, workspace, binding = project
    if damage == "marker-link":
        context = workspace / ".vigil-client-context.json"
        target = workspace / "context-copy.json"
        context.rename(target)
        context.symlink_to(target)
    elif damage == "helper":
        (workspace / "bin/vigil").write_text("#!/bin/sh\nexit 0\n")
    else:
        binding["install_root"] = str(install / "source")
        raw = (json.dumps(binding, sort_keys=True, indent=2) + "\n").encode()
        (workspace / ".vigil-client-context.json").write_bytes(raw)
        # Even a self-consistent digest cannot move ownership into another tree.
        import hashlib
        manifest = workspace / ".vigil-managed-files.json"
        recorded = json.loads(manifest.read_text())
        recorded[".vigil-client-context.json"] = hashlib.sha256(raw).hexdigest()
        manifest.write_text(json.dumps(recorded))
    with pytest.raises(SystemExit, match="project context"):
        cli.main(["engagement", "mode", "--json"])
