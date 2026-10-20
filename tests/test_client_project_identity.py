"""Project identity survives GUI shells without selecting application code from CWD."""
import json
import hashlib
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


@pytest.fixture
def stable_project(project, monkeypatch):
    install, engagement, snapshot, binding = project
    entry = engagement / "clients" / binding["client"] / binding["mode"]
    entry.mkdir(parents=True)
    descriptor = {key: binding[key] for key in (
        "client", "mode", "install_root", "engagement_dir", "engagement_key")}
    descriptor.update(schema_version=1, protocol=1, project=str(entry), engagements_root=str(engagement.parent))
    files = {".vigil-client-project.json": json.dumps(descriptor).encode(),
             "AGENTS.md": b"Acme project router", "bin/vigil": b"Acme bootstrap",
             "bootstrap.mjs": b"Acme bootstrap", "vigil-project.mjs": b"Acme validator"}
    for name, data in files.items():
        target = entry / name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
    (entry / ".vigil-managed-files.json").write_text(json.dumps({
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()}))
    if binding["client"] == "zcode":
        plugin = install / "client-plugins/dispatcher-v1/zcode"
        assets = {".zcode-plugin/plugin.json": b'{"name":"vigil-project-v1","version":"1.0.0"}',
                  "marketplace.json": b"{}", "hooks/hooks.json": b"{}",
                  "hooks/dispatch.mjs": b"Acme dispatcher", "hooks/project-binding.mjs": b"Acme binding validator",
                  "hooks/launch.sh": b"Acme launcher", "vigil-owner.json": json.dumps({
                      "schema_version": 1, "install_root": str(install),
                      "engagements_root": str(engagement.parent)}).encode()}
        for name, data in assets.items():
            path = plugin / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes(data)
        (plugin / ".vigil-managed-files.json").write_text(json.dumps({
            name: hashlib.sha256(data).hexdigest() for name, data in assets.items()}))
        (entry / "plugin").symlink_to(plugin)
    binding["project"] = str(entry)
    context = snapshot / ".vigil-client-context.json"
    context.write_text(json.dumps(binding))
    manifest = snapshot / ".vigil-managed-files.json"
    recorded = json.loads(manifest.read_text())
    recorded[context.name] = hashlib.sha256(context.read_bytes()).hexdigest()
    manifest.write_text(json.dumps(recorded))
    (entry / ".vigil-current-context.json").write_text(json.dumps({
        "schema_version": 1, "binding_path": str(context),
        "binding_sha256": hashlib.sha256(context.read_bytes()).hexdigest()}))
    monkeypatch.chdir(entry)
    return install, engagement, entry, snapshot, binding


def test_stable_project_mode_inspection_uses_current_context(stable_project, capsys):
    _, _, _, _, binding = stable_project
    cli.main(["engagement", "mode", "--json"])
    captured = capsys.readouterr()
    state = json.loads(captured.out)
    assert state["mode"] == binding["mode"]
    assert state["client"] == binding["client"]
    assert "new-task" in captured.err.lower()


def test_stable_project_assessment_requires_task_binding(stable_project, monkeypatch):
    monkeypatch.setattr(cli.os, "execvpe", lambda *a, **k: pytest.fail("Unbound project must not execute assessment"))
    with pytest.raises(SystemExit, match="task.*binding|bound.*helper"):
        cli.main(["assess", "contract", "finding"])


def test_stable_project_accepts_pinned_task_when_current_selector_is_unavailable(stable_project, monkeypatch):
    _, _, entry, snapshot, binding = stable_project
    (entry / ".vigil-current-context.json").write_text("unavailable current selection")
    context = snapshot / ".vigil-client-context.json"
    monkeypatch.setenv("VIGIL_CLIENT_CONTEXT", str(context))
    captured = {}
    monkeypatch.setattr(cli.os, "execvpe", lambda executable, argv, env: captured.update(env=env))
    cli.main(["assess", "contract", "finding"])
    assert captured["env"]["VIGIL_CLIENT_CONTEXT"] == str(context)
    assert captured["env"]["VIGIL_CLIENT_NAME"] == binding["client"]


@pytest.mark.parametrize("damage", ["selector-link", "selector-digest", "project-router", "foreign-binding"])
def test_stable_project_rejects_invalid_selection(stable_project, damage):
    _, engagement, entry, snapshot, _ = stable_project
    selection = entry / ".vigil-current-context.json"
    if damage == "selector-link":
        saved = entry / "saved.json"
        selection.rename(saved)
        selection.symlink_to(saved)
    elif damage == "selector-digest":
        row = json.loads(selection.read_text())
        row["binding_sha256"] = "0" * 64
        selection.write_text(json.dumps(row))
    elif damage == "project-router":
        (entry / "AGENTS.md").write_text("unmanaged replacement")
    else:
        row = json.loads(selection.read_text())
        row["binding_path"] = str(engagement / "other" / snapshot.name / ".vigil-client-context.json")
        selection.write_text(json.dumps(row))
    with pytest.raises(SystemExit, match="project context"):
        cli.main(["engagement", "mode", "--json"])


@pytest.mark.parametrize("damaged", [False, True])
def test_pinned_client_diagnostics_verify_stable_project_entry(stable_project, damaged):
    from vigil_cli.client_checks import collect_client_checks

    install, engagement, entry, snapshot, binding = stable_project
    if damaged:
        (entry / "AGENTS.md").write_text("unmanaged router")
    checks = collect_client_checks(binding["client"], engagement=engagement, mode="code",
                                   install_root=install, context_file=snapshot / ".vigil-client-context.json")
    indexed = {check.name: check for check in checks}
    if damaged:
        assert indexed["client-context"].status == "FAIL"
    else:
        assert indexed["project-entry"].status == "OK"


@pytest.mark.parametrize("project", ["zcode"], indirect=True)
@pytest.mark.parametrize("damage", ["script", "launcher-inventory", "dispatcher-owner"])
def test_pinned_client_diagnostics_verify_zcode_dispatcher(stable_project, damage):
    from vigil_cli.client_checks import collect_client_checks

    install, engagement, entry, snapshot, _ = stable_project
    if damage == "script":
        (entry / "plugin/hooks/dispatch.mjs").write_text("unmanaged replacement")
    elif damage == "launcher-inventory":
        manifest = entry / "plugin/.vigil-managed-files.json"
        assets = json.loads(manifest.read_text())
        assets.pop("hooks/launch.sh")
        manifest.write_text(json.dumps(assets))
    else:
        owner = entry / "plugin/vigil-owner.json"
        owner.write_text(json.dumps({"schema_version": 1, "install_root": str(install),
                                    "engagements_root": str(engagement.parent / "other")}))
        manifest = entry / "plugin/.vigil-managed-files.json"
        assets = json.loads(manifest.read_text())
        assets[owner.name] = hashlib.sha256(owner.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(assets))
    checks = collect_client_checks("zcode", engagement=engagement, mode="code",
                                   install_root=install, context_file=snapshot / ".vigil-client-context.json")
    assert next(check for check in checks if check.name == "client-context").status == "FAIL"
