from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import threading
from types import SimpleNamespace

import pytest


def test_route_accepts_ticket_references_without_a_ticket_flag() -> None:
    from vigil_cli.remediation import register_remediation_parser

    parser = argparse.ArgumentParser()
    register_remediation_parser(parser.add_subparsers(dest="command"))
    args = parser.parse_args([
        "remediation", "-k", "acme", "route", "SEC-123",
        "https://jira.example.com/browse/SEC-123",
    ])
    assert args.references == ["SEC-123", "https://jira.example.com/browse/SEC-123"]


@pytest.mark.parametrize("references, expected", [
    (["SEC-123", "https://jira.example.com/browse/SEC-123"], ["SEC-123"]),
    (["sec-123", "SEC-124", "SEC-123"], ["SEC-123", "SEC-124"]),
    (["https://tracker.example.com/issues/12", "https://tracker.example.com/issues/12"],
     ["https://tracker.example.com/issues/12"]),
])
def test_reference_routing_deduplicates_without_claiming_retrieval(references, expected) -> None:
    from vigil_cli.remediation_sessions import normalize_references

    inputs = normalize_references(references)
    assert [item["identity_hint"] for item in inputs] == expected
    assert all(item["resolved"] is False for item in inputs)
    assert sum(len(item["references"]) for item in inputs) == len(set(references))


@pytest.mark.parametrize("reference", ["", "$(touch /tmp/marker)", "SEC-123\nSEC-124", "file:///report", "report text"])
def test_reference_routing_rejects_non_reference_data(reference) -> None:
    from vigil_cli.remediation_sessions import normalize_references

    with pytest.raises(ValueError):
        normalize_references([reference])


@pytest.mark.parametrize("reference", ["123", "#123", "1bb41c53-1c3e-4738-bf68-a85fd4bda2f5", "acme:report_12"])
def test_reference_routing_supports_non_jira_ticket_identifiers(reference) -> None:
    from vigil_cli.remediation_sessions import normalize_references

    assert normalize_references([reference])[0]["identity_hint"] == reference


@pytest.mark.parametrize("inputs, role", [(["SEC-123", "https://jira.example.com/browse/SEC-123"], "developer"),
                                         (["SEC-123", "SEC-124"], "coordinator")])
def test_route_preserves_pending_inputs_and_returns_only_selected_role(tmp_path, inputs, role) -> None:
    from vigil_cli.remediation_sessions import route_context

    result = route_context(tmp_path / "install", tmp_path / "engagement", {"repository": "/acme"}, inputs)
    assert result["role"] == role
    assert Path(result["instructions"]).name == f"remediation-{role}.md"
    assert json.loads(Path(result["pending_input"]).read_text()) == result
    assert "case_id" not in result
    assert "snapshot" not in result


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    from vigil_cli import remediation_sessions as sessions

    monkeypatch.setattr(sessions.os, "environ", {"PATH": "/usr/bin"})
    installation = tmp_path / "installation"
    command = installation / "agent/.claude/commands/vigil-remediate.md"
    command.parent.mkdir(parents=True)
    command.write_text("command")
    engagement = tmp_path / "engagement"
    repository = tmp_path / "acme"
    repository.mkdir()
    workspace = repository / "worktrees/SEC-123"
    workspace.mkdir(parents=True)
    handoff = engagement / "remediation/cases/1/handoff.md"
    handoff.parent.mkdir(parents=True)
    handoff.write_text("case context")
    project = {"repository": str(repository), "remediation": {"hook_policy": "disabled"}}
    project["_profile_path"] = str(repository / "PROJECT.md")
    monkeypatch.setattr(sessions, "adapter", lambda _: SimpleNamespace(
        registered=lambda root, path: path == workspace,
        branch_matches=lambda path, branch: branch == "fix/SEC-123"))
    calls = []
    rows = []

    def native_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv == ["claude", "--version"]:
            return subprocess.CompletedProcess(argv, 0, "2.1.296 (Claude Code)", "")
        if argv == ["claude", "--help"]:
            return subprocess.CompletedProcess(argv, 0, "--bg\nCommands:\n  agents [options]\n  attach <id|name>\n", "")
        if argv == ["claude", "agents", "--json", "--all"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps(rows), "")
        if "--bg" in argv:
            session_id = argv[argv.index("--session-id") + 1]
            rows.append({"id": "job1", "sessionId": session_id, "cwd": str(repository), "kind": "background", "state": "blocked"})
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(sessions.subprocess, "run", native_run)
    return SimpleNamespace(module=sessions, installation=installation, engagement=engagement,
                           repository=repository, workspace=workspace, project=project,
                           calls=calls, rows=rows,
                           case={"id": 1, "worktree_path": str(workspace), "worktree_branch": "fix/SEC-123"})


def run_case(prepared, command="session", **kwargs):
    args = argparse.Namespace(remediation_command=command, engagement_key="acme", case_id="1",
                              bind=False, session_id=None)
    for name, value in kwargs.items():
        setattr(args, name, value)
    return prepared.module.run_session_command(args, prepared.installation, prepared.engagement,
                                              prepared.project, case_reader=lambda _: prepared.case)


def test_start_hosts_and_attaches_same_native_conversation_with_repository_config(prepared, monkeypatch, capsys) -> None:
    monkeypatch.setenv("VIGIL_OPERATOR_MODE", "web")
    monkeypatch.setenv("CLAUDECODE", "1")
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="claude")
    assert prepared.module.run_session_command(args, prepared.installation, prepared.engagement, prepared.project) == 0
    launches = [(argv, opts) for argv, opts in prepared.calls if "--bg" in argv]
    assert len(launches) == 1
    argv, opts = launches[0]
    settings = json.loads(argv[argv.index("--settings") + 1])
    assert settings == {"disableAllHooks": True, "worktree": {"bgIsolation": "none"}, "env": {
        "ENGAGEMENT_DIR": str(prepared.engagement), "ENGAGEMENT_KEY": "acme", "VIGIL_CLIENT_NAME": "claude"}}
    assert opts["cwd"] == prepared.repository
    assert "VIGIL_OPERATOR_MODE" not in opts["env"]
    assert opts["env"].get("CLAUDECODE") is None
    assert opts["env"]["ENGAGEMENT_DIR"] == str(prepared.engagement)
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]
    assert "--bare" not in argv
    assert "--strict-mcp-config" not in argv
    assert "--dangerously-skip-permissions" not in argv
    added_directories = [argv[index + 1] for index, item in enumerate(argv) if item == "--add-dir"]
    assert added_directories == [str(prepared.engagement / "remediation/client-context"),
                                 str(prepared.engagement / "remediation")]
    assert str(prepared.repository / "PROJECT.md") in argv[-1]
    assert "Non-managed hooks are disabled" in capsys.readouterr().out
    overlay = prepared.engagement / "remediation/client-context/.claude/commands"
    assert [path.name for path in overlay.iterdir()] == ["vigil-remediate.md"]
    assert not (prepared.repository / ".claude").exists()


def test_inherited_hooks_are_not_disabled_by_generic_launcher(prepared) -> None:
    prepared.project["remediation"]["hook_policy"] = "inherit"
    run_case(prepared)
    argv = next(argv for argv, _ in prepared.calls if "--bg" in argv)
    assert "disableAllHooks" not in json.loads(argv[argv.index("--settings") + 1])


def test_worker_binding_is_idempotent_and_join_attaches_exact_job(prepared) -> None:
    run_case(prepared)
    binding_path = prepared.engagement / "remediation/cases/1/session.json"
    binding = json.loads(binding_path.read_text())
    assert binding["session_id"] == prepared.rows[0]["sessionId"]
    assert binding["workspace"] == str(prepared.workspace)
    run_case(prepared)
    assert sum("--bg" in argv for argv, _ in prepared.calls) == 1
    run_case(prepared, command="join")
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]
    assert all("--resume" not in argv and "--fork-session" not in argv for argv, _ in prepared.calls)


def test_single_case_binds_existing_conversation_without_new_launch(prepared) -> None:
    prepared.project["remediation"]["hook_policy"] = "inherit"
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    prepared.rows.append({"id": "existing", "sessionId": session_id, "cwd": str(prepared.repository)})
    run_case(prepared, bind=True, session_id=session_id)
    assert not any("--bg" in argv for argv, _ in prepared.calls)
    binding = json.loads((prepared.engagement / "remediation/cases/1/session.json").read_text())
    assert binding["job_id"] == "existing"
    run_case(prepared, command="join")
    assert prepared.calls[-1][0] == ["claude", "attach", "existing"]


def test_hook_disabled_profile_cannot_bind_an_uncontrolled_session(prepared) -> None:
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    prepared.rows.append({"id": "existing", "sessionId": session_id, "cwd": str(prepared.repository)})
    with pytest.raises(SystemExit, match="start"):
        run_case(prepared, bind=True, session_id=session_id)


def test_single_case_can_bind_vigil_started_hook_disabled_session(prepared) -> None:
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="claude")
    prepared.module.run_session_command(args, prepared.installation, prepared.engagement, prepared.project)
    session_id = prepared.rows[0]["sessionId"]
    run_case(prepared, bind=True, session_id=session_id)
    assert sum("--bg" in argv for argv, _ in prepared.calls) == 1


def test_corrupt_launch_manifest_cannot_bind_case(prepared) -> None:
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    path = prepared.engagement / f"remediation/sessions/{session_id}.json"
    path.parent.mkdir(parents=True)
    path.write_text("broken")
    with pytest.raises(SystemExit, match="session binding"):
        run_case(prepared, bind=True, session_id=session_id)


@pytest.mark.parametrize("field,value", [("cwd", "/other"), ("sessionId", "638131c5-4bcd-4a2f-898b-ecb1a5489638")])
def test_join_refuses_native_identity_drift(prepared, field, value) -> None:
    run_case(prepared)
    prepared.rows[0][field] = value
    with pytest.raises(SystemExit, match="identity or repository"):
        run_case(prepared, command="join")
    assert not any(argv[:2] == ["claude", "attach"] for argv, _ in prepared.calls)


def test_missing_recorded_session_does_not_create_replacement(prepared) -> None:
    run_case(prepared)
    prepared.rows.clear()
    with pytest.raises(SystemExit, match="recover it"):
        run_case(prepared)
    with pytest.raises(SystemExit, match="absent"):
        run_case(prepared, command="join")
    assert sum("--bg" in argv for argv, _ in prepared.calls) == 1


def test_unregistered_workspace_cannot_launch(prepared) -> None:
    prepared.case["worktree_path"] = str(prepared.repository)
    with pytest.raises(SystemExit, match="not registered"):
        run_case(prepared)
    assert not any("--bg" in argv for argv, _ in prepared.calls)


@pytest.mark.parametrize("bind", [True, False])
def test_new_developer_cannot_bind_or_launch_switched_case_branch(prepared, bind) -> None:
    prepared.project["remediation"]["hook_policy"] = "inherit"
    prepared.rows.append({"id": "existing", "sessionId": "638131c5-4bcd-4a2f-898b-ecb1a5489638",
                          "cwd": str(prepared.repository)})
    prepared.case["worktree_branch"] = "unexpected"
    with pytest.raises(SystemExit, match="branch"):
        run_case(prepared, bind=bind, session_id="638131c5-4bcd-4a2f-898b-ecb1a5489638" if bind else None)
    assert not any("--bg" in argv for argv, _ in prepared.calls)


def test_join_preserves_conversation_for_diagnosing_branch_and_revision_drift(prepared, capsys) -> None:
    run_case(prepared)
    prepared.case["worktree_branch"] = "unexpected"
    prepared.case["worktree_revision"] = "changed-during-editing"
    run_case(prepared, command="join")
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]
    assert "branch" in capsys.readouterr().out


def test_join_announces_recorded_hook_policy_when_profile_changed(prepared, capsys) -> None:
    run_case(prepared)
    capsys.readouterr()
    prepared.project["remediation"]["hook_policy"] = "inherit"
    run_case(prepared, command="join")
    assert "Non-managed hooks are disabled" in capsys.readouterr().out


def test_failed_launch_retains_binding_and_does_not_retry_implicitly(prepared, monkeypatch) -> None:
    native_run = prepared.module.subprocess.run

    def launch_fails(argv, **kwargs):
        if "--bg" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "Workspace not trusted")
        return native_run(argv, **kwargs)

    monkeypatch.setattr(prepared.module.subprocess, "run", launch_fails)
    with pytest.raises(SystemExit, match="binding retained"):
        run_case(prepared)
    assert (prepared.engagement / "remediation/cases/1/session.json").is_file()
    with pytest.raises(SystemExit, match="recover it"):
        run_case(prepared)


def test_old_client_fails_before_dispatch(prepared, monkeypatch) -> None:
    monkeypatch.setattr(prepared.module.subprocess, "run", lambda argv, **_: subprocess.CompletedProcess(argv, 0, "2.1.200", ""))
    with pytest.raises(SystemExit, match="2.1.257"):
        run_case(prepared)


@pytest.mark.parametrize("help_text", ["Commands:\n  agents [options]\n  attach <id|name>",
                                      "--bg\nCommands:\n  agents [options]"])
def test_client_without_native_host_capabilities_fails_before_recording_binding(prepared, monkeypatch, help_text) -> None:
    native_run = prepared.module.subprocess.run

    def no_native_host(argv, **kwargs):
        if argv == ["claude", "--help"]:
            return subprocess.CompletedProcess(argv, 0, help_text, "")
        return native_run(argv, **kwargs)

    monkeypatch.setattr(prepared.module.subprocess, "run", no_native_host)
    with pytest.raises(SystemExit, match="native background"):
        run_case(prepared)
    assert not (prepared.engagement / "remediation/cases/1/session.json").exists()
    assert not any("--bg" in argv for argv, _ in prepared.calls)


def test_parallel_workers_share_command_overlay_without_creation_race(prepared, monkeypatch) -> None:
    barrier = threading.Barrier(2)
    symlink = Path.symlink_to

    def simultaneous_symlink(path, target, **kwargs):
        barrier.wait(timeout=5)
        return symlink(path, target, **kwargs)

    monkeypatch.setattr(Path, "symlink_to", simultaneous_symlink)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(prepared.module._command_overlay, prepared.installation, prepared.engagement)
                   for _ in range(2)]
        assert futures[0].result() == futures[1].result()


def test_source_arguments_never_become_shell_code(tmp_path, monkeypatch) -> None:
    from vigil_cli import remediation_sessions as sessions

    monkeypatch.setattr(sessions.subprocess, "run", lambda *args, **kwargs: pytest.fail("route must not run any process"))
    reference = "https://tracker.example.com/issues/12?note=$(touch%20marker)"
    args = argparse.Namespace(remediation_command="route", references=[reference])
    sessions.run_session_command(args, tmp_path, tmp_path / "engagement", {"repository": "/acme"})
    assert sessions.normalize_references([reference])[0]["references"] == [reference]
