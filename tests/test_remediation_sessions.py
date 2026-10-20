from __future__ import annotations

import argparse
from contextlib import contextmanager
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
    (installation / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(installation))
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
    monkeypatch.setattr(sessions, "adapter", lambda _, **kwargs: SimpleNamespace(
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
        "ENGAGEMENT_DIR": str(prepared.engagement), "VIGIL_SESSION_ENGAGEMENT_DIR": str(prepared.engagement),
        "ENGAGEMENT_KEY": "acme", "VIGIL_CLIENT_NAME": "claude", "VIGIL_INSTALL_DIR": str(prepared.installation),
        "VIGIL_APPLICATION_DIR": str(prepared.installation), "VIGIL_AGENT_ROOT": str(prepared.installation / "agent"),
        "PATH": "/usr/bin"}}
    assert opts["cwd"] == prepared.repository
    assert "VIGIL_OPERATOR_MODE" not in opts["env"]
    assert opts["env"].get("CLAUDECODE") is None
    assert opts["env"]["ENGAGEMENT_DIR"] == str(prepared.engagement)
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]
    assert "--bare" not in argv
    assert "--strict-mcp-config" not in argv
    assert "--dangerously-skip-permissions" not in argv
    added_directories = [argv[index + 1] for index, item in enumerate(argv) if item == "--add-dir"]
    assert len(added_directories) == 2
    assert Path(added_directories[0]).parent == prepared.engagement / "remediation/client-context"
    assert added_directories[1] == str(prepared.engagement / "remediation")
    assert str(prepared.repository / "PROJECT.md") in argv[-1]
    assert f"Profile: {prepared.repository / 'PROJECT.md'}" in capsys.readouterr().out
    overlay = Path(added_directories[0]) / ".claude/commands"
    assert [path.name for path in overlay.iterdir()] == ["vigil-remediate.md"]
    assert not (prepared.repository / ".claude").exists()


def test_start_reports_profile_checks_before_attaching(prepared, capsys) -> None:
    prepared.project["remediation"]["check_commands"] = [
        {"name": "lint", "command": "npm run lint", "directory": "."},
        {"name": "tests", "command": "npm test", "directory": "."},
    ]
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="claude")
    assert prepared.module.run_session_command(args, prepared.installation, prepared.engagement, prepared.project) == 0
    assert capsys.readouterr().out.splitlines()[:4] == [
        "Starting Claude remediation session",
        f"Repository: {prepared.repository}",
        f"Profile: {prepared.repository / 'PROJECT.md'}",
        "Profile checks: lint, tests",
    ]
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]


def test_inherited_hooks_are_not_disabled_by_generic_launcher(prepared) -> None:
    prepared.project["remediation"]["hook_policy"] = "inherit"
    run_case(prepared)
    argv = next(argv for argv, _ in prepared.calls if "--bg" in argv)
    assert "disableAllHooks" not in json.loads(argv[argv.index("--settings") + 1])


def test_background_host_assigned_uuid_is_recorded_and_bindable(prepared, monkeypatch) -> None:
    native_run = prepared.module.subprocess.run
    actual_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"

    def host_assigns_identity(argv, **kwargs):
        result = native_run(argv, **kwargs)
        if "--bg" in argv:
            prepared.rows[-1].update(sessionId=actual_id, name=argv[argv.index("--name") + 1])
        return result

    monkeypatch.setattr(prepared.module.subprocess, "run", host_assigns_identity)
    monkeypatch.setattr(prepared.module.time, "sleep", lambda _: None)
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="claude")
    assert prepared.module.run_session_command(args, prepared.installation, prepared.engagement, prepared.project) == 0
    launch = next(argv for argv, _ in prepared.calls if "--bg" in argv)
    requested_id = launch[launch.index("--session-id") + 1]
    for identity in (requested_id, actual_id):
        manifest = prepared.engagement / f"remediation/sessions/{identity}.json"
        assert json.loads(manifest.read_text())["session_id"] == actual_id
    run_case(prepared, bind=True, session_id=actual_id)
    run_case(prepared, command="join")
    assert prepared.calls[-1][0] == ["claude", "attach", "job1"]


def test_start_recovers_pending_launch_by_exact_name_without_dispatch(prepared) -> None:
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    actual_id = "f715d449-0960-46cc-b875-a88e4abc71b2"
    path = prepared.engagement / f"remediation/sessions/{session_id}.json"
    prepared.module._write_json(path, {
        "engagement_key": "acme", "session_cwd": str(prepared.repository),
        "session_id": session_id, "job_id": None,
        "settings": prepared.module._settings(prepared.project),
    })
    prepared.rows.append({"id": "existing", "sessionId": actual_id,
                          "cwd": str(prepared.repository), "name": f"vigil-{session_id}"})
    args = argparse.Namespace(remediation_command="start", engagement_key="acme", client="claude", session_id=session_id)
    assert prepared.module.run_session_command(args, prepared.installation, prepared.engagement, prepared.project) == 0
    assert not any("--bg" in argv for argv, _ in prepared.calls)
    assert prepared.calls[-1][0] == ["claude", "attach", "existing"]
    assert json.loads(path.read_text())["session_id"] == actual_id


@pytest.mark.parametrize("variant", ["duplicate", "wrong-directory", "invalid-uuid"])
def test_launch_name_reconciliation_rejects_ambiguous_or_invalid_host_identity(prepared, variant) -> None:
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    binding = {"session_id": session_id, "job_id": None, "session_cwd": str(prepared.repository)}
    row = {"id": "existing", "sessionId": "f715d449-0960-46cc-b875-a88e4abc71b2",
           "cwd": str(prepared.repository), "name": f"vigil-{session_id}"}
    rows = [row]
    if variant == "duplicate":
        rows.append(dict(row, id="other"))
    elif variant == "wrong-directory":
        row["cwd"] = str(prepared.repository / "other")
    else:
        row["sessionId"] = "invalid"
    with pytest.raises(SystemExit):
        prepared.module._launched_session(binding, rows)


@pytest.mark.parametrize("command", ["session", "join"])
def test_case_recovers_pending_host_identity_without_dispatch(prepared, command) -> None:
    requested_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    actual_id = "f715d449-0960-46cc-b875-a88e4abc71b2"
    path = prepared.engagement / "remediation/cases/1/session.json"
    prepared.module._write_json(path, {
        "case_id": "1", "engagement_key": "acme", "workspace": str(prepared.workspace),
        "session_cwd": str(prepared.repository), "session_id": requested_id, "job_id": None,
        "settings": prepared.module._settings(prepared.project),
    })
    prepared.rows.append({"id": "existing", "sessionId": actual_id,
                          "cwd": str(prepared.repository), "name": f"vigil-{requested_id}"})
    run_case(prepared, command=command)
    assert json.loads(path.read_text())["session_id"] == actual_id
    assert not any("--bg" in argv for argv, _ in prepared.calls)
    run_case(prepared, command="join")
    assert prepared.calls[-1][0] == ["claude", "attach", "existing"]


def test_resolved_binding_does_not_follow_a_reused_launch_name(prepared) -> None:
    run_case(prepared)
    binding = json.loads((prepared.engagement / "remediation/cases/1/session.json").read_text())
    prepared.rows[:] = [{"id": "other", "sessionId": "f715d449-0960-46cc-b875-a88e4abc71b2",
                        "cwd": str(prepared.repository), "name": f"vigil-{binding['session_id']}"}]
    with pytest.raises(SystemExit, match="absent"):
        run_case(prepared, command="join")


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


def test_join_progress_stops_before_native_terminal_handoff(prepared, monkeypatch):
    from vigil_cli import term
    run_case(prepared)
    events = []
    active = []
    class Progress:
        def update(self, message):
            events.append(message)
        def stop(self):
            active.clear()
    @contextmanager
    def activity(message, *, enabled=True):
        if enabled:
            active.append(True)
            events.append(message)
        try:
            yield Progress()
        finally:
            active.clear()
    monkeypatch.setattr(term, "activity", activity)
    run = prepared.module.subprocess.run
    def native(argv, **kwargs):
        if argv == ["claude", "attach", "job1"]:
            assert not active
        else:
            assert active
        return run(argv, **kwargs)
    monkeypatch.setattr(prepared.module.subprocess, "run", native)
    assert run_case(prepared, command="join") == 0
    assert any("workspace" in message.lower() for message in events)
    assert any("conversation" in message.lower() for message in events)


@pytest.mark.parametrize("query", ["capabilities", "inventory"])
def test_native_query_timeout_reports_actionable_error(prepared, monkeypatch, query):
    def stalled(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 0))
    monkeypatch.setattr(prepared.module.subprocess, "run", stalled)
    operation = prepared.module._claude_capabilities if query == "capabilities" else prepared.module._inventory
    with pytest.raises(SystemExit, match="[Tt]imed out"):
        operation()


def test_case_lock_wait_is_bounded(prepared):
    directory = prepared.engagement / "remediation/cases/1"
    with prepared.module._session_lock(directory):
        with pytest.raises(SystemExit, match="[Tt]imed out"):
            with prepared.module._session_lock(directory, timeout=0.01):
                pytest.fail("another operation owns the case lock")


def test_join_resolves_application_once_for_environment_and_workspace(prepared, monkeypatch):
    from vigil_cli import application
    from vigil_cli.remediation_vcs import adapter
    run_case(prepared)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "agent/scripts"))
    from assess.lib import remediation_vcs
    monkeypatch.setattr(remediation_vcs, "registered", lambda root, path: path == prepared.workspace)
    monkeypatch.setattr(remediation_vcs, "branch_matches", lambda path, branch: True)
    monkeypatch.setattr(prepared.module, "adapter", adapter)
    resolutions = []
    resolve = application.resolve_application_root
    def counted(*args, **kwargs):
        resolutions.append(True)
        return resolve(*args, **kwargs)
    monkeypatch.setattr(application, "resolve_application_root", counted)
    assert run_case(prepared, command="join") == 0
    assert len(resolutions) == 1


def test_failed_inventory_leaves_recorded_binding_unchanged(prepared, monkeypatch):
    run_case(prepared)
    path = prepared.engagement / "remediation/cases/1/session.json"
    original = path.read_bytes()
    prepared.calls.clear()
    run = prepared.module.subprocess.run
    def stalled(argv, **kwargs):
        if argv == ["claude", "agents", "--json", "--all"]:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return run(argv, **kwargs)
    monkeypatch.setattr(prepared.module.subprocess, "run", stalled)
    with pytest.raises(SystemExit, match="Timed out"):
        run_case(prepared, command="join")
    assert path.read_bytes() == original
    assert prepared.calls and all(call[0][1] in {"--version", "--help"} for call in prepared.calls)


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


def _bind_after_previous(prepared, state):
    prepared.project["remediation"]["hook_policy"] = "inherit"
    previous_id = "0d3f4a7e-5b8c-4c1d-9e2f-3a4b5c6d7e8f"
    session_id = "638131c5-4bcd-4a2f-898b-ecb1a5489638"
    prepared.rows.append({"id": "previous", "sessionId": previous_id, "cwd": str(prepared.repository), "state": state})
    run_case(prepared, bind=True, session_id=previous_id)
    prepared.rows.append({"id": "current", "sessionId": session_id, "cwd": str(prepared.repository), "state": "working"})
    return previous_id, session_id


def test_bind_offers_replacement_only_when_previous_conversation_stopped(prepared) -> None:
    previous_id, session_id = _bind_after_previous(prepared, "stopped")
    binding_path = prepared.engagement / "remediation/cases/1/session.json"
    with pytest.raises(SystemExit, match="--replace-stopped"):
        run_case(prepared, bind=True, session_id=session_id)
    assert json.loads(binding_path.read_text())["session_id"] == previous_id
    run_case(prepared, bind=True, session_id=session_id, replace_stopped=True)
    binding = json.loads(binding_path.read_text())
    assert (binding["session_id"], binding["job_id"], binding["replaced_session_id"]) == (session_id, "current", previous_id)


def test_replace_stopped_refuses_a_running_conversation(prepared) -> None:
    previous_id, session_id = _bind_after_previous(prepared, "working")
    binding_path = prepared.engagement / "remediation/cases/1/session.json"
    with pytest.raises(SystemExit, match="use join"):
        run_case(prepared, bind=True, session_id=session_id)
    with pytest.raises(SystemExit, match="still running"):
        run_case(prepared, bind=True, session_id=session_id, replace_stopped=True)
    assert json.loads(binding_path.read_text())["session_id"] == previous_id


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
    assert "This profile disables" in capsys.readouterr().out


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
