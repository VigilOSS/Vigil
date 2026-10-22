"""Real terminal/CLI launches with inert native executables, never a model or app."""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def launch_environment(tmp_path):
    missing = [name for name in ("uv", "bash", "jq", "node") if shutil.which(name) is None]
    if missing:
        pytest.skip("Native workspace prerequisites unavailable: " + ", ".join(missing))
    workspace = tmp_path / "private"
    workspace.mkdir()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    capture = tmp_path / "native.json"
    executable = (
        f"#!{sys.executable}\n"
        "import json, os, pathlib, sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('1.18.10')\n"
        "    raise SystemExit(0)\n"
        "context = os.environ.get('VIGIL_CLIENT_CONTEXT')\n"
        "row = {'argv': sys.argv[1:], 'cwd': os.getcwd(), 'context_path': context}\n"
        "if context:\n"
        "    row['binding'] = json.loads(pathlib.Path(context).read_text())\n"
        "pathlib.Path(os.environ['ACME_NATIVE_CAPTURE']).write_text(json.dumps(row))\n"
        "print('Acme inert native executable reached', flush=True)\n"
    )
    for name in ("opencode", "open"):
        path = binaries / name
        path.write_text(executable)
        path.chmod(0o755)
    environment = {
        "PATH": str(binaries) + os.pathsep + os.environ.get("PATH", os.defpath),
        "TERM": "dumb", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(ROOT / "src"), "VIGIL_APPLICATION_DIR": str(ROOT),
        "VIGIL_CONFIG": str(tmp_path / "config.json"),
        "VIGIL_APPLICATION_CACHE": str(tmp_path / "application-cache"),
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"), "UV_OFFLINE": "1",
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
        "XDG_CACHE_HOME": str(tmp_path / "cache"),
        "ORCHESTRATOR_BASE_URL": "http://127.0.0.1:9",
        "ACME_NATIVE_CAPTURE": str(capture),
    }
    return workspace, environment, capture


def engagement(workspace, key, *, dual=False, created="2026-01-01T00:00:00Z"):
    directory = workspace / "engagements" / key
    directory.mkdir(parents=True)
    tracks = {"web": {"phase": "recon"}}
    if dual:
        tracks["code"] = {"phase": "ingest"}
    (directory / "scope.json").write_text(json.dumps({
        "engagement_type": "offensive", "status": "in_progress", "tracks": tracks,
    }))
    (directory / "engagement.json").write_text(json.dumps({
        "target": "https://app.example.com", "created_at": created,
    }))
    return directory.resolve()


def terminal_run(argv, *, environment, cwd, answers):
    """Respond to actual prompts and reap only the child this test owns."""
    master, slave = pty.openpty()
    process = None
    transcript = bytearray()
    deadline = time.monotonic() + 20
    pending = iter(answers)
    next_answer = next(pending, None)
    consumed = 0
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment,
                                   stdin=slave, stdout=slave, stderr=slave,
                                   start_new_session=True)
        os.close(slave)
        slave = -1
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                pytest.fail("CLI terminal timed out:\n" + transcript.decode(errors="replace"))
            readable, _, _ = select.select([master], [], [], remaining)
            if not readable:
                continue
            try:
                output = os.read(master, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
            if not output:
                break
            transcript.extend(output)
            if next_answer is not None:
                prompt, answer = next_answer
                observed = transcript[consumed:].decode(errors="replace")
                if prompt in observed and observed.rstrip().endswith(">"):
                    os.write(master, (answer + "\n").encode())
                    consumed = len(transcript)
                    next_answer = next(pending, None)
        result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        rendered = transcript.decode(errors="replace")
        assert next_answer is None, rendered
        return result, rendered
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
        if slave != -1:
            os.close(slave)


def cli_argv(workspace, *arguments):
    return [sys.executable, "-m", "vigil_cli.main", "--root", str(workspace),
            "engagement", "start", *arguments, "--skip-preflight"]


@pytest.mark.parametrize("second_client", ["codex", "claude"])
def test_real_concurrent_shared_clients_retain_release_then_adopt_after_exit(launch_environment, tmp_path, second_client):
    from vigil_cli import client_sessions, engagements

    workspace, environment, _ = launch_environment
    selected = engagement(workspace, "acme", dual=True)
    releases = []
    for version in ("1.0.0", "2.0.0"):
        release = tmp_path / f"application-{version}"
        (release / "agent").mkdir(parents=True)
        (release / "orchestrator").mkdir()
        (release / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n')
        (release / "agent/AGENTS.md").write_text(f"Acme web prompt {version}\n")
        (release / "agent/operator-core-code.md").write_text(f"Acme code prompt {version}\n")
        releases.append(release)
    old, current = releases
    engagements._write_prompt_wrappers(old / "agent", selected, "claude", engagement_type="offensive", workspace_root=workspace)
    engagements._write_launchers(old / "agent", selected, "claude", skip_permissions=False, workspace_root=workspace)
    binaries = Path(environment["PATH"].split(os.pathsep)[0])
    helper = binaries / "vigil"
    helper.write_text(f'#!/bin/sh\nexec {sys.executable} -m vigil_cli.main "$@"\n')
    helper.chmod(0o755)
    for client in ("codex", "claude"):
        executable = binaries / client
        executable.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "row = {'application': os.environ['VIGIL_APPLICATION_DIR'], 'pid': os.getpid(),\n"
            "       'engagement': os.environ['VIGIL_SESSION_ENGAGEMENT_DIR'], 'mode': os.environ['VIGIL_OPERATOR_MODE']}\n"
            "pathlib.Path(os.environ['ACME_NATIVE_CAPTURE']).write_text(json.dumps(row))\n"
            "print('Acme shared client ready', flush=True)\n"
            "if os.environ.get('ACME_HOLD_CLIENT') == '1': sys.stdin.read(1)\n"
        )
        executable.chmod(0o755)
    first_capture = tmp_path / "first.json"
    first_environment = {**environment, "VIGIL_APPLICATION_DIR": str(old),
                         "ACME_HOLD_CLIENT": "1", "ACME_NATIVE_CAPTURE": str(first_capture)}
    first = subprocess.Popen(cli_argv(workspace, "acme", "--client", "claude", "--mode", "code", "--no-autoprompt"),
                             env=first_environment, cwd=selected, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert first.stdout is not None
        ready, _, _ = select.select([first.stdout], [], [], 20)
        assert ready, "First client did not reach its executable"
        assert first.stdout.readline().strip() == "Acme shared client ready"
        assert first.poll() is None
        first_row = json.loads(first_capture.read_text())
        shared_paths = [path for path in selected.rglob("*") if path.is_file()]
        original = {path: (path.read_bytes(), path.resolve()) for path in shared_paths}
        receipts = {path: path.read_bytes() for path in (workspace / "state/runtime/client-sessions").glob("*.json")}
        second_capture = tmp_path / "second.json"
        next_environment = {**environment, "VIGIL_APPLICATION_DIR": str(current),
                            "ACME_NATIVE_CAPTURE": str(second_capture)}
        result = subprocess.run(cli_argv(workspace, "acme", "--client", second_client, "--mode", "web", "--no-autoprompt"),
                                env=next_environment, cwd=selected, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert "Warning:" in result.stderr and f"PID {first.pid}" in result.stderr
        assert "retained release 1.0.0" in result.stderr
        second_row = json.loads(second_capture.read_text())
        assert second_row["application"] == first_row["application"] == str(old)
        assert second_row["mode"] == "web" and first_row["mode"] == "code"
        assert first_row["engagement"] == second_row["engagement"] == str(selected)
        assert first.poll() is None
        assert all((path.read_bytes(), path.resolve()) == contents for path, contents in original.items())
        assert all(path.read_bytes() == contents for path, contents in receipts.items())
        assert {row["pid"] for row in client_sessions.active_client_sessions(workspace)} == {first.pid}
        first.communicate(input="\n", timeout=5)
        adopted = subprocess.run(cli_argv(workspace, "acme", "--client", second_client, "--mode", "web", "--no-autoprompt"),
                                 env=next_environment, cwd=selected, stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=20)
        assert adopted.returncode == 0, adopted.stderr
        assert json.loads(second_capture.read_text())["application"] == str(current)
    finally:
        if first.poll() is None:
            first.kill()
        first.communicate(timeout=5)


@pytest.mark.parametrize("selection", ["dual", "single", "explicit", "switch", "prompted-client"])
def test_real_cli_opencode_selection_executes_bound_native_workspace(launch_environment, selection):
    workspace, environment, capture = launch_environment
    selected = engagement(workspace, "acme-selected", dual=selection in {"dual", "explicit"},
                          created="2026-02-01T00:00:00Z")
    ambient = selected if selection == "single" else engagement(workspace, "acme-ambient")
    environment["VIGIL_SESSION_ENGAGEMENT_DIR"] = str(ambient)
    environment["ENGAGEMENT_DIR"] = str(ambient)
    environment["VIGIL_OPERATOR_MODE"] = "web"
    Path(environment["VIGIL_CONFIG"]).write_text(json.dumps({"active_engagement_dir": str(ambient)}))
    arguments = [] if selection == "prompted-client" else ["--client", "opencode"]
    answers = []
    if selection == "explicit":
        arguments = [selected.name, *arguments, "--mode", "code"]
    else:
        answers.append(("Select engagement", "1"))
        if selection == "prompted-client":
            answers.append(("Select client", "3"))
        answers.append(("Select operator mode", "1" if selection == "single" else "2"))
    code, transcript = terminal_run(cli_argv(workspace, *arguments), environment=environment,
                                    cwd=ambient, answers=answers)
    assert code == 0, transcript
    assert "Acme inert native executable reached" in transcript
    if selection != "explicit":
        assert "Select engagement" in transcript
        assert "Create new engagement" in transcript
    else:
        assert "Select engagement" not in transcript
    mode = "web" if selection == "single" else "code"
    native = json.loads(capture.read_text())
    binding = native["binding"]
    context = Path(native["context_path"])
    assert binding["engagement_dir"] == str(selected)
    assert binding["mode"] == mode
    assert binding["native_version"] == "1.18.10"
    assert binding["backend_url"] == "http://127.0.0.1:9"
    project = selected / "clients/opencode" / mode
    assert Path(native["cwd"]) == project
    assert binding["project"] == str(project)
    descriptor = json.loads((project / ".vigil-client-project.json").read_text())
    assert (descriptor["engagement_dir"], descriptor["client"], descriptor["mode"]) == (
        str(selected), "opencode", mode)
    selection_row = json.loads((project / ".vigil-current-context.json").read_text())
    assert selection_row["binding_path"] == str(context)
    assert context.parent.parent.parent == selected / "client-context"
    assert native["argv"][:2] == ["--agent", "operator"]
    assert "--prompt" in native["argv"]
    assert os.access(binding["vigil_cli"], os.X_OK)
    assert (context.parent / "AGENTS.md").is_file()
    assert (context.parent / ".opencode/plugins/vigil-assessment.js").is_file()
    config = json.loads((context.parent / ".opencode/opencode.json").read_text())
    assert config["instructions"] == [str(project / "AGENTS.md")]
    assert (project / "AGENTS.md").is_file()
    assert (context.parent / ".opencode/vigil-assessment-runtime.mjs").is_file()
    markers = [json.loads(path.read_text()) for path in
               (workspace / "state/runtime/client-launches").glob("*.json")]
    assert [(row["event"], row["client"], row["mode"], row["engagement"]) for row in markers] == [
        ("launch_requested", "opencode", mode, str(selected)),
    ]


@pytest.mark.parametrize("explicit", [False, True])
def test_real_noninteractive_cli_requires_selection_before_launch(launch_environment, explicit):
    workspace, environment, capture = launch_environment
    selected = engagement(workspace, "acme", dual=True)
    environment["VIGIL_SESSION_ENGAGEMENT_DIR"] = str(selected)
    arguments = ([selected.name] if explicit else []) + ["--client", "opencode"]
    result = subprocess.run(cli_argv(workspace, *arguments), env=environment, cwd=selected,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert ("--mode" if explicit else "explicit engagement key") in result.stderr
    assert not capture.exists()


def test_real_zcode_selection_materializes_workspace_and_records_only_open_intent(launch_environment, tmp_path):
    workspace, environment, capture = launch_environment
    selected = engagement(workspace, "acme", dual=True)
    application = tmp_path / "Acme-ZCode.app"
    application.mkdir()
    # Discovery alone is substituted: the real selection, preparation and opener run.
    script = (
        "from pathlib import Path; import sys; "
        "from vigil_cli import remediation_clients; "
        f"remediation_clients._zcode_application=lambda: (Path({str(application)!r}), '3.15.3'); "
        "from vigil_cli.main import main; main(sys.argv[1:])"
    )
    argv = [sys.executable, "-c", script, *cli_argv(workspace, "--client", "zcode")[3:]]
    code, transcript = terminal_run(argv, environment=environment, cwd=selected,
                                    answers=[("Select engagement", "1"), ("Select operator mode", "2")])
    assert code == 0, transcript
    opened = json.loads(capture.read_text())
    context = Path(opened["argv"][-1])
    assert opened["argv"][:2] == ["-a", str(application)]
    assert context == selected / "clients/zcode/code"
    descriptor = json.loads((context / ".vigil-client-project.json").read_text())
    assert (descriptor["engagement_dir"], descriptor["client"], descriptor["mode"]) == (
        str(selected), "zcode", "code")
    selection = json.loads((context / ".vigil-current-context.json").read_text())
    snapshot = Path(selection["binding_path"]).parent
    assert snapshot.parent.parent == selected / "client-context"
    binding = json.loads(Path(selection["binding_path"]).read_text())
    assert binding["engagement_dir"] == str(selected)
    assert binding["mode"] == "code"
    assert os.access(binding["vigil_cli"], os.X_OK)
    assert (context / "AGENTS.md").is_file()
    assert (context / "plugin/marketplace.json").is_file()
    assert (snapshot / "AGENTS.md").is_file()
    assert binding["workspace"] == str(snapshot)
    assert binding["project"] == str(context)
    markers = [json.loads(path.read_text()) for path in
               (workspace / "state/runtime/client-launches").glob("*.json")]
    assert [(row["event"], row["client"], row["mode"]) for row in markers] == [
        ("workspace_opened", "zcode", "code"),
    ]
    assert list((workspace / "state/runtime/client-sessions").glob("*.json")) == []
