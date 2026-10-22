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
