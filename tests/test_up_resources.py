"""Consumer contracts for resource checks and safe stack startup."""
import io
import json
import subprocess
import sys
from contextlib import redirect_stdout

import pytest

from rich.console import Console
from vigil_cli import config, docker, runtime, up
from vigil_cli import main as cli
from vigil_cli import orchestrator
from vigil_cli.main import main


def capacity_runner(gib, cpus=8, neighbors=()):
    def run(argv, **kwargs):
        if argv[:2] == ["docker", "info"]:
            return docker.DockerResult(0, json.dumps({"MemTotal": gib * 1024**3, "NCPU": cpus}), "")
        if argv[:2] == ["docker", "ps"]:
            return docker.DockerResult(0, "\n".join(neighbors), "")
        return docker.DockerResult(0, "", "")
    return run


def test_default_runtime_limits(monkeypatch):
    monkeypatch.delenv("VIGIL_RUNTIME_MEMORY_GB", raising=False)
    monkeypatch.delenv("VIGIL_RUNTIME_CPUS", raising=False)
    limits = config.runtime_resources()
    assert (limits.memory_gb, limits.cpus) == (2, 1)


@pytest.mark.parametrize("recreate", [False, True])
@pytest.mark.parametrize("memory_gib", [7, 8, 16])
def test_high_memory_limit_warns_and_allows_startup(tmp_path, capsys, monkeypatch, recreate, memory_gib):
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    runtime._preflight_shared_vm(config.RuntimeResources(memory_gib, 1, 512, "1g"),
        runtime.RuntimeOptions(install_root=tmp_path, recreate=recreate), runner=capacity_runner(8))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert f"{memory_gib} GiB" in captured.err
    assert "8.0 GiB" in captured.err
    assert "Starting anyway" in captured.err
    assert "VIGIL_RUNTIME_MEMORY_GB" in captured.err


def test_memory_warning_uses_rich_terminal_style(tmp_path, monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(runtime.sys, "stderr", stream)
    monkeypatch.setattr(runtime.term, "console", lambda output: Console(
        file=output, force_terminal=True, color_system="standard", width=120))
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    runtime._preflight_shared_vm(config.RuntimeResources(6, 1, 512, "1g"),
        runtime.RuntimeOptions(install_root=tmp_path), runner=capacity_runner(8))
    assert "\x1b[" in stream.getvalue()
    assert "Docker memory headroom" in stream.getvalue()


def test_runtime_restart_preserves_container_on_startup_refusal(monkeypatch, tmp_path):
    removals = []
    monkeypatch.setattr(cli, "stop_runtime", lambda: removals.append("removed"))
    monkeypatch.setattr(cli, "start_runtime", lambda *a, **kw: (_ for _ in ()).throw(SystemExit("capacity refused")))
    with pytest.raises(SystemExit, match="capacity refused"):
        main(["--root", str(tmp_path), "runtime", "restart"])
    assert removals == []


@pytest.mark.parametrize("neighbors", [(), ("acme-db", "vigil-proxy")])
def test_ample_capacity_is_quiet_even_with_neighbors(tmp_path, capsys, monkeypatch, neighbors):
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    runtime._preflight_shared_vm(config.RuntimeResources(2, 1, 512, "1g"),
        runtime.RuntimeOptions(install_root=tmp_path), runner=capacity_runner(64, neighbors=neighbors))
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_resource_warning_is_stderr_and_describes_a_limit(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    runtime._preflight_shared_vm(config.RuntimeResources(6, 1, 512, "1g"),
        runtime.RuntimeOptions(install_root=tmp_path), runner=capacity_runner(8))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "limit" in captured.err
    assert "75%" in captured.err


@pytest.mark.parametrize("failure", [False, True])
def test_up_json_is_one_result_on_success_or_failure(monkeypatch, tmp_path, capsys, failure):
    monkeypatch.setattr(up, "resolve_application_root", lambda *a, **kw: tmp_path)
    monkeypatch.setattr(up, "initialize_workspace", lambda *a, **kw: None)
    def start(*args, **kwargs):
        print("lower-level progress")
        if failure:
            raise SystemExit("capacity refused")
    monkeypatch.setattr(up, "_start_stack", start)
    monkeypatch.setattr(cli, "run_up", up.run_up)
    if failure:
        with pytest.raises(SystemExit) as exc:
            main(["--root", str(tmp_path), "up", "--json"])
        assert exc.value.code == 1
    else:
        main(["--root", str(tmp_path), "up", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == ("error" if failure else "ready")
    assert "lower-level progress" in captured.err
    if failure:
        assert payload["error"]["message"] == "capacity refused"


@pytest.mark.parametrize("action", ["_npm_ci", "_build_frontend", "_build_report"])
def test_ui_build_output_follows_progress_stream(monkeypatch, tmp_path, capfd, action):
    real_run = subprocess.run
    def emit_build_output(argv, **kwargs):
        return real_run([sys.executable, "-c", "print('acme build progress')"],
            stdout=kwargs.get("stdout"), check=True)
    monkeypatch.setattr(orchestrator.subprocess, "run", emit_build_output)
    monkeypatch.setattr(orchestrator, "_require_editable_build", lambda root: None)
    monkeypatch.setattr(orchestrator.restart_manifest, "record_frontend_build", lambda root: None)
    monkeypatch.setattr(orchestrator.restart_manifest, "record_report_build", lambda root: None)
    with redirect_stdout(sys.stderr):
        getattr(orchestrator, action)(tmp_path)
    captured = capfd.readouterr()
    assert captured.out == ""
    assert "acme build progress" in captured.err


@pytest.mark.parametrize("error", [OSError("acme build unavailable"), subprocess.CalledProcessError(1, ["npm", "run", "build"])])
def test_up_json_reports_process_failures(monkeypatch, tmp_path, capsys, error):
    monkeypatch.setattr(up, "resolve_application_root", lambda *a, **kw: tmp_path)
    monkeypatch.setattr(up, "initialize_workspace", lambda *a, **kw: None)
    monkeypatch.setattr(up, "_start_stack", lambda *a, **kw: (_ for _ in ()).throw(error))
    with pytest.raises(SystemExit) as exc:
        up.run_up(up.UpOptions(install_root=tmp_path, json_output=True))
    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["error"]["message"] == str(error)


@pytest.mark.parametrize("recreate", [False, True])
def test_up_starts_runtime_with_high_memory_limit(tmp_path, monkeypatch, capsys, recreate):
    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "16")
    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **kw: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **kw: recreate)
    monkeypatch.setattr(runtime.docker, "container_exists", lambda *a, **kw: recreate)
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    monkeypatch.setattr(up, "_runtime_image_drift", lambda *a, **kw: recreate)
    for check in ("_validate_image_current", "_validate_mounts", "_validate_tools",
                  "_check_runtime_ulimits", "generate_subfinder_provider_config"):
        monkeypatch.setattr(runtime, check, lambda *a, **kw: None)
    calls = []
    base_runner = capacity_runner(8)
    def runner(argv, **kwargs):
        calls.append(argv)
        return base_runner(argv, **kwargs)
    state = up._start_or_restart_runtime(tmp_path, recreate, False,
        up.UpOptions(install_root=tmp_path, yes_restart_runtime=True), runner=runner)
    assert state == "running"
    run = next(argv for argv in calls if argv[:2] == ["docker", "run"])
    assert "--memory=16g" in run
    assert "Starting anyway" in capsys.readouterr().err
