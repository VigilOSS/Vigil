"""Consumer contracts for resource checks and safe stack startup."""
import json
import subprocess
import sys
from contextlib import redirect_stdout

import pytest

from vigil_cli import config, docker, runtime, up
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


def test_up_override_reaches_runtime(monkeypatch, tmp_path):
    from vigil_cli import main as cli
    calls = []
    monkeypatch.setattr(cli, "run_up", lambda options, **kw: calls.append(options))
    main(["--root", str(tmp_path), "up", "--allow-oversubscribe"])
    assert calls[0].allow_oversubscribe is True


def test_up_restart_preserves_running_container_when_capacity_refuses(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setattr(up, "_runtime_image_drift", lambda *a, **kw: True)
    monkeypatch.setattr(runtime.docker, "image_exists", lambda *a, **kw: True)
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **kw: True)
    removals = []
    base_runner = capacity_runner(8)
    def runner(argv, **kw):
        if argv[:3] == ["docker", "ps", "-a"]:
            return docker.DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "rm", "-f"]:
            removals.append(argv)
        return base_runner(argv, **kw)
    with pytest.raises(SystemExit):
        up._start_or_restart_runtime(tmp_path, True, False, up.UpOptions(
            install_root=tmp_path, yes_restart_runtime=True), runner=runner)
    assert removals == []


def test_runtime_restart_preserves_container_on_startup_refusal(monkeypatch, tmp_path):
    from vigil_cli import main as cli
    removals = []
    monkeypatch.setattr(cli, "stop_runtime", lambda: removals.append("removed"))
    monkeypatch.setattr(cli, "start_runtime", lambda *a, **kw: (_ for _ in ()).throw(SystemExit("capacity refused")))
    with pytest.raises(SystemExit, match="capacity refused"):
        main(["--root", str(tmp_path), "runtime", "restart"])
    assert removals == []


def test_memory_refusal_gives_effective_recovery(tmp_path):
    with pytest.raises(SystemExit) as exc:
        runtime._preflight_shared_vm(config.RuntimeResources(8, 4, 512, "1g"),
            runtime.RuntimeOptions(install_root=tmp_path), runner=capacity_runner(8))
    assert "VIGIL_RUNTIME_MEMORY_GB=6 vigil up" in str(exc.value)
    assert "vigil up --allow-oversubscribe" in str(exc.value)


def test_restart_refusal_recovery_applies_limits_to_existing_container(tmp_path):
    with pytest.raises(SystemExit) as exc:
        runtime._preflight_shared_vm(config.RuntimeResources(8, 4, 512, "1g"),
            runtime.RuntimeOptions(install_root=tmp_path, recreate=True), runner=capacity_runner(8))
    assert "VIGIL_RUNTIME_MEMORY_GB=6 vigil runtime start --recreate" in str(exc.value)
    assert "vigil runtime start --recreate --allow-oversubscribe" in str(exc.value)


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
    from vigil_cli import main as cli
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
    from vigil_cli import orchestrator
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
