from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from vigil_cli import orchestrator


@pytest.fixture
def isolated_launch(tmp_path, monkeypatch):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator/backend").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setenv("UV_PYTHON", sys.executable)
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "unrelated-cli"))
    monkeypatch.setattr(orchestrator, "_frontend_build_needed", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orchestrator, "_report_build_needed", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(orchestrator, "_check_port_available", lambda *_args: None)
    monkeypatch.setattr(orchestrator.os, "chdir", lambda _: None)
    return application, workspace


def test_backend_launch_uses_real_uv_interface_without_installing_or_mutating_project(isolated_launch, monkeypatch):
    application, workspace = isolated_launch
    uv = shutil.which("uv")
    assert uv is not None, "uv is a required repository/runtime prerequisite"
    backend = application / "orchestrator/backend"
    package = application / "src/vigil_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("RELEASE_MARKER = 'ACME_BACKEND_READY'\n")
    (backend / "pyproject.toml").write_text(
        '[project]\nname = "acme-synthetic-backend"\nversion = "0.0.0"\n'
        'requires-python = ">=3.11"\ndependencies = []\n'
    )
    real_run = subprocess.run
    real_run([uv, "lock", "--offline", "--python", sys.executable, "--directory", str(backend)],
             env=os.environ.copy(), check=True, capture_output=True, text=True, timeout=30)
    before = {path.relative_to(application): path.read_bytes() for path in application.rglob("*") if path.is_file()}
    launched = []

    class ExecIntercepted(Exception):
        pass

    def launch(_command, argv, env):
        prefix = argv[:argv.index("python")]
        completed = real_run(
            [*prefix, "python", "-c", "from vigil_cli import RELEASE_MARKER; print(RELEASE_MARKER)"], cwd=application,
            env=env, capture_output=True, text=True, timeout=30,
        )
        launched.append((completed, env))
        raise ExecIntercepted

    monkeypatch.setattr(orchestrator.os, "execvpe", launch)
    with pytest.raises(ExecIntercepted):
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(workspace, foreground=True))
    completed, env = launched[0]
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ACME_BACKEND_READY"
    assert Path(env["UV_PROJECT_ENVIRONMENT"]).is_relative_to(workspace / "cache")
    assert (Path(env["UV_PROJECT_ENVIRONMENT"]) / "bin/python").is_file()
    assert {path.relative_to(application): path.read_bytes() for path in application.rglob("*") if path.is_file()} == before
    assert not (backend / ".venv").exists()
    assert not list(application.rglob("*.egg-info"))


@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_backend_sync_failure_is_actionable_and_never_launches_service(isolated_launch, monkeypatch, failure):
    application, workspace = isolated_launch
    launched = []

    def failed_sync(argv, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))
        raise subprocess.CalledProcessError(9, argv)

    monkeypatch.setattr(orchestrator.subprocess, "run", failed_sync)
    def intercepted_launch(*_args):
        launched.append(True)
        raise SystemExit("test intercepted backend launch")

    monkeypatch.setattr(orchestrator.os, "execvpe", intercepted_launch)
    with pytest.raises(SystemExit) as error:
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(workspace, foreground=True))
    assert launched == []
    assert "synchroniz" in str(error.value) or "dependenc" in str(error.value)
    assert not (workspace / "state/runtime/pids/orchestrator.pid").exists()
    assert not (application / "orchestrator/backend/.venv").exists()


@pytest.mark.parametrize("layout", ["src", "cli"])
def test_backend_environment_prepends_matched_cli_and_preserves_inherited_pythonpath(isolated_launch, monkeypatch, layout):
    application, workspace = isolated_launch
    package = application / layout / "vigil_cli"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# synthetic matched CLI snapshot\n")
    inherited = os.environ["PYTHONPATH"]
    observed = []

    class ExecIntercepted(Exception):
        pass

    def launch(_command, _argv, env):
        observed.append(env)
        raise ExecIntercepted

    monkeypatch.setattr(orchestrator, "_sync_backend_environment", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orchestrator.os, "execvpe", launch)
    with pytest.raises(ExecIntercepted):
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(workspace, foreground=True))
    assert observed[0]["PYTHONPATH"].split(os.pathsep) == [str(application / layout), inherited]


def test_health_and_readiness_share_one_startup_budget(isolated_launch, monkeypatch, capsys):
    from types import SimpleNamespace

    _application, workspace = isolated_launch
    now = {"value": 0.0}
    budgets = []
    monkeypatch.setenv("VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS", "600")
    monkeypatch.setattr(orchestrator.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(orchestrator, "_sync_backend_environment", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(orchestrator.subprocess, "Popen", lambda *_args, **_kwargs: SimpleNamespace(pid=1234))

    def health(*_args, **kwargs):
        budgets.append(kwargs.get("timeout"))
        now["value"] = 90.0
        return True

    def readiness(*_args, **kwargs):
        budgets.append(kwargs.get("timeout"))
        return True

    monkeypatch.setattr(orchestrator, "_wait_for_health", health)
    monkeypatch.setattr(orchestrator, "_wait_for_readiness", readiness)
    orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(workspace))
    assert budgets == [600.0, 510.0]
    output = capsys.readouterr().out
    assert "600" in output
    assert "logs" in output or "orchestrator.log" in output
