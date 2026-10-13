"""Execution first-use starts only the managed runtime, never other containers."""
from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

from assess.lib import kali_runtime_exec
from assess.lib.client import AssessError


@pytest.fixture(autouse=True)
def _matched_cli_source(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[4] / 'src'))


def test_first_execution_starts_managed_runtime_once(tmp_path, monkeypatch, capsys):
    from vigil_cli import runtime
    running = False
    started = []
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv("VIGIL_RUNTIME_CONTAINER", "vigil")
    def start(options, **kwargs):
        nonlocal running
        assert 'Preparing the testing environment' in capsys.readouterr().err
        started.append((options, kwargs))
        running = True
    monkeypatch.setattr(runtime, "start_runtime", start)
    monkeypatch.setattr(kali_runtime_exec.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="vigil\n" if running else "", stderr=""))
    kali_runtime_exec._check_container_running("vigil")
    kali_runtime_exec._check_container_running("vigil")
    assert len(started) == 1
    assert started[0][0].install_root == tmp_path
    assert started[0][0].recreate is False
    assert started[0][1]["allow_existing"] is True
    assert 'ready' in capsys.readouterr().err


def test_running_managed_runtime_is_validated_against_this_install(tmp_path, monkeypatch):
    """A same-named container from another Vigil install is not safe to reuse."""
    from vigil_cli import runtime

    validated = []
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv("VIGIL_RUNTIME_CONTAINER", "vigil")
    monkeypatch.setattr(
        runtime,
        "start_runtime",
        lambda options, **kwargs: validated.append((options, kwargs)),
    )
    monkeypatch.setattr(
        kali_runtime_exec.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="vigil\n", stderr=""),
    )

    kali_runtime_exec._check_container_running("vigil")
    kali_runtime_exec._check_container_running("vigil")

    assert len(validated) == 1
    assert validated[0][0].install_root == tmp_path
    assert validated[0][1]["allow_existing"] is True


def test_cached_managed_runtime_is_revalidated_after_it_stops(tmp_path, monkeypatch):
    from vigil_cli import runtime

    state = {"running": True, "generation": 1}
    validated = []
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(tmp_path))
    monkeypatch.setenv("VIGIL_RUNTIME_CONTAINER", "vigil")

    def start(options, **kwargs):
        validated.append((options, kwargs))
        state["running"] = True
        state["generation"] += 1

    def run(argv, **_kwargs):
        if argv[1] == "ps":
            return SimpleNamespace(
                returncode=0,
                stdout="vigil\n" if state["running"] else "",
                stderr="",
            )
        if argv[1] == "inspect":
            return SimpleNamespace(
                returncode=0,
                stdout=f"container-{state['generation']}\n",
                stderr="",
            )
        raise AssertionError(argv)

    monkeypatch.setattr(runtime, "start_runtime", start)
    monkeypatch.setattr(kali_runtime_exec.subprocess, "run", run)

    kali_runtime_exec._check_container_running("vigil")
    state["running"] = False
    kali_runtime_exec._check_container_running("vigil")

    assert len(validated) == 2


def test_explicit_external_container_is_never_created_or_replaced(monkeypatch):
    from vigil_cli import runtime
    monkeypatch.setenv("VIGIL_RUNTIME_CONTAINER", "vigil")
    monkeypatch.setattr(runtime, "start_runtime", lambda *a, **k: pytest.fail("must not manage an external container"))
    monkeypatch.setattr(kali_runtime_exec.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    with pytest.raises(AssessError, match="acme-runtime"):
        kali_runtime_exec._check_container_running("acme-runtime")


@pytest.mark.parametrize('detail', ['Docker Desktop is paused', 'Cannot connect to the Docker daemon'])
def test_unavailable_docker_explains_how_to_retry_same_execution(monkeypatch, detail):
    monkeypatch.setattr(kali_runtime_exec.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1, stdout='', stderr=detail))
    with pytest.raises(AssessError) as error:
        kali_runtime_exec._check_container_running('vigil')
    assert detail in str(error.value)
    assert 'unpause Docker' in str(error.value)
    assert 'retry this command' in str(error.value)


def test_detached_job_finishes_after_its_launching_client_exits(tmp_path):
    """Execute the actual worker wrapper after its host launcher has exited."""
    import os
    import shlex
    import signal
    import socket
    import subprocess
    import sys
    from assess.lib.kali_jobs import _build_job_wrapper

    import tempfile
    from pathlib import Path
    socket_directory = tempfile.TemporaryDirectory(prefix="vigil-job-", dir="/tmp")
    address = str(Path(socket_directory.name) / "worker.sock")
    stdout = tmp_path / "job.out"
    stderr = tmp_path / "job.err"
    marker = tmp_path / "job.exit"
    worker = (
        "import socket; s=socket.socket(socket.AF_UNIX); "
        f"s.connect({address!r}); s.sendall(b'ready'); s.recv(1); "
        "print('Acme completed'); s.close()"
    )
    finished = (
        "import socket; s=socket.socket(socket.AF_UNIX); "
        f"s.connect({address!r}); s.sendall(b'finished'); s.close()"
    )
    wrapper = _build_job_wrapper(
        shlex.join([sys.executable, "-c", worker]), stdout_path=str(stdout),
        stderr_path=str(stderr), exit_path=str(marker), pid_file=str(tmp_path / "job.pid"),
    ) + "; " + shlex.join([sys.executable, "-c", finished])
    launcher = (
        "import subprocess,sys; p=subprocess.Popen(['sh','-c',sys.argv[1]], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL, "
        "start_new_session=True); print(p.pid)"
    )
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(address)
        listener.listen(2)
        listener.settimeout(5)
        launched = subprocess.run([sys.executable, "-c", launcher, wrapper], capture_output=True, text=True, check=True, timeout=5)
        pid = int(launched.stdout)
        try:
            # The launching process has already exited successfully. The tool
            # remains alive and only proceeds when this new client permits it.
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                assert connection.recv(20) == b"ready"
                connection.sendall(b"x")
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                assert connection.recv(20) == b"finished"
            assert marker.read_text() == "0"
            assert stdout.read_text() == "Acme completed\n"
        finally:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            socket_directory.cleanup()
