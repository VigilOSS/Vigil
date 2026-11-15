"""A fresh runtime keeps nuclei templates under the persistent /data mount.

The runtime container points nuclei at ``/data/nuclei-templates`` so templates
survive a recreate, and a start that finds none there begins downloading them
in the background with one line saying so; a failure to start that never
blocks the runtime.
"""
from __future__ import annotations

import pytest

from vigil_cli import docker, runtime, up


def _start(tmp_path, monkeypatch, *, exec_result):
    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **kw: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **kw: False)
    monkeypatch.setattr(runtime.docker, "container_exists", lambda *a, **kw: False)
    monkeypatch.setattr(runtime, "_host_memory_gb", lambda: None)
    monkeypatch.setattr(up, "_runtime_image_drift", lambda *a, **kw: False)
    for check in ("_validate_image_current", "_validate_mounts", "_validate_tools",
                  "_check_runtime_ulimits", "generate_subfinder_provider_config"):
        monkeypatch.setattr(runtime, check, lambda *a, **kw: None)
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[:2] == ["docker", "info"]:
            return docker.DockerResult(0, '{"MemTotal": 68719476736, "NCPU": 8}', "")
        if argv[:2] == ["docker", "exec"] and any("nuclei" in part for part in argv):
            return exec_result(argv)
        return docker.DockerResult(0, "", "")

    up._start_or_restart_runtime(
        tmp_path, False, False, up.UpOptions(install_root=tmp_path), runner=runner
    )
    return calls


def test_the_runtime_points_nuclei_at_the_persistent_data_mount(tmp_path, monkeypatch):
    calls = _start(tmp_path, monkeypatch, exec_result=lambda argv: docker.DockerResult(0, "present\n", ""))

    run = next(argv for argv in calls if argv[:2] == ["docker", "run"])
    index = run.index(f"NUCLEI_TEMPLATES_DIR={runtime.NUCLEI_TEMPLATES_DIR}")
    assert run[index - 1] == "-e"
    assert runtime.NUCLEI_TEMPLATES_DIR.startswith("/data/")


def test_present_templates_start_nothing_and_say_nothing(tmp_path, monkeypatch, capsys):
    calls = _start(tmp_path, monkeypatch, exec_result=lambda argv: docker.DockerResult(0, "present\n", ""))

    assert not any(argv[:3] == ["docker", "exec", "-d"] for argv in calls)
    assert "nuclei" not in capsys.readouterr().err


def test_missing_templates_start_a_background_download_and_say_so(tmp_path, monkeypatch, capsys):
    calls = _start(tmp_path, monkeypatch, exec_result=lambda argv: docker.DockerResult(0, "missing\n", ""))

    background = [argv for argv in calls if argv[:3] == ["docker", "exec", "-d"]]
    assert len(background) == 1 and "-update-templates" in " ".join(background[0])
    err = capsys.readouterr().err
    assert err.count("nuclei templates") == 1
    assert runtime.NUCLEI_TEMPLATES_DIR in err


@pytest.mark.parametrize("returncode", [1, docker.TIMEOUT_RETURNCODE])
def test_a_failed_template_check_warns_once_and_never_blocks(tmp_path, monkeypatch, capsys, returncode):
    _start(tmp_path, monkeypatch, exec_result=lambda argv: docker.DockerResult(returncode, "", "boom"))

    err = capsys.readouterr().err
    assert err.count("nuclei templates") == 1
    assert "--update-templates" in err
