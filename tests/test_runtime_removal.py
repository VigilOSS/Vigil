from __future__ import annotations

import pytest

from vigil_cli import docker, runtime


def test_stop_runtime_reports_failed_removal():
    def runner(argv):
        if argv[:2] == ['docker', 'ps']:
            return docker.DockerResult(0, 'vigil\n', '')
        return docker.DockerResult(1, '', 'permission denied')
    with pytest.raises(SystemExit, match='permission denied'):
        runtime.stop_runtime('vigil', runner=runner)


def test_runtime_recreation_stops_before_start_when_removal_fails(tmp_path, monkeypatch):
    from vigil_cli import runtime_images

    monkeypatch.setattr(runtime_images, 'ensure_runtime_image', lambda *a, **kw: None)
    monkeypatch.setattr(runtime.docker, 'daemon_status', lambda **kw: docker.DaemonStatus(True, False, ''))
    monkeypatch.setattr(runtime.docker, 'image_exists', lambda *a, **kw: True)
    monkeypatch.setattr(runtime.docker, 'container_running', lambda *a, **kw: False)
    monkeypatch.setattr(runtime.docker, 'container_exists', lambda *a, **kw: True)
    monkeypatch.setattr(runtime, '_preflight_shared_vm', lambda *a, **kw: None)
    calls = []
    def runner(argv):
        calls.append(argv)
        return docker.DockerResult(1, '', 'remove denied') if argv[:3] == ['docker', 'rm', '-f'] else docker.DockerResult(0, '', '')
    with pytest.raises(SystemExit, match='remove denied'):
        runtime.start_runtime(runtime.RuntimeOptions(install_root=tmp_path, recreate=True), runner=runner, validate_tools=False)
    assert not any(argv[:2] == ['docker', 'run'] for argv in calls)
