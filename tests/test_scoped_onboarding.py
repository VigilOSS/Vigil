"""Task-specific setup and registered-source intake behavior."""
from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from vigil_cli import engagements, preflight


@pytest.fixture(autouse=True)
def _isolate_service_locks(tmp_path, monkeypatch):
    from vigil_cli import service_locks

    monkeypatch.setattr(service_locks, '_application_cache', lambda: tmp_path / 'service-cache')


def test_registered_source_is_selected_without_creating_a_staging_copy(tmp_path, monkeypatch):
    origin = tmp_path / "acme"
    origin.mkdir()
    (origin / "parser.py").write_text("print('Acme')\n")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    monkeypatch.setattr(engagements, "_install_client_kind", lambda *_: "both")
    options = engagements.CreateEngagementOptions(install_root=tmp_path / "workspace", engagement_type="code", name="Acme", source_dir=origin)
    created = engagements.create_engagement(options, contact_backend=False)
    manifest = json.loads((created.path / "engagement.json").read_text())
    assert manifest.get("source_dir") == str(origin.resolve())
    assert list((created.path / "source").iterdir()) == []
    source = engagements.engagement_source_state(created.path)
    assert source["path"] == str(origin.resolve())
    assert source["state"] == "present"
    assert source["file_count"] == 1
    assert (origin / "parser.py").read_text() == "print('Acme')\n"
    (origin / "parser.py").unlink()
    origin.rmdir()
    assert engagements.engagement_source_state(created.path)["state"] == "unavailable"


def test_code_session_preflight_does_not_query_docker(tmp_path, monkeypatch):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text(json.dumps({"engagement_type": "offensive", "tracks": {"code": {"phase": "hunt"}}}))
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "orchestrator_status", lambda _: "running")
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(preflight, "runtime_status", lambda: pytest.fail("static session must not query Docker"))
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    preflight._preflight_engagement_start(tmp_path, engagement, "codex")


def test_session_recovers_only_managed_local_backend(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "orchestrator_status", lambda _: "stopped")
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    started = []
    monkeypatch.setattr(orchestrator, "start_orchestrator", lambda options: started.append(options))
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    preflight._preflight_engagement_start(tmp_path, engagement, "codex")
    assert len(started) == 1
    assert started[0].allow_existing is True
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "https://orchestrator.example.com")
    preflight._preflight_engagement_start(tmp_path, engagement, "codex")
    assert len(started) == 1


def test_failed_managed_backend_recovery_refuses_launch(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "orchestrator_status", lambda _: "stopped")
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    monkeypatch.setattr(orchestrator, "start_orchestrator", lambda _: None)
    monkeypatch.setattr(engagements, "_verify_backend_install_root", lambda *_: engagements.BackendInstallRootStatus.UNREACHABLE)
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    with pytest.raises(SystemExit, match="backend"):
        preflight._preflight_engagement_start(tmp_path, engagement, "codex")


def test_explicit_remote_backend_outage_warns_without_blocking_local_launch(tmp_path, monkeypatch, capsys):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    monkeypatch.setattr(
        engagements,
        "_verify_backend_install_root",
        lambda *_: engagements.BackendInstallRootStatus.UNREACHABLE,
    )
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "https://orchestrator.example.com")

    preflight._preflight_engagement_start(tmp_path, engagement, "codex")

    assert "unreachable" in capsys.readouterr().err.lower()


def test_transient_backend_sync_failure_warns_without_blocking_launch(tmp_path, monkeypatch, capsys):
    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "orchestrator_status", lambda _: "running")
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    monkeypatch.setattr(
        engagements,
        "_verify_backend_install_root",
        lambda *_: engagements.BackendInstallRootStatus.SYNC_PENDING,
    )

    preflight._preflight_engagement_start(tmp_path, engagement, "codex")

    assert "sync" in capsys.readouterr().err.lower()


@pytest.mark.parametrize(
    ('status_code', 'body'),
    [
        (500, '{}'),
        (404, '{}'),
        (200, '{malformed'),
        (200, '[]'),
        (200, '{}'),
        (200, '{"install_root":""}'),
    ],
    ids=[
        'admin-http-error',
        'legacy-admin-unsupported',
        'malformed-admin-json',
        'non-object-admin-json',
        'missing-install-root',
        'blank-install-root',
    ],
)
def test_reachable_remote_backend_protocol_error_refuses_launch(
    tmp_path, monkeypatch, status_code, body
):
    import http.client

    engagement = tmp_path / "acme"
    engagement.mkdir()
    (engagement / "scope.json").write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, "which", lambda _: "/bin/acme")
    monkeypatch.setattr(preflight, "_warn_if_install_stale", lambda _: None)
    monkeypatch.setattr(preflight, "_ensure_backend_freshness", lambda *a: None)
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://orchestrator.example.com")

    class Response:
        status = status_code

        def read(self):
            return body.encode()

    class Connection:
        def __init__(self, *_args, **_kwargs):
            pass

        def request(self, *_args, **_kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(http.client, 'HTTPConnection', Connection)

    with pytest.raises(SystemExit, match='backend is not ready'):
        preflight._preflight_engagement_start(tmp_path, engagement, "codex")


def test_concurrent_backend_starts_share_one_process(tmp_path, monkeypatch):
    """Second engagement waits for startup rather than racing the PID write."""
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from types import SimpleNamespace
    from vigil_cli import orchestrator

    first_at_port = threading.Event()
    second_at_port = threading.Event()
    release = threading.Event()
    port_checks = []
    launches = []
    monkeypatch.setattr(orchestrator, "application_root_for_workspace", lambda _: tmp_path)
    monkeypatch.setattr(orchestrator, "_frontend_build_needed", lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, "_report_build_needed", lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda _: "acme-birth")
    monkeypatch.setattr(orchestrator, "_sync_backend_environment", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_wait_for_health", lambda *a, **k: True)
    monkeypatch.setattr(orchestrator, "_wait_for_readiness", lambda *a, **k: True)
    monkeypatch.setattr(orchestrator.subprocess, "Popen", lambda *a, **k: launches.append(a) or SimpleNamespace(pid=42))

    def port_check(*_):
        port_checks.append(True)
        if len(port_checks) == 1:
            first_at_port.set()
            assert release.wait(3)
        else:
            second_at_port.set()

    monkeypatch.setattr(orchestrator, "_check_port_available", port_check)
    options = orchestrator.OrchestratorOptions(install_root=tmp_path, allow_existing=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(orchestrator.start_orchestrator, options)
        assert first_at_port.wait(3)
        second = pool.submit(orchestrator.start_orchestrator, options)
        try:
            assert not second_at_port.wait(0.2), "another engagement raced the backend startup"
        finally:
            release.set()
        first.result()
        second.result()
    assert len(launches) == 1


def test_runtime_start_resolves_default_image_on_demand_without_capture(tmp_path, monkeypatch):
    from vigil_cli import docker, runtime, runtime_images
    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **_: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "image_exists", lambda *a, **k: False)
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **k: False)
    monkeypatch.setattr(runtime.docker, "container_exists", lambda *a, **k: False)
    resolved = []
    def image(*args, **kwargs):
        resolved.append(args[0])
        raise SystemExit("Acme image resolved")
    monkeypatch.setattr(runtime_images, "ensure_runtime_image", image)
    with pytest.raises(SystemExit, match="Acme image resolved"):
        runtime.start_runtime(runtime.RuntimeOptions(install_root=tmp_path), validate_tools=False)
    assert resolved == [tmp_path]


def test_stopped_runtime_refreshes_an_existing_stale_release_image_before_start(tmp_path, monkeypatch):
    from vigil_cli import docker, runtime, runtime_images

    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **_: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "image_exists", lambda *a, **k: True)
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **k: False)
    monkeypatch.setattr(runtime.docker, "container_exists", lambda *a, **k: False)
    prepared = []

    def refresh(*args, **kwargs):
        prepared.append(args[0])
        raise SystemExit("Acme matched runtime prepared")

    monkeypatch.setattr(runtime_images, "ensure_runtime_image", refresh)
    monkeypatch.setattr(runtime, "_preflight_shared_vm", lambda *a, **k: pytest.fail("stale image reached container startup"))
    with pytest.raises(SystemExit, match="Acme matched runtime prepared"):
        runtime.start_runtime(runtime.RuntimeOptions(install_root=tmp_path), validate_tools=False, allow_existing=True)
    assert prepared == [tmp_path]


def test_existing_runtime_can_be_reused_after_local_image_update(tmp_path, monkeypatch, capsys):
    from vigil_cli import docker, runtime, runtime_images

    monkeypatch.setattr(runtime_images, "ensure_runtime_image", lambda *a, **k: pytest.fail("running jobs must retain their existing image"))
    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **_: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "image_exists", lambda *a, **k: True)
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **k: True)
    monkeypatch.setattr(runtime.docker, "container_image_id", lambda *a, **k: "running-image")
    monkeypatch.setattr(runtime.docker, "image_id", lambda *a, **k: "updated-image")
    monkeypatch.setattr(runtime, "_validate_mounts", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "_check_runtime_ulimits", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "generate_subfinder_provider_config", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "warn_if_local_hosts_need_restart", lambda *a, **k: None)
    calls = []
    runtime.start_runtime(runtime.RuntimeOptions(install_root=tmp_path), runner=lambda argv: calls.append(argv), validate_tools=False, allow_existing=True)
    assert calls == []
    assert "image update pending" in capsys.readouterr().err


@pytest.mark.parametrize("no_build", [False, True])
def test_stack_start_reuses_runtime_started_by_another_engagement(tmp_path, monkeypatch, no_build):
    from vigil_cli import up
    calls = []
    monkeypatch.setattr(up.docker, "image_exists", lambda *a, **k: True)
    monkeypatch.setattr(up, "start_runtime", lambda options, **kwargs: calls.append((options, kwargs)))
    assert up._start_or_restart_runtime(tmp_path, False, False, up.UpOptions(install_root=tmp_path, no_build=no_build), runner=lambda _: None) == "running"
    assert calls[0][1].get("allow_existing") is True
    assert calls[0][1]["prepare_image"] is False
    assert calls[0][0].recreate is False


def test_registered_source_cannot_contain_its_own_engagement_snapshots(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(Path(__file__).resolve().parents[1]))
    with pytest.raises(SystemExit, match="source.*engagement|engagement.*source"):
        engagements.create_engagement(engagements.CreateEngagementOptions(
            install_root=tmp_path / "workspace", engagement_type="code", name="Acme", source_dir=tmp_path,
        ), contact_backend=False)


def test_concurrent_stack_starts_do_not_restart_shared_capture(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from vigil_cli import up

    first_start = threading.Event()
    restarted = threading.Event()
    release = threading.Event()
    starts = []
    running = False
    monkeypatch.setattr(up.docker, "container_running", lambda *a, **k: running)
    monkeypatch.setattr(up.docker, "container_mounts", lambda *a, **k: {"/engagements": str(tmp_path / "engagements")})
    monkeypatch.setattr(up, "proxy_image_drift", lambda **k: False)
    def start(*a, **k):
        nonlocal running
        starts.append(True)
        if len(starts) == 1:
            first_start.set()
            assert release.wait(3)
            running = True
        else:
            restarted.set()
    monkeypatch.setattr(up, "start_proxy", start)
    options = up.UpOptions(install_root=tmp_path)
    def invoke():
        return up._start_mitmproxy_if_needed(tmp_path, options, runner=lambda _: None, build_runner=lambda _: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke)
        assert first_start.wait(3)
        second = pool.submit(invoke)
        try:
            assert not restarted.wait(0.2), "another engagement recreated the capture service"
        finally:
            release.set()
        assert first.result() == second.result() == "running"
    assert len(starts) == 1


def test_shared_capture_from_another_working_root_is_not_silently_reused(tmp_path, monkeypatch):
    from vigil_cli import up
    monkeypatch.setattr(up.docker, "container_running", lambda *a, **k: True)
    monkeypatch.setattr(up.docker, "container_mounts", lambda *a, **k: {"/engagements": str(tmp_path / "other-engagements")})
    monkeypatch.setattr(up, "proxy_image_drift", lambda **k: False)
    monkeypatch.setattr(up, "start_proxy", lambda *a, **k: pytest.fail("existing capture must not be interrupted"))
    with pytest.raises(SystemExit, match="engagements|working root"):
        up._start_mitmproxy_if_needed(tmp_path, up.UpOptions(install_root=tmp_path), runner=lambda _: None, build_runner=lambda _: None)


def test_on_demand_start_preserves_a_stopped_custom_runtime(tmp_path, monkeypatch):
    from vigil_cli import docker, runtime
    monkeypatch.setattr(runtime.docker, "daemon_status", lambda **_: docker.DaemonStatus(True, False, ""))
    monkeypatch.setattr(runtime.docker, "image_exists", lambda *a, **k: True)
    monkeypatch.setattr(runtime.docker, "container_running", lambda *a, **k: False)
    monkeypatch.setattr(runtime.docker, "container_exists", lambda *a, **k: True)
    monkeypatch.setattr(runtime, "_preflight_shared_vm", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "generate_subfinder_provider_config", lambda *a, **k: None)
    calls = []
    def runner(argv):
        calls.append(argv)
        return docker.DockerResult(0, "acme-custom:latest" if "{{.Config.Image}}" in argv else "", "")
    with pytest.raises(SystemExit, match="custom|image"):
        runtime.start_runtime(runtime.RuntimeOptions(install_root=tmp_path), runner=runner, validate_tools=False, allow_existing=True)
    assert not any(argv[:3] == ["docker", "rm", "-f"] for argv in calls)


def test_no_build_stack_start_requires_an_available_runtime_image(tmp_path, monkeypatch):
    from vigil_cli import up
    monkeypatch.setattr(up.docker, "image_exists", lambda *a, **k: False)
    monkeypatch.setattr(up, "start_runtime", lambda *a, **k: pytest.fail("no-build must not prepare a missing runtime image"))
    with pytest.raises(SystemExit, match="image|build"):
        up._start_or_restart_runtime(tmp_path, False, False, up.UpOptions(install_root=tmp_path, no_build=True), runner=lambda _: None)


def test_no_build_capture_start_uses_available_image_without_building(tmp_path, monkeypatch):
    from vigil_cli import docker, mitmproxy, up
    running_probes = iter([False, False, True])
    monkeypatch.setattr(docker, "container_running", lambda *a, **k: next(running_probes))
    monkeypatch.setattr(docker, "container_exists", lambda *a, **k: False)
    monkeypatch.setattr(docker, "image_exists", lambda *a, **k: True)
    monkeypatch.setattr(mitmproxy, "application_root_for_workspace", lambda _: tmp_path)
    monkeypatch.setattr(mitmproxy, "mitmproxy_image_inputs", lambda _: [])
    monkeypatch.setattr(mitmproxy.image_freshness, "image_outdated", lambda *a, **k: True)
    monkeypatch.setattr(mitmproxy, "_wait_for_port", lambda *a: True)
    builds = []
    monkeypatch.setattr(mitmproxy, "build_image", lambda *a, **k: builds.append(True))
    def runner(_):
        return docker.DockerResult(0, "", "")
    result = up._start_mitmproxy_if_needed(tmp_path, up.UpOptions(install_root=tmp_path, no_build=True), runner=runner, build_runner=runner)
    assert result == "running"
    assert builds == []


def test_native_linux_missing_host_recon_tools_are_reported_as_optional(monkeypatch):
    from vigil_cli import runtime, status

    monkeypatch.setattr(runtime.shutil, 'which', lambda name: None)
    monkeypatch.setattr(status, 'platform_system', lambda: 'Linux', raising=False)
    row = status._host_recon_tools_check()
    assert row.status == 'OPTIONAL'
    assert 'missing' in row.detail
    assert 'subfinder' in row.detail
    assert 'native Linux' in row.detail


def test_stack_runtime_image_preparation_and_start_are_one_serialized_operation(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from vigil_cli import up

    first_prepared = threading.Event()
    second_prepared = threading.Event()
    release = threading.Event()
    current_image = None
    roots = [tmp_path / 'acme-a', tmp_path / 'acme-b']
    started = []
    monkeypatch.setattr(up.docker, 'container_running', lambda *a, **k: False)
    monkeypatch.setattr(up, 'image_outdated', lambda *a, **k: True)
    monkeypatch.setattr(up, 'start_orchestrator', lambda *a, **k: None)
    monkeypatch.setattr(up, '_build_mitmproxy_image', lambda *a, **k: None)
    monkeypatch.setattr(up, 'mitmproxy_image_inputs', lambda *a, **k: [])
    monkeypatch.setattr(up, '_start_mitmproxy_if_needed', lambda *a, **k: 'running')
    monkeypatch.setattr(up, '_start_oob_if_needed', lambda *a, **k: 'disabled')

    def prepare(root, **kwargs):
        nonlocal current_image
        current_image = root
        if root == roots[0]:
            first_prepared.set()
            assert release.wait(3)
        else:
            second_prepared.set()

    def start(root, *args, **kwargs):
        started.append((root, current_image))
        return 'running'

    monkeypatch.setattr(up, 'ensure_runtime_image', prepare)
    monkeypatch.setattr(up, '_start_or_restart_runtime', start)

    def invoke(root):
        up._start_stack(root, root, up.UpOptions(install_root=root), runner=lambda _: None,
                        build_runner=lambda _: None, state={})

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(invoke, roots[0])
        assert first_prepared.wait(3)
        second = pool.submit(invoke, roots[1])
        try:
            assert not second_prepared.wait(0.2), 'another release changed the shared image before startup'
        finally:
            release.set()
        first.result()
        second.result()
    assert started == [(roots[0], roots[0]), (roots[1], roots[1])]


def test_shared_service_lock_supports_nested_ownership_without_deadlock(tmp_path):
    import os
    import subprocess
    import sys

    script = '''from pathlib import Path
import sys
from vigil_cli import service_locks
service_locks._application_cache = lambda: Path(sys.argv[1])
with service_locks.service_start_lock('runtime:acme'):
    with service_locks.service_start_lock('runtime:acme'):
        print('nested ownership retained')
'''
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)], capture_output=True,
                            text=True, timeout=3, env={**os.environ,
                            'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'nested ownership retained'


def test_service_lock_reentrancy_does_not_reuse_another_process_identity(tmp_path, monkeypatch):
    import os
    from vigil_cli import service_locks

    monkeypatch.setattr(service_locks, '_application_cache', lambda: tmp_path)
    monkeypatch.setattr(service_locks._held_locks, 'identities', {(os.getpid() + 1, 'runtime:acme')}, raising=False)
    acquired = []
    monkeypatch.setattr(service_locks.fcntl, 'flock', lambda *args: acquired.append(args))
    with service_locks.service_start_lock('runtime:acme'):
        assert len(acquired) == 1


def test_shared_service_lock_excludes_an_independent_process(tmp_path, monkeypatch):
    import os
    import subprocess
    import sys
    from vigil_cli import service_locks

    monkeypatch.setattr(service_locks, '_application_cache', lambda: tmp_path)
    script = '''from pathlib import Path
import sys
from vigil_cli import service_locks
service_locks._application_cache = lambda: Path(sys.argv[1])
print('waiting', flush=True)
with service_locks.service_start_lock('runtime:acme'):
    print('acquired', flush=True)
'''
    with service_locks.service_start_lock('runtime:acme'):
        process = subprocess.Popen([sys.executable, '-c', script, str(tmp_path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
        assert process.stdout.readline().strip() == 'waiting'
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.2)
    stdout, stderr = process.communicate(timeout=3)
    assert process.returncode == 0, stderr
    assert stdout.strip() == 'acquired'


@pytest.mark.parametrize('operation', ['build', 'release'])
def test_image_mutation_waits_for_other_container_startup(tmp_path, monkeypatch, operation):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from vigil_cli import runtime, runtime_images, service_locks

    reached = threading.Event()

    def image_operation(*args, **kwargs):
        reached.set()
        raise RuntimeError('Acme image operation entered')

    monkeypatch.setattr(runtime.docker, 'require_daemon', image_operation)
    monkeypatch.setattr(runtime_images, 'application_root_for_workspace', lambda _: tmp_path)
    monkeypatch.setattr(runtime_images, 'release_image_pin', lambda _: None)
    monkeypatch.setattr(runtime, 'runtime_inputs_digest', lambda _: 'a' * 64)
    monkeypatch.setattr(runtime, 'runtime_image_build_state', image_operation)

    def invoke():
        if operation == 'build':
            runtime.build_runtime(tmp_path)
        else:
            runtime_images.ensure_runtime_image(tmp_path)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with service_locks.service_start_lock('runtime-image:vigil:latest'):
            work = pool.submit(invoke)
            assert not reached.wait(0.2), 'shared tag changed during another container startup'
        with pytest.raises(RuntimeError, match='Acme image operation entered'):
            work.result()


def _scripted_backend(monkeypatch, *, get, post):
    """Patch HTTPConnection so GET/POST each return a status or raise an error."""
    import http.client

    requests = []

    class Response:
        def __init__(self, status):
            self.status = status

        def read(self):
            return json.dumps({"install_root": str(_ROOT_HOLDER[0])}).encode()

    class Connection:
        def __init__(self, *_args, **_kwargs):
            self.method = ""

        def request(self, method, path):
            self.method = method
            requests.append((method, path))

        def getresponse(self):
            outcome = get if self.method == "GET" else post
            if isinstance(outcome, BaseException):
                raise outcome
            return Response(outcome)

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://orchestrator.example.com")
    return requests


_ROOT_HOLDER: list = [None]


@pytest.mark.parametrize(
    ("get", "post", "expected"),
    [
        (200, 200, "verified"),
        # An older backend without /admin/install-root still receives the sync;
        # only the drift comparison is skipped.
        (404, 200, "verified"),
        (404, 404, "protocol_error"),
        (200, 500, "protocol_error"),
        (200, 404, "protocol_error"),
        (200, ConnectionResetError("reset"), "sync_pending"),
        (404, ConnectionResetError("reset"), "sync_pending_ownership_unverified"),
        (ConnectionRefusedError("refused"), 200, "unreachable"),
        (ssl.SSLError("certificate verify failed"), 200, "protocol_error"),
        (200, ssl.SSLError("handshake failure"), "protocol_error"),
    ],
    ids=[
        "verified", "legacy-install-root-synced", "legacy-sync-missing",
        "sync-server-error", "sync-not-found", "sync-transport-drop",
        "legacy-sync-transport-drop",
        "unreachable", "tls-on-install-root", "tls-on-sync",
    ],
)
def test_backend_install_root_status_maps_each_outcome(tmp_path, monkeypatch, capsys, get, post, expected):
    install_root = tmp_path / "install"
    install_root.mkdir()
    _ROOT_HOLDER[0] = install_root.resolve()
    requests = _scripted_backend(monkeypatch, get=get, post=post)
    status = engagements._verify_backend_install_root(install_root, install_root / "eng")
    assert status == engagements.BackendInstallRootStatus(expected)
    if get == 404:
        assert [method for method, _ in requests] == ["GET", "POST"]
        assert "ownership cannot be verified" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("get", "expected", "absent"),
    [
        (200, "install root matched", "ownership is unverified"),
        (404, "ownership is unverified", "install root matched"),
    ],
    ids=["confirmed-root", "legacy-root"],
)
def test_dropped_sync_warning_states_what_was_verified(tmp_path, monkeypatch, capsys, get, expected, absent):
    install_root = tmp_path / "install"
    engagement = install_root / "eng"
    engagement.mkdir(parents=True)
    _ROOT_HOLDER[0] = install_root.resolve()
    _scripted_backend(monkeypatch, get=get, post=ConnectionResetError("reset"))

    preflight._ensure_engagement_backend(install_root, engagement)

    err = capsys.readouterr().err
    warning = next(line for line in err.splitlines() if line.startswith("[vigil] WARN:"))
    assert expected in warning
    assert absent not in warning
