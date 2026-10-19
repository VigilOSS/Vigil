import http.client
import json
import ssl
from contextlib import contextmanager

import pytest

from vigil_cli import engagements, preflight, main, docker, mitmproxy


@pytest.mark.parametrize(('stage', 'exc', 'expected'), [
    (0, http.client.RemoteDisconnected('connection dropped'), 'unreachable'),
    (1, http.client.RemoteDisconnected('connection dropped'), 'sync_pending'),
    (0, ssl.SSLError('TLS validation failed'), 'protocol_error'),
    (1, http.client.BadStatusLine('not HTTP'), 'protocol_error'),
])
def test_backend_transport_classification_closes_connection(tmp_path, monkeypatch, capsys, stage, exc, expected):
    connections = []
    class Connection:
        def __init__(self, *a, **kw):
            self.index = len(connections)
            self.closed = False
            connections.append(self)
        def request(self, *a):
            if self.index == stage:
                raise exc
        def getresponse(self):
            return type('Response', (), {'status': 200, 'read': lambda _: json.dumps({'install_root': str(tmp_path)}).encode()})()
        def close(self):
            self.closed = True
    monkeypatch.setattr(http.client, 'HTTPConnection', Connection)
    monkeypatch.setattr(engagements, 'resolve_orchestrator_base_url', lambda *a: 'http://127.0.0.1:18000')
    assert engagements._verify_backend_install_root(tmp_path, tmp_path / 'acme') == expected
    assert all(conn.closed for conn in connections)
    assert str(exc) in capsys.readouterr().err


def test_proof_request_refusal_is_clean_system_exit(tmp_path, monkeypatch):
    from vigil_cli.paths import add_assess_import_path
    add_assess_import_path(tmp_path)
    from assess.lib.client import AssessError
    @contextmanager
    def connect(*a):
        raise AssessError('work is blocked')
        yield
    monkeypatch.setattr(main, '_resolve_current_or_selected_engagement', lambda *a, **k: tmp_path / 'acme')
    monkeypatch.setattr(main, '_build_assessment_client', connect)
    with pytest.raises(SystemExit, match='work is blocked'):
        main.main(['--root', str(tmp_path), 'engagement', 'prove', 'acme'])


def test_invalid_track_refuses_before_backend_start(tmp_path, monkeypatch):
    (tmp_path / 'scope.json').write_text('{"engagement_type":"offensive","tracks":{"code":{"phase":"review"}}}')
    monkeypatch.setattr(preflight.shutil, 'which', lambda *a: '/usr/bin/acme')
    calls = []
    monkeypatch.setattr(preflight, '_ensure_engagement_backend', lambda *a: calls.append('backend'))
    with pytest.raises(SystemExit, match='not enabled'):
        preflight._preflight_engagement_start(tmp_path, tmp_path, 'codex', mode='web')
    assert calls == []


def test_proxy_unavailable_daemon_is_unknown_not_missing(tmp_path):
    calls = []
    def runner(argv, **kw):
        calls.append(argv)
        return docker.DockerResult(1, '', 'daemon unavailable')
    result = mitmproxy.proxy_status_payload(tmp_path, tmp_path, runner=runner)
    assert result['state'] == 'unknown'
    assert result['image_present'] is None
    assert result['exists'] is None
    assert [call[:2] for call in calls] == [['docker', 'info']]


def test_stale_pid_receipt_does_not_claim_reused_process(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    directory = tmp_path / 'state/runtime/pids'
    directory.mkdir(parents=True)
    (directory / 'orchestrator.pid').write_text('4242\n')
    (directory / 'orchestrator.json').write_text(json.dumps({
        'pid': 4242, 'process_identity': 'old-birth', 'workspace': str(tmp_path),
        'host': '127.0.0.1', 'port': 18000, 'process_group': 4242,
    }))
    monkeypatch.setattr(orchestrator, '_pid_alive', lambda _: True)
    monkeypatch.setattr(orchestrator, '_process_identity', lambda _: 'new-birth', raising=False)
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    assert orchestrator.orchestrator_status(tmp_path) == 'stopped'


def test_live_listener_without_owned_receipt_is_not_stopped(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: True)
    monkeypatch.setattr(orchestrator, '_port_listener_pid', lambda *a: None)
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a, **k: engagements.BackendOwnership(engagements.BackendInstallRootStatus.OWNERSHIP_UNVERIFIED, 'http://127.0.0.1:18000'))
    assert orchestrator.orchestrator_status(tmp_path) == 'unknown'


def test_status_unavailable_docker_does_not_claim_images_absent(tmp_path, monkeypatch):
    from vigil_cli import status
    monkeypatch.setattr(status, '_orchestrator_readyz_bundle', lambda *a: {})
    monkeypatch.setattr(status, 'orchestrator_status', lambda *a: 'stopped')
    calls = []
    def runner(argv, **kwargs):
        calls.append(argv[:2])
        return docker.DockerResult(1, '', 'offline')
    result = status.collect_status(tmp_path, runner=runner)
    assert result['runtime']['image_exists'] is None
    assert result['mitmproxy']['state'] == 'unknown'
    assert result['mitmproxy']['image_exists'] is None
    assert calls == [['docker', 'info']]


@pytest.mark.parametrize(('url', 'host'), [
    ('http://localhost:18000/', '127.0.0.1'),
    ('http://127.0.0.2:18000', '127.0.0.2'),
    ('http://[::1]:18000', '::1'),
])
def test_managed_loopback_endpoint_starts_compatible_listener(tmp_path, monkeypatch, url, host):
    from vigil_cli import orchestrator
    monkeypatch.setattr(preflight, 'resolve_orchestrator_base_url', lambda *a: url)
    monkeypatch.setattr(preflight, 'orchestrator_status', lambda *a: 'stopped')
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a: engagements.BackendOwnership(engagements.BackendInstallRootStatus.UNREACHABLE, url))
    monkeypatch.setattr(engagements, '_verify_backend_install_root', lambda *a: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(engagements, '_backend_request', lambda *a: (404, b'', '', False))
    started = []
    monkeypatch.setattr(orchestrator, 'start_orchestrator', lambda options: started.append(options))
    preflight._ensure_engagement_backend(tmp_path, tmp_path / 'acme')
    assert [options.host for options in started] == [host]


def test_foreign_backend_refuses_before_start(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    url = 'http://127.0.0.1:18000'
    monkeypatch.setattr(preflight, 'resolve_orchestrator_base_url', lambda *a: url)
    monkeypatch.setattr(preflight, 'orchestrator_status', lambda *a: 'stopped')
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a: engagements.BackendOwnership(engagements.BackendInstallRootStatus.FOREIGN, url, str(tmp_path / 'other')))
    started = []
    monkeypatch.setattr(orchestrator, 'start_orchestrator', lambda *a: started.append(True))
    monkeypatch.setattr(engagements, '_verify_backend_install_root', lambda *a: engagements.BackendInstallRootStatus.VERIFIED)
    with pytest.raises(SystemExit, match='other'):
        preflight._ensure_engagement_backend(tmp_path, tmp_path / 'acme')
    assert started == []


def test_stale_backend_refuses_client_with_quoted_restart_command(tmp_path, monkeypatch):
    from vigil_cli import application
    url = 'http://127.0.0.1:18000'
    monkeypatch.setattr(preflight, 'resolve_orchestrator_base_url', lambda *a: url)
    monkeypatch.setattr(preflight, 'orchestrator_status', lambda *a: 'running')
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a: engagements.BackendOwnership(engagements.BackendInstallRootStatus.VERIFIED, url, str(tmp_path)))
    monkeypatch.setattr(engagements, '_verify_backend_install_root', lambda *a: engagements.BackendInstallRootStatus.VERIFIED)
    payload = {'backend_runtime': {'install_root': str(tmp_path), 'application_root': str(application.application_root_for_workspace(tmp_path)), 'restart_required': True}}
    monkeypatch.setattr(engagements, '_backend_request', lambda *a: (200, json.dumps(payload).encode(), '', False))
    with pytest.raises(SystemExit, match='orchestrator restart'):
        preflight._ensure_engagement_backend(tmp_path, tmp_path / 'acme')


def test_create_allocates_directory_atomically_when_another_creator_wins(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(engagements, '_install_client_kind', lambda *a: 'none')
    original = Path.mkdir
    winner = []
    def mkdir(path, *a, **kw):
        if path.parent == tmp_path / 'engagements' and not winner:
            original(path, *a, **kw)
            (path / 'winner.txt').write_text('Acme concurrent creation')
            winner.append(path)
            raise FileExistsError(str(path))
        return original(path, *a, **kw)
    monkeypatch.setattr(Path, 'mkdir', mkdir)
    result = engagements.create_engagement(engagements.CreateEngagementOptions(tmp_path, 'code', name='Acme'), contact_backend=False)
    assert result.path != winner[0]
    assert (result.path / 'scope.json').is_file()
    assert (winner[0] / 'winner.txt').read_text() == 'Acme concurrent creation'


def test_create_checks_foreign_ownership_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a: engagements.BackendOwnership(engagements.BackendInstallRootStatus.FOREIGN, 'http://127.0.0.1:18000', str(tmp_path / 'other')))
    monkeypatch.setattr(engagements, '_verify_backend_install_root', lambda *a: engagements.BackendInstallRootStatus.VERIFIED)
    with pytest.raises(SystemExit, match='other'):
        engagements.create_engagement(engagements.CreateEngagementOptions(tmp_path, 'code', name='Acme'))
    assert not (tmp_path / 'engagements').exists()


def test_create_json_preserves_committed_identity_on_sync_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a: engagements.BackendOwnership(engagements.BackendInstallRootStatus.VERIFIED, 'http://127.0.0.1:18000', str(tmp_path)))
    monkeypatch.setattr(engagements, '_verify_backend_install_root', lambda *a: engagements.BackendInstallRootStatus.PROTOCOL_ERROR)
    monkeypatch.setattr(engagements, '_install_client_kind', lambda *a: 'none')
    with pytest.raises(SystemExit) as exc:
        main.main(['--root', str(tmp_path), 'engagement', 'create', '--type', 'code', '--name', 'Acme', '--no-prompt', '--json'])
    assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload['created'] is True
    assert payload['backend_state'] == 'protocol_error'
    assert (tmp_path / 'engagements' / payload['key'] / 'scope.json').is_file()


def test_owned_orphan_listener_can_be_recovered_only_with_process_identity(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: True)
    monkeypatch.setattr(orchestrator, '_port_listener_pid', lambda *a: 4242)
    monkeypatch.setattr(orchestrator, '_process_identity', lambda *a: 'acme-birth')
    monkeypatch.setattr(orchestrator, '_listener_application_matches', lambda *a: True, raising=False)
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a, **k: engagements.BackendOwnership(engagements.BackendInstallRootStatus.VERIFIED, 'http://127.0.0.1:18000', str(tmp_path)))
    result = orchestrator.orchestrator_status_payload(tmp_path)
    assert result['state'] == 'running'
    assert result['ownership'] == 'owned'
    assert result['pid'] == 4242
    assert result['process_group'] is None


def test_receipt_from_copied_workspace_never_authorizes_restore(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    directory = tmp_path / 'state/runtime/pids'
    directory.mkdir(parents=True)
    (directory / 'orchestrator.pid').write_text('4242\n')
    (directory / 'orchestrator.json').write_text(json.dumps({'pid': 4242, 'process_identity': 'acme-birth', 'workspace': str(tmp_path / 'original')}))
    monkeypatch.setattr(orchestrator, '_process_identity', lambda *a: 'acme-birth')
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    assert orchestrator.orchestrator_status(tmp_path) == 'foreign'


@pytest.mark.parametrize('stage', ['health', 'readiness'])
def test_startup_exit_names_code_and_log_instead_of_timeout(tmp_path, monkeypatch, stage):
    from types import SimpleNamespace
    from vigil_cli import orchestrator
    monkeypatch.setattr(orchestrator, 'application_root_for_workspace', lambda *a: tmp_path)
    monkeypatch.setattr(orchestrator, '_frontend_build_needed', lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, '_report_build_needed', lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, '_sync_backend_environment', lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, '_process_identity', lambda *a: 'acme-birth')
    monkeypatch.setattr(orchestrator.subprocess, 'Popen', lambda *a, **k: SimpleNamespace(pid=4242, poll=lambda: 8))
    monkeypatch.setattr(orchestrator, '_wait_for_health', lambda *a, **k: stage != 'health')
    monkeypatch.setattr(orchestrator, '_wait_for_readiness', lambda *a, **k: False)
    with pytest.raises(SystemExit, match='exited with code 8.*orchestrator.log'):
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(tmp_path))


def test_pi_nonremediation_refuses_before_backend_side_effect(tmp_path, monkeypatch):
    (tmp_path / 'scope.json').write_text('{"engagement_type":"code"}')
    monkeypatch.setattr(preflight.shutil, 'which', lambda *a: '/usr/bin/acme')
    monkeypatch.setattr(preflight, '_ensure_engagement_backend', lambda *a: pytest.fail('must validate before starting services'))
    with pytest.raises(SystemExit, match='remediation'):
        preflight._preflight_engagement_start(tmp_path, tmp_path, 'pi')


@pytest.mark.parametrize('state', ['unknown', 'foreign'])
def test_restart_manifest_does_not_clear_unknown_ownership_as_stopped(tmp_path, monkeypatch, state):
    from vigil_cli import orchestrator, restart_manifest
    monkeypatch.setattr(orchestrator, 'orchestrator_status_payload', lambda *a, **k: {'state': state, 'pid': None, 'port_in_use': False, 'detail': 'ownership cannot be established'})
    result = restart_manifest.backend_state_from_readiness(tmp_path, {'reachable': False, 'unreachable_reason': 'refused'})
    assert result.state == 'unknown'
    assert 'ownership' in result.detail


def test_owned_legacy_backend_process_can_match_workspace_application(tmp_path, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    from vigil_cli import orchestrator
    original_is_dir = Path.is_dir
    monkeypatch.setattr(Path, 'is_dir', lambda path: False if path == Path('/proc') else original_is_dir(path))
    monkeypatch.setattr(orchestrator, 'application_root_for_workspace', lambda *a: tmp_path / 'new-release')
    def inspect(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout=('python -m uvicorn app.main:app --port 18000' if argv[0] == 'ps' else f'p4242\nn{tmp_path}/orchestrator/backend\n'))
    monkeypatch.setattr(orchestrator.subprocess, 'run', inspect)
    assert orchestrator._listener_application_matches(4242, tmp_path)


def test_owned_receipt_with_invalid_endpoint_is_unknown_instead_of_traceback(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    directory = tmp_path / 'state/runtime/pids'
    directory.mkdir(parents=True)
    (directory / 'orchestrator.pid').write_text('4242\n')
    (directory / 'orchestrator.json').write_text(json.dumps({'pid': 4242, 'process_identity': 'acme-birth', 'workspace': str(tmp_path), 'port': 'broken'}))
    monkeypatch.setattr(orchestrator, '_process_identity', lambda *a: 'acme-birth')
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    assert orchestrator.orchestrator_status(tmp_path) == 'unknown'


@pytest.mark.parametrize('endpoint', ['http://192.0.2.10:18000', 'http://host.docker.internal:18000'])
def test_unreachable_remote_configuration_does_not_block_local_lifecycle(tmp_path, monkeypatch, endpoint):
    from vigil_cli import orchestrator, paths
    monkeypatch.setattr(paths, 'resolve_orchestrator_base_url', lambda *a: endpoint)
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a, **kw: engagements.BackendOwnership(engagements.BackendInstallRootStatus.UNREACHABLE, endpoint))
    orchestrator.stop_orchestrator(tmp_path)


def test_legacy_pid_reused_by_unrelated_process_does_not_block_local_start(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    directory = tmp_path / 'state/runtime/pids'
    directory.mkdir(parents=True)
    (directory / 'orchestrator.pid').write_text('4242\n')
    monkeypatch.setattr(orchestrator, '_process_identity', lambda _: 'unrelated-birth')
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    monkeypatch.setattr(orchestrator, '_listener_application_matches', lambda *a: False)
    assert orchestrator.orchestrator_status_payload(tmp_path)['state'] == 'stopped'
    orchestrator.stop_orchestrator(tmp_path)


def test_legacy_backend_starting_without_listener_has_actionable_status(tmp_path, monkeypatch):
    from vigil_cli import orchestrator
    directory = tmp_path / 'state/runtime/pids'
    directory.mkdir(parents=True)
    (directory / 'orchestrator.pid').write_text('4242\n')
    monkeypatch.setattr(orchestrator, '_process_identity', lambda _: 'backend-birth')
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    monkeypatch.setattr(orchestrator, '_listener_application_matches', lambda *a: True)
    state = orchestrator.orchestrator_status_payload(tmp_path)
    assert state['state'] == 'unknown'
    assert '4242' in state['detail']
    assert 'wait' in state['detail']


def test_unreachable_remote_configuration_preserves_restore_uncertainty(tmp_path, monkeypatch):
    from vigil_cli import orchestrator, paths
    endpoint = 'http://backend.example:18000'
    monkeypatch.setattr(paths, 'resolve_orchestrator_base_url', lambda *a: endpoint)
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    monkeypatch.setattr(engagements, 'inspect_backend_ownership', lambda *a, **kw: engagements.BackendOwnership(engagements.BackendInstallRootStatus.UNREACHABLE, endpoint))
    state = orchestrator.orchestrator_status_payload(tmp_path)
    assert state['state'] == 'unknown'
    assert endpoint in state['detail']
    assert 'owning host' in state['detail']
    assert 'shared database' in state['detail']
    with pytest.raises(SystemExit, match='ownership is unknown.*owning host'):
        main.main(['--root', str(tmp_path), 'backup', 'restore', 'acme.sqlite'])


@pytest.mark.parametrize('endpoint', ['http://192.0.2.10:18000', 'http://host.docker.internal:18000'])
def test_explicit_start_uses_local_endpoint_despite_remote_client_url(tmp_path, monkeypatch, endpoint):
    from types import SimpleNamespace
    from vigil_cli import orchestrator, paths
    monkeypatch.setattr(paths, 'resolve_orchestrator_base_url', lambda *a: endpoint)
    monkeypatch.setattr(orchestrator, 'application_root_for_workspace', lambda *a: tmp_path)
    monkeypatch.setattr(orchestrator, '_frontend_build_needed', lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, '_report_build_needed', lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, '_sync_backend_environment', lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, '_port_in_use', lambda *a: False)
    monkeypatch.setattr(orchestrator, '_process_identity', lambda *a: 'acme-birth')
    launched = []
    def spawn(argv, **kwargs):
        launched.append(argv)
        return SimpleNamespace(pid=4242, poll=lambda: 8)
    monkeypatch.setattr(orchestrator.subprocess, 'Popen', spawn)
    monkeypatch.setattr(orchestrator, '_wait_for_health', lambda *a, **k: False)
    with pytest.raises(SystemExit, match='exited with code 8'):
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(tmp_path))
    assert launched[0][-4:] == ['--host', '127.0.0.1', '--port', '18000']
