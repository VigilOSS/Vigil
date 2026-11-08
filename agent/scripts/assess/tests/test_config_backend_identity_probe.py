"""Backend preflight checks engagement visibility through its identity endpoint."""
from __future__ import annotations

import http.client
import json

import pytest

from assess.lib import config


def _connections(monkeypatch, *, status=200, body=b'{}', failure=None):
    seen = []

    def factory(scheme):
        class Connection:
            def __init__(self, host, port, *, timeout):
                self.scheme, self.host, self.port, self.timeout = scheme, host, port, timeout
                self.requests = []
                self.closed = False
                seen.append(self)

            def request(self, method, path):
                self.requests.append((method, path))
                if failure is not None:
                    raise failure

            def getresponse(self):
                return type('Response', (), {'status': status, 'read': lambda _: body})()

            def close(self):
                self.closed = True
        return Connection

    monkeypatch.setattr(http.client, 'HTTPConnection', factory('http'))
    monkeypatch.setattr(http.client, 'HTTPSConnection', factory('https'))
    return seen


@pytest.mark.parametrize(('url', 'scheme', 'host', 'port', 'prefix'), [
    ('http://backend.example:18001/api/', 'http', 'backend.example', 18001, '/api'),
    ('https://backend.example', 'https', 'backend.example', 443, ''),
    ('https://backend.example:9443/stack', 'https', 'backend.example', 9443, '/stack'),
    ('http://[::1]:18001/prefix', 'http', '::1', 18001, '/prefix'),
])
def test_backend_probe_reads_the_selected_engagement_identity(
    monkeypatch, capsys, url, scheme, host, port, prefix,
):
    seen = _connections(monkeypatch)
    cfg = config.Config(url, '/acme/engagements/acme-code', 'acme-code', '/acme/agent')

    config._verify_backend(cfg)

    assert len(seen) == 1
    connection = seen[0]
    assert (connection.scheme, connection.host, connection.port, connection.timeout) == (scheme, host, port, 2)
    assert connection.requests == [('GET', prefix + '/engagements/acme-code')]
    assert connection.closed
    assert capsys.readouterr().err == ''


def test_load_config_keeps_explicit_engagement_and_application_binding(monkeypatch, tmp_path):
    from vigil_cli import application

    engagement = tmp_path / 'acme-code'
    engagement.mkdir()
    (engagement / 'scope.json').write_text(json.dumps({'hostname': 'acme.example'}))
    assets = tmp_path / 'application'
    monkeypatch.setattr(application, 'resolve_application_root', lambda: assets)
    monkeypatch.setenv('ORCHESTRATOR_BASE_URL', 'https://backend.example/api')
    seen = _connections(monkeypatch)

    cfg = config.load_config(str(engagement))

    assert cfg == config.Config('https://backend.example/api', str(engagement.resolve()),
                                'acme-code', str(assets / 'agent'))
    assert seen[0].requests == [('GET', '/api/engagements/acme-code')]
    assert seen[0].closed


def test_unknown_engagement_still_warns_without_aborting(monkeypatch, capsys):
    seen = _connections(monkeypatch, status=404)
    config._verify_backend(config.Config('http://backend.example', '/acme/engagement', 'acme-code', '/acme/agent'))
    warning = capsys.readouterr().err
    assert '404' in warning
    assert 'acme-code' in warning
    assert '/acme/engagement' in warning
    assert seen[0].closed


@pytest.mark.parametrize('status', [400, 422, 503])
def test_failed_identity_read_reports_status_and_reason_without_aborting(monkeypatch, capsys, status):
    seen = _connections(monkeypatch, status=status, body=b'Acme identity lookup failed')
    config._verify_backend(config.Config('http://backend.example', '/acme/engagement', 'acme-code', '/acme/agent'))
    warning = capsys.readouterr().err
    assert f'HTTP {status}' in warning
    assert 'Acme identity lookup failed' in warning
    assert seen[0].closed


@pytest.mark.parametrize('failure', [TimeoutError('Acme timeout'), ConnectionRefusedError('Acme offline')])
def test_offline_local_workflows_remain_nonfatal_and_close_the_probe(monkeypatch, capsys, failure):
    seen = _connections(monkeypatch, failure=failure)
    config._verify_backend(config.Config('http://backend.example', '/acme/engagement', 'acme-code', '/acme/agent'))
    assert seen[0].closed
    assert capsys.readouterr().err == ''
