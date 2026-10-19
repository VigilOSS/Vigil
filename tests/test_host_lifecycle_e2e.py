"""Self-contained host E2E: real uv environment and subprocess, isolated HTTP port."""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys

import pytest

from vigil_cli import backup, engagements, main, orchestrator, service_locks


@pytest.mark.parametrize(('orphan', 'host'), [(False, '127.0.0.1'), (True, '127.0.0.1'), (True, '::1')])
def test_managed_backend_start_identity_status_stop_on_isolated_port(tmp_path, monkeypatch, orphan, host):
    application = tmp_path / 'application'
    backend = application / 'orchestrator/backend'
    backend.mkdir(parents=True)
    (application / 'agent').mkdir()
    workspace = tmp_path / 'workspace'
    (backend / 'pyproject.toml').write_text('[project]\nname="acme-backend"\nversion="0.0.0"\nrequires-python=">=3.11"\ndependencies=[]\n')
    (backend / 'uvicorn.py').write_text('''import json, os, sys, socket
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"install_root": os.environ["VIGIL_INSTALL_DIR"], "status": "ready"}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
host = sys.argv[sys.argv.index("--host") + 1]
port = int(sys.argv[sys.argv.index("--port") + 1])
HTTPServer.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
HTTPServer((host, port), Handler).serve_forever()
''')
    monkeypatch.setenv('VIGIL_APPLICATION_DIR', str(application))
    monkeypatch.setenv('UV_PYTHON', sys.executable)
    monkeypatch.setenv('UV_OFFLINE', '1')
    monkeypatch.setenv('VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS', '10')
    monkeypatch.setattr(service_locks, '_application_cache', lambda: tmp_path / 'locks')
    monkeypatch.setattr(orchestrator, '_frontend_build_needed', lambda *a, **k: False)
    monkeypatch.setattr(orchestrator, '_report_build_needed', lambda *a, **k: False)
    subprocess.run(['uv', 'lock', '--offline', '--directory', str(backend)], env=os.environ.copy(), check=True, capture_output=True, timeout=30)
    with socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET) as reservation:
        reservation.bind((host, 0))
        port = reservation.getsockname()[1]
    endpoint_host = '[' + host + ']' if ':' in host else host
    monkeypatch.setenv('ORCHESTRATOR_BASE_URL', f'http://{endpoint_host}:{port}')
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,::1')
    database = backup.live_database(workspace)
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE acme (value TEXT)')
        connection.execute("INSERT INTO acme VALUES ('original')")
    saved = backup.create_backup(workspace)
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE acme SET value='changed'")
    children = []
    real_popen = subprocess.Popen
    def spawn(argv, **kwargs):
        child = real_popen(argv, **kwargs)
        if '-m' in argv and 'uvicorn' in argv:
            children.append(child)
        return child
    monkeypatch.setattr(orchestrator.subprocess, 'Popen', spawn)
    try:
        orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(workspace, host=host, port=port))
        assert len(children) == 1
        receipt_path = workspace / 'state/runtime/pids/orchestrator.json'
        receipt = json.loads(receipt_path.read_text())
        assert receipt['pid'] == children[0].pid
        assert receipt['workspace'] == str(workspace)
        assert receipt['process_identity']
        if orphan:
            receipt_path.unlink()
            receipt_path.with_suffix('.pid').unlink()
        state = orchestrator.orchestrator_status_payload(workspace, host=host, port=port)
        assert state['state'] == 'running'
        assert state['ownership'] == 'owned'
        assert state['pid'] == children[0].pid
        with pytest.raises(SystemExit, match='running or ownership is unknown'):
            main.main(['--root', str(workspace), 'backup', 'restore', str(saved)])
        with sqlite3.connect(database) as connection:
            assert connection.execute('SELECT value FROM acme').fetchone()[0] == 'changed'
        orchestrator.stop_orchestrator(workspace, host=host, port=port)
        children[0].wait(timeout=5)
        assert orchestrator.orchestrator_status_payload(workspace, host=host, port=port)['state'] == 'stopped'
        main.main(['--root', str(workspace), 'backup', 'restore', str(saved)])
        with sqlite3.connect(database) as connection:
            assert connection.execute('SELECT value FROM acme').fetchone()[0] == 'original' 
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)


def test_concurrent_same_name_creates_produce_distinct_complete_engagements(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime
    monkeypatch.setattr(engagements, '_install_client_kind', lambda *a: 'none')
    plan = engagements.plan_engagement
    monkeypatch.setattr(engagements, 'plan_engagement', lambda options: plan(options, now=datetime(2026, 1, 1)))
    options = engagements.CreateEngagementOptions(tmp_path, 'code', name='Acme')
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: engagements.create_engagement(options, contact_backend=False), range(2)))
    assert len({item.key for item in results}) == 2
    for item in results:
        assert json.loads((item.path / 'engagement.json').read_text())['key'] == item.key
        assert json.loads((item.path / 'scope.json').read_text())['name'] == 'Acme'
