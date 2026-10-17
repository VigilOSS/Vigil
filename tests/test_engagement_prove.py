from contextlib import contextmanager

from vigil_cli import main as cli


class Client:
    def __init__(self):
        self.calls = []
    def get(self, path):
        self.calls.append(('get', path))
        return {'owed': [], 'items': []}
    def post(self, path, payload):
        self.calls.append(('post', path, payload))
        return {'id': int(path.split('/')[1]) if path.startswith('proof-work/') else 1, **payload}


def invoke(tmp_path, monkeypatch, args):
    client = Client()
    @contextmanager
    def connect(root, key):
        assert key == 'acme'
        yield client
    monkeypatch.setattr(cli, '_resolve_current_or_selected_engagement', lambda *a, **k: tmp_path / 'acme')
    monkeypatch.setattr(cli, '_build_assessment_client', connect)
    try:
        cli.main(['--root', str(tmp_path), 'engagement', 'prove', 'acme', *args])
    except SystemExit as exc:
        assert exc.code == 0, 'manual proof workflow must be registered'
    return client.calls


def test_manual_proof_default_lists_without_launch_or_writes(tmp_path, monkeypatch):
    assert invoke(tmp_path, monkeypatch, []) == [('get', 'proof-work')]


def test_manual_proof_prepares_selected_candidate_route_and_objective(tmp_path, monkeypatch):
    calls = invoke(tmp_path, monkeypatch, ['--finding', 'VA-001', '--mode', 'code', '--objective', 'Challenge supported parser input'])
    assert calls == [('post', 'proof-work', {'finding_slug': 'VA-001', 'route': 'code', 'objective': 'Challenge supported parser input', 'target_hosts': []})]


def test_manual_proof_approval_binds_only_selected_work(tmp_path, monkeypatch):
    assert invoke(tmp_path, monkeypatch, ['--work', '9', '--approve']) == [('post', 'proof-work/9/approval', {'approved': True})]


def test_manual_proof_release_records_human_recovery_reason(tmp_path, monkeypatch):
    assert invoke(tmp_path, monkeypatch, ['--work', '9', '--release', '--reason', 'Ended worker and terminal jobs inspected']) == [('post', 'proof-work/9/release', {'reason': 'Ended worker and terminal jobs inspected'})]


def test_manual_proof_reports_uncertain_success_without_durable_work_identity(tmp_path, monkeypatch):
    import pytest
    @contextmanager
    def connect(root, key):
        client = Client()
        client.post = lambda *args: {}
        yield client
    monkeypatch.setattr(cli, '_resolve_current_or_selected_engagement', lambda *a, **k: tmp_path / 'acme')
    monkeypatch.setattr(cli, '_build_assessment_client', connect)
    with pytest.raises(SystemExit, match='may have committed'):
        cli.main(['--root', str(tmp_path), 'engagement', 'prove', 'acme', '--work', '9', '--approve'])
