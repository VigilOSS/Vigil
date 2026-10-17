from __future__ import annotations

import json

from assess import cli
from assess.lib import config
from assess.lib.client import AssessmentClient


def test_prepare_and_claim_expose_explicit_route_and_atomic_ownership(tmp_path, monkeypatch, capsys):
    (tmp_path / 'scope.json').write_text('{}\n')
    monkeypatch.setattr(config, '_verify_backend', lambda _: None)
    calls = []
    from assess.commands import agent
    monkeypatch.setattr(agent, '_attach_dispatch_provenance', lambda _p, _cfg: [])

    def post(_self, endpoint, payload):
        calls.append((endpoint, payload))
        return {'id': 3, 'finding_slug': 'VA-050', 'route': 'code',
                'status': 'claimed' if endpoint.endswith('/claim') else 'prepared'}

    monkeypatch.setattr(AssessmentClient, 'post', post)
    cli.main(['--engagement-dir', str(tmp_path), 'proof-work', 'prepare', 'VA-050',
              '--route', 'code', '--objective', 'Challenge the supported API replay'])
    assert json.loads(capsys.readouterr().out)['route'] == 'code'
    cli.main(['--engagement-dir', str(tmp_path), 'proof-work', 'claim', '3',
              '--agent-id', 'PROOF-1', '--agent-role', 'exploit-developer'])
    assert json.loads(capsys.readouterr().out)['status'] == 'claimed'
    assert calls == [
        ('proof-work', {'finding_slug': 'VA-050', 'route': 'code',
                        'objective': 'Challenge the supported API replay', 'target_hosts': []}),
        ('proof-work/3/claim', {'agent_id': 'PROOF-1', 'agent_role': 'exploit-developer'}),
    ]


def test_claim_observes_installed_instruction_identity_without_payload_handwork(tmp_path, monkeypatch, capsys):
    from assess.commands import agent
    (tmp_path / 'scope.json').write_text('{}\n')
    monkeypatch.setattr(config, '_verify_backend', lambda _: None)
    calls = []

    def identity(payload, _cfg):
        payload['source_revision'] = 'observed-revision'
        return []

    monkeypatch.setattr(agent, '_attach_dispatch_provenance', identity)
    monkeypatch.setattr(AssessmentClient, 'post', lambda _c, endpoint, payload:
                        calls.append((endpoint, payload)) or {'id': 3})
    cli.main(['--engagement-dir', str(tmp_path), 'proof-work', 'claim', '3',
              '--agent-id', 'PROOF-1', '--agent-role', 'exploit-developer'])
    capsys.readouterr()
    assert calls[0][1].get('source_revision') == 'observed-revision'
