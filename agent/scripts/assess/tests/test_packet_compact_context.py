from __future__ import annotations

import argparse
import json

from assess.commands import agent
from test_handoff_renderer_provenance import _run_renderer


def test_packet_context_preserves_actionable_values_and_traffic_identity(tmp_path):
    context = {key: 'not supplied' for key in agent._PROMPT_CONTEXT_FIELDS}
    context.update({'authorized_phase': 'code-hunt', 'auth_context': 'Acme reviewer',
                    'credential_id': 'unknown', 'prior_state': 'unknown'})
    payload = {'agent_id': 'acme-lane', 'agent_role': 'general', 'task': 'Review assigned files',
               'requested_model': 'acme-model', 'requested_reasoning': 'high'}
    rendered = agent._dispatch_prompt(payload, engagement_dir=tmp_path, agent_root=tmp_path,
        source_identity=[], args=argparse.Namespace(prompt_context=context, prompt_context_json=None,
                                no_target_traffic=True, rate_budget=None), client=None)
    body = rendered.split('## Dispatch Context\n')[1].split('\n## ')[0]
    fields = dict(line.split(': ', 1) for line in body.splitlines() if ': ' in line)
    assert fields == {'outcome objective': 'Review assigned files',
                      'skills': 'none — this role declares no skill list',
                      'auth_context': 'Acme reviewer',
                      'rate_limit_budget': 'not applicable — no target traffic'}
    assert 'authorized_phase: code-hunt' in rendered
    assert payload['requested_model'] == 'acme-model'
    assert payload['requested_reasoning'] == 'high'


def test_handoff_separates_requested_and_reported_skill_facts(tmp_path, monkeypatch, capsys):
    _run_renderer(monkeypatch, tmp_path, dispatch_slugs=[], handoff_slugs=[], max_lines=0,
        dispatch_extra={'skills': 'code-architecture-mapping,code-vulnerability-analysis',
                        'agent_role': 'code-architect'},
        handoff_extra={'extras': {'skills_loaded': ['code-vulnerability-analysis',
                                                   'code-vulnerability-analysis']}})
    lines = capsys.readouterr().out.splitlines()
    requested = next(line for line in lines if '**Skills requested:**' in line)
    loaded = next(line for line in lines if '**Skills loaded:**' in line)
    assert requested.split('**Skills requested:** ', 1)[1] == 'code-architecture-mapping, code-vulnerability-analysis'
    assert loaded.split('**Skills loaded:** ', 1)[1] == 'code-vulnerability-analysis'


def test_family_manifest_common_floor_and_deltas_reconstruct_every_item(tmp_path):
    rows = [dict(id=1, file_path='src/acme.php', loc=10, repo_id=7, repo_generation=3,
                 applicable_vuln_classes=['injection', 'ssrf'], path_suggested_vuln_classes=[]),
            dict(id=2, file_path='src/other.php', loc=20, repo_id=7, repo_generation=3,
                 applicable_vuln_classes=['injection', 'auth-bypass'], path_suggested_vuln_classes=[])]
    lane = tmp_path / 'lane.json'
    lane.write_text(json.dumps([{**row, 'file': row, 'repo': {'id': 7}} for row in rows]))
    class Client:
        def get(self, endpoint):
            if endpoint.startswith('code/analysis-queue?'):
                return {'items': rows, 'has_more': False}
            if endpoint.startswith('code/files?'):
                return {'items': rows, 'offset': 0, 'count': 2, 'total': 2, 'has_more': False}
            raise AssertionError(endpoint)
    lines = agent._lane_file_manifest(lane, client=Client(),
                                     source_identity=['repo_id: 7', 'repo_generation: 3'])
    common = next(line.split(': ', 1)[1] for line in lines
                  if line.startswith('- common_applicable_vuln_classes: '))
    file_lines = [line for line in lines if ' LOC; queue item ' in line]
    assert common == 'injection'
    assert [line.split('additional_applicable_vuln_classes: ', 1)[1].split(';')[0].rstrip(')')
            for line in file_lines] == ['ssrf', 'auth-bypass']
