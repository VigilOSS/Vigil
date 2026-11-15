from __future__ import annotations

import argparse
import json

from assess.commands import agent
from test_handoff_renderer_provenance import _run_renderer


def test_packet_context_preserves_actionable_values_and_traffic_identity(tmp_path):
    context = {key: 'not supplied' for key in agent._PROMPT_CONTEXT_FIELDS}
    context.update({'authorized_phase': 'code-hunt', 'auth_context': 'Acme reviewer',
                    'credential_id': 'unknown', 'prior_state': 'unknown'})
    payload = {'agent_id': 'acme-lane', 'agent_role': 'blind-reviewer', 'task': 'Review assigned files',
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


def _render(tmp_path, *, phase, skills=None, role='code-vuln-hunter'):
    context = {key: 'not supplied' for key in agent._PROMPT_CONTEXT_FIELDS}
    context['authorized_phase'] = phase
    payload = {'agent_id': 'acme-lane', 'agent_role': role, 'task': 'Review assigned files',
               'skills': skills}
    return agent._dispatch_prompt(payload, engagement_dir=tmp_path, agent_root=tmp_path,
        source_identity=[], args=argparse.Namespace(prompt_context=context, prompt_context_json=None,
                                no_target_traffic=True, rate_budget=None), client=None)


def test_the_missing_phase_stop_rule_renders_only_when_the_phase_is_missing(tmp_path):
    marker = agent._UNSET_AUTHORIZED_PHASE
    stamped = _render(tmp_path, phase='code-hunt')
    missing = _render(tmp_path, phase=marker)
    assert f"authorized_phase: {marker}" in missing
    assert missing.count(marker) > stamped.count(marker)
    assert marker not in stamped


def test_named_skills_share_one_read_order_and_list_one_path_each(tmp_path):
    one = _render(tmp_path, phase='code-hunt', skills='code-vulnerability-analysis')
    two = _render(tmp_path, phase='code-hunt',
                  skills='code-vulnerability-analysis,code-variant-analysis')
    for name in ('code-vulnerability-analysis', 'code-variant-analysis'):
        assert two.count(f"agent/skills/{name}/SKILL.md") == 1
    # Adding a skill adds exactly its path line, not another copy of the order.
    assert len(two.splitlines()) == len(one.splitlines()) + 1
