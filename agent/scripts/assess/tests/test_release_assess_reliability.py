from types import SimpleNamespace

import pytest

from assess.commands import approve_exploit, code_dispatch, review_exploits, transition_phase
from assess.lib import exploit_targets


@pytest.mark.parametrize('scope', [
    {'tracks': {'web': {'phase': 'exploit'}, 'code': {'phase': 'hunt'}}},
    {'engagement_type': 'web', 'current_phase': 'exploit'},
])
def test_exploit_gate_reads_the_web_track(monkeypatch, scope):
    monkeypatch.setattr(exploit_targets, 'load_exploit_candidates', lambda _: [{'slug': 'VA-001'}])
    assert exploit_targets.resolve_approved_target_slugs(None, scope | {'exploit_policy': 'full_send'}) == ['VA-001']


def test_exploit_review_reports_the_web_track(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(review_exploits, 'load_config', lambda _: SimpleNamespace(engagement_dir=tmp_path))
    monkeypatch.setattr(review_exploits, 'load_scope', lambda _: {'tracks': {'web': {'phase': 'exploit'}}})
    monkeypatch.setattr(review_exploits, 'load_exploit_candidates', lambda _: [])
    monkeypatch.setattr(review_exploits, '_print_runtime_proof_owed', lambda _: None)
    review_exploits.run(SimpleNamespace(engagement_dir=tmp_path))
    assert 'current_phase: exploit' in capsys.readouterr().out


def test_selected_approval_checks_every_candidate_before_scope_write(tmp_path, monkeypatch):
    from assess.lib.client import AssessmentClient
    monkeypatch.setattr(approve_exploit, 'load_config', lambda _: SimpleNamespace(
        engagement_dir=tmp_path, base_url='http://127.0.0.1:1', engagement_key='acme'))
    monkeypatch.setattr(AssessmentClient, 'get', lambda *_: [{'slug': 'VA-001'}])
    mutations = []
    monkeypatch.setattr(approve_exploit, 'mutate_scope', lambda *_: mutations.append(True))
    with pytest.raises(SystemExit):
        approve_exploit.run(SimpleNamespace(engagement_dir=tmp_path, decision='selected', slugs=['VA-001', 'VA-002']))
    assert mutations == []


@pytest.mark.parametrize('verification', ['blocked', 'pending_runtime_proof', 'unreviewed', 'false_positive'])
def test_blind_triage_only_requires_verdicts_for_reportable_findings(verification):
    class Client:
        def get(self, endpoint):
            if endpoint == 'findings':
                return [{'slug': 'VA-001', 'severity': 'high', 'workflow_status': 'active',
                         'verification_status': verification}]
            return []
    assert transition_phase._blind_triage_blockers(Client()) == []


def test_queue_done_dry_run_refuses_empty_analysis_coverage(tmp_path):
    coverage = tmp_path / 'coverage.json'
    coverage.write_text('[]')
    with pytest.raises(SystemExit):
        code_dispatch._done(SimpleNamespace(engagement_dir=tmp_path), '1', 'HUNT-1',
                            'lease', 'clean', str(coverage), 'Reviewed supported input path', dry_run=True)


def test_resume_shows_renewed_verification_without_parked_work():
    from assess.commands.resume_brief import _render_proof_work
    lines = []
    _render_proof_work(lines, {'owed_findings': 0, 'queue_state_counts': {},
                              'reverification_required': 1, 'read_command': 'vigil assess proof-work list'})
    assert 'verification required again: 1' in '\n'.join(lines)
