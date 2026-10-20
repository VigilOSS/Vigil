from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_cli import remediation


def parser():
    result = argparse.ArgumentParser()
    remediation.register_remediation_parser(result.add_subparsers(dest='command'))
    return result


def test_first_plan_cannot_be_sent_without_evidence_requirements(monkeypatch, tmp_path):
    monkeypatch.setattr(remediation, '_engagement_key', lambda *_: 'acme')
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path, {'repository': str(tmp_path)}))
    monkeypatch.setattr(remediation, '_case', lambda *_: {'id': 1, 'verification_plan': ''})
    monkeypatch.setattr(remediation, '_api', lambda *_: pytest.fail('incomplete plan must not be sent'))
    plan = tmp_path / 'plan.md'
    plan.write_text('Run native tests')
    args = parser().parse_args(['remediation', '-k', 'acme', 'plan', '1', '--file', str(plan)])
    with pytest.raises(SystemExit, match='requirements-file'):
        remediation.run_remediation(args, tmp_path)


def test_worktree_uses_profile_base_and_repository_workspace(monkeypatch, tmp_path):
    engagement = tmp_path / 'engagement'
    repository = tmp_path / 'application'
    repository.mkdir()
    config = {'repository': str(repository), 'base_branch': 'develop',
              'workspace_directory': str(repository / 'worktrees')}
    calls = []
    monkeypatch.setattr(remediation, '_project', lambda *_: (engagement, config))
    monkeypatch.setattr(remediation, '_case', lambda *_: {'id': 1})
    monkeypatch.setattr(remediation, '_revision', lambda *_: 'a' * 40)
    monkeypatch.setattr(remediation, '_vcs', lambda: SimpleNamespace(
        create_workspace=lambda *values: calls.append(values),
        review_base=lambda *_args, **_kwargs: 'b' * 40,
    ))
    monkeypatch.setattr(remediation, '_api', lambda *_args: {})
    args = parser().parse_args(['remediation', '-k', 'acme', 'worktree', '1', '--branch', 'fix/SEC-1'])
    remediation.run_remediation(args, tmp_path)
    assert calls[0] == (repository, repository / 'worktrees/case-1', 'fix/SEC-1', 'develop')


def test_sync_accepts_registered_repository_local_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / 'application/worktrees/SEC-1'
    workspace.mkdir(parents=True)
    case = {'worktree_path': str(workspace), 'worktree_branch': 'fix/SEC-1'}
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path / 'eng', {'repository': str(tmp_path / 'application')}))
    monkeypatch.setattr(remediation, '_case', lambda *_: case)
    monkeypatch.setattr(remediation, '_require_case_worktree', lambda *_: workspace)
    monkeypatch.setattr(remediation, '_require_clean_worktree', lambda *_: None)
    monkeypatch.setattr(remediation, '_revision', lambda *_: 'a' * 40)
    calls = []
    monkeypatch.setattr(remediation, '_api', lambda *args: calls.append(args) or {})
    args = parser().parse_args(['remediation', '-k', 'acme', 'sync-revision', '1'])
    remediation.run_remediation(args, tmp_path)
    assert calls[-1][-1]['worktree_revision'] == 'a' * 40


def test_plan_transmits_explicit_verification_requirements(monkeypatch, tmp_path):
    brief = tmp_path / 'brief.txt'
    brief.write_text('Verify the real caller using the native test runner.')
    requirements = [{'kind': 'green-test', 'methods': ['pytest'], 'outcome': 'passed',
                     'revision': 'current', 'execution': 'executed', 'rationale': ''}]
    contract = tmp_path / 'requirements.json'
    contract.write_text(json.dumps(requirements))
    calls = []
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path, {}))
    monkeypatch.setattr(remediation, '_api', lambda *args: calls.append(args) or {})
    args = parser().parse_args(['remediation', '-k', 'acme', 'plan', '1', '--file', str(brief),
                               '--requirements-file', str(contract), '--alternatives-reason', 'Backend-only change'])
    remediation.run_remediation(args, tmp_path)
    assert calls[-1][-1]['requirements'] == requirements
    assert calls[-1][-1]['alternatives_reason'] == 'Backend-only change'


def test_generic_green_evidence_accepts_native_runner(monkeypatch, tmp_path):
    artifact = tmp_path / 'remediation/cases/1/tests/green.txt'
    artifact.parent.mkdir(parents=True)
    artifact.write_text('1 passed')
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path, {}))
    calls = []
    monkeypatch.setattr(remediation, '_api', lambda *args: calls.append(args) or {})
    args = parser().parse_args(['remediation', '-k', 'acme', 'evidence', '1', '--kind', 'green-test',
                               '--method', 'pytest', '--environment', 'local', '--command', 'pytest regression.py',
                               '--observed', '1 passed', '--proved', 'Caller boundary holds', '--artifact', str(artifact),
                               '--revision', 'a' * 40, '--executed-revision', 'a' * 40, '--outcome', 'passed'])
    remediation.run_remediation(args, tmp_path)
    assert calls[-1][-1]['method'] == 'pytest'
    assert calls[-1][-1]['executed_revision'] == 'a' * 40


def test_short_pr_body_does_not_require_case_ledger(monkeypatch):
    case = {'title': 'Restrict report ownership', 'source_key': 'SEC-1',
            'verification_plan': 'Open your own report. Another user cannot open it.',
            'verification_requirements': {'requirements': [{'kind': 'green-test', 'methods': ['pytest']}]},
            'release_plan': {'production_canary_decision': 'not_required',
                             'production_canary_rationale': 'No production fixture is required.',
                             'safe_procedure': '', 'monitoring': 'Watch authorization errors.'},
            'verification_matches': [{'requirement_index': 0, 'evidence_ids': [1]}],
            'approvals': [{'review_digest': 'd' * 64, 'evidence_cutoff_id': 1}],
            'approval_current': True, 'worktree_revision': 'a' * 40,
            'evidence': [{'id': 1, 'kind': 'green-test', 'method': 'pytest', 'outcome': 'passed',
                          'revision': 'a' * 40, 'observed': '1 passed', 'proved': 'Ownership boundary holds'}]}
    body = remediation._pr_body(case, {}, 'Reports accepted identifiers without checking the current owner.',
                                'Scope the report lookup to the authenticated owner.')
    assert 'd' * 64 not in body
    assert 'a' * 40 not in body
    assert 'Scope the report lookup' in body
    assert len(body.split()) < 300


def test_handoff_is_generated_from_ticket_case_without_finding(monkeypatch, tmp_path, capsys):
    case = {'id': 1, 'source_type': 'jira', 'source_key': 'SEC-1', 'title': 'A report',
            'snapshot': {'report': 'Original supplied report', 'analysis': 'Unverified hypothesis'},
            'evidence': [], 'status': 'intake'}
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path, {'repository': str(tmp_path / 'application')}))
    monkeypatch.setattr(remediation, '_case', lambda *_: case)
    args = parser().parse_args(['remediation', '-k', 'acme', 'handoff', '1'])
    remediation.run_remediation(args, tmp_path)
    result = json.loads(capsys.readouterr().out)
    assert Path(result['path']).is_relative_to(tmp_path / 'remediation/cases/1')
    assert Path(result['path']).is_file()
    assert 'Original supplied report' in Path(result['path']).read_text()


def test_checks_failure_is_recorded_and_does_not_claim_pass(monkeypatch, tmp_path, capsys):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    config = {'repository': str(tmp_path), 'remediation': {
        'check_commands': [{'name': 'regression', 'command': 'exit 9'}]}}
    case = {'id': 1, 'worktree_path': str(workspace), 'worktree_revision': 'a' * 40}
    monkeypatch.setattr(remediation, '_project', lambda *_: (tmp_path, config))
    monkeypatch.setattr(remediation, '_case', lambda *_: case)
    monkeypatch.setattr(remediation, '_require_case_worktree', lambda *_: workspace)
    monkeypatch.setattr(remediation, '_require_clean_worktree', lambda *_: None)
    monkeypatch.setattr(remediation, '_worktree_status', lambda *_: '')
    monkeypatch.setattr(remediation, '_revision', lambda *_: 'a' * 40)
    calls = []
    monkeypatch.setattr(remediation, '_api', lambda *args: calls.append(args) or {})
    args = parser().parse_args(['remediation', '-k', 'acme', 'checks', '1', '--actor', 'developer'])
    with pytest.raises(SystemExit):
        remediation.run_remediation(args, tmp_path)
    evidence = [args[-1] for args in calls if args[-2].endswith('/evidence')]
    assert evidence and evidence[0]['outcome'] == 'failed'
    assert evidence[0]['executed_revision'] == 'a' * 40


def test_existing_pr_lookup_uses_configured_base(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(remediation, '_github_repository', lambda *_: None)
    monkeypatch.setattr(remediation.subprocess, 'run', lambda argv, **kwargs: (
        calls.append(argv) or SimpleNamespace(returncode=0, stdout='[]', stderr='')))
    assert remediation._existing_draft_pr(tmp_path, 'fix/SEC-1', 'Reviewed body', base_branch='develop') is None
    assert calls[0][calls[0].index('--base') + 1] == 'develop'


def test_stagehand_validates_the_captured_case_profile(monkeypatch, tmp_path):
    captured = {'repository': str(tmp_path), 'stagehand': {'approved_account': 'captured-account'}}
    live = {'repository': str(tmp_path), 'stagehand': {'approved_account': 'changed-account'}}
    monkeypatch.setattr(remediation, '_case', lambda *_: {'id': 1, 'review_policy': captured})
    validated = []

    def validate(config, _environment):
        validated.append(config)
        raise SystemExit('Stopped before any browser execution')

    monkeypatch.setattr(remediation, 'validate_stagehand_config', validate)
    args = argparse.Namespace(driver='stagehand', environment='local', case_id='1')
    with pytest.raises(SystemExit, match='Stopped before any browser execution'):
        remediation._run_stagehand(tmp_path, tmp_path, 'acme', args, live)
    assert validated == [captured]


def test_profile_checks_keep_an_existing_environment_lease(monkeypatch, tmp_path):
    config = {'repository': str(tmp_path), 'remediation': {
        'shared_environment': 'acme-local', 'check_commands': [{'name': 'native', 'command': 'true'}],
    }}
    case = {'id': 1, 'worktree_revision': 'a' * 40}
    monkeypatch.setattr(remediation, '_require_case_worktree', lambda *_: tmp_path)
    monkeypatch.setattr(remediation, '_require_clean_worktree', lambda *_: None)
    monkeypatch.setattr(remediation, '_revision', lambda *_: 'a' * 40)
    monkeypatch.setattr(remediation, '_worktree_status', lambda *_: '')
    calls = []

    def api(*args):
        calls.append(args[-2])
        if args[-2].endswith('/acquire'):
            return {'token': 'existing-owner-token', 'created': False}
        return {}

    monkeypatch.setattr(remediation, '_api', api)
    result = remediation._run_profile_checks(tmp_path, tmp_path, 'acme', case, config, 'owner')
    assert result['checks'][0]['outcome'] == 'passed'
    assert '/environments/release' not in calls


def test_profile_checks_expose_the_cases_recorded_base(monkeypatch, tmp_path):
    config = {'repository': str(tmp_path), 'remediation': {'check_commands': [{
        'name': 'base', 'command': 'printf "%s" "$VIGIL_CASE_BASE_REVISION"',
    }]}}
    case = {'id': 1, 'worktree_revision': 'a' * 40, 'base_revision': 'b' * 40}
    monkeypatch.setattr(remediation, '_require_case_worktree', lambda *_: tmp_path)
    monkeypatch.setattr(remediation, '_require_clean_worktree', lambda *_: None)
    monkeypatch.setattr(remediation, '_revision', lambda *_: 'a' * 40)
    monkeypatch.setattr(remediation, '_worktree_status', lambda *_: '')
    monkeypatch.setattr(remediation, '_api', lambda *_: {})
    result = remediation._run_profile_checks(tmp_path, tmp_path, 'acme', case, config, 'owner')
    artifact = Path(result['checks'][0]['artifact']).read_text()
    assert '\nstdout:\n' + case['base_revision'] + '\nstderr:' in artifact
