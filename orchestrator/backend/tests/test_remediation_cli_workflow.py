from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from app import db
from vigil_cli import remediation


@pytest.mark.parametrize('vcs', ['git', 'jj'])
def test_cli_report_to_workspace_checks_and_handoff(client, isolate_settings, monkeypatch, capsys, vcs):
    install = isolate_settings['install_dir'].resolve()
    key = 'acme-remediation'
    engagement = isolate_settings['engagements_dir'].resolve() / key
    engagement.mkdir()
    (engagement / 'scope.json').write_text(json.dumps({'engagement_type': 'remediation'}))
    db.create_engagement(key, 'Acme', 'in_progress', str(engagement), 'remediation')
    repository = install.parent / 'application'

    def run(*command):
        return subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip()

    run('git', 'init', '-b', 'develop', str(repository))
    run('git', '-C', str(repository), 'config', 'user.name', 'Acme Test')
    run('git', '-C', str(repository), 'config', 'user.email', 'test@example.com')
    (repository / '.gitignore').write_text('worktrees/\n')
    (repository / 'app.txt').write_text('baseline\n')
    check = 'test "$(cat app.txt)" = fixed && printf "source=%s\\nrevision=%s\\n" "$PWD" "$VIGIL_CASE_REVISION"'
    profile = repository / 'PROJECT.md'
    profile.write_text(
        '+++\nrepository = "."\nbase_branch = "develop"\nworkspace_directory = "worktrees"\n'
        '[remediation]\nshared_environment = "local-tests"\n'
        'check_commands = [{ name = "native-check", command = ' + json.dumps(check) + ' }]\n+++\n')
    run('git', '-C', str(repository), 'add', '.')
    run('git', '-C', str(repository), 'commit', '-m', 'Baseline')
    baseline = run('git', '-C', str(repository), 'rev-parse', 'HEAD')
    if vcs == 'jj':
        run('jj', 'git', 'init', '--colocate', str(repository))
        run('jj', '--repository', str(repository), 'config', 'set', '--repo', 'user.name', 'Acme Test')
        run('jj', '--repository', str(repository), 'config', 'set', '--repo', 'user.email', 'test@example.com')
    (engagement / 'PROJECT.md').symlink_to(profile)

    def api(_install, _engagement, engagement_key, method, suffix, payload=None):
        response = client.request(method, f'/engagements/{engagement_key}/remediation{suffix}', json=payload)
        assert response.is_success, response.text
        return response.json()

    monkeypatch.setattr(remediation, '_api', api)
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest='command'))

    def command(*arguments):
        remediation.run_remediation(parser.parse_args(['remediation', '-k', key, *arguments]), install)
        return json.loads(capsys.readouterr().out)

    source = install.parent / 'report.json'
    source.write_text(json.dumps({'original_report': 'Reported account boundary',
                                 'suggested_remediation': 'Unverified suggestion'}))
    imported = command('import', '--source', 'manual', '--source-key', 'report-123',
                       '--title', 'Account boundary', '--snapshot-file', str(source))
    identifier = str(imported['id'])
    registered = command('worktree', identifier, '--branch', 'fix/SEC-123')
    workspace = repository / f'worktrees/case-{identifier}'
    assert Path(registered['worktree_path']) == workspace
    assert not workspace.is_relative_to(engagement)
    assert registered['base_branch'] == 'develop'
    assert registered['base_revision'] == baseline
    assert registered['review_policy']['repository'] == str(repository)

    (workspace / 'app.txt').write_text('fixed\n')
    if vcs == 'jj':
        run('jj', '--repository', str(workspace), 'describe', '-m', 'Boundary fix')
    else:
        run('git', '-C', str(workspace), 'add', 'app.txt')
        run('git', '-C', str(workspace), 'commit', '-m', 'Boundary fix')
    synchronized = command('sync-revision', identifier)
    checked = command('checks', identifier, '--actor', 'developer')
    revision = synchronized['worktree_revision']
    assert checked['revision'] == revision and revision != baseline
    assert checked['checks'][0]['outcome'] == 'passed'
    current = client.get(f'/engagements/{key}/remediation/cases/{identifier}').json()
    proof = next(item for item in current['evidence'] if item['kind'] == 'profile-check')
    assert proof['executed_revision'] == revision
    assert proof['executed_directory'] == str(workspace)
    assert proof['command'] == check
    assert proof['shared_environment'] == 'local-tests'
    output = (engagement / proof['artifact_path']).read_text()
    assert f'source={workspace}' in output and f'revision={revision}' in output
    assert current['source_type'] == 'manual'
    assert len(current['environment_leases']) == 1
    assert current['environment_leases'][0]['released_at']
    assert current['environment_leases'][0]['token'] == proof['environment_token']

    handoff = Path(command('handoff', identifier)['path'])
    assert handoff == engagement / 'remediation/cases' / identifier / 'handoff.md'
    context = handoff.read_text()
    assert 'Reported account boundary' in context
    assert 'Unverified suggestion' in context
    assert 'proposed remediation is a hypothesis' in context
    assert revision in context and str(workspace) in context

    profile.write_text(profile.read_text().replace('repository = "."', 'repository = "../another-application"'))
    assert command('sync-revision', identifier)['worktree_revision'] == revision
