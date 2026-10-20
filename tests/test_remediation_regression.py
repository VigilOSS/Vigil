import subprocess
from argparse import Namespace

import pytest

from test_remediation_vcs_policy import commit

pytest_plugins = ['test_remediation_vcs_policy']


def test_scratch_red_retains_regression_and_restores_only_fix(vcs_repo):
    from assess.lib.remediation_regression import scratch_source

    vcs, _, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('fixed\n')
    (workspace / 'test_regression.py').write_text('assert open("application.txt").read() == "fixed\\n"\n')
    head = commit(vcs, workspace, 'Fix with regression')
    with scratch_source(workspace, base, head, ['application.txt']) as (scratch, proof):
        assert (scratch / 'application.txt').read_text() == 'baseline\n'
        assert (scratch / 'test_regression.py').is_file()
        result = subprocess.run(['python3', 'test_regression.py'], cwd=scratch, capture_output=True, text=True)
        assert result.returncode != 0 and 'AssertionError' in result.stderr
        assert proof['base_revision'] == base
        assert proof['reverted_paths'] == ['application.txt']
        assert proof['scratch_tree'] != vcs.tree_id(workspace, head)
    assert vcs.revision(workspace) == head
    assert (workspace / 'application.txt').read_text() == 'fixed\n'
    assert not scratch.exists()


@pytest.mark.parametrize('paths', [[], ['../application.txt'], ['.'], ['application.txt', 'application.txt'], ['unchanged.txt']])
def test_scratch_red_rejects_invalid_restore_paths(vcs_repo, paths):
    from assess.lib.remediation_regression import scratch_source

    vcs, _, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('fixed\n')
    head = commit(vcs, workspace, 'Fix')
    with pytest.raises(ValueError):
        with scratch_source(workspace, base, head, paths):
            pytest.fail('invalid restore paths accepted')


def test_scratch_red_restores_deleted_fix_and_removes_added_fix(vcs_repo):
    from assess.lib.remediation_regression import scratch_source

    vcs, _, workspace, base = vcs_repo
    (workspace / 'application.txt').unlink()
    (workspace / 'new_fix.py').write_text('fixed = True\n')
    head = commit(vcs, workspace, 'Replace source')
    with scratch_source(workspace, base, head, ['application.txt', 'new_fix.py']) as (scratch, proof):
        assert (scratch / 'application.txt').read_text() == 'baseline\n'
        assert not (scratch / 'new_fix.py').exists()
        assert proof['reverted_paths'] == ['application.txt', 'new_fix.py']


@pytest.mark.parametrize('name', ['fix with spaces.txt', 'fix-é.txt'])
def test_scratch_red_supports_literal_fix_filenames(vcs_repo, name):
    from assess.lib.remediation_regression import scratch_source

    vcs, _, workspace, base = vcs_repo
    (workspace / name).write_text('fixed\n')
    head = commit(vcs, workspace, 'Add fix file')
    with scratch_source(workspace, base, head, [name]) as (scratch, proof):
        assert not (scratch / name).exists()
        assert proof['reverted_paths'] == [name]


@pytest.mark.parametrize('expected_failure', ['AssertionError', 'wrong failure'])
def test_paired_runner_records_proof_and_requires_expected_failure(vcs_repo, tmp_path, monkeypatch, expected_failure):
    from vigil_cli import remediation as cli
    from vigil_cli.remediation_regression import run_regression

    vcs, repo, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('fixed\n')
    (workspace / 'test_regression.py').write_text(
        f'import os\nassert os.environ["VIGIL_REPOSITORY"] == {str(repo)!r}\n'
        'assert open("application.txt").read() == "fixed\\n"\n'
    )
    head = commit(vcs, workspace, 'Fix with regression')
    case = {'id': 1, 'worktree_path': str(workspace), 'worktree_branch': 'security/SEC-123',
            'worktree_revision': head, 'base_revision': base}
    receipts = []
    monkeypatch.setattr(cli, '_api', lambda *args: receipts.append(args[-1]))
    args = Namespace(fix_path=['application.txt'], directory='.', method='pytest',
                     test_command='python3 test_regression.py', expected_failure=expected_failure, setup_command=None)
    if expected_failure == 'wrong failure':
        with pytest.raises(SystemExit, match='did not establish'):
            run_regression(args, repo, tmp_path / 'engagement', 'acme', case, {'repository': str(repo)})
        assert [r['outcome'] for r in receipts] == ['failed']
    else:
        result = run_regression(args, repo, tmp_path / 'engagement', 'acme', case, {'repository': str(repo)})
        assert result['outcome'] == 'passed'
        assert [r['outcome'] for r in receipts] == ['failed_as_expected', 'passed']
        assert receipts[0]['scratch_proof']['reverted_paths'] == ['application.txt']
        assert all(r['revision'] == head for r in receipts)


def test_paired_runner_rejects_changed_scratch_source_even_when_staged(vcs_repo, tmp_path, monkeypatch):
    from vigil_cli import remediation as cli
    from vigil_cli.remediation_regression import run_regression

    vcs, repo, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('fixed\n')
    (workspace / 'test_regression.py').write_text('assert open("application.txt").read() == "fixed\\n"\n')
    head = commit(vcs, workspace, 'Fix with regression')
    case = {'id': 1, 'worktree_path': str(workspace), 'worktree_branch': 'security/SEC-123',
            'worktree_revision': head, 'base_revision': base}
    receipts = []
    monkeypatch.setattr(cli, '_api', lambda *args: receipts.append(args[-1]))
    command = 'python3 test_regression.py; result=$?; echo corrupted > application.txt; if [ -e .git ]; then git add application.txt; fi; exit "$result"'
    args = Namespace(fix_path=['application.txt'], directory='.', method='pytest', test_command=command,
                     expected_failure='AssertionError', setup_command=None)
    with pytest.raises(SystemExit, match='did not establish'):
        run_regression(args, repo, tmp_path / 'engagement', 'acme', case, {'repository': str(repo)})
    assert [r['outcome'] for r in receipts] == ['failed']
