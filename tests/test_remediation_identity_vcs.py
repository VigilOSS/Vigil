from pathlib import Path
import subprocess

import pytest

from vigil_cli import remediation


@pytest.fixture(params=['git', 'jj', 'jj-colocated'])
def case_workspace(tmp_path, request):
    adapter = remediation._vcs()
    repo = tmp_path / 'repo'
    repo.mkdir()
    def run(*args):
        return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()
    if request.param == 'git':
        run('git', 'init', '-b', 'main', str(repo))
        run('git', '-C', str(repo), 'config', 'user.name', 'Acme Test')
        run('git', '-C', str(repo), 'config', 'user.email', 'test@example.com')
        (repo / 'app.txt').write_text('baseline\n')
        run('git', '-C', str(repo), 'add', '.')
        run('git', '-C', str(repo), 'commit', '-qm', 'Baseline')
    else:
        run('jj', 'git', 'init', '--colocate' if request.param == 'jj-colocated' else '--no-colocate', str(repo))
        run('jj', '-R', str(repo), 'config', 'set', '--repo', 'user.name', 'Acme Test')
        run('jj', '-R', str(repo), 'config', 'set', '--repo', 'user.email', 'test@example.com')
        (repo / 'app.txt').write_text('baseline\n')
        run('jj', '-R', str(repo), 'describe', '-m', 'Baseline')
        run('jj', '-R', str(repo), 'bookmark', 'create', 'main', '-r', '@')
    workspace = tmp_path / 'case-42'
    adapter.create_workspace(repo, workspace, 'remediation/case-42', 'main')
    return adapter, repo, workspace, run


def test_finalize_preserves_revision_workspace_and_supports_retry(case_workspace):
    adapter, repo, workspace, _run = case_workspace
    before = adapter.revision(workspace)
    adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)
    assert adapter.branch_matches(workspace, 'fix/ACME-7')
    adapter.verify_finalized_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)
    assert adapter.revision(workspace) == before
    assert adapter.registered(repo, workspace)
    adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)
    assert adapter.revision(workspace) == before


def test_finalize_rejects_local_target_collision(case_workspace):
    adapter, repo, workspace, run = case_workspace
    adapter.create_workspace(repo, workspace.parent / 'other-case', 'fix/ACME-7', 'main')
    with pytest.raises(ValueError, match='already exists'):
        adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', adapter.revision(workspace))
    assert adapter.branch_matches(workspace, 'remediation/case-42')


def test_finalize_rejects_changed_source(case_workspace):
    adapter, _repo, workspace, _run = case_workspace
    before = adapter.revision(workspace)
    (workspace / 'app.txt').write_text('unreviewed\n')
    with pytest.raises(ValueError, match='changed'):
        adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)
    assert adapter.branch_matches(workspace, 'remediation/case-42')


def test_workspace_directory_uses_permanent_case_id(tmp_path):
    project = remediation.project_module(tmp_path)
    config = {'workspace_directory': str(tmp_path / 'worktrees')}
    case = tmp_path / 'engagement/remediation/cases/42'
    assert project.workspace_path(config, case, 'fix/ACME-7') == tmp_path / 'worktrees/case-42'
    assert project.workspace_path(config, case, 'remediation/case-42') == tmp_path / 'worktrees/case-42'


def test_check_command_stage_validation(tmp_path):
    project = remediation.project_module(tmp_path)
    for stage in ['verification', 'publication']:
        config = {'remediation': {'check_commands': [{'name': 'acme', 'command': 'true', 'stage': stage}]}}
        project.validate_project(config)
        assert project.effective_policy(config)['check_commands'][0]['stage'] == stage
    with pytest.raises(ValueError, match='stage'):
        project.validate_project({'remediation': {'check_commands': [{'name': 'acme', 'command': 'true', 'stage': 'unknown'}]}})


def test_finalize_rejects_known_remote_reference(case_workspace):
    adapter, repo, workspace, run = case_workspace
    before = adapter.revision(workspace)
    remote = workspace.parent / 'remote.git'
    run('git', 'init', '--bare', str(remote))
    if adapter.is_jj(repo):
        run('jj', '-R', str(repo), 'git', 'remote', 'add', 'origin', str(remote))
    else:
        run('git', '-C', str(repo), 'remote', 'add', 'origin', str(remote))
    adapter.push(workspace, 'remediation/case-42', before)
    with pytest.raises(ValueError, match='remote reference'):
        adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)
    assert adapter.branch_matches(workspace, 'remediation/case-42')


def test_finalize_rejects_unregistered_workspace(case_workspace):
    adapter, repo, workspace, run = case_workspace
    if not adapter.is_jj(repo):
        pytest.skip('Git worktree unregister removes its metadata and cannot retain a usable checkout')
    before = adapter.revision(workspace)
    names = run('jj', '-R', str(repo), 'workspace', 'list', '-T', 'name ++ "\n"').splitlines()
    for name in names:
        candidate = Path(run('jj', '-R', str(repo), 'workspace', 'root', '--name', name))
        if candidate.resolve() == workspace.resolve():
            run('jj', '-R', str(repo), 'workspace', 'forget', name)
            break
    with pytest.raises(ValueError, match='not registered'):
        adapter.finalize_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)


def test_remote_guard_checks_actual_origin_without_fetch(case_workspace):
    adapter, repo, workspace, run = case_workspace
    adapter.ensure_unpublished_branches(workspace, ['remediation/case-42', 'fix/ACME-7'])
    remote = workspace.parent / 'remote.git'
    run('git', 'init', '--bare', str(remote))
    if adapter.is_jj(repo):
        run('jj', '-R', str(repo), 'git', 'remote', 'add', 'origin', str(remote))
    else:
        run('git', '-C', str(repo), 'remote', 'add', 'origin', str(remote))
    adapter.ensure_unpublished_branches(workspace, ['remediation/case-42', 'fix/ACME-7'])
    adapter.push(workspace, 'remediation/case-42', adapter.revision(workspace))
    with pytest.raises(ValueError, match='exists at origin'):
        adapter.ensure_unpublished_branches(workspace, ['remediation/case-42', 'fix/ACME-7'])


def test_verify_finalization_rejects_other_existing_branch(case_workspace):
    adapter, repo, workspace, _run = case_workspace
    before = adapter.revision(workspace)
    adapter.create_workspace(repo, workspace.parent / 'other-case', 'fix/ACME-7', 'main')
    with pytest.raises(ValueError, match='replace the old branch'):
        adapter.verify_finalized_branch(workspace, 'remediation/case-42', 'fix/ACME-7', before)


@pytest.mark.parametrize('name', ['@', '@{-1}', '-invalid', 'bad..name', ''])
def test_prepare_finalization_rejects_invalid_branch_names(case_workspace, name):
    adapter, _repo, workspace, _run = case_workspace
    with pytest.raises(ValueError, match='valid Git branch'):
        adapter.prepare_branch_finalization(workspace, 'remediation/case-42', name, adapter.revision(workspace))
    assert adapter.branch_matches(workspace, 'remediation/case-42')


def test_prepare_rejects_expanded_branch_shorthand_with_checkout_history(case_workspace):
    adapter, _repo, workspace, run = case_workspace
    if adapter.is_jj(workspace):
        pytest.skip('Git checkout shorthand applies to Git worktrees')
    run('git', '-C', str(workspace), 'switch', '-c', 'other-branch')
    run('git', '-C', str(workspace), 'switch', 'remediation/case-42')
    assert run('git', '-C', str(workspace), 'check-ref-format', '--branch', '@{-1}') == 'other-branch'
    with pytest.raises(ValueError, match='valid Git branch'):
        adapter.prepare_branch_finalization(workspace, 'remediation/case-42', '@{-1}', adapter.revision(workspace))
    assert adapter.branch_matches(workspace, 'remediation/case-42')
