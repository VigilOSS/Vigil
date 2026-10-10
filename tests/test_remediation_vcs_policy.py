import subprocess
from pathlib import Path

import pytest

from vigil_cli.remediation_vcs import adapter


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture(params=['git', 'jj', 'colocated-jj'])
def vcs_repo(tmp_path, request):
    vcs = adapter(Path(__file__).resolve().parents[1])
    repo = tmp_path / 'repository'
    if request.param == 'git':
        run('git', 'init', '-b', 'develop', str(repo))
        run('git', '-C', str(repo), 'config', 'user.name', 'Acme Test')
        run('git', '-C', str(repo), 'config', 'user.email', 'test@example.com')
        (repo / 'application.txt').write_text('baseline\n')
        run('git', '-C', str(repo), 'add', '.')
        run('git', '-C', str(repo), 'commit', '-m', 'Baseline')
    else:
        run('jj', 'git', 'init', '--colocate' if request.param == 'colocated-jj' else '--no-colocate', str(repo))
        run(*vcs.command(repo, 'config', 'set', '--repo', 'user.name', 'Acme Test'))
        run(*vcs.command(repo, 'config', 'set', '--repo', 'user.email', 'test@example.com'))
        (repo / 'application.txt').write_text('baseline\n')
        run(*vcs.command(repo, 'describe', '-m', 'Baseline'))
        run(*vcs.command(repo, 'bookmark', 'create', 'develop', '-r', '@'))
        run(*vcs.command(repo, 'new'))
    base = vcs.resolve_revision(repo, 'develop')
    workspace = tmp_path / 'worktrees' / 'security' / 'SEC-123'
    workspace.parent.mkdir(parents=True)
    vcs.create_workspace(repo, workspace, 'security/SEC-123', 'develop')
    return vcs, repo, workspace, base


def commit(vcs, workspace, message):
    if vcs.is_jj(workspace):
        run(*vcs.command(workspace, 'describe', '-m', message))
    else:
        run('git', '-C', str(workspace), 'add', '.')
        run('git', '-C', str(workspace), 'commit', '-m', message)
    return vcs.revision(workspace)


def test_review_uses_configured_branch_and_preserves_stored_base(vcs_repo):
    vcs, repo, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('fixed\n')
    commit(vcs, workspace, 'Fix')
    assert vcs.registered(repo, workspace)
    assert vcs.review_base(workspace, 'develop') == base
    assert vcs.review_base(workspace, 'develop', base_revision=base) == base
    # A profile branch rename must not retarget an already captured review base.
    assert vcs.review_base(workspace, 'no-longer-configured', base_revision=base) == base


def test_review_rejects_stored_nonancestor(vcs_repo):
    vcs, repo, workspace, _ = vcs_repo
    (repo / 'unrelated.txt').write_text('root work\n')
    unrelated = commit(vcs, repo, 'Unrelated root work')
    with pytest.raises(ValueError, match='ancestor'):
        vcs.review_base(workspace, 'develop', base_revision=unrelated)


def test_review_prefers_origin_bookmark_over_moved_local_branch(vcs_repo, tmp_path):
    vcs, repo, workspace, base = vcs_repo
    if vcs.is_jj(repo):
        remote = tmp_path / 'remote.git'
        run('git', 'init', '--bare', str(remote))
        run(*vcs.command(repo, 'git', 'remote', 'add', 'origin', str(remote)))
        run(*vcs.command(repo, 'git', 'push', '--remote', 'origin', '--bookmark', 'exact:develop'))
    else:
        run('git', '-C', str(repo), 'update-ref', 'refs/remotes/origin/develop', base)
    (workspace / 'application.txt').write_text('fixed\n')
    head = commit(vcs, workspace, 'Fix')
    if vcs.is_jj(repo):
        run(*vcs.command(workspace, 'bookmark', 'move', 'develop', '--to', head))
    else:
        run('git', '-C', str(repo), 'update-ref', 'refs/heads/develop', head)
    assert vcs.review_base(workspace, 'develop') == base


def test_publish_rejects_changed_content_before_any_push(vcs_repo):
    vcs, _, workspace, base = vcs_repo
    (workspace / 'application.txt').write_text('unapproved\n')
    with pytest.raises(ValueError, match='changed after approval'):
        vcs.push(workspace, 'security/SEC-123', base)


def test_workspace_creation_creates_nested_parent_directories(vcs_repo, tmp_path):
    vcs, repo, _, _ = vcs_repo
    nested = tmp_path / 'new-worktrees' / 'security' / 'SEC-124'
    vcs.create_workspace(repo, nested, 'security/SEC-124', 'develop')
    assert vcs.registered(repo, nested)


def attach_remote(vcs, repo, tmp_path):
    remote = tmp_path / 'publish.git'
    run('git', 'init', '--bare', str(remote))
    if vcs.is_jj(repo):
        run(*vcs.command(repo, 'git', 'remote', 'add', 'origin', str(remote)))
    else:
        run('git', '-C', str(repo), 'remote', 'add', 'origin', str(remote))
    return remote


@pytest.mark.parametrize("local_base", ["remote-only", "stale-local"])
def test_new_workspace_starts_from_fetched_origin_base(vcs_repo, tmp_path, local_base):
    vcs, repo, _, base = vcs_repo
    remote = attach_remote(vcs, repo, tmp_path)
    if vcs.is_jj(repo):
        run(*vcs.command(repo, 'git', 'push', '--remote', 'origin', '--bookmark', 'exact:develop'))
    else:
        run('git', '-C', str(repo), 'push', 'origin', 'develop')
    upstream = tmp_path / 'upstream'
    run('git', 'clone', '--branch', 'develop', str(remote), str(upstream))
    run('git', '-C', str(upstream), 'config', 'user.name', 'Acme Test')
    run('git', '-C', str(upstream), 'config', 'user.email', 'test@example.com')
    (upstream / 'application.txt').write_text('current upstream base\n')
    run('git', '-C', str(upstream), 'add', '.')
    run('git', '-C', str(upstream), 'commit', '-m', 'Advance integration branch')
    tip = run('git', '-C', str(upstream), 'rev-parse', 'HEAD')
    run('git', '-C', str(upstream), 'push', 'origin', 'develop')
    if vcs.is_jj(repo):
        run(*vcs.command(repo, 'git', 'fetch', '--remote', 'origin'))
        if local_base == 'remote-only':
            run(*vcs.command(repo, 'bookmark', 'delete', 'develop'))
        else:
            run(*vcs.command(repo, 'bookmark', 'move', 'develop', '--to', base, '--allow-backwards'))
    else:
        run('git', '-C', str(repo), 'fetch', 'origin')
        if local_base == 'remote-only':
            run('git', '-C', str(repo), 'checkout', '--detach', base)
            run('git', '-C', str(repo), 'branch', '-D', 'develop')
    workspace = tmp_path / 'new-workspaces' / 'SEC-124'
    vcs.create_workspace(repo, workspace, 'security/SEC-124', 'develop')
    assert vcs.revision(workspace) == tip
    assert (workspace / 'application.txt').read_text() == 'current upstream base\n'
    assert vcs.review_base(workspace, 'develop') == tip


def test_origin_revision_reads_exact_publishing_branch(vcs_repo, tmp_path):
    vcs, repo, workspace, _ = vcs_repo
    attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('fixed\n')
    approved = commit(vcs, workspace, 'Fix')
    vcs.push(workspace, 'security/SEC-123', approved)
    assert vcs.origin_revision(workspace, 'security/SEC-123') == approved


def test_origin_revision_reports_missing_branch(vcs_repo, tmp_path):
    vcs, repo, workspace, _ = vcs_repo
    attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('fixed\n')
    approved = commit(vcs, workspace, 'Fix')
    vcs.push(workspace, 'security/SEC-123', approved)
    with pytest.raises(ValueError, match='origin'):
        vcs.origin_revision(workspace, 'security/SEC-124')


def test_explicit_pr_update_pushes_reviewed_rewrite_with_remote_lease(vcs_repo, tmp_path):
    vcs, repo, workspace, _ = vcs_repo
    remote = attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('initial fix\n')
    previous = commit(vcs, workspace, 'Initial fix')
    vcs.push(workspace, 'security/SEC-123', previous)
    (workspace / 'application.txt').write_text('reviewed amendment\n')
    if vcs.is_jj(workspace):
        run(*vcs.command(workspace, 'describe', '-m', 'Reviewed amended fix'))
    else:
        run('git', '-C', str(workspace), 'add', '.')
        run('git', '-C', str(workspace), 'commit', '--amend', '-m', 'Reviewed amended fix')
    approved = vcs.revision(workspace)
    assert not vcs.ancestor(workspace, previous, approved)
    vcs.push(workspace, 'security/SEC-123', approved, expected_remote_revision=previous)
    assert run('git', '--git-dir', str(remote), 'rev-parse', 'refs/heads/security/SEC-123') == approved


def test_explicit_pr_update_refuses_unexpected_remote_changes(vcs_repo, tmp_path):
    vcs, repo, workspace, _ = vcs_repo
    remote = attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('initial fix\n')
    previous = commit(vcs, workspace, 'Initial fix')
    vcs.push(workspace, 'security/SEC-123', previous)
    # A mismatched recorded PR head must fail before any bookmark or push mutation.
    with pytest.raises(ValueError, match='remote'):
        vcs.push(workspace, 'security/SEC-123', previous, expected_remote_revision='f' * 40)
    assert run('git', '--git-dir', str(remote), 'rev-parse', 'refs/heads/security/SEC-123') == previous


def test_explicit_pr_update_lease_catches_change_after_remote_read(vcs_repo, tmp_path, monkeypatch):
    vcs, repo, workspace, base = vcs_repo
    remote = attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('initial fix\n')
    previous = commit(vcs, workspace, 'Initial fix')
    vcs.push(workspace, 'security/SEC-123', previous)
    if vcs.is_jj(workspace):
        run(*vcs.command(workspace, 'new'))
    (workspace / 'application.txt').write_text('updated fix\n')
    approved = commit(vcs, workspace, 'Updated fix')
    original_run = vcs._run

    def race(args):
        if 'push' in args:
            run('git', '--git-dir', str(remote), 'update-ref', 'refs/heads/security/SEC-123', base)
        return original_run(args)

    monkeypatch.setattr(vcs, '_run', race)
    with pytest.raises(subprocess.CalledProcessError):
        vcs.push(workspace, 'security/SEC-123', approved, expected_remote_revision=previous)
    assert run('git', '--git-dir', str(remote), 'rev-parse', 'refs/heads/security/SEC-123') == base


def test_push_publishes_only_approved_commit_when_local_bookmark_moves(vcs_repo, tmp_path, monkeypatch):
    vcs, repo, workspace, _ = vcs_repo
    remote = attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('approved fix\n')
    approved = commit(vcs, workspace, 'Approved fix')
    original_run = vcs._run
    changed = False

    def race(args):
        nonlocal changed
        if 'push' in args and not changed:
            changed = True
            if vcs.is_jj(workspace):
                run(*vcs.command(workspace, 'new'))
            (workspace / 'application.txt').write_text('unreviewed local change\n')
            unexpected = commit(vcs, workspace, 'Unreviewed local change')
            if vcs.is_jj(workspace):
                run(*vcs.command(workspace, 'bookmark', 'move', 'security/SEC-123', '--to', unexpected))
        return original_run(args)

    monkeypatch.setattr(vcs, '_run', race)
    vcs.push(workspace, 'security/SEC-123', approved)
    assert changed
    assert run('git', '--git-dir', str(remote), 'rev-parse', 'refs/heads/security/SEC-123') == approved
    assert (workspace / 'application.txt').read_text() == 'unreviewed local change\n'
    if vcs.is_jj(workspace):
        assert vcs.resolve_revision(workspace, 'bookmarks(exact:"security/SEC-123")') == vcs.revision(workspace)


def test_jj_push_refuses_bookmark_move_before_operation_is_pinned(vcs_repo, tmp_path, monkeypatch):
    vcs, repo, workspace, _ = vcs_repo
    if not vcs.is_jj(workspace):
        pytest.skip('Git publishes an immutable refspec without an operation snapshot')
    remote = attach_remote(vcs, repo, tmp_path)
    (workspace / 'application.txt').write_text('approved fix\n')
    approved = commit(vcs, workspace, 'Approved fix')
    original_run = vcs._run

    def race(args):
        if 'op' in args and 'log' in args:
            run(*vcs.command(workspace, 'new'))
            (workspace / 'application.txt').write_text('unreviewed local change\n')
            unexpected = commit(vcs, workspace, 'Unreviewed local change')
            run(*vcs.command(workspace, 'bookmark', 'move', 'security/SEC-123', '--to', unexpected))
        return original_run(args)

    monkeypatch.setattr(vcs, '_run', race)
    with pytest.raises(ValueError, match='bookmark changed'):
        vcs.push(workspace, 'security/SEC-123', approved)
    assert not run('git', '--git-dir', str(remote), 'for-each-ref', '--format=%(refname)')
