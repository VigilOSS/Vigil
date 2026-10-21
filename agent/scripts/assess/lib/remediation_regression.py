"""Disposable regression source: retain tests while restoring explicit fix files."""

from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import shutil
import json
import subprocess
import tempfile
import uuid

from . import remediation_vcs as vcs


def _run(args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True, timeout=30).stdout.strip()


def changed_paths(repo: Path, base: str, head: str) -> set[str]:
    if vcs.is_jj(repo):
        store = vcs._jj_store(repo) / 'store'
        git_dir = (store / (store / 'git_target').read_text().strip()).resolve()
        args = ['git', '--git-dir', str(git_dir)]
    else:
        args = ['git', '-C', str(repo)]
    result = subprocess.run([*args, 'diff', '--name-only', '-z', '--no-renames', base, head],
                            check=True, capture_output=True, timeout=30)
    return {value.decode('utf-8', errors='surrogateescape') for value in result.stdout.split(b'\0') if value}


def validate_fix_paths(repo: Path, base: str, head: str, paths: list[str]) -> list[str]:
    if not paths or not all(isinstance(path, str) for path in paths) or len(paths) != len(set(paths)):
        raise ValueError('Name distinct fix files to restore; keep regression tests in the scratch source')
    changed = changed_paths(repo, base, head)
    for value in paths:
        path = PurePosixPath(value)
        if path.is_absolute() or '..' in path.parts or str(path) != value or value not in changed:
            raise ValueError(f'Fix path must name a changed repository-relative file: {value}')
    return sorted(paths)


@contextmanager
def scratch_source(repo: Path, base: str, head: str, paths: list[str]):
    base, head = vcs.resolve_revision(repo, base), vcs.resolve_revision(repo, head)
    paths = validate_fix_paths(repo, base, head, paths)
    temporary = Path(tempfile.mkdtemp(prefix='vigil-regression-'))
    scratch = temporary / 'source'
    name = 'regression-' + uuid.uuid4().hex
    registered = False
    try:
        if vcs.is_jj(repo):
            _run(vcs.command(repo, 'workspace', 'add', '--name', name, '--sparse-patterns', 'full', '-r', head, str(scratch)))
        else:
            _run(['git', '-C', str(repo), 'worktree', 'add', '--detach', str(scratch), head])
        registered = True
        if vcs.is_jj(scratch):
            _run(vcs.command(scratch, 'restore', '--from', base, *[f'file:{json.dumps(p, ensure_ascii=False)}' for p in paths]), cwd=scratch)
            scratch_revision = vcs.revision(scratch)
            tree = vcs.tree_id(scratch, scratch_revision)
        else:
            _run(['git', '--literal-pathspecs', '-C', str(scratch), 'restore', '--source', base, '--staged', '--worktree', '--', *paths])
            tree = _run(['git', '-C', str(scratch), 'write-tree'])
        yield scratch, {'base_revision': base, 'head_revision': head, 'reverted_paths': paths, 'scratch_tree': tree}
    finally:
        try:
            if registered:
                if vcs.is_jj(repo):
                    _run(vcs.command(repo, 'workspace', 'forget', name))
                else:
                    _run(['git', '-C', str(repo), 'worktree', 'remove', '--force', str(scratch)])
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
