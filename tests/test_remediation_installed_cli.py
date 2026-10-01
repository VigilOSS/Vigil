from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.parametrize('interactive', [False, True])
def test_installed_creation_uses_explicit_root_without_default_install(tmp_path, interactive):
    repo_root = Path(__file__).resolve().parents[1]
    site = tmp_path / 'site'
    shutil.copytree(repo_root / 'src' / 'vigil_cli', site / 'vigil_cli', ignore=shutil.ignore_patterns('__pycache__'))
    install = tmp_path / 'custom-install'
    library = install / 'agent' / 'scripts' / 'assess' / 'lib'
    library.mkdir(parents=True)
    for relative in ('__init__.py', 'lib/__init__.py', 'lib/remediation_vcs.py', 'lib/remediation_project.py'):
        source = repo_root / 'agent' / 'scripts' / 'assess' / relative
        shutil.copy2(source, install / 'agent' / 'scripts' / 'assess' / relative)
    repository = tmp_path / 'application'
    subprocess.run(['git', 'init', str(repository)], check=True, capture_output=True)
    argv = ['--root', str(install), 'engagement', 'create', '--type', 'remediation', '--name', 'Example', '--dry-run', '--json']
    if not interactive:
        argv += ['--repo', str(repository), '--no-prompt']
    script = '''
import builtins, json
from pathlib import Path
from types import SimpleNamespace
from vigil_cli import main, paths
assert Path(main.__file__).is_relative_to(Path(SITE))
assert paths.find_repo_root(Path(main.__file__)) is None
main.sys.stdin = SimpleNamespace(isatty=lambda: INTERACTIVE)
main._uses_prompt_ui = lambda: False
builtins.input = lambda: REPOSITORY
main.main(ARGV)
'''
    script = ('SITE = ' + repr(str(site)) + '\nINTERACTIVE = ' + repr(interactive)
              + '\nREPOSITORY = ' + repr(str(repository)) + '\nARGV = ' + repr(argv) + '\n' + script)
    environment = {**os.environ, 'PYTHONPATH': str(site), 'VIGIL_INSTALL_DIR': str(tmp_path / 'absent-default')}
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['manifest']['repos'] == [{'path': str(repository), 'name': 'application'}]
    assert not (install / 'agent' / 'engagements').exists()
