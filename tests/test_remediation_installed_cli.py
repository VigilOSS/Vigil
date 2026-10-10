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
    from vigil_cli.install import InstallOptions, install_from_source
    install_from_source(InstallOptions(source_root=repo_root, install_root=install))
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
    environment = {**os.environ, 'PYTHONPATH': str(site), 'VIGIL_INSTALL_DIR': str(tmp_path / 'absent-default'),
                   'VIGIL_APPLICATION_DIR': str(repo_root), 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-c', script], cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['manifest']['repos'] == [{'path': str(repository), 'name': 'application'}]
    assert not list((install / 'engagements').iterdir())
    assert not (install / 'agent').exists()
    assert not (install / 'orchestrator').exists()


def test_workspace_uses_application_remediation_dependencies_and_documentation(tmp_path):
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.paths import agent_root

    source = Path(__file__).resolve().parents[1]
    installed = tmp_path / 'installed'
    install_from_source(InstallOptions(source_root=source, install_root=installed))
    scripts = agent_root(installed) / 'scripts'
    environment = {**os.environ, 'PYTHONPATH': str(scripts)}
    result = subprocess.run(
        [sys.executable, '-c', 'from assess.lib import remediation_project, remediation_vcs; '
         'print(remediation_project.__file__); print(remediation_vcs.__file__)'],
        cwd=tmp_path, env=environment, capture_output=True, text=True, check=True,
    )
    assert all(Path(line).is_relative_to(source) for line in result.stdout.splitlines())
    assert (source / 'docs/remediation.md').is_file()
    assert not (installed / 'agent').exists()
    assert not (installed / 'docs').exists()
