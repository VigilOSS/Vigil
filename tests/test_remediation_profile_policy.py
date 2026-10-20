from pathlib import Path

import pytest

from vigil_cli.project_config import project_module


@pytest.fixture
def project():
    return project_module(Path(__file__).resolve().parents[1])


def test_render_preserves_repository_policy_and_extension_tables(project, tmp_path):
    config = {
        'repository': '.', 'base_branch': 'develop', 'workspace_directory': 'worktrees',
        'remediation': {
            'instruction_files': ['AGENTS.md'], 'skills': ['write-test-plan'],
            'mcps': ['tickets'], 'source_reader': 'tickets.read', 'hook_policy': 'disabled',
            'check_commands': [{'name': 'unit', 'command': 'python -m pytest', 'directory': 'app'}],
            'pr_template': '.github/pull_request_template.md', 'pr_guidance': ['runbook.md'],
            'development_ticket_required': True, 'deployment_skill': 'deploy-dev',
            'deployment_inputs': {'run_tests': False, 'environment': 'development'},
            'deployment_test_inputs': ['run_tests'],
            'borrowed_dependency_manifests': ['private/composer.lock', 'package-lock.json'],
        },
        'extension': {'enabled': True, 'threshold': 3, 'labels': ['security']},
        'extension.version': '1.2',
    }
    path = tmp_path / 'PROJECT.md'
    path.write_text(project.render_project(config, 'Acme'))
    actual = project.parse_project(path)
    for key, value in config.items():
        assert actual[key] == value


@pytest.mark.parametrize('policy, message', [
    ({'hook_policy': 'silent'}, 'hook_policy'),
    ({'shared_environment': ['local']}, 'shared_environment'),
    ({'deployment_test_inputs': ['']}, 'deployment_test_inputs'),
    ({'borrowed_dependency_manifests': ['']}, 'borrowed_dependency_manifests'),
    ({'borrowed_dependency_manifests': ['/tmp/package-lock.json']}, 'borrowed_dependency_manifests'),
    ({'borrowed_dependency_manifests': ['../main/package-lock.json']}, 'borrowed_dependency_manifests'),
    ({'instruction_files': 'AGENTS.md'}, 'instruction_files'),
    ({'mcps': [2]}, 'mcps'),
    ({'development_ticket_required': 'yes'}, 'development_ticket_required'),
    ({'check_commands': ['pytest']}, 'check_commands'),
    ({'check_commands': [{'name': 'unit'}]}, 'command'),
    ({'check_commands': [{'name': 'unit', 'command': 'pytest', 'directory': '../main'}]}, 'directory'),
    ({'check_commands': [{'name': 'unit', 'command': 'pytest'}, {'name': 'unit', 'command': 'lint'}]}, 'name'),
])
def test_invalid_execution_policy_rejected(project, policy, message):
    with pytest.raises(ValueError, match=message):
        project.validate_project({'remediation': policy})


def test_loaded_policy_resolves_references_and_repo_local_workspace(project, tmp_path):
    profile_dir = tmp_path / 'profiles'
    profile_dir.mkdir()
    repo = tmp_path / 'application'
    repo.mkdir()
    profile = profile_dir / 'PROJECT.md'
    profile.write_text('+++\nrepository = "../application"\nbase_branch = "develop"\nworkspace_directory = "worktrees"\n[remediation]\ninstruction_files = ["../application/AGENTS.md"]\npr_template = "../application/.github/pull_request_template.md"\npr_guidance = ["runbook.md"]\n+++\n')
    config = project.load_project(profile)
    assert config['workspace_directory'] == str(repo / 'worktrees')
    assert config['remediation']['instruction_files'] == [str(repo / 'AGENTS.md')]
    assert config['remediation']['pr_template'] == str(repo / '.github/pull_request_template.md')
    assert config['remediation']['pr_guidance'] == [str(profile_dir / 'runbook.md')]
    assert project.workspace_path(config, tmp_path / '42', 'security/SEC-123') == repo / 'worktrees/case-42'


def test_legacy_profile_defaults_and_workspace_path_traversal(project, tmp_path):
    profile = tmp_path / 'PROJECT.md'
    profile.write_text('+++\nrepository = "."\n+++\n')
    config = project.load_project(profile)
    assert project.effective_policy(config)['base_branch'] == 'main'
    assert project.effective_policy(config)['hook_policy'] == 'inherit'
    assert project.effective_policy(config)['deployment_test_inputs'] == []
    assert project.effective_policy(config)['borrowed_dependency_manifests'] == []
    assert project.workspace_path(config, tmp_path / 'case', 'security/fix') == tmp_path / 'case/worktree'
    config['workspace_directory'] = str(tmp_path / 'worktrees')
    with pytest.raises(ValueError, match='numeric case ID'):
        project.workspace_path(config, tmp_path / '../outside', 'security/fix')
