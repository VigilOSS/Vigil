"""Canonical repository-owned PROJECT.md configuration for remediation."""
from __future__ import annotations

from datetime import date, datetime, time
import hashlib
import json
import os
from pathlib import Path
import tomllib

_FIELDS = ('repository', 'development_url', 'test_url', 'production_url', 'browser_cdp_url', 'deployment_workflow', 'base_branch', 'workspace_directory')
_STAGEHAND_FIELDS = ('model', 'approved_account', 'api_key_env')
_POLICY_STRINGS = ('source_reader', 'hook_policy', 'pr_template', 'deployment_skill', 'shared_environment')
_POLICY_LISTS = ('instruction_files', 'skills', 'mcps', 'pr_guidance', 'deployment_test_inputs', 'borrowed_dependency_manifests')


def parse_project(path: Path) -> dict[str, object]:
    source = path.expanduser().resolve()
    lines = source.read_text(encoding='utf-8').splitlines()
    if not lines or lines[0] != '+++':
        raise ValueError(f'{path}: PROJECT.md requires TOML frontmatter delimited by +++')
    try:
        end = lines.index('+++', 1)
    except ValueError:
        raise ValueError(f'{path}: missing closing +++ frontmatter delimiter') from None
    try:
        config = tomllib.loads('\n'.join(lines[1:end]))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f'{path}: invalid PROJECT.md TOML: {exc}') from exc
    validate_project(config)
    return config


def validate_project(config: dict[str, object]) -> None:
    for key in _FIELDS:
        if key in config and not isinstance(config[key], str):
            raise ValueError(f'PROJECT.md: {key} must be a string (blank when unknown)')
    stagehand = config.get('stagehand', {})
    if not isinstance(stagehand, dict):
        raise ValueError('PROJECT.md: stagehand must be a TOML table')
    for key in _STAGEHAND_FIELDS:
        if key in stagehand and not isinstance(stagehand[key], str):
            raise ValueError(f'PROJECT.md: stagehand.{key} must be a string (blank when unknown)')
    policy = config.get('remediation', {})
    if not isinstance(policy, dict):
        raise ValueError('PROJECT.md: remediation must be a TOML table')
    for key in _POLICY_STRINGS:
        if key in policy and not isinstance(policy[key], str):
            raise ValueError(f'PROJECT.md: remediation.{key} must be a string')
    if policy.get('hook_policy', 'inherit') not in {'inherit', 'disabled'}:
        raise ValueError('PROJECT.md: remediation.hook_policy must be inherit or disabled')
    for key in _POLICY_LISTS:
        if key in policy and (not isinstance(policy[key], list) or any(not isinstance(item, str) or not item.strip() for item in policy[key])):
            raise ValueError(f'PROJECT.md: remediation.{key} must be a list of nonempty strings')
    if any(Path(value).is_absolute() or '..' in Path(value).parts for value in policy.get('borrowed_dependency_manifests', [])):
        raise ValueError('PROJECT.md: remediation.borrowed_dependency_manifests must contain repository-relative paths without ..')
    if 'development_ticket_required' in policy and not isinstance(policy['development_ticket_required'], bool):
        raise ValueError('PROJECT.md: remediation.development_ticket_required must be a boolean')
    checks = policy.get('check_commands', [])
    if not isinstance(checks, list):
        raise ValueError('PROJECT.md: remediation.check_commands must be a list of tables')
    names = set()
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError('PROJECT.md: remediation.check_commands entries must be tables')
        for key in ('name', 'command'):
            if not isinstance(check.get(key), str) or not check[key].strip():
                raise ValueError(f'PROJECT.md: remediation.check_commands.{key} must be a nonempty string')
        if check['name'] in names:
            raise ValueError('PROJECT.md: remediation.check_commands name must be unique')
        names.add(check['name'])
        directory = check.get('directory', '.')
        if not isinstance(directory, str) or Path(directory).is_absolute() or '..' in Path(directory).parts:
            raise ValueError('PROJECT.md: remediation.check_commands.directory must stay within the case workspace')
    inputs = policy.get('deployment_inputs', {})
    if not isinstance(inputs, dict) or any(not isinstance(value, (str, bool)) for value in inputs.values()):
        raise ValueError('PROJECT.md: remediation.deployment_inputs must contain string or boolean values')


def load_project(path: Path) -> dict[str, object]:
    source = path.expanduser().resolve()
    config = parse_project(source)
    for key in _FIELDS:
        name = f'VIGIL_REMEDIATION_{key.upper()}'
        if name in os.environ:
            config[key] = os.environ[name]
    stagehand = dict(config.get('stagehand', {}))
    for key in _STAGEHAND_FIELDS:
        name = f'VIGIL_REMEDIATION_STAGEHAND_{key.upper()}'
        if name in os.environ:
            stagehand[key] = os.environ[name]
    config['stagehand'] = stagehand
    repository = config.get('repository', '')
    if repository:
        config['repository'] = str((source.parent / Path(repository).expanduser()).resolve())
    workspace = config.get('workspace_directory', '')
    if workspace:
        repo = Path(config.get('repository') or source.parent)
        destination = (repo / Path(workspace).expanduser()).resolve()
        if not destination.is_relative_to(repo.resolve()):
            raise ValueError('PROJECT.md: workspace_directory must stay within the repository')
        config['workspace_directory'] = str(destination)
    policy = dict(config.get('remediation', {}))
    for key in ('instruction_files', 'pr_guidance'):
        if key in policy:
            policy[key] = [str((source.parent / Path(item).expanduser()).resolve()) for item in policy[key]]
    if policy.get('pr_template'):
        policy['pr_template'] = str((source.parent / Path(policy['pr_template']).expanduser()).resolve())
    config['remediation'] = policy
    config['_profile_path'] = str(source)
    return config


def load_engagement_project(root: Path) -> dict[str, object]:
    path = root / 'PROJECT.md'
    if not path.is_file():
        raise ValueError('Missing canonical PROJECT.md; explicitly import legacy remediation-project.json with engagement create --project-config into a repository PROJECT.md before continuing')
    return load_project(path)


def effective_policy(config: dict[str, object]) -> dict[str, object]:
    """Return execution defaults without making company integrations mandatory."""
    policy = dict(config.get('remediation', {}))
    for key in _POLICY_LISTS:
        policy.setdefault(key, [])
    for key in _POLICY_STRINGS:
        policy.setdefault(key, 'inherit' if key == 'hook_policy' else '')
    policy.setdefault('check_commands', [])
    policy.setdefault('development_ticket_required', False)
    policy.setdefault('deployment_inputs', {})
    policy['base_branch'] = config.get('base_branch') or 'main'
    policy['workspace_directory'] = config.get('workspace_directory', '')
    return policy


def workspace_path(config: dict[str, object], case_directory: Path, branch: str) -> Path:
    destination = config.get('workspace_directory', '')
    if not destination:
        return case_directory / 'worktree'
    name = Path(branch)
    if not branch or name.is_absolute() or any(part in {'.', '..'} for part in branch.split('/')):
        raise ValueError('Case branch must identify a repository-local workspace')
    parent = Path(destination).resolve()
    path = (parent / name).resolve()
    if not path.is_relative_to(parent):
        raise ValueError('Case branch must identify a repository-local workspace')
    return path


def policy_digest(config: dict[str, object]) -> str:
    """Bind approvals to effective configuration and the referenced guidance bytes."""
    policy = effective_policy(config)
    paths = [*policy['instruction_files'], *policy['pr_guidance']]
    if policy['pr_template']:
        paths.append(policy['pr_template'])
    if config.get('_profile_path'):
        paths.append(config['_profile_path'])
    references = {}
    for value in paths:
        path = Path(value)
        try:
            references[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            # Removal or loss of access invalidates an earlier approval too.
            references[str(path)] = {'unavailable': type(exc).__name__}
    payload = {'configuration': config, 'references': references}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def _toml_value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, list):
        return '[' + ', '.join(_toml_value(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{' + ', '.join(f'{json.dumps(key)} = {_toml_value(item)}' for key, item in value.items()) + '}'
    raise ValueError(f'PROJECT.md: cannot render TOML value {type(value).__name__}')


def _toml_key(key: str) -> str:
    return key if key and all(char.isascii() and (char.isalnum() or char in '_-') for char in key) else json.dumps(key)


def _toml_table(values: dict[str, object], path: tuple[str, ...] = ()) -> list[str]:
    lines = [f'[{".".join(_toml_key(key) for key in path)}]'] if path else []
    for key, value in values.items():
        if not isinstance(value, dict):
            lines.append(f'{_toml_key(key)} = {_toml_value(value)}')
    for key, value in values.items():
        if isinstance(value, dict):
            lines.extend(_toml_table(value, (*path, key)))
    return lines


def render_project(config: dict[str, object], title: str) -> str:
    validate_project(config)
    values = {key: config.get(key, '') for key in _FIELDS}
    values.update({key: value for key, value in config.items() if key != '_profile_path'})
    values['stagehand'] = {key: values.get('stagehand', {}).get(key, '') for key in _STAGEHAND_FIELDS} | values.get('stagehand', {})
    lines = ['+++', *_toml_table(values)]
    lines.extend(['+++', '', f'# {title} remediation', '',
        'Fill known configuration values from the repository and explicit owner instructions. Ask the owner for missing values; leave unknown values blank and never guess.', '',
        'Repository and instruction references are relative to this file; workspace_directory is relative to the repository. Machine-specific overrides use VIGIL_REMEDIATION_<FIELD> environment variables; Stagehand overrides use VIGIL_REMEDIATION_STAGEHAND_<FIELD>. api_key_env names an environment variable containing the approved provider key.', '',
        '## Environment and accounts', '', 'Record account, fixture, and development setup prerequisites here.', '',
        '## Case workflow', '', 'Keep one workspace per case. Select source readers, relevant skills, instruction references, and automated checks in the remediation table. Agree on verification appropriate to the fix; record actual evidence and review through vigil remediation.', '',
        '## Release', '', 'Use the configured PR template and deployment workflow. Ask before publishing or deploying; record the run ID and observed revision before claiming verification.', ''])
    return '\n'.join(lines)
