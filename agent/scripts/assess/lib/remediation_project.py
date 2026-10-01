"""Canonical repository-owned PROJECT.md configuration for remediation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tomllib

_FIELDS = ('repository', 'development_url', 'test_url', 'production_url', 'browser_cdp_url', 'deployment_workflow')
_STAGEHAND_FIELDS = ('model', 'approved_account', 'api_key_env')


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
    return config


def load_engagement_project(root: Path) -> dict[str, object]:
    path = root / 'PROJECT.md'
    if not path.is_file():
        raise ValueError('Missing canonical PROJECT.md; explicitly import legacy remediation-project.json with engagement create --project-config into a repository PROJECT.md before continuing')
    return load_project(path)


def render_project(config: dict[str, object], title: str) -> str:
    validate_project(config)
    lines = ['+++']
    for key in _FIELDS:
        lines.append(f'{key} = {json.dumps(config.get(key, ""), ensure_ascii=False)}')
    lines.append('[stagehand]')
    stagehand = config.get('stagehand', {})
    for key in _STAGEHAND_FIELDS:
        lines.append(f'{key} = {json.dumps(stagehand.get(key, ""), ensure_ascii=False)}')
    lines.extend(['+++', '', f'# {title} remediation', '',
        'Fill known configuration values from the repository and explicit owner instructions. Ask the owner for missing values; leave unknown values blank and never guess.', '',
        'Repository paths are relative to this file. Machine-specific overrides use VIGIL_REMEDIATION_<FIELD> environment variables; Stagehand overrides use VIGIL_REMEDIATION_STAGEHAND_<FIELD>. api_key_env names an environment variable containing the approved provider key.', '',
        '## Environment and accounts', '', 'Record account, fixture, and development setup prerequisites here.', '',
        '## Case workflow', '', 'Keep one worktree per case. Record baseline, red/green tests, browser rehearsal, review, deployment identity, and human verification through vigil remediation.', '',
        '## Release', '', 'The first development deployment is a human GitHub Actions handoff. Record its run ID and observed revision before claiming verification.', ''])
    return '\n'.join(lines)
