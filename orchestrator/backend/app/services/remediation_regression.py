"""Validate scratch regression provenance against immutable case source."""

import json
from pathlib import Path
import subprocess

from fastapi import HTTPException


def validate_proof(row, data, revision):
    from .remediation import _vcs
    from assess.lib.remediation_regression import scratch_source

    proof = data.get('scratch_proof')
    if data['kind'] != 'red-test':
        if proof is not None:
            raise HTTPException(400, 'Scratch proof belongs to red-test evidence')
        return None
    if not isinstance(proof, dict) or not row['worktree_path'] or not row['base_revision']:
        raise HTTPException(400, 'Run remediation test to record red evidence with scratch source provenance')
    if (data.get('execution', 'executed') != 'executed' or data.get('environment') != 'local'
            or data.get('shared_environment') or not data.get('command', '').strip()
            or data.get('executed_revision') != revision or not data.get('artifact_path')
            or not isinstance(proof.get('expected_failure'), str) or not proof['expected_failure'].strip()
            or proof.get('head_revision') != revision or not isinstance(proof.get('reverted_paths'), list)):
        raise HTTPException(400, 'Red evidence requires executed source, saved output, expected failure and reverted files')
    if data.get('outcome') == 'failed_as_expected' and (type(proof.get('exit_code')) is not int or proof['exit_code'] <= 0):
        raise HTTPException(400, 'Expected regression failure requires a positive command exit code')
    path = Path(row['worktree_path'])
    try:
        if revision != row['worktree_revision'] or proof.get('base_revision') != row['base_revision']:
            raise ValueError('Scratch proof must use the current case revision and recorded review base')
        with scratch_source(path, row['base_revision'], revision, proof['reverted_paths']) as (_, actual):
            if actual['scratch_tree'] != proof.get('scratch_tree'):
                raise ValueError('Scratch tree differs from the current source with the named fix files restored')
        return {**proof, 'base_tree': _vcs.tree_id(path, row['base_revision']), 'source_tree': _vcs.tree_id(path, revision)}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise HTTPException(400, f'Invalid scratch proof: {exc}') from exc


def proof_satisfies(row, item, requirement=None):
    from .remediation import _tree_id

    try:
        proof = json.loads(item.get('scratch_proof_json') or 'null')
        if not proof or not item.get('executed_directory') or item.get('executed_revision') != item.get('revision'):
            return False
        if requirement and sorted(requirement.get('fix_paths', [])) != proof['reverted_paths']:
            return False
        path = Path(row['worktree_path'])
        return bool(proof['expected_failure'] and proof['scratch_tree'] != proof['source_tree']
                    and proof['source_tree'] == item.get('tree_id')
                    and proof['base_tree'] == _tree_id(path, row['base_revision']))
    except (KeyError, TypeError, OSError, ValueError, subprocess.SubprocessError):
        return False
