import pytest
import subprocess
import json
from pydantic import ValidationError

from app.api.remediation import VerificationRequirement
from test_remediation_policy import BASE, case, workspace


def test_red_requirement_names_fix_files_and_expected_failure():
    requirement = VerificationRequirement(kind='red-test', methods=['pytest'], outcome='failed_as_expected',
                                          fix_paths=['src/accounts.py'])
    assert requirement.fix_paths == ['src/accounts.py']


@pytest.mark.parametrize('fields', [
    {'fix_paths': []}, {'execution': 'reasoned'}, {'outcome': 'passed'}, {'fix_paths': ['../accounts.py']},
    {'fix_paths': ['src/accounts.py', 'src/accounts.py']},
])
def test_red_requirement_rejects_unusable_proof(fields):
    values = {'kind': 'red-test', 'methods': ['pytest'], 'outcome': 'failed_as_expected', 'fix_paths': ['src/accounts.py']}
    values.update(fields)
    with pytest.raises(ValidationError):
        VerificationRequirement(**values)


def test_red_evidence_requires_scratch_provenance(client, isolate_settings):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    proof = root / 'remediation/cases' / str(item['id']) / 'red.txt'
    proof.write_text('AssertionError\n')
    response = client.post(f"{BASE}/cases/{item['id']}/evidence", json={
        'kind': 'red-test', 'method': 'pytest', 'environment': 'local', 'outcome': 'failed_as_expected',
        'command': 'pytest', 'observed': 'AssertionError', 'proved': 'Expected failure', 'revision': revision,
        'executed_revision': revision, 'artifact_path': str(proof.relative_to(root)),
    })
    assert response.status_code == 400
    assert 'scratch' in response.json()['detail']


@pytest.mark.parametrize('tamper', [None, 'tree', 'output', 'path-null', 'path-object', 'path-number', 'output-list'])
def test_red_proof_matches_reconstructed_scratch_tree(client, isolate_settings, tamper):
    from assess.lib.remediation_regression import scratch_source

    root, item = case(client, isolate_settings)
    path, base = workspace(client, root, item)
    (path / 'fix.py').write_text('fixed = False\n')
    (path / 'test_fix.py').write_text('from fix import fixed\nassert fixed is False\n')
    subprocess.run(['git', '-C', str(path), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(path), '-c', 'user.name=Acme Test', '-c', 'user.email=test@example.com',
                    'commit', '-qm', 'Fix with regression'], check=True)
    head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    endpoint = f"{BASE}/cases/{item['id']}"
    assert client.patch(endpoint, json={'worktree_revision': head, 'base_revision': base, 'base_branch': 'main'}).status_code == 200
    requirements = [
        {'kind': 'red-test', 'methods': ['pytest'], 'outcome': 'failed_as_expected', 'fix_paths': ['fix.py']},
        {'kind': 'green-test', 'methods': ['pytest']},
    ]
    assert client.patch(endpoint + '/verification-plan', json={
        'verification_plan': 'Regression proves the fix', 'requirements': requirements, 'alternatives_reason': 'Native test',
    }).status_code == 200
    with scratch_source(path, base, head, ['fix.py']) as (scratch, proof):
        run = subprocess.run(['python3', 'test_fix.py'], cwd=scratch, capture_output=True, text=True)
        assert run.returncode != 0
        proof.update(expected_failure='AssertionError', exit_code=run.returncode)
        if tamper == 'tree':
            proof['scratch_tree'] = '0' * 40
        invalid_paths = {'path-null': [None], 'path-object': [{}], 'path-number': [1]}
        if tamper in invalid_paths:
            proof['reverted_paths'] = invalid_paths[tamper]
        artifact = root / 'remediation/cases' / str(item['id']) / 'red.txt'
        artifact.write_text(json.dumps({'command': 'python3 test_fix.py', 'revision': head, 'exit_code': run.returncode,
                                        'stdout': [] if tamper == 'output-list' else run.stdout,
                                        'stderr': (['AssertionError'] if tamper == 'output-list'
                                                   else '' if tamper == 'output' else run.stderr),
                                        'source_changed': False,
                                        'scratch_proof': proof}))
        response = client.post(endpoint + '/evidence', json={
            'kind': 'red-test', 'method': 'pytest', 'environment': 'local', 'outcome': 'failed_as_expected',
            'command': 'python3 test_fix.py', 'observed': 'AssertionError', 'proved': 'Expected regression failure',
            'revision': head, 'executed_revision': head, 'executed_directory': str(scratch),
            'artifact_path': str(artifact.relative_to(root)), 'scratch_proof': proof,
        })
        assert response.status_code == (400 if tamper else 201), response.text
    if not tamper:
        missing = client.get(endpoint).json()['review_evidence_missing']
        assert missing == ['green-test (executed, current revision)']
