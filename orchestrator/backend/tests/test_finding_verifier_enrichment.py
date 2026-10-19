from __future__ import annotations

import json

import pytest

from tests.test_proof_receipts_api import BASE, _seed, _verified_command_finding


@pytest.fixture
def confirmed(client, isolate_settings):
    _seed(client, isolate_settings)
    command, receipt = _verified_command_finding(client, slug='VA-905', stdout='Acme cross-account response')
    return command, receipt


def test_same_verifier_enrichment_preserves_verdict_and_original_author(client, confirmed):
    command, receipt = confirmed
    before = client.get(f'{BASE}/findings/VA-905').json()
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'source_name': 'Acme verifier display',
        'details': {'steps_to_reproduce': ['Run the bounded Acme request'], 'repro_runs': [command['id']]},
        'evidence_ref': 'evidence/acme-replay.txt', 'evidence_type': 'network-confirmed',
    })
    assert response.status_code == 200, response.text
    finding = client.get(f'{BASE}/findings/VA-905').json()
    assert finding['verification_status'] == 'confirmed'
    assert finding['verification_audit']['claim_review_pending'] is False
    assert finding['provenance']['agent_id'] == before['provenance']['agent_id'] == 'HUNT-1'
    assert finding['verification_audit']['proof_receipt_ids'] == [receipt['id']]
    transitions = client.get(f'{BASE}/findings/VA-905/transitions').json()
    assert transitions[0]['actor'] == 'VERIFY-1'
    detail = client.get(f'{BASE}/findings/VA-905/transitions/{transitions[0]["id"]}').json()
    assert json.loads(detail['metadata_json'])['enrichment'] is True


@pytest.mark.parametrize('editor', [None, 'HUNT-1'])
def test_unattributed_or_other_editor_retains_conservative_claim_review(client, confirmed, editor):
    body = {'details': {'steps_to_reproduce': ['Run the Acme request']}}
    if editor:
        body['dispatch_agent_id'] = editor
    response = client.patch(f'{BASE}/findings/VA-905', json=body)
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_audit']['claim_review_pending'] is True


def test_same_verifier_mixed_material_patch_still_invalidates(client, confirmed):
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'severity': 'high',
        'details': {'steps_to_reproduce': ['Run the Acme request']},
    })
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_status'] == 'unreviewed'


def test_runtime_invalidation_projects_reverification_without_parked_proof(client, confirmed):
    response = client.patch(f'{BASE}/findings/VA-905', json={'severity': 'high'})
    assert response.status_code == 200, response.text
    listing = client.get(f'{BASE}/proof-work').json()
    assert listing['owed'] == []
    assert len(listing['reverification_required']) == 1
    item = listing['reverification_required'][0]
    assert item['finding_slug'] == 'VA-905'
    assert item['invalidating_transition_id'] > 0
    assert item['next_action'] == 'Re-verify the finding; park a new runtime proof plan if execution is still needed.'
    assert client.get(f'{BASE}/resume-brief').json()['proof_work']['reverification_required'] == 1


@pytest.mark.parametrize('terminal', ['finished', 'resolved'])
def test_runtime_invalidation_preserves_terminal_work_history(client, confirmed, terminal):
    from app import db
    with db.get_connection() as connection:
        finding = connection.execute("SELECT * FROM assessment_findings WHERE slug='VA-905'").fetchone()
        binding = {'finding_claim_sha256': 'a' * 64, 'parking_transition_id': None,
                   'source_binding': None, 'source_status': 'not_applicable', 'target_admission': {},
                   'route': 'code', 'objective': 'Historical Acme proof', 'target_hosts': []}
        work_id = connection.execute(
            'INSERT INTO assessment_proof_work(engagement_id,finding_id,binding_digest,binding_json,route,objective,status) VALUES(?,?,?,?,?,?,?)',
            (finding['engagement_id'], finding['id'], 'a' * 64, json.dumps(binding), 'code', 'Historical Acme proof', terminal),
        ).lastrowid
    assert client.patch(f'{BASE}/findings/VA-905', json={'severity': 'high'}).status_code == 200
    for _ in range(2):
        work = client.post(f'{BASE}/proof-work/{work_id}/reconcile').json()
        assert (work['status'], work['queue_state'], work['reverification_required']) == (terminal, 'stale', True)
        assert work['event_count'] == 0


def test_destructive_evidence_replacement_does_not_qualify_as_enrichment(client, confirmed):
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'evidence_ref': 'evidence/acme-original.txt',
    }).status_code == 200
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'evidence_ref': 'evidence/acme-replacement.txt',
    })
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_status'] == 'unreviewed'


def test_exploit_verifier_can_review_claim_equivalence_independently(client, confirmed):
    assert client.post(f'{BASE}/dispatches', json={
        'agent_id': 'EXPLOIT-REVIEW', 'agent_role': 'exploit-developer', 'assessment_mode': 'web',
        'task': 'Review the revised Acme claim',
    }).status_code == 201
    assert client.patch(f'{BASE}/findings/VA-905', json={'summary': 'Clarified Acme boundary'}).status_code == 200
    audit = client.get(f'{BASE}/findings/VA-905').json()['verification_audit']
    response = client.post(f'{BASE}/dispatch-decisions', json={
        'kind': 'claim_equivalence', 'payload': {
            'finding_slug': 'VA-905', 'verdict': 'equivalent',
            'claim_transition_id': audit['claim_transition_id'], 'new_claim_sha256': audit['current_claim_sha256'],
            'verifier_dispatch_agent_id': 'EXPLOIT-REVIEW', 'reason': 'Same evidence and boundary',
        },
    })
    assert response.status_code == 201, response.text


@pytest.mark.parametrize('mode', ['merge', 'append', 'replace'])
def test_enrichment_evaluates_resolved_details_modes_and_retains_receipts(client, confirmed, mode):
    from tests.proof_fixtures import completed_confirm_check
    command, receipt = confirmed
    initial = {'steps_to_reproduce': ['Request the Acme object'], 'repro_runs': [command['id']]}
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': initial,
    }).status_code == 200
    finding = client.get(f'{BASE}/findings/VA-905').json()
    steps = ['Request the Acme object', 'Observe the Acme account boundary']
    additions = {'steps_to_reproduce': steps[1:] if mode == 'append' else steps}
    if mode == 'replace':
        additions = dict(finding['details'], steps_to_reproduce=steps)
    body = {'dispatch_agent_id': 'VERIFY-1', 'details': additions, 'details_mode': mode}
    if mode == 'replace':
        body['expected_row_version'] = finding['row_version']
    response = client.patch(f'{BASE}/findings/VA-905', json=body)
    assert response.status_code == 200, response.text
    finding = client.get(f'{BASE}/findings/VA-905').json()
    assert finding['verification_status'] == 'confirmed'
    assert finding['verification_audit']['claim_review_pending'] is False
    assert finding['details']['repro_runs'] == [command['id']]
    reused = client.post(f'{BASE}/findings/VA-905/verify', json={
        'verification_status': 'confirmed', 'reason_text': 'Repeat the verdict',
        'proof_receipt_ids': [receipt['id']], 'confirm_check': completed_confirm_check(receipt['id']),
    })
    assert reused.status_code == 400, reused.text
    assert 'already supports an earlier verification event' in reused.json()['detail']


def test_same_verifier_removing_reproduction_dependencies_still_requires_review(client, confirmed):
    command, _ = confirmed
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': {'repro_runs': [command['id']]},
    }).status_code == 200
    finding = client.get(f'{BASE}/findings/VA-905').json()
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details_mode': 'replace',
        'expected_row_version': finding['row_version'], 'details': {},
    })
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_audit']['claim_review_pending'] is True


def test_attribution_rejects_unknown_dispatch_without_mutation(client, confirmed):
    before = client.get(f'{BASE}/findings/VA-905').json()
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'MISSING-ACME', 'details': {'steps_to_reproduce': ['Request Acme object']},
    })
    assert response.status_code == 400, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['row_version'] == before['row_version']


@pytest.mark.parametrize('evidence_kind', ['http_exchange', 'browser_action', 'oob_event'])
def test_observed_runtime_event_invalidation_requires_reverification(client, isolate_settings, evidence_kind):
    from tests.proof_fixtures import completed_confirm_check
    from tests.test_proof_receipts_api import _artifact, _complete_run, _link_run, _run

    engagement_dir = _seed(client, isolate_settings)
    finding = client.post(f'{BASE}/findings', json={
        'slug': 'VA-906', 'title': 'Acme observed runtime boundary', 'severity': 'medium',
        'workflow_status': 'active', 'verification_status': 'unreviewed',
        'canonical_location': 'https://acme.example/objects',
        'summary': 'Acme runtime event demonstrated the boundary violation.',
        'source_name': 'vulnerability-analyst', 'provenance': {'agent_id': 'HUNT-1'},
    })
    assert finding.status_code == 201, finding.text
    run = _run(client)
    _link_run(client, run, 'VA-906')
    artifact = _artifact(client, engagement_dir, 'evidence/event.txt', 'Acme cross-account response')
    receipt = client.post(f'{BASE}/proof-receipts', json={
        'run_id': run['id'], 'evidence_kind': evidence_kind, 'artifact_id': artifact['id'],
        'observed_result': 'Acme cross-account response',
    })
    assert receipt.status_code == 201, receipt.text
    _complete_run(client, run)
    verified = client.post(f'{BASE}/findings/VA-906/verify', json={
        'verification_status': 'confirmed', 'reason_text': 'Independent runtime event confirmed the defect.',
        'proof_receipt_ids': [receipt.json()['id']],
        'confirm_check': completed_confirm_check(receipt.json()['id']),
    })
    assert verified.status_code == 200, verified.text
    assert client.patch(f'{BASE}/findings/VA-906', json={'severity': 'high'}).status_code == 200
    assert [item['finding_slug'] for item in client.get(f'{BASE}/proof-work').json()['reverification_required']] == ['VA-906']


@pytest.mark.parametrize(('field', 'value'), [
    ('evidence_ref', 'evidence/acme-proof.txt'), ('evidence_type', 'network-confirmed'),
])
def test_standalone_evidence_enrichment_records_lossless_audit(client, confirmed, field, value):
    before = client.get(f'{BASE}/findings/VA-905').json()
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', field: value,
    })
    assert response.status_code == 200, response.text
    assert response.json()['finding']['verification_status'] == 'confirmed'
    transition = response.json()['transition']
    assert transition is not None
    assert transition['actor'] == 'VERIFY-1'
    detail = client.get(f'{BASE}/findings/VA-905/transitions/{transition["id"]}').json()
    metadata = json.loads(detail['metadata_json'])
    assert metadata['enrichment'] is True
    assert metadata[field + '_before'] == (before.get(field) or '')
    assert metadata[field + '_after'] == value
    assert len(metadata['prior_claim_sha256']) == len(metadata['claim_sha256']) == 64


@pytest.mark.parametrize('steps', [
    ['Request another object'],
    ['Observe the Acme response', 'Request the Acme object'],
    ['Request the Acme object'],
])
def test_same_verifier_replacing_reordering_or_deleting_steps_requires_review(client, confirmed, steps):
    original = ['Request the Acme object', 'Observe the Acme response']
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': {'steps_to_reproduce': original},
    }).status_code == 200
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': {'steps_to_reproduce': steps},
    })
    assert response.status_code == 200, response.text
    finding = client.get(f'{BASE}/findings/VA-905').json()
    assert finding['verification_audit']['claim_review_pending'] is True
    transition = response.json()['transition']
    assert transition is not None
    detail = client.get(f'{BASE}/findings/VA-905/transitions/{transition["id"]}').json()
    assert json.loads(detail['metadata_json']).get('enrichment') is not True


def test_same_verifier_reordering_reproduction_runs_requires_review(client, confirmed):
    command, _ = confirmed
    added = client.post(f'{BASE}/command-runs', json={
        'command': 'python control.py', 'argv': ['python', 'control.py'], 'tool_name': 'python',
        'agent_name': 'VERIFY-1', 'phase': 'verify', 'return_code': 0, 'success': True,
        'started_at': '2026-09-09T12:00:02Z', 'completed_at': '2026-09-09T12:00:03Z',
        'duration_ms': 1000, 'stdout': 'Acme control', 'stderr': '', 'run_uuid': 'acme-control',
    })
    assert added.status_code == 201, added.text
    original = [command['id'], added.json()['id']]
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': {'repro_runs': original},
    }).status_code == 200
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'details': {'repro_runs': list(reversed(original))},
    })
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_audit']['claim_review_pending'] is True


def test_same_verifier_replacing_evidence_type_requires_review(client, confirmed):
    assert client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'evidence_type': 'network-confirmed',
    }).status_code == 200
    response = client.patch(f'{BASE}/findings/VA-905', json={
        'dispatch_agent_id': 'VERIFY-1', 'evidence_type': 'code-inferred',
    })
    assert response.status_code == 200, response.text
    assert client.get(f'{BASE}/findings/VA-905').json()['verification_status'] == 'unreviewed'
