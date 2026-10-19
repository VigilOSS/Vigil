from __future__ import annotations

import json
import pytest

from tests.test_proof_work_api import BASE, seed, prepare, claim


def approval(client, work, approved=True, **kwargs):
    return client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={
        'approved': approved, 'actor': 'operator',
        **({'human_confirmation': ' Yes, bounded Acme proof.\n'} if approved else {'reason': 'Stop this proof'}),
        **kwargs,
    })


def policy(path, policy, **extra):
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(exploit_policy=policy, **extra)
    (path / 'scope.json').write_text(json.dumps(scope))


@pytest.mark.parametrize('body', [
    {'approved': True}, {'approved': True, 'actor': 'specialist', 'human_confirmation': 'Yes'},
    {'approved': True, 'actor': 'operator', 'human_confirmation': '  '},
    {'approved': True, 'actor': 'ui', 'human_confirmation': 'x' * 2001},
    {'approved': False, 'actor': 'operator', 'reason': '  '},
])
def test_approval_requires_audited_human_decision(client, isolate_settings, body):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    response = client.post(f'{BASE}/proof-work/{work["id"]}/approval', json=body)
    assert response.status_code == 422, response.text


@pytest.mark.parametrize('policy_name', ['full_send', 'ask', 'selected'])
def test_exact_decision_controls_live_authority_without_rebinding(client, isolate_settings, policy_name):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert approval(client, work).status_code == 200
    policy(path, policy_name)
    current = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert current['current'] is True
    assert current['approval_required'] is False
    assert prepare(client, 'web')['id'] == work['id']
    assert claim(client, work).status_code == 200
    revoked = approval(client, work, False)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()['queue_state'] == 'blocked'
    assert revoked.json()['blocker_cause'] == 'approval'
    assert claim(client, work).status_code == 409
    assert client.patch(f'{BASE}/proof-work/{work["id"]}', json={'agent_id': 'PROOF-1', 'status': 'finished'}).status_code == 409
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile').json()['status'] == 'blocked'
    renewed = approval(client, work)
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()['queue_state'] == 'in_progress'
    assert claim(client, work).json()['launch_required'] is False
    event = json.loads(renewed.json()['events'][-1]['details_json'])
    assert event['human_confirmation'] == ' Yes, bounded Acme proof.\n'
    assert event['actor'] == 'operator'


def test_selected_exploit_authority_does_not_grant_parked_proof(client, isolate_settings):
    path = seed(client, isolate_settings)
    policy(path, 'selected', exploit_review_state='approved', approved_targets=['VA-050', '*'])
    work = prepare(client, 'web')
    assert work['approval_required'] is True
    assert claim(client, work).status_code == 409


def test_reapproval_preserves_independent_blocker(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert approval(client, work).status_code == 200
    assert claim(client, work).status_code == 200
    assert client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'blocked', 'blocker': 'Missing Acme test account',
    }).status_code == 200
    assert approval(client, work, False).status_code == 200
    assert approval(client, work).json()['queue_state'] == 'blocked'
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['blocker'] == 'Missing Acme test account'


def test_proof_owner_cannot_continue_after_release(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    owned = claim(client, work).json()
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    assert client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Execution ended'}).status_code == 200
    response = client.post(f'{BASE}/dispatches', json={
        'agent_id': 'PROOF-CONTINUE', 'agent_role': 'exploit-developer', 'task': 'Continue proof', 'assessment_mode': 'code',
        'continued_from_dispatch_id': owned['owner_dispatch_id'],
    })
    assert response.status_code == 409, response.text
    assert 'proof' in response.json()['detail'].lower()


def test_installed_instruction_identity_retains_hashes_without_attesting_loading(client, isolate_settings):
    seed(client, isolate_settings)
    response = client.post(f'{BASE}/dispatches', json={
        'agent_id': 'ACME-INSTALLED', 'agent_role': 'vulnerability-analyst', 'task': 'Review Acme',
        'client_name': 'codex', 'instruction_identity_status': 'installed',
        'operator_instruction_path': 'AGENTS.md', 'operator_instruction_sha256': 'a' * 64,
        'specialist_instruction_path': 'agent/agents/vulnerability-analyst.md',
        'specialist_instruction_sha256': 'b' * 64, 'instructions_stale': False,
    })
    assert response.status_code == 201, response.text
    assert response.json()['instruction_identity_status'] == 'installed'
    assert response.json()['actual_model'] == 'unknown'


def test_ordinary_continuation_requires_closed_predecessor(client, isolate_settings):
    seed(client, isolate_settings)
    parent = client.post(f'{BASE}/dispatches', json={
        'agent_id': 'ACME-PARENT', 'agent_role': 'vulnerability-analyst', 'task': 'Inspect Acme',
    }).json()
    body = {'agent_id': 'ACME-CHILD', 'agent_role': 'vulnerability-analyst', 'task': 'Continue Acme',
            'continued_from_dispatch_id': parent['id']}
    assert client.post(f'{BASE}/dispatches', json=body).status_code == 409
    assert client.patch(f'{BASE}/dispatches/ACME-PARENT', json={'status': 'completed'}).status_code == 200
    assert client.post(f'{BASE}/dispatches', json=body).status_code == 201


@pytest.mark.parametrize('execution', ['descendant', 'ambiguous'])
def test_release_refuses_historical_descendant_or_ambiguous_execution(client, isolate_settings, execution):
    from app import db
    seed(client, isolate_settings)
    work = prepare(client)
    owner = claim(client, work).json()
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    with db.get_connection() as connection:
        if execution == 'descendant':
            connection.execute(
                "INSERT INTO assessment_dispatches(engagement_id,agent_id,agent_role,task,continued_from_dispatch_id,status,dispatched_at) VALUES(?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                (work['engagement_id'], 'OLD-CHILD', 'exploit-developer', 'Historical proof continuation', owner['owner_dispatch_id'], 'completed'),
            )
        command_id = connection.execute(
            "INSERT INTO assessment_command_runs(engagement_id,agent_name,command,started_at,status,run_uuid,tool_name,phase,completed_at,command_hash) VALUES(?,?,?,CURRENT_TIMESTAMP,?,'acme-release-command','sleep','verify','','acme-hash')",
            (work['engagement_id'], 'OLD-CHILD' if execution == 'descendant' else 'operator', 'sleep 60', 'running'),
        ).lastrowid
    response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Owner ended'})
    assert response.status_code == 409, response.text
    assert str(command_id) in response.json()['detail']


@pytest.mark.parametrize('missing', ['threat_model', 'structural_index'])
def test_source_bound_claim_checks_current_prerequisites_before_dispatch(client, isolate_settings, missing):
    from app import db
    from tests.test_proof_work_api import bind_source_candidate
    from app.services.code_analysis_support import STRUCTURAL_INDEX_SCHEMA
    seed(client, isolate_settings)
    bind_source_candidate()
    with db.get_connection() as connection:
        connection.execute("UPDATE code_repos SET threat_model_json='{}',threat_model_generation=1,structural_index_generation=1,structural_index_schema=?,structural_index_manifest_path='source/acme/index.json'", (STRUCTURAL_INDEX_SCHEMA,))
        connection.execute('UPDATE code_repos SET ' + ('threat_model_generation' if missing == 'threat_model' else 'structural_index_generation') + '=NULL')
    work = prepare(client)
    response = claim(client, work)
    assert response.status_code == 409, response.text
    assert missing.replace('_', ' ') in response.json()['detail'].lower()
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['owner_dispatch_id'] is None
    with db.get_connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM assessment_dispatches WHERE agent_id='PROOF-1'").fetchone()[0] == 0
        connection.execute('UPDATE code_repos SET threat_model_generation=1,structural_index_generation=1')
    assert claim(client, work).status_code == 200


def test_code_only_dispatch_defaults_to_code_and_rejects_web(client, isolate_settings):
    seed(client, isolate_settings)
    body = {'agent_id': 'CODE-VERIFY', 'agent_role': 'code-vuln-verifier', 'task': 'Review Acme'}
    response = client.post(f'{BASE}/dispatches', json=body)
    assert response.status_code == 201, response.text
    assert response.json()['assessment_mode'] == 'code'
    body.update(agent_id='CODE-WEB', assessment_mode='web')
    assert client.post(f'{BASE}/dispatches', json=body).status_code == 422


@pytest.mark.parametrize('approved', [False, True])
def test_full_send_loss_blocks_only_work_without_exact_approval(client, isolate_settings, approved):
    path = seed(client, isolate_settings)
    policy(path, 'full_send')
    work = prepare(client, 'web')
    if approved:
        assert approval(client, work).status_code == 200
    assert claim(client, work).status_code == 200
    policy(path, 'selected')
    current = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert current['current'] is True
    assert current['queue_state'] == ('in_progress' if approved else 'blocked')
    assert claim(client, work).status_code == (200 if approved else 409)


def test_legacy_binding_approval_events_normalize_and_reprepare_resets_epoch(client, isolate_settings):
    from app import db
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    with db.get_connection() as connection:
        binding = dict(work['binding'], approval_posture={'policy': 'pause', 'selected_authorized': False})
        connection.execute('UPDATE assessment_proof_work SET binding_json=?,approved=1 WHERE id=?', (json.dumps(binding), work['id']))
        connection.execute("INSERT INTO assessment_proof_work_events(work_id,action,details_json) VALUES(?,'approval',?)", (work['id'], '{"approved":true}'))
    assert prepare(client, 'web')['id'] == work['id']
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['approval_required'] is False
    scope = json.loads((path / 'scope.json').read_text())
    scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile').json()['status'] == 'stale'
    scope['out_of_scope'] = []
    (path / 'scope.json').write_text(json.dumps(scope))
    restored = prepare(client, 'web')
    assert restored['id'] == work['id']
    assert restored['approval_required'] is True
    assert restored['approval_decision'] is None


def test_release_uses_claim_time_not_preparation_time_for_ambiguous_command(client, isolate_settings):
    from app import db
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_proof_work SET created_at='2026-01-01 00:00:00' WHERE id=?", (work['id'],))
        connection.execute("UPDATE assessment_proof_work_events SET created_at='2026-01-03 00:00:00' WHERE work_id=?", (work['id'],))
        connection.execute(
            "INSERT INTO assessment_command_runs(engagement_id,agent_name,command,started_at,status,run_uuid,tool_name,phase,completed_at,command_hash) VALUES(?,'operator','sleep 60','2026-01-02 00:00:00','running','acme-prior-command','sleep','verify','','acme-hash')",
            (work['engagement_id'],),
        )
    response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Prior command predates this proof claim'})
    assert response.status_code == 200, response.text


def test_revocation_refuses_run_attachment_but_retains_canonical_run(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert approval(client, work).status_code == 200
    assert claim(client, work).status_code == 200
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'acme-live-proof', 'run_kind': 'web', 'run_purpose': 'proof',
        'producer_dispatch_agent_id': 'PROOF-1',
    })
    assert run.status_code == 201, run.text
    assert approval(client, work, False).status_code == 200
    response = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'claimed', 'run_id': run.json()['id'],
    })
    assert response.status_code == 409, response.text
    assert client.get(f'{BASE}/assessment-runs/{run.json()["id"]}').status_code == 200
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['run_ids'] == []


def test_approval_changes_do_not_reopen_finished_work(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert approval(client, work).status_code == 200
    assert claim(client, work).status_code == 200
    assert client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'finished',
    }).status_code == 200
    assert approval(client, work, False).json()['status'] == 'finished'
    assert approval(client, work).json()['status'] == 'finished'


def test_code_only_dispatch_roles_match_assess_packet_roles():
    from app.api.assessment_operator import _CODE_ASSESSMENT_ROLES
    from assess.commands.agent import _CODE_SOURCE_IDENTITY_ROLES

    assert _CODE_ASSESSMENT_ROLES == _CODE_SOURCE_IDENTITY_ROLES


def test_scope_admission_failure_names_requested_host_and_flag(client, isolate_settings):
    seed(client, isolate_settings)
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'web', 'objective': 'Challenge Acme boundary',
        'target_hosts': ['outside.example'],
    })
    assert response.status_code == 400, response.text
    assert 'outside.example' in response.json()['detail']
    assert '--host' in response.json()['detail']
