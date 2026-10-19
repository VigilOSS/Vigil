from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app import db
from tests.proof_fixtures import RUNTIME_PROOF_PLAN
from tests.test_engagements_api import write_engagement, _author_provenance

KEY = '2026-03-30-120000-example'
BASE = f'/engagements/{KEY}/assessment'


@pytest.mark.parametrize(
    'create_schema',
    (db._create_remediation_tables, db.db_proof_work_schema.create_tables),
)
def test_additive_schema_helpers_preserve_the_callers_transaction(create_schema):
    connection = sqlite3.connect(':memory:')
    try:
        connection.execute('BEGIN IMMEDIATE')
        create_schema(connection)
        assert connection.in_transaction is True
    finally:
        connection.close()


def seed(client, isolate_settings):
    path = write_engagement(isolate_settings['engagements_dir'])
    response = client.post(f'{BASE}/findings', json={
        'slug': 'VA-050', 'title': 'Acme replay hypothesis', 'severity': 'high',
        'canonical_location': 'https://example.com/login',
        'summary': 'Challenge the replay hypothesis',
        'provenance': _author_provenance(client, 'VA-050'),
    })
    assert response.status_code == 201, response.text
    response = client.post(f'{BASE}/findings/VA-050/verify', json={
        'verification_status': 'pending_runtime_proof', 'reason_code': 'source-review',
        'reason_text': 'Runtime challenge still required', 'source_name': 'verifier',
        'next_test': RUNTIME_PROOF_PLAN,
    })
    assert response.status_code == 200, response.text
    return path


def prepare(client, route='code', **extra):
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': route,
        'objective': 'Try to disprove replay under the supported execution path',
        'target_hosts': ['example.com'] if route == 'web' else [], **extra,
    })
    assert response.status_code == 201, response.text
    return response.json()


def claim(client, work, agent='PROOF-1'):
    return client.post(f'{BASE}/proof-work/{work["id"]}/claim', json={
        'agent_id': agent, 'agent_role': 'exploit-developer',
        'task': 'Challenge the hypothesis using the prepared route',
        'prompt_packet': {
            'schema': 'dispatch-prompt/v1',
            'context': {'authorized_phase': work['authorized_phase']},
            'rendered_prompt': f'Proof assignment for {work["id"]}',
        },
    })


def test_prepare_rejects_an_objective_larger_than_dispatch_task(client, isolate_settings):
    seed(client, isolate_settings)
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'code', 'objective': 'x' * 4097,
        'target_hosts': [],
    })
    assert response.status_code == 422


def bind_source_candidate():
    with db.get_connection() as connection:
        engagement_id = connection.execute('SELECT id FROM engagements WHERE key=?', (KEY,)).fetchone()['id']
        repo_id = connection.execute(
            'INSERT INTO code_repos(engagement_id,repo_key,name,repo_path,active_generation,source_manifest_digest,source_snapshot_quality) '
            'VALUES(?,?,?,?,?,?,?)', (engagement_id, 'acme', 'Acme', 'source/acme', 1, 'a'*64, 'verified'),
        ).lastrowid
        from app.services.code_analysis_support import STRUCTURAL_INDEX_SCHEMA
        connection.execute(
            "UPDATE code_repos SET threat_model_generation=1,structural_index_generation=1,"
            "structural_index_schema=?,structural_index_manifest_path='source/acme/index.json' WHERE id=?",
            (STRUCTURAL_INDEX_SCHEMA, repo_id),
        )
        row = connection.execute("SELECT provenance_json FROM assessment_findings WHERE engagement_id=? AND slug='VA-050'", (engagement_id,)).fetchone()
        provenance = json.loads(row['provenance_json'])
        provenance['code_snapshot'] = {'repo_id': repo_id, 'repo_generation': 1, 'source_manifest_digest': 'a'*64}
        connection.execute("UPDATE assessment_findings SET provenance_json=?,canonical_location='file:parser.py:7' WHERE engagement_id=? AND slug='VA-050'",
                           (json.dumps(provenance), engagement_id))


@pytest.mark.parametrize(('route', 'candidate_mode'), [('code', 'code'), ('web', 'code'), ('code', 'web'), ('web', 'web')])
def test_resume_uses_proof_candidate_mode_and_retains_released_handoffs(client, isolate_settings, monkeypatch, route, candidate_mode):
    from app.services import assessment_memory

    path = seed(client, isolate_settings)
    if candidate_mode == 'code':
        bind_source_candidate()
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(engagement_type='offensive', tracks={'code': {'phase': 'hunt'}, 'web': {'phase': 'verify'}})
    (path / 'scope.json').write_text(json.dumps(scope))
    monkeypatch.setattr(assessment_memory, '_DISPATCH_LIST_RENDER_CAP', 1)

    def picture(mode=None):
        response = client.get(f'{BASE}/resume-brief', params={'mode': mode} if mode else {})
        assert response.status_code == 200, response.text
        return response.json()['dispatches']

    baseline = {mode: picture(mode) for mode in ['code', 'web', None]}
    work = prepare(client, route)
    if route == 'web':
        assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    response = claim(client, work, 'ACME-PROOF')
    assert response.status_code == 200, response.text
    assigned = picture(candidate_mode)
    assert [row['agent_id'] for row in assigned['recent_dispatches']] == ['ACME-PROOF']
    assert assigned['handoff_gaps_count'] == baseline[candidate_mode]['handoff_gaps_count'] + 1

    next_steps = [{'action': f'Test Acme boundary {index}', 'rationale': f'Unresolved observation {index}'} for index in range(7)]
    response = client.post(f'{BASE}/dispatch-handoffs', json={
        'agent_id': 'ACME-PROOF', 'agent_role': 'exploit-developer',
        'summary': 'Supported invocation needs another boundary check',
        'handoff_status': 'ready', 'next_steps': next_steps,
        'extras': {'observation': 'A queued export survives a role change; replay access remains unknown'},
    })
    assert response.status_code == 201, response.text
    for released in [False, True]:
        if released:
            assert client.patch(f'{BASE}/dispatches/ACME-PROOF', json={'status': 'completed'}).status_code == 200
            response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Ended worker inspected'})
            assert response.status_code == 200, response.text
        for mode in ['code', 'web', None]:
            actual = picture(mode)
            belongs = mode in [candidate_mode, None]
            assert actual['recent_dispatches_count'] == baseline[mode]['recent_dispatches_count'] + int(belongs)
            assert actual['latest_handoffs_count'] == baseline[mode]['latest_handoffs_count'] + int(belongs)
            assert len(actual['recent_dispatches']) <= 1
            assert len(actual['latest_handoffs']) <= 1
            assert ('ACME-PROOF' in {row['agent_id'] for row in actual['recent_dispatches']}) == belongs
            if belongs:
                handoff = actual['latest_handoffs'][0]
                assert handoff['agent_id'] == 'ACME-PROOF'
                assert handoff['next_steps'] == next_steps
                assert handoff['extras']['observation'].startswith('A queued export')
            else:
                assert actual['latest_handoffs'] == baseline[mode]['latest_handoffs']


def test_resume_proof_mode_filter_precedes_cap_and_preserves_previous_owner(client, isolate_settings, monkeypatch):
    from app.services import assessment_memory

    path = seed(client, isolate_settings)
    bind_source_candidate()
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(engagement_type='offensive', tracks={'code': {'phase': 'hunt'}, 'web': {'phase': 'verify'}})
    (path / 'scope.json').write_text(json.dumps(scope))
    work = prepare(client)
    assert claim(client, work, 'ACME-PROOF').status_code == 200
    response = client.post(f'{BASE}/dispatch-handoffs', json={
        'agent_id': 'ACME-PROOF', 'agent_role': 'exploit-developer',
        'summary': 'Prior proof worker retained an unresolved Acme clue',
    })
    assert response.status_code == 201, response.text
    assert client.patch(f'{BASE}/dispatches/ACME-PROOF', json={'status': 'completed'}).status_code == 200
    assert client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Ended worker inspected'}).status_code == 200
    assert claim(client, work, 'ACME-PROOF-2').status_code == 200
    for index in range(4):
        agent = f'WEB-{index}'
        assert client.post(f'{BASE}/dispatches', json={
            'agent_id': agent, 'agent_role': 'vulnerability-analyst', 'task': 'Ordinary Acme web investigation',
        }).status_code == 201
        assert client.post(f'{BASE}/dispatch-handoffs', json={
            'agent_id': agent, 'agent_role': 'vulnerability-analyst', 'summary': 'Web checkpoint',
        }).status_code == 201
    monkeypatch.setattr(assessment_memory, '_DISPATCH_LIST_RENDER_CAP', 1)
    code = client.get(f'{BASE}/resume-brief', params={'mode': 'code'}).json()['dispatches']
    web = client.get(f'{BASE}/resume-brief', params={'mode': 'web'}).json()['dispatches']
    full = client.get(f'{BASE}/resume-brief').json()['dispatches']
    assert code['recent_dispatches_count'] == 2
    assert code['recent_dispatches'][0]['agent_id'] == 'ACME-PROOF-2'
    assert code['latest_handoffs_count'] == 1
    assert code['latest_handoffs'][0]['agent_id'] == 'ACME-PROOF'
    assert code['handoff_gaps_count'] == 1
    assert code['handoff_gaps'][0]['agent_id'] == 'ACME-PROOF-2'
    assert web['recent_dispatches_count'] == full['recent_dispatches_count'] - 2
    assert web['latest_handoffs_count'] == 4
    assert web['recent_dispatches'][0]['agent_id'] == full['recent_dispatches'][0]['agent_id'] == 'WEB-3'
    assert full['latest_handoffs_count'] == 5


def test_code_only_resume_keeps_live_proof_return_without_starting_a_web_campaign(client, isolate_settings):
    path = seed(client, isolate_settings)
    bind_source_candidate()
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(engagement_type='offensive', tracks={'code': {'phase': 'verify'}})
    (path / 'scope.json').write_text(json.dumps(scope))
    work = prepare(client, 'web')
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    response = claim(client, work, 'ACME-LIVE-PROOF')
    assert response.status_code == 200, response.text
    assert response.json()['authorized_phase'] == 'exploit'
    assert client.post(f'{BASE}/dispatch-handoffs', json={
        'agent_id': 'ACME-LIVE-PROOF', 'agent_role': 'exploit-developer',
        'summary': 'The live request contradicted the source hypothesis',
        'extras': {'observation': 'A different account could still replay the job result'},
    }).status_code == 201
    response = client.get(f'{BASE}/resume-brief', params={'mode': 'code'})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['engagement']['current_phase'] == 'verify'
    assert set(body['engagement']['track_state']) == {'code'}
    assert body['dispatches']['latest_handoffs'][0]['agent_id'] == 'ACME-LIVE-PROOF'
    assert body['dispatches']['latest_handoffs'][0]['extras']['observation'].startswith('A different account')


def test_owed_visible_without_preparation_and_preparation_does_not_resolve(client, isolate_settings):
    seed(client, isolate_settings)
    response = client.get(f'{BASE}/proof-work')
    assert response.status_code == 200, response.text
    assert response.json()['owed'][0]['finding_slug'] == 'VA-050'
    assert response.json()['items'] == []
    work = prepare(client)
    assert prepare(client)['id'] == work['id']
    assert work['route'] == 'code'
    assert work['target_hosts'] == []
    assert client.get(f'{BASE}/findings/VA-050').json()['verification_status'] == 'pending_runtime_proof'
    assert client.get(f'/engagements/{KEY}').json()['current_phase'] == 'exploit'


def test_local_claim_atomic_and_idempotent_without_live_approval(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    first = claim(client, work)
    assert first.status_code == 200, first.text
    assert first.json()['owner_agent_id'] == 'PROOF-1'
    assert claim(client, work).json()['owner_dispatch_id'] == first.json()['owner_dispatch_id']
    second = claim(client, work, 'PROOF-2')
    assert second.status_code == 409, second.text
    assert client.get(f'{BASE}/dispatches/PROOF-2').status_code == 404


def test_parallel_claims_create_only_one_dispatch(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda a: claim(client, work, a), ['PROOF-A', 'PROOF-B']))
    assert sorted(r.status_code for r in responses) == [200, 409]
    statuses = [client.get(f'{BASE}/dispatches/{a}').status_code for a in ['PROOF-A', 'PROOF-B']]
    assert sorted(statuses) == [200, 404]


def test_web_requires_admitted_hosts_and_bound_approval(client, isolate_settings):
    seed(client, isolate_settings)
    rejected = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'web', 'objective': 'Challenge replay',
        'target_hosts': ['outside.example'],
    })
    assert rejected.status_code == 400, rejected.text
    work = prepare(client, 'web')
    denied = claim(client, work)
    assert denied.status_code == 409, denied.text
    assert client.get(f'{BASE}/dispatches/PROOF-1').status_code == 404
    approved = client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'})
    assert approved.status_code == 200, approved.text
    assert claim(client, work).status_code == 200
    assert client.get(f'{BASE}/exploit-candidates').json() == []


def test_changed_claim_or_scope_blocks_work_without_erasing_history(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'})
    scope = json.loads((path / 'scope.json').read_text())
    scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert claim(client, work).status_code == 409
    read = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert read['current'] is False
    assert read['status'] == 'prepared'  # reading cannot mutate lifecycle
    reconciled = client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={})
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()['status'] == 'stale'
    assert reconciled.json()['approved'] is True  # historical approval is preserved


def test_reconcile_does_not_reclaim_running_work_on_client_exit_or_age(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_proof_work SET updated_at='2000-01-01' WHERE id=?", (work['id'],))
    response = client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={})
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'claimed'
    assert claim(client, work, 'PROOF-2').status_code == 409


def test_owner_updates_blockers_and_run_links_but_cannot_complete_finding(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'proof-work-run', 'run_kind': 'code',
        'producer_dispatch_agent_id': 'PROOF-1',
    })
    assert run.status_code == 201, run.text
    wrong = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'OTHER', 'status': 'blocked', 'blocker': 'Need test credentials',
    })
    assert wrong.status_code == 409
    response = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'blocked', 'blocker': 'Need test credentials',
        'run_id': run.json()['id'],
    })
    assert response.status_code == 200, response.text
    assert response.json()['run_ids'] == [run.json()['id']]
    assert response.json()['blocker'] == 'Need test credentials'
    assert client.get(f'{BASE}/proof-work').json()['owed'][0]['finding_slug'] == 'VA-050'


def test_scope_wildcards_and_cidr_reuse_admitted_roots_but_deny_wins(client, isolate_settings):
    path = seed(client, isolate_settings)
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(hosts=['*.example.com', '192.0.2.0/24'], scope_hosts=[], scope=[], hostname='',
                 out_of_scope=['*.private.example.com'])
    (path / 'scope.json').write_text(json.dumps(scope))
    assert prepare(client, 'web', target_hosts=['api.example.com'])['target_hosts'] == ['api.example.com']
    assert prepare(client, 'web', target_hosts=['192.0.2.2'])['target_hosts'] == ['192.0.2.2']
    denied = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'web', 'objective': 'Challenge replay',
        'target_hosts': ['api.private.example.com'],
    })
    assert denied.status_code == 400, denied.text


def test_policy_change_preserves_exact_work_approval(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    scope = json.loads((path / 'scope.json').read_text())
    scope['exploit_policy'] = 'pause'
    (path / 'scope.json').write_text(json.dumps(scope))
    assert claim(client, work).status_code == 200
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True


def test_release_requires_terminal_dispatch_and_terminal_owned_execution(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    endpoint = f'{BASE}/proof-work/{work["id"]}/release'
    response = client.post(endpoint, json={'reason': 'Inspect finished work'})
    assert response.status_code == 409, response.text
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'proof-recovery', 'run_kind': 'code', 'producer_dispatch_agent_id': 'PROOF-1',
    }).json()
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'aborted'}).status_code == 200
    assert client.post(endpoint, json={'reason': 'Inspect finished work'}).status_code == 409
    assert client.patch(f'{BASE}/assessment-runs/{run["id"]}', json={'status': 'interrupted'}).status_code == 200
    response = client.post(endpoint, json={'reason': 'Owner aborted; runtime work reconciled'})
    assert response.status_code == 200, response.text
    assert response.json()['owner_dispatch_id'] is None
    assert response.json()['status'] == 'prepared'
    assert any(e['action'] == 'released' for e in response.json()['events'])
    assert claim(client, work, 'PROOF-2').status_code == 200


def test_scan_runs_cannot_be_attached_as_proof_work_evidence(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'scan-wrong-purpose', 'run_kind': 'code', 'producer_dispatch_agent_id': 'PROOF-1',
    }).json()
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_runs SET run_purpose='scan' WHERE id=?", (run['id'],))
    response = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'claimed', 'run_id': run['id'],
    })
    assert response.status_code == 400, response.text


def test_source_generation_change_invalidates_proof_preparation(client, isolate_settings):
    seed(client, isolate_settings)
    with db.get_connection() as connection:
        engagement_id = connection.execute('SELECT id FROM engagements WHERE key=?', (KEY,)).fetchone()['id']
        repo_id = connection.execute(
            'INSERT INTO code_repos(engagement_id,repo_key,name,repo_path,active_generation,source_manifest_digest,source_snapshot_quality) '
            'VALUES(?,?,?,?,?,?,?)', (engagement_id, 'acme', 'Acme', 'source/acme', 1, 'a'*64, 'verified'),
        ).lastrowid
        row = connection.execute("SELECT provenance_json FROM assessment_findings WHERE engagement_id=? AND slug='VA-050'", (engagement_id,)).fetchone()
        provenance = json.loads(row['provenance_json'])
        provenance['code_snapshot'] = {'repo_id': repo_id, 'repo_generation': 1, 'source_manifest_digest': 'a'*64}
        connection.execute("UPDATE assessment_findings SET provenance_json=? WHERE engagement_id=? AND slug='VA-050'", (json.dumps(provenance), engagement_id))
    work = prepare(client)
    with db.get_connection() as connection:
        connection.execute('UPDATE code_repos SET active_generation=2 WHERE id=?', (repo_id,))
    assert claim(client, work).status_code == 409
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False


def test_upgrade_adds_recoverable_proof_work_without_rewriting_existing_findings(client, isolate_settings):
    from pathlib import Path
    import sqlite3

    seed(client, isolate_settings)
    with db.get_connection() as connection:
        before = [dict(r) for r in connection.execute('SELECT * FROM assessment_findings')]
        transitions = [dict(r) for r in connection.execute('SELECT * FROM assessment_finding_transitions')]
        # Model the populated immediately preceding database schema.
        connection.execute('DROP TABLE assessment_proof_work_events')
        connection.execute('DROP TABLE assessment_proof_work_runs')
        connection.execute('DROP TABLE assessment_proof_work')
    db.close_thread_connection()
    db.init_db()
    db.init_db()
    with db.get_connection() as connection:
        assert [dict(r) for r in connection.execute('SELECT * FROM assessment_findings')] == before
        assert [dict(r) for r in connection.execute('SELECT * FROM assessment_finding_transitions')] == transitions
        rows = connection.execute("SELECT * FROM schema_migrations WHERE migration_id='proof-work-v1'").fetchall()
    assert len(rows) == 1
    backup = Path(rows[0]['backup_path'])
    assert backup.is_file()
    with sqlite3.connect(backup) as connection:
        assert connection.execute('SELECT COUNT(*) FROM assessment_findings').fetchone()[0] == len(before)


def test_concurrent_upgrade_preserves_one_migration_record_and_original_backup(client, isolate_settings, monkeypatch):
    import sqlite3
    import threading
    from pathlib import Path

    seed(client, isolate_settings)
    with db.get_connection() as connection:
        before = [dict(row) for row in connection.execute('SELECT * FROM assessment_findings')]
        for table in ('assessment_proof_work_events', 'assessment_proof_work_runs', 'assessment_proof_work'):
            connection.execute(f'DROP TABLE {table}')
    db.close_thread_connection()
    backed_up = threading.Barrier(2)
    original_backup = db._create_adjacent_migration_backup
    backups = []

    def backup(path, *, label):
        saved = original_backup(path, label=label)
        if label == 'proof-work':
            backups.append(saved)
            # Both workers observed the prior schema before either migrates it.
            backed_up.wait(timeout=10)
        return saved

    monkeypatch.setattr(db, '_create_adjacent_migration_backup', backup)

    def initialize():
        try:
            db.init_db()
        finally:
            db.close_thread_connection()

    with ThreadPoolExecutor(max_workers=2) as pool:
        workers = [pool.submit(initialize) for _ in range(2)]
        for worker in workers:
            worker.result(timeout=20)

    with db.get_connection() as connection:
        assert [dict(row) for row in connection.execute('SELECT * FROM assessment_findings')] == before
        migration = [dict(row) for row in connection.execute(
            "SELECT * FROM schema_migrations WHERE migration_id='proof-work-v1'"
        )]
    assert len(migration) == 1
    assert Path(migration[0]['backup_path']) in backups
    with sqlite3.connect(migration[0]['backup_path']) as saved:
        saved.row_factory = sqlite3.Row
        assert [dict(row) for row in saved.execute('SELECT * FROM assessment_findings')] == before
    monkeypatch.setattr(db, '_create_adjacent_migration_backup', original_backup)
    db.init_db()
    with db.get_connection() as connection:
        assert [dict(row) for row in connection.execute(
            "SELECT * FROM schema_migrations WHERE migration_id='proof-work-v1'"
        )] == migration


def test_owner_can_archive_result_after_finding_evidence_changes(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'proof-with-final-evidence', 'run_kind': 'code',
        'producer_dispatch_agent_id': 'PROOF-1',
    }).json()
    changed = client.patch(f'{BASE}/findings/VA-050', json={
        'summary': 'Runtime challenge changed our understanding of the replay hypothesis',
    })
    assert changed.status_code == 200, changed.text
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False
    closed = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'finished', 'run_id': run['id'],
    })
    assert closed.status_code == 200, closed.text
    assert closed.json()['run_ids'] == [run['id']]
    assert closed.json()['status'] == 'finished'


def test_route_specific_specialists_cannot_claim_wrong_method_bundle(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    response = client.post(f'{BASE}/proof-work/{work["id"]}/claim', json={
        'agent_id': 'WRONG-ROUTE', 'agent_role': 'vulnerability-analyst',
    })
    assert response.status_code == 400, response.text
    assert client.get(f'{BASE}/dispatches/WRONG-ROUTE').status_code == 404


def test_rewording_objective_cannot_mint_second_owner_for_same_finding_route(client, isolate_settings):
    seed(client, isolate_settings)
    first = prepare(client)
    assert claim(client, first).status_code == 200
    second = prepare(client, objective='Try another angle on the same replay claim')
    response = claim(client, second, 'PROOF-2')
    assert response.status_code == 409, response.text
    assert client.get(f'{BASE}/dispatches/PROOF-2').status_code == 404


def test_claim_replay_explicitly_prevents_duplicate_native_launch(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).json().get('launch_required') is True
    assert claim(client, work).json().get('launch_required') is False


def test_unverified_source_snapshot_cannot_authorize_proof_preparation(client, isolate_settings):
    seed(client, isolate_settings)
    with db.get_connection() as connection:
        engagement_id = connection.execute('SELECT id FROM engagements WHERE key=?', (KEY,)).fetchone()['id']
        repo_id = connection.execute(
            'INSERT INTO code_repos(engagement_id,repo_key,name,repo_path,active_generation,source_manifest_digest) '
            'VALUES(?,?,?,?,?,?)', (engagement_id, 'acme', 'Acme', 'source/acme', 1, 'a'*64),
        ).lastrowid
        row = connection.execute("SELECT provenance_json FROM assessment_findings WHERE engagement_id=? AND slug='VA-050'", (engagement_id,)).fetchone()
        provenance = json.loads(row['provenance_json'])
        provenance['code_snapshot'] = {'repo_id': repo_id, 'repo_generation': 1, 'source_manifest_digest': 'a'*64}
        connection.execute("UPDATE assessment_findings SET provenance_json=? WHERE engagement_id=? AND slug='VA-050'", (json.dumps(provenance), engagement_id))
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'code', 'objective': 'Challenge hypothesis',
    })
    assert response.status_code == 409, response.text


def test_targeted_live_proof_can_run_without_full_web_campaign(client, isolate_settings):
    path = seed(client, isolate_settings)
    scope = json.loads((path / 'scope.json').read_text())
    scope['tracks'] = {'code': {'phase': 'code-review'}}
    (path / 'scope.json').write_text(json.dumps(scope))
    work = prepare(client, 'web')
    assert claim(client, work).status_code == 409
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    assert claim(client, work).status_code == 200
    assert json.loads((path / 'scope.json').read_text())['tracks'] == {'code': {'phase': 'code-review'}}


def test_blocked_proof_work_requires_nonblank_reason(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    response = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'blocked', 'blocker': '  ',
    })
    assert response.status_code == 400, response.text


def test_stale_owner_can_be_released_without_authorizing_old_context(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'})
    assert claim(client, work).status_code == 200
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'aborted'}).status_code == 200
    scope = json.loads((path / 'scope.json').read_text())
    scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))
    response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={
        'reason': 'Owner ended; all runtime work inspected after target admission changed',
    })
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'stale'
    assert response.json()['owner_dispatch_id'] is None
    scope['out_of_scope'] = []
    (path / 'scope.json').write_text(json.dumps(scope))
    fresh = prepare(client, 'web', objective='Challenge the updated bounded Acme path')
    assert fresh['id'] != work['id']
    assert claim(client, fresh, 'PROOF-2').status_code == 409


def test_route_derives_explicit_audit_phase_for_specialist(client, isolate_settings):
    seed(client, isolate_settings)
    local = prepare(client)
    assert local.get('authorized_phase') == 'code-verify'
    live = prepare(client, 'web')
    assert live.get('authorized_phase') == 'exploit'


def test_proof_route_is_authoritative_for_mixed_role_assessment_mode(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    response = client.post(f'{BASE}/proof-work/{work["id"]}/claim', json={
        'agent_id': 'PROOF-MODE', 'agent_role': 'exploit-developer',
        'assessment_mode': 'code',
        'task': 'Challenge the prepared web proof',
        'prompt_packet': {
            'schema': 'dispatch-prompt/v1',
            'context': {'authorized_phase': work['authorized_phase']},
            'rendered_prompt': 'Prepared web proof assignment',
        },
    })
    assert response.status_code == 200, response.text
    assert response.json()['prompt_packet']['context']['assessment_mode'] == 'web'
    assert response.json()['prompt_packet']['rendered_prompt'].startswith('proof_route: web\n')
    dispatch = client.get(f'{BASE}/dispatches/PROOF-MODE').json()
    assert dispatch['assessment_mode'] == 'web'


def test_list_reports_event_count_with_exact_history_available_by_id(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    claim(client, work)
    listed = client.get(f'{BASE}/proof-work').json()['items'][0]
    detailed = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert listed.get('event_count') == len(detailed['events']) == 1


def test_running_supervised_job_prevents_recovery_even_when_parent_command_is_terminal(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    claimed = claim(client, work).json()
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'aborted'}).status_code == 200
    with db.get_connection() as connection:
        command_id = connection.execute(
            'INSERT INTO assessment_command_runs(engagement_id,run_uuid,command,tool_name,agent_name,phase,status,started_at,completed_at,command_hash) '
            'VALUES(?,?,?,?,?,?,?,?,?,?)',
            (claimed['engagement_id'], 'supervised-proof', 'sleep 1', 'shell', 'PROOF-1', 'code-verify', 'completed', '2026-01-01', '2026-01-01', 'a'*64),
        ).lastrowid
        job_id = connection.execute(
            'INSERT INTO assessment_jobs(engagement_id,parent_command_run_id,status) VALUES(?,?,?)',
            (claimed['engagement_id'], command_id, 'running'),
        ).lastrowid
    endpoint = f'{BASE}/proof-work/{work["id"]}/release'
    assert client.post(endpoint, json={'reason': 'Inspect owner'}).status_code == 409
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_jobs SET status='completed' WHERE id=?", (job_id,))
    assert client.post(endpoint, json={'reason': 'Supervised runtime job completed'}).status_code == 200


def test_owner_records_existing_run_progress_when_context_changes_without_resuming_execution(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    claim(client, work)
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'existing-run-before-revision', 'run_kind': 'code',
        'producer_dispatch_agent_id': 'PROOF-1',
    }).json()
    assert client.patch(f'{BASE}/findings/VA-050', json={'summary': 'The hypothesis changed after a runtime observation'}).status_code == 200
    response = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'claimed', 'run_id': run['id'],
    })
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'stale'
    assert response.json()['run_ids'] == [run['id']]
    assert claim(client, work).status_code == 409


def test_blank_proof_objective_and_release_reason_are_rejected(client, isolate_settings):
    seed(client, isolate_settings)
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'code', 'objective': '   ',
    })
    assert response.status_code == 400, response.text


def test_blank_release_reason_is_rejected(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': '   '})
    assert response.status_code == 400, response.text


def test_freeform_notes_do_not_change_canonical_claim_identity(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert client.patch(f'{BASE}/findings/VA-050', json={'notes': 'Working reproduction notes'}).status_code == 200
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True


def test_repreparation_of_restored_context_rearms_stale_unowned_work_without_reusing_approval(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'})
    original = (path / 'scope.json').read_text()
    scope = json.loads(original)
    scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={}).json()['status'] == 'stale'
    (path / 'scope.json').write_text(original)
    restored = prepare(client, 'web')
    assert restored['status'] == 'prepared'
    assert restored['approved'] is False
    assert any(event['action'] == 'reprepared' for event in restored['events'])


def test_repreparing_stale_owned_work_requires_explicit_release(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve bounded Acme proof'}).status_code == 200
    assert claim(client, work).status_code == 200
    original = (path / 'scope.json').read_text()
    scope = json.loads(original)
    scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={}).json()['status'] == 'stale'
    (path / 'scope.json').write_text(original)

    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'web',
        'objective': 'Try to disprove replay under the supported execution path',
        'target_hosts': ['example.com'],
    })
    assert response.status_code == 409, response.text
    assert 'release' in response.json()['detail'].lower()


def test_unrelated_scope_changes_do_not_stale_selected_target_work(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    scope = json.loads((path / 'scope.json').read_text())
    scope.setdefault('hosts', ['example.com']).append('unrelated.example')
    scope['out_of_scope'] = ['private.unrelated.example']
    (path / 'scope.json').write_text(json.dumps(scope))

    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True


@pytest.mark.parametrize('route', ['code', 'web'])
def test_legacy_scope_bound_work_remains_current_and_prepare_is_idempotent(
    client, isolate_settings, route
):
    path = seed(client, isolate_settings)
    work = prepare(client, route)
    legacy = dict(work['binding'])
    legacy.pop('target_admission')
    legacy['scope_hosts'] = ['example.com'] if route == 'web' else []
    legacy['out_of_scope'] = []
    encoded = json.dumps(legacy, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    with db.get_connection() as connection:
        connection.execute(
            'UPDATE assessment_proof_work SET binding_json=?,binding_digest=? WHERE id=?',
            (encoded, digest, work['id']),
        )

    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True
    assert prepare(client, route)['id'] == work['id']

    if route == 'web':
        scope = json.loads((path / 'scope.json').read_text())
        scope.setdefault('hosts', ['example.com']).append('unrelated.example')
        scope['out_of_scope'] = ['private.unrelated.example']
        (path / 'scope.json').write_text(json.dumps(scope))
        assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True
        scope['out_of_scope'] = ['example.com']
        (path / 'scope.json').write_text(json.dumps(scope))
        assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False


@pytest.mark.parametrize('scope_change', ['remove', 'exclude'])
def test_selected_target_removal_or_exclusion_stales_web_proof(
    client, isolate_settings, scope_change
):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    scope = json.loads((path / 'scope.json').read_text())
    if scope_change == 'remove':
        scope.update(hostname='other.example', scope_hosts=['other.example'], scope=['other.example'])
    else:
        scope['out_of_scope'] = ['example.com']
    (path / 'scope.json').write_text(json.dumps(scope))

    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False


def test_unrelated_selected_approval_does_not_invalidate_existing_authorized_proof(client, isolate_settings):
    path = seed(client, isolate_settings)
    scope = json.loads((path / 'scope.json').read_text())
    scope['approved_targets'] = ['VA-050']
    (path / 'scope.json').write_text(json.dumps(scope))
    work = prepare(client, 'web')
    assert work['approval_required'] is True
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True, 'actor': 'operator', 'human_confirmation': 'Approve Acme proof'}).status_code == 200
    scope['approved_targets'].append('VA-051')
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True
    assert claim(client, work).status_code == 200
    scope['approved_targets'] = ['VA-051']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True


_QUEUE_MATRIX = [
    # (status, owed, current, approval_required, owner_dispatch_status, expected)
    # done wins: finished/resolved, or the finding no longer owes proof.
    ('finished', True, True, False, 'completed', 'done'),
    ('resolved', True, True, False, None, 'done'),
    ('prepared', False, True, False, None, 'done'),
    ('claimed', False, False, True, 'in-progress', 'done'),
    ('stale', False, False, False, None, 'done'),
    # stale next: stored stale, or context no longer current.
    ('stale', True, True, False, None, 'stale'),
    ('prepared', True, False, False, None, 'stale'),
    ('prepared', True, False, True, None, 'stale'),
    ('claimed', True, False, False, 'in-progress', 'stale'),
    ('blocked', True, False, False, 'completed', 'stale'),
    # blocked: stored blocker, or a claim whose owner already ended (reconcile blocks it).
    ('blocked', True, True, False, 'completed', 'blocked'),
    ('claimed', True, True, False, 'aborted', 'blocked'),
    ('claimed', True, True, False, 'completed', 'blocked'),
    # in_progress: owned claim whose dispatch is still running.
    ('claimed', True, True, False, 'in-progress', 'in_progress'),
    ('claimed', True, True, True, 'in-progress', 'blocked'),
    # prepared, current, owed: approval decides.
    ('prepared', True, True, True, None, 'needs_approval'),
    ('prepared', True, True, False, None, 'ready'),
]


@pytest.mark.parametrize(
    ('status', 'owed', 'current', 'approval_required', 'owner_dispatch_status', 'expected'),
    _QUEUE_MATRIX,
)
def test_queue_state_precedence_matrix(status, owed, current, approval_required,
                                       owner_dispatch_status, expected):
    from app.services.state_manager import proof_work

    work = {
        'status': status, 'owed': owed, 'current': current,
        'approval_required': approval_required, 'verification_invalidated': False,
        'waiting_on_work_id': None,
        'owner_dispatch_id': 7 if owner_dispatch_status else None,
        'owner_dispatch_status': owner_dispatch_status,
    }
    assert proof_work.queue_state(work) == expected


@pytest.mark.parametrize(('status', 'expected'), [
    ('prepared', 'stale'), ('claimed', 'stale'), ('blocked', 'stale'), ('stale', 'stale'),
    ('finished', 'done'), ('resolved', 'done'),
])
def test_invalidated_verification_stales_open_work_and_keeps_ended_work_done(status, expected):
    from app.services.state_manager import proof_work

    assert proof_work.queue_state({
        'status': status, 'owed': False, 'current': False, 'approval_required': False,
        'verification_invalidated': True, 'waiting_on_work_id': None, 'owner_dispatch_id': 7,
        'owner_dispatch_status': 'in-progress',
    }) == expected


def test_queue_state_is_derived_on_every_list_and_get_entry(client, isolate_settings):
    seed(client, isolate_settings)
    listed = client.get(f'{BASE}/proof-work').json()
    assert [row['queue_state'] for row in listed['owed']] == ['unprepared']
    assert listed['queue_state_counts'] == {'unprepared': 1}

    local = prepare(client)
    live = prepare(client, 'web')
    assert local['queue_state'] == 'ready'
    assert live['queue_state'] == 'needs_approval'
    listed = client.get(f'{BASE}/proof-work').json()
    assert {row['id']: row['queue_state'] for row in listed['items']} == {
        local['id']: 'ready', live['id']: 'needs_approval',
    }
    assert listed['owed'][0]['work_ids'] == [local['id'], live['id']]
    # A claimable item is the next action, ahead of one still awaiting approval.
    assert listed['owed'][0]['queue_state'] == 'ready'
    assert listed['queue_state_counts'] == {'ready': 1, 'needs_approval': 1}

    assert claim(client, local).status_code == 200
    assert client.get(f'{BASE}/proof-work/{local["id"]}').json()['queue_state'] == 'in_progress'
    listed = client.get(f'{BASE}/proof-work').json()
    assert listed['owed'][0]['queue_state'] == 'in_progress'
    # Reading derives the state; it never writes lifecycle.
    with db.get_connection() as connection:
        stored = connection.execute('SELECT status FROM assessment_proof_work WHERE id=?',
                                    (local['id'],)).fetchone()['status']
    assert stored == 'claimed'


@pytest.mark.parametrize('ended_status', ['blocked', 'finished'])
def test_repreparing_ended_owned_work_requires_explicit_release(client, isolate_settings, ended_status):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    update = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': ended_status,
        'blocker': 'Need Acme tenant credentials' if ended_status == 'blocked' else '',
    })
    assert update.status_code == 200, update.text
    response = client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': 'code',
        'objective': 'Try to disprove replay under the supported execution path',
        'target_hosts': [],
    })
    assert response.status_code == 409, response.text
    detail = response.json()['detail'].lower()
    assert 'release' in detail and ended_status in detail


def test_prepare_prefers_the_newest_live_row_among_equivalent_legacy_bindings(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client, 'web')
    legacy = dict(work['binding'])
    legacy.pop('target_admission')
    legacy['out_of_scope'] = []
    with db.get_connection() as connection:
        for roots in (['example.com', 'old.example'], ['example.com']):
            variant = dict(legacy, scope_hosts=roots)
            encoded = json.dumps(variant, sort_keys=True, separators=(',', ':'))
            connection.execute(
                'UPDATE assessment_proof_work SET binding_json=?,binding_digest=? WHERE id=?',
                (encoded, hashlib.sha256(encoded.encode()).hexdigest(), work['id']),
            ) if roots == ['example.com', 'old.example'] else connection.execute(
                'INSERT INTO assessment_proof_work '
                '(engagement_id,finding_id,binding_digest,binding_json,route,objective,target_hosts_json) '
                'SELECT engagement_id,finding_id,?,?,route,objective,target_hosts_json '
                'FROM assessment_proof_work WHERE id=?',
                (hashlib.sha256(encoded.encode()).hexdigest(), encoded, work['id']),
            )
        connection.execute("UPDATE assessment_proof_work SET status='finished' WHERE id=?", (work['id'],))
        newest = connection.execute('SELECT MAX(id) FROM assessment_proof_work').fetchone()[0]
    assert newest != work['id']
    assert prepare(client, 'web')['id'] == newest


def test_resume_brief_counts_all_owed_proof_work_whatever_the_session_mode(client, isolate_settings):
    path = seed(client, isolate_settings)
    scope = json.loads((path / 'scope.json').read_text())
    scope.update(engagement_type='offensive', tracks={'code': {'phase': 'hunt'}, 'web': {'phase': 'verify'}})
    (path / 'scope.json').write_text(json.dumps(scope))

    def section(mode=None):
        response = client.get(f'{BASE}/resume-brief', params={'mode': mode} if mode else {})
        assert response.status_code == 200, response.text
        return response.json()['proof_work']

    expected = {
        'owed_findings': 1, 'reverification_required': 0, 'queue_state_counts': {'unprepared': 1},
        'read_command': 'vigil assess proof-work list',
    }
    # The current operator owns every proof obligation, so a session of either
    # mode sees the same owed set and readiness.
    assert [section(mode) for mode in (None, 'web', 'code')] == [expected] * 3
    prepare(client)
    prepare(client, 'web')
    for mode in (None, 'web', 'code'):
        assert section(mode)['queue_state_counts'] == {'ready': 1, 'needs_approval': 1}

REVISED_PLAN = {
    **RUNTIME_PROOF_PLAN,
    'hypothesis': 'The Acme handler still accepts a captured token after logout.',
}


def repark(client, plan=REVISED_PLAN):
    """Park the finding again with a revised plan: a new pending_runtime_proof event."""
    response = client.post(f'{BASE}/findings/VA-050/verify', json={
        'verification_status': 'pending_runtime_proof', 'reason_code': 'source-review',
        'reason_text': 'Runtime challenge revised after the earlier pass',
        'source_name': 'verifier', 'next_test': plan,
    })
    assert response.status_code == 200, response.text


def prepare_response(client, route='code'):
    return client.post(f'{BASE}/proof-work', json={
        'finding_slug': 'VA-050', 'route': route,
        'objective': 'Try to disprove replay under the supported execution path',
        'target_hosts': ['example.com'] if route == 'web' else [],
    })


def owed_listing(client):
    listed = client.get(f'{BASE}/proof-work').json()
    [entry] = listed['owed']
    return entry, listed


def test_repark_after_finished_work_owes_a_fresh_preparation(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    finished = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'finished',
    })
    assert finished.status_code == 200, finished.text
    repark(client)

    entry, listed = owed_listing(client)
    assert entry['queue_state'] == 'unprepared'
    assert entry['work_ids'] == []
    assert entry['next_test']['hypothesis'] == REVISED_PLAN['hypothesis']
    assert listed['queue_state_counts'] == {'unprepared': 1, 'done': 1}
    historical = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert (historical['status'], historical['queue_state'], historical['current']) == (
        'finished', 'done', False)
    # History keeps the plan it was prepared for, not the revised one.
    assert historical['next_test'] == RUNTIME_PROOF_PLAN

    fresh = prepare_response(client)
    assert fresh.status_code == 201, fresh.text
    assert fresh.json()['id'] != work['id']
    assert fresh.json()['next_test'] == REVISED_PLAN
    # Its earlier owner is still running, so claiming waits on it.
    assert (fresh.json()['queue_state'], fresh.json()['waiting_on_work_id']) == ('blocked', work['id'])
    assert claim(client, fresh.json(), 'PROOF-2').status_code == 409
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    entry, _ = owed_listing(client)
    assert (entry['queue_state'], entry['work_ids']) == ('ready', [fresh.json()['id']])
    assert claim(client, fresh.json(), 'PROOF-2').status_code == 200


def test_repark_after_resolved_work_prepares_new_work_and_keeps_the_resolved_row(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    left = client.post(f'{BASE}/findings/VA-050/verify', json={
        'verification_status': 'disputed', 'reason_text': 'Claim contested.',
    })
    assert left.status_code == 200, left.text
    reconciled = client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={})
    assert reconciled.json()['status'] == 'resolved'
    repark(client)

    entry, listed = owed_listing(client)
    assert (entry['queue_state'], entry['work_ids']) == ('unprepared', [])
    assert listed['queue_state_counts'] == {'unprepared': 1, 'done': 1}
    fresh = prepare(client)
    assert fresh['id'] != work['id']
    assert (fresh['queue_state'], fresh['waiting_on_work_id']) == ('ready', None)
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['status'] == 'resolved'


def test_repark_while_claimed_stales_the_claim_and_preserves_its_evidence(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    run = client.post(f'{BASE}/assessment-runs', json={
        'run_uuid': 'proof-before-repark', 'run_kind': 'code', 'producer_dispatch_agent_id': 'PROOF-1',
    }).json()
    repark(client)

    old = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert (old['status'], old['queue_state'], old['current']) == ('claimed', 'stale', False)
    entry, listed = owed_listing(client)
    assert (entry['queue_state'], entry['work_ids']) == ('unprepared', [])
    assert listed['queue_state_counts'] == {'unprepared': 1, 'stale': 1}

    fresh = prepare_response(client)
    assert fresh.status_code == 201, fresh.text
    assert fresh.json()['id'] != work['id']
    # One worker per finding and route: the new work waits for the earlier owner.
    assert (fresh.json()['queue_state'], fresh.json()['waiting_on_work_id']) == ('blocked', work['id'])
    entry, _ = owed_listing(client)
    assert entry['queue_state'] == 'blocked'
    assert claim(client, fresh.json(), 'PROOF-2').status_code == 409

    # The earlier owner keeps attributing what it already ran.
    recorded = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'claimed', 'run_id': run['id'],
    })
    assert recorded.status_code == 200, recorded.text
    assert (recorded.json()['status'], recorded.json()['run_ids']) == ('stale', [run['id']])
    assert client.patch(f'{BASE}/assessment-runs/{run["id"]}', json={'status': 'interrupted'}).status_code == 200
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    released = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={
        'reason': 'Earlier plan owner ended; its run is reconciled',
    })
    assert released.status_code == 200, released.text
    assert released.json()['status'] == 'stale'
    assert client.get(f'{BASE}/proof-work/{fresh.json()["id"]}').json()['queue_state'] == 'ready'
    assert claim(client, fresh.json(), 'PROOF-2').status_code == 200


def test_claim_whose_owner_dispatch_row_is_missing_reads_blocked(client, isolate_settings):
    from app.services.state_manager import proof_work

    assert proof_work.queue_state({
        'status': 'claimed', 'owed': True, 'current': True, 'approval_required': False,
        'verification_invalidated': False, 'waiting_on_work_id': None,
        'owner_dispatch_id': 7, 'owner_dispatch_status': None,
    }) == 'blocked'

    seed(client, isolate_settings)
    work = prepare(client)
    owner = claim(client, work).json()['owner_dispatch_id']
    with db.get_connection() as connection:
        connection.execute('PRAGMA foreign_keys=OFF')
        connection.execute('DELETE FROM assessment_dispatches WHERE id=?', (owner,))
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['queue_state'] == 'blocked'
    reconciled = client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={})
    assert reconciled.status_code == 200, reconciled.text
    assert reconciled.json()['status'] == 'blocked'
    # Missing ownership authorizes neither a release nor another worker.
    released = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={'reason': 'Owner row lost'})
    assert released.status_code == 409, released.text
    assert 'missing' in released.json()['detail']
    other = prepare(client, objective='Challenge replay with a second supported driver')
    assert other['queue_state'] == 'blocked'
    assert claim(client, other, 'PROOF-2').status_code == 409


def merge_parked_finding(client):
    target = client.post(f'{BASE}/findings', json={
        'slug': 'VA-051', 'title': 'Acme replay canonical record', 'severity': 'high',
        'canonical_location': 'https://example.com/login',
        'summary': 'Canonical replay record',
        'provenance': _author_provenance(client, 'VA-051'),
    })
    assert target.status_code == 201, target.text
    merged = client.post(f'{BASE}/findings/merge', json={
        'source_slug': 'VA-050', 'target_slug': 'VA-051',
        'reason': 'Same replay root cause', 'source_name': 'operator',
    })
    assert merged.status_code == 200, merged.text
    merged_finding = client.get(f'{BASE}/findings/VA-050').json()
    assert merged_finding['verification_status'] == 'pending_runtime_proof'
    # A merged finding owes no proof, so it has no current plan.
    assert merged_finding['next_test'] is None


def test_merged_findings_owe_no_proof_work(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    merge_parked_finding(client)

    listed = client.get(f'{BASE}/proof-work').json()
    assert listed['owed'] == []
    assert listed['queue_state_counts'] == {'done': 1}
    historical = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert (historical['owed'], historical['queue_state']) == (False, 'done')
    brief = client.get(f'{BASE}/resume-brief').json()['proof_work']
    assert brief['owed_findings'] == 0
    owed_rows = client.get(f'{BASE}/findings', params={'runtime_proof_owed': True}).json()
    assert [row['slug'] for row in owed_rows] == []

    refused = prepare_response(client)
    assert refused.status_code == 400, refused.text
    assert 'merged' in refused.json()['detail']
    assert claim(client, work).status_code == 409


def test_runtime_proof_owed_filter_lists_parked_live_findings(client, isolate_settings):
    seed(client, isolate_settings)
    owed_rows = client.get(f'{BASE}/findings', params={'runtime_proof_owed': True}).json()
    assert [row['slug'] for row in owed_rows] == ['VA-050']


def test_work_bound_before_parks_were_named_belongs_to_the_plan_it_was_prepared_under(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    legacy = dict(work['binding'])
    legacy.pop('parking_transition_id')
    encoded = json.dumps(legacy, sort_keys=True, separators=(',', ':'))
    with db.get_connection() as connection:
        connection.execute("UPDATE assessment_finding_next_tests SET created_at='2026-01-01 00:00:00'")
        connection.execute(
            "UPDATE assessment_proof_work SET binding_json=?,binding_digest=?,"
            "created_at='2026-01-01 00:00:01' WHERE id=?",
            (encoded, hashlib.sha256(encoded.encode()).hexdigest(), work['id']),
        )
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True
    assert prepare(client)['id'] == work['id']

    repark(client)
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False
    entry, _ = owed_listing(client)
    assert (entry['queue_state'], entry['work_ids']) == ('unprepared', [])
    assert prepare(client)['id'] != work['id']


def test_material_edit_that_invalidates_a_parked_finding_stales_its_open_work(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    patched = client.patch(f'{BASE}/findings/VA-050', json={'severity': 'medium'})
    assert patched.status_code == 200, patched.text
    assert patched.json()['finding']['verification_status'] == 'unreviewed'

    read = client.get(f'{BASE}/proof-work/{work["id"]}').json()
    assert (read['status'], read['owed'], read['queue_state']) == ('claimed', False, 'stale')
    assert client.get(f'{BASE}/proof-work').json()['queue_state_counts'] == {'stale': 1}
    reconciled = client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={}).json()
    assert (reconciled['status'], reconciled['queue_state']) == ('stale', 'stale')
    assert 'invalidated' in reconciled['blocker']
    # The owner still records what it ran; nothing reads the work as done.
    recorded = client.patch(f'{BASE}/proof-work/{work["id"]}', json={
        'agent_id': 'PROOF-1', 'status': 'claimed',
    })
    assert recorded.status_code == 200, recorded.text
    assert (recorded.json()['status'], recorded.json()['queue_state']) == ('stale', 'stale')
    assert 'invalidated' in recorded.json()['blocker']
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'completed'}).status_code == 200
    released = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={
        'reason': 'Owner ended after the finding was edited',
    }).json()
    assert (released['status'], released['owner_dispatch_id']) == ('stale', None)
    assert 'invalidated' in released['blocker']


def test_an_explicit_verification_decision_still_reads_open_work_done(client, isolate_settings):
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    decided = client.post(f'{BASE}/findings/VA-050/verify', json={
        'verification_status': 'disputed', 'reason_text': 'Claim contested.',
    })
    assert decided.status_code == 200, decided.text
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['queue_state'] == 'done'
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={}).json()['status'] == 'resolved'
