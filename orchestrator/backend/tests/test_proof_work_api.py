from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from app import db
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
        assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True}).status_code == 200
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
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True}).status_code == 200
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
    approved = client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True})
    assert approved.status_code == 200, approved.text
    assert claim(client, work).status_code == 200
    assert client.get(f'{BASE}/exploit-candidates').json() == []


def test_changed_claim_or_scope_blocks_work_without_erasing_history(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True})
    scope = json.loads((path / 'scope.json').read_text())
    scope['scope_hosts'] = ['other.example']
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


def test_policy_change_invalidates_exact_work_approval(client, isolate_settings):
    path = seed(client, isolate_settings)
    work = prepare(client, 'web')
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True}).status_code == 200
    scope = json.loads((path / 'scope.json').read_text())
    scope['exploit_policy'] = 'pause'
    (path / 'scope.json').write_text(json.dumps(scope))
    assert claim(client, work).status_code == 409
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False


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
    assert client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True}).status_code == 200
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
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True})
    assert claim(client, work).status_code == 200
    assert client.patch(f'{BASE}/dispatches/PROOF-1', json={'status': 'aborted'}).status_code == 200
    scope = json.loads((path / 'scope.json').read_text())
    scope['exploit_policy'] = 'pause'
    (path / 'scope.json').write_text(json.dumps(scope))
    response = client.post(f'{BASE}/proof-work/{work["id"]}/release', json={
        'reason': 'Owner ended; all runtime work inspected after policy change',
    })
    assert response.status_code == 200, response.text
    assert response.json()['status'] == 'stale'
    assert response.json()['owner_dispatch_id'] is None
    fresh = prepare(client, 'web')
    assert fresh['id'] != work['id']
    assert claim(client, fresh, 'PROOF-2').status_code == 409


def test_route_derives_explicit_audit_phase_for_specialist(client, isolate_settings):
    seed(client, isolate_settings)
    local = prepare(client)
    assert local.get('authorized_phase') == 'code-verify'
    live = prepare(client, 'web')
    assert live.get('authorized_phase') == 'exploit'


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
    client.post(f'{BASE}/proof-work/{work["id"]}/approval', json={'approved': True})
    original = (path / 'scope.json').read_text()
    scope = json.loads(original)
    scope['exploit_policy'] = 'pause'
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.post(f'{BASE}/proof-work/{work["id"]}/reconcile', json={}).json()['status'] == 'stale'
    (path / 'scope.json').write_text(original)
    restored = prepare(client, 'web')
    assert restored['status'] == 'prepared'
    assert restored['approved'] is False
    assert any(event['action'] == 'reprepared' for event in restored['events'])


def test_unrelated_selected_approval_does_not_invalidate_existing_authorized_proof(client, isolate_settings):
    path = seed(client, isolate_settings)
    scope = json.loads((path / 'scope.json').read_text())
    scope['approved_targets'] = ['VA-050']
    (path / 'scope.json').write_text(json.dumps(scope))
    work = prepare(client, 'web')
    assert work['approval_required'] is False
    scope['approved_targets'].append('VA-051')
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is True
    assert claim(client, work).status_code == 200
    scope['approved_targets'] = ['VA-051']
    (path / 'scope.json').write_text(json.dumps(scope))
    assert client.get(f'{BASE}/proof-work/{work["id"]}').json()['current'] is False
