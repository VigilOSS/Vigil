"""A dispatch retry may recover the same capture, never create a second worker."""
from tests.test_dispatch_client_binding_api import BASE, _seed


def test_exact_packet_registration_retry_is_inspection_not_launch(client, isolate_settings):
    _seed(client, isolate_settings['engagements_dir'])
    body = {'agent_id': 'acme-retry', 'agent_role': 'vulnerability-analyst', 'task': 'Investigate Acme boundary',
            'prompt_packet': {'schema': 'dispatch-prompt/v1', 'context': {'authorized_phase': 'hunt'},
                              'rendered_prompt': 'agent_id: acme-retry\nAcme assignment'}}
    first = client.post(f'{BASE}/dispatches', json=body)
    assert first.status_code == 201, first.text
    repeated = client.post(f'{BASE}/dispatches', json=body)
    assert repeated.status_code == 201, repeated.text
    assert repeated.json()['id'] == first.json()['id']
    assert repeated.json()['launch_required'] is False
    assert repeated.json()['idempotent_replay'] is True
    changed = {**body, 'task': 'Changed assignment'}
    conflict = client.post(f'{BASE}/dispatches', json=changed)
    assert conflict.status_code == 409, conflict.text


def test_terminal_capture_never_authorizes_a_native_launch(client, isolate_settings):
    _seed(client, isolate_settings['engagements_dir'])
    response = client.post(f'{BASE}/dispatches', json={
        'agent_id': 'acme-history', 'agent_role': 'vulnerability-analyst', 'status': 'completed',
        'prompt_packet': {'schema': 'dispatch-prompt/v1', 'context': {}, 'rendered_prompt': 'Historical assignment'},
    })
    assert response.status_code == 201, response.text
    assert response.json()['launch_required'] is False


def test_released_proof_work_requires_a_fresh_dispatch_identity(client, isolate_settings):
    from tests.test_proof_work_api import BASE as proof_base, seed, prepare, claim
    seed(client, isolate_settings)
    work = prepare(client)
    assert claim(client, work).status_code == 200
    assert client.patch(f'{proof_base}/dispatches/PROOF-1', json={'status': 'aborted'}).status_code == 200
    released = client.post(f'{proof_base}/proof-work/{work["id"]}/release', json={'reason': 'Observed native return; no execution remains'})
    assert released.status_code == 200, released.text
    repeated = claim(client, work)
    assert repeated.status_code == 409, repeated.text
    current = client.get(f'{proof_base}/proof-work/{work["id"]}').json()
    assert current['owner_dispatch_id'] is None
    fresh = claim(client, work, 'PROOF-2')
    assert fresh.status_code == 200, fresh.text
    assert fresh.json()['launch_required'] is True


def test_saved_variant_dispatch_replays_after_current_parent_scope_changes(client, isolate_settings):
    from tests.test_code_analysis_api import write_engagement, _create_repo, _create_files, _create_code_parent_finding
    key = '2026-10-23-acme-variant-replay'
    write_engagement(isolate_settings['engagements_dir'], key)
    repo = _create_repo(client, key, repo_key='acme-variant-replay')
    _create_files(client, key, int(repo['id']))
    _create_code_parent_finding(client, key, int(repo['id']), slug='AC-001')
    endpoint = f'/engagements/{key}/assessment/dispatches'
    body = {'agent_id': 'acme-variant', 'agent_role': 'code-variant-hunter', 'task': 'Review the registered Acme root scope',
            'finding_slugs': ['AC-001'], 'prompt_packet': {'schema': 'dispatch-prompt/v1', 'context': {}, 'rendered_prompt': 'Captured original Acme assignment'}}
    first = client.post(endpoint, json=body)
    assert first.status_code == 201, first.text
    _create_code_parent_finding(client, key, int(repo['id']), slug='AC-002')
    replay = client.post(endpoint, json=body)
    assert replay.status_code == 201, replay.text
    assert replay.json()['id'] == first.json()['id']
    assert replay.json()['launch_required'] is False
    changed = client.post(endpoint, json={**body, 'agent_id': 'acme-new-worker'})
    assert changed.status_code == 409, changed.text
