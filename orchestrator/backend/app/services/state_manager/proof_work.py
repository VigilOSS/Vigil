"""Durable, current-context proof scheduling; finding verification remains canonical.

Claims create the normal audited dispatch inside the same SQLite transaction. A
native launcher acts only on a successful claim; retries inspect ownership rather
than launching another worker. Reconciliation never infers death from elapsed time.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import HTTPException

from . import _common
from .dispatches import record_dispatch
from .finding_snapshots import finding_code_snapshot_status
from .findings import _current_claim_sha256
from ..engagements import get_engagement_view_or_404
from ..scope_admission import admitted_host


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _fail(message: str, code: int = 409) -> None:
    raise HTTPException(status_code=code, detail=message)


def _finding(connection, engagement_id, slug):
    row = connection.execute(
        'SELECT * FROM assessment_findings WHERE engagement_id=? AND slug=?',
        (engagement_id, slug),
    ).fetchone()
    if row is None:
        _fail('Finding not found', 404)
    return row


def _binding(connection, engagement_id, finding, route, objective, hosts):
    engagement = _common._engagement_or_404(engagement_id)
    view = get_engagement_view_or_404(engagement.key)
    provenance = json.loads(finding['provenance_json'] or '{}')
    source = provenance.get('code_snapshot')
    return {
        'finding_claim_sha256': _current_claim_sha256(finding),
        'source_binding': source,
        'source_status': finding_code_snapshot_status(connection, engagement_id, finding),
        # Bind web work to the admission result for its selected hosts, not to
        # the engagement's entire scope document. Adding or excluding an
        # unrelated host cannot change the authority for this exact proof.
        'target_admission': {
            host: admitted_host(host, view.scope_hosts, view.out_of_scope or [])
            for host in hosts
        } if route == 'web' else {},
        'approval_posture': {
            'policy': view.exploit_policy, 'review_state': view.exploit_review_state,
            'selected_authorized': ('*' in view.approved_targets
                                    or finding['slug'] in view.approved_targets),
        } if route == 'web' else None,
        'route': route, 'objective': objective, 'target_hosts': hosts,
    }


def _source_current(binding):
    return binding['source_status'] in ('current', 'not_applicable')


def _normalized_binding(binding: dict) -> dict:
    """Project pre-target-scoped bindings onto the current durable contract."""
    normalized = dict(binding)
    roots = list(normalized.pop('scope_hosts', []) or [])
    denied = list(normalized.pop('out_of_scope', []) or [])
    if 'target_admission' not in normalized:
        hosts = list(normalized.get('target_hosts') or [])
        normalized['target_admission'] = (
            {host: admitted_host(host, roots, denied) for host in hosts}
            if normalized.get('route') == 'web' else {}
        )
    return normalized


def _row(connection, engagement_id, work_id):
    row = connection.execute(
        'SELECT w.*, f.slug AS finding_slug, d.agent_id AS owner_agent_id, '
        'd.status AS owner_dispatch_status FROM assessment_proof_work w '
        'JOIN assessment_findings f ON f.id=w.finding_id '
        'LEFT JOIN assessment_dispatches d ON d.id=w.owner_dispatch_id '
        'WHERE w.engagement_id=? AND w.id=?', (engagement_id, work_id),
    ).fetchone()
    if row is None:
        _fail('Proof work not found', 404)
    return row


def _serialize(connection, engagement_id, row, *, with_history=True):
    data = dict(row)
    binding = json.loads(data.pop('binding_json'))
    hosts = json.loads(data.pop('target_hosts_json'))
    finding = _finding(connection, engagement_id, data['finding_slug'])
    current = _binding(connection, engagement_id, finding, data['route'], data['objective'], hosts)
    data['binding'] = binding
    data['target_hosts'] = hosts
    data['approved'] = bool(data['approved'])
    data['authorized_phase'] = 'exploit' if data['route'] == 'web' else 'code-verify'
    data['owed'] = finding['verification_status'] == 'pending_runtime_proof'
    data['current'] = (
        _normalized_binding(current) == _normalized_binding(binding)
        and _source_current(current)
    )
    data['run_ids'] = [r['run_id'] for r in connection.execute(
        'SELECT run_id FROM assessment_proof_work_runs WHERE work_id=? ORDER BY run_id',
        (data['id'],),
    )]
    data['event_count'] = connection.execute(
        'SELECT COUNT(*) FROM assessment_proof_work_events WHERE work_id=?', (data['id'],),
    ).fetchone()[0]
    data['events'] = [dict(r) for r in connection.execute(
        'SELECT * FROM assessment_proof_work_events WHERE work_id=? ORDER BY id', (data['id'],),
    )] if with_history else []
    view = get_engagement_view_or_404(_common._engagement_or_404(engagement_id).key)
    data['approval_required'] = data['route'] == 'web' and not _approved(view, data)
    return data


def _event(connection, work_id, action, details):
    connection.execute(
        'INSERT INTO assessment_proof_work_events(work_id,action,details_json) VALUES(?,?,?)',
        (work_id, action, _json(details)),
    )


def _approved(view, work):
    return bool(work['approved'] or view.exploit_policy == 'full_send' or (
        view.exploit_review_state == 'approved' and (
            '*' in view.approved_targets or work['finding_slug'] in view.approved_targets)))


def _require_current(work):
    if not work['current']:
        _fail('Proof work context changed; reconcile and prepare against current evidence/scope')
    if not work['owed']:
        _fail('Finding no longer owes runtime proof; inspect its canonical verification state')


def get_proof_work(engagement_id: int, work_id: int) -> dict:
    with _common.get_connection() as connection:
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def list_proof_work(engagement_id: int) -> dict:
    with _common.get_connection() as connection:
        items = [_serialize(connection, engagement_id, row, with_history=False) for row in connection.execute(
            'SELECT w.*, f.slug AS finding_slug, d.agent_id AS owner_agent_id, '
            'd.status AS owner_dispatch_status FROM assessment_proof_work w '
            'JOIN assessment_findings f ON f.id=w.finding_id '
            'LEFT JOIN assessment_dispatches d ON d.id=w.owner_dispatch_id '
            'WHERE w.engagement_id=? ORDER BY w.id', (engagement_id,),
        )]
        owed = [{'finding_slug': row['slug'], 'finding_id': row['id'],
                 'title': row['title'], 'canonical_location': row['canonical_location'],
                 'work_ids': [w['id'] for w in items if w['finding_id'] == row['id']]}
                for row in connection.execute(
                    "SELECT * FROM assessment_findings WHERE engagement_id=? "
                    "AND verification_status='pending_runtime_proof' ORDER BY id", (engagement_id,),
                )]
        return {'owed': owed, 'items': items}


def prepare_proof_work(engagement_id: int, *, finding_slug: str, route: str,
                       objective: str, target_hosts: list[str]) -> dict:
    objective = objective.strip()
    if not objective:
        _fail('Proof objective must describe the hypothesis to challenge', 400)
    hosts = sorted(set(h.strip().lower().rstrip('.') for h in target_hosts))
    if route == 'code' and hosts:
        _fail('Local code proof does not take live target hosts; choose web for live effects', 400)
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        finding = _finding(connection, engagement_id, finding_slug)
        if finding['verification_status'] != 'pending_runtime_proof':
            _fail('Only pending_runtime_proof findings can be prepared', 400)
        binding = _binding(connection, engagement_id, finding, route, objective, hosts)
        if not _source_current(binding):
            _fail('Finding source generation is no longer current')
        if route == 'web' and (
            not hosts or not all(binding['target_admission'].values())
        ):
            _fail('Live proof requires explicitly admitted target hosts outside denied scope', 400)
        digest = hashlib.sha256(_json(binding).encode()).hexdigest()
        hosts_json = _json(hosts)
        work_id = next((
            row['id']
            for row in connection.execute(
                'SELECT id,binding_json FROM assessment_proof_work '
                'WHERE engagement_id=? AND finding_id=? AND route=? '
                'AND objective=? AND target_hosts_json=? ORDER BY id',
                (engagement_id, finding['id'], route, objective, hosts_json),
            )
            if _normalized_binding(json.loads(row['binding_json']))
            == _normalized_binding(binding)
        ), None)
        if work_id is None:
            connection.execute(
                'INSERT OR IGNORE INTO assessment_proof_work '
                '(engagement_id,finding_id,binding_digest,binding_json,route,objective,target_hosts_json) '
                'VALUES(?,?,?,?,?,?,?)',
                (engagement_id, finding['id'], digest, _json(binding), route, objective, hosts_json),
            )
            work_id = connection.execute(
                'SELECT id FROM assessment_proof_work WHERE engagement_id=? AND finding_id=? '
                'AND binding_digest=?', (engagement_id, finding['id'], digest),
            ).fetchone()['id']
        prepared = _row(connection, engagement_id, work_id)
        if prepared['owner_dispatch_id'] is not None and prepared['status'] in ('stale', 'resolved'):
            _fail(
                'Matching proof work is still owned; reconcile the owner execution and '
                'release it before preparing this context again'
            )
        if prepared['owner_dispatch_id'] is None and prepared['status'] in ('stale', 'resolved'):
            connection.execute(
                "UPDATE assessment_proof_work SET status='prepared',approved=0,blocker='', "
                "updated_at=CURRENT_TIMESTAMP WHERE id=?", (work_id,),
            )
            _event(connection, work_id, 'reprepared', {'previous_status': prepared['status']})
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def approve_proof_work(engagement_id: int, work_id: int, *, approved: bool) -> dict:
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        work = _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))
        _require_current(work)
        connection.execute('UPDATE assessment_proof_work SET approved=?,updated_at=CURRENT_TIMESTAMP '
                           'WHERE id=?', (int(approved), work_id))
        _event(connection, work_id, 'approval', {'approved': approved})
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def claim_proof_work(engagement_id: int, work_id: int, *, dispatch: dict) -> dict:
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        work = _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))
        _require_current(work)
        if work['owner_dispatch_id'] is not None:
            if work['owner_agent_id'] == dispatch['agent_id']:
                return {**work, 'launch_required': False}
            _fail('Proof work is already owned; reconcile its dispatch and runtime runs')
        if work['status'] != 'prepared':
            _fail('Proof work is not available for a new claim')
        if dispatch.get('status', 'in-progress') != 'in-progress':
            _fail('Proof work requires a new in-progress dispatch', 400)
        allowed_roles = {'exploit-developer', 'code-vuln-verifier' if work['route'] == 'code' else 'vulnerability-analyst'}
        if dispatch['agent_role'] not in allowed_roles:
            _fail('Proof work requires an appropriate verifier specialist role', 400)
        if not dispatch.get('prompt_packet'):
            _fail('Proof work requires the canonical rendered dispatch prompt packet', 400)
        if work['approval_required']:
            _fail('Live proof approval required for this exact work or existing selected scope')
        author = json.loads(_finding(connection, engagement_id, work['finding_slug'])['provenance_json']).get('agent_id')
        if author == dispatch['agent_id']:
            _fail('Finding author cannot own its independent proof work', 400)
        competing = connection.execute(
            'SELECT w.id,w.owner_dispatch_id,d.status AS dispatch_status,w.status FROM assessment_proof_work w '
            'JOIN assessment_dispatches d ON d.id=w.owner_dispatch_id '
            'WHERE w.engagement_id=? AND w.finding_id=? AND w.route=? AND w.id<>?',
            (engagement_id, work['finding_id'], work['route'], work_id),
        ).fetchall()
        for other in competing:
            if other['status'] not in ('finished', 'resolved') or other['dispatch_status'] not in _common.TERMINAL_DISPATCH_STATUSES:
                _fail('Another proof worker already owns this finding and route; reconcile and release it first')
            if _owned_execution_active(connection, engagement_id, other['owner_dispatch_id']):
                _fail('Previous proof worker still owns active runtime work; reconcile it first')
        payload = dict(dispatch)
        payload.pop('status', None)
        # A prepared proof route is stronger than an ordinary dispatch hint.
        # Persist the effective mode the specialist actually receives.
        payload['assessment_mode'] = work['route']
        packet = dict(payload['prompt_packet'])
        packet_context = dict(packet.get('context') or {})
        packet_context['assessment_mode'] = work['route']
        packet['context'] = packet_context
        packet['rendered_prompt'] = (
            f"proof_route: {work['route']}\n" + str(packet['rendered_prompt'])
        )
        payload['prompt_packet'] = packet
        payload['finding_slugs'] = [work['finding_slug']]
        payload['dispatch_mode'] = 'deep-manual'
        payload['task'] = (payload.get('task') or work['objective']) + f"\nproof_route: {work['route']}\nproof_work_id: {work_id}\nauthorized_phase: {'exploit' if work['route'] == 'web' else 'code-verify'}"
        created = record_dispatch(engagement_id, **payload)
        connection.execute('UPDATE assessment_proof_work SET owner_dispatch_id=?,status=\'claimed\', '
                           'updated_at=CURRENT_TIMESTAMP WHERE id=?', (created['id'], work_id))
        _event(connection, work_id, 'claimed', {'dispatch_id': created['id'], 'agent_id': dispatch['agent_id']})
        return {
            **_serialize(connection, engagement_id, _row(connection, engagement_id, work_id)),
            'launch_required': True,
            'prompt_packet': created['prompt_packet'],
        }


def update_proof_work(engagement_id: int, work_id: int, *, agent_id: str,
                      status: str, blocker: str = '', run_id: int | None = None) -> dict:
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        work = _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))
        if status == 'claimed' and (not work['current'] or not work['owed']):
            status = 'stale' if work['owed'] else 'resolved'
            blocker = blocker or 'Context changed; existing evidence retained, new execution requires current work'
        if status == 'blocked' and not blocker.strip():
            _fail('Blocked proof work requires the missing prerequisite or blocker', 400)
        if work['owner_agent_id'] != agent_id:
            _fail('Only the owning dispatch can update proof work')
        if run_id is not None:
            run = connection.execute('SELECT * FROM assessment_runs WHERE id=? AND engagement_id=?',
                                     (run_id, engagement_id)).fetchone()
            if run is None or run['producer_dispatch_id'] != work['owner_dispatch_id']:
                _fail('Proof run must belong to the work owner', 400)
            if run['run_purpose'] != 'proof':
                _fail('Only proof-purpose runs can be linked to proof work', 400)
            if run['run_kind'] not in (work['route'], 'shared'):
                _fail('Proof run route does not match prepared work', 400)
            connection.execute('INSERT OR IGNORE INTO assessment_proof_work_runs(work_id,run_id) VALUES(?,?)',
                               (work_id, run_id))
        connection.execute('UPDATE assessment_proof_work SET status=?,blocker=?,updated_at=CURRENT_TIMESTAMP '
                           'WHERE id=?', (status, blocker, work_id))
        _event(connection, work_id, status, {'agent_id': agent_id, 'blocker': blocker, 'run_id': run_id})
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def reconcile_proof_work(engagement_id: int, work_id: int) -> dict:
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        work = _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))
        new_status = None
        blocker = work['blocker']
        if not work['owed']:
            new_status = 'resolved'
        elif not work['current']:
            new_status, blocker = 'stale', 'Finding, source generation, or admitted scope changed'
        elif work['owner_dispatch_status'] in ('failed', 'aborted', 'blocked', 'completed') and work['status'] == 'claimed':
            new_status, blocker = 'blocked', 'Owner dispatch ended; inspect durable proof runs before retrying'
        if new_status and new_status != work['status']:
            connection.execute('UPDATE assessment_proof_work SET status=?,blocker=?,updated_at=CURRENT_TIMESTAMP '
                               'WHERE id=?', (new_status, blocker, work_id))
            _event(connection, work_id, 'reconciled', {'status': new_status, 'blocker': blocker})
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def release_proof_work(engagement_id: int, work_id: int, *, reason: str) -> dict:
    """Explicitly retry ended work only after canonical execution owners reconcile.

    No clock threshold, client PID inference, or native-chat exit can authorize a
    second worker. Every owned run/command/job must already have terminal truth.
    """
    reason = reason.strip()
    if not reason:
        _fail('Release requires a reason describing the inspected recovery state', 400)
    with _common.get_connection() as connection:
        connection.execute('BEGIN IMMEDIATE')
        work = _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))
        if work['owner_dispatch_id'] is None:
            return work
        if work['owner_dispatch_status'] not in _common.TERMINAL_DISPATCH_STATUSES:
            _fail('Owner dispatch is still active; inspect its native session before recovery')
        if _owned_execution_active(connection, engagement_id, work['owner_dispatch_id']):
            _fail('Owned runtime work remains active; reconcile proof runs, command runs, and supervised jobs first')
        _event(connection, work_id, 'released', {
            'reason': reason, 'previous_dispatch_id': work['owner_dispatch_id'],
            'previous_agent_id': work['owner_agent_id'],
        })
        connection.execute(
            "UPDATE assessment_proof_work SET owner_dispatch_id=NULL,status=?,blocker='', "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            ('resolved' if not work['owed'] else 'prepared' if work['current'] else 'stale', work_id),
        )
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def _owned_execution_active(connection, engagement_id, dispatch_id):
    owner = connection.execute('SELECT agent_id FROM assessment_dispatches WHERE id=? AND engagement_id=?',
                               (dispatch_id, engagement_id)).fetchone()
    if owner is None:
        return True  # Missing ownership cannot authorize another worker.
    active_run = connection.execute(
        "SELECT id FROM assessment_runs WHERE engagement_id=? AND producer_dispatch_id=? "
        "AND status IN ('queued','running') LIMIT 1", (engagement_id, dispatch_id),
    ).fetchone()
    active_command = connection.execute(
        "SELECT id FROM assessment_command_runs WHERE engagement_id=? AND agent_name=? "
        "AND status IN ('queued','running') LIMIT 1", (engagement_id, owner['agent_id']),
    ).fetchone()
    active_job = connection.execute(
        "SELECT j.id FROM assessment_jobs j JOIN assessment_command_runs c ON c.id=j.parent_command_run_id "
        "WHERE j.engagement_id=? AND c.agent_name=? "
        "AND j.status IN ('queued','running','stop_failed') LIMIT 1", (engagement_id, owner['agent_id']),
    ).fetchone()
    return bool(active_run or active_command or active_job)
