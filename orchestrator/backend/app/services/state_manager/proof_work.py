"""Durable, current-context proof scheduling; finding verification remains canonical.

Claims create the normal audited dispatch inside the same SQLite transaction. A
native launcher acts only on a successful claim; retries inspect ownership rather
than launching another worker. Reconciliation never infers death from elapsed time.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from fastapi import HTTPException

from . import _common
from .dispatches import record_dispatch
from .finding_next_tests import (
    current_next_test, current_parking_transition_id, next_tests_by_transition,
    owes_runtime_proof, parking_transition_id_at, runtime_proof_owed_sql,
)
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


def _view(engagement_id):
    return get_engagement_view_or_404(_common._engagement_or_404(engagement_id).key)


def _binding(connection, engagement_id, finding, route, objective, hosts, view):
    provenance = json.loads(finding['provenance_json'] or '{}')
    source = provenance.get('code_snapshot')
    return {
        'finding_claim_sha256': _current_claim_sha256(finding),
        # The park whose plan this work proves. A revised plan is a new park, so
        # work prepared for an earlier one becomes history, never the current item.
        'parking_transition_id': current_parking_transition_id(
            connection, engagement_id, finding['id'], finding['verification_status']),
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


# Derived readiness, never stored. Precedence is top to bottom: the first rule
# that matches names the state. Work is ``done`` once it finished or resolved, or
# once a verification decision or merge answered its finding's obligation, even
# while stale. Stale context outranks any stored lifecycle, including a finding
# whose verification a material edit invalidated before anyone decided it.
QUEUE_STATES = ('unprepared', 'ready', 'needs_approval', 'in_progress', 'blocked', 'stale', 'done')
# How an owed finding summarizes its current-park work: the most live item, and
# a claimable item ahead of one awaiting approval because claiming is the next action.
_OWED_QUEUE_PRIORITY = ('in_progress', 'ready', 'needs_approval', 'blocked', 'stale', 'done')
_LIVE_WORK_STATUSES = ('prepared', 'claimed', 'blocked')


def queue_state(work: dict) -> str:
    """Classify one serialized proof-work item for the operator queue."""
    if work['status'] in ('finished', 'resolved') or (
        not work['owed'] and not work['verification_invalidated']
    ):
        return 'done'
    if work['status'] == 'stale' or not work['current'] or not work['owed']:
        return 'stale'
    if work['status'] == 'blocked':
        return 'blocked'
    if work['status'] == 'claimed':
        # A claim whose owner ended, or whose owner row is gone, is what
        # reconcile turns into blocked.
        if _owner_ended(work):
            return 'blocked'
        return 'in_progress'
    if work['waiting_on_work_id'] is not None:
        # Claimable only after the earlier owner of this finding and route ends
        # and is released: one worker per finding and route.
        return 'blocked'
    return 'needs_approval' if work['approval_required'] else 'ready'


def _owner_ended(work: dict) -> bool:
    return (work['owner_dispatch_status'] is None
            or work['owner_dispatch_status'] in _common.TERMINAL_DISPATCH_STATUSES)


# ``finding verify`` never sets ``unreviewed``; a finding whose work was prepared
# while parked reads it only after a later edit reset its verification (a
# material change, a reopen, or a relationship change). Nobody decided the owed
# proof, so open work goes stale rather than done, and the finding needs
# re-verification before new proof work.
_INVALIDATED_BLOCKER = (
    'Finding verification was invalidated after this work was prepared (now unreviewed); '
    're-verify it before preparing proof again. Existing runs and evidence are retained.'
)


def _verification_invalidated(finding) -> bool:
    return finding['status'] != 'merged' and finding['verification_status'] == 'unreviewed'


def _competing_owner(connection, engagement_id, finding_id, route, work_id):
    """The other work whose owner still holds this finding and route, and why.

    A missing owner dispatch row counts as holding: missing ownership cannot
    authorize another worker.
    """
    for other in connection.execute(
        'SELECT w.id,w.owner_dispatch_id,d.status AS dispatch_status,w.status FROM assessment_proof_work w '
        'LEFT JOIN assessment_dispatches d ON d.id=w.owner_dispatch_id '
        'WHERE w.engagement_id=? AND w.finding_id=? AND w.route=? AND w.id<>? '
        'AND w.owner_dispatch_id IS NOT NULL ORDER BY w.id',
        (engagement_id, finding_id, route, work_id),
    ):
        if other['status'] not in ('finished', 'resolved') or other['dispatch_status'] not in _common.TERMINAL_DISPATCH_STATUSES:
            return other['id'], 'Another proof worker already owns this finding and route; reconcile and release it first'
        if _owned_execution_active(connection, engagement_id, other['owner_dispatch_id']):
            return other['id'], 'Previous proof worker still owns active runtime work; reconcile it first'
    return None, ''


def _owed_queue_state(item_states: list[str]) -> str:
    if not item_states:
        return 'unprepared'
    return next(state for state in _OWED_QUEUE_PRIORITY if state in item_states)


def _source_current(binding):
    return binding['source_status'] in ('current', 'not_applicable')


def _stored_binding(connection, engagement_id, row) -> dict:
    """A row's binding, projecting work written before bindings named their park."""
    binding = json.loads(row['binding_json'])
    if 'parking_transition_id' not in binding:
        binding['parking_transition_id'] = parking_transition_id_at(
            connection, engagement_id, row['finding_id'], row['created_at'])
    return binding


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


def _serialize(connection, engagement_id, row, *, with_history=True, view=None):
    view = view or _view(engagement_id)
    data = dict(row)
    binding = json.loads(data.pop('binding_json'))
    stored = _stored_binding(connection, engagement_id, row)
    hosts = json.loads(data.pop('target_hosts_json'))
    finding = _finding(connection, engagement_id, data['finding_slug'])
    current = _binding(connection, engagement_id, finding, data['route'], data['objective'], hosts, view)
    data['binding'] = binding
    data['parking_transition_id'] = stored['parking_transition_id']
    data['target_hosts'] = hosts
    data['approved'] = bool(data['approved'])
    data['authorized_phase'] = 'exploit' if data['route'] == 'web' else 'code-verify'
    data['owed'] = owes_runtime_proof(finding)
    data['verification_invalidated'] = _verification_invalidated(finding)
    # The finding's runtime proof plan: untrusted context for the worker, never authority.
    # The plan this work was prepared for; after a re-park, history keeps its own.
    data['next_test'] = next_tests_by_transition(
        connection, engagement_id, finding['id'], [data['parking_transition_id']],
    ).get(data['parking_transition_id']) if data['parking_transition_id'] is not None else None
    data['waiting_on_work_id'] = _competing_owner(
        connection, engagement_id, finding['id'], data['route'], data['id'],
    )[0] if data['status'] == 'prepared' and data['owner_dispatch_id'] is None else None
    data['current'] = (
        _normalized_binding(current) == _normalized_binding(stored)
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
    data['approval_required'] = data['route'] == 'web' and not _approved(view, data)
    data['queue_state'] = queue_state(data)
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
    if work['verification_invalidated']:
        _fail(_INVALIDATED_BLOCKER)
    if not work['current']:
        _fail('Proof work context changed; reconcile and prepare against the current plan, evidence, and scope')
    if not work['owed']:
        _fail('Finding no longer owes runtime proof; inspect its canonical verification state')


def get_proof_work(engagement_id: int, work_id: int) -> dict:
    with _common.get_connection() as connection:
        return _serialize(connection, engagement_id, _row(connection, engagement_id, work_id))


def list_proof_work(engagement_id: int) -> dict:
    """Every owed finding and every work item; the current operator owns them all."""
    view = _view(engagement_id)
    with _common.get_connection() as connection:
        items = [_serialize(connection, engagement_id, row, with_history=False, view=view)
                 for row in connection.execute(
            'SELECT w.*, f.slug AS finding_slug, d.agent_id AS owner_agent_id, '
            'd.status AS owner_dispatch_status FROM assessment_proof_work w '
            'JOIN assessment_findings f ON f.id=w.finding_id '
            'LEFT JOIN assessment_dispatches d ON d.id=w.owner_dispatch_id '
            'WHERE w.engagement_id=? ORDER BY w.id', (engagement_id,),
        )]
        owed = []
        for row in connection.execute(
            'SELECT * FROM assessment_findings WHERE engagement_id=? AND '
            + runtime_proof_owed_sql() + ' ORDER BY id', (engagement_id,),
        ):
            park = current_parking_transition_id(
                connection, engagement_id, row['id'], row['verification_status'])
            # Work prepared for an earlier park stays in ``items`` as history;
            # only work for the current plan decides what this finding needs next.
            work = [w for w in items
                    if w['finding_id'] == row['id'] and w['parking_transition_id'] == park]
            owed.append({
                'finding_slug': row['slug'], 'finding_id': row['id'],
                'title': row['title'], 'canonical_location': row['canonical_location'],
                'next_test': current_next_test(
                    connection, engagement_id, row['id'], row['verification_status'],
                    workflow_status=row['status']),
                'work_ids': [w['id'] for w in work],
                'queue_state': _owed_queue_state([w['queue_state'] for w in work]),
            })
        # Each unit counted once: every item, plus each owed finding with no
        # current-park work.
        counts = Counter(w['queue_state'] for w in items)
        counts.update(entry['queue_state'] for entry in owed if entry['queue_state'] == 'unprepared')
        return {'owed': owed, 'items': items,
                'queue_state_counts': {state: counts[state] for state in QUEUE_STATES if counts[state]}}


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
        if finding['status'] == 'merged':
            _fail('Merged findings owe no proof work; prepare proof for the finding it was merged into', 400)
        if not owes_runtime_proof(finding):
            _fail('Only pending_runtime_proof findings can be prepared', 400)
        binding = _binding(connection, engagement_id, finding, route, objective, hosts,
                           _view(engagement_id))
        if not _source_current(binding):
            _fail('Finding source generation is no longer current')
        if route == 'web' and (
            not hosts or not all(binding['target_admission'].values())
        ):
            _fail('Live proof requires explicitly admitted target hosts outside denied scope', 400)
        digest = hashlib.sha256(_json(binding).encode()).hexdigest()
        hosts_json = _json(hosts)
        # Legacy bindings can normalize equal; reuse the newest live row before
        # any ended one, so an old stale or finished row cannot shadow it.
        matches = [
            row for row in connection.execute(
                'SELECT id,status,binding_json,finding_id,created_at FROM assessment_proof_work '
                'WHERE engagement_id=? AND finding_id=? AND route=? '
                'AND objective=? AND target_hosts_json=? ORDER BY id DESC',
                (engagement_id, finding['id'], route, objective, hosts_json),
            )
            if _normalized_binding(_stored_binding(connection, engagement_id, row))
            == _normalized_binding(binding)
        ]
        work_id = next((
            row['id'] for row in sorted(
                matches, key=lambda row: row['status'] not in _LIVE_WORK_STATUSES)
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
        if prepared['owner_dispatch_id'] is not None and prepared['status'] != 'claimed':
            _fail(
                f"Matching proof work is still owned with status={prepared['status']}; "
                f"reconcile the owner execution and run `vigil assess proof-work release "
                f"{work_id}` before preparing this context again"
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
        competing, reason = _competing_owner(
            connection, engagement_id, work['finding_id'], work['route'], work_id)
        if competing is not None:
            _fail(reason)
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
        if status == 'claimed' and work['verification_invalidated']:
            status, blocker = 'stale', blocker or _INVALIDATED_BLOCKER
        elif status == 'claimed' and (not work['current'] or not work['owed']):
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
        if work['verification_invalidated'] and work['status'] not in ('finished', 'resolved'):
            new_status, blocker = 'stale', _INVALIDATED_BLOCKER
        elif not work['owed']:
            new_status = 'resolved'
        elif not work['current']:
            new_status, blocker = 'stale', 'Finding, runtime proof plan, source generation, or admitted scope changed'
        elif work['status'] == 'claimed' and _owner_ended(work):
            new_status, blocker = 'blocked', 'Owner dispatch ended or is missing; inspect durable proof runs before retrying'
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
        if work['owner_dispatch_status'] is None:
            _fail('Owner dispatch record is missing, so ownership cannot be verified; this work cannot be released')
        if work['owner_dispatch_status'] not in _common.TERMINAL_DISPATCH_STATUSES:
            _fail('Owner dispatch is still active; inspect its native session before recovery')
        if _owned_execution_active(connection, engagement_id, work['owner_dispatch_id']):
            _fail('Owned runtime work remains active; reconcile proof runs, command runs, and supervised jobs first')
        _event(connection, work_id, 'released', {
            'reason': reason, 'previous_dispatch_id': work['owner_dispatch_id'],
            'previous_agent_id': work['owner_agent_id'],
        })
        connection.execute(
            "UPDATE assessment_proof_work SET owner_dispatch_id=NULL,status=?,blocker=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            ('stale' if work['verification_invalidated'] else 'resolved' if not work['owed']
             else 'prepared' if work['current'] else 'stale',
             _INVALIDATED_BLOCKER if work['verification_invalidated'] else '', work_id),
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
