from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from assess.commands import agent
from assess.lib.client import AssessError


class RecoveryClient:
    def __init__(self, handoff=None):
        self.handoff = copy.deepcopy(handoff)
        self.row = {'id': 1, 'agent_id': 'HUNT-1', 'agent_role': 'code-vuln-hunter', 'status': 'in-progress'}
        self.writes = []

    def get_handoff(self, agent_id):
        return copy.deepcopy(self.handoff)

    def get_dispatch(self, agent_id):
        return dict(self.row)

    def record_handoff(self, body):
        self.writes.append(('handoff', copy.deepcopy(body)))
        self.handoff = dict(body, id=2, handoff_version=1)
        return dict(self.handoff)

    def update_handoff(self, agent_id, patch):
        self.writes.append(('handoff_patch', copy.deepcopy(patch)))
        self.handoff.update(patch, handoff_version=self.handoff['handoff_version'] + 1)
        return dict(self.handoff)

    def update_dispatch(self, agent_id, patch):
        self.writes.append(('dispatch', dict(patch)))
        self.row.update(patch)
        return dict(self.row)

    def record_decision(self, body):
        self.writes.append(('decision', copy.deepcopy(body)))
        return dict(body, id=3)

    def close(self):
        pass


def args(reason=' Native worker returned at its context limit; owned commands have ended.\n',
         status='failed'):
    return SimpleNamespace(extra=['HUNT-1'], agent_id=None, completed_at=None,
                           close_status=status, reason=reason)


@pytest.mark.parametrize('checkpoint', [False, True])
@pytest.mark.parametrize('status', ['failed', 'blocked'])
def test_returned_without_handoff_has_audited_closure_and_preserves_checkpoint(
    monkeypatch, checkpoint, status
):
    """`--status blocked` is the same recovery for a lane that DID produce work.

    A lane that returned with receipts and closed leases but only a checkpointed
    handoff could previously be closed `failed` only, which reads as no work
    done. Both statuses keep the identical operator_recovery stamp, the reason
    requirement, and every checkpointed field.
    """
    old = {'id': 2, 'agent_id': 'HUNT-1', 'agent_role': 'code-vuln-hunter',
           'handoff_status': 'checkpointed', 'handoff_version': 4,
           'summary': 'Acme boundary checked; caller path unfinished.',
           'working_artifacts': [{'path': 'evidence/acme-checkpoint.md'}],
           'coverage_gaps': [{'path': 'src/acme.py', 'reason': 'caller path unfinished'}],
           'extras': {'checkpoint_note': 'Acme exact bytes'}} if checkpoint else None
    client = RecoveryClient(old)
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    agent._close(args(status=status))
    assert client.row['status'] == status
    assert client.handoff['handoff_status'] == 'blocked'
    assert client.handoff['closed_dispatch_status'] == status
    recovery = client.handoff['extras']['operator_recovery']
    assert recovery['reason'] == args().reason
    assert recovery['actor'] == 'operator'
    if checkpoint:
        for field in ('summary', 'working_artifacts', 'coverage_gaps'):
            assert client.handoff[field] == old[field]
        assert client.handoff['extras']['checkpoint_note'] == old['extras']['checkpoint_note']
    decision = client.writes[-1][1]
    assert decision['kind'] == 'dispatch_closed_from_handoff'
    assert decision['payload']['reason'] == args().reason
    assert decision['payload']['closed_dispatch_status'] == status
    assert decision['payload']['handoff_version'] == client.handoff['handoff_version']


def test_close_unions_the_dispatch_input_scope_with_the_handoff_slugs(monkeypatch):
    """`agent start --finding-slugs` records the input/related scope.

    The close used to pass the handoff's list alone into a PATCH that replaces
    the column, so closing a dispatch dropped every slug the handoff author
    omitted — while the renderer deliberately unions the same two lists.
    """
    client = RecoveryClient({'id': 2, 'agent_id': 'HUNT-1', 'agent_role': 'code-vuln-hunter',
                             'handoff_status': 'ready', 'handoff_version': 2,
                             'summary': 'Acme variant produced VA-002.',
                             'finding_slugs': ['VA-002']})
    client.row['finding_slugs'] = ['VA-001']
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))

    agent._close(SimpleNamespace(extra=['HUNT-1'], agent_id=None, completed_at=None,
                                 close_status=None, reason='ready handoff reviewed'))

    patch = next(body for kind, body in client.writes if kind == 'dispatch')
    assert patch['finding_slugs'] == ['VA-001', 'VA-002']


def test_close_does_not_patch_finding_slugs_the_row_already_carries(monkeypatch):
    client = RecoveryClient({'id': 2, 'agent_id': 'HUNT-1', 'agent_role': 'code-vuln-hunter',
                             'handoff_status': 'ready', 'handoff_version': 2,
                             'summary': 'Acme done.', 'finding_slugs': ['VA-001']})
    client.row['finding_slugs'] = ['VA-001']
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))

    agent._close(SimpleNamespace(extra=['HUNT-1'], agent_id=None, completed_at=None,
                                 close_status=None, reason='ready handoff reviewed'))

    patch = next(body for kind, body in client.writes if kind == 'dispatch')
    assert 'finding_slugs' not in patch


@pytest.mark.parametrize('reason', ['', '   ', 'x' * 8193])
def test_failed_return_requires_explicit_bounded_reason_before_writing(monkeypatch, reason):
    client = RecoveryClient()
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(SystemExit):
        agent._close(args(reason))
    assert client.writes == []


def test_failed_return_does_not_replace_a_specialists_final_handoff(monkeypatch):
    client = RecoveryClient({'handoff_status': 'ready', 'handoff_version': 4, 'summary': 'Acme completed'})
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(SystemExit):
        agent._close(args())
    assert client.row['status'] == 'in-progress'
    assert client.writes == []


def test_failed_return_stops_before_close_when_recovery_handoff_write_fails(monkeypatch):
    client = RecoveryClient()
    def fail(_body):
        raise AssessError('Acme handoff write unavailable')
    client.record_handoff = fail
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(AssessError, match='handoff write unavailable'):
        agent._close(args())
    assert client.row['status'] == 'in-progress'
    assert client.writes == []


def test_failed_return_cannot_rewrite_a_previously_closed_dispatch(monkeypatch):
    client = RecoveryClient()
    client.row['status'] = 'completed'
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(SystemExit):
        agent._close(args())
    assert client.row['status'] == 'completed'
    assert client.writes == []


def test_failed_return_respects_arbitrary_existing_handoff_extras(monkeypatch):
    client = RecoveryClient({'handoff_status': 'blocked', 'closed_dispatch_status': 'failed',
                             'handoff_version': 2, 'extras': {'operator_recovery': 'Acme note'}})
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(SystemExit):
        agent._close(args())
    assert client.writes == []


def test_failed_return_retry_finishes_audit_after_decision_write_failure(monkeypatch):
    client = RecoveryClient()
    original = client.record_decision
    client.record_decision = lambda _body: (_ for _ in ()).throw(AssessError('Acme decision unavailable'))
    monkeypatch.setattr(agent.dispatch, '_client_for', lambda _: (client, None))
    with pytest.raises(AssessError, match='decision unavailable'):
        agent._close(args())
    completed_at = client.row['completed_at']
    client.record_decision = original
    agent._close(args())
    assert client.row['status'] == 'failed'
    assert client.row['completed_at'] == completed_at
    assert client.writes[-1][0] == 'decision'
    assert client.handoff['handoff_version'] == 1
