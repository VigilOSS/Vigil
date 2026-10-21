// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { approveProofWork, getProofWork, listProofWork, prepareProofWork, reconcileProofWork, releaseProofWork } from '../lib/api';
import type { ProofWork } from '../lib/api';
import { defaultProofRoute, nextFindingAction, nextWorkAction } from '../lib/proofWorkApi';
import { ProofWorkTab } from './ProofWorkTab';

vi.mock('../lib/api', () => ({ getProofWork: vi.fn(), listProofWork: vi.fn(), prepareProofWork: vi.fn(), approveProofWork: vi.fn(), reconcileProofWork: vi.fn(), releaseProofWork: vi.fn() }));

const work = { id: 9, finding_slug: 'VA-001', finding_title: 'Acme export hypothesis', finding_severity: 'high', route: 'web', objective: 'Challenge export access', target_hosts: ['app.example.com'], status: 'prepared', current: true, owed: true, approved: false, approval_required: true, approval_renewal_required: false, owner_agent_id: null, owner_dispatch_id: null, owner_dispatch_status: null, blocker: '', run_ids: [], runs: [], queue_state: 'needs_approval', next_test: null, created_at: '2026-10-10 10:00:00', updated_at: '' };
const owed = { finding_slug: 'VA-001', finding_id: 1, title: 'Acme export hypothesis', canonical_location: 'https://app.example.com/export', severity: 'high', parked_reason: 'Static review cannot show whether the export checks the tenant.', parked_at: '2026-10-09 17:03:48', source_bound: false, suggested_hosts: ['app.example.com', 'api.example.com'], work_ids: [9], queue_state: 'needs_approval', next_test: null };
const unprepared = { ...owed, finding_slug: 'VA-002', finding_id: 2, title: 'Acme import hypothesis', canonical_location: 'file:src/import.py:7', work_ids: [], queue_state: 'unprepared' };
const nextTest = { hypothesis: 'A viewer can export another tenant report', confirm_if: 'The export returns the other tenant rows', falsify_if: 'The export returns 403 for the other tenant while the own-tenant control succeeds', route_hint: 'live', prerequisites: 'Two viewer accounts on app.example.com' };

function queue(overrides: Record<string, unknown> = {}) {
  return { owed: [owed], items: [work], reverification_required: [], queue_state_counts: { needs_approval: 1 }, ...overrides } as never;
}

beforeEach(() => {
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, '', '#/engagements/acme?tab=proof');
  vi.mocked(listProofWork).mockResolvedValue(queue());
});
afterEach(() => { cleanup(); vi.resetAllMocks(); });

describe('proof work decisions', () => {
  it('defaults the route from the plan hint, then the finding location', () => {
    expect(defaultProofRoute({ next_test: { ...nextTest, route_hint: 'local' } as never, canonical_location: 'https://app.example.com' })).toBe('code');
    expect(defaultProofRoute({ next_test: nextTest as never, canonical_location: 'file:src/a.py:1' })).toBe('web');
    expect(defaultProofRoute({ next_test: { ...nextTest, route_hint: 'unknown' } as never, source_bound: true })).toBe('code');
    expect(defaultProofRoute({ canonical_location: 'file:src/a.py:1' })).toBe('code');
    expect(defaultProofRoute({ canonical_location: 'POST https://app.example.com/export' })).toBe('web');
  });

  it('maps each queue state to its single next action', () => {
    const item = (patch: Partial<ProofWork>) => ({ ...work, ...patch }) as ProofWork;
    expect(nextWorkAction(item({ queue_state: 'needs_approval' }))).toBe('approve');
    expect(nextWorkAction(item({ queue_state: 'ready', approval_required: false }))).toBe('none');
    expect(nextWorkAction(item({ queue_state: 'in_progress', approval_required: false }))).toBe('revoke');
    expect(nextWorkAction(item({ queue_state: 'in_progress', route: 'code', approval_required: false }))).toBe('none');
    expect(nextWorkAction(item({ queue_state: 'blocked', blocker_cause: 'approval' }))).toBe('approve');
    expect(nextWorkAction(item({ queue_state: 'blocked', route: 'code', approval_required: false, blocker_cause: 'operator' }))).toBe('reconcile');
    expect(nextWorkAction(item({ queue_state: 'blocked', owner_agent_id: 'PROOF-1', owner_dispatch_status: 'completed' }))).toBe('release');
    expect(nextWorkAction(item({ queue_state: 'stale' }))).toBe('reconcile');
    expect(nextWorkAction(item({ queue_state: 'done' }))).toBe('none');
    expect(nextFindingAction({ queue_state: 'unprepared' }, [])).toBe('prepare');
    expect(nextFindingAction({ queue_state: 'stale' }, [item({ queue_state: 'stale' })])).toBe('prepare');
    expect(nextFindingAction({ queue_state: 'needs_approval' }, [item({ queue_state: 'needs_approval' })])).toBe('approve');
  });
});

describe('ProofWorkTab', () => {
  it('explains the queue in plain language and remembers when the explainer is collapsed', async () => {
    const view = render(<ProofWorkTab engagementKey="acme" />);
    expect(screen.getByRole('heading', { name: 'Proof work' })).toBeTruthy();
    expect(screen.getByText(/Finishing a test does not confirm the finding; an independent verifier still decides/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /How proof work works/ }));
    expect(screen.queryByText(/Finishing a test does not confirm the finding/)).toBeNull();
    expect(window.localStorage.getItem('vigil.proofWork.explainerCollapsed')).toBe('1');
    view.unmount();
    render(<ProofWorkTab engagementKey="acme" />);
    expect(screen.queryByText(/Finishing a test does not confirm the finding/)).toBeNull();
  });

  it('shows one card per parked finding with why it is parked and a missing plan called out', async () => {
    render(<ProofWorkTab engagementKey="acme" />);
    const card = (await screen.findByRole('heading', { name: 'Acme export hypothesis' })).closest('section')!;
    expect(within(card).getByText('VA-001')).toBeTruthy();
    expect(within(card).getByTitle('Severity: High').textContent).toBe('High');
    expect(within(card).getByText('Static review cannot show whether the export checks the tenant.')).toBeTruthy();
    expect(within(card).getByText(/No plan recorded. Ask the verifier to record the next test/)).toBeTruthy();
    expect(within(card).getAllByText('Needs approval').length).toBeGreaterThan(0);
    expect(within(card).getByRole('link', { name: 'Acme export hypothesis' }).getAttribute('href')).toBe('#/engagements/acme?tab=findings&finding=VA-001');
  });

  it('prepares from the card with the route defaulted and in-scope host suggestions', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    vi.mocked(prepareProofWork).mockResolvedValue(work as never);
    render(<ProofWorkTab engagementKey="acme" />);
    const card = (await screen.findByRole('heading', { name: 'Acme import hypothesis' })).closest('section')!;
    fireEvent.click(within(card).getByRole('button', { name: 'Prepare a test…' }));
    // A file-located finding defaults to a local reproduction.
    expect((within(card).getByLabelText('Proof route') as HTMLSelectElement).value).toBe('code');
    fireEvent.change(within(card).getByLabelText('Proof route'), { target: { value: 'web' } });
    fireEvent.change(within(card).getByLabelText('Proof objective'), { target: { value: 'Try another account and a denied control' } });
    fireEvent.click(within(card).getByRole('button', { name: 'api.example.com' }));
    expect((within(card).getByLabelText('Admitted target hosts') as HTMLInputElement).value).toBe('api.example.com');
    fireEvent.click(within(card).getByRole('button', { name: 'Prepare proof' }));
    await waitFor(() => expect(prepareProofWork).toHaveBeenCalledWith('acme', { finding_slug: 'VA-002', route: 'web', objective: 'Try another account and a denied control', target_hosts: ['api.example.com'] }));
  });

  it('asks for an explicit confirmation naming hosts and objective before approving', async () => {
    vi.mocked(approveProofWork).mockResolvedValue({ ...work, approved: true } as never);
    render(<ProofWorkTab engagementKey="acme" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve live proof 9' }));
    expect(approveProofWork).not.toHaveBeenCalled();
    const confirm = screen.getByRole('group', { name: 'Confirm approval for proof 9' });
    expect(confirm.textContent).toContain('app.example.com');
    expect(confirm.textContent).toContain('Challenge export access');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Confirm approval' }));
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, true));
  });

  it('keeps stale work visible, prevents approval, and offers reconcile first', async () => {
    vi.mocked(reconcileProofWork).mockResolvedValue(work as never);
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, current: false, queue_state: 'stale' }], owed: [{ ...owed, queue_state: 'stale' }] }));
    render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByText('Stale context — prepare against current evidence')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Reconcile proof 9' }));
    await waitFor(() => expect(reconcileProofWork).toHaveBeenCalledWith('acme', 9));
    // Stale work means the finding needs a fresh preparation.
    expect(screen.getByRole('button', { name: 'Prepare a test…' })).toBeTruthy();
  });

  it('shows fetch failure and supports retry', async () => {
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('Backend unavailable'));
    render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    vi.mocked(listProofWork).mockResolvedValue(queue());
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
  });

  it('releases ended ownership with an explanation without relaunching a worker', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, status: 'blocked', queue_state: 'blocked', owner_agent_id: 'PROOF-1', owner_dispatch_id: 4, owner_dispatch_status: 'completed' }], owed: [{ ...owed, queue_state: 'blocked' }] }));
    vi.mocked(releaseProofWork).mockResolvedValue({ ...work, status: 'prepared' } as never);
    render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByText('PROOF-1 (completed)')).toBeTruthy();
    fireEvent.change(screen.getAllByLabelText('Recovery reason for proof 9')[0], { target: { value: 'Owner ended and no live work remains' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Release proof 9' })[0]);
    await waitFor(() => expect(releaseProofWork).toHaveBeenCalledWith('acme', 9, 'Owner ended and no live work remains'));
  });

  it('revokes in-progress live authority with a lossless reason', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, approval_required: false, status: 'claimed', owner_agent_id: 'PROOF-1', owner_dispatch_status: 'in-progress', queue_state: 'in_progress' }], owed: [{ ...owed, queue_state: 'in_progress' }] }));
    render(<ProofWorkTab engagementKey="acme" />);
    // Work a verifier is running waits on nobody: it is listed under All.
    fireEvent.click(within(await screen.findByRole('group', { name: 'Scope' })).getByRole('button', { name: /^All/ }));
    const button = (await screen.findAllByRole('button', { name: 'Revoke live proof 9' }))[0];
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getAllByLabelText('Revocation reason for proof 9')[0], { target: { value: ' Stop this proof.\n' } });
    fireEvent.click(button);
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, false, ' Stop this proof.\n'));
  });

  it('keeps a pending action scoped to its engagement when reused for another engagement', async () => {
    let finishApproval!: (value: never) => void;
    vi.mocked(approveProofWork).mockReturnValue(new Promise<never>((resolve) => { finishApproval = resolve; }));
    vi.mocked(listProofWork).mockImplementation(async (key) => queue({ owed: [{ ...owed, title: key === 'acme' ? 'Acme export hypothesis' : 'Beta export hypothesis' }] }));
    const view = render(<ProofWorkTab engagementKey="acme" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve live proof 9' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));
    view.rerender(<ProofWorkTab engagementKey="beta" />);
    await screen.findByRole('heading', { name: 'Beta export hypothesis' });
    finishApproval({ ...work, approved: true } as never);
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('group', { name: 'Confirm approval for proof 9' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Beta export hypothesis' })).toBeTruthy();
  });

  it('summarizes queue states as filters with counts', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme import hypothesis' });
    const states = screen.getByRole('group', { name: 'State' });
    fireEvent.click(within(states).getByRole('button', { name: /Unprepared\s*1/ }));
    expect(screen.queryByRole('heading', { name: 'Acme export hypothesis' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Acme import hypothesis' })).toBeTruthy();
    fireEvent.click(within(states).getByRole('button', { name: /Unprepared\s*1/ }));
    expect(screen.getByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
  });

  it('opens on the shared Needs attention scope, counted by the rail rule', async () => {
    const ready = { ...owed, finding_slug: 'VA-003', finding_id: 3, title: 'Acme ready hypothesis', work_ids: [10], queue_state: 'ready' };
    const reverify = { finding_id: 4, finding_slug: 'VA-004', title: 'Acme changed claim', severity: 'low', invalidating_transition_id: 7, next_action: 'Re-verify', work_ids: [] };
    vi.mocked(listProofWork).mockResolvedValue(queue({
      owed: [owed, unprepared, ready],
      items: [work, { ...work, id: 10, finding_slug: 'VA-003', queue_state: 'ready', approval_required: false }],
      reverification_required: [reverify],
      queue_state_counts: { needs_approval: 1, unprepared: 1, ready: 1 },
    }));
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme import hypothesis' });
    const scope = screen.getByRole('group', { name: 'Scope' });
    expect(within(scope).getByRole('button', { name: /^Needs attention\s*3/ }).getAttribute('aria-pressed')).toBe('true');
    expect(within(scope).getByRole('button', { name: /^All\s*4/ })).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Acme ready hypothesis' })).toBeNull();
    expect(screen.getByRole('list', { name: 'Summary' }).textContent).toContain('3 need attention');
    fireEvent.click(within(scope).getByRole('button', { name: /^All/ }));
    expect(screen.getByRole('heading', { name: 'Acme ready hypothesis' })).toBeTruthy();
  });

  it('opens on All when nothing needs attention, and on Needs attention again next visit', async () => {
    const ready = { ...owed, queue_state: 'ready' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [ready], items: [{ ...work, queue_state: 'ready', approval_required: false }], queue_state_counts: { ready: 1 } }));
    const first = render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
    expect(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^All/ }).getAttribute('aria-pressed')).toBe('true');
    first.unmount();
    vi.mocked(listProofWork).mockResolvedValue(queue());
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    expect(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^Needs attention/ }).getAttribute('aria-pressed')).toBe('true');
  });

  it('names the scope, not filters, when only the scope hides everything', async () => {
    const ready = { ...owed, queue_state: 'ready' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [ready], items: [{ ...work, queue_state: 'ready', approval_required: false }], queue_state_counts: { ready: 1 } }));
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    fireEvent.click(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^Needs attention/ }));
    expect(await screen.findByText('Nothing in the proof queue needs your attention.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Show all proof work' }));
    expect(await screen.findByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
  });

  it('reports the same needs-attention count to the rail as the page shows, one per finding', async () => {
    const onQueueCounts = vi.fn();
    vi.mocked(listProofWork).mockResolvedValue(queue({
      owed: [{ ...owed, work_ids: [9, 12] }],
      items: [work, { ...work, id: 12 }],
      queue_state_counts: { needs_approval: 2 },
    }));
    render(<ProofWorkTab engagementKey="acme" onQueueCounts={onQueueCounts} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    expect(screen.getByRole('list', { name: 'Summary' }).textContent).toContain('1 need attention');
    await waitFor(() => expect(onQueueCounts).toHaveBeenLastCalledWith(expect.objectContaining({ needs_attention: 1 })));
  });

  it('orders cards by what they need first, then severity, and says so', async () => {
    const low = { ...unprepared, finding_slug: 'VA-005', finding_id: 5, title: 'Acme low hypothesis', severity: 'low' };
    const critical = { ...unprepared, finding_slug: 'VA-006', finding_id: 6, title: 'Acme critical hypothesis', severity: 'critical' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [low, critical, owed], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 2 } }));
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme low hypothesis' });
    const titles = screen.getAllByRole('heading', { level: 3 }).map((heading) => heading.textContent);
    expect(titles).toEqual(['Acme export hypothesis', 'Acme critical hypothesis', 'Acme low hypothesis']);
    expect(screen.getByText(/Sorted by Status, most urgent first, then severity/)).toBeTruthy();
  });

  it('filters re-verification with a real chip instead of a link styled as one', async () => {
    const reverify = { finding_id: 4, finding_slug: 'VA-004', title: 'Acme changed claim', severity: 'low', invalidating_transition_id: 7, next_action: 'Re-verify', work_ids: [] };
    vi.mocked(listProofWork).mockResolvedValue(queue({ reverification_required: [reverify] }));
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    const chip = within(screen.getByRole('group', { name: 'State' })).getByRole('button', { name: /Needs re-verification\s*1/ });
    expect(chip.getAttribute('aria-pressed')).toBe('false');
    fireEvent.click(chip);
    expect(chip.getAttribute('aria-pressed')).toBe('true');
    expect(screen.queryByRole('heading', { name: 'Acme export hypothesis' })).toBeNull();
    expect(screen.getByRole('heading', { name: 'Needs re-verification' })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Search proof work'), { target: { value: 'zzz' } });
    expect(await screen.findByText('No proof work matches these filters.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
  });

  it('keeps scope, state and search when the tab is left and reopened', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    const first = render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme import hypothesis' });
    fireEvent.change(screen.getByLabelText('Search proof work'), { target: { value: 'import' } });
    first.unmount();
    render(<ProofWorkTab engagementKey="acme" />);
    await screen.findByRole('heading', { name: 'Acme import hypothesis' });
    expect((screen.getByLabelText('Search proof work') as HTMLInputElement).value).toBe('import');
    expect(screen.queryByRole('heading', { name: 'Acme export hypothesis' })).toBeNull();
  });

  it('says plainly when nothing is parked, without empty filter chips', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], items: [], queue_state_counts: {} }));
    render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByText('No findings await runtime proof.')).toBeTruthy();
    expect(screen.getByText(/Verifiers park a finding here when it looks real/)).toBeTruthy();
    expect(screen.queryByRole('group', { name: 'State' })).toBeNull();
  });

  it('shows a work item a link names even when the scope would hide it', async () => {
    const ready = { ...owed, finding_slug: 'VA-003', finding_id: 3, title: 'Acme ready hypothesis', work_ids: [10], queue_state: 'ready' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, ready], items: [work, { ...work, id: 10, finding_slug: 'VA-003', queue_state: 'ready', approval_required: false }], queue_state_counts: { needs_approval: 1, ready: 1 } }));
    render(<ProofWorkTab engagementKey="acme" workId={10} />);
    expect(await screen.findByRole('heading', { name: 'Acme ready hypothesis' })).toBeTruthy();
    expect(document.getElementById('proof-work-10')?.className).toContain('is-highlighted');
  });

  it('says why no approval is needed instead of claiming one was given', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({
      items: [{ ...work, approval_required: false, approved: false, approval_decision: null, queue_state: 'ready' }],
      owed: [{ ...owed, queue_state: 'ready' }],
      queue_state_counts: { ready: 1 },
    }));
    render(<ProofWorkTab engagementKey="acme" workId={9} />);
    expect(await screen.findByText(/No separate approval needed: the engagement's exploit policy authorizes live proof/)).toBeTruthy();
    expect(screen.queryByText('Approved for this work')).toBeNull();
    cleanup();
    vi.mocked(listProofWork).mockResolvedValue(queue({
      items: [{ ...work, approval_required: false, approved: true, approval_decision: 'approved', queue_state: 'ready' }],
      owed: [{ ...owed, queue_state: 'ready' }],
      queue_state_counts: { ready: 1 },
    }));
    render(<ProofWorkTab engagementKey="acme" workId={9} />);
    expect(await screen.findByText('Approved by the operator for this work')).toBeTruthy();
  });

  it('lets a suggested host be removed again and keeps the route hint honest', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    render(<ProofWorkTab engagementKey="acme" />);
    const card = (await screen.findByRole('heading', { name: 'Acme import hypothesis' })).closest('section')!;
    fireEvent.click(within(card).getByRole('button', { name: 'Prepare a test…' }));
    expect(within(card).getByText(/Defaulted from the finding's source location/)).toBeTruthy();
    fireEvent.change(within(card).getByLabelText('Proof route'), { target: { value: 'web' } });
    expect(within(card).queryByText(/Defaulted from/)).toBeNull();
    expect(within(card).getByText(/You chose this route/)).toBeTruthy();
    const host = within(card).getByRole('button', { name: 'api.example.com' });
    fireEvent.click(host);
    expect(host.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(host);
    expect(host.getAttribute('aria-pressed')).toBe('false');
    expect((within(card).getByLabelText('Admitted target hosts') as HTMLInputElement).value).toBe('');
  });

  it('reads audit history without refreshing the queue and says when there is none', async () => {
    vi.mocked(getProofWork).mockResolvedValue({ ...work, events: [] } as never);
    render(<ProofWorkTab engagementKey="acme" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show audit history for proof 9' }));
    expect(await screen.findByText('No audit events recorded for this proof work yet.')).toBeTruthy();
    expect(listProofWork).toHaveBeenCalledTimes(1);
  });

  it('blocks reconcile, like every write, while the queue state is unknown', async () => {
    const view = render(<ProofWorkTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('queue offline'));
    view.rerender(<ProofWorkTab engagementKey="acme" refreshVersion={1} />);
    await screen.findByText(/queue offline/);
    for (const button of screen.getAllByRole('button', { name: 'Reconcile proof 9' })) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it('keeps actions available after a failed write once the queue re-reads', async () => {
    vi.mocked(approveProofWork).mockRejectedValueOnce(new Error('Approval conflicts with a newer preparation'));
    render(<ProofWorkTab engagementKey="acme" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve live proof 9' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));
    // The error sits on the card whose action failed, beside its actions.
    const card = screen.getByRole('heading', { name: 'Acme export hypothesis' }).closest('section')!;
    const alert = await within(card).findByRole('alert');
    expect(alert.textContent).toContain('Approval conflicts with a newer preparation');
    expect(alert.textContent).toContain('The queue was re-read');
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    await waitFor(() => expect((screen.getByRole('button', { name: 'Confirm approval' }) as HTMLButtonElement).disabled).toBe(false));
  });

  it('offers Reload queue after a failed read and re-enables actions once it loads', async () => {
    const view = render(<ProofWorkTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('queue offline'));
    view.rerender(<ProofWorkTab engagementKey="acme" refreshVersion={1} />);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('queue offline');
    expect((screen.getByRole('button', { name: 'Approve live proof 9' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(alert).getByRole('button', { name: 'Reload queue' }));
    await waitFor(() => expect((screen.getByRole('button', { name: 'Approve live proof 9' }) as HTMLButtonElement).disabled).toBe(false));
    expect(listProofWork).toHaveBeenCalledTimes(3);
  });

  it('renders the next test as plain text', async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [{ ...owed, next_test: { ...nextTest, hypothesis: hostile } }] }));
    const view = render(<ProofWorkTab engagementKey="acme" />);
    expect(await screen.findByText(hostile)).toBeTruthy();
    expect(view.container.querySelector('img')).toBeNull();
    expect(screen.getByText('Live target')).toBeTruthy();
    expect(screen.getByText('The export returns the other tenant rows')).toBeTruthy();
    expect(screen.getByText('Two viewer accounts on app.example.com')).toBeTruthy();
  });

  it('loads approval history on request and renders raw text safely', async () => {
    const confirmation = '<img src=x onerror=alert(1)> approved\n  Acme';
    vi.mocked(getProofWork).mockResolvedValue({ ...work, events: [{ id: 1, action: 'approval', created_at: '', details_json: JSON.stringify({ actor: 'operator', human_confirmation: confirmation }) }] } as never);
    const view = render(<ProofWorkTab engagementKey="acme" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show audit history for proof 9' }));
    await waitFor(() => expect(getProofWork).toHaveBeenCalledWith('acme', 9));
    expect(await screen.findByText((_, element) => element?.tagName === 'PRE' && !!element.textContent?.includes(confirmation.replace('\n', '\\n')))).toBeTruthy();
    expect(view.container.querySelector('img')).toBeNull();
  });

  it('lists findings that need re-verification by title in their own section', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], items: [], reverification_required: [{ finding_id: 1, finding_slug: 'VA-001', title: 'Acme export hypothesis', severity: 'low', invalidating_transition_id: 7, next_action: 'Independently re-verify the changed claim', work_ids: [9] }], queue_state_counts: {} }));
    render(<ProofWorkTab engagementKey="acme" />);
    const section = (await screen.findByRole('heading', { name: 'Needs re-verification' })).closest('section')!;
    expect(within(section).getByRole('link', { name: 'Acme export hypothesis' })).toBeTruthy();
    expect(within(section).getByText('Independently re-verify the changed claim')).toBeTruthy();
  });

  it('links each evidence run to the Runs drawer', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, run_ids: [41], runs: [{ id: 41, run_uuid: 'acme-proof-run', run_kind: 'web', status: 'completed', started_at: '2026-10-10 10:00:00', finished_at: null, proof_receipts: 2 }] }] }));
    render(<ProofWorkTab engagementKey="acme" />);
    const link = await screen.findByRole('link', { name: 'Run 41' });
    expect(link.getAttribute('href')).toBe('#/engagements/acme?tab=runs&run=41');
    expect(link.textContent).toBe('acme-proof-run');
    expect(screen.getByText('2 receipts')).toBeTruthy();
  });

  it('highlights the prepared test a link names', async () => {
    const view = render(<ProofWorkTab engagementKey="acme" workId={9} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    expect(document.getElementById('proof-work-9')?.className).toContain('is-highlighted');
    view.rerender(<ProofWorkTab engagementKey="acme" />);
    expect(document.getElementById('proof-work-9')?.className).not.toContain('is-highlighted');
  });

  it('scrolls to a linked item once, not again on every refresh', async () => {
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    const view = render(<ProofWorkTab engagementKey="acme" workId={9} refreshVersion={0} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    await waitFor(() => expect(scroll).toHaveBeenCalledTimes(1));
    vi.mocked(listProofWork).mockResolvedValueOnce(queue());
    view.rerender(<ProofWorkTab engagementKey="acme" workId={9} refreshVersion={1} />);
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(scroll).toHaveBeenCalledTimes(1);
  });

  it('coalesces refresh bursts and keeps the queue visible meanwhile', async () => {
    const view = render(<ProofWorkTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByRole('heading', { name: 'Acme export hypothesis' });
    let finish!: (value: never) => void;
    vi.mocked(listProofWork).mockReturnValueOnce(new Promise<never>((resolve) => { finish = resolve; }));
    view.rerender(<ProofWorkTab engagementKey="acme" refreshVersion={1} />);
    view.rerender(<ProofWorkTab engagementKey="acme" refreshVersion={2} />);
    expect(listProofWork).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('heading', { name: 'Acme export hypothesis' })).toBeTruthy();
    finish(queue());
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(3));
  });
});
