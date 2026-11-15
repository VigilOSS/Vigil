// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../contexts/ToastContext';
import { approveProofWork, getProofWork, listProofWork, prepareProofWork, reconcileProofWork, releaseProofWork } from '../lib/api';
import type { ProofWork } from '../lib/api';
import { defaultProofRoute, nextFindingAction, nextWorkAction } from '../lib/proofWorkApi';
import { ProofWorkCard } from './ProofWorkCard';
import { ProofWorkTab } from './ProofWorkTab';

vi.mock('../lib/api', () => ({ getProofWork: vi.fn(), listProofWork: vi.fn(), prepareProofWork: vi.fn(), approveProofWork: vi.fn(), reconcileProofWork: vi.fn(), releaseProofWork: vi.fn() }));

const work = { id: 9, finding_slug: 'VA-001', finding_title: 'Acme export hypothesis', finding_severity: 'high', route: 'web', objective: 'Challenge export access', target_hosts: ['app.example.com'], status: 'prepared', current: true, owed: true, approved: false, approval_required: true, approval_renewal_required: false, owner_agent_id: null, owner_dispatch_id: null, owner_dispatch_status: null, blocker: '', run_ids: [], runs: [], queue_state: 'needs_approval', next_test: null, created_at: '2026-10-10 10:00:00', updated_at: '' };
const owed = { finding_slug: 'VA-001', finding_id: 1, title: 'Acme export hypothesis', canonical_location: 'https://app.example.com/export', severity: 'high', parked_reason: 'Static review cannot show whether the export checks the tenant.', parked_at: '2026-10-09 17:03:48', source_bound: false, suggested_hosts: ['app.example.com', 'api.example.com'], work_ids: [9], queue_state: 'needs_approval', next_test: null };
const unprepared = { ...owed, finding_slug: 'VA-002', finding_id: 2, title: 'Acme import hypothesis', canonical_location: 'file:src/import.py:7', work_ids: [], queue_state: 'unprepared' };
const nextTest = { hypothesis: 'A viewer can export another tenant report', confirm_if: 'The export returns the other tenant rows', falsify_if: 'The export returns 403 for the other tenant while the own-tenant control succeeds', route_hint: 'live', prerequisites: 'Two viewer accounts on app.example.com' };
// A second and third finding waiting on approval, for stepping between records.
const owedB = { ...owed, finding_slug: 'VA-003', finding_id: 3, title: 'Acme billing hypothesis', work_ids: [12] };
const workB = { ...work, id: 12, finding_slug: 'VA-003', finding_title: 'Acme billing hypothesis', objective: 'Challenge billing access', target_hosts: ['api.example.com'] };
const owedC = { ...owed, finding_slug: 'VA-005', finding_id: 5, title: 'Acme audit hypothesis', work_ids: [13] };
const workC = { ...work, id: 13, finding_slug: 'VA-005', finding_title: 'Acme audit hypothesis', objective: 'Challenge audit access' };

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

type TabProps = Parameters<typeof ProofWorkTab>[0];
const tab = (props: Partial<TabProps> = {}) => (
  <ToastProvider><ProofWorkTab engagementKey="acme" {...props} /></ToastProvider>
);
/** A finding's row in the results, by slug (null while the list does not hold it). */
const rowOf = (slug: string) => document.querySelector<HTMLElement>(`[data-record-key="${slug}"]`);
const findRow = async (slug: string) => {
  await waitFor(() => expect(rowOf(slug)).toBeTruthy());
  return rowOf(slug)!;
};
/** The slugs of the rows the results show, in order. */
const shownRows = () => [...document.querySelectorAll<HTMLElement>('[data-record-key]')].map((row) => row.getAttribute('data-record-key'));
const record = () => screen.findByRole('region', { name: 'Proof work' });
const noRecord = () => waitFor(() => expect(screen.queryByRole('region', { name: 'Proof work' })).toBeNull());
const openRecord = async (slug: string) => {
  fireEvent.click(await findRow(slug));
  return record();
};
const recordTitle = (view: HTMLElement, name: string) => within(view).findByRole('heading', { level: 2, name });

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

describe('ProofWorkTab results', () => {
  it('explains the queue in plain language and remembers when the explainer is collapsed', async () => {
    const view = render(tab());
    expect(screen.getByRole('heading', { name: 'Proof work' })).toBeTruthy();
    expect(screen.getByText(/Finishing a test does not confirm the finding; an independent verifier still decides/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /How proof work works/ }));
    expect(screen.queryByText(/Finishing a test does not confirm the finding/)).toBeNull();
    expect(window.localStorage.getItem('vigil.proofWork.explainerCollapsed')).toBe('1');
    view.unmount();
    render(tab());
    expect(screen.queryByText(/Finishing a test does not confirm the finding/)).toBeNull();
  });

  it('lists one row per parked finding with its state and the first line of the reason, and opens none on the bare tab link', async () => {
    const reason = 'Static review cannot show whether the export checks the tenant.\nThe handler reads the tenant from the session, but the query is built elsewhere.';
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [{ ...owed, parked_reason: reason }, { ...unprepared, parked_reason: '' }], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    render(tab());
    const row = await findRow('VA-001');
    expect(row.tagName).toBe('BUTTON');
    expect(within(row).getByText('VA-001')).toBeTruthy();
    expect(within(row).getByTitle('Severity: High').textContent).toBe('High');
    expect(within(row).getByText('Acme export hypothesis')).toBeTruthy();
    expect(within(row).getByText('Needs approval')).toBeTruthy();
    // The row carries the reason's first line only; the record holds all of it.
    expect(row.textContent).toContain('Static review cannot show whether the export checks the tenant.');
    expect(row.textContent).not.toContain('The handler reads the tenant from the session');
    expect(rowOf('VA-002')!.textContent).toContain('The parking decision recorded no reason.');
    expect(screen.queryByRole('region', { name: 'Proof work' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Approve live proof 9' })).toBeNull();

    const view = await openRecord('VA-001');
    expect(within(view).getByText(reason, { normalizer: (text) => text })).toBeTruthy();
  });

  it('shows fetch failure and supports retry', async () => {
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('Backend unavailable'));
    render(tab());
    expect(await screen.findByRole('alert')).toBeTruthy();
    vi.mocked(listProofWork).mockResolvedValue(queue());
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await findRow('VA-001')).toBeTruthy();
  });

  it('summarizes queue states as filters with counts', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    render(tab());
    await findRow('VA-002');
    const states = screen.getByRole('group', { name: 'State' });
    fireEvent.click(within(states).getByRole('button', { name: /Unprepared\s*1/ }));
    expect(shownRows()).toEqual(['VA-002']);
    fireEvent.click(within(states).getByRole('button', { name: /Unprepared\s*1/ }));
    expect(shownRows()).toEqual(['VA-001', 'VA-002']);
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
    render(tab());
    await findRow('VA-002');
    const scope = screen.getByRole('group', { name: 'Scope' });
    expect(within(scope).getByRole('button', { name: /^Needs attention\s*3/ }).getAttribute('aria-pressed')).toBe('true');
    expect(within(scope).getByRole('button', { name: /^All\s*4/ })).toBeTruthy();
    expect(rowOf('VA-003')).toBeNull();
    expect(screen.getByRole('list', { name: 'Summary' }).textContent).toContain('3 need attention');
    fireEvent.click(within(scope).getByRole('button', { name: /^All/ }));
    expect(rowOf('VA-003')).toBeTruthy();
  });

  it('opens on All when nothing needs attention, and on Needs attention again next visit', async () => {
    const ready = { ...owed, queue_state: 'ready' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [ready], items: [{ ...work, queue_state: 'ready', approval_required: false }], queue_state_counts: { ready: 1 } }));
    const first = render(tab());
    expect(await findRow('VA-001')).toBeTruthy();
    expect(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^All/ }).getAttribute('aria-pressed')).toBe('true');
    first.unmount();
    vi.mocked(listProofWork).mockResolvedValue(queue());
    render(tab());
    await findRow('VA-001');
    expect(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^Needs attention/ }).getAttribute('aria-pressed')).toBe('true');
  });

  it('names the scope, not filters, when only the scope hides everything', async () => {
    const ready = { ...owed, queue_state: 'ready' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [ready], items: [{ ...work, queue_state: 'ready', approval_required: false }], queue_state_counts: { ready: 1 } }));
    render(tab());
    await findRow('VA-001');
    fireEvent.click(within(screen.getByRole('group', { name: 'Scope' })).getByRole('button', { name: /^Needs attention/ }));
    expect(await screen.findByText('Nothing in the proof queue needs your attention.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Show all proof work' }));
    expect(await findRow('VA-001')).toBeTruthy();
  });

  it('reports the same needs-attention count to the rail as the page shows, one per finding', async () => {
    const onQueueCounts = vi.fn();
    vi.mocked(listProofWork).mockResolvedValue(queue({
      owed: [{ ...owed, work_ids: [9, 12] }],
      items: [work, { ...work, id: 12 }],
      queue_state_counts: { needs_approval: 2 },
    }));
    render(tab({ onQueueCounts }));
    await findRow('VA-001');
    expect(screen.getByRole('list', { name: 'Summary' }).textContent).toContain('1 need attention');
    await waitFor(() => expect(onQueueCounts).toHaveBeenLastCalledWith(expect.objectContaining({ needs_attention: 1 })));
  });

  it('orders rows by what they need first, then severity, and says so', async () => {
    const low = { ...unprepared, finding_slug: 'VA-005', finding_id: 5, title: 'Acme low hypothesis', severity: 'low' };
    const critical = { ...unprepared, finding_slug: 'VA-006', finding_id: 6, title: 'Acme critical hypothesis', severity: 'critical' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [low, critical, owed], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 2 } }));
    render(tab());
    await findRow('VA-005');
    expect(shownRows()).toEqual(['VA-001', 'VA-006', 'VA-005']);
    expect(screen.getByText(/Sorted by Status, most urgent first, then severity/)).toBeTruthy();
  });

  it('filters re-verification with a real chip instead of a link styled as one', async () => {
    const reverify = { finding_id: 4, finding_slug: 'VA-004', title: 'Acme changed claim', severity: 'low', invalidating_transition_id: 7, next_action: 'Re-verify', work_ids: [] };
    vi.mocked(listProofWork).mockResolvedValue(queue({ reverification_required: [reverify] }));
    render(tab());
    await findRow('VA-001');
    const chip = within(screen.getByRole('group', { name: 'State' })).getByRole('button', { name: /Needs re-verification\s*1/ });
    expect(chip.getAttribute('aria-pressed')).toBe('false');
    fireEvent.click(chip);
    expect(chip.getAttribute('aria-pressed')).toBe('true');
    expect(rowOf('VA-001')).toBeNull();
    expect(screen.getByRole('heading', { name: 'Needs re-verification' })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Search proof work'), { target: { value: 'zzz' } });
    expect(await screen.findByText('No proof work matches these filters.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await findRow('VA-001')).toBeTruthy();
  });

  it('keeps scope, state and search when the tab is left and reopened', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    const first = render(tab());
    await findRow('VA-002');
    fireEvent.change(screen.getByLabelText('Search proof work'), { target: { value: 'import' } });
    first.unmount();
    render(tab());
    await findRow('VA-002');
    expect((screen.getByLabelText('Search proof work') as HTMLInputElement).value).toBe('import');
    expect(shownRows()).toEqual(['VA-002']);
  });

  it('says plainly when nothing is parked, without empty filter chips', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], items: [], queue_state_counts: {} }));
    render(tab());
    expect(await screen.findByText('No findings await runtime proof.')).toBeTruthy();
    expect(screen.getByText(/Verifiers park a finding here when it looks real/)).toBeTruthy();
    expect(screen.queryByRole('group', { name: 'State' })).toBeNull();
  });

  it('counts the findings no longer parked in the All scope that lists them, with no empty State group', async () => {
    // Earlier proof work whose finding is no longer parked: nothing owed, one item kept as history.
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], queue_state_counts: {} }));
    render(tab());
    expect(await screen.findByText(/Findings no longer parked/)).toBeTruthy();
    // The scope that lists that finding counts it.
    expect(screen.getByRole('button', { name: /^All/ }).textContent).toContain('1');
    // No state to filter by: the group is not shown as a bare label.
    expect(screen.queryByRole('group', { name: 'State' })).toBeNull();
    // Its kept proof work opens as a record like a parked finding's.
    const view = await openRecord('VA-001');
    expect(await recordTitle(view, 'Acme export hypothesis')).toBeTruthy();
    expect(within(view).getByText('Proof #9')).toBeTruthy();
    expect(within(view).queryByText('Why it is parked')).toBeNull();
  });

  it('lists findings that need re-verification by title in their own section, as links to Findings', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], items: [], reverification_required: [{ finding_id: 1, finding_slug: 'VA-001', title: 'Acme export hypothesis', severity: 'low', invalidating_transition_id: 7, next_action: 'Independently re-verify the changed claim', work_ids: [9] }], queue_state_counts: {} }));
    render(tab());
    const section = (await screen.findByRole('heading', { name: 'Needs re-verification' })).closest('section')!;
    expect(within(section).getByRole('link', { name: 'Acme export hypothesis' }).getAttribute('href')).toBe('#/engagements/acme?tab=findings&finding=VA-001');
    expect(within(section).getByText('Independently re-verify the changed claim')).toBeTruthy();
    expect(shownRows()).toEqual([]);
  });

  it('coalesces refresh bursts and keeps the queue visible meanwhile', async () => {
    const view = render(tab({ refreshVersion: 0 }));
    await findRow('VA-001');
    let finish!: (value: never) => void;
    vi.mocked(listProofWork).mockReturnValueOnce(new Promise<never>((resolve) => { finish = resolve; }));
    view.rerender(tab({ refreshVersion: 1 }));
    view.rerender(tab({ refreshVersion: 2 }));
    expect(listProofWork).toHaveBeenCalledTimes(2);
    expect(rowOf('VA-001')).toBeTruthy();
    finish(queue());
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(3));
  });
});

describe('ProofWorkTab record', () => {
  it('opens a finding from its row in the record view, and Back returns to the list with focus on that row', async () => {
    render(tab());
    const before = window.history.length;
    const view = await openRecord('VA-001');
    expect(await recordTitle(view, 'Acme export hypothesis')).toBeTruthy();
    expect(within(view).getByText('1 of 1 results')).toBeTruthy();
    expect(within(view).getByTitle('Severity: High').textContent).toBe('High');
    expect(within(view).getAllByText('Needs approval').length).toBeGreaterThan(0);
    expect(within(view).getByRole('group', { name: 'Proof work dates' }).textContent).toContain('Parked');
    expect(within(view).getByRole('button', { name: 'Copy finding ID' })).toBeTruthy();
    expect(within(view).getByRole('button', { name: 'Copy link to this finding' })).toBeTruthy();
    expect(within(view).getByText('Static review cannot show whether the export checks the tenant.')).toBeTruthy();
    expect(within(view).getByText(/No plan recorded. Ask the verifier to record the next test/)).toBeTruthy();
    expect(within(view).getByRole('link', { name: 'Review finding' }).getAttribute('href')).toBe('#/engagements/acme?tab=findings&finding=VA-001');
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof&proof=VA-001');
    expect(window.history.length).toBe(before + 1);
    // The list stays mounted behind the record, out of the accessibility tree.
    expect(rowOf('VA-001')).toBeTruthy();
    expect(screen.queryByRole('heading', { level: 1, name: 'Proof work' })).toBeNull();

    fireEvent.click(within(view).getByRole('button', { name: 'Back to results' }));
    await noRecord();
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof');
    await waitFor(() => expect(document.activeElement).toBe(rowOf('VA-001')));
  });

  it('steps with [ and ] in the order the list shows, and Escape returns to the row last shown', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owedC, unprepared, owed], items: [work, workC], queue_state_counts: { needs_approval: 2, unprepared: 1 } }));
    render(tab());
    const view = await openRecord('VA-001');
    expect(within(view).getByText('1 of 3 results')).toBeTruthy();
    expect((within(view).getByRole('button', { name: 'Previous finding' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(window, { key: ']' });
    await recordTitle(view, 'Acme audit hypothesis');
    expect(within(view).getByText('2 of 3 results')).toBeTruthy();
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof&proof=VA-005');
    fireEvent.click(within(view).getByRole('button', { name: 'Next finding' }));
    await recordTitle(view, 'Acme import hypothesis');
    expect((within(view).getByRole('button', { name: 'Next finding' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme audit hypothesis');

    fireEvent.keyDown(window, { key: 'Escape' });
    await noRecord();
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof');
    await waitFor(() => expect(document.activeElement).toBe(rowOf('VA-005')));
  });

  it('follows the address: a link opens its record, Back shows the list, Forward reopens it', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, owedB], items: [work, workB], queue_state_counts: { needs_approval: 2 } }));
    const view = render(tab({ initialProofSlug: 'VA-003' }));
    await recordTitle(await record(), 'Acme billing hypothesis');
    expect(within(await record()).getByText('2 of 2 results')).toBeTruthy();
    view.rerender(tab());
    await noRecord();
    expect(rowOf('VA-003')).toBeTruthy();
    view.rerender(tab({ initialProofSlug: 'VA-001' }));
    await recordTitle(await record(), 'Acme export hypothesis');
    view.rerender(tab({ initialProofSlug: 'VA-003' }));
    await recordTitle(await record(), 'Acme billing hypothesis');
  });

  it('shows the list and says so when the address names a finding with no proof work', async () => {
    window.history.replaceState(null, '', '#/engagements/acme?tab=proof&proof=VA-404');
    const before = window.history.length;
    render(tab({ initialProofSlug: 'VA-404' }));
    expect(await screen.findByText(/VA-404 has no proof work/)).toBeTruthy();
    await noRecord();
    expect(rowOf('VA-001')).toBeTruthy();
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof');
    expect(window.history.length).toBe(before);
  });

  it('reports a failed first read inside a deep-linked record and loads it from Try again', async () => {
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('Backend unavailable'));
    render(tab({ initialProofSlug: 'VA-001' }));
    const view = await record();
    expect((await within(view).findByRole('alert')).textContent).toContain('Backend unavailable');
    expect(within(view).getByText('Position in results unavailable')).toBeTruthy();
    fireEvent.click(within(view).getByRole('button', { name: 'Try again' }));
    expect(await recordTitle(view, 'Acme export hypothesis')).toBeTruthy();
  });

  it('keeps a record open when its finding leaves the results, and still steps to its former neighbours', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, owedB, owedC], items: [work, workB, workC], queue_state_counts: { needs_approval: 3 } }));
    vi.mocked(approveProofWork).mockResolvedValue({ ...workB, approved: true } as never);
    render(tab());
    const view = await openRecord('VA-003');
    expect(within(view).getByText('2 of 3 results')).toBeTruthy();
    // Approving takes the finding out of Needs attention.
    vi.mocked(listProofWork).mockResolvedValue(queue({
      owed: [owed, { ...owedB, queue_state: 'ready' }, owedC],
      items: [work, { ...workB, queue_state: 'ready', approval_required: false, approved: true, approval_decision: 'approved' }, workC],
      queue_state_counts: { needs_approval: 2, ready: 1 },
    }));
    fireEvent.click(within(view).getByRole('button', { name: 'Approve live proof 12' }));
    fireEvent.click(within(view).getByRole('button', { name: 'Confirm approval' }));
    expect(await within(view).findByText('Outside current results')).toBeTruthy();
    expect(await recordTitle(view, 'Acme billing hypothesis')).toBeTruthy();
    expect(within(view).getByText('Approved by the operator for this work')).toBeTruthy();
    expect((within(view).getByRole('button', { name: 'Previous finding' }) as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(within(view).getByRole('button', { name: 'Next finding' }));
    await recordTitle(view, 'Acme audit hypothesis');
    expect(within(view).getByText('2 of 2 results')).toBeTruthy();
    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme export hypothesis');
  });

  it('prepares from the record with the route defaulted and in-scope host suggestions', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    vi.mocked(prepareProofWork).mockResolvedValue(work as never);
    render(tab());
    const view = await openRecord('VA-002');
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare a test…' }));
    // A file-located finding defaults to a local reproduction.
    expect((within(view).getByLabelText('Proof route') as HTMLSelectElement).value).toBe('code');
    fireEvent.change(within(view).getByLabelText('Proof route'), { target: { value: 'web' } });
    fireEvent.change(within(view).getByLabelText('Proof objective'), { target: { value: 'Try another account and a denied control' } });
    fireEvent.click(within(view).getByRole('button', { name: 'api.example.com' }));
    expect((within(view).getByLabelText('Admitted target hosts') as HTMLInputElement).value).toBe('api.example.com');
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare proof' }));
    await waitFor(() => expect(prepareProofWork).toHaveBeenCalledWith('acme', { finding_slug: 'VA-002', route: 'web', objective: 'Try another account and a denied control', target_hosts: ['api.example.com'] }));
    // A prepared test closes the form; the next one starts empty.
    await waitFor(() => expect(within(view).queryByLabelText('Proof objective')).toBeNull());
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare a test…' }));
    expect((within(view).getByLabelText('Proof objective') as HTMLTextAreaElement).value).toBe('');
  });

  it('lets a suggested host be removed again and keeps the route hint honest', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, unprepared], items: [work], queue_state_counts: { needs_approval: 1, unprepared: 1 } }));
    render(tab());
    const view = await openRecord('VA-002');
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare a test…' }));
    expect(within(view).getByText(/Defaulted from the finding's source location/)).toBeTruthy();
    fireEvent.change(within(view).getByLabelText('Proof route'), { target: { value: 'web' } });
    expect(within(view).queryByText(/Defaulted from/)).toBeNull();
    expect(within(view).getByText(/You chose this route/)).toBeTruthy();
    const host = within(view).getByRole('button', { name: 'api.example.com' });
    fireEvent.click(host);
    expect(host.getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(host);
    expect(host.getAttribute('aria-pressed')).toBe('false');
    expect((within(view).getByLabelText('Admitted target hosts') as HTMLInputElement).value).toBe('');
    // Cancel discards the form.
    fireEvent.change(within(view).getByLabelText('Proof objective'), { target: { value: 'Discarded' } });
    fireEvent.click(within(view).getByRole('button', { name: 'Cancel' }));
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare a test…' }));
    expect((within(view).getByLabelText('Proof objective') as HTMLTextAreaElement).value).toBe('');
    expect((within(view).getByLabelText('Proof route') as HTMLSelectElement).value).toBe('code');
  });

  it('asks for an explicit confirmation naming hosts and objective before approving', async () => {
    vi.mocked(approveProofWork).mockResolvedValue({ ...work, approved: true } as never);
    render(tab());
    const view = await openRecord('VA-001');
    fireEvent.click(within(view).getByRole('button', { name: 'Approve live proof 9' }));
    expect(approveProofWork).not.toHaveBeenCalled();
    const confirm = within(view).getByRole('group', { name: 'Confirm approval for proof 9' });
    expect(confirm.textContent).toContain('Approving lets the verifier that claims proof #9 for VA-001 send live requests to app.example.com for this objective only:');
    expect(confirm.textContent).toContain('Challenge export access');
    expect(confirm.textContent).toContain('Changing the finding, plan, or hosts later requires a fresh approval.');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Confirm approval' }));
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, true));
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    expect(approveProofWork).toHaveBeenCalledTimes(1);
  });

  it('closes an open approval confirmation when stepping to another finding, and approves nothing', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, owedB], items: [work, workB], queue_state_counts: { needs_approval: 2 } }));
    render(tab());
    const view = await openRecord('VA-001');
    fireEvent.click(within(view).getByRole('button', { name: 'Approve live proof 9' }));
    expect(within(view).getByRole('group', { name: 'Confirm approval for proof 9' })).toBeTruthy();

    fireEvent.keyDown(window, { key: ']' });
    await recordTitle(view, 'Acme billing hypothesis');
    // The confirmation belonged to VA-001: VA-003 shows its own first step only.
    expect(screen.queryByRole('group', { name: /^Confirm approval for proof/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Confirm approval' })).toBeNull();
    expect(within(view).getByRole('button', { name: 'Approve live proof 12' })).toBeTruthy();

    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme export hypothesis');
    expect(screen.queryByRole('group', { name: /^Confirm approval for proof/ })).toBeNull();
    expect(within(view).getByRole('button', { name: 'Approve live proof 9' })).toBeTruthy();
    expect(approveProofWork).not.toHaveBeenCalled();
  });

  it('keeps a half-written prepare form and typed reasons through stepping, Escape and the address', async () => {
    const ended = { ...work, status: 'blocked', queue_state: 'blocked', owner_agent_id: 'PROOF-1', owner_dispatch_id: 4, owner_dispatch_status: 'completed' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [{ ...owed, queue_state: 'blocked' }, unprepared], items: [ended], queue_state_counts: { blocked: 1, unprepared: 1 } }));
    const rendered = render(tab());
    const view = await openRecord('VA-002');
    fireEvent.click(within(view).getByRole('button', { name: 'Prepare a test…' }));
    fireEvent.change(within(view).getByLabelText('Proof route'), { target: { value: 'web' } });
    fireEvent.change(within(view).getByLabelText('Proof objective'), { target: { value: 'Half-written objective' } });
    fireEvent.change(within(view).getByLabelText('Admitted target hosts'), { target: { value: 'api.example.com, app.exa' } });
    const form = () => ({
      route: (screen.getByLabelText('Proof route') as HTMLSelectElement).value,
      objective: (screen.getByLabelText('Proof objective') as HTMLTextAreaElement).value,
      hosts: (screen.getByLabelText('Admitted target hosts') as HTMLInputElement).value,
    });
    const written = { route: 'web', objective: 'Half-written objective', hosts: 'api.example.com, app.exa' };

    // Step to the blocked finding and leave both of its reasons half-written.
    fireEvent.click(within(view).getByRole('button', { name: 'Previous finding' }));
    await recordTitle(view, 'Acme export hypothesis');
    expect(screen.queryByLabelText('Proof objective')).toBeNull();
    fireEvent.change(within(view).getAllByLabelText('Recovery reason for proof 9')[0], { target: { value: 'Owner ended, no live' } });
    fireEvent.change(within(view).getAllByLabelText('Revocation reason for proof 9')[0], { target: { value: ' Stop: scope\n' } });
    const reasons = () => ({
      release: (screen.getAllByLabelText('Recovery reason for proof 9')[0] as HTMLInputElement).value,
      revoke: (screen.getAllByLabelText('Revocation reason for proof 9')[0] as HTMLTextAreaElement).value,
    });
    const typed = { release: 'Owner ended, no live', revoke: ' Stop: scope\n' };

    // Step away and back.
    fireEvent.keyDown(window, { key: ']' });
    await recordTitle(view, 'Acme import hypothesis');
    expect(form()).toEqual(written);
    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme export hypothesis');
    expect(reasons()).toEqual(typed);

    // Escape to the list and reopen each record.
    fireEvent.keyDown(window, { key: 'Escape' });
    await noRecord();
    await openRecord('VA-002');
    expect(form()).toEqual(written);
    fireEvent.click(within(await record()).getByRole('button', { name: 'Back to results' }));
    await noRecord();
    await openRecord('VA-001');
    expect(reasons()).toEqual(typed);

    // The page passes back the address the tab wrote; browser Back then shows
    // the list, and Forward or a link reopens each record.
    rendered.rerender(tab({ initialProofSlug: 'VA-001' }));
    expect(reasons()).toEqual(typed);
    rendered.rerender(tab());
    await noRecord();
    rendered.rerender(tab({ initialProofSlug: 'VA-002' }));
    await recordTitle(await record(), 'Acme import hypothesis');
    expect(form()).toEqual(written);
    rendered.rerender(tab({ initialProofSlug: 'VA-001' }));
    await recordTitle(await record(), 'Acme export hypothesis');
    expect(reasons()).toEqual(typed);
    expect(prepareProofWork).not.toHaveBeenCalled();
    expect(releaseProofWork).not.toHaveBeenCalled();
    expect(approveProofWork).not.toHaveBeenCalled();
  });

  it('re-reads an open record on a refresh bump without dropping its draft or an open confirmation', async () => {
    const view = render(tab({ refreshVersion: 0 }));
    const open = await openRecord('VA-001');
    fireEvent.click(within(open).getByRole('button', { name: 'Approve live proof 9' }));
    fireEvent.change(within(open).getByLabelText('Revocation reason for proof 9'), { target: { value: 'Half-written reason' } });
    vi.mocked(listProofWork).mockResolvedValueOnce(queue({ items: [{ ...work, objective: 'Challenge export access again' }] }));
    view.rerender(tab({ refreshVersion: 1 }));
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    const confirm = await within(open).findByRole('group', { name: 'Confirm approval for proof 9' });
    await waitFor(() => expect(confirm.textContent).toContain('Challenge export access again'));
    expect((within(open).getByLabelText('Revocation reason for proof 9') as HTMLTextAreaElement).value).toBe('Half-written reason');
    expect(approveProofWork).not.toHaveBeenCalled();
  });

  it('keeps stale work visible, prevents approval, and offers reconcile first', async () => {
    vi.mocked(reconcileProofWork).mockResolvedValue(work as never);
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, current: false, queue_state: 'stale' }], owed: [{ ...owed, queue_state: 'stale' }] }));
    render(tab());
    const view = await openRecord('VA-001');
    expect(within(view).getByText('Stale context — prepare against current evidence')).toBeTruthy();
    fireEvent.click(within(view).getByRole('button', { name: 'Reconcile proof 9' }));
    await waitFor(() => expect(reconcileProofWork).toHaveBeenCalledWith('acme', 9));
    // Stale work means the finding needs a fresh preparation.
    expect(within(view).getByRole('button', { name: 'Prepare a test…' })).toBeTruthy();
  });

  it('releases ended ownership with an explanation without relaunching a worker', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, status: 'blocked', queue_state: 'blocked', owner_agent_id: 'PROOF-1', owner_dispatch_id: 4, owner_dispatch_status: 'completed' }], owed: [{ ...owed, queue_state: 'blocked' }] }));
    vi.mocked(releaseProofWork).mockResolvedValue({ ...work, status: 'prepared' } as never);
    render(tab());
    const view = await openRecord('VA-001');
    expect(within(view).getByText('PROOF-1 (completed)')).toBeTruthy();
    fireEvent.change(within(view).getAllByLabelText('Recovery reason for proof 9')[0], { target: { value: 'Owner ended and no live work remains' } });
    fireEvent.click(within(view).getAllByRole('button', { name: 'Release proof 9' })[0]);
    await waitFor(() => expect(releaseProofWork).toHaveBeenCalledWith('acme', 9, 'Owner ended and no live work remains'));
  });

  it('revokes in-progress live authority with a lossless reason', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, approval_required: false, status: 'claimed', owner_agent_id: 'PROOF-1', owner_dispatch_status: 'in-progress', queue_state: 'in_progress' }], owed: [{ ...owed, queue_state: 'in_progress' }] }));
    render(tab());
    // Work a verifier is running waits on nobody: it is listed under All.
    fireEvent.click(within(await screen.findByRole('group', { name: 'Scope' })).getByRole('button', { name: /^All/ }));
    const view = await openRecord('VA-001');
    const button = within(view).getAllByRole('button', { name: 'Revoke live proof 9' })[0];
    expect((button as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(within(view).getAllByLabelText('Revocation reason for proof 9')[0], { target: { value: ' Stop this proof.\n' } });
    fireEvent.click(button);
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, false, ' Stop this proof.\n'));
  });

  it('keeps a pending action scoped to its engagement when reused for another engagement', async () => {
    let finishApproval!: (value: never) => void;
    vi.mocked(approveProofWork).mockReturnValue(new Promise<never>((resolve) => { finishApproval = resolve; }));
    vi.mocked(listProofWork).mockImplementation(async (key) => queue({ owed: [{ ...owed, title: key === 'acme' ? 'Acme export hypothesis' : 'Beta export hypothesis' }] }));
    const view = render(tab());
    const open = await openRecord('VA-001');
    fireEvent.click(within(open).getByRole('button', { name: 'Approve live proof 9' }));
    fireEvent.click(within(open).getByRole('button', { name: 'Confirm approval' }));
    view.rerender(tab({ engagementKey: 'beta' }));
    await noRecord();
    await waitFor(() => expect(rowOf('VA-001')?.textContent).toContain('Beta export hypothesis'));
    finishApproval({ ...work, approved: true } as never);
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledTimes(1));
    expect(screen.queryByRole('group', { name: 'Confirm approval for proof 9' })).toBeNull();
    expect(rowOf('VA-001')?.textContent).toContain('Beta export hypothesis');
  });

  it('reads audit history without refreshing the queue and says when there is none', async () => {
    vi.mocked(getProofWork).mockResolvedValue({ ...work, events: [] } as never);
    render(tab());
    const view = await openRecord('VA-001');
    fireEvent.click(within(view).getByRole('button', { name: 'Show audit history for proof 9' }));
    expect(await within(view).findByText('No audit events recorded for this proof work yet.')).toBeTruthy();
    expect(listProofWork).toHaveBeenCalledTimes(1);
  });

  it('loads approval history on request and renders raw text safely', async () => {
    const confirmation = '<img src=x onerror=alert(1)> approved\n  Acme';
    const details = JSON.stringify({ actor: 'operator', human_confirmation: confirmation });
    vi.mocked(getProofWork).mockResolvedValue({ ...work, events: [{ id: 1, action: 'approval', created_at: '', details_json: details }] } as never);
    const rendered = render(tab());
    const view = await openRecord('VA-001');
    fireEvent.click(within(view).getByRole('button', { name: 'Show audit history for proof 9' }));
    await waitFor(() => expect(getProofWork).toHaveBeenCalledWith('acme', 9));
    // The stored details print whole.
    await waitFor(() => expect(within(view).getByRole('list', { name: 'Audit history for proof 9' }).querySelector('pre')?.textContent).toBe(details));
    expect(rendered.container.querySelector('img')).toBeNull();
  });

  it('blocks reconcile, like every write, while the queue state is unknown', async () => {
    const view = render(tab({ refreshVersion: 0 }));
    const open = await openRecord('VA-001');
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('queue offline'));
    view.rerender(tab({ refreshVersion: 1 }));
    await within(open).findByText(/queue offline/);
    for (const button of within(open).getAllByRole('button', { name: 'Reconcile proof 9' })) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it('keeps actions available after a failed write once the queue re-reads', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, owedB], items: [work, workB], queue_state_counts: { needs_approval: 2 } }));
    vi.mocked(approveProofWork).mockRejectedValueOnce(new Error('Approval conflicts with a newer preparation'));
    render(tab());
    const view = await openRecord('VA-001');
    fireEvent.click(within(view).getByRole('button', { name: 'Approve live proof 9' }));
    fireEvent.click(within(view).getByRole('button', { name: 'Confirm approval' }));
    // The error sits on the record whose action failed, beside its actions.
    const alert = await within(view).findByRole('alert');
    expect(alert.textContent).toContain('Approval conflicts with a newer preparation');
    expect(alert.textContent).toContain('The queue was re-read');
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    await waitFor(() => expect((within(view).getByRole('button', { name: 'Confirm approval' }) as HTMLButtonElement).disabled).toBe(false));
    expect(approveProofWork).toHaveBeenCalledTimes(1);
    // It belongs to that finding: the next record does not show it.
    fireEvent.keyDown(window, { key: ']' });
    await recordTitle(view, 'Acme billing hypothesis');
    expect(within(view).queryByRole('alert')).toBeNull();
    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme export hypothesis');
    expect(within(view).getByRole('alert').textContent).toContain('Approval conflicts with a newer preparation');
    fireEvent.click(within(view).getByRole('button', { name: 'Dismiss' }));
    expect(within(view).queryByRole('alert')).toBeNull();
  });

  it('offers Reload queue after a failed read and re-enables actions once it loads', async () => {
    const view = render(tab({ refreshVersion: 0 }));
    const open = await openRecord('VA-001');
    vi.mocked(listProofWork).mockRejectedValueOnce(new Error('queue offline'));
    view.rerender(tab({ refreshVersion: 1 }));
    const alert = await within(open).findByRole('alert');
    expect(alert.textContent).toContain('queue offline');
    expect(alert.textContent).toContain('actions stay off until it reloads');
    expect((within(open).getByRole('button', { name: 'Approve live proof 9' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(alert).getByRole('button', { name: 'Reload queue' }));
    await waitFor(() => expect((within(open).getByRole('button', { name: 'Approve live proof 9' }) as HTMLButtonElement).disabled).toBe(false));
    expect(listProofWork).toHaveBeenCalledTimes(3);
  });

  it('renders the next test as plain text', async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [{ ...owed, next_test: { ...nextTest, hypothesis: hostile } }] }));
    const rendered = render(tab());
    const view = await openRecord('VA-001');
    expect(within(view).getByText(hostile)).toBeTruthy();
    expect(rendered.container.querySelector('img')).toBeNull();
    expect(within(view).getByText('Live target')).toBeTruthy();
    expect(within(view).getByText('The export returns the other tenant rows')).toBeTruthy();
    expect(within(view).getByText('Two viewer accounts on app.example.com')).toBeTruthy();
  });

  it('shows a long reason clamped with the whole text one click away', async () => {
    const reason = Array.from({ length: 6 }, (_, index) => `Line ${index + 1} of the Acme parking decision.`).join('\n');
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [{ ...owed, parked_reason: reason }] }));
    render(tab());
    const view = await openRecord('VA-001');
    const text = within(view).getByText(reason, { normalizer: (value) => value });
    expect(text.className).toContain('is-clamped');
    fireEvent.click(within(view).getByRole('button', { name: 'Show full reason' }));
    expect(text.className).not.toContain('is-clamped');
  });

  it('keeps earlier preparations behind their own disclosure', async () => {
    const earlier = { ...work, id: 7, status: 'resolved', current: false, owed: false, queue_state: 'done', objective: 'Earlier export attempt' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [earlier, work] }));
    render(tab());
    const view = await openRecord('VA-001');
    const disclosure = within(view).getByText('Earlier preparations (1)').closest('details')!;
    expect(disclosure.open).toBe(false);
    expect(within(disclosure).getByText('Earlier export attempt')).toBeTruthy();
  });

  it('links each evidence run to the Runs drawer', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [{ ...work, run_ids: [41], runs: [{ id: 41, run_uuid: 'acme-proof-run', run_kind: 'web', status: 'completed', started_at: '2026-10-10 10:00:00', finished_at: null, proof_receipts: 2 }] }] }));
    render(tab());
    const view = await openRecord('VA-001');
    const link = within(view).getByRole('link', { name: 'Run 41' });
    expect(link.getAttribute('href')).toBe('#/engagements/acme?tab=runs&run=41');
    expect(link.textContent).toBe('acme-proof-run');
    expect(within(view).getByText('2 receipts')).toBeTruthy();
  });
});

describe('ProofWorkTab work links', () => {
  const ready = { ...owed, finding_slug: 'VA-003', finding_id: 3, title: 'Acme ready hypothesis', work_ids: [10], queue_state: 'ready' };
  const readyWork = { ...work, id: 10, finding_slug: 'VA-003', queue_state: 'ready', approval_required: false };

  it('opens the record holding a work item a link names even when the scope would hide it, and names both in the address', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, ready], items: [work, readyWork], queue_state_counts: { needs_approval: 1, ready: 1 } }));
    window.history.replaceState(null, '', '#/engagements/acme?tab=proof&work=10');
    const before = window.history.length;
    render(tab({ workId: 10 }));
    const view = await record();
    expect(await recordTitle(view, 'Acme ready hypothesis')).toBeTruthy();
    expect(document.getElementById('proof-work-10')?.className).toContain('is-highlighted');
    // The scope widened so the record sits in the results it returns to.
    expect(within(view).getByText('2 of 2 results')).toBeTruthy();
    // The landed link names the record too, in place of the bare link.
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof&proof=VA-003&work=10');
    expect(window.history.length).toBe(before);
  });

  it('reopens the record and highlights the test from the landed address', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, ready], items: [work, readyWork], queue_state_counts: { needs_approval: 1, ready: 1 } }));
    render(tab({ initialProofSlug: 'VA-003', workId: 10 }));
    expect(await recordTitle(await record(), 'Acme ready hypothesis')).toBeTruthy();
    await waitFor(() => expect(document.getElementById('proof-work-10')?.className).toContain('is-highlighted'));
  });

  it('says why no approval is needed instead of claiming one was given', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({
      items: [{ ...work, approval_required: false, approved: false, approval_decision: null, queue_state: 'ready' }],
      owed: [{ ...owed, queue_state: 'ready' }],
      queue_state_counts: { ready: 1 },
    }));
    render(tab({ workId: 9 }));
    expect(await screen.findByText(/No separate approval needed: the engagement's exploit policy authorizes live proof/)).toBeTruthy();
    expect(screen.queryByText('Approved for this work')).toBeNull();
    cleanup();
    vi.mocked(listProofWork).mockResolvedValue(queue({
      items: [{ ...work, approval_required: false, approved: true, approval_decision: 'approved', queue_state: 'ready' }],
      owed: [{ ...owed, queue_state: 'ready' }],
      queue_state_counts: { ready: 1 },
    }));
    render(tab({ workId: 9 }));
    expect(await screen.findByText('Approved by the operator for this work')).toBeTruthy();
  });

  it('highlights the prepared test a link names until another record is opened', async () => {
    vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [owed, owedB], items: [work, workB], queue_state_counts: { needs_approval: 2 } }));
    render(tab({ workId: 9 }));
    const view = await record();
    await recordTitle(view, 'Acme export hypothesis');
    expect(document.getElementById('proof-work-9')?.className).toContain('is-highlighted');
    fireEvent.keyDown(window, { key: ']' });
    await recordTitle(view, 'Acme billing hypothesis');
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof&proof=VA-003');
    fireEvent.keyDown(window, { key: '[' });
    await recordTitle(view, 'Acme export hypothesis');
    expect(document.getElementById('proof-work-9')).toBeTruthy();
    expect(document.getElementById('proof-work-9')?.className).not.toContain('is-highlighted');
  });

  it('opens the earlier preparations when the linked test is one of them', async () => {
    const earlier = { ...work, id: 7, status: 'resolved', current: false, owed: false, queue_state: 'done', objective: 'Earlier export attempt' };
    vi.mocked(listProofWork).mockResolvedValue(queue({ items: [earlier, work] }));
    render(tab({ workId: 7 }));
    const view = await record();
    await recordTitle(view, 'Acme export hypothesis');
    expect(within(view).getByText('Earlier preparations (1)').closest('details')!.open).toBe(true);
    expect(document.getElementById('proof-work-7')?.className).toContain('is-highlighted');
  });

  it('scrolls to a linked item once, not again on every refresh', async () => {
    const scrolled: Element[] = [];
    Element.prototype.scrollIntoView = function scrollIntoView(this: Element) { scrolled.push(this); };
    const toLinked = () => scrolled.filter((element) => element.id === 'proof-work-9').length;
    const view = render(tab({ workId: 9, refreshVersion: 0 }));
    await recordTitle(await record(), 'Acme export hypothesis');
    await waitFor(() => expect(toLinked()).toBe(1));
    vi.mocked(listProofWork).mockResolvedValueOnce(queue());
    view.rerender(tab({ workId: 9, refreshVersion: 1 }));
    await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(toLinked()).toBe(1);
  });

  it('shows the list and says so when the link names a test the queue does not hold', async () => {
    window.history.replaceState(null, '', '#/engagements/acme?tab=proof&work=77');
    render(tab({ workId: 77 }));
    expect(await screen.findByText(/Proof #77 is not in the proof queue/)).toBeTruthy();
    expect(screen.queryByRole('region', { name: 'Proof work' })).toBeNull();
    expect(rowOf('VA-001')).toBeTruthy();
    expect(window.location.hash).toBe('#/engagements/acme?tab=proof&work=77');
  });
});

describe('ProofWorkCard without a draft owner', () => {
  const props = {
    engagementKey: 'acme', severity: 'high', busy: false,
  };

  it('keeps the prepare form in its own state', async () => {
    const onAction = vi.fn(async (operation: () => Promise<unknown>) => { await operation(); return true; });
    vi.mocked(prepareProofWork).mockResolvedValue(work as never);
    render(<ProofWorkCard {...props} owed={{ ...unprepared, finding_slug: 'VA-001' } as never} items={[]} onAction={onAction} />);
    fireEvent.click(screen.getByRole('button', { name: 'Prepare a test…' }));
    fireEvent.change(screen.getByLabelText('Proof objective'), { target: { value: 'Replay the import locally' } });
    fireEvent.click(screen.getByRole('button', { name: 'Prepare proof' }));
    await waitFor(() => expect(prepareProofWork).toHaveBeenCalledWith('acme', { finding_slug: 'VA-001', route: 'code', objective: 'Replay the import locally', target_hosts: [] }));
    await waitFor(() => expect(screen.queryByLabelText('Proof objective')).toBeNull());
  });

  it('keeps a typed reason in its own state', async () => {
    const onAction = vi.fn(async (operation: () => Promise<unknown>) => { await operation(); return true; });
    vi.mocked(approveProofWork).mockResolvedValue(work as never);
    const running = { ...work, approval_required: false, status: 'claimed', owner_agent_id: 'PROOF-1', owner_dispatch_status: 'in-progress', queue_state: 'in_progress' };
    render(<ProofWorkCard {...props} owed={{ ...owed, queue_state: 'in_progress' } as never} items={[running as never]} onAction={onAction} />);
    fireEvent.change(screen.getByLabelText('Revocation reason for proof 9'), { target: { value: 'Stop this proof.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Revoke live proof 9' }));
    await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, false, 'Stop this proof.'));
  });
});
