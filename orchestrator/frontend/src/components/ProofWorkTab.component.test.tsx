// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { listProofWork, prepareProofWork, approveProofWork, reconcileProofWork, releaseProofWork } from '../lib/api';
import { ProofWorkTab } from './ProofWorkTab';
vi.mock('../lib/api', () => ({ listProofWork: vi.fn(), prepareProofWork: vi.fn(), approveProofWork: vi.fn(), reconcileProofWork: vi.fn(), releaseProofWork: vi.fn() }));
const work = { id: 9, finding_slug: 'VA-001', route: 'web', objective: 'Challenge export access', target_hosts: ['app.example.com'], status: 'prepared', current: true, owed: true, approved: false, approval_required: true, owner_agent_id: null, owner_dispatch_id: null, blocker: 'Live proof approval required', run_ids: [], created_at: '', updated_at: '', stale_reasons: [] };
const owed = { finding_slug: 'VA-001', title: 'Acme export hypothesis', work_ids: [9] };
beforeEach(() => { vi.mocked(listProofWork).mockResolvedValue({owed: [owed], items: [work]} as never); });
afterEach(() => { cleanup(); vi.resetAllMocks(); });
it('shows owed candidates, ownership, blockers and linked evidence', async () => {
  vi.mocked(listProofWork).mockResolvedValue({ owed: [owed], items: [{ ...work, owner_agent_id: 'PROOF-1', status: 'blocked', blocker: 'Need a second account', run_ids: [41] }] } as never);
  render(<ProofWorkTab engagementKey="acme" />);
  expect(await screen.findByText('Acme export hypothesis')).toBeTruthy();
  expect(screen.getByText('PROOF-1')).toBeTruthy();
  expect(screen.getByText('Need a second account')).toBeTruthy();
  expect(screen.getByRole('link', {name: 'Run 41'}).getAttribute('href')).toContain('run=41');
});
it('prepares an explicit objective and selected route', async () => {
  vi.mocked(prepareProofWork).mockResolvedValue(work as never);
  render(<ProofWorkTab engagementKey="acme" />);
  await screen.findByText('Acme export hypothesis');
  fireEvent.change(screen.getByLabelText('Proof objective'), {target: {value: 'Try another account and a denied control'}});
  fireEvent.change(screen.getByLabelText('Proof route'), {target: {value: 'web'}});
  fireEvent.change(screen.getByLabelText('Admitted target hosts'), {target: {value: 'app.example.com'}});
  fireEvent.click(screen.getByRole('button', {name: 'Prepare proof'}));
  await waitFor(() => expect(prepareProofWork).toHaveBeenCalledWith('acme', {finding_slug: 'VA-001', route: 'web', objective: 'Try another account and a denied control', target_hosts: ['app.example.com']}));
});
it('records approval only for selected work and explicitly reconciles', async () => {
  vi.mocked(approveProofWork).mockResolvedValue({...work, approved: true} as never);
  vi.mocked(reconcileProofWork).mockResolvedValue(work as never);
  render(<ProofWorkTab engagementKey="acme" />);
  fireEvent.click(await screen.findByRole('button', {name: 'Approve live proof 9'}));
  await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith('acme', 9, true));
  fireEvent.click(screen.getByRole('button', {name: 'Reconcile proof 9'}));
  await waitFor(() => expect(reconcileProofWork).toHaveBeenCalledWith('acme', 9));
});
it('keeps stale work visible and prevents approval', async () => {
  vi.mocked(listProofWork).mockResolvedValue({owed: [owed], items: [{...work, current: false}]} as never);
  render(<ProofWorkTab engagementKey="acme" />);
  expect(await screen.findByText('Stale context — prepare against current evidence')).toBeTruthy();
  expect((screen.getByRole('button', {name: 'Approve live proof 9'}) as HTMLButtonElement).disabled).toBe(true);
});
it('shows fetch failure and supports retry', async () => {
  vi.mocked(listProofWork).mockRejectedValueOnce(new Error('Backend unavailable'));
  render(<ProofWorkTab engagementKey="acme" />);
  expect(await screen.findByRole('alert')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', {name: 'Refresh proof work'}));
  expect(await screen.findByText('Acme export hypothesis')).toBeTruthy();
});

it('releases ended ownership with an explanation without relaunching a worker', async () => {
  vi.mocked(listProofWork).mockResolvedValue({owed: [owed], items: [{...work, status: 'blocked', owner_agent_id: 'PROOF-1', owner_dispatch_status: 'completed'}]} as never);
  vi.mocked(releaseProofWork).mockResolvedValue({...work, status: 'prepared'} as never);
  render(<ProofWorkTab engagementKey="acme" />);
  await screen.findByText('PROOF-1 (completed)');
  fireEvent.change(screen.getByLabelText('Recovery reason for proof 9'), {target: {value: 'Owner ended and no live work remains'}});
  fireEvent.click(screen.getByRole('button', {name: 'Release proof 9'}));
  await waitFor(() => expect(releaseProofWork).toHaveBeenCalledWith('acme', 9, 'Owner ended and no live work remains'));
});

it('keeps a pending action scoped to its engagement when reused for another engagement', async () => {
  let finishApproval!: (value: never) => void;
  const pending = new Promise<never>(resolve => {finishApproval = resolve;});
  vi.mocked(approveProofWork).mockReturnValue(pending);
  vi.mocked(listProofWork).mockImplementation(async key => ({owed: [{...owed, title: key === 'acme' ? 'Acme export hypothesis' : 'Beta export hypothesis'}], items: [work]}) as never);
  const view = render(<ProofWorkTab engagementKey="acme" />);
  fireEvent.change(await screen.findByLabelText('Proof objective'), {target: {value: 'Acme-specific investigation'}});
  fireEvent.click(screen.getByRole('button', {name: 'Approve live proof 9'}));
  view.rerender(<ProofWorkTab engagementKey="beta" />);
  await screen.findByText('Beta export hypothesis');
  finishApproval({...work, approved: true} as never);
  await waitFor(() => expect(approveProofWork).toHaveBeenCalledTimes(1));
  expect((screen.getByLabelText('Proof objective') as HTMLTextAreaElement).value).toBe('');
  expect(screen.getByText('Beta export hypothesis')).toBeTruthy();
});
