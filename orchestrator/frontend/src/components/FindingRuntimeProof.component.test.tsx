// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { approveProofWork, listProofWork } from "../lib/api";
import { FindingRuntimeProof } from "./FindingRuntimeProof";

vi.mock("../lib/api", () => ({ getProofWork: vi.fn(), listProofWork: vi.fn(), prepareProofWork: vi.fn(), approveProofWork: vi.fn(), reconcileProofWork: vi.fn(), releaseProofWork: vi.fn() }));

const work = { id: 9, finding_slug: "VA-001", finding_title: "Acme export hypothesis", finding_severity: "high", route: "web", objective: "Challenge export access", target_hosts: ["app.example.com"], status: "prepared", current: true, owed: true, approved: false, approval_required: true, approval_renewal_required: false, owner_agent_id: null, owner_dispatch_id: null, owner_dispatch_status: null, blocker: "", run_ids: [], runs: [], queue_state: "needs_approval", next_test: null, created_at: "2026-10-10 10:00:00", updated_at: "" };
const owed = { finding_slug: "VA-001", finding_id: 1, title: "Acme export hypothesis", canonical_location: "https://app.example.com/export", severity: "high", parked_reason: "Static review cannot show whether the export checks the tenant.", parked_at: "2026-10-09 17:03:48", source_bound: false, suggested_hosts: ["app.example.com"], work_ids: [9], queue_state: "needs_approval", next_test: null };
const queue = (overrides: Record<string, unknown> = {}) => ({ owed: [owed], items: [work], reverification_required: [], queue_state_counts: { needs_approval: 1 }, ...overrides }) as never;

beforeEach(() => vi.mocked(listProofWork).mockResolvedValue(queue()));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("shows the finding's proof card without repeating the finding the record already names", async () => {
  render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" />);
  const heading = await screen.findByRole("heading", { name: "Runtime proof" });
  expect(within(heading).queryByRole("link")).toBeNull();
  expect(screen.queryByText("Acme export hypothesis")).toBeNull();
  expect(screen.getByText("Static review cannot show whether the export checks the tenant.")).toBeTruthy();
  expect(listProofWork).toHaveBeenCalledWith("acme");
});

it("says when the finding is not in the proof queue and links to Proof work", async () => {
  vi.mocked(listProofWork).mockResolvedValue(queue({ owed: [], items: [] }));
  render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" />);
  const link = await screen.findByRole("link", { name: "Open proof work" });
  expect(link.getAttribute("href")).toBe("#/engagements/acme?tab=proof");
});

it("approves through the card, then re-reads the queue", async () => {
  vi.mocked(approveProofWork).mockResolvedValue({ ...work, approved: true } as never);
  render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve live proof 9" }));
  const confirm = screen.getByRole("group", { name: "Confirm approval for proof 9" });
  fireEvent.click(within(confirm).getByRole("button", { name: "Confirm approval" }));
  await waitFor(() => expect(approveProofWork).toHaveBeenCalledWith("acme", 9, true));
  await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
});

it("coalesces refresh bumps and keeps the card visible meanwhile", async () => {
  const view = render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={0} />);
  await screen.findByRole("heading", { name: "Runtime proof" });
  let finish!: (value: never) => void;
  vi.mocked(listProofWork).mockReturnValueOnce(new Promise<never>((resolve) => { finish = resolve; }));
  view.rerender(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={1} />);
  view.rerender(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={2} />);
  expect(listProofWork).toHaveBeenCalledTimes(2);
  expect(screen.getByRole("heading", { name: "Runtime proof" })).toBeTruthy();
  await act(async () => finish(queue()));
  await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(3));
});

it("keeps the last card and blocks writes when a refresh fails", async () => {
  const view = render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={0} />);
  await screen.findByRole("heading", { name: "Runtime proof" });
  vi.mocked(listProofWork).mockRejectedValueOnce(new Error("queue offline"));
  view.rerender(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={1} />);
  await screen.findByText(/queue offline · Showing the last loaded proof work/);
  expect((screen.getByRole("button", { name: "Approve live proof 9" }) as HTMLButtonElement).disabled).toBe(true);
});

it("keeps actions available after a failed write once the queue re-reads", async () => {
  vi.mocked(approveProofWork).mockRejectedValueOnce(new Error("Approval conflicts with a newer preparation"));
  render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve live proof 9" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm approval" }));
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("Approval conflicts with a newer preparation");
  await waitFor(() => expect(listProofWork).toHaveBeenCalledTimes(2));
  await waitFor(() => expect((screen.getByRole("button", { name: "Confirm approval" }) as HTMLButtonElement).disabled).toBe(false));
});

it("offers a reload after a failed read and re-enables actions once it loads", async () => {
  const view = render(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={0} />);
  await screen.findByRole("heading", { name: "Runtime proof" });
  vi.mocked(listProofWork).mockRejectedValueOnce(new Error("queue offline"));
  view.rerender(<FindingRuntimeProof engagementKey="acme" slug="VA-001" refreshVersion={1} />);
  const alert = await screen.findByRole("alert");
  fireEvent.click(within(alert).getByRole("button", { name: "Reload proof work" }));
  await waitFor(() => expect((screen.getByRole("button", { name: "Approve live proof 9" }) as HTMLButtonElement).disabled).toBe(false));
  expect(listProofWork).toHaveBeenCalledTimes(3);
});
