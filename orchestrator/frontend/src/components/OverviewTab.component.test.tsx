// @vitest-environment jsdom
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OverviewTab } from "./OverviewTab";
import { getReportReadiness, type AssessmentFinding, type AssessmentSummary, type ReportReadiness } from "../lib/api";

vi.mock("../lib/api", () => ({ getReportReadiness: vi.fn() }));
const finding = { slug: "finding-one", title: "Example finding", severity: "high", workflow_status: "draft", verification_status: "unverified" } as AssessmentFinding;
const props = { engagementKey: "one", events: [], assessmentSummary: null, findings: [finding], chains: [], chainLinks: [], currentPhase: "recon", assessmentRefreshVersion: 0 };
beforeEach(() => vi.mocked(getReportReadiness).mockResolvedValue({ ready: true, blocker_count: 0, blockers: [] } as unknown as ReportReadiness));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("puts a navigable finding queue before coverage", async () => {
  render(<OverviewTab {...props} />);
  const queue = screen.getByRole("region", { name: "Finding queue" });
  const link = screen.getByRole("link", { name: "Example finding" });
  expect(link.getAttribute("href")).toBe("#/engagements/one?tab=findings&finding=finding-one");
  const coverage = screen.getByRole("heading", { name: "Coverage" });
  expect(queue.compareDocumentPosition(coverage) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  await waitFor(() => expect(screen.getByTestId("readiness-panel")).toBeTruthy());
});

it("does not declare an empty finding ledger while its first request is pending", async () => {
  render(<OverviewTab {...props} findings={[]} assessmentSummary={{ finding_count: 0 } as AssessmentSummary} findingsLoading />);
  expect(screen.getByText("Loading finding ledger…")).toBeTruthy();
  expect(screen.queryByText("No findings recorded yet.")).toBeNull();
  await screen.findByTestId("readiness-panel");
});

it("does not declare an empty finding ledger after its request fails", async () => {
  render(<OverviewTab {...props} findings={[]} assessmentSummary={{ finding_count: 0 } as AssessmentSummary} findingsLoadError="ledger unavailable" />);
  expect(screen.getByText("Finding ledger unavailable: ledger unavailable")).toBeTruthy();
  expect(screen.queryByText("No findings recorded yet.")).toBeNull();
  await screen.findByTestId("readiness-panel");
});

it("does not label the complete finding ledger with a filtered aggregate count", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_count: 0 } as AssessmentSummary} />);
  expect(screen.getByRole("link", { name: "All findings" })).toBeTruthy();
  await screen.findByTestId("readiness-panel");
});

it("names the current finding summary and makes the exclusion scope explicit", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_count: 2, open_surface_count: 3 } as AssessmentSummary} />);
  expect(screen.getAllByText("Current findings").length).toBeGreaterThan(0);
  expect(screen.getByText("Current findings exclude merged and false-positive records.")).toBeTruthy();
  expect(screen.getAllByText("Open surfaces").length).toBeGreaterThan(0);
  await screen.findByTestId("readiness-panel");
});

it("keeps coverage-specific inventory visible without repeating the claim summary", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_count: 2, probe_count: 7, target_count: 4 } as AssessmentSummary} />);
  const coverage = screen.getByRole("heading", { name: "Coverage" }).closest("section")!;
  expect(within(coverage).queryByText("Current findings")).toBeNull();
  expect(within(coverage).getByText("Probe runs")).toBeTruthy();
  expect(within(coverage).getByText("7")).toBeTruthy();
  expect(within(coverage).getByText("Targets")).toBeTruthy();
  expect(within(coverage).getByText("4")).toBeTruthy();
  expect(within(coverage).getByRole("link", { name: "Full coverage ledger" }).getAttribute("href")).toBe("#/engagements/one?tab=coverage");
  await screen.findByTestId("readiness-panel");
});

it("keeps blocker attention primary rather than repeating it in the claim KPI strip", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_count: 2, report_blocker_count: 3 } as AssessmentSummary} />);
  expect(within(screen.getByTestId("overview-charts")).queryByText("Report blockers")).toBeNull();
  expect(screen.getByRole("link", { name: "3 report blockers" })).toBeTruthy();
  await screen.findByTestId("readiness-panel");
});

it("counts every nonterminal verification status in the attention panel", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_verification_statuses: { unreviewed: 2, disputed: 3, pending_runtime_proof: 5, blocked: 7, confirmed: 11, downgraded: 13, false_positive: 17 } } as unknown as AssessmentSummary} />);
  expect(screen.getByRole("link", { name: "17 findings awaiting verification" }).getAttribute("href")).toBe("#/engagements/one?tab=findings");
  await screen.findByTestId("readiness-panel");
});

it("reports zero verification work when only terminal statuses are present", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_verification_statuses: { confirmed: 11, downgraded: 13, false_positive: 17 } } as unknown as AssessmentSummary} />);
  expect(screen.getByRole("link", { name: "0 findings awaiting verification" })).toBeTruthy();
  await screen.findByTestId("readiness-panel");
});

it("opens the exact finding named by a report blocker", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: false, blocker_count: 1, blockers: [{ kind: "finding_review", slug: "finding-one", detail: "Review the finding evidence." }] } as unknown as ReportReadiness);
  render(<OverviewTab {...props} />);
  expect((await screen.findByRole("link", { name: "finding-one" })).getAttribute("href")).toBe("#/engagements/one?tab=findings&finding=finding-one");
});

it("names report checks without suggesting that an unfinished track is complete", async () => {
  render(<OverviewTab {...props} trackState={{ code: { phase: "hunt", complete: false } }} aggregateComplete={false} />);
  const checks = (await screen.findByRole("heading", { name: "Report checks" })).closest("section")!;
  expect(within(checks).getByText("READY")).toBeTruthy();
  expect(screen.getByText("Tracks in progress")).toBeTruthy();
});

it("does not claim zero host coverage when the report endpoint omits its host matrix", async () => {
  render(<OverviewTab {...props} />);
  const checks = await screen.findByTestId("readiness-panel");
  expect(within(checks).getAllByText("Unknown")).toHaveLength(3);
});

it("describes missing host signals without prescribing web recon for a code-only engagement", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: true, blocker_count: 0, blockers: [], per_host_coverage: { hosts: [], scope_hosts: [], objectives: [] } } as unknown as ReportReadiness);
  render(<OverviewTab {...props} trackState={{ code: { phase: "hunt", complete: false } }} />);
  await screen.findByTestId("readiness-panel");
  expect(screen.queryByText(/Dispatch recon-specialist/)).toBeNull();
  expect(screen.getByText("No per-host coverage signals are recorded.")).toBeTruthy();
});

it("clears readiness immediately across engagement identity and ignores late responses", async () => {
  let finishOld!: (value: ReportReadiness) => void;
  vi.mocked(getReportReadiness).mockReturnValueOnce(new Promise(resolve => { finishOld = resolve; }));
  vi.mocked(getReportReadiness).mockReturnValueOnce(new Promise(() => {}));
  const view = render(<OverviewTab {...props} />);
  view.rerender(<OverviewTab {...props} engagementKey="two" />);
  await act(async () => finishOld({ ready: true, blocker_count: 0, blockers: [] } as unknown as ReportReadiness));
  expect(screen.queryByTestId("readiness-panel")).toBeNull();
});

it("does not display the previous engagement readiness while loading another", async () => {
  const view = render(<OverviewTab {...props} />);
  await screen.findByTestId("readiness-panel");
  vi.mocked(getReportReadiness).mockReturnValueOnce(new Promise(() => {}));
  view.rerender(<OverviewTab {...props} engagementKey="two" />);
  expect(screen.queryByTestId("readiness-panel")).toBeNull();
});

it("shows egress mitigation guidance without offering controls that do nothing", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ egress_status: { blocked_pct: 60, pattern: "blocked" } } as unknown as AssessmentSummary} />);
  const guidance = screen.getByTestId("egress-reputation-banner");
  expect(guidance.querySelectorAll("button")).toHaveLength(0);
  expect(guidance.textContent).toMatch(/Record the operator decision/);
  await screen.findByTestId("readiness-panel");
});
