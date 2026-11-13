// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { OverviewTab } from "./OverviewTab";
import { getReportReadiness, type AssessmentFinding, type AssessmentSummary, type ReportReadiness } from "../lib/api";

import { listActivityFeed, type ActivityFeedPage, type ActivityItem } from "../lib/activityApi";

vi.mock("../lib/api", () => ({ getReportReadiness: vi.fn() }));
vi.mock("../lib/activityApi", () => ({ listActivityFeed: vi.fn() }));
const emptyFeed: ActivityFeedPage = { items: [], has_more: false, total: 0, categories: [] };
const finding = { slug: "finding-one", title: "Example finding", severity: "high", workflow_status: "draft", verification_status: "unreviewed" } as AssessmentFinding;
const props = { engagementKey: "one", assessmentSummary: null, findings: [finding], chains: [], chainLinks: [], currentPhase: "recon", assessmentRefreshVersion: 0, readinessRefreshVersion: 0 };
beforeEach(() => {
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: true, blocker_count: 0, blockers: [] } as unknown as ReportReadiness);
  vi.mocked(listActivityFeed).mockResolvedValue(emptyFeed);
});
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
  const queue = screen.getByRole("region", { name: "Finding queue" });
  expect(within(queue).getByRole("status", { name: "Loading content" }).getAttribute("aria-busy")).toBe("true");
  expect(screen.queryByText("No findings recorded yet.")).toBeNull();
  await screen.findByTestId("readiness-panel");
});

it("shows content-shaped placeholders while the summary, ledger and readiness load", async () => {
  vi.mocked(getReportReadiness).mockReturnValue(new Promise<never>(() => {}));
  render(<OverviewTab {...props} findings={[]} findingsLoading />);
  const busy = (region: HTMLElement) => within(region).getAllByRole("status").filter((node) => node.getAttribute("aria-busy") === "true");
  expect(busy(screen.getByRole("region", { name: "Needs attention" })).length).toBeGreaterThan(0);
  expect(busy(screen.getByRole("region", { name: "Finding queue" })).length).toBeGreaterThan(0);
  expect(busy(screen.getByRole("heading", { name: "Coverage" }).closest("section")!).length).toBeGreaterThan(0);
  expect(busy(screen.getByRole("region", { name: "Report checks" })).length).toBeGreaterThan(0);
});

it("says which load is slow after two seconds", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    vi.mocked(getReportReadiness).mockReturnValue(new Promise<never>(() => {}));
    render(<OverviewTab {...props} findings={[]} findingsLoading />);
    await act(async () => { await vi.advanceTimersByTimeAsync(2_100); });
    expect(screen.getByText("Still loading the finding ledger…")).toBeTruthy();
    expect(screen.getByText("Still loading report readiness…")).toBeTruthy();
  } finally {
    vi.useRealTimers();
  }
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
  expect(screen.getByRole("button", { name: "3 report blockers" })).toBeTruthy();
  await screen.findByTestId("readiness-panel");
});

it("counts every nonterminal verification status in the attention panel", async () => {
  render(<OverviewTab {...props} assessmentSummary={{ finding_verification_statuses: { unreviewed: 2, disputed: 3, pending_runtime_proof: 5, blocked: 7, confirmed: 11, downgraded: 13, false_positive: 17 } } as unknown as AssessmentSummary} />);
  expect(screen.getByRole("link", { name: "17 findings awaiting verification" }).getAttribute("href")).toBe("#/engagements/one?tab=findings&verification=unreviewed%2Cdisputed%2Cpending_runtime_proof%2Cblocked");
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
  const checks = await screen.findByTestId("readiness-panel");
  expect(within(checks).getByRole("heading", { name: "Report checks" })).toBeTruthy();
  expect(within(checks).getByText("Ready")).toBeTruthy();
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

const activityItem: ActivityItem = {
  id: "audit:7", source: "audit", source_id: 7, cursor: "c7",
  occurred_at: "2026-10-20T11:58:00Z",
  actor: { name: "verifier", kind: "agent" },
  category: "findings", kind: "finding.verified",
  summary: "Verifier confirmed Acme export hypothesis",
  entities: [{ type: "finding", key: "acme-export", label: "acme-export" }, { type: "run", key: "41", label: "Run #41" }],
  dispatch: null, detail: {},
};

it("shows the newest activity as sentences that link to the records they name", async () => {
  vi.mocked(listActivityFeed).mockResolvedValue({ ...emptyFeed, items: [activityItem], total: 1, categories: [{ key: "findings", label: "Findings", count: 1, default: true }] });
  render(<OverviewTab {...props} />);
  const section = await screen.findByRole("region", { name: "Latest activity" });
  await within(section).findByText("Verifier confirmed Acme export hypothesis");
  expect(listActivityFeed).toHaveBeenCalledWith("one", { limit: 5 });
  expect(within(section).getByText("Findings")).toBeTruthy();
  expect(within(section).getByRole("link", { name: /acme-export/ }).getAttribute("href")).toBe("#/engagements/one?tab=findings&finding=acme-export");
  expect(within(section).getByRole("link", { name: /Run #41/ }).getAttribute("href")).toBe("#/engagements/one?tab=runs&run=41");
  expect(within(section).getByRole("link", { name: "All activity" }).getAttribute("href")).toBe("#/engagements/one?tab=activity");
});

it("says when no activity is recorded and keeps the last entries when a refresh fails", async () => {
  const view = render(<OverviewTab {...props} />);
  await screen.findByText("No activity recorded yet.");
  vi.mocked(listActivityFeed).mockResolvedValueOnce({ ...emptyFeed, items: [activityItem], total: 1 });
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={1} />);
  await screen.findByText("Verifier confirmed Acme export hypothesis");
  vi.mocked(listActivityFeed).mockRejectedValueOnce(new Error("feed offline"));
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={2} />);
  await screen.findByText(/Showing the last loaded entries: feed offline/);
  expect(screen.getByText("Verifier confirmed Acme export hypothesis")).toBeTruthy();
});

it("coalesces refresh bursts into one follow-up read per source", async () => {
  const view = render(<OverviewTab {...props} />);
  await screen.findByText("No activity recorded yet.");
  let finish!: (value: ActivityFeedPage) => void;
  vi.mocked(listActivityFeed).mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
  let finishReadiness!: (value: ReportReadiness) => void;
  vi.mocked(getReportReadiness).mockReturnValueOnce(new Promise((resolve) => { finishReadiness = resolve; }));
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={1} readinessRefreshVersion={1} />);
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={2} readinessRefreshVersion={2} />);
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={3} readinessRefreshVersion={3} />);
  expect(listActivityFeed).toHaveBeenCalledTimes(2);
  expect(getReportReadiness).toHaveBeenCalledTimes(2);
  await act(async () => finish(emptyFeed));
  await act(async () => finishReadiness({ ready: true, blocker_count: 0, blockers: [] } as unknown as ReportReadiness));
  await waitFor(() => expect(listActivityFeed).toHaveBeenCalledTimes(3));
  await waitFor(() => expect(getReportReadiness).toHaveBeenCalledTimes(3));
});

it("summarizes report blockers by kind and keeps every blocker one click away", async () => {
  const blockers = Array.from({ length: 16 }, (_, index) => ({ kind: index < 12 ? "missing_evidence" : "unverified_claim", slug: `acme-${index}`, detail: `Blocker detail ${index}` }));
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: false, blocker_count: 16, blockers } as unknown as ReportReadiness);
  render(<OverviewTab {...props} />);
  const panel = await screen.findByRole("region", { name: "Report blockers" });
  const kinds = Array.from(panel.querySelectorAll("details > summary")).map((summary) => summary.textContent);
  expect(kinds).toEqual(["Missing evidence12", "Unverified claim4"]);
  // The largest kind opens with its first blockers listed; the rest are one click away.
  const missing = panel.querySelectorAll("details")[0];
  expect(missing.open).toBe(true);
  expect(missing.querySelectorAll("article")).toHaveLength(10);
  fireEvent.click(within(missing).getByRole("button", { name: "Show all 12 missing evidence blockers" }));
  expect(missing.querySelectorAll("article")).toHaveLength(12);
  expect(within(panel).getByText("Blocker detail 15")).toBeTruthy();
});

it("shows the advisories a passing gate leaves behind, and says they never block", async () => {
  // `report_readiness` returns advisories alongside blockers and they are not
  // empty just because the gate passes — they quote QA doubt about the
  // engagement's own evidence. The SPA rendered none of them, so the only way
  // to read them was the CLI.
  vi.mocked(getReportReadiness).mockResolvedValue({
    ready: true,
    blocker_count: 0,
    blockers: [],
    advisory_count: 2,
    advisories: [
      { kind: "missing_cited_markdown_artifact", severity: "advisory", slug: "acme-1", detail: "notes/scope.md cites an artifact that is absent." },
      { kind: "finding_repro_runs_missing", severity: "advisory", slug: "acme-2", detail: "advisory, not a report blocker: no command run backs the steps." },
    ],
  } as unknown as ReportReadiness);
  render(<OverviewTab {...props} />);

  const panel = await screen.findByRole("region", { name: "Report advisories" });
  expect(panel.textContent).toContain("None of these blocks a final report export");
  expect(within(panel).getByText("notes/scope.md cites an artifact that is absent.")).toBeTruthy();
  expect(screen.getByTestId("readiness-advisory-count").textContent).toContain("2");
  // The blockers panel is a different gate and must not appear for them.
  expect(screen.queryByRole("region", { name: "Report blockers" })).toBeNull();
});

it("gates each readiness item on the severity the backend stamped, not the array it arrived in", async () => {
  // `missing_cited_markdown_artifact` never gates and
  // `finding_evidence_missing_artifact` always does, yet both describe a cited
  // artifact that is absent. The stamp is the only thing that tells them
  // apart, so the panels read it rather than the list position.
  vi.mocked(getReportReadiness).mockResolvedValue({
    ready: false,
    blocker_count: 1,
    blockers: [{ kind: "misfiled_advisory", severity: "advisory", detail: "Stamped advisory, delivered in blockers." }],
    advisories: [{ kind: "misfiled_blocker", severity: "block", detail: "Stamped block, delivered in advisories." }],
  } as unknown as ReportReadiness);
  render(<OverviewTab {...props} />);

  const blockers = await screen.findByRole("region", { name: "Report blockers" });
  expect(within(blockers).getByText("Stamped block, delivered in advisories.")).toBeTruthy();
  expect(within(blockers).queryByText("Stamped advisory, delivered in blockers.")).toBeNull();

  const advisories = screen.getByRole("region", { name: "Report advisories" });
  expect(within(advisories).getByText("Stamped advisory, delivered in blockers.")).toBeTruthy();
});

it("keeps an unstamped payload's items in the bucket that delivered them", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue({
    ready: false,
    blocker_count: 1,
    blockers: [{ kind: "unstamped_blocker", detail: "No severity key." }],
    advisories: [{ kind: "unstamped_advisory", detail: "Also no severity key." }],
  } as unknown as ReportReadiness);
  render(<OverviewTab {...props} />);

  const blockers = await screen.findByRole("region", { name: "Report blockers" });
  expect(within(blockers).getByText("No severity key.")).toBeTruthy();
  const advisories = screen.getByRole("region", { name: "Report advisories" });
  expect(within(advisories).getByText("Also no severity key.")).toBeTruthy();
});

it("opens with a page header naming what the page is for", async () => {
  render(<OverviewTab {...props} readinessRefreshVersion={0} />);
  expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeTruthy();
  expect(screen.getByText(/Where this engagement stands/)).toBeTruthy();
  await screen.findByTestId("readiness-panel");
});

it("re-reads report readiness only when readiness can have changed", async () => {
  const view = render(<OverviewTab {...props} readinessRefreshVersion={0} />);
  await screen.findByTestId("readiness-panel");
  expect(getReportReadiness).toHaveBeenCalledTimes(1);
  // An activity note: the activity feed refreshes, readiness does not.
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={1} readinessRefreshVersion={0} />);
  await waitFor(() => expect(listActivityFeed).toHaveBeenCalledTimes(2));
  expect(getReportReadiness).toHaveBeenCalledTimes(1);
  view.rerender(<OverviewTab {...props} assessmentRefreshVersion={2} readinessRefreshVersion={2} />);
  await waitFor(() => expect(getReportReadiness).toHaveBeenCalledTimes(2));
});

it("links each attention count to exactly the records it counts", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: false, blocker_count: 2, blockers: [{ kind: "coverage", detail: "Coverage blockers remain" }, { kind: "unreviewed_findings", slug: "finding-one" }], coverage: { blocker_count: 9, unresolved_surfaces: new Array(6).fill({}), partially_covered_surfaces: new Array(2).fill({}), high_risk_deferred_surfaces: new Array(1).fill({}) } } as unknown as ReportReadiness);
  render(<OverviewTab {...props} readinessRefreshVersion={0} assessmentSummary={{ coverage_blocker_count: 9, report_blocker_count: 2, finding_verification_statuses: { unreviewed: 3, blocked: 1, confirmed: 4 } } as unknown as AssessmentSummary} />);
  const attention = screen.getByRole("region", { name: "Needs attention" });
  expect(within(attention).getAllByRole("link").map((link) => link.textContent)).toEqual(["4 findings awaiting verification"]);
  expect(within(attention).getByRole("link", { name: /4 findings awaiting verification/ }).getAttribute("href")).toBe("#/engagements/one?tab=findings&verification=unreviewed%2Cdisputed%2Cpending_runtime_proof%2Cblocked");
  // The gate counts scroll to their causes on this page (the hash is the route).
  const blockers = await screen.findByRole("region", { name: "Report blockers" });
  const scrolled = vi.fn();
  blockers.scrollIntoView = scrolled;
  fireEvent.click(within(attention).getByRole("button", { name: /2 report blockers/ }));
  expect(scrolled).toHaveBeenCalledTimes(1);
  expect(document.activeElement).toBe(blockers);
  fireEvent.click(within(attention).getByRole("button", { name: /9 surfaces block the coverage check/ }));
  expect(scrolled).toHaveBeenCalledTimes(2);
  expect(blockers.textContent).toContain("6 discovered surfaces on hosts with active findings");
  expect(blockers.textContent).toContain("2 partially covered");
  expect(blockers.textContent).toContain("1 deferred high-risk");
});

it("queues the findings whose verification is unsettled, current findings first, with sentence-case statuses", async () => {
  const row = (slug: string, severity: string, workflow: string, verification: string) => ({ slug, title: `Claim ${slug}`, severity, workflow_status: workflow, verification_status: verification }) as AssessmentFinding;
  const findings = [
    row("settled", "critical", "active", "confirmed"),
    row("merged-high", "high", "merged", "unreviewed"),
    row("active-medium", "medium", "active", "unreviewed"),
    row("draft-high", "high", "draft", "pending_runtime_proof"),
  ];
  render(<OverviewTab {...props} findings={findings} readinessRefreshVersion={0} />);
  const queue = screen.getByRole("region", { name: "Finding queue" });
  const titles = within(queue).getAllByRole("link").filter((link) => link.textContent?.startsWith("Claim")).map((link) => link.textContent);
  expect(titles).toEqual(["Claim draft-high", "Claim active-medium", "Claim merged-high"]);
  expect(queue.textContent).toContain("3 findings awaiting verification");
  expect(queue.textContent).toContain("Pending runtime proof");
  expect(queue.textContent).toContain("Draft");
  expect(queue.textContent).not.toMatch(/\bunreviewed\b/);
  await screen.findByTestId("readiness-panel");
});

it("keeps attack-chain narratives behind a disclosure and links the findings they name", async () => {
  const chain = { chain_key: "acme-chain", title: "Acme takeover chain", status: "candidate", severity: "high", narrative: "A long narrative." };
  render(<OverviewTab {...props} readinessRefreshVersion={0} chains={[chain] as never[]} chainLinks={[{ chain_key: "acme-chain", entity_kind: "finding", entity_ref: "finding-one" }] as never[]} />);
  const section = screen.getByRole("region", { name: "Attack chains" });
  const narrative = within(section).getByText("A long narrative.").closest("details");
  expect(narrative?.open).toBe(false);
  expect(within(section).getByRole("link", { name: /finding-one/ }).getAttribute("href")).toBe("#/engagements/one?tab=findings&finding=finding-one");
  await screen.findByTestId("readiness-panel");
});

it("does not dress report-blocker kinds as high-severity findings", async () => {
  const blockers = Array.from({ length: 12 }, (_, index) => ({ kind: index < 9 ? "missing_evidence" : "unverified_claim", slug: `acme-${index}`, detail: `Blocker detail ${index}` }));
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: false, blocker_count: 12, blockers } as unknown as ReportReadiness);
  render(<OverviewTab {...props} readinessRefreshVersion={0} />);
  const panel = await screen.findByRole("region", { name: "Report blockers" });
  // Each kind reads as a plain group label with its count, not a severity tag.
  const kind = within(panel).getByText("Missing evidence");
  expect(kind.className).toBe("report-blocker-kind-label");
  expect(kind.closest("summary")?.textContent).toBe("Missing evidence9");
});

it("reads field=value blocker details as labels and keeps the raw detail on hover", async () => {
  const blockers = [
    { kind: "finding_verification_status", slug: "acme-1", detail: "verification_status=pending_runtime_proof" },
    { kind: "finding_verification_status", slug: "acme-2", detail: "verification_status=confirmed" },
    { kind: "duplicate_root_cause", slugs: ["acme-3", "acme-4"], detail: "root_cause_key=acme-tenant-selector" },
    { kind: "finding_field_quality", slug: "acme-5", detail: "missing structured fields: remediation" },
  ];
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: false, blocker_count: 4, blockers } as unknown as ReportReadiness);
  render(<OverviewTab {...props} readinessRefreshVersion={0} />);
  const panel = await screen.findByRole("region", { name: "Report blockers" });
  for (const details of panel.querySelectorAll("details")) details.open = true;
  const pending = within(panel).getByText("Verification: Pending runtime proof");
  expect(pending.getAttribute("title")).toBe("verification_status=pending_runtime_proof");
  expect(within(panel).getByText("Verification: Verified")).toBeTruthy();
  expect(within(panel).getByText("Root cause key: acme-tenant-selector")).toBeTruthy();
  expect(within(panel).getByText("missing structured fields: remediation")).toBeTruthy();
});

it("counts current findings as awaiting verification and names the merged and false-positive ones apart", () => {
  const row = (slug: string, workflow: string, verification: string) => ({ ...finding, slug, title: `Claim ${slug}`, workflow_status: workflow, verification_status: verification }) as AssessmentFinding;
  const ledger = [
    row("acme-active", "active", "unreviewed"),
    row("acme-merged", "merged", "unreviewed"),
    row("acme-dropped", "false_positive", "disputed"),
    row("acme-settled", "active", "confirmed"),
  ];
  render(<OverviewTab {...props} findings={ledger} assessmentSummary={{
    finding_verification_statuses: { unreviewed: 2, disputed: 1, confirmed: 1 },
    finding_workflow_statuses: { active: 2, merged: 1, false_positive: 1 },
  } as unknown as AssessmentSummary} />);
  // The summary counts every row; what needs the operator is the current ones.
  const link = screen.getByRole("link", { name: /findings awaiting verification/ });
  expect(link.textContent).toBe("1 findings awaiting verification");
  // The link lands on exactly those: the same verification filter, current workflows only.
  expect(new URLSearchParams(link.getAttribute("href")!.split("?")[1]).get("workflow")).toBe("active");
  const attention = link.closest("div")!;
  expect(attention.textContent).toContain("2 more are merged or false positive");
  expect(screen.getByRole("region", { name: "Finding queue" }).textContent).toContain("2 merged or false positive, listed last");
});

it("remembers the per-host matrix as collapsed or expanded only once the operator chooses", async () => {
  window.localStorage.removeItem("overview.perHostMatrix.collapsed");
  const hosts = Array.from({ length: 13 }, (_, index) => ({ host: `app${index}.example.com`, outcomes: {}, unmet_objectives: [], deferred_objectives: [], deferrals: [] }));
  vi.mocked(getReportReadiness).mockResolvedValue({ ready: true, blocker_count: 0, blockers: [], per_host_coverage: { hosts, scope_hosts: [], objectives: [], engagement_signals: {} } } as unknown as ReportReadiness);
  try {
    render(<OverviewTab {...props} />);
    const toggle = await screen.findByTestId("readiness-matrix-collapse");
    // A large matrix opens collapsed by its size alone; that default is not a stored choice,
    // so it cannot decide how another engagement's matrix opens.
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(window.localStorage.getItem("overview.perHostMatrix.collapsed")).toBeNull();
    fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-expanded")).toBe("true");
    expect(window.localStorage.getItem("overview.perHostMatrix.collapsed")).toBe("0");
  } finally {
    window.localStorage.removeItem("overview.perHostMatrix.collapsed");
  }
});

const reportQc = (over = {}) => ({
  required: true, status: "current", verdict: "pass", artifact_id: 812, sha256: "a".repeat(64), reviewed_sha256: "a".repeat(64),
  decision_id: 5471, reviewer_dispatch_agent_id: "report-writer:qc-2", writer_dispatch_agent_id: "report-writer:draft-1",
  decided_at: "2026-10-02T12:00:00Z", issue: "", ...over,
});
const ready = (over = {}) => ({ ready: true, blocker_count: 0, blockers: [], ...over }) as unknown as ReportReadiness;

it("shows the report QC standing: who reviewed which bytes, and whether that review still covers them", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue(ready({ report_qc: reportQc() }));
  const view = render(<OverviewTab {...props} />);
  const qc = await screen.findByRole("group", { name: "Report QC" });
  expect(within(qc).getByText("Passed")).toBeTruthy();
  expect(qc.textContent).toContain("verdict pass");
  expect(qc.textContent).toContain("reviewer report-writer:qc-2");
  expect(qc.textContent).toContain("writer report-writer:draft-1");
  expect(qc.textContent).toContain("decision #5471");
  // The registered bytes are named in full, with whether the review covered them.
  expect(qc.textContent).toContain(`report.md artifact #812 · sha256 ${"a".repeat(64)}`);
  expect(qc.textContent).toContain("the reviewed bytes");

  // The file changed after its review: the backend's issue is shown in its own words.
  vi.mocked(getReportReadiness).mockResolvedValue(ready({
    report_qc: reportQc({ status: "stale", reviewed_sha256: "b".repeat(64), issue: "was registered with different bytes after its QC review" }),
  }));
  view.rerender(<OverviewTab {...props} readinessRefreshVersion={1} />);
  await waitFor(() => expect(within(screen.getByRole("group", { name: "Report QC" })).getByText("Passed, now stale")).toBeTruthy());
  const stale = screen.getByRole("group", { name: "Report QC" });
  expect(stale.textContent).toContain("The registered report.md was registered with different bytes after its QC review.");
  expect(stale.textContent).toContain(`reviewed sha256 ${"b".repeat(64)}`);
});

it("says a registered report has no QC verdict, and that an unregistered one owes none", async () => {
  vi.mocked(getReportReadiness).mockResolvedValue(ready({
    report_qc: reportQc({
      status: "missing", verdict: null, reviewed_sha256: null, decision_id: null, reviewer_dispatch_agent_id: null,
      writer_dispatch_agent_id: null, decided_at: null, issue: "has no passing independent report-writer QC verdict",
    }),
  }));
  const view = render(<OverviewTab {...props} />);
  const qc = await screen.findByRole("group", { name: "Report QC" });
  expect(within(qc).getByText("No verdict recorded")).toBeTruthy();
  expect(qc.textContent).toContain("The registered report.md has no passing independent report-writer QC verdict.");
  expect(qc.textContent).not.toContain("reviewer");

  vi.mocked(getReportReadiness).mockResolvedValue(ready({
    report_qc: reportQc({
      required: false, status: "missing", verdict: null, artifact_id: null, sha256: null, reviewed_sha256: null, decision_id: null,
      reviewer_dispatch_agent_id: null, writer_dispatch_agent_id: null, decided_at: null,
    }),
  }));
  view.rerender(<OverviewTab {...props} readinessRefreshVersion={1} />);
  await waitFor(() => expect(screen.getByRole("group", { name: "Report QC" }).textContent).toContain("No report.md is registered, so no report QC is owed yet."));
  expect(within(screen.getByRole("group", { name: "Report QC" })).queryByText("No verdict recorded")).toBeNull();
});

it("says nothing about report QC when the readiness read carries no standing", async () => {
  render(<OverviewTab {...props} />);
  await screen.findByTestId("readiness-panel");
  expect(screen.queryByRole("group", { name: "Report QC" })).toBeNull();
});

it("says whether a WAF fronts each host whose WAF tier was measured, and names measurements that were ignored", async () => {
  window.localStorage.setItem("overview.perHostMatrix.collapsed", "0");
  const outcome = (met: boolean, extra = {}) => ({ met, evidence: [], deferred: false, ...extra });
  const host = (name: string, waf: Record<string, unknown>) => ({
    host: name, outcomes: { waf_tier: waf, osint: outcome(true) }, unmet_objectives: [], deferred_objectives: [], deferrals: [],
  });
  vi.mocked(getReportReadiness).mockResolvedValue(ready({
    per_host_coverage: {
      objectives: ["waf_tier", "osint"],
      scope_hosts: [],
      hosts: [
        host("shop.acme.example", outcome(true, { waf_detected: true, evidence: ["detected: Acme Edge WAF (intel #41, run #7)(host)"] })),
        host("api.acme.example", outcome(true, { waf_detected: false, evidence: ["none_detected: wafw00f sweep (intel #42, run #8)(host)"] })),
        host("old.acme.example", outcome(false, { waf_detected: false })),
      ],
      engagement_signals: {
        waf_intel_count: 0, waf_measurement_count: 2, tech_scan_intel_count: 3, osint_intel_total: 4,
        waf_measurements_ignored: [{ intel_id: 43, problem: "provenance.waf.hosts must list each measured host (non-empty strings)" }],
      },
    },
  }));
  try {
    render(<OverviewTab {...props} />);
    const cell = async (name: string) => (await screen.findByTestId(`readiness-cell-${name}-waf_tier`)).closest("td")!;
    expect((await cell("shop.acme.example")).textContent).toBe("YWAF detected");
    // A measured negative is met, and says no WAF was found rather than reading as one.
    expect((await cell("api.acme.example")).textContent).toBe("YNo WAF detected");
    // An unmeasured host has no verdict to show.
    expect((await cell("old.acme.example")).textContent).toBe("N");
    // Other objectives carry no WAF verdict.
    expect(screen.getByTestId("readiness-cell-shop.acme.example-osint").closest("td")!.textContent).toBe("Y");

    expect(within(screen.getByTestId("readiness-signal-waf_measurement_count")).getByText("2")).toBeTruthy();
    const ignored = screen.getByRole("group", { name: "Ignored WAF measurements" });
    expect(ignored.textContent).toContain("1 WAF measurement is ignored");
    expect(ignored.textContent).toContain("provenance.waf.hosts must list each measured host (non-empty strings)");
    expect(within(ignored).getByRole("link", { name: "Tech stack record #43" }).getAttribute("href")).toBe("#/engagements/one?tab=intel&intel_type=tech_component&intel_id=43");
  } finally {
    window.localStorage.removeItem("overview.perHostMatrix.collapsed");
  }
});

it("says the engagement summary could not be read instead of loading forever", () => {
  const view = render(<OverviewTab {...props} summaryLoadError="summary read failed (500)" />);
  const attention = screen.getByRole("heading", { name: "Needs attention" }).closest("section")!;
  expect(within(attention).getByRole("alert").textContent).toContain("summary read failed (500)");
  expect(within(attention).queryByRole("status", { name: "Loading engagement summary" })).toBeNull();
  // Still loading (no failure reported): the placeholder stays.
  view.rerender(<OverviewTab {...props} />);
  expect(within(attention).getByRole("status", { name: "Loading engagement summary" })).toBeTruthy();
});

it("says the awaiting-verification figure includes merged and false-positive findings until the ledger can split it", () => {
  const summary = { finding_verification_statuses: { unreviewed: 5 }, finding_workflow_statuses: { active: 2, merged: 3 } } as unknown as AssessmentSummary;
  // While the ledger loads the page holds only the summary's top findings, which cannot say how many are retired.
  const view = render(<OverviewTab {...props} findingsLoading assessmentSummary={summary} />);
  const attention = () => screen.getByRole("heading", { name: "Needs attention" }).closest("section")!;
  expect(attention().textContent).toContain("5 findings awaiting verification");
  expect(attention().textContent).toContain("merged and false-positive findings included until the finding ledger loads");
  view.rerender(<OverviewTab {...props} findingsLoadError="ledger down" assessmentSummary={summary} />);
  expect(attention().textContent).toContain("merged and false-positive findings included; the finding ledger could not be read");
  // With the ledger on screen the figure is the current findings and needs no caveat.
  view.rerender(<OverviewTab {...props} assessmentSummary={summary} />);
  expect(attention().textContent).not.toContain("included");
});
