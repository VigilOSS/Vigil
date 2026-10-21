// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode, useEffect, useState, type ReactNode } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as api from "../lib/api";
import * as commandsApi from "../lib/commandsApi";
import * as submissionsApi from "../lib/submissionsApi";
import { EngagementPage } from "./EngagementPage";

vi.mock("../contexts/ToastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock("../components/OverviewTab", () => ({ OverviewTab: ({ findings, findingsLoading, findingsLoadError }: { findings: api.AssessmentFinding[]; findingsLoading?: boolean; findingsLoadError?: string | null }) => <div>{findingsLoading && <span>Finding ledger loading</span>}{findingsLoadError && <span>Finding ledger unavailable: {findingsLoadError}</span>}{findings.map(f => <span key={f.slug}>{f.title}</span>)}</div> }));
vi.mock("../components/CodeAnalysisTab", () => ({ CodeAnalysisTab: ({ persistedPhase }: { persistedPhase: string }) => <div>Code phase: {persistedPhase}</div> }));
vi.mock("../components/FindingsTab", () => ({ FindingsTab: ({ renderRuntimeProof }: { renderRuntimeProof?: (finding: { slug: string }) => ReactNode }) => <div>Finding ledger{renderRuntimeProof?.({ slug: "acme-proof" })}</div> }));
vi.mock("../components/FindingRuntimeProof", () => ({ FindingRuntimeProof: ({ slug, refreshVersion }: { slug: string; refreshVersion?: number }) => <div>Runtime proof {slug} refresh {refreshVersion}</div> }));
vi.mock("../components/RunsTab", async () => {
  const { useEffect } = await vi.importActual<typeof import("react")>("react");
  return { RunsTab: ({ refreshVersion, onHealthCounts }: { refreshVersion?: number; onHealthCounts?: (counts: { healthy: number; attention: number; failed: number; running: number }) => void }) => {
    useEffect(() => { onHealthCounts?.({ healthy: 5, attention: 2, failed: 1, running: 0 }); }, [onHealthCounts]);
    return <div>Runs refresh {refreshVersion}</div>;
  } };
});
vi.mock("../components/CommandsTab", async () => {
  const { useEffect } = await vi.importActual<typeof import("react")>("react");
  return { CommandsTab: ({ refreshVersion, commandId, onAttentionCount }: { refreshVersion?: number; commandId?: number; onAttentionCount?: (count: number) => void }) => {
    useEffect(() => { onAttentionCount?.(11); }, [onAttentionCount]);
    return <div>Commands refresh {refreshVersion}{commandId ? ` command ${commandId}` : ""}</div>;
  } };
});
vi.mock("../components/OastTab", async () => {
  const { useEffect } = await vi.importActual<typeof import("react")>("react");
  return { OastTab: ({ onToReviewCount }: { onToReviewCount?: (count: number) => void }) => {
    useEffect(() => { onToReviewCount?.(4); }, [onToReviewCount]);
    return <div>OAST probes</div>;
  } };
});
vi.mock("../components/SubmissionsTab", async () => {
  const { useEffect } = await vi.importActual<typeof import("react")>("react");
  return { SubmissionsTab: ({ onToDoCount }: { onToDoCount?: (count: number) => void }) => {
    useEffect(() => { onToDoCount?.(8); }, [onToDoCount]);
    return <div>Submission desk</div>;
  } };
});
vi.mock("../components/CoverageTab", () => ({ CoverageTab: () => <div>Coverage ledger</div> }));
vi.mock("../components/SurfacesTab", () => ({ SurfacesTab: ({ surfaces, findings, snapshotLimit }: { surfaces: api.AssessmentSurface[] | null; findings?: api.AssessmentFinding[]; snapshotLimit?: number }) => <div>Surfaces {surfaces === null ? "loading" : `${surfaces.length} loaded`} (limit {snapshotLimit ?? "unset"}){findings?.map((f) => <span key={f.slug}>Linked {f.title}</span>)}</div> }));
vi.mock("../components/ActivityTab", () => ({ ActivityTab: ({ refreshVersion }: { refreshVersion?: number }) => <div>Activity refresh {refreshVersion}</div> }));
vi.mock("../components/FilesTab", () => ({ FilesTab: ({ refreshVersion }: { refreshVersion?: number }) => <div>Files refresh {refreshVersion}</div> }));
vi.mock("../components/ProofWorkTab", async () => {
  const { useEffect } = await vi.importActual<typeof import("react")>("react");
  return { ProofWorkTab: ({ workId, onQueueCounts }: { workId?: number; onQueueCounts?: (counts: { queue_state_counts?: Record<string, number>; reverification_count: number; needs_attention: number }) => void }) => {
    useEffect(() => { onQueueCounts?.({ queue_state_counts: { needs_approval: 2, stale: 1, ready: 3 }, reverification_count: 0, needs_attention: 2 }); }, [onQueueCounts]);
    return <div>Proof work{workId ? ` item ${workId}` : ""}</div>;
  } };
});
vi.mock("../lib/commandsApi", async (importOriginal) => ({ ...(await importOriginal<typeof commandsApi>()), fetchCommandFacets: vi.fn() }));
vi.mock("../lib/submissionsApi", async (importOriginal) => ({ ...(await importOriginal<typeof submissionsApi>()), listSubmissionDesk: vi.fn() }));
vi.mock("../lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof api>();
  return { ...original, getEngagement: vi.fn(), getAssessmentSummary: vi.fn(), getIntelSummary: vi.fn(), listIntel: vi.fn(), listIntelCredentials: vi.fn(), getIntelReadiness: vi.fn(), listAssessmentFindings: vi.fn(), listAssessmentFindingSummaries: vi.fn(), listAssessmentRuns: vi.fn(), listSurfaces: vi.fn(), listAssessmentAttackChains: vi.fn(), listAssessmentAttackChainLinks: vi.fn(), listProofWork: vi.fn(), listOobProbes: vi.fn(), getCodeQueueStats: vi.fn() };
});
// The engagement's target name in the workspace header (the open view's title is the page heading).
const targetName = (name: string) => screen.findByText(name, { selector: ".workspace-header .workspace-target" });

const engagement = { id: 1, key: "one", target: "Target one", status: "in_progress", current_phase: "exploit", code_phase: null, track_state: { web: { phase: "exploit", complete: false } }, aggregate_complete: false, engagement_root: "/tmp/one", exploit_policy: "pause", exploit_review_state: "not_requested", approved_targets: [], created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z", session_count: 0 } satisfies api.Engagement;

beforeEach(() => {
  vi.stubGlobal("WebSocket", class { close() {} });
  vi.mocked(api.getEngagement).mockResolvedValue(engagement);
  vi.mocked(api.getAssessmentSummary).mockResolvedValue({ top_findings: [], attack_chains: [] } as unknown as api.AssessmentSummary);
  vi.mocked(api.getIntelSummary).mockResolvedValue({ counts: {} } as api.IntelSummary);
  vi.mocked(api.listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: 0, items: [] }));
  vi.mocked(api.listIntelCredentials).mockResolvedValue([]);
  vi.mocked(api.getIntelReadiness).mockResolvedValue({ applicable: true, engagement_type: "red", open_high_cves: [], open_leads: [], exploited_unlinked_cves: [], dangling_links: [] });
  vi.mocked(api.listAssessmentFindings).mockResolvedValue([{ slug: "one", title: "Finding one" } as api.AssessmentFindingDetail]);
  // The lean rows are the same ledger without `details`; tests steer both through the ledger mock.
  vi.mocked(api.listAssessmentFindingSummaries).mockImplementation((key) => api.listAssessmentFindings(key));
  vi.mocked(api.listAssessmentRuns).mockResolvedValue([]);
  vi.mocked(api.listAssessmentAttackChains).mockResolvedValue([]);
  vi.mocked(api.listAssessmentAttackChainLinks).mockResolvedValue([]);
  vi.mocked(api.listProofWork).mockResolvedValue({ owed: [], items: [], reverification_required: [], queue_state_counts: {} } as unknown as api.ProofWorkList);
  vi.mocked(api.listOobProbes).mockResolvedValue([]);
  vi.mocked(api.getCodeQueueStats).mockResolvedValue({ pending: 0, processing: 0, done: 0, error: 0, needs_context: 0, total: 0 } as api.CodeQueueStats);
  vi.mocked(submissionsApi.listSubmissionDesk).mockResolvedValue({ counts: { actionable: 0 } } as unknown as Awaited<ReturnType<typeof submissionsApi.listSubmissionDesk>>);
  vi.mocked(commandsApi.fetchCommandFacets).mockResolvedValue({ total: 0, scope_totals: { attention: 0, all: 0 }, engagement_totals: { attention: 0, all: 0 } } as unknown as commandsApi.CommandLedgerFacets);
});
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.unstubAllGlobals(); });

it("keeps the Intel route authoritative through a native Back and Forward handoff", async () => {
  window.history.replaceState({}, "", "#/engagements/one?tab=intel&intel_type=cve&intel_id=44");
  vi.mocked(api.getIntelSummary).mockResolvedValue({ counts: { cves: 1 } } as api.IntelSummary);
  const record: api.IntelCve = {
    id: 44, engagement_id: 1, source_name: "recorded", notes: "", provenance: {},
    superseded_by_id: null, superseded_at: null, canonical_id: 44,
    created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z",
    cve_id: "CVE-2026-4444", affected_component: "", affected_version_range: "",
    cvss_score: null, cvss_vector: "", cwe_id: "", poc_available: false,
    validation_status: "unverified", linked_finding_slug: "",
  };
  vi.mocked(api.listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: entityType === "cve" ? 1 : 0, items: entityType === "cve" ? [record] : [] }));
  function HistoryWorkspace() {
    const [hash, setHash] = useState(window.location.hash);
    useEffect(() => {
      const sync = () => setHash(window.location.hash);
      window.addEventListener("hashchange", sync);
      window.addEventListener("popstate", sync);
      return () => { window.removeEventListener("hashchange", sync); window.removeEventListener("popstate", sync); };
    }, []);
    const params = new URLSearchParams(hash.split("?")[1]);
    return <EngagementPage engagementKey="one" onBack={() => {}} initialTab="intel" initialIntelType={params.get("intel_type") ?? undefined} initialIntelId={params.has("intel_id") ? Number(params.get("intel_id")) : undefined} />;
  }
  render(<HistoryWorkspace />);
  // The first mount of the real Intel view in this file is its slowest render.
  const view = await screen.findByRole("region", { name: "Intel record" }, { timeout: 5000 });
  expect(within(view).getByRole("heading", { level: 2, name: "CVE-2026-4444" })).toBeTruthy();
  fireEvent.click(within(view).getByRole("button", { name: "Back to results" }));
  await waitFor(() => expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull());
  expect(window.location.hash).toBe("#/engagements/one?tab=intel");
  fireEvent.keyDown(document.body, { key: "k", metaKey: true });
  expect(screen.getByRole("dialog", { name: "Jump to intel" })).toBeTruthy();
  window.history.back();
  expect(await screen.findByRole("region", { name: "Intel record" })).toBeTruthy();
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull());
  window.history.forward();
  await waitFor(() => expect(window.location.hash).toBe("#/engagements/one?tab=intel"));
  await waitFor(() => expect(screen.queryByRole("region", { name: "Intel record" })).toBeNull());
  expect(document.body.classList.contains("detail-modal-open")).toBe(false);
});

it("preserves the last good engagement and ledger while a refresh fails", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  vi.mocked(api.getEngagement).mockRejectedValueOnce(new Error("temporarily unavailable"));
  fireEvent(document, new Event("visibilitychange"));
  await screen.findByText(/temporarily unavailable/);
  expect(await targetName("Target one")).toBeTruthy();
  expect(screen.getByText("Finding one")).toBeTruthy();
});

it("degrades the live feed when a malformed WebSocket frame arrives", async () => {
  class ControlledSocket {
    static instance: ControlledSocket;
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onmessage: ((message: MessageEvent) => void) | null = null;
    close = vi.fn();
    constructor() { ControlledSocket.instance = this; }
  }
  vi.stubGlobal("WebSocket", ControlledSocket);
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await targetName("Target one");

  act(() => {
    ControlledSocket.instance.onopen?.();
    ControlledSocket.instance.onmessage?.(
      new MessageEvent("message", { data: "not-json" }),
    );
  });

  expect(ControlledSocket.instance.close).toHaveBeenCalledOnce();
  expect(await screen.findByText(/Live updates unavailable/)).toBeTruthy();
});

it("does not offer a remediation route owned by the assessment engagement", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await targetName("Target one");
  expect(screen.queryByRole("link", { name: "Remediation" })).toBeNull();
});

it("keeps independent enabled-track phases visible in the header outside overview", async () => {
  vi.mocked(api.getEngagement).mockResolvedValue({ ...engagement, track_state: { web: { phase: "consume-test", complete: true }, code: { phase: "fuzz", complete: false, repair_required: true } } });
  render(<EngagementPage engagementKey="one" initialTab="findings" onBack={vi.fn()} />);
  const tracks = await screen.findByRole("list", { name: "Enabled track status" });
  expect(within(tracks).getByText("web: consume-test")).toBeTruthy();
  expect(within(tracks).getByText("code: fuzz")).toBeTruthy();
  expect(within(tracks).getByText("Complete")).toBeTruthy();
  expect(within(tracks).getByText("Repair required")).toBeTruthy();
  expect(within(tracks).queryByText(/exploit/)).toBeNull();
});

it("does not fabricate a header track from the legacy phase", async () => {
  vi.mocked(api.getEngagement).mockResolvedValue({ ...engagement, track_state: undefined });
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await targetName("Target one");
  expect(screen.getByText("Track state unavailable")).toBeTruthy();
  expect(screen.queryByRole("list", { name: "Enabled track status" })).toBeNull();
});

it("labels filtered summary badges separately from the complete ledgers they open", async () => {
  vi.mocked(api.getAssessmentSummary).mockResolvedValue({ finding_count: 2, open_surface_count: 3, top_findings: [], attack_chains: [] } as unknown as api.AssessmentSummary);
  vi.mocked(api.listAssessmentFindings).mockResolvedValue([
    { slug: "one", title: "Finding one", workflow_status: "draft" },
    { slug: "two", title: "Finding two", workflow_status: "submitted" },
    { slug: "three", title: "False-positive record", workflow_status: "false_positive" },
  ] as api.AssessmentFindingDetail[]);
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  expect(await screen.findByRole("tab", { name: /^Findings 2 current findings/ })).toBeTruthy();
  expect(screen.getByRole("tab", { name: /^Surfaces 3 open attack surfaces/ })).toBeTruthy();
  expect(await screen.findByText("False-positive record")).toBeTruthy();
});

it("labels a loaded finding fallback without implying a filtered current count", async () => {
  vi.mocked(api.getAssessmentSummary).mockRejectedValue(new Error("summary unavailable"));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  expect(await screen.findByRole("tab", { name: /^Findings 1 finding loaded/ })).toBeTruthy();
});

it("keeps the overview ledger loading state separate from the available summary", async () => {
  vi.mocked(api.listAssessmentFindings).mockReturnValueOnce(new Promise(() => {}));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await targetName("Target one");
  expect(screen.getByText("Finding ledger loading")).toBeTruthy();
});

it("passes a finding-ledger failure to overview without treating it as empty", async () => {
  vi.mocked(api.listAssessmentFindings).mockRejectedValueOnce(new Error("ledger request failed"));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  expect(await screen.findByText("Finding ledger unavailable: ledger request failed")).toBeTruthy();
});

it("renders the Files view for the files tab and passes live refreshes", async () => {
  render(<EngagementPage engagementKey="one" initialTab="artifacts" onBack={vi.fn()} />);
  expect((await screen.findByRole("tab", { name: "Files" })).getAttribute("aria-selected")).toBe("true");
  const before = Number((await screen.findByText(/Files refresh/)).textContent?.replace(/\D+/g, ""));
  fireEvent(document, new Event("visibilitychange"));
  await waitFor(() => expect(Number(screen.getByText(/Files refresh/).textContent?.replace(/\D+/g, ""))).toBeGreaterThan(before));
});

it("clears all prior engagement data before the next identity finishes loading", async () => {
  const view = render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  vi.mocked(api.getEngagement).mockReturnValueOnce(new Promise(() => {}));
  view.rerender(<EngagementPage engagementKey="two" onBack={vi.fn()} />);
  await waitFor(() => expect(screen.queryByText("Finding one")).toBeNull());
  expect(screen.queryByText("Target one")).toBeNull();
  expect(screen.getByText("Engagement lifecycle")).toBeTruthy();
});

it("never borrows the web phase for the code track", async () => {
  render(<EngagementPage engagementKey="one" initialTab="code" onBack={vi.fn()} />);
  await screen.findByText("Code phase: unknown");
  expect(screen.queryByText("Code phase: exploit")).toBeNull();
});

it("does not carry the previous finding ledger into a newly loaded engagement", async () => {
  const view = render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  vi.mocked(api.getEngagement).mockResolvedValueOnce({ ...engagement, key: "two", target: "Target two" });
  vi.mocked(api.listAssessmentFindings).mockReturnValueOnce(new Promise(() => {}));
  view.rerender(<EngagementPage engagementKey="two" onBack={vi.fn()} />);
  await targetName("Target two");
  expect(screen.queryByText("Finding one")).toBeNull();
});

it("switches tabs without a full page refresh", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  await waitFor(() => expect(api.getAssessmentSummary).toHaveBeenCalledTimes(1));
  fireEvent.click(screen.getByRole("tab", { name: /^Coverage/ }));
  await screen.findByText("Coverage ledger");
  fireEvent.click(screen.getByRole("tab", { name: /^Runs/ }));
  await screen.findByText(/Runs refresh/);
  expect(api.getEngagement).toHaveBeenCalledTimes(1);
  expect(api.getAssessmentSummary).toHaveBeenCalledTimes(1);
  expect(api.getIntelReadiness).toHaveBeenCalledTimes(1);
  expect(api.listProofWork).toHaveBeenCalledTimes(1);
});

it("delivers tab refreshes while a slow assessment summary is still loading", async () => {
  vi.mocked(api.getAssessmentSummary).mockReturnValue(new Promise(() => {}));
  render(<EngagementPage engagementKey="one" initialTab="runs" onBack={vi.fn()} />);
  await screen.findByText(/Runs refresh/);
  const before = Number(screen.getByText(/Runs refresh/).textContent?.replace(/\D+/g, ""));
  fireEvent(document, new Event("visibilitychange"));
  await waitFor(() => {
    const after = Number(screen.getByText(/Runs refresh/).textContent?.replace(/\D+/g, ""));
    expect(after).toBeGreaterThan(before);
  });
  expect(api.getAssessmentSummary).toHaveBeenCalledTimes(1);
});

it("loads the intel type counts only for the Intel view", async () => {
  render(<EngagementPage engagementKey="one" initialTab="runs" onBack={vi.fn()} />);
  await screen.findByText(/Runs refresh/);
  await waitFor(() => expect(api.getIntelReadiness).toHaveBeenCalledTimes(1));
  expect(api.getIntelSummary).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("tab", { name: /^Intel/ }));
  await waitFor(() => expect(api.getIntelSummary).toHaveBeenCalledTimes(1));
});

it("runs the mount refresh once under StrictMode", async () => {
  render(<StrictMode><EngagementPage engagementKey="one" onBack={vi.fn()} /></StrictMode>);
  await screen.findByText("Finding one");
  await waitFor(() => expect(api.getAssessmentSummary).toHaveBeenCalledTimes(1));
  expect(api.getEngagement).toHaveBeenCalledTimes(1);
  expect(api.listAssessmentFindingSummaries).toHaveBeenCalledTimes(1);
  expect(api.listAssessmentAttackChains).toHaveBeenCalledTimes(1);
});

it("opens a bookmarked audit-log link on the Activity view", async () => {
  render(<EngagementPage engagementKey="one" initialTab="log" onBack={vi.fn()} />);
  expect((await screen.findByRole("tab", { name: "Activity" })).getAttribute("aria-selected")).toBe("true");
  expect(await screen.findByText(/Activity refresh/)).toBeTruthy();
});

it("passes proof-work and command deep links to their views", async () => {
  const view = render(<EngagementPage engagementKey="one" initialTab="proof" initialWorkId={9} onBack={vi.fn()} />);
  expect(await screen.findByText("Proof work item 9")).toBeTruthy();
  view.rerender(<EngagementPage engagementKey="one" initialTab="commands" initialCommandId={77} onBack={vi.fn()} />);
  expect(await screen.findByText(/command 77/)).toBeTruthy();
});

it("badges each view with what needs action", async () => {
  vi.mocked(api.getEngagement).mockResolvedValue({ ...engagement, engagement_type: "both", track_state: { web: { phase: "exploit", complete: false }, code: { phase: "hunt", complete: false } } });
  vi.mocked(api.getAssessmentSummary).mockResolvedValue({ finding_count: 2, open_surface_count: 3, coverage_statuses: { blocked: 4, covered: 9, pending: 1 }, top_findings: [], attack_chains: [] } as unknown as api.AssessmentSummary);
  // Three parked findings hold ten work items; two findings and one re-verification need the operator.
  vi.mocked(api.listProofWork).mockResolvedValue({
    owed: [{ finding_slug: "a", queue_state: "unprepared" }, { finding_slug: "b", queue_state: "needs_approval" }, { finding_slug: "c", queue_state: "ready" }],
    items: [], reverification_required: [{ finding_id: 1 }], queue_state_counts: { unprepared: 2, needs_approval: 3, ready: 5 },
  } as unknown as api.ProofWorkList);
  vi.mocked(submissionsApi.listSubmissionDesk).mockResolvedValue({ counts: { actionable: 6 } } as unknown as Awaited<ReturnType<typeof submissionsApi.listSubmissionDesk>>);
  vi.mocked(api.getIntelReadiness).mockResolvedValue({ applicable: true, engagement_type: "both", open_high_cves: [], open_leads: [{ id: 1, title: "Lead", lead_status: "open" }], exploited_unlinked_cves: [], dangling_links: [] } as unknown as api.IntelReadiness);
  vi.mocked(api.getCodeQueueStats).mockResolvedValue({ pending: 3, processing: 1, done: 8, error: 0, needs_context: 1, total: 13 } as api.CodeQueueStats);
  vi.mocked(api.listOobProbes).mockResolvedValue([{ status: "fired" }, { status: "fired" }] as api.OobProbe[]);
  vi.mocked(commandsApi.fetchCommandFacets).mockResolvedValue({ total: 12, scope_totals: { attention: 7, all: 12 }, engagement_totals: { attention: 7, all: 12 } } as unknown as commandsApi.CommandLedgerFacets);
  render(<EngagementPage engagementKey="one" initialTab="runs" onBack={vi.fn()} />);
  const badge = (name: string) => screen.getByRole("tab", { name: new RegExp(`^${name}`) }).querySelector("[aria-hidden='true']")?.textContent ?? null;
  await waitFor(() => expect(badge("OAST")).toBe("2 attention"));
  expect(listSubmissionsCall()).toEqual(["one", { findingLimit: 1 }]);
  expect(api.listOobProbes).toHaveBeenCalledWith("one", "fired");
  expect(badge("Findings")).toBe("2 current");
  // The Proof work page's own "needs attention" count, one per finding.
  expect(badge("Proof work")).toBe("3 attention");
  expect(badge("Submissions")).toBe("6 attention");
  expect(badge("Intel")).toBe("1 open");
  expect(badge("Surfaces")).toBe("3 open");
  expect(badge("Coverage")).toBe("5 open");
  expect(badge("Code")).toBe("5 open");
  await waitFor(() => expect(badge("Runs")).toBe("3 attention"));
  await waitFor(() => expect(badge("Commands")).toBe("7 attention"));
  expect(vi.mocked(commandsApi.fetchCommandFacets).mock.calls[0]?.slice(1)).toEqual([commandsApi.DEFAULT_COMMAND_FILTERS, 1]);
});

it("keeps refreshing after StrictMode's repeated mount", async () => {
  render(<StrictMode><EngagementPage engagementKey="one" initialTab="runs" onBack={vi.fn()} /></StrictMode>);
  await screen.findByText(/Runs refresh/);
  await waitFor(() => expect(api.getEngagement).toHaveBeenCalledTimes(1));
  fireEvent(document, new Event("visibilitychange"));
  await waitFor(() => expect(api.getEngagement).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(screen.getByText(/Runs refresh/).textContent).toBe("Runs refresh 1"));
});

it("embeds the finding's runtime proof in the Findings view with live refreshes", async () => {
  render(<EngagementPage engagementKey="one" initialTab="findings" onBack={vi.fn()} />);
  expect(await screen.findByText("Runtime proof acme-proof refresh 0")).toBeTruthy();
  fireEvent(document, new Event("visibilitychange"));
  expect(await screen.findByText("Runtime proof acme-proof refresh 1")).toBeTruthy();
});

it("keeps the open view's own badge, and the Runs badge without a visit", async () => {
  vi.mocked(api.listProofWork).mockResolvedValue({ owed: [], items: [], reverification_required: [], queue_state_counts: { needs_approval: 2 } } as unknown as api.ProofWorkList);
  vi.mocked(api.listAssessmentRuns).mockResolvedValue([
    { id: 1, status: "failed", blockers: [] },
    { id: 2, status: "completed", blockers: [{ code: "unresolved_obligation" }] },
    { id: 3, status: "completed", blockers: [] },
  ] as unknown as api.AssessmentRun[]);
  render(<EngagementPage engagementKey="one" initialTab="proof" initialWorkId={3} onBack={vi.fn()} />);
  await screen.findByText("Proof work item 3");
  const badge = (name: string) => screen.getByRole("tab", { name: new RegExp(`^${name}`) }).querySelector("[aria-hidden='true']")?.textContent ?? null;
  await waitFor(() => expect(badge("Proof work")).toBe("2 attention"));
  await waitFor(() => expect(badge("Runs")).toBe("2 attention"));
  // The open view's own read feeds its badge; the page does not repeat it.
  expect(api.listProofWork).not.toHaveBeenCalled();
});

it("takes the badge of an open OAST, Submissions or Commands view from the view itself", async () => {
  const badge = (name: string) => screen.getByRole("tab", { name: new RegExp(`^${name}`) }).querySelector("[aria-hidden='true']")?.textContent ?? null;
  const cases = [
    { tab: "oast", name: "OAST", text: "4 attention", read: () => vi.mocked(api.listOobProbes).mock.calls.filter((call) => call[1] === "fired") },
    { tab: "submissions", name: "Submissions", text: "8 attention", read: () => vi.mocked(submissionsApi.listSubmissionDesk).mock.calls },
    { tab: "commands", name: "Commands", text: "11 attention", read: () => vi.mocked(commandsApi.fetchCommandFacets).mock.calls },
  ] as const;
  for (const { tab, name, text, read } of cases) {
    vi.clearAllMocks();
    const view = render(<EngagementPage engagementKey="one" initialTab={tab} onBack={vi.fn()} />);
    await waitFor(() => expect(badge(name)).toBe(text));
    // The other views' badges load, so the page has finished its badge pass.
    await waitFor(() => expect(api.listProofWork).toHaveBeenCalled());
    expect(read()).toEqual([]);
    view.unmount();
  }
});

function listSubmissionsCall() {
  return vi.mocked(submissionsApi.listSubmissionDesk).mock.calls[0];
}

it("does not read the code queue for an engagement without a code track", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  await waitFor(() => expect(api.listOobProbes).toHaveBeenCalled());
  expect(api.getCodeQueueStats).not.toHaveBeenCalled();
});

it("passes live refreshes to the Commands view", async () => {
  render(<EngagementPage engagementKey="one" initialTab="commands" onBack={vi.fn()} />);
  const view = await screen.findByText(/Commands refresh/);
  const before = Number(view.textContent?.replace(/\D+/g, ""));
  fireEvent(document, new Event("visibilitychange"));
  await waitFor(() => expect(Number(screen.getByText(/Commands refresh/).textContent?.replace(/\D+/g, ""))).toBeGreaterThan(before));
});

it("reports a dropped live feed separately from a failed data refresh", async () => {
  class ControlledSocket {
    static instance: ControlledSocket;
    onopen: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onclose: (() => void) | null = null;
    onmessage: ((message: MessageEvent) => void) | null = null;
    close = vi.fn();
    constructor() { ControlledSocket.instance = this; }
  }
  vi.stubGlobal("WebSocket", ControlledSocket);
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  act(() => { ControlledSocket.instance.onerror?.(); });
  const live = await screen.findByText(/Live updates unavailable/);
  expect(live.textContent).not.toMatch(/Refresh failed/);
  vi.mocked(api.getAssessmentSummary).mockRejectedValueOnce(new Error("summary offline"));
  fireEvent(document, new Event("visibilitychange"));
  const failure = await screen.findByText(/summary offline/);
  expect(failure).not.toBe(live);
  expect(screen.getByText(/Live updates unavailable/)).toBeTruthy();
});

class LiveSocket {
  static instance: LiveSocket;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onmessage: ((message: MessageEvent) => void) | null = null;
  close = vi.fn();
  constructor() { LiveSocket.instance = this; }
  send(payload: unknown) {
    act(() => { this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(payload) })); });
  }
}

it("re-reads only the data a live change can touch", async () => {
  vi.stubGlobal("WebSocket", LiveSocket);
  render(<EngagementPage engagementKey="one" initialTab="findings" onBack={vi.fn()} />);
  await screen.findByText("Finding ledger");
  await waitFor(() => expect(api.listAssessmentFindings).toHaveBeenCalledTimes(1));
  act(() => { LiveSocket.instance.onopen?.(); });
  LiveSocket.instance.send({ type: "activity.updated", engagement_key: "one", record_type: "activity_entry", payload: {} });
  await waitFor(() => expect(api.getEngagement).toHaveBeenCalledTimes(2));
  expect(api.listAssessmentFindings).toHaveBeenCalledTimes(1);
  expect(api.listAssessmentAttackChains).toHaveBeenCalledTimes(1);
  expect(api.listProofWork).toHaveBeenCalledTimes(1);
  // Past the 2 s message throttle, a finding change re-reads the ledger and its badges.
  await new Promise((resolve) => setTimeout(resolve, 2100));
  LiveSocket.instance.send({ type: "assessment.updated", engagement_key: "one", record_type: "finding_patch", payload: {} });
  await waitFor(() => expect(api.listAssessmentFindings).toHaveBeenCalledTimes(2));
  expect(api.listAssessmentAttackChains).toHaveBeenCalledTimes(2);
  expect(api.listOobProbes).toHaveBeenCalledTimes(1);
}, 10_000);

it("gives Overview the lean finding rows instead of the full ledger", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  expect(api.listAssessmentFindingSummaries).toHaveBeenCalledTimes(1);
  expect(vi.mocked(api.listAssessmentFindings).mock.calls.length).toBe(1);
  // Returning to Overview with nothing changed reads nothing again.
  fireEvent.click(screen.getByRole("tab", { name: /^Activity/ }));
  await screen.findByText(/Activity refresh/);
  fireEvent.click(screen.getByRole("tab", { name: /^Overview/ }));
  await screen.findByText("Finding one");
  expect(api.listAssessmentFindingSummaries).toHaveBeenCalledTimes(1);
});

it("resolves linked finding titles on Surfaces without visiting Findings", async () => {
  vi.mocked(api.listSurfaces).mockResolvedValue([]);
  render(<EngagementPage engagementKey="one" initialTab="surfaces" onBack={vi.fn()} />);
  expect(await screen.findByText("Linked Finding one")).toBeTruthy();
  expect(api.listAssessmentFindingSummaries).toHaveBeenCalledTimes(1);
});

it("tells Surfaces its ledger is still loading rather than empty", async () => {
  let resolveSurfaces: (rows: api.AssessmentSurface[]) => void = () => {};
  vi.mocked(api.listSurfaces).mockReturnValue(new Promise((resolve) => { resolveSurfaces = resolve; }));
  render(<EngagementPage engagementKey="one" initialTab="surfaces" onBack={vi.fn()} />);
  expect(await screen.findByText(/Surfaces loading/)).toBeTruthy();
  await act(async () => resolveSurfaces([]));
  expect(await screen.findByText(/Surfaces 0 loaded/)).toBeTruthy();
});

it("tells Surfaces the limit its ledger was read with, so a full read says it may be incomplete", async () => {
  vi.mocked(api.listSurfaces).mockResolvedValue([]);
  render(<EngagementPage engagementKey="one" initialTab="surfaces" onBack={vi.fn()} />);
  await screen.findByText(/Surfaces 0 loaded/);
  const readLimit = vi.mocked(api.listSurfaces).mock.calls[0][1]?.limit;
  expect(readLimit).toBeGreaterThan(0);
  expect(screen.getByText(/Surfaces 0 loaded/).textContent).toContain(`(limit ${readLimit})`);
});

it("refreshes when the browser tab comes back into view during the first load", async () => {
  let resolveEngagement: (value: api.Engagement) => void = () => {};
  vi.mocked(api.getEngagement).mockReturnValueOnce(new Promise((resolve) => { resolveEngagement = resolve; }));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  fireEvent(document, new Event("visibilitychange"));
  await act(async () => resolveEngagement(engagement));
  await waitFor(() => expect(api.getEngagement).toHaveBeenCalledTimes(2));
});

it("re-reads Runs for a run change and not for each command run", async () => {
  vi.stubGlobal("WebSocket", LiveSocket);
  render(<EngagementPage engagementKey="one" initialTab="runs" onBack={vi.fn()} />);
  expect((await screen.findByText(/Runs refresh/)).textContent).toBe("Runs refresh 0");
  act(() => { LiveSocket.instance.onopen?.(); });
  LiveSocket.instance.send({ type: "assessment.updated", engagement_key: "one", record_type: "command_run", payload: {} });
  await waitFor(() => expect(api.getEngagement).toHaveBeenCalledTimes(2));
  // Let the pass that read the command change settle; Runs keeps its data.
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 50)); });
  expect(screen.getByText(/Runs refresh/).textContent).toBe("Runs refresh 0");
  await new Promise((resolve) => setTimeout(resolve, 2100));
  LiveSocket.instance.send({ type: "assessment.updated", engagement_key: "one", record_type: "assessment_run", payload: {} });
  await waitFor(() => expect(screen.getByText(/Runs refresh/).textContent).not.toBe("Runs refresh 0"));
}, 10_000);

it("rewrites an unknown or retired tab in the address to the view shown", async () => {
  window.history.replaceState({}, "", "#/engagements/one?tab=bogus");
  const view = render(<EngagementPage engagementKey="one" initialTab="bogus" onBack={vi.fn()} />);
  await targetName("Target one");
  expect(window.location.hash).toBe("#/engagements/one");
  view.unmount();
  window.history.replaceState({}, "", "#/engagements/one?tab=log");
  render(<EngagementPage engagementKey="one" initialTab="log" onBack={vi.fn()} />);
  await screen.findByText(/Activity refresh/);
  expect(window.location.hash).toBe("#/engagements/one?tab=activity");
});

it("adds one history entry per rail activation and none for arrow keys", async () => {
  window.history.replaceState({}, "", "#/engagements/one");
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  const before = window.history.length;
  const overview = screen.getByRole("tab", { name: /^Overview/ });
  overview.focus();
  for (let press = 0; press < 5; press += 1) fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowDown" });
  expect(document.activeElement?.textContent).toMatch(/^Surfaces/);
  expect(window.history.length).toBe(before);
  expect(overview.getAttribute("aria-selected")).toBe("true");
  fireEvent.click(screen.getByRole("tab", { name: /^Coverage/ }));
  await screen.findByText("Coverage ledger");
  expect(window.history.length).toBe(before + 1);
  expect(window.location.hash).toBe("#/engagements/one?tab=coverage");
});

it("shows an archived engagement's lifecycle as a styled status", async () => {
  vi.mocked(api.getEngagement).mockResolvedValue({ ...engagement, status: "archived" });
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  const pill = (await screen.findByText("Archived")).closest(".ui-status");
  expect(pill?.getAttribute("data-tone")).toBe("neutral");
});
