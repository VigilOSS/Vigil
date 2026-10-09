// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { useEffect, useState } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as api from "../lib/api";
import { EngagementPage } from "./EngagementPage";

vi.mock("../contexts/ToastContext", () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock("../components/OverviewTab", () => ({ OverviewTab: ({ findings, findingsLoading, findingsLoadError }: { findings: api.AssessmentFinding[]; findingsLoading?: boolean; findingsLoadError?: string | null }) => <div>{findingsLoading && <span>Finding ledger loading</span>}{findingsLoadError && <span>Finding ledger unavailable: {findingsLoadError}</span>}{findings.map(f => <span key={f.slug}>{f.title}</span>)}</div> }));
vi.mock("../components/CodeAnalysisTab", () => ({ CodeAnalysisTab: ({ persistedPhase }: { persistedPhase: string }) => <div>Code phase: {persistedPhase}</div> }));
vi.mock("../components/FindingsTab", () => ({ FindingsTab: () => <div>Finding ledger</div> }));
vi.mock("../lib/api", async (importOriginal) => {
  const original = await importOriginal<typeof api>();
  return { ...original, getEngagement: vi.fn(), listEvents: vi.fn(), getAssessmentSummary: vi.fn(), getIntelSummary: vi.fn(), listIntel: vi.fn(), listIntelCredentials: vi.fn(), getIntelReadiness: vi.fn(), listActivityEntries: vi.fn(), listAssessmentFindings: vi.fn(), listAssessmentAttackChains: vi.fn(), listAssessmentAttackChainLinks: vi.fn(), listArtifacts: vi.fn(), readArtifact: vi.fn() };
});
const engagement = { id: 1, key: "one", target: "Target one", status: "in_progress", current_phase: "exploit", code_phase: null, track_state: { web: { phase: "exploit", complete: false } }, aggregate_complete: false, engagement_root: "/tmp/one", exploit_policy: "pause", exploit_review_state: "not_requested", approved_targets: [], created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z", session_count: 0 } satisfies api.Engagement;

beforeEach(() => {
  vi.stubGlobal("WebSocket", class { close() {} });
  vi.mocked(api.getEngagement).mockResolvedValue(engagement);
  vi.mocked(api.listEvents).mockResolvedValue([]);
  vi.mocked(api.getAssessmentSummary).mockResolvedValue({ top_findings: [], attack_chains: [] } as unknown as api.AssessmentSummary);
  vi.mocked(api.getIntelSummary).mockResolvedValue({ counts: {} } as api.IntelSummary);
  vi.mocked(api.listIntel).mockImplementation(async (_key, entityType) => ({ entity_type: entityType, total: 0, items: [] }));
  vi.mocked(api.listIntelCredentials).mockResolvedValue([]);
  vi.mocked(api.getIntelReadiness).mockResolvedValue({ applicable: true, engagement_type: "red", open_high_cves: [], open_leads: [], exploited_unlinked_cves: [], dangling_links: [] });
  vi.mocked(api.listActivityEntries).mockResolvedValue({ total: 0, items: [] } as unknown as Awaited<ReturnType<typeof api.listActivityEntries>>);
  vi.mocked(api.listAssessmentFindings).mockResolvedValue([{ slug: "one", title: "Finding one" } as api.AssessmentFindingDetail]);
  vi.mocked(api.listAssessmentAttackChains).mockResolvedValue([]);
  vi.mocked(api.listAssessmentAttackChainLinks).mockResolvedValue([]);
  vi.mocked(api.listArtifacts).mockResolvedValue([{ name: "notes.md", relative_path: "notes.md", exists: true }] as api.Artifact[]);
  vi.mocked(api.readArtifact).mockResolvedValue({ name: "notes.md", relative_path: "notes.md", exists: true, media_type: "text/markdown", content: "Recorded notes" });
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
  await screen.findByRole("heading", { name: "CVE-2026-4444" });
  await waitFor(() => expect(screen.getAllByRole("dialog")).toHaveLength(1));
  fireEvent.keyDown(screen.getByRole("button", { name: /close detail/i }), { key: "k", metaKey: true });
  expect(screen.getByRole("dialog", { name: "Jump to intel" })).toBeTruthy();
  expect(window.location.hash).toBe("#/engagements/one?tab=intel");
  window.history.back();
  await screen.findByRole("heading", { name: "CVE-2026-4444" });
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  expect(screen.queryByRole("dialog", { name: "Jump to intel" })).toBeNull();
  window.history.forward();
  await waitFor(() => expect(window.location.hash).toBe("#/engagements/one?tab=intel"));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(document.body.classList.contains("detail-modal-open")).toBe(false);
});

it("preserves the last good engagement and ledger while a refresh fails", async () => {
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByText("Finding one");
  vi.mocked(api.getEngagement).mockRejectedValueOnce(new Error("temporarily unavailable"));
  fireEvent(document, new Event("visibilitychange"));
  await screen.findByText(/temporarily unavailable/);
  expect(screen.getByRole("heading", { name: "Target one" })).toBeTruthy();
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
  await screen.findByRole("heading", { name: "Target one" });

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
  await screen.findByRole("heading", { name: "Target one" });
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
  await screen.findByRole("heading", { name: "Target one" });
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
  expect(await screen.findByRole("tab", { name: "Findings 2 current" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: "Surfaces 3 open" })).toBeTruthy();
  expect(await screen.findByText("False-positive record")).toBeTruthy();
});

it("labels a loaded finding fallback without implying a filtered current count", async () => {
  vi.mocked(api.getAssessmentSummary).mockRejectedValue(new Error("summary unavailable"));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  expect(await screen.findByRole("tab", { name: "Findings 1 loaded" })).toBeTruthy();
});

it("keeps the overview ledger loading state separate from the available summary", async () => {
  vi.mocked(api.listAssessmentFindings).mockReturnValueOnce(new Promise(() => {}));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  await screen.findByRole("heading", { name: "Target one" });
  expect(screen.getByText("Finding ledger loading")).toBeTruthy();
});

it("passes a finding-ledger failure to overview without treating it as empty", async () => {
  vi.mocked(api.listAssessmentFindings).mockRejectedValueOnce(new Error("ledger request failed"));
  render(<EngagementPage engagementKey="one" onBack={vi.fn()} />);
  expect(await screen.findByText("Finding ledger unavailable: ledger request failed")).toBeTruthy();
});

it("reports a failed selected-file lookup in the files workspace instead of keeping Loading", async () => {
  vi.mocked(api.readArtifact).mockRejectedValue(new Error("file read unavailable"));
  render(<EngagementPage engagementKey="one" initialTab="artifacts" onBack={vi.fn()} />);
  expect((await screen.findByRole("alert")).textContent).toContain("notes.md unavailable: file read unavailable");
  expect(screen.queryByText("Loading notes.md…")).toBeNull();
});

it("ignores a late file-read failure after the selection identity has changed", async () => {
  let rejectOld!: (error: Error) => void;
  vi.mocked(api.listArtifacts).mockResolvedValue([
    { name: "notes.md", relative_path: "notes.md", exists: true },
    { name: "scope.json", relative_path: "scope.json", exists: true },
  ] as api.Artifact[]);
  vi.mocked(api.readArtifact).mockImplementation(async (_key, name) => name === "notes.md"
    ? new Promise((_resolve, reject) => { rejectOld = reject; })
    : { name, relative_path: name, exists: true, media_type: "application/json", content: "{\"hosts\":[\"example.test\"]}" });
  render(<EngagementPage engagementKey="one" initialTab="artifacts" onBack={vi.fn()} />);
  await screen.findByText("Loading notes.md…");
  fireEvent.click(screen.getByRole("button", { name: /scope.json/ }));
  await screen.findByText("example.test");
  rejectOld(new Error("old file failure"));
  await Promise.resolve();
  expect(screen.queryByText(/old file failure/)).toBeNull();
  expect(screen.getByText("example.test")).toBeTruthy();
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
  await screen.findByRole("heading", { name: "Target two" });
  expect(screen.queryByText("Finding one")).toBeNull();
});
