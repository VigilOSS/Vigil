// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import * as api from "../lib/api";
import * as codeApi from "../lib/codeApi";
import type { CodeAnalysisResult, CodeCoverage, CodeQueuePage, CodeQueueStats, CodeReadiness, CodeRepo } from "../lib/api";
import type { CodeAnalysisResultDetail, CodeAnalysisResultPage } from "../lib/codeApi";
import { ToastProvider } from "../contexts/ToastContext";
import { CodeAnalysisTab } from "./CodeAnalysisTab";

vi.mock("../lib/api", () => ({
  listCodeRepos: vi.fn(),
  getCodeCoverage: vi.fn(),
  getCodeQueueStats: vi.fn(),
  getCodeReadiness: vi.fn(),
  listCodeModules: vi.fn(),
}));
vi.mock("../lib/codeApi", () => ({
  listCodeRepoReviewProgress: vi.fn(),
  listCodeAnalysisResultPage: vi.fn(),
  getCodeAnalysisResult: vi.fn(),
  getCodeAnalysisResultPosition: vi.fn(),
  listCodeQueueLane: vi.fn(),
}));

function repo(overrides: Partial<CodeRepo> = {}): CodeRepo {
  return {
    id: 7,
    repo_key: "acme-api-0123456789ab",
    name: "acme-api",
    language: "python",
    repo_path: "/work/repos/acme-api",
    total_files: 12,
    analyzable_files: 10,
    total_loc: 900,
    commit_hash: "0123456789abcdef0123456789abcdef01234567",
    branch: "release/security-review",
    active_generation: 3,
    source_origin_path: "/operator/source/acme-api",
    source_kind: "git",
    snapshot_manifest_path: "evidence/code/acme-api/source-manifest.json",
    snapshot_digest: "snapshot-digest-full-value",
    source_manifest_version: "2",
    source_manifest_digest: "manifest-digest-full-value",
    source_snapshot_quality: "verified",
    repo_role: "analysis",
    worktree_dirty: false,
    lsp_config: {},
    structural_index_schema: "structural-index/v7",
    structural_index_generation: 3,
    structural_index_manifest_path: "evidence/code/acme-api/structural-index.json",
    structural_degraded_files: 0,
    structural_degraded_file_paths: [],
    structural_artifact_truncated_files: 0,
    structural_artifact_truncated_file_paths: [],
    structural_analysis_status_counts: { complete: 10 },
    threat_model_generation: 3,
    analysis_status: "in_progress",
    threat_model: {},
    git_churn: {},
    created_at: "2026-09-12T12:00:00Z",
    updated_at: "2026-09-12T12:00:00Z",
    structural_index_state: { current: true, reasons: [] },
    ...overrides,
  };
}

function readiness(overrides: Partial<CodeReadiness> = {}): CodeReadiness {
  return {
    track: "code",
    target_phase: "verify-variant",
    transition_ready: false,
    track_enabled: true,
    blockers: [],
    structural_debt_count: 0,
    structural_debt: [],
    quality_gate: { passed: true, warnings: [] },
    ...overrides,
  };
}

const queueStats: CodeQueueStats = {
  pending: 40,
  processing: 2,
  done: 60,
  error: 0,
  needs_context: 0,
  total: 102,
  historical_total: 0,
  superseded_history: 0,
  invalid_active_identity: 0,
  invalid_active_history: 0,
  reference_repo_items: [],
};

const coverage: CodeCoverage = {
  total_files: 102,
  reference_repos: [],
  by_classification: {
    critical: { count: 50, analyzed: 30 },
    high: { count: 20, analyzed: 12 },
    medium: { count: 32, analyzed: 18 },
  },
  by_status: { analyzed: 60, queued: 40, in_progress: 2 },
  findings_summary: { total_code_findings: 30, by_severity: { high: 4, medium: 14, low: 11, info: 1 }, variant_count: 0 },
  confidence: {
    critical_coverage_pct: 60,
    high_coverage_pct: 60,
    overall_loc_analyzed: 500,
    unresolved_needs_context: 0,
    active_queue_items: 42,
    invalid_active_history: 0,
    unprocessed_triggers: 20,
    skip_reasons: {},
  },
  gate: { passed: false, reasons: [] },
  trigger_summary: { pending: 20, queued: 30, resolved: 5 },
};

function result(id: number, overrides: Partial<CodeAnalysisResult> = {}): CodeAnalysisResult {
  return {
    id,
    queue_item_id: id,
    file_id: 1,
    repo_id: 7,
    file_path: "src/parser.py",
    agent_name: "code-vuln-hunter",
    receipt_kind: "file",
    receipt_binding_status: "source_span",
    callable_refs: [],
    callable_ref_count: 0,
    reviewed_spans: [],
    function_name: "",
    hypothesis: "",
    evidence: "",
    disposition: "clean",
    confidence: "high",
    finding_slug: "",
    cwe_id: "",
    slot_type: "",
    notes: "",
    awaiting_verdict: false,
    superseded_at: null,
    created_at: "2026-09-12T12:00:00Z",
    ...overrides,
  };
}

function detailOf(row: CodeAnalysisResult, overrides: Partial<CodeAnalysisResultDetail> = {}): CodeAnalysisResultDetail {
  return {
    ...row,
    repo_key: "acme-api-0123456789ab",
    repo_role: "analysis",
    queue_status: "done",
    queue_disposition: row.disposition,
    replaced_by_result_id: null,
    latest_attempt: { id: row.queue_item_id ?? 0, status: "done" },
    current: true,
    evidence_ref: "",
    result_fingerprint: "fingerprint-0123",
    repo_generation: 3,
    cwe_coverage: [],
    cross_file_triggers: [],
    audit_metadata: {},
    ...overrides,
  };
}

function resultPage(items: CodeAnalysisResult[], total = items.length, overrides: Partial<CodeAnalysisResultPage> = {}): CodeAnalysisResultPage {
  return {
    scope: "current",
    total,
    file_total: total,
    offset: 0,
    count: items.length,
    has_more: total > items.length,
    items,
    facets: { disposition: { clean: 3, suspicious: 1 }, confidence: { high: 4 }, workflow_status: {} },
    awaiting_verdict: { files: 1, results: 1 },
    not_listed: [],
    ...overrides,
  };
}

function emptyLane(): CodeQueuePage {
  return { total: 0, offset: 0, count: 0, has_more: false, item_ids: [], items: [] };
}

function lanePage(total: number, ids: number[]): CodeQueuePage {
  return {
    total,
    offset: 0,
    count: ids.length,
    has_more: total > ids.length,
    item_ids: ids,
    items: ids.map((id) => ({
      id,
      file_id: id,
      file_path: `src/module_${id}.py`,
      classification: "high",
      analysis_priority: 50,
      repo_id: 7,
      repo_key: "acme-api-0123456789ab",
      repo_role: "analysis",
      status: "pending",
      queue_mode: "initial",
      priority: 90 - id,
      batch_theme: "",
      slot_types: [],
      guidance_hypotheses: [],
      cross_file_triggers: [],
      agent_name: "",
      lease_token: "",
      repo_generation: 3,
      disposition: "",
      skip_reason: "",
      reanalysis_of_queue_item_id: null,
      consumed_at: null,
      last_heartbeat_at: null,
      lease_activity_at: null,
      heartbeat_age_seconds: null,
      current_result_count: 0,
      adopted_leases: [],
      completed_at: null,
      created_at: "2026-09-12T12:00:00Z",
      updated_at: "2026-09-12T12:00:00Z",
    })),
  };
}

function go(hash: string) {
  window.history.replaceState(null, "", hash);
}

function renderTab(phase = "hunt", refreshVersion = 0) {
  return render(<CodeAnalysisTab engagementKey="demo" persistedPhase={phase} refreshVersion={refreshVersion} />, { wrapper: ToastProvider });
}

beforeEach(() => {
  go("#/engagements/demo?tab=code");
  vi.mocked(api.listCodeRepos).mockResolvedValue([repo()]);
  vi.mocked(codeApi.listCodeRepoReviewProgress).mockResolvedValue([
    { repo_id: 7, repo_role: "analysis", admitted_files: 10, reviewed_files: 4 },
  ]);
  vi.mocked(api.getCodeCoverage).mockResolvedValue(coverage);
  vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(resultPage([result(1)]));
  vi.mocked(api.getCodeQueueStats).mockResolvedValue(queueStats);
  vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) => readiness({ target_phase: target }));
  vi.mocked(api.listCodeModules).mockResolvedValue([]);
  vi.mocked(codeApi.listCodeQueueLane).mockResolvedValue(emptyLane());
  vi.mocked(codeApi.getCodeAnalysisResult).mockImplementation(async (_key, id) => detailOf(result(id)));
  vi.mocked(codeApi.getCodeAnalysisResultPosition).mockResolvedValue({ index: 0, total: 1, previous: null, next: null });
});

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
});

describe("CodeAnalysisTab header", () => {
  it("states the phase, what blocks the next one, and real progress numbers", async () => {
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        structural_debt_count: 25,
        blockers: target === "verify-variant"
          ? [
              { code: "admitted_files_unaccounted", message: "Repository has 42 admitted file(s) without a current terminal review.", overrideable: false, repo_id: 7 },
              { code: "pending_triggers", message: "Repository has 20 unprocessed cross-file trigger(s).", overrideable: true, repo_id: 7 },
            ]
          : [],
      }),
    );
    renderTab();

    expect(await screen.findByText(/2 things block Verify \+ Variant \(1 required\)/)).toBeTruthy();
    expect(screen.getByText("Hunting")).toBeTruthy();
    const numbers = screen.getByRole("list", { name: "Key numbers" });
    expect(within(numbers).getByRole("link", { name: /Files reviewed\s*60 \/ 102/ })).toBeTruthy();
    expect(within(numbers).getByRole("link", { name: /Critical reviewed\s*30 \/ 50/ })).toBeTruthy();
    // The code-findings count opens Findings narrowed to findings located in source files.
    const codeFindings = within(numbers).getByRole("link", { name: /Code findings\s*30/ });
    expect(Object.fromEntries(new URLSearchParams(codeFindings.getAttribute("href")!.split("?")[1]))).toEqual({
      tab: "findings",
      q: "location:file:",
    });
    expect(within(numbers).getByRole("link", { name: /Need a direct read\s*25/ })).toBeTruthy();
    expect(within(numbers).getByRole("link", { name: /Leads to follow\s*20/ })).toBeTruthy();
    // Completion readiness is requested alongside the next transition.
    expect(vi.mocked(api.getCodeReadiness).mock.calls.map((call) => call[1]).sort()).toEqual(["complete", "verify-variant"]);
  });

  it("names the page in the shared page header and counts results awaiting a verdict on the Results tab", async () => {
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        blockers: target === "complete"
          ? [{ code: "unresolved_suspicious_analysis", message: "Repository has 5 current suspicious analysis attempt(s).", overrideable: false, repo_id: 7 }]
          : [],
      }),
    );
    renderTab();
    expect(await screen.findByRole("heading", { level: 1, name: "Code" })).toBeTruthy();
    await waitFor(() => expect(screen.getByRole("tab", { name: /Results/ }).textContent).toContain("5"));
  });

  it("loads repositories even when the engagement has no code phase", async () => {
    renderTab("unknown");
    expect(await screen.findByText("Code track not started")).toBeTruthy();
    await waitFor(() => expect(api.listCodeRepos).toHaveBeenCalledWith("demo"));
    expect(vi.mocked(api.getCodeReadiness).mock.calls.map((call) => call[1])).toEqual(["complete"]);
  });

  it("shows review job counts as loading, not unavailable, while they are still being read", async () => {
    vi.mocked(api.getCodeQueueStats).mockImplementation(() => new Promise<CodeQueueStats>(() => {}));
    vi.mocked(api.getCodeCoverage).mockImplementation(() => new Promise<CodeCoverage>(() => {}));
    go("#/engagements/demo?tab=code&view=queue");
    renderTab();
    expect(await screen.findByLabelText("Loading review job counts")).toBeTruthy();
    expect(screen.getByLabelText("Loading lead counts")).toBeTruthy();
  });

  it("offers Try again when a source fails, and shows it once it loads", async () => {
    vi.mocked(api.getCodeQueueStats).mockRejectedValueOnce(new Error("Queue statistics unavailable"));
    go("#/engagements/demo?tab=code&view=queue");
    renderTab();
    const alert = await screen.findByRole("alert");
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    const counts = await screen.findByRole("list", { name: "Review job counts" });
    expect(counts.textContent).toContain("Total 102");
  });

  it("shows an unavailable source as unknown, never as zero", async () => {
    vi.mocked(api.getCodeQueueStats).mockRejectedValue(new Error("Queue statistics unavailable"));
    go("#/engagements/demo?tab=code&view=queue");
    renderTab();
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.getByText(/review queue counts: Queue statistics unavailable/)).toBeTruthy();
    expect(screen.getByText("Review job counts are unavailable.")).toBeTruthy();
  });
});

describe("CodeAnalysisTab sections", () => {
  it("deep-links a section and switches sections through the URL and the keyboard", async () => {
    go("#/engagements/demo?tab=code&view=files");
    renderTab();
    const files = await screen.findByRole("tab", { name: /Files/ });
    expect(files.getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe("cv-tab-files");

    fireEvent.click(screen.getByRole("tab", { name: /Review queue/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=queue");
    await waitFor(() => expect(screen.getByRole("tab", { name: /Review queue/ }).getAttribute("aria-selected")).toBe("true"));

    fireEvent.keyDown(screen.getByRole("tab", { name: /Review queue/ }), { key: "ArrowRight" });
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=files");
    fireEvent.keyDown(screen.getByRole("tab", { name: /Files/ }), { key: "Home" });
    expect(window.location.hash).toBe("#/engagements/demo?tab=code");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("tab", { name: /Overview/ })));
  });

  it("lists what is left in plain words with requirement tags and section links", async () => {
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        blockers: target === "verify-variant"
          ? [
              { code: "structural_analysis_debt_unreviewed", message: "Repository has 25 admitted source file(s) with degraded structural analysis.", overrideable: false, repo_id: 7 },
              { code: "unresolved_suspicious_analysis", message: "Repository has 5 current suspicious analysis attempt(s).", overrideable: false, repo_id: 7 },
              { code: "critical_high_incomplete", message: "Repository has 26 incomplete critical/high file(s).", overrideable: true, repo_id: 7 },
            ]
          : [{ code: "findings_unverified", message: "12 current code finding(s) have not completed verification triage.", overrideable: false }],
      }),
    );
    renderTab();
    const left = await screen.findByRole("list", { name: "Blocking Verify + Variant" });
    const rows = within(left).getAllByRole("listitem").filter((item) => item.parentElement === left);
    expect(rows.map((row) => row.querySelector(".cv-check-label")?.textContent)).toEqual([
      "Files needing a direct read",
      "Suspicious results awaiting a verdict",
      "Critical/high files not yet reviewed",
    ]);
    expect(within(rows[0]).getByText("25")).toBeTruthy();
    expect(within(rows[0]).getByText("Required")).toBeTruthy();
    expect(within(rows[2]).getByText("Can be skipped with a recorded reason")).toBeTruthy();
    // Exactly the results behind the count: the awaiting-verdict scope, not every suspicious receipt.
    expect(within(rows[1]).getByRole("link", { name: "Open Results" }).getAttribute("href")).toBe(
      "#/engagements/demo?tab=code&view=results&scope=attention",
    );
    // Critical/high review debt opens the risk table that counts it, not the direct-read list.
    expect(within(rows[2]).getByRole("link", { name: "Open Files" }).getAttribute("href")).toBe(
      "#/engagements/demo?tab=code&view=files&focus=risk",
    );
    expect(within(rows[0]).getByRole("link", { name: "Open Files" }).getAttribute("href")).toBe(
      "#/engagements/demo?tab=code&view=files&focus=direct",
    );
    // The raw code stays reachable for experts.
    expect(within(rows[0]).getByText("structural_analysis_debt_unreviewed")).toBeTruthy();

    const completion = screen.getByRole("list", { name: "Blocking completion" });
    expect(within(completion).getByText("Findings not yet verified")).toBeTruthy();
    // The Findings link opens the code findings the blocker counts, already filtered.
    const href = within(completion).getByRole("link", { name: "Open Findings" }).getAttribute("href") ?? "";
    const params = new URLSearchParams(href.split("?")[1]);
    expect(Object.fromEntries(params)).toEqual({
      tab: "findings",
      q: "location:file:",
      workflow: "active,blocked,exploited,contained,eradicated,recovered,reported",
      verification: "unreviewed,disputed,pending_runtime_proof",
    });
  });

  it("opens Findings filtered to what each findings blocker counts", async () => {
    const reportable = "active,blocked,exploited,contained,eradicated,recovered,reported";
    const notBlocked = "unreviewed,disputed,pending_runtime_proof,confirmed,downgraded,false_positive";
    const expected: Record<string, Record<string, string>> = {
      draft_code_findings_unresolved: { workflow: "draft", verification: notBlocked },
      unbound_draft_code_findings_unresolved: { workflow: "draft", verification: notBlocked },
      finding_snapshot_stale: { workflow: reportable, verification: notBlocked },
      findings_unverified: { workflow: reportable, verification: "unreviewed,disputed,pending_runtime_proof" },
      findings_blind_triage_incomplete: { workflow: reportable, verification: "unreviewed,disputed,pending_runtime_proof,false_positive" },
      variant_parent_verification_incomplete: { workflow: reportable, verification: "unreviewed,disputed" },
    };
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        blockers: target === "complete"
          ? Object.keys(expected).map((code) => ({ code, message: `3 ${code}`, overrideable: false }))
          : [],
      }),
    );
    renderTab();
    const completion = await screen.findByRole("list", { name: "Blocking completion" });
    const rows = within(completion).getAllByRole("listitem").filter((item) => item.parentElement === completion);
    const links = Object.fromEntries(rows.map((row) => {
      const code = row.querySelector("details code")?.textContent ?? "";
      const href = within(row).getByRole("link", { name: "Open Findings" }).getAttribute("href") ?? "";
      return [code, Object.fromEntries(new URLSearchParams(href.split("?")[1]))];
    }));
    expect(links).toEqual(Object.fromEntries(Object.entries(expected).map(([code, filters]) => [code, { tab: "findings", q: "location:file:", ...filters }])));
  });

  it("names the actual stale-index trigger", async () => {
    vi.mocked(api.listCodeRepos).mockResolvedValue([
      repo({
        structural_index_schema: "structural-index/v5",
        structural_index_state: {
          current: false,
          reasons: [{ code: "format_outdated", message: "The code index uses format structural-index/v5; the current format is structural-index/v7." }],
        },
      }),
    ]);
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        blockers: [{ code: "structural_index_stale", message: "Structural index is not bound to the current repository snapshot.", overrideable: false, repo_id: 7 }],
      }),
    );
    renderTab();
    const left = await screen.findByRole("list", { name: "Blocking Verify + Variant" });
    expect(within(left).getByText("Code index out of date — re-index")).toBeTruthy();
    expect(within(left).getByText(/uses format structural-index\/v5; the current format is structural-index\/v7/)).toBeTruthy();
    // Direct-read debt is unmeasured for that repository, not zero.
    expect(screen.getByRole("link", { name: /Need a direct read\s*Unknown/ })).toBeTruthy();
  });
});

describe("CodeAnalysisTab repositories", () => {
  const reference = repo({
    id: 9,
    name: "acme-api",
    repo_key: "acme-api-fedcba987654",
    repo_role: "reference",
    structural_index_generation: null,
    threat_model_generation: null,
    structural_analysis_status_counts: { complete: 3, degraded: 40 },
    structural_artifact_truncated_files: 12,
    structural_index_state: { current: false, reasons: [{ code: "never_indexed", message: "No code index has been built for this repository snapshot." }] },
  });
  const second = repo({ id: 8, name: "acme-web", repo_key: "acme-web", structural_index_state: { current: true, reasons: [] } });

  beforeEach(() => {
    go("#/engagements/demo?tab=code&view=repositories");
    vi.mocked(api.listCodeRepos).mockResolvedValue([repo(), second, reference]);
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        structural_debt_count: 2,
        structural_debt: [
          { repo_id: 7, file_path: "src/bundle.min.js", classification: "critical", structural_analysis_status: "degraded", structural_artifact_truncated: true },
          { repo_id: 7, file_path: "src/legacy.cbl", classification: "high", structural_analysis_status: "unsupported", structural_artifact_truncated: false },
        ],
      }),
    );
  });

  it("collapses repositories, expands them on demand, and tells same-named repositories apart", async () => {
    renderTab();
    const head = await screen.findByRole("button", { name: /acme-api\s*0123456789ab/ });
    expect(head.getAttribute("aria-expanded")).toBe("false");
    expect(within(head).getByText("2 need a direct read")).toBeTruthy();
    expect(screen.queryByText("Source identity")).toBeNull();

    fireEvent.click(head);
    expect(head.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("Source identity")).toBeTruthy();
    expect(screen.getByText("/work/repos/acme-api")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(head.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: "Expand all" }));
    expect(screen.getAllByText("Source identity")).toHaveLength(3);
  });

  it("groups reference code apart with no review debt or index warnings", async () => {
    renderTab();
    const group = await screen.findByRole("button", { name: /Reference code \(read for context, not reviewed\)/ });
    expect(group.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(group);
    const referenceList = screen.getByRole("list", { name: "Reference repositories" });
    const referenceHead = within(referenceList).getByRole("button", { name: /acme-api\s*fedcba987654/ });
    expect(within(referenceHead).queryByText(/direct read/)).toBeNull();
    expect(within(referenceHead).queryByText(/warning/)).toBeNull();
    fireEvent.click(referenceHead);
    expect(within(referenceList).queryByText("Code index out of date — re-index")).toBeNull();
  });

  it("opens and focuses a deep-linked repository", async () => {
    go("#/engagements/demo?tab=code&view=repositories&repo=8");
    renderTab();
    const head = await screen.findByRole("button", { name: /^▸?▾?\s*acme-web/ });
    await waitFor(() => expect(head.getAttribute("aria-expanded")).toBe("true"));
  });
});

describe("CodeAnalysisTab files and quality", () => {
  it("lists files needing a direct read with plain reasons", async () => {
    go("#/engagements/demo?tab=code&view=files");
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        structural_debt_count: 2,
        structural_debt: [
          { repo_id: 7, file_path: "src/legacy.cbl", classification: "high", structural_analysis_status: "unsupported", structural_artifact_truncated: false },
          { repo_id: 7, file_path: "src/bundle.min.js", classification: "critical", structural_analysis_status: "degraded", structural_artifact_truncated: true },
        ],
      }),
    );
    renderTab();
    const heading = await screen.findByRole("heading", { name: /Files needing a direct read/ });
    const table = heading.closest("section")!.querySelector("table")!;
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((row) => within(row).getAllByRole("cell").map((cell) => cell.textContent))).toEqual([
      ["src/bundle.min.js", "Critical", "Partly parsed, too large to fully index"],
      ["src/legacy.cbl", "High", "Not parsed"],
    ]);
  });

  it("counts direct reads as unknown, not zero, while the code index is out of date", async () => {
    go("#/engagements/demo?tab=code&view=files");
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        blockers: [{ code: "structural_index_stale", message: "Structural index is not bound to the current repository snapshot.", overrideable: false, repo_id: 7 }],
      }),
    );
    renderTab();
    const heading = await screen.findByRole("heading", { name: /Files needing a direct read/ });
    await waitFor(() => expect(heading.textContent).toContain("Unknown"));
    expect(heading.textContent).not.toMatch(/\b0\b/);
  });

  it("groups under-reviewed files by vulnerability type", async () => {
    go("#/engagements/demo?tab=code&view=quality");
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) =>
      readiness({
        target_phase: target,
        quality_gate: {
          passed: false,
          warnings: [
            "High file src/a.js: family 'algorithmic-dos' effort 45 < 50",
            "Critical file src/b.js: family 'algorithmic-dos' effort 58 < 70",
            "Critical file src/c.js: family 'deserialization' effort 45 < 70",
            "src/d.js: an unrecognised integrity note",
          ],
        },
      }),
    );
    renderTab();
    expect(await screen.findByText("Algorithmic DoS")).toBeTruthy();
    expect(screen.getByText("2 files under-reviewed")).toBeTruthy();
    expect(screen.getByText("Deserialization")).toBeTruthy();
    expect(screen.getByText("58 of 70")).toBeTruthy();
    // Unrecognised warnings are kept verbatim.
    expect(screen.getByText("src/d.js: an unrecognised integrity note")).toBeTruthy();
  });
});

describe("CodeAnalysisTab results", () => {
  beforeEach(() => go("#/engagements/demo?tab=code&view=results"));

  it("pages results from the server and opens one in the shared record view", async () => {
    const finding = result(9, {
      disposition: "finding",
      finding_slug: "VIGIL-204",
      finding_workflow_status: "active",
      evidence: "Acme token reaches the sink unchecked",
      callable_ref_count: 2,
      callable_refs: [
        { callable_key: "a", file_id: 1, file_path: "src/parser.py", name: "decode", qualified_name: "Parser.decode", start_line: 1, end_line: 9 },
        { callable_key: "b", file_id: 1, file_path: "src/parser.py", name: "frame", qualified_name: "Parser.frame", start_line: 10, end_line: 20 },
      ],
    });
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(resultPage([finding], 60));
    vi.mocked(codeApi.getCodeAnalysisResult).mockImplementation(async (_key, id) =>
      detailOf(id === 9 ? finding : result(id, { file_path: "src/lexer.py" })),
    );
    vi.mocked(codeApi.getCodeAnalysisResultPosition).mockResolvedValue({ index: 0, total: 60, previous: null, next: result(10, { file_path: "src/lexer.py" }) });
    renderTab();
    expect(await screen.findByText("Showing 1–25 of 60")).toBeTruthy();
    // The server's order, in the shared status-sort wording.
    expect(screen.getByText(/Sorted by Result, most urgent first, newest first within each/)).toBeTruthy();
    expect(screen.getByRole("link", { name: "VIGIL-204" }).getAttribute("href")).toBe(
      "#/engagements/demo?tab=findings&finding=VIGIL-204",
    );
    expect(screen.queryByText("Parser.decode")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /^Open result #9/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results&result=9");
    const record = await screen.findByRole("region", { name: "Analysis result record" });
    // The record replaces the results and the page header, like every other record.
    expect(screen.queryByRole("heading", { level: 1, name: "Code" })).toBeNull();
    expect(within(record).getByText("Result #9")).toBeTruthy();
    expect(await within(record).findByText("Acme token reaches the sink unchecked")).toBeTruthy();
    expect(await within(record).findByText("1 of 60 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Source anchors/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results&result=9&dtab=anchors");
    expect(within(record).getByText("Parser.decode")).toBeTruthy();

    vi.mocked(codeApi.getCodeAnalysisResultPosition).mockResolvedValue({ index: 1, total: 60, previous: finding, next: null });
    fireEvent.click(within(record).getByRole("button", { name: "Next analysis result" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results&result=10&dtab=anchors");
    await waitFor(() => expect(codeApi.getCodeAnalysisResult).toHaveBeenLastCalledWith("demo", 10));
    expect(await within(record).findByRole("heading", { level: 2, name: /src\/lexer\.py/ })).toBeTruthy();

    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results");
    expect(await screen.findByRole("heading", { level: 1, name: "Code" })).toBeTruthy();
  });

  it("counts a deep-linked receipt's source anchors from the receipt itself", async () => {
    go("#/engagements/demo?tab=code&view=results&result=12");
    const refs = ["decode", "frame", "flush"].map((name, index) => ({
      callable_key: name, file_id: 1, file_path: "src/parser.py", name, qualified_name: `Parser.${name}`, start_line: index * 10 + 1, end_line: index * 10 + 9,
    }));
    // The point read lists every callable and carries no separate count.
    const receipt: Record<string, unknown> = { ...detailOf(result(12, { callable_refs: refs })) };
    delete receipt.callable_ref_count;
    vi.mocked(codeApi.getCodeAnalysisResult).mockResolvedValue(receipt as CodeAnalysisResultDetail);
    renderTab();
    const record = await screen.findByRole("region", { name: "Analysis result record" });
    await waitFor(() => expect(within(record).getByRole("button", { name: /^Source anchors/ }).textContent).toBe("Source anchors3"));
  });

  it("opens a deep-linked result and keeps the list on the page that holds it", async () => {
    go("#/engagements/demo?tab=code&view=results&result=31&dtab=review");
    vi.mocked(codeApi.getCodeAnalysisResultPosition).mockResolvedValue({ index: 30, total: 60, previous: result(30), next: result(32) });
    renderTab();
    const record = await screen.findByRole("region", { name: "Analysis result record" });
    expect(await within(record).findByText("31 of 60 results")).toBeTruthy();
    // Back returns to the page that holds the record (page 2 of 25-row pages).
    await waitFor(() =>
      expect(codeApi.listCodeAnalysisResultPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ offset: 25 })),
    );
  });

  it("writes chips, search and page to the URL and reads them back", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^Suspicious/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results&disposition=suspicious");
    await waitFor(() =>
      expect(codeApi.listCodeAnalysisResultPage).toHaveBeenCalledWith(
        "demo",
        expect.objectContaining({ disposition: ["suspicious"], offset: 0, limit: 25 }),
      ),
    );
    const search = screen.getByRole("searchbox", { name: "Search analysis results" });
    fireEvent.change(search, { target: { value: "cwe:79 token" } });
    // Enter commits the search at once; typing alone commits after a pause.
    fireEvent.keyDown(search, { key: "Enter" });
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results&disposition=suspicious&q=cwe%3A79+token");
    await waitFor(() =>
      expect(codeApi.listCodeAnalysisResultPage).toHaveBeenCalledWith(
        "demo",
        expect.objectContaining({ cwe: "79", q: ["token"], disposition: ["suspicious"] }),
      ),
    );
  });

  it("shows each chip's count under the other filters, and keeps a selected value listed", async () => {
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockImplementation(async (_key, query) =>
      resultPage([result(1)], 1, {
        facets: query?.disposition?.includes("suspicious")
          ? { disposition: { clean: 85, finding: 20, suspicious: 4 }, confidence: { medium: 3, high: 1 }, workflow_status: {} }
          : { disposition: { clean: 85, finding: 20, suspicious: 4 }, confidence: { high: 102, medium: 7 }, workflow_status: {} },
      }),
    );
    renderTab();
    const confidence = await screen.findByRole("group", { name: "Confidence" });
    await waitFor(() => expect(within(confidence).getByRole("button", { name: /^High/ }).textContent).toBe("High102"));
    fireEvent.click(screen.getByRole("button", { name: /^Suspicious/ }));
    await waitFor(() => expect(within(confidence).getByRole("button", { name: /^High/ }).textContent).toBe("High1"));
    fireEvent.click(within(confidence).getByRole("button", { name: /^Medium/ }));
    expect(window.location.hash).toContain("confidence=medium");
  });

  it("restores a page, search and filters from the URL", async () => {
    go("#/engagements/demo?tab=code&view=results&disposition=suspicious&confidence=high&q=cwe%3A79&page=2");
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(resultPage([result(1)], 60));
    renderTab();
    await waitFor(() =>
      expect(codeApi.listCodeAnalysisResultPage).toHaveBeenCalledWith(
        "demo",
        expect.objectContaining({ disposition: ["suspicious"], confidence: ["high"], cwe: "79", offset: 25 }),
      ),
    );
    expect((screen.getByRole("searchbox", { name: "Search analysis results" }) as HTMLInputElement).value).toBe("cwe:79");
    fireEvent.click(await screen.findByRole("button", { name: "Next analysis results page" }));
    expect(window.location.hash).toContain("page=3");
  });

  it("lands the awaiting-verdict link on exactly those results", async () => {
    go("#/engagements/demo?tab=code&view=results&scope=attention");
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(
      resultPage([result(3, { disposition: "suspicious", awaiting_verdict: true })], 7, { scope: "awaiting_verdict", awaiting_verdict: { files: 7, results: 7 } }),
    );
    renderTab();
    await waitFor(() =>
      expect(codeApi.listCodeAnalysisResultPage).toHaveBeenCalledWith("demo", expect.objectContaining({ scope: "awaiting_verdict" })),
    );
    const scope = await screen.findByRole("group", { name: "Results scope" });
    expect(within(scope).getByRole("button", { name: /Needs attention\s*7/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("offers Try again when the results page fails to load", async () => {
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockRejectedValueOnce(new Error("upstream timeout"));
    renderTab();
    const alert = await screen.findByText(/Results unavailable: upstream timeout/);
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Showing 1–1 of 1")).toBeTruthy();
  });

  it("offers Clear filters when no result matches", async () => {
    go("#/engagements/demo?tab=code&view=results&disposition=finding");
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(resultPage([], 0));
    renderTab();
    expect(await screen.findByText("No results match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=code&view=results");
  });

  it("says why finished reviews have no listed results", async () => {
    vi.mocked(codeApi.listCodeAnalysisResultPage).mockResolvedValue(
      resultPage([], 0, {
        not_listed: [{ code: "legacy_receipts", count: 120, message: "120 receipt(s) were recorded before receipts were tied to the code index, so they are not listed." }],
      }),
    );
    renderTab();
    expect(await screen.findByText("No current analysis results.")).toBeTruthy();
    expect(screen.getByText(/120 receipt\(s\) were recorded before receipts were tied to the code index/)).toBeTruthy();
  });

  it("keeps an open result's receipt read in flight across refreshes and re-reads it once", async () => {
    go("#/engagements/demo?tab=code&view=results&result=5");
    const releases: Array<(value: CodeAnalysisResultDetail) => void> = [];
    vi.mocked(codeApi.getCodeAnalysisResult).mockImplementation(
      () => new Promise<CodeAnalysisResultDetail>((resolve) => { releases.push(resolve); }),
    );
    const view = renderTab("hunt", 0);
    const record = await screen.findByRole("region", { name: "Analysis result record" });
    await waitFor(() => expect(codeApi.getCodeAnalysisResult).toHaveBeenCalledTimes(1));
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={1} />);
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={2} />);
    expect(codeApi.getCodeAnalysisResult).toHaveBeenCalledTimes(1);
    // The first answer is shown, not discarded, and one follow-up read runs after it.
    await act(async () => releases[0](detailOf(result(5, { file_path: "src/first_answer.py" }))));
    expect(await within(record).findByText("src/first_answer.py")).toBeTruthy();
    await waitFor(() => expect(codeApi.getCodeAnalysisResult).toHaveBeenCalledTimes(2));
  });

  it("distinguishes an unanchored skipped receipt from historical ones", async () => {
    go("#/engagements/demo?tab=code&view=results&result=1");
    vi.mocked(codeApi.getCodeAnalysisResult).mockImplementation(async (_key, id) =>
      detailOf(id === 1
        ? result(1, { receipt_binding_status: "skipped_unbound", disposition: "skipped" })
        : result(2, { receipt_binding_status: "legacy_unbound" })),
    );
    vi.mocked(codeApi.getCodeAnalysisResultPosition).mockResolvedValue({ index: 0, total: 2, previous: null, next: result(2, { receipt_binding_status: "legacy_unbound" }) });
    renderTab();
    const record = await screen.findByRole("region", { name: "Analysis result record" });
    fireEvent.click(await within(record).findByRole("button", { name: /^Source anchors/ }));
    expect(await within(record).findByText("Skipped — no source anchors")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Next analysis result" }));
    expect(await within(record).findByText("Historical receipt without source anchors")).toBeTruthy();
  });
});

describe("CodeAnalysisTab review queue", () => {
  beforeEach(() => go("#/engagements/demo?tab=code&view=queue"));

  it("pages every current job in a lane instead of stopping at the first few", async () => {
    vi.mocked(codeApi.listCodeQueueLane).mockImplementation(async (_key, status, page) =>
      status === "pending" ? lanePage(45, Array.from({ length: 10 }, (_, index) => page.offset + index + 1)) : emptyLane(),
    );
    renderTab();
    const lane = await screen.findByRole("region", { name: "Next up" });
    expect(within(lane).getByText("Showing 1–10 of 45 · highest priority first")).toBeTruthy();
    expect(vi.mocked(codeApi.listCodeQueueLane).mock.calls.every(([, , page]) => page.offset === 0)).toBe(true);
    fireEvent.click(within(lane).getByRole("button", { name: "Next page of Next up" }));
    await waitFor(() => expect(codeApi.listCodeQueueLane).toHaveBeenLastCalledWith("demo", "pending", { limit: 10, offset: 10 }));
    expect(await within(lane).findByText("Showing 11–20 of 45 · highest priority first")).toBeTruthy();
  });

  it("keeps a later lane page's read in flight across refreshes and re-reads it once", async () => {
    const later: Array<(value: CodeQueuePage) => void> = [];
    vi.mocked(codeApi.listCodeQueueLane).mockImplementation((_key, status, page) => {
      if (status !== "pending") return Promise.resolve(emptyLane());
      if (page.offset === 0) return Promise.resolve(lanePage(45, Array.from({ length: 10 }, (_, index) => index + 1)));
      return new Promise<CodeQueuePage>((resolve) => { later.push(resolve); });
    });
    const view = renderTab("hunt", 0);
    const lane = await screen.findByRole("region", { name: "Next up" });
    fireEvent.click(within(lane).getByRole("button", { name: "Next page of Next up" }));
    const laterCalls = () => vi.mocked(codeApi.listCodeQueueLane).mock.calls.filter(([, , page]) => page.offset === 10).length;
    await waitFor(() => expect(laterCalls()).toBe(1));
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={1} />);
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={2} />);
    expect(laterCalls()).toBe(1);
    await act(async () => later[0]({ ...lanePage(45, Array.from({ length: 10 }, (_, index) => index + 11)), offset: 10 }));
    expect(await within(lane).findByText("Showing 11–20 of 45 · highest priority first")).toBeTruthy();
    await waitFor(() => expect(laterCalls()).toBe(2));
  });

  it("explains finished jobs that do not count as reviewed", async () => {
    vi.mocked(codeApi.listCodeRepoReviewProgress).mockResolvedValue([
      {
        repo_id: 7,
        repo_role: "analysis",
        admitted_files: 150,
        reviewed_files: 0,
        finished_files: 24,
        finished_not_reviewed: [
          { code: "legacy_receipts", count: 24, message: "24 finished review(s) only have receipts recorded before receipts were tied to the code index." },
        ],
      },
    ]);
    renderTab();
    const note = await screen.findByRole("note", { name: "Finished reviews that do not count" });
    expect(within(note).getByText(/24 finished review\(s\) only have receipts recorded before receipts were tied to the code index/)).toBeTruthy();
    expect(within(note).getByText(/24 finished · 0 count as reviewed/)).toBeTruthy();
    // The header's reviewed count says the same thing where the low number shows.
    expect(screen.getByRole("link", { name: /Files reviewed\s*60 \/ 102\s*24 finished · 0 count as reviewed/ })).toBeTruthy();
  });
});

describe("CodeAnalysisTab without a code track", () => {
  it("shows no owed code work on a web or blue engagement", async () => {
    vi.mocked(api.listCodeRepos).mockResolvedValue([]);
    vi.mocked(api.getCodeReadiness).mockImplementation(async (_key, target) => ({
      ...readiness({
        target_phase: target,
        blockers: [{ code: "no_repositories", message: "No code repositories have been ingested.", overrideable: false }],
      }),
      track_enabled: false,
    }));
    renderTab("unknown");
    expect(await screen.findByText("This engagement has no code track.")).toBeTruthy();
    expect(screen.queryByText("Required")).toBeNull();
    expect(screen.queryByText("No repository ingested yet")).toBeNull();
    expect(screen.queryByRole("tablist", { name: "Code review sections" })).toBeNull();
  });
});

describe("CodeAnalysisTab refresh", () => {
  it("coalesces refreshes that arrive while a load is in flight", async () => {
    let release: (value: CodeQueueStats) => void = () => {};
    vi.mocked(api.getCodeQueueStats).mockImplementation(
      () => new Promise<CodeQueueStats>((resolve) => { release = resolve; }),
    );
    const view = renderTab("hunt", 0);
    await waitFor(() => expect(api.getCodeQueueStats).toHaveBeenCalledTimes(1));
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={1} />);
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={2} />);
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={3} />);
    expect(api.getCodeQueueStats).toHaveBeenCalledTimes(1);
    await act(async () => release(queueStats));
    await waitFor(() => expect(api.getCodeQueueStats).toHaveBeenCalledTimes(2));
    await act(async () => release(queueStats));
    expect(api.getCodeQueueStats).toHaveBeenCalledTimes(2);
    // Section data loads only while its section is open.
    expect(api.listCodeModules).not.toHaveBeenCalled();
    expect(codeApi.listCodeAnalysisResultPage).not.toHaveBeenCalled();
  });

  it("re-reads at most once per refresh window under a burst of live updates, then once more", async () => {
    const view = renderTab("hunt", 0);
    await waitFor(() => expect(api.getCodeQueueStats).toHaveBeenCalledTimes(1));
    view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={1} />);
    await waitFor(() => expect(api.getCodeQueueStats).toHaveBeenCalledTimes(2));
    vi.useFakeTimers({ now: Date.now(), toFake: ["setTimeout", "clearTimeout", "Date"] });
    try {
      view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={2} />);
      view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={3} />);
      view.rerender(<CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={4} />);
      await vi.advanceTimersByTimeAsync(0);
      expect(api.getCodeQueueStats).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(6_000);
    } finally {
      vi.useRealTimers();
    }
    await waitFor(() => expect(api.getCodeQueueStats).toHaveBeenCalledTimes(3));
  });

  it("reads each source once under StrictMode's repeated mount effects", async () => {
    go("#/engagements/demo?tab=code&view=repositories");
    render(<StrictMode><CodeAnalysisTab engagementKey="demo" persistedPhase="hunt" refreshVersion={0} /></StrictMode>);
    await waitFor(() => expect(codeApi.listCodeRepoReviewProgress).toHaveBeenCalled());
    await waitFor(() => expect(api.getCodeReadiness).toHaveBeenCalledTimes(2));
    expect(api.listCodeRepos).toHaveBeenCalledTimes(1);
    expect(api.getCodeQueueStats).toHaveBeenCalledTimes(1);
    expect(api.getCodeCoverage).toHaveBeenCalledTimes(1);
    expect(codeApi.listCodeRepoReviewProgress).toHaveBeenCalledTimes(1);
  });
});
