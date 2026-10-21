// @vitest-environment jsdom

// Recency on the Findings page: when each finding was recorded and last
// changed, date sorts, the recency filters, the "since you last looked"
// summary, and the per-engagement last-visit mark. Also pins the count labels
// and that live refreshes coalesce instead of stacking or starving requests.

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import {
  getAssessmentFinding,
  getFindingRemediationCases,
  listAssessmentFindingGroups,
  listAssessmentFindingLinks,
  listAssessmentFindingTransitions,
  listEngagements,
} from "../lib/api";
import { FindingsTab } from "./FindingsTab";
import type { Derived } from "./FindingsTab";

vi.mock("./FindingsGrid", () => ({ default: ({ rows, onOpen, sort }: { rows: Derived[]; onOpen: (slug: string) => void; sort?: string | null }) => (
  <div data-testid="grid" data-sort={sort ?? ""}>{rows.map((row) => <button key={row.slug} onClick={() => onOpen(row.slug)}>Grid {row.title}</button>)}</div>
) }));

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    getAssessmentFinding: vi.fn(),
    listAssessmentFindingGroups: vi.fn(),
    listAssessmentFindingLinks: vi.fn(),
    listAssessmentFindingTransitions: vi.fn(),
    getFindingRemediationCases: vi.fn(),
    listEngagements: vi.fn(),
  };
});

const HOUR = 60 * 60 * 1000;

function ago(ms: number): string {
  return new Date(Date.now() - ms).toISOString().replace("T", " ").slice(0, 19);
}

function record(slug: string, title: string, over: Record<string, unknown> = {}) {
  return {
    id: Number(slug.replace(/\D/g, "")), slug, title, severity: "medium",
    workflow_status: "active", submission_status: "none", verification_status: "confirmed",
    canonical_location: `https://app.example/${slug.toLowerCase()}`, summary: "Acme portal claim.",
    source_name: "vulnerability-analyst", row_version: 1, evidence_ref: "", notes: "",
    defect_family: "authorization", root_cause_key: slug, auth_context: "", details: {}, provenance: {},
    updated_at: ago(5 * 60 * 1000), last_seen_at: ago(5 * 60 * 1000),
    ...over,
  };
}

// Recorded long ago, but its last ledger change is the newest of all.
const OLD_CHANGED_AT = ago(1 * HOUR);
const oldButChanged = record("VA-001", "Old claim changed recently", { severity: "critical", created_at: ago(30 * 24 * HOUR), last_transition_at: OLD_CHANGED_AT, last_transition_action: "verified_confirmed", last_transition_actor: "operator" });
// Recorded two hours ago and not changed since.
const freshlyRecorded = record("VA-002", "Fresh claim", { severity: "low", created_at: ago(2 * HOUR), last_transition_at: ago(2 * HOUR), last_transition_action: "created" });
// Recorded and last changed weeks ago.
const quiet = record("VA-003", "Quiet claim", { severity: "high", created_at: ago(20 * 24 * HOUR), last_transition_at: ago(20 * 24 * HOUR), last_transition_action: "created" });
// Merged into another finding: counted in the ledger total, not as current.
const merged = record("VA-004", "Merged duplicate", { severity: "info", workflow_status: "merged", created_at: ago(40 * 24 * HOUR), last_transition_at: ago(40 * 24 * HOUR), last_transition_action: "created" });
const ledger = [oldButChanged, freshlyRecorded, quiet, merged];

function renderTab(findings: unknown[] = ledger, over: Record<string, unknown> = {}) {
  const props = { engagementKey: "acme", findings: findings as never[], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0, ...over };
  return render(<ToastProvider><FindingsTab {...props} /></ToastProvider>);
}

function queueTitles(): string[] {
  const queue = screen.getByRole("region", { name: "Finding queue" });
  return Array.from(queue.querySelectorAll(".mini-finding-row strong, .group-root-title")).map((node) => node.textContent ?? "");
}

beforeEach(() => {
  vi.mocked(getAssessmentFinding).mockReset().mockImplementation(async (_key, slug) => ledger.find((item) => item.slug === slug) as never);
  vi.mocked(listAssessmentFindingGroups).mockReset().mockResolvedValue([]);
  vi.mocked(listAssessmentFindingLinks).mockReset().mockResolvedValue([]);
  vi.mocked(listAssessmentFindingTransitions).mockReset().mockResolvedValue([]);
  vi.mocked(getFindingRemediationCases).mockReset().mockResolvedValue([]);
  vi.mocked(listEngagements).mockReset().mockResolvedValue([]);
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/acme?tab=findings");
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("finding dates", () => {
  it("labels the ledger total separately from current findings", () => {
    renderTab();
    const stats = screen.getByRole("list", { name: "Summary" });
    expect(stats.textContent).toContain("3 current");
    expect(stats.textContent).toContain("4 recorded");
  });

  it("shows when each grouped row last changed, with the absolute UTC time available", () => {
    renderTab();
    const row = screen.getByRole("button", { name: /Old claim changed recently/ });
    const time = row.querySelector("time");
    expect(time?.textContent).toBe("1h ago");
    expect(time?.getAttribute("title")).toMatch(/UTC$/);
    expect(row.textContent).toContain("Changed");
  });

  it("shows created and last-changed absolute times in the finding header", async () => {
    renderTab();
    fireEvent.click(screen.getByRole("button", { name: /Old claim changed recently/ }));
    const header = await screen.findByLabelText("Finding dates");
    expect(header.textContent).toContain("Created");
    expect(header.textContent).toContain("Last changed");
    expect(header.textContent).toContain("verified confirmed");
    expect(header.textContent).toContain("operator");
    expect(header.querySelectorAll("time")).toHaveLength(2);
    expect(header.querySelector("time")?.textContent).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
  });
});

describe("sorting", () => {
  it("defaults the grouped view to severity and makes the active sort visible", () => {
    renderTab();
    const sort = screen.getByRole("group", { name: "Sort findings" });
    expect(within(sort).getByRole("button", { name: /^Severity/ }).getAttribute("aria-pressed")).toBe("true");
    expect(queueTitles()).toEqual(["Old claim changed recently", "Quiet claim", "Fresh claim", "Merged duplicate"]);
  });

  it("switches to a flat creation-date list and to a last-change list", () => {
    renderTab();
    const sort = screen.getByRole("group", { name: "Sort findings" });
    fireEvent.click(within(sort).getByRole("button", { name: /^Newest/ }));
    expect(within(sort).getByRole("button", { name: /^Newest/ }).getAttribute("aria-pressed")).toBe("true");
    expect(queueTitles()).toEqual(["Fresh claim", "Quiet claim", "Old claim changed recently", "Merged duplicate"]);
    expect(screen.queryByText("Standalone Findings")).toBeNull();
    expect(screen.getByText(/newest first/i)).toBeTruthy();
    fireEvent.click(within(sort).getByRole("button", { name: /^Recently changed/ }));
    expect(queueTitles()).toEqual(["Old claim changed recently", "Fresh claim", "Quiet claim", "Merged duplicate"]);
  });

  it("keeps each row's root cause visible when a date sort removes the group cards", async () => {
    const sibling = record("VA-005", "Sibling claim", { created_at: ago(HOUR) });
    vi.mocked(listAssessmentFindingGroups).mockResolvedValue([{ root: oldButChanged, siblings: [sibling], sibling_count: 1, residual_path_count: 0 }] as never);
    renderTab([...ledger, sibling]);
    await waitFor(() => expect(screen.queryByText("Loading groups")).toBeNull());
    fireEvent.click(within(screen.getByRole("group", { name: "Sort findings" })).getByRole("button", { name: /^Newest/ }));
    expect(within(screen.getByRole("button", { name: /Sibling claim/ })).getByText("Sibling of VA-001")).toBeTruthy();
    expect(within(screen.getByRole("button", { name: /Old claim changed recently/ })).getByText("Root · 1 sibling")).toBeTruthy();
  });

  it("defaults the table view to creation date, newest first", async () => {
    renderTab();
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    const grid = await screen.findByTestId("grid");
    expect(grid.getAttribute("data-sort")).toBe("newest");
    expect(within(grid).getAllByRole("button").map((button) => button.textContent)).toEqual([
      "Grid Fresh claim", "Grid Quiet claim", "Grid Old claim changed recently", "Grid Merged duplicate",
    ]);
  });

  it("counts flat pages in findings and grouped pages in groups plus ungrouped findings", () => {
    const many = Array.from({ length: 30 }, (_, index) => record(`VA-${100 + index}`, `Claim ${index}`, { created_at: ago((index + 1) * HOUR) }));
    renderTab(many);
    expect(screen.getAllByText(/1–25 of 30 entries \(0 root-cause groups, 30 ungrouped findings\)/)).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: /^Newest/ }));
    expect(screen.getAllByText(/findings 1–25 of 30/)).toHaveLength(2);
  });
});

describe("recency filters", () => {
  it("filters new and changed findings within a window without overlap", () => {
    renderTab();
    const chips = screen.getByRole("group", { name: "Recency" });
    fireEvent.click(within(chips).getByRole("button", { name: /^New 24h/ }));
    expect(queueTitles()).toEqual(["Fresh claim"]);
    fireEvent.click(within(chips).getByRole("button", { name: /^Changed 24h/ }));
    expect(within(chips).getByRole("button", { name: /^New 24h/ }).getAttribute("aria-pressed")).toBe("false");
    expect(queueTitles()).toEqual(["Old claim changed recently"]);
    fireEvent.click(within(chips).getByRole("button", { name: /^Changed 24h/ }));
    expect(queueTitles()).toHaveLength(4);
  });

  it("summarizes what changed since the last visit and applies that filter on request", () => {
    window.localStorage.setItem("findings.lastVisit.acme", String(Date.now() - 3 * HOUR));
    renderTab();
    const bar = screen.getByRole("region", { name: "Recent finding changes" });
    expect(bar.textContent).toContain("1 new · 1 changed since you last looked");
    fireEvent.click(within(bar).getByRole("button", { name: /Review/ }));
    const chips = screen.getByRole("group", { name: "Recency" });
    expect(within(chips).getByRole("button", { name: /^Since my last visit/ }).getAttribute("aria-pressed")).toBe("true");
    expect(queueTitles()).toEqual(["Old claim changed recently", "Fresh claim"]);
  });

  it("falls back to the last 24 hours when this browser has no earlier visit", () => {
    renderTab();
    const bar = screen.getByRole("region", { name: "Recent finding changes" });
    expect(bar.textContent).toContain("1 new · 1 changed in the last 24 hours");
    const since = within(screen.getByRole("group", { name: "Recency" })).getByRole("button", { name: /^Since my last visit/ }) as HTMLButtonElement;
    expect(since.disabled).toBe(true);
  });

  it("still renders the page when browser storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("SecurityError"); });
    renderTab();
    expect(screen.getByRole("region", { name: "Finding queue" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Recent finding changes" }).textContent).toContain("in the last 24 hours");
  });
});

describe("last-visit mark", () => {
  it("records the newest ledger time only after the page has been viewed long enough", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    const first = renderTab();
    act(() => { vi.advanceTimersByTime(9_000); });
    expect(window.localStorage.getItem("findings.lastVisit.acme")).toBeNull();
    first.unmount();
    renderTab();
    act(() => { vi.advanceTimersByTime(10_000); });
    const mark = Number(window.localStorage.getItem("findings.lastVisit.acme"));
    // The newest creation-or-change on screen: VA-001's ledger change.
    expect(mark).toBe(Date.parse(`${OLD_CHANGED_AT.replace(" ", "T")}Z`));
  });

  it("keeps the mark it opened with while the operator works through the list", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    window.localStorage.setItem("findings.lastVisit.acme", String(Date.now() - 3 * HOUR));
    renderTab();
    act(() => { vi.advanceTimersByTime(10_000); });
    expect(screen.getByRole("region", { name: "Recent finding changes" }).textContent).toContain("1 new · 1 changed since you last looked");
  });

  it("does not record a mark from the summary fallback before the ledger loads", () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval"] });
    renderTab([], { fallbackFindings: [freshlyRecorded], ledgerLoading: true });
    act(() => { vi.advanceTimersByTime(20_000); });
    expect(window.localStorage.getItem("findings.lastVisit.acme")).toBeNull();
  });
});

describe("refresh coalescing", () => {
  it("requests groups and links once on mount, even under StrictMode", async () => {
    render(<StrictMode><ToastProvider><FindingsTab engagementKey="acme" findings={ledger as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={0} /></ToastProvider></StrictMode>);
    await waitFor(() => expect(listAssessmentFindingGroups).toHaveBeenCalled());
    await act(async () => {});
    expect(listAssessmentFindingGroups).toHaveBeenCalledTimes(1);
    expect(listAssessmentFindingLinks).toHaveBeenCalledTimes(1);
  });

  it("folds refresh bursts into one follow-up request and keeps the loaded groups visible", async () => {
    const pending: Array<(value: never) => void> = [];
    vi.mocked(listAssessmentFindingGroups).mockImplementation(() => new Promise((resolve) => { pending.push(resolve as never); }));
    const sibling = record("VA-005", "Sibling claim", { created_at: ago(HOUR) });
    const rows = [...ledger, sibling];
    const view = renderTab(rows);
    expect(pending).toHaveLength(1);
    await act(async () => { pending[0]([{ root: oldButChanged, siblings: [sibling], sibling_count: 1, residual_path_count: 0 }] as never); });
    expect(screen.getByText("1 engagement root-cause group")).toBeTruthy();
    for (const version of [1, 2, 3]) {
      view.rerender(<ToastProvider><FindingsTab engagementKey="acme" findings={rows as never[]} fallbackFindings={[]} chains={[]} chainLinks={[]} assessmentRefreshVersion={version} /></ToastProvider>);
    }
    expect(pending).toHaveLength(2);
    expect(screen.getByText("1 engagement root-cause group")).toBeTruthy();
    expect(screen.queryByText("Loading groups")).toBeNull();
    await act(async () => { pending[1]([{ root: oldButChanged, siblings: [sibling], sibling_count: 1, residual_path_count: 0 }] as never); });
    // Versions 2 and 3 arrived while version 1 was loading: one more request.
    expect(pending).toHaveLength(3);
    await act(async () => { pending[2]([] as never); });
    expect(pending).toHaveLength(3);
    expect(screen.getByText("No root-cause groups")).toBeTruthy();
  });
});

describe("runtime proof slot", () => {
  it("renders the supplied runtime proof section for a finding that owes proof", async () => {
    const owed = record("VA-006", "Proof owed claim", { verification_status: "pending_runtime_proof", created_at: ago(HOUR) });
    vi.mocked(getAssessmentFinding).mockResolvedValue(owed as never);
    const renderRuntimeProof = vi.fn((finding: { slug: string }) => <p>Proof work for {finding.slug}</p>);
    renderTab([owed], { renderRuntimeProof, initialFindingSlug: "VA-006" });
    expect(await screen.findByText("Proof work for VA-006")).toBeTruthy();
    expect(screen.getByText("Runtime proof outstanding")).toBeTruthy();
    expect(renderRuntimeProof).toHaveBeenCalledWith(expect.objectContaining({ slug: "VA-006", verification_status: "pending_runtime_proof" }));
  });

  it("does not render the runtime proof section for a finding that owes none", async () => {
    const renderRuntimeProof = vi.fn(() => <p>Proof work</p>);
    renderTab(ledger, { renderRuntimeProof, initialFindingSlug: "VA-001" });
    await screen.findByRole("heading", { name: "Old claim changed recently" });
    expect(screen.queryByText("Proof work")).toBeNull();
  });
});
