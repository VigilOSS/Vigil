// @vitest-environment jsdom

// The Findings queue and how a finding is opened from it: status and severity
// read as words, the jump palette honours an exact slug, every page of a long
// list can be turned from either end, the empty states say which case applies,
// a link can carry filters in, Back lands on the record last shown, and a deep
// link or a live refresh reads the open finding's detail exactly once.

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

vi.mock("./FindingsGrid", () => ({ default: ({ rows, onOpen, onSortChange }: { rows: Derived[]; onOpen: (slug: string) => void; onSortChange?: (named: string | null, column: unknown) => void }) => (
  <div data-testid="grid">
    <button onClick={() => onSortChange?.(null, { label: "Title", direction: "asc", kind: "text" })}>Sort by title</button>
    {rows.map((row) => <div key={row.slug} className="ag-row" row-id={row.slug}><button onClick={() => onOpen(row.slug)}>Grid {row.title}</button></div>)}
  </div>
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

function record(slug: string, title: string, over: Record<string, unknown> = {}) {
  return {
    id: Number(slug.replace(/\D/g, "")) || 1, slug, title, severity: "medium",
    workflow_status: "active", submission_status: "none", verification_status: "confirmed",
    canonical_location: `https://app.example/${slug.toLowerCase()}`, summary: "Acme portal claim.",
    source_name: "vulnerability-analyst", row_version: 1, evidence_ref: "", notes: "",
    defect_family: "authorization", root_cause_key: slug, auth_context: "", details: {}, provenance: {},
    created_at: "2026-10-01 10:00:00", updated_at: "2026-10-01 10:00:00", last_seen_at: "2026-10-01 10:00:00",
    ...over,
  };
}

// A point read carries the verification audit and receipts the list rows omit.
function detail(row: ReturnType<typeof record>) {
  return { ...row, proof_receipts: [], verification_audit: { proof_receipt_ids: [], proof_receipt_total: 0, counter_checks: [], counter_check_total: 0, severity_variances: [], severity_variance_total: 0, record_limit: 20, truncated: false } };
}

type TabProps = Parameters<typeof FindingsTab>[0];

function tab(over: Partial<TabProps> = {}) {
  const props: TabProps = { engagementKey: "acme", findings: [], fallbackFindings: [], chains: [], chainLinks: [], assessmentRefreshVersion: 0, ...over } as TabProps;
  return <ToastProvider><FindingsTab {...props} /></ToastProvider>;
}

function queue() {
  return screen.getByRole("region", { name: "Finding queue" });
}

beforeEach(() => {
  vi.mocked(getAssessmentFinding).mockReset();
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
  vi.restoreAllMocks();
});

describe("opening a finding reads its detail once", () => {
  it("lets operators filter from the disclosure and remove a selected facet from the queue", async () => {
    render(tab({ findings: [record("VA-001", "Medium claim"), record("VA-002", "High claim", { severity: "high" })] as never[] }));
    const trigger = screen.getByRole("button", { name: "Filters (0)" });
    fireEvent.click(trigger);
    const filters = screen.getByRole("region", { name: "Finding filters" });
    expect(filters.contains(document.activeElement)).toBe(true);
    fireEvent.click(within(filters).getByRole("button", { name: /High/ }));
    expect(within(queue()).getByText("High claim")).toBeTruthy();
    fireEvent.keyDown(filters, { key: "Escape" });
    expect(document.activeElement).toBe(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(trigger);
    fireEvent.pointerDown(screen.getByRole("banner"));
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByRole("button", { name: "Filters (1)" })).toBeTruthy();
    fireEvent.click(trigger);
    act(() => within(queue()).getByRole("button", { name: /High claim/ }).focus());
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: "Remove severity High" }));
    expect(within(queue()).getByText("Medium claim")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Filters (0)" })).toBeTruthy();
  });

  it("looks a deep-linked finding up once while the page around it keeps re-rendering", async () => {
    const listed = record("VA-012", "Export claim");
    vi.mocked(getAssessmentFinding).mockResolvedValue(detail(listed) as never);
    const view = render(tab({ initialFindingSlug: "VA-012", ledgerLoading: true }));
    await screen.findByRole("heading", { name: "Export claim" });
    // The workspace re-renders while its ledger loads; each pass hands over
    // fresh (empty) arrays.
    for (let pass = 0; pass < 5; pass += 1) view.rerender(tab({ initialFindingSlug: "VA-012", ledgerLoading: true, findings: [], fallbackFindings: [] }));
    await act(async () => {});
    // The ledger arrives with the same row version as the point read.
    view.rerender(tab({ initialFindingSlug: "VA-012", findings: [{ ...listed }] as never[] }));
    await act(async () => {});
    expect(getAssessmentFinding).toHaveBeenCalledTimes(1);
  });

  it("reads a deep-linked finding once when the ledger lands before its lookup returns", async () => {
    const listed = record("VA-012", "Export claim");
    let finish!: (value: unknown) => void;
    vi.mocked(getAssessmentFinding).mockImplementation(() => new Promise((resolve) => { finish = resolve; }) as never);
    const view = render(tab({ initialFindingSlug: "VA-012", ledgerLoading: true }));
    view.rerender(tab({ initialFindingSlug: "VA-012", findings: [{ ...listed }] as never[] }));
    await screen.findByRole("heading", { name: "Export claim" });
    await act(async () => { finish(detail(listed)); });
    await act(async () => {});
    expect(getAssessmentFinding).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("re-reads the open finding once per live refresh, however its ledger row arrives", async () => {
    const listed = record("VA-012", "Export claim");
    vi.mocked(getAssessmentFinding).mockResolvedValue(detail(listed) as never);
    const view = render(tab({ initialFindingSlug: "VA-012", findings: [listed] as never[] }));
    await screen.findByRole("heading", { name: "Export claim" });
    await act(async () => {});
    expect(getAssessmentFinding).toHaveBeenCalledTimes(1);
    // One refresh pass: the version bumps, then the re-read ledger arrives as new objects.
    view.rerender(tab({ initialFindingSlug: "VA-012", findings: [listed] as never[], assessmentRefreshVersion: 1 }));
    await act(async () => {});
    view.rerender(tab({ initialFindingSlug: "VA-012", findings: [{ ...listed }] as never[], assessmentRefreshVersion: 1 }));
    await act(async () => {});
    expect(getAssessmentFinding).toHaveBeenCalledTimes(2);
  });
});

describe("status and severity read as words", () => {
  const rows = [
    record("VA-001", "Draft claim", { workflow_status: "draft", verification_status: "pending_runtime_proof", severity: "high" }),
    record("VA-002", "Blocked claim", { verification_status: "blocked", severity: "low" }),
  ];

  it("labels every workflow and verification chip in sentence case", () => {
    render(tab({ findings: rows as never[] }));
    fireEvent.click(screen.getByRole("button", { name: /^Filters \(/ }));
    expect(within(screen.getByRole("group", { name: "Workflow" })).getByRole("button", { name: /^Draft/ })).toBeTruthy();
    const verification = screen.getByRole("group", { name: "Verification" });
    expect(within(verification).getByRole("button", { name: /^Pending runtime proof/ })).toBeTruthy();
    expect(within(verification).getByRole("button", { name: /^Blocked/ })).toBeTruthy();
    expect(within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: /^High/ })).toBeTruthy();
  });

  it("names the verification state in the record header", async () => {
    vi.mocked(getAssessmentFinding).mockResolvedValue(detail(rows[0]) as never);
    render(tab({ findings: rows as never[], initialFindingSlug: "VA-001" }));
    await screen.findByRole("heading", { name: "Draft claim" });
    const header = screen.getByRole("region", { name: "Finding investigation" });
    const labels = Array.from(header.querySelectorAll(".ui-status-label")).map((node) => node.textContent);
    expect(labels).toEqual(expect.arrayContaining(["Draft", "Pending runtime proof"]));
  });

  it("shows each row's severity as text, not colour alone", () => {
    render(tab({ findings: rows as never[] }));
    expect(within(screen.getByRole("button", { name: /Draft claim/ })).getByText("High")).toBeTruthy();
    expect(within(screen.getByRole("button", { name: /Blocked claim/ })).getByText("Low")).toBeTruthy();
  });

  it("names each bar of the header severity chart", () => {
    render(tab({ findings: rows as never[] }));
    const chart = screen.getByRole("img", { name: /Severity mix/ });
    expect(chart.getAttribute("aria-label")).toBe("Severity mix: Critical 0, High 1, Medium 0, Low 1, Info 0");
    expect(chart.textContent).toContain("High");
  });
});

describe("root-cause groups", () => {
  it("shows the root's own severity and names a more severe sibling separately", async () => {
    const root = record("VA-061", "Root claim", { severity: "medium" });
    const sibling = record("VA-164", "Sibling claim", { severity: "high" });
    vi.mocked(listAssessmentFindingGroups).mockResolvedValue([{ root, siblings: [sibling], sibling_count: 1, residual_path_count: 1 }] as never);
    render(tab({ findings: [root, sibling] as never[] }));
    await waitFor(() => expect(screen.queryByText("Loading groups")).toBeNull());
    const card = screen.getByRole("button", { name: /Root claim/ }).closest(".root-group-card") as HTMLElement;
    const head = card.querySelector(".group-card-head") as HTMLElement;
    expect(within(head).getByText("Medium")).toBeTruthy();
    expect(head.textContent).toContain("Highest in group: High");
    expect(head.textContent).toContain("1 sibling");
    expect(head.textContent).not.toContain("1 siblings");
  });
});

describe("paging", () => {
  it("offers the pager after the list as well as before it", () => {
    const rows = Array.from({ length: 30 }, (_, index) => record(`VA-${100 + index}`, `Claim ${index}`));
    render(tab({ findings: rows as never[] }));
    const pagers = screen.getAllByRole("navigation", { name: /Result pages/ });
    expect(pagers).toHaveLength(2);
    fireEvent.click(within(pagers[1]).getByRole("button", { name: "Next" }));
    for (const pager of screen.getAllByRole("navigation", { name: /Result pages/ })) expect(pager.textContent).toContain("Page 2 of 2");
  });
});

describe("search", () => {
  it("matches a double quote only where the finding's text has one", () => {
    const rows = [
      record("VA-001", "Plain claim"),
      record("VA-002", "Request claim", { details: { poc_request: { method: "GET", url: "https://app.example/x" } } }),
      record("VA-003", "Quoted \"payload\" claim"),
    ];
    render(tab({ findings: rows as never[] }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search findings" }), { target: { value: "\"" } });
    const titles = Array.from(queue().querySelectorAll(".mini-finding-row strong")).map((node) => node.textContent);
    expect(titles).toEqual(["Quoted \"payload\" claim"]);
  });
});

describe("empty states", () => {
  it("shows only an explanation when nothing is recorded yet", () => {
    render(tab());
    expect(screen.getByText("No findings recorded yet.")).toBeTruthy();
    expect(screen.queryByRole("group", { name: "Severity" })).toBeNull();
    expect(screen.queryByRole("img", { name: /Severity mix/ })).toBeNull();
    expect(screen.queryByText("focus search")).toBeNull();
  });

  it("offers Clear filters when the filters match nothing", () => {
    render(tab({ findings: [record("VA-001", "Only claim")] as never[] }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search findings" }), { target: { value: "no such claim" } });
    expect(screen.getByText("No findings match these filters.")).toBeTruthy();
    fireEvent.click(within(queue()).getByRole("button", { name: "Clear filters" }));
    expect(screen.getByRole("button", { name: /Only claim/ })).toBeTruthy();
  });
});

describe("order", () => {
  it("names the table column the operator sorted by", async () => {
    render(tab({ findings: [record("VA-001", "Only claim")] as never[] }));
    fireEvent.click(screen.getByRole("button", { name: "Table" }));
    fireEvent.click(await screen.findByRole("button", { name: "Sort by title" }));
    expect(queue().textContent).toContain("Sorted by Title, A to Z");
  });
});

describe("jump palette", () => {
  it("opens the finding whose slug is typed exactly, ahead of findings that only mention it", () => {
    const rows = [
      record("VA-061", "Medium root", { severity: "medium" }),
      record("VA-164", "High sibling of VA-061", { severity: "high", summary: "Builds on VA-061." }),
    ];
    vi.mocked(getAssessmentFinding).mockImplementation(async (_key, slug) => detail(rows.find((row) => row.slug === slug)!) as never);
    render(tab({ findings: rows as never[] }));
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    const input = screen.getByRole("textbox", { name: "Search findings to jump to" });
    fireEvent.change(input, { target: { value: "VA-061" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(screen.getByRole("heading", { name: "Medium root" })).toBeTruthy();
  });

  it("says how many matches it does not list", () => {
    const rows = Array.from({ length: 33 }, (_, index) => record(`VA-${200 + index}`, `Stored XSS ${index}`));
    render(tab({ findings: rows as never[] }));
    fireEvent.click(screen.getByRole("button", { name: /Jump to…/ }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search findings to jump to" }), { target: { value: "xss" } });
    expect(screen.getByRole("dialog", { name: "Jump to finding" }).textContent).toContain("Showing 30 of 33 matches");
  });
});

describe("links that carry filters", () => {
  it("applies verification filters named in the address and then drops them from it", () => {
    window.history.replaceState(null, "", "#/engagements/acme?tab=findings&verification=unreviewed,blocked");
    const rows = [
      record("VA-001", "Unreviewed claim", { verification_status: "unreviewed" }),
      record("VA-002", "Blocked claim", { verification_status: "blocked" }),
      record("VA-003", "Verified claim"),
    ];
    render(tab({ findings: rows as never[] }));
    fireEvent.click(screen.getByRole("button", { name: /^Filters \(/ }));
    const verification = screen.getByRole("group", { name: "Verification" });
    expect(within(verification).getByRole("button", { name: /^Unreviewed/ }).getAttribute("aria-pressed")).toBe("true");
    expect(within(verification).getByRole("button", { name: /^Blocked/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.queryByRole("button", { name: /Verified claim/ })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/acme?tab=findings");
  });
});

describe("links that carry a search", () => {
  it("opens the queue on the code findings when the address names their location", () => {
    window.history.replaceState(null, "", "#/engagements/acme?tab=findings&q=location:file:");
    const rows = [
      record("CH-001", "Source claim", { canonical_location: "file:src/export.ts:42" }),
      record("VA-002", "Runtime claim", { canonical_location: "https://app.example/export" }),
    ];
    render(tab({ findings: rows as never[] }));
    expect((screen.getByRole("textbox", { name: "Search findings" }) as HTMLInputElement).value).toBe("location:file:");
    expect(screen.getByRole("button", { name: /Source claim/ })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Runtime claim/ })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/acme?tab=findings");
  });
});

describe("links followed while the queue is open", () => {
  it("applies filters from a new address without leaving the page", () => {
    const rows = [
      record("VA-001", "Unreviewed claim", { verification_status: "unreviewed" }),
      record("VA-003", "Verified claim"),
    ];
    render(tab({ findings: rows as never[] }));
    expect(screen.getByRole("button", { name: /Verified claim/ })).toBeTruthy();
    act(() => {
      window.history.pushState(null, "", "#/engagements/acme?tab=findings&verification=unreviewed");
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(screen.queryByRole("button", { name: /Verified claim/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /^Filters \(/ }));
    expect(within(screen.getByRole("group", { name: "Verification" })).getByRole("button", { name: /^Unreviewed/ }).getAttribute("aria-pressed")).toBe("true");
    expect(window.location.hash).toBe("#/engagements/acme?tab=findings");
  });
});

describe("returning to the results", () => {
  it("lands on the record last shown, on its page", async () => {
    const rows = Array.from({ length: 26 }, (_, index) => record(`VA-${100 + index}`, `Claim ${String(index).padStart(2, "0")}`));
    vi.mocked(getAssessmentFinding).mockImplementation(async (_key, slug) => detail(rows.find((row) => row.slug === slug)!) as never);
    render(tab({ findings: rows as never[] }));
    fireEvent.click(screen.getByRole("button", { name: /Claim 24/ }));
    await screen.findByRole("heading", { name: "Claim 24" });
    fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
    await screen.findByRole("heading", { name: "Claim 25" });
    fireEvent.click(screen.getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(document.activeElement?.closest("[data-record-key]")?.getAttribute("data-record-key")).toBe("VA-125"));
    expect(screen.getAllByRole("navigation", { name: /Result pages/ })[0].textContent).toContain("Page 2 of 2");
  });
});

describe("runtime proof inside a finding", () => {
  it("puts the outstanding proof work before the long claim", async () => {
    const owed = record("VA-006", "Proof owed claim", { verification_status: "pending_runtime_proof", summary: "A long claim." });
    vi.mocked(getAssessmentFinding).mockResolvedValue(detail(owed) as never);
    render(tab({ findings: [owed] as never[], initialFindingSlug: "VA-006", renderRuntimeProof: () => <p>Proof card</p> }));
    const card = await screen.findByText("Proof card");
    const claim = screen.getByText("Security claim");
    expect(card.compareDocumentPosition(claim) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("counts a single residual path and sibling in the singular", async () => {
    const root = record("VA-061", "Root claim");
    const sibling = record("VA-164", "Sibling claim");
    vi.mocked(listAssessmentFindingGroups).mockResolvedValue([{ root, siblings: [sibling], sibling_count: 1, residual_path_count: 1 }] as never);
    vi.mocked(getAssessmentFinding).mockResolvedValue(detail(root) as never);
    render(tab({ findings: [root, sibling] as never[], initialFindingSlug: "VA-061" }));
    await screen.findByRole("heading", { name: "Root claim" });
    await waitFor(() => expect(screen.getByLabelText("Current attention").textContent).toContain("Root · 1 sibling"));
    expect(screen.getByLabelText("Current attention").textContent).not.toContain("siblings");
  });
});

describe("record actions", () => {
  it("opens a current finding in Submissions and offers no link for a merged one", async () => {
    const current = record("VA-012", "Export claim");
    const merged = record("VA-013", "Merged claim", { workflow_status: "merged" });
    vi.mocked(getAssessmentFinding).mockImplementation(async (_key, slug) => detail(slug === "VA-012" ? current : merged) as never);
    const view = render(tab({ findings: [current, merged] as never[], initialFindingSlug: "VA-012" }));
    await screen.findByRole("heading", { name: "Export claim" });
    expect(screen.getByRole("link", { name: "Open in Submissions" }).getAttribute("href")).toBe("#/engagements/acme?tab=submissions&submission=VA-012");
    view.rerender(tab({ findings: [current, merged] as never[], initialFindingSlug: "VA-013" }));
    await screen.findByRole("heading", { name: "Merged claim" });
    expect(screen.queryByRole("link", { name: "Open in Submissions" })).toBeNull();
  });
});
