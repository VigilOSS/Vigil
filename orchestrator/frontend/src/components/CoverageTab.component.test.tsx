// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AssessmentSummary } from "../lib/api";
import { ToastProvider } from "../contexts/ToastContext";
import {
  fetchCoverageFacets,
  fetchCoverageItem,
  fetchCoveragePosition,
  fetchCoverageReasons,
  type CoverageFacets,
  type CoverageFilters,
  type CoverageItemDetail,
  type CoverageLedgerItem,
  type CoverageReasonRollup,
} from "../lib/coverageApi";
import { CoverageTab } from "./CoverageTab";

vi.mock("../lib/coverageApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/coverageApi")>()),
  fetchCoverageFacets: vi.fn(),
  fetchCoverageReasons: vi.fn(),
  fetchCoverageItem: vi.fn(),
  fetchCoveragePage: vi.fn(),
  fetchCoveragePosition: vi.fn(),
}));

const BLOCKED_REASON = "Needs a second tenant account; only one Acme tenant is provisioned.";

const row: CoverageLedgerItem = {
  id: 41,
  engagement_id: 1,
  request_variant_id: 44,
  service_id: null,
  application_unit_id: null,
  auth_context: "member",
  input_slot: "query",
  attack_family: "idor",
  status: "blocked",
  created_at: "2026-09-20 10:00:00",
  updated_at: "2026-09-21 12:30:00",
  method: "GET",
  canonical_url: "https://shop.acme.example/orders?id=1",
  normalized_path: "/orders",
  host: "shop.acme.example",
  service_endpoint: null,
  service_name: null,
  item_host: "shop.acme.example",
  latest_reason: BLOCKED_REASON,
  created_from: "Auto-generated from request observation",
};

// The grid is ag-grid in production; here it renders the filters it was given
// and reports the window the real grid would, so the tab's wiring is visible.
const gridFilters: CoverageFilters[] = [];
const gridSorts: unknown[] = [];
let gridWindowTotal = 1_240;
vi.mock("./coverage/CoverageGrid", () => ({
  default: ({ filters, sort, onRowOpen, onWindow, onSortChange }: {
    filters: CoverageFilters;
    sort?: unknown;
    onRowOpen: (item: CoverageLedgerItem, invoker: HTMLElement | null) => void;
    onWindow: (window: { total: number | null; first: number; last: number }) => void;
    onSortChange?: (order: { sort: "host" | "status"; dir: "asc" | "desc" }) => void;
  }) => {
    gridFilters.push(filters);
    gridSorts.push(sort);
    return (
      <div>
        <button type="button" onClick={() => onWindow({ total: gridWindowTotal, first: 1, last: Math.min(100, gridWindowTotal) })}>report window</button>
        <div data-record-key="41">
          <button type="button" onClick={(event) => onRowOpen(row, event.currentTarget)}>open row 41</button>
        </div>
        <div data-record-key="42">
          <button type="button">row 42</button>
        </div>
        <button type="button" onClick={() => onSortChange?.({ sort: "host", dir: "asc" })}>sort by host</button>
        <button type="button" onClick={() => onSortChange?.({ sort: "status", dir: "desc" })}>sort by status</button>
      </div>
    );
  },
}));

const statusTotals = { blocked: 1_000, deferred: 40, pending: 200, covered: 150, not_applicable: 10 };

function facets(total = 1_400): CoverageFacets {
  const group = (values: [string, number][]) => ({
    values: values.map(([value, count]) => ({ value, count })),
    distinct: values.length,
    omitted_count: 0,
  });
  return {
    total,
    status_totals: statusTotals,
    facets: {
      status: group(Object.entries(statusTotals)),
      attack_family: group([["endpoint-review", 700], ["idor", 300]]),
      auth_context: group([["member", 1_350], ["anonymous", 50]]),
      input_slot: group([["endpoint", 1_100], ["query", 90]]),
      method: group([["GET", 1_390], ["", 10]]),
      host: group([["shop.acme.example", 800], ["api.acme.example", 600]]),
    },
  };
}

const rollup: CoverageReasonRollup = {
  total: 1_240,
  statuses: [
    {
      status: "pending",
      count: 200,
      distinct: 1,
      omitted_count: 0,
      reasons: [{ reason: null, created_from: "gf bucket 'idor' matched at ingest", count: 200 }],
    },
    {
      status: "blocked",
      count: 1_000,
      distinct: 2,
      omitted_count: 0,
      reasons: [
        { reason: BLOCKED_REASON, created_from: null, count: 930 },
        { reason: "Gateway refuses both tenants.", created_from: null, count: 70 },
      ],
    },
    {
      status: "deferred",
      count: 40,
      distinct: 1,
      omitted_count: 0,
      reasons: [{ reason: "Deferred until the rate-limit window resets.", created_from: null, count: 40 }],
    },
  ],
};

const detail: CoverageItemDetail = {
  item: row,
  note_lines: [
    { text: "Auto-generated from request observation", provenance: true },
    { text: "First look: gateway returns 429.", provenance: false },
    { text: BLOCKED_REASON, provenance: false },
  ],
  work_items: {
    total: 1,
    items: [{
      id: 9,
      status: "skipped",
      retry_count: 2,
      terminal_reason: "coverage item blocked",
      triage_rationale: "needs second tenant",
      type: "api",
      source: "crawl",
      method: "GET",
      url: "https://shop.acme.example/orders?id=1",
      assigned_agent: null,
      priority_score: 10,
      priority_reason: null,
      live_status: null,
      consumed_at: null,
      created_at: "2026-09-20 10:00:00",
      updated_at: "2026-09-21 12:00:00",
    }],
  },
  probe_runs: {
    total: 1,
    items: [{
      id: 5,
      attack_family: "idor",
      input_slot: "query",
      auth_context: "member",
      payload_family: "",
      tool_name: "manual",
      agent_name: "web-specialist",
      result_status: "blocked",
      observed_http_status: 403,
      signal_type: "",
      outcome_assertion: "",
      evidence_ref: "scans/orders-idor.txt",
      notes: "",
      lens: "",
      target_host: "shop.acme.example",
      target_path: "/orders",
      finding_id: null,
      finding_slug: null,
      created_at: "2026-09-21 11:00:00",
    }],
  },
  request_variant: {
    id: 44,
    method: "GET",
    scheme: "https",
    host: "shop.acme.example",
    port: 443,
    normalized_path: "/orders",
    path_template: "",
    canonical_url: "https://shop.acme.example/orders?id=1",
    auth_context: "member",
    content_type_family: "unknown",
    discovery_source: "crawl",
    first_seen_at: "2026-09-20 10:00:00",
    last_seen_at: "2026-09-20 10:00:00",
  },
  service: null,
  blocked_techniques: [{
    id: 3,
    technique_key: "idor-orders",
    technique: "IDOR",
    target_kind: "endpoint",
    target_ref: "GET https://shop.acme.example/orders",
    reason: "Only one tenant provisioned.",
    retry_state: "blocked_on_dependency",
    evidence_ref: "",
    notes: "",
    created_at: "2026-09-21 10:00:00",
    updated_at: "2026-09-21 10:00:00",
    relation: "endpoint",
  }],
};

// Row 42 sits after row 41 in the server's order, in a block the grid never loaded.
const nextRow: CoverageLedgerItem = {
  ...row,
  id: 42,
  canonical_url: "https://shop.acme.example/orders/export",
  status: "deferred",
  latest_reason: "Deferred until the rate-limit window resets.",
};

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/demo?tab=coverage");
  gridFilters.length = 0;
  gridSorts.length = 0;
  gridWindowTotal = 1_240;
  vi.mocked(fetchCoveragePosition).mockImplementation(async (_key, id) => id === 41
    ? { index: 99, total: 1_240, previous: null, next: nextRow }
    : { index: 100, total: 1_240, previous: row, next: null });
  vi.mocked(fetchCoverageFacets).mockImplementation(async (_key, filters) => facets(filters.status.length ? 1_000 : 1_400));
  vi.mocked(fetchCoverageReasons).mockResolvedValue(rollup);
  vi.mocked(fetchCoverageItem).mockImplementation(async (_key, id) => id === 42 ? { ...detail, item: nextRow } : detail);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderTab(props: Partial<Parameters<typeof CoverageTab>[0]> = {}) {
  return render(<CoverageTab engagementKey="demo" summary={null} {...props} />, { wrapper: ToastProvider });
}

describe("CoverageTab", () => {
  it("states engagement-wide totals from the server, not from loaded rows", async () => {
    renderTab();
    const legend = await screen.findByRole("list", { name: "Status legend" });
    expect(within(legend).getByText("1,000")).toBeTruthy();
    expect(within(legend).getByText("Can't be tested with the current access or conditions.")).toBeTruthy();
    expect(within(legend).getByText("Intentionally postponed.")).toBeTruthy();
    // Open work = blocked + deferred + pending (+ queued), not a fixed sample.
    const stats = screen.getByRole("list", { name: "Summary" });
    expect(stats.textContent).toContain("1,240 open");
    expect(stats.textContent).toContain("1,400 items");
    expect(vi.mocked(fetchCoverageReasons).mock.calls[0][1].status).toEqual(["blocked", "deferred", "pending", "queued"]);
  });

  it("orders reason groups by status and shows why items have no reason yet", async () => {
    renderTab();
    const groups = await screen.findAllByRole("heading", { level: 3 });
    expect(groups.map((heading) => heading.textContent)).toEqual([
      expect.stringContaining("Blocked"),
      expect.stringContaining("Deferred"),
      expect.stringContaining("Pending"),
    ]);
    expect(screen.getByText(/No reason recorded yet/)).toBeTruthy();
    expect(screen.getByText(/created from: gf bucket 'idor' matched at ingest/)).toBeTruthy();
  });

  it("opens All items filtered to exactly the picked reason", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /View 930 items/ }));
    await screen.findByRole("button", { name: "Remove reason filter" });
    const applied = gridFilters.at(-1)!;
    expect(applied.status).toEqual(["blocked"]);
    expect(applied.reason).toBe(BLOCKED_REASON);
    expect(applied.reason_missing).toBe(false);
    expect(screen.getByRole("button", { name: /^All items/ }).getAttribute("aria-pressed")).toBe("true");
    await waitFor(() =>
      expect(vi.mocked(fetchCoverageFacets).mock.calls.some(([, filters]) => filters.reason === BLOCKED_REASON)).toBe(true),
    );

    fireEvent.click(screen.getByRole("button", { name: "Remove reason filter" }));
    expect(gridFilters.at(-1)!.reason).toBeNull();
    expect(gridFilters.at(-1)!.status).toEqual(["blocked"]);
  });

  it("filters never-touched items by their creation note", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /View 200 items/ }));
    await screen.findByRole("button", { name: "Remove reason filter" });
    const applied = gridFilters.at(-1)!;
    expect(applied.status).toEqual(["pending"]);
    expect(applied.reason ?? null).toBeNull();
    expect(applied.reason_missing).toBe(true);
    expect(applied.created_from).toBe("gf bucket 'idor' matched at ingest");
  });

  it("shows the visible window against the full matching total", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "report window" }));
    const summary = screen.getByText(/coverage items/, { selector: ".ui-results-summary" });
    expect(summary.textContent).toBe("1,240 of 1,400 coverage items · Sorted by Updated, newest first");
    expect(screen.getByText(/Rows 1–100 in view/)).toBeTruthy();
  });

  it("names the server's status order by urgency", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "sort by status" }));
    fireEvent.click(screen.getByRole("button", { name: "report window" }));
    expect(screen.getByText(/coverage items/, { selector: ".ui-results-summary" }).textContent).toContain("Sorted by Status, most urgent first");
  });

  it("explains an item in the shared record view: why, history, related work and techniques", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "open row 41" }));
    const record = await screen.findByRole("region", { name: "Coverage item record" });
    expect(screen.queryByRole("dialog")).toBeNull();
    // The record replaces the list and the page header.
    expect(screen.queryByRole("region", { name: "All coverage items" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Coverage" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=coverage&item=41");
    expect(fetchCoverageItem).toHaveBeenCalledWith("demo", 41);
    expect(within(record).getByText("Coverage item #41")).toBeTruthy();
    expect(within(record).getByText("Can't be tested with the current access or conditions.")).toBeTruthy();
    expect(within(record).getByLabelText("Coverage item dates").textContent).toContain("Last updated");
    await within(record).findByText("Created from");
    expect(within(record).getByText("Auto-generated from request observation")).toBeTruthy();
    expect(within(record).getByText("Note 1")).toBeTruthy();
    expect(within(record).getByText("Note 2 · latest")).toBeTruthy();
    expect(within(record).getByText("First look: gateway returns 429.")).toBeTruthy();

    fireEvent.click(within(record).getByRole("button", { name: /^Related work/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=coverage&item=41&dtab=work");
    expect(within(record).getByText(/2 retries/)).toBeTruthy();
    expect(within(record).getByText("coverage item blocked")).toBeTruthy();
    expect(within(record).getByText("needs second tenant")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Probe runs/ }));
    expect(within(record).getByText("scans/orders-idor.txt")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Blocked techniques/ }));
    expect(within(record).getByText("Waiting on a dependency")).toBeTruthy();
    expect(within(record).getByText("This endpoint")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Request/ }));
    expect(within(record).getByRole("link", { name: "Open request variant #44" }).getAttribute("href")).toBe(
      "#/engagements/demo?tab=http&request=44",
    );

    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(screen.queryByRole("region", { name: "Coverage item record" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=coverage");
    expect(screen.getByRole("region", { name: "All coverage items" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "open row 41" })));
  });

  it("steps through the server's paged order under the grid's sort, past the loaded rows", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "sort by host" }));
    fireEvent.click(screen.getByRole("button", { name: "open row 41" }));
    const record = await screen.findByRole("region", { name: "Coverage item record" });
    expect(await within(record).findByText("100 of 1,240 results")).toBeTruthy();
    expect(fetchCoveragePosition).toHaveBeenCalledWith("demo", 41, expect.objectContaining({ status: [] }), { sort: "host", dir: "asc" });
    expect((within(record).getByRole("button", { name: "Previous coverage item" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(within(record).getByRole("button", { name: /^Probe runs/ }));
    fireEvent.click(within(record).getByRole("button", { name: "Next coverage item" }));
    expect(within(record).getByText("101 of 1,240 results")).toBeTruthy();
    expect(await within(record).findByRole("heading", { level: 2, name: /\/orders\/export/ })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=coverage&item=42&dtab=probes");
    expect(within(record).getByRole("button", { name: /^Probe runs/ }).getAttribute("aria-current")).toBe("page");
    await waitFor(() => expect((within(record).getByRole("button", { name: "Next coverage item" }) as HTMLButtonElement).disabled).toBe(true));
    expect(fetchCoveragePosition).toHaveBeenLastCalledWith("demo", 42, expect.anything(), { sort: "host", dir: "asc" });

    fireEvent.keyDown(document.body, { key: "[" });
    expect(await within(record).findByRole("heading", { level: 2, name: /\/orders\?id=1/ })).toBeTruthy();
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Coverage item record" })).toBeNull();
  });

  it("opens a deep-linked item on its section and follows history back to the list", async () => {
    const view = renderTab({ initialItemId: 41, initialDrawerTab: "probes" });
    const record = await screen.findByRole("region", { name: "Coverage item record" });
    expect(await within(record).findByText("scans/orders-idor.txt")).toBeTruthy();
    expect(within(record).getByRole("button", { name: /^Probe runs/ }).getAttribute("aria-current")).toBe("page");
    expect(await within(record).findByText("100 of 1,240 results")).toBeTruthy();
    view.rerender(<CoverageTab engagementKey="demo" summary={null} />);
    await waitFor(() => expect(screen.queryByRole("region", { name: "Coverage item record" })).toBeNull());
    expect(screen.getByRole("button", { name: /^All items/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("says when the open item does not match the current filters", async () => {
    vi.mocked(fetchCoveragePosition).mockResolvedValue({ index: null, total: 40, previous: null, next: null });
    renderTab({ initialItemId: 41 });
    const record = await screen.findByRole("region", { name: "Coverage item record" });
    expect(await within(record).findByText("Outside current results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Next coverage item" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("reloads counts on live refresh without refetching for every burst", async () => {
    const view = renderTab({ refreshVersion: 0 });
    await screen.findByRole("list", { name: "Status legend" });
    const before = vi.mocked(fetchCoverageFacets).mock.calls.length;
    view.rerender(<CoverageTab engagementKey="demo" summary={null} refreshVersion={1} />);
    await waitFor(() => expect(vi.mocked(fetchCoverageFacets).mock.calls.length).toBe(before + 1));
    vi.useFakeTimers({ now: Date.now() });
    try {
      view.rerender(<CoverageTab engagementKey="demo" summary={null} refreshVersion={2} />);
      view.rerender(<CoverageTab engagementKey="demo" summary={null} refreshVersion={3} />);
      expect(vi.mocked(fetchCoverageFacets).mock.calls.length).toBe(before + 1);
      await vi.advanceTimersByTimeAsync(6_000);
    } finally {
      vi.useRealTimers();
    }
    await waitFor(() => expect(vi.mocked(fetchCoverageFacets).mock.calls.length).toBe(before + 2));
  });

  it("keeps the grid's sort when the operator switches views, so Previous / Next walk the order shown", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "sort by host" }));
    fireEvent.click(screen.getByRole("button", { name: /^Open work by reason/ }));
    await screen.findByRole("button", { name: /View 930 items/ });
    fireEvent.click(screen.getByRole("button", { name: /^All items/ }));
    await screen.findByRole("button", { name: "open row 41" });
    // The remounted grid starts from the order the record navigation walks.
    expect(gridSorts.at(-1)).toEqual({ sort: "host", dir: "asc" });
    fireEvent.click(screen.getByRole("button", { name: "open row 41" }));
    await screen.findByRole("region", { name: "Coverage item record" });
    await waitFor(() => expect(fetchCoveragePosition).toHaveBeenLastCalledWith("demo", 41, expect.anything(), { sort: "host", dir: "asc" }));
  });

  it("returns to the record last shown, not the row that opened the first one", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    fireEvent.click(await screen.findByRole("button", { name: "open row 41" }));
    const record = await screen.findByRole("region", { name: "Coverage item record" });
    await within(record).findByText("100 of 1,240 results");
    fireEvent.click(within(record).getByRole("button", { name: "Next coverage item" }));
    expect(await within(record).findByRole("heading", { level: 2, name: /\/orders\/export/ })).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(document.activeElement?.closest("[data-record-key]")?.getAttribute("data-record-key")).toBe("42"));
  });

  it("says once that an empty engagement has no coverage items yet", async () => {
    vi.mocked(fetchCoverageFacets).mockResolvedValue({
      total: 0,
      status_totals: {},
      facets: {
        status: { values: [], distinct: 0, omitted_count: 0 },
        attack_family: { values: [], distinct: 0, omitted_count: 0 },
        auth_context: { values: [], distinct: 0, omitted_count: 0 },
        input_slot: { values: [], distinct: 0, omitted_count: 0 },
        method: { values: [], distinct: 0, omitted_count: 0 },
        host: { values: [], distinct: 0, omitted_count: 0 },
      },
    });
    vi.mocked(fetchCoverageReasons).mockResolvedValue({ total: 0, statuses: [] });
    renderTab();
    expect(await screen.findByText("No coverage items recorded yet.")).toBeTruthy();
    expect(screen.getAllByText(/No coverage items recorded yet/)).toHaveLength(1);
  });

  it("offers Clear filters when no item matches, and says so in one wording", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^Blocked/ }));
    await screen.findByRole("button", { name: "open row 41" });
    gridWindowTotal = 0;
    fireEvent.click(screen.getByRole("button", { name: "report window" }));
    expect(await screen.findByText("No coverage items match these filters.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Clear filters (1)" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(gridFilters.at(-1)!.status).toEqual([]);
  });

  it("names the page in the shared page header with its open and total counts", async () => {
    renderTab();
    expect(await screen.findByRole("heading", { level: 1, name: "Coverage" })).toBeTruthy();
    const stats = await screen.findByRole("list", { name: "Summary" });
    await waitFor(() => expect(stats.textContent).toContain("1,240 open"));
    expect(stats.textContent).toContain("1,400 items");
  });

  it("keeps its view, filters, search and sort when the operator leaves the tab and comes back", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^All items/ }));
    const statusChips = await screen.findByRole("group", { name: "Status" });
    fireEvent.click(within(statusChips).getByRole("button", { name: /^Blocked/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search coverage items" }), { target: { value: "orders" } });
    fireEvent.click(screen.getByRole("button", { name: "sort by host" }));
    await waitFor(() => expect(gridFilters.at(-1)!.q).toBe("orders"));
    cleanup();
    gridFilters.length = 0;
    gridSorts.length = 0;

    renderTab();
    expect(screen.getByRole("button", { name: /^All items/ }).getAttribute("aria-pressed")).toBe("true");
    await screen.findByRole("button", { name: "open row 41" });
    expect(gridFilters.at(-1)).toEqual(expect.objectContaining({ status: ["blocked"], q: "orders" }));
    expect(gridSorts.at(-1)).toEqual({ sort: "host", dir: "asc" });
    expect((screen.getByRole("searchbox", { name: "Search coverage items" }) as HTMLInputElement).value).toBe("orders");
  });

  it("keeps the reason view's closed-items choice per engagement across visits", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("checkbox", { name: /Include covered and not-applicable items/ }));
    await waitFor(() => expect(vi.mocked(fetchCoverageReasons).mock.calls.at(-1)![1].status).toEqual([]));
    cleanup();
    renderTab();
    expect((screen.getByRole("checkbox", { name: /Include covered and not-applicable items/ }) as HTMLInputElement).checked).toBe(true);
    cleanup();
    renderTab({ engagementKey: "other" });
    expect((screen.getByRole("checkbox", { name: /Include covered and not-applicable items/ }) as HTMLInputElement).checked).toBe(false);
  });

  it("offers Try again when the coverage totals fail to load", async () => {
    vi.mocked(fetchCoverageFacets).mockRejectedValueOnce(new Error("upstream timeout"));
    renderTab();
    const alert = await screen.findByText(/Coverage totals unavailable: upstream timeout/);
    fireEvent.click(within(alert).getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("list", { name: "Status legend" })).toBeTruthy();
  });

  it("keeps the service-level rollup reachable", async () => {
    const summary = {
      service_coverage_gaps: [
        { endpoint: "api.acme.example:443", service: "https", coverage_status: "blocked", updated_at: "2026-09-21 10:00:00" },
      ],
    } as unknown as AssessmentSummary;
    renderTab({ summary });
    await screen.findByRole("list", { name: "Status legend" });
    expect(screen.getByText("api.acme.example:443")).toBeTruthy();
  });
});
