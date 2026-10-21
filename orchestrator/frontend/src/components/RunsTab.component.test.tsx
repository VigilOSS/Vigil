// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  getAssessmentRun,
  getAssessmentRunComparison,
  listAssessmentRunChildren,
  listAssessmentRuns,
  type AssessmentRunChild,
  type AuditPage,
} from "../lib/api";
import type { AssessmentRun } from "../lib/api";
import type { RunRow } from "../lib/runAudit";
import { ToastProvider } from "../contexts/ToastContext";
import { RunsTab } from "./RunsTab";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ApiError: actual.ApiError,
    getAssessmentRun: vi.fn(),
    getAssessmentRunComparison: vi.fn(),
    listAssessmentRunChildren: vi.fn(),
    listAssessmentRuns: vi.fn(),
  };
});

// The grid is ag-grid in production; here a plain list exposes the rows the
// workspace hands it, in order, with their derived health. `gridSort` stands
// in for a header click: the grid reports the order and sort it shows.
const gridSort: {
  compare: ((a: RunRow, b: RunRow) => number) | null;
  state: { colId: string; sort: "asc" | "desc" }[] | null;
  silent: boolean;
} = { compare: null, state: null, silent: false };
const gridProps: { initialSort?: { colId: string; sort: "asc" | "desc" } | null } = {};
vi.mock("./RunsGrid", async () => {
  const { useEffect } = await import("react");
  return {
    default: function RunsGridMock({ rows, onRowOpen, onViewChange, initialSort }: {
      rows: RunRow[];
      onRowOpen: (id: number, invoker: HTMLElement) => void;
      onViewChange?: (view: { ids: number[]; sort: { colId: string; sort: "asc" | "desc" }[] }) => void;
      initialSort?: { colId: string; sort: "asc" | "desc" } | null;
    }) {
      gridProps.initialSort = initialSort;
      const shown = gridSort.compare ? [...rows].sort(gridSort.compare) : rows;
      const order = shown.map((row) => row.id).join(",");
      const sort = JSON.stringify(gridSort.state ?? (initialSort ? [initialSort] : [{ colId: "started", sort: "desc" }]));
      useEffect(() => {
        if (!gridSort.silent) onViewChange?.({ ids: order ? order.split(",").map(Number) : [], sort: JSON.parse(sort) });
      }, [order, sort, onViewChange]);
      return (
        <div data-testid="runs-grid">
          {shown.map((row) => (
            <button key={row.id} type="button" onClick={(event) => onRowOpen(row.id, event.currentTarget)}>
              {`row ${row.name} ${row.health.key} ${row.health.status} ${row.health.reason}`}
            </button>
          ))}
        </div>
      );
    },
  };
});

function renderTab(ui: ReactElement) {
  return render(ui, { wrapper: ToastProvider });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((next, fail) => { resolve = next; reject = fail; });
  return { promise, resolve, reject };
}

function page(items: AssessmentRunChild[], total = items.length, offset = 0, hasMore = false): AuditPage<AssessmentRunChild> {
  return { items, total, offset, limit: 50, has_more: hasMore };
}

const proofRun: AssessmentRun = {
  id: 42,
  run_uuid: "acme-export-replay",
  run_kind: "web",
  run_purpose: "proof",
  status: "completed",
  created_at: "2026-10-10 22:26:22",
  started_at: "2026-10-10 22:26:22",
  finished_at: "2026-10-10 22:27:10",
  elapsed_seconds: 48,
  producer_dispatch_id: 5,
  producer_dispatch_agent_id: "acme-va-1",
  producer_dispatch_agent_role: "vulnerability-analyst",
  producer_dispatch_task: "Replay the Acme export request with another tenant's id",
  dispatch_finding_slugs: ["VA-007"],
  associated_finding_slugs: ["VA-007"],
  finding_slugs: [],
  counts: { proof_receipts: 1, findings: 0 },
  proof_health: { healthy: 1, missing: 0, stale: 0, tombstoned: 0 },
  evidence_kind_counts: { http_exchange: 1 },
  blockers: [],
  proof_work_ids: [3],
  target_identity: {},
  lifecycle_history: [
    { id: 1, from_status: null, to_status: "running", created_at: "2026-10-10 22:26:22" },
    { id: 2, from_status: "running", to_status: "completed", created_at: "2026-10-10 22:27:10" },
  ],
  launcher_effective_client: "codex",
  requested_model: "gpt-acme",
};

const staleRun: AssessmentRun = {
  ...proofRun,
  id: 41,
  run_uuid: "acme-import-replay",
  producer_dispatch_task: "Check the Acme import parser",
  dispatch_finding_slugs: ["VA-009"],
  associated_finding_slugs: [],
  proof_health: { healthy: 0, missing: 0, stale: 1, tombstoned: 0 },
  blockers: [{
    code: "proof_stale",
    message: "1 proof receipt(s) are stale.",
    object_type: "proof_receipts",
    object_id: 41,
    action: "restore or replace the proof before completion",
  }],
  proof_work_ids: [],
};

const scanRun: AssessmentRun = {
  ...proofRun,
  id: 40,
  run_uuid: "acme-source-scan",
  run_kind: "code",
  run_purpose: "scan",
  status: "partial",
  producer_dispatch_task: "Review declared Acme source roots",
  dispatch_finding_slugs: [],
  associated_finding_slugs: [],
  evidence_kind_counts: {},
  counts: { inventory_total: 2, obligations: 1, proof_receipts: 0 },
  target_identity: {
    host: "app.example.com",
    aws_secret_access_key: "aws-private-value",
    authorization: "Bearer opaque-token",
  },
  blockers: [{
    code: "unresolved_obligation",
    message: "Hard obligation repo-review is open.",
    object_type: "obligation",
    object_id: 9,
    action: "resolve with recorded evidence or retain a partial run",
  }],
  proof_work_ids: [],
  seal: {
    requested_status: "completed",
    effective_status: "partial",
    dispatch_provenance: {
      dispatch_id: 5,
      agent_id: "acme-hunter",
      requested_client: "claude",
      launcher_effective_client: "codex",
      provider_observed_client: "unknown",
      client_name: "codex",
      launcher_effective_model: null,
    },
  },
  seal_sha256: "c".repeat(64),
};

const receipt: AssessmentRunChild = {
  id: 343,
  evidence_kind: "http_exchange",
  evidence_health: "healthy",
  expected_result: "The export denies another tenant",
  observed_result: "HTTP 200 with the other tenant's rows",
  artifact_relative_path: "evidence/export.txt",
  evidence_sha256: "a".repeat(64),
  created_at: "2026-10-10 22:26:56",
  origin_run_id: 42,
};

// The list renders the grid lazily: load it once up front so no test's first
// grid render waits on a cold module import.
beforeAll(async () => {
  await import("./RunsGrid");
});

beforeEach(() => {
  window.history.replaceState(null, "", "#/engagements/acme?tab=runs");
  vi.mocked(listAssessmentRuns).mockResolvedValue([proofRun, staleRun, scanRun]);
  vi.mocked(getAssessmentRun).mockRejectedValue(new ApiError("assessment run not found", 404, null));
  vi.mocked(getAssessmentRunComparison).mockRejectedValue(new ApiError("no compatible baseline run found", 404, null));
  vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, runId, section) => {
    if (section === "proof-receipts" && runId === 42) return page([receipt]);
    return page([]);
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  gridSort.compare = null;
  gridSort.state = null;
  gridSort.silent = false;
  window.sessionStorage.clear();
});

describe("RunsTab list", () => {
  it("states its purpose and shows a content-shaped skeleton, then the empty state", async () => {
    const list = deferred<AssessmentRun[]>();
    vi.mocked(listAssessmentRuns).mockReturnValue(list.promise);
    const view = renderTab(<RunsTab engagementKey="acme" />);
    expect(screen.getByRole("heading", { name: "Runs" })).toBeTruthy();
    expect(screen.getByText(/Each run is one evidence-gathering session by an agent/)).toBeTruthy();
    expect(view.container.querySelector('[aria-busy="true"]')).not.toBeNull();
    list.resolve([]);
    expect(await screen.findByText("No assessment runs have been recorded.")).toBeTruthy();
  });

  it("explains a failed first load and retries on request", async () => {
    vi.mocked(listAssessmentRuns).mockRejectedValueOnce(new Error("run ledger unavailable"));
    renderTab(<RunsTab engagementKey="acme" />);
    expect(await screen.findByText("run ledger unavailable")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText(/row acme-export-replay/)).toBeTruthy();
  });

  it("never shows a run with blockers or stale evidence as healthy", async () => {
    renderTab(<RunsTab engagementKey="acme" />);
    expect(await screen.findByText("row acme-export-replay healthy completed")).toBeTruthy();
    expect(screen.getByText("row acme-import-replay attention completed 1 stale receipt")).toBeTruthy();
    expect(screen.getByText("row acme-source-scan attention partial 1 open obligation")).toBeTruthy();
    expect(screen.getByRole("list", { name: "Summary" }).textContent).toContain("2 need attention");
  });

  it("filters by status, finding, live evidence, and search with counts on every chip", async () => {
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    const attention = within(screen.getByRole("group", { name: "Status" })).getByRole("button", { name: /Needs attention\s*2/ });
    fireEvent.click(attention);
    expect(attention.getAttribute("aria-pressed")).toBe("true");
    const grid = screen.getByTestId("runs-grid");
    expect(within(grid).queryByText(/row acme-export-replay/)).toBeNull();
    expect(within(grid).getByText(/row acme-import-replay/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Clear filters/ }));

    fireEvent.change(screen.getByLabelText("Filter by finding"), { target: { value: "VA-009" } });
    expect(within(grid).getAllByRole("button").map((row) => row.textContent)).toEqual([
      "row acme-import-replay attention completed 1 stale receipt",
    ]);
    fireEvent.click(screen.getByRole("button", { name: /Clear filters/ }));

    fireEvent.click(screen.getByRole("button", { name: /Live target evidence\s*2/ }));
    expect(within(grid).queryByText(/row acme-source-scan/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /Clear filters/ }));

    fireEvent.change(screen.getByLabelText("Search runs"), { target: { value: "source roots" } });
    expect(within(grid).getAllByRole("button")).toHaveLength(1);
    expect(within(grid).getByText(/row acme-source-scan/)).toBeTruthy();
  });

  it("coalesces refresh bursts into one in-flight read and one trailing read", async () => {
    const view = renderTab(<RunsTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByText(/row acme-export-replay/);
    expect(listAssessmentRuns).toHaveBeenCalledTimes(1);

    const slow = deferred<AssessmentRun[]>();
    vi.mocked(listAssessmentRuns).mockReturnValueOnce(slow.promise);
    view.rerender(<RunsTab engagementKey="acme" refreshVersion={1} />);
    view.rerender(<RunsTab engagementKey="acme" refreshVersion={2} />);
    view.rerender(<RunsTab engagementKey="acme" refreshVersion={3} />);
    expect(listAssessmentRuns).toHaveBeenCalledTimes(2);
    // The last loaded list stays visible while the refresh runs.
    expect(screen.getByText(/row acme-export-replay/)).toBeTruthy();
    expect(screen.getByText("Updating…")).toBeTruthy();

    vi.mocked(listAssessmentRuns).mockResolvedValueOnce([{ ...proofRun, run_uuid: "acme-export-replay-latest" }]);
    slow.resolve([proofRun]);
    expect(await screen.findByText(/row acme-export-replay-latest/)).toBeTruthy();
    expect(listAssessmentRuns).toHaveBeenCalledTimes(3);
  });

  it("keeps the last loaded list when a refresh fails", async () => {
    const view = renderTab(<RunsTab engagementKey="acme" refreshVersion={0} />);
    await screen.findByText(/row acme-export-replay/);
    vi.mocked(listAssessmentRuns).mockRejectedValueOnce(new Error("backend restarting"));
    view.rerender(<RunsTab engagementKey="acme" refreshVersion={1} />);
    expect(await screen.findByText(/Could not refresh runs: backend restarting/)).toBeTruthy();
    expect(screen.getByText(/row acme-export-replay/)).toBeTruthy();
  });
});

describe("RunsTab list views", () => {
  it("offers the shared Needs attention scope and names the sort the grid shows", async () => {
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    const scope = screen.getByRole("group", { name: "Scope" });
    expect(within(scope).getByRole("button", { name: /^Needs attention\s*2/ })).toBeTruthy();
    expect(within(scope).getByRole("button", { name: /^All\s*3/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText(/Sorted by Started, newest first/)).toBeTruthy();
    fireEvent.click(within(scope).getByRole("button", { name: /^Needs attention/ }));
    const grid = screen.getByTestId("runs-grid");
    expect(within(grid).queryByText(/row acme-export-replay/)).toBeNull();
    expect(within(grid).getAllByRole("button")).toHaveLength(2);
    expect(screen.getByText((_, element) => element?.classList.contains("ui-results-summary") === true && /2\s*of\s*3\s*runs/.test(element.textContent ?? ""))).toBeTruthy();
  });

  it("reports a header re-sort in the results line instead of a fixed order", async () => {
    gridSort.compare = (a, b) => (a.run.elapsed_seconds ?? 0) - (b.run.elapsed_seconds ?? 0);
    gridSort.state = [{ colId: "duration", sort: "asc" }];
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    expect(await screen.findByText(/Sorted by Duration, lowest first/)).toBeTruthy();
    expect(screen.queryByText(/Started, newest first/)).toBeNull();
  });

  it("names a status sort the way every status sort reads", async () => {
    gridSort.state = [{ colId: "status", sort: "desc" }];
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    expect(await screen.findByText(/Sorted by Status, most urgent first/)).toBeTruthy();
  });

  it("keeps search, chips, scope and sort when the tab is left and reopened", async () => {
    gridSort.state = [{ colId: "duration", sort: "asc" }];
    const first = renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    fireEvent.change(screen.getByLabelText("Search runs"), { target: { value: "acme" } });
    fireEvent.click(within(screen.getByRole("group", { name: "Track" })).getByRole("button", { name: /web/ }));
    await screen.findByText(/Sorted by Duration/);
    first.unmount();
    gridSort.state = null;

    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    expect((screen.getByLabelText("Search runs") as HTMLInputElement).value).toBe("acme");
    expect(within(screen.getByRole("group", { name: "Track" })).getByRole("button", { name: /web/ }).getAttribute("aria-pressed")).toBe("true");
    expect(gridProps.initialSort).toEqual({ colId: "duration", sort: "asc" });
    // Another engagement starts clean.
    cleanup();
    renderTab(<RunsTab engagementKey="acme-other" />);
    await screen.findByText(/row acme-export-replay/);
    expect((screen.getByLabelText("Search runs") as HTMLInputElement).value).toBe("");
  });

  it("explains a filtered-out list with Clear filters, and an empty ledger without one", async () => {
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    fireEvent.change(screen.getByLabelText("Search runs"), { target: { value: "zzzz-no-such-run" } });
    expect(await screen.findByText("No runs match these filters.")).toBeTruthy();
    const clear = screen.getAllByRole("button", { name: /^Clear filters/ });
    fireEvent.click(clear[clear.length - 1]);
    expect(await screen.findByText(/row acme-export-replay/)).toBeTruthy();
  });

  it("names the scope, not filters, when only Needs attention hides every run", async () => {
    vi.mocked(listAssessmentRuns).mockResolvedValue([proofRun]);
    renderTab(<RunsTab engagementKey="acme" />);
    await screen.findByText(/row acme-export-replay/);
    fireEvent.click(within(screen.getByRole("group", { name: "Scope" })).getByRole("button", { name: /^Needs attention/ }));
    expect(await screen.findByText("No run needs attention.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show all runs" }));
    expect(await screen.findByText(/row acme-export-replay/)).toBeTruthy();
  });

  it("says when a run link does not name a run instead of ignoring it", async () => {
    window.history.replaceState(null, "", "#/engagements/acme?tab=runs&run=abc");
    renderTab(<RunsTab engagementKey="acme" />);
    expect(await screen.findByText(/Run link “abc” does not name a run/)).toBeTruthy();
    expect(await screen.findByText(/row acme-export-replay/)).toBeTruthy();
  });
});

describe("RunsTab record", () => {
  it("opens a run in the shared record view on its overview, with findings and proof work linked", async () => {
    renderTab(<RunsTab engagementKey="acme" />);
    fireEvent.click(await screen.findByText(/row acme-export-replay/));
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(screen.queryByRole("dialog")).toBeNull();
    // The record replaces the list; the list keeps its state behind it.
    expect(screen.queryByRole("region", { name: "Assessment runs" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Runs" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/acme?tab=runs&run=42");
    expect(document.activeElement).toBe(within(record).getByRole("heading", { level: 2, name: "acme-export-replay" }));
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    expect(within(record).getByText("Run #42")).toBeTruthy();
    expect(within(record).getByText("Replay the Acme export request with another tenant's id")).toBeTruthy();
    expect(within(record).getByRole("link", { name: "VA-007" }).getAttribute("href")).toBe("#/engagements/acme?tab=findings&finding=VA-007");
    expect(within(record).getByText("run started to verify it · the agent was dispatched for it")).toBeTruthy();
    expect(within(record).getByRole("link", { name: "Proof #3" }).getAttribute("href")).toBe("#/engagements/acme?tab=proof&work=3");
    expect(within(record).getByLabelText("Run dates").textContent).toContain("Started");
    // Child records page in only for the section on screen.
    expect(listAssessmentRunChildren).not.toHaveBeenCalled();
    expect(within(record).queryByRole("button", { name: /^Blockers/ })).toBeNull();

    fireEvent.click(within(record).getByRole("button", { name: /^Evidence/ }));
    expect(window.location.hash).toBe("#/engagements/acme?tab=runs&run=42&dtab=evidence");
    expect(await within(record).findByText("HTTP 200 with the other tenant's rows")).toBeTruthy();
    expect(within(record).getByText("The export denies another tenant")).toBeTruthy();
    expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 42, "proof-receipts", { limit: 50, offset: 0 });
    expect(vi.mocked(listAssessmentRunChildren).mock.calls.some((call) => call[2] === "sources")).toBe(false);
    // The record renders the list row; it does not re-read the run.
    expect(getAssessmentRun).not.toHaveBeenCalled();
    // Comparison belongs to scan runs only.
    expect(getAssessmentRunComparison).not.toHaveBeenCalled();

    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Run record" })).toBeNull());
    expect(window.location.hash).toBe("#/engagements/acme?tab=runs");
    expect(screen.getByRole("region", { name: "Assessment runs" })).toBeTruthy();
    await waitFor(() => expect(document.activeElement?.textContent).toContain("row acme-export-replay"));
  });

  it("walks the grid's current order with previous and next, keeping the open section", async () => {
    // A header click put the scan run first.
    gridSort.compare = (a, b) => a.name.localeCompare(b.name);
    renderTab(<RunsTab engagementKey="acme" />);
    fireEvent.click(await screen.findByText(/row acme-import-replay/));
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByText("2 of 3 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Evidence/ }));
    fireEvent.click(within(record).getByRole("button", { name: "Next run" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "acme-source-scan" })).toBeTruthy();
    expect(within(record).getByText("3 of 3 results")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/acme?tab=runs&run=40&dtab=evidence");
    expect((within(record).getByRole("button", { name: "Next run" }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(record).getByRole("button", { name: /^Evidence/ }).getAttribute("aria-current")).toBe("page");
    fireEvent.keyDown(document.body, { key: "[" });
    fireEvent.keyDown(document.body, { key: "[" });
    expect(await within(record).findByRole("heading", { level: 2, name: "acme-export-replay" })).toBeTruthy();
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Previous run" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(screen.getByTestId("runs-grid")).toBeTruthy();
    await waitFor(() => expect(document.activeElement?.textContent).toContain("row acme-import-replay"));
  });

  it("follows the URL: a deep link opens its section and history leaves the record", async () => {
    const view = renderTab(<RunsTab engagementKey="acme" initialRunId={42} initialDrawerTab="audit" />);
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByRole("button", { name: /^Audit details/ }).getAttribute("aria-current")).toBe("page");
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 42, "dispatches", { limit: 50, offset: 0 }));
    view.rerender(<RunsTab engagementKey="acme" />);
    await waitFor(() => expect(screen.queryByRole("region", { name: "Run record" })).toBeNull());
    expect(screen.getByTestId("runs-grid")).toBeTruthy();
  });

  it("walks the grid's default order, newest first, before the hidden grid reports one", async () => {
    gridSort.silent = true;
    vi.mocked(listAssessmentRuns).mockResolvedValue([
      { ...proofRun, started_at: "2026-10-10 22:00:00" },
      { ...staleRun, started_at: "2026-10-12 09:00:00" },
      { ...scanRun, started_at: "2026-10-11 09:00:00" },
    ]);
    renderTab(<RunsTab engagementKey="acme" initialRunId={40} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByText("2 of 3 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Previous run" }));
    expect(await within(record).findByRole("heading", { level: 2, name: "acme-import-replay" })).toBeTruthy();
  });

  it("marks a deep-linked run outside the current filters", async () => {
    const view = renderTab(<RunsTab engagementKey="acme" />);
    fireEvent.change(await screen.findByLabelText("Search runs"), { target: { value: "source roots" } });
    view.rerender(<RunsTab engagementKey="acme" initialRunId={42} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByText("Outside current results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Next run" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows blockers with record links and full audit data verbatim for a scan run", async () => {
    renderTab(<RunsTab engagementKey="acme" initialRunId={40} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByText("1 open obligation")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Blockers/ }));
    expect(within(record).getByRole("heading", { name: /^Blockers/ })).toBeTruthy();
    expect(within(record).getByText("Hard obligation repo-review is open.")).toBeTruthy();
    expect(within(record).getByRole("link", { name: "Open record" }).getAttribute("href")).toBe(
      "#/engagements/acme?tab=runs&run=40&section=obligations&object=9",
    );
    expect(within(record).queryByText("aws-private-value")).toBeNull();
    fireEvent.click(within(record).getByRole("button", { name: /^Audit details/ }));
    // The audit view is the evidence trail: the run's own credential material
    // renders verbatim, with no reveal step in front of it.
    expect(record.textContent).toContain("aws-private-value");
    expect(record.textContent).toContain("Bearer opaque-token");
    const provenance = within(record).getByLabelText("Dispatch provenance");
    expect(provenance.textContent).toContain("claude");
    expect(provenance.textContent).toContain("launcher effective client");
    expect(within(record).getByText("Running → Completed")).toBeTruthy();
    expect(await within(record).findByText("No earlier compatible scan run to compare with.")).toBeTruthy();
    expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 40, "sources", { limit: 50, offset: 0 });
  });

  it("follows a record deep link through pages and reports a record that is not present", async () => {
    vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, _runId, section, params) => {
      if (section !== "sources") return page([]);
      return (params?.offset ?? 0) === 0
        ? page([{ id: 1, path: "src/first.py" }], 2, 0, true)
        : page([{ id: 2, path: "src/second.py" }], 2, 1, false);
    });
    const view = renderTab(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" initialObject="2" />);
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByRole("button", { name: /^Audit details/ }).getAttribute("aria-current")).toBe("page");
    expect(await within(record).findByText("src/second.py")).toBeTruthy();
    expect(record.querySelector("#run-audit-sources-2")?.className).toContain("is-focused");
    view.unmount();

    renderTab(<RunsTab engagementKey="acme" initialRunId={42} initialSection="proof-receipts" initialObject="99" />);
    expect(await screen.findByText(/Requested record #99 is not present/)).toBeTruthy();
  });

  it("stops deep-link paging after a failed page and keeps the recorded ledger", async () => {
    vi.mocked(listAssessmentRunChildren)
      .mockImplementation(() => new Promise(() => {}))
      .mockResolvedValueOnce(page([receipt], 2, 0, true))
      .mockRejectedValueOnce(new Error("next page unavailable"));
    renderTab(<RunsTab engagementKey="acme" initialRunId={42} initialSection="proof-receipts" initialObject="2" />);
    expect(await screen.findByText(/next page unavailable · Showing last recorded ledger/)).toBeTruthy();
    await new Promise((resolve) => setTimeout(resolve, 25));
    expect(listAssessmentRunChildren).toHaveBeenCalledTimes(2);
    expect(screen.getByText("HTTP 200 with the other tenant's rows")).toBeTruthy();
  });

  it("switches evidence and record sections and writes them to navigable history", async () => {
    renderTab(<RunsTab engagementKey="acme" initialRunId={42} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    fireEvent.click(within(record).getByRole("button", { name: /^Evidence/ }));
    fireEvent.click(within(record).getByRole("button", { name: "Commands" }));
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 42, "commands", { limit: 50, offset: 0 }));
    expect(window.location.hash).toContain("section=commands");
    expect(window.location.hash).toContain("dtab=evidence");
    fireEvent.click(within(record).getByRole("button", { name: /^Audit details/ }));
    expect(window.location.hash).toBe("#/engagements/acme?tab=runs&run=42&dtab=audit");
    fireEvent.click(within(record).getByRole("button", { name: /Tool signals/ }));
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 42, "tool-signals", { limit: 50, offset: 0 }));
    expect(window.location.hash).toContain("section=tool-signals");
  });

  it("keeps every loaded page of a run's records through a live refresh", async () => {
    const sources = Array.from({ length: 60 }, (_, index) => ({ id: index + 1, path: `src/acme-${index + 1}.py` }));
    vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, _runId, section, params) => {
      if (section !== "sources") return page([]);
      const offset = params?.offset ?? 0;
      const limit = params?.limit ?? 50;
      return { ...page(sources.slice(offset, offset + limit), sources.length, offset, offset + limit < sources.length), limit };
    });
    const view = renderTab(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" refreshVersion={0} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    fireEvent.click(await within(record).findByRole("button", { name: /Load more · 10 remaining/ }));
    expect(await within(record).findByText("src/acme-60.py")).toBeTruthy();
    view.rerender(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" refreshVersion={1} />);
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenLastCalledWith("acme", 40, "sources", { limit: 60, offset: 0 }));
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
    expect(within(record).getByText("src/acme-60.py")).toBeTruthy();
  });

  it("runs Load more through the same queue as live refreshes", async () => {
    const sources = Array.from({ length: 60 }, (_, index) => ({ id: index + 1, path: `src/acme-${index + 1}.py` }));
    const read = (offset: number, limit: number) => ({ ...page(sources.slice(offset, offset + limit), sources.length, offset, offset + limit < sources.length), limit });
    const first = deferred<AuditPage<AssessmentRunChild>>();
    const more = deferred<AuditPage<AssessmentRunChild>>();
    // The record shell can appear before its first child read starts. Route
    // deferred responses by page instead of letting "next call" capture that
    // initial read and prevent Load more from ever becoming available.
    vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, _runId, section, params) => {
      if (section !== "sources") return page([]);
      const offset = params?.offset ?? 0;
      const limit = params?.limit ?? 50;
      if (offset === 50) return more.promise;
      if (offset === 0 && limit === 50) return first.promise;
      return read(offset, limit);
    });
    const view = renderTab(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" refreshVersion={0} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenCalledWith("acme", 40, "sources", { limit: 50, offset: 0 }));
    await act(async () => { first.resolve(read(0, 50)); });
    fireEvent.click(await within(record).findByRole("button", { name: /Load more · 10 remaining/ }));
    expect(listAssessmentRunChildren).toHaveBeenLastCalledWith("acme", 40, "sources", { limit: 50, offset: 50 });
    const before = vi.mocked(listAssessmentRunChildren).mock.calls.length;
    view.rerender(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" refreshVersion={1} />);
    view.rerender(<RunsTab engagementKey="acme" initialRunId={40} initialSection="sources" refreshVersion={2} />);
    expect(vi.mocked(listAssessmentRunChildren).mock.calls.length).toBe(before);
    await act(async () => { more.resolve(read(50, 50)); });
    await waitFor(() => expect(listAssessmentRunChildren).toHaveBeenLastCalledWith("acme", 40, "sources", { limit: 60, offset: 0 }));
    expect(vi.mocked(listAssessmentRunChildren).mock.calls.length).toBe(before + 1);
    expect(within(record).getByText("src/acme-60.py")).toBeTruthy();
  });

  it("keeps the open run's evidence on screen while a refresh fails", async () => {
    const view = renderTab(<RunsTab engagementKey="acme" initialRunId={42} initialDrawerTab="evidence" refreshVersion={0} />);
    const record = await screen.findByRole("region", { name: "Run record" });
    await within(record).findByText("HTTP 200 with the other tenant's rows");
    vi.mocked(listAssessmentRunChildren).mockRejectedValue(new Error("ledger refresh unavailable"));
    view.rerender(<RunsTab engagementKey="acme" initialRunId={42} initialDrawerTab="evidence" refreshVersion={1} />);
    expect(await within(record).findByText(/ledger refresh unavailable · Showing last recorded ledger/)).toBeTruthy();
    expect(within(record).getByText("HTTP 200 with the other tenant's rows")).toBeTruthy();
  });

  it("settles a deep link to a run outside the list when its read returns later", async () => {
    const missing = deferred<AssessmentRun>();
    vi.mocked(getAssessmentRun).mockReturnValue(missing.promise);
    renderTab(<RunsTab engagementKey="acme" initialRunId={77} />);
    expect((await screen.findByRole("status", { name: "Loading run #77" })).getAttribute("aria-busy")).toBe("true");
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
    await act(async () => { missing.reject(new ApiError("assessment run not found", 404, null)); });
    expect(await screen.findByText(/Run #77 could not be opened: assessment run not found/)).toBeTruthy();
    expect(screen.queryByRole("status", { name: "Loading run #77" })).toBeNull();
  });

  it("opens a deep-linked run read after the list loaded", async () => {
    const later = deferred<AssessmentRun>();
    vi.mocked(getAssessmentRun).mockReturnValue(later.promise);
    renderTab(<RunsTab engagementKey="acme" initialRunId={77} />);
    expect((await screen.findByRole("status", { name: "Loading run #77" })).getAttribute("aria-busy")).toBe("true");
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
    await act(async () => { later.resolve({ ...proofRun, id: 77, run_uuid: "acme-older-run" }); });
    const record = await screen.findByRole("region", { name: "Run record" });
    expect(within(record).getByRole("heading", { level: 2, name: "acme-older-run" })).toBeTruthy();
  });

  it("marks unhealthy evidence so a stale-receipt blocker lands on it", async () => {
    vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, runId, section) => {
      if (section === "proof-receipts" && runId === 41) {
        return page([
          { ...receipt, id: 501, origin_run_id: 41 },
          { ...receipt, id: 502, origin_run_id: 41, evidence_kind: "command", evidence_health: "stale" },
        ]);
      }
      return page([]);
    });
    renderTab(<RunsTab engagementKey="acme" initialRunId={41} initialSection="proof-receipts" />);
    const record = await screen.findByRole("region", { name: "Run record" });
    const notice = await within(record).findByRole("status", { name: "Unhealthy evidence" });
    expect(notice.textContent).toContain("1 stale receipt");
    // The notice renders from the run's own counts first; the receipt link follows its read.
    expect((await within(notice).findByRole("link", { name: /#502/ })).getAttribute("href")).toBe("#run-audit-proof-receipts-502");
    const card = record.querySelector("#run-audit-proof-receipts-502");
    expect(card?.className).toContain("is-unhealthy");
    expect(card?.textContent).toContain("Stale");
  });

  it("renders a single audit record as dated key-values with nested objects behind a disclosure", async () => {
    vi.mocked(listAssessmentRunChildren).mockImplementation(async (_key, _runId, section) => {
      if (section !== "dispatches") return page([]);
      return page([{
        id: 5,
        agent_id: "acme-va-1",
        dispatched_at: "2026-10-09T22:15:13Z",
        client_binding: { id: 84, asserted_client: "codex", asserted_session_namespace: "/srv/acme/engagements/acme" },
      }]);
    });
    renderTab(<RunsTab engagementKey="acme" initialRunId={42} initialDrawerTab="audit" />);
    const record = await screen.findByRole("region", { name: "Run record" });
    const ledger = await within(record).findByLabelText("Dispatches records");
    expect(ledger.textContent).toContain("2026-10-09 22:15:13 UTC");
    expect(ledger.textContent).not.toContain("2026-10-09T22:15:13Z");
    const binding = within(ledger).getByText(/3 fields/);
    expect(binding.closest("details")).not.toBeNull();
    // Full values stay reachable verbatim.
    expect(ledger.textContent).toContain("/srv/acme/engagements/acme");
  });

  it("explains a deep-linked run that the ledger does not hold", async () => {
    renderTab(<RunsTab engagementKey="acme" initialRunId={77} />);
    expect(await screen.findByText(/Run #77 could not be opened: assessment run not found/)).toBeTruthy();
    expect(getAssessmentRun).toHaveBeenCalledWith("acme", 77);
    await act(async () => {});
    expect(screen.queryByRole("region", { name: "Run record" })).toBeNull();
  });
});
