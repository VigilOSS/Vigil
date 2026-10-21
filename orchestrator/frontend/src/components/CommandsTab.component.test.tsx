// @vitest-environment jsdom

import { cleanup, fireEvent, render as renderUi, screen, waitFor, within } from "@testing-library/react";
import { useEffect, useState, type ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToastProvider } from "../contexts/ToastContext";
import {
  fetchCommandFacets,
  fetchCommandPage,
  fetchCommandPosition,
  getCommandRunRecord,
  type CommandFilters,
  type CommandLedgerFacets,
  type CommandLedgerRow,
  type CommandSort,
} from "../lib/commandsApi";
import type { AssessmentCommandRunDetail } from "../lib/api";
import { CommandsTab } from "./CommandsTab";

// The record view's copy actions report through toasts.
function render(ui: ReactElement) {
  return renderUi(ui, { wrapper: ToastProvider });
}

function commandRecord() {
  return screen.getByRole("region", { name: "Command run record" });
}

vi.mock("../lib/commandsApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/commandsApi")>()),
  fetchCommandPage: vi.fn(),
  fetchCommandFacets: vi.fn(),
  fetchCommandPosition: vi.fn(),
  getCommandRunRecord: vi.fn(),
}));

// Grid stand-in: reads the first block the way the infinite grid does (same
// filters, in the sort the tab hands it), renders each row as a button keyed
// like a grid row, reports the server total, and offers a header-click sort.
const gridMounts = vi.hoisted(() => ({ initialSorts: [] as Array<CommandSort | null | undefined> }));
vi.mock("./CommandsGrid", () => ({
  default: function GridStub({ engagementKey, filters, filtersKey, refreshToken, initialSort, onRowOpen, onWindow, onTargetClick, onSortChange }: {
    engagementKey: string;
    filters: CommandFilters;
    filtersKey: string;
    refreshToken: number;
    initialSort?: CommandSort | null;
    onRowOpen: (row: CommandLedgerRow, invoker: HTMLElement | null) => void;
    onWindow: (window: { total: number | null; first: number; last: number }) => void;
    onTargetClick: (target: string) => void;
    onSortChange: (sort: CommandSort) => void;
  }) {
    const [rows, setRows] = useState<CommandLedgerRow[]>([]);
    const [sort, setSort] = useState<CommandSort>(() => {
      gridMounts.initialSorts.push(initialSort);
      return initialSort ?? { sort: "created_at", dir: "desc" };
    });
    useEffect(() => {
      let active = true;
      void fetchCommandPage(engagementKey, filters, { ...sort, limit: 100, offset: 0 }).then((page) => {
        if (!active) return;
        setRows(page.items);
        onWindow({ total: page.total, first: 1, last: page.items.length });
      });
      return () => { active = false; };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [engagementKey, filtersKey, refreshToken, sort]);
    return (
      <div role="grid">
        <button type="button" onClick={() => { setSort({ sort: "tool", dir: "asc" }); onSortChange({ sort: "tool", dir: "asc" }); }}>sort by tool</button>
        <button type="button" onClick={() => { setSort({ sort: "status", dir: "desc" }); onSortChange({ sort: "status", dir: "desc" }); }}>sort by status</button>
        {rows.map((row) => (
          <div key={row.id} data-record-key={String(row.id)}>
            <button type="button" onClick={(event) => onRowOpen(row, event.currentTarget)}>
              command grid {row.id} {row.status} {row.target} {row.target_source}
            </button>
            {row.target && <button type="button" onClick={() => onTargetClick(row.target)}>target {row.target}</button>}
          </div>
        ))}
      </div>
    );
  },
}));

function row(id: number, extra: Partial<CommandLedgerRow> = {}): CommandLedgerRow {
  const minute = String(id % 60).padStart(2, "0");
  return {
    id,
    engagement_id: 1,
    run_uuid: `run-${id}`,
    command_preview: `curl https://app.example.com/${id}`,
    command_chars: 30,
    tool_name: "curl",
    tool_bin: "curl",
    tool: "curl",
    route: "vigil assess kali/curl",
    agent_name: "vulnerability-analyst",
    phase: "consume-test",
    audit_source: "header",
    status: "failed",
    return_code: 7,
    timed_out: false,
    success: false,
    started_at: `2026-10-01T10:${minute}:00Z`,
    completed_at: `2026-10-01T10:${minute}:05Z`,
    duration_ms: 5000,
    command_hash: `hash-${id}`,
    output_retention_status: "retained",
    output_cleanup_status: "not_required",
    output_integrity_status: "verified",
    stdout_bytes: 10,
    stderr_bytes: 0,
    created_at: `2026-10-01 10:${minute}:00`,
    target_host: "",
    target: "app.example.com",
    target_source: "inferred",
    auth_context: "anonymous",
    superseded_by_id: null,
    timeout_seconds_requested: null,
    partial_results: false,
    finding_id: null,
    finding_slug: null,
    technique: "SSRF",
    intent: `probe endpoint ${id}`,
    probe_kind: "payload",
    destructive: false,
    needs_attention: true,
    attention_reasons: ["finished unsuccessfully"],
    ...extra,
  };
}

function record(id: number, extra: Partial<AssessmentCommandRunDetail> = {}): AssessmentCommandRunDetail {
  const base = row(id);
  return {
    ...base,
    command: `curl https://app.example.com/${id} --full-argument-list`,
    argv: ["curl", `https://app.example.com/${id}`, "--full-argument-list"],
    stdout_preview: `stdout of ${id}`,
    stderr_preview: "",
    stdout_sha256: "",
    stderr_sha256: "",
    output_cleanup_warning: "",
    output_integrity_warning: "",
    stdout_suppression_reason: "",
    stderr_suppression_reason: "",
    stdout_artifact_ref: "",
    stderr_artifact_ref: "",
    indexed_for_embeddings_at: null,
    output_recovery_observed_at: null,
    notes: "",
    started_at: base.started_at ?? "",
    completed_at: base.completed_at ?? "",
    target_host: "",
    ...extra,
  } as AssessmentCommandRunDetail;
}

function facets(extra: Partial<CommandLedgerFacets> = {}): CommandLedgerFacets {
  return {
    total: 312,
    scope_totals: { attention: 312, all: 1450 },
    engagement_totals: { attention: 312, all: 1450 },
    facets: {
      status: { values: [{ value: "completed", count: 900 }, { value: "failed", count: 120 }, { value: "lost", count: 40 }], distinct: 3, omitted_count: 0 },
      tool: { values: [{ value: "curl", count: 700 }, { value: "bash", count: 150 }], distinct: 2, omitted_count: 0 },
      agent: { values: [{ value: "vulnerability-analyst", count: 640 }], distinct: 1, omitted_count: 0 },
      technique: { values: [{ value: "SSRF", count: 900 }, { value: "ssrf", count: 12 }, { value: "", count: 40 }], distinct: 3, omitted_count: 0 },
      probe_kind: { values: [{ value: "payload", count: 210 }, { value: "exploit", count: 53 }], distinct: 2, omitted_count: 0 },
    },
    ...extra,
  };
}

// The ledger newest first; the server answers pages, facets, positions and records.
function serveLedger(ledger: CommandLedgerRow[], ledgerFacets: CommandLedgerFacets = facets({ total: ledger.length })) {
  vi.mocked(fetchCommandPage).mockImplementation(async (_key, _filters, { offset, limit }) => ({
    total: ledger.length,
    offset,
    count: Math.min(limit, Math.max(0, ledger.length - offset)),
    has_more: offset + limit < ledger.length,
    items: ledger.slice(offset, offset + limit),
  }));
  vi.mocked(fetchCommandFacets).mockResolvedValue(ledgerFacets);
  vi.mocked(fetchCommandPosition).mockImplementation(async (_key, id) => {
    const index = ledger.findIndex((item) => item.id === id);
    return {
      index: index < 0 ? null : index,
      total: ledger.length,
      previous: index > 0 ? ledger[index - 1] : null,
      next: index >= 0 && index < ledger.length - 1 ? ledger[index + 1] : null,
    };
  });
  vi.mocked(getCommandRunRecord).mockImplementation(async (_key, id) => {
    const listed = ledger.find((item) => item.id === id);
    if (!listed) throw new Error("command run not found");
    return record(id, listed as unknown as Partial<AssessmentCommandRunDetail>);
  });
}

beforeEach(() => {
  window.history.replaceState(null, "", "#/engagements/demo?tab=commands");
  window.sessionStorage.clear();
  gridMounts.initialSorts = [];
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.useRealTimers();
});

describe("CommandsTab ledger", () => {
  it("shows the server's totals for both scopes and the matching count, with the sort it is shown in", async () => {
    serveLedger([row(3), row(2), row(1)], facets());
    render(<CommandsTab engagementKey="demo" />);

    const scope = await screen.findByRole("group", { name: "Command run scope" });
    await waitFor(() => expect(within(scope).getByRole("button", { name: /Needs attention/ }).textContent).toContain("312"));
    expect(within(scope).getByRole("button", { name: /^All/ }).textContent).toContain("1,450");
    // A history opens on every run; "Needs attention" is one click away.
    expect(within(scope).getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
    expect(within(scope).getByRole("button", { name: /Needs attention/ }).getAttribute("aria-pressed")).toBe("false");
    expect(screen.getByText(/of/, { selector: ".ui-results-summary" }).textContent)
      .toBe("312 of 1,450 command runs · Sorted by Time, newest first");
    // The page header counts the whole ledger.
    expect(screen.getByRole("heading", { level: 1, name: "Commands" })).toBeTruthy();
    expect(screen.getByRole("list", { name: "Summary" }).textContent).toContain("1,450 runs");
    expect(fetchCommandFacets).toHaveBeenCalledWith("demo", expect.objectContaining({ scope: "all" }), expect.any(Number));
  });

  it("filters on the server from status, tool and agent chips with server counts", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    const tool = await screen.findByRole("button", { name: /^curl/ });
    expect(tool.textContent).toContain("700");
    expect(tool.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(tool);
    expect(tool.getAttribute("aria-pressed")).toBe("true");
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ tool: ["curl"] }), expect.anything()));
    expect(fetchCommandFacets).toHaveBeenLastCalledWith("demo", expect.objectContaining({ tool: ["curl"] }), expect.any(Number));
    fireEvent.click(screen.getByRole("button", { name: /^Lost/ }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ status: ["lost"], tool: ["curl"] }), expect.anything()));
    fireEvent.click(screen.getByRole("button", { name: "Clear filters (2)" }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ status: [], tool: [] }), expect.anything()));
  });

  it("filters on the server from technique and kind chips, showing values as stored", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /^SSRF/ });
    const technique = screen.getByRole("group", { name: "Technique" });
    // Stored values are case-sensitive: SSRF and ssrf are separate chips.
    expect(within(technique).getAllByRole("button").map((chip) => chip.textContent)).toEqual(["SSRF900", "ssrf12", "None declared40"]);
    const kind = screen.getByRole("group", { name: "Kind" });
    fireEvent.click(within(technique).getByRole("button", { name: /^None declared/ }));
    fireEvent.click(within(kind).getByRole("button", { name: /^exploit/ }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ technique: [""], probe_kind: ["exploit"] }), expect.anything()));
    expect(fetchCommandFacets).toHaveBeenLastCalledWith("demo", expect.objectContaining({ technique: [""], probe_kind: ["exploit"] }), expect.any(Number));
    fireEvent.click(screen.getByRole("button", { name: "Clear filters (2)" }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ technique: [], probe_kind: [] }), expect.anything()));
  });

  it("keeps long tool lists one click away and says how many runs the unlisted tools cover", async () => {
    const tools = Array.from({ length: 14 }, (_, index) => ({ value: `tool-${index}`, count: 100 - index }));
    serveLedger([row(3), row(2), row(1)], facets({ facets: { ...facets().facets, tool: { values: tools, distinct: 20, omitted_count: 37 } } }));
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /^tool-0/ });
    const tool = screen.getByRole("group", { name: "Tool" });
    expect(within(tool).getAllByRole("button", { pressed: false })).toHaveLength(10);
    fireEvent.click(within(tool).getByRole("button", { name: "Show all 14" }));
    expect(within(tool).getAllByRole("button", { pressed: false })).toHaveLength(14);
    expect(tool.textContent).toContain("6 more not listed");
    expect(tool.textContent).toContain("37 runs");
    expect(tool.textContent).toContain("tool:name");
  });

  it("searches on the server, including a run_uuid prefix", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    const search = await screen.findByRole("searchbox", { name: "Search command runs" });
    fireEvent.change(search, { target: { value: "3f2a91c4" } });
    // Enter sends the search at once instead of after the typing pause.
    fireEvent.keyDown(search, { key: "Enter" });
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ q: "3f2a91c4" }), expect.anything()));
  });

  it("switches the scope on the server, and a target click searches that target", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /^Needs attention/ }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ scope: "attention" }), expect.anything()));
    await waitFor(() => expect(screen.getAllByRole("button", { name: "target app.example.com" }).length).toBeGreaterThan(0));
    fireEvent.click(screen.getAllByRole("button", { name: "target app.example.com" })[0]);
    await waitFor(() => expect((screen.getByRole("searchbox", { name: "Search command runs" }) as HTMLInputElement).value).toBe("target:app.example.com"));
  });

  it("says when nothing is recorded yet, and offers Clear filters when filters hide every run", async () => {
    serveLedger([], facets({ total: 0, scope_totals: { attention: 0, all: 0 }, engagement_totals: { attention: 0, all: 0 } }));
    const view = render(<CommandsTab engagementKey="demo" />);
    expect(await screen.findByText("No command runs recorded yet.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Clear filters" })).toBeNull();
    view.unmount();

    serveLedger([], facets({ total: 0, scope_totals: { attention: 0, all: 40 }, engagement_totals: { attention: 3, all: 40 } }));
    render(<CommandsTab engagementKey="demo" />);
    const search = await screen.findByRole("searchbox", { name: "Search command runs" });
    fireEvent.change(search, { target: { value: "nothing-matches" } });
    fireEvent.keyDown(search, { key: "Enter" });
    expect(await screen.findByText("No command runs match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect((screen.getByRole("searchbox", { name: "Search command runs" }) as HTMLInputElement).value).toBe(""));
  });

  it("reloads counts and rows on live refreshes, at most once per burst window", async () => {
    serveLedger([row(1)]);
    const view = render(<CommandsTab engagementKey="demo" refreshVersion={0} />);
    await screen.findByRole("button", { name: /command grid 1/ });
    await waitFor(() => expect(fetchCommandFacets).toHaveBeenCalledTimes(1));
    view.rerender(<CommandsTab engagementKey="demo" refreshVersion={1} />);
    await waitFor(() => expect(fetchCommandFacets).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenCalledTimes(2));
    vi.useFakeTimers({ now: Date.now() });
    view.rerender(<CommandsTab engagementKey="demo" refreshVersion={2} />);
    view.rerender(<CommandsTab engagementKey="demo" refreshVersion={3} />);
    expect(fetchCommandFacets).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(10_000);
    vi.useRealTimers();
    await waitFor(() => expect(fetchCommandFacets).toHaveBeenCalledTimes(3));
  });

  it("keeps the rows on screen and says so when the counts cannot be read", async () => {
    serveLedger([row(1)]);
    vi.mocked(fetchCommandFacets).mockRejectedValue(new Error("facets unavailable"));
    render(<CommandsTab engagementKey="demo" />);
    expect((await screen.findByRole("alert")).textContent).toContain("facets unavailable");
    expect(await screen.findByRole("button", { name: /command grid 1/ })).toBeTruthy();
  });
});

describe("CommandsTab palette", () => {
  it("jumps to a run the server finds by run_uuid prefix, across the whole ledger", async () => {
    serveLedger([row(3), row(2), row(1, { run_uuid: "3f2a91c40b7d4e21", intent: "the old run" })]);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /command grid 3/ });
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    // The palette searches after a 200 ms typing pause; step past it.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    fireEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Jump to command" });
    const input = within(dialog).getByRole("combobox", { name: "Search commands to jump to" });
    vi.mocked(fetchCommandPage).mockResolvedValueOnce({ total: 1, offset: 0, count: 1, has_more: false, items: [row(1, { run_uuid: "3f2a91c40b7d4e21", intent: "the old run" })] });
    fireEvent.change(input, { target: { value: "3f2a91c4" } });
    await vi.advanceTimersByTimeAsync(200);
    vi.useRealTimers();
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ q: "3f2a91c4", scope: "all", status: [], tool: [], agent: [] }), expect.objectContaining({ offset: 0 })));
    expect(await within(dialog).findByText(/1 match/)).toBeTruthy();
    // The results are a listbox the search box drives: arrows move the active option.
    const option = within(within(dialog).getByRole("listbox", { name: "Matching command runs" })).getByRole("option", { name: /the old run/ });
    expect(option.getAttribute("aria-selected")).toBe("true");
    expect(input.getAttribute("aria-activedescendant")).toBe(option.id);
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("heading", { level: 2, name: "the old run" })).toBeTruthy();
    expect(screen.queryByRole("dialog", { name: "Jump to command" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands&command=1");
  });

  it("contains focus and restores its opener on Escape", async () => {
    serveLedger([row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    await screen.findByRole("button", { name: /command grid 1/ });
    const opener = screen.getByRole("button", { name: /Jump to…/ });
    opener.focus();
    fireEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Jump to command" });
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.body.classList.contains("detail-modal-open")).toBe(true);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog", { name: "Jump to command" })).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
  });
});

describe("CommandsTab record", () => {
  it("opens a run in the shared record view from the full record read, walks the server order, and returns to the stepped run", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    const opener = await screen.findByRole("button", { name: /command grid 2 failed/ });
    opener.focus();
    fireEvent.click(opener);

    const view = commandRecord();
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands&command=2");
    expect(within(view).getByRole("heading", { level: 2, name: "probe endpoint 2" })).toBeTruthy();
    expect(within(view).getByText("Command run #2")).toBeTruthy();
    expect(await within(view).findByText("2 of 3 results")).toBeTruthy();
    // The status reason is the server's rule plus the exit outcome.
    expect(within(view).getByText("finished unsuccessfully · exit code 7")).toBeTruthy();
    // The full command and argv come from the record read, not the list preview.
    expect(await within(view).findByText("curl https://app.example.com/2 --full-argument-list")).toBeTruthy();
    expect(getCommandRunRecord).toHaveBeenCalledWith("demo", 2);

    fireEvent.click(within(view).getByRole("button", { name: /^Stdout/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands&command=2&dtab=stdout");
    expect(await within(view).findByText("stdout of 2")).toBeTruthy();
    fireEvent.click(within(view).getByRole("button", { name: "Next command run" }));
    expect(await within(view).findByRole("heading", { level: 2, name: "probe endpoint 1" })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands&command=1&dtab=stdout");
    expect(await within(view).findByText("3 of 3 results")).toBeTruthy();
    expect(fetchCommandPosition).toHaveBeenLastCalledWith("demo", 1, expect.objectContaining({ scope: "all" }), { sort: "created_at", dir: "desc" });
    await waitFor(() => expect((within(view).getByRole("button", { name: "Next command run" }) as HTMLButtonElement).disabled).toBe(true));

    fireEvent.click(within(view).getByRole("button", { name: "Back to results" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands");
    expect(screen.queryByRole("region", { name: "Command run record" })).toBeNull();
    // Back lands on the run last shown, not the one first opened.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: /command grid 1 failed/ })));
  });

  it("opens a deep-linked run by id; a run that needs no attention widens a saved attention scope to all runs", async () => {
    const clean = row(4242, { status: "completed", return_code: 0, success: true, needs_attention: false, attention_reasons: [], intent: "nmap sweep" });
    serveLedger([row(3), clean]);
    window.sessionStorage.setItem("commands.view.demo", JSON.stringify({ filters: { scope: "attention" } }));
    render(<CommandsTab engagementKey="demo" commandId={4242} initialDrawerTab="audit" />);
    const view = await screen.findByRole("region", { name: "Command run record" });
    expect(await within(view).findByRole("heading", { level: 2, name: "nmap sweep" })).toBeTruthy();
    expect(within(view).getByRole("button", { name: /^Audit/ }).getAttribute("aria-current")).toBe("page");
    expect(await within(view).findByText("Raw record")).toBeTruthy();
    await waitFor(() => expect(fetchCommandPosition).toHaveBeenLastCalledWith("demo", 4242, expect.objectContaining({ scope: "all" }), expect.anything()));
    fireEvent.click(within(view).getByRole("button", { name: "Back to results" }));
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("says when a deep-linked run cannot be read and shows no record", async () => {
    serveLedger([row(1)]);
    render(<CommandsTab engagementKey="demo" commandId={99} />);
    expect((await screen.findByText(/Command run #99 could not be opened: command run not found/)).getAttribute("role")).toBe("alert");
    expect(screen.queryByRole("region", { name: "Command run record" })).toBeNull();
  });

  it("follows the URL: history leaves the record, and Escape closes it", async () => {
    serveLedger([row(2), row(1)]);
    const view = render(<CommandsTab engagementKey="demo" commandId={1} />);
    await screen.findByRole("region", { name: "Command run record" });
    view.rerender(<CommandsTab engagementKey="demo" commandId={undefined} />);
    await waitFor(() => expect(screen.queryByRole("region", { name: "Command run record" })).toBeNull());
    view.rerender(<CommandsTab engagementKey="demo" commandId={2} />);
    await screen.findByRole("region", { name: "Command run record" });
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(screen.queryByRole("region", { name: "Command run record" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=commands");
  });

  it("links the recorded finding and shows stored attribution, superseding and the inferred target", async () => {
    serveLedger([row(11, {
      finding_id: 74,
      finding_slug: "VA-012",
      superseded_by_id: 12,
      partial_results: true,
      target: "stored.example",
      target_source: "stored",
      target_host: "stored.example",
      attention_reasons: ["finished unsuccessfully", "partial results", "superseded by #12"],
    })]);
    vi.mocked(getCommandRunRecord).mockResolvedValue(record(11, {
      finding_id: 74,
      finding_slug: "VA-012",
      superseded_by_id: 12,
      partial_results: true,
      target: "stored.example",
      target_source: "stored",
      target_host: "stored.example",
      auth_context: "admin-session",
      scope_version: "sha256:scope-v3",
      attention_reasons: ["finished unsuccessfully", "partial results", "superseded by #12"],
    }));
    render(<CommandsTab engagementKey="demo" commandId={11} />);
    const view = await screen.findByRole("region", { name: "Command run record" });
    expect((await within(view).findByRole("link", { name: "VA-012" })).getAttribute("href")).toBe("#/engagements/demo?tab=findings&finding=VA-012");
    expect(within(view).getByText("Superseded by run 12")).toBeTruthy();
    expect(within(view).getByText("finished unsuccessfully · exit code 7 · partial results · superseded by #12")).toBeTruthy();
    fireEvent.click(within(view).getByRole("button", { name: /^Context/ }));
    expect(within(view).getByText("admin-session")).toBeTruthy();
    expect(within(view).getByText("sha256:scope-v3")).toBeTruthy();
    expect(within(view).getByText("Target (stored)")).toBeTruthy();
  });

  it.each(["pending", "warning"])("shows captured stdout with a clear %s integrity warning", async (integrity) => {
    serveLedger([row(41)]);
    vi.mocked(getCommandRunRecord).mockResolvedValue(record(41, {
      output_integrity_status: integrity,
      output_integrity_warning: "Capture has not completed its integrity check.",
      stdout_preview: "operator-evidence",
    }));
    render(<CommandsTab engagementKey="demo" commandId={41} initialDrawerTab="stdout" />);
    const view = await screen.findByRole("region", { name: "Command run record" });
    expect(await within(view).findByText("operator-evidence")).toBeTruthy();
    expect(within(view).getByText(`Output integrity is ${integrity}`)).toBeTruthy();
  });

  it("labels full-output artifact references and offers the runs that share this command", async () => {
    serveLedger([row(21, { output_retention_status: "artifact" })]);
    vi.mocked(getCommandRunRecord).mockResolvedValue(record(21, {
      output_retention_status: "artifact",
      stdout_bytes: 99999,
      stdout_artifact_ref: "scans/command-runs/21/stdout.log",
      stdout_preview: "first 12 chars",
      command_hash: "abcdef0123456789",
    }));
    render(<CommandsTab engagementKey="demo" commandId={21} initialDrawerTab="stdout" />);
    const view = await screen.findByRole("region", { name: "Command run record" });
    expect(await within(view).findByText("Full output artifact")).toBeTruthy();
    expect(within(view).getByRole("button", { name: "Copy artifact reference" })).toBeTruthy();
    fireEvent.click(within(view).getByRole("button", { name: /^Audit/ }));
    fireEvent.click(within(view).getByRole("button", { name: "Show runs with this command" }));
    expect(screen.queryByRole("region", { name: "Command run record" })).toBeNull();
    expect((screen.getByRole("searchbox", { name: "Search command runs" }) as HTMLInputElement).value).toBe("hash:abcdef012345");
  });
});

describe("CommandsTab view memory", () => {
  it("names the server's status order by urgency", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: "sort by status" }));
    await waitFor(() => expect(screen.getByText(/Sorted by/, { selector: ".ui-results-sort" }).textContent).toContain("Status, most urgent first"));
  });

  it("brings the grid back in the order the summary names after a search that matched nothing", async () => {
    serveLedger([row(3), row(2), row(1)]);
    render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: "sort by tool" }));
    await waitFor(() => expect(screen.getByText(/Sorted by/, { selector: ".ui-results-sort" }).textContent).toContain("Tool, A to Z"));

    vi.mocked(fetchCommandFacets).mockResolvedValue(facets({ total: 0 }));
    const search = screen.getByRole("searchbox", { name: "Search command runs" });
    fireEvent.change(search, { target: { value: "nothing-matches" } });
    fireEvent.keyDown(search, { key: "Enter" });
    expect(await screen.findByText("No command runs match these filters.")).toBeTruthy();

    vi.mocked(fetchCommandFacets).mockResolvedValue(facets({ total: 3 }));
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await screen.findByRole("button", { name: /command grid 3/ });
    // The rebuilt grid starts in the tab's sort, so the rows, the summary and
    // Previous / Next all use the same order.
    expect(gridMounts.initialSorts.at(-1)).toEqual({ sort: "tool", dir: "asc" });
    expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ q: "" }), expect.objectContaining({ sort: "tool", dir: "asc" }));
    expect(screen.getByText(/Sorted by/, { selector: ".ui-results-sort" }).textContent).toContain("Tool, A to Z");
  });

  it("keeps scope, chips, search and sort when the operator leaves the tab and comes back", async () => {
    serveLedger([row(3), row(2), row(1)]);
    const first = render(<CommandsTab engagementKey="demo" />);
    fireEvent.click(await screen.findByRole("button", { name: /^Needs attention/ }));
    fireEvent.click(await screen.findByRole("button", { name: /^curl/ }));
    const search = screen.getByRole("searchbox", { name: "Search command runs" });
    fireEvent.change(search, { target: { value: "agent:recon" } });
    fireEvent.keyDown(search, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "sort by tool" }));
    await waitFor(() => expect(fetchCommandPage).toHaveBeenLastCalledWith("demo", expect.objectContaining({ scope: "attention", tool: ["curl"], q: "agent:recon" }), expect.objectContaining({ sort: "tool" })));
    first.unmount();
    vi.clearAllMocks();
    serveLedger([row(3), row(2), row(1)]);

    render(<CommandsTab engagementKey="demo" />);
    expect((await screen.findByRole("button", { name: /^Needs attention/ })).getAttribute("aria-pressed")).toBe("true");
    expect((await screen.findByRole("button", { name: /^curl/ })).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByRole("searchbox", { name: "Search command runs" }) as HTMLInputElement).value).toBe("agent:recon");
    await waitFor(() => expect(fetchCommandPage).toHaveBeenCalledWith("demo", expect.objectContaining({ scope: "attention", tool: ["curl"], q: "agent:recon" }), expect.objectContaining({ sort: "tool", dir: "asc" })));
    expect(fetchCommandFacets).toHaveBeenCalledWith("demo", expect.objectContaining({ scope: "attention", tool: ["curl"], q: "agent:recon" }), expect.any(Number));
    expect(gridMounts.initialSorts.at(-1)).toEqual({ sort: "tool", dir: "asc" });

    // Another engagement keeps its own view.
    cleanup();
    render(<CommandsTab engagementKey="other" />);
    expect((await screen.findByRole("button", { name: /^All/ })).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByRole("searchbox", { name: "Search command runs" }) as HTMLInputElement).value).toBe("");
  });
});

describe("CommandsTab live refresh of an open run", () => {
  it("keeps the record read in flight through a refresh and re-reads once after it lands", async () => {
    serveLedger([row(7)]);
    const reads: Array<(value: AssessmentCommandRunDetail) => void> = [];
    vi.mocked(getCommandRunRecord).mockImplementation(() => new Promise((resolve) => { reads.push(resolve); }));
    const view = render(<CommandsTab engagementKey="demo" commandId={7} refreshVersion={0} />);
    await waitFor(() => expect(getCommandRunRecord).toHaveBeenCalledTimes(1));

    view.rerender(<CommandsTab engagementKey="demo" commandId={7} refreshVersion={1} />);
    await waitFor(() => expect(fetchCommandFacets).toHaveBeenCalledTimes(2));
    // The refresh waits for the read already in flight instead of replacing it.
    expect(getCommandRunRecord).toHaveBeenCalledTimes(1);

    reads[0](record(7, { intent: "first read" }));
    const recordView = await screen.findByRole("region", { name: "Command run record" });
    expect(await within(recordView).findByRole("heading", { level: 2, name: "first read" })).toBeTruthy();
    await waitFor(() => expect(getCommandRunRecord).toHaveBeenCalledTimes(2));
    reads[1](record(7, { intent: "refreshed read" }));
    expect(await within(recordView).findByRole("heading", { level: 2, name: "refreshed read" })).toBeTruthy();
  });
});
