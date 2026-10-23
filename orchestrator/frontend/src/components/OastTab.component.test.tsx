// @vitest-environment jsdom

import { StrictMode } from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError, getOobProbe, listOobProbes, request } from "../lib/api";
import { ToastProvider } from "../contexts/ToastContext";
import { OastTab } from "./OastTab";

vi.mock("../lib/api", async (importOriginal) => ({
  ApiError: (await importOriginal<typeof import("../lib/api")>()).ApiError,
  getOobProbe: vi.fn(),
  listOobProbes: vi.fn(),
  request: vi.fn(),
}));

// ag-grid stand-in: renders rowData in order (or reversed, standing in for a
// header click) and reports that order the way the grid's model update does.
const gridSort = { reverse: false, column: "lasthit" };
vi.mock("ag-grid-react", async () => {
  const { useEffect } = await import("react");
  return {
    AgGridReact: function AgGridMock({
      rowData = [],
      onRowClicked,
      onCellKeyDown,
      onModelUpdated,
      overlayNoRowsTemplate = "",
    }: {
      rowData?: Array<{ nonce: string }>;
      onRowClicked?: (event: unknown) => void;
      onCellKeyDown?: (event: unknown) => void;
      onModelUpdated?: (event: unknown) => void;
      overlayNoRowsTemplate?: string;
    }) {
      const shown = gridSort.reverse ? [...rowData].reverse() : rowData;
      const order = shown.map((row) => row.nonce).join(",");
      useEffect(() => {
        onModelUpdated?.({ api: {
          forEachNodeAfterFilterAndSort: (visit: (node: { data: unknown }) => void) => shown.forEach((data) => visit({ data })),
          getColumnState: () => [{ colId: gridSort.column, sort: gridSort.reverse ? "asc" : "desc" }],
        } });
      }, [order]);
      return (
        <div role="grid">
          {shown.length === 0
            ? <span>{overlayNoRowsTemplate.replace(/<[^>]+>/g, "")}</span>
            : shown.map((row) => (
              <div key={row.nonce} className="ag-row" row-id={row.nonce}>
                <div
                  className="ag-cell"
                  role="gridcell"
                  tabIndex={0}
                  onClick={(event) => onRowClicked?.({ data: row, event })}
                  onKeyDown={(event) => onCellKeyDown?.({ data: row, event })}
                >
                  {row.nonce}
                </div>
              </div>
            ))}
        </div>
      );
    },
  };
});

const RECORD = { name: "OAST probe record" };

const probe = {
  id: 1,
  engagement_id: 1,
  nonce: "oast-123",
  oob_domain: "oast.example",
  target_url: "https://target.example/callback",
  technique: "ssrf",
  param: "url",
  probe_kind: "http",
  request_hash: "request-sha256",
  client_name: "ssrf-a",
  client_payload_host: "client-a.oast.example",
  status: "pending",
  notes: "",
  created_at: "2026-09-12T00:00:00Z",
  updated_at: "2026-09-12T00:00:00Z",
  interaction_count: 0,
  last_interaction_at: "",
};

const firedProbe = {
  ...probe,
  status: "fired",
  interaction_count: 4,
  last_interaction_at: "2026-09-12T05:06:07Z",
};

function interaction(id: number, overrides: Record<string, string> = {}) {
  return {
    id,
    engagement_id: 1,
    probe_id: 1,
    protocol: "dns",
    remote_address: "172.17.0.2",
    query_type: "A",
    raw_request: `[oast-123.client-a.oast.example] Received DNS interaction ${id}`,
    interaction_hash: `interaction-${id}`,
    observed_at: "2026-09-12T05:06:07Z",
    created_at: "2026-09-12T05:06:08Z",
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

// The tab lazy-loads its grid (and ag-grid with it); load that chunk once up
// front so the first test's render does not pay for it inside its waits.
beforeAll(async () => {
  await import("./OastGrid");
});

beforeEach(() => {
  gridSort.reverse = false;
  gridSort.column = "lasthit";
  window.history.replaceState({}, "", "#/engagements");
  window.sessionStorage.clear();
  vi.mocked(listOobProbes).mockResolvedValue([probe]);
});

async function openCallbacks() {
  const record = await screen.findByRole("region", RECORD);
  fireEvent.click(within(record).getByRole("button", { name: /^Callbacks/ }));
  return record;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("OastTab detail evidence", () => {
  it("updates an open record's lifecycle when the probe list refreshes", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    fireEvent.click(await screen.findByRole("gridcell", { name: probe.nonce }));
    expect(within(await screen.findByRole("region", RECORD)).getAllByText("Awaiting callback").length).toBeGreaterThan(0);

    const fired = { ...probe, status: "fired", interaction_count: 1, client_name: "updated-client" };
    vi.mocked(listOobProbes).mockResolvedValue([fired]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...fired, interactions: [] });
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getOobProbe).toHaveBeenCalledTimes(2));
    const record = screen.getByRole("region", RECORD);
    await waitFor(() => expect(within(record).getAllByText("Callback received").length).toBeGreaterThan(0));
    expect(within(record).getAllByText("updated-client").length).toBeGreaterThan(0);
    expect(within(record).queryByText("Awaiting callback")).toBeNull();
  });

  it("returns to the results when its open probe leaves a refreshed list", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    fireEvent.click(await screen.findByRole("gridcell", { name: probe.nonce }));
    await screen.findByRole("region", RECORD);
    vi.mocked(listOobProbes).mockResolvedValue([]);
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast");
  });

  it("defaults to callbacks to review, newest callback first, and keeps every probe in All probes", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([
      { ...probe, nonce: "pending-probe", status: "pending" },
      { ...probe, nonce: "fired-older", status: "fired", interaction_count: 1, last_interaction_at: "2026-09-12 05:00:00" },
      { ...probe, nonce: "expired-probe", status: "expired" },
      { ...probe, nonce: "fired-newer", status: "fired", interaction_count: 4, last_interaction_at: "2026-09-12T06:00:00Z" },
      { ...probe, nonce: "confirmed-probe", status: "confirmed", interaction_count: 1 },
    ]);

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    const review = await screen.findByRole("button", { name: /^Needs attention/ });
    expect(review.getAttribute("aria-pressed")).toBe("true");
    await waitFor(() => expect(review.textContent).toContain("2"));
    await screen.findByRole("gridcell", { name: "fired-newer" });
    expect(screen.getAllByRole("gridcell").map((cell) => cell.textContent)).toEqual(["fired-newer", "fired-older"]);

    const all = screen.getByRole("button", { name: /^All/ });
    expect(all.textContent).toContain("5");
    fireEvent.click(all);
    expect(await screen.findByRole("gridcell", { name: "pending-probe" })).toBeTruthy();
    expect(screen.getByRole("gridcell", { name: "expired-probe" })).toBeTruthy();
    expect(screen.getByRole("gridcell", { name: "confirmed-probe" })).toBeTruthy();
  });

  it("opens on all probes when none needs attention, and explains an empty review list when chosen", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect(await screen.findByRole("gridcell", { name: probe.nonce })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: /^Needs attention/ }));
    expect(await screen.findByText(/No callbacks to review/)).toBeTruthy();
  });

  it("searches client name, notes, and payload host", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([
      { ...probe, nonce: "by-client", client_name: "acme-lane-7" },
      { ...probe, nonce: "by-notes", notes: "planted in the Acme avatar importer" },
      { ...probe, nonce: "by-host", client_payload_host: "zz9plural.oast.example" },
    ]);
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    const search = screen.getByRole("searchbox", { name: "Search OAST probes" });

    for (const [term, nonce] of [["acme-lane-7", "by-client"], ["avatar importer", "by-notes"], ["zz9plural", "by-host"]]) {
      fireEvent.change(search, { target: { value: term } });
      await waitFor(() => expect(screen.getAllByRole("gridcell").map((cell) => cell.textContent)).toEqual([nonce]));
    }
  });

  it("loads the probe list once under StrictMode's repeated mount effect", async () => {
    render(<StrictMode><ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider></StrictMode>);
    await screen.findByRole("gridcell", { name: probe.nonce });

    expect(listOobProbes).toHaveBeenCalledTimes(1);
  });

  it("uses truthful distinct lifecycle labels and accessible filters", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([
      { ...probe, nonce: "fired-probe", status: "fired", interaction_count: 1 },
      { ...probe, nonce: "confirmed-probe", status: "confirmed", interaction_count: 1 },
    ]);

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    expect((await screen.findByRole("button", { name: /^Callback received/ }))
      .getAttribute("aria-pressed")).toBe("false");
    const confirmed = screen.getByRole("button", { name: /^Operator confirmed/ });
    expect(confirmed.getAttribute("aria-pressed")).toBe("false");
    // One chip per status present, in urgency order, with its count.
    expect(within(screen.getByRole("group", { name: "Status" })).getAllByRole("button").map((chip) => chip.textContent))
      .toEqual(["Callback received1", "Operator confirmed1"]);
    expect(screen.getByRole("searchbox", { name: "Search OAST probes" })).toBeTruthy();
  });

  it("summarizes callbacks by protocol and type, flags relay-masked sources, and keeps receipts exact", async () => {
    const raw = "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==";
    vi.mocked(listOobProbes).mockResolvedValue([firedProbe]);
    vi.mocked(getOobProbe).mockResolvedValue({
      ...firedProbe,
      interactions: [
        interaction(44, { protocol: "http", query_type: "", raw_request: raw, observed_at: "2026-09-12T05:06:07Z" }),
        interaction(45, { query_type: "A", observed_at: "2026-09-12 05:01:00" }),
        interaction(46, { query_type: "A", observed_at: "2026-09-12 05:02:00" }),
        interaction(47, { query_type: "AAAA", observed_at: "2026-09-12 05:03:00" }),
      ],
    });

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));

    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByRole("heading", { level: 2, name: "https://target.example/callback · url · ssrf" })).toBeTruthy();
    expect(within(record).getByText(/reached out 4 times/)).toBeTruthy();
    expect(within(record).getAllByText("ssrf-a").length).toBeGreaterThan(0);
    expect(within(record).getByText("client-a.oast.example")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Callbacks\s*4/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast&probe=1&dtab=callbacks");
    const dialog = record;
    await within(dialog).findByText("4 callbacks");
    expect(within(dialog).getByText(/Every callback arrived from 172\.17\.0\.2.*masked by relay NAT/)).toBeTruthy();
    expect(within(dialog).getByText("First 2026-09-12 05:01:00 UTC")).toBeTruthy();
    expect(within(dialog).getByText("Latest 2026-09-12 05:06:07 UTC")).toBeTruthy();
    expect(within(dialog).getByRole("img", { name: /Callbacks over time/ })).toBeTruthy();

    const groups = within(dialog).getByRole("group", { name: "Protocol" });
    expect(within(groups).getAllByRole("button").map((button) => button.textContent)).toEqual([
      "All4", "DNS A2", "DNS AAAA1", "HTTP1",
    ]);
    const table = within(dialog).getByRole("table");
    // Newest first, all times in UTC.
    expect(within(table).getAllByRole("row").slice(1).map((row) => within(row).getAllByRole("cell")[0].textContent))
      .toEqual(["2026-09-12 05:06:07 UTC", "2026-09-12 05:03:00 UTC", "2026-09-12 05:02:00 UTC", "2026-09-12 05:01:00 UTC"]);
    fireEvent.click(within(groups).getByRole("button", { name: /^DNS A\s*2$/ }));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    fireEvent.click(within(groups).getByRole("button", { name: /^All/ }));

    fireEvent.click(within(table).getAllByRole("button", { name: "Show receipt" })[0]);
    expect(within(dialog).getByText(raw)).toBeTruthy();
    expect(within(dialog).getByText("GET /callback HTTP/1.1")).toBeTruthy();
    expect(within(dialog).getByText("interaction-44")).toBeTruthy();
  });

  it("pages a long callback history", async () => {
    const many = Array.from({ length: 30 }, (_, index) =>
      interaction(index + 1, { observed_at: `2026-09-12 05:${String(index).padStart(2, "0")}:00` }));
    vi.mocked(listOobProbes).mockResolvedValue([{ ...firedProbe, interaction_count: 30 }]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...firedProbe, interactions: many });

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));
    const dialog = await openCallbacks();
    const table = await within(dialog).findByRole("table");

    expect(within(table).getAllByRole("row")).toHaveLength(26);
    expect(within(dialog).getByText("1–25 of 30")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Older" }));
    expect(within(table).getAllByRole("row")).toHaveLength(6);
    expect(within(dialog).getByText("26–30 of 30")).toBeTruthy();
  });

  it("marks a probe with no recorded target, parameter, or technique as unattributed", async () => {
    const bare = { ...firedProbe, target_url: "", param: "", technique: "" };
    vi.mocked(listOobProbes).mockResolvedValue([bare]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...bare, interactions: [] });

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));

    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByText("Unattributed")).toBeTruthy();
    expect(within(record).getByRole("heading", { level: 2, name: "Unattributed probe" })).toBeTruthy();
  });

  it("shows when a pending probe was planted and how long it has waited", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-09-15T00:00:00Z"));
    try {
      vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
      render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
      fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
      fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));

      const dialog = await screen.findByRole("region", RECORD);
      expect(within(dialog).getAllByText("Awaiting callback").length).toBeGreaterThan(0);
      expect(within(dialog).getByText("Waiting since").nextElementSibling?.textContent).toContain("2026-09-12 00:00 UTC");
      expect(within(dialog).getByText("Planted 3d ago; no callback yet.")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("opens a production grid row by keyboard and restores focus after Escape", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([firedProbe]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...firedProbe, interactions: [] });
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    const invoker = await screen.findByRole("gridcell", { name: "oast-123" });
    invoker.focus();
    fireEvent.keyDown(invoker, { key: "Enter" });
    const record = await screen.findByRole("region", RECORD);
    expect(document.activeElement).toBe(within(record).getByRole("heading", { level: 2 }));

    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    await waitFor(() => expect(document.activeElement).toBe(invoker));
  });

  it("does not render the production grid's no-match overlay when the initial probe request fails", async () => {
    vi.mocked(listOobProbes).mockRejectedValue(new Error("probe ledger unavailable"));

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect((await screen.findByRole("alert")).textContent).toContain("probe ledger unavailable");
    expect(screen.queryByText("No OAST probes match the current filters.")).toBeNull();
    expect(screen.queryByRole("grid")).toBeNull();
  });

  it("keeps the last probe row visible when a background refresh fails", async () => {
    vi.mocked(listOobProbes)
      .mockResolvedValueOnce([firedProbe])
      .mockRejectedValueOnce(new Error("probe refresh unavailable"));

    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    expect(await screen.findByRole("gridcell", { name: "oast-123" })).toBeTruthy();
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);

    expect((await screen.findByRole("alert")).textContent).toContain("probe refresh unavailable");
    expect(screen.getByRole("gridcell", { name: "oast-123" })).toBeTruthy();
  });

  it("shows detail-load failure instead of claiming no callbacks were observed", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([firedProbe]);
    vi.mocked(getOobProbe).mockRejectedValue(new Error("callback ledger unavailable"));
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));
    await openCallbacks();

    expect((await screen.findByRole("alert")).textContent).toContain("callback ledger unavailable");
    expect(screen.queryByText(/No callbacks observed/)).toBeNull();
  });

  it("queues a websocket refresh that arrives during an in-flight load", async () => {
    const first = deferred<typeof probe[]>();
    vi.mocked(listOobProbes)
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce([{ ...firedProbe, nonce: "oast-fresh" }]);

    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(1));
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    first.resolve([firedProbe]);

    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("gridcell", { name: "oast-fresh" })).toBeTruthy();
  });
});

describe("OastTab record view", () => {
  const probes = [
    { ...firedProbe, id: 11, nonce: "fired-a", target_url: "https://acme.example/a", last_interaction_at: "2026-09-12T06:00:00Z" },
    { ...firedProbe, id: 12, nonce: "fired-b", target_url: "https://acme.example/b", last_interaction_at: "2026-09-12T05:00:00Z" },
    { ...firedProbe, id: 13, nonce: "fired-c", target_url: "https://acme.example/c", last_interaction_at: "2026-09-12T04:00:00Z" },
    { ...probe, id: 14, nonce: "pending-d", target_url: "https://acme.example/d" },
  ];
  beforeEach(() => {
    vi.mocked(listOobProbes).mockResolvedValue(probes);
    vi.mocked(getOobProbe).mockImplementation(async (_key, nonce) => ({ ...probes.find((item) => item.nonce === nonce)!, interactions: [] }));
  });

  it("walks the grid's order with previous and next and returns to the list intact", async () => {
    gridSort.reverse = true;
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    const row = await screen.findByRole("gridcell", { name: "fired-b" });
    fireEvent.click(row);
    const record = await screen.findByRole("region", RECORD);
    expect(screen.queryByRole("dialog")).toBeNull();
    // The record replaces the results; they keep their state behind it.
    expect(screen.queryByRole("button", { name: /^Needs attention/ })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast&probe=12");
    expect(within(record).getByText("Probe #12")).toBeTruthy();
    expect(within(record).getByText("2 of 3 results")).toBeTruthy();
    expect(within(record).getByLabelText("OAST probe dates").textContent).toContain("Last callback");

    // The grid shows c, b, a: Next goes to a, the last result.
    fireEvent.click(within(record).getByRole("button", { name: "Next probe" }));
    expect(await within(record).findByRole("heading", { level: 2, name: /acme\.example\/a/ })).toBeTruthy();
    expect(within(record).getByText("3 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Next probe" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.keyDown(document.body, { key: "[" });
    fireEvent.keyDown(document.body, { key: "[" });
    expect(await within(record).findByRole("heading", { level: 2, name: /acme\.example\/c/ })).toBeTruthy();
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    expect((within(record).getByRole("button", { name: "Previous probe" }) as HTMLButtonElement).disabled).toBe(true);
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast&probe=13");

    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast");
    expect(screen.getByRole("button", { name: /^Needs attention/ }).getAttribute("aria-pressed")).toBe("true");
    // Back lands on the record last shown (stepped to c), not the row that opened b.
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("gridcell", { name: "fired-c" })));
    expect(row.isConnected).toBe(true);
  });

  it("keeps the open section while stepping and follows the URL", async () => {
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={11} initialDrawerTab="callbacks" /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByRole("button", { name: /^Callbacks/ }).getAttribute("aria-current")).toBe("page");
    expect(within(record).getByText("1 of 3 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Next probe" }));
    expect(await within(record).findByRole("heading", { level: 2, name: /acme\.example\/b/ })).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=oast&probe=12&dtab=callbacks");
    expect(within(record).getByRole("button", { name: /^Callbacks/ }).getAttribute("aria-current")).toBe("page");
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
  });

  it("shows a deep-linked probe the review view hides among all probes", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={14} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByRole("heading", { level: 2, name: /acme\.example\/d/ })).toBeTruthy();
    expect(within(record).getByText("4 of 4 results")).toBeTruthy();
    fireEvent.keyDown(document.body, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("explains a deep link to a probe the ledger does not hold", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={404} /></ToastProvider>);
    expect((await screen.findByRole("alert")).textContent).toContain("OAST probe #404 is not in this engagement's probe ledger");
    expect(screen.queryByRole("region", RECORD)).toBeNull();
  });
});

describe("OastTab deep links and scope", () => {
  const probes = [
    { ...firedProbe, id: 11, nonce: "fired-a", target_url: "https://acme.example/a", last_interaction_at: "2026-09-12T06:00:00Z" },
    { ...firedProbe, id: 12, nonce: "fired-b", target_url: "https://acme.example/b", last_interaction_at: "2026-09-12T05:00:00Z" },
    { ...probe, id: 14, nonce: "pending-d", target_url: "https://acme.example/d" },
    { ...probe, id: 15, nonce: "expired-e", status: "expired", target_url: "https://acme.example/e", notes: "retired lane" },
  ];
  beforeEach(() => {
    vi.mocked(listOobProbes).mockResolvedValue(probes);
    vi.mocked(getOobProbe).mockImplementation(async (_key, nonce) => ({ ...probes.find((item) => item.nonce === nonce)!, interactions: [] }));
  });

  it("drops the open record when the link changes to a probe the ledger does not hold", async () => {
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={11} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByText("Probe #11")).toBeTruthy();
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={99999} /></ToastProvider>);
    expect((await screen.findByRole("alert")).textContent).toContain("OAST probe #99999 is not in this engagement's probe ledger");
    expect(screen.queryByRole("region", RECORD)).toBeNull();
    // Linking back to the first probe opens it again.
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={11} /></ToastProvider>);
    expect(within(await screen.findByRole("region", RECORD)).getByText("Probe #11")).toBeTruthy();
  });

  it("says why a linked probe outside Needs attention switched the list to all probes", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={14} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByText("3 of 4 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByText(/Showing all probes: probe #14 is awaiting callback/i)).toBeTruthy();
  });

  it("widens a status filter that hides a linked probe instead of leaving it outside the results", async () => {
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    fireEvent.click(await screen.findByRole("button", { name: /^Callback received/ }));
    await waitFor(() => expect(screen.getAllByRole("gridcell")).toHaveLength(2));
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={15} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByText("4 of 4 results")).toBeTruthy();
  });

  it("offers all probes when Needs attention has no match but other probes do", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await screen.findByRole("gridcell", { name: "fired-a" });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search OAST probes" }), { target: { value: "retired lane" } });
    expect(await screen.findByText("No probes need attention that match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Show all probes/ }));
    expect(await screen.findByRole("gridcell", { name: "expired-e" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
  });

  it("names the order the grid shows", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await screen.findByRole("gridcell", { name: "fired-a" });
    expect(await screen.findByText(/Sorted by Last callback, newest first/)).toBeTruthy();
  });

  it("names a status sort by urgency, like every other status column", async () => {
    gridSort.column = "status";
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await screen.findByRole("gridcell", { name: "fired-a" });
    expect(await screen.findByText(/Sorted by Status, most urgent first/)).toBeTruthy();
  });
});

describe("OastTab operator verdicts", () => {
  const fired = { ...firedProbe, id: 21, nonce: "fired-v", target_url: "https://acme.example/v" };
  const other = { ...firedProbe, id: 22, nonce: "fired-w", target_url: "https://acme.example/w", last_interaction_at: "2026-09-12T04:00:00Z" };
  beforeEach(() => {
    vi.mocked(listOobProbes).mockResolvedValue([fired, other]);
    vi.mocked(getOobProbe).mockImplementation(async (_key, nonce) => ({ ...[fired, other].find((item) => item.nonce === nonce)!, interactions: [], verdict: null }));
  });

  it("confirms a callback after a confirmation that says what will happen, and the probe leaves Needs attention", async () => {
    const confirmed = { ...fired, status: "confirmed", interactions: [], verdict: { verdict: "confirmed", note: "egress from the Acme importer", actor: "operator", recorded_at: "2026-09-13T10:00:00Z" } };
    vi.mocked(request).mockResolvedValue(confirmed as never);
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={21} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).getByText(/No verdict yet/)).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Confirm callback…" }));
    const dialog = screen.getByRole("dialog", { name: /Confirm the callback on probe #21/ });
    expect(dialog.textContent).toContain("written to the engagement's audit log");
    expect(dialog.textContent).toContain("leaves Needs attention");
    expect(request).not.toHaveBeenCalled();
    fireEvent.change(within(dialog).getByRole("textbox", { name: /Note/ }), { target: { value: "egress from the Acme importer" } });
    vi.mocked(listOobProbes).mockResolvedValue([{ ...fired, status: "confirmed" }, other]);
    fireEvent.click(within(dialog).getByRole("button", { name: "Record verdict: Operator confirmed" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(request).toHaveBeenCalledWith("/engagements/demo/assessment/oob-probes/fired-v", {
      method: "PATCH",
      body: JSON.stringify({ verdict: "confirmed", note: "egress from the Acme importer", actor: "operator" }),
    });
    expect(within(record).getAllByText("Operator confirmed").length).toBeGreaterThan(0);
    expect(within(record).getByText("egress from the Acme importer")).toBeTruthy();
    // The reviewed probe stays steppable while its record is open.
    expect(within(record).getByText("1 of 2 results")).toBeTruthy();
    expect(within(record).getByRole("button", { name: "Ignore instead…" })).toBeTruthy();
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    await waitFor(() => expect(screen.queryByRole("region", RECORD)).toBeNull());
    expect(screen.getByRole("button", { name: /^Needs attention/ }).textContent).toContain("1");
    expect(screen.getAllByRole("gridcell").map((cell) => cell.textContent)).toEqual(["fired-w"]);
  });

  it("reports the probes awaiting a verdict to the rail as soon as a verdict is recorded", async () => {
    const confirmed = { ...fired, status: "confirmed", interactions: [], verdict: { verdict: "confirmed", note: "", actor: "operator", recorded_at: "2026-09-13T10:00:00Z" } };
    vi.mocked(request).mockResolvedValue(confirmed as never);
    // The list re-read is held back, so the new count can only come from the verdict itself.
    vi.mocked(listOobProbes).mockResolvedValueOnce([fired, other]).mockReturnValue(new Promise(() => {}));
    const onToReviewCount = vi.fn();
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={21} onToReviewCount={onToReviewCount} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    await waitFor(() => expect(onToReviewCount).toHaveBeenLastCalledWith(2));
    fireEvent.click(within(record).getByRole("button", { name: "Confirm callback…" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Record verdict: Operator confirmed" }));
    await waitFor(() => expect(onToReviewCount).toHaveBeenLastCalledWith(1));
  });

  it("shows a rejected verdict in the dialog and keeps the probe as it was", async () => {
    vi.mocked(request).mockRejectedValue(new ApiError("oob probe is pending: only a probe with a callback takes a verdict", 409, undefined));
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={21} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    fireEvent.click(within(record).getByRole("button", { name: "Ignore callback…" }));
    const dialog = screen.getByRole("dialog", { name: /Ignore the callback on probe #21/ });
    fireEvent.click(within(dialog).getByRole("button", { name: "Record verdict: Ignored" }));
    expect((await within(dialog).findByRole("alert")).textContent).toContain("only a probe with a callback takes a verdict");
    expect(within(record).getAllByText("Callback received").length).toBeGreaterThan(0);
  });

  it("explains why a probe without a callback takes no verdict", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([{ ...probe, id: 31 }]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, id: 31, interactions: [] });
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={31} /></ToastProvider>);
    const record = await screen.findByRole("region", RECORD);
    expect(within(record).queryByRole("button", { name: /Confirm callback/ })).toBeNull();
    expect(within(record).getByText(/A verdict can be recorded once a callback arrives/)).toBeTruthy();
  });
});

describe("OastTab refresh, errors and saved view", () => {
  const probes = [
    { ...firedProbe, id: 41, nonce: "fired-x", target_url: "https://acme.example/x", last_interaction_at: "2026-09-12T06:00:00Z" },
    { ...probe, id: 42, nonce: "pending-y", target_url: "https://acme.example/y" },
    { ...probe, id: 43, nonce: "expired-z", status: "expired", target_url: "https://acme.example/z" },
  ];
  beforeEach(() => {
    vi.mocked(listOobProbes).mockResolvedValue(probes);
  });

  it("re-reads the probe list once per refresh signal when the browser tab regains focus", async () => {
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await screen.findByRole("gridcell", { name: "fired-x" });
    expect(listOobProbes).toHaveBeenCalledTimes(1);
    // The page turns a visibility change into one refresh signal for the open tab.
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    document.dispatchEvent(new Event("visibilitychange"));
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(listOobProbes).toHaveBeenCalledTimes(2);
  });

  it("offers Try again when the probe list cannot be read", async () => {
    vi.mocked(listOobProbes).mockRejectedValueOnce(new Error("probe ledger unavailable"));
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("OAST probes could not be loaded: probe ledger unavailable");
    // Nothing was read, so the scope shows no counts rather than zero.
    expect(screen.getByRole("button", { name: /^All/ }).textContent).toBe("All");
    fireEvent.click(within(alert.closest(".oast-banner") as HTMLElement).getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("gridcell", { name: "fired-x" })).toBeTruthy();
    expect(listOobProbes).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: /^All/ }).textContent).toBe("All3");
  });

  it("explains a missing linked probe below the page header, with the results", async () => {
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} initialProbeId={404} /></ToastProvider>);
    const alert = await screen.findByRole("alert");
    const heading = screen.getByRole("heading", { level: 1, name: "OAST" });
    expect(heading.compareDocumentPosition(alert) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("keeps scope, status chips and search when the operator leaves the tab and comes back", async () => {
    const first = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: /^All/ }));
    fireEvent.click(await screen.findByRole("button", { name: /^Awaiting callback/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search OAST probes" }), { target: { value: "acme.example/y" } });
    await waitFor(() => expect(screen.getAllByRole("gridcell").map((cell) => cell.textContent)).toEqual(["pending-y"]));
    first.unmount();

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.getAllByRole("gridcell").map((cell) => cell.textContent)).toEqual(["pending-y"]));
    expect(screen.getByRole("button", { name: /^All/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: /^Awaiting callback/ }).getAttribute("aria-pressed")).toBe("true");
    expect((screen.getByRole("searchbox", { name: "Search OAST probes" }) as HTMLInputElement).value).toBe("acme.example/y");

    // Another engagement keeps its own view: it opens on Needs attention.
    cleanup();
    render(<ToastProvider><OastTab engagementKey="other" refreshVersion={0} /></ToastProvider>);
    expect((await screen.findByRole("button", { name: /^Needs attention/ })).getAttribute("aria-pressed")).toBe("true");
  });
});
