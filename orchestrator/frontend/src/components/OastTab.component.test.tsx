// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getOobProbe, listOobProbes } from "../lib/api";
import { ToastProvider } from "../contexts/ToastContext";
import { OastTab } from "./OastTab";

vi.mock("../lib/api", () => ({
  getOobProbe: vi.fn(),
  listOobProbes: vi.fn(),
}));

vi.mock("ag-grid-react", () => ({
  AgGridReact: ({
    rowData = [],
    onRowClicked,
    onCellKeyDown,
    overlayNoRowsTemplate = "",
  }: {
    rowData?: Array<{ nonce: string }>;
    onRowClicked?: (event: unknown) => void;
    onCellKeyDown?: (event: unknown) => void;
    overlayNoRowsTemplate?: string;
  }) => (
    <div role="grid">
      {rowData.length === 0
        ? <span>{overlayNoRowsTemplate.replace(/<[^>]+>/g, "")}</span>
        : rowData.map((row) => (
          <div
            key={row.nonce}
            role="gridcell"
            tabIndex={0}
            onClick={(event) => onRowClicked?.({ data: row, event })}
            onKeyDown={(event) => onCellKeyDown?.({ data: row, event })}
          >
            {row.nonce}
          </div>
        ))}
    </div>
  ),
}));

const probe = {
  id: 1,
  engagement_id: 1,
  nonce: "oast-123",
  oob_domain: "oast.test",
  target_url: "https://target.test/callback",
  technique: "ssrf",
  param: "url",
  probe_kind: "http",
  request_hash: "request-sha256",
  client_name: "ssrf-a",
  client_payload_host: "client-a.oast.test",
  status: "pending",
  notes: "",
  created_at: "2026-09-12T00:00:00Z",
  updated_at: "2026-09-12T00:00:00Z",
  interaction_count: 0,
  last_interaction_at: "",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.mocked(listOobProbes).mockResolvedValue([probe]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("OastTab detail evidence", () => {
  it("updates an open drawer's lifecycle when the probe list refreshes", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: probe.nonce }));
    expect(within(await screen.findByRole("dialog")).getAllByText("Awaiting callback").length).toBeGreaterThan(0);

    const fired = { ...probe, status: "fired", interaction_count: 1, client_name: "updated-client" };
    vi.mocked(listOobProbes).mockResolvedValue([fired]);
    vi.mocked(getOobProbe).mockResolvedValue({ ...fired, interactions: [] });
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(getOobProbe).toHaveBeenCalledTimes(2));
    await screen.findByText("Callback received · confirmation needed");

    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Callback received · confirmation needed")).toBeTruthy();
    expect(within(dialog).getByText("updated-client")).toBeTruthy();
    expect(within(dialog).queryByText("Awaiting callback")).toBeNull();
  });

  it("closes the drawer when its selected probe is removed by a refreshed list", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: probe.nonce }));
    await screen.findByRole("dialog");
    vi.mocked(listOobProbes).mockResolvedValue([]);
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.classList.contains("detail-modal-open")).toBe(false);
  });

  it("defaults to the actionable worklist and keeps the full inventory available", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([
      { ...probe, nonce: "pending-probe", status: "pending" },
      { ...probe, nonce: "fired-probe", status: "fired", interaction_count: 1 },
      { ...probe, nonce: "expired-probe", status: "expired" },
      { ...probe, nonce: "confirmed-probe", status: "confirmed", interaction_count: 1 },
      { ...probe, nonce: "ignored-probe", status: "ignored" },
    ]);

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect((await screen.findByRole("button", { name: /^Worklist/ })).getAttribute("aria-pressed"))
      .toBe("true");
    expect(screen.getByRole("button", { name: /^Inventory/ }).getAttribute("aria-pressed"))
      .toBe("false");
    expect(await screen.findByRole("gridcell", { name: "pending-probe" })).toBeTruthy();
    expect(screen.getByRole("gridcell", { name: "fired-probe" })).toBeTruthy();
    expect(screen.getByRole("gridcell", { name: "expired-probe" })).toBeTruthy();
    expect(screen.queryByRole("gridcell", { name: "confirmed-probe" })).toBeNull();
    expect(screen.queryByRole("gridcell", { name: "ignored-probe" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /^Inventory/ }));
    expect(await screen.findByRole("gridcell", { name: "confirmed-probe" })).toBeTruthy();
    expect(screen.getByRole("gridcell", { name: "ignored-probe" })).toBeTruthy();
  });

  it("uses truthful distinct lifecycle labels and accessible filters", async () => {
    vi.mocked(listOobProbes).mockResolvedValue([
      { ...probe, nonce: "fired-probe", status: "fired", interaction_count: 1 },
      { ...probe, nonce: "confirmed-probe", status: "confirmed", interaction_count: 1 },
    ]);

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect((await screen.findByRole("button", { name: /Filter status Callback received/ }))
      .getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(screen.getByRole("button", { name: /^Inventory/ }));
    const confirmed = screen.getByRole("button", { name: /Filter status Operator confirmed/ });
    expect(confirmed.getAttribute("aria-pressed")).toBe("false");
    expect(screen.queryByRole("button", { name: /unmatched/i })).toBeNull();
    expect(screen.getByRole("searchbox", { name: "Search OAST probes" })).toBeTruthy();
  });

  it("shows binding truth, interaction summary, exact receipt metadata, and separate decoding", async () => {
    const raw = "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==";
    const firedProbe = {
      ...probe,
      status: "fired",
      interaction_count: 1,
      last_interaction_at: "2026-09-12T05:06:07Z",
    };
    vi.mocked(listOobProbes).mockResolvedValue([firedProbe]);
    vi.mocked(getOobProbe).mockResolvedValue({
      ...firedProbe,
      interactions: [{
        id: 44,
        engagement_id: 1,
        probe_id: 1,
        protocol: "http",
        remote_address: "203.0.113.8",
        query_type: "A",
        raw_request: raw,
        interaction_hash: "interaction-sha256",
        observed_at: "2026-09-12T05:06:07Z",
        created_at: "2026-09-12T05:06:08Z",
      }],
    });

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Callback received · confirmation needed")).toBeTruthy();
    expect(within(dialog).getByText("ssrf-a")).toBeTruthy();
    expect(within(dialog).getByText("client-a.oast.test")).toBeTruthy();
    expect(within(dialog).getByText("Complete")).toBeTruthy();
    expect(within(dialog).getByText("1 callback")).toBeTruthy();
    expect(within(dialog).getAllByText("HTTP")).toHaveLength(2);
    expect(within(dialog).getByText("interaction-sha256")).toBeTruthy();
    expect(within(dialog).getByText("2026-09-12 05:06:07.000 UTC")).toBeTruthy();
    expect(within(dialog).getByText(raw)).toBeTruthy();
    expect(within(dialog).getByText("GET /callback HTTP/1.1")).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "Close OAST probe details" })).toBeTruthy();
  });

  it("makes pending age and the absence of a durable expiry explicit", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getAllByText("Awaiting callback").length).toBeGreaterThan(0);
    expect(within(dialog).getByText("Pending age")).toBeTruthy();
    expect(within(dialog).getByText("Not recorded by OAST ledger")).toBeTruthy();
  });

  it("opens a production grid row by keyboard and restores focus after Escape", async () => {
    vi.mocked(getOobProbe).mockResolvedValue({ ...probe, interactions: [] });
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    const invoker = await screen.findByRole("gridcell", { name: "oast-123" });
    invoker.focus();
    fireEvent.keyDown(invoker, { key: "Enter" });
    const dialog = await screen.findByRole("dialog");
    await waitFor(() => expect(dialog.contains(document.activeElement)).toBe(true));
    fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    const dialogButtons = within(dialog).getAllByRole("button");
    expect(document.activeElement).toBe(dialogButtons[dialogButtons.length - 1]);

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(invoker);
  });

  it("does not render the production grid's no-match overlay when the initial probe request fails", async () => {
    vi.mocked(listOobProbes).mockRejectedValue(new Error("probe ledger unavailable"));

    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect((await screen.findByRole("alert")).textContent).toContain("probe ledger unavailable");
    expect(screen.queryByText("No OAST probes minted yet.")).toBeNull();
    expect(screen.queryByText("No OAST probes match the current filters.")).toBeNull();
  });

  it("keeps the last probe row visible when a background refresh fails", async () => {
    vi.mocked(listOobProbes)
      .mockResolvedValueOnce([probe])
      .mockRejectedValueOnce(new Error("probe refresh unavailable"));

    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    expect(await screen.findByRole("gridcell", { name: "oast-123" })).toBeTruthy();
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);

    expect((await screen.findByRole("alert")).textContent).toContain("probe refresh unavailable");
    expect(screen.getByRole("gridcell", { name: "oast-123" })).toBeTruthy();
  });

  it("shows detail-load failure instead of claiming no callbacks were observed", async () => {
    vi.mocked(getOobProbe).mockRejectedValue(new Error("callback ledger unavailable"));
    render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    fireEvent.click(await screen.findByRole("gridcell", { name: "oast-123" }));

    expect((await screen.findByRole("alert")).textContent).toContain("callback ledger unavailable");
    expect(screen.queryByText(/No callbacks observed/)).toBeNull();
  });

  it("queues a websocket refresh that arrives during an in-flight load", async () => {
    const first = deferred<typeof probe[]>();
    vi.mocked(listOobProbes)
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce([{ ...probe, nonce: "oast-fresh" }]);

    const view = render(<ToastProvider><OastTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(1));
    view.rerender(<ToastProvider><OastTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    first.resolve([probe]);

    await waitFor(() => expect(listOobProbes).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("gridcell", { name: "oast-fresh" })).toBeTruthy();
  });
});
