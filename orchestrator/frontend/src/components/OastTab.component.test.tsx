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
  payload: "https://oast.test/oast-123",
  status: "pending",
  notes: "",
  created_at: "2026-09-12T00:00:00Z",
  updated_at: "2026-09-12T00:00:00Z",
  interaction_count: 0,
  last_interaction_at: null,
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
