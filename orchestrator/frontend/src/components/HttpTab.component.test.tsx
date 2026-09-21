// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  getCapturePolicy,
  listHttpFlows,
  listRequestObservations,
  listRequestVariants,
} from "../lib/api";
import { ToastProvider } from "../contexts/ToastContext";
import { HttpTab } from "./HttpTab";

vi.mock("../lib/api", () => ({
  exportHarUrl: vi.fn(),
  getCapturePolicy: vi.fn(),
  getHttpFlow: vi.fn(),
  listHttpFlows: vi.fn(),
  listRequestObservations: vi.fn(),
  listRequestVariants: vi.fn(),
  setCapturePolicy: vi.fn(),
}));

vi.mock("./HttpGrid", () => ({
  default: ({ rows, onRowOpen }: { rows: Array<{ id: number; normalized_path: string }>; onRowOpen: (row: never) => void }) => (
    <div>{rows.length === 0
      ? <span>No request variants match the current filters.</span>
      : rows.map((row) => <button key={row.id} onClick={() => onRowOpen(row as never)}>{row.normalized_path}</button>)}</div>
  ),
}));

vi.mock("./HttpFlowsGrid", () => ({
  default: ({ rows }: { rows: unknown[] }) => rows.length === 0
    ? <span>No HTTP flows match the current filters.</span>
    : <div>flow grid</div>,
}));

const variant = {
  id: 1,
  engagement_id: 1,
  scheme: "https",
  host: "target.test",
  port: 443,
  method: "GET",
  normalized_path: "/admin",
  canonical_url: "https://target.test/admin",
  path_template: "/admin",
  query_schema_json: "{}",
  body_schema_json: "{}",
  path_schema_json: "{}",
  cookie_schema_json: "{}",
  header_schema_json: "{}",
  params_schema_hash: "params-sha256",
  body_schema_hash: "body-sha256",
  content_type_family: "unknown",
  auth_context: "anonymous",
  discovery_source: "test",
  notes: "",
  first_seen_at: "2026-09-12T00:00:00Z",
  last_seen_at: "2026-09-12T00:00:00Z",
  observation_count: 0,
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

beforeEach(() => {
  vi.mocked(getCapturePolicy).mockRejectedValue(new Error("policy unavailable"));
  vi.mocked(listHttpFlows).mockResolvedValue([]);
  vi.mocked(listRequestVariants).mockResolvedValue([variant]);
  vi.mocked(listRequestObservations).mockResolvedValue([]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("HttpTab live evidence", () => {
  it("describes an exact canonical-flow limit as potentially incomplete", async () => {
    vi.mocked(listHttpFlows).mockResolvedValue(
      Array.from({ length: 5000 }, (_, index) => ({ flow_uid: `flow-${index}` })) as never,
    );

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured traffic" }));

    expect(await screen.findByText(/flow limit reached · results may be incomplete/i)).toBeTruthy();
  });

  it("discloses the observation limit independently from the variant limit", async () => {
    vi.mocked(listRequestObservations).mockResolvedValue(
      Array.from({ length: 5000 }, (_, index) => ({
        id: index + 1,
        request_variant_id: 1,
      })) as never,
    );

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect(await screen.findByText(/observation limit reached · results may be incomplete/i)).toBeTruthy();
  });

  it("does not render a false empty state or grid overlay when the initial variant request fails", async () => {
    vi.mocked(listRequestVariants).mockRejectedValue(new Error("variant ledger unavailable"));

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("variant ledger unavailable"))).toBe(true);
    expect(screen.queryByText("No HTTP request traffic recorded yet.")).toBeNull();
    expect(screen.queryByText("No request variants match the current filters.")).toBeNull();
  });

  it("does not render a false empty state or grid overlay when the initial flow request fails", async () => {
    vi.mocked(listHttpFlows).mockRejectedValue(new Error("flow ledger unavailable"));

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured traffic" }));

    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("flow ledger unavailable"))).toBe(true);
    expect(screen.queryByText(/No canonical HTTP flows captured yet/)).toBeNull();
    expect(screen.queryByText("No HTTP flows match the current filters.")).toBeNull();
  });

  it("keeps stale variants visible when a background refresh fails", async () => {
    vi.mocked(listRequestVariants)
      .mockResolvedValueOnce([variant])
      .mockRejectedValueOnce(new Error("variant refresh unavailable"));

    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    expect(await screen.findByRole("button", { name: "/admin" })).toBeTruthy();
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);

    await waitFor(() => expect(
      screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("variant refresh unavailable")),
    ).toBe(true));
    expect(screen.getByRole("button", { name: "/admin" })).toBeTruthy();
  });

  it("keeps stale flows visible when a background refresh fails", async () => {
    vi.mocked(listHttpFlows)
      .mockResolvedValueOnce([{ flow_uid: "flow-1" }] as never)
      .mockRejectedValueOnce(new Error("flow refresh unavailable"));

    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured traffic" }));
    expect(await screen.findByText("flow grid")).toBeTruthy();
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);

    await waitFor(() => expect(
      screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("flow refresh unavailable")),
    ).toBe(true));
    expect(screen.getByText("flow grid")).toBeTruthy();
  });

  it("queues a flow refresh that arrives during the initial flow load", async () => {
    const firstFlows = deferred<never[]>();
    vi.mocked(listHttpFlows)
      .mockReturnValueOnce(firstFlows.promise)
      .mockResolvedValueOnce([]);

    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured traffic" }));
    await waitFor(() => expect(listHttpFlows).toHaveBeenCalledTimes(1));
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    firstFlows.resolve([]);

    await waitFor(() => expect(listHttpFlows).toHaveBeenCalledTimes(2));
  });

  it("does not present a failed observation request as an empty history", async () => {
    vi.mocked(listRequestObservations).mockRejectedValue(new Error("observation ledger unavailable"));
    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    fireEvent.click(await screen.findByRole("button", { name: "/admin" }));

    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("observation ledger unavailable"))).toBe(true);
    expect(screen.queryByText(/No observations recorded/)).toBeNull();
  });

  it("queues a websocket refresh that arrives during an in-flight load", async () => {
    const firstVariants = deferred<typeof variant[]>();
    const firstObservations = deferred<never[]>();
    vi.mocked(listRequestVariants)
      .mockReturnValueOnce(firstVariants.promise)
      .mockResolvedValueOnce([{ ...variant, id: 2, normalized_path: "/fresh" }]);
    vi.mocked(listRequestObservations)
      .mockReturnValueOnce(firstObservations.promise)
      .mockResolvedValueOnce([]);

    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(listRequestVariants).toHaveBeenCalledTimes(1));
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);
    firstVariants.resolve([variant]);
    firstObservations.resolve([]);

    await waitFor(() => expect(listRequestVariants).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("button", { name: "/fresh" })).toBeTruthy();
  });
});
