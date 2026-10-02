// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  exportHarUrl,
  getCapturePolicy,
  getHttpFlow,
  listHttpFlows,
  listRequestObservations,
  listRequestVariants,
  setCapturePolicy,
} from "../lib/api";
import { ToastProvider } from "../contexts/ToastContext";
import { HttpTab } from "./HttpTab";

vi.mock("../lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/api")>();
  return {
    ...actual,
    exportHarUrl: vi.fn(),
    getCapturePolicy: vi.fn(),
    getHttpFlow: vi.fn(),
    listHttpFlows: vi.fn(),
    listRequestObservations: vi.fn(),
    listRequestVariants: vi.fn(),
    setCapturePolicy: vi.fn(),
  };
});

vi.mock("./HttpGrid", () => ({
  default: ({ rows, onRowOpen }: { rows: Array<{ id: number; normalized_path: string }>; onRowOpen: (row: never) => void }) => (
    <div>{rows.length === 0
      ? <span>No request variants match the current filters.</span>
      : rows.map((row) => <button key={row.id} onClick={() => onRowOpen(row as never)}>{row.normalized_path}</button>)}</div>
  ),
}));

vi.mock("./HttpFlowsGrid", () => ({
  default: ({ rows, onRowOpen }: { rows: Array<{ flow_uid: string }>; onRowOpen: (row: never) => void }) => rows.length === 0
    ? <span>No HTTP flows match the current filters.</span>
    : <div>{rows.map((row) => (
      <button key={row.flow_uid} onClick={() => onRowOpen(row as never)}>{row.flow_uid}</button>
    ))}</div>,
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

const capturePolicy = {
  enabled: false,
  capture_request_bodies: true,
  capture_response_bodies: false,
  max_body_bytes: 1_048_576,
  content_type_allow: [],
  content_type_deny: [],
  retention: "until_engagement_deletion" as const,
};

const flow = {
  id: 41,
  engagement_id: 1,
  request_variant_id: 1,
  flow_uid: "flow-1",
  method: "POST",
  scheme: "https",
  host: "target.test",
  port: 443,
  url: "https://target.test/admin",
  path: "/admin",
  response_status: 200,
  request_content_type: "application/json",
  response_content_type: "application/json",
  content_type_family: "json",
  auth_context: "authenticated",
  request_body_sha256: "a".repeat(64),
  response_body_sha256: "b".repeat(64),
  request_body_bytes: 24,
  response_body_bytes: 48,
  request_body_truncated: false,
  response_body_truncated: false,
  request_body_capture_status: "captured",
  response_body_capture_status: "captured",
  request_body_capture_error: "",
  response_body_capture_error: "",
  request_body_artifact_path: "traffic/mitmproxy/bodies/request.bin",
  response_body_artifact_path: "traffic/mitmproxy/bodies/response.bin",
  request_headers: { Authorization: "Bearer operator-token" },
  response_headers: { "Content-Type": "application/json" },
  host_mismatch: false,
  url_authority: "target.test",
  host_header: "target.test",
  sni: "target.test",
  timing_ms: 17,
  started_at: "2026-09-12T00:00:00Z",
  created_at: "2026-09-12T00:00:01Z",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

beforeEach(() => {
  window.history.replaceState(null, "", "#/engagements/demo?tab=http");
  vi.mocked(getCapturePolicy).mockRejectedValue(new Error("policy unavailable"));
  vi.mocked(listHttpFlows).mockResolvedValue([]);
  vi.mocked(listRequestVariants).mockResolvedValue([variant]);
  vi.mocked(listRequestObservations).mockResolvedValue([]);
  vi.mocked(exportHarUrl).mockImplementation(
    (_engagementKey, filters = {}) => `/http-flows/export-har?${new URLSearchParams(filters as Record<string, string>)}`,
  );
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("HttpTab live evidence", () => {
  it("does not show a different selected request when a routed identity is outside the loaded snapshot", async () => {
    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} initialRequestVariantId={1} /></ToastProvider>);
    await screen.findByRole("dialog");
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} initialRequestVariantId={999} /></ToastProvider>);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("status").textContent).toContain("Request #999 cannot be resolved from the loaded endpoint inventory");
    vi.mocked(listRequestVariants).mockResolvedValue([{ ...variant, id: 999, normalized_path: "/other", canonical_url: "https://target.test/other" }]);
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} initialRequestVariantId={999} /></ToastProvider>);
    expect((await screen.findByRole("dialog")).textContent).toContain("/other");
  });
  it("records manually opened requests in canonical browser history and clears selection on close", async () => {
    const push = vi.spyOn(window.history, "pushState");
    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "/admin" }));
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&request=1");
    expect(push).toHaveBeenLastCalledWith(expect.anything(), "", "#/engagements/demo?tab=http&request=1");
    fireEvent.click(screen.getByTitle("Close (Esc)"));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http");
    fireEvent.click(screen.getByRole("button", { name: "/admin" }));
    await screen.findByRole("dialog");
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http");
    push.mockRestore();
  });

  it("closes on browser Back's empty request selection and restores the exact request on return", async () => {
    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} initialRequestVariantId={1} /></ToastProvider>);
    await screen.findByRole("dialog");
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} initialRequestVariantId={1} /></ToastProvider>);
    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByText("https://target.test/admin")).toBeTruthy();
  });

  it("opens an explicitly deep-linked request variant", async () => {
    render(
      <ToastProvider>
        <HttpTab engagementKey="demo" refreshVersion={0} initialRequestVariantId={1} />
      </ToastProvider>,
    );

    expect(await screen.findByRole("dialog")).toBeTruthy();
    expect(screen.getByText("Canonical URL")).toBeTruthy();
    expect(screen.getByText("https://target.test/admin")).toBeTruthy();
  });

  it("describes an exact canonical-flow limit as potentially incomplete", async () => {
    vi.mocked(listHttpFlows).mockResolvedValue(
      Array.from({ length: 5000 }, (_, index) => ({ flow_uid: `flow-${index}` })) as never,
    );

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));

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
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));

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
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));
    expect(await screen.findByRole("button", { name: "flow-1" })).toBeTruthy();
    view.rerender(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={1} /></ToastProvider>);

    await waitFor(() => expect(
      screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("flow refresh unavailable")),
    ).toBe(true));
    expect(screen.getByRole("button", { name: "flow-1" })).toBeTruthy();
  });

  it("queues a flow refresh that arrives during the initial flow load", async () => {
    const firstFlows = deferred<never[]>();
    vi.mocked(listHttpFlows)
      .mockReturnValueOnce(firstFlows.promise)
      .mockResolvedValueOnce([]);

    const view = render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));
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

  it("separates endpoint inventory from non-retroactive captured exchanges", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);

    expect(await screen.findByRole("button", { name: "Endpoint inventory" })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Endpoint inventory" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Captured exchanges" }));
    expect(await screen.findByText(/future proxy traffic only/i)).toBeTruthy();
    expect(screen.getByText(/existing endpoint inventory and earlier traffic are not backfilled/i)).toBeTruthy();
  });

  it("keeps full-flow enablement separate from request and response body fidelity", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));

    const fullFlow = await screen.findByRole("button", { name: "Enable full-flow capture" });
    expect(fullFlow.getAttribute("aria-pressed")).toBe("false");
    const options = screen.getByRole("button", { name: "Options" });
    expect(options.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(options);
    expect(options.getAttribute("aria-expanded")).toBe("true");
    expect((screen.getByRole("checkbox", { name: "Capture request bodies" }) as HTMLInputElement).checked)
      .toBe(true);
    expect((screen.getByRole("checkbox", { name: "Capture response bodies" }) as HTMLInputElement).checked)
      .toBe(false);
    expect(screen.getByRole("status").textContent).toContain("Full-flow capture OFF");
  });

  it("adopts database-updated policy while surfacing a failed filesystem mirror", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);
    const savedPolicy = { ...capturePolicy, enabled: true };
    vi.mocked(setCapturePolicy).mockRejectedValue(new ApiError(
      "capture policy saved, but its filesystem mirror was not updated",
      503,
      {
        detail: {
          message: "capture policy saved, but its filesystem mirror was not updated",
          database_updated: true,
          filesystem_mirror_updated: false,
          error: "simulated read-only engagement root",
          policy: savedPolicy,
        },
      },
    ));

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));
    fireEvent.click(await screen.findByRole("button", { name: "Enable full-flow capture" }));

    expect(await screen.findByRole("button", { name: "Disable full-flow capture" })).toBeTruthy();
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("Policy saved to the database");
    expect(alert.textContent).toContain("filesystem mirror was not updated");
    expect(alert.textContent).toContain("simulated read-only engagement root");
  });

  it("links a selected exchange to its request variant, artifacts, and exact HAR export", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);
    vi.mocked(listHttpFlows).mockResolvedValue([flow]);
    vi.mocked(getHttpFlow).mockResolvedValue(flow);

    render(<ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} /></ToastProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Captured exchanges" }));
    fireEvent.click(await screen.findByRole("button", { name: "flow-1" }));

    expect((await screen.findByRole("link", { name: "Request variant #1" })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=http&request=1");
    expect(screen.getByText("traffic/mitmproxy/bodies/request.bin")).toBeTruthy();
    expect(screen.getByText("traffic/mitmproxy/bodies/response.bin")).toBeTruthy();
    const har = screen.getByRole("link", { name: "Export this exchange as HAR" });
    expect(har.getAttribute("href")).toContain("flow_uid=flow-1");
    expect(exportHarUrl).toHaveBeenCalledWith("demo", { flow_uid: "flow-1" });
  });
});
