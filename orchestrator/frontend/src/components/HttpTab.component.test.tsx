// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ApiError,
  exportHarUrl,
  getCapturePolicy,
  getHttpFlow,
  listHttpFlows,
  setCapturePolicy,
  type RequestVariant,
} from "../lib/api";
import {
  fetchRequestVariant,
  fetchRequestVariantFacets,
  fetchRequestVariantObservations,
  fetchRequestVariantPage,
  fetchRequestVariantPosition,
  type RequestVariantFilters,
} from "../lib/httpApi";
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
    setCapturePolicy: vi.fn(),
  };
});

vi.mock("../lib/httpApi", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/httpApi")>();
  return {
    ...actual,
    // Small pages keep the paging tests to a handful of rows.
    FLOW_PAGE_SIZE: 3,
    FLOW_REFRESH_PROBE: 2,
    fetchRequestVariant: vi.fn(),
    fetchRequestVariantFacets: vi.fn(),
    fetchRequestVariantObservations: vi.fn(),
    fetchRequestVariantPage: vi.fn(),
    fetchRequestVariantPosition: vi.fn(),
  };
});

// The inventory grid is ag-grid's infinite row model in production; this
// stand-in reads its first block through the same server page the real
// datasource uses and renders rows marked with their record key.
vi.mock("./HttpGrid", async () => {
  const { useEffect, useState } = await import("react");
  const httpApi = await import("../lib/httpApi");
  return {
    default: function HttpGridMock({ engagementKey, filters, filtersKey, refreshToken, onRowOpen, onWindow, onError }: {
      engagementKey: string;
      filters: RequestVariantFilters;
      filtersKey: string;
      refreshToken: number;
      onRowOpen: (row: RequestVariant, invoker: HTMLElement) => void;
      onWindow: (window: { total: number | null; first: number; last: number }) => void;
      onError: (message: string | null) => void;
    }) {
      const [rows, setRows] = useState<RequestVariant[]>([]);
      useEffect(() => {
        httpApi.fetchRequestVariantPage(engagementKey, filters, { sort: "last_seen_at", dir: "desc", limit: 100, offset: 0 })
          .then((page) => {
            setRows(page.items);
            onWindow({ total: page.total, first: page.items.length ? 1 : 0, last: page.items.length });
            onError(null);
          })
          .catch((error: Error) => onError(error.message));
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [engagementKey, filtersKey, refreshToken]);
      return (
        <div>
          {rows.map((row) => (
            <button key={row.id} data-record-key={row.id} onClick={(event) => onRowOpen(row, event.currentTarget)}>
              {row.normalized_path}
            </button>
          ))}
        </div>
      );
    },
  };
});

vi.mock("./HttpFlowsGrid", () => ({
  default: ({ rows, onRowOpen }: { rows: Array<{ flow_uid: string }>; onRowOpen: (row: never) => void }) => (
    // The real grid virtualizes; the first rows are enough here.
    <div>{rows.slice(0, 50).map((row) => (
      <button key={row.flow_uid} onClick={() => onRowOpen(row as never)}>{row.flow_uid}</button>
    ))}</div>
  ),
}));

const variant: RequestVariant = {
  id: 1,
  engagement_id: 1,
  scheme: "https",
  host: "target.example",
  port: 443,
  method: "GET",
  normalized_path: "/admin",
  canonical_url: "https://target.example/admin",
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
  discovery_source: "crawler",
  notes: "",
  first_seen_at: "2026-09-12T00:00:00Z",
  last_seen_at: "2026-09-12T00:00:00Z",
  observation_count: 0,
  last_observed_at: null,
};

// Newest first, as the server's default order returns them.
const inventory: RequestVariant[] = [
  { ...variant, id: 3, normalized_path: "/three", last_seen_at: "2026-09-12T03:00:00Z", query_schema_json: "{\"q\": \"string\"}" },
  { ...variant, id: 2, normalized_path: "/two", method: "POST", last_seen_at: "2026-09-12T02:00:00Z", observation_count: 3 },
  { ...variant, id: 1, normalized_path: "/one", last_seen_at: "2026-09-12T01:00:00Z" },
];

function facetsFor(rows: RequestVariant[], engagementTotal = inventory.length) {
  const methods = new Map<string, number>();
  for (const row of rows) methods.set(row.method, (methods.get(row.method) ?? 0) + 1);
  const group = (values: { value: string; count: number }[]) => ({ values, distinct: values.length, omitted_count: 0 });
  return {
    total: rows.length,
    engagement_total: engagementTotal,
    facets: {
      method: group([...methods].map(([value, count]) => ({ value, count }))),
      auth_context: group([{ value: "anonymous", count: rows.length }]),
      content_type: group([{ value: "unknown", count: rows.length }]),
      source: group([{ value: "crawler", count: rows.length }]),
      host: group([{ value: "target.example", count: rows.length }]),
    },
  };
}

function matching(filters: RequestVariantFilters): RequestVariant[] {
  const q = filters.q.trim().toLowerCase();
  return inventory.filter((row) => (!filters.method.length || filters.method.includes(row.method))
    && (!q || row.normalized_path.includes(q)));
}

const observation = (id: number, url: string) => ({
  id,
  engagement_id: 1,
  request_variant_id: 2,
  observed_url: url,
  source_name: "proxy",
  response_status: 403,
  evidence_ref: "",
  raw_payload: "",
  created_at: "2026-09-12T02:00:00Z",
});

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
  host: "target.example",
  port: 443,
  url: "https://target.example/admin",
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
  url_authority: "target.example",
  host_header: "target.example",
  sni: "target.example",
  timing_ms: 17,
  started_at: "2026-09-12T00:00:00Z",
  created_at: "2026-09-12T00:00:01Z",
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

/** Runs `step` with the debounce timers under the test's control, then lets them elapse. */
async function withDebounce(step: () => void, ms: number) {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  try {
    step();
    await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
  } finally {
    vi.useRealTimers();
  }
  // Let the reads the debounce started answer.
  await act(async () => {});
}

/** The inventory rows the grid shows, in order. */
const shownPaths = () => [...document.querySelectorAll("[data-record-key]")].map((row) => row.textContent);

function renderTab(props: Partial<Parameters<typeof HttpTab>[0]> = {}) {
  const element = (next: Partial<Parameters<typeof HttpTab>[0]>) => (
    <ToastProvider><HttpTab engagementKey="demo" refreshVersion={0} {...props} {...next} /></ToastProvider>
  );
  const view = render(element({}));
  return { ...view, update: (next: Partial<Parameters<typeof HttpTab>[0]>) => view.rerender(element(next)) };
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState(null, "", "#/engagements/demo?tab=http");
  vi.mocked(getCapturePolicy).mockRejectedValue(new Error("policy unavailable"));
  vi.mocked(listHttpFlows).mockResolvedValue([]);
  vi.mocked(fetchRequestVariantPage).mockImplementation(async (_key, filters, params) => {
    const rows = matching(filters);
    return { total: rows.length, offset: params.offset, count: rows.length, has_more: false, items: rows.slice(params.offset, params.offset + params.limit) };
  });
  vi.mocked(fetchRequestVariantFacets).mockImplementation(async (_key, filters) => facetsFor(matching(filters)));
  vi.mocked(fetchRequestVariant).mockImplementation(async (_key, id) => {
    const row = inventory.find((candidate) => candidate.id === id);
    if (!row) throw new ApiError("request variant not found", 404, { detail: "request variant not found" });
    return row;
  });
  vi.mocked(fetchRequestVariantPosition).mockImplementation(async (_key, id, filters) => {
    const rows = matching(filters);
    const index = rows.findIndex((row) => row.id === id);
    if (index < 0) return { index: null, total: rows.length, previous: null, next: null };
    return { index, total: rows.length, previous: rows[index - 1] ?? null, next: rows[index + 1] ?? null };
  });
  vi.mocked(fetchRequestVariantObservations).mockResolvedValue({ total: 0, offset: 0, count: 0, has_more: false, items: [] });
  vi.mocked(exportHarUrl).mockImplementation(
    (_engagementKey, filters = {}) => `/http-flows/export-har?${new URLSearchParams(filters as Record<string, string>)}`,
  );
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("HttpTab endpoint inventory", () => {
  it("states its purpose and counts the whole inventory from the server", async () => {
    vi.mocked(fetchRequestVariantFacets).mockImplementation(async (_key, filters) => facetsFor(matching(filters), 9738));
    vi.mocked(fetchRequestVariantPage).mockImplementation(async (_key, _filters, params) => ({
      total: 9738, offset: params.offset, count: 3, has_more: true, items: inventory,
    }));
    renderTab();
    expect(screen.getByRole("heading", { level: 1, name: "HTTP" })).toBeTruthy();
    expect(screen.getByText(/request Vigil has seen/i)).toBeTruthy();
    expect((await screen.findByRole("list", { name: "Summary" })).textContent).toMatch(/9,738\s+request variants/);
    expect((await screen.findByRole("button", { name: /^Endpoint inventory\s*9,738/ })).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: /^GET\s*2/ })).toBeTruthy();
  });

  it("searches the whole inventory on the server, not a loaded window", async () => {
    renderTab();
    await screen.findByRole("button", { name: "/three" });
    await withDebounce(() => {
      fireEvent.change(screen.getByRole("searchbox", { name: "Search endpoint inventory" }), { target: { value: "/two" } });
    }, 300);
    expect(vi.mocked(fetchRequestVariantPage).mock.calls.some(([, filters]) => filters.q === "/two")).toBe(true);
    expect(vi.mocked(fetchRequestVariantFacets).mock.calls.some(([, filters]) => filters.q === "/two")).toBe(true);
    expect(await screen.findByRole("button", { name: "/two" })).toBeTruthy();
    expect(shownPaths()).toEqual(["/two"]);
  });

  it("filters by method on the server with counts from the facets", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^POST\s*1/ }));
    await waitFor(() => expect(vi.mocked(fetchRequestVariantPage).mock.calls.some(([, filters]) => filters.method.includes("POST"))).toBe(true));
    expect(await screen.findByRole("button", { name: "/two" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^POST\s*1/ }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "Clear filters (1)" })).toBeTruthy();
  });

  it("offers Clear filters when nothing matches, and says so only when filters are set", async () => {
    renderTab();
    await screen.findByRole("button", { name: "/three" });
    await withDebounce(() => {
      fireEvent.change(screen.getByRole("searchbox", { name: "Search endpoint inventory" }), { target: { value: "nomatch" } });
    }, 300);
    expect(await screen.findByText("No request variants match these filters.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("button", { name: "/three" })).toBeTruthy();
    expect((screen.getByRole("searchbox", { name: "Search endpoint inventory" }) as HTMLInputElement).value).toBe("");
  });

  it("explains an empty inventory without offering to clear filters", async () => {
    vi.mocked(fetchRequestVariantFacets).mockResolvedValue(facetsFor([], 0));
    vi.mocked(fetchRequestVariantPage).mockResolvedValue({ total: 0, offset: 0, count: 0, has_more: false, items: [] });
    renderTab();
    expect(await screen.findByText("No endpoint inventory recorded yet.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Clear filters/ })).toBeNull();
  });

  it("does not render a false empty state when the inventory read fails", async () => {
    vi.mocked(fetchRequestVariantFacets).mockRejectedValue(new Error("variant ledger unavailable"));
    vi.mocked(fetchRequestVariantPage).mockRejectedValue(new Error("variant ledger unavailable"));
    renderTab();
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("variant ledger unavailable"))).toBe(true);
    expect(screen.queryByText("No endpoint inventory recorded yet.")).toBeNull();
    expect(screen.queryByText("No request variants match these filters.")).toBeNull();
  });

  it("re-reads counts and rows on a live refresh without downloading the ledger", async () => {
    const { update } = renderTab();
    await screen.findByRole("button", { name: "/three" });
    const pages = vi.mocked(fetchRequestVariantPage).mock.calls.length;
    const facets = vi.mocked(fetchRequestVariantFacets).mock.calls.length;
    update({ refreshVersion: 1 });
    await waitFor(() => expect(vi.mocked(fetchRequestVariantFacets).mock.calls.length).toBeGreaterThan(facets));
    await waitFor(() => expect(vi.mocked(fetchRequestVariantPage).mock.calls.length).toBeGreaterThan(pages));
    expect(screen.getByRole("button", { name: "/three" })).toBeTruthy();
  });

  it("keeps the inventory and exchanges views in the URL", async () => {
    const { update } = renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^Captured exchanges/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&view=exchanges");
    update({ initialView: "exchanges" });
    expect(screen.getByRole("button", { name: /^Captured exchanges/ }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: /^Endpoint inventory/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http");
    cleanup();
    renderTab({ initialView: "exchanges" });
    expect(screen.getByRole("button", { name: /^Captured exchanges/ }).getAttribute("aria-pressed")).toBe("true");
    expect(await screen.findByText(/No full HTTP exchanges captured yet/)).toBeTruthy();
  });
});

describe("HttpTab saved view", () => {
  it("keeps the inventory search and filters when the tab is left and reopened", async () => {
    const first = renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /^POST\s*1/ }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Search endpoint inventory" }), { target: { value: "two" } });
    first.unmount();

    renderTab();
    expect((screen.getByRole("searchbox", { name: "Search endpoint inventory" }) as HTMLInputElement).value).toBe("two");
    expect(await screen.findByRole("button", { name: "/two" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^POST\s*1/ }).getAttribute("aria-pressed")).toBe("true");
    expect(vi.mocked(fetchRequestVariantPage).mock.calls.at(-1)?.[1]).toMatchObject({ method: ["POST"], q: "two" });
  });

  it("keeps the exchange filters when the tab is left and reopened", async () => {
    vi.mocked(listHttpFlows).mockResolvedValue([flow] as never);
    const first = renderTab({ initialView: "exchanges" });
    await screen.findByRole("button", { name: "flow-1" });
    fireEvent.change(screen.getByRole("searchbox", { name: "Search captured exchanges" }), { target: { value: "admin" } });
    first.unmount();

    renderTab({ initialView: "exchanges" });
    expect((screen.getByRole("searchbox", { name: "Search captured exchanges" }) as HTMLInputElement).value).toBe("admin");
    await waitFor(() => expect(vi.mocked(listHttpFlows).mock.calls.some(([, params]) => params?.q === "admin")).toBe(true));
  });
});

describe("HttpTab request records", () => {
  it("counts every observation of a request and pages its history from the server", async () => {
    vi.mocked(fetchRequestVariantObservations).mockImplementation(async (_key, _id, params) => (params.offset === 0
      ? { total: 3, offset: 0, count: 2, has_more: true, items: [observation(9, "https://target.example/two?seen=3"), observation(8, "https://target.example/two?seen=2")] }
      : { total: 3, offset: 2, count: 1, has_more: false, items: [observation(7, "https://target.example/two?seen=1")] }));
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: "/two" }));
    const record = await screen.findByRole("region", { name: "Request record" });
    const tab = within(record).getByRole("button", { name: /^Observations/ });
    expect(tab.textContent).toContain("3");
    fireEvent.click(tab);
    expect(await within(record).findByText("https://target.example/two?seen=3")).toBeTruthy();
    expect(fetchRequestVariantObservations).toHaveBeenCalledWith("demo", 2, { limit: 100, offset: 0 });
    fireEvent.click(within(record).getByRole("button", { name: /Show 1 more observation/ }));
    expect(await within(record).findByText("https://target.example/two?seen=1")).toBeTruthy();
    expect(within(record).queryByRole("button", { name: /more observation/ })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&request=2&dtab=observations");
  });

  it("opens a deep-linked request by id and locates it on the server", async () => {
    vi.mocked(fetchRequestVariant).mockResolvedValue({ ...variant, id: 7001, normalized_path: "/deep" });
    vi.mocked(fetchRequestVariantPosition).mockResolvedValue({ index: 7000, total: 9738, previous: inventory[0], next: inventory[2] });
    renderTab({ initialRequestVariantId: 7001 });
    const record = await screen.findByRole("region", { name: "Request record" });
    expect(await within(record).findByText("7,001 of 9,738 results")).toBeTruthy();
    expect(within(record).getByRole("heading", { level: 2 }).textContent).toContain("/deep");
    expect(fetchRequestVariant).toHaveBeenCalledWith("demo", 7001);
    // No inventory page past the first block was read to find it.
    expect(vi.mocked(fetchRequestVariantPage).mock.calls.every(([, , params]) => params.offset === 0)).toBe(true);
  });

  it("says a deep-linked request is not in the inventory without reading the inventory", async () => {
    renderTab({ initialRequestVariantId: 999 });
    expect((await screen.findByText(/Request #999 is not in the endpoint inventory/))).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Request record" })).toBeNull();
  });

  it("walks the server order, keeps the open section, and Back lands on the record last shown", async () => {
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: "/two" }));
    const record = await screen.findByRole("region", { name: "Request record" });
    expect(await within(record).findByText("2 of 3 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: /^Observations/ }));
    fireEvent.click(within(record).getByRole("button", { name: "Next request" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&request=1&dtab=observations");
    expect(await within(record).findByText("3 of 3 results")).toBeTruthy();
    expect(within(record).getByRole("heading", { level: 2 }).textContent).toContain("/one");
    expect(within(record).getByRole("button", { name: /^Observations/ }).getAttribute("aria-current")).toBe("page");
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(screen.queryByRole("region", { name: "Request record" })).toBeNull();
    expect(window.location.hash).toBe("#/engagements/demo?tab=http");
    await waitFor(() => expect(document.activeElement).toBe(screen.getByRole("button", { name: "/one" })));
  });

  it("closes on browser Back and restores the exact request on return", async () => {
    const { update } = renderTab({ initialRequestVariantId: 1 });
    await screen.findByRole("region", { name: "Request record" });
    update({ initialRequestVariantId: undefined });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Request record" })).toBeNull());
    update({ initialRequestVariantId: 1 });
    expect(await screen.findByRole("region", { name: "Request record" })).toBeTruthy();
    expect(screen.getByText("https://target.example/admin")).toBeTruthy();
  });
});

describe("HttpTab captured exchanges", () => {
  it("says older exchanges are not loaded yet after a full page", async () => {
    vi.mocked(listHttpFlows).mockResolvedValue(
      Array.from({ length: 3 }, (_, index) => ({ ...flow, id: 3 - index, flow_uid: `flow-${index}` })) as never,
    );
    renderTab({ initialView: "exchanges" });
    expect((await screen.findAllByText(/older exchanges not loaded yet/i)).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Load 3 older exchanges" })).toBeTruthy();
  });

  it("marks filter counts taken over the loaded exchanges as lower bounds", async () => {
    vi.mocked(listHttpFlows).mockResolvedValue(
      Array.from({ length: 3 }, (_, index) => ({ ...flow, id: 3 - index, flow_uid: `flow-${index}`, method: index ? "GET" : "POST" })) as never,
    );
    renderTab({ initialView: "exchanges" });
    const methods = await screen.findByRole("group", { name: "Method" });
    expect(within(methods).getByRole("button", { name: "GET 2+" })).toBeTruthy();
    expect(within(methods).getByRole("button", { name: "POST 1+" })).toBeTruthy();
  });

  it("reads only the exchanges newer than those it holds on a live refresh", async () => {
    const older = { ...flow, id: 40, flow_uid: "flow-0" };
    const newer = { ...flow, id: 42, flow_uid: "flow-2" };
    vi.mocked(listHttpFlows).mockResolvedValueOnce([flow, older] as never);
    const { update } = renderTab({ initialView: "exchanges" });
    expect(await screen.findByRole("button", { name: "flow-1" })).toBeTruthy();
    const ledger = [newer, flow, older];
    vi.mocked(listHttpFlows).mockImplementation(async (_key, params = {}) => ledger.slice(params.offset ?? 0, (params.offset ?? 0) + (params.limit ?? 3)) as never);
    update({ refreshVersion: 1 });
    expect(await screen.findByRole("button", { name: "flow-2" })).toBeTruthy();
    // One short read of the newest exchanges, not the page.
    expect(listHttpFlows).toHaveBeenLastCalledWith("demo", { limit: 2, offset: 0 });
    expect(screen.getAllByRole("button", { name: /^flow-/ }).map((button) => button.textContent)).toEqual(["flow-2", "flow-1", "flow-0"]);
  });

  it("re-reads at most once per live-update window, with a trailing read", async () => {
    const { update } = renderTab({ initialView: "exchanges" });
    expect(await screen.findByText(/No full HTTP exchanges captured yet/)).toBeTruthy();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const reads = () => vi.mocked(listHttpFlows).mock.calls.length;
      const before = reads();
      await act(async () => { update({ refreshVersion: 1 }); });
      expect(reads()).toBe(before + 1);
      await act(async () => { update({ refreshVersion: 2 }); });
      await act(async () => { update({ refreshVersion: 3 }); });
      expect(reads()).toBe(before + 1);
      await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
      expect(reads()).toBe(before + 2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not render a false empty state when the initial flow request fails", async () => {
    vi.mocked(listHttpFlows).mockRejectedValue(new Error("flow ledger unavailable"));
    renderTab({ initialView: "exchanges" });
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((alert) => alert.textContent?.includes("flow ledger unavailable"))).toBe(true);
    expect(screen.queryByText(/No full HTTP exchanges captured yet/)).toBeNull();
  });

  it("keeps stale flows visible when a background refresh fails", async () => {
    vi.mocked(listHttpFlows)
      .mockResolvedValueOnce([flow] as never)
      .mockRejectedValueOnce(new Error("flow refresh unavailable"));
    const { update } = renderTab({ initialView: "exchanges" });
    expect(await screen.findByRole("button", { name: "flow-1" })).toBeTruthy();
    update({ refreshVersion: 1 });
    await waitFor(() => expect(
      screen.getAllByRole("alert").some((alert) => alert.textContent?.includes("flow refresh unavailable")),
    ).toBe(true));
    expect(screen.getByRole("button", { name: "flow-1" })).toBeTruthy();
  });

  it("queues a flow refresh that arrives during the initial flow load", async () => {
    const firstFlows = deferred<never[]>();
    vi.mocked(listHttpFlows).mockReturnValueOnce(firstFlows.promise).mockResolvedValueOnce([]);
    const { update } = renderTab({ initialView: "exchanges" });
    await waitFor(() => expect(listHttpFlows).toHaveBeenCalledTimes(1));
    update({ refreshVersion: 1 });
    firstFlows.resolve([]);
    await waitFor(() => expect(listHttpFlows).toHaveBeenCalledTimes(2));
  });

  it("offers Clear filters when no exchange matches", async () => {
    vi.mocked(listHttpFlows).mockImplementation(async (_key, params = {}) => ((params as { method?: string }).method === "GET" ? [] : [flow]) as never);
    renderTab({ initialView: "exchanges" });
    await screen.findByRole("button", { name: "flow-1" });
    vi.mocked(listHttpFlows).mockResolvedValue([] as never);
    await withDebounce(() => {
      fireEvent.change(screen.getByRole("searchbox", { name: "Search captured exchanges" }), { target: { value: "x" } });
    }, 250);
    expect(await screen.findByText("No captured exchanges match these filters.")).toBeTruthy();
    vi.mocked(listHttpFlows).mockResolvedValue([flow] as never);
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByRole("button", { name: "flow-1" })).toBeTruthy();
  });

  it("separates endpoint inventory from non-retroactive captured exchanges", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);
    renderTab();
    expect(await screen.findByRole("button", { name: /^Endpoint inventory/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^Captured exchanges/ }));
    expect(await screen.findByText(/future proxy traffic only/i)).toBeTruthy();
    expect(screen.getByText(/existing endpoint inventory and earlier traffic are not backfilled/i)).toBeTruthy();
  });

  it("keeps full-flow enablement separate from request and response body fidelity", async () => {
    vi.mocked(getCapturePolicy).mockResolvedValue(capturePolicy);
    renderTab({ initialView: "exchanges" });
    const fullFlow = await screen.findByRole("button", { name: "Enable full-flow capture" });
    expect(fullFlow.getAttribute("aria-pressed")).toBe("false");
    const options = screen.getByRole("button", { name: "Options" });
    expect(options.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(options);
    expect(options.getAttribute("aria-expanded")).toBe("true");
    expect((screen.getByRole("checkbox", { name: "Capture request bodies" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("checkbox", { name: "Capture response bodies" }) as HTMLInputElement).checked).toBe(false);
    expect(screen.getByText("Full-flow capture off")).toBeTruthy();
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
    renderTab({ initialView: "exchanges" });
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
    renderTab({ initialView: "exchanges" });
    fireEvent.click(await screen.findByRole("button", { name: "flow-1" }));
    const record = await screen.findByRole("region", { name: "Exchange record" });
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&flow=41");
    expect((await within(record).findByRole("link", { name: "Request variant #1" })).getAttribute("href"))
      .toBe("#/engagements/demo?tab=http&request=1");
    const har = within(record).getByRole("link", { name: "Export this exchange as HAR" });
    expect(har.getAttribute("href")).toContain("flow_uid=flow-1");
    expect(exportHarUrl).toHaveBeenCalledWith("demo", { flow_uid: "flow-1" });
    fireEvent.click(within(record).getByRole("button", { name: /^Bodies/ }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&flow=41&dtab=bodies");
    expect(within(record).getByText("traffic/mitmproxy/bodies/request.bin")).toBeTruthy();
    expect(within(record).getByText("traffic/mitmproxy/bodies/response.bin")).toBeTruthy();
  });

  it("opens a deep-linked exchange on its section and returns to the exchanges", async () => {
    const older = { ...flow, id: 40, flow_uid: "flow-0", path: "/older", created_at: "2026-09-11T00:00:00Z" };
    vi.mocked(listHttpFlows).mockResolvedValue([flow, older]);
    vi.mocked(getHttpFlow).mockImplementation(async (_key, uid) => (uid === "flow-0" ? older : flow));
    const { update } = renderTab({ initialFlowId: 41, initialDrawerTab: "headers" });
    const record = await screen.findByRole("region", { name: "Exchange record" });
    expect(within(record).getByRole("button", { name: /^Headers/ }).getAttribute("aria-current")).toBe("page");
    expect(within(record).getByText(/operator-token/)).toBeTruthy();
    expect(within(record).getByText("1 of 2 results")).toBeTruthy();
    fireEvent.click(within(record).getByRole("button", { name: "Next exchange" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&flow=40&dtab=headers");
    update({ initialFlowId: 40 });
    expect(within(record).getByText("2 of 2 results")).toBeTruthy();
    expect(within(record).getByRole("heading", { level: 2 }).textContent).toContain("/older");
    fireEvent.click(within(record).getByRole("button", { name: "Back to results" }));
    expect(window.location.hash).toBe("#/engagements/demo?tab=http&view=exchanges");
    update({ initialFlowId: undefined, initialDrawerTab: undefined, initialView: "exchanges" });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Exchange record" })).toBeNull());
    // The exchanges stay the open view.
    expect(screen.getByRole("button", { name: "flow-1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /^Captured exchanges/ }).getAttribute("aria-pressed")).toBe("true");
  });
});
