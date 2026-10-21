import { describe, expect, it, vi } from "vitest";

import { EMPTY_COVERAGE_FILTERS, coverageFilterQuery, type CoverageLedgerPage } from "../../lib/coverageApi";
import {
  COVERAGE_COLUMN_SORT,
  DEFAULT_COVERAGE_SORT,
  columnInitialSort,
  coverageFiltersKey,
  createCoverageDatasource,
  parseCoverageView,
  serverSortFromModel,
} from "./coverageGridModel";

function page(total: number, ids: number[]): CoverageLedgerPage {
  return {
    total,
    offset: 0,
    count: ids.length,
    has_more: false,
    items: ids.map((id) => ({ id }) as CoverageLedgerPage["items"][number]),
  };
}

describe("coverage grid model", () => {
  it("maps grid sorting onto the server allowlist and defaults to newest first", () => {
    expect(serverSortFromModel([])).toEqual({ sort: "updated_at", dir: "desc" });
    expect(serverSortFromModel([{ colId: "host", sort: "asc" }])).toEqual({ sort: "host", dir: "asc" });
    expect(serverSortFromModel([{ colId: "family", sort: "desc" }])).toEqual({ sort: "attack_family", dir: "desc" });
    // The reason column is not server-sortable, so it falls back to the default.
    expect(serverSortFromModel([{ colId: "reason", sort: "asc" }])).toEqual({ sort: "updated_at", dir: "desc" });
    expect(Object.keys(COVERAGE_COLUMN_SORT)).not.toContain("reason");
  });

  it("starts a remounted grid on the order the tab holds, on exactly one column", () => {
    const order = { sort: "host", dir: "asc" } as const;
    const sorted = Object.keys(COVERAGE_COLUMN_SORT).filter((colId) => columnInitialSort(colId, order) !== undefined);
    expect(sorted).toEqual(["host"]);
    expect(columnInitialSort("host", order)).toBe("asc");
    expect(columnInitialSort("updated", { sort: "updated_at", dir: "desc" })).toBe("desc");
    expect(columnInitialSort("reason", order)).toBeUndefined();
  });

  it("requests each block by offset and reports the server total as the last row", async () => {
    const fetchPage = vi.fn().mockResolvedValue(page(18_883, [7, 8]));
    const onPage = vi.fn();
    const datasource = createCoverageDatasource(fetchPage, { onPage });
    const successCallback = vi.fn();
    datasource.getRows({
      startRow: 200,
      endRow: 300,
      sortModel: [{ colId: "updated", sort: "asc" }],
      successCallback,
      failCallback: vi.fn(),
    });
    await vi.waitFor(() => expect(successCallback).toHaveBeenCalled());
    expect(fetchPage).toHaveBeenCalledWith({ sort: "updated_at", dir: "asc", limit: 100, offset: 200 });
    expect(successCallback).toHaveBeenCalledWith([{ id: 7 }, { id: 8 }], 18_883);
    expect(onPage).toHaveBeenCalledTimes(1);
  });

  it("fails the block and surfaces the error when the page request fails", async () => {
    const onError = vi.fn();
    const failCallback = vi.fn();
    const datasource = createCoverageDatasource(vi.fn().mockRejectedValue(new Error("backend down")), { onError });
    datasource.getRows({ startRow: 0, endRow: 100, sortModel: [], successCallback: vi.fn(), failCallback });
    await vi.waitFor(() => expect(failCallback).toHaveBeenCalled());
    expect(onError).toHaveBeenCalledWith("backend down");
  });

  it("keys filter sets by content, not order", () => {
    const a = { ...EMPTY_COVERAGE_FILTERS, status: ["blocked", "deferred"] };
    const b = { ...EMPTY_COVERAGE_FILTERS, status: ["deferred", "blocked"] };
    expect(coverageFiltersKey(a)).toBe(coverageFiltersKey(b));
    expect(coverageFiltersKey(a)).not.toBe(coverageFiltersKey({ ...a, reason_missing: true }));
  });

  it("serializes repeatable filters and exact reason filters for the routes", () => {
    const query = coverageFilterQuery({
      ...EMPTY_COVERAGE_FILTERS,
      status: ["blocked", "deferred"],
      host: ["api.acme.example"],
      q: "  orders  ",
      reason_missing: true,
      created_from: "",
    });
    expect(query.getAll("status")).toEqual(["blocked", "deferred"]);
    expect(query.getAll("host")).toEqual(["api.acme.example"]);
    expect(query.get("q")).toBe("orders");
    expect(query.get("reason_missing")).toBe("true");
    // An empty creation note is still a filter value, distinct from no filter.
    expect(query.has("created_from")).toBe(true);
    expect(query.has("reason")).toBe(false);
  });
});

describe("parseCoverageView", () => {
  it("reads a kept view and falls back to the defaults for anything malformed", () => {
    const kept = parseCoverageView(JSON.stringify({
      view: "items",
      filters: { status: ["blocked", 7], host: ["shop.acme.example"], q: "orders", reason: "Needs a second tenant." },
      includeClosed: true,
      sort: { sort: "host", dir: "asc" },
    }));
    expect(kept).toEqual({
      view: "items",
      filters: { ...EMPTY_COVERAGE_FILTERS, status: ["blocked"], host: ["shop.acme.example"], q: "orders", reason: "Needs a second tenant." },
      includeClosed: true,
      sort: { sort: "host", dir: "asc" },
    });
    expect(parseCoverageView("{not json")).toEqual({ view: "reasons", filters: EMPTY_COVERAGE_FILTERS, includeClosed: false, sort: DEFAULT_COVERAGE_SORT });
    expect(parseCoverageView(JSON.stringify({ sort: { sort: "rank", dir: "up" } })).sort).toEqual(DEFAULT_COVERAGE_SORT);
  });
});
