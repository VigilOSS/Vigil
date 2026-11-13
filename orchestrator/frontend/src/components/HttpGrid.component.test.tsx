// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import type { ColDef, IDatasource } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import type { RequestVariant } from "../lib/api";
import {
  EMPTY_REQUEST_VARIANT_FILTERS,
  REQUEST_VARIANT_COLUMN_SORT,
  fetchRequestVariantPage,
  type RequestVariantOrder,
  type RequestVariantPage,
} from "../lib/httpApi";
import HttpGrid from "./HttpGrid";

vi.mock("../lib/httpApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/httpApi")>()),
  fetchRequestVariantPage: vi.fn(),
}));

// ag-grid stand-in: keeps the props the grid is given.
type GridProps = {
  columnDefs: ColDef<RequestVariant>[];
  datasource: IDatasource;
  onGridReady: (event: { api: unknown }) => void;
  onBodyScroll: () => void;
};
const grid = vi.hoisted(() => ({ props: null as GridProps | null }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: GridProps) => {
    grid.props = props;
    return <div>grid</div>;
  },
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderGrid(sort: RequestVariantOrder, onWindow: (window: unknown) => void = () => {}) {
  return render(
    <HttpGrid
      engagementKey="acme-web"
      filters={EMPTY_REQUEST_VARIANT_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      selectedId={null}
      sort={sort}
      onRowOpen={() => {}}
      onWindow={onWindow}
      onError={() => {}}
    />,
  );
}

const startSorts = () => (grid.props?.columnDefs ?? [])
  .filter((column) => column.initialSort)
  .map((column) => [column.colId, column.initialSort]);

it("starts in the order the tab hands it, on exactly one column", () => {
  renderGrid({ sort: "path", dir: "asc" });
  expect(startSorts()).toEqual([["path", "asc"]]);
  cleanup();
  renderGrid({ sort: "last_seen_at", dir: "desc" });
  expect(startSorts()).toEqual([["lastseen", "desc"]]);
});

it("sorts every sortable column on the server, and a header click never clears the sort", () => {
  renderGrid({ sort: "last_seen_at", dir: "desc" });
  for (const column of (grid.props?.columnDefs ?? []).filter((entry) => entry.sortable !== false)) {
    // A sortable column the server cannot order would sort only the loaded block.
    expect(REQUEST_VARIANT_COLUMN_SORT[column.colId as string], column.colId).toBeTruthy();
    expect([...(column.sortingOrder ?? [null])].sort(), column.colId).toEqual(["asc", "desc"]);
  }
});

// What the component uses of the grid API, as ag-grid behaves after `destroy()`.
function gridApi() {
  const api = {
    destroyed: false,
    isDestroyed: () => api.destroyed,
    getVerticalPixelRange: vi.fn(() => ({ top: 0, bottom: 320 })),
    setColumnsVisible: vi.fn(),
    redrawRows: vi.fn(),
    refreshInfiniteCache: vi.fn(),
  };
  return api;
}

function mountWithPageInFlight() {
  let answer!: (page: RequestVariantPage) => void;
  vi.mocked(fetchRequestVariantPage).mockReturnValue(new Promise<RequestVariantPage>((resolve) => { answer = resolve; }));
  const onWindow = vi.fn();
  const view = renderGrid({ sort: "last_seen_at", dir: "desc" }, onWindow);
  const api = gridApi();
  act(() => grid.props!.onGridReady({ api }));
  grid.props!.datasource.getRows({ startRow: 0, endRow: 100, sortModel: [], successCallback: () => {}, failCallback: () => {} } as never);
  const page: RequestVariantPage = { total: 240, offset: 0, count: 0, has_more: true, items: [] };
  return { view, api, onWindow, answer: () => act(async () => { answer(page); }) };
}

it("reports the rows in view once a page answers", async () => {
  const { api, onWindow, answer } = mountWithPageInFlight();
  await answer();
  expect(api.getVerticalPixelRange).toHaveBeenCalled();
  expect(onWindow).toHaveBeenLastCalledWith(expect.objectContaining({ total: 240, first: 1 }));
});

it("leaves a grid alone once it is gone, whenever the page it asked for answers", async () => {
  const { view, api, onWindow, answer } = mountWithPageInFlight();
  // The operator opens the other view: ag-grid destroys the grid, then React unmounts it.
  api.destroyed = true;
  grid.props!.onBodyScroll();
  expect(api.getVerticalPixelRange).not.toHaveBeenCalled();
  view.unmount();
  const reports = onWindow.mock.calls.length;
  await answer();
  expect(api.getVerticalPixelRange).not.toHaveBeenCalled();
  expect(onWindow.mock.calls.length).toBe(reports);
});
