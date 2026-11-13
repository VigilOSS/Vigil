// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import type { ColDef, IDatasource } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import { EMPTY_COVERAGE_FILTERS, fetchCoveragePage, type CoverageLedgerItem, type CoverageLedgerPage } from "../../lib/coverageApi";
import CoverageGrid from "./CoverageGrid";

vi.mock("../../lib/coverageApi", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/coverageApi")>()),
  fetchCoveragePage: vi.fn(),
}));

// ag-grid stand-in: keeps the props the grid is given.
type GridProps = {
  columnDefs: ColDef<CoverageLedgerItem>[];
  datasource: IDatasource;
  onGridReady: (event: { api: unknown }) => void;
  onBodyScroll: () => void;
};
const grid = vi.hoisted(() => ({ columnDefs: [] as ColDef<CoverageLedgerItem>[], props: null as GridProps | null }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: GridProps) => {
    grid.columnDefs = props.columnDefs;
    grid.props = props;
    return <div>grid</div>;
  },
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// What the component uses of the grid API, as ag-grid behaves after `destroy()`.
function gridApi() {
  const api = {
    destroyed: false,
    isDestroyed: () => api.destroyed,
    getVerticalPixelRange: vi.fn(() => ({ top: 0, bottom: 320 })),
  };
  return api;
}

function mountWithPageInFlight() {
  let answer!: (page: CoverageLedgerPage) => void;
  vi.mocked(fetchCoveragePage).mockReturnValue(new Promise<CoverageLedgerPage>((resolve) => { answer = resolve; }));
  const onWindow = vi.fn();
  const view = render(
    <CoverageGrid
      engagementKey="acme-web"
      filters={EMPTY_COVERAGE_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      selectedId={null}
      sort={{ sort: "updated_at", dir: "desc" }}
      onRowOpen={() => {}}
      onWindow={onWindow}
      onError={() => {}}
    />,
  );
  const api = gridApi();
  act(() => grid.props!.onGridReady({ api }));
  grid.props!.datasource.getRows({ startRow: 0, endRow: 100, sortModel: [], successCallback: () => {}, failCallback: () => {} } as never);
  const page: CoverageLedgerPage = { total: 240, offset: 0, count: 0, has_more: true, items: [] };
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
  // The operator switches views: ag-grid destroys the grid, then React unmounts it.
  api.destroyed = true;
  grid.props!.onBodyScroll();
  expect(api.getVerticalPixelRange).not.toHaveBeenCalled();
  view.unmount();
  const reports = onWindow.mock.calls.length;
  await answer();
  expect(api.getVerticalPixelRange).not.toHaveBeenCalled();
  expect(onWindow.mock.calls.length).toBe(reports);
});

it("puts the most urgent items first on the first Status header click", () => {
  render(
    <CoverageGrid
      engagementKey="acme-web"
      filters={EMPTY_COVERAGE_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      selectedId={null}
      sort={{ sort: "updated_at", dir: "desc" }}
      onRowOpen={() => {}}
      onWindow={() => {}}
      onError={() => {}}
    />,
  );
  const status = grid.columnDefs.find((column) => column.colId === "status");
  expect(status?.sortingOrder?.[0]).toBe("desc");
});
