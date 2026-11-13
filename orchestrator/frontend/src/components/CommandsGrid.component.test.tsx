// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import type { ColDef, ICellRendererParams } from "ag-grid-community";
import type { ComponentType } from "react";
import { afterEach, expect, it, vi } from "vitest";

import { COMMAND_COLUMN_SORT, DEFAULT_COMMAND_FILTERS, type CommandLedgerRow } from "../lib/commandsApi";
import CommandsGrid from "./CommandsGrid";

type GridApiStub = {
  ensureIndexVisible: (index: number, position?: string) => void;
  getColumnState: () => { colId: string; sort?: "asc" | "desc" | null }[];
  getVerticalPixelRange: () => { top: number; bottom: number };
  redrawRows: () => void;
  refreshInfiniteCache: () => void;
};
type GridProps = {
  columnDefs?: ColDef<CommandLedgerRow>[];
  rowModelType?: string;
  cacheBlockSize?: number;
  onGridReady?: (event: { api: GridApiStub }) => void;
  onSortChanged?: (event: { api: GridApiStub }) => void;
};

const grid = vi.hoisted(() => ({ props: {} as GridProps }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: GridProps) => {
    grid.props = props;
    return <div>grid</div>;
  },
}));

afterEach(() => {
  cleanup();
});

function renderGrid() {
  render(
    <CommandsGrid
      engagementKey="acme-web"
      filters={DEFAULT_COMMAND_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      selectedId={null}
      onRowOpen={() => {}}
      onWindow={() => {}}
      onError={() => {}}
      onSortChange={() => {}}
      onTargetClick={() => {}}
    />,
  );
  return grid.props.columnDefs ?? [];
}

it("pages the ledger on the server and shows its default order, newest first, on the Time column", () => {
  const columns = renderGrid();
  expect(grid.props.rowModelType).toBe("infinite");
  expect(columns.filter((column) => column.sort).map((column) => [column.colId, column.sort])).toEqual([["time", "desc"]]);
  expect(columns.map((column) => column.headerName)).toEqual([
    "Time", "Status", "Tool", "Agent", "Phase", "Target", "Command", "Duration", "Exit",
  ]);
});

it("sorts every sortable column on the server, including Tool", () => {
  const columns = renderGrid();
  const sortable = columns.filter((column) => column.sortable !== false).map((column) => column.colId);
  expect(sortable).toContain("tool");
  // A sortable column the server cannot order would sort only the loaded block.
  for (const colId of sortable) expect(COMMAND_COLUMN_SORT[colId as string]).toBeTruthy();
  expect(columns.filter((column) => column.sortable === false).map((column) => column.colId)).toEqual(["target", "command"]);
});

it("keeps rows one line tall: long commands are cut, never wrapped", () => {
  const columns = renderGrid();
  expect(columns.some((column) => column.autoHeight || column.wrapText)).toBe(false);
});

it("starts in the sort the tab hands it, so a rebuilt grid keeps the operator's order", () => {
  render(
    <CommandsGrid
      engagementKey="acme-web"
      filters={DEFAULT_COMMAND_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      initialSort={{ sort: "tool", dir: "asc" }}
      selectedId={null}
      onRowOpen={() => {}}
      onWindow={() => {}}
      onError={() => {}}
      onSortChange={() => {}}
      onTargetClick={() => {}}
    />,
  );
  const columns = grid.props.columnDefs ?? [];
  expect(columns.filter((column) => column.sort).map((column) => [column.colId, column.sort])).toEqual([["tool", "asc"]]);
});

it("puts the most urgent runs first on the first Status header click", () => {
  const status = renderGrid().find((column) => column.colId === "status");
  expect(status?.sortingOrder?.[0]).toBe("desc");
});

it("returns to the first row when the filters or the sort change", () => {
  const props = {
    engagementKey: "acme-web",
    refreshToken: 0,
    selectedId: null,
    onRowOpen: () => {},
    onWindow: () => {},
    onError: () => {},
    onSortChange: () => {},
    onTargetClick: () => {},
  };
  const view = render(<CommandsGrid {...props} filters={DEFAULT_COMMAND_FILTERS} filtersKey="[]" />);
  const api = {
    ensureIndexVisible: vi.fn(),
    getColumnState: () => [{ colId: "duration", sort: "desc" as const }],
    getVerticalPixelRange: () => ({ top: 0, bottom: 0 }),
    redrawRows: vi.fn(),
    refreshInfiniteCache: vi.fn(),
  };
  act(() => grid.props.onGridReady?.({ api }));
  // The grid opens at the top by itself.
  expect(api.ensureIndexVisible).not.toHaveBeenCalled();
  view.rerender(<CommandsGrid {...props} filters={{ ...DEFAULT_COMMAND_FILTERS, status: ["failed"] }} filtersKey='["failed"]' />);
  expect(api.ensureIndexVisible).toHaveBeenLastCalledWith(0, "top");
  api.ensureIndexVisible.mockClear();
  act(() => grid.props.onSortChanged?.({ api }));
  expect(api.ensureIndexVisible).toHaveBeenLastCalledWith(0, "top");
});

it("keeps the time of day on runs too old for a relative age", () => {
  const time = renderGrid().find((column) => column.colId === "time");
  const Cell = time?.cellRenderer as ComponentType<Partial<ICellRendererParams<CommandLedgerRow>>>;
  const old = { id: 1, created_at: "2026-01-05 14:07:09", started_at: null } as CommandLedgerRow;
  const recent = { id: 2, created_at: new Date(Date.now() - 2 * 3_600_000).toISOString(), started_at: null } as CommandLedgerRow;
  const cells = render(<><span data-testid="old"><Cell data={old} /></span><span data-testid="recent"><Cell data={recent} /></span></>);
  expect(cells.getByTestId("old").textContent).toBe("2026-01-05 14:07 UTC");
  expect(cells.getByTestId("recent").textContent).toBe("2h ago");
});
