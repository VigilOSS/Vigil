// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import { COMMAND_COLUMN_SORT, DEFAULT_COMMAND_FILTERS, type CommandLedgerRow } from "../lib/commandsApi";
import CommandsGrid from "./CommandsGrid";

const grid = vi.hoisted(() => ({
  props: {} as { columnDefs?: ColDef<CommandLedgerRow>[]; rowModelType?: string; cacheBlockSize?: number },
}));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: { columnDefs: ColDef<CommandLedgerRow>[]; rowModelType: string; cacheBlockSize: number }) => {
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
