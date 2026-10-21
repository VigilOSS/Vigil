// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef, RowClickedEvent } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import { deriveRunRow, type RunRow } from "../lib/runAudit";
import type { AssessmentRun } from "../lib/api";
import RunsGrid from "./RunsGrid";

const grid = vi.hoisted(() => ({
  columnDefs: [] as ColDef<RunRow>[],
  onRowClicked: undefined as undefined | ((event: RowClickedEvent<RunRow>) => void),
}));

vi.mock("ag-grid-react", () => ({
  AgGridReact: ({ columnDefs, onRowClicked }: { columnDefs: ColDef<RunRow>[]; onRowClicked: (event: RowClickedEvent<RunRow>) => void }) => {
    grid.columnDefs = columnDefs;
    grid.onRowClicked = onRowClicked;
    return <div>grid</div>;
  },
}));

afterEach(() => {
  cleanup();
});

const run: AssessmentRun = {
  id: 9,
  run_uuid: "acme-export-replay",
  run_kind: "web",
  run_purpose: "proof",
  status: "completed",
  created_at: "2026-10-10 22:26:22",
};

it("sorts newest first by start time by default, with the sort shown on the column", () => {
  render(<RunsGrid engagementKey="acme" rows={[deriveRunRow(run)]} selectedId={null} onRowOpen={() => {}} />);
  const sorted = grid.columnDefs.filter((column) => column.initialSort);
  expect(sorted.map((column) => [column.colId, column.initialSort])).toEqual([["started", "desc"]]);
  expect(grid.columnDefs.map((column) => column.headerName)).toEqual([
    "Started", "Status", "Run · agent", "Findings", "Task", "Evidence", "Duration", "Client · model",
  ]);
  // Every column sorts; none opts out.
  expect(grid.columnDefs.every((column) => column.sortable !== false)).toBe(true);
  const started = grid.columnDefs[0].comparator as unknown as (
    a: string | null, b: string | null, nodeA: unknown, nodeB: unknown, descending: boolean,
  ) => number;
  // Missing start times sort last whichever direction is chosen (ag-grid
  // negates the result of a descending sort).
  expect(started(null, "2026-10-20 10:00:00", {}, {}, false)).toBeGreaterThan(0);
  expect(started(null, "2026-10-20 10:00:00", {}, {}, true)).toBeLessThan(0);
});

it("opens with the operator's last sort instead of the default", () => {
  render(<RunsGrid engagementKey="acme" rows={[deriveRunRow(run)]} selectedId={null} onRowOpen={() => {}} initialSort={{ colId: "duration", sort: "asc" }} />);
  expect(grid.columnDefs.filter((column) => column.initialSort).map((column) => [column.colId, column.initialSort])).toEqual([["duration", "asc"]]);
});

it("opens a run from its row but not from a link inside the row", () => {
  const open = vi.fn();
  const row = deriveRunRow(run);
  render(<RunsGrid engagementKey="acme" rows={[row]} selectedId={null} onRowOpen={open} />);
  const link = document.createElement("a");
  grid.onRowClicked?.({ data: row, event: { target: link } } as unknown as RowClickedEvent<RunRow>);
  expect(open).not.toHaveBeenCalled();
  const cell = document.createElement("div");
  grid.onRowClicked?.({ data: row, event: { target: cell } } as unknown as RowClickedEvent<RunRow>);
  expect(open).toHaveBeenCalledWith(9, null);
});
