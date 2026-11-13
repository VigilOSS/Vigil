// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef, SortComparatorFn } from "ag-grid-community";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { HttpFlow } from "../lib/api";
import HttpFlowsGrid from "./HttpFlowsGrid";

// ag-grid stand-in: keeps the column definitions the grid is given.
const grid = vi.hoisted(() => ({ props: {} as { columnDefs?: ColDef<HttpFlow>[] } }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: { columnDefs: ColDef<HttpFlow>[] }) => {
    grid.props = props;
    return <div>grid</div>;
  },
}));

afterEach(cleanup);

const flow = (id: number, created_at: string) => ({ id, created_at }) as HttpFlow;

function columns(initialSort?: { colId: string; sort: "asc" | "desc" } | null): ColDef<HttpFlow>[] {
  render(<HttpFlowsGrid rows={[]} selectedUid={null} initialSort={initialSort} onRowOpen={() => {}} />);
  return grid.props.columnDefs ?? [];
}

function column(colId: string): ColDef<HttpFlow> {
  const found = columns().find((definition) => definition.colId === colId);
  if (!found) throw new Error(`no ${colId} column`);
  return found;
}

const startSorts = (definitions: ColDef<HttpFlow>[]) =>
  definitions.filter((definition) => definition.initialSort).map((definition) => [definition.colId, definition.initialSort]);

// Sorts the way ag-grid does: the comparator gets each row's value and node,
// and a descending sort negates its result.
function sortedBy(definition: ColDef<HttpFlow>, rows: HttpFlow[], direction: "asc" | "desc") {
  const node = (data: HttpFlow) => ({ data }) as never;
  const value = (data: HttpFlow) => (typeof definition.valueGetter === "function" ? definition.valueGetter(node(data)) : undefined);
  const descending = direction === "desc";
  return [...rows]
    .sort((a, b) => {
      const result = (definition.comparator as SortComparatorFn<HttpFlow>)(value(a), value(b), node(a), node(b), descending);
      return descending ? -result : result;
    })
    .map((row) => row.id);
}

describe("HttpFlowsGrid Seen column", () => {
  it("lists exchanges without a capture time last in both directions", () => {
    const seen = column("seen");
    const rows = [flow(1, ""), flow(2, "2026-09-12 00:00:01"), flow(3, "2026-09-12T05:00:00Z")];
    expect(seen.initialSort).toBe("desc");
    expect(sortedBy(seen, rows, "desc")).toEqual([3, 2, 1]);
    expect(sortedBy(seen, rows, "asc")).toEqual([2, 3, 1]);
  });
});

describe("HttpFlowsGrid sort", () => {
  it("starts in the sort the tab hands it, on exactly one column", () => {
    expect(startSorts(columns({ colId: "status", sort: "desc" }))).toEqual([["status", "desc"]]);
    cleanup();
    expect(startSorts(columns())).toEqual([["seen", "desc"]]);
    cleanup();
    // A sort the grid cannot show (a column it does not sort) falls back to the default.
    expect(startSorts(columns({ colId: "flags", sort: "asc" }))).toEqual([["seen", "desc"]]);
  });

  it("always shows some order: a header click flips the direction and never clears the sort", () => {
    for (const definition of columns().filter((entry) => entry.sortable !== false)) {
      expect([...(definition.sortingOrder ?? [null])].sort(), definition.colId).toEqual(["asc", "desc"]);
    }
  });
});
