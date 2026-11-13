// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef, SortComparatorFn } from "ag-grid-community";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AssessmentSurface } from "../lib/api";
import SurfacesGrid from "./SurfacesGrid";

// ag-grid stand-in: keeps the column definitions the grid is given.
const grid = vi.hoisted(() => ({ props: {} as { columnDefs?: ColDef<AssessmentSurface>[] } }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: { columnDefs: ColDef<AssessmentSurface>[] }) => {
    grid.props = props;
    return <div>grid</div>;
  },
}));

afterEach(cleanup);

const surface = (id: number, updated_at: string, status = "discovered") => ({ id, updated_at, status }) as AssessmentSurface;

function columns(initialSort?: { colId: string; sort: "asc" | "desc" } | null): ColDef<AssessmentSurface>[] {
  render(<SurfacesGrid rows={[]} linkCounts={new Map()} selectedId={null} initialSort={initialSort} onRowOpen={() => {}} />);
  return grid.props.columnDefs ?? [];
}

function column(colId: string): ColDef<AssessmentSurface> {
  const found = columns().find((definition) => definition.colId === colId);
  if (!found) throw new Error(`no ${colId} column`);
  return found;
}

const startSorts = (definitions: ColDef<AssessmentSurface>[]) =>
  definitions.filter((definition) => definition.initialSort).map((definition) => [definition.colId, definition.initialSort]);

// Sorts the way ag-grid does: the comparator gets each row's value and node,
// and a descending sort negates its result.
function sortedBy(definition: ColDef<AssessmentSurface>, rows: AssessmentSurface[], direction: "asc" | "desc") {
  const node = (data: AssessmentSurface) => ({ data }) as never;
  const value = (data: AssessmentSurface) => (typeof definition.valueGetter === "function" ? definition.valueGetter(node(data)) : undefined);
  const descending = direction === "desc";
  return [...rows]
    .sort((a, b) => {
      const result = (definition.comparator as SortComparatorFn<AssessmentSurface>)(value(a), value(b), node(a), node(b), descending);
      return descending ? -result : result;
    })
    .map((row) => row.id);
}

describe("SurfacesGrid Updated column", () => {
  it("lists surfaces without an update time last in both directions", () => {
    const updated = column("updated");
    const rows = [surface(1, ""), surface(2, "2026-09-21 12:00:00"), surface(3, "2026-09-22T08:00:00Z")];
    expect(updated.initialSort).toBe("desc");
    expect(sortedBy(updated, rows, "desc")).toEqual([3, 2, 1]);
    expect(sortedBy(updated, rows, "asc")).toEqual([2, 3, 1]);
  });
});

describe("SurfacesGrid Status column", () => {
  it("puts the most urgent surfaces first on its first, descending sort", () => {
    const status = column("status");
    const rows = [surface(1, "", "covered"), surface(2, "", "administratively-closed"), surface(3, "", "discovered"), surface(4, "", "partially-covered")];
    expect(status.sortingOrder?.[0]).toBe("desc");
    expect(sortedBy(status, rows, "desc")).toEqual([3, 4, 1, 2]);
    expect(sortedBy(status, rows, "asc")).toEqual([2, 1, 4, 3]);
  });
});

describe("SurfacesGrid sort", () => {
  it("starts in the sort the tab hands it, on exactly one column", () => {
    expect(startSorts(columns({ colId: "target", sort: "asc" }))).toEqual([["target", "asc"]]);
    cleanup();
    expect(startSorts(columns())).toEqual([["updated", "desc"]]);
    cleanup();
    // A sort the grid cannot show (a column it does not sort) falls back to the default.
    expect(startSorts(columns({ colId: "findings", sort: "asc" }))).toEqual([["updated", "desc"]]);
  });

  it("always shows some order: a header click flips the direction and never clears the sort", () => {
    for (const definition of columns().filter((entry) => entry.sortable !== false)) {
      expect([...(definition.sortingOrder ?? [null])].sort(), definition.colId).toEqual(["asc", "desc"]);
    }
  });
});
