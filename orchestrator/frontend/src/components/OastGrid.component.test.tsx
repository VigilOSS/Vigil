// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef, SortComparatorFn } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import type { OobProbe } from "../lib/api";
import OastGrid from "./OastGrid";

// ag-grid stand-in: keeps the props and hands the grid-ready callback an API
// that records the column state the grid applies.
const grid = vi.hoisted(() => ({
  props: {} as { columnDefs?: ColDef<OobProbe>[] },
  applied: [] as unknown[],
}));

vi.mock("ag-grid-react", async () => {
  const { useEffect } = await import("react");
  return {
    AgGridReact: (props: { columnDefs: ColDef<OobProbe>[]; onGridReady?: (event: unknown) => void }) => {
      grid.props = props;
      useEffect(() => {
        props.onGridReady?.({
          api: {
            applyColumnState: (state: unknown) => grid.applied.push(state),
            getRowNode: () => null,
            ensureNodeVisible: () => {},
          },
        });
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, []);
      return <div>grid</div>;
    },
  };
});

afterEach(() => {
  cleanup();
  grid.applied = [];
});

function probe(nonce: string, extra: Partial<OobProbe> = {}): OobProbe {
  return {
    id: 1,
    engagement_id: 1,
    nonce,
    oob_domain: "oast.example",
    target_url: "https://app.example.com/hook",
    technique: "ssrf",
    param: "url",
    probe_kind: "http",
    request_hash: "",
    client_name: "",
    client_payload_host: "",
    status: "pending",
    notes: "",
    created_at: "2026-09-12T00:00:00Z",
    updated_at: "2026-09-12T00:00:00Z",
    interaction_count: 0,
    last_interaction_at: "",
    ...extra,
  } as OobProbe;
}

function renderGrid(initialSort?: { colId: string; sort: "asc" | "desc" }[] | null) {
  render(<OastGrid rows={[]} sortColumn="lasthit" initialSort={initialSort} selectedNonce={null} onRowOpen={() => {}} />);
  return grid.props.columnDefs ?? [];
}

// Sorts the way ag-grid does: the comparator gets each row's value and node,
// and a descending sort negates its result.
function sortedBy(column: ColDef<OobProbe>, rows: OobProbe[], direction: "asc" | "desc") {
  const node = (data: OobProbe) => ({ data }) as never;
  const value = (data: OobProbe) => (typeof column.valueGetter === "function" ? column.valueGetter(node(data)) : undefined);
  const compare = column.comparator as SortComparatorFn<OobProbe>;
  const descending = direction === "desc";
  return [...rows]
    .sort((a, b) => {
      const result = compare(value(a), value(b), node(a), node(b), descending);
      return descending ? -result : result;
    })
    .map((row) => row.nonce);
}

it("starts in the scope's default order, or in the order the operator last chose", () => {
  renderGrid();
  expect(grid.applied.at(-1)).toEqual({ state: [{ colId: "lasthit", sort: "desc" }], defaultState: { sort: null } });
  cleanup();
  renderGrid([{ colId: "linked", sort: "asc" }]);
  expect(grid.applied.at(-1)).toEqual({ state: [{ colId: "linked", sort: "asc" }], defaultState: { sort: null } });
});

it("keeps probes with no callback or plant time last in both directions", () => {
  const columns = renderGrid();
  const rows = [
    probe("never", { last_interaction_at: "" }),
    probe("older", { last_interaction_at: "2026-09-12T04:00:00Z" }),
    probe("newer", { last_interaction_at: "2026-09-12T06:00:00Z" }),
  ];
  const lastHit = columns.find((column) => column.colId === "lasthit")!;
  expect(sortedBy(lastHit, rows, "desc")).toEqual(["newer", "older", "never"]);
  expect(sortedBy(lastHit, rows, "asc")).toEqual(["older", "newer", "never"]);

  const planted = columns.find((column) => column.colId === "created")!;
  const plantedRows = [probe("unknown", { created_at: "" }), probe("first", { created_at: "2026-09-10T00:00:00Z" }), probe("second", { created_at: "2026-09-11T00:00:00Z" })];
  expect(sortedBy(planted, plantedRows, "desc")).toEqual(["second", "first", "unknown"]);
  expect(sortedBy(planted, plantedRows, "asc")).toEqual(["first", "second", "unknown"]);
});

it("sorts Status most urgent first on its first click: callbacks to review lead", () => {
  const columns = renderGrid();
  const status = columns.find((column) => column.colId === "status")!;
  expect(status.sortingOrder?.[0]).toBe("desc");
  const rows = [probe("ignored", { status: "ignored" }), probe("pending", { status: "pending" }), probe("fired", { status: "fired" }), probe("confirmed", { status: "confirmed" })];
  const valued = (row: OobProbe) => row.status;
  const compare = status.comparator as SortComparatorFn<OobProbe>;
  const order = (direction: "asc" | "desc") => [...rows]
    .sort((a, b) => {
      const result = compare(valued(a), valued(b), { data: a } as never, { data: b } as never, direction === "desc");
      return direction === "desc" ? -result : result;
    })
    .map((row) => row.nonce);
  expect(order("desc")).toEqual(["fired", "pending", "confirmed", "ignored"]);
  expect(order("asc")).toEqual(["ignored", "confirmed", "pending", "fired"]);
});
