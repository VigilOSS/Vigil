// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import type { ColDef } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";

import { EMPTY_COVERAGE_FILTERS, type CoverageLedgerItem } from "../../lib/coverageApi";
import CoverageGrid from "./CoverageGrid";

const grid = vi.hoisted(() => ({ columnDefs: [] as ColDef<CoverageLedgerItem>[] }));

vi.mock("ag-grid-react", () => ({
  AgGridReact: (props: { columnDefs: ColDef<CoverageLedgerItem>[] }) => {
    grid.columnDefs = props.columnDefs;
    return <div>grid</div>;
  },
}));

afterEach(cleanup);

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
