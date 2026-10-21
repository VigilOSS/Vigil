// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { forwardRef, useImperativeHandle, type ReactElement } from "react";
import type { ColDef } from "ag-grid-community";
import { afterEach, expect, it, vi } from "vitest";
import FindingsGrid from "./FindingsGrid";
import type { Derived } from "./FindingsTab";

const grid = vi.hoisted(() => ({
  columnDefs: [] as ColDef[],
  columnState: [] as Array<{ colId: string; sort?: "asc" | "desc" | null }>,
  applyColumnState: vi.fn(),
  onSortChanged: undefined as undefined | ((event: unknown) => void),
}));

vi.mock("ag-grid-react", () => ({ AgGridReact: forwardRef(function MockGrid({ onModelUpdated, onSortChanged, animateRows, columnDefs }: { onModelUpdated: (event: unknown) => void; onSortChanged?: (event: unknown) => void; animateRows?: boolean; columnDefs: ColDef[] }, ref) {
  const api = { applyColumnState: grid.applyColumnState, getColumnState: () => grid.columnState };
  useImperativeHandle(ref, () => ({ api }));
  grid.columnDefs = columnDefs;
  grid.onSortChanged = (event) => onSortChanged?.({ api, ...(event as object) });
  return (
    <button data-row-animation={String(animateRows)} onClick={() => onModelUpdated({ api: { forEachNodeAfterFilterAndSort: (visit: (node: unknown) => void) => {
      visit({ data: { slug: "VA-003" } });
      visit({ data: undefined });
      visit({ data: { slug: "VA-001" } });
    } } })}>Update displayed model</button>
  );
}) }));

afterEach(() => {
  cleanup();
  grid.applyColumnState.mockReset();
  grid.columnState = [];
});

it("reports the grid's filtered and sorted record identities rather than source row order", () => {
  const report = vi.fn();
  render(<FindingsGrid rows={[] as Derived[]} selected={null} onOpen={() => {}} onOrderChange={report} />);
  fireEvent.click(screen.getByRole("button", { name: "Update displayed model" }));
  expect(report).toHaveBeenCalledExactlyOnceWith(["VA-003", "VA-001"]);
});

it("updates filtered rows without a second animated row-position transition", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  expect(screen.getByRole("button", { name: "Update displayed model" }).getAttribute("data-row-animation")).toBe("false");
});

it("places created and changed dates early and opens sorted by creation date, newest first", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  const ids = grid.columnDefs.map((column) => column.colId);
  expect(ids.indexOf("created")).toBeLessThan(ids.indexOf("workflow"));
  expect(ids.indexOf("changed")).toBeLessThan(ids.indexOf("workflow"));
  expect(grid.columnDefs.filter((column) => column.initialSort)).toEqual([expect.objectContaining({ colId: "created", initialSort: "desc" })]);
});

it("keeps long locations on one line under the title, whole in the text", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  const Title = grid.columnDefs.find((column) => column.colId === "title")!.cellRenderer as (props: { data: Derived }) => ReactElement;
  const location = "https://app.example/a/very/long/recorded/location?token=verbatim-recorded-token";
  const view = render(<Title data={{ title: "Acme claim", canonical_location: location } as unknown as Derived} />);
  const line = view.container.querySelector(".findings-grid-location")!;
  expect(line.classList.contains("findings-grid-ellipsis")).toBe(true);
  expect(line.textContent).toBe(location);
  expect(line.getAttribute("title")).toBe(location);
});

it("orders severity by rank, not alphabetically", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  const comparator = grid.columnDefs.find((column) => column.colId === "severity")!.comparator as (a: string, b: string) => number;
  expect(["info", "critical", "low", "high", "medium"].sort(comparator)).toEqual(["critical", "high", "medium", "low", "info"]);
});

it("applies a chosen page sort to the grid columns", () => {
  const view = render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} sort="newest" />);
  grid.applyColumnState.mockReset();
  view.rerender(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} sort="changed" />);
  expect(grid.applyColumnState).toHaveBeenLastCalledWith({ state: [{ colId: "changed", sort: "desc" }], defaultState: { sort: null } });
  view.rerender(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} sort="changed" sortRequest={1} />);
  expect(grid.applyColumnState).toHaveBeenCalledTimes(2);
});

it("reports header-click sorts as the matching named sort or none", () => {
  const report = vi.fn();
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} onSortChange={report} />);
  grid.columnState = [{ colId: "severity", sort: "asc" }, { colId: "title", sort: null }];
  grid.onSortChanged?.({ source: "uiColumnSorted" });
  expect(report).toHaveBeenLastCalledWith("severity", expect.objectContaining({ label: "Severity" }));
  grid.columnState = [{ colId: "title", sort: "asc" }];
  grid.onSortChanged?.({ source: "uiColumnSorted" });
  expect(report).toHaveBeenLastCalledWith(null, expect.objectContaining({ label: "Title" }));
  grid.onSortChanged?.({ source: "api" });
  expect(report).toHaveBeenCalledTimes(2);
});

it("names the column and direction of any header-click sort", () => {
  const report = vi.fn();
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} onSortChange={report} />);
  grid.columnState = [{ colId: "title", sort: "asc" }];
  grid.onSortChanged?.({ source: "uiColumnSorted" });
  expect(report).toHaveBeenLastCalledWith(null, { label: "Title", direction: "asc", kind: "text" });
  // The severity comparator puts the most severe first on an ascending sort.
  grid.columnState = [{ colId: "severity", sort: "asc" }];
  grid.onSortChanged?.({ source: "uiColumnSorted" });
  expect(report).toHaveBeenLastCalledWith("severity", { label: "Severity", direction: "desc", kind: "rank" });
  // Status columns read like every status sort: vocabulary order is most urgent first.
  grid.columnState = [{ colId: "verification", sort: "asc" }];
  grid.onSortChanged?.({ source: "uiColumnSorted" });
  expect(report).toHaveBeenLastCalledWith(null, { label: "Verification", direction: "desc", kind: "status" });
});

it("renders severity and statuses in the shared sentence-case styles", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  const row = { slug: "VA-001", severity: "high", workflow_status: "draft", verification_status: "pending_runtime_proof", verificationKey: "pending_runtime_proof", submission_status: "needs_info" } as unknown as Derived;
  const cell = (colId: string) => {
    const Renderer = grid.columnDefs.find((column) => column.colId === colId)!.cellRenderer as (props: { data: Derived }) => ReactElement;
    const view = render(<Renderer data={row} />);
    const text = view.container.textContent;
    const pill = view.container.querySelector(".ui-status, .sev-tag");
    view.unmount();
    return { text, pill };
  };
  expect(cell("severity").text).toBe("High");
  expect(cell("severity").pill).not.toBeNull();
  expect(cell("workflow")).toEqual({ text: "Draft", pill: expect.anything() });
  expect(cell("verification")).toEqual({ text: "Pending runtime proof", pill: expect.anything() });
  expect(cell("submission")).toEqual({ text: "Needs info", pill: expect.anything() });
});

// ag-grid calls a comparator with `isDescending` and then reverses its result
// for a descending sort.
function agSort(colId: string, values: string[], direction: "asc" | "desc") {
  const comparator = grid.columnDefs.find((column) => column.colId === colId)!.comparator as (a: string, b: string, nodeA: unknown, nodeB: unknown, isDescending: boolean) => number;
  return [...values].sort((a, b) => {
    const result = comparator(a, b, undefined, undefined, direction === "desc");
    return direction === "asc" ? result : -result;
  });
}

it("sorts missing created and changed dates last in both directions", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  const values = ["2026-01-02 00:00:00", "", "2026-03-01 00:00:00"];
  for (const colId of ["created", "changed"]) {
    expect(agSort(colId, values, "desc")).toEqual(["2026-03-01 00:00:00", "2026-01-02 00:00:00", ""]);
    expect(agSort(colId, values, "asc")).toEqual(["2026-01-02 00:00:00", "2026-03-01 00:00:00", ""]);
  }
});

it("sorts workflow, submission and verification most urgent first, not alphabetically", () => {
  render(<FindingsGrid rows={[]} selected={null} onOpen={() => {}} onOrderChange={() => {}} />);
  expect(agSort("workflow", ["reported", "draft", "blocked", "active"], "asc")).toEqual(["blocked", "active", "draft", "reported"]);
  expect(agSort("verification", ["confirmed", "unreviewed", "disputed"], "asc")).toEqual(["disputed", "unreviewed", "confirmed"]);
  expect(agSort("submission", ["accepted", "none", "submitted", "rejected"], "asc")).toEqual(["rejected", "submitted", "accepted", "none"]);
});
