// @vitest-environment jsdom
//
// Row-open behaviour pin for every ag-grid list. The grids' own component
// tests drive the column definitions; the row-open handlers and the shared
// <AgGridReact> prop prelude had no coverage at all, so this file pins both
// before `lib/agGrid.ts` owns them:
//
//   • a plain click opens the row and hands the opener the focused gridcell
//   • a drag selection across the row does NOT open it
//   • Enter and Space open it (preventDefault'd); any other key does not
//   • RunsGrid's in-row link/button guard, and CommandsGrid's button-only
//     guard, which deliberately lets a click on an anchor through
//   • the theme, row/header heights and tooltip delay each grid renders with
//
// The handlers are invoked directly with the shapes ag-grid passes, because
// the grid itself is mocked (as in every other grid test here).

import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import { DEFAULT_COMMAND_FILTERS } from "../lib/commandsApi";
import { EMPTY_COVERAGE_FILTERS } from "../lib/coverageApi";
import { EMPTY_REQUEST_VARIANT_FILTERS } from "../lib/httpApi";
import { GRID_HEADER_HEIGHT, GRID_ROW_HEIGHT, defaultColDef } from "../lib/agGrid";
import CommandsGrid from "./CommandsGrid";
import CoverageGrid from "./coverage/CoverageGrid";
import HttpFlowsGrid from "./HttpFlowsGrid";
import HttpGrid from "./HttpGrid";
import OastGrid from "./OastGrid";
import RunsGrid from "./RunsGrid";
import SurfacesGrid from "./SurfacesGrid";

type GridProps = {
  theme?: unknown;
  rowHeight?: number;
  headerHeight?: number;
  tooltipShowDelay?: number;
  defaultColDef?: unknown;
  onRowClicked?: (event: unknown) => void;
  onCellKeyDown?: (event: unknown) => void;
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
  grid.props = {};
  vi.restoreAllMocks();
});

/** A gridcell with an anchor and a button in it, as a row renders. */
let cell: HTMLElement;
let link: HTMLElement;
let button: HTMLElement;

beforeEach(() => {
  document.body.innerHTML = `<div role="gridcell" tabindex="-1"><a href="#/x">link</a><button type="button">act</button></div>`;
  cell = document.querySelector('[role="gridcell"]')!;
  link = document.querySelector("a")!;
  button = document.querySelector("button")!;
});

/** A text selection dragged across the row. */
function selectRange() {
  vi.spyOn(window, "getSelection").mockReturnValue({
    type: "Range",
    toString: () => "dragged text",
  } as unknown as Selection);
}

function clickRow(data: unknown, target: HTMLElement = cell) {
  grid.props.onRowClicked!({ data, event: { target } });
}

function keyRow(data: unknown, key: string, target: HTMLElement = cell) {
  const preventDefault = vi.fn();
  grid.props.onCellKeyDown!({ data, event: { key, target, preventDefault } });
  return preventDefault;
}

const rows = [
  {
    name: "SurfacesGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(<SurfacesGrid rows={[]} linkCounts={new Map()} selectedId={null} onRowOpen={onRowOpen} />),
    data: { id: 3 },
    opens: (data: { id: number }) => data,
  },
  {
    name: "OastGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(<OastGrid rows={[]} sortColumn="lasthit" selectedNonce={null} onRowOpen={onRowOpen} />),
    data: { nonce: "abc" },
    opens: (data: { nonce: string }) => data,
  },
  {
    name: "HttpFlowsGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(<HttpFlowsGrid rows={[]} selectedUid={null} onRowOpen={onRowOpen} />),
    data: { id: 5, flow_uid: "flow-5" },
    opens: (data: { id: number }) => data,
  },
  {
    name: "HttpGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(
        <HttpGrid
          engagementKey="acme-web"
          filters={EMPTY_REQUEST_VARIANT_FILTERS}
          filtersKey="[]"
          refreshToken={0}
          selectedId={null}
          onRowOpen={onRowOpen}
          onWindow={() => {}}
          onError={() => {}}
        />,
      ),
    data: { id: 9 },
    opens: (data: { id: number }) => data,
  },
  {
    name: "CoverageGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(
        <CoverageGrid
          engagementKey="acme-web"
          filters={EMPTY_COVERAGE_FILTERS}
          filtersKey="[]"
          refreshToken={0}
          selectedId={null}
          sort={{ sort: "updated_at", dir: "desc" }}
          onRowOpen={onRowOpen}
          onWindow={() => {}}
          onError={() => {}}
        />,
      ),
    data: { id: 11 },
    opens: (data: { id: number }) => data,
  },
  {
    name: "CommandsGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(
        <CommandsGrid
          engagementKey="acme-web"
          filters={DEFAULT_COMMAND_FILTERS}
          filtersKey="[]"
          refreshToken={0}
          selectedId={null}
          onRowOpen={onRowOpen}
          onWindow={() => {}}
          onError={() => {}}
          onSortChange={() => {}}
          onTargetClick={() => {}}
        />,
      ),
    data: { id: 13 },
    opens: (data: { id: number }) => data,
  },
  {
    name: "RunsGrid",
    render: (onRowOpen: (...args: unknown[]) => void) =>
      render(<RunsGrid engagementKey="acme-web" rows={[]} selectedId={null} onRowOpen={onRowOpen} />),
    data: { id: 17 },
    // RunsGrid opens by id, not by row.
    opens: (data: { id: number }) => data.id,
  },
] as const;

for (const grid_ of rows) {
  const { name, data } = grid_;
  const open = () => {
    const onRowOpen = vi.fn();
    (grid_.render as (fn: (...args: unknown[]) => void) => unknown)(onRowOpen);
    return onRowOpen;
  };
  const expected = (grid_.opens as (data: unknown) => unknown)(data);

  it(`${name} opens a clicked row and focuses the invoking cell`, () => {
    const onRowOpen = open();
    clickRow(data);
    expect(onRowOpen).toHaveBeenCalledExactlyOnceWith(expected, cell);
    expect(document.activeElement).toBe(cell);
  });

  it(`${name} does not open a row a selection was dragged across`, () => {
    const onRowOpen = open();
    selectRange();
    clickRow(data);
    expect(onRowOpen).not.toHaveBeenCalled();
  });

  it(`${name} opens a row on Enter and on Space, and on nothing else`, () => {
    const onRowOpen = open();
    expect(keyRow(data, "Enter")).toHaveBeenCalledOnce();
    expect(keyRow(data, " ")).toHaveBeenCalledOnce();
    expect(onRowOpen.mock.calls).toEqual([[expected, cell], [expected, cell]]);
    expect(keyRow(data, "a")).not.toHaveBeenCalled();
    expect(keyRow(data, "Tab")).not.toHaveBeenCalled();
    expect(onRowOpen).toHaveBeenCalledTimes(2);
  });

  it(`${name} opens nothing for a row ag-grid hands over without data`, () => {
    const onRowOpen = open();
    clickRow(undefined);
    keyRow(undefined, "Enter");
    expect(onRowOpen).not.toHaveBeenCalled();
  });
}

it("RunsGrid leaves a click on an in-row link or button to that control", () => {
  const onRowOpen = vi.fn();
  render(<RunsGrid engagementKey="acme-web" rows={[]} selectedId={null} onRowOpen={onRowOpen} />);
  clickRow({ id: 17 }, link);
  clickRow({ id: 17 }, button);
  keyRow({ id: 17 }, "Enter", link);
  keyRow({ id: 17 }, "Enter", button);
  expect(onRowOpen).not.toHaveBeenCalled();
});

it("CommandsGrid guards its in-row button and still opens from a link", () => {
  const onRowOpen = vi.fn();
  render(
    <CommandsGrid
      engagementKey="acme-web"
      filters={DEFAULT_COMMAND_FILTERS}
      filtersKey="[]"
      refreshToken={0}
      selectedId={null}
      onRowOpen={onRowOpen}
      onWindow={() => {}}
      onError={() => {}}
      onSortChange={() => {}}
      onTargetClick={() => {}}
    />,
  );
  clickRow({ id: 13 }, button);
  keyRow({ id: 13 }, "Enter", button);
  expect(onRowOpen).not.toHaveBeenCalled();
  clickRow({ id: 13 }, link);
  keyRow({ id: 13 }, "Enter", link);
  expect(onRowOpen).toHaveBeenCalledTimes(2);
});

const prelude = [
  ["SurfacesGrid", () => render(<SurfacesGrid rows={[]} linkCounts={new Map()} selectedId={null} onRowOpen={() => {}} />)],
  ["OastGrid", () => render(<OastGrid rows={[]} sortColumn="lasthit" selectedNonce={null} onRowOpen={() => {}} />)],
  ["HttpFlowsGrid", () => render(<HttpFlowsGrid rows={[]} selectedUid={null} onRowOpen={() => {}} />)],
  [
    "HttpGrid",
    () =>
      render(
        <HttpGrid
          engagementKey="acme-web"
          filters={EMPTY_REQUEST_VARIANT_FILTERS}
          filtersKey="[]"
          refreshToken={0}
          selectedId={null}
          onRowOpen={() => {}}
          onWindow={() => {}}
          onError={() => {}}
        />,
      ),
  ],
  [
    "CoverageGrid",
    () =>
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
      ),
  ],
  [
    "CommandsGrid",
    () =>
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
      ),
  ],
] as const;

for (const [name, mount] of prelude) {
  it(`${name} renders the legacy theme, the dense row metrics and the 400ms tooltip delay`, () => {
    mount();
    expect(grid.props.theme).toBe("legacy");
    expect(grid.props.rowHeight).toBe(GRID_ROW_HEIGHT);
    expect(grid.props.headerHeight).toBe(GRID_HEADER_HEIGHT);
    expect(grid.props.tooltipShowDelay).toBe(400);
    expect(grid.props.defaultColDef).toBe(defaultColDef);
  });
}

it("RunsGrid renders taller rows and leaves the tooltip delay to ag-grid", () => {
  render(<RunsGrid engagementKey="acme-web" rows={[]} selectedId={null} onRowOpen={() => {}} />);
  expect(grid.props.theme).toBe("legacy");
  expect(grid.props.rowHeight).toBe(56);
  expect(grid.props.headerHeight).toBe(GRID_HEADER_HEIGHT);
  expect(grid.props.tooltipShowDelay).toBe(undefined);
  expect(grid.props.defaultColDef).toBe(defaultColDef);
});
