// ── ag-grid shared setup ──────────────────────────────────────────────
//
// A once-guard plus the shared theme decision and column defaults.
//
// THEME DECISION — legacy CSS-var theme (NOT the v35 Theming API).
//
// ag-grid v35 defaults to the new Theming API (themeQuartz et al.). We
// instead pass `theme="legacy"` on every <AgGridReact> (see GRID_THEME_PROP)
// and import the legacy structural stylesheet here. The visual theme is a
// hand-written CSS class `.ag-theme-vigil` (see app.css → "ag-grid theme")
// that maps --ag-* variables onto OUR design tokens (--panel, --border,
// --ink, --accent, …).
//
// Why legacy over the Theming API:
//   • Our whole design system already flips light/dark by REDEFINING the
//     same `--panel`/`--border`/… custom properties under
//     `:root[data-theme="dark"]`. A CSS-var class theme inherits that for
//     free: `--ag-background-color: var(--panel)` re-resolves on theme
//     switch with zero JS and zero extra theme objects. The Theming API
//     would need a `themeQuartz.withParams({...})` object whose param
//     values are `var(--…)` references — workable, but strictly more code
//     for the same result, and it complicates lazy-loading (the theme
//     object has to be constructed in the bundle that imports ag-grid).
//   • Least CSS: one structural import + one ~20-line class.
//
// This module is only ever imported by the lazy grid components
// (Commands, Surfaces, Findings, HTTP, Runs, Coverage, OAST), so ag-grid + its CSS land
// in a code-split chunk and never bloat the main entry bundle.

import { AllCommunityModule, ModuleRegistry } from "ag-grid-community";
import type { CellKeyDownEvent, RowClickedEvent } from "ag-grid-community";

// Legacy structural stylesheet. Our `.ag-theme-vigil` class supplies the
// look via --ag-* vars; we do NOT import ag-theme-quartz.css because we
// define our own theme class.
import "ag-grid-community/styles/ag-grid.css";

let registered = false;

/**
 * Register the community module set exactly once. Safe to call from every
 * grid component's module scope — subsequent calls are no-ops.
 */
export function registerAgGrid(): void {
  if (!registered) {
    ModuleRegistry.registerModules([AllCommunityModule]);
    registered = true;
  }
}

// The theme class consumed via className on the grid wrapper div.
export const AG_GRID_THEME = "ag-theme-vigil";

// Required for the CSS-var class theme under ag-grid v35 (the default is
// the Theming API). Spread onto <AgGridReact theme={...}> — passing the
// string literal "legacy" opts back into stylesheet-driven theming.
export const GRID_THEME_PROP = "legacy" as const;

// Row/header heights tuned to our dense list look (matches the old
// hand-rolled .frow density of ~34px rows). Header mirrors .list-header.
export const GRID_ROW_HEIGHT = 38;
export const GRID_HEADER_HEIGHT = 34;

// The structural stylesheet ships no icon font, so ag-grid's icon glyphs
// render as empty boxes. Text arrows keep the active sort direction visible
// in every grid header (styled by `.grid-sort-icon` in app.css). Column-level
// `icons` apply to that column's header, so the shared default covers every
// grid that spreads `defaultColDef`.
const GRID_SORT_ICONS = {
  sortAscending: '<span class="grid-sort-icon" aria-hidden="true">↑</span>',
  sortDescending: '<span class="grid-sort-icon" aria-hidden="true">↓</span>',
  sortUnSort: '<span class="grid-sort-icon" aria-hidden="true"></span>',
};

// Shared default column definition. Individual grids extend per-column.
export const defaultColDef = {
  resizable: true,
  sortable: true,
  icons: GRID_SORT_ICONS,
  // Filtering stays in React state feeding rowData (the existing chip /
  // search pipeline), so the per-column floating filters are off.
  filter: false,
  suppressHeaderMenuButton: true,
} as const;

// The <AgGridReact> prelude the dense list grids share: the legacy CSS-var
// theme, the shared column defaults, the dense row metrics and the tooltip
// delay the lists open with. Spread it first so a grid can still state its
// own value after it.
export const gridBaseProps = {
  theme: GRID_THEME_PROP,
  defaultColDef,
  rowHeight: GRID_ROW_HEIGHT,
  headerHeight: GRID_HEADER_HEIGHT,
  tooltipShowDelay: 400,
};

/** Focus and return the AG Grid cell that invoked a row-level action. */
export function focusGridInvoker(
  event: { target: EventTarget | null } | null | undefined,
): HTMLElement | null {
  const target = event?.target;
  if (!(target instanceof HTMLElement)) return null;
  const cell = target.closest<HTMLElement>('[role="gridcell"]');
  cell?.focus();
  return cell;
}

/**
 * The row-open wiring every list grid shares: a click, or Enter / Space on a
 * cell, opens that row's record and focuses the invoking cell so the record
 * can hand focus back to it. Text dragged across a row selects the text
 * instead of opening the row.
 *
 * `clickIgnore` / `keyIgnore` are CSS selectors for the controls inside a row
 * that handle their own activation (an in-row link or action button). They are
 * separate because the grids guard different sets, and a grid that guards
 * neither passes neither.
 */
export function rowOpenHandlers<T>(
  open: (row: T, invoker: HTMLElement | null) => void,
  options: { clickIgnore?: string; keyIgnore?: string } = {},
): {
  onRowClicked: (event: RowClickedEvent<T>) => void;
  onCellKeyDown: (event: CellKeyDownEvent<T>) => void;
} {
  return {
    onRowClicked: (event) => {
      const selection = window.getSelection?.();
      if (selection && selection.type === "Range" && selection.toString().length > 0) return;
      if (options.clickIgnore) {
        const target = event.event?.target as HTMLElement | undefined;
        if (target?.closest(options.clickIgnore)) return;
      }
      if (event.data) open(event.data, focusGridInvoker(event.event));
    },
    onCellKeyDown: (event) => {
      const keyboardEvent = event.event as KeyboardEvent;
      if (options.keyIgnore) {
        const target = keyboardEvent.target as HTMLElement | null;
        if (target?.closest(options.keyIgnore)) return;
      }
      if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
      keyboardEvent.preventDefault();
      open(event.data, focusGridInvoker(keyboardEvent));
    },
  };
}
