// ── ag-grid shared setup ──────────────────────────────────────────────
//
// Ported from the reference-project reference's `ag-grid-register.ts` once-guard
// pattern, plus our own theme decision + shared column defaults.
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
// (CommandsGrid / SurfacesGrid / FindingsGrid), so ag-grid + its CSS land
// in a code-split chunk and never bloat the main entry bundle.

import { AllCommunityModule, ModuleRegistry } from "ag-grid-community";

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

// Shared default column definition. Individual grids extend per-column.
// `suppressCellFocus` (a grid-level option, set on the components) plus
// these defaults give resizable + sortable columns with no in-cell focus
// ring, matching our read-only table feel.
export const defaultColDef = {
  resizable: true,
  sortable: true,
  // Filtering stays in React state feeding rowData (the existing chip /
  // search pipeline), so the per-column floating filters are off.
  filter: false,
  suppressHeaderMenuButton: true,
} as const;
