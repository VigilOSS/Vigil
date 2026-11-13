// ── SurfacesGrid ──────────────────────────────────────────────────────
// ag-grid rendering of the Surfaces tab's already-filtered rows. Lazy-
// loaded by SurfacesTab so ag-grid lands in a code-split chunk. Filtering
// (scope, chips + search) stays in SurfacesTab React state feeding rowData;
// this component renders, opens a row's record, and reports what it shows
// (row order and the column sort behind it) so the record's Previous / Next
// walk it and the summary line names the order. The grid always shows some
// order: it starts in the sort the tab hands it (newest update first when
// there is none) and a header click flips a column's direction.

import { useEffect, useMemo, useRef, useState } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef, GridApi, ICellRendererParams, ModelUpdatedEvent } from "ag-grid-community";
import type { AssessmentSurface } from "../lib/api";
import { AG_GRID_THEME, gridBaseProps, registerAgGrid, rowOpenHandlers } from "../lib/agGrid";
import { gridTimeComparator } from "../lib/serverTime";
import { TimeStamp } from "./formatting";
import { StatusPill, compareStatus, humanizeStatus } from "./ui";
import { readGridView, type GridSort, type GridView } from "./record/recordNavigation";

registerAgGrid();

const DEFAULT_SORT: GridSort = { colId: "updated", sort: "desc" };

/** The column definitions with the starting sort on its column (and no other); a sort no column shows starts on `DEFAULT_SORT`. */
function withStartSort(columns: ColDef<AssessmentSurface>[], start: GridSort | null | undefined): ColDef<AssessmentSurface>[] {
  const shown = start && columns.some((column) => column.colId === start.colId && column.sortable !== false) ? start : DEFAULT_SORT;
  return columns.map((column) => ({ ...column, initialSort: column.colId === shown.colId ? shown.sort : undefined }));
}

type SurfacesGridProps = {
  rows: AssessmentSurface[];
  // surface id → number of linked findings (for the Findings count badge).
  linkCounts: Map<number, number>;
  selectedId: number | null;
  /**
   * The sort the grid starts in (the tab keeps it across visits). Read once
   * on mount; later header clicks report through `onViewChange`.
   */
  initialSort?: GridSort | null;
  onRowOpen: (surface: AssessmentSurface, invoker: HTMLElement | null) => void;
  /** The shown row order and the column sort behind it, after every model update. */
  onViewChange?: (view: GridView<number>) => void;
  /** The grid API once ready, null on unmount (record return reveals rows through it). */
  onApi?: (api: GridApi<AssessmentSurface> | null) => void;
};

function StatusCell({ data }: ICellRendererParams<AssessmentSurface>) {
  if (!data) return null;
  return <StatusPill domain="surface" value={data.status} size="sm" />;
}

function UpdatedCell({ data }: ICellRendererParams<AssessmentSurface>) {
  if (!data) return null;
  return <TimeStamp value={data.updated_at} />;
}

export default function SurfacesGrid({
  rows,
  linkCounts,
  selectedId,
  initialSort,
  onRowOpen,
  onViewChange,
  onApi,
}: SurfacesGridProps) {
  // Read once: the columns carry the starting sort; the grid owns it after that.
  const [startSort] = useState(initialSort);
  const gridRef = useRef<AgGridReact<AssessmentSurface>>(null);
  const onApiRef = useRef(onApi);
  onApiRef.current = onApi;
  useEffect(() => () => onApiRef.current?.(null), []);

  const FindingsCell = useMemo(
    () =>
      function FindingsCellInner({ data }: ICellRendererParams<AssessmentSurface>) {
        if (!data) return null;
        const n = linkCounts.get(data.id) || 0;
        return n > 0 ? (
          <span className="surface-link-count">{n}</span>
        ) : (
          <span className="surface-cell-muted" aria-label="No linked findings">—</span>
        );
      },
    [linkCounts],
  );

  const columnDefs = useMemo<ColDef<AssessmentSurface>[]>(
    () => withStartSort([
      {
        headerName: "Target",
        colId: "target",
        flex: 2,
        minWidth: 220,
        valueGetter: (p) => p.data?.target_descriptor || "",
        tooltipValueGetter: (p) => p.data?.target_descriptor || "",
        cellClass: "ag-mono ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Type",
        colId: "type",
        width: 140,
        valueGetter: (p) => humanizeStatus(p.data?.surface_type || "unknown"),
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Status",
        colId: "status",
        width: 170,
        cellRenderer: StatusCell,
        valueGetter: (p) => p.data?.status || "",
        // Lifecycle order, not alphabetical: ascending runs from the least
        // urgent, so the first (descending) sort puts untested surfaces first.
        comparator: (_a, _b, nodeA, nodeB) => compareStatus("surface", nodeB.data?.status, nodeA.data?.status),
        sortingOrder: ["desc", "asc"],
      },
      {
        headerName: "Source",
        colId: "source",
        width: 150,
        valueGetter: (p) => p.data?.source_name || "—",
        tooltipValueGetter: (p) => p.data?.source_name || "",
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--muted)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Rationale",
        colId: "rationale",
        flex: 2,
        minWidth: 200,
        valueGetter: (p) => p.data?.rationale || "—",
        tooltipValueGetter: (p) => p.data?.rationale || "",
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Follow-up",
        colId: "followup",
        flex: 1.2,
        minWidth: 150,
        valueGetter: (p) => p.data?.followup_condition || "—",
        tooltipValueGetter: (p) => p.data?.followup_condition || "",
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Findings",
        colId: "findings",
        width: 96,
        sortable: false,
        cellRenderer: FindingsCell,
      },
      {
        headerName: "Updated",
        colId: "updated",
        width: 112,
        cellRenderer: UpdatedCell,
        valueGetter: (p) => p.data?.updated_at || "",
        // Missing update times sort last in both directions.
        comparator: gridTimeComparator,
        sortingOrder: ["desc", "asc"],
      },
    ], startSort),
    [FindingsCell, startSort],
  );

  const { onRowClicked, onCellKeyDown } = rowOpenHandlers<AssessmentSurface>(onRowOpen);

  return (
    <div className={`${AG_GRID_THEME} grid-host surfaces-grid-host`}>
      <AgGridReact<AssessmentSurface>
        ref={gridRef}
        {...gridBaseProps}
        rowData={rows}
        columnDefs={columnDefs}
        getRowId={(p) => String(p.data.id)}
        onGridReady={(event) => onApiRef.current?.(event.api)}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onModelUpdated={(event: ModelUpdatedEvent<AssessmentSurface>) => onViewChange?.(readGridView(event.api, (row) => row.id))}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.id === selectedId,
        }}
      />
    </div>
  );
}
