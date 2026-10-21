// ── SurfacesGrid ──────────────────────────────────────────────────────
// ag-grid rendering of the Surfaces tab's already-filtered rows. Lazy-
// loaded by SurfacesTab so ag-grid lands in a code-split chunk. Filtering
// (scope, chips + search) stays in SurfacesTab React state feeding rowData;
// this component renders, opens a row's record, and reports what it shows
// (row order and the column sort behind it) so the record's Previous / Next
// walk it and the summary line names the order.

import { useEffect, useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, GridApi, ICellRendererParams, ModelUpdatedEvent, RowClickedEvent } from "ag-grid-community";
import type { AssessmentSurface } from "../lib/api";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import { gridTimeComparator } from "../lib/serverTime";
import { TimeStamp } from "./formatting";
import { StatusPill, compareStatus, humanizeStatus } from "./ui";
import { readGridView, type GridView } from "./record/recordNavigation";

registerAgGrid();


type SurfacesGridProps = {
  rows: AssessmentSurface[];
  // surface id → number of linked findings (for the Findings count badge).
  linkCounts: Map<number, number>;
  selectedId: number | null;
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
  onRowOpen,
  onViewChange,
  onApi,
}: SurfacesGridProps) {
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
    () => [
      {
        headerName: "Target",
        colId: "target",
        flex: 2,
        minWidth: 220,
        valueGetter: (p) => p.data?.target_descriptor || "",
        tooltipValueGetter: (p) => p.data?.target_descriptor || "",
        cellClass: "ag-mono ag-clip-cell",
      },
      {
        headerName: "Type",
        colId: "type",
        width: 140,
        valueGetter: (p) => humanizeStatus(p.data?.surface_type || "unknown"),
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
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
        // The default order, newest first; the header shows it.
        initialSort: "desc",
        sortingOrder: ["desc", "asc"],
      },
    ],
    [FindingsCell],
  );

  const onRowClicked = (event: RowClickedEvent<AssessmentSurface>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<AssessmentSurface>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host surfaces-grid-host`}>
      <AgGridReact<AssessmentSurface>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        tooltipShowDelay={400}
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
