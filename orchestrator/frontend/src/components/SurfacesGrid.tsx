// ── SurfacesGrid ──────────────────────────────────────────────────────
// ag-grid rendering of the Surfaces tab's already-filtered rows. Lazy-
// loaded by SurfacesTab so ag-grid lands in a code-split chunk. Filtering
// (chips + search) stays in SurfacesTab React state feeding rowData; this
// component only renders + wires row→detail-drawer clicks.

import { useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
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

registerAgGrid();

type SurfacesGridProps = {
  rows: AssessmentSurface[];
  // surface id → number of linked findings (for the Findings count badge).
  linkCounts: Map<number, number>;
  selectedId: number | null;
  onRowOpen: (surface: AssessmentSurface, invoker: HTMLElement | null) => void;
};

function StatusCell({ data }: ICellRendererParams<AssessmentSurface>) {
  if (!data) return null;
  return <span className={`badge status-${data.status}`}>{data.status || "—"}</span>;
}

export default function SurfacesGrid({
  rows,
  linkCounts,
  selectedId,
  onRowOpen,
}: SurfacesGridProps) {
  const gridRef = useRef<AgGridReact<AssessmentSurface>>(null);

  const FindingsCell = useMemo(
    () =>
      function FindingsCellInner({ data }: ICellRendererParams<AssessmentSurface>) {
        if (!data) return null;
        const n = linkCounts.get(data.id) || 0;
        return n > 0 ? (
          <span className="badge">{n}</span>
        ) : (
          <span style={{ color: "var(--muted)" }}>—</span>
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
        width: 130,
        valueGetter: (p) => p.data?.surface_type || "unknown",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Status",
        colId: "status",
        width: 130,
        cellRenderer: StatusCell,
        valueGetter: (p) => p.data?.status || "",
      },
      {
        headerName: "Source",
        colId: "source",
        width: 150,
        valueGetter: (p) => p.data?.source_name || "—",
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
        headerName: "Findings",
        colId: "findings",
        width: 100,
        sortable: false,
        cellRenderer: FindingsCell,
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
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<AssessmentSurface>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        animateRows
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.id === selectedId,
        }}
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No surfaces match the current filters.</span>'
      />
    </div>
  );
}
