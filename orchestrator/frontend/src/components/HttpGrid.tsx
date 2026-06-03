// ── HttpGrid ──────────────────────────────────────────────────────────
// ag-grid rendering of the HTTP tab's already-filtered request variants
// (one row per variant). Lazy-loaded by HttpTab (React.lazy + Suspense) so
// ag-grid + its CSS land in the shared code-split chunk, never the main
// entry bundle. ALL filtering (method chips + text search) stays upstream
// in HttpTab React state feeding rowData; this component only renders +
// wires row→detail-drawer clicks — the exact CommandsGrid / SurfacesGrid
// contract.

import { useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import type { RequestVariant } from "../lib/api";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  registerAgGrid,
} from "../lib/agGrid";
import { RelTime, relTime } from "./formatting";
import { methodClass } from "./HttpTab";

registerAgGrid();

type HttpGridProps = {
  rows: RequestVariant[];
  // variant id → number of recorded observations (for the count badge).
  observationCounts: Map<number, number>;
  selectedId: number | null;
  onRowOpen: (variant: RequestVariant) => void;
};

function MethodCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return null;
  const m = (data.method || "GET").toUpperCase();
  return <span className={`method-badge ${methodClass(m)}`}>{m}</span>;
}

// RelTime needs the same time-comparator the React list sorts on; the cell
// renderer just renders the span.
function LastSeenCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return null;
  return <RelTime iso={data.last_seen_at} />;
}

export default function HttpGrid({
  rows,
  observationCounts,
  selectedId,
  onRowOpen,
}: HttpGridProps) {
  const gridRef = useRef<AgGridReact<RequestVariant>>(null);

  const ObsCell = useMemo(
    () =>
      function ObsCellInner({ data }: ICellRendererParams<RequestVariant>) {
        if (!data) return null;
        const n = observationCounts.get(data.id) || 0;
        return n > 0 ? (
          <span className="badge">{n}</span>
        ) : (
          <span style={{ color: "var(--muted)" }}>—</span>
        );
      },
    [observationCounts],
  );

  const columnDefs = useMemo<ColDef<RequestVariant>[]>(
    () => [
      {
        headerName: "Method",
        colId: "method",
        width: 110,
        cellRenderer: MethodCell,
        valueGetter: (p) => (p.data?.method || "").toUpperCase(),
      },
      {
        headerName: "Path",
        colId: "path",
        flex: 2,
        minWidth: 240,
        valueGetter: (p) => p.data?.normalized_path || "/",
        wrapText: true,
        autoHeight: true,
        cellClass: "ag-mono ag-wrap-cell",
        cellStyle: { color: "var(--ink)" },
      },
      {
        headerName: "Host",
        colId: "host",
        flex: 1,
        minWidth: 150,
        valueGetter: (p) => p.data?.host || "",
        cellClass: "ag-mono",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Port",
        colId: "port",
        width: 80,
        valueGetter: (p) => p.data?.port ?? null,
        cellClass: "ag-mono",
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Content-Type",
        colId: "ctype",
        width: 130,
        valueGetter: (p) => p.data?.content_type_family || "—",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Auth",
        colId: "auth",
        width: 130,
        valueGetter: (p) => p.data?.auth_context || "—",
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Source",
        colId: "source",
        width: 140,
        valueGetter: (p) => p.data?.discovery_source || "—",
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Obs",
        colId: "obs",
        width: 80,
        sortable: false,
        cellRenderer: ObsCell,
      },
      {
        headerName: "Last seen",
        colId: "lastseen",
        width: 120,
        cellRenderer: LastSeenCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.last_seen_at || "",
        // Sort by raw timestamp, not the formatted "3h ago" string.
        comparator: (_a, _b, nodeA, nodeB) =>
          (nodeA.data?.last_seen_at || "").localeCompare(nodeB.data?.last_seen_at || ""),
        // Tooltip-friendly: surface the relative string for screen readers
        // via valueFormatter while the cell renderer paints the styled span.
        valueFormatter: (p) => relTime(p.value as string),
      },
    ],
    [ObsCell],
  );

  const onRowClicked = (event: RowClickedEvent<RequestVariant>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data) onRowOpen(event.data);
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<RequestVariant>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        suppressCellFocus
        animateRows
        onRowClicked={onRowClicked}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.id === selectedId,
        }}
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No request variants match the current filters.</span>'
      />
    </div>
  );
}
