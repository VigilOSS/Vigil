// ── OastGrid ──────────────────────────────────────────────────────────
// ag-grid rendering of the OAST tab's already-filtered probes (one row per
// probe). Lazy-loaded by OastTab (React.lazy + Suspense) so ag-grid + its
// CSS land in the shared code-split chunk, never the main entry bundle.
// Filtering (status chips + text search) stays upstream in OastTab React
// state feeding rowData; this component only renders + wires row→detail
// clicks — the same CommandsGrid / SurfacesGrid / HttpGrid contract.

import { useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import type { OobProbe } from "../lib/api";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  registerAgGrid,
} from "../lib/agGrid";
import { RelTime, relTime } from "./formatting";
import { oobStatusClass } from "./OastTab";

registerAgGrid();

type OastGridProps = {
  rows: OobProbe[];
  selectedNonce: string | null;
  onRowOpen: (probe: OobProbe) => void;
};

function StatusCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  const s = data.status || "pending";
  return <span className={`oob-status-badge ${oobStatusClass(s)}`}>{s}</span>;
}

function TargetCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  if (!data.target_url) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <span>{data.target_url}</span>;
}

function CreatedCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  return <RelTime iso={data.created_at} />;
}

function LastInteractionCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data || !data.last_interaction_at) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <RelTime iso={data.last_interaction_at} />;
}

export default function OastGrid({ rows, selectedNonce, onRowOpen }: OastGridProps) {
  const gridRef = useRef<AgGridReact<OobProbe>>(null);

  const columnDefs = useMemo<ColDef<OobProbe>[]>(
    () => [
      {
        headerName: "Status",
        colId: "status",
        width: 120,
        cellRenderer: StatusCell,
        valueGetter: (p) => p.data?.status || "",
      },
      {
        headerName: "Technique",
        colId: "technique",
        width: 140,
        valueGetter: (p) => p.data?.technique || "—",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Kind",
        colId: "kind",
        width: 120,
        valueGetter: (p) => p.data?.probe_kind || "—",
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Target URL",
        colId: "target",
        flex: 2,
        minWidth: 240,
        cellRenderer: TargetCell,
        cellClass: "ag-mono ag-wrap-cell",
        valueGetter: (p) => p.data?.target_url || "",
      },
      {
        headerName: "Param",
        colId: "param",
        width: 120,
        valueGetter: (p) => p.data?.param || "—",
        cellClass: "ag-mono",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "OOB domain",
        colId: "domain",
        flex: 1,
        minWidth: 160,
        valueGetter: (p) => p.data?.oob_domain || "—",
        cellClass: "ag-mono",
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Hits",
        colId: "hits",
        width: 80,
        valueGetter: (p) => p.data?.interaction_count ?? 0,
        cellRenderer: (p: ICellRendererParams<OobProbe>) => {
          const n = p.data?.interaction_count ?? 0;
          return n > 0 ? (
            <span className="badge">{n}</span>
          ) : (
            <span style={{ color: "var(--muted)" }}>—</span>
          );
        },
      },
      {
        headerName: "Last hit",
        colId: "lasthit",
        width: 110,
        cellRenderer: LastInteractionCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.last_interaction_at || "",
        comparator: (_a, _b, nodeA, nodeB) =>
          (nodeA.data?.last_interaction_at || "").localeCompare(
            nodeB.data?.last_interaction_at || "",
          ),
        valueFormatter: (p) => relTime(p.value as string),
      },
      {
        headerName: "Created",
        colId: "created",
        width: 110,
        cellRenderer: CreatedCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.created_at || "",
        comparator: (_a, _b, nodeA, nodeB) =>
          (nodeA.data?.created_at || "").localeCompare(nodeB.data?.created_at || ""),
        valueFormatter: (p) => relTime(p.value as string),
      },
    ],
    [],
  );

  const onRowClicked = (event: RowClickedEvent<OobProbe>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data) onRowOpen(event.data);
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<OobProbe>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => p.data.nonce}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        suppressCellFocus
        animateRows
        onRowClicked={onRowClicked}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.nonce === selectedNonce,
        }}
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No OAST probes match the current filters.</span>'
      />
    </div>
  );
}
