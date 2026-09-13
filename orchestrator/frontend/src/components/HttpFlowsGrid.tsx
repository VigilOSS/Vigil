// ── HttpFlowsGrid ─────────────────────────────────────────────────────
// ag-grid rendering of the HTTP tab's Phase-5 canonical flow store (one row
// per assessment_http_flows row). Lazy-loaded by HttpTab (React.lazy +
// Suspense) so ag-grid + its CSS land in the shared code-split chunk. Server-
// side filtering happens upstream in HttpTab (the fetch passes the filters as
// query params); this component only renders rows + wires row→detail-drawer
// clicks — the exact HttpGrid / CommandsGrid contract.

import { useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import type { HttpFlow } from "../lib/api";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import { RelTime, relTime } from "./formatting";
import { methodClass, statusClass } from "./HttpTab";

registerAgGrid();

type HttpFlowsGridProps = {
  rows: HttpFlow[];
  selectedUid: string | null;
  onRowOpen: (flow: HttpFlow, invoker: HTMLElement | null) => void;
};

// Compact human byte size (matches the terse style used across the grids).
export function fmtBytes(n: number | null | undefined): string {
  if (n == null || n <= 0) return "—";
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb < 10 ? kb.toFixed(1) : Math.round(kb)} KB`;
  const mb = kb / 1024;
  return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`;
}

function MethodCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  const m = (data.method || "GET").toUpperCase();
  return <span className={`method-badge ${methodClass(m)}`}>{m}</span>;
}

function StatusCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data || data.response_status == null) {
    return <span style={{ color: "var(--muted)" }}>—</span>;
  }
  return (
    <span className={`status-badge ${statusClass(data.response_status)}`}>
      {data.response_status}
    </span>
  );
}

// Truncation / integrity flags: either-side body truncation and a scope
// integrity warning (host_mismatch) rendered as compact warn chips so the
// operator can spot lossy or off-authority flows at a glance.
function FlagsCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  const trunc = data.request_body_truncated || data.response_body_truncated;
  if (!trunc && !data.host_mismatch) {
    return <span style={{ color: "var(--muted)" }}>—</span>;
  }
  return (
    <span style={{ display: "inline-flex", gap: 4 }}>
      {trunc && (
        <span className="tag warning" title="Response/request body was truncated at capture time">
          TRUNC
        </span>
      )}
      {data.host_mismatch && (
        <span
          className="tag warning"
          title="URL authority / Host header / SNI disagree — possible off-scope routing"
        >
          HOST≠
        </span>
      )}
    </span>
  );
}

function LastSeenCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  return <RelTime iso={data.created_at} />;
}

export default function HttpFlowsGrid({ rows, selectedUid, onRowOpen }: HttpFlowsGridProps) {
  const gridRef = useRef<AgGridReact<HttpFlow>>(null);

  const columnDefs: ColDef<HttpFlow>[] = [
    {
      headerName: "Method",
      colId: "method",
      width: 100,
      cellRenderer: MethodCell,
      valueGetter: (p) => (p.data?.method || "").toUpperCase(),
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
      headerName: "Path",
      colId: "path",
      flex: 2,
      minWidth: 240,
      valueGetter: (p) => p.data?.path || p.data?.url || "/",
      wrapText: true,
      autoHeight: true,
      cellClass: "ag-mono ag-wrap-cell",
      cellStyle: { color: "var(--ink)" },
    },
    {
      headerName: "Status",
      colId: "status",
      width: 90,
      cellRenderer: StatusCell,
      valueGetter: (p) => p.data?.response_status ?? null,
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
      width: 120,
      valueGetter: (p) => p.data?.auth_context || "—",
      cellStyle: { color: "var(--muted)" },
    },
    {
      headerName: "Req",
      colId: "reqbytes",
      width: 84,
      valueGetter: (p) => p.data?.request_body_bytes ?? 0,
      valueFormatter: (p) => fmtBytes(p.value as number),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
    },
    {
      headerName: "Resp",
      colId: "respbytes",
      width: 84,
      valueGetter: (p) => p.data?.response_body_bytes ?? 0,
      valueFormatter: (p) => fmtBytes(p.value as number),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
    },
    {
      headerName: "Flags",
      colId: "flags",
      width: 110,
      sortable: false,
      cellRenderer: FlagsCell,
    },
    {
      headerName: "Seen",
      colId: "seen",
      width: 110,
      cellRenderer: LastSeenCell,
      cellClass: "ag-mono",
      valueGetter: (p) => p.data?.created_at || "",
      comparator: (_a, _b, nodeA, nodeB) =>
        (nodeA.data?.created_at || "").localeCompare(nodeB.data?.created_at || ""),
      valueFormatter: (p) => relTime(p.value as string),
    },
  ];

  const onRowClicked = (event: RowClickedEvent<HttpFlow>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<HttpFlow>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<HttpFlow>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => p.data.flow_uid || String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        animateRows
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        rowClassRules={{
          "ag-row-selected": (p) => (p.data?.flow_uid ?? null) === selectedUid,
        }}
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No HTTP flows match the current filters.</span>'
      />
    </div>
  );
}
