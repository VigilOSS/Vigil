// ── HttpFlowsGrid ─────────────────────────────────────────────────────
// ag-grid rendering of the HTTP tab's canonical flow store (one row per
// assessment_http_flows row). Lazy-loaded by HttpTab (React.lazy +
// Suspense) so ag-grid + its CSS land in the shared code-split chunk. Server-
// side filtering happens upstream in HttpTab (the fetch passes the filters as
// query params); this component only renders rows, wires row→record clicks,
// and reports the order it shows (after a header sort) for the record's
// Previous / Next — the exact HttpGrid / CommandsGrid contract.

import { useEffect, useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, GridApi, ICellRendererParams, ModelUpdatedEvent, RowClickedEvent } from "ag-grid-community";
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
import { TimeStamp, formatBytes } from "./formatting";
import { formatRelativeTime, gridTimeComparator } from "../lib/serverTime";
import { HttpStatusPill, methodClass } from "./HttpTab";
import { StatusPill } from "./ui";

import { readGridView, type GridView } from "./record/recordNavigation";

registerAgGrid();

type HttpFlowsGridProps = {
  rows: HttpFlow[];
  selectedUid: string | null;
  /** The shown row order and the column sort behind it, after every model update. */
  onViewChange?: (view: GridView<number>) => void;
  onRowOpen: (flow: HttpFlow, invoker: HTMLElement | null) => void;
  /** The grid API once ready, null on unmount (record return reveals rows through it). */
  onApi?: (api: GridApi<HttpFlow> | null) => void;
};

function MethodCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  const m = (data.method || "GET").toUpperCase();
  return <span className={`method-badge ${methodClass(m)}`}>{m}</span>;
}

function StatusCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data || data.response_status == null) {
    return <span className="http-cell-muted" aria-label="No response recorded">—</span>;
  }
  return <HttpStatusPill status={data.response_status} />;
}

// Truncation / integrity flags: either-side body truncation and a scope
// integrity warning (host_mismatch) rendered as compact warn chips so the
// operator can spot lossy or off-authority flows at a glance.
function FlagsCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  const trunc = data.request_body_truncated || data.response_body_truncated;
  if (!trunc && !data.host_mismatch) {
    return <span className="http-cell-muted" aria-label="No flags">—</span>;
  }
  return (
    <span className="http-flags">
      {trunc && (
        <StatusPill
          value="truncated"
          label="Truncated"
          tone="warning"
          size="sm"
          title="The request or response body was cut at the capture size cap"
        />
      )}
      {data.host_mismatch && (
        <StatusPill
          value="host_mismatch"
          label="Host mismatch"
          tone="warning"
          size="sm"
          title="URL authority, Host header and SNI disagree: possible off-scope routing"
        />
      )}
    </span>
  );
}

function LastSeenCell({ data }: ICellRendererParams<HttpFlow>) {
  if (!data) return null;
  return <TimeStamp value={data.created_at} />;
}

export default function HttpFlowsGrid({ rows, selectedUid, onRowOpen, onViewChange, onApi }: HttpFlowsGridProps) {
  const gridRef = useRef<AgGridReact<HttpFlow>>(null);
  const onApiRef = useRef(onApi);
  onApiRef.current = onApi;
  useEffect(() => () => onApiRef.current?.(null), []);

  const columnDefs = useMemo<ColDef<HttpFlow>[]>(() => [
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
      tooltipValueGetter: (p) => p.data?.url || p.data?.path || "",
      cellClass: "ag-mono ag-clip-cell",
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
      valueGetter: (p) => p.data?.request_body_bytes ?? null,
      valueFormatter: (p) => formatBytes(p.value as number | null),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
    },
    {
      headerName: "Resp",
      colId: "respbytes",
      width: 84,
      valueGetter: (p) => p.data?.response_body_bytes ?? null,
      valueFormatter: (p) => formatBytes(p.value as number | null),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
    },
    {
      headerName: "Flags",
      colId: "flags",
      width: 150,
      sortable: false,
      cellRenderer: FlagsCell,
    },
    {
      headerName: "Seen",
      colId: "seen",
      width: 110,
      // The default sort column stays on screen however narrow the grid.
      pinned: "right",
      cellRenderer: LastSeenCell,
      valueGetter: (p) => p.data?.created_at || "",
      // The default order, newest first; the header shows it.
      initialSort: "desc",
      sortingOrder: ["desc", "asc"],
      // Missing capture times sort last in both directions.
      comparator: gridTimeComparator,
      valueFormatter: (p) => formatRelativeTime(p.value as string),
    },
  ], []);

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
        tooltipShowDelay={400}
        onGridReady={(event) => onApiRef.current?.(event.api)}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onModelUpdated={(event: ModelUpdatedEvent<HttpFlow>) => onViewChange?.(readGridView(event.api, (row) => row.id))}
        rowClassRules={{
          "ag-row-selected": (p) => (p.data?.flow_uid ?? null) === selectedUid,
        }}
      />
    </div>
  );
}
