// ── HttpFlowsGrid ─────────────────────────────────────────────────────
// ag-grid rendering of the HTTP tab's canonical flow store (one row per
// assessment_http_flows row). Lazy-loaded by HttpTab (React.lazy +
// Suspense) so ag-grid + its CSS land in the shared code-split chunk. Server-
// side filtering happens upstream in HttpTab (the fetch passes the filters as
// query params); this component only renders rows, wires row→record clicks,
// and reports the order it shows (after a header sort) for the record's
// Previous / Next — the exact HttpGrid / CommandsGrid contract. The grid
// always shows some order: it starts in the sort the tab hands it (newest
// first when there is none) and a header click flips a column's direction.

import { useEffect, useMemo, useRef, useState } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef, GridApi, ICellRendererParams, ModelUpdatedEvent } from "ag-grid-community";
import type { HttpFlow } from "../lib/api";
import { AG_GRID_THEME, gridBaseProps, registerAgGrid, rowOpenHandlers } from "../lib/agGrid";
import { TimeStamp, formatBytes } from "./formatting";
import { formatRelativeTime, gridTimeComparator } from "../lib/serverTime";
import { HttpStatusPill, methodClass } from "./HttpTab";
import { StatusPill } from "./ui";

import { readGridView, type GridSort, type GridView } from "./record/recordNavigation";

registerAgGrid();

const DEFAULT_SORT: GridSort = { colId: "seen", sort: "desc" };

/** The column definitions with the starting sort on its column (and no other); a sort no column shows starts on `DEFAULT_SORT`. */
function withStartSort(columns: ColDef<HttpFlow>[], start: GridSort | null | undefined): ColDef<HttpFlow>[] {
  const shown = start && columns.some((column) => column.colId === start.colId && column.sortable !== false) ? start : DEFAULT_SORT;
  return columns.map((column) => ({ ...column, initialSort: column.colId === shown.colId ? shown.sort : undefined }));
}

type HttpFlowsGridProps = {
  rows: HttpFlow[];
  selectedUid: string | null;
  /**
   * The sort the grid starts in (the tab keeps it across visits). Read once
   * on mount; later header clicks report through `onViewChange`.
   */
  initialSort?: GridSort | null;
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

export default function HttpFlowsGrid({ rows, selectedUid, initialSort, onRowOpen, onViewChange, onApi }: HttpFlowsGridProps) {
  // Read once: the columns carry the starting sort; the grid owns it after that.
  const [startSort] = useState(initialSort);
  const gridRef = useRef<AgGridReact<HttpFlow>>(null);
  const onApiRef = useRef(onApi);
  onApiRef.current = onApi;
  useEffect(() => () => onApiRef.current?.(null), []);

  const columnDefs = useMemo<ColDef<HttpFlow>[]>(() => withStartSort([
    {
      headerName: "Method",
      colId: "method",
      width: 100,
      cellRenderer: MethodCell,
      valueGetter: (p) => (p.data?.method || "").toUpperCase(),
      sortingOrder: ["asc", "desc"],
    },
    {
      headerName: "Host",
      colId: "host",
      flex: 1,
      minWidth: 150,
      valueGetter: (p) => p.data?.host || "",
      cellClass: "ag-mono",
      cellStyle: { color: "var(--ink-2)" },
      sortingOrder: ["asc", "desc"],
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
      sortingOrder: ["asc", "desc"],
    },
    {
      headerName: "Status",
      colId: "status",
      width: 90,
      cellRenderer: StatusCell,
      valueGetter: (p) => p.data?.response_status ?? null,
      sortingOrder: ["asc", "desc"],
    },
    {
      headerName: "Content-Type",
      colId: "ctype",
      width: 130,
      valueGetter: (p) => p.data?.content_type_family || "—",
      cellStyle: { color: "var(--ink-2)" },
      sortingOrder: ["asc", "desc"],
    },
    {
      headerName: "Auth",
      colId: "auth",
      width: 120,
      valueGetter: (p) => p.data?.auth_context || "—",
      cellStyle: { color: "var(--muted)" },
      sortingOrder: ["asc", "desc"],
    },
    {
      headerName: "Req",
      colId: "reqbytes",
      width: 84,
      valueGetter: (p) => p.data?.request_body_bytes ?? null,
      valueFormatter: (p) => formatBytes(p.value as number | null),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
      // Sizes open largest first.
      sortingOrder: ["desc", "asc"],
    },
    {
      headerName: "Resp",
      colId: "respbytes",
      width: 84,
      valueGetter: (p) => p.data?.response_body_bytes ?? null,
      valueFormatter: (p) => formatBytes(p.value as number | null),
      cellClass: "ag-mono",
      cellStyle: { color: "var(--muted)" },
      sortingOrder: ["desc", "asc"],
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
      sortingOrder: ["desc", "asc"],
      // Missing capture times sort last in both directions.
      comparator: gridTimeComparator,
      valueFormatter: (p) => formatRelativeTime(p.value as string),
    },
  ], startSort), [startSort]);

  const { onRowClicked, onCellKeyDown } = rowOpenHandlers<HttpFlow>(onRowOpen);

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<HttpFlow>
        ref={gridRef}
        {...gridBaseProps}
        rowData={rows}
        columnDefs={columnDefs}
        getRowId={(p) => p.data.flow_uid || String(p.data.id)}
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
