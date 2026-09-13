// ── CommandsGrid ──────────────────────────────────────────────────────
// ag-grid rendering of the Commands tab's already-filtered/sorted rows.
//
// This component is lazy-loaded by CommandsTab (React.lazy + Suspense) so
// ag-grid + its CSS land in a code-split chunk, never in the main entry
// bundle. ALL data shaping (filtering, search, sort, dup-detection) stays
// upstream in CommandsTab React state — we only receive the final
// Derived[] as rowData. That keeps the filter-chip / search pipeline and
// the DetailModal flow exactly as they were.

import { useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import {
  agentColor,
  fmtDuration,
  relTime,
  toolColor,
  type Derived,
} from "./CommandsTab";

registerAgGrid();

type CommandsGridProps = {
  rows: Derived[];
  dupCounts: Map<string, number>;
  selectedId: number | null;
  onRowOpen: (id: number, invoker: HTMLElement | null) => void;
  onTargetClick: (target: string) => void;
  onDupClick: (hash: string) => void;
};

// ── Cell renderers (React components) ─────────────────────────────────
function TimeCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return (
    <span style={{ color: "var(--muted)" }}>
      {relTime(data.row.created_at || data.row.started_at)}
    </span>
  );
}

function ToolCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  const color = toolColor(data.toolBin);
  return (
    <span
      className="tag"
      style={{ background: `color-mix(in srgb, ${color} 10%, transparent)`, color, fontWeight: 600 }}
      title={data.toolBin || "(unknown)"}
    >
      {data.toolBin || "(unknown)"}
    </span>
  );
}

function AgentCell({ data }: ICellRendererParams<Derived>) {
  if (!data || !data.agentName) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <span style={{ color: agentColor(data.agentName) }}>{data.agentName}</span>;
}

function RcCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  const rc = data.row.return_code;
  const b = data.rcBucket;
  const cls =
    b === "zero"
      ? "tag-rc-ok"
      : b === "timeout"
      ? "tag-rc-warn"
      : b === "nonzero"
      ? "tag-rc-danger"
      : "tag-rc-pending";
  return (
    <span className={`tag ${cls}`}>
      {b === "timeout" ? "t/o" : rc == null ? "—" : String(rc)}
    </span>
  );
}

export default function CommandsGrid({
  rows,
  dupCounts,
  selectedId,
  onRowOpen,
  onTargetClick,
  onDupClick,
}: CommandsGridProps) {
  const gridRef = useRef<AgGridReact<Derived>>(null);

  // Target / dup cells need the click handlers, so build them inside the
  // component (closures over the props) rather than as module renderers.
  const DupCell = useMemo(
    () =>
      function DupCellInner({ data }: ICellRendererParams<Derived>) {
        if (!data) return null;
        const count = data.row.command_hash ? dupCounts.get(data.row.command_hash) || 0 : 0;
        if (count <= 1) return null;
        return (
          <span
            className="tag"
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              if (data.row.command_hash) onDupClick(data.row.command_hash);
            }}
            style={{ cursor: "pointer", background: "var(--count-bg)", color: "var(--accent)" }}
            title={`${count} rows share this command_hash — click to filter`}
          >
            ×{count}
          </span>
        );
      },
    [dupCounts, onDupClick],
  );

  const TargetCell = useMemo(
    () =>
      function TargetCellInner({ data }: ICellRendererParams<Derived>) {
        if (!data) return null;
        if (!data.target) return <span style={{ color: "var(--muted)" }}>—</span>;
        return (
          <span
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation();
              onTargetClick(data.target);
            }}
            style={{ cursor: "pointer", color: "var(--ink-2)" }}
            title={`Filter by target:${data.target}`}
          >
            {data.target}
          </span>
        );
      },
    [onTargetClick],
  );

  const columnDefs = useMemo<ColDef<Derived>[]>(
    () => [
      {
        headerName: "Time",
        colId: "time",
        width: 110,
        cellRenderer: TimeCell,
        cellClass: "ag-mono",
        // Sort by the same key the React list sorts on.
        comparator: (_a, _b, nodeA, nodeB) => {
          const aT = nodeA.data?.row.created_at || nodeA.data?.row.started_at || "";
          const bT = nodeB.data?.row.created_at || nodeB.data?.row.started_at || "";
          return aT.localeCompare(bT);
        },
      },
      { headerName: "Tool", colId: "tool", width: 120, cellRenderer: ToolCell },
      {
        headerName: "Agent",
        colId: "agent",
        width: 150,
        cellRenderer: AgentCell,
        valueGetter: (p) => p.data?.agentName || "",
      },
      {
        headerName: "Phase",
        colId: "phase",
        width: 110,
        valueGetter: (p) => p.data?.phase || "",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Target",
        colId: "target",
        width: 170,
        cellRenderer: TargetCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.target || "",
      },
      {
        headerName: "Command",
        colId: "command",
        flex: 1,
        minWidth: 260,
        valueGetter: (p) => p.data?.commandPreview || "",
        // Long argv WRAPS instead of ellipsing (explicit plan requirement).
        wrapText: true,
        autoHeight: true,
        cellClass: "ag-mono ag-wrap-cell",
        cellStyle: { color: "var(--ink)" },
      },
      {
        headerName: "Dur",
        colId: "duration",
        width: 90,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.row.duration_ms ?? 0,
        valueFormatter: (p) => fmtDuration((p.value as number) || 0),
        cellStyle: { color: "var(--muted)" },
      },
      {
        headerName: "Dup",
        colId: "dup",
        width: 80,
        sortable: false,
        cellRenderer: DupCell,
      },
      {
        headerName: "RC",
        colId: "rc",
        width: 80,
        cellRenderer: RcCell,
        valueGetter: (p) => p.data?.row.return_code ?? null,
      },
    ],
    [DupCell, TargetCell],
  );

  const onRowClicked = (event: RowClickedEvent<Derived>) => {
    // Guard text-selection clicks and clicks on the inline target/dup
    // buttons so they don't double-fire the row open.
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest('[role="button"]')) return;
    if (event.data?.id != null) onRowOpen(event.data.id, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<Derived>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    const target = keyboardEvent.target as HTMLElement | null;
    if (target?.closest('[role="button"]')) return;
    if (
      event.data?.id == null
      || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")
    ) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data.id, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<Derived>
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
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No command runs match.</span>'
      />
    </div>
  );
}
