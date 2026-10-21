// ── CommandsGrid ──────────────────────────────────────────────────────
// ag-grid Infinite Row Model over `/command-runs/page`: blocks of
// COMMAND_GRID_BLOCK_SIZE lean rows load as the operator scrolls, every
// sortable column sorts on the server, and the scroll extent is the full
// matching total. Lazy-loaded by CommandsTab so ag-grid stays in a
// code-split chunk. The tab owns filters and the open record; the grid
// reports its visible window, its sort, and a small handle for keyboard
// movement and the return to a stepped record.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AgGridReact } from "ag-grid-react";
import type {
  CellKeyDownEvent,
  ColDef,
  GridApi,
  ICellRendererParams,
  IDatasource,
  RowClickedEvent,
  SortChangedEvent,
} from "ag-grid-community";
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
  DEFAULT_COMMAND_SORT,
  commandSortColumn,
  commandSortFromModel,
  commandStatusReason,
  createCommandDatasource,
  fetchCommandPage,
  type CommandFilters,
  type CommandLedgerPage,
  type CommandLedgerRow,
  type CommandSort,
} from "../lib/commandsApi";
import { formatDuration } from "../lib/serverTime";
import { TimeStamp } from "./formatting";
import { Skeleton } from "./Skeletons";
import { StatusPill } from "./ui";
import { agentColor, toolColor } from "./CommandsTab";

registerAgGrid();

export const COMMAND_GRID_BLOCK_SIZE = 100;

/** What the tab may ask of the grid: rows by position, and scrolling to one. */
export type CommandsGridHandle = {
  /** Position of a loaded row, or null when its block is not loaded. */
  indexOf: (id: number) => number | null;
  /** The loaded row at a position, or null while its block loads. */
  rowAt: (index: number) => CommandLedgerRow | null;
  /** Scroll a position into view (loading its block); `focus` moves keyboard focus there. */
  reveal: (index: number, focus?: boolean) => void;
};

export type CommandsGridProps = {
  engagementKey: string;
  filters: CommandFilters;
  /** Changes whenever `filters` changes; resets the grid to the top. */
  filtersKey: string;
  /** Bump to re-read the loaded blocks in place (live refresh). */
  refreshToken: number;
  /**
   * The order the grid starts in: the tab's current sort, so a grid rebuilt
   * after an empty state (or a return to the tab) keeps the operator's order.
   * Later header clicks report through `onSortChange`.
   */
  initialSort?: CommandSort | null;
  /** The row last opened or stepped to (highlighted). */
  selectedId: number | null;
  onRowOpen: (row: CommandLedgerRow, invoker: HTMLElement | null) => void;
  onWindow: (window: { total: number | null; first: number; last: number }) => void;
  onError: (message: string | null) => void;
  /** The server order the grid shows (record navigation walks the same order). */
  onSortChange: (sort: CommandSort) => void;
  onTargetClick: (target: string) => void;
  onHandle?: (handle: CommandsGridHandle | null) => void;
};

function Pending() {
  return <Skeleton width="70%" height={10} />;
}

function TimeCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  return <TimeStamp value={data.created_at || data.started_at} />;
}

function StatusCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  const reason = data.needs_attention ? commandStatusReason(data) : "";
  return (
    <span className="commands-status-cell" title={reason || undefined}>
      <StatusPill domain="command" value={data.status} size="sm" />
      {data.status === "completed" && data.needs_attention && (
        <span className="commands-status-note">{data.attention_reasons.join(" · ")}</span>
      )}
    </span>
  );
}

function ToolCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  const tool = data.tool || "(unknown)";
  const color = toolColor(data.tool);
  return (
    <span className="tag commands-tool" style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, color }} title={tool}>
      {tool}
    </span>
  );
}

function AgentCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  if (!data.agent_name) return <span className="commands-muted">—</span>;
  return <span style={{ color: agentColor(data.agent_name) }} title={data.agent_name}>{data.agent_name}</span>;
}

function CommandCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  const cut = data.command_chars > data.command_preview.length;
  return (
    <span className="commands-command" title={data.command_preview + (cut ? "…" : "")}>
      {data.command_preview || <span className="commands-muted">(no command recorded)</span>}
      {cut && <span className="commands-muted">…</span>}
    </span>
  );
}

function RcCell({ data }: ICellRendererParams<CommandLedgerRow>) {
  if (!data) return <Pending />;
  if (data.timed_out) return <span className="tag tag-rc-warn" title="Timed out">t/o</span>;
  if (data.return_code == null) return <span className="tag tag-rc-pending">—</span>;
  return <span className={`tag ${data.return_code === 0 ? "tag-rc-ok" : "tag-rc-danger"}`}>{data.return_code}</span>;
}

/** The column definitions with the starting sort on its column (and no other). */
function withStartSort(columns: ColDef<CommandLedgerRow>[], start: { colId: string; dir: CommandSort["dir"] }): ColDef<CommandLedgerRow>[] {
  return columns.map((column) => (column.colId === start.colId ? { ...column, sort: start.dir } : column));
}

export default function CommandsGrid({
  engagementKey,
  filters,
  filtersKey,
  refreshToken,
  initialSort,
  selectedId,
  onRowOpen,
  onWindow,
  onError,
  onSortChange,
  onTargetClick,
  onHandle,
}: CommandsGridProps) {
  // Read once: the columns carry the starting sort; the grid owns it after that.
  const [startSort] = useState(() => commandSortColumn(initialSort ?? DEFAULT_COMMAND_SORT));
  const apiRef = useRef<GridApi<CommandLedgerRow> | null>(null);
  const totalRef = useRef<number | null>(null);
  const callbacks = useRef({ onWindow, onError, onTargetClick });
  callbacks.current = { onWindow, onError, onTargetClick };

  const reportWindow = useCallback(() => {
    const api = apiRef.current;
    const total = totalRef.current;
    if (!api || total == null) {
      callbacks.current.onWindow({ total, first: 0, last: 0 });
      return;
    }
    const range = api.getVerticalPixelRange();
    const first = Math.floor(range.top / GRID_ROW_HEIGHT) + 1;
    const last = Math.max(first, Math.floor(Math.max(range.bottom - 1, 0) / GRID_ROW_HEIGHT) + 1);
    callbacks.current.onWindow({ total, first: Math.min(first, total), last: Math.min(last, total) });
  }, []);

  // A new filter set is a new datasource: the grid drops its cache and starts
  // at the top. Answers for a datasource that is no longer active are ignored.
  const activeDatasourceRef = useRef<IDatasource | null>(null);
  const datasource = useMemo<IDatasource>(() => {
    const created: IDatasource = createCommandDatasource(
      (params) => fetchCommandPage(engagementKey, filters, params),
      {
        onPage: (page: CommandLedgerPage) => {
          if (activeDatasourceRef.current !== created) return;
          totalRef.current = page.total;
          callbacks.current.onError(null);
          reportWindow();
        },
        onError: (message) => {
          if (activeDatasourceRef.current === created) callbacks.current.onError(message);
        },
      },
    ) as IDatasource;
    return created;
    // `filtersKey` is the identity of `filters`, so `filters` itself is not a dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [engagementKey, filtersKey, reportWindow]);

  useEffect(() => {
    activeDatasourceRef.current = datasource;
    totalRef.current = null;
    callbacks.current.onWindow({ total: null, first: 0, last: 0 });
  }, [datasource]);

  // Live refresh re-reads the loaded blocks while keeping rows on screen.
  const firstRefreshToken = useRef(refreshToken);
  useEffect(() => {
    if (refreshToken === firstRefreshToken.current) return;
    apiRef.current?.refreshInfiniteCache();
  }, [refreshToken]);

  // The highlighted row follows the record last opened or stepped to.
  useEffect(() => {
    apiRef.current?.redrawRows();
  }, [selectedId]);

  const handle = useMemo<CommandsGridHandle>(() => ({
    indexOf: (id) => apiRef.current?.getRowNode(String(id))?.rowIndex ?? null,
    rowAt: (index) => apiRef.current?.getDisplayedRowAtIndex(index)?.data ?? null,
    reveal: (index, focus) => {
      const api = apiRef.current;
      if (!api || index < 0) return;
      api.ensureIndexVisible(index, "middle");
      if (focus) api.setFocusedCell(index, "time");
    },
  }), []);
  const onHandleRef = useRef(onHandle);
  onHandleRef.current = onHandle;
  useEffect(() => () => onHandleRef.current?.(null), []);

  const TargetCell = useMemo(
    () =>
      function TargetCellInner({ data }: ICellRendererParams<CommandLedgerRow>) {
        if (!data) return <Pending />;
        if (!data.target) return <span className="commands-muted">—</span>;
        const inferred = data.target_source === "inferred";
        return (
          <button
            type="button"
            className="grid-link-button"
            onClick={(event) => {
              event.stopPropagation();
              callbacks.current.onTargetClick(data.target);
            }}
            title={`Search target:${data.target}${inferred ? " (inferred from the command)" : ""}`}
            aria-label={`Search runs against ${data.target}${inferred ? ", inferred from the command" : ""}`}
          >
            {data.target}
          </button>
        );
      },
    [],
  );

  const columnDefs = useMemo<ColDef<CommandLedgerRow>[]>(
    () => withStartSort([
      {
        headerName: "Time",
        colId: "time",
        width: 88,
        cellRenderer: TimeCell,
        headerTooltip: "When the run was recorded",
        sortingOrder: ["desc", "asc"],
      },
      { headerName: "Status", colId: "status", width: 150, cellRenderer: StatusCell, cellClass: "ag-clip-cell", sortingOrder: ["desc", "asc"] },
      { headerName: "Tool", colId: "tool", width: 92, cellRenderer: ToolCell, sortingOrder: ["asc", "desc"] },
      { headerName: "Agent", colId: "agent", width: 132, cellRenderer: AgentCell, cellClass: "ag-clip-cell", sortingOrder: ["asc", "desc"] },
      {
        headerName: "Phase",
        colId: "phase",
        width: 92,
        valueGetter: (p) => p.data?.phase ?? "",
        cellClass: "ag-clip-cell commands-ink-2",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Target",
        colId: "target",
        width: 140,
        sortable: false,
        cellRenderer: TargetCell,
        cellClass: "ag-mono ag-clip-cell",
        headerTooltip: "The stored target host, or one inferred from the command",
      },
      {
        headerName: "Command",
        colId: "command",
        flex: 1,
        minWidth: 180,
        sortable: false,
        cellRenderer: CommandCell,
        cellClass: "ag-mono ag-clip-cell",
      },
      {
        headerName: "Duration",
        colId: "duration",
        width: 98,
        cellClass: "ag-mono commands-muted",
        valueGetter: (p) => p.data?.duration_ms ?? null,
        valueFormatter: (p) => (p.data ? formatDuration(p.value as number) : ""),
        sortingOrder: ["desc", "asc"],
      },
      { headerName: "Exit", colId: "rc", width: 60, cellRenderer: RcCell, headerTooltip: "Exit code", sortingOrder: ["asc", "desc"] },
    ], startSort),
    [TargetCell, startSort],
  );

  const onRowClicked = (event: RowClickedEvent<CommandLedgerRow>) => {
    // Text selection and the target button inside the row do not open it.
    const selection = window.getSelection?.();
    if (selection && selection.type === "Range" && selection.toString().length > 0) return;
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest("button")) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<CommandLedgerRow>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if ((keyboardEvent.target as HTMLElement | null)?.closest("button")) return;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  const onSortChanged = (event: SortChangedEvent<CommandLedgerRow>) => {
    const model = event.api.getColumnState().map((column) => ({ colId: column.colId, sort: column.sort }));
    onSortChange(commandSortFromModel(model));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host commands-grid-host`}>
      <AgGridReact<CommandLedgerRow>
        theme={GRID_THEME_PROP}
        rowModelType="infinite"
        datasource={datasource}
        cacheBlockSize={COMMAND_GRID_BLOCK_SIZE}
        maxBlocksInCache={40}
        blockLoadDebounceMillis={80}
        infiniteInitialRowCount={COMMAND_GRID_BLOCK_SIZE}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        suppressMultiSort
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        tooltipShowDelay={400}
        onGridReady={(event) => {
          apiRef.current = event.api;
          onHandleRef.current?.(handle);
        }}
        onBodyScroll={reportWindow}
        onGridSizeChanged={reportWindow}
        onModelUpdated={reportWindow}
        onViewportChanged={reportWindow}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onSortChanged={onSortChanged}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.id === selectedId,
        }}
      />
    </div>
  );
}
