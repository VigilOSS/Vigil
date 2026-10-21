// ── CoverageGrid ──────────────────────────────────────────────────────
// ag-grid Infinite Row Model over `/coverage-items/page`: blocks of
// COVERAGE_GRID_BLOCK_SIZE rows are fetched as the operator scrolls, sorting
// runs on the server, and the scroll extent is the full matching total.
// Lazy-loaded by CoverageItemsView so ag-grid stays in a code-split chunk.

import { useCallback, useEffect, useMemo, useRef, type MutableRefObject } from "react";
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
} from "../../lib/agGrid";
import {
  fetchCoveragePage,
  type CoverageFilters,
  type CoverageLedgerItem,
  type CoverageLedgerPage,
  type CoverageSortDir,
  type CoverageSortKey,
} from "../../lib/coverageApi";
import { TimeStamp } from "../formatting";
import { Skeleton } from "../Skeletons";
import { StatusPill } from "../ui";
import {
  COVERAGE_GRID_BLOCK_SIZE,
  columnInitialSort,
  coverageTargetLabel,
  createCoverageDatasource,
  serverSortFromModel,
} from "./coverageGridModel";

registerAgGrid();

export type CoverageGridProps = {
  engagementKey: string;
  filters: CoverageFilters;
  /** Changes whenever `filters` changes; resets the grid to the top. */
  filtersKey: string;
  /** Bump to re-read loaded blocks in place (live refresh). */
  refreshToken: number;
  selectedId: number | null;
  /**
   * The order to start in. The tab owns it, so a grid remounted after a view
   * switch shows the order record navigation walks; later header clicks
   * report through `onSortChange`.
   */
  sort: { sort: CoverageSortKey; dir: CoverageSortDir };
  onRowOpen: (item: CoverageLedgerItem, invoker: HTMLElement | null) => void;
  onWindow: (window: { total: number | null; first: number; last: number }) => void;
  onError: (message: string | null) => void;
  /** The server order the grid is showing (record navigation walks the same order). */
  onSortChange?: (order: { sort: CoverageSortKey; dir: CoverageSortDir }) => void;
  /** Receives a function that scrolls a row index into view (returning from a record). */
  revealRef?: MutableRefObject<((index: number) => void) | null>;
};

function Pending() {
  return <Skeleton width="70%" height={10} />;
}

function StatusCell({ data }: ICellRendererParams<CoverageLedgerItem>) {
  if (!data) return <Pending />;
  return <StatusPill domain="coverage" value={data.status} size="sm" />;
}

function ReasonCell({ data }: ICellRendererParams<CoverageLedgerItem>) {
  if (!data) return <Pending />;
  if (data.latest_reason) return <span title={data.latest_reason}>{data.latest_reason}</span>;
  return (
    <span className="cov-cell-muted" title={`Created from: ${data.created_from}`}>
      No reason recorded · created from: {data.created_from || "—"}
    </span>
  );
}

function TargetCell({ data }: ICellRendererParams<CoverageLedgerItem>) {
  if (!data) return <Pending />;
  const { method, target } = coverageTargetLabel(data);
  return (
    <span className="cov-target" title={data.canonical_url || data.service_endpoint || ""}>
      {method ? <span className={`cov-method m-${method.toLowerCase()}`}>{method}</span> : <span className="cov-method cov-method-none">SVC</span>}
      <span className="cov-target-path">{target}</span>
    </span>
  );
}

function UpdatedCell({ data }: ICellRendererParams<CoverageLedgerItem>) {
  if (!data) return <Pending />;
  return <TimeStamp value={data.updated_at} />;
}

export default function CoverageGrid({
  engagementKey,
  filters,
  filtersKey,
  refreshToken,
  selectedId,
  sort,
  onRowOpen,
  onWindow,
  onError,
  onSortChange,
  revealRef,
}: CoverageGridProps) {
  const apiRef = useRef<GridApi<CoverageLedgerItem> | null>(null);
  const totalRef = useRef<number | null>(null);
  const callbacks = useRef({ onWindow, onError });
  callbacks.current = { onWindow, onError };

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
  // at the top. Responses for a datasource that is no longer active are ignored.
  const activeDatasourceRef = useRef<IDatasource | null>(null);
  const datasource = useMemo<IDatasource>(() => {
    const created: IDatasource = createCoverageDatasource(
      (params) => fetchCoveragePage(engagementKey, filters, params),
      {
        onPage: (page: CoverageLedgerPage) => {
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

  // Mount-time order only: after mount the grid's own header state leads.
  const initialOrder = useRef(sort).current;
  const columnDefs = useMemo<ColDef<CoverageLedgerItem>[]>(() => {
    const columns: ColDef<CoverageLedgerItem>[] = [
      { headerName: "Status", colId: "status", width: 146, cellRenderer: StatusCell, sortingOrder: ["desc", "asc"] },
      {
        headerName: "Reason",
        colId: "reason",
        flex: 2.4,
        minWidth: 160,
        sortable: false,
        cellRenderer: ReasonCell,
        cellClass: "ag-clip-cell",
      },
      {
        headerName: "Method + URL",
        colId: "url",
        flex: 1.8,
        minWidth: 150,
        cellRenderer: TargetCell,
        cellClass: "ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Family",
        colId: "family",
        width: 112,
        valueGetter: (p) => p.data?.attack_family ?? "",
        cellClass: "ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Input slot",
        colId: "slot",
        width: 112,
        valueGetter: (p) => p.data?.input_slot ?? "",
        cellClass: "ag-mono ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Auth",
        colId: "auth",
        width: 92,
        valueGetter: (p) => p.data?.auth_context ?? "",
        cellClass: "ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Host",
        colId: "host",
        flex: 1,
        minWidth: 130,
        valueGetter: (p) => p.data?.item_host ?? "",
        tooltipValueGetter: (p) => p.data?.item_host ?? "",
        cellClass: "ag-clip-cell",
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Updated",
        colId: "updated",
        width: 110,
        cellRenderer: UpdatedCell,
        sortingOrder: ["desc", "asc"],
      },
    ];
    return columns.map((column) => ({ ...column, initialSort: columnInitialSort(column.colId ?? "", initialOrder) }));
  }, [initialOrder]);

  useEffect(() => {
    if (!revealRef) return undefined;
    revealRef.current = (index: number) => {
      const api = apiRef.current;
      if (api && !api.isDestroyed()) api.ensureIndexVisible(index, "middle");
    };
    return () => {
      revealRef.current = null;
    };
  }, [revealRef]);

  const onRowClicked = (event: RowClickedEvent<CoverageLedgerItem>) => {
    const selection = window.getSelection?.();
    if (selection && selection.type === "Range" && selection.toString().length > 0) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onSortChanged = (event: SortChangedEvent<CoverageLedgerItem>) => {
    const model = event.api.getColumnState().map((column) => ({ colId: column.colId, sort: column.sort }));
    onSortChange?.(serverSortFromModel(model));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<CoverageLedgerItem>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} cov-grid-host`}>
      <AgGridReact<CoverageLedgerItem>
        theme={GRID_THEME_PROP}
        rowModelType="infinite"
        datasource={datasource}
        cacheBlockSize={COVERAGE_GRID_BLOCK_SIZE}
        maxBlocksInCache={40}
        blockLoadDebounceMillis={80}
        infiniteInitialRowCount={COVERAGE_GRID_BLOCK_SIZE}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        suppressMultiSort
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        tooltipShowDelay={400}
        onGridReady={(event) => {
          apiRef.current = event.api;
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
