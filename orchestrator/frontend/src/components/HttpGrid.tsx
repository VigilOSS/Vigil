// ── HttpGrid ──────────────────────────────────────────────────────────
// ag-grid Infinite Row Model over `/request-variants/page`: blocks of
// HTTP_GRID_BLOCK_SIZE rows are fetched as the operator scrolls, sorting and
// filtering run on the server, and the scroll extent is the full matching
// total. Lazy-loaded by HttpTab so ag-grid stays in a code-split chunk.
// Each row's observation count covers every observation of the variant.

import { useCallback, useEffect, useMemo, useRef } from "react";
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
  createRequestVariantDatasource,
  fetchRequestVariantPage,
  requestVariantOrderFromModel,
  type RequestVariantFilters,
  type RequestVariantOrder,
  type RequestVariantPage,
} from "../lib/httpApi";
import type { RequestVariant } from "../lib/api";
import { TimeStamp } from "./formatting";
import { Skeleton } from "./Skeletons";
import { methodClass } from "./HttpTab";

registerAgGrid();

export const HTTP_GRID_BLOCK_SIZE = 100;

// Narrow grids drop the columns the record repeats, widest-first, so Path,
// Obs and Last seen stay on screen (every value stays in the record).
const NARROW_HIDDEN: { below: number; columns: string[] }[] = [
  { below: 1040, columns: ["port", "ctype"] },
  { below: 820, columns: ["source"] },
  { below: 640, columns: ["auth", "host"] },
];

export type HttpGridWindow = { total: number | null; first: number; last: number };

type HttpGridProps = {
  engagementKey: string;
  filters: RequestVariantFilters;
  /** Changes whenever `filters` changes; resets the grid to the top. */
  filtersKey: string;
  /** Bump to re-read loaded blocks in place (live refresh). */
  refreshToken: number;
  selectedId: number | null;
  onRowOpen: (row: RequestVariant, invoker: HTMLElement | null) => void;
  onWindow: (window: HttpGridWindow) => void;
  onError: (message: string | null) => void;
  /** The server order the grid shows (record navigation walks the same order). */
  onSortChange?: (order: RequestVariantOrder) => void;
  /** The grid API once ready, null on unmount (record return reveals rows through it). */
  onApi?: (api: GridApi<RequestVariant> | null) => void;
};

function Pending() {
  return <Skeleton width="70%" height={10} />;
}

function MethodCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return <Pending />;
  const method = (data.method || "GET").toUpperCase();
  return <span className={`method-badge ${methodClass(method)}`}>{method}</span>;
}

function PathCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return <Pending />;
  const path = data.normalized_path || "/";
  return <span title={data.canonical_url || path}>{path}</span>;
}

function ObservationsCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return null;
  return data.observation_count > 0
    ? <span className="http-obs-count">{data.observation_count.toLocaleString("en-US")}</span>
    : <span className="http-cell-muted" aria-label="No observations">—</span>;
}

function LastSeenCell({ data }: ICellRendererParams<RequestVariant>) {
  if (!data) return null;
  return <TimeStamp value={data.last_seen_at} />;
}

export default function HttpGrid({
  engagementKey,
  filters,
  filtersKey,
  refreshToken,
  selectedId,
  onRowOpen,
  onWindow,
  onError,
  onSortChange,
  onApi,
}: HttpGridProps) {
  const apiRef = useRef<GridApi<RequestVariant> | null>(null);
  const totalRef = useRef<number | null>(null);
  const callbacks = useRef({ onWindow, onError, onApi });
  callbacks.current = { onWindow, onError, onApi };

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
    const created: IDatasource = createRequestVariantDatasource(
      (params) => fetchRequestVariantPage(engagementKey, filters, params),
      {
        onPage: (page: RequestVariantPage) => {
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
    // `filtersKey` is the identity of `filters`.
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

  // The opened row keeps its highlight when the operator returns.
  useEffect(() => {
    apiRef.current?.redrawRows();
  }, [selectedId]);

  useEffect(() => () => callbacks.current.onApi?.(null), []);

  const fitColumns = useCallback((api: GridApi<RequestVariant>, width: number) => {
    for (const { below, columns } of NARROW_HIDDEN) api.setColumnsVisible(columns, !(width > 0 && width < below));
  }, []);

  const columnDefs = useMemo<ColDef<RequestVariant>[]>(
    () => [
      { headerName: "Method", colId: "method", width: 92, cellRenderer: MethodCell, sortingOrder: ["asc", "desc"] },
      {
        headerName: "Path",
        colId: "path",
        flex: 2.4,
        minWidth: 200,
        cellRenderer: PathCell,
        cellClass: "ag-mono ag-clip-cell",
        cellStyle: { color: "var(--ink)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Host",
        colId: "host",
        flex: 1,
        minWidth: 140,
        valueGetter: (p) => p.data?.host ?? "",
        tooltipValueGetter: (p) => p.data?.host ?? "",
        cellClass: "ag-mono ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Port",
        colId: "port",
        width: 72,
        valueGetter: (p) => p.data?.port ?? null,
        cellClass: "ag-mono",
        cellStyle: { color: "var(--muted)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Content type",
        colId: "ctype",
        width: 116,
        valueGetter: (p) => (p.data ? p.data.content_type_family || "—" : ""),
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--ink-2)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Auth",
        colId: "auth",
        width: 112,
        valueGetter: (p) => (p.data ? p.data.auth_context || "—" : ""),
        tooltipValueGetter: (p) => p.data?.auth_context ?? "",
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--muted)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Source",
        colId: "source",
        width: 132,
        valueGetter: (p) => (p.data ? p.data.discovery_source || "—" : ""),
        tooltipValueGetter: (p) => p.data?.discovery_source ?? "",
        cellClass: "ag-clip-cell",
        cellStyle: { color: "var(--muted)" },
        sortingOrder: ["asc", "desc"],
      },
      {
        headerName: "Obs",
        headerTooltip: "Observations: every time this request was seen",
        colId: "obs",
        width: 80,
        cellRenderer: ObservationsCell,
        sortingOrder: ["desc", "asc"],
      },
      {
        headerName: "Last seen",
        colId: "lastseen",
        width: 112,
        cellRenderer: LastSeenCell,
        initialSort: "desc",
        sortingOrder: ["desc", "asc"],
      },
    ],
    [],
  );

  const onRowClicked = (event: RowClickedEvent<RequestVariant>) => {
    const selection = window.getSelection?.();
    if (selection && selection.type === "Range" && selection.toString().length > 0) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<RequestVariant>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  const onSortChanged = (event: SortChangedEvent<RequestVariant>) => {
    const model = event.api.getColumnState().map((column) => ({ colId: column.colId, sort: column.sort }));
    onSortChange?.(requestVariantOrderFromModel(model));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host http-grid-host`}>
      <AgGridReact<RequestVariant>
        theme={GRID_THEME_PROP}
        rowModelType="infinite"
        datasource={datasource}
        cacheBlockSize={HTTP_GRID_BLOCK_SIZE}
        maxBlocksInCache={40}
        blockLoadDebounceMillis={80}
        infiniteInitialRowCount={HTTP_GRID_BLOCK_SIZE}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        suppressMultiSort
        getRowId={(p) => String(p.data.id)}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        tooltipShowDelay={400}
        onGridReady={(event) => {
          apiRef.current = event.api;
          callbacks.current.onApi?.(event.api);
        }}
        onGridSizeChanged={(event) => {
          fitColumns(event.api, event.clientWidth);
          reportWindow();
        }}
        onBodyScroll={reportWindow}
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
