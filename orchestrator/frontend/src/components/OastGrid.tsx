// ── OastGrid ──────────────────────────────────────────────────────────
// ag-grid rendering of the OAST tab's already-filtered probes (one row per
// probe). Lazy-loaded by OastTab (React.lazy + Suspense) so ag-grid + its
// CSS land in the shared code-split chunk, never the main entry bundle.
// Filtering (scope, status chips, text search) stays upstream in OastTab
// React state feeding rowData; this component renders, shows the scope's
// default sort on its column header, opens a row's record, and reports the
// order and sort it shows so the record's Previous / Next walk it and the
// results line names it — the same RunsGrid / SurfacesGrid contract.

import { useEffect, useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, GridApi, GridReadyEvent, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import type { OobProbe } from "../lib/api";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import { linkedToParts, oobStatus } from "../lib/oastApi";
import { TimeStamp } from "./formatting";
import { gridTimeComparator, gridTimeMode } from "../lib/serverTime";
import { readGridView, type GridSort, type GridView } from "./record/recordNavigation";
import { compareStatus, StatusPill } from "./ui";
import { LinkedTo } from "./OastTab";

registerAgGrid();

export type OastSortColumn = "lasthit" | "created";

type OastGridProps = {
  rows: OobProbe[];
  // The scope's default order, shown on that column header; header clicks
  // can still re-sort any column.
  sortColumn: OastSortColumn;
  /**
   * The order to start in instead of the scope default: the sort the operator
   * last chose, so a grid rebuilt after an empty state (or a return to the
   * tab) keeps it. An empty list starts unsorted.
   */
  initialSort?: GridSort[] | null;
  selectedNonce: string | null;
  onRowOpen: (probe: OobProbe, invoker: HTMLElement | null) => void;
  /** Probe nonces in display order and the sort behind it, after every sort or row change. */
  onViewChange?: (view: GridView<string>) => void;
  /** Hands over a function that scrolls a probe's row into the grid viewport. */
  onReady?: (reveal: (nonce: string) => void) => void;
};

function applySort(api: GridApi<OobProbe>, sort: GridSort[]) {
  api.applyColumnState({ state: sort.map(({ colId, sort: direction }) => ({ colId, sort: direction })), defaultState: { sort: null } });
}

const defaultSort = (column: OastSortColumn): GridSort[] => [{ colId: column, sort: "desc" }];

function StatusCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  return <StatusPill domain="oast" value={oobStatus(data)} size="sm" />;
}

// Relative while recent; the absolute minute once the age would show only a date.
function GridTime({ value }: { value: string | null | undefined }) {
  if (!value) return <span style={{ color: "var(--muted)" }}>—</span>;
  return gridTimeMode(value) === "absolute" ? <TimeStamp value={value} mode="absolute" /> : <TimeStamp value={value} />;
}

function LinkedCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  return <LinkedTo probe={data} />;
}

function Muted({ text }: { text: string }) {
  return text ? <span>{text}</span> : <span style={{ color: "var(--muted)" }}>—</span>;
}

function CreatedCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  return <GridTime value={data.created_at} />;
}

function LastInteractionCell({ data }: ICellRendererParams<OobProbe>) {
  if (!data) return null;
  return <GridTime value={data.last_interaction_at} />;
}

export default function OastGrid({ rows, sortColumn, initialSort, selectedNonce, onRowOpen, onViewChange, onReady }: OastGridProps) {
  const gridRef = useRef<AgGridReact<OobProbe>>(null);
  // Read once, when the grid is ready; header clicks own the sort after that.
  const startSortRef = useRef(initialSort ?? defaultSort(sortColumn));

  const columnDefs = useMemo<ColDef<OobProbe>[]>(
    () => [
      {
        headerName: "Status",
        colId: "status",
        width: 160,
        cellRenderer: StatusCell,
        valueGetter: (p) => (p.data ? oobStatus(p.data) : ""),
        // By urgency (the vocabulary order: callbacks to review lead), so the
        // first click, descending, reads "most urgent first" like every status column.
        comparator: (a, b) => compareStatus("oast", b as string, a as string),
        sortingOrder: ["desc", "asc"],
      },
      {
        headerName: "Linked to",
        colId: "linked",
        headerTooltip: "Target URL · parameter · technique recorded when the probe was minted",
        flex: 2,
        minWidth: 150,
        tooltipValueGetter: (p) => (p.data ? linkedToParts(p.data).join(" · ") || undefined : undefined),
        cellRenderer: LinkedCell,
        cellClass: "ag-mono",
        valueGetter: (p) => (p.data ? linkedToParts(p.data).join(" · ") : ""),
      },
      {
        headerName: "Client",
        colId: "client",
        width: 112,
        cellRenderer: (p: ICellRendererParams<OobProbe>) => <Muted text={p.data?.client_name || ""} />,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.client_name || "",
      },
      {
        headerName: "Payload host",
        colId: "payload-host",
        flex: 1,
        minWidth: 100,
        // The full host is the hover text; the record and search carry it too.
        tooltipValueGetter: (p) => p.data?.client_payload_host || undefined,
        cellRenderer: (p: ICellRendererParams<OobProbe>) => <Muted text={p.data?.client_payload_host || ""} />,
        cellClass: "ag-mono",
        cellStyle: { color: "var(--ink-2)" },
        valueGetter: (p) => p.data?.client_payload_host || "",
      },
      {
        headerName: "Callbacks",
        colId: "hits",
        width: 104,
        type: "numericColumn",
        valueGetter: (p) => p.data?.interaction_count ?? 0,
        cellRenderer: (p: ICellRendererParams<OobProbe>) => {
          const n = p.data?.interaction_count ?? 0;
          return n > 0 ? (
            <span className="oast-hits">{n}</span>
          ) : (
            <span style={{ color: "var(--muted)" }}>—</span>
          );
        },
      },
      {
        headerName: "Last callback",
        colId: "lasthit",
        width: 164,
        cellRenderer: LastInteractionCell,
        valueGetter: (p) => p.data?.last_interaction_at || "",
        comparator: gridTimeComparator,
      },
      {
        headerName: "Planted",
        colId: "created",
        width: 164,
        cellRenderer: CreatedCell,
        valueGetter: (p) => p.data?.created_at || "",
        comparator: gridTimeComparator,
      },
    ],
    [],
  );

  // A view switch re-applies that view's default order (not on mount: the
  // grid starts in `initialSort` when it is ready).
  const shownSortColumn = useRef(sortColumn);
  useEffect(() => {
    if (shownSortColumn.current === sortColumn) return;
    shownSortColumn.current = sortColumn;
    const api = gridRef.current?.api;
    if (api) applySort(api, defaultSort(sortColumn));
  }, [sortColumn]);

  const onGridReady = (event: GridReadyEvent<OobProbe>) => {
    applySort(event.api, startSortRef.current);
    onReady?.((nonce) => {
      const node = event.api.getRowNode(nonce);
      if (node) event.api.ensureNodeVisible(node, "middle");
    });
  };

  const onRowClicked = (event: RowClickedEvent<OobProbe>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data) onRowOpen(event.data, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<OobProbe>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host oast-grid-host`}>
      <AgGridReact<OobProbe>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => p.data.nonce}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        tooltipShowDelay={400}
        animateRows
        onGridReady={onGridReady}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onModelUpdated={(event) => onViewChange?.(readGridView(event.api, (row) => row.nonce))}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.nonce === selectedNonce,
          "oast-row-fired": (p) => (p.data ? oobStatus(p.data) === "fired" : false),
          "oast-row-finished": (p) => (p.data ? ["expired", "ignored"].includes(oobStatus(p.data)) : false),
        }}
      />
    </div>
  );
}
