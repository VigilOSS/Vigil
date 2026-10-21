// ── FindingsGrid ──────────────────────────────────────────────────────
// OPTIONAL flat ag-grid "table view" for the Findings tab. The grouped
// root-cause list is the DEFAULT and stays fully intact in FindingsTab —
// this is an alternate view rendered over the SAME filtered Derived[] rows.
//
// Lazy-loaded by FindingsTab so ag-grid lands in the shared code-split
// chunk. Row click calls the SAME onOpen(slug) handler the grouped list
// uses, so the drawer / deep-link flow is identical regardless of view.

import { useEffect, useMemo, useRef, type MutableRefObject } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, GridApi, ICellRendererParams, RowClickedEvent, SortChangedEvent, SortDirection } from "ag-grid-community";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import { compareSeverity, type Derived, type TableColumnSort } from "./FindingsTab";
import { TimeStamp } from "./formatting";
import { SeverityTag, StatusPill, compareStatus, type SortKind, type StatusDomain } from "./ui";
import { gridTimeComparator } from "../lib/serverTime";
import type { FindingsSort } from "../lib/findingRecency";

registerAgGrid();

type FindingsGridProps = {
  rows: Derived[];
  selected: string | null;
  onOpen: (slug: string) => void;
  onOrderChange: (slugs: string[]) => void;
  // The page's named sort, applied as the grid's column sort; a new
  // `sortRequest` re-applies it after a header click replaced it.
  sort?: FindingsSort;
  sortRequest?: number;
  // A header click reports the named sort it matches (null for any other
  // column order) and the column order itself (null when no column sorts).
  onSortChange?: (sort: FindingsSort | null, column: TableColumnSort | null) => void;
  // Receives a function that scrolls a finding's row into view (record return).
  revealRef?: MutableRefObject<((slug: string) => void) | null>;
};

// Named page sorts as grid column sorts.
const SORT_COLUMNS: Record<FindingsSort, { colId: string; sort: SortDirection }> = {
  severity: { colId: "severity", sort: "asc" },
  newest: { colId: "created", sort: "desc" },
  changed: { colId: "changed", sort: "desc" },
};

function applySort(api: GridApi<Derived>, sort: FindingsSort) {
  const { colId, sort: direction } = SORT_COLUMNS[sort];
  api.applyColumnState({ state: [{ colId, sort: direction }], defaultState: { sort: null } });
}

function namedSort(api: GridApi<Derived>): FindingsSort | null {
  const sorted = api.getColumnState().filter((column) => column.sort);
  if (sorted.length !== 1) return null;
  const [column] = sorted;
  for (const [name, target] of Object.entries(SORT_COLUMNS) as [FindingsSort, (typeof SORT_COLUMNS)[FindingsSort]][]) {
    if (target.colId === column.colId && target.sort === column.sort) return name;
  }
  return null;
}

// What each sortable column holds, so the results line names the order in
// words ("Title, A to Z"). Severity and the status columns are ranked: their
// comparators put the most severe (or most urgent, in status order) first on an
// ascending sort.
const COLUMN_SORTS: Record<string, { label: string; kind: SortKind; inverted?: boolean }> = {
  slug: { label: "Slug", kind: "text" },
  severity: { label: "Severity", kind: "rank", inverted: true },
  title: { label: "Title", kind: "text" },
  created: { label: "Created", kind: "time" },
  changed: { label: "Last changed", kind: "time" },
  workflow: { label: "Workflow", kind: "status", inverted: true },
  submission: { label: "Submission", kind: "status", inverted: true },
  verification: { label: "Verification", kind: "status", inverted: true },
};

// Status columns sort in their domain's urgency order (unlisted values last).
const statusComparator = (domain: StatusDomain) => (a: string, b: string) => compareStatus(domain, a, b);

function columnSort(api: GridApi<Derived>): TableColumnSort | null {
  const [column] = api.getColumnState()
    .filter((state) => state.sort)
    .sort((a, b) => (a.sortIndex ?? 0) - (b.sortIndex ?? 0));
  const known = column && COLUMN_SORTS[column.colId];
  if (!column?.sort || !known) return null;
  const direction = known.inverted ? (column.sort === "asc" ? "desc" : "asc") : column.sort;
  return { label: known.label, direction, kind: known.kind };
}

function SeverityCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <SeverityTag severity={data.severity} size="sm" />;
}

function WorkflowCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <StatusPill domain="finding-workflow" value={data.workflow_status} size="sm" />;
}

function SubmissionCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  // External-program submission state is a separate axis from workflow_status
  // and is only meaningful once a finding has actually been submitted — render
  // an empty cell for the "none" default so the column stays quiet.
  if (!data.submission_status || data.submission_status === "none") return null;
  return <StatusPill domain="finding-submission" value={data.submission_status} size="sm" />;
}

function VerificationCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <StatusPill domain="finding-verification" value={data.verificationKey} size="sm" />;
}

// Titles wrap to at most two lines so one long title cannot make a row tower
// over its neighbours; the location sits under the title on one line, cut
// with an ellipsis. Both stay whole in the DOM text and the hover title, so
// the table fits a 1280 px screen without scrolling sideways.
function TitleCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return (
    <span className="findings-grid-title-cell">
      <span className="findings-grid-title" title={data.title}>{data.title}</span>
      {data.canonical_location && <span className="findings-grid-ellipsis findings-grid-location" title={data.canonical_location}>{data.canonical_location}</span>}
    </span>
  );
}

function CreatedCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <TimeStamp value={data.created_at} />;
}

// Last ledger change, with what the change was on a muted line under it.
function ChangedCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  const action = data.last_transition_action?.replace(/_/g, " ");
  return (
    <span className="findings-grid-changed">
      <TimeStamp value={data.changed_at} />
      {action && (
        <span className="findings-grid-ellipsis findings-grid-changed-action" title={data.last_transition_actor ? `${action} by ${data.last_transition_actor}` : action}>
          {action}
        </span>
      )}
    </span>
  );
}

export default function FindingsGrid({ rows, selected, onOpen, onOrderChange, sort = "newest", sortRequest = 0, onSortChange, revealRef }: FindingsGridProps) {
  const gridRef = useRef<AgGridReact<Derived>>(null);
  // Column definitions are built once; they take the sort the grid opens with.
  const initialSort = useRef(SORT_COLUMNS[sort]);

  useEffect(() => {
    const api = gridRef.current?.api;
    if (api) applySort(api, sort);
  }, [sort, sortRequest]);

  const onSortChanged = (event: SortChangedEvent<Derived>) => {
    if (event.source !== "uiColumnSorted") return;
    onSortChange?.(namedSort(event.api), columnSort(event.api));
  };

  useEffect(() => {
    if (!revealRef) return undefined;
    revealRef.current = (slug: string) => {
      const api = gridRef.current?.api;
      const node = api?.getRowNode(slug);
      if (api && node) api.ensureNodeVisible(node, "middle");
    };
    return () => { revealRef.current = null; };
  }, [revealRef]);

  const columnDefs = useMemo<ColDef<Derived>[]>(
    () => [
      {
        headerName: "Slug",
        colId: "slug",
        width: 84,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.slug || "",
        cellStyle: { color: "var(--accent)" },
      },
      {
        headerName: "Sev",
        colId: "severity",
        width: 92,
        cellRenderer: SeverityCell,
        valueGetter: (p) => p.data?.severity || "",
        comparator: (a: string, b: string) => compareSeverity(a, b),
        initialSort: initialSort.current.colId === "severity" ? initialSort.current.sort : undefined,
      },
      {
        headerName: "Title · location",
        colId: "title",
        flex: 1,
        minWidth: 240,
        valueGetter: (p) => p.data?.title || "",
        cellRenderer: TitleCell,
        autoHeight: true,
        cellClass: "ag-wrap-cell",
        cellStyle: { color: "var(--ink)" },
      },
      {
        headerName: "Created",
        colId: "created",
        width: 102,
        cellRenderer: CreatedCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.created_at || "",
        comparator: gridTimeComparator,
        initialSort: initialSort.current.colId === "created" ? initialSort.current.sort : undefined,
      },
      {
        headerName: "Changed",
        colId: "changed",
        width: 112,
        cellRenderer: ChangedCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.changed_at || "",
        comparator: gridTimeComparator,
        initialSort: initialSort.current.colId === "changed" ? initialSort.current.sort : undefined,
      },
      {
        headerName: "Workflow",
        colId: "workflow",
        width: 112,
        cellRenderer: WorkflowCell,
        valueGetter: (p) => p.data?.workflow_status || "",
        comparator: statusComparator("finding-workflow"),
      },
      {
        headerName: "Submission",
        colId: "submission",
        width: 112,
        cellRenderer: SubmissionCell,
        valueGetter: (p) => p.data?.submission_status || "",
        comparator: statusComparator("finding-submission"),
      },
      {
        headerName: "Verification",
        colId: "verification",
        width: 172,
        cellRenderer: VerificationCell,
        valueGetter: (p) => p.data?.verificationKey || "",
        comparator: statusComparator("finding-verification"),
      },
    ],
    [],
  );

  const onRowClicked = (event: RowClickedEvent<Derived>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data?.slug) {
      focusGridInvoker(event.event);
      onOpen(event.data.slug);
    }
  };

  const onCellKeyDown = (event: CellKeyDownEvent<Derived>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    if (!event.data?.slug || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    focusGridInvoker(keyboardEvent);
    onOpen(event.data.slug);
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host`}>
      <AgGridReact<Derived>
        ref={gridRef}
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(p) => p.data.slug}
        rowHeight={GRID_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        animateRows={false}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onSortChanged={onSortChanged}
        onModelUpdated={(event) => {
          const slugs: string[] = [];
          event.api.forEachNodeAfterFilterAndSort((node) => { if (node.data) slugs.push(node.data.slug); });
          onOrderChange(slugs);
        }}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.slug === selected,
        }}
      />
    </div>
  );
}
