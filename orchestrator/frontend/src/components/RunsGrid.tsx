// ── RunsGrid ──────────────────────────────────────────────────────────
// ag-grid rendering of the Runs workspace's already-filtered rows.
//
// Lazy-loaded by RunsTab so ag-grid and its CSS stay in a code-split chunk.
// All filtering stays upstream in RunsTab state; this component only owns
// column presentation and sorting, and reports its view (row order and sort)
// so the run record's Previous / Next walk the rows as shown and the results
// line names the order. The sort starts on the column RunsTab passes
// (Started, newest first unless the operator re-sorted), so the header shows it.
//
// Columns fit a 1280 px window beside the rail; narrower windows scroll the
// grid sideways inside its panel, never the page.

import { useMemo } from "react";
import { AgGridReact } from "ag-grid-react";
import type { CellKeyDownEvent, ColDef, GridApi, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  focusGridInvoker,
  registerAgGrid,
} from "../lib/agGrid";
import { DEFAULT_RUN_SORT, type RunRow, type RunSort } from "../lib/runAudit";
import { formatDuration, gridTimeComparator } from "../lib/serverTime";
import { readGridView, type GridView } from "./record/recordNavigation";
import { engagementHref } from "../lib/workspaceRoutes";
import { TimeStamp } from "./formatting";
import { RunHealthChip } from "./RunHealthChip";
import { statusOrder } from "./ui";

registerAgGrid();

const RUN_ROW_HEIGHT = 56;
// Header clicks toggle between the two directions: the list always has a
// visible sort to name.
const NEWEST_FIRST: ("asc" | "desc")[] = ["desc", "asc"];
const A_TO_Z: ("asc" | "desc")[] = ["asc", "desc"];
// Status sorts by what it asks of the operator (the run-health vocabulary
// order, most urgent first): descending puts failed runs first.
const HEALTH_URGENCY = statusOrder("run-health");

type RunsGridProps = {
  engagementKey: string;
  rows: RunRow[];
  selectedId: number | null;
  onRowOpen: (id: number, invoker: HTMLElement | null) => void;
  /** The run ids in the order the grid shows them, and the sort that put them there. */
  onViewChange?: (view: GridView<number>) => void;
  /** The sort the grid opens with (the operator's last choice). */
  initialSort?: RunSort | null;
  /** The grid API while mounted (null after), for revealing a row on return. */
  onApi?: (api: GridApi<RunRow> | null) => void;
};

function StartedCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  return <TimeStamp value={data.startedAt} fallback="Not recorded" className="run-cell-time" />;
}

function StatusCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  return (
    <div className="run-cell-stack">
      <RunHealthChip health={data.health} size="sm" />
      {data.health.reason && <span className="run-cell-sub" title={data.health.reason}>{data.health.reason}</span>}
    </div>
  );
}

function RunCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  const agent = [data.role, data.agent].filter(Boolean).join(" · ");
  return (
    <div className="run-cell-stack">
      <span className="run-cell-name">
        <span className="run-cell-title" title={data.name}>{data.name}</span>
        <span className={`run-track-tag run-track-${data.track}`}>{data.track}</span>
        {data.purpose === "scan" && <span className="run-track-tag run-purpose-scan">scan</span>}
      </span>
      <span className="run-cell-sub" title={agent}>{agent || "Agent not recorded"}</span>
    </div>
  );
}

function TaskCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  if (!data.task) return <span className="run-cell-muted">No task recorded</span>;
  return <span className="run-cell-task" title={data.task}>{data.task}</span>;
}

// Receipts and their kinds in one column: the kinds always add up to the receipts.
function EvidenceCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  if (data.receipts === 0 && data.evidenceMix === "None") return <span className="run-cell-muted">No receipts</span>;
  return (
    <div className="run-cell-stack" title={`${data.receipts} evidence receipt${data.receipts === 1 ? "" : "s"}: ${data.evidenceMix}`}>
      <span>{data.receipts} receipt{data.receipts === 1 ? "" : "s"}</span>
      <span className="run-cell-sub">{data.evidenceMix}</span>
    </div>
  );
}

function ClientCell({ data }: ICellRendererParams<RunRow>) {
  if (!data) return null;
  if (!data.client && !data.model) return <span className="run-cell-muted">Not recorded</span>;
  return (
    <div className="run-cell-stack">
      <span title={data.client}>{data.client || "Client not recorded"}</span>
      <span className="run-cell-sub" title={data.model}>{data.model || "Model not recorded"}</span>
    </div>
  );
}

export default function RunsGrid({ engagementKey, rows, selectedId, onRowOpen, onViewChange, initialSort, onApi }: RunsGridProps) {
  const startSort = initialSort ?? DEFAULT_RUN_SORT;
  const FindingsCell = useMemo(
    () =>
      function FindingsCellInner({ data }: ICellRendererParams<RunRow>) {
        if (!data) return null;
        if (data.findings.length === 0 && data.proofWorkIds.length === 0) {
          return <span className="run-cell-muted">None linked</span>;
        }
        const shown = data.findings.slice(0, 1);
        const hidden = data.findings.slice(1).map((finding) => finding.slug);
        return (
          <span className="run-cell-links">
            {shown.map((finding) => (
              <a
                key={finding.slug}
                className="run-finding-chip"
                href={engagementHref(engagementKey, { tab: "findings", finding: finding.slug })}
                title={`${finding.slug}: ${finding.relations.join(", ")}`}
              >
                {finding.slug}
              </a>
            ))}
            {hidden.length > 0 && <span className="run-cell-sub" title={hidden.join(", ")}>+{hidden.length}</span>}
            {data.proofWorkIds.map((workId) => (
              <a
                key={`work-${workId}`}
                className="run-proof-chip"
                href={engagementHref(engagementKey, { tab: "proof", work: workId })}
                title={`Proof task ${workId}`}
              >
                Proof #{workId}
              </a>
            ))}
          </span>
        );
      },
    [engagementKey],
  );

  // `initialSort` applies once when the grid builds its columns; later header
  // clicks belong to the grid and are reported through onViewChange.
  const columnDefs = useMemo<ColDef<RunRow>[]>(
    () => {
      const sortFor = (colId: string) => (startSort.colId === colId ? startSort.sort : undefined);
      return [
        {
          headerName: "Started",
          colId: "started",
          sortingOrder: NEWEST_FIRST,
          width: 100,
          initialSort: sortFor("started"),
          cellRenderer: StartedCell,
          valueGetter: (params) => params.data?.startedAt ?? null,
          // Missing start times sort last in either direction.
          comparator: gridTimeComparator,
        },
        {
          headerName: "Status",
          colId: "status",
          sortingOrder: NEWEST_FIRST,
          width: 128,
          initialSort: sortFor("status"),
          cellRenderer: StatusCell,
          valueGetter: (params) => params.data ? HEALTH_URGENCY.length - HEALTH_URGENCY.indexOf(params.data.health.key) : null,
        },
        {
          headerName: "Run · agent",
          colId: "run",
          sortingOrder: A_TO_Z,
          flex: 1,
          minWidth: 160,
          initialSort: sortFor("run"),
          cellRenderer: RunCell,
          valueGetter: (params) => params.data?.name ?? "",
        },
        {
          headerName: "Findings",
          colId: "findings",
          sortingOrder: A_TO_Z,
          width: 132,
          initialSort: sortFor("findings"),
          cellRenderer: FindingsCell,
          valueGetter: (params) => params.data?.findings.map((finding) => finding.slug).join(" ") ?? "",
        },
        {
          headerName: "Task",
          colId: "task",
          sortingOrder: A_TO_Z,
          flex: 1.4,
          minWidth: 160,
          initialSort: sortFor("task"),
          cellRenderer: TaskCell,
          valueGetter: (params) => params.data?.task ?? "",
        },
        {
          headerName: "Evidence",
          colId: "evidence",
          sortingOrder: NEWEST_FIRST,
          width: 124,
          initialSort: sortFor("evidence"),
          cellRenderer: EvidenceCell,
          valueGetter: (params) => params.data?.receipts ?? 0,
        },
        {
          headerName: "Duration",
          colId: "duration",
          sortingOrder: NEWEST_FIRST,
          width: 96,
          initialSort: sortFor("duration"),
          valueGetter: (params) => params.data?.durationSeconds ?? null,
          valueFormatter: (params) => formatDuration(params.value == null ? null : (params.value as number) * 1000),
        },
        {
          headerName: "Client · model",
          colId: "client",
          sortingOrder: A_TO_Z,
          width: 130,
          initialSort: sortFor("client"),
          cellRenderer: ClientCell,
          valueGetter: (params) => `${params.data?.client ?? ""} ${params.data?.model ?? ""}`,
        },
      ];
    },
    // Built once per mount: a re-sort must not be undone by a re-render.
    [FindingsCell],
  );

  const onRowClicked = (event: RowClickedEvent<RunRow>) => {
    const selection = window.getSelection?.();
    if (selection && selection.type === "Range" && selection.toString().length > 0) return;
    const target = event.event?.target as HTMLElement | undefined;
    if (target?.closest("a, button")) return;
    if (event.data) onRowOpen(event.data.id, focusGridInvoker(event.event));
  };

  const onCellKeyDown = (event: CellKeyDownEvent<RunRow>) => {
    const keyboardEvent = event.event as KeyboardEvent;
    const target = keyboardEvent.target as HTMLElement | null;
    if (target?.closest("a, button")) return;
    if (!event.data || (keyboardEvent.key !== "Enter" && keyboardEvent.key !== " ")) return;
    keyboardEvent.preventDefault();
    onRowOpen(event.data.id, focusGridInvoker(keyboardEvent));
  };

  return (
    <div className={`${AG_GRID_THEME} grid-host runs-grid-host`}>
      <AgGridReact<RunRow>
        theme={GRID_THEME_PROP}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        getRowId={(params) => String(params.data.id)}
        rowHeight={RUN_ROW_HEIGHT}
        headerHeight={GRID_HEADER_HEIGHT}
        onRowClicked={onRowClicked}
        onCellKeyDown={onCellKeyDown}
        onGridReady={(event) => onApi?.(event.api)}
        onGridPreDestroyed={() => onApi?.(null)}
        onModelUpdated={(event) => onViewChange?.(readGridView(event.api, (row: RunRow) => row.id))}
        rowClassRules={{
          "ag-row-selected": (params) => params.data?.id === selectedId,
          "run-row-attention": (params) => params.data?.health.key === "attention" || params.data?.health.key === "failed",
        }}
      />
    </div>
  );
}
