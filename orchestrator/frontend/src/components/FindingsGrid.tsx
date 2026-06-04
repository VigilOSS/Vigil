// ── FindingsGrid ──────────────────────────────────────────────────────
// OPTIONAL flat ag-grid "table view" for the Findings tab. The grouped
// root-cause list is the DEFAULT and stays fully intact in FindingsTab —
// this is an alternate view rendered over the SAME filtered Derived[] rows.
//
// Lazy-loaded by FindingsTab so ag-grid lands in the shared code-split
// chunk. Row click calls the SAME onOpen(slug) handler the grouped list
// uses, so the drawer / deep-link flow is identical regardless of view.

import { useMemo, useRef } from "react";
import { AgGridReact } from "ag-grid-react";
import type { ColDef, ICellRendererParams, RowClickedEvent } from "ag-grid-community";
import {
  AG_GRID_THEME,
  GRID_HEADER_HEIGHT,
  GRID_ROW_HEIGHT,
  GRID_THEME_PROP,
  defaultColDef,
  registerAgGrid,
} from "../lib/agGrid";
import { relTime, sevDotColor, type Derived } from "./FindingsTab";

registerAgGrid();

type FindingsGridProps = {
  rows: Derived[];
  selected: string | null;
  onOpen: (slug: string) => void;
};

function SeverityCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return (
    <span
      className={`badge severity-${data.severity}`}
      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
    >
      <span className="sev-dot" style={{ background: sevDotColor(data.severity) }} />
      {data.severity}
    </span>
  );
}

function WorkflowCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <span className={`pill pill-${data.workflow_status}`}>{data.workflowLabel}</span>;
}

function VerificationCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  // Verification reuses the same status-* badge classes the drawer uses,
  // keyed on the normalised verificationKey (confirmed / downgraded / …).
  return (
    <span className={`badge status-${data.verificationKey}`}>{data.verificationLabel}</span>
  );
}

function UpdatedCell({ data }: ICellRendererParams<Derived>) {
  if (!data) return null;
  return <span style={{ color: "var(--muted)" }}>{relTime(data.updated_at)}</span>;
}

export default function FindingsGrid({ rows, selected, onOpen }: FindingsGridProps) {
  const gridRef = useRef<AgGridReact<Derived>>(null);

  const columnDefs = useMemo<ColDef<Derived>[]>(
    () => [
      {
        headerName: "Slug",
        colId: "slug",
        width: 180,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.slug || "",
        cellStyle: { color: "var(--accent)" },
      },
      {
        headerName: "Sev",
        colId: "severity",
        width: 110,
        cellRenderer: SeverityCell,
        valueGetter: (p) => p.data?.severity || "",
      },
      {
        headerName: "Title",
        colId: "title",
        flex: 2,
        minWidth: 240,
        valueGetter: (p) => p.data?.title || "",
        wrapText: true,
        autoHeight: true,
        cellClass: "ag-wrap-cell",
        cellStyle: { color: "var(--ink)" },
      },
      {
        headerName: "Workflow",
        colId: "workflow",
        width: 130,
        cellRenderer: WorkflowCell,
        valueGetter: (p) => p.data?.workflow_status || "",
      },
      {
        headerName: "Verification",
        colId: "verification",
        width: 140,
        cellRenderer: VerificationCell,
        valueGetter: (p) => p.data?.verificationKey || "",
      },
      {
        headerName: "Location",
        colId: "location",
        flex: 1,
        minWidth: 180,
        valueGetter: (p) => p.data?.canonical_location || "",
        wrapText: true,
        autoHeight: true,
        cellClass: "ag-mono ag-wrap-cell",
        cellStyle: { color: "var(--ink-2)" },
      },
      {
        headerName: "Updated",
        colId: "updated",
        width: 110,
        cellRenderer: UpdatedCell,
        cellClass: "ag-mono",
        valueGetter: (p) => p.data?.updated_at || "",
      },
    ],
    [],
  );

  const onRowClicked = (event: RowClickedEvent<Derived>) => {
    const sel = window.getSelection?.();
    if (sel && sel.type === "Range" && sel.toString().length > 0) return;
    if (event.data?.slug) onOpen(event.data.slug);
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
        suppressCellFocus
        animateRows
        onRowClicked={onRowClicked}
        rowClassRules={{
          "ag-row-selected": (p) => p.data?.slug === selected,
        }}
        overlayNoRowsTemplate='<span class="ag-vigil-empty">No findings match.</span>'
      />
    </div>
  );
}
