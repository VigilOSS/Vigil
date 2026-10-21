// Visible sort, for every list.
//
// ag-grid lists: give the default sort column its sort in the column
// definition (`sort: "desc"` on Started / Updated / Last seen) instead of
// pre-sorting `rowData`. The grid then draws the header arrow and sets
// `aria-sort`, and a header click re-sorts from the same state. Report the
// grid's current sort (recordNavigation `readGridView`) to <ResultsSummary> so
// the line under the list names the order actually shown.
//
// Custom lists and tables: put <SortIndicator> in the sorted header (with
// `aria-sort` from `ariaSort`) or name the order in <ResultsSummary>.

import { ArrowDown, ArrowUp } from "lucide-react";
import "../../styles/ui.css";

export type SortDirection = "asc" | "desc";

/** What kind of values a column holds; picks the direction words. */
export type SortKind = "time" | "number" | "text" | "rank" | "status";

const DIRECTION_WORDS: Record<SortKind, Record<SortDirection, string>> = {
  time: { desc: "newest first", asc: "oldest first" },
  number: { desc: "highest first", asc: "lowest first" },
  text: { asc: "A to Z", desc: "Z to A" },
  // Ranked vocabularies (severity, status order): "desc" puts the most severe first.
  rank: { desc: "most severe first", asc: "least severe first" },
  // Statuses ranked by what they ask of the operator: "desc" puts the most
  // urgent first, as with `rank`. Every status column uses this wording.
  status: { desc: "most urgent first", asc: "least urgent first" },
};

/** "Started, newest first" / "Tool, A to Z" / "Status, most urgent first". */
export function describeSort(column: string, direction: SortDirection, kind: SortKind): string {
  return `${column}, ${DIRECTION_WORDS[kind][direction]}`;
}

/** `aria-sort` for a header cell. */
export function ariaSort(direction: SortDirection | null | undefined): "ascending" | "descending" | "none" {
  return direction === "asc" ? "ascending" : direction === "desc" ? "descending" : "none";
}

/** The arrow beside a sorted custom header; renders nothing for an unsorted one. */
export function SortIndicator({ direction }: { direction: SortDirection | null | undefined }) {
  if (!direction) return null;
  const Icon = direction === "asc" ? ArrowUp : ArrowDown;
  return <Icon className="ui-sort-indicator" size={12} aria-hidden="true" />;
}

type ResultsSummaryProps = {
  /** Rows shown after search, filters and scope. */
  shown: number;
  /** Every row the list could show; null while unknown. */
  total?: number | null;
  /** Plural noun: "findings", "command runs". */
  noun: string;
  /** The order shown, from describeSort: "Started, newest first". */
  sort?: string;
  /** `total` counts only the loaded rows of a windowed ledger ("1,000+"). */
  partial?: boolean;
  className?: string;
};

/**
 * The line above or below a list: "18 of 25 findings · Sorted by Severity,
 * most severe first". The count is never a silent cap: a windowed ledger says
 * so with "+".
 */
export function ResultsSummary({ shown, total, noun, sort, partial, className }: ResultsSummaryProps) {
  const count = (value: number) => value.toLocaleString("en-US");
  return (
    <p className={["ui-results-summary", className].filter(Boolean).join(" ")} role="status">
      <strong>{count(shown)}</strong>
      {total != null && <> of <strong>{count(total)}{partial ? "+" : ""}</strong></>} {noun}
      {sort && <span className="ui-results-sort"> · Sorted by {sort}</span>}
    </p>
  );
}
