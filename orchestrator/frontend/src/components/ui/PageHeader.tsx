import type { ReactNode } from "react";

import type { StatusTone } from "./statusTones";
import "../../styles/ui.css";

export type PageStat = {
  /** A count (grouped with separators) or preformatted text; null or undefined hides the stat. */
  value: number | string | null | undefined;
  /** Unit after the value, lower case: "runs", "need attention". */
  label: string;
  /** Full sentence for hover and assistive technology when the label is terse. */
  title?: string;
  /** Colors the value for counts that need the operator (`warning`, `danger`). */
  tone?: StatusTone;
};

type PageHeaderProps = {
  /** The page name as the rail shows it ("Runs", "Proof work"). */
  title: ReactNode;
  /** One plain sentence: what this page is for. */
  purpose: ReactNode;
  /** Right-aligned summary counts, most important first. */
  stats?: PageStat[];
  /** Short state beside the counts, e.g. "Updating…" or an "Updated 4m ago" TimeStamp. */
  status?: ReactNode;
  /** Page-level actions, right-aligned after the counts (secondary buttons, Jump to…). */
  actions?: ReactNode;
  /** Header content under the title row: a status bar, a view switch, a scope toggle. */
  children?: ReactNode;
  /** Hidden while a record view replaces the page body. */
  hidden?: boolean;
  /** Id for the title (aria-labelledby targets); defaults to none. */
  titleId?: string;
  className?: string;
};

const formatValue = (value: number | string) => (typeof value === "number" ? value.toLocaleString("en-US") : value);

/**
 * The top of every workspace page: title, one-sentence purpose, and on the
 * right the page's summary counts and actions. Same size and spacing on every
 * tab, and compact so the content starts high on the page.
 *
 *   <PageHeader
 *     title="Runs"
 *     purpose="Each run is one evidence-gathering session by an agent; open one to see what it tested and what it proved."
 *     stats={[{ value: 40, label: "runs" }, { value: 12, label: "need attention", tone: "warning" }]}
 *     status={loading ? "Updating…" : null}
 *     hidden={recordOpen}
 *   />
 */
export function PageHeader({ title, purpose, stats, status, actions, children, hidden, titleId, className }: PageHeaderProps) {
  const shownStats = (stats ?? []).filter((stat): stat is PageStat & { value: number | string } => stat.value != null && stat.value !== "");
  const hasSide = shownStats.length > 0 || status || actions;
  return (
    <header className={["ui-page-header", className].filter(Boolean).join(" ")} hidden={hidden}>
      <div className="ui-page-header-row">
        <div className="ui-page-header-text">
          <h1 className="ui-page-title" id={titleId}>{title}</h1>
          <p className="ui-page-purpose">{purpose}</p>
        </div>
        {hasSide && (
          <div className="ui-page-header-side">
            {shownStats.length > 0 && (
              <ul className="ui-page-stats" aria-label="Summary">
                {shownStats.map((stat) => (
                  <li key={stat.label} title={stat.title} data-tone={stat.tone}>
                    <strong>{formatValue(stat.value)}</strong> {stat.label}
                    {stat.title && <span className="sr-only">: {stat.title}</span>}
                  </li>
                ))}
              </ul>
            )}
            {status && <span className="ui-page-status" role="status">{status}</span>}
            {actions && <div className="ui-page-actions">{actions}</div>}
          </div>
        )}
      </div>
      {children && <div className="ui-page-header-body">{children}</div>}
    </header>
  );
}
