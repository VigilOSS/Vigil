import type { ReactNode } from "react";
import { Inbox, SearchX } from "lucide-react";
import "../../styles/ui.css";

type EmptyStateBase = {
  /** One sentence naming what is missing: "No command runs recorded yet." */
  title: ReactNode;
  /** What fills this list, or why it may be empty (plain text, short). */
  children?: ReactNode;
  /** A further action beside Clear filters (e.g. "Show all probes"). */
  action?: ReactNode;
  /** Tighter spacing for empty panes inside a card or a record section. */
  compact?: boolean;
  className?: string;
};

type EmptyStateProps =
  | (EmptyStateBase & {
      /** Nothing has been recorded for this engagement yet. */
      variant: "empty";
    })
  | (EmptyStateBase & {
      /** Records exist, but none match the current search, filters or scope. */
      variant: "filtered";
      onClearFilters: () => void;
      /** Defaults to "Clear filters". */
      clearLabel?: string;
    });

/**
 * The one empty state. It always says which case applies: nothing recorded
 * yet (`empty`), or nothing matching what the operator chose (`filtered`,
 * which always offers Clear filters). Never show the filtered wording when no
 * filter is set.
 *
 *   <EmptyState variant="empty" title="No command runs recorded yet.">Agents record each tool call here.</EmptyState>
 *   <EmptyState variant="filtered" title="No command runs match these filters." onClearFilters={clearAll} />
 */
export function EmptyState(props: EmptyStateProps) {
  const { title, children, action, compact, className, variant } = props;
  const Icon = variant === "filtered" ? SearchX : Inbox;
  return (
    <div
      className={["ui-empty", compact ? "ui-empty-compact" : null, className].filter(Boolean).join(" ")}
      data-variant={variant}
      role="status"
    >
      <Icon className="ui-empty-icon" size={compact ? 18 : 22} aria-hidden="true" />
      <p className="ui-empty-title">{title}</p>
      {children && <div className="ui-empty-detail">{children}</div>}
      {(variant === "filtered" || action) && (
        <div className="ui-empty-actions">
          {variant === "filtered" && (
            <button type="button" className="ui-button" onClick={props.onClearFilters}>
              {props.clearLabel ?? "Clear filters"}
            </button>
          )}
          {action}
        </div>
      )}
    </div>
  );
}
