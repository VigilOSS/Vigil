// ── RecordView ────────────────────────────────────────────────────────
// The one detail view every workspace tab opens a record in. It replaces the
// tab's list inside the workspace panel (the rail and page header stay), so a
// finding, a run, or a coverage item reads and behaves the same way:
//
//   top bar   "← Back to results"              "N of M results  ← Previous  Next →"
//   header    ID chip + copy · actions, title, pills, dated facts
//   tabs      the record's sections, with counts
//   body      the active section
//
// The tab owns the data, the list order, and the URL; this module owns layout,
// keyboard behaviour (Escape returns, [ / ] step), focus (the record heading on
// open, the originating row and scroll position on return), and copy actions.
// `useResultsScrollMemory` keeps the hidden results' inner scroll positions
// (grid viewports) for the return trip and lands it on the record last shown.

import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode, type RefObject } from "react";
import { Check, Copy, Link as LinkIcon } from "lucide-react";

import { useToast } from "../../contexts/ToastContext";
import { CopyChip } from "../drawer/DrawerKit";
import { TimeStamp } from "../formatting";
import type { StatusTone } from "../ui/statusTones";
import "../../styles/ui.css";
import "../../styles/record.css";

/** Where the open record sits in the tab's current filtered and sorted results. */
export type RecordNavigation = {
  /** 0-based position; null when the record is outside the current results; undefined while it is being located. */
  index: number | null | undefined;
  /** Size of the current results; undefined while unknown. */
  total: number | null | undefined;
  /** Open the record before this one; omit at the first record. */
  onPrevious?: () => void;
  /** Open the record after this one; omit at the last record. */
  onNext?: () => void;
  /**
   * A neighbour lookup is in flight: the step buttons stay focusable but
   * inert until it settles, so keyboard focus is not dropped mid-walk.
   */
  pending?: boolean;
  /** The record could not be located; stepping is unavailable. */
  error?: string;
  /**
   * `total` counts only the loaded results of a windowed list; more exist
   * beyond them, so the count reads "N of M+".
   */
  partialTotal?: boolean;
  /** Loading results past the loaded edge failed; stepping there again retries. */
  stepError?: string;
};

const PARTIAL_TOTAL_HINT = "Counted among the loaded results; stepping past the last one loads more.";

function recordPositionText({ index, total, error, partialTotal }: Pick<RecordNavigation, "index" | "total" | "error" | "partialTotal">): string {
  if (error) return "Position in results unavailable";
  if (index === null) return "Outside current results";
  if (index === undefined || total == null) return "Locating in results…";
  return `${(index + 1).toLocaleString()} of ${total.toLocaleString()}${partialTotal ? "+" : ""} results`;
}

const TYPING_TARGET = "input, textarea, select, [contenteditable]:not([contenteditable='false'])";
// Widgets that read printable keys themselves (type-ahead).
const KEY_WIDGET_TARGET = "[role='combobox'], [role='listbox'], [role='grid'], [role='tree']";

type RecordViewProps = {
  /** Accessible name of the record region, e.g. "Finding investigation". */
  label: string;
  /** Singular noun for the step buttons: "finding" → "Previous finding". */
  noun: string;
  navigation: RecordNavigation;
  /** Return to the results (the tab clears its selection and URL). */
  onBack: () => void;
  /** Id of the record heading (RecordHeader `titleId`); it takes focus on open. */
  titleId: string;
  /**
   * Element to focus when the record closes. Defaults to whatever had focus
   * when the record opened (the row that opened it).
   */
  returnFocusRef?: RefObject<HTMLElement | null>;
  className?: string;
  children: ReactNode;
};

export function RecordView({ label, noun, navigation, onBack, titleId, returnFocusRef, className, children }: RecordViewProps) {
  const regionRef = useRef<HTMLElement | null>(null);
  const backRef = useRef(onBack);
  backRef.current = onBack;
  const navigationRef = useRef(navigation);
  navigationRef.current = navigation;

  // Open: remember where the operator came from, then move to the record.
  // Close (unmount): if focus was lost with the record, return to the row
  // (useResultsScrollMemory has already put the results' scroll back). A tab
  // switch disconnects the row, so nothing is restored then.
  const headingRef = useRef<HTMLElement | null>(null);
  useLayoutEffect(() => {
    const active = document.activeElement;
    const opener = returnFocusRef?.current ?? (active instanceof HTMLElement && active !== document.body ? active : null);
    const region = regionRef.current;
    const heading = document.getElementById(titleId);
    headingRef.current = heading;
    (heading && region?.contains(heading) ? heading : region)?.focus({ preventScroll: true });
    region?.scrollIntoView?.({ block: "start", behavior: "instant" });
    return () => {
      queueMicrotask(() => {
        const target = returnFocusRef?.current ?? opener;
        if (!target?.isConnected) return;
        const current = document.activeElement;
        if (current && current !== document.body && current.isConnected) return;
        target.focus({ preventScroll: true });
      });
    };
    // Runs once per open: stepping between records keeps the view mounted.
  }, []);

  // Stepping replaces the record's content. When focus was inside the old
  // record (its heading, a section tab) it would fall to the page; carry it to
  // the new record's heading instead.
  useLayoutEffect(() => {
    const heading = document.getElementById(titleId);
    if (!heading || heading === headingRef.current) return;
    headingRef.current = heading;
    const current = document.activeElement;
    if (!current || current === document.body || !current.isConnected) heading.focus({ preventScroll: true });
  });

  // Reaching the first or last record disables the step button just used;
  // a disabled button drops focus to the page. Hand it to the other step
  // button (or the heading when both are disabled).
  const previousRef = useRef<HTMLButtonElement | null>(null);
  const nextRef = useRef<HTMLButtonElement | null>(null);
  useLayoutEffect(() => {
    const active = document.activeElement;
    for (const [button, other] of [[previousRef.current, nextRef.current], [nextRef.current, previousRef.current]]) {
      if (!button || active !== button || !button.disabled) continue;
      const target = other && !other.disabled ? other : document.getElementById(titleId);
      target?.focus({ preventScroll: true });
      return;
    }
  });

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.key !== "Escape" && event.key !== "[" && event.key !== "]") return;
      // A dialog over the record (a command palette) handles its own keys.
      if (document.querySelector('[aria-modal="true"]')) return;
      const target = event.target instanceof HTMLElement ? event.target : null;
      if (target?.closest(TYPING_TARGET)) return;
      if (event.key === "Escape") {
        event.preventDefault();
        backRef.current();
        return;
      }
      if (target?.closest(KEY_WIDGET_TARGET)) return;
      const { onPrevious, onNext, pending } = navigationRef.current;
      const step = event.key === "[" ? onPrevious : onNext;
      if (!step || pending) return;
      event.preventDefault();
      step();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const { onPrevious, onNext, pending } = navigation;
  const position = recordPositionText(navigation);
  const nounTitle = noun.charAt(0).toUpperCase() + noun.slice(1);
  return (
    <section ref={regionRef} className={`findings-redesign record-view${className ? ` ${className}` : ""}`} aria-label={label} tabIndex={-1}>
      <div className="record-topbar">
        <button type="button" className="ghost-button" onClick={onBack} aria-label="Back to results" title="Back to results (Esc)">
          ← Back to results
        </button>
        <div className="record-nav" role="group" aria-label={`${nounTitle} review navigation`}>
          {navigation.stepError && <span className="error-text record-nav-error" role="alert">{navigation.stepError}</span>}
          <span className="meta-text" aria-live="polite" title={navigation.error ?? (navigation.partialTotal ? PARTIAL_TOTAL_HINT : undefined)}>{position}</span>
          <button
            ref={previousRef}
            type="button"
            className="ghost-button"
            onClick={() => { if (!pending) onPrevious?.(); }}
            disabled={!pending && !onPrevious}
            aria-disabled={pending || !onPrevious}
            aria-label={`Previous ${noun}`}
            title={`Previous ${noun} ([)`}
          >
            ← Previous
          </button>
          <button
            ref={nextRef}
            type="button"
            className="ghost-button"
            onClick={() => { if (!pending) onNext?.(); }}
            disabled={!pending && !onNext}
            aria-disabled={pending || !onNext}
            aria-label={`Next ${noun}`}
            title={`Next ${noun} (])`}
          >
            Next →
          </button>
        </div>
      </div>
      {children}
    </section>
  );
}

/** Options for returning from a record to its row in the results. */
export type ResultsReturn = {
  /** Key of the open record (null while the results show). */
  recordKey: string | number | null;
  /**
   * Brings a row the list does not render into the DOM, e.g. a grid's
   * `api.ensureNodeVisible(api.getRowNode(key))` or a pager jump. Called once
   * on return, before the row is looked up.
   */
  reveal?: (key: string) => void;
};

const RETURN_HIGHLIGHT_CLASS = "record-return-highlight";
const RETURN_HIGHLIGHT_MS = 2400;
// Frames to wait for a revealed row and its cells to render (a grid re-lays
// out after it is shown again, or lays out for the first time after a deep link).
const RETURN_LOOKUP_FRAMES = 60;
const FOCUSABLE = "button, a[href], input, select, textarea, [tabindex]";

/**
 * The row of a record inside the results: an element marked
 * `data-record-key`, or an ag-grid row by its row id (`getRowId`).
 */
export function findRecordRow(container: ParentNode, key: string): HTMLElement | null {
  const escaped = typeof CSS !== "undefined" && CSS.escape ? CSS.escape(key) : key.replace(/["\\]/g, "\\$&");
  return container.querySelector<HTMLElement>(`[data-record-key="${escaped}"], .ag-row[row-id="${escaped}"]`);
}

function highlightRow(row: HTMLElement) {
  row.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  row.classList.add(RETURN_HIGHLIGHT_CLASS);
  window.setTimeout(() => row.classList.remove(RETURN_HIGHLIGHT_CLASS), RETURN_HIGHLIGHT_MS);
}

/**
 * Focuses the row (a focusable row, or its first cell or control). False
 * while nothing in it can take focus yet: a grid shown again, or shown for
 * the first time after a deep link, renders a row before its cells.
 */
function focusRow(row: HTMLElement): boolean {
  // A grid row takes focus on its first cell, where the grid's keyboard
  // navigation (arrows, Enter to open) continues from.
  const target = row.classList.contains("ag-row")
    ? row.querySelector<HTMLElement>(".ag-cell")
    : row.matches(FOCUSABLE) ? row : row.querySelector<HTMLElement>(FOCUSABLE);
  if (!target) return false;
  target.focus({ preventScroll: true });
  return document.activeElement === target;
}

/**
 * The results stay mounted (hidden) behind an open record so filters, sort and
 * loaded rows survive, but hiding them loses the page's scroll position and
 * every inner scroller's offset (grid viewports). This remembers both while
 * the results are shown and puts them back when the record closes, before the
 * record view returns focus to the originating row.
 *
 * With `returnTo`, closing the record lands on the record last shown, not the
 * row that opened the first one: after stepping with Previous / Next, or
 * after a deep link that never showed the list, its row is revealed, scrolled
 * into view, focused and briefly highlighted. Rows are found by
 * `data-record-key` or the ag-grid row id; when the row cannot be found the
 * record view's own focus return (the opener) stands.
 */
export function useResultsScrollMemory(resultsRef: RefObject<HTMLElement | null>, recordOpen: boolean, returnTo?: ResultsReturn): void {
  const offsets = useRef(new Map<Element, { top: number; left: number }>());
  const page = useRef<{ x: number; y: number } | null>(null);
  const lastKey = useRef<string | null>(null);
  const revealRef = useRef(returnTo?.reveal);
  revealRef.current = returnTo?.reveal;
  if (returnTo?.recordKey != null) lastKey.current = String(returnTo.recordKey);
  useEffect(() => {
    const root = resultsRef.current;
    if (!root || recordOpen) return undefined;
    page.current = { x: window.scrollX, y: window.scrollY };
    const onScroll = (event: Event) => {
      const target = event.target;
      if (target instanceof Element && root.contains(target)) {
        offsets.current.set(target, { top: target.scrollTop, left: target.scrollLeft });
      } else if (target === document || target === window) {
        page.current = { x: window.scrollX, y: window.scrollY };
      }
    };
    // Scroll does not bubble; listen in the capture phase.
    window.addEventListener("scroll", onScroll, true);
    return () => window.removeEventListener("scroll", onScroll, true);
  }, [resultsRef, recordOpen]);
  const wasOpen = useRef(recordOpen);
  useLayoutEffect(() => {
    let frame: number | null = null;
    if (wasOpen.current && !recordOpen) {
      const saved = page.current;
      if (saved && (window.scrollX !== saved.x || window.scrollY !== saved.y)) window.scrollTo(saved.x, saved.y);
      for (const [element, offset] of offsets.current) {
        if (!element.isConnected) {
          offsets.current.delete(element);
          continue;
        }
        if (element.scrollTop !== offset.top) element.scrollTop = offset.top;
        if (element.scrollLeft !== offset.left) element.scrollLeft = offset.left;
      }
      const key = returnTo ? lastKey.current : null;
      const root = resultsRef.current;
      if (key !== null && root) {
        revealRef.current?.(key);
        // Highlight the row as soon as it renders; focus it once something in
        // it can take focus.
        let highlighted: HTMLElement | null = null;
        const land = (): boolean => {
          const row = findRecordRow(root, key);
          if (!row) return false;
          if (row !== highlighted) {
            highlighted = row;
            highlightRow(row);
          }
          return focusRow(row);
        };
        if (!land() && typeof requestAnimationFrame === "function") {
          // A revealed or re-shown grid renders its rows and cells a frame or more later.
          let attempts = 0;
          const retry = () => {
            frame = null;
            // Only take focus the record view handed back to the results or dropped.
            const active = document.activeElement;
            if (active && active !== document.body && !root.contains(active)) return;
            if (land()) return;
            attempts += 1;
            if (attempts < RETURN_LOOKUP_FRAMES) frame = requestAnimationFrame(retry);
          };
          frame = requestAnimationFrame(retry);
        }
      }
    }
    wasOpen.current = recordOpen;
    return () => {
      if (frame !== null) cancelAnimationFrame(frame);
    };
  }, [recordOpen]);
}

// ── Header ────────────────────────────────────────────────────────────

export type RecordDate = {
  label: string;
  value: string | null | undefined;
  /** Shown when the value is missing. */
  fallback?: string;
  /** Extra context after the time, e.g. " · verified by reviewer". */
  detail?: ReactNode;
};

type RecordHeaderProps = {
  /** The record's identity as operators cite it ("VA-12", "Run #7"). */
  id: ReactNode;
  /** Text the ID copy button copies; omit for no copy button. */
  copyId?: string;
  copyIdLabel?: string;
  title: ReactNode;
  titleId: string;
  /**
   * Status tone of the left accent bar: the same color as the record's status
   * pill. Records colored by something other than a status (severity, method)
   * pass `accent` instead.
   */
  tone?: StatusTone;
  /** Color of the left accent bar (a CSS color, usually a token). */
  accent?: string;
  /** Header actions, top right (RecordCopyButton / RecordCopyLinkButton). */
  actions?: ReactNode;
  /** Status pills; put a status's reason right after its pill. */
  pills?: ReactNode;
  dates?: RecordDate[];
  /** Accessible name of the dates group, e.g. "Finding dates". */
  datesLabel?: string;
  /** Notices that belong to the whole record, under the dates. */
  children?: ReactNode;
};

export function RecordHeader({
  id,
  copyId,
  copyIdLabel = "Copy ID",
  title,
  titleId,
  tone,
  accent,
  actions,
  pills,
  dates,
  datesLabel,
  children,
}: RecordHeaderProps) {
  const { toast } = useToast();
  const style = accent ? ({ "--record-accent": accent } as CSSProperties) : undefined;
  return (
    <header className={`record-header${accent || tone ? " has-accent" : ""}`} data-tone={tone} style={style}>
      <div className="record-top">
        <div className="record-id">
          <span>{id}</span>
          {copyId && <CopyChip text={copyId} toast={toast} label={copyIdLabel} />}
        </div>
        {actions && <div className="record-actions">{actions}</div>}
      </div>
      <h2 id={titleId} className="record-title" tabIndex={-1}>{title}</h2>
      {pills && <div className="record-pills">{pills}</div>}
      {dates && dates.length > 0 && (
        <div className="record-dates" role="group" aria-label={datesLabel}>
          {dates.map((date) => (
            <span key={date.label}>
              <span className="record-dates-label">{date.label}</span>{" "}
              <TimeStamp value={date.value} mode="both" fallback={date.fallback ?? "not recorded"} />
              {date.detail && <span className="record-dates-detail">{date.detail}</span>}
            </span>
          ))}
        </div>
      )}
      {children}
    </header>
  );
}

// ── Copy actions ──────────────────────────────────────────────────────

type RecordCopyButtonProps = {
  /** Accessible name and tooltip. */
  label: string;
  /** Produces the text at click time. */
  text: () => string;
  successMessage: string;
  failureMessage: string;
  icon?: ReactNode;
  disabled?: boolean;
};

/**
 * Header copy action: a check mark and a toast confirm the copy. Only the
 * newest click reports, and nothing reports after the record changed (the
 * header remounts per record).
 */
export function RecordCopyButton({ label, text, successMessage, failureMessage, icon, disabled }: RecordCopyButtonProps) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);
  const mounted = useRef(true);
  const request = useRef(0);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      window.clearTimeout(timer.current);
    };
  }, []);
  const copy = async () => {
    const current = ++request.current;
    setCopied(false);
    try {
      if (!navigator.clipboard) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(text());
      if (!mounted.current || current !== request.current) return;
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1500);
      toast(successMessage, "success");
    } catch {
      if (!mounted.current || current !== request.current) return;
      toast(failureMessage, "error");
    }
  };
  return (
    <button type="button" className="copy-btn" onClick={copy} disabled={disabled} title={label} aria-label={label}>
      {copied ? <Check size={13} /> : icon ?? <Copy size={13} />}
    </button>
  );
}

/** Copies the address of the open record (the URL is the record's deep link). */
export function RecordCopyLinkButton({ noun }: { noun: string }) {
  return (
    <RecordCopyButton
      label={`Copy link to this ${noun}`}
      text={() => window.location.href}
      successMessage="Link copied"
      failureMessage="Could not copy link. Copy the address from your browser."
      icon={<LinkIcon size={13} />}
    />
  );
}

// ── Sections ──────────────────────────────────────────────────────────

export type RecordTab<T extends string> = {
  id: T;
  label: string;
  /** Shown beside the label; omit while unknown. */
  count?: number;
  hidden?: boolean;
};

type RecordTabsProps<T extends string> = {
  tabs: RecordTab<T>[];
  active: T;
  onChange: (tab: T) => void;
  /** Accessible name, e.g. "Finding sections". */
  label: string;
  /** Controls for the active section, right-aligned (e.g. a prose view toggle). */
  trailing?: ReactNode;
};

export function RecordTabs<T extends string>({ tabs, active, onChange, label, trailing }: RecordTabsProps<T>) {
  return (
    <div className="record-tabs" role="group" aria-label={label}>
      {tabs.filter((tab) => !tab.hidden).map((tab) => (
        <button
          key={tab.id}
          type="button"
          className={`record-tab${active === tab.id ? " is-active" : ""}`}
          onClick={() => onChange(tab.id)}
          aria-current={active === tab.id ? "page" : undefined}
        >
          {tab.label}
          {tab.count != null && <span className="count">{tab.count.toLocaleString()}</span>}
        </button>
      ))}
      {trailing && <div className="record-tabs-trailing">{trailing}</div>}
    </div>
  );
}

export function RecordBody({ children, busy }: { children: ReactNode; busy?: boolean }) {
  return <div className="record-body" aria-busy={busy || undefined}>{children}</div>;
}
