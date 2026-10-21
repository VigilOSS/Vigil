// A loaded window over a server-ordered ledger (newest first): the newest
// page, plus every older page read since. Tabs whose filters run in the
// browser (Commands, HTTP) load the ledger this way instead of capping it at
// one page: a refresh re-reads only the newest page and keeps the older pages
// it still lines up with, and `loadOlder` reads the next page past the loaded
// edge — from the list, or when a record steps or deep-links beyond it
// (`useWindowedNavigation`).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { createCoalescedRunner } from "../../lib/coalesce";

export type LedgerWindow<T> = {
  /** Loaded rows in ledger order; null until the first page loads. */
  rows: T[] | null;
  /** Every row of the ledger is loaded (a page came back short). */
  complete: boolean;
  /** A first or explicit load of the newest page is in flight. */
  loading: boolean;
  /** The last read of the newest page failed; loaded rows stay. */
  error: string | null;
  /** An older page is being read. */
  extending: boolean;
  /** The last read of an older page failed. */
  extendError: string | null;
  /**
   * Re-read the newest page and keep the older pages it still lines up with.
   * Overlapping calls coalesce: one read in flight, one re-read after it;
   * every caller's promise settles once the last read has.
   */
  refresh: (showLoading?: boolean) => Promise<void>;
  /** Read the page after the loaded rows. */
  loadOlder: () => Promise<void>;
};

type Loaded<T> = { rows: T[]; complete: boolean };

/**
 * Merges a fresh newest page into the loaded window. Older rows survive when
 * the page's last row is among them (nothing between the two is missing); a
 * row that moved into the newest page is kept once, at its new place. When
 * more than a page of rows arrived since, the window starts over from the
 * newest page.
 */
function mergeLedgerHead<T>(
  head: T[],
  previous: Loaded<T> | null,
  pageSize: number,
  keyOf: (row: T) => string | number,
): Loaded<T> {
  if (head.length < pageSize) return { rows: head, complete: true };
  const last = keyOf(head[head.length - 1]);
  const at = previous ? previous.rows.findIndex((row) => keyOf(row) === last) : -1;
  if (!previous || at < 0) return { rows: head, complete: false };
  const headKeys = new Set(head.map(keyOf));
  const older = previous.rows.slice(at + 1).filter((row) => !headKeys.has(keyOf(row)));
  return { rows: older.length > 0 ? [...head, ...older] : head, complete: previous.complete };
}

function failureText(failure: unknown, fallback: string): string {
  return failure instanceof Error && failure.message ? failure.message : fallback;
}

export function useLedgerWindow<T>({
  identity,
  pageSize,
  fetchPage,
  keyOf,
  failureMessage,
  enabled = true,
}: {
  /** Everything the ledger order depends on (engagement, server filters); a change starts over. */
  identity: string;
  pageSize: number;
  fetchPage: (offset: number, limit: number) => Promise<T[]>;
  keyOf: (row: T) => string | number;
  /** Error text when a read fails without a message. */
  failureMessage: string;
  /** False holds the window empty and reads nothing (a view not in use). */
  enabled?: boolean;
}): LedgerWindow<T> {
  const [loaded, setLoaded] = useState<(Loaded<T> & { identity: string }) | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [extending, setExtending] = useState(false);
  const [extendError, setExtendError] = useState<string | null>(null);

  const identityRef = useRef(identity);
  identityRef.current = identity;
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;
  const keyRef = useRef(keyOf);
  keyRef.current = keyOf;
  const messageRef = useRef(failureMessage);
  messageRef.current = failureMessage;
  const loadedRef = useRef(loaded);
  loadedRef.current = loaded;
  const enabledRef = useRef(enabled);
  enabledRef.current = enabled;
  const extendingRef = useRef(false);

  // Reads of the newest page share lib/coalesce.ts's rule: one in flight, and
  // refreshes meanwhile fold into one more read after it. A pass shows the
  // loading state when any request folded into it asked to.
  const showLoadingRef = useRef(false);
  const readHead = useMemo(() => createCoalescedRunner(async () => {
    const showLoading = showLoadingRef.current;
    showLoadingRef.current = false;
    const id = identityRef.current;
    if (showLoading) setLoading(true);
    try {
      const page = await fetchRef.current(0, pageSize);
      if (id === identityRef.current) {
        setLoaded((previous) => ({
          identity: id,
          ...mergeLedgerHead(page, previous?.identity === id ? previous : null, pageSize, keyRef.current),
        }));
        setError(null);
        setExtendError(null);
      }
    } catch (failure) {
      if (id === identityRef.current) setError(failureText(failure, messageRef.current));
    } finally {
      if (showLoading && id === identityRef.current) setLoading(false);
    }
  }), [pageSize]);

  const refresh = useCallback(async (showLoading = false) => {
    if (!enabledRef.current) return;
    if (showLoading) showLoadingRef.current = true;
    await readHead();
  }, [readHead]);

  const loadOlder = useCallback(async () => {
    const current = loadedRef.current;
    const id = identityRef.current;
    if (extendingRef.current || !current || current.identity !== id || current.complete) return;
    extendingRef.current = true;
    setExtending(true);
    setExtendError(null);
    try {
      const page = await fetchRef.current(current.rows.length, pageSize);
      if (id !== identityRef.current) return;
      const keyOfRow = keyRef.current;
      const known = new Set(current.rows.map(keyOfRow));
      if (page.length === pageSize && page.every((row) => known.has(keyOfRow(row)))) {
        // More than a page of newer rows arrived since the window was read:
        // the offset no longer reaches past it. Re-read the newest page (it
        // restarts the window and clears this error) before going further.
        setExtendError("Newer results arrived while loading older ones; try again.");
        void refresh();
        return;
      }
      const edge = keyOfRow(current.rows[current.rows.length - 1]);
      setLoaded((previous) => {
        if (!previous || previous.identity !== id) return previous;
        // A refresh restarted the window meanwhile: this page no longer
        // continues it, and appending it would leave a gap.
        if (previous.rows.length === 0 || keyOfRow(previous.rows[previous.rows.length - 1]) !== edge) return previous;
        const keys = new Set(previous.rows.map(keyOfRow));
        const added = page.filter((row) => !keys.has(keyOfRow(row)));
        return { identity: id, rows: added.length > 0 ? [...previous.rows, ...added] : previous.rows, complete: page.length < pageSize };
      });
    } catch (failure) {
      if (id === identityRef.current) setExtendError(failureText(failure, messageRef.current));
    } finally {
      extendingRef.current = false;
      setExtending(false);
    }
  }, [pageSize, refresh]);

  useEffect(() => {
    setError(null);
    setExtendError(null);
    if (enabled) void refresh(true);
  }, [identity, enabled, refresh]);

  const current = enabled && loaded?.identity === identity ? loaded : null;
  return {
    rows: current?.rows ?? null,
    complete: current?.complete ?? false,
    loading: enabled && loading,
    error: enabled ? error : null,
    extending,
    extendError,
    refresh,
    loadOlder,
  };
}
