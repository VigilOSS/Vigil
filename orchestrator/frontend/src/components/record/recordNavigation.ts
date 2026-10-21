// Record navigation sources for RecordView's "N of M" and Previous / Next.
//
// `listNavigation` walks a list the tab already holds in display order (after
// its filters and the grid's sort). `useRecordPosition` asks the server where
// the open record sits when the list is paged (only a window of rows is ever
// loaded), so stepping crosses page and block boundaries instead of stopping
// at the edge of what happens to be loaded. `useWindowedNavigation` walks a
// list filtered in the browser over a loaded ledger window (ledgerWindow.ts):
// stepping past the loaded edge, or opening a record beyond it, reads older
// pages until the neighbour or the record turns up.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { createCoalescedRunner } from "../../lib/coalesce";
import type { LedgerWindow } from "./ledgerWindow";
import type { RecordNavigation } from "./RecordView";

/** Navigation over the tab's current results, in the order they are shown. */
export function listNavigation<K>(order: readonly K[], current: K | null | undefined, open: (key: K) => void): RecordNavigation {
  const index = current == null ? -1 : order.indexOf(current);
  if (index < 0) return { index: null, total: order.length };
  return {
    index,
    total: order.length,
    onPrevious: index > 0 ? () => open(order[index - 1]) : undefined,
    onNext: index < order.length - 1 ? () => open(order[index + 1]) : undefined,
  };
}

/** A paged list's answer to "where is this record, and what is beside it". */
export type RecordPosition<T> = {
  /** 0-based; null when the record does not match the current filters. */
  index: number | null;
  total: number;
  previous: T | null;
  next: T | null;
};

type Settled<T> = { key: string; identity: string; position: RecordPosition<T> };

/**
 * Server-located navigation for the open record `key`. `identity` names
 * everything the order depends on (filters, sort, refresh signal). For the
 * same record a change re-locates it through one coalesced lookup (lib/
 * coalesce.ts): the lookup in flight always settles, and any changes that
 * arrived meanwhile fold into exactly one more, so live refreshes faster than
 * the server answers never starve it. Until the re-locate answers, the last
 * answer for the record stays on screen and its neighbours stay steppable.
 * Opening another record supersedes the lookup for the old one. Stepping to a
 * neighbour shows its expected position immediately and settles when the
 * server answers.
 */
export function useRecordPosition<T>({
  key,
  identity,
  load,
  keyOf,
  open,
}: {
  key: string | null;
  identity: string;
  load: () => Promise<RecordPosition<T>>;
  keyOf: (item: T) => string;
  open: (item: T) => void;
}): RecordNavigation {
  const [settled, setSettled] = useState<Settled<T> | null>(null);
  const [failure, setFailure] = useState<{ key: string; identity: string; message: string } | null>(null);
  const latest = useRef({ key, identity, load });
  latest.current = { key, identity, load };
  const openRef = useRef(open);
  openRef.current = open;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // One coalesced lookup per open record. A pass asks with the order current
  // when it starts; an answer for a record no longer open is dropped.
  const locate = useMemo(() => createCoalescedRunner(async () => {
    const { key: requestKey, identity: requestIdentity, load: requestLoad } = latest.current;
    if (requestKey === null || requestKey !== key || !mounted.current) return;
    try {
      const position = await requestLoad();
      if (!mounted.current || latest.current.key !== requestKey) return;
      setSettled({ key: requestKey, identity: requestIdentity, position });
      setFailure(null);
    } catch (error) {
      if (!mounted.current || latest.current.key !== requestKey) return;
      setFailure({ key: requestKey, identity: requestIdentity, message: error instanceof Error ? error.message : "Position unavailable" });
    }
  }), [key]);

  // StrictMode repeats the mount effect; the repeat joins the lookup in flight.
  const requested = useRef<{ locate: typeof locate; identity: string } | null>(null);
  useEffect(() => {
    if (key === null) return;
    const repeat = requested.current?.locate === locate && requested.current.identity === identity;
    requested.current = { locate, identity };
    void locate(repeat ? "join" : "refresh");
  }, [key, identity, locate]);

  if (key === null) return { index: undefined, total: undefined };
  const current = settled?.key === key;
  const failed = failure?.key === key && failure.identity === identity;
  // A failed re-locate keeps the last answer for this record.
  if (failed && !current) return { index: undefined, total: undefined, error: failure.message };
  if (current) {
    const { position } = settled;
    const previous = position.previous;
    const next = position.next;
    return {
      index: position.index,
      total: position.total,
      onPrevious: previous ? () => openRef.current(previous) : undefined,
      onNext: next ? () => openRef.current(next) : undefined,
      pending: false,
    };
  }
  // Stepped from the settled record to one of its neighbours: its position is known.
  if (settled && settled.position.index !== null) {
    const { index, total, previous, next } = settled.position;
    if (next && keyOf(next) === key) return { index: index + 1, total, pending: true };
    if (previous && keyOf(previous) === key) return { index: index - 1, total, pending: true };
  }
  return { index: undefined, total: undefined, pending: true };
}

// ── Windowed lists ────────────────────────────────────────────────────

/** Where rows not loaded yet would land in the shown order. */
export type WindowGrowth = "end" | "start" | "both";

export type GridSort = { colId: string; sort: "asc" | "desc" };

/** What a grid shows: its row order after its own sort, and that sort. */
export type GridView<K> = { ids: K[]; sort: GridSort[] };

type GridModel<T> = {
  forEachNodeAfterFilterAndSort: (callback: (node: { data?: T }) => void) => void;
  getColumnState: () => { colId: string; sort?: "asc" | "desc" | null; sortIndex?: number | null }[];
};

/** Reads a grid's view from its API (call it from `onModelUpdated`). */
export function readGridView<T, K>(api: GridModel<T>, keyOf: (row: T) => K): GridView<K> {
  const ids: K[] = [];
  api.forEachNodeAfterFilterAndSort((node) => { if (node.data) ids.push(keyOf(node.data)); });
  const sort = api.getColumnState()
    .filter((column): column is { colId: string; sort: "asc" | "desc"; sortIndex?: number | null } => Boolean(column.sort))
    .sort((a, b) => (a.sortIndex ?? 0) - (b.sortIndex ?? 0))
    .map((column) => ({ colId: column.colId, sort: column.sort }));
  return { ids, sort };
}

/**
 * The last view a grid reported, kept by identity while it is unchanged so
 * order-dependent work does not re-run on every grid model update.
 */
export function useGridView<K>(): [GridView<K> | null, (view: GridView<K>) => void] {
  const [view, setView] = useState<GridView<K> | null>(null);
  const report = useCallback((next: GridView<K>) => {
    setView((previous) => previous
      && previous.ids.length === next.ids.length
      && previous.ids.every((id, index) => id === next.ids[index])
      && previous.sort.length === next.sort.length
      && previous.sort.every((entry, index) => entry.colId === next.sort[index].colId && entry.sort === next.sort[index].sort)
      ? previous
      : next);
  }, []);
  return [view, report];
}

/**
 * The order Previous / Next walk for a windowed list: the grid's order once
 * it covers the filtered rows (a deep link opens the record before the hidden
 * grid lays out), else the filtered rows in ledger order.
 */
export function windowedReviewOrder<K>(filtered: readonly K[], view: GridView<K> | null, timeColumn: string): { order: K[]; growsAt: WindowGrowth } {
  const visible = new Set(filtered);
  const shown = view?.ids.filter((id) => visible.has(id));
  if (view && shown && shown.length === visible.size) return { order: shown, growsAt: windowGrowthForSort(view.sort, timeColumn) };
  return { order: [...filtered], growsAt: "end" };
}

/**
 * Where older rows land under a grid sort, for a ledger loaded newest first.
 * Unsorted (ledger order) or newest first on the ledger's time column: after
 * the last row. Oldest first: before the first. Any other column: anywhere.
 */
function windowGrowthForSort(sort: readonly GridSort[], timeColumn: string): WindowGrowth {
  if (sort.length === 0) return "end";
  if (sort.length === 1 && sort[0].colId === timeColumn) return sort[0].sort === "desc" ? "end" : "start";
  return "both";
}

type WindowedStep<K> = { from: K; direction: -1 | 1; attempted: boolean };

/**
 * Navigation over a list filtered in the browser from a loaded ledger window.
 * `order` is the shown order of the loaded rows that match the filters (keep
 * its identity stable between renders). While older rows are unloaded the
 * count reads "N of M+", and a step past an edge where they would land reads
 * older pages until a neighbour appears or the ledger ends. A record opened
 * from outside the loaded rows (a deep link) reads older pages until it loads.
 */
export function useWindowedNavigation<K>({
  order,
  current,
  loaded,
  window,
  growsAt,
  open,
}: {
  order: readonly K[];
  /** The open record; null when the list shows. */
  current: K | null;
  /** The open record is among the loaded rows, whether or not it matches the filters. */
  loaded: boolean;
  /** The ledger window the list is filtered from. */
  window: Pick<LedgerWindow<unknown>, "rows" | "complete" | "extending" | "extendError" | "loadOlder">;
  growsAt: WindowGrowth;
  open: (key: K) => void;
}): RecordNavigation {
  const { rows, complete, extending, extendError, loadOlder } = window;
  const [step, setStep] = useState<WindowedStep<K> | null>(null);
  const openRef = useRef(open);
  openRef.current = open;

  // A step belongs to the record it started from.
  useEffect(() => {
    setStep((pending) => (pending && pending.from !== current ? null : pending));
  }, [current]);

  // Opened beyond the loaded rows: read older pages until the record loads.
  const locating = current !== null && rows !== null && !loaded && !complete && extendError === null;
  useEffect(() => {
    if (locating && !extending) void loadOlder();
  }, [locating, extending, rows, loadOlder]);

  // Stepped past the loaded edge: read older pages until a neighbour appears
  // on that side, the ledger ends, or a read fails.
  useEffect(() => {
    if (!step) return;
    const index = order.indexOf(step.from);
    if (index < 0) {
      setStep(null);
      return;
    }
    const target = index + step.direction;
    if (target >= 0 && target < order.length) {
      setStep(null);
      openRef.current(order[target]);
      return;
    }
    if (complete || (step.attempted && extendError !== null)) {
      setStep(null);
      return;
    }
    if (extending || rows === null) return;
    void loadOlder();
    if (!step.attempted) setStep({ ...step, attempted: true });
  }, [step, order, rows, complete, extending, extendError, loadOlder]);

  if (current === null || rows === null) return { index: undefined, total: undefined };
  if (!loaded) {
    if (extendError !== null) return { index: undefined, total: undefined, error: extendError };
    if (!complete) return { index: undefined, total: undefined, pending: true };
    // The whole ledger is loaded and the record is not in it.
    return { index: null, total: order.length };
  }
  const partialTotal = !complete;
  const index = order.indexOf(current);
  if (index < 0) return { index: null, total: order.length, partialTotal };
  const growsBefore = !complete && growsAt !== "end";
  const growsAfter = !complete && growsAt !== "start";
  return {
    index,
    total: order.length,
    partialTotal,
    onPrevious: index > 0
      ? () => open(order[index - 1])
      : growsBefore ? () => setStep({ from: current, direction: -1, attempted: false }) : undefined,
    onNext: index < order.length - 1
      ? () => open(order[index + 1])
      : growsAfter ? () => setStep({ from: current, direction: 1, attempted: false }) : undefined,
    pending: step !== null,
    stepError: extendError === null ? undefined : `Could not load older results: ${extendError}`,
  };
}
