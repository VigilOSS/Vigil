// @vitest-environment jsdom

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { useMemo, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useLedgerWindow } from "./ledgerWindow";
import { useWindowedNavigation, windowedReviewOrder, type GridSort, type WindowGrowth } from "./recordNavigation";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

type Row = { id: number; even: boolean };
const key = (row: Row) => row.id;

// A ledger newest first: ids count down from `size`.
function ledgerOf(size: number): Row[] {
  return Array.from({ length: size }, (_, index) => ({ id: size - index, even: (size - index) % 2 === 0 }));
}

function pager(rows: () => Row[]) {
  return vi.fn((offset: number, limit: number) => Promise.resolve(rows().slice(offset, offset + limit)));
}

describe("useLedgerWindow refresh", () => {
  const rows = (...ids: number[]) => ids.map((id) => ({ id, even: id % 2 === 0 }));

  // A window over the whole of `initial`, three rows a page; `setLedger` changes what the server holds.
  async function loadedWindow(initial: Row[]) {
    let ledger = initial;
    const fetchPage = vi.fn((offset: number, limit: number) => Promise.resolve(ledger.slice(offset, offset + limit)));
    const hook = renderHook(() => useLedgerWindow({ identity: "acme", pageSize: 3, fetchPage, keyOf: key, failureMessage: "failed" }));
    await waitFor(() => expect(hook.result.current.rows).not.toBeNull());
    while (!hook.result.current.complete) await act(() => hook.result.current.loadOlder());
    const refreshWith = async (next: Row[]) => {
      ledger = next;
      await act(() => hook.result.current.refresh());
      return { rows: hook.result.current.rows, complete: hook.result.current.complete };
    };
    return refreshWith;
  }

  it("keeps the older pages a fresh newest page still lines up with", async () => {
    const refreshWith = await loadedWindow(rows(6, 5, 4, 3, 2, 1));
    // Two new rows arrived: the page now ends inside the loaded rows.
    expect(await refreshWith(rows(8, 7, 6, 5, 4, 3, 2, 1))).toEqual({ rows: rows(8, 7, 6, 5, 4, 3, 2, 1), complete: true });
    // A row moved to the top (re-seen): kept once, at its new place.
    expect(await refreshWith(rows(3, 8, 7, 6, 5, 4, 2, 1))).toEqual({ rows: rows(3, 8, 7, 6, 5, 4, 2, 1), complete: true });
  });

  it("starts over when more than a page arrived, and ends at a short page", async () => {
    const refreshWith = await loadedWindow(rows(6, 5, 4, 3, 2, 1));
    expect(await refreshWith(rows(12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1))).toEqual({ rows: rows(12, 11, 10), complete: false });
    expect(await refreshWith(rows(2, 1))).toEqual({ rows: rows(2, 1), complete: true });
  });
});

describe("useLedgerWindow", () => {
  it("loads the newest page, then older pages until a short page ends the ledger", async () => {
    let ledger = ledgerOf(5);
    const fetchPage = pager(() => ledger);
    const { result } = renderHook(() => useLedgerWindow({ identity: "acme", pageSize: 2, fetchPage, keyOf: key, failureMessage: "failed" }));
    await waitFor(() => expect(result.current.rows?.map(key)).toEqual([5, 4]));
    expect(result.current.complete).toBe(false);
    await act(() => result.current.loadOlder());
    expect(result.current.rows?.map(key)).toEqual([5, 4, 3, 2]);
    await act(() => result.current.loadOlder());
    expect(result.current.rows?.map(key)).toEqual([5, 4, 3, 2, 1]);
    expect(result.current.complete).toBe(true);
    // A refresh re-reads only the newest page and keeps the rest.
    ledger = ledgerOf(6);
    await act(() => result.current.refresh());
    expect(result.current.rows?.map(key)).toEqual([6, 5, 4, 3, 2, 1]);
    expect(fetchPage).toHaveBeenLastCalledWith(0, 2);
  });

  it("keeps loaded rows when a read fails and reports which read failed", async () => {
    const fetchPage = vi.fn((offset: number) => (offset === 0 ? Promise.resolve(ledgerOf(4).slice(0, 2)) : Promise.reject(new Error("offline"))));
    const { result } = renderHook(() => useLedgerWindow({ identity: "acme", pageSize: 2, fetchPage, keyOf: key, failureMessage: "failed" }));
    await waitFor(() => expect(result.current.rows).not.toBeNull());
    await act(() => result.current.loadOlder());
    expect(result.current.extendError).toBe("offline");
    expect(result.current.rows?.map(key)).toEqual([4, 3]);
    fetchPage.mockImplementationOnce(() => Promise.reject(new Error("head offline")));
    await act(() => result.current.refresh());
    expect(result.current.error).toBe("head offline");
    expect(result.current.rows?.map(key)).toEqual([4, 3]);
  });

  it("folds refreshes during a read into one more read, which its callers wait for", async () => {
    let ledger = ledgerOf(3);
    const releases: Array<() => void> = [];
    const fetchPage = vi.fn((offset: number, limit: number) => new Promise<Row[]>((resolve) => {
      releases.push(() => resolve(ledger.slice(offset, offset + limit)));
    }));
    const { result } = renderHook(() => useLedgerWindow({ identity: "acme", pageSize: 2, fetchPage, keyOf: key, failureMessage: "failed" }));
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(1));
    let queued!: Promise<void>;
    act(() => {
      void result.current.refresh();
      queued = result.current.refresh();
    });
    let settled = false;
    void queued.then(() => { settled = true; });
    ledger = ledgerOf(4);
    await act(async () => releases[0]());
    await waitFor(() => expect(fetchPage).toHaveBeenCalledTimes(2));
    expect(settled).toBe(false);
    await act(async () => { releases[1](); await queued; });
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(result.current.rows?.map(key)).toEqual([4, 3]);
  });

  it("drops an older page that no longer continues a window a refresh restarted", async () => {
    let ledger = ledgerOf(6);
    let release!: () => void;
    const fetchPage = vi.fn((offset: number, limit: number) => {
      const page = ledger.slice(offset, offset + limit);
      return offset === 0 ? Promise.resolve(page) : new Promise<Row[]>((resolve) => { release = () => resolve(page); });
    });
    const { result } = renderHook(() => useLedgerWindow({ identity: "acme", pageSize: 2, fetchPage, keyOf: key, failureMessage: "failed" }));
    await waitFor(() => expect(result.current.rows?.map(key)).toEqual([6, 5]));
    let older!: Promise<void>;
    act(() => { older = result.current.loadOlder(); });
    // Many new rows arrive and a refresh restarts the window meanwhile.
    ledger = ledgerOf(20);
    await act(() => result.current.refresh());
    expect(result.current.rows?.map(key)).toEqual([20, 19]);
    await act(async () => { release(); await older; });
    expect(result.current.rows?.map(key)).toEqual([20, 19]);
  });
});

describe("windowedReviewOrder", () => {
  it("places older rows by the grid's sort", () => {
    const growsAt = (sort: GridSort[]) => windowedReviewOrder([1, 2], { ids: [1, 2], sort }, "time").growsAt;
    expect(growsAt([])).toBe("end");
    expect(growsAt([{ colId: "time", sort: "desc" }])).toBe("end");
    expect(growsAt([{ colId: "time", sort: "asc" }])).toBe("start");
    expect(growsAt([{ colId: "tool", sort: "asc" }])).toBe("both");
  });

  it("walks the filtered rows in ledger order until the grid shows them all", () => {
    expect(windowedReviewOrder([3, 2, 1], { ids: [2, 3], sort: [{ colId: "time", sort: "asc" }] }, "time")).toEqual({ order: [3, 2, 1], growsAt: "end" });
    expect(windowedReviewOrder([3, 2], { ids: [1, 2, 3], sort: [{ colId: "time", sort: "asc" }] }, "time")).toEqual({ order: [2, 3], growsAt: "start" });
  });
});

// A tab in miniature: a ledger loaded two rows a page, an "even ids only"
// filter, and one open record.
function useMiniTab(fetchPage: (offset: number, limit: number) => Promise<Row[]>, initial: number | null, { evenOnly = false, growsAt = "end" as WindowGrowth } = {}) {
  const window = useLedgerWindow({ identity: "acme", pageSize: 2, fetchPage, keyOf: key, failureMessage: "failed" });
  const [open, setOpen] = useState<number | null>(initial);
  const rows = window.rows ?? [];
  const order = useMemo(() => {
    const shown = (window.rows ?? []).filter((row) => !evenOnly || row.even).map(key);
    return growsAt === "start" ? [...shown].reverse() : shown;
  }, [window.rows, evenOnly, growsAt]);
  const navigation = useWindowedNavigation({
    order,
    current: open,
    loaded: rows.some((row) => row.id === open),
    window,
    growsAt,
    open: setOpen,
  });
  return { window, navigation, open, setOpen };
}

describe("useWindowedNavigation", () => {
  it("counts the loaded results as a lower bound and steps past the loaded edge", async () => {
    const rows = ledgerOf(9);
    const { result } = renderHook(() => useMiniTab(pager(() => rows), 8, { evenOnly: true }));
    await waitFor(() => expect(result.current.navigation.index).toBe(0));
    // Loaded: 9, 8 → shown: 8.
    expect(result.current.navigation).toMatchObject({ total: 1, partialTotal: true, onPrevious: undefined });
    act(() => result.current.navigation.onNext?.());
    expect(result.current.navigation.pending).toBe(true);
    // 7, 6 load; 6 matches and opens.
    await waitFor(() => expect(result.current.open).toBe(6));
    expect(result.current.navigation).toMatchObject({ index: 1, total: 2, partialTotal: true, pending: false });
    act(() => result.current.navigation.onPrevious?.());
    expect(result.current.open).toBe(8);
  });

  it("reads to the end of the ledger when no further result exists, then stops", async () => {
    const rows = ledgerOf(5);
    const { result } = renderHook(() => useMiniTab(pager(() => rows), 2, { evenOnly: true }));
    // A deep link to an older row: older pages load until it is found.
    await waitFor(() => expect(result.current.navigation.index).toBe(1));
    expect(result.current.window.rows?.map(key)).toEqual([5, 4, 3, 2]);
    act(() => result.current.navigation.onNext?.());
    await waitFor(() => expect(result.current.window.complete).toBe(true));
    expect(result.current.open).toBe(2);
    expect(result.current.navigation).toMatchObject({ index: 1, total: 2, partialTotal: false, onNext: undefined, pending: false });
  });

  it("steps backwards into older rows when the shown order is oldest first", async () => {
    const rows = ledgerOf(4);
    const { result } = renderHook(() => useMiniTab(pager(() => rows), 3, { growsAt: "start" }));
    // Shown oldest first: 3, 4.
    await waitFor(() => expect(result.current.navigation.index).toBe(0));
    expect(result.current.navigation.onNext).toBeDefined();
    act(() => result.current.navigation.onPrevious?.());
    await waitFor(() => expect(result.current.open).toBe(2));
    expect(result.current.navigation).toMatchObject({ index: 1, total: 4 });
  });

  it("says when a record is not in the ledger, and when loading older rows fails", async () => {
    const rows = ledgerOf(3);
    const { result } = renderHook(() => useMiniTab(pager(() => rows), 42));
    await waitFor(() => expect(result.current.window.complete).toBe(true));
    expect(result.current.navigation).toMatchObject({ index: null, total: 3 });

    const failing = ledgerOf(6);
    const fetchFailing = pager(() => failing);
    const second = renderHook(() => useMiniTab(fetchFailing, 6, { evenOnly: true }));
    await waitFor(() => expect(second.result.current.navigation.index).toBe(0));
    fetchFailing.mockImplementation(() => Promise.reject(new Error("offline")));
    act(() => second.result.current.navigation.onNext?.());
    await waitFor(() => expect(second.result.current.navigation.stepError).toBe("Could not load older results: offline"));
    expect(second.result.current.navigation).toMatchObject({ index: 0, pending: false });
    expect(second.result.current.open).toBe(6);
  });
});
