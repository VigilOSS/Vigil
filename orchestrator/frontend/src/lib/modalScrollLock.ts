// Body scroll lock used by every DetailModal (Issue 1).
//
// Multiple modals may mount/unmount in quick succession (e.g. tab switch
// with a stale selection). A boolean toggle is fragile because the last
// unmount wins — a stale close would clear the class even if a new modal
// is still open. Instead, maintain a reference count and only remove the
// class when the count reaches zero.
//
// The count lives on the window so HMR or multiple bundle copies share it.

import { useEffect } from "react";

const CLASS_NAME = "detail-modal-open";
const COUNT_KEY = "__aithModalOpenCount";

type GlobalWithCount = typeof window & { [COUNT_KEY]?: number };

function readCount(): number {
  const g = window as GlobalWithCount;
  return g[COUNT_KEY] ?? 0;
}

function writeCount(next: number): void {
  const g = window as GlobalWithCount;
  g[COUNT_KEY] = next;
}

/** Increment the open count; apply the body class on first open. */
export function acquireScrollLock(): void {
  const next = readCount() + 1;
  writeCount(next);
  if (next === 1) {
    document.body.classList.add(CLASS_NAME);
  }
}

/** Decrement the open count; remove the body class when the last modal closes. */
export function releaseScrollLock(): void {
  const cur = readCount();
  const next = Math.max(0, cur - 1);
  writeCount(next);
  if (next === 0) {
    document.body.classList.remove(CLASS_NAME);
  }
}

/**
 * React hook wrapper. Call from inside a DetailModal's render. Runs the
 * acquire/release pair in a useEffect so the cleanup always fires on
 * unmount — React guarantees the effect cleanup runs for every matched
 * setup, which keeps the reference count balanced even if an ancestor
 * component throws after the effect mounts.
 */
export function useBodyScrollLock(active: boolean = true): void {
  useEffect(() => {
    if (!active) return undefined;
    acquireScrollLock();
    return () => {
      releaseScrollLock();
    };
  }, [active]);
}
