// Body scroll lock used by every DetailModal (Issue 1).
//
// Multiple modals may mount/unmount in quick succession (e.g. tab switch
// with a stale selection). A boolean toggle is fragile because the last
// unmount wins — a stale close would clear the class even if a new modal
// is still open. Instead, maintain a reference count and only remove the
// class when the count reaches zero.
//
// The count lives on the window so HMR or multiple bundle copies share it.

import { useEffect, useRef, type RefObject } from "react";

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

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "details > summary:first-of-type",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

const modalPanels: HTMLElement[] = [];

function isExposed(element: HTMLElement): boolean {
  if (element.closest('[hidden], [inert], [aria-hidden="true"]')) return false;
  for (let ancestor: HTMLElement | null = element; ancestor; ancestor = ancestor.parentElement) {
    if (ancestor instanceof HTMLDetailsElement && !ancestor.open) {
      const summary = ancestor.querySelector(":scope > summary");
      if (!summary?.contains(element)) return false;
    }
  }
  return true;
}

function focusableElements(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    isExposed,
  );
}

/** Keep keyboard focus inside a modal and restore it when the modal closes. */
export function useModalFocus(
  panelRef: RefObject<HTMLElement | null>,
  onClose: () => void,
  active: boolean = true,
  returnFocusRef?: RefObject<HTMLElement | null>,
): void {
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    if (!active) return undefined;
    const panel = panelRef.current;
    if (!panel) return undefined;
    const priorFocus = returnFocusRef?.current ?? document.activeElement;
    modalPanels.push(panel);
    let lastFocusedInside: HTMLElement = panel;

    const onFocusIn = (event: FocusEvent) => {
      if (modalPanels.at(-1) !== panel || !panel.isConnected) return;
      const target = event.target;
      if (target instanceof HTMLElement && panel.contains(target)) {
        lastFocusedInside = target;
        return;
      }
      const destination = lastFocusedInside.isConnected
        && panel.contains(lastFocusedInside)
        && isExposed(lastFocusedInside)
        ? lastFocusedInside : panel;
      destination.focus();
    };

    queueMicrotask(() => {
      if (modalPanels.at(-1) !== panel || !panel.isConnected || panel.contains(document.activeElement)) return;
      panel.focus();
    });

    const onKeyDown = (event: KeyboardEvent) => {
      if (modalPanels.at(-1) !== panel) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;

      const focusable = focusableElements(panel);
      if (focusable.length === 0) {
        event.preventDefault();
        panel.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const current = document.activeElement;
      if (
        event.shiftKey
        && (current === panel || current === first || !panel.contains(current))
      ) {
        event.preventDefault();
        last.focus();
      } else if (
        !event.shiftKey
        && (current === panel || current === last || !panel.contains(current))
      ) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("focusin", onFocusIn);
      const wasTop = modalPanels.at(-1) === panel;
      const index = modalPanels.indexOf(panel);
      if (index >= 0) modalPanels.splice(index, 1);
      if (wasTop && priorFocus instanceof HTMLElement && priorFocus.isConnected) priorFocus.focus();
    };
  }, [active, panelRef, returnFocusRef]);
}
