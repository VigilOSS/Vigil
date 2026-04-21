import { useCallback, useEffect, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";

// ── useResizableColumns ──────────────────────────────────────────────
// Persist column widths (in px) to localStorage, clamp to per-column
// minimums, and expose a pointer-based drag handler. Dragging uses
// pointer capture so the drag continues even when the cursor leaves the
// tiny handle element.
//
// Returned `gridTemplate` is a space-joined list of "<px>px" values,
// suitable for inline style on both the header and each row so they stay
// aligned.
//
// Double-clicking a handle (see `resetColumn`) resets that column to its
// default width. The caller should wire `resetColumn` via
// `onDoubleClick` on the same handle element.

function readStored(storageKey: string, defaults: number[]): number[] {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return defaults.slice();
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return defaults.slice();
    if (parsed.length !== defaults.length) return defaults.slice();
    const out: number[] = [];
    for (let i = 0; i < defaults.length; i += 1) {
      const v = parsed[i];
      out.push(typeof v === "number" && Number.isFinite(v) ? v : defaults[i]);
    }
    return out;
  } catch {
    return defaults.slice();
  }
}

function writeStored(storageKey: string, widths: number[]): void {
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(widths));
  } catch {
    // ignore — quota / private-mode
  }
}

export function useResizableColumns(
  storageKey: string,
  defaults: number[],
  minWidths?: number[],
): {
  widths: number[];
  gridTemplate: string;
  startResize: (colIndex: number, e: ReactPointerEvent) => void;
  resetColumn: (colIndex: number) => void;
} {
  const mins = (minWidths && minWidths.length === defaults.length
    ? minWidths
    : defaults.map(() => 60)
  ).slice();

  const [widths, setWidths] = useState<number[]>(() =>
    readStored(storageKey, defaults),
  );

  // If defaults length changes across reloads (e.g. a new column was
  // added), reseed to defaults. We intentionally do not pick this up on
  // every render — only when the length diverges.
  const lenRef = useRef<number>(defaults.length);
  useEffect(() => {
    if (widths.length !== defaults.length) {
      setWidths(defaults.slice());
      lenRef.current = defaults.length;
    }
  }, [defaults, widths.length]);

  // Persist after every change.
  useEffect(() => {
    writeStored(storageKey, widths);
  }, [storageKey, widths]);

  const startResize = useCallback(
    (colIndex: number, e: ReactPointerEvent) => {
      if (colIndex < 0 || colIndex >= defaults.length) return;
      e.preventDefault();
      e.stopPropagation();
      const target = e.currentTarget as HTMLElement;
      try {
        target.setPointerCapture(e.pointerId);
      } catch {
        // ignore — some browsers / non-pointer inputs
      }
      const startX = e.clientX;
      const startWidth = widths[colIndex] ?? defaults[colIndex];
      const min = mins[colIndex] ?? 60;

      const onMove = (ev: PointerEvent) => {
        const delta = ev.clientX - startX;
        const next = Math.max(min, Math.round(startWidth + delta));
        setWidths((cur) => {
          if (cur[colIndex] === next) return cur;
          const copy = cur.slice();
          copy[colIndex] = next;
          return copy;
        });
      };

      const onUp = (ev: PointerEvent) => {
        try {
          target.releasePointerCapture(ev.pointerId);
        } catch {
          // ignore
        }
        target.removeEventListener("pointermove", onMove);
        target.removeEventListener("pointerup", onUp);
        target.removeEventListener("pointercancel", onUp);
      };

      target.addEventListener("pointermove", onMove);
      target.addEventListener("pointerup", onUp);
      target.addEventListener("pointercancel", onUp);
    },
    // mins/defaults are stable per-call-site (caller should pass module-
    // level arrays), so we only depend on the current widths.
    [widths, defaults, mins],
  );

  const resetColumn = useCallback(
    (colIndex: number) => {
      if (colIndex < 0 || colIndex >= defaults.length) return;
      setWidths((cur) => {
        const copy = cur.slice();
        copy[colIndex] = defaults[colIndex];
        return copy;
      });
    },
    [defaults],
  );

  const gridTemplate = widths.map((w) => `${w}px`).join(" ");

  return { widths, gridTemplate, startResize, resetColumn };
}
