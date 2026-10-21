// React forms of the shared refresh coalescing (lib/coalesce.ts):
//
//   useCoalescedRunner   a stable runner for a tab's own load task
//   useCoalescedRequest  keyed data with loading / error state
//
// A slow load says so with the shared SlowLoadHint (components/Skeletons.tsx),
// which keeps its own timer.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { createCoalescedRunner } from "./coalesce.ts";

/**
 * createCoalescedRunner as a hook: one runner per component that always runs
 * the latest `task` (one pass) and, when given, the latest `onSettled` once
 * the last queued pass finishes. Call it with "join" for the mount load
 * (StrictMode repeats it) and "refresh" (the default) for refresh signals.
 */
export function useCoalescedRunner(task: () => Promise<void>, onSettled?: () => void) {
  const latest = useRef({ task, onSettled });
  latest.current = { task, onSettled };
  return useMemo(() => createCoalescedRunner(
    () => latest.current.task(),
    () => latest.current.onSettled?.(),
  ), []);
}

export type CoalescedRequestState<T> = {
  data: T | null;
  /** The key `data` was loaded for (may lag the current key while reloading). */
  dataKey: string | null;
  error: string | null;
  loading: boolean;
};

/**
 * Load `key` with at most one request in flight. A key change or `reloadToken`
 * bump while a request runs queues exactly one follow-up with the latest
 * loader, so refresh bursts coalesce without starving. A response for a key
 * that is no longer current is discarded; previous data stays visible while
 * the next one loads. Nothing loads while `enabled` is false.
 */
export function useCoalescedRequest<T>(
  key: string,
  load: () => Promise<T>,
  reloadToken = 0,
  enabled = true,
): CoalescedRequestState<T> {
  const latest = useRef({ key, load });
  latest.current = { key, load };
  const mounted = useRef(true);
  const [state, setState] = useState<CoalescedRequestState<T>>({
    data: null,
    dataKey: null,
    error: null,
    loading: true,
  });

  const run = useMemo(() => createCoalescedRunner(
    async ({ rerunQueued }) => {
      // A pass queued before unmount has nothing left to update.
      if (!mounted.current) return;
      const { key: requestKey, load: requestLoad } = latest.current;
      setState((current) => (current.loading ? current : { ...current, loading: true }));
      try {
        const data = await requestLoad();
        if (mounted.current && requestKey === latest.current.key) {
          setState({ data, dataKey: requestKey, error: null, loading: rerunQueued() });
        }
      } catch (error) {
        if (mounted.current && requestKey === latest.current.key) {
          const message = error instanceof Error ? error.message : String(error);
          setState((current) => ({ ...current, error: message, loading: rerunQueued() }));
        }
      }
    },
    () => {
      if (mounted.current) {
        setState((current) => (current.loading ? { ...current, loading: false } : current));
      }
    },
  ), []);
  const refresh = useCallback(() => {
    void run("refresh");
  }, [run]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (enabled) refresh();
  }, [key, reloadToken, enabled, refresh]);

  return state;
}
