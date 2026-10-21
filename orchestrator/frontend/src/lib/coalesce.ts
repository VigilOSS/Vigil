// ── Refresh coalescing ────────────────────────────────────────────────
// The one rule every tab's reloads follow: keep one load in flight, and fold
// any refresh that arrives meanwhile into exactly one more pass after it
// settles. Bursts of refresh signals never cancel each other (which could
// starve under 2 s live-update bursts) and every burst still ends on fresh
// data. React callers use the hooks in lib/useCoalescedRequest.ts.

/** What a running pass can ask its runner. */
export type CoalescedPass = {
  /** True once a refresh arrived during this pass, so another pass will follow it. */
  rerunQueued: () => boolean;
};

/**
 * Keep one load in flight. A refresh requested while one runs schedules
 * exactly one more pass after it settles. A "join" request (initial mount,
 * which StrictMode repeats) shares the in-flight load without scheduling more.
 * The returned promise settles after the last queued pass; `onSettled` runs
 * synchronously at that point, before any later call can start a new load.
 */
export function createCoalescedRunner(task: (pass: CoalescedPass) => Promise<void>, onSettled?: () => void) {
  let running: Promise<void> | null = null;
  let again = false;
  const pass: CoalescedPass = { rerunQueued: () => again };
  return function run(mode: "join" | "refresh" = "refresh"): Promise<void> {
    if (running) {
      if (mode === "refresh") again = true;
      return running;
    }
    running = (async () => {
      try {
        do {
          again = false;
          await task(pass);
        } while (again);
      } finally {
        running = null;
        onSettled?.();
      }
    })();
    return running;
  };
}
