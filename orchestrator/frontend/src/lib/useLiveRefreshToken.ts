import { useEffect, useRef, useState } from "react";

/**
 * Throttles the workspace refresh signal (live updates, and the page's own
 * re-read when the browser tab is shown again) into a local token: a change
 * refreshes at once, a burst refreshes at most once per `minIntervalMs`, and
 * the last change of a burst gets one trailing refresh. The version the view
 * mounted with is not a change.
 */
export function useLiveRefreshToken(refreshVersion: number | undefined, minIntervalMs: number): number {
  const [token, setToken] = useState(0);
  const lastRefresh = useRef(0);
  const firstVersion = useRef(refreshVersion);
  useEffect(() => {
    if (refreshVersion === firstVersion.current) return undefined;
    const run = () => {
      lastRefresh.current = Date.now();
      setToken((current) => current + 1);
    };
    const wait = lastRefresh.current + minIntervalMs - Date.now();
    if (wait <= 0) {
      run();
      return undefined;
    }
    const timer = window.setTimeout(run, wait);
    return () => window.clearTimeout(timer);
  }, [refreshVersion, minIntervalMs]);
  return token;
}
