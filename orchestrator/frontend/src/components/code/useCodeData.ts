// The Code view loads its own data. Summary sources (repositories, queue
// counts, coverage, review progress, readiness) load on mount and on every refresh; heavier
// per-section sources load only while their section is open (a lane's later
// pages and the results list load in their own components). Each source is
// single-flight (lib/coalesce): a refresh that arrives mid-request folds into
// one follow-up load, and the previous value stays on screen until the new one
// lands. Live updates reach the view through the tab's throttled refresh token
// (lib/useLiveRefreshToken).

import { useCallback, useEffect, useRef, useState } from "react";

import { createCoalescedRunner } from "../../lib/coalesce";

import {
  getCodeCoverage,
  getCodeQueueStats,
  getCodeReadiness,
  listCodeModules,
  listCodeRepos,
  type CodeCoverage,
  type CodeModule,
  type CodeQueuePage,
  type CodeQueueStats,
  type CodeReadiness,
  type CodeReadinessTarget,
  type CodeRepo,
} from "../../lib/api";
import {
  listCodeQueueLane,
  listCodeRepoReviewProgress,
  type CodeQueueLane,
  type CodeRepoReviewProgress,
} from "../../lib/codeApi";
import type { CodeView } from "./codeLabels";

export const QUEUE_LANES: CodeQueueLane[] = ["error", "needs_context", "processing", "pending"];
/** Jobs per lane page; every page is reachable (CodeQueue pages past the first). */
export const QUEUE_LANE_PAGE = 10;

export type CodeData = {
  repos: CodeRepo[] | null;
  queueStats: CodeQueueStats | null;
  coverage: CodeCoverage | null;
  readiness: CodeReadiness | null;
  completion: CodeReadiness | null;
  progress: CodeRepoReviewProgress[] | null;
  modules: CodeModule[] | null;
  lanes: Record<CodeQueueLane, CodeQueuePage> | null;
};

export type CodeSource = keyof CodeData;

const EMPTY: CodeData = {
  repos: null,
  queueStats: null,
  coverage: null,
  readiness: null,
  completion: null,
  progress: null,
  modules: null,
  lanes: null,
};

const SOURCE_LABELS: Record<CodeSource, string> = {
  repos: "repositories",
  queueStats: "review queue counts",
  coverage: "coverage",
  readiness: "next-transition readiness",
  completion: "completion readiness",
  progress: "repository progress",
  modules: "modules",
  lanes: "review jobs",
};

const VIEW_SOURCES: Partial<Record<CodeView, CodeSource[]>> = {
  queue: ["lanes"],
  modules: ["modules"],
};

type Runner = ReturnType<typeof createCoalescedRunner>;

export function useCodeData({
  engagementKey,
  target,
  view,
  refreshVersion,
}: {
  engagementKey: string;
  target: CodeReadinessTarget;
  view: CodeView;
  refreshVersion: number;
}) {
  const [data, setData] = useState<CodeData>(EMPTY);
  const [errors, setErrors] = useState<Partial<Record<CodeSource, string>>>({});
  const [pending, setPending] = useState<ReadonlySet<CodeSource>>(new Set());
  const [manualVersion, setManualVersion] = useState(0);
  // One single-flight runner per source; each pass runs the latest task.
  const runners = useRef(new Map<CodeSource, Runner>());
  const tasks = useRef(new Map<CodeSource, () => Promise<void>>());
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const fetchers = useCallback(
    (source: CodeSource): (() => Promise<CodeData[CodeSource]>) => {
      switch (source) {
        case "repos":
          return () => listCodeRepos(engagementKey);
        case "queueStats":
          return () => getCodeQueueStats(engagementKey);
        case "coverage":
          return () => getCodeCoverage(engagementKey);
        case "readiness":
          return () => getCodeReadiness(engagementKey, target);
        case "completion":
          return () => getCodeReadiness(engagementKey, "complete");
        case "progress":
          return () => listCodeRepoReviewProgress(engagementKey);
        case "modules":
          return () => listCodeModules(engagementKey);
        case "lanes":
          return async () => {
            const pages = await Promise.all(
              QUEUE_LANES.map((status) => listCodeQueueLane(engagementKey, status, { limit: QUEUE_LANE_PAGE, offset: 0 })),
            );
            return Object.fromEntries(QUEUE_LANES.map((lane, index) => [lane, pages[index]])) as Record<
              CodeQueueLane,
              CodeQueuePage
            >;
          };
      }
    },
    [engagementKey, target],
  );

  const load = useCallback(
    (source: CodeSource) => {
      const fetcher = fetchers(source);
      const task = async () => {
        // A pass queued before unmount has nothing left to update.
        if (!mounted.current) return;
        setPending((current) => new Set(current).add(source));
        try {
          const value = await fetcher();
          if (!mounted.current) return;
          setData((current) => ({ ...current, [source]: value }));
          setErrors((current) => {
            if (!(source in current)) return current;
            const next = { ...current };
            delete next[source];
            return next;
          });
        } catch (error: unknown) {
          if (!mounted.current) return;
          const detail = error instanceof Error ? error.message : "request failed";
          setErrors((current) => ({ ...current, [source]: `${SOURCE_LABELS[source]}: ${detail}` }));
        } finally {
          if (mounted.current) {
            setPending((current) => {
              const next = new Set(current);
              next.delete(source);
              return next;
            });
          }
        }
      };
      tasks.current.set(source, task);
      let runner = runners.current.get(source);
      if (!runner) {
        runner = createCoalescedRunner(() => tasks.current.get(source)!());
        runners.current.set(source, runner);
      }
      void runner("refresh");
    },
    [fetchers],
  );

  const sameTarget = target === "complete";
  // Each trigger loads once: a development StrictMode re-run of the same
  // effect with the same trigger would otherwise queue a duplicate read.
  const summaryTrigger = useRef<string | null>(null);
  const sectionTrigger = useRef<string | null>(null);
  // Summary sources: mount, refresh, and an explicit reload.
  useEffect(() => {
    const trigger = `${engagementKey}|${target}|${refreshVersion}|${manualVersion}`;
    if (summaryTrigger.current === trigger) return;
    summaryTrigger.current = trigger;
    load("repos");
    load("queueStats");
    load("coverage");
    // Progress explains why finished review jobs do not count as reviewed
    // files, next to the reviewed count every section shows.
    load("progress");
    load("readiness");
    if (!sameTarget) load("completion");
  }, [load, engagementKey, target, sameTarget, refreshVersion, manualVersion]);

  // Section sources: while their section is open, on the same triggers.
  useEffect(() => {
    const trigger = `${engagementKey}|${target}|${view}|${refreshVersion}|${manualVersion}`;
    if (sectionTrigger.current === trigger) return;
    sectionTrigger.current = trigger;
    for (const source of VIEW_SOURCES[view] ?? []) load(source);
  }, [load, engagementKey, target, view, refreshVersion, manualVersion]);

  const reload = useCallback(() => setManualVersion((value) => value + 1), []);
  const completion = sameTarget ? data.readiness : data.completion;
  return {
    data: { ...data, completion },
    errors: Object.values(errors),
    errorBySource: errors,
    pending,
    reload,
  };
}
