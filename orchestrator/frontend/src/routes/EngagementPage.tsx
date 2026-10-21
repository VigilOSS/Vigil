import { useCallback, useEffect, useEffectEvent, useMemo, useRef, useState } from "react";

import { FileDown } from "lucide-react";

import {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFindingDetail,
  AssessmentFindingSummary,
  AssessmentSurface,
  ApiError,
  AssessmentSummary,
  CodeQueueStats,
  Engagement,
  IntelSummary,
  ProofWorkList,
  engagementWebSocketUrl,
  exportReport,
  getAssessmentSummary,
  getCodeQueueStats,
  getEngagement,
  getIntelReadiness,
  getIntelSummary,
  listAssessmentAttackChainLinks,
  listAssessmentAttackChains,
  listAssessmentFindingSummaries,
  listAssessmentFindings,
  listAssessmentRuns,
  listOobProbes,
  listProofWork,
  listSurfaces,
  reportDownloadUrl,
} from "../lib/api";
import { DEFAULT_COMMAND_FILTERS, fetchCommandFacets } from "../lib/commandsApi";
import { listSubmissionDesk } from "../lib/submissionsApi";
import { countCallbacksToReview } from "../lib/oastApi";
import { proofNeedsAttentionCount } from "../lib/proofWorkApi";
import { ALL_LIVE_SCOPES, INITIAL_SCOPE_VERSIONS, bumpScopes, scopeVersion, scopesForMessage, type LiveScope, type ScopeVersions } from "../lib/liveScopes";
import { railBadges, type RailBadgeInputs } from "../lib/railBadges";
import { RUN_ATTENTION_HEALTH, collectBarePages, runHealth, type RunHealthKey } from "../lib/runAudit";
import { ActivityTab } from "../components/ActivityTab";
import { CodeAnalysisTab } from "../components/CodeAnalysisTab";
import { CommandsTab } from "../components/CommandsTab";
import { CoverageTab } from "../components/CoverageTab";
import { FilesTab } from "../components/FilesTab";
import { FindingRuntimeProof } from "../components/FindingRuntimeProof";
import { FindingsTab } from "../components/FindingsTab";
import { HttpTab } from "../components/HttpTab";
import { IntelTab } from "../components/IntelTab";
import { OastTab } from "../components/OastTab";
import { OverviewTab } from "../components/OverviewTab";
import { ProofWorkTab } from "../components/ProofWorkTab";
import { RunsTab } from "../components/RunsTab";
import { SurfacesTab } from "../components/SurfacesTab";
import { SubmissionsTab } from "../components/SubmissionsTab";
import { TabBar, TABS } from "../components/TabBar";
import type { TabKey } from "../components/TabBar";
import { ThemeToggle } from "../components/ThemeToggle";
import { CardSkeleton, Skeleton, TableSkeleton } from "../components/Skeletons";
import { StatusPill } from "../components/ui";
import { useToast } from "../contexts/ToastContext";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import "../styles/workspace.css";

type EngagementPageProps = {
  engagementKey: string;
  onBack: () => void;
  // Deep-link entry params (see App.parseEngagementRoute). Applied on first
  // mount and re-applied whenever the PARSED ROUTE VALUES change (e.g. a
  // hashchange while this engagement is already mounted) via the sync effects
  // below. A normal manual tab click / drawer open does not change these
  // props, so it is never reverted; FindingsTab's route rewrite
  // reproduces the same values for the active selection, so the sync is
  // idempotent (compare-before-set guards against a redundant render).
  initialTab?: string;
  initialFindingSlug?: string;
  // Open record section (`dtab`) for a deep-linked finding, run, or coverage item.
  initialDrawerTab?: string;
  initialIntelType?: string;
  initialIntelId?: number;
  initialRequestVariantId?: number;
  initialRunId?: number;
  initialRunSection?: string;
  initialRunObject?: string;
  // Proof work item to highlight (?tab=proof&work=…).
  initialWorkId?: number;
  // Command run to open (?tab=commands&command=…).
  initialCommandId?: number;
  initialSurfaceId?: number;
  initialProbeId?: number;
  initialFlowId?: number;
  // Coverage item whose record is open (?tab=coverage&item=…).
  initialCoverageItemId?: number;
  // Submission whose document is open (?tab=submissions&submission=…&dtab=…).
  initialSubmissionSlug?: string;
  // Engagement file open in the viewer (?tab=artifacts&file=…).
  initialFileName?: string;
  // Activity search, categories (comma-separated), actor kind and time range
  // (?tab=activity&q=…&cats=…&actor=…&range=…).
  initialActivityQuery?: string;
  initialActivityCategories?: string;
  initialActivityActor?: string;
  initialActivityRange?: string;
  // HTTP sub-view (?tab=http&view=inventory|exchanges).
  initialHttpView?: string;
};

const SURFACE_FETCH_LIMIT = 5000;
const RUN_PAGE_SIZE = 200;
// WebSocket messages arrive in bursts; refresh at most once per window.
const WS_THROTTLE_MS = 2000;
// Polling cadence while the live socket is down.
const POLL_INTERVAL_MS = 30_000;
// Rail badge sources refresh at most this often (the assessment summary can
// take tens of seconds when its cache is cold).
const BADGE_INTERVAL_MS = 15_000;
const SUBMISSIONS_BADGE_INTERVAL_MS = 60_000;
// Run health without the Runs view open reads the whole run list.
const RUNS_BADGE_INTERVAL_MS = 60_000;
// A command run can change the run list only through the evidence health of
// a run receipt that cites it (its retained output), which is rare; the open
// Runs view folds command changes into one re-read this long after the first.
const RUNS_COMMAND_DELAY_MS = 60_000;

// The live scopes each view's `refreshVersion` follows (lib/liveScopes.ts).
// Activity and Files follow every change: the audit log records every
// mutation, and engagement-root files are written outside the API. Runs
// follows command changes only after RUNS_COMMAND_DELAY_MS (see below).
const VIEW_SCOPES: Record<TabKey, readonly LiveScope[]> = {
  overview: ALL_LIVE_SCOPES,
  findings: ["findings"],
  proof: ["proof", "findings"],
  submissions: ["submissions", "findings"],
  intel: ["intel"],
  surfaces: ["surfaces"],
  http: ["http", "surfaces"],
  coverage: ["coverage"],
  code: ["code"],
  runs: ["runs"],
  commands: ["commands"],
  oast: ["oast"],
  activity: ALL_LIVE_SCOPES,
  artifacts: ALL_LIVE_SCOPES,
};
const RUNTIME_PROOF_SCOPES: readonly LiveScope[] = ["findings", "proof", "runs"];
const READINESS_SCOPES: readonly LiveScope[] = ["readiness"];

const HTTP_VIEWS = new Set(["inventory", "exchanges"]);

type RefreshChannel = {
  task: () => Promise<void>;
  minIntervalMs: number;
  inFlight: boolean;
  queued: boolean;
  lastStartedAt: number;
  timer: ReturnType<typeof setTimeout> | null;
};

// Independent single-flight loads keyed by data source. A request that
// arrives while the same source is loading folds into one follow-up load, so
// a slow source (the summary) never stacks requests and never delays another
// source or a tab's own refresh. A "join" request shares an in-flight load
// instead of queueing another (the mount refresh, which StrictMode repeats).
class CoalescedLoads {
  private channels = new Map<string, RefreshChannel>();
  private disposed = false;

  run(name: string, task: () => Promise<void>, minIntervalMs = 0, mode: "join" | "rerun" = "rerun") {
    if (this.disposed) return;
    let channel = this.channels.get(name);
    if (!channel) {
      channel = { task, minIntervalMs, inFlight: false, queued: false, lastStartedAt: 0, timer: null };
      this.channels.set(name, channel);
    }
    channel.task = task;
    channel.minIntervalMs = minIntervalMs;
    if (channel.inFlight) {
      if (mode === "rerun") channel.queued = true;
      return;
    }
    const wait = channel.lastStartedAt + minIntervalMs - Date.now();
    if (wait > 0) {
      // Trailing load so the last change inside the interval is not lost.
      channel.timer ??= setTimeout(() => {
        channel.timer = null;
        this.run(name, channel.task, channel.minIntervalMs);
      }, wait);
      return;
    }
    if (channel.timer !== null) {
      clearTimeout(channel.timer);
      channel.timer = null;
    }
    channel.inFlight = true;
    channel.queued = false;
    channel.lastStartedAt = Date.now();
    void channel.task().catch(() => undefined).finally(() => {
      channel.inFlight = false;
      if (channel.queued) {
        channel.queued = false;
        this.run(name, channel.task, channel.minIntervalMs);
      }
    });
  }

  // Stops new loads and pending trailing timers. In-flight state is kept so
  // a development StrictMode remount (dispose, then revive) joins the load
  // already running instead of starting a duplicate.
  dispose() {
    this.disposed = true;
    for (const channel of this.channels.values()) {
      if (channel.timer !== null) clearTimeout(channel.timer);
      channel.timer = null;
      channel.queued = false;
    }
  }

  revive() {
    this.disposed = false;
  }
}

function errorText(error: unknown, fallback = "request failed"): string {
  return error instanceof Error ? error.message : error == null ? fallback : String(error);
}

const VALID_TAB_KEYS = new Set<string>(TABS.map((t) => t.key));

function coerceTabKey(value: string | undefined): TabKey {
  // Bookmarked audit-log links open the merged Activity view.
  if (value === "log") return "activity";
  return value && VALID_TAB_KEYS.has(value) ? (value as TabKey) : "overview";
}

function hasCodeTrack(engagement: Engagement): boolean {
  return Boolean(engagement.track_state?.code) || engagement.engagement_type === "code" || engagement.engagement_type === "both";
}

export function EngagementPage(props: EngagementPageProps) {
  return <EngagementWorkspace key={props.engagementKey} {...props} />;
}

function EngagementWorkspace({
  engagementKey,
  onBack,
  initialTab,
  initialFindingSlug,
  initialDrawerTab,
  initialIntelType,
  initialIntelId,
  initialRequestVariantId,
  initialRunId,
  initialRunSection,
  initialRunObject,
  initialWorkId,
  initialCommandId,
  initialSurfaceId,
  initialProbeId,
  initialFlowId,
  initialCoverageItemId,
  initialSubmissionSlug,
  initialFileName,
  initialActivityQuery,
  initialActivityCategories,
  initialActivityActor,
  initialActivityRange,
  initialHttpView,
}: EngagementPageProps) {
  const { toast } = useToast();
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  // Honor a deep-linked tab on first mount (lazy init); the sync effect below
  // re-applies it when the parsed route's `tab` actually changes.
  const [activeTab, setActiveTab] = useState<TabKey>(() => coerceTabKey(initialTab));
  // A deep-linked finding only makes sense on the findings tab. Capture it
  // once; FindingsTab consumes it to auto-open the drawer, then clears it
  // (via the tab-switch handler below) so navigating away drops the param.
  const [pendingFindingSlug, setPendingFindingSlug] = useState<string | undefined>(
    coerceTabKey(initialTab) === "findings" ? initialFindingSlug : undefined,
  );
  // The deep-linked drawer-tab (?dtab=…), forwarded to FindingsTab so a copied
  // link opens the drawer on the intended pane. Same findings-tab gate as the
  // pending slug above.
  const [pendingDrawerTab, setPendingDrawerTab] = useState<string | undefined>(
    coerceTabKey(initialTab) === "findings" ? initialDrawerTab : undefined,
  );
  const [assessmentSummary, setAssessmentSummary] = useState<AssessmentSummary | null>(null);
  // The full finding ledger (Findings) and its lean rows without `details`
  // (Overview, Surfaces). Each keeps the findings-scope version it was read
  // at, so the views show whichever is fresher.
  const [assessmentFindings, setAssessmentFindings] = useState<{ rows: AssessmentFindingDetail[]; version: number } | null>(null);
  const [findingSummaries, setFindingSummaries] = useState<{ rows: AssessmentFindingSummary[]; version: number } | null>(null);
  const [findingRowsError, setFindingRowsError] = useState<string | null>(null);
  const [assessmentChains, setAssessmentChains] = useState<AssessmentAttackChainDetail[]>([]);
  const [assessmentChainLinks, setAssessmentChainLinks] = useState<AssessmentAttackChainLink[]>([]);
  // Per-scope refresh counters; each view's refreshVersion sums the scopes it reads.
  const [scopeVersions, setScopeVersions] = useState<ScopeVersions>(INITIAL_SCOPE_VERSIONS);
  const [intelSummary, setIntelSummary] = useState<IntelSummary | null>(null);
  // Null until the surface ledger first loads, so Surfaces can tell loading from empty.
  const [assessmentSurfaces, setAssessmentSurfaces] = useState<AssessmentSurface[] | null>(null);
  const [surfaceLoadError, setSurfaceLoadError] = useState<string | null>(null);
  // Rail badge inputs beyond the summary (see lib/railBadges.ts).
  const [proofNeedsAttention, setProofNeedsAttention] = useState<RailBadgeInputs["proofNeedsAttention"]>(null);
  const [submissionsToDo, setSubmissionsToDo] = useState<number | null>(null);
  const [openIntelLeads, setOpenIntelLeads] = useState<number | null>(null);
  const [codeQueueStats, setCodeQueueStats] = useState<CodeQueueStats | null>(null);
  const [oastToReview, setOastToReview] = useState<number | null>(null);
  const [runHealthCounts, setRunHealthCounts] = useState<Record<RunHealthKey, number> | null>(null);
  const [commandsNeedingAttention, setCommandsNeedingAttention] = useState<number | null>(null);
  // The commands-scope pass the open Runs view last folded in (RUNS_COMMAND_DELAY_MS).
  const [runsCommandVersion, setRunsCommandVersion] = useState(0);
  const runsCommandTimerRef = useRef<number | null>(null);
  const [exportingReport, setExportingReport] = useState(false);
  // Failed refreshes by data source. `loadError` is the engagement record
  // itself; a dropped live socket is tracked separately in `liveUpdates`
  // because polling keeps the data current while it reconnects.
  const [refreshErrors, setRefreshErrors] = useState<Record<string, string>>({});
  const [liveUpdates, setLiveUpdates] = useState<"connecting" | "live" | "polling">("connecting");
  const activeEngagement = engagement?.key === engagementKey ? engagement : null;
  const loadsRef = useRef<CoalescedLoads | null>(null);
  const hasLoadedOnceRef = useRef(false);
  // Scopes changed since the last refresh pass; the mount pass reads everything.
  const pendingScopesRef = useRef(new Set<LiveScope>(ALL_LIVE_SCOPES));
  // Synchronous mirror of `scopeVersions` for the loaders below.
  const scopeVersionsRef = useRef<ScopeVersions>(INITIAL_SCOPE_VERSIONS);
  // Page datasets by name → the scope version they were last read at; a view
  // re-reads a dataset only when its scope moved since.
  const datasetVersionsRef = useRef(new Map<string, number>());
  const socketConnectedRef = useRef(false);
  const hasConnectedOnceRef = useRef(false);
  // Tracks whether the live feed has dropped since the last successful open,
  // so the reconnect toast fires on recovery but not on the first connect.
  const liveFeedDroppedRef = useRef(false);
  const lastWsRefreshRef = useRef(0);
  const wsThrottleTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const shellRef = useRef<HTMLElement | null>(null);
  const headerRef = useRef<HTMLElement | null>(null);

  // Sticky offsets and viewport-bounded panes read the header's real height
  // (it grows when the target name or track list wraps). workspace.css holds
  // the first-paint default.
  useEffect(() => {
    const header = headerRef.current;
    const shell = shellRef.current;
    if (!header || !shell || typeof ResizeObserver === "undefined") return;
    const apply = () => shell.style.setProperty("--workspace-header-height", `${header.getBoundingClientRect().height}px`);
    apply();
    const observer = new ResizeObserver(apply);
    observer.observe(header);
    return () => observer.disconnect();
  }, []);

  // One load coordinator per mounted workspace. A StrictMode remount revives
  // the same instance so the mount refresh joins the load already running.
  useEffect(() => {
    mountedRef.current = true;
    const loads = loadsRef.current ?? new CoalescedLoads();
    loads.revive();
    loadsRef.current = loads;
    return () => {
      mountedRef.current = false;
      loads.dispose();
      if (runsCommandTimerRef.current !== null) window.clearTimeout(runsCommandTimerRef.current);
      runsCommandTimerRef.current = null;
    };
  }, []);

  function settle(source: string, error: unknown) {
    if (!mountedRef.current) return;
    setRefreshErrors((current) => {
      if (error === undefined) {
        if (!(source in current)) return current;
        const next = { ...current };
        delete next[source];
        return next;
      }
      return { ...current, [source]: errorText(error) };
    });
  }

  // Run one source's load through its coalescing channel and record the
  // outcome for the refresh banner.
  function load(source: string, task: () => Promise<unknown>, minIntervalMs = 0) {
    loadsRef.current?.run(source, async () => {
      try {
        await task();
        settle(source, undefined);
      } catch (error) {
        settle(source, error ?? new Error("request failed"));
      }
    }, minIntervalMs);
  }

  async function refreshEngagement() {
    const nextEngagement = await getEngagement(engagementKey);
    setEngagement(nextEngagement);
    setLoadError(null);
    return nextEngagement;
  }

  function markStale(scopes: Iterable<LiveScope>) {
    for (const scope of scopes) pendingScopesRef.current.add(scope);
  }

  // Load a page dataset when its scope moved since it was last read. The
  // version is taken when the read starts, so a change that lands meanwhile
  // leaves the dataset stale for the next pass; a failed read leaves it stale.
  function loadDataset(name: string, scope: LiveScope, task: (version: number) => Promise<unknown>, source = name) {
    const version = scopeVersionsRef.current[scope];
    if (datasetVersionsRef.current.get(name) === version) return;
    datasetVersionsRef.current.set(name, version);
    load(source, async () => {
      try {
        await task(version);
      } catch (error) {
        if (datasetVersionsRef.current.get(name) === version) datasetVersionsRef.current.delete(name);
        throw error;
      }
    });
  }

  // Rail badge sources, refreshed only when a change touched their scope.
  // Each is coalesced on its own so the slow assessment summary never delays
  // the cheap counts, tab data, or tab refreshes, and refreshes at most every
  // BADGE_INTERVAL_MS (with a trailing load). An open Runs, Proof work,
  // Submissions, Commands or OAST view reports its own count from the read it
  // already makes (its count callback prop), so its badge never lags the page
  // and is not read twice; the other open views' badges stay live here.
  // The summary refreshes on every pass while a view that shows it (Overview,
  // Coverage) is open.
  const loadBadges = useEffectEvent((current: Engagement, scopes: ReadonlySet<LiveScope>) => {
    const keep = <T,>(apply: (value: T) => void) => (value: T) => { if (mountedRef.current) apply(value); };
    // The summary feeds the Findings, Surfaces, and Coverage badges.
    if (scopes.has("summary")) load("summary", () => getAssessmentSummary(engagementKey).then(keep(setAssessmentSummary)),
      activeTab === "overview" || activeTab === "coverage" ? 0 : BADGE_INTERVAL_MS);
    if (scopes.has("proof") && activeTab !== "proof") load("proof work", () => listProofWork(engagementKey)
      .then(keep((queue: ProofWorkList) => setProofNeedsAttention(proofNeedsAttentionCount(queue)))), BADGE_INTERVAL_MS);
    // The listing evaluates every finding's workspace, so it refreshes least often.
    if (scopes.has("submissions") && activeTab !== "submissions") load("submissions", () => listSubmissionDesk(engagementKey, { findingLimit: 1 })
      .then(keep((listing: Awaited<ReturnType<typeof listSubmissionDesk>>) => setSubmissionsToDo(listing.counts.actionable))),
      SUBMISSIONS_BADGE_INTERVAL_MS);
    if (scopes.has("intel")) load("intel readiness", () => getIntelReadiness(engagementKey)
      .then(keep((readiness: Awaited<ReturnType<typeof getIntelReadiness>>) => setOpenIntelLeads(readiness.applicable ? readiness.open_leads.length : null))),
      BADGE_INTERVAL_MS);
    if (hasCodeTrack(current) && scopes.has("code")) {
      load("code queue", () => getCodeQueueStats(engagementKey).then(keep(setCodeQueueStats)), BADGE_INTERVAL_MS);
    }
    if (scopes.has("oast") && activeTab !== "oast") load("OAST callbacks", () => listOobProbes(engagementKey, "fired")
      .then(keep((probes: Awaited<ReturnType<typeof listOobProbes>>) => setOastToReview(countCallbacksToReview(probes)))),
      BADGE_INTERVAL_MS);
    if (scopes.has("commands") && activeTab !== "commands") load("command attention", () => fetchCommandFacets(engagementKey, DEFAULT_COMMAND_FILTERS, 1)
      .then(keep((facets: Awaited<ReturnType<typeof fetchCommandFacets>>) => setCommandsNeedingAttention(facets.engagement_totals.attention))),
      BADGE_INTERVAL_MS);
    if (scopes.has("runs") && activeTab !== "runs") load("run health", async () => {
      const runs = await collectBarePages((offset, limit) => listAssessmentRuns(engagementKey, { limit, offset }), RUN_PAGE_SIZE);
      const counts: Record<RunHealthKey, number> = { healthy: 0, attention: 0, failed: 0, running: 0 };
      for (const run of runs) counts[runHealth(run).key] += 1;
      keep(handleRunHealth)(counts);
    }, RUNS_BADGE_INTERVAL_MS);
  });

  // Page-level data for one view, re-read only where its scope moved. Views
  // not listed here own their reads.
  const loadTabData = useEffectEvent((tab: TabKey) => {
    const keep = <T,>(apply: (value: T) => void) => (value: T) => { if (mountedRef.current) apply(value); };
    const findingRows = (full: boolean) => {
      if (full) {
        loadDataset("finding ledger", "findings", (version) => listAssessmentFindings(engagementKey).then((rows) => {
          if (!mountedRef.current) return;
          setAssessmentFindings({ rows, version });
          setFindingRowsError(null);
        }).catch((error: unknown) => {
          if (mountedRef.current) setFindingRowsError(errorText(error));
          throw error;
        }), "findings");
        return;
      }
      // The full ledger already covers this version; the lean rows add nothing.
      if (datasetVersionsRef.current.get("finding ledger") === scopeVersionsRef.current.findings) return;
      loadDataset("finding summaries", "findings", (version) => listAssessmentFindingSummaries(engagementKey).then((rows) => {
        if (!mountedRef.current) return;
        setFindingSummaries({ rows, version });
        setFindingRowsError(null);
      }).catch((error: unknown) => {
        if (mountedRef.current) setFindingRowsError(errorText(error));
        throw error;
      }), "findings");
    };
    const chains = () => {
      loadDataset("attack chains", "findings", () => listAssessmentAttackChains(engagementKey).then(keep(setAssessmentChains)));
      loadDataset("attack chain links", "findings", () => listAssessmentAttackChainLinks(engagementKey).then(keep(setAssessmentChainLinks)));
    };
    switch (tab) {
      case "overview":
        findingRows(false);
        chains();
        break;
      case "findings":
        findingRows(true);
        chains();
        break;
      case "intel":
        // Per-type counts for the Intel view's type rail.
        loadDataset("intel summary", "intel", () => getIntelSummary(engagementKey).then(keep(setIntelSummary)));
        break;
      case "surfaces": {
        // Linked findings resolve their titles and severities from the lean rows.
        findingRows(false);
        const version = scopeVersionsRef.current.surfaces;
        if (datasetVersionsRef.current.get("surfaces") === version) break;
        datasetVersionsRef.current.set("surfaces", version);
        // SurfacesTab reports this failure itself.
        loadsRef.current?.run("surfaces", () => listSurfaces(engagementKey, { limit: SURFACE_FETCH_LIMIT })
          .then((surfaces) => {
            if (!mountedRef.current) return;
            setAssessmentSurfaces(surfaces);
            setSurfaceLoadError(null);
          })
          .catch((error: unknown) => {
            if (datasetVersionsRef.current.get("surfaces") === version) datasetVersionsRef.current.delete("surfaces");
            if (mountedRef.current) setSurfaceLoadError(errorText(error, "Failed to load attack surfaces"));
          }));
        break;
      }
      default:
        break;
    }
  });

  // One refresh pass: re-read the engagement, advance the refresh counter of
  // every scope that changed (views reading them refetch their own data), then
  // refresh those scopes' badges and the active view's page data without
  // waiting on either.
  const refreshPage = useEffectEvent(async () => {
    const scopes = new Set(pendingScopesRef.current);
    pendingScopesRef.current.clear();
    let refreshed: Engagement;
    try {
      refreshed = await refreshEngagement();
    } catch (error) {
      // Nothing was refreshed; the next pass retries these scopes.
      markStale(scopes);
      if (mountedRef.current) setLoadError(errorText(error, "Failed to load engagement"));
      return;
    }
    if (!mountedRef.current) return;
    // Views mount with fresh data on the first load; later passes ask them to refetch.
    if (hasLoadedOnceRef.current && scopes.size > 0) {
      scopeVersionsRef.current = bumpScopes(scopeVersionsRef.current, scopes);
      setScopeVersions(scopeVersionsRef.current);
      if (scopes.has("commands") && activeTab === "runs" && runsCommandTimerRef.current === null) {
        runsCommandTimerRef.current = window.setTimeout(() => {
          runsCommandTimerRef.current = null;
          // A runs-scope pass since then already re-read the list (pass
          // numbers only grow), so this re-reads only when none did.
          if (mountedRef.current) setRunsCommandVersion(scopeVersionsRef.current.commands);
        }, RUNS_COMMAND_DELAY_MS);
      }
    }
    hasLoadedOnceRef.current = true;
    loadBadges(refreshed, scopes);
    loadTabData(activeTab);
  });

  const requestRefresh = useEffectEvent((mode: "join" | "rerun" = "rerun") => {
    if (!mountedRef.current) return;
    loadsRef.current?.run("engagement", refreshPage, 0, mode);
  });

  // A refresh that cannot know what changed (polling, a tab back in view, a
  // reconnect) refreshes every scope.
  const requestFullRefresh = useEffectEvent(() => {
    markStale(ALL_LIVE_SCOPES);
    requestRefresh();
  });

  // Throttled refresh for WebSocket messages — at most once per window to
  // avoid constant re-renders during rapid-fire backend events.
  const throttledRefresh = useEffectEvent(() => {
    const now = Date.now();
    const elapsed = now - lastWsRefreshRef.current;
    if (wsThrottleTimerRef.current !== null) {
      return; // already scheduled
    }
    if (elapsed >= WS_THROTTLE_MS) {
      lastWsRefreshRef.current = now;
      requestRefresh();
    } else {
      wsThrottleTimerRef.current = window.setTimeout(() => {
        wsThrottleTimerRef.current = null;
        lastWsRefreshRef.current = Date.now();
        requestRefresh();
      }, WS_THROTTLE_MS - elapsed);
    }
  });

  useEffect(() => {
    requestRefresh("join");
  }, [engagementKey]);

  // A tab switch loads only that view's page-level data where it is stale.
  // It is not a full refresh: the view mounts and reads its own data, and the
  // badges are already live.
  useEffect(() => {
    if (!activeEngagement) return;
    loadTabData(activeTab);
  }, [activeTab]);

  useEffect(() => {
    if (!activeEngagement) return;

    let reconnectTimer: number | null = null;
    let socket: WebSocket | null = null;
    let cancelled = false;
    let reconnectDelayMs = 1000;

    const connect = () => {
      if (cancelled) return;

      socket = new WebSocket(engagementWebSocketUrl(engagementKey));
      socket.onopen = () => {
        if (cancelled) return;
        socketConnectedRef.current = true;
        reconnectDelayMs = 1000;
        setLiveUpdates("live");
        // Toast only on a genuine recovery: the live feed had dropped (error
        // or a close after we'd connected at least once) and is now back. The
        // first connect on mount is not a "reconnect" so it stays silent.
        if (liveFeedDroppedRef.current) {
          liveFeedDroppedRef.current = false;
          toast("Live updates reconnected", "success");
        }
        if (hasConnectedOnceRef.current) {
          // Changes made while disconnected were never announced.
          requestFullRefresh();
        } else {
          hasConnectedOnceRef.current = true;
        }
      };
      socket.onerror = () => {
        if (cancelled) return;
        liveFeedDroppedRef.current = true;
        setLiveUpdates("polling");
      };
      socket.onclose = () => {
        socketConnectedRef.current = false;
        if (hasConnectedOnceRef.current) {
          liveFeedDroppedRef.current = true;
        }
        if (cancelled) return;
        setLiveUpdates("polling");
        reconnectTimer = window.setTimeout(() => {
          connect();
        }, reconnectDelayMs);
        reconnectDelayMs = Math.min(reconnectDelayMs * 2, 30000);
      };
      socket.onmessage = (message) => {
        if (cancelled) return;
        // Every well-formed frame names what changed; the refresh it triggers
        // re-reads only the scopes that change can touch.
        let parsed: unknown;
        try {
          if (typeof message.data !== "string") throw new TypeError("non-text frame");
          parsed = JSON.parse(message.data);
        } catch {
          socketConnectedRef.current = false;
          liveFeedDroppedRef.current = true;
          setLiveUpdates("polling");
          socket?.close();
          return;
        }
        markStale(scopesForMessage(parsed));
        throttledRefresh();
      };
    };

    connect();

    return () => {
      cancelled = true;
      socketConnectedRef.current = false;
      hasConnectedOnceRef.current = false;
      liveFeedDroppedRef.current = false;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      if (wsThrottleTimerRef.current !== null) {
        window.clearTimeout(wsThrottleTimerRef.current);
        wsThrottleTimerRef.current = null;
      }
      socket?.close();
    };
  }, [activeEngagement?.key, engagementKey]);

  useEffect(() => {
    if (!activeEngagement) return;

    const interval = window.setInterval(() => {
      if (document.hidden || socketConnectedRef.current) {
        return;
      }
      requestFullRefresh();
    }, POLL_INTERVAL_MS);

    return () => window.clearInterval(interval);
  }, [activeEngagement?.key]);

  // A tab back in view refreshes everything, including while the first load
  // runs (that refresh folds into one more pass after it).
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        requestFullRefresh();
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => document.removeEventListener("visibilitychange", handleVisibilityChange);
  }, []);

  // Deep-link sync: re-apply the parsed-route entry params when they change.
  // This handles a hashchange that arrives while this engagement is ALREADY
  // mounted — without these, the lazy state initializers above would
  // only fire on first mount and a pasted finding/tab deep-link would be a
  // no-op. Explicit selection updates the parsed props through canonical
  // history; compare-before-set keeps incoming Back/Forward state idempotent.
  useEffect(() => {
    const nextTab = coerceTabKey(initialTab);
    setActiveTab((current) => (current === nextTab ? current : nextTab));
    // An unknown or retired `tab=` (a bookmarked `log`) shows another view;
    // the address names the view actually shown.
    if (initialTab !== undefined && initialTab !== nextTab) {
      writeWorkspaceHash(engagementHref(engagementKey, { tab: nextTab }), "replace");
    }
  }, [initialTab, engagementKey]);

  useEffect(() => {
    const nextTab = coerceTabKey(initialTab);
    const nextSlug = nextTab === "findings" ? initialFindingSlug : undefined;
    const nextDrawerTab = nextTab === "findings" ? initialDrawerTab : undefined;
    setPendingFindingSlug((current) => (current === nextSlug ? current : nextSlug));
    setPendingDrawerTab((current) => (current === nextDrawerTab ? current : nextDrawerTab));
  }, [initialTab, initialFindingSlug, initialDrawerTab]);

  // The fresher of the full ledger and the lean rows, else the summary's top findings.
  const ledgerRows = assessmentFindings?.rows ?? null;
  const findingRows = assessmentFindings && (!findingSummaries || assessmentFindings.version >= findingSummaries.version)
    ? assessmentFindings.rows
    : findingSummaries?.rows ?? null;
  const findingRowsLoaded = findingRows !== null;
  const displayFindings = findingRows && findingRows.length > 0 ? findingRows : (assessmentSummary?.top_findings ?? []);
  const chains = assessmentChains.length > 0 ? assessmentChains : (assessmentSummary?.attack_chains ?? []);
  const displaySummary = assessmentSummary;
  const viewVersion = (tab: TabKey) => {
    const version = scopeVersion(scopeVersions, VIEW_SCOPES[tab]);
    return tab === "runs" ? Math.max(version, runsCommandVersion) : version;
  };
  const activityCategories = useMemo(
    () => initialActivityCategories?.split(",").map((value) => value.trim()).filter(Boolean),
    [initialActivityCategories],
  );
  const routed = <T,>(tab: TabKey, value: T) => (initialTab === tab ? value : undefined);

  const tabBadges = railBadges({
    summary: displaySummary,
    loadedFindingCount: findingRows?.length ?? 0,
    loadedSurfaceCount: assessmentSurfaces?.length ?? 0,
    proofNeedsAttention,
    submissionsToDo,
    openIntelLeads,
    codeQueue: codeQueueStats,
    runHealth: runHealthCounts,
    commandsNeedingAttention,
    oastCallbacksToReview: oastToReview,
  });
  // The open Proof work view reports the count its own "Needs attention" scope shows.
  const handleProofQueueCounts = useCallback((counts: { needs_attention: number }) => setProofNeedsAttention(counts.needs_attention), []);
  const handleRunHealth = useCallback((counts: Record<RunHealthKey, number>) => {
    setRunHealthCounts((current) => (current && [...RUN_ATTENTION_HEALTH].every((key) => current[key] === counts[key]) ? current : counts));
  }, []);

  const runtimeProofVersion = scopeVersion(scopeVersions, RUNTIME_PROOF_SCOPES);
  const renderRuntimeProof = useCallback(
    (finding: { slug: string }) => <FindingRuntimeProof key={finding.slug} engagementKey={engagementKey} slug={finding.slug} refreshVersion={runtimeProofVersion} />,
    [engagementKey, runtimeProofVersion],
  );

  const refreshFailures: Array<[string, string]> = [
    ...(loadError ? [["engagement", loadError] as [string, string]] : []),
    ...Object.entries(refreshErrors),
  ];

  // One history entry per activation (a click, Enter or Space on the rail).
  const handleTabChange = (tab: TabKey) => {
    setActiveTab(tab);
    // A finding deep-link only applies to the findings tab. Switching tabs
    // drops the param: clear the pending slug and rewrite the hash to a
    // bare tab URL (FindingsTab re-adds ?finding=… while its drawer is open).
    if (tab !== "findings") {
      setPendingFindingSlug(undefined);
      setPendingDrawerTab(undefined);
    }
    writeWorkspaceHash(engagementHref(engagementKey, { tab }));
  };

  const handleExportReport = async () => {
    if (exportingReport) return;
    setExportingReport(true);
    try {
      // Draft export — no readiness gate. (A future "final" control can pass
      // mode="final"; the helper + backend already enforce the 409 gate.)
      const result = await exportReport(engagementKey, "draft");
      if (!mountedRef.current) return;
      toast("Report exported", "success");
      // Trigger a browser download by pointing a transient hidden anchor at
      // the attachment endpoint. Same-origin app URL, so no popup blocker.
      const anchor = document.createElement("a");
      anchor.href = reportDownloadUrl(engagementKey, result.artifact_id);
      anchor.rel = "noopener";
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // The export endpoint returns 503 with a template-not-built hint and
      // 409 (final mode only) with the readiness payload. Classify by the
      // HTTP status (carried on ApiError); only fall back to the message-text
      // heuristics when the status is unavailable (non-ApiError throw).
      const status = error instanceof ApiError ? error.status : undefined;
      if (status === 503) {
        toast("Report template not built", "error");
      } else if (status === 409) {
        toast("Report not ready for a final export", "error");
      } else if (status !== undefined) {
        toast(`Report export failed: ${message}`, "error");
      } else if (/template/i.test(message)) {
        toast("Report template not built", "error");
      } else if (/blocker|not ready|"ready"\s*:\s*false/i.test(message)) {
        toast("Report not ready for a final export", "error");
      } else {
        toast(`Report export failed: ${message}`, "error");
      }
    } finally {
      setExportingReport(false);
    }
  };

  return (
    <main className="shell engagement-shell" ref={shellRef}>
      {/* Header */}
      <section className="dashboard-header workspace-header" ref={headerRef}>
        <div>
          <p className="eyebrow">Vigil / {engagementKey}</p>
          {/* Not a heading: each view's PageHeader title is the page's one h1. */}
          <p className="workspace-target">{activeEngagement?.target ?? engagementKey}</p>
          {activeEngagement && (Object.keys(activeEngagement.track_state ?? {}).length > 0 ? (
            <ul className="workspace-header-tracks" aria-label="Enabled track status">
              {Object.entries(activeEngagement.track_state ?? {}).map(([track, state]) => <li key={track}>
                <span>{track}: {state.phase || "unknown"}</span>
                {state.repair_required ? <span className="workspace-track-repair">Repair required</span> : state.complete && <span className="meta-text">Complete</span>}
              </li>)}
            </ul>
          ) : <p className="workspace-header-track-unknown meta-text">Track state unavailable</p>)}
        </div>
        <div className="page-actions">
          <div className="status-summary">
            <div className="status-summary-row">
              <span className="status-summary-label">Engagement lifecycle</span>
              {activeEngagement
                ? <StatusPill domain="engagement" value={activeEngagement.status || "unknown"} />
                : <Skeleton width={84} height={20} rounded />}
            </div>
          </div>
          <button
            className="ghost-button export-report-button"
            onClick={handleExportReport}
            disabled={exportingReport || !activeEngagement}
            title="Generate a single-file HTML report (draft)"
          >
            <FileDown size={15} aria-hidden="true" />
            {exportingReport ? "Exporting…" : "Export report"}
          </button>
          <ThemeToggle />
          <button className="ghost-button" onClick={onBack}>Back</button>
        </div>
      </section>
      {!activeEngagement && loadError && <div className="workspace-refresh-error error-text" role="status">Engagement unavailable: {loadError}</div>}
      {activeEngagement && refreshFailures.length > 0 && (
        <div className="workspace-refresh-error error-text" role="status">
          Refresh failed. Showing the last loaded data. {refreshFailures.map(([source, message]) => `${source}: ${message}`).join("; ")}
        </div>
      )}
      {activeEngagement && liveUpdates === "polling" && (
        <div className="workspace-live-status" role="status">
          Live updates unavailable. Checking for changes every {POLL_INTERVAL_MS / 1000} seconds while reconnecting.
        </div>
      )}

      {!activeEngagement ? (
        // Initial page load: show a skeleton until the engagement resolves.
        // A hard failure surfaces via the existing error banner in the header
        // (loadError), so suppress the skeleton once that is set.
        loadError ? null : (
          <section className="panel" aria-busy="true" style={{ display: "grid", gap: 16 }}>
            <CardSkeleton lines={2} />
            <TableSkeleton rows={6} />
          </section>
        )
      ) : (
        <div className="workspace-layout">
          <TabBar active={activeTab} onChange={handleTabChange} badges={tabBadges} />
          <div className="workspace-main" id="workspace-panel" role="tabpanel" aria-labelledby={`workspace-tab-${activeTab}`} tabIndex={0}>

          {activeTab === "overview" && (
            <OverviewTab
              engagementKey={engagementKey}
              assessmentSummary={displaySummary}
              findings={displayFindings}
              findingsLoading={!findingRowsLoaded && findingRowsError === null}
              findingsLoadError={findingRowsError}
              chains={chains}
              chainLinks={assessmentChainLinks}
              currentPhase={activeEngagement.current_phase}
              trackState={activeEngagement.track_state}
              aggregateComplete={activeEngagement.aggregate_complete}
              assessmentRefreshVersion={viewVersion("overview")}
              readinessRefreshVersion={scopeVersion(scopeVersions, READINESS_SCOPES)}
            />
          )}

          {activeTab === "findings" && (
            <FindingsTab
              engagementKey={engagementKey}
              findings={ledgerRows && ledgerRows.length > 0 ? ledgerRows : (displaySummary?.top_findings ?? [])}
              ledgerLoading={ledgerRows === null && findingRowsError === null}
              ledgerError={findingRowsError}
              fallbackFindings={displaySummary?.top_findings ?? []}
              chains={assessmentChains}
              chainLinks={assessmentChainLinks}
              assessmentRefreshVersion={viewVersion("findings")}
              initialFindingSlug={pendingFindingSlug}
              initialDrawerTab={pendingDrawerTab}
              renderRuntimeProof={renderRuntimeProof}
            />
          )}

          {activeTab === "proof" && (
            <ProofWorkTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("proof")}
              workId={routed("proof", initialWorkId)}
              onQueueCounts={handleProofQueueCounts}
            />
          )}

          {activeTab === "runs" && (
            <RunsTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("runs")}
              initialRunId={initialRunId}
              initialSection={initialRunSection}
              initialObject={initialRunObject}
              initialDrawerTab={routed("runs", initialDrawerTab)}
              onHealthCounts={handleRunHealth}
            />
          )}

          {activeTab === "submissions" && (
            <SubmissionsTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("submissions")}
              initialSubmissionSlug={routed("submissions", initialSubmissionSlug)}
              initialDrawerTab={routed("submissions", initialDrawerTab)}
              onToDoCount={setSubmissionsToDo}
            />
          )}

          {activeTab === "code" && (
            <CodeAnalysisTab
              engagementKey={engagementKey}
              persistedPhase={activeEngagement.track_state?.code?.phase ?? "unknown"}
              refreshVersion={viewVersion("code")}
            />
          )}

          {activeTab === "coverage" && (
            <CoverageTab
              engagementKey={engagementKey}
              summary={displaySummary}
              refreshVersion={viewVersion("coverage")}
              initialItemId={routed("coverage", initialCoverageItemId)}
              initialDrawerTab={routed("coverage", initialDrawerTab)}
            />
          )}

          {activeTab === "activity" && (
            <ActivityTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("activity")}
              initialQuery={routed("activity", initialActivityQuery)}
              initialCategories={routed("activity", activityCategories)}
              initialActor={routed("activity", initialActivityActor)}
              initialRange={routed("activity", initialActivityRange)}
            />
          )}

          {activeTab === "intel" && (
            <IntelTab
              engagementKey={engagementKey}
              summary={intelSummary}
              refreshVersion={viewVersion("intel")}
              initialIntelType={routed("intel", initialIntelType)}
              initialIntelId={routed("intel", initialIntelId)}
              initialDrawerTab={routed("intel", initialDrawerTab)}
            />
          )}

          {activeTab === "surfaces" && (
            <SurfacesTab
              engagementKey={engagementKey}
              surfaces={assessmentSurfaces}
              snapshotLimit={SURFACE_FETCH_LIMIT}
              loadError={surfaceLoadError}
              findings={displayFindings}
              initialSurfaceId={routed("surfaces", initialSurfaceId)}
              initialDrawerTab={routed("surfaces", initialDrawerTab)}
            />
          )}

          {activeTab === "http" && (
            <HttpTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("http")}
              initialView={routed("http", initialHttpView && HTTP_VIEWS.has(initialHttpView) ? initialHttpView as "inventory" | "exchanges" : undefined)}
              initialRequestVariantId={routed("http", initialRequestVariantId)}
              initialFlowId={routed("http", initialFlowId)}
              initialDrawerTab={routed("http", initialDrawerTab)}
            />
          )}

          {activeTab === "commands" && (
            <CommandsTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("commands")}
              commandId={routed("commands", initialCommandId)}
              initialDrawerTab={routed("commands", initialDrawerTab)}
              onAttentionCount={setCommandsNeedingAttention}
            />
          )}

          {activeTab === "oast" && (
            <OastTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("oast")}
              initialProbeId={routed("oast", initialProbeId)}
              initialDrawerTab={routed("oast", initialDrawerTab)}
              onToReviewCount={setOastToReview}
            />
          )}

          {activeTab === "artifacts" && (
            <FilesTab
              engagementKey={engagementKey}
              refreshVersion={viewVersion("artifacts")}
              initialFileName={routed("artifacts", initialFileName)}
            />
          )}
          </div>
        </div>
      )}
    </main>
  );
}
