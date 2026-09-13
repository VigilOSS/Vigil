import { useEffect, useEffectEvent, useRef, useState } from "react";

import { FileDown } from "lucide-react";

import {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentCoverageItem,
  AssessmentFindingDetail,
  AssessmentService,
  AssessmentSurface,
  ApiError,
  AssessmentSummary,
  AssessmentTarget,
  Artifact,
  ArtifactContent,
  CodeAnalysisResult,
  CodeCoverage,
  CodeModule,
  CodeQueueStats,
  CodeReadiness,
  CodeRepo,
  Engagement,
  EngagementSession,
  EventRecord,
  IntelSummary,
  engagementWebSocketUrl,
  exportReport,
  getAssessmentSummary,
  getCodeCoverage,
  getCodeQueueStats,
  getCodeReadiness,
  getEngagement,
  getIntelSummary,
  listActivityEntries,
  listArtifacts,
  listAssessmentAttackChainLinks,
  listAssessmentAttackChains,
  listAssessmentCoverageItems,
  listAssessmentFindings,
  listAssessmentServices,
  listAssessmentTargets,
  listCodeAnalysisResults,
  listCodeModules,
  listCodeRepos,
  listEngagementSessions,
  listEvents,
  listSurfaces,
  readArtifact,
  reportDownloadUrl,
} from "../lib/api";
import { ActivityTab } from "../components/ActivityTab";
import { ArtifactViewer } from "../components/ArtifactViewer";
import { CodeAnalysisTab } from "../components/CodeAnalysisTab";
import { CommandsTab } from "../components/CommandsTab";
import { CoverageTab } from "../components/CoverageTab";
import { FindingsTab } from "../components/FindingsTab";
import { HttpTab } from "../components/HttpTab";
import { IntelTab } from "../components/IntelTab";
import { LogTab } from "../components/LogTab";
import { OastTab } from "../components/OastTab";
import { OverviewTab } from "../components/OverviewTab";
import { RunsTab } from "../components/RunsTab";
import { SurfacesTab } from "../components/SurfacesTab";
import { SubmissionsTab } from "../components/SubmissionsTab";
import { TabBar, TABS } from "../components/TabBar";
import type { TabKey } from "../components/TabBar";
import { ThemeToggle } from "../components/ThemeToggle";
import { CardSkeleton, TableSkeleton } from "../components/Skeletons";
import { useToast } from "../contexts/ToastContext";

type EngagementPageProps = {
  engagementKey: string;
  onBack: () => void;
  // Deep-link entry params (see App.parseEngagementRoute). Applied on first
  // mount and re-applied whenever the PARSED ROUTE VALUES change (e.g. a
  // hashchange while this engagement is already mounted) via the sync effects
  // below. A normal manual tab click / drawer open does not change these
  // props, so it is never reverted; FindingsTab's replaceState rewrite
  // reproduces the same values for the active selection, so the sync is
  // idempotent (compare-before-set guards against a redundant render).
  initialTab?: string;
  initialFindingSlug?: string;
  // Drawer-tab (poc/code/links/history/intel) for a deep-linked finding.
  initialDrawerTab?: string;
  initialRunId?: number;
  initialRunSection?: string;
  initialRunObject?: string;
};

const ASSESSMENT_WIDE_FETCH_LIMIT = 5000;

function formatStatusLabel(value: string | undefined) {
  return (value ?? "unknown").replace(/_/g, " ");
}

const VALID_TAB_KEYS = new Set<string>(TABS.map((t) => t.key));

function coerceTabKey(value: string | undefined): TabKey {
  return value && VALID_TAB_KEYS.has(value) ? (value as TabKey) : "overview";
}

// Rewrite the engagement deep-link hash WITHOUT emitting a `hashchange`
// (replaceState is silent), so App's hashchange listener never re-routes on a
// self-write. `tab` is omitted for the default "overview" to keep clean URLs;
// the `finding` param is owned by FindingsTab and intentionally dropped here.
function writeEngagementHash(engagementKey: string, tab: TabKey) {
  const base = `#/engagements/${encodeURIComponent(engagementKey)}`;
  const params = new URLSearchParams();
  if (tab !== "overview") params.set("tab", tab);
  const qs = params.toString();
  const next = qs ? `${base}?${qs}` : base;
  if (window.location.hash !== next) {
    window.history.replaceState(null, "", next);
  }
}

export function EngagementPage({
  engagementKey,
  onBack,
  initialTab,
  initialFindingSlug,
  initialDrawerTab,
  initialRunId,
  initialRunSection,
  initialRunObject,
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
  const [sessions, setSessions] = useState<EngagementSession[]>([]);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [assessmentSummary, setAssessmentSummary] = useState<AssessmentSummary | null>(null);
  const [assessmentFindings, setAssessmentFindings] = useState<AssessmentFindingDetail[]>([]);
  const [assessmentChains, setAssessmentChains] = useState<AssessmentAttackChainDetail[]>([]);
  const [assessmentChainLinks, setAssessmentChainLinks] = useState<AssessmentAttackChainLink[]>([]);
  const [assessmentTargets, setAssessmentTargets] = useState<AssessmentTarget[]>([]);
  const [assessmentServices, setAssessmentServices] = useState<AssessmentService[]>([]);
  const [assessmentCoverageItems, setAssessmentCoverageItems] = useState<AssessmentCoverageItem[]>([]);
  const [assessmentRefreshVersion, setAssessmentRefreshVersion] = useState(0);
  const [codeRepos, setCodeRepos] = useState<CodeRepo[]>([]);
  const [codeModules, setCodeModules] = useState<CodeModule[]>([]);
  const [codeQueueStats, setCodeQueueStats] = useState<CodeQueueStats | null>(null);
  const [codeCoverage, setCodeCoverage] = useState<CodeCoverage | null>(null);
  const [codeReadiness, setCodeReadiness] = useState<CodeReadiness | null>(null);
  const [codeResults, setCodeResults] = useState<CodeAnalysisResult[]>([]);
  const [codeLoadError, setCodeLoadError] = useState<string | null>(null);
  const [intelSummary, setIntelSummary] = useState<IntelSummary | null>(null);
  const [assessmentSurfaces, setAssessmentSurfaces] = useState<AssessmentSurface[]>([]);
  const [surfaceLoadError, setSurfaceLoadError] = useState<string | null>(null);
  const [activityTotal, setActivityTotal] = useState<number>(0);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactContent | null>(null);
  const [exportingReport, setExportingReport] = useState(false);
  const activeEngagement = engagement?.key === engagementKey ? engagement : null;
  const selectedNameRef = useRef<string | null>(selectedName);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const refreshQueuedRef = useRef(false);
  const socketConnectedRef = useRef(false);
  const hasConnectedOnceRef = useRef(false);
  // Tracks whether the live feed has dropped since the last successful open,
  // so the reconnect toast fires on recovery but not on the first connect.
  const liveFeedDroppedRef = useRef(false);
  const lastWsRefreshRef = useRef(0);
  const wsThrottleTimerRef = useRef<number | null>(null);

  useEffect(() => {
    selectedNameRef.current = selectedName;
  }, [selectedName]);

  function refreshArtifacts() {
    return listArtifacts(engagementKey).then((nextArtifacts) => {
      setArtifacts(nextArtifacts);
      if (!selectedName) {
        const firstAvailable = nextArtifacts.find((artifact) => artifact.exists);
        if (firstAvailable) {
          setSelectedName(firstAvailable.name);
        }
      }
    }).catch((error: unknown) => {
      setArtifacts([]);
      setSelectedArtifact(null);
      throw error;
    });
  }

  function refreshSelectedArtifact(name: string) {
    return readArtifact(engagementKey, name)
      .then(setSelectedArtifact)
      .catch(() => setSelectedArtifact(null));
  }

  async function refreshEngagement() {
    const nextEngagement = await getEngagement(engagementKey);
    setEngagement(nextEngagement);
    setLoadError(null);
    return nextEngagement;
  }

  function refreshSessions() {
    return listEngagementSessions(engagementKey).then(setSessions);
  }

  function refreshEvents() {
    return listEvents(engagementKey).then(setEvents);
  }

  async function refreshCodeAnalysis() {
    const failures: string[] = [];
    const captureFailure = (label: string, error: unknown) => {
      const detail = error instanceof Error ? error.message : "request failed";
      failures.push(`${label}: ${detail}`);
    };
    await Promise.all([
      listCodeRepos(engagementKey)
        .then(setCodeRepos)
        .catch((error: unknown) => {
          setCodeRepos([]);
          captureFailure("repositories", error);
        }),
      listCodeModules(engagementKey)
        .then(setCodeModules)
        .catch((error: unknown) => {
          setCodeModules([]);
          captureFailure("modules", error);
        }),
      getCodeQueueStats(engagementKey)
        .then(setCodeQueueStats)
        .catch((error: unknown) => {
          setCodeQueueStats(null);
          captureFailure("queue", error);
        }),
      getCodeCoverage(engagementKey)
        .then(setCodeCoverage)
        .catch((error: unknown) => {
          setCodeCoverage(null);
          captureFailure("coverage", error);
        }),
      getCodeReadiness(engagementKey, "complete")
        .then(setCodeReadiness)
        .catch((error: unknown) => {
          setCodeReadiness(null);
          captureFailure("readiness", error);
        }),
      listCodeAnalysisResults(engagementKey)
        .then(setCodeResults)
        .catch((error: unknown) => {
          setCodeResults([]);
          captureFailure("results", error);
        }),
    ]);
    setCodeLoadError(
      failures.length > 0
        ? `Some code-analysis data is unavailable: ${failures.join("; ")}`
        : null,
    );
  }

  const refreshPage = useEffectEvent(async () => {
    try {
      try {
        await refreshEngagement();
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to load engagement";
        setLoadError(message);
        setEngagement(null);
        setSessions([]);
        setEvents([]);
        setArtifacts([]);
        setAssessmentSummary(null);
        setAssessmentFindings([]);
        setAssessmentChains([]);
        setAssessmentChainLinks([]);
        setAssessmentTargets([]);
        setAssessmentServices([]);
        setAssessmentCoverageItems([]);
        setCodeRepos([]);
        setCodeModules([]);
        setCodeQueueStats(null);
        setCodeCoverage(null);
        setCodeReadiness(null);
        setCodeResults([]);
        setCodeLoadError(null);
        setIntelSummary(null);
        setAssessmentSurfaces([]);
        setSurfaceLoadError(null);
        setActivityTotal(0);
        setSelectedName(null);
        setSelectedArtifact(null);
        return;
      }

      // Always refresh events + assessment summary (lightweight, needed for tab counts)
      const promises: Promise<unknown>[] = [
        refreshEvents(),
        getAssessmentSummary(engagementKey).then(setAssessmentSummary),
        // Intel summary is cheap and drives the Intel tab count + left-rail
        // per-type counts. 501s while B1 is in flight collapse to null.
        getIntelSummary(engagementKey).then(setIntelSummary).catch(() => setIntelSummary(null)),
        // Activity entry count for the Log tab badge. Fetch the first page
        // only — we just need `total`.
        listActivityEntries(engagementKey, { limit: 1 })
          .then((resp) => setActivityTotal(resp.total))
          .catch(() => setActivityTotal(0)),
      ];

      // Only fetch data needed by the active tab
      const tab = activeTab;
      switch (tab) {
        case "overview":
        case "findings":
          promises.push(
            listAssessmentFindings(engagementKey).then(setAssessmentFindings),
            listAssessmentAttackChains(engagementKey).then(setAssessmentChains),
            listAssessmentAttackChainLinks(engagementKey).then(setAssessmentChainLinks),
          );
          break;
        case "coverage":
          promises.push(
            listAssessmentTargets(engagementKey).then(setAssessmentTargets),
            listAssessmentServices(engagementKey).then(setAssessmentServices),
            listAssessmentCoverageItems(engagementKey, { limit: ASSESSMENT_WIDE_FETCH_LIMIT }).then(setAssessmentCoverageItems),
          );
          break;
        case "code":
          promises.push(refreshCodeAnalysis());
          break;
        case "activity":
          promises.push(refreshSessions());
          break;
        case "surfaces":
          promises.push(
            listSurfaces(engagementKey, { limit: ASSESSMENT_WIDE_FETCH_LIMIT })
              .then((surfaces) => {
                setAssessmentSurfaces(surfaces);
                setSurfaceLoadError(null);
              })
              .catch((error: unknown) => {
                setSurfaceLoadError(
                  error instanceof Error ? error.message : "Failed to load attack surfaces",
                );
              }),
          );
          break;
        case "intel":
          // IntelTab owns its own per-entity fetches; only the summary is
          // needed at the page level (already fetched above for tab counts).
          break;
        case "runs":
          // RunsTab owns bounded run/detail/drill-down and comparison reads.
          break;
        case "submissions":
          // SubmissionsTab owns finding selection, workspace reads, attachment
          // choices, immutable export, recovery, and version history.
          break;
        case "commands":
          // CommandsTab owns its own fetch (list + lazy detail); the page
          // only needs the active-tab switch to trigger the component mount.
          break;
        case "http":
          // HttpTab owns its own fetch (variants + observations) and a
          // visibility-driven refresh, mirroring CommandsTab. The page only
          // needs the active-tab switch to trigger the component mount.
          break;
        case "oast":
          // OastTab owns its own fetch (probe list + lazy per-probe detail)
          // and a visibility-driven refresh, mirroring CommandsTab.
          break;
        case "log":
          // LogTab owns its own search+fetch; page-level only needs the
          // total (already fetched above for the tab count).
          break;
        case "artifacts":
          promises.push(refreshArtifacts());
          break;
      }

      await Promise.all(promises);
      setAssessmentRefreshVersion((version) => version + 1);

      const nextSelectedName = selectedNameRef.current;
      if (tab === "artifacts" && nextSelectedName) {
        await refreshSelectedArtifact(nextSelectedName);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to load engagement details";
      setLoadError(message);
    }
  });

  const requestRefresh = useEffectEvent(() => {
    if (refreshInFlightRef.current) {
      refreshQueuedRef.current = true;
      return;
    }

    const task = (async () => {
      do {
        refreshQueuedRef.current = false;
        await refreshPage();
      } while (refreshQueuedRef.current);
    })().finally(() => {
      refreshInFlightRef.current = null;
    });
    refreshInFlightRef.current = task;
  });

  // Throttled refresh for WebSocket messages — at most once per 2 seconds to
  // avoid constant re-renders during rapid-fire backend events.
  const WS_THROTTLE_MS = 2000;
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
    requestRefresh();
  }, [engagementKey]);

  // Refresh tab-specific data when switching tabs
  useEffect(() => {
    if (!activeEngagement) return;
    requestRefresh();
  }, [activeTab]);

  useEffect(() => {
    if (!activeEngagement || !selectedName || activeTab !== "artifacts") {
      setSelectedArtifact(null);
      return;
    }
    void refreshSelectedArtifact(selectedName);
  }, [activeEngagement?.key, engagementKey, selectedName, activeTab]);

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
        socketConnectedRef.current = true;
        reconnectDelayMs = 1000;
        setLoadError((current) => current === "Live updates unavailable" ? null : current);
        // Toast only on a genuine recovery: the live feed had dropped (error
        // or a close after we'd connected at least once) and is now back. The
        // first connect on mount is not a "reconnect" so it stays silent.
        if (liveFeedDroppedRef.current) {
          liveFeedDroppedRef.current = false;
          toast("Live updates reconnected", "success");
        }
        if (hasConnectedOnceRef.current) {
          requestRefresh();
        } else {
          hasConnectedOnceRef.current = true;
        }
      };
      socket.onerror = () => {
        liveFeedDroppedRef.current = true;
        setLoadError((current) => current ?? "Live updates unavailable");
      };
      socket.onclose = () => {
        socketConnectedRef.current = false;
        if (hasConnectedOnceRef.current) {
          liveFeedDroppedRef.current = true;
        }
        if (cancelled) return;
        reconnectTimer = window.setTimeout(() => {
          connect();
        }, reconnectDelayMs);
        reconnectDelayMs = Math.min(reconnectDelayMs * 2, 30000);
      };
      socket.onmessage = (message) => {
        const payload = JSON.parse(message.data);
        if (payload.type === "event.created") {
          setEvents((current) => {
            const nextEvent = payload.event as EventRecord;
            return current.at(-1)?.id === nextEvent.id ? current : [...current, nextEvent];
          });
        }
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
      requestRefresh();
    }, 30000);

    return () => window.clearInterval(interval);
  }, [activeEngagement?.key]);

  useEffect(() => {
    if (!activeEngagement) return;

    const handleVisibilityChange = () => {
      if (!document.hidden) {
        requestRefresh();
      }
    };

    document.addEventListener("visibilitychange", handleVisibilityChange);
    return () => document.removeEventListener("visibilitychange", handleVisibilityChange);
  }, [activeEngagement?.key]);

  // Deep-link sync: re-apply the parsed-route entry params when they change.
  // This handles a hashchange that arrives while this engagement is ALREADY
  // mounted (App renders EngagementPage without a `key`, so the same instance
  // stays mounted) — without these, the lazy state initializers above would
  // only fire on first mount and a pasted finding/tab deep-link would be a
  // no-op. The deps are exactly the parsed-route props: a manual tab click or
  // drawer interaction does NOT change them (FindingsTab's replaceState only
  // rewrites the hash to the active selection's own values), so the user is
  // never fought; compare-before-set keeps the sync idempotent and loop-free.
  useEffect(() => {
    const nextTab = coerceTabKey(initialTab);
    setActiveTab((current) => (current === nextTab ? current : nextTab));
  }, [initialTab]);

  useEffect(() => {
    const nextTab = coerceTabKey(initialTab);
    const nextSlug = nextTab === "findings" ? initialFindingSlug : undefined;
    const nextDrawerTab = nextTab === "findings" ? initialDrawerTab : undefined;
    setPendingFindingSlug((current) => (current === nextSlug ? current : nextSlug));
    setPendingDrawerTab((current) => (current === nextDrawerTab ? current : nextDrawerTab));
  }, [initialTab, initialFindingSlug, initialDrawerTab]);

  const displayEvents = events;
  const displayFindings = assessmentFindings.length > 0 ? assessmentFindings : (assessmentSummary?.top_findings ?? []);
  const chains = assessmentChains.length > 0 ? assessmentChains : (assessmentSummary?.attack_chains ?? []);
  const displaySummary = assessmentSummary;

  const intelTotal = intelSummary
    ? Object.values(intelSummary.counts).reduce((a, b) => a + b, 0)
    : undefined;

  const tabCounts: Partial<Record<TabKey, number>> = {
    findings: displaySummary?.finding_count ?? displayFindings.length,
    coverage: displaySummary?.coverage_count ?? 0,
    code: codeRepos.length > 0 ? codeResults.length : undefined,
    intel: intelTotal,
    // `open_surface_count` is the closest cheap figure in the existing
    // assessment summary; fall back to the loaded list if present.
    surfaces: displaySummary?.open_surface_count ?? assessmentSurfaces.length,
    // HTTP count = request-variant count, available cheaply in the summary
    // (already fetched for every tab). OAST has no summary figure, so its
    // count badge is owned by the tab (left undefined here).
    http: displaySummary?.request_variant_count || undefined,
    log: activityTotal || undefined,
  };

  const handleTabChange = (tab: TabKey) => {
    setActiveTab(tab);
    // A finding deep-link only applies to the findings tab. Switching tabs
    // drops the param: clear the pending slug and rewrite the hash to a
    // bare tab URL (FindingsTab re-adds ?finding=… while its drawer is open).
    if (tab !== "findings") {
      setPendingFindingSlug(undefined);
      setPendingDrawerTab(undefined);
    }
    writeEngagementHash(engagementKey, tab);
  };

  const handleExportReport = async () => {
    if (exportingReport) return;
    setExportingReport(true);
    try {
      // Draft export — no readiness gate. (A future "final" control can pass
      // mode="final"; the helper + backend already enforce the 409 gate.)
      const result = await exportReport(engagementKey, "draft");
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
    <main className="shell engagement-shell">
      {/* Header */}
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Engagement detail</p>
          <h1>{activeEngagement?.target ?? engagementKey}</h1>
        </div>
        <div className="page-actions">
          <div className="status-summary">
            <div className="status-summary-row">
              <span className="status-summary-label">Run status</span>
              <span className={`status-pill status-${engagement?.status ?? "queued"}`}>
                {formatStatusLabel(activeEngagement?.status)}
              </span>
            </div>
            <div className="status-summary-row">
              <span className="status-summary-label">Phase</span>
              <span className="meta-text">{formatStatusLabel(activeEngagement?.current_phase)}</span>
            </div>
          </div>
          {loadError && <span className="error-text">{loadError}</span>}
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
        <>
          <TabBar active={activeTab} onChange={handleTabChange} counts={tabCounts} />

          {activeTab === "overview" && (
            <OverviewTab
              engagementKey={engagementKey}
              events={displayEvents}
              assessmentSummary={displaySummary}
              findings={displayFindings}
              chains={chains}
              chainLinks={assessmentChainLinks}
              currentPhase={activeEngagement.current_phase}
              assessmentRefreshVersion={assessmentRefreshVersion}
            />
          )}

          {activeTab === "findings" && (
            <FindingsTab
              engagementKey={engagementKey}
              findings={displayFindings}
              fallbackFindings={displaySummary?.top_findings ?? []}
              chains={assessmentChains}
              chainLinks={assessmentChainLinks}
              assessmentRefreshVersion={assessmentRefreshVersion}
              initialFindingSlug={pendingFindingSlug}
              initialDrawerTab={pendingDrawerTab}
            />
          )}

          {activeTab === "runs" && (
            <RunsTab
              engagementKey={engagementKey}
              refreshVersion={assessmentRefreshVersion}
              initialRunId={initialRunId}
              initialSection={initialRunSection}
              initialObject={initialRunObject}
            />
          )}

          {activeTab === "submissions" && (
            <SubmissionsTab
              engagementKey={engagementKey}
              refreshVersion={assessmentRefreshVersion}
            />
          )}

          {activeTab === "code" && (
            <CodeAnalysisTab
              persistedPhase={activeEngagement.code_phase ?? activeEngagement.current_phase}
              loadError={codeLoadError}
              repos={codeRepos}
              modules={codeModules}
              queueStats={codeQueueStats}
              coverage={codeCoverage}
              readiness={codeReadiness}
              results={codeResults}
            />
          )}

          {activeTab === "coverage" && (
            <CoverageTab
              summary={displaySummary}
              targets={assessmentTargets}
              services={assessmentServices}
              coverageItems={assessmentCoverageItems}
            />
          )}

          {activeTab === "activity" && (
            <ActivityTab events={displayEvents} sessions={sessions} />
          )}

          {activeTab === "intel" && (
            <IntelTab engagementKey={engagementKey} summary={intelSummary} />
          )}

          {activeTab === "surfaces" && (
            <SurfacesTab
              engagementKey={engagementKey}
              surfaces={assessmentSurfaces}
              loadError={surfaceLoadError}
              findings={displayFindings}
            />
          )}

          {activeTab === "http" && (
            <HttpTab engagementKey={engagementKey} refreshVersion={assessmentRefreshVersion} />
          )}

          {activeTab === "commands" && (
            <CommandsTab engagementKey={engagementKey} />
          )}

          {activeTab === "oast" && (
            <OastTab engagementKey={engagementKey} refreshVersion={assessmentRefreshVersion} />
          )}

          {activeTab === "log" && (
            <LogTab engagementKey={engagementKey} />
          )}

          {activeTab === "artifacts" && (
            <ArtifactViewer
              artifacts={artifacts}
              selectedName={selectedName}
              selectedArtifact={selectedArtifact}
              onSelect={setSelectedName}
            />
          )}
        </>
      )}
    </main>
  );
}
