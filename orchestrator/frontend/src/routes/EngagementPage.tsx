import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";

import {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentCoverageItem,
  AssessmentFindingDetail,
  AssessmentService,
  AssessmentSummary,
  AssessmentTarget,
  Artifact,
  ArtifactContent,
  CodeAnalysisResult,
  CodeCoverage,
  CodeModule,
  CodeQueueStats,
  CodeRepo,
  Engagement,
  EngagementSession,
  EventRecord,
  engagementWebSocketUrl,
  getAssessmentSummary,
  getCodeCoverage,
  getCodeQueueStats,
  getEngagement,
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
  readArtifact,
} from "../lib/api";
import { ActivityTab } from "../components/ActivityTab";
import { ArtifactViewer } from "../components/ArtifactViewer";
import { CodeAnalysisTab } from "../components/CodeAnalysisTab";
import { CoverageTab } from "../components/CoverageTab";
import { FindingsTab } from "../components/FindingsTab";
import { OverviewTab } from "../components/OverviewTab";
import { TabBar } from "../components/TabBar";
import type { TabKey } from "../components/TabBar";

type EngagementPageProps = {
  engagementKey: string;
  onBack: () => void;
};

function formatStatusLabel(value: string | undefined) {
  return (value ?? "unknown").replace(/_/g, " ");
}

export function EngagementPage({ engagementKey, onBack }: EngagementPageProps) {
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
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
  const [codeRepos, setCodeRepos] = useState<CodeRepo[]>([]);
  const [codeModules, setCodeModules] = useState<CodeModule[]>([]);
  const [codeQueueStats, setCodeQueueStats] = useState<CodeQueueStats | null>(null);
  const [codeCoverage, setCodeCoverage] = useState<CodeCoverage | null>(null);
  const [codeResults, setCodeResults] = useState<CodeAnalysisResult[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactContent | null>(null);
  const activeEngagement = engagement?.key === engagementKey ? engagement : null;
  const selectedNameRef = useRef<string | null>(selectedName);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const refreshQueuedRef = useRef(false);
  const socketConnectedRef = useRef(false);
  const hasConnectedOnceRef = useRef(false);
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

  function refreshCodeAnalysis() {
    return Promise.all([
      listCodeRepos(engagementKey).then(setCodeRepos).catch(() => setCodeRepos([])),
      listCodeModules(engagementKey).then(setCodeModules).catch(() => setCodeModules([])),
      getCodeQueueStats(engagementKey).then(setCodeQueueStats).catch(() => setCodeQueueStats(null)),
      getCodeCoverage(engagementKey).then(setCodeCoverage).catch(() => setCodeCoverage(null)),
      listCodeAnalysisResults(engagementKey).then(setCodeResults).catch(() => setCodeResults([])),
    ]);
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
        setCodeResults([]);
        setSelectedName(null);
        setSelectedArtifact(null);
        return;
      }

      // Always refresh events + assessment summary (lightweight, needed for tab counts)
      const promises: Promise<unknown>[] = [
        refreshEvents(),
        getAssessmentSummary(engagementKey).then(setAssessmentSummary),
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
            listAssessmentCoverageItems(engagementKey).then(setAssessmentCoverageItems),
          );
          break;
        case "code":
          promises.push(refreshCodeAnalysis());
          break;
        case "activity":
          promises.push(refreshSessions());
          break;
        case "artifacts":
          promises.push(refreshArtifacts());
          break;
      }

      await Promise.all(promises);

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
        if (hasConnectedOnceRef.current) {
          requestRefresh();
        } else {
          hasConnectedOnceRef.current = true;
        }
      };
      socket.onerror = () => {
        setLoadError((current) => current ?? "Live updates unavailable");
      };
      socket.onclose = () => {
        socketConnectedRef.current = false;
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

  const displayEvents = events;
  const displayFindings = assessmentFindings.length > 0 ? assessmentFindings : (assessmentSummary?.top_findings ?? []);
  const chains = assessmentChains.length > 0 ? assessmentChains : (assessmentSummary?.attack_chains ?? []);
  const displaySummary = assessmentSummary;

  const latestSummary = useMemo(
    () => (activeEngagement ? displayEvents.at(-1)?.summary ?? "Waiting for recorded activity" : "Waiting for recorded activity"),
    [activeEngagement, displayEvents],
  );

  const tabCounts: Partial<Record<TabKey, number>> = {
    findings: displaySummary?.finding_count ?? displayFindings.length,
    coverage: displaySummary?.coverage_count ?? 0,
    code: codeRepos.length > 0 ? codeResults.length : undefined,
  };

  return (
    <main className="shell engagement-shell">
      {/* Header */}
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Engagement detail</p>
          <h1>{activeEngagement?.target ?? engagementKey}</h1>
          <p className="lead">{latestSummary}</p>
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
          <button className="ghost-button" onClick={onBack}>Back</button>
        </div>
      </section>

      {!activeEngagement ? null : (
        <>
          <TabBar active={activeTab} onChange={setActiveTab} counts={tabCounts} />

          {activeTab === "overview" && (
            <OverviewTab
              events={displayEvents}
              assessmentSummary={displaySummary}
              findings={displayFindings}
              chains={chains}
              chainLinks={assessmentChainLinks}
              currentPhase={activeEngagement.current_phase}
            />
          )}

          {activeTab === "findings" && (
            <FindingsTab
              engagementKey={engagementKey}
              findings={displayFindings}
              fallbackFindings={displaySummary?.top_findings ?? []}
              chains={assessmentChains}
              chainLinks={assessmentChainLinks}
            />
          )}

          {activeTab === "code" && (
            <CodeAnalysisTab
              repos={codeRepos}
              modules={codeModules}
              queueStats={codeQueueStats}
              coverage={codeCoverage}
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
