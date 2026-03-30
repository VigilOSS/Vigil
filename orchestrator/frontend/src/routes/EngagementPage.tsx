import { useEffect, useMemo, useState } from "react";

import {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentCoverageItem,
  AssessmentFindingDetail,
  AssessmentFindingLink,
  AssessmentProbeDetail,
  AssessmentService,
  AssessmentSummary,
  AssessmentSurface,
  AssessmentTarget,
  Artifact,
  ArtifactContent,
  Engagement,
  EngagementSession,
  EventRecord,
  engagementWebSocketUrl,
  getAssessmentSummary,
  getEngagement,
  listArtifacts,
  listAssessmentAttackChainLinks,
  listAssessmentAttackChains,
  listAssessmentCoverageItems,
  listAssessmentFindingLinks,
  listAssessmentFindings,
  listAssessmentProbes,
  listAssessmentServices,
  listAssessmentSurfaces,
  listAssessmentTargets,
  listEngagementSessions,
  listEvents,
  readArtifact,
} from "../lib/api";
import { ActivityTab } from "../components/ActivityTab";
import { ArtifactViewer } from "../components/ArtifactViewer";
import { CoverageTab } from "../components/CoverageTab";
import { FindingsTab } from "../components/FindingsTab";
import { OverviewTab } from "../components/OverviewTab";
import { TabBar } from "../components/TabBar";
import type { TabKey } from "../components/TabBar";

type EngagementPageProps = {
  engagementKey: string;
  onBack: () => void;
};

export function EngagementPage({ engagementKey, onBack }: EngagementPageProps) {
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [sessions, setSessions] = useState<EngagementSession[]>([]);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [assessmentSummary, setAssessmentSummary] = useState<AssessmentSummary | null>(null);
  const [assessmentSurfaces, setAssessmentSurfaces] = useState<AssessmentSurface[]>([]);
  const [assessmentFindings, setAssessmentFindings] = useState<AssessmentFindingDetail[]>([]);
  const [assessmentFindingLinks, setAssessmentFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [assessmentProbes, setAssessmentProbes] = useState<AssessmentProbeDetail[]>([]);
  const [assessmentChains, setAssessmentChains] = useState<AssessmentAttackChainDetail[]>([]);
  const [assessmentChainLinks, setAssessmentChainLinks] = useState<AssessmentAttackChainLink[]>([]);
  const [assessmentTargets, setAssessmentTargets] = useState<AssessmentTarget[]>([]);
  const [assessmentServices, setAssessmentServices] = useState<AssessmentService[]>([]);
  const [assessmentCoverageItems, setAssessmentCoverageItems] = useState<AssessmentCoverageItem[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactContent | null>(null);
  const activeEngagement = engagement?.key === engagementKey ? engagement : null;

  // Keep link state fetched for future use
  void assessmentFindingLinks;
  void assessmentChainLinks;
  void assessmentSurfaces;
  void assessmentProbes;

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
    readArtifact(engagementKey, name)
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

  function refreshAssessment() {
    return Promise.all([
      getAssessmentSummary(engagementKey).then(setAssessmentSummary),
      listAssessmentSurfaces(engagementKey).then(setAssessmentSurfaces),
      listAssessmentFindings(engagementKey).then(setAssessmentFindings),
      listAssessmentFindingLinks(engagementKey).then(setAssessmentFindingLinks),
      listAssessmentProbes(engagementKey).then(setAssessmentProbes),
      listAssessmentAttackChains(engagementKey).then(setAssessmentChains),
      listAssessmentAttackChainLinks(engagementKey).then(setAssessmentChainLinks),
      listAssessmentTargets(engagementKey).then(setAssessmentTargets),
      listAssessmentServices(engagementKey).then(setAssessmentServices),
      listAssessmentCoverageItems(engagementKey).then(setAssessmentCoverageItems),
    ]);
  }

  useEffect(() => {
    let cancelled = false;
    let refreshing = false;

    async function refreshPage() {
      if (refreshing) return;
      refreshing = true;
      try {
        try {
          await refreshEngagement();
        } catch (error) {
          if (cancelled) return;
          const message = error instanceof Error ? error.message : "Failed to load engagement";
          setLoadError(message);
          setEngagement(null);
          setSessions([]);
          setEvents([]);
          setArtifacts([]);
          setAssessmentSummary(null);
          setAssessmentSurfaces([]);
          setAssessmentFindings([]);
          setAssessmentFindingLinks([]);
          setAssessmentProbes([]);
          setAssessmentChains([]);
          setAssessmentChainLinks([]);
          setAssessmentTargets([]);
          setAssessmentServices([]);
          setAssessmentCoverageItems([]);
          setSelectedName(null);
          setSelectedArtifact(null);
          return;
        }

        if (cancelled) return;

        await Promise.all([refreshSessions(), refreshEvents(), refreshArtifacts(), refreshAssessment()]);
      } catch (error) {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : "Failed to load engagement details";
        setLoadError(message);
      } finally {
        refreshing = false;
      }
    }

    void refreshPage();

    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  useEffect(() => {
    if (!activeEngagement || !selectedName) {
      setSelectedArtifact(null);
      return;
    }
    refreshSelectedArtifact(selectedName);
  }, [activeEngagement, engagementKey, selectedName]);

  useEffect(() => {
    if (!activeEngagement) return;

    const socket = new WebSocket(engagementWebSocketUrl(engagementKey));
    socket.onerror = () => {
      setLoadError((current) => current ?? "Live updates unavailable");
    };
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === "event.created") {
        setEvents((current) => [...current, payload.event as EventRecord]);
      }
      if (payload.type === "assessment.updated") {
        refreshAssessment();
      }
      refreshEngagement();
      refreshSessions();
      refreshArtifacts();
      if (selectedName) {
        refreshSelectedArtifact(selectedName);
      }
    };

    return () => socket.close();
  }, [activeEngagement, engagementKey, selectedName]);

  useEffect(() => {
    if (!activeEngagement) return;

    let refreshing = false;
    const interval = window.setInterval(() => {
      if (refreshing) return;
      refreshing = true;
      void refreshEngagement()
        .then(() => Promise.all([refreshSessions(), refreshEvents(), refreshArtifacts(), refreshAssessment()]))
        .then(() => {
          if (selectedName) {
            refreshSelectedArtifact(selectedName);
          }
        })
        .catch((error) => {
          const message = error instanceof Error ? error.message : "Failed to refresh engagement";
          setLoadError(message);
        })
        .finally(() => {
          refreshing = false;
        });
    }, 5000);

    return () => window.clearInterval(interval);
  }, [activeEngagement, engagementKey, selectedName]);

  const latestSummary = useMemo(
    () => (activeEngagement ? events.at(-1)?.summary ?? "Waiting for events" : "Waiting for events"),
    [activeEngagement, events],
  );

  const findings = assessmentFindings.length > 0 ? assessmentFindings : (assessmentSummary?.top_findings ?? []);
  const chains = assessmentChains.length > 0 ? assessmentChains : (assessmentSummary?.attack_chains ?? []);

  const tabCounts: Partial<Record<TabKey, number>> = {
    findings: assessmentSummary?.finding_count ?? 0,
    coverage: assessmentSummary?.coverage_count ?? 0,
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
          <span className={`status-pill status-${engagement?.status ?? "queued"}`}>
            {activeEngagement?.status ?? "queued"}
          </span>
          <span className="meta-text">Phase: {activeEngagement?.current_phase ?? "unknown"}</span>
          {loadError && <span className="error-text">{loadError}</span>}
          <button className="ghost-button" onClick={onBack}>Back</button>
        </div>
      </section>

      {!activeEngagement ? null : (
        <>
          <TabBar active={activeTab} onChange={setActiveTab} counts={tabCounts} />

          {activeTab === "overview" && (
            <OverviewTab
              events={events}
              assessmentSummary={assessmentSummary}
              findings={findings}
              chains={chains}
            />
          )}

          {activeTab === "findings" && (
            <FindingsTab
              findings={assessmentFindings}
              fallbackFindings={assessmentSummary?.top_findings ?? []}
              summary={assessmentSummary}
            />
          )}

          {activeTab === "coverage" && (
            <CoverageTab
              summary={assessmentSummary}
              targets={assessmentTargets}
              services={assessmentServices}
              coverageItems={assessmentCoverageItems}
            />
          )}

          {activeTab === "activity" && (
            <ActivityTab events={events} sessions={sessions} />
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
