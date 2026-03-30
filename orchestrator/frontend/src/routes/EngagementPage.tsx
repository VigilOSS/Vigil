import { useEffect, useMemo, useState } from "react";

import {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFindingDetail,
  AssessmentFindingLink,
  AssessmentProbeDetail,
  AssessmentSummary,
  AssessmentSurface,
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
  listAssessmentFindingLinks,
  listAssessmentFindings,
  listAssessmentProbes,
  listAssessmentSurfaces,
  listEngagementSessions,
  listEvents,
  readArtifact,
} from "../lib/api";
import { ArtifactViewer } from "../components/ArtifactViewer";
import { PhaseWaterfall } from "../components/PhaseWaterfall";
import { TaskTimeline } from "../components/TaskTimeline";

type EngagementPageProps = {
  engagementKey: string;
  onBack: () => void;
};

export function EngagementPage({ engagementKey, onBack }: EngagementPageProps) {
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<EngagementSession[]>([]);
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [assessmentSummary, setAssessmentSummary] = useState<AssessmentSummary | null>(null);
  const [assessmentSurfaces, setAssessmentSurfaces] = useState<AssessmentSurface[]>([]);
  const [assessmentFindings, setAssessmentFindings] = useState<AssessmentFindingDetail[]>([]);
  const [assessmentFindingLinks, setAssessmentFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [assessmentProbes, setAssessmentProbes] = useState<AssessmentProbeDetail[]>([]);
  const [assessmentChains, setAssessmentChains] = useState<AssessmentAttackChainDetail[]>([]);
  const [assessmentChainLinks, setAssessmentChainLinks] = useState<AssessmentAttackChainLink[]>([]);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactContent | null>(null);
  const activeEngagement = engagement?.key === engagementKey ? engagement : null;

  useEffect(() => {
    setEngagement(null);
    setLoadError(null);
    setSessions([]);
    setSessionsOpen(false);
    setEvents([]);
    setArtifacts([]);
    setAssessmentSummary(null);
    setAssessmentSurfaces([]);
    setAssessmentFindings([]);
    setAssessmentFindingLinks([]);
    setAssessmentProbes([]);
    setAssessmentChains([]);
    setAssessmentChainLinks([]);
    setSelectedName(null);
    setSelectedArtifact(null);
  }, [engagementKey]);

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
    ]);
  }

  useEffect(() => {
    let cancelled = false;
    let refreshing = false;

    async function refreshPage() {
      if (refreshing) {
        return;
      }
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
    if (!activeEngagement) {
      return;
    }

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
    if (!activeEngagement) {
      return;
    }

    let refreshing = false;
    const interval = window.setInterval(() => {
      if (refreshing) {
        return;
      }
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
  const surfaces = assessmentSurfaces.length > 0 ? assessmentSurfaces : (assessmentSummary?.top_surfaces ?? []);
  const probes = assessmentProbes.length > 0 ? assessmentProbes : (assessmentSummary?.recent_probes ?? []);
  const chains = assessmentChains.length > 0 ? assessmentChains : (assessmentSummary?.attack_chains ?? []);
  const showNotFound = !activeEngagement && Boolean(loadError);

  return (
    <main className="shell engagement-shell">
      {/* ── Header ─────────────────────────────────────────────── */}
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Engagement detail</p>
          <h1>{activeEngagement?.target ?? engagementKey}</h1>
          <p className="lead">{latestSummary}</p>
        </div>
        <div className="page-actions">
          <button className="ghost-button" onClick={onBack}>
            Back to engagements
          </button>
        </div>
      </section>

      {/* ── Overview ───────────────────────────────────────────── */}
      <section className="engagement-overview panel">
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <span className={`status-pill status-${engagement?.status ?? "queued"}`}>
            {activeEngagement?.status ?? "queued"}
          </span>
          <span className="meta-text">Phase: {activeEngagement?.current_phase ?? "unknown"}</span>
          {loadError ? <span className="error-text">{loadError}</span> : null}
        </div>
      </section>

      {showNotFound ? (
        <section className="panel empty-state">Engagement not found.</section>
      ) : null}

      {!activeEngagement || showNotFound ? null : (
        <>
          {/* ── Phase waterfall ────────────────────────────────── */}
          <PhaseWaterfall events={events} />

          {/* ── Findings + Attack chains ───────────────────────── */}
          <section className="engagement-grid">
            <article className="panel">
              <p className="eyebrow">Findings</p>
              <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
                {findings.map((finding) => (
                  <div key={finding.slug} style={{ display: "grid", gap: "4px" }}>
                    <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                      <strong>{finding.title}</strong>
                      <span className={`badge severity-${finding.severity}`}>{finding.severity}</span>
                    </div>
                    <p className="meta-text">
                      {finding.status}
                      {finding.source_name ? ` · ${finding.source_name}` : ""}
                    </p>
                    {(finding.canonical_location || finding.summary) && (
                      <p className="meta-text">{finding.canonical_location || finding.summary}</p>
                    )}
                  </div>
                ))}
                {findings.length === 0 && (
                  <p className="meta-text">No findings recorded yet.</p>
                )}
              </div>
            </article>

            <article className="panel">
              <p className="eyebrow">Attack chains</p>
              <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
                {chains.map((chain) => (
                  <div key={chain.chain_key} style={{ display: "grid", gap: "4px" }}>
                    <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                      <strong>{chain.title}</strong>
                      <span className={`badge severity-${chain.severity}`}>{chain.severity}</span>
                    </div>
                    <p className="meta-text">{chain.status}</p>
                    {chain.narrative && <p className="meta-text">{chain.narrative}</p>}
                  </div>
                ))}
                {chains.length === 0 && (
                  <p className="meta-text">No attack chains linked yet.</p>
                )}
              </div>
            </article>
          </section>

          {/* ── Coverage stats ─────────────────────────────────── */}
          <section className="panel">
            <div className="panel-header">
              <div>
                <p className="eyebrow">Assessment state</p>
                <h2>Coverage</h2>
              </div>
            </div>
            <div className="stats-grid">
              <article className="stat-card">
                <span className="stat-value">{assessmentSummary?.finding_count ?? 0}</span>
                <span className="meta-text">Findings</span>
              </article>
              <article className="stat-card">
                <span className="stat-value">{assessmentSummary?.attack_chain_count ?? 0}</span>
                <span className="meta-text">Attack chains</span>
              </article>
              <article className="stat-card">
                <span className="stat-value">{assessmentSummary?.probe_count ?? 0}</span>
                <span className="meta-text">Probe runs</span>
              </article>
              <article className="stat-card">
                <span className="stat-value">{assessmentSummary?.target_count ?? 0}</span>
                <span className="meta-text">Targets</span>
              </article>
            </div>
          </section>

          {/* ── Surfaces + Probe runs ──────────────────────────── */}
          <section className="engagement-grid">
            <article className="panel">
              <p className="eyebrow">Priority surfaces</p>
              <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
                {surfaces.map((surface) => (
                  <div key={`${surface.surface_type}:${surface.target_descriptor}`} style={{ display: "grid", gap: "4px" }}>
                    <strong>{surface.surface_type}</strong>
                    <p className="meta-text">{surface.target_descriptor}</p>
                    <p className="meta-text">
                      {surface.status}
                      {surface.source_name ? ` · ${surface.source_name}` : ""}
                    </p>
                  </div>
                ))}
                {surfaces.length === 0 && (
                  <p className="meta-text">No surfaces recorded yet.</p>
                )}
              </div>
            </article>

            <article className="panel">
              <p className="eyebrow">Probe runs</p>
              <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
                {probes.map((probe, index) => (
                  <div key={`${probe.created_at}-${probe.attack_family}-${index}`} style={{ display: "grid", gap: "4px" }}>
                    <strong>{probe.attack_family}</strong>
                    <p className="meta-text">
                      {probe.result_status}
                      {probe.signal_type ? ` · ${probe.signal_type}` : ""}
                      {probe.agent_name ? ` · ${probe.agent_name}` : ""}
                    </p>
                  </div>
                ))}
                {probes.length === 0 && (
                  <p className="meta-text">No probe runs recorded yet.</p>
                )}
              </div>
            </article>
          </section>

          {/* ── Activity log ───────────────────────────────────── */}
          <TaskTimeline events={events} />

          {/* ── Sessions (collapsible) ─────────────────────────── */}
          <section className="panel">
            <button
              type="button"
              className="sessions-toggle"
              onClick={() => setSessionsOpen((o) => !o)}
              aria-expanded={sessionsOpen}
            >
              <span>Sessions</span>
              <span className="sessions-count">{sessions.length}</span>
              <span>{sessionsOpen ? "▴" : "▾"}</span>
            </button>
            {sessionsOpen && (
              <div className="timeline" style={{ marginTop: "14px" }}>
                {sessions.map((session) => (
                  <article key={session.id} className="timeline-row">
                    <div className="timeline-pill">{session.merge_state}</div>
                    <div className="timeline-body">
                      <div className="timeline-title-row">
                        <strong>{session.session_id}</strong>
                        <span className="meta-text">{session.status}</span>
                      </div>
                      {session.assigned_findings.length > 0 && (
                        <p className="meta-text">{session.assigned_findings.join(", ")}</p>
                      )}
                    </div>
                  </article>
                ))}
                {sessions.length === 0 && <p className="empty-state">No sessions recorded yet.</p>}
              </div>
            )}
          </section>

          {/* ── Artifacts ──────────────────────────────────────── */}
          <ArtifactViewer
            artifacts={artifacts}
            selectedName={selectedName}
            selectedArtifact={selectedArtifact}
            onSelect={setSelectedName}
          />
        </>
      )}
    </main>
  );
}
