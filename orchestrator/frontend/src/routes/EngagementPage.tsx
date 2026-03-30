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
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactContent | null>(null);

  function refreshArtifacts() {
    listArtifacts(engagementKey).then((nextArtifacts) => {
      setArtifacts(nextArtifacts);
      if (!selectedName) {
        const firstAvailable = nextArtifacts.find((artifact) => artifact.exists);
        if (firstAvailable) {
          setSelectedName(firstAvailable.name);
        }
      }
    });
  }

  function refreshSelectedArtifact(name: string) {
    readArtifact(engagementKey, name)
      .then(setSelectedArtifact)
      .catch(() => setSelectedArtifact(null));
  }

  function refreshEngagement() {
    getEngagement(engagementKey).then(setEngagement);
    listEngagementSessions(engagementKey).then(setSessions);
  }

  function refreshEvents() {
    listEvents(engagementKey).then(setEvents);
  }

  function refreshAssessment() {
    getAssessmentSummary(engagementKey).then(setAssessmentSummary);
    listAssessmentSurfaces(engagementKey).then(setAssessmentSurfaces);
    listAssessmentFindings(engagementKey).then(setAssessmentFindings);
    listAssessmentFindingLinks(engagementKey).then(setAssessmentFindingLinks);
    listAssessmentProbes(engagementKey).then(setAssessmentProbes);
    listAssessmentAttackChains(engagementKey).then(setAssessmentChains);
    listAssessmentAttackChainLinks(engagementKey).then(setAssessmentChainLinks);
  }

  useEffect(() => {
    refreshEngagement();
    refreshEvents();
    refreshArtifacts();
    refreshAssessment();
  }, [engagementKey]);

  useEffect(() => {
    if (!selectedName) {
      setSelectedArtifact(null);
      return;
    }
    refreshSelectedArtifact(selectedName);
  }, [engagementKey, selectedName]);

  useEffect(() => {
    const socket = new WebSocket(engagementWebSocketUrl(engagementKey));
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === "event.created") {
        setEvents((current) => [...current, payload.event as EventRecord]);
      }
      if (payload.type === "assessment.updated") {
        refreshAssessment();
      }
      refreshEngagement();
      refreshArtifacts();
      if (selectedName) {
        refreshSelectedArtifact(selectedName);
      }
    };

    return () => socket.close();
  }, [engagementKey, selectedName]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      refreshEngagement();
      refreshEvents();
      refreshArtifacts();
      refreshAssessment();
      if (selectedName) {
        refreshSelectedArtifact(selectedName);
      }
    }, 3000);

    return () => window.clearInterval(interval);
  }, [engagementKey, selectedName]);

  const latestSummary = useMemo(() => events.at(-1)?.summary ?? "Waiting for events", [events]);
  const findingLinksBySlug = useMemo(() => {
    const groups = new Map<string, AssessmentFindingLink[]>();
    assessmentFindingLinks.forEach((link) => {
      const current = groups.get(link.finding_slug) ?? [];
      current.push(link);
      groups.set(link.finding_slug, current);
    });
    return groups;
  }, [assessmentFindingLinks]);
  const chainLinksByKey = useMemo(() => {
    const groups = new Map<string, AssessmentAttackChainLink[]>();
    assessmentChainLinks.forEach((link) => {
      const current = groups.get(link.chain_key) ?? [];
      current.push(link);
      groups.set(link.chain_key, current);
    });
    return groups;
  }, [assessmentChainLinks]);

  return (
    <main className="shell engagement-shell">
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Engagement detail</p>
          <h1>{engagement?.target ?? engagementKey}</h1>
          <p className="lead">{latestSummary}</p>
        </div>
        <div className="page-actions">
          <button className="ghost-button" onClick={onBack}>
            Back to engagements
          </button>
        </div>
      </section>

      <section className="engagement-overview panel">
        <div>
          <span className={`status-pill status-${engagement?.status ?? "queued"}`}>
            {engagement?.status ?? "queued"}
          </span>
          <p className="meta-text">{engagement?.engagement_root ?? "Pending engagement root"}</p>
          <p className="meta-text">
            Phase: {engagement?.current_phase ?? "unknown"} | Exploit policy:{" "}
            {engagement?.exploit_policy ?? "pause"} | Review: {engagement?.exploit_review_state ?? "pending"}
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Sessions</p>
            <h2>AI session state</h2>
          </div>
        </div>
        <div className="timeline">
          {sessions.map((session) => (
            <article key={session.id} className="timeline-row">
              <div className="timeline-pill">{session.merge_state}</div>
              <div className="timeline-body">
                <div className="timeline-title-row">
                  <strong>{session.session_id}</strong>
                  <span className="meta-text">{session.status}</span>
                </div>
                <p>{session.assigned_findings.length > 0 ? session.assigned_findings.join(", ") : "No assigned findings recorded."}</p>
                <p className="meta-text">{session.session_path}</p>
              </div>
            </article>
          ))}
          {sessions.length === 0 ? <p className="empty-state">No sessions recorded yet.</p> : null}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Assessment state</p>
            <h2>Coverage ledger</h2>
          </div>
        </div>
        <div className="stats-grid">
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.target_count ?? 0}</span>
            <span className="meta-text">Targets</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.service_count ?? 0}</span>
            <span className="meta-text">Services</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.request_variant_count ?? 0}</span>
            <span className="meta-text">Request variants</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.coverage_count ?? 0}</span>
            <span className="meta-text">Coverage items</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.probe_count ?? 0}</span>
            <span className="meta-text">Probe runs</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.attack_chain_count ?? 0}</span>
            <span className="meta-text">Attack chains</span>
          </article>
        </div>
      </section>

      <PhaseWaterfall events={events} />
      <TaskTimeline events={events} />

      <section className="engagement-grid">
        <article className="panel">
          <p className="eyebrow">Priority surfaces</p>
          {(assessmentSurfaces.length > 0 ? assessmentSurfaces : assessmentSummary?.top_surfaces ?? []).map((surface) => (
            <div key={`${surface.surface_type}:${surface.target_descriptor}`} style={{ marginBottom: "1rem" }}>
              <strong>{surface.surface_type}</strong>
              <p className="meta-text">{surface.target_descriptor}</p>
              <p className="meta-text">{surface.status} via {surface.source_name || "unknown source"}</p>
            </div>
          ))}
          {!assessmentSurfaces.length && !(assessmentSummary?.top_surfaces.length) && (
            <p className="meta-text">No structured surfaces recorded yet.</p>
          )}
        </article>
        <article className="panel">
          <p className="eyebrow">Live findings</p>
          {(assessmentFindings.length > 0 ? assessmentFindings : assessmentSummary?.top_findings ?? []).map((finding) => (
            <div key={finding.slug} style={{ marginBottom: "1rem" }}>
              <strong>{finding.title}</strong>
              <p className="meta-text">
                {finding.status} · {finding.severity}
                {finding.source_name ? ` · ${finding.source_name}` : ""}
              </p>
              <p className="meta-text">{finding.canonical_location || finding.summary || "No location recorded yet."}</p>
              {(findingLinksBySlug.get(finding.slug) ?? []).length > 0 ? (
                <p className="meta-text">
                  {(findingLinksBySlug.get(finding.slug) ?? [])
                    .map((link) => `${link.link_kind}:${link.target_kind}`)
                    .join(" | ")}
                </p>
              ) : null}
            </div>
          ))}
          {!(assessmentFindings.length || assessmentSummary?.top_findings.length) && (
            <p className="meta-text">No durable findings recorded yet.</p>
          )}
        </article>
      </section>

      <section className="engagement-grid">
        <article className="panel">
          <p className="eyebrow">Exploit activity</p>
          {(assessmentProbes.length > 0 ? assessmentProbes : assessmentSummary?.recent_probes ?? []).map((probe, index) => (
            <div key={`${probe.created_at}-${probe.attack_family}-${index}`} style={{ marginBottom: "1rem" }}>
              <strong>{probe.attack_family}</strong>
              <p className="meta-text">
                {probe.result_status}
                {probe.signal_type ? ` · ${probe.signal_type}` : ""}
                {probe.agent_name ? ` · ${probe.agent_name}` : ""}
              </p>
              <p className="meta-text">{probe.evidence_ref || "No evidence artifact recorded."}</p>
            </div>
          ))}
          {!(assessmentProbes.length || assessmentSummary?.recent_probes.length) && (
            <p className="meta-text">No exploit or validation probes recorded yet.</p>
          )}
        </article>
        <article className="panel">
          <p className="eyebrow">Attack chains</p>
          {(assessmentChains.length > 0 ? assessmentChains : assessmentSummary?.attack_chains ?? []).map((chain) => (
            <div key={chain.chain_key} style={{ marginBottom: "1rem" }}>
              <strong>{chain.title}</strong>
              <p className="meta-text">
                {chain.status} · {chain.severity}
              </p>
              <p className="meta-text">{chain.narrative || "No narrative recorded yet."}</p>
              {(chainLinksByKey.get(chain.chain_key) ?? []).length > 0 ? (
                <p className="meta-text">
                  {(chainLinksByKey.get(chain.chain_key) ?? [])
                    .map((link) => `${link.relation}:${link.entity_kind}`)
                    .join(" | ")}
                </p>
              ) : null}
            </div>
          ))}
          {!(assessmentChains.length || assessmentSummary?.attack_chains.length) && (
            <p className="meta-text">No attack chains linked yet.</p>
          )}
        </article>
      </section>

      <ArtifactViewer
        artifacts={artifacts}
        selectedName={selectedName}
        selectedArtifact={selectedArtifact}
        onSelect={setSelectedName}
      />
    </main>
  );
}
