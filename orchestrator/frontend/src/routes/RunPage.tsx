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
  EventRecord,
  Run,
  createWebSocketTicket,
  listAssessmentAttackChainLinks,
  listAssessmentAttackChains,
  listAssessmentFindingLinks,
  listAssessmentFindings,
  listAssessmentProbes,
  getAssessmentSummary,
  listArtifacts,
  listAssessmentSurfaces,
  listEvents,
  listRuns,
  readArtifact,
  runWebSocketUrl,
} from "../lib/api";
import { ArtifactViewer } from "../components/ArtifactViewer";
import { PhaseWaterfall } from "../components/PhaseWaterfall";
import { TaskTimeline } from "../components/TaskTimeline";

type RunPageProps = {
  token: string;
  projectId: number;
  runId: number;
  onBack: () => void;
  onDeleteRun: (projectId: number, runId: number) => Promise<void>;
};

export function RunPage({ token, projectId, runId, onBack, onDeleteRun }: RunPageProps) {
  const [run, setRun] = useState<Run | null>(null);
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
    listArtifacts(token, projectId, runId).then((nextArtifacts) => {
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
    readArtifact(token, projectId, runId, name)
      .then(setSelectedArtifact)
      .catch(() => setSelectedArtifact(null));
  }

  function refreshRunState() {
    listRuns(token, projectId).then((runs) => {
      setRun(runs.find((candidate) => candidate.id === runId) ?? null);
    });
  }

  function refreshEvents() {
    listEvents(token, projectId, runId).then(setEvents);
  }

  function refreshAssessment() {
    getAssessmentSummary(token, projectId, runId).then(setAssessmentSummary);
    listAssessmentSurfaces(token, projectId, runId).then(setAssessmentSurfaces);
    listAssessmentFindings(token, projectId, runId).then(setAssessmentFindings);
    listAssessmentFindingLinks(token, projectId, runId).then(setAssessmentFindingLinks);
    listAssessmentProbes(token, projectId, runId).then(setAssessmentProbes);
    listAssessmentAttackChains(token, projectId, runId).then(setAssessmentChains);
    listAssessmentAttackChainLinks(token, projectId, runId).then(setAssessmentChainLinks);
  }

  useEffect(() => {
    refreshRunState();
    refreshEvents();
    refreshArtifacts();
    refreshAssessment();
  }, [projectId, runId, token]);

  useEffect(() => {
    if (!selectedName) {
      setSelectedArtifact(null);
      return;
    }
    refreshSelectedArtifact(selectedName);
  }, [projectId, runId, selectedName, token]);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let cancelled = false;

    async function connect() {
      const ticket = await createWebSocketTicket(token);
      if (cancelled) {
        return;
      }

      socket = new WebSocket(runWebSocketUrl(projectId, runId, ticket.ticket));
      socket.onmessage = (message) => {
        const payload = JSON.parse(message.data);
        if (payload.type === "event.created") {
          setEvents((current) => [...current, payload.event as EventRecord]);
        }
        if (payload.type === "run.status.updated") {
          setRun(payload.run as Run);
        }
        if (payload.type === "assessment.updated") {
          refreshAssessment();
        }
        refreshArtifacts();
        if (selectedName) {
          refreshSelectedArtifact(selectedName);
        }
      };
    }

    void connect();

    return () => {
      cancelled = true;
      socket?.close();
    };
  }, [projectId, runId, token]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      refreshRunState();
      refreshEvents();
      refreshArtifacts();
      refreshAssessment();
      if (selectedName) {
        refreshSelectedArtifact(selectedName);
      }
    }, 3000);

    return () => window.clearInterval(interval);
  }, [projectId, runId, selectedName, token]);

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

  async function handleDeleteRun() {
    if (!window.confirm("Delete this run and all of its files?")) {
      return;
    }
    await onDeleteRun(projectId, runId);
  }

  return (
    <main className="shell run-shell">
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Run detail</p>
          <h1>{run?.target ?? `Run #${runId}`}</h1>
          <p className="lead">{latestSummary}</p>
        </div>
        <div className="page-actions">
          <button className="ghost-button danger-button" onClick={() => void handleDeleteRun()}>
            Delete run
          </button>
          <button className="ghost-button" onClick={onBack}>
            Back to projects
          </button>
        </div>
      </section>

      <section className="run-overview panel">
        <div>
          <span className={`status-pill status-${run?.status ?? "queued"}`}>{run?.status ?? "queued"}</span>
          <p className="meta-text">{run?.engagement_root ?? "Pending engagement root"}</p>
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
            <span className="stat-value">{assessmentSummary?.open_surface_count ?? 0}</span>
            <span className="meta-text">Open surfaces</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.credential_count ?? 0}</span>
            <span className="meta-text">Credentials</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.access_count ?? 0}</span>
            <span className="meta-text">Access records</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.pivot_count ?? 0}</span>
            <span className="meta-text">Pivots</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.tunnel_count ?? 0}</span>
            <span className="meta-text">Tunnels</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.blocked_technique_count ?? 0}</span>
            <span className="meta-text">Blocked techniques</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{assessmentSummary?.attack_chain_count ?? 0}</span>
            <span className="meta-text">Attack chains</span>
          </article>
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Phase workers</p>
            {assessmentSummary?.phase_workers.map((phase) => (
              <div key={phase.phase} style={{ marginBottom: "1rem" }}>
                <strong>{phase.title}</strong>
                <p className="meta-text">
                  {phase.workers.map((worker) => `${worker.agent}: ${worker.responsibility}`).join(" | ")}
                </p>
                <p className="meta-text">
                  Active: {phase.active_agents.length > 0 ? phase.active_agents.join(", ") : "none yet"}
                </p>
              </div>
            ))}
          </article>
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
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Live findings</p>
            {(assessmentSummary?.top_findings ?? []).map((finding) => (
              <div key={finding.slug} style={{ marginBottom: "1rem" }}>
                <strong>{finding.title}</strong>
                <p className="meta-text">
                  {finding.status} · {finding.severity}
                  {finding.source_name ? ` · ${finding.source_name}` : ""}
                </p>
                <p className="meta-text">{finding.canonical_location || finding.summary || "No location recorded yet."}</p>
              </div>
            ))}
            {!(assessmentSummary?.top_findings.length) && <p className="meta-text">No durable findings recorded yet.</p>}
          </article>
          <article className="panel">
            <p className="eyebrow">Exploit activity</p>
            {(assessmentSummary?.recent_probes ?? []).map((probe, index) => (
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
            {!(assessmentSummary?.recent_probes.length) && <p className="meta-text">No exploit or validation probes recorded yet.</p>}
          </article>
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Attack chains</p>
            {(assessmentSummary?.attack_chains ?? []).map((chain) => (
              <div key={chain.chain_key} style={{ marginBottom: "1rem" }}>
                <strong>{chain.title}</strong>
                <p className="meta-text">
                  {chain.status} · {chain.severity}
                </p>
                <p className="meta-text">{chain.narrative || "No narrative recorded yet."}</p>
              </div>
            ))}
            {!(assessmentSummary?.attack_chains.length) && <p className="meta-text">No attack chains linked yet.</p>}
          </article>
          <article className="panel">
            <p className="eyebrow">Coverage gaps</p>
            {(assessmentSummary?.open_coverage_items ?? []).map((item, index) => (
              <div key={`${item.updated_at}-${item.input_slot}-${index}`} style={{ marginBottom: "1rem" }}>
                <strong>{item.attack_family}</strong>
                <p className="meta-text">
                  {item.status} · {item.input_slot} · {item.auth_context}
                </p>
                <p className="meta-text">{item.canonical_url || item.service_endpoint || "No target descriptor recorded."}</p>
              </div>
            ))}
            {!(assessmentSummary?.open_coverage_items.length) && <p className="meta-text">No open request or service coverage gaps.</p>}
          </article>
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Service coverage</p>
            {(assessmentSummary?.service_coverage_gaps ?? []).map((service) => (
              <div key={service.endpoint} style={{ marginBottom: "1rem" }}>
                <strong>{service.endpoint}</strong>
                <p className="meta-text">
                  {service.service || "unknown"} · {service.coverage_status}
                </p>
              </div>
            ))}
            {!(assessmentSummary?.service_coverage_gaps.length) && <p className="meta-text">No open service-level coverage gaps.</p>}
          </article>
          <article className="panel">
            <p className="eyebrow">Finding lifecycle</p>
            {Object.entries(assessmentSummary?.finding_statuses ?? {}).map(([findingStatus, total]) => (
              <div key={findingStatus} style={{ marginBottom: "0.75rem" }}>
                <strong>{findingStatus}</strong>
                <p className="meta-text">{total} finding(s)</p>
              </div>
            ))}
            {!Object.keys(assessmentSummary?.finding_statuses ?? {}).length && (
              <p className="meta-text">No finding states recorded yet.</p>
            )}
          </article>
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Findings ledger</p>
            {assessmentFindings.map((finding) => (
              <div key={finding.slug} style={{ marginBottom: "1rem" }}>
                <strong>{finding.title}</strong>
                <p className="meta-text">
                  {finding.slug} · {finding.status} · {finding.severity} · {finding.auth_context}
                </p>
                <p className="meta-text">{finding.canonical_location || finding.summary || "No location recorded yet."}</p>
                <p className="meta-text">
                  {finding.defect_family || "unknown family"}
                  {finding.merged_into_slug ? ` · merged into ${finding.merged_into_slug}` : ""}
                </p>
                <p className="meta-text">{finding.evidence_ref || "No primary evidence ref recorded."}</p>
              </div>
            ))}
            {!assessmentFindings.length && <p className="meta-text">No detailed findings available yet.</p>}
          </article>
          <article className="panel">
            <p className="eyebrow">Evidence and related links</p>
            {assessmentFindings.map((finding) => {
              const links = findingLinksBySlug.get(finding.slug) ?? [];
              if (!links.length) {
                return null;
              }
              return (
                <div key={finding.slug} style={{ marginBottom: "1rem" }}>
                  <strong>{finding.slug}</strong>
                  {links.slice(0, 6).map((link) => (
                    <p className="meta-text" key={link.id}>
                      {link.link_kind} · {link.target_kind} · {link.target_ref || "id-backed link"}
                    </p>
                  ))}
                </div>
              );
            })}
            {!assessmentFindingLinks.length && <p className="meta-text">No finding links recorded yet.</p>}
          </article>
        </div>
        <div className="run-grid">
          <article className="panel">
            <p className="eyebrow">Chain inspection</p>
            {assessmentChains.map((chain) => (
              <div key={chain.chain_key} style={{ marginBottom: "1rem" }}>
                <strong>{chain.title}</strong>
                <p className="meta-text">
                  {chain.chain_key} · {chain.status} · {chain.severity}
                </p>
                <p className="meta-text">{chain.narrative || "No narrative recorded yet."}</p>
                {(chainLinksByKey.get(chain.chain_key) ?? []).slice(0, 6).map((link) => (
                  <p className="meta-text" key={link.id}>
                    {link.relation} · {link.entity_kind} · {link.entity_ref || "id-backed relation"}
                  </p>
                ))}
              </div>
            ))}
            {!assessmentChains.length && <p className="meta-text">No detailed attack chains available yet.</p>}
          </article>
          <article className="panel">
            <p className="eyebrow">Probe history</p>
            {assessmentProbes.slice(0, 12).map((probe) => (
              <div key={probe.id} style={{ marginBottom: "1rem" }}>
                <strong>{probe.attack_family}</strong>
                <p className="meta-text">
                  {probe.result_status} · {probe.input_slot} · {probe.auth_context}
                </p>
                <p className="meta-text">
                  {probe.payload_family || "no payload family"} · {probe.tool_name || "unknown tool"}
                </p>
                <p className="meta-text">{probe.evidence_ref || probe.notes || "No evidence or notes recorded."}</p>
              </div>
            ))}
            {!assessmentProbes.length && <p className="meta-text">No detailed probe history available yet.</p>}
          </article>
        </div>
      </section>

      <PhaseWaterfall events={events} />

      <section className="run-grid">
        <TaskTimeline events={events} />
        <ArtifactViewer
          artifacts={artifacts}
          selectedName={selectedName}
          selectedArtifact={selectedArtifact}
          onSelect={setSelectedName}
        />
      </section>
    </main>
  );
}
