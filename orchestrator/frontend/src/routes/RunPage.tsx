import { useEffect, useMemo, useState } from "react";

import {
  AssessmentSummary,
  AssessmentSurface,
  Artifact,
  ArtifactContent,
  EventRecord,
  Run,
  createWebSocketTicket,
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
