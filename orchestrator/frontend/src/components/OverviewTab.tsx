import type {
  AssessmentAttackChain,
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentSummary,
  EventRecord,
} from "../lib/api";
import { PhaseWaterfall } from "./PhaseWaterfall";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

type OverviewTabProps = {
  events: EventRecord[];
  assessmentSummary: AssessmentSummary | null;
  findings: (AssessmentFindingDetail | AssessmentFinding)[];
  chains: (AssessmentAttackChainDetail | AssessmentAttackChain)[];
  chainLinks: AssessmentAttackChainLink[];
  currentPhase: string;
};

function sortFindings(findings: (AssessmentFindingDetail | AssessmentFinding)[]) {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

export function OverviewTab({ events, assessmentSummary, findings, chains, chainLinks, currentPhase }: OverviewTabProps) {
  const s = assessmentSummary;
  const sortedFindings = sortFindings(findings);
  const latestEvents = events
    .filter((e) => e.event_type !== "artifact.updated")
    .slice(-5);

  return (
    <>
      <PhaseWaterfall events={events} currentPhase={currentPhase} />

      <section className="panel">
        <div className="panel-header">
          <h2>Coverage</h2>
        </div>
        <div className="stats-grid">
          <article className="stat-card">
            <span className="stat-value">{s?.finding_count ?? 0}</span>
            <span className="meta-text">Findings</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.attack_chain_count ?? 0}</span>
            <span className="meta-text">Attack chains</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.probe_count ?? 0}</span>
            <span className="meta-text">Probe runs</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.target_count ?? 0}</span>
            <span className="meta-text">Targets</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.service_count ?? 0}</span>
            <span className="meta-text">Services</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.open_surface_count ?? 0}</span>
            <span className="meta-text">Open surfaces</span>
          </article>
        </div>
      </section>

      <section className="engagement-grid">
        <article className="panel">
          <p className="eyebrow">Findings</p>
          <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
            {sortedFindings.slice(0, 5).map((f) => (
              <div key={f.slug} style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                <strong>{f.title}</strong>
                <span className={`badge severity-${f.severity}`}>{f.severity}</span>
                <span className="meta-text">{f.status}</span>
              </div>
            ))}
            {sortedFindings.length > 5 && (
              <p className="meta-text">+{sortedFindings.length - 5} more</p>
            )}
            {sortedFindings.length === 0 && <p className="meta-text">No findings recorded yet.</p>}
          </div>
        </article>

        <article className="panel">
          <p className="eyebrow">Attack chains</p>
          <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
            {chains.map((c) => {
              const linkedFindings = chainLinks
                .filter((link) => link.chain_key === c.chain_key && link.entity_kind === "finding")
                .map((link) => {
                  const match = findings.find((f) =>
                    (link.entity_ref && f.slug === link.entity_ref) ||
                    (link.entity_id != null && "id" in f && f.id === link.entity_id)
                  );
                  return match ? match.title : (link.entity_ref || `finding #${link.entity_id}`);
                });
              return (
                <div key={c.chain_key} style={{ display: "grid", gap: "4px" }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                    <span className={`badge severity-${c.severity}`}>{c.severity}</span>
                    <strong>{c.title}</strong>
                    <span className="meta-text">{c.status}</span>
                  </div>
                  {c.narrative && <p className="meta-text">{c.narrative}</p>}
                  {linkedFindings.length > 0 && (
                    <p className="meta-text">Findings: {linkedFindings.join(", ")}</p>
                  )}
                </div>
              );
            })}
            {chains.length === 0 && <p className="meta-text">No attack chains linked yet.</p>}
          </div>
        </article>
      </section>

      {latestEvents.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Latest activity</h2>
          </div>
          <div className="timeline">
            {latestEvents.map((event) => (
              <article key={event.id} className="timeline-row">
                <div className="timeline-pill">{event.phase}</div>
                <div className="timeline-body">
                  <div className="timeline-title-row">
                    <strong>{event.task_name}</strong>
                    <span className="meta-text">{event.agent_name}</span>
                  </div>
                  <p>{event.summary}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}
    </>
  );
}
