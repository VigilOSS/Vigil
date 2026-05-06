import { useEffect, useState } from "react";
import type {
  AssessmentAttackChain,
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentSummary,
  EventRecord,
  ReportReadiness,
} from "../lib/api";
import { getReportReadiness } from "../lib/api";
import { PhaseWaterfall } from "./PhaseWaterfall";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

type OverviewTabProps = {
  engagementKey: string;
  events: EventRecord[];
  assessmentSummary: AssessmentSummary | null;
  findings: (AssessmentFindingDetail | AssessmentFinding)[];
  chains: (AssessmentAttackChainDetail | AssessmentAttackChain)[];
  chainLinks: AssessmentAttackChainLink[];
  currentPhase: string;
  assessmentRefreshVersion: number;
};

function sortFindings(findings: (AssessmentFindingDetail | AssessmentFinding)[]) {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

function verificationSummary(finding: AssessmentFindingDetail | AssessmentFinding) {
  if (finding.verification_state === "disputed") return "disputed";
  if (finding.verification_disposition !== "none") return finding.verification_disposition;
  return finding.verification_state;
}

export function OverviewTab({ engagementKey, events, assessmentSummary, findings, chains, chainLinks, currentPhase, assessmentRefreshVersion }: OverviewTabProps) {
  const s = assessmentSummary;
  const [readiness, setReadiness] = useState<ReportReadiness | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const sortedFindings = sortFindings(findings);
  const latestEvents = events
    .filter((e) => e.event_type !== "artifact.updated")
    .slice(-5);

  const vendorSaasPending = s?.vendor_saas_hosts_pending_decision ?? [];
  const egressStatus = s?.egress_status;
  const egressBlockedPct = egressStatus?.blocked_pct ?? 0;
  const egressBannerVisible = egressBlockedPct > 50;

  useEffect(() => {
    let cancelled = false;
    getReportReadiness(engagementKey)
      .then((row) => {
        if (!cancelled) {
          setReadiness(row);
          setReadinessError(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) setReadinessError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, assessmentRefreshVersion]);

  return (
    <>
      <PhaseWaterfall events={events} currentPhase={currentPhase} />

      {egressBannerVisible && (
        <section className="panel" data-testid="egress-reputation-banner">
          <div className="panel-header">
            <h2>Egress reputation block detected</h2>
          </div>
          <p>
            <strong>{egressBlockedPct}%</strong> of representative live hosts returned 403 / 000-status from
            the runtime egress IP (pattern: <code>{egressStatus?.pattern ?? "unknown"}</code>). Choose a
            mitigation before continuing Phase 3 dispatch:
          </p>
          <ol>
            <li>
              <button type="button" data-testid="egress-choice-allowlist">
                Request IP allowlisting from the program
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-proxy">
                Route through a residential proxy or clean-IP VPS
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-browser">
                Use a browser-based tool inside the runtime
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-accept">
                Accept the limited coverage and document the gap
              </button>
            </li>
          </ol>
          <p className="meta-text">
            Detail: <code>agent/references/runtime-guides/cdn-ip-blocking.md</code>
          </p>
        </section>
      )}

      {vendorSaasPending.length > 0 && (
        <section className="panel" data-testid="vendor-saas-pending-panel">
          <div className="panel-header">
            <h2>Vendor-SaaS hosts pending scope decision</h2>
          </div>
          <ul>
            {vendorSaasPending.map((row) => (
              <li key={row.host}>
                <span className="badge" data-testid={`vendor-saas-badge-${row.host}`}>
                  vendor-saas: {row.vendor}
                </span>
                <code style={{ marginLeft: "8px" }}>{row.host}</code>
              </li>
            ))}
          </ul>
          <p className="meta-text">
            Surface the numbered checkpoint when recon identifies vendor-managed SaaS; record the
            choice as a backend scope_decision row with{" "}
            <code>aith assess dispatch record-decision --kind scope_decision</code>.
          </p>
        </section>
      )}

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
          <article className="stat-card">
            <span className="stat-value">{s?.exploit_candidate_count ?? 0}</span>
            <span className="meta-text">Exploit candidates</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.coverage_blocker_count ?? 0}</span>
            <span className="meta-text">Coverage blockers</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.report_blocker_count ?? 0}</span>
            <span className="meta-text">Report blockers</span>
          </article>
        </div>
      </section>

      {readiness && !readiness.ready && (
        <section className="panel report-blockers-panel">
          <div className="panel-header">
            <h2>Report blockers</h2>
          </div>
          <div className="blocker-list">
            {readiness.blockers.map((blocker, index) => {
              const affected = blocker.slug ? [blocker.slug] : blocker.slugs || [];
              return (
                <article key={`${blocker.kind}-${index}`} className="blocker-row">
                  <span className="badge severity-high">{blocker.kind.replace(/_/g, " ")}</span>
                  <div>
                    {affected.length > 0 && (
                      <p className="meta-text">
                        Findings: {affected.map((slug) => <code key={slug}>{slug}</code>)}
                      </p>
                    )}
                    <p>{blocker.detail || "No detail provided."}</p>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      )}
      {readinessError && (
        <section className="panel">
          <p className="meta-text">Report readiness unavailable: {readinessError}</p>
        </section>
      )}

      <section className="engagement-grid">
        <article className="panel">
          <p className="eyebrow">Findings</p>
          <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
            {sortedFindings.slice(0, 5).map((f) => (
              <div key={f.slug} style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                <strong>{f.title}</strong>
                <span className={`badge severity-${f.severity}`}>{f.severity}</span>
                <span className="meta-text">{f.workflow_status}</span>
                <span className="meta-text">{verificationSummary(f)}</span>
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
