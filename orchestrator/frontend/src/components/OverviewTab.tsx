import { useEffect, useState } from "react";
import type {
  AssessmentAttackChain,
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentSummary,
  EventRecord,
  PerHostCoverage,
  PerHostCoverageHost,
  PerHostOutcome,
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

// C58 — labels for the five C40 per-host objectives. The map is the only
// place the user-facing copy lives; backend objective names are the keys.
const OBJECTIVE_LABELS: Record<string, string> = {
  waf_tier: "WAF tier",
  service_inventory: "Service inventory",
  directory_fuzz: "Directory-fuzz coverage",
  nikto_trigger: "Nikto trigger",
  osint: "OSINT",
};

function objectiveLabel(objective: string): string {
  return OBJECTIVE_LABELS[objective] ?? objective.replace(/_/g, " ");
}

function outcomeBadgeClass(outcome: PerHostOutcome | undefined): string {
  if (!outcome) return "badge severity-info";
  if (outcome.deferred) return "badge severity-medium";
  if (outcome.met) return "badge severity-low";
  return "badge severity-high";
}

function outcomeMarker(outcome: PerHostOutcome | undefined): string {
  if (!outcome) return "—";
  if (outcome.deferred) return "D";
  if (outcome.met) return "Y";
  return "N";
}

function describeDeferralPayload(payload: Record<string, unknown>): string {
  const objectives = Array.isArray(payload.deferred_objectives)
    ? payload.deferred_objectives.filter((v) => typeof v === "string").join(", ")
    : "";
  const reason = typeof payload.reason === "string" ? payload.reason : "";
  if (objectives && reason) return `${objectives} — ${reason}`;
  if (objectives) return objectives;
  if (reason) return reason;
  return JSON.stringify(payload);
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
            <code>aith assess agent decision --kind scope_decision</code>.
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

      {readiness && (
        <ReadinessPanel readiness={readiness} />
      )}

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


type ReadinessPanelProps = {
  readiness: ReportReadiness;
};

// C58 — Readiness panel renders:
//  1. The Definition-of-Done summary (overall ready/blocked indicator + blocker count)
//  2. The C40 per-host outcome matrix (5 objectives × N hosts)
//  3. Active coverage_deferral decision rows surfaced inline so operators
//     can audit which objectives were intentionally skipped.
//
// The panel is read-only. Operators dispatch missing work from the CLI; the
// UI reports state, it does not fix it. That mirrors the prevailing pattern
// in this codebase: backend tables are canonical, the UI is a view onto them.
function ReadinessPanel({ readiness }: ReadinessPanelProps) {
  const perHost = readiness.per_host_coverage;
  const hasHosts = !!perHost && perHost.hosts.length > 0;
  const totalUnmet = perHost
    ? perHost.hosts.reduce((sum, row) => sum + row.unmet_objectives.length, 0)
    : 0;
  const totalDeferrals = perHost
    ? perHost.hosts.reduce((sum, row) => sum + row.deferrals.length, 0)
    : 0;

  return (
    <section className="panel" data-testid="readiness-panel">
      <div className="panel-header">
        <h2>Readiness</h2>
        <span
          className={`badge ${readiness.ready ? "severity-low" : "severity-high"}`}
          data-testid="readiness-overall-badge"
        >
          {readiness.ready ? "READY" : `BLOCKED (${readiness.blocker_count})`}
        </span>
      </div>

      <div className="stats-grid">
        <article className="stat-card">
          <span className="stat-value">{readiness.blocker_count}</span>
          <span className="meta-text">Definition-of-Done blockers</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{hasHosts ? perHost!.hosts.length : 0}</span>
          <span className="meta-text">Hosts with signal</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{totalUnmet}</span>
          <span className="meta-text">Per-host objectives unmet (WARN)</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{totalDeferrals}</span>
          <span className="meta-text">Active coverage deferrals</span>
        </article>
      </div>

      <PerHostCoverageMatrix perHost={perHost} />

      <EngagementSignalsCard perHost={perHost} />

      <ActiveDeferralsList perHost={perHost} />
    </section>
  );
}

// FU4 — engagement-level signal counts shipped by `per_host_coverage()` but
// not previously rendered. waf_intel_count satisfies the WAF tier objective
// engagement-wide (CDN WAFs typically front the whole property);
// tech_scan_intel_count powers the nikto-trigger objective; osint_intel_total
// is the OSINT objective. Surfacing them makes the matrix Y/D/N marks
// self-explanatory — operators can see why a row went green at engagement
// level even when no host-specific intel was recorded.
const ENGAGEMENT_SIGNAL_LABELS: Record<string, string> = {
  waf_intel_count: "WAF intel rows (engagement-wide)",
  tech_scan_intel_count: "Tech-scan intel rows",
  osint_intel_total: "OSINT intel rows",
};

function EngagementSignalsCard({ perHost }: { perHost: PerHostCoverage | undefined }) {
  if (!perHost) return null;
  const signals = perHost.engagement_signals ?? {};
  const entries = Object.entries(ENGAGEMENT_SIGNAL_LABELS);
  // Render even when every value is 0/undefined — a row of zeros is itself
  // useful operator signal ("OSINT hasn't run yet").
  return (
    <div className="readiness-engagement-signals" data-testid="readiness-engagement-signals">
      <h3>Engagement-level signals</h3>
      <div className="stats-grid">
        {entries.map(([key, label]) => {
          const value = typeof signals[key] === "number" ? (signals[key] as number) : 0;
          return (
            <article className="stat-card" key={key} data-testid={`readiness-signal-${key}`}>
              <span className="stat-value">{value}</span>
              <span className="meta-text">{label}</span>
            </article>
          );
        })}
      </div>
      <p className="meta-text">
        Engagement-wide intel feeds matrix objectives without per-host
        evidence: WAF-class intel satisfies <code>waf_tier</code> for every
        host, OSINT intel satisfies <code>osint</code> engagement-wide.
      </p>
    </div>
  );
}

function PerHostCoverageMatrix({ perHost }: { perHost: PerHostCoverage | undefined }) {
  if (!perHost) {
    return (
      <p className="meta-text" data-testid="readiness-no-per-host">
        Per-host coverage projection unavailable.
      </p>
    );
  }
  if (perHost.hosts.length === 0) {
    return (
      <p className="meta-text" data-testid="readiness-no-hosts">
        No hosts have backend signal yet. Dispatch recon-specialist to populate
        services / surfaces / intel tables before re-checking.
      </p>
    );
  }
  return (
    <div className="readiness-matrix" data-testid="readiness-matrix">
      <table>
        <thead>
          <tr>
            <th>Host</th>
            {perHost.objectives.map((obj) => (
              <th key={obj} title={obj}>
                {objectiveLabel(obj)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {perHost.hosts.map((row) => (
            <ReadinessMatrixRow key={row.host} row={row} objectives={perHost.objectives} />
          ))}
        </tbody>
      </table>
      <p className="meta-text">
        Cells: <strong>Y</strong> objective met, <strong>D</strong> intentionally
        deferred via <code>coverage_deferral</code>, <strong>N</strong> unmet
        (WARN-only — does not block phase advance).
      </p>
    </div>
  );
}

function ReadinessMatrixRow({
  row,
  objectives,
}: {
  row: PerHostCoverageHost;
  objectives: string[];
}) {
  return (
    <tr data-testid={`readiness-row-${row.host}`}>
      <th scope="row">
        <code>{row.host}</code>
      </th>
      {objectives.map((obj) => {
        const outcome = row.outcomes[obj];
        const evidence = outcome?.evidence?.length
          ? outcome.evidence.join(", ")
          : "";
        return (
          <td key={obj} className="readiness-cell">
            <span
              className={outcomeBadgeClass(outcome)}
              title={evidence}
              data-testid={`readiness-cell-${row.host}-${obj}`}
            >
              {outcomeMarker(outcome)}
            </span>
          </td>
        );
      })}
    </tr>
  );
}

function ActiveDeferralsList({ perHost }: { perHost: PerHostCoverage | undefined }) {
  if (!perHost) return null;
  const allDeferrals = perHost.hosts.flatMap((row) =>
    row.deferrals.map((d) => ({ host: row.host, deferral: d })),
  );
  if (allDeferrals.length === 0) return null;
  return (
    <div className="readiness-deferrals" data-testid="readiness-deferrals">
      <h3>Active coverage deferrals</h3>
      <ul>
        {allDeferrals.map((entry, idx) => (
          <li key={`${entry.host}-${entry.deferral.id}-${idx}`}>
            <code>{entry.host}</code>
            <span className="meta-text">
              {" "}
              — {describeDeferralPayload(entry.deferral.payload)}
            </span>
          </li>
        ))}
      </ul>
      <p className="meta-text">
        Deferrals are queryable via{" "}
        <code>aith assess agent list --kind coverage_deferral</code>; resolve via{" "}
        <code>aith assess agent decision-update</code> when the work is done.
      </p>
    </div>
  );
}
