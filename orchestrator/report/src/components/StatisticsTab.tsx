import type { ReportData } from "../types";
import { SeverityDonut } from "./SeverityDonut";
import { formatDateTime, formatLabel, SEVERITY_RANK } from "../lib/format";

interface Props {
  data: ReportData;
}

interface StatCard {
  label: string;
  value: number | string;
}

// Horizontal breakdown bar for a `{key: count}` map (workflow/verification).
function BreakdownBars({ title, counts }: { title: string; counts: Record<string, number> }) {
  const entries = Object.entries(counts).filter(([, v]) => v > 0);
  const total = entries.reduce((sum, [, v]) => sum + v, 0);
  if (entries.length === 0) return null;
  entries.sort((a, b) => b[1] - a[1]);
  return (
    <div className="rpt-breakdown">
      <h3 className="rpt-breakdown-title">{title}</h3>
      <ul className="rpt-breakdown-list">
        {entries.map(([key, value]) => {
          const pct = total > 0 ? Math.round((value / total) * 100) : 0;
          return (
            <li key={key} className="rpt-breakdown-row">
              <span className="rpt-breakdown-label">{formatLabel(key)}</span>
              <span className="rpt-breakdown-track" aria-hidden="true">
                <span className="rpt-breakdown-fill" style={{ width: `${pct}%` }} />
              </span>
              <span className="rpt-breakdown-count">{value}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function StatisticsTab({ data }: Props) {
  const { engagement, summary, attack_chains } = data;
  const severities = summary.finding_severities ?? {};
  const findingCount = summary.finding_count ?? data.finding_groups.finding_count ?? 0;

  const highCount =
    Object.entries(severities)
      .filter(([sev]) => (SEVERITY_RANK[sev] ?? 0) >= SEVERITY_RANK.high)
      .reduce((sum, [, v]) => sum + v, 0) ?? 0;

  const cards: StatCard[] = [
    { label: "Findings", value: findingCount },
    { label: "High+ severity", value: highCount },
    { label: "Attack chains", value: summary.attack_chain_count ?? attack_chains.length },
    { label: "Open surfaces", value: summary.open_surface_count ?? 0 },
    { label: "Credentials", value: summary.credential_count ?? 0 },
    { label: "Hosts in scope", value: engagement.scope_hosts.length },
  ];

  return (
    <div className="rpt-section">
      <section className="rpt-hero">
        <div className="rpt-hero-main">
          <p className="rpt-eyebrow">Security Assessment Report</p>
          <h1 className="rpt-hero-title">{engagement.target}</h1>
          <div className="rpt-hero-badges">
            <span className={`rpt-mode-badge rpt-mode-${data.mode}`}>{data.mode}</span>
            <span className="rpt-chip">{formatLabel(engagement.status)}</span>
            <span className="rpt-chip">Phase: {formatLabel(engagement.current_phase)}</span>
            {engagement.engagement_type && (
              <span className="rpt-chip">{formatLabel(engagement.engagement_type)}</span>
            )}
          </div>
        </div>
        <dl className="rpt-hero-meta">
          <div>
            <dt>Engagement</dt>
            <dd>{engagement.key}</dd>
          </div>
          {engagement.customer && (
            <div>
              <dt>Customer</dt>
              <dd>{engagement.customer}</dd>
            </div>
          )}
          <div>
            <dt>Started</dt>
            <dd>{formatDateTime(engagement.created_at)}</dd>
          </div>
          <div>
            <dt>Generated</dt>
            <dd>{formatDateTime(data.generated_at)}</dd>
          </div>
        </dl>
      </section>

      <section className="rpt-stat-grid">
        {cards.map((card) => (
          <div key={card.label} className="rpt-stat-card">
            <span className="rpt-stat-value">{card.value}</span>
            <span className="rpt-stat-label">{card.label}</span>
          </div>
        ))}
      </section>

      <section className="rpt-panels">
        <div className="rpt-panel">
          <h2 className="rpt-panel-title">Findings by severity</h2>
          <SeverityDonut counts={severities} size={160} centerLabel={String(findingCount)} legend />
        </div>
        <div className="rpt-panel">
          <BreakdownBars title="Workflow status" counts={summary.finding_workflow_statuses ?? {}} />
          <BreakdownBars title="Verification status" counts={summary.finding_verification_statuses ?? {}} />
        </div>
      </section>

      {engagement.scope_hosts.length > 0 && (
        <section className="rpt-panel">
          <h2 className="rpt-panel-title">Scope</h2>
          <ul className="rpt-scope-list">
            {engagement.scope_hosts.map((host) => (
              <li key={host} className="rpt-chip rpt-chip-mono">
                {host}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

export default StatisticsTab;
