import type { Engagement } from "../lib/api";

type EngagementsPageProps = {
  engagements: Engagement[];
  onOpenEngagement: (engagementKey: string) => void;
};

export function EngagementsPage({ engagements, onOpenEngagement }: EngagementsPageProps) {
  return (
    <main className="shell dashboard-shell">
      <section className="dashboard-header">
        <div>
          <p className="eyebrow">Overview</p>
          <h1>Engagements</h1>
          <p className="lead">
            Local orchestrator view for the configured install root. Each engagement may carry multiple AI sessions.
          </p>
        </div>
      </section>

      <section className="engagement-column">
        {engagements.map((engagement) => (
          <article className="panel engagement-card" key={engagement.key}>
            <div className="engagement-heading">
              <div>
                <h2>{engagement.target}</h2>
                <p className="meta-text">{engagement.key}</p>
              </div>
              <div className="engagement-actions">
                <span className={`status-pill status-${engagement.status}`}>{engagement.status}</span>
              </div>
            </div>
            <p className="meta-text">
              Phase: {engagement.current_phase} &middot; {engagement.session_count} session{engagement.session_count !== 1 ? "s" : ""}
            </p>
            <button
              className="secondary-button"
              type="button"
              onClick={() => onOpenEngagement(engagement.key)}
            >
              Open engagement
            </button>
          </article>
        ))}
        {engagements.length === 0 ? (
          <section className="panel empty-state">No engagements discovered under `agent/engagements`.</section>
        ) : null}
      </section>
    </main>
  );
}
