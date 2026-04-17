import { useState } from "react";
import { deleteEngagement, type Engagement } from "../lib/api";

type EngagementsPageProps = {
  engagements: Engagement[];
  onOpenEngagement: (engagementKey: string) => void;
  onEngagementDeleted?: () => void;
};

export function EngagementsPage({ engagements, onOpenEngagement, onEngagementDeleted }: EngagementsPageProps) {
  const [pendingDelete, setPendingDelete] = useState<Engagement | null>(null);
  const [confirmText, setConfirmText] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const closeDialog = () => {
    setPendingDelete(null);
    setConfirmText("");
    setDeleteError(null);
    setIsSubmitting(false);
  };

  const submitDelete = async () => {
    if (!pendingDelete) return;
    if (confirmText !== pendingDelete.key) {
      setDeleteError("Typed key does not match.");
      return;
    }
    setIsSubmitting(true);
    setDeleteError(null);
    try {
      await deleteEngagement(pendingDelete.key);
      closeDialog();
      onEngagementDeleted?.();
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
      setIsSubmitting(false);
    }
  };

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
          <article
            className="panel engagement-card engagement-card-clickable"
            key={engagement.key}
            onClick={() => onOpenEngagement(engagement.key)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => { if (e.key === "Enter") onOpenEngagement(engagement.key); }}
          >
            <div className="engagement-heading">
              <div>
                <h2>{engagement.target}</h2>
                <p className="meta-text">{engagement.key}</p>
              </div>
              <div className="engagement-actions">
                <span className={`status-pill status-${engagement.status}`}>{engagement.status}</span>
                <button
                  type="button"
                  className="engagement-delete-button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setPendingDelete(engagement);
                    setConfirmText("");
                    setDeleteError(null);
                  }}
                  aria-label={`Delete engagement ${engagement.key}`}
                  title="Delete engagement and all findings, probes, command runs, and code analysis."
                >
                  Delete
                </button>
              </div>
            </div>
            <p className="meta-text">
              Phase: {engagement.current_phase} &middot; {engagement.session_count} session{engagement.session_count !== 1 ? "s" : ""}
            </p>
          </article>
        ))}
        {engagements.length === 0 ? (
          <section className="panel empty-state">No engagements discovered under `agent/engagements`.</section>
        ) : null}
      </section>

      {pendingDelete ? (
        <div
          className="finding-overlay"
          onClick={closeDialog}
          role="presentation"
        >
          <div
            className="panel finding-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-engagement-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="delete-engagement-title">Delete engagement?</h2>
            <p>
              This will permanently remove <strong>{pendingDelete.key}</strong> and
              cascade-delete every associated finding, probe run, command-run audit
              record, credential, code analysis result, and attack chain. This
              cannot be undone from the UI.
            </p>
            <p className="meta-text">
              The filesystem directory under <code>agent/engagements/</code> is not
              touched — remove that yourself if you want the engagement gone from
              both the DB and disk.
            </p>
            <label className="delete-confirm-label">
              Type <code>{pendingDelete.key}</code> to confirm:
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                autoFocus
                spellCheck={false}
                autoComplete="off"
              />
            </label>
            {deleteError ? <p className="error-text">{deleteError}</p> : null}
            <div className="finding-modal-actions">
              <button type="button" onClick={closeDialog} disabled={isSubmitting}>
                Cancel
              </button>
              <button
                type="button"
                className="engagement-delete-button"
                onClick={submitDelete}
                disabled={isSubmitting || confirmText !== pendingDelete.key}
              >
                {isSubmitting ? "Deleting..." : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}
