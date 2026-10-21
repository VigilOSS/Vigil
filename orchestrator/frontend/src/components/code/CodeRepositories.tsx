import { useEffect, useMemo, useState } from "react";

import type { CodeRepo } from "../../lib/api";
import type { CodeRepoReviewProgress } from "../../lib/codeApi";
import { TimeStamp } from "../formatting";
import { EmptyState, humanizeStatus, statusLabel } from "../ui";
import { BLOCKER_LABELS, blockerLabel } from "./codeLabels";
import { debtByRepo, debtUnknownRepoIds, isReference, percent, repoDisambiguator, type Blocker } from "./codeModel";
import type { CodeData } from "./useCodeData";
import { codeViewHref } from "./useCodeRoute";

type Props = { engagementKey: string; data: CodeData; focusRepoId?: number };

type Warning = { key: string; text: string; details: string[] };

const REFERENCE_GROUP = "reference";

export function CodeRepositories({ engagementKey, data, focusRepoId }: Props) {
  const repos = useMemo(() => data.repos ?? [], [data.repos]);
  const analysis = repos.filter((repo) => !isReference(repo));
  const reference = repos.filter(isReference);
  const [expanded, setExpanded] = useState<Set<number | typeof REFERENCE_GROUP>>(() => new Set());
  const soleRepoId = analysis.length === 1 ? analysis[0].id : null;

  // A deep-linked repository opens (with its group) and scrolls into view.
  useEffect(() => {
    if (focusRepoId == null) return;
    const repo = repos.find((entry) => entry.id === focusRepoId);
    if (!repo) return;
    setExpanded((current) => {
      const next = new Set(current).add(repo.id);
      if (isReference(repo)) next.add(REFERENCE_GROUP);
      return next;
    });
    window.requestAnimationFrame(() => {
      const row = document.getElementById(`cv-repo-${repo.id}`);
      row?.scrollIntoView?.({ block: "start" });
      row?.querySelector<HTMLButtonElement>("button")?.focus({ preventScroll: true });
    });
  }, [focusRepoId, repos]);

  // A single repository under review opens by default.
  useEffect(() => {
    if (soleRepoId != null) setExpanded((current) => (current.has(soleRepoId) ? current : new Set(current).add(soleRepoId)));
  }, [soleRepoId]);

  const toggle = (key: number | typeof REFERENCE_GROUP) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const expandAll = () => setExpanded(new Set<number | typeof REFERENCE_GROUP>([...repos.map((repo) => repo.id), REFERENCE_GROUP]));
  const collapseAll = () => setExpanded(new Set());

  const blockers = [...(data.readiness?.blockers ?? []), ...(data.completion?.blockers ?? [])];
  const debt = debtByRepo(data.readiness);
  const debtUnknown = debtUnknownRepoIds(data.readiness);
  const progress = new Map((data.progress ?? []).map((row) => [row.repo_id, row]));

  if (repos.length === 0) {
    return (
      <section className="panel cv-section">
        {data.repos === null ? (
          <p className="meta-text">Repositories are unavailable.</p>
        ) : (
          <EmptyState variant="empty" title="No code repositories ingested yet.">
            <p>Run <code>vigil assess code-ingest</code> to start code analysis.</p>
          </EmptyState>
        )}
      </section>
    );
  }

  const rowProps = { engagementKey, repos, blockers, debt, debtUnknown, progress, expanded, toggle, readinessKnown: Boolean(data.readiness) };
  return (
    <section className="panel cv-section" aria-labelledby="cv-repos-title">
      <header className="cv-section-head cv-section-head-row">
        <div>
          <h3 id="cv-repos-title">Repositories</h3>
          <p className="meta-text">
            {analysis.length} under review{reference.length > 0 ? ` · ${reference.length} reference` : ""}. Open a repository for its
            warnings and source identity.
          </p>
        </div>
        <div className="cv-actions">
          <button type="button" className="ghost-button cv-small-button" onClick={expandAll}>
            Expand all
          </button>
          <button type="button" className="ghost-button cv-small-button" onClick={collapseAll}>
            Collapse all
          </button>
        </div>
      </header>

      <ul className="cv-repo-list" aria-label="Repositories under review">
        {analysis.map((repo) => (
          <RepoRow key={repo.id} repo={repo} {...rowProps} />
        ))}
      </ul>

      {reference.length > 0 && (
        <div className="cv-repo-group">
          <button
            type="button"
            className="cv-disclosure"
            aria-expanded={expanded.has(REFERENCE_GROUP)}
            aria-controls="cv-reference-repos"
            onClick={() => toggle(REFERENCE_GROUP)}
          >
            <span className="cv-chevron" aria-hidden="true">{expanded.has(REFERENCE_GROUP) ? "▾" : "▸"}</span>
            Reference code (read for context, not reviewed)
            <span className="cv-count">{reference.length}</span>
          </button>
          {expanded.has(REFERENCE_GROUP) && (
            <ul className="cv-repo-list" id="cv-reference-repos" aria-label="Reference repositories">
              {reference.map((repo) => (
                <RepoRow key={repo.id} repo={repo} {...rowProps} />
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}

type RowProps = {
  engagementKey: string;
  repo: CodeRepo;
  repos: CodeRepo[];
  blockers: Blocker[];
  debt: ReturnType<typeof debtByRepo>;
  debtUnknown: Set<number>;
  progress: Map<number, CodeRepoReviewProgress>;
  expanded: Set<number | typeof REFERENCE_GROUP>;
  toggle: (key: number) => void;
  readinessKnown: boolean;
};

function RepoRow({ engagementKey, repo, repos, blockers, debt, debtUnknown, progress, expanded, toggle, readinessKnown }: RowProps) {
  const open = expanded.has(repo.id);
  const reference = isReference(repo);
  const tag = repoDisambiguator(repo, repos);
  const reviewed = progress.get(repo.id);
  const directReads = debt.get(repo.id)?.length ?? 0;
  const warnings = repoWarnings(repo, blockers, readinessKnown);
  const bodyId = `cv-repo-body-${repo.id}`;

  return (
    <li className={`cv-repo${open ? " is-open" : ""}`} id={`cv-repo-${repo.id}`}>
      <button type="button" className="cv-repo-head" aria-expanded={open} aria-controls={bodyId} onClick={() => toggle(repo.id)}>
        <span className="cv-chevron" aria-hidden="true">{open ? "▾" : "▸"}</span>
        <span className="cv-repo-name">
          {repo.name}
          {tag && <span className="cv-repo-tag" title={repo.repo_key}>{tag}</span>}
        </span>
        <span className="cv-repo-chips">
          <span className="cv-chip">{reference ? "Reference" : "Under review"}</span>
          <span className="cv-chip">{repo.analyzable_files.toLocaleString()} files</span>
          {!reference && reviewed && (
            <span className="cv-chip">{percent(reviewed.reviewed_files, reviewed.admitted_files)}% reviewed</span>
          )}
          {!reference && readinessKnown && (
            debtUnknown.has(repo.id) ? (
              <span className="cv-chip is-warn">Direct reads unknown</span>
            ) : directReads > 0 ? (
              <span className="cv-chip is-warn">{directReads.toLocaleString()} need a direct read</span>
            ) : null
          )}
          {warnings.length > 0 && (
            <span className="cv-chip is-warn">
              {warnings.length} {warnings.length === 1 ? "warning" : "warnings"}
            </span>
          )}
        </span>
      </button>

      {open && (
        <div className="cv-repo-body" id={bodyId}>
          <dl className="cv-facts">
            <div><dt>Files</dt><dd>{repo.analyzable_files.toLocaleString()} reviewable of {repo.total_files.toLocaleString()}</dd></div>
            <div><dt>Lines of code</dt><dd>{repo.total_loc.toLocaleString()}</dd></div>
            <div><dt>Language</dt><dd>{repo.language || "mixed"}</dd></div>
            <div><dt>Source</dt><dd>{humanizeStatus(repo.source_kind)} · Snapshot {repo.active_generation}</dd></div>
            <div><dt>Added</dt><dd><TimeStamp value={repo.created_at} mode="both" /></dd></div>
            {!reference && reviewed && (
              <div>
                <dt>Reviewed</dt>
                <dd>
                  {reviewed.reviewed_files.toLocaleString()} of {reviewed.admitted_files.toLocaleString()} files
                </dd>
              </div>
            )}
          </dl>

          {reference && (
            <p className="meta-text">
              Reference code is indexed so reviewers can resolve and cite symbols. It never creates review work and is not
              counted in progress.
            </p>
          )}

          {!reference && (reviewed?.finished_not_reviewed?.length ?? 0) > 0 && (
            <div className="cv-inline-note is-warn" role="note" aria-label={`Finished reviews that do not count for ${repo.name}`}>
              <p>
                <strong>
                  {(reviewed?.finished_files ?? 0).toLocaleString()} finished · {reviewed?.reviewed_files.toLocaleString()} reviewed.
                </strong>
              </p>
              <ul>
                {reviewed?.finished_not_reviewed?.map((gap) => <li key={gap.code}>{gap.message}</li>)}
              </ul>
            </div>
          )}

          {warnings.length > 0 && (
            <ul className="cv-warnings" aria-label={`Warnings for ${repo.name}`}>
              {warnings.map((warning) => (
                <li key={warning.key}>
                  <strong>{warning.text}</strong>
                  {warning.details.map((detail) => (
                    <span key={detail} className="cv-warning-detail">{detail}</span>
                  ))}
                </li>
              ))}
            </ul>
          )}

          {!reference && directReads > 0 && (
            <p className="cv-inline-note">
              {directReads.toLocaleString()} {directReads === 1 ? "file needs" : "files need"} a direct read because the code index
              couldn't fully parse {directReads === 1 ? "it" : "them"}.{" "}
              <a href={codeViewHref(engagementKey, { view: "files", repo: repo.id })}>Show files</a>
            </p>
          )}

          <details className="cv-identity">
            <summary>Source identity</summary>
            <dl className="cv-identity-list">
              <div><dt>Repository key</dt><dd className="cv-mono">{repo.repo_key}</dd></div>
              <div><dt>Repository path</dt><dd className="cv-mono">{repo.repo_path || "—"}</dd></div>
              <div><dt>Source origin</dt><dd className="cv-mono">{repo.source_origin_path || "—"}</dd></div>
              <div><dt>Branch</dt><dd className="cv-mono">{repo.branch || "—"}</dd></div>
              <div><dt>Commit</dt><dd className="cv-mono">{repo.commit_hash || "—"}</dd></div>
              <div><dt>Snapshot fingerprint</dt><dd className="cv-mono">{repo.snapshot_digest || "—"}</dd></div>
              <div><dt>Manifest fingerprint</dt><dd className="cv-mono">{repo.source_manifest_digest || "—"}</dd></div>
              <div><dt>Snapshot quality</dt><dd>{humanizeStatus(repo.source_snapshot_quality)}</dd></div>
              <div><dt>Worktree at ingest</dt><dd>{repo.worktree_dirty == null ? "Not recorded" : repo.worktree_dirty ? "Uncommitted changes" : "Clean"}</dd></div>
              <div><dt>Code index</dt><dd>{indexSummary(repo)}</dd></div>
              <div><dt>Index parse results</dt><dd>{parseSummary(repo)}</dd></div>
              <div><dt>Threat model</dt><dd>{repo.threat_model_generation == null ? "None" : `Snapshot ${repo.threat_model_generation}`}</dd></div>
              <div><dt>Status</dt><dd>{statusLabel("code-repo", repo.analysis_status)}</dd></div>
            </dl>
          </details>
        </div>
      )}
    </li>
  );
}

function indexSummary(repo: CodeRepo): string {
  if (repo.structural_index_generation == null) return "Not built";
  return `Snapshot ${repo.structural_index_generation} · ${repo.structural_index_schema || "unknown format"}`;
}

// Raw index records, including files already reviewed directly.
function parseSummary(repo: CodeRepo): string {
  const counts = repo.structural_analysis_status_counts;
  const parts = [
    `${counts.complete ?? 0} fully parsed`,
    `${counts.degraded ?? 0} partly parsed`,
    `${counts.unsupported ?? 0} not parsed`,
    `${repo.structural_artifact_truncated_files} too large`,
  ];
  return `${parts.join(" · ")} (all files, reviewed or not)`;
}

const REPO_BLOCKER_CODES = new Set(
  Object.entries(BLOCKER_LABELS)
    .filter(([, label]) => label.view === "repositories")
    .map(([code]) => code),
);

/** Actionable warnings: readiness blockers about this repository's source and
 *  index, plus worktree facts. Reference code never owes index work. */
function repoWarnings(repo: CodeRepo, blockers: Blocker[], readinessKnown: boolean): Warning[] {
  const warnings: Warning[] = [];
  if (!isReference(repo)) {
    const seen = new Set<string>();
    const indexDetails = (repo.structural_index_state?.reasons ?? []).map((reason) => reason.message);
    if (readinessKnown) {
      for (const blocker of blockers) {
        if (blocker.repo_id !== repo.id || !REPO_BLOCKER_CODES.has(blocker.code) || seen.has(blocker.code)) continue;
        seen.add(blocker.code);
        warnings.push({
          key: blocker.code,
          text: blockerLabel(blocker.code).label,
          details: blocker.code === "structural_index_stale" ? indexDetails : [blocker.message],
        });
      }
    } else if (repo.structural_index_state && !repo.structural_index_state.current) {
      warnings.push({ key: "structural_index_stale", text: blockerLabel("structural_index_stale").label, details: indexDetails });
    }
  }
  if (repo.worktree_dirty === true) {
    warnings.push({ key: "dirty", text: "Source had uncommitted changes when it was ingested", details: [] });
  } else if (repo.worktree_dirty == null && repo.source_kind === "git") {
    warnings.push({ key: "worktree", text: "Worktree state was not recorded at ingest", details: [] });
  }
  return warnings;
}
