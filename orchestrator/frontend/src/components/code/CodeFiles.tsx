import { useEffect, useRef } from "react";

import type { CodeRepo } from "../../lib/api";
import { EmptyState, SortIndicator, ariaSort, statusLabel } from "../ui";
import {
  DIRECT_READ_SUBTITLE,
  DIRECT_READ_TITLE,
  directReadReason,
} from "./codeLabels";
import { debtUnknownRepoIds, isReference, percent, repoLabel } from "./codeModel";
import { RiskTag } from "./RiskTag";
import type { CodeData } from "./useCodeData";
import { codeViewHref, type CodeFilesFocus } from "./useCodeRoute";

type Props = { engagementKey: string; data: CodeData; repoFilter?: number; focus?: CodeFilesFocus };

// The tiers whose unreviewed files block Verify (the "Critical/high files not yet reviewed" blocker).
const BLOCKING_TIERS = new Set(["critical", "high"]);

const RISK_ORDER = ["critical", "high", "medium", "low", "skip", "unclassified"];

export function CodeFiles({ engagementKey, data, repoFilter, focus }: Props) {
  const coverage = data.coverage;
  const repos = data.repos ?? [];
  const analysisRepos = repos.filter((repo) => !isReference(repo));
  const filterRepo = repoFilter != null ? repos.find((repo) => repo.id === repoFilter) : undefined;
  const allDebt = data.readiness?.structural_debt ?? [];
  const debt = filterRepo ? allDebt.filter((entry) => entry.repo_id === filterRepo.id) : allDebt;
  const sortedDebt = [...debt].sort(
    (a, b) =>
      rank(a.classification) - rank(b.classification) || a.file_path.localeCompare(b.file_path),
  );
  const unknown = [...debtUnknownRepoIds(data.readiness)]
    .filter((id) => !filterRepo || id === filterRepo.id)
    .map((id) => repos.find((repo) => repo.id === id))
    .filter((repo): repo is CodeRepo => Boolean(repo));
  const classes = coverage
    ? Object.keys(coverage.by_classification).sort((a, b) => rank(a) - rank(b))
    : [];
  const blockingLeft = coverage
    ? classes
        .filter((classification) => BLOCKING_TIERS.has(classification))
        .reduce((sum, classification) => sum + coverage.by_classification[classification].count - coverage.by_classification[classification].analyzed, 0)
    : null;
  // Direct-read debt is unknown, not zero, for a repository whose index is out of date.
  const directCount = !data.readiness ? null : unknown.length > 0 && sortedDebt.length === 0 ? "Unknown" : sortedDebt.length.toLocaleString();

  // A blocker link names the table that counts it: scroll to it once its data is shown.
  const riskRef = useRef<HTMLElement | null>(null);
  const directRef = useRef<HTMLElement | null>(null);
  const focused = useRef<string | null>(null);
  const ready = focus === "risk" ? Boolean(coverage) : focus === "direct" ? Boolean(data.readiness) : false;
  useEffect(() => {
    if (!focus || !ready || focused.current === focus) return;
    focused.current = focus;
    (focus === "risk" ? riskRef : directRef).current?.scrollIntoView?.({ block: "start" });
  }, [focus, ready]);

  return (
    <>
      <section
        ref={riskRef}
        className={`panel cv-section cv-focusable${focus === "risk" ? " is-focused" : ""}`}
        aria-labelledby="cv-risk-title"
      >
        <header className="cv-section-head">
          <h3 id="cv-risk-title">Files by risk</h3>
          <p className="meta-text">
            Files are risk-ranked before review. Unreviewed critical and high files block Verify unless skipped with a
            recorded reason.
            {blockingLeft != null ? (
              <> <strong>{blockingLeft.toLocaleString()}</strong> critical or high {blockingLeft === 1 ? "file is" : "files are"} left.</>
            ) : null}
          </p>
        </header>
        {!coverage ? (
          <p className="meta-text">File counts are unavailable.</p>
        ) : (
          <>
            <table className="cv-table">
              <thead>
                <tr>
                  <th scope="col" aria-sort={ariaSort("desc")}>Risk <SortIndicator direction="desc" /></th>
                  <th scope="col" className="cv-num">Files</th>
                  <th scope="col" className="cv-num">Reviewed</th>
                  <th scope="col" className="cv-num">Left</th>
                  <th scope="col">Progress</th>
                </tr>
              </thead>
              <tbody>
                {classes.map((classification) => {
                  const entry = coverage.by_classification[classification];
                  return (
                    <tr key={classification} className={focus === "risk" && BLOCKING_TIERS.has(classification) ? "is-marked" : undefined}>
                      <th scope="row">
                        <RiskTag classification={classification} />
                      </th>
                      <td className="cv-num">{entry.count.toLocaleString()}</td>
                      <td className="cv-num">{entry.analyzed.toLocaleString()}</td>
                      <td className="cv-num">{(entry.count - entry.analyzed).toLocaleString()}</td>
                      <td>
                        <span className="cv-mini-bar" aria-label={`${percent(entry.analyzed, entry.count)}% reviewed`}>
                          <span style={{ width: `${percent(entry.analyzed, entry.count)}%` }} />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {Object.keys(coverage.by_status).length > 0 && (
              <p className="meta-text cv-states">
                {Object.entries(coverage.by_status)
                  .map(([state, count]) => `${count.toLocaleString()} ${statusLabel("code-file", state).toLowerCase()}`)
                  .join(" · ")}
              </p>
            )}
            {coverage.reference_repos.length > 0 && (
              <p className="meta-text">
                Not counted — reference code is read for context and never owes review:{" "}
                {coverage.reference_repos
                  .map((repo) => {
                    const full = repos.find((entry) => entry.id === repo.repo_id);
                    return `${full ? repoLabel(full, repos) : repo.name} (${repo.admitted_files.toLocaleString()} files)`;
                  })
                  .join(", ")}
              </p>
            )}
          </>
        )}
      </section>

      <section
        ref={directRef}
        className={`panel cv-section cv-focusable${focus === "direct" ? " is-focused" : ""}`}
        aria-labelledby="cv-direct-title"
      >
        <header className="cv-section-head cv-section-head-row">
          <div>
            <h3 id="cv-direct-title">
              {DIRECT_READ_TITLE} {directCount != null && <span className="cv-count">{directCount}</span>}
            </h3>
            <p className="meta-text">{DIRECT_READ_SUBTITLE} Files already read directly are not listed.</p>
          </div>
          {filterRepo && (
            <a className="cv-filter-pill" href={codeViewHref(engagementKey, { view: "files" })} aria-label={`Clear repository filter ${filterRepo.name}`}>
              Repository: {repoLabel(filterRepo, repos)} ✕
            </a>
          )}
        </header>
        {unknown.length > 0 && (
          <p className="cv-inline-note is-warn">
            Unknown for {unknown.map((repo) => repoLabel(repo, repos)).join(", ")}: the code index is out of date, so
            unparsed files can't be counted until it is rebuilt.
          </p>
        )}
        {!data.readiness ? (
          <p className="meta-text">Readiness is unavailable, so the list can't be shown.</p>
        ) : sortedDebt.length === 0 ? (
          unknown.length > 0 ? (
            <p className="meta-text">None among repositories with a current code index.</p>
          ) : (
            <EmptyState variant="empty" compact title="No file needs a direct read.">
              Every file was either fully parsed or has been read directly.
            </EmptyState>
          )
        ) : (
          <table className="cv-table">
            <thead>
              <tr>
                <th scope="col">File</th>
                {analysisRepos.length > 1 && !filterRepo && <th scope="col">Repository</th>}
                <th scope="col" aria-sort={ariaSort("desc")}>Risk <SortIndicator direction="desc" /></th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {sortedDebt.map((entry) => {
                const repo = repos.find((candidate) => candidate.id === entry.repo_id);
                return (
                  <tr key={`${entry.repo_id}:${entry.file_path}`}>
                    <td className="cv-path-cell"><span className="cv-path" title={entry.file_path}>{entry.file_path}</span></td>
                    {analysisRepos.length > 1 && !filterRepo && <td>{repo ? repoLabel(repo, repos) : entry.repo_id}</td>}
                    <td>
                      <RiskTag classification={entry.classification || "unclassified"} />
                    </td>
                    <td title={`structural_analysis_status=${entry.structural_analysis_status}; truncated=${entry.structural_artifact_truncated}`}>
                      {directReadReason(entry.structural_analysis_status, entry.structural_artifact_truncated)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

function rank(classification: string): number {
  const index = RISK_ORDER.indexOf(classification);
  return index < 0 ? RISK_ORDER.length : index;
}

