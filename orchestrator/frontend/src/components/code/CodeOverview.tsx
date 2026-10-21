import { engagementHref } from "../../lib/workspaceRoutes";
import type { CodeRepo } from "../../lib/api";
import { StatusPill } from "../ui";
import { VIEW_LABELS, blockerLabel, requirementLabel } from "./codeLabels";
import { additionalBlockers, groupBlockers, isReference, repoLabel, type BlockerGroup } from "./codeModel";
import type { CodeData } from "./useCodeData";
import { codeViewHref, type CodeRouteTarget } from "./useCodeRoute";

type Props = {
  engagementKey: string;
  data: CodeData;
  groups: BlockerGroup[];
  nextLabel: string;
  targetIsCompletion: boolean;
};

export function CodeOverview({ engagementKey, data, groups, nextLabel, targetIsCompletion }: Props) {
  const repos = data.repos ?? [];
  const extra = groupBlockers(
    additionalBlockers(data.readiness?.blockers ?? [], data.completion?.blockers ?? []),
  );

  return (
    <>
      <section className="panel cv-section" aria-labelledby="cv-left-title">
        <header className="cv-section-head">
          <h3 id="cv-left-title">What's left before {nextLabel}</h3>
          <p className="meta-text">
            Each item below must be cleared before the code track can move on. Items marked{" "}
            <em>Can be skipped</em> may instead be overridden with a recorded reason.
          </p>
        </header>
        {!data.readiness ? (
          <p className="meta-text">Readiness is unavailable; nothing here means "done".</p>
        ) : groups.length === 0 ? (
          <p className="cv-ok">Nothing blocks {nextLabel}.</p>
        ) : (
          <ul className="cv-checklist" aria-label={`Blocking ${nextLabel}`}>
            {groups.map((group) => (
              <BlockerRow key={group.code} engagementKey={engagementKey} group={group} repos={repos} />
            ))}
          </ul>
        )}
      </section>

      {!targetIsCompletion && (
        <section className="panel cv-section" aria-labelledby="cv-complete-title">
          <header className="cv-section-head">
            <h3 id="cv-complete-title">Also needed before the code review is complete</h3>
            <p className="meta-text">Later-phase work, listed so nothing surprises you at the end.</p>
          </header>
          {!data.completion ? (
            <p className="meta-text">Completion readiness is unavailable.</p>
          ) : extra.length === 0 ? (
            <p className="meta-text">Nothing beyond the list above.</p>
          ) : (
            <ul className="cv-checklist is-compact" aria-label="Blocking completion">
              {extra.map((group) => (
                <BlockerRow key={group.code} engagementKey={engagementKey} group={group} repos={repos} />
              ))}
            </ul>
          )}
        </section>
      )}
    </>
  );
}

function BlockerRow({ engagementKey, group, repos }: { engagementKey: string; group: BlockerGroup; repos: CodeRepo[] }) {
  const named = group.repoIds
    .map((id) => repos.find((repo) => repo.id === id))
    .filter((repo): repo is CodeRepo => Boolean(repo));
  // Name repositories only when more than one is under review.
  const showRepos = named.length > 0 && repos.filter((repo) => !isReference(repo)).length > 1;
  const link = blockerLink(engagementKey, group, named);
  const staleReasons =
    group.code === "structural_index_stale"
      ? named.flatMap((repo) =>
          (repo.structural_index_state?.reasons ?? []).map((reason) => ({
            key: `${repo.id}:${reason.code}`,
            text: showRepos ? `${repoLabel(repo, repos)}: ${reason.message}` : reason.message,
          })),
        )
      : [];

  return (
    <li className={`cv-check ${group.required ? "is-required" : "is-optional"}`}>
      <div className="cv-check-main">
        <span className="cv-check-label" title={group.code}>
          {group.label}
        </span>
        {group.count != null && <span className="cv-check-count">{group.count.toLocaleString()}</span>}
        <StatusPill
          size="sm"
          value={group.required ? "required" : "skippable"}
          tone={group.required ? "danger" : "neutral"}
          label={requirementLabel(!group.required)}
          title={group.required ? "Must be cleared before the code track can move on." : "May be overridden with a recorded reason instead."}
        />
        <details className="cv-raw">
          <summary>Details</summary>
          <ul>
            {group.blockers.map((blocker, index) => (
              <li key={`${blocker.code}-${blocker.repo_id ?? "all"}-${index}`}>
                <code>{blocker.code}</code> {blocker.message}
              </li>
            ))}
          </ul>
        </details>
        {link && (
          <a className="cv-check-link" href={link.href}>
            {link.label}
          </a>
        )}
      </div>
      {showRepos && <p className="meta-text cv-check-repos">{named.map((repo) => repoLabel(repo, repos)).join(", ")}</p>}
      {staleReasons.length > 0 && (
        <ul className="cv-check-reasons">
          {staleReasons.map((reason) => (
            <li key={reason.key}>{reason.text}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

// Where a blocker's link lands, when it is narrower than the section: the
// list or table that counts exactly what the blocker counts.
const BLOCKER_TARGETS: Record<string, Partial<CodeRouteTarget>> = {
  // The results awaiting a verdict (the backend's one definition), not every suspicious receipt.
  unresolved_suspicious_analysis: { scope: "attention" },
  // The risk table's Left column for critical and high adds up to this count.
  critical_high_incomplete: { focus: "risk" },
  structural_coverage_unresolved: { focus: "risk" },
  files_unclassified: { focus: "risk" },
  structural_analysis_debt_unreviewed: { focus: "direct" },
};

// Findings blockers open the Findings list filtered (its `q`, `workflow` and
// `verification` route params) to the code findings readiness counts: code
// findings are those at a `file:` location, and each list mirrors the
// blocker's rule in `services/code_analysis.py`. The source-snapshot and
// variant-link parts of a rule have no Findings filter, so those lists can be
// a little longer than the count.
const REPORTABLE_WORKFLOWS = "active,blocked,exploited,contained,eradicated,recovered,reported";
const VERIFICATION_NOT_BLOCKED = "unreviewed,disputed,pending_runtime_proof,confirmed,downgraded,false_positive";
const FINDINGS_BLOCKER_FILTERS: Record<string, { workflow: string; verification: string }> = {
  draft_code_findings_unresolved: { workflow: "draft", verification: VERIFICATION_NOT_BLOCKED },
  unbound_draft_code_findings_unresolved: { workflow: "draft", verification: VERIFICATION_NOT_BLOCKED },
  finding_snapshot_stale: { workflow: REPORTABLE_WORKFLOWS, verification: VERIFICATION_NOT_BLOCKED },
  findings_unverified: { workflow: REPORTABLE_WORKFLOWS, verification: "unreviewed,disputed,pending_runtime_proof" },
  findings_blind_triage_incomplete: { workflow: REPORTABLE_WORKFLOWS, verification: "unreviewed,disputed,pending_runtime_proof,false_positive" },
  variant_parent_verification_incomplete: { workflow: REPORTABLE_WORKFLOWS, verification: "unreviewed,disputed" },
};

function blockerLink(engagementKey: string, group: BlockerGroup, repos: CodeRepo[]) {
  const view = blockerLabel(group.code).view;
  if (!view) return null;
  if (view === "findings") {
    return {
      href: engagementHref(engagementKey, { tab: "findings", q: "location:file:", ...FINDINGS_BLOCKER_FILTERS[group.code] }),
      label: "Open Findings",
    };
  }
  const repo = repos.length === 1 ? repos[0].id : undefined;
  return {
    href: codeViewHref(engagementKey, {
      view,
      repo: view === "repositories" ? repo : undefined,
      ...BLOCKER_TARGETS[group.code],
    }),
    label: `Open ${VIEW_LABELS[view]}`,
  };
}
