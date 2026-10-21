// Derivations shared by the Code view's sections. Everything here is computed
// from backend payloads; nothing is estimated.

import type { CodeCoverage, CodeReadiness, CodeRepo } from "../../lib/api";
import type { CodeRepoReviewProgress, CodeReviewGap } from "../../lib/codeApi";
import { blockerCount, blockerLabel, type BlockerLabel } from "./codeLabels";

export type Blocker = CodeReadiness["blockers"][number];
export type StructuralDebt = NonNullable<CodeReadiness["structural_debt"]>[number];

export type BlockerGroup = {
  code: string;
  label: string;
  view: BlockerLabel["view"];
  required: boolean;
  // Summed across repositories; null when any message carried no count.
  count: number | null;
  repoIds: number[];
  blockers: Blocker[];
};

/** One row per blocker code, required work first, backend order otherwise. */
export function groupBlockers(blockers: Blocker[]): BlockerGroup[] {
  const groups = new Map<string, BlockerGroup>();
  for (const blocker of blockers) {
    const meta = blockerLabel(blocker.code);
    const count = blockerCount(blocker.code, blocker.message);
    const group = groups.get(blocker.code);
    if (!group) {
      groups.set(blocker.code, {
        code: blocker.code,
        label: meta.label,
        view: meta.view,
        required: !blocker.overrideable,
        count,
        repoIds: blocker.repo_id != null ? [blocker.repo_id] : [],
        blockers: [blocker],
      });
      continue;
    }
    group.required ||= !blocker.overrideable;
    group.count = group.count == null || count == null ? null : group.count + count;
    if (blocker.repo_id != null && !group.repoIds.includes(blocker.repo_id)) group.repoIds.push(blocker.repo_id);
    group.blockers.push(blocker);
  }
  const ordered = [...groups.values()];
  return [...ordered.filter((group) => group.required), ...ordered.filter((group) => !group.required)];
}

/** Completion blockers not already listed for the next transition. */
export function additionalBlockers(next: Blocker[], completion: Blocker[]): Blocker[] {
  const seen = new Set(next.map((blocker) => `${blocker.code}:${blocker.repo_id ?? ""}`));
  return completion.filter((blocker) => !seen.has(`${blocker.code}:${blocker.repo_id ?? ""}`));
}

export function isReference(repo: Pick<CodeRepo, "repo_role">): boolean {
  return repo.repo_role === "reference";
}

/** A short tag that tells same-named repositories apart (the repo key's suffix). */
export function repoDisambiguator(repo: CodeRepo, repos: CodeRepo[]): string | null {
  if (!repos.some((other) => other.id !== repo.id && other.name === repo.name)) return null;
  const prefix = `${repo.name}-`;
  return repo.repo_key.startsWith(prefix) ? repo.repo_key.slice(prefix.length) : repo.repo_key;
}

export function repoLabel(repo: CodeRepo, repos: CodeRepo[]): string {
  const tag = repoDisambiguator(repo, repos);
  return tag ? `${repo.name} · ${tag}` : repo.name;
}

export function debtByRepo(readiness: CodeReadiness | null): Map<number, StructuralDebt[]> {
  const byRepo = new Map<number, StructuralDebt[]>();
  for (const debt of readiness?.structural_debt ?? []) {
    const list = byRepo.get(debt.repo_id) ?? [];
    list.push(debt);
    byRepo.set(debt.repo_id, list);
  }
  return byRepo;
}

// Readiness only measures direct-read debt for a repository whose index is
// current and complete; for these the count is unknown, not zero.
const DEBT_UNMEASURED_CODES = new Set(["structural_index_stale", "structural_index_metadata_incomplete"]);

export function debtUnknownRepoIds(readiness: CodeReadiness | null): Set<number> {
  return new Set(
    (readiness?.blockers ?? [])
      .filter((blocker) => DEBT_UNMEASURED_CODES.has(blocker.code) && blocker.repo_id != null)
      .map((blocker) => blocker.repo_id as number),
  );
}

export type ReviewTotals = { reviewed: number; total: number };

export function fileReviewTotals(coverage: CodeCoverage | null): ReviewTotals | null {
  if (!coverage) return null;
  const reviewed = Object.values(coverage.by_classification).reduce((sum, entry) => sum + entry.analyzed, 0);
  return { reviewed, total: coverage.total_files };
}

export function classReviewTotals(coverage: CodeCoverage | null, classification: string): ReviewTotals | null {
  if (!coverage) return null;
  const entry = coverage.by_classification[classification];
  return { reviewed: entry?.analyzed ?? 0, total: entry?.count ?? 0 };
}

export function pendingLeads(coverage: CodeCoverage | null): number | null {
  if (!coverage) return null;
  return coverage.trigger_summary?.pending ?? coverage.confidence.unprocessed_triggers;
}

export function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

/**
 * Files whose suspicious review awaits a verdict, from completion readiness
 * (it always evaluates the obligation; the backend's one definition also
 * feeds the results page's "awaiting a verdict" scope). Null while unknown.
 */
export function awaitingVerdictFiles(completion: CodeReadiness | null): number | null {
  if (!completion) return null;
  let total = 0;
  for (const blocker of completion.blockers) {
    if (blocker.code !== "unresolved_suspicious_analysis") continue;
    const count = blockerCount(blocker.code, blocker.message);
    if (count == null) return null;
    total += count;
  }
  return total;
}

export type FinishedNotReviewed = {
  /** Files whose latest job is done (the queue's Done lane). */
  finished: number;
  /** Of those, files that count as reviewed. */
  reviewed: number;
  /** Why the rest do not count, summed across repositories by reason. */
  reasons: CodeReviewGap[];
};

/**
 * Why "done" review jobs and "files reviewed" disagree, from per-repository
 * review progress. Null until progress loads or when nothing is missing.
 */
export function finishedNotReviewed(progress: CodeRepoReviewProgress[] | null): FinishedNotReviewed | null {
  if (!progress) return null;
  const analysis = progress.filter((row) => row.repo_role !== "reference");
  const reasons = new Map<string, CodeReviewGap>();
  let finished = 0;
  for (const row of analysis) {
    finished += row.finished_files ?? 0;
    for (const gap of row.finished_not_reviewed ?? []) {
      const known = reasons.get(gap.code);
      // One repository's message names its own count; several get a summed count with each message kept.
      reasons.set(gap.code, known
        ? { code: gap.code, count: known.count + gap.count, message: `${known.message} ${gap.message}` }
        : gap);
    }
  }
  if (reasons.size === 0) return null;
  const notCounted = [...reasons.values()].reduce((sum, gap) => sum + gap.count, 0);
  return { finished, reviewed: Math.max(0, finished - notCounted), reasons: [...reasons.values()] };
}
