// Code-analysis reads added for the Code view: the paged analysis-result
// projection (with facets), one result and its place in that order, the
// current-attempt queue lanes, and per-repository review progress. The shared
// code contract (repositories, coverage, queue, readiness) lives in lib/api.ts.

import { request, type CodeAnalysisResult, type CodeQueuePage, type CodeQueueStatus } from "./api";

/** Why receipts or finished reviews are not counted or listed (`code`, count, plain message). */
export type CodeReviewGap = { code: string; count: number; message: string };

export type CodeRepoReviewProgress = {
  repo_id: number;
  repo_role: "analysis" | "reference";
  admitted_files: number;
  reviewed_files: number;
  /** Files whose latest job is done (the queue's Done lane). */
  finished_files?: number;
  /** Why finished files do not count as reviewed. */
  finished_not_reviewed?: CodeReviewGap[];
};

/**
 * One receipt as the point read returns it, with its standing. It lists every
 * callable ref, so it carries no separate `callable_ref_count`.
 */
export type CodeAnalysisResultDetail = Omit<CodeAnalysisResult, "callable_ref_count"> & {
  repo_key: string;
  repo_role: string;
  queue_status: string | null;
  queue_disposition: string | null;
  replaced_by_result_id: number | null;
  latest_attempt: { id: number; status: string } | null;
  /** Listed among the current results (not superseded or replaced). */
  current: boolean;
  evidence_ref: string;
  result_fingerprint: string;
  repo_generation: number;
  lease_token?: string;
  supersedes?: number | null;
  source_superseded_at?: string | null;
  source_supersession_reason?: string;
  cwe_coverage: Array<{
    family: string;
    disposition: string;
    effort?: number;
    functions_analyzed?: number;
    entry_chains_traced?: number;
    total_entry_chains?: number;
    notes?: string;
  }>;
  cross_file_triggers: Array<{ file_path?: string; reason?: string; vuln_class?: string }>;
  audit_metadata: Record<string, unknown>;
};

export type CodeAnalysisResultFacets = {
  disposition: Record<string, number>;
  confidence: Record<string, number>;
  workflow_status: Record<string, number>;
};

/** `current`: every current receipt. `awaiting_verdict`: the receipts behind files awaiting a verdict. */
export type CodeResultScope = "current" | "awaiting_verdict";

export type CodeAnalysisResultPage = {
  scope: CodeResultScope;
  total: number;
  file_total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CodeAnalysisResult[];
  facets: CodeAnalysisResultFacets;
  /** Engagement-wide size of the awaiting-verdict scope (ignores filters). */
  awaiting_verdict: { files: number; results: number };
  /** Receipts no scope lists, and why. */
  not_listed: CodeReviewGap[];
};

export type CodeAnalysisResultQuery = {
  scope?: CodeResultScope;
  disposition?: string[];
  confidence?: string[];
  workflow_status?: string[];
  cwe?: string;
  agent?: string;
  slot?: string;
  file?: string;
  function?: string;
  q?: string[];
  limit?: number;
  offset?: number;
};

export type CodeAnalysisResultPosition = {
  /** 0-based; null when the result is outside the filtered results. */
  index: number | null;
  total: number;
  previous: CodeAnalysisResult | null;
  next: CodeAnalysisResult | null;
};

export type CodeQueueLane = Exclude<CodeQueueStatus, "done">;

function base(engagementKey: string) {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/code`;
}

function resultParams(query: CodeAnalysisResultQuery): string {
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      for (const entry of value) if (entry) params.append(name, entry);
    } else if (value !== undefined && value !== null && value !== "") {
      params.set(name, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

export function listCodeRepoReviewProgress(engagementKey: string) {
  return request<CodeRepoReviewProgress[]>(`${base(engagementKey)}/repos/review-progress`);
}

export function listCodeAnalysisResultPage(engagementKey: string, query: CodeAnalysisResultQuery = {}) {
  return request<CodeAnalysisResultPage>(`${base(engagementKey)}/analysis-results/page${resultParams(query)}`);
}

/** One receipt by id, superseded or not. */
export function getCodeAnalysisResult(engagementKey: string, resultId: number) {
  return request<CodeAnalysisResultDetail>(`${base(engagementKey)}/analysis-results/${resultId}`);
}

/** Where a receipt sits in the results page order under the same filters and scope. */
export function getCodeAnalysisResultPosition(
  engagementKey: string,
  resultId: number,
  query: Omit<CodeAnalysisResultQuery, "limit" | "offset">,
) {
  return request<CodeAnalysisResultPosition>(`${base(engagementKey)}/analysis-results/${resultId}/position${resultParams(query)}`);
}

/**
 * One page of a queue lane: the latest attempt per file in that status,
 * exactly what `analysis-queue/stats` counts, highest priority first.
 */
export function listCodeQueueLane(engagementKey: string, status: CodeQueueLane, page: { limit: number; offset: number }) {
  const params = new URLSearchParams({
    status,
    current_only: "true",
    limit: String(page.limit),
    offset: String(page.offset),
  });
  return request<CodeQueuePage>(`${base(engagementKey)}/analysis-queue?${params.toString()}`);
}
