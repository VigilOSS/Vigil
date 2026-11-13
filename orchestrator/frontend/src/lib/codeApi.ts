// Code-analysis reads added for the Code view: the paged analysis-result
// projection (with facets), one result and its place in that order, the
// current-attempt queue lanes, and per-repository review progress. The shared
// code contract (repositories, coverage, queue, readiness) lives in lib/api.ts.

import { request, type CodeAnalysisResult, type CodeQueuePage, type CodeQueueStatus } from "./api";
import type { RecordPosition } from "../components/record/recordNavigation";

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

/** Where a receipt sits in the filtered order; `index` is 0-based and null when the result is outside the filtered results. */
export type CodeAnalysisResultPosition = RecordPosition<CodeAnalysisResult>;

export type CodeQueueLane = Exclude<CodeQueueStatus, "done">;

/**
 * One lead a review left (`code_analysis_triggers`). `origin` says why:
 * `cross_file` — data flows into another file, so that file gets reviewed with
 * this context; `depth_floor` — a critical or high closeout left `vuln_class`
 * below its tier's effort floor, so that family is owed a deeper pass.
 */
export type CodeTrigger = {
  id: number;
  status: string;
  origin: string;
  vuln_class: string;
  reason: string;
  repo_id: number;
  /** The file to review, as the lead named it; `resolved_target_file_path` when it matched a snapshot file. */
  target_file_path: string;
  resolved_target_file_path: string | null;
  /** The file whose review left the lead. */
  source_file_path: string | null;
  source_queue_item_id: number | null;
  /** The review job that followed it, once one did. */
  resolved_queue_item_id: number | null;
  /** Why it was settled without another review. */
  resolution_note: string;
  created_at: string;
  updated_at: string;
};

/** One row of the paged code-file listing (`GET code/files`). */
export type CodeFileRow = {
  id: number;
  repo_id: number;
  file_path: string;
  language: string | null;
  loc: number;
  classification: string;
  /** The architect's free-text role for the file. */
  role: string;
  analysis_status: string;
  slot_types: string[];
  context_tags: string[];
  /** False when the classification recorded no tags at all (not "none apply"). */
  context_tags_recorded: boolean;
};

export type CodeFilePage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CodeFileRow[];
};

export type CodeFileQuery = {
  repo_id?: number;
  classification?: string;
  search?: string;
  context_tags_recorded?: boolean;
  /** Files whose recorded context tags include this tag. */
  context_tag?: string;
  limit: number;
  offset: number;
};

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

/** One page of the current leads in one status, most recently updated first (`GET code/triggers`). */
export type CodeTriggerPage = {
  total: number;
  offset: number;
  count: number;
  has_more: boolean;
  items: CodeTrigger[];
  /** Every lead in the status by kind, whatever `origin` the page selected. */
  by_origin: { cross_file: number; depth_floor: number };
};

export function listCodeTriggers(
  engagementKey: string,
  status: string,
  page: { limit: number; offset: number; origin?: "cross_file" | "depth_floor" },
) {
  const params = new URLSearchParams({ status, limit: String(page.limit), offset: String(page.offset) });
  if (page.origin) params.set("origin", page.origin);
  return request<CodeTriggerPage>(`${base(engagementKey)}/triggers?${params.toString()}`);
}

/** One page of the code files, highest review priority first. */
export function listCodeFiles(engagementKey: string, query: CodeFileQuery) {
  const params = new URLSearchParams({ limit: String(query.limit), offset: String(query.offset) });
  if (query.repo_id != null) params.set("repo_id", String(query.repo_id));
  if (query.classification) params.set("classification", query.classification);
  if (query.search) params.set("search", query.search);
  if (query.context_tags_recorded != null) params.set("context_tags_recorded", String(query.context_tags_recorded));
  if (query.context_tag) params.set("context_tag", query.context_tag);
  return request<CodeFilePage>(`${base(engagementKey)}/files?${params.toString()}`);
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
