import { request } from "./api";
import type {
  AssessmentFindingDetail,
  SubmissionAttachmentPage,
  SubmissionPendingVersion,
  SubmissionVersion,
} from "./api";

// Submissions desk contract (`/assessment/submissions…`). The backend owns
// every queue state, readiness gate, and default attachment selection; this
// module only names the shapes it returns.

export type SubmissionPlatform = "bugcrowd" | "hackerone" | "direct" | "ghsa";

// One queue state per finding, in the backend's precedence order.
export type SubmissionQueueState =
  | "filed"
  | "not_candidate"
  | "needs_draft"
  | "exported"
  | "ready"
  | "blocked";

export type SubmissionListingFilter =
  | SubmissionQueueState
  | "actionable"
  | "incomplete_exports"
  | "all";

export type SubmissionDeskRow = {
  id: number;
  slug: string;
  title: string;
  severity: string;
  workflow_status: string;
  verification_status: string;
  submission_status: string;
  submission_platform: string;
  submission_ref: string;
  submission_url: string;
  row_version: number;
  version_count: number;
  latest_version_number: number | null;
  staging_version_count: number;
  failed_version_count: number;
  created_at: string;
  updated_at: string;
  readiness: SubmissionQueueState;
  readiness_reason: string;
  blocker_count: number;
  first_blocker: string;
  latest_version_platform: SubmissionPlatform | null;
  latest_version_completed_at: string | null;
  default_platform: SubmissionPlatform | null;
};

export type SubmissionDeskCounts = Record<SubmissionQueueState, number> & {
  actionable: number;
  incomplete_exports: number;
  all: number;
};

export type SubmissionDeskListing = {
  findings: SubmissionDeskRow[];
  findings_page: SubmissionAttachmentPage;
  // Every finding, regardless of filters.
  counts: SubmissionDeskCounts;
  // Findings matching the readiness, search, and recency filters.
  facets: { severity: Record<string, number>; platform: Record<string, number> };
  staging_count: number;
  failed_count: number;
};

export type SubmissionDeskQuery = {
  readiness?: SubmissionListingFilter;
  severity?: string[];
  platform?: string[];
  q?: string;
  changedWithinHours?: number | null;
  findingOffset?: number;
  findingLimit?: number;
};

// Registration metadata for an attachable artifact (never indexed text).
export type SubmissionAttachmentRow = {
  id: number;
  relative_path: string;
  kind: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  present: boolean;
  related_finding_slug: string | null;
  integrity_status: string;
  created_at: string;
  updated_at: string;
  // Only on rows fetched by id: an internal submission-workspace file.
  internal?: boolean;
};

export type SubmissionBlockerItem = { message: string; fix: string; command: string };

export type SubmissionReadiness = {
  pass1_qa: SubmissionPass1QA;
  attachment_ids: number[];
  final_ready: boolean;
  blockers: string[];
  items: SubmissionBlockerItem[];
  // A completed version an export of exactly this selection would replay.
  existing_version_number: number | null;
  attachment_total_bytes: number;
  attachment_limit_bytes: number;
  platform: SubmissionPlatform | null;
  external_body_sha256: string;
  submission_sha256: string;
  finding_row_version: number | null;
};

export type SubmissionReadinessResponse = SubmissionReadiness & { finding_slug: string };

export type SubmissionTriageAttachment = {
  artifact_id: number | null;
  source_path: string;
  packet_path: string;
  media_type: string;
  bytes: number | null;
  sha256: string;
};

export type SubmissionBlindTriage = {
  required: boolean;
  verdict: string | null;
  accepted: boolean;
  packet_id: string | null;
  decided_at: string | null;
  platform: string | null;
  reviewed_body_sha256: string | null;
  attachments: SubmissionTriageAttachment[];
  // null unless the packet manifest names registered artifacts for every file.
  attachment_ids: number[] | null;
  manifest_error: string;
};

export type SubmissionDeskWorkspace = {
  present: boolean;
  submission_path: string;
  context_path: string;
  markdown: string;
  submission_sha256: string;
  external_body_sha256?: string;
  context: Record<string, unknown>;
  final_ready: boolean;
  blockers: string[];
  external_body: string;
  external_body_valid_utf8: boolean;
};

export type SubmissionPass1QA = {
  status: "missing" | "current" | "stale" | "blocked";
  verdict: "pass" | "blocked" | null;
  packet_id: string | null;
  auditor_dispatch_agent_id: string | null;
  reason: string;
  decided_at: string | null;
  issue: string;
};

export type SubmissionDeskDetail = {
  finding: AssessmentFindingDetail;
  workspace: SubmissionDeskWorkspace;
  platform: SubmissionPlatform | null;
  blind_triage: SubmissionBlindTriage;
  pass1_qa: SubmissionPass1QA;
  latest_version: SubmissionVersion | null;
  default_attachment_ids: number[];
  default_attachment_source: "blind_triage" | "latest_version" | "none";
  default_attachments: SubmissionAttachmentRow[];
  // Evaluated for default_attachment_ids.
  readiness: SubmissionReadiness;
  // Linked to this finding, first page.
  eligible_attachments: SubmissionAttachmentRow[];
  eligible_attachments_page: SubmissionAttachmentPage;
  // Every attachable file in the engagement (browse via listSubmissionAttachments).
  engagement_attachment_total: number;
  versions: SubmissionVersion[];
  versions_page: SubmissionAttachmentPage;
  pending_version_count: number;
  pending_versions: SubmissionPendingVersion[];
  pending_versions_page: SubmissionAttachmentPage;
};

export type SubmissionAttachmentScope = "finding" | "engagement";

export type SubmissionAttachmentListing = {
  scope: SubmissionAttachmentScope;
  query: string;
  attachments: SubmissionAttachmentRow[];
  page: SubmissionAttachmentPage;
};

function submissionsBase(engagementKey: string): string {
  return `/engagements/${encodeURIComponent(engagementKey)}/assessment/submissions`;
}

function withQuery(path: string, query: URLSearchParams): string {
  const qs = query.toString();
  return qs ? `${path}?${qs}` : path;
}

/** Findings per desk listing page, and the largest page a refresh re-reads at once (the backend's cap). */
export const SUBMISSION_PAGE_SIZE = 100;
export const SUBMISSION_MAX_PAGE_SIZE = 500;

export function listSubmissionDesk(engagementKey: string, params: SubmissionDeskQuery = {}) {
  const query = new URLSearchParams();
  if (params.readiness) query.set("readiness", params.readiness);
  for (const value of params.severity ?? []) query.append("severity", value);
  for (const value of params.platform ?? []) query.append("platform", value);
  if (params.q?.trim()) query.set("q", params.q.trim());
  if (params.changedWithinHours != null) {
    query.set("changed_within_hours", String(params.changedWithinHours));
  }
  if (params.findingOffset != null) query.set("finding_offset", String(params.findingOffset));
  if (params.findingLimit != null) query.set("finding_limit", String(params.findingLimit));
  return request<SubmissionDeskListing>(withQuery(submissionsBase(engagementKey), query));
}

export function getSubmissionDesk(
  engagementKey: string,
  findingSlug: string,
  params: {
    versionOffset?: number;
    versionLimit?: number;
    pendingVersionOffset?: number;
    pendingVersionLimit?: number;
  } = {},
) {
  const query = new URLSearchParams();
  if (params.versionOffset != null) query.set("version_offset", String(params.versionOffset));
  if (params.versionLimit != null) query.set("version_limit", String(params.versionLimit));
  if (params.pendingVersionOffset != null) {
    query.set("pending_version_offset", String(params.pendingVersionOffset));
  }
  if (params.pendingVersionLimit != null) {
    query.set("pending_version_limit", String(params.pendingVersionLimit));
  }
  return request<SubmissionDeskDetail>(
    withQuery(`${submissionsBase(engagementKey)}/${encodeURIComponent(findingSlug)}`, query),
  );
}

export function getSubmissionReadiness(
  engagementKey: string,
  findingSlug: string,
  attachmentIds: number[],
) {
  const query = new URLSearchParams();
  for (const id of [...attachmentIds].sort((a, b) => a - b)) {
    query.append("attachment_id", String(id));
  }
  return request<SubmissionReadinessResponse>(
    withQuery(
      `${submissionsBase(engagementKey)}/${encodeURIComponent(findingSlug)}/readiness`,
      query,
    ),
  );
}

export function listSubmissionAttachments(
  engagementKey: string,
  findingSlug: string,
  params: { scope?: SubmissionAttachmentScope; q?: string; offset?: number; limit?: number } = {},
) {
  const query = new URLSearchParams();
  if (params.scope) query.set("scope", params.scope);
  if (params.q?.trim()) query.set("q", params.q.trim());
  if (params.offset != null) query.set("offset", String(params.offset));
  if (params.limit != null) query.set("limit", String(params.limit));
  return request<SubmissionAttachmentListing>(
    withQuery(
      `${submissionsBase(engagementKey)}/${encodeURIComponent(findingSlug)}/attachments`,
      query,
    ),
  );
}
