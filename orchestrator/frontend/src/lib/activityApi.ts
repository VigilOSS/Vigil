import { request } from "./api";

// GET /engagements/{key}/activity — audit-log entries merged with structured
// events, newest first (backend services/activity_feed.py owns the contract).

export type ActivityActorKind = "operator" | "agent" | "system";

/**
 * The record an entity chip opens, by type (backend `activity_feed._entity_ref`):
 * finding `{finding_slug}` · run `{run_id}` · http_variant `{request_variant_id}` ·
 * surface `{surface_id}` · intel `{intel_type, intel_id}` · chain `{chain_key,
 * finding_slug}` · code_file `{code_file_id, repo_id, file_path, result_id}` ·
 * file `{file_name}` (engagement root documents only) · oob_probe `{probe_id}`.
 */
export type ActivityEntityRef = Record<string, string | number | null | undefined>;

export type ActivityEntity = {
  /** finding · run · http_variant · surface · intel · chain · code_file · file · oob_probe */
  type: string;
  key: string;
  label: string;
  /** The record to open; null when none can be opened (see `unlinked_reason`). Absent from older feeds. */
  ref?: ActivityEntityRef | null;
  /** Why `ref` is null, in one sentence; "" when linked. */
  unlinked_reason?: string;
};

export type ActivityDispatch = {
  agent_id: string;
  role: string;
  run_id: number | null;
};

export type ActivityItem = {
  /** `audit:<id>` or `event:<id>`; unique across both sources. */
  id: string;
  source: "audit" | "event";
  source_id: number;
  /** Opaque position in the feed order, for `before` / `after`. */
  cursor: string;
  /** ISO-8601 UTC. */
  occurred_at: string;
  actor: { name: string; kind: ActivityActorKind };
  category: string;
  /** Audit title or event type, verbatim. */
  kind: string;
  /** One plain sentence. */
  summary: string;
  entities: ActivityEntity[];
  dispatch: ActivityDispatch | null;
  /** Stored fields verbatim (ADR 0019): action, result, body, metadata, … */
  detail: Record<string, unknown>;
};

export type ActivityCategory = {
  key: string;
  label: string;
  /** Rows in this category under the actor, time, and search filters. */
  count: number;
  /** Shown when no category is chosen explicitly. */
  default: boolean;
};

export type ActivityFeedPage = {
  items: ActivityItem[];
  /** More rows remain in the requested direction (older, or newer for `after`). */
  has_more: boolean;
  /** Rows matching every filter, including the category selection. */
  total: number;
  categories: ActivityCategory[];
};

export type ActivityFeedQuery = {
  categories?: string[];
  actor?: ActivityActorKind | "";
  q?: string;
  since?: string;
  until?: string;
  before?: string;
  after?: string;
  limit?: number;
};

export function listActivityFeed(engagementKey: string, query: ActivityFeedQuery = {}) {
  const params = new URLSearchParams();
  if (query.categories?.length) params.set("category", query.categories.join(","));
  if (query.actor) params.set("actor", query.actor);
  if (query.q) params.set("q", query.q);
  if (query.since) params.set("since", query.since);
  if (query.until) params.set("until", query.until);
  if (query.before) params.set("before", query.before);
  if (query.after) params.set("after", query.after);
  if (query.limit != null) params.set("limit", String(query.limit));
  const qs = params.toString();
  return request<ActivityFeedPage>(`/engagements/${encodeURIComponent(engagementKey)}/activity${qs ? `?${qs}` : ""}`);
}
