// Pure shaping for the Activity view: page merging, day groups, dispatch
// cards, and burst folding. Rows arrive newest first in the backend's total
// order; nothing here re-sorts them, so loaded pages stay exactly in feed order.

import type { ActivityEntity, ActivityEntityRef, ActivityItem } from "../../lib/activityApi";
import { formatAbsoluteTime, formatDuration, serverTimeMs } from "../../lib/serverTime";
import { engagementHref } from "../../lib/workspaceRoutes";
import { statusEntry, statusOrder, type StatusEntry } from "../ui/statusTones";

/** Consecutive top-level entries further apart than this start a new cluster. */
export const BURST_GAP_MS = 15 * 60_000;
/** Fewer repeats than this stay as individual rows. */
export const BURST_MIN = 3;

/**
 * A dispatch card's status: the stored dispatch status (statusTones `dispatch`,
 * reported by its "agent done" row or "in-progress" while only started), or
 * what the loaded rows show without one: handed off, finished with a
 * free-text result, or nothing to go on.
 */
export type DispatchStatus = string;

// Statuses the loaded rows imply when no stored status is among them.
const DERIVED_DISPATCH_STATUS: Readonly<Record<string, StatusEntry>> = {
  "handed-off": { label: "Handed off", tone: "info", meaning: "The agent handed its work off; no done report is loaded." },
  finished: { label: "Finished", tone: "info", meaning: "The agent reported done with a free-text result and no stored status; open the card for the result." },
  unknown: { label: "Status not recorded", tone: "neutral", meaning: "No start, handoff or done report is among the loaded entries." },
};

/** Label, tone and meaning for a dispatch card's status. */
export function dispatchStatusEntry(status: DispatchStatus): StatusEntry {
  return DERIVED_DISPATCH_STATUS[status] ?? statusEntry("dispatch", status);
}

export type RowEntry = { type: "row"; id: string; at: string; item: ActivityItem };

export type DispatchEntry = {
  type: "dispatch";
  id: string;
  at: string;
  agentId: string;
  role: string;
  runId: number | null;
  /** Loaded member rows, newest first. */
  items: ActivityItem[];
  oldestAt: string;
  /** Whether the dispatch's start row is loaded, so the duration is exact. */
  startLoaded: boolean;
  durationMs: number;
  status: DispatchStatus;
  findings: ActivityEntity[];
  handoff: ActivityItem | null;
};

export type BurstEntry = {
  type: "burst";
  /** `burst:<oldest member id>`; a newer repeat joining the burst keeps it. */
  id: string;
  /**
   * `burst:<member id>` for every member: the burst is open when any of them
   * was recorded open, so it stays open as members join on either end.
   */
  memberKeys: string[];
  at: string;
  oldestAt: string;
  label: string;
  /** Set when every member shares one actor. */
  actorName: string | null;
  entries: Array<RowEntry | DispatchEntry>;
  entities: ActivityEntity[];
};

export type FeedEntry = RowEntry | DispatchEntry | BurstEntry;

export type DayGroup = {
  /** UTC calendar day, `YYYY-MM-DD`. */
  day: string;
  label: string;
  entries: FeedEntry[];
  /** Loaded rows in the day, counting every member of cards and bursts. */
  count: number;
};

// ── Paging ─────────────────────────────────────────────────────────────

/** Newer rows (newest first) go on top; rows already loaded keep their place. */
export function mergeNewer(current: ActivityItem[], newer: ActivityItem[]): ActivityItem[] {
  const known = new Set(current.map((row) => row.id));
  const fresh = newer.filter((row) => !known.has(row.id));
  return fresh.length ? [...fresh, ...current] : current;
}

/** An older page goes underneath, skipping anything already loaded. */
export function appendOlder(current: ActivityItem[], older: ActivityItem[]): ActivityItem[] {
  const known = new Set(current.map((row) => row.id));
  return [...current, ...older.filter((row) => !known.has(row.id))];
}

// ── Entity links ───────────────────────────────────────────────────────

function positiveId(value: unknown): number | null {
  const number = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function refText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * The Code view's best deep link for one reviewed file: the results of its
 * repository, searched by its path, naming the receipt to open.
 */
export function codeFileHref(engagementKey: string, ref: ActivityEntityRef): string | null {
  const repo = positiveId(ref.repo_id);
  const path = refText(ref.file_path);
  if (!repo && !path) return null;
  return engagementHref(engagementKey, {
    tab: "code",
    view: "results",
    repo: repo ?? undefined,
    q: path || undefined,
    result: positiveId(ref.result_id) ?? undefined,
  });
}

/** Where an entity chip leads: the record its `ref` names, or null when no view can open it. */
export function entityHref(engagementKey: string, entity: ActivityEntity): string | null {
  const { ref } = entity;
  if (ref === undefined) {
    // Feeds without refs: only keys that are the record's own id link.
    if (entity.type === "finding" && entity.key) return engagementHref(engagementKey, { tab: "findings", finding: entity.key });
    const id = positiveId(entity.key);
    if (entity.type === "run" && id) return engagementHref(engagementKey, { tab: "runs", run: id });
    if (entity.type === "http_variant" && id) return engagementHref(engagementKey, { tab: "http", request: id });
    return null;
  }
  if (ref === null) return null;
  switch (entity.type) {
    case "finding":
    case "chain": {
      const slug = refText(ref.finding_slug);
      return slug ? engagementHref(engagementKey, { tab: "findings", finding: slug }) : null;
    }
    case "run": {
      const run = positiveId(ref.run_id);
      return run ? engagementHref(engagementKey, { tab: "runs", run }) : null;
    }
    case "http_variant": {
      const request = positiveId(ref.request_variant_id);
      return request ? engagementHref(engagementKey, { tab: "http", request }) : null;
    }
    case "surface": {
      const surface = positiveId(ref.surface_id);
      return surface ? engagementHref(engagementKey, { tab: "surfaces", surface }) : null;
    }
    case "intel": {
      const type = refText(ref.intel_type);
      const id = positiveId(ref.intel_id);
      return type && id ? engagementHref(engagementKey, { tab: "intel", intel_type: type, intel_id: id }) : null;
    }
    case "code_file":
      return codeFileHref(engagementKey, ref);
    case "file": {
      const file = refText(ref.file_name);
      return file ? engagementHref(engagementKey, { tab: "artifacts", file }) : null;
    }
    case "oob_probe": {
      const probe = positiveId(ref.probe_id);
      return probe ? engagementHref(engagementKey, { tab: "oast", probe }) : null;
    }
    default:
      return null;
  }
}

/** Why a chip does not open anything, for its label and the entry detail. */
export function entityUnlinkedReason(entity: ActivityEntity): string {
  return refText(entity.unlinked_reason) || "No view opens this record.";
}

// ── Day groups ─────────────────────────────────────────────────────────

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** UTC day of a server timestamp (the app shows every time in UTC). */
export function utcDay(value: string): string {
  return formatAbsoluteTime(value, "minute").slice(0, 10);
}

export function dayLabel(day: string, now: number): string {
  const today = new Date(now).toISOString().slice(0, 10);
  const yesterday = new Date(now - 86_400_000).toISOString().slice(0, 10);
  if (day === today) return "Today";
  if (day === yesterday) return "Yesterday";
  const ms = Date.parse(`${day}T00:00:00Z`);
  return Number.isNaN(ms) ? day : `${WEEKDAYS[new Date(ms).getUTCDay()]} ${day}`;
}

// ── Dispatch cards ─────────────────────────────────────────────────────

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function uniqueEntities(entities: ActivityEntity[]): ActivityEntity[] {
  const seen = new Set<string>();
  return entities.filter((entity) => {
    const key = `${entity.type}:${entity.key}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const STORED_DISPATCH_STATUSES = new Set(statusOrder("dispatch"));

function dispatchStatus(items: ActivityItem[]): DispatchStatus {
  const done = items.find((row) => row.kind === "agent done");
  // The done report's result is the dispatch row's stored status
  // (`PATCH /dispatches/{id}`); older reports may hold free text instead.
  const result = text(done?.detail.result);
  if (done) return STORED_DISPATCH_STATUSES.has(result) ? result : result ? "finished" : "unknown";
  if (items.some((row) => row.kind === "agent handoff")) return "handed-off";
  if (items.some((row) => row.kind === "agent start")) return "in-progress";
  return "unknown";
}

function dispatchEntry(items: ActivityItem[]): DispatchEntry {
  const newest = items[0];
  const oldest = items[items.length - 1];
  const dispatch = newest.dispatch!;
  return {
    type: "dispatch",
    id: `dispatch:${dispatch.agent_id}`,
    at: newest.occurred_at,
    agentId: dispatch.agent_id,
    role: dispatch.role,
    runId: items.find((row) => row.dispatch?.run_id)?.dispatch?.run_id ?? null,
    items,
    oldestAt: oldest.occurred_at,
    startLoaded: items.some((row) => row.kind === "agent start"),
    durationMs: Math.max(0, (serverTimeMs(newest.occurred_at) ?? 0) - (serverTimeMs(oldest.occurred_at) ?? 0)),
    status: dispatchStatus(items),
    findings: uniqueEntities(items.flatMap((row) => row.entities.filter((entity) => entity.type === "finding"))),
    handoff: items.find((row) => row.kind === "agent handoff") ?? null,
  };
}

/** Rows of a dispatch with two or more loaded rows become one card at its newest row. */
function withDispatchCards(items: ActivityItem[]): Array<RowEntry | DispatchEntry> {
  const byDispatch = new Map<string, ActivityItem[]>();
  for (const row of items) {
    const agentId = row.dispatch?.agent_id;
    if (!agentId) continue;
    const members = byDispatch.get(agentId);
    if (members) members.push(row);
    else byDispatch.set(agentId, [row]);
  }
  const placed = new Set<string>();
  const entries: Array<RowEntry | DispatchEntry> = [];
  for (const row of items) {
    const agentId = row.dispatch?.agent_id;
    const members = agentId ? byDispatch.get(agentId) : undefined;
    if (!agentId || !members || members.length < 2) {
      entries.push({ type: "row", id: row.id, at: row.occurred_at, item: row });
    } else if (!placed.has(agentId)) {
      placed.add(agentId);
      entries.push(dispatchEntry(members));
    }
  }
  return entries;
}

// ── Bursts ─────────────────────────────────────────────────────────────

const KIND_PLURALS: Record<string, string> = {
  "code-record analysis": "code file reviews",
  "code-record-analysis": "code file reviews",
  "code-record variant-check": "variant checks",
  "code-dispatch done": "code queue items closed",
  "code-dispatch requeue-triggers": "code trigger requeues",
  "agent start": "dispatches started",
  "agent done": "dispatches finished",
  "agent handoff": "handoffs",
  "agent decision": "decisions",
  "agent bind-client-handle": "client bindings",
  "finding-record": "findings recorded",
  "record-finding": "findings recorded",
  "finding-update": "finding updates",
  "update-finding": "finding updates",
  "finding-verify": "verification changes",
  "verify-finding": "verification changes",
  "finding-link": "finding links",
  "link-finding": "finding links",
  "artifact register": "files registered",
  "Bash": "shell commands",
  "apply_patch": "file edits",
  "Edit": "file edits",
  "Write": "file writes",
  "surface.updated": "surface updates",
  "intel.recorded": "intel records",
  "finding.created": "findings recorded",
  "chain.created": "attack chains recorded",
};

function foldKey(entry: RowEntry | DispatchEntry): string | null {
  if (entry.type === "dispatch") return `dispatch|${entry.role}`;
  const row = entry.item;
  // Narrative notes are what people read the log for; never hide them.
  if (row.category === "notes") return null;
  const metadata = row.detail.metadata;
  const decisionKind = metadata && typeof metadata === "object" ? text((metadata as Record<string, unknown>).kind) : "";
  return `${row.category}|${row.kind}|${decisionKind}|${row.actor.name}`;
}

function burstLabel(members: Array<RowEntry | DispatchEntry>): string {
  const count = members.length;
  const first = members[0];
  if (first.type === "dispatch") {
    const tally = new Map<string, number>();
    for (const member of members) {
      if (member.type === "dispatch" && member.status !== "unknown") tally.set(member.status, (tally.get(member.status) ?? 0) + 1);
    }
    const outcomes = [...tally].map(([status, n]) => `${n} ${dispatchStatusEntry(status).label.toLowerCase()}`).join(", ");
    return `${count} ${first.role || "agent"} dispatches${outcomes ? ` · ${outcomes}` : ""}`;
  }
  const summaries = new Set(members.map((member) => (member.type === "row" ? member.item.summary : "")));
  if (summaries.size === 1) return `${count} × ${first.item.summary}`;
  const plural = KIND_PLURALS[first.item.kind];
  return plural ? `${count} ${plural}` : `${count} × ${first.item.kind}`;
}

function memberItems(entry: RowEntry | DispatchEntry): ActivityItem[] {
  return entry.type === "row" ? [entry.item] : entry.items;
}

function burstEntry(members: Array<RowEntry | DispatchEntry>): BurstEntry {
  const actors = new Set(members.flatMap((member) => memberItems(member).map((row) => row.actor.name)));
  const last = members[members.length - 1];
  return {
    type: "burst",
    id: `burst:${last.id}`,
    memberKeys: members.map((member) => `burst:${member.id}`),
    at: members[0].at,
    oldestAt: last.type === "dispatch" ? last.oldestAt : last.at,
    label: burstLabel(members),
    actorName: actors.size === 1 && members[0].type === "row" ? [...actors][0] : null,
    entries: members,
    entities: uniqueEntities(members.flatMap((member) =>
      member.type === "dispatch" ? member.findings : member.item.entities.filter((entity) => entity.type === "finding"),
    )),
  };
}

/**
 * Within each cluster of entries no more than BURST_GAP_MS apart, repeats of
 * one fold key (same kind by the same actor, or dispatches of one role) fold
 * into a single burst at the position of the newest repeat. Other entries
 * keep their order.
 */
function foldBursts(entries: Array<RowEntry | DispatchEntry>): FeedEntry[] {
  const folded: FeedEntry[] = [];
  let cluster: Array<RowEntry | DispatchEntry> = [];
  const flush = () => {
    const groups = new Map<string, Array<RowEntry | DispatchEntry>>();
    for (const entry of cluster) {
      const key = foldKey(entry);
      if (!key) continue;
      const members = groups.get(key);
      if (members) members.push(entry);
      else groups.set(key, [entry]);
    }
    const emitted = new Set<string>();
    for (const entry of cluster) {
      const key = foldKey(entry);
      const members = key ? groups.get(key) : undefined;
      if (!key || !members || members.length < BURST_MIN) folded.push(entry);
      else if (!emitted.has(key)) {
        emitted.add(key);
        folded.push(burstEntry(members));
      }
    }
    cluster = [];
  };
  let previousMs: number | null = null;
  for (const entry of entries) {
    const ms = serverTimeMs(entry.at);
    if (previousMs != null && ms != null && previousMs - ms > BURST_GAP_MS) flush();
    cluster.push(entry);
    // A dispatch card spans time; the next entry is measured from its oldest row.
    previousMs = serverTimeMs(entry.type === "dispatch" ? entry.oldestAt : entry.at) ?? previousMs;
  }
  flush();
  return folded;
}

function entryCount(entry: FeedEntry): number {
  if (entry.type === "row") return 1;
  if (entry.type === "dispatch") return entry.items.length;
  return entry.entries.reduce((total, member) => total + entryCount(member), 0);
}

/** Day groups (newest first) of dispatch cards, bursts, and rows. */
export function buildFeed(items: ActivityItem[], now: number): DayGroup[] {
  const byDay = new Map<string, Array<RowEntry | DispatchEntry>>();
  for (const entry of withDispatchCards(items)) {
    const day = utcDay(entry.at) || "Unknown date";
    const entries = byDay.get(day);
    if (entries) entries.push(entry);
    else byDay.set(day, [entry]);
  }
  return [...byDay].map(([day, entries]) => {
    const folded = foldBursts(entries);
    return {
      day,
      label: dayLabel(day, now),
      entries: folded,
      count: folded.reduce((total, entry) => total + entryCount(entry), 0),
    };
  });
}

/**
 * How long a dispatch card spans. Without its start row loaded the span is a
 * lower bound, and a sub-second bound says nothing, so it says the start is
 * not loaded instead.
 */
export function dispatchSpanText(entry: Pick<DispatchEntry, "startLoaded" | "durationMs">): string {
  if (entry.durationMs < 1000) return entry.startLoaded ? "under 1s" : "start not loaded";
  return `${entry.startLoaded ? "" : "≥ "}${formatDuration(entry.durationMs)}`;
}
