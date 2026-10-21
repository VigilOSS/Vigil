// Workspace rail badges: what each view holds that needs the operator, never
// a raw row total. Pure so the mapping is tested apart from the page that
// gathers its inputs. A missing input (not loaded, not applicable, failed)
// shows no badge rather than a guess; a zero shows none either.
//
// One word per kind of view: action queues (Proof work, Submissions, Runs,
// Commands, OAST) read "N attention", the same count as their "Needs
// attention" scope; open-work views (Intel, Surfaces, Coverage, Code) read
// "N open"; Findings reads "N current".

import { OPEN_COVERAGE_STATUSES } from "../components/coverage/coverageStatus.ts";
import type { AssessmentSummary } from "./api.ts";
import { RUN_ATTENTION_HEALTH, type RunHealthKey } from "./runAudit.ts";

export type RailBadge = {
  /** Short text in the rail, e.g. "12 open". */
  text: string;
  /** Full sentence for assistive technology and the hover title. */
  label: string;
};

export type RailBadgeInputs = {
  summary: Pick<AssessmentSummary, "finding_count" | "open_surface_count" | "coverage_statuses"> | null;
  /** Findings loaded from the ledger, used only while the summary is unavailable. */
  loadedFindingCount?: number;
  /** Surfaces loaded on the Surfaces view, used only while the summary is unavailable. */
  loadedSurfaceCount?: number;
  /** The Proof work "Needs attention" count (lib/proofWorkApi.ts proofNeedsAttentionCount). */
  proofNeedsAttention?: number | null;
  /** The Submissions "To do" count (ready, blocked, needs draft, exported but not filed). */
  submissionsToDo?: number | null;
  /** Open intel leads; null where intel readiness does not apply. */
  openIntelLeads?: number | null;
  codeQueue?: { pending: number; processing: number; error: number; needs_context: number } | null;
  /** Runs per health key, from the Runs view's last load or the badge read. */
  runHealth?: Partial<Record<RunHealthKey, number>> | null;
  /** Command runs the server's "needs attention" rule selects. */
  commandsNeedingAttention?: number | null;
  /** OAST probes with callbacks waiting for review. */
  oastCallbacksToReview?: number | null;
};

const count = (value: number) => value.toLocaleString("en-US");
const plural = (value: number, one: string, many: string) => (value === 1 ? one : many);

function badge(value: number | null | undefined, text: (n: string) => string, label: (n: string, value: number) => string): RailBadge | undefined {
  if (value == null || !Number.isFinite(value) || value <= 0) return undefined;
  const n = count(value);
  return { text: text(n), label: label(n, value) };
}

export type RailBadgeKey =
  | "findings" | "proof" | "submissions" | "intel" | "surfaces" | "coverage" | "code" | "runs" | "commands" | "oast";

export function railBadges(inputs: RailBadgeInputs): Partial<Record<RailBadgeKey, RailBadge>> {
  const { summary } = inputs;
  const badges: Partial<Record<RailBadgeKey, RailBadge>> = {};
  const set = (key: RailBadgeKey, value: RailBadge | undefined) => {
    if (value) badges[key] = value;
  };

  set("findings", summary?.finding_count != null
    ? badge(summary.finding_count, (n) => `${n} current`, (n, v) => `${n} current ${plural(v, "finding", "findings")} (excludes merged and false positives)`)
    : badge(inputs.loadedFindingCount, (n) => `${n} loaded`, (n, v) => `${n} ${plural(v, "finding", "findings")} loaded; current count unavailable`));

  set("proof", badge(inputs.proofNeedsAttention, (n) => `${n} attention`, (n, v) => `${n} ${plural(v, "finding needs", "findings need")} attention: a live test to approve, a blocked or stale test, no test prepared yet, or a changed finding to re-verify`));

  set("submissions", badge(inputs.submissionsToDo, (n) => `${n} attention`, (n, v) => `${n} ${plural(v, "finding needs", "findings need")} attention: ready to export, blocked, needing a draft, or exported but not filed`));

  set("intel", badge(inputs.openIntelLeads, (n) => `${n} open`, (n, v) => `${n} open intel ${plural(v, "lead", "leads")}`));

  set("surfaces", summary?.open_surface_count != null
    ? badge(summary.open_surface_count, (n) => `${n} open`, (n, v) => `${n} open attack ${plural(v, "surface", "surfaces")}`)
    : badge(inputs.loadedSurfaceCount, (n) => `${n} loaded`, (n, v) => `${n} attack ${plural(v, "surface", "surfaces")} loaded; open count unavailable`));

  if (summary?.coverage_statuses) {
    const statuses = summary.coverage_statuses;
    const open = OPEN_COVERAGE_STATUSES.reduce((total, status) => total + (statuses[status] ?? 0), 0);
    set("coverage", badge(open, (n) => `${n} open`, (n, v) => `${n} coverage ${plural(v, "item", "items")} still open: blocked, deferred, pending, or queued`));
  }

  if (inputs.codeQueue) {
    const q = inputs.codeQueue;
    set("code", badge(q.pending + q.processing + q.error + q.needs_context, (n) => `${n} open`, (n, v) => `${n} open code review ${plural(v, "job", "jobs")}: pending, processing, failed, or needing context`));
  }

  if (inputs.runHealth) {
    const health = inputs.runHealth;
    const attention = [...RUN_ATTENTION_HEALTH].reduce((total, key) => total + (health[key] ?? 0), 0);
    set("runs", badge(attention, (n) => `${n} attention`, (n, v) => `${n} ${plural(v, "run needs", "runs need")} attention or failed (as of the last Runs load)`));
  }

  set("commands", badge(inputs.commandsNeedingAttention, (n) => `${n} attention`, (n, v) => `${n} command ${plural(v, "run needs", "runs need")} attention`));

  set("oast", badge(inputs.oastCallbacksToReview, (n) => `${n} attention`, (n, v) => `${n} OAST ${plural(v, "probe has", "probes have")} callbacks to review`));

  return badges;
}
