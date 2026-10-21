// The pure decisions the proof-work queue UI makes (default proof route,
// the one next action per state) over the api.ts proof-work contract.
//
// Nothing here grants scope or approval. Route hints and host suggestions
// only prefill the operator's choice — preparation still admits every host
// itself.

import type { ProofNextTest, ProofOwedEntry, ProofWork, ProofWorkList, ProofWorkQueueState } from "./api";

export type ProofRoute = "code" | "web";

/**
 * The route a new preparation starts on: the verifier's route hint when it
 * names one, otherwise local code for source-bound or file-located findings
 * and a live test for everything else. The operator can always change it.
 */
export function defaultProofRoute(entry: {
  next_test?: ProofNextTest | null;
  source_bound?: boolean;
  canonical_location?: string;
}): ProofRoute {
  if (entry.next_test?.route_hint === "local") return "code";
  if (entry.next_test?.route_hint === "live") return "web";
  if (entry.source_bound) return "code";
  if ((entry.canonical_location ?? "").startsWith("file:")) return "code";
  return "web";
}

export type ProofAction = "prepare" | "approve" | "revoke" | "reconcile" | "release" | "none";

function ownerEnded(work: ProofWork): boolean {
  return Boolean(work.owner_agent_id)
    && ["completed", "failed", "aborted", "blocked"].includes(work.owner_dispatch_status ?? "");
}

/** The one action that moves a prepared item forward from its state. */
export function nextWorkAction(work: ProofWork): ProofAction {
  switch (work.queue_state) {
    case "needs_approval":
      return work.current && work.owed ? "approve" : "reconcile";
    case "in_progress":
      return work.route === "web" && !work.approval_required ? "revoke" : "none";
    case "blocked":
      if (ownerEnded(work)) return "release";
      if (work.blocker_cause === "approval" || (work.route === "web" && work.approval_required && work.current && work.owed)) {
        return "approve";
      }
      return "reconcile";
    case "stale":
      return ownerEnded(work) ? "release" : "reconcile";
    default:
      return "none";
  }
}

/** The one action for a parked finding as a whole. */
export function nextFindingAction(entry: Pick<ProofOwedEntry, "queue_state">, current: ProofWork[]): ProofAction {
  if (entry.queue_state === "unprepared") return "prepare";
  const live = current.filter((work) => work.queue_state !== "done" && work.queue_state !== "stale");
  if (live.length === 0) return "prepare";
  const lead = current.find((work) => work.queue_state === entry.queue_state) ?? live[0];
  return nextWorkAction(lead);
}

/**
 * The parked findings that need the operator: the one rule behind the Proof
 * work "Needs attention" scope and the rail badge. Findings that need
 * re-verification always count too.
 */
export const PROOF_ATTENTION_STATES: readonly ProofWorkQueueState[] = ["needs_approval", "blocked", "stale", "unprepared"];

export const PROOF_ATTENTION_RULE =
  "Findings waiting on you or a preparation: a live test to approve, a blocked or stale test, no test prepared yet, or a changed finding to re-verify.";

export function proofNeedsAttention(state: ProofWorkQueueState | undefined): boolean {
  return state !== undefined && PROOF_ATTENTION_STATES.includes(state);
}

/**
 * The one "needs attention" count for Proof work, shared by the page header,
 * its "Needs attention" scope and the rail badge: each parked finding whose
 * state needs the operator counts once (however many work items it holds),
 * plus each finding that needs re-verification.
 */
export function proofNeedsAttentionCount(queue: Pick<ProofWorkList, "owed" | "reverification_required">): number {
  return queue.owed.filter((entry) => proofNeedsAttention(entry.queue_state)).length + queue.reverification_required.length;
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * The Proof work order: what the card asks of the operator first (the
 * proof-work vocabulary order: approvals and blockers before ready and
 * done), then severity, then slug.
 */
export function compareProofCards(
  stateOrder: readonly string[],
  a: { state?: string; severity?: string; slug: string },
  b: { state?: string; severity?: string; slug: string },
): number {
  const rank = (state?: string) => {
    const index = stateOrder.indexOf(state ?? "");
    return index < 0 ? stateOrder.length : index;
  };
  return rank(a.state) - rank(b.state)
    || (SEVERITY_RANK[a.severity ?? ""] ?? 5) - (SEVERITY_RANK[b.severity ?? ""] ?? 5)
    || a.slug.localeCompare(b.slug, undefined, { numeric: true });
}

/** How a work item's live authority stands, in words (never claims an approval that was not given). */
export function approvalText(work: Pick<ProofWork, "current" | "route" | "approval_required" | "approval_renewal_required" | "approval_decision">): string {
  if (!work.current) return "Context changed; approval cannot authorize execution";
  if (work.route === "code") return "Local sandbox work; no live approval needed";
  if (work.approval_decision === "revoked") return "Approval revoked; a fresh approval is required";
  if (work.approval_required) {
    return work.approval_renewal_required ? "Fresh approval required for this preparation" : "Live proof approval required";
  }
  if (work.approval_decision === "approved") return "Approved by the operator for this work";
  return "No separate approval needed: the engagement's exploit policy authorizes live proof";
}

/** Everything a ProofWorkCard needs for one finding, from the queue. */
export function proofCardForFinding(queue: ProofWorkList, slug: string): {
  slug: string;
  title: string;
  severity?: string;
  owed: ProofOwedEntry | null;
  items: ProofWork[];
} | null {
  const owed = queue.owed.find((entry) => entry.finding_slug === slug) ?? null;
  const items = queue.items.filter((work) => work.finding_slug === slug);
  if (!owed && items.length === 0) return null;
  return {
    slug,
    title: owed?.title ?? items[0]?.finding_title ?? slug,
    severity: owed?.severity ?? items[0]?.finding_severity,
    owed,
    items,
  };
}
