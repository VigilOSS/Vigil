import type { FindingOperatorAuthority, FindingProvenance, AssessmentVerificationAudit } from "./api.ts";

// The same states drive Overview's attention queue and Findings' summary.
export const AWAITING_VERIFICATION = ["unreviewed", "disputed", "pending_runtime_proof", "blocked"] as const;

// ── Operator-authority verdicts ───────────────────────────────────────
//
// A terminal verdict normally requires a decision receipt from a completed,
// evidence-healthy, verifier-produced proof run. `finding verify
// --operator-authority --intel-id <id>` is the one route that does not: the
// operator stands behind the verdict with evidence that is NOT in the
// engagement snapshot, and the backend stamps
// `provenance.operator_authority = {kind, intel_id, intel_type, at, reason}` in place of
// the receipt ids. ADR 0019 permits that — Vigil does not defend against its
// own operator — but it says nothing about hiding it, and the whole point of
// the stamp is that such a verdict must never read as a dispatch-verified one.
//
// So every view that renders a verdict reads it through here, and `null` means
// "a receipt or nothing", never "unknown".

/** A finding-shaped object a verdict renders from: a list row or a point read. */
type VerdictSource = {
  provenance?: FindingProvenance | null;
  verification_audit?: AssessmentVerificationAudit | null;
};

function isStamp(value: unknown): value is FindingOperatorAuthority {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * The stored operator-authority stamp, or null. It survives invalidation;
 * label/sentence callers pass the current status to distinguish prior authority.
 *
 * Two carriers, one value: the point read stamps it onto
 * `verification_audit.operator_authority` beside the receipts it replaces,
 * while `provenance.operator_authority` is on every ledger row — which is why
 * the grid and the clipboard can show it at all. The backend derives both from
 * the same provenance key, so preferring the audit costs nothing and keeps the
 * reads from disagreeing.
 *
 * `superseded_operator_authority` is deliberately NOT consulted. A later
 * dispatch-verified verdict moves the stamp there rather than deleting it, and
 * presenting a retired waiver as the standing authority would invert the very
 * distinction this function exists to draw.
 */
export function operatorAuthorityOf(source: VerdictSource | null | undefined): FindingOperatorAuthority | null {
  if (!source) return null;
  const fromAudit = source.verification_audit?.operator_authority;
  if (isStamp(fromAudit)) return fromAudit;
  const fromProvenance = source.provenance?.operator_authority;
  return isStamp(fromProvenance) ? fromProvenance : null;
}

/**
 * The cited row as `tech-component 1` — table then id — or `""` for no row.
 *
 * The table is half the citation. `intel get` takes the type as a required
 * positional and the ten intel tables allocate ids independently, so an id on
 * its own resolves against whichever table the surface guessed: a verdict citing
 * `tech-component 1` reads as a note on id 1, and the reader who went to check
 * the verdict ends up at an unrelated record. The spelling is the CLI's, which
 * is also the command that opens the row, so the page and the terminal name the
 * same record the same way.
 *
 * A stamp recording no type states its id by itself. Stamps predating the field
 * carry none, and saying less is correct where guessing a table is the hazard.
 */
export function operatorAuthorityIntelRef(stamp: FindingOperatorAuthority): string {
  if (typeof stamp.intel_id !== "number") return "";
  const intelType = typeof stamp.intel_type === "string" ? stamp.intel_type : "";
  return intelType ? `${intelType} ${stamp.intel_id}` : String(stamp.intel_id);
}

/** Short badge text: the authority, plus the intel row it cited when there is one. */
export function operatorAuthorityLabel(stamp: FindingOperatorAuthority, verification?: string): string {
  const intel = operatorAuthorityIntelRef(stamp);
  const label = verification !== undefined && !["confirmed", "downgraded", "false_positive"].includes(verification)
    ? "Prior operator authority" : "Operator authority";
  return intel ? `${label} · intel ${intel}` : label;
}

/**
 * One sentence naming what the verdict rests on, for a notice or a clipboard.
 *
 * `kind` is rendered rather than interpreted: the backend writes
 * `out_of_snapshot` today and a renderer that switched on a closed set would
 * silently blank a future one.
 */
export function operatorAuthoritySentence(stamp: FindingOperatorAuthority, verification?: string): string {
  const prior = verification !== undefined && !["confirmed", "downgraded", "false_positive"].includes(verification);
  const parts = [prior
    ? "A prior verdict rested on the operator's own authority, not a proof receipt. The current finding requires verification."
    : "This verdict rests on the operator's own authority, not a proof receipt."];
  if (stamp.kind) parts.push(`Evidence: ${String(stamp.kind).replace(/_/g, " ")}.`);
  const intel = operatorAuthorityIntelRef(stamp);
  if (intel) parts.push(`Cited intel ${intel}.`);
  return parts.join(" ");
}
