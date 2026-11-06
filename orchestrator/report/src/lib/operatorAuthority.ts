// How a terminal verdict was reached, when it was not reached by a proof receipt.
//
// Every terminal verification status normally requires a decision receipt from
// a completed, evidence-healthy, author-independent dispatch run. ADR 0043
// adds one route that does not: `finding verify --operator-authority --intel-id
// <id>` lets the operator settle a finding on evidence that lies outside the
// sealed snapshot by design — a deployment configuration that disables the
// vulnerable path is not source under review, so no receipt in the engagement
// can carry it. The backend stamps
// `provenance.operator_authority = {kind, intel_id, intel_type, at, reason}` and
// the report projection carries the whole stamp to the top level beside
// `verification_status`.
//
// ADR 0019 makes the operator the authority over their own engagement. What it
// does not permit is weakening a gate silently, and this document is the one
// Vigil artifact whose reader is the CLIENT: a waived verdict rendered here as
// indistinguishable from a dispatch-verified one is an honest operator record
// turned into a laundered proof. ADR 0043's visibility obligation names this
// report explicitly, so every surface that states a verdict states how it was
// reached, and this module is the single place that decides the wording.
//
// Narrowed here rather than typed in types.ts, exactly as `poc_request` is in
// lib/poc.ts: the field is a free-form JSON column, and a renderer must not
// throw on one.

export interface OperatorAuthority {
  kind?: string;
  intel_id?: number;
  intel_type?: string;
  at?: string;
  reason?: string;
}

/**
 * The stamp behind this verdict, or `null` when it rests on a proof receipt.
 *
 * `null` is the ordinary case and the field is delivered on every finding, so
 * absence here means "receipt-backed", never "unknown".
 */
export function asOperatorAuthority(value: unknown): OperatorAuthority | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  const stamp: OperatorAuthority = {};
  if (typeof raw.kind === "string" && raw.kind) stamp.kind = raw.kind;
  // The citation is the part a distrustful reader can go and open, so it is
  // kept only when it is a usable row id rather than coerced from anything.
  if (typeof raw.intel_id === "number" && Number.isFinite(raw.intel_id)) {
    stamp.intel_id = raw.intel_id;
  }
  // The other half of the citation. `intel get` takes the type as a required
  // positional over ten entity types whose ids are allocated independently, so
  // the id alone resolves against whichever table the reader guessed. Kept only
  // when it arrives as a table NAME, because a value that is not one would
  // assert a table nobody resolved.
  if (typeof raw.intel_type === "string" && raw.intel_type) {
    stamp.intel_type = raw.intel_type;
  }
  if (typeof raw.at === "string" && raw.at) stamp.at = raw.at;
  // Verbatim, including whitespace: this is the operator's own attestation and
  // the only statement of what the out-of-snapshot evidence settles.
  if (typeof raw.reason === "string" && raw.reason) stamp.reason = raw.reason;
  // An empty object is a stamp that names nothing; treat it as no waiver rather
  // than printing a bare "operator attested" with nothing behind it.
  return Object.keys(stamp).length > 0 ? stamp : null;
}

/**
 * `intel tech-component 17` — the row a reader can go and open, or `""`.
 *
 * Spelled the way the CLI spells it, which is also the command a reader would
 * type, so the citation in this document and the one in the operator's terminal
 * name the same row the same way. A stamp recording no type states its id by
 * itself: half a citation is honest, and a guessed table is not.
 */
function citation(stamp: OperatorAuthority): string {
  if (stamp.intel_id == null) return "";
  return stamp.intel_type
    ? `intel ${stamp.intel_type} ${stamp.intel_id}`
    : `intel ${stamp.intel_id}`;
}

/** Short badge text: the authority, plus the intel row it cited. */
export function operatorAuthorityLabel(stamp: OperatorAuthority): string {
  const intel = citation(stamp);
  return intel ? `Operator attested · ${intel}` : "Operator attested";
}

/**
 * One sentence saying what the verdict rests on.
 *
 * `kind` is rendered rather than interpreted: the backend writes
 * `out_of_snapshot` today, and a renderer switching on a closed set would
 * silently blank a future one — which on this surface means silently restoring
 * the appearance of a dispatch-verified verdict.
 */
export function operatorAuthoritySentence(stamp: OperatorAuthority): string {
  const parts = [
    "This verdict was recorded on the operator's own attestation rather than a proof receipt.",
  ];
  if (stamp.kind) parts.push(`Evidence: ${stamp.kind.replace(/_/g, " ")}.`);
  const intel = citation(stamp);
  if (intel) parts.push(`Cited ${intel}.`);
  return parts.join(" ");
}
