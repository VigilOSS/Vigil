// The same states drive Overview's attention queue and Findings' summary.
export const AWAITING_VERIFICATION = ["unreviewed", "disputed", "pending_runtime_proof", "blocked"] as const;
