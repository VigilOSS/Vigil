import type { RemediationBaseline, RemediationReleasePlan } from "./api";

export type RemediationDraftValues = {
  plan: string;
  baseline: Partial<RemediationBaseline>;
  releasePlan: Partial<RemediationReleasePlan>;
};

type Draft<T> = {
  value: T;
  base_value: T;
  review_digest: string | null;
  worktree_revision: string | null;
};

export type RemediationDrafts = { [K in keyof RemediationDraftValues]?: Draft<RemediationDraftValues[K]> };

export class InvalidRemediationDraftError extends Error {
  constructor(readonly rawRecord: string) {
    super("Stored remediation drafts are invalid");
    this.name = "InvalidRemediationDraftError";
  }
}

function storageKey(engagementKey: string, caseId: number): string {
  return `vigil.remediation.drafts.${encodeURIComponent(engagementKey)}:${caseId}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isDraftValue(field: string, value: unknown): boolean {
  if (field === "plan") return typeof value === "string";
  if (!isRecord(value)) return false;
  const nullable = field === "baseline" ? ["owner_actor", "owner_reason", "owner_decision"] : [];
  if (!Object.entries(value).every(([key, item]) => typeof item === "string" || (item === null && nullable.includes(key)))) return false;
  if (field === "baseline") {
    return (value.outcome === undefined || ["", "runtime_reproduced", "code_test_confirmed", "unreproduced"].includes(value.outcome as string))
      && (value.owner_decision === undefined || value.owner_decision === null || ["", "proceed", "pause"].includes(value.owner_decision as string));
  }
  return value.production_canary_decision === undefined || ["", "required", "not_required", "defer"].includes(value.production_canary_decision as string);
}

export function readRemediationDrafts(engagementKey: string, caseId: number): RemediationDrafts {
  const stored = window.sessionStorage.getItem(storageKey(engagementKey, caseId));
  if (!stored) return {};
  let parsed: unknown;
  try { parsed = JSON.parse(stored); }
  catch { throw new InvalidRemediationDraftError(stored); }
  if (!isRecord(parsed)) throw new InvalidRemediationDraftError(stored);
  for (const [field, draft] of Object.entries(parsed)) {
    if (!["plan", "baseline", "releasePlan"].includes(field) || !isRecord(draft)
      || !isDraftValue(field, draft.value) || !isDraftValue(field, draft.base_value)
      || !(draft.review_digest === null || typeof draft.review_digest === "string")
      || !(draft.worktree_revision === null || typeof draft.worktree_revision === "string")) {
      throw new InvalidRemediationDraftError(stored);
    }
  }
  return parsed as RemediationDrafts;
}

export function writeRemediationDrafts(engagementKey: string, caseId: number, drafts: RemediationDrafts): void {
  const key = storageKey(engagementKey, caseId);
  if (Object.keys(drafts).length) window.sessionStorage.setItem(key, JSON.stringify(drafts));
  else window.sessionStorage.removeItem(key);
}
