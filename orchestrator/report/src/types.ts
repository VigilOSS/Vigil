// Payload contract for the single-file Vigil report.
//
// This mirrors EXACTLY what the backend export endpoint injects into the
// `#vigil-report-data` script node (see
// orchestrator/backend/app/api/report_export.py::_assemble_report_payload).
// The two sides are designed together — any field added here must be added
// there and vice versa.
//
// The exported HTML is delivered to the CLIENT, so the backend ships only the
// fields listed here rather than the whole SQL rows behind them: its
// `_FINDING_FIELDS` / `_SUMMARY_FIELDS` / `_CHAIN_FIELDS` / `_CHAIN_LINK_FIELDS`
// allow-lists are derived from these declarations AND from what the components
// read. That is why the projections below carry no `[key: string]: unknown`
// escape hatch — a renderer reaching for a field the payload no longer ships is
// a type error, which is the drift signal we want. Fields stay optional because
// a sparse finding legitimately omits most of them.

export type ReportMode = "draft" | "final";

export interface ReportEngagement {
  key: string;
  target: string;
  status: string;
  current_phase: string;
  engagement_type: string | null;
  customer: string | null;
  scope_hosts: string[];
  created_at: string;
}

// The headline numbers the Statistics tab renders. Two halves, and the split
// matters:
//
// The four finding rollups are DERIVED at the delivery boundary from this
// report's own `finding_groups`, not copied from assessment_summary. That
// projection is not mode-filtered — its status rollups are unfiltered
// `GROUP BY`s over every finding row, and its counts admit anything that is not
// merged or false-positive — while the finding LIST is filtered to reportable
// findings. Copying them shipped a client a headline count and a donut that
// disagreed with the body of their own report, and a Workflow chart with a
// literal `false positive` row on it.
//
// The remaining three describe the engagement rather than its triage state, and
// are copied verbatim.
export interface ReportSummary {
  finding_count?: number;
  finding_severities?: Record<string, number>;
  finding_workflow_statuses?: Record<string, number>;
  finding_verification_statuses?: Record<string, number>;
  attack_chain_count?: number;
  open_surface_count?: number;
  credential_count?: number;
}

// A single report-projected finding (root, sibling, or standalone). Matches
// report_readiness._report_record(): top-level severity/summary plus the
// flattened details fields the report-writer needs.
export interface ReportFinding {
  report_id?: string;
  slug?: string;
  title?: string;
  severity?: string;
  workflow_status?: string;
  verification_status?: string;
  canonical_location?: string;
  // Severity-defining context a reader needs before the severity means anything:
  // what privilege the attack requires, and whether the proof was observed on
  // the wire or inferred from source.
  auth_context?: string;
  // Nullable in the schema (`evidence_type TEXT`, no default), unlike
  // `auth_context` — a finding recorded without one ships an explicit null.
  evidence_type?: string | null;
  summary?: string;
  impact?: string;
  evidence_detail?: string;
  remediation?: string;
  // Authored either as one block (the preferred shape — the author owns the
  // numbering, and other sections cite those numbers) or as a list of steps.
  // The backend projection normalizes to a list, but renderers accept both so a
  // raw record never breaks them; see lib/steps.ts.
  steps_to_reproduce?: string | string[];
  // The command-run ids behind those steps, in step order. Projected beside them
  // so a reader can tell a reproduction that was executed from one that was
  // written; see lib/steps.ts:reproRunIds.
  repro_runs?: string | string[];
  cwe_id?: string;
  owasp_category?: string;
  cvss_score?: number | null;
  cvss_vector?: string;
  entry_point?: string;
  sink?: string;
  poc_code?: string;
  // Structured HTTP proof, shaped by the `web/v1` extension of
  // agent/schemas/finding-record.schema.json: request is
  // {method,url,headers,body}, response is {status,headers,body_excerpt}.
  // Typed as `unknown` and narrowed in lib/poc.ts rather than trusted here —
  // these are free-form JSON columns, and a renderer must not throw on one.
  poc_request?: unknown;
  poc_response?: unknown;
  references?: unknown[];
  source_name?: string;
  // Root-cause link metadata present on siblings only, written by
  // links.py:_root_cause_link_metadata. `root_cause_effect` says what fixing the
  // root buys for THIS sibling (`eliminates_finding` / `eliminates_attack_path`).
  // Its other three keys are not here: the group structure already names the
  // root (`root_cause_slug`) and already carries the siblings in order
  // (`sibling_order`, which the backend sorts by), and `root_cause_link_id` is a
  // row id. Nothing renders them.
  root_cause_effect?: string;
  root_cause_note?: string;
}

export interface ReportFindingGroup {
  root: ReportFinding;
  siblings: ReportFinding[];
  sibling_count: number;
  residual_path_count: number;
  highest_severity: string;
}

// Shape of list_report_finding_groups(mode).
export interface ReportFindingGroups {
  mode: ReportMode;
  groups: ReportFindingGroup[];
  standalone: ReportFinding[];
  group_count: number;
  standalone_count: number;
  finding_count: number;
}

// A row from list_attack_chains() (assessment_attack_chains table).
export interface ReportAttackChain {
  chain_key?: string;
  title?: string;
  status?: string;
  severity?: string;
  narrative?: string;
  // `created_at` is not here: the chain header shows when the path was last
  // established, and when a row was first inserted is engagement chronology the
  // report never renders.
  updated_at?: string;
}

// A row from list_attack_chain_links() — the structured attack path the
// narrative above describes in prose. The backend ships these already sorted
// into the order they were recorded, which is the only step order the schema
// carries (assessment_attack_chain_links has no order column).
//
// `relation` and `entity_kind` are free-form TEXT, max 64, with no enum and no
// CHECK constraint behind either. Exactly one value carries semantics anywhere
// in Vigil: report_readiness gates on `relation === "step"`, requiring every
// such link to resolve to a reportable finding slug. A renderer must therefore
// treat every other relation as supporting context of an unknown vocabulary
// rather than switching on a fixed set.
export interface ReportAttackChainLink {
  chain_key?: string;
  relation?: string;
  entity_kind?: string;
  entity_ref?: string;
  notes?: string;
}

// Blockers and advisories are heterogeneous by kind (a chain blocker carries a
// `chain_key`, a snapshot blocker a `snapshot_status`), and they ship verbatim:
// the reader of a draft is the operator, from whom ADR 0019 withholds nothing.
// So this one projection deliberately keeps its index signature.
export interface ReportReadinessItem {
  kind?: string;
  detail?: string;
  slug?: string;
  [key: string]: unknown;
}

// report_readiness() returns blockers AND advisories (a blocker stops a `final`
// export; an advisory never does). Both were previously undeclared on the
// advisory side, so the payload carried data the contract did not admit existed.
export interface ReportReadiness {
  ready: boolean;
  blocker_count: number;
  blockers: ReportReadinessItem[];
  advisory_count?: number;
  advisories?: ReportReadinessItem[];
}

// The complete injected payload.
export interface ReportData {
  generated_at: string;
  vigil_version: string;
  mode: ReportMode;
  engagement: ReportEngagement;
  summary: ReportSummary;
  finding_groups: ReportFindingGroups;
  attack_chains: ReportAttackChain[];
  attack_chain_links: ReportAttackChainLink[];
  // Draft exports only. A `final` export is refused while blockers stand, so
  // its reader is shown no readiness at all (StatisticsTab:ReadinessNotice) —
  // and the advisories that survive a passing gate quote internal QA doubt
  // about the engagement's own evidence, which is not the client's to read.
  report_readiness?: ReportReadiness;
}
