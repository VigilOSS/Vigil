// Payload contract for the single-file Vigil report.
//
// This mirrors EXACTLY what the backend export endpoint injects into the
// `#vigil-report-data` script node (see
// orchestrator/backend/app/api/report_export.py::_assemble_report_payload).
// The two sides are designed together — any field added here must be added
// there and vice versa.
//
// Shapes are intentionally loose (lots of optional fields / index signatures)
// because they are projections of existing backend SQL rows
// (assessment_summary, list_report_finding_groups, list_attack_chains) that
// carry more columns than the report renders. We type the fields we actually
// read and tolerate the rest.

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

// Subset of assessment_summary(engagement_id) that the Statistics tab reads.
// Extra keys from the backend are preserved via the index signature.
export interface ReportSummary {
  finding_count?: number;
  finding_severities?: Record<string, number>;
  finding_workflow_statuses?: Record<string, number>;
  finding_verification_statuses?: Record<string, number>;
  attack_chain_count?: number;
  open_surface_count?: number;
  credential_count?: number;
  access_count?: number;
  target_count?: number;
  service_count?: number;
  coverage_count?: number;
  probe_count?: number;
  report_blocker_count?: number;
  coverage_blocker_count?: number;
  [key: string]: unknown;
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
  evidence_type?: string;
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
  root_cause_effect?: string;
  root_cause_slug?: string;
  root_cause_note?: string;
  sibling_order?: number | null;
  [key: string]: unknown;
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
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

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
  [key: string]: unknown;
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
  report_readiness: ReportReadiness;
}
