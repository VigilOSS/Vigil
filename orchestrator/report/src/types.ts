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
  finding_verification_states?: Record<string, number>;
  finding_verification_dispositions?: Record<string, number>;
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
  verification_state?: string;
  verification_disposition?: string;
  canonical_location?: string;
  summary?: string;
  impact?: string;
  evidence_detail?: string;
  remediation?: string;
  // Authored either as one block (the preferred shape — the author owns the
  // numbering, and other sections cite those numbers) or as a list of steps.
  // The backend projection normalizes to a list, but renderers accept both so a
  // raw record never breaks them; see lib/steps.ts.
  steps_to_reproduce?: string | string[];
  cwe_id?: string;
  owasp_category?: string;
  cvss_score?: number | null;
  cvss_vector?: string;
  entry_point?: string;
  sink?: string;
  poc_code?: string;
  references?: unknown[];
  source_name?: string;
  // Root-cause link metadata present on siblings only.
  root_cause_effect?: string;
  root_cause_relationship?: string;
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

export interface ReportReadiness {
  ready: boolean;
  blocker_count: number;
  blockers: Array<{ kind?: string; detail?: string; [key: string]: unknown }>;
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
