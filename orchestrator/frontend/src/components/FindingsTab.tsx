import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import type {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentFindingGroup,
  AssessmentFindingLink,
  AssessmentFindingTransition,
  AssessmentFindingTransitionSummary,
  AssessmentProofReceipt,
  AssessmentConfirmCheck,
  AssessmentVerificationAudit,
  FindingDetails,
  FindingPocRequest,
  FindingPocResponse,
  FindingProvenance,
  FindingReference,
  IntelResolutionResult,
  ProofNextTest,
} from "../lib/api";
import { List, Table2 } from "lucide-react";
import { getAssessmentFinding, getAssessmentFindingTransition, listAssessmentFindingGroups, listAssessmentFindingLinks, listAssessmentFindingTransitions, resolveIntelIds } from "../lib/api";
import { JsonTree } from "./ArtifactViewer";
import { JsonView } from "./JsonView";
import { engagementHref, parseWorkspaceRoute, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { createCoalescedRunner } from "../lib/coalesce";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import "../styles/findings.css";
import { CodeBlock, isCurlLike, TimeStamp } from "./formatting";
import { CopyChip, KV, KVTime, Prose, ProseModeToggle, SectionHead } from "./drawer/DrawerKit";
import type { ProseMode, ToastFn } from "./drawer/DrawerKit";
import { Skeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  SegmentedControl,
  SeverityTag,
  StatusPill,
  compareStatus,
  describeSort,
  humanizeStatus,
  severityColor,
  severityLabel,
  statusLabel,
  type SortDirection,
  type SortKind,
} from "./ui";
import {
  compareByRecency,
  countRecency,
  findingChangedAt,
  FINDINGS_SORTS,
  LAST_VISIT_DWELL_MS,
  matchesRecency,
  newestLedgerTime,
  RECENCY_FILTERS,
  readLastVisit,
  summarizeRecentChanges,
  writeLastVisit,
  type FindingsSort,
  type RecencyFilter,
} from "../lib/findingRecency";

// Optional flat table view — lazy-loaded ag-grid (code-split chunk).
// The grouped root-cause list remains the default and is NOT lazy.
const FindingsGrid = lazy(() => import("./FindingsGrid"));

// Grouped-view pagination. One "page item" is a top-level entry: a root-cause
// group (root + its siblings) OR a standalone finding. Only the grouped view
// paginates — the Table view is ag-grid, which virtualizes its own rows.
const GROUPED_PAGE_SIZE = 25;

const SORT_LABELS: Record<FindingsSort, string> = {
  severity: "Severity",
  newest: "Newest",
  changed: "Recently changed",
};
const SORT_HINTS: Record<FindingsSort, string> = {
  severity: "Highest severity first; the list view groups findings by root cause",
  newest: "Most recently recorded first, as one list",
  changed: "Most recent ledger change first (verification, workflow, or content), as one list",
};
const RECENCY_LABELS: Record<RecencyFilter, string> = {
  new24h: "New 24h",
  new7d: "New 7d",
  changed24h: "Changed 24h",
  changed7d: "Changed 7d",
  sinceVisit: "Since my last visit",
};
const RECENCY_HINTS: Record<RecencyFilter, string> = {
  new24h: "Recorded in the last 24 hours",
  new7d: "Recorded in the last 7 days",
  changed24h: "Recorded earlier, with a ledger change in the last 24 hours",
  changed7d: "Recorded earlier, with a ledger change in the last 7 days",
  sinceVisit: "Recorded or changed since you last viewed these findings in this browser",
};

// View toggle, persisted in localStorage alongside findings.selected.
type FindingsView = "grouped" | "table";
const FINDINGS_VIEW_KEY = "findings.view";
function readFindingsView(): FindingsView {
  try {
    return window.localStorage.getItem(FINDINGS_VIEW_KEY) === "table" ? "table" : "grouped";
  } catch {
    return "grouped";
  }
}

// Each view keeps its own order: the grouped list defaults to severity (root
// causes first), the flat table to creation date, newest first.
type SortByView = Record<FindingsView, FindingsSort>;
const DEFAULT_SORT_BY_VIEW: SortByView = { grouped: "severity", table: "newest" };
// Each named sort as the results line describes it.
const SORT_DESCRIPTIONS: Record<FindingsSort, string> = {
  severity: describeSort("Severity", "desc", "rank"),
  newest: describeSort("Created", "desc", "time"),
  changed: describeSort("Last changed", "desc", "time"),
};

/** A column order the table reports after a header click. */
export type TableColumnSort = { label: string; direction: SortDirection; kind: SortKind };

type QueueContext = { query: string; severity: string[]; workflow: string[]; verification: string[]; recency: RecencyFilter | null; sort: SortByView; page: number };

function readQueueContext(engagementKey: string): QueueContext {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(`findings.queue.${engagementKey}`) || "{}");
    const strings = (items: unknown): string[] => Array.isArray(items) ? items.filter((item): item is string => typeof item === "string") : [];
    const sortOf = (view: FindingsView): FindingsSort => (FINDINGS_SORTS as readonly unknown[]).includes(value.sort?.[view]) ? value.sort[view] : DEFAULT_SORT_BY_VIEW[view];
    return {
      query: typeof value.query === "string" ? value.query : "",
      severity: strings(value.severity),
      workflow: strings(value.workflow),
      verification: strings(value.verification),
      recency: (RECENCY_FILTERS as readonly unknown[]).includes(value.recency) ? value.recency : null,
      sort: { grouped: sortOf("grouped"), table: sortOf("table") },
      page: Number.isSafeInteger(value.page) && value.page >= 0 ? value.page : 0,
    };
  } catch {
    return { query: "", severity: [], workflow: [], verification: [], recency: null, sort: DEFAULT_SORT_BY_VIEW, page: 0 };
  }
}

// A link can open the queue already filtered (Overview's "awaiting
// verification" count names the verification states it counts):
// `?tab=findings&verification=unreviewed,blocked`, likewise `severity`,
// `workflow`, `recency` and `q`. Filters named in the address replace the
// remembered ones; the address then drops them (replace, no history entry) so
// the operator's later changes are not undone by a reload.
const ROUTE_FILTER_PARAMS = ["q", "severity", "workflow", "verification", "recency"] as const;

type RouteFilters = { filters: Pick<QueueContext, "query" | "severity" | "workflow" | "verification" | "recency" | "page">; href: string };

function readRouteFilters(engagementKey: string): RouteFilters | null {
  const route = parseWorkspaceRoute(window.location.hash);
  if (route.kind !== "engagement" || route.key !== engagementKey || route.params.get("tab") !== "findings") return null;
  const params = route.params;
  if (!ROUTE_FILTER_PARAMS.some((name) => params.has(name))) return null;
  const list = (name: string) => (params.get(name) ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  const recency = params.get("recency");
  const kept = Object.fromEntries([...params].filter(([name]) => !(ROUTE_FILTER_PARAMS as readonly string[]).includes(name)));
  return {
    filters: {
      query: params.get("q") ?? "",
      severity: list("severity"),
      workflow: list("workflow"),
      verification: list("verification"),
      recency: (RECENCY_FILTERS as readonly unknown[]).includes(recency) ? recency as RecencyFilter : null,
      page: 0,
    },
    href: engagementHref(engagementKey, kept),
  };
}

// Live refreshes bump `assessmentRefreshVersion` as often as every 2 s. Each
// engagement-wide read here keeps ONE request in flight per key through the
// shared coalescing runner (lib/coalesce): versions that arrive meanwhile fold
// into a single follow-up request once it settles, so a slow response is never
// discarded and re-requested indefinitely. Loaded data stays on screen while a
// refresh runs; a failed refresh keeps it and reports the error. A new key
// (engagement or finding) starts from empty, at once, or from `seed` when the
// caller already holds that key's data: a seeded key is not read again until
// the next version.
type CoalescedLoad<T> = { key: string | null; data: T; loaded: boolean; error: string | null };
type LoadChannel = { key: string; seen: number | null; run: ReturnType<typeof createCoalescedRunner> };

function useCoalescedLoad<T>(key: string | null, version: number, load: () => Promise<T>, empty: T, seed?: T | null): CoalescedLoad<T> {
  const [state, setState] = useState<CoalescedLoad<T>>({ key, data: empty, loaded: false, error: null });
  const loadRef = useRef(load);
  loadRef.current = load;
  const emptyRef = useRef(empty);
  emptyRef.current = empty;
  const seedRef = useRef(seed);
  seedRef.current = seed;
  const channelRef = useRef<LoadChannel | null>(null);
  const mountedRef = useRef(false);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);
  useEffect(() => {
    if (key === null) {
      channelRef.current = null;
      return;
    }
    let channel = channelRef.current;
    if (!channel || channel.key !== key) {
      const seeded = seedRef.current;
      // Each key has its own runner, so a new key never waits on the last one.
      const current: LoadChannel = {
        key,
        seen: seeded != null ? version : null,
        run: createCoalescedRunner(async () => {
          const live = () => mountedRef.current && channelRef.current === current;
          if (!live()) return;
          try {
            const data = await loadRef.current();
            if (live()) setState({ key: current.key, data, loaded: true, error: null });
          } catch (error) {
            if (!live()) return;
            const message = error instanceof Error ? error.message : String(error);
            setState((previous) => ({ key: current.key, data: previous.key === current.key ? previous.data : emptyRef.current, loaded: true, error: message }));
          }
        }),
      };
      channel = current;
      channelRef.current = channel;
      if (seeded != null) setState({ key, data: seeded, loaded: true, error: null });
    }
    // Already read for this version: React StrictMode re-running the effect,
    // or a seeded key.
    if (channel.seen === version) return;
    channel.seen = version;
    void channel.run("refresh");
  }, [key, version]);
  if (key === null) return { key, data: empty, loaded: true, error: null };
  if (state.key === key) return state;
  return seed != null ? { key, data: seed, loaded: true, error: null } : { key, data: empty, loaded: false, error: null };
}

const NO_FINDING_LINKS: AssessmentFindingLink[] = [];
const NO_FINDING_GROUPS: AssessmentFindingGroup[] = [];
const NO_TRANSITIONS: AssessmentFindingTransitionSummary[] = [];
import { useToast } from "../contexts/ToastContext";
import { findingToMarkdown } from "../lib/findingMarkdown";
import { FindingRemediation } from "./FindingRemediation";
import { RecordBody, RecordCopyButton, RecordCopyLinkButton, RecordHeader, RecordTabs, RecordView, useResultsScrollMemory } from "./record/RecordView";
import { listNavigation } from "./record/recordNavigation";

// ── Types & helpers ───────────────────────────────────────────────────

type FindingLike = AssessmentFinding | AssessmentFindingDetail;

type FindingsTabProps = {
  engagementKey: string;
  findings: FindingLike[];
  fallbackFindings: AssessmentFinding[];
  chains: AssessmentAttackChainDetail[];
  chainLinks: AssessmentAttackChainLink[];
  assessmentRefreshVersion: number;
  // Resolve routed findings against the loaded queue or an exact lookup.
  initialFindingSlug?: string;
  // Deep-link entry: which drawer tab (?dtab=…) to open the auto-opened
  // finding on. Validated against the finding's visible tabs; falls back to
  // "overview" when absent / invalid / hidden. Only applies to the deep-link
  // auto-open, not to later manual drawer navigation.
  initialDrawerTab?: string;
  ledgerLoading?: boolean;
  ledgerError?: string | null;
  // Optional "Runtime proof" section for a finding that still owes runtime
  // proof (pending_runtime_proof and not merged), rendered in the Claim &
  // evidence pane beside the outstanding-proof notice. The page owns proof
  // work; this tab only places it.
  renderRuntimeProof?: (finding: RuntimeProofSlotFinding) => React.ReactNode;
};

export type RuntimeProofSlotFinding = {
  engagementKey: string;
  slug: string;
  title: string;
  severity: string;
  workflow_status: string;
  verification_status: string;
  next_test?: ProofNextTest | null;
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_RANK: Record<string, number> = Object.fromEntries(
  SEVERITY_ORDER.map((s, i) => [s, i]),
);

const KNOWN_DETAIL_KEYS = new Set<string>([
  "discovered_by",
  "owasp_category",
  "cwe_id",
  "parameter",
  "request_method",
  "evidence",
  "kill_reason",
  "kill_check",
  "impact",
  "attack_scenario",
  "cvss_vector",
  "cvss_score",
  "remediation",
  "steps_to_reproduce",
  "chain_required",
  "chain_rationale",
  "required_followup",
  "block_reason",
  "unblock_requirements",
  "attempts_summary",
  "poc_code",
  "poc_language",
  "poc_request",
  "poc_response",
  "references",
  "related_intel_ids",
  "slot_type",
  "entry_point",
  "sink",
  "taint_path",
  "guards_evaluated",
  "variant_of",
  "original_pattern",
]);

function isDetail(finding: FindingLike): finding is AssessmentFindingDetail {
  return "id" in finding;
}

// List-row recency fields; summary fallback rows carry none.
function listRow(finding: FindingLike): Pick<AssessmentFindingDetail, "created_at" | "last_transition_at" | "last_transition_action" | "last_transition_actor"> {
  return isDetail(finding) ? finding : {};
}

// The API returns `details` / `provenance` already parsed, under the same names
// the writer used, so these are shape guards rather than parsers.
function parseDetails(finding: FindingLike): FindingDetails {
  if (!isDetail(finding)) return {};
  return asObject(finding.details) as FindingDetails;
}

function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function parseProvenance(
  value: FindingProvenance | undefined | null,
): FindingProvenance | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}

function hasFindingProvenance(provenance: FindingProvenance | null): boolean {
  return Boolean(
    provenance &&
    (provenance.agent_name || provenance.captured_at || provenance.artifact_ref || provenance.evidence_quote),
  );
}

function verificationKey(finding: FindingLike): string {
  return finding.verification_status;
}

// Status labels come from the shared vocabulary (components/ui/statusTones.ts),
// so chips, pills, the table and the palette name a status the same way.
function verificationLabel(finding: FindingLike): string {
  return statusLabel("finding-verification", verificationKey(finding));
}

function workflowLabel(finding: FindingLike): string {
  return statusLabel("finding-workflow", finding.workflow_status);
}

// External-program submission state is a separate axis from workflow_status.
function submissionLabel(finding: FindingLike): string {
  return statusLabel("finding-submission", finding.submission_status);
}

// A submission_status is worth surfacing only when it is set to something
// other than the "none" default — otherwise every never-submitted finding
// would carry a noisy pill. Tolerates older payloads where the field is
// absent (treated as none / not meaningful).
function hasSubmissionStatus(status: string | undefined | null): boolean {
  return !!status && status !== "none";
}

// Source binding of a code finding to the repository generation under review.
function SourceSnapshotPill({ status, size = "md" }: { status: string; size?: "sm" | "md" }) {
  return <StatusPill domain="finding-source-snapshot" value={status} size={size} />;
}

/** Workflow states outside the current findings (the summary's finding_count, the rail, Overview). */
export const RETIRED_WORKFLOWS: ReadonlySet<string> = new Set(["merged", "false_positive"]);

function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`;
}

/** Severity order (critical first); unknown severities sort last. */
export function compareSeverity(a: string, b: string): number {
  return (SEV_RANK[a] ?? 99) - (SEV_RANK[b] ?? 99);
}

function compareSeverityThenTitle(a: Derived, b: Derived): number {
  return compareSeverity(a.severity, b.severity) || a.title.localeCompare(b.title);
}

function extractHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function formatHttp(
  obj: FindingPocRequest | FindingPocResponse | string | undefined,
  kind: "req" | "resp",
): string {
  if (!obj) return "";
  if (typeof obj === "string") return obj;
  const lines: string[] = [];
  if (kind === "req") {
    const req = obj as FindingPocRequest;
    // Verbatim: a case-sensitive-routing probe records `get`/`GeT` on purpose,
    // and upper-casing it showed the operator a request their own finding did
    // not make. lib/findingMarkdown.ts's twin of this formatter has always kept
    // the recorded case (and a test pinning it), so the page was the lossy half.
    lines.push(`${req.method || "GET"} ${req.url || ""}`.trim());
  } else if (kind === "resp") {
    const resp = obj as FindingPocResponse;
    if (resp.status != null) lines.push(`HTTP ${resp.status}`);
  }
  const headers = (obj as FindingPocRequest | FindingPocResponse).headers;
  if (headers && typeof headers === "object") {
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
  } else if (typeof headers === "string" && headers.trim()) {
    lines.push(headers.trim());
  }
  const body = (obj as FindingPocRequest | FindingPocResponse).body;
  if (body) {
    lines.push("");
    lines.push(body);
  }
  return lines.join("\n");
}

function normalizeReference(
  ref: FindingReference,
): { label: string; href?: string } {
  if (typeof ref === "string") {
    const trimmed = ref.trim();
    if (/^https?:\/\//i.test(trimmed)) return { label: trimmed, href: trimmed };
    return { label: trimmed };
  }
  if (ref && typeof ref === "object") {
    const href = ref.url && /^https?:\/\//i.test(ref.url) ? ref.url : undefined;
    const label = ref.title || ref.url || ref.id || "";
    return { label, href };
  }
  return { label: String(ref) };
}

// ── Search tokenizer ──────────────────────────────────────────────────

const SCOPES = [
  "severity",
  "status",
  "workflow",
  "verification",
  "cwe",
  "owasp",
  "cve",
  "source",
  "agent",
  "auth",
  "method",
  "slug",
  "family",
  "chain",
  // The recorded location; `location:file:` keeps the source (code) findings.
  "location",
] as const;
type Scope = (typeof SCOPES)[number];

type ParsedQuery = {
  tokens: { scope: Scope; value: string }[];
  freeTerms: string[];
};

function parseQuery(q: string): ParsedQuery {
  const tokens: ParsedQuery["tokens"] = [];
  const freeTerms: string[] = [];
  const re = /(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q || "")) !== null) {
    const tok = m[1];
    const idx = tok.indexOf(":");
    if (idx > 0) {
      const scope = tok.slice(0, idx).toLowerCase();
      if ((SCOPES as readonly string[]).includes(scope)) {
        tokens.push({ scope: scope as Scope, value: tok.slice(idx + 1).toLowerCase() });
        continue;
      }
    }
    freeTerms.push(tok.toLowerCase());
  }
  return { tokens, freeTerms };
}

// ── Derived-finding shape (one-pass normalisation) ────────────────────

type DerivedLink = {
  link_kind: string;
  target_kind: "finding" | "chain" | "cve" | string;
  target_ref: string;
  notes?: string;
  id?: number;
};

export type Derived = {
  finding: FindingLike;
  slug: string;
  title: string;
  severity: string;
  workflow_status: string;
  submission_status: string;
  verification_status: string;
  verificationKey: string;
  verificationLabel: string;
  workflowLabel: string;
  submissionLabel: string;
  canonical_location: string;
  summary: string;
  source_name: string;
  updated_at: string;
  // When the finding was recorded, and its newest transition-ledger change
  // (falling back to creation; see lib/findingRecency.ts). Empty when the row
  // does not carry them (summary fallback rows).
  created_at: string;
  changed_at: string;
  last_transition_action?: string;
  last_transition_actor?: string;
  // details-derived
  cwe_id?: string;
  owasp_category?: string;
  cvss_vector?: string;
  cvss_score?: number;
  impact?: string;
  attack_scenario?: string;
  remediation?: string;
  evidence?: string;
  kill_reason?: string;
  kill_check?: number;
  steps_to_reproduce?: string[];
  parameter?: string;
  request_method?: string;
  discovered_by?: string;
  poc_code?: string;
  poc_language?: string;
  poc_request?: FindingPocRequest | string;
  poc_response?: FindingPocResponse | string;
  references: FindingReference[];
  related_intel_ids?: Array<string | number>;
  chain_required?: boolean;
  chain_rationale?: string;
  required_followup?: string[];
  block_reason?: string;
  unblock_requirements?: Record<string, unknown>;
  attempts_summary?: string;
  slot_type?: string;
  entry_point?: string;
  sink?: string;
  taint_path?: string[];
  guards_evaluated?: string | string[] | Record<string, unknown>;
  variant_of?: string;
  original_pattern?: string;
  // detail-only
  defect_family?: string;
  auth_context?: string;
  root_cause_key?: string;
  merged_into_slug?: string | null;
  notes?: string;
  evidence_ref?: string;
  code_snapshot_status?: "current" | "stale" | "unbound" | "not_applicable";
  verification_audit?: AssessmentVerificationAudit;
  // derived
  details: FindingDetails;
  provenance: FindingProvenance | null;
  links: DerivedLink[];
  root_cause_role?: "root" | "sibling";
  root_cause_slug?: string;
  root_cause_note?: string;
  root_cause_effect?: "eliminates_finding" | "eliminates_attack_path";
  sibling_order?: number | null;
  sibling_count?: number;
  residual_path_count?: number;
  searchCorpus: string;
};

type RootCauseMeta = {
  root_cause_slug: string;
  root_cause_note: string;
  root_cause_effect: "eliminates_finding" | "eliminates_attack_path";
  sibling_order: number | null;
};

function toStringArray(v: unknown): string[] | undefined {
  if (v == null) return undefined;
  if (Array.isArray(v)) return v.map((x) => (typeof x === "string" ? x : JSON.stringify(x)));
  if (typeof v === "string") return [v];
  return undefined;
}

function buildSearchCorpus(d: Omit<Derived, "searchCorpus">): string {
  const parts: (string | undefined | null)[] = [
    d.slug,
    d.title,
    d.summary,
    d.canonical_location,
    d.source_name,
    d.severity,
    d.workflow_status,
    d.verificationKey,
    d.verificationLabel,
    d.cwe_id,
    d.owasp_category,
    d.defect_family,
    d.auth_context,
    d.parameter,
    d.request_method,
    d.discovered_by,
    d.impact,
    d.attack_scenario,
    d.remediation,
    d.evidence,
    d.kill_reason,
    d.block_reason,
    d.attempts_summary,
    d.root_cause_key,
    d.root_cause_role,
    d.root_cause_slug,
    d.root_cause_effect,
    d.root_cause_note,
    d.code_snapshot_status,
    d.poc_code,
    d.entry_point,
    d.sink,
    (d.steps_to_reproduce || []).join(" "),
    (d.taint_path || []).join(" "),
    // The request and response as the record shows them. Stringifying an
    // absent capture put `""` in every corpus, so a quote matched everything.
    d.poc_request ? formatHttp(d.poc_request, "req") : "",
    d.poc_response ? formatHttp(d.poc_response, "resp") : "",
    d.links.map((l) => `${l.link_kind} ${l.target_kind}:${l.target_ref}`).join(" "),
    d.references
      .map((r) => (typeof r === "string" ? r : `${r.title || ""} ${r.url || ""}`))
      .join(" "),
    d.provenance?.agent_name,
  ];
  return parts.filter(Boolean).join(" \n ").toLowerCase();
}

// ── Highlight helper ──────────────────────────────────────────────────

function highlight(text: string | undefined, freeTerms: string[]): React.ReactNode {
  if (!text) return text ?? "";
  if (!freeTerms || !freeTerms.length) return text;
  const lower = text.toLowerCase();
  let bestIdx = -1;
  let bestLen = 0;
  for (const t of freeTerms) {
    const i = lower.indexOf(t);
    if (i >= 0 && (bestIdx < 0 || i < bestIdx)) {
      bestIdx = i;
      bestLen = t.length;
    }
  }
  if (bestIdx < 0) return text;
  return (
    <>
      {text.slice(0, bestIdx)}
      <mark className="hl">{text.slice(bestIdx, bestIdx + bestLen)}</mark>
      {text.slice(bestIdx + bestLen)}
    </>
  );
}

// ── Icons (inline SVG) ────────────────────────────────────────────────

const IconSearch = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    className="search-icon"
  >
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
const IconClose = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);
const IconExternal = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    width={11}
    height={11}
  >
    <path d="M14 4h6v6" />
    <path d="M10 14L21 3" />
    <path d="M19 14v6H4V4h6" />
  </svg>
);
// ── JsonTree value safety ─────────────────────────────────────────────

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
function toJsonValue(value: unknown): JsonValue {
  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean") return value as JsonValue;
  if (Array.isArray(value)) return value.map(toJsonValue);
  if (t === "object") {
    const out: { [key: string]: JsonValue } = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = toJsonValue(v);
    }
    return out;
  }
  return String(value);
}

// ── Chain link ↔ finding matcher ──────────────────────────────────────

function chainLinkFindingSlug(
  link: AssessmentAttackChainLink,
  detailIdToSlug: Map<number, string>,
): string | null {
  if (link.entity_kind !== "finding") return null;
  if (link.entity_ref) return link.entity_ref;
  if (link.entity_id != null) return detailIdToSlug.get(link.entity_id) ?? null;
  return null;
}

// ── Component ─────────────────────────────────────────────────────────

export function FindingsTab({
  engagementKey,
  findings,
  fallbackFindings,
  chains,
  chainLinks,
  assessmentRefreshVersion,
  initialFindingSlug,
  initialDrawerTab,
  ledgerLoading = false,
  ledgerError = null,
  renderRuntimeProof,
}: FindingsTabProps) {
  const [routeFinding, setRouteFinding] = useState<{ engagementKey: string; requestedSlug: string; finding: AssessmentFindingDetail } | null>(null);
  const resolvedInitialSlug = routeFinding?.engagementKey === engagementKey && routeFinding.requestedSlug === initialFindingSlug ? routeFinding.finding.slug : initialFindingSlug;
  const [routeLookupError, setRouteLookupError] = useState<string | null>(null);
  const [routeLookupLoading, setRouteLookupLoading] = useState(false);
  const [routeLookupAttempt, setRouteLookupAttempt] = useState(0);
  const allFindingsRaw = useMemo(() => {
    const listed = findings.length > 0 ? findings : fallbackFindings;
    if (routeFinding?.engagementKey === engagementKey && routeFinding.finding.slug === resolvedInitialSlug && !listed.some((item) => item.slug === resolvedInitialSlug)) return [...listed, routeFinding.finding];
    // A point read at the row's version is the same row plus its review
    // (verification audit), so it stands in for the ledger row.
    if (routeFinding?.engagementKey === engagementKey) return listed.map((item) => item.slug === routeFinding.finding.slug && (!isDetail(item) || routeFinding.finding.row_version >= item.row_version) ? routeFinding.finding : item);
    return listed;
  }, [findings, fallbackFindings, routeFinding, engagementKey, resolvedInitialSlug]);
  const findingLinksLoad = useCoalescedLoad(engagementKey, assessmentRefreshVersion, () => listAssessmentFindingLinks(engagementKey), NO_FINDING_LINKS);
  const findingGroupsLoad = useCoalescedLoad(engagementKey, assessmentRefreshVersion, () => listAssessmentFindingGroups(engagementKey), NO_FINDING_GROUPS);
  const allFindingLinks = findingLinksLoad.data;
  const findingLinksError = findingLinksLoad.error;
  const allFindingGroups = findingGroupsLoad.data;
  const findingGroupsError = findingGroupsLoad.error;

  const [routeFilters] = useState(() => readRouteFilters(engagementKey));
  const [queueContext] = useState(() => ({ ...readQueueContext(engagementKey), ...routeFilters?.filters }));
  useEffect(() => {
    if (routeFilters) writeWorkspaceHash(routeFilters.href, "replace");
  }, [routeFilters]);
  const [query, setQuery] = useState(queueContext.query);
  const [sevFilters, setSevFilters] = useState<Set<string>>(() => new Set(queueContext.severity));
  const [workflowFilters, setWorkflowFilters] = useState<Set<string>>(() => new Set(queueContext.workflow));
  const [verifFilters, setVerifFilters] = useState<Set<string>>(() => new Set(queueContext.verification));
  const [recencyFilter, setRecencyFilter] = useState<RecencyFilter | null>(queueContext.recency);
  const [sortByView, setSortByView] = useState<SortByView>(queueContext.sort);
  // A filtered link followed while the queue is already open.
  useEffect(() => {
    const apply = () => {
      const next = readRouteFilters(engagementKey);
      if (!next) return;
      setQuery(next.filters.query);
      setSevFilters(new Set(next.filters.severity));
      setWorkflowFilters(new Set(next.filters.workflow));
      setVerifFilters(new Set(next.filters.verification));
      setRecencyFilter(next.filters.recency);
      setGroupedPage(0);
      writeWorkspaceHash(next.href, "replace");
    };
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, [engagementKey]);
  const [cmdOpen, setCmdOpen] = useState(false);

  // Recency windows are relative to "now"; re-evaluate them each minute.
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 60_000);
    return () => window.clearInterval(timer);
  }, []);
  // The last-visit mark this page opened with (see lib/findingRecency.ts). It
  // is read once per engagement and held for the visit, so "since my last
  // visit" does not shift while the operator works through it.
  const [visit, setVisit] = useState(() => ({ engagementKey, mark: readLastVisit(engagementKey) }));
  const lastVisitMs = visit.engagementKey === engagementKey ? visit.mark : readLastVisit(engagementKey);
  useEffect(() => {
    setVisit((current) => current.engagementKey === engagementKey ? current : { engagementKey, mark: readLastVisit(engagementKey) });
  }, [engagementKey]);

  const [selected, setSelected] = useState<string | null>(() => {
    try {
      return window.localStorage.getItem(`findings.selected.${engagementKey}`);
    } catch {
      return null;
    }
  });
  // Grouped (default) vs flat table view. Persisted via the same
  // localStorage idiom as findings.selected below.
  const [view, setView] = useState<FindingsView>(() => readFindingsView());
  const [tableOrder, setTableOrder] = useState<string[] | null>(null);
  const reportTableOrder = useCallback((slugs: string[]) => {
    setTableOrder((previous) => previous?.length === slugs.length && previous.every((slug, index) => slug === slugs[index]) ? previous : slugs);
  }, []);
  const acceptFindingDetail = useCallback((finding: AssessmentFindingDetail) => { setRouteFinding({ engagementKey, requestedSlug: finding.slug, finding }); }, [engagementKey]);
  const [detailOpen, setDetailOpen] = useState(false);
  const [reviewSection, setReviewSection] = useState<TabId>(isDrawerTabId(initialDrawerTab) ? initialDrawerTab : "overview");
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const commandInvokerRef = useRef<HTMLElement | null>(null);
  const openCommandPalette = useCallback((invoker?: HTMLElement) => {
    if (cmdOpen) return;
    commandInvokerRef.current = invoker ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    setCmdOpen(true);
  }, [cmdOpen]);

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Persist selection
  useEffect(() => {
    try {
      if (selected) window.localStorage.setItem(`findings.selected.${engagementKey}`, selected);
      else window.localStorage.removeItem(`findings.selected.${engagementKey}`);
    } catch {
      // ignore
    }
  }, [selected, engagementKey]);

  // Persist chosen view (grouped | table).
  useEffect(() => {
    try {
      window.localStorage.setItem(FINDINGS_VIEW_KEY, view);
    } catch {
      // ignore
    }
  }, [view]);

  // Tracks which deep-linked slug we've already auto-opened (see the
  // auto-open effect placed after derivedBySlug is in scope, below).
  const consumedInitialSlugRef = useRef<string | null>(null);

  // Whether the routed finding is already among the loaded rows. A routed
  // finding the rows lack is looked up once per route: the workspace hands
  // over new arrays on every render while its ledger loads, and each one used
  // to re-read the same finding. A lookup still running when the ledger lands
  // completes; its point read is the record's detail.
  const routedSlugListed = Boolean(initialFindingSlug) && (findings.length > 0 ? findings : fallbackFindings).some((item) => item.slug === initialFindingSlug);
  const routedSlugListedRef = useRef(routedSlugListed);
  routedSlugListedRef.current = routedSlugListed;
  useEffect(() => {
    let active = true;
    setRouteLookupError(null);
    if (!initialFindingSlug || routedSlugListedRef.current) {
      setRouteLookupLoading(false);
      return;
    }
    setRouteLookupLoading(true);
    getAssessmentFinding(engagementKey, initialFindingSlug).then((finding) => {
      if (!active) return;
      setRouteFinding({ engagementKey, requestedSlug: initialFindingSlug, finding });
      const route = parseWorkspaceRoute(window.location.hash);
      if (finding.slug !== initialFindingSlug && route.kind === "engagement" && route.key === engagementKey && route.params.get("finding") === initialFindingSlug) {
        writeWorkspaceHash(engagementHref(engagementKey, { ...Object.fromEntries(route.params), finding: finding.slug }), "replace");
      }
    }).catch((error: unknown) => {
      if (active) setRouteLookupError(error instanceof Error ? error.message : "Finding lookup failed");
    }).finally(() => { if (active) setRouteLookupLoading(false); });
    return () => { active = false; };
  }, [engagementKey, initialFindingSlug, routeLookupAttempt]);

  // ── Derived findings (one pass) ──
  const detailIdToSlug = useMemo(() => {
    const map = new Map<number, string>();
    for (const f of allFindingsRaw) {
      if (isDetail(f)) map.set(f.id, f.slug);
    }
    return map;
  }, [allFindingsRaw]);

  const chainLinksByFindingSlug = useMemo(() => {
    const map = new Map<string, AssessmentAttackChainLink[]>();
    for (const link of chainLinks) {
      const slug = chainLinkFindingSlug(link, detailIdToSlug);
      if (!slug) continue;
      if (!map.has(slug)) map.set(slug, []);
      map.get(slug)!.push(link);
    }
    return map;
  }, [chainLinks, detailIdToSlug]);

  const findingLinksBySlug = useMemo(() => {
    const map = new Map<string, AssessmentFindingLink[]>();
    for (const link of allFindingLinks) {
      if (!map.has(link.finding_slug)) map.set(link.finding_slug, []);
      map.get(link.finding_slug)!.push(link);
    }
    return map;
  }, [allFindingLinks]);

  const rootCauseBySibling = useMemo(() => {
    const map = new Map<string, RootCauseMeta>();
    for (const group of allFindingGroups) {
      const rootSlug = group.root.slug;
      for (const sibling of group.siblings || []) {
        map.set(sibling.slug, {
          root_cause_slug: sibling.root_cause_slug || rootSlug,
          root_cause_note: sibling.root_cause_note || "",
          root_cause_effect: sibling.root_cause_effect || "eliminates_finding",
          sibling_order: sibling.sibling_order ?? null,
        });
      }
    }
    return map;
  }, [allFindingGroups]);

  const rootCauseMetricsByRoot = useMemo(() => {
    const map = new Map<string, { sibling_count: number; residual_path_count: number }>();
    for (const group of allFindingGroups) {
      map.set(group.root.slug, {
        sibling_count: group.sibling_count,
        residual_path_count: group.residual_path_count,
      });
    }
    return map;
  }, [allFindingGroups]);

  const derivedList = useMemo<Derived[]>(() => {
    return allFindingsRaw.map((f) => {
      const details = parseDetails(f);
      const provenance = isDetail(f) ? parseProvenance(f.provenance) : null;

      const findingLinks = findingLinksBySlug.get(f.slug) || [];
      const chainLinkSet = chainLinksByFindingSlug.get(f.slug) || [];
      const rootMeta = rootCauseBySibling.get(f.slug);
      const rootMetrics = rootCauseMetricsByRoot.get(f.slug);

      // Build derived links: prefer AssessmentFindingLink for finding/chain/cve.
      const links: DerivedLink[] = [];
      const seenChains = new Set<string>();
      for (const link of findingLinks) {
        links.push({
          link_kind: link.link_kind,
          target_kind: link.target_kind,
          target_ref: link.target_ref,
          notes: link.notes,
          id: link.id,
        });
        if (link.target_kind === "chain") seenChains.add(link.target_ref);
      }
      // Fallback: add chain links from chainLinks prop if not already present.
      for (const cl of chainLinkSet) {
        if (!seenChains.has(cl.chain_key)) {
          links.push({
            link_kind: cl.relation || "attack-chain",
            target_kind: "chain",
            target_ref: cl.chain_key,
          });
        }
      }

      const taintArr = toStringArray(details.taint_path);

      const base: Omit<Derived, "searchCorpus"> = {
        finding: f,
        slug: f.slug,
        title: f.title,
        severity: f.severity,
        workflow_status: f.workflow_status,
        submission_status: f.submission_status,
        verification_status: f.verification_status,
        verificationKey: verificationKey(f),
        verificationLabel: verificationLabel(f),
        workflowLabel: workflowLabel(f),
        submissionLabel: submissionLabel(f),
        canonical_location: f.canonical_location,
        summary: f.summary,
        source_name: f.source_name,
        updated_at: f.updated_at,
        created_at: listRow(f).created_at || "",
        changed_at: findingChangedAt(listRow(f)),
        last_transition_action: listRow(f).last_transition_action || undefined,
        last_transition_actor: listRow(f).last_transition_actor || undefined,
        cwe_id: details.cwe_id,
        owasp_category: details.owasp_category,
        cvss_vector: details.cvss_vector,
        cvss_score: typeof details.cvss_score === "number" ? details.cvss_score : undefined,
        impact: details.impact,
        attack_scenario: typeof details.attack_scenario === "string" ? details.attack_scenario : undefined,
        remediation: details.remediation,
        evidence: details.evidence,
        kill_reason: details.kill_reason,
        kill_check: typeof details.kill_check === "number" ? details.kill_check : undefined,
        // Coerce list-typed detail fields: agents occasionally record these as
        // a single string instead of an array (e.g. a numbered multi-step block).
        // Without coercion the search-corpus builder's `(x || []).join(...)` and
        // the Submission pane's `.map(...)` throw on a truthy non-array, which crashes
        // the entire derivedList useMemo and white-screens the Findings tab.
        steps_to_reproduce: toStringArray(details.steps_to_reproduce),
        parameter: details.parameter,
        request_method: details.request_method,
        discovered_by: details.discovered_by,
        poc_code: details.poc_code,
        poc_language: details.poc_language,
        poc_request: details.poc_request,
        poc_response: details.poc_response,
        references: details.references || [],
        related_intel_ids: Array.isArray(details.related_intel_ids)
          ? details.related_intel_ids.filter(
              (id): id is string | number => typeof id === "string" || typeof id === "number",
            )
          : undefined,
        chain_required: details.chain_required,
        chain_rationale: details.chain_rationale,
        required_followup: toStringArray(details.required_followup),
        block_reason: typeof details.block_reason === "string" ? details.block_reason : undefined,
        unblock_requirements: asObject(details.unblock_requirements),
        attempts_summary: typeof details.attempts_summary === "string" ? details.attempts_summary : undefined,
        slot_type: details.slot_type,
        entry_point: details.entry_point,
        sink: details.sink,
        taint_path: taintArr,
        guards_evaluated: details.guards_evaluated,
        variant_of: details.variant_of,
        original_pattern: details.original_pattern,
        defect_family: isDetail(f) ? f.defect_family : undefined,
        auth_context: isDetail(f) ? f.auth_context : undefined,
        root_cause_key: isDetail(f) ? f.root_cause_key : undefined,
        merged_into_slug: isDetail(f) ? f.merged_into_slug ?? null : undefined,
        notes: isDetail(f) ? f.notes : undefined,
        evidence_ref: isDetail(f) ? f.evidence_ref : undefined,
        code_snapshot_status: isDetail(f) ? f.code_snapshot_status : undefined,
        verification_audit: isDetail(f) ? f.verification_audit : undefined,
        details,
        provenance,
        links,
        root_cause_role: rootMeta ? "sibling" : rootMetrics ? "root" : undefined,
        root_cause_slug: rootMeta?.root_cause_slug,
        root_cause_note: rootMeta?.root_cause_note,
        root_cause_effect: rootMeta?.root_cause_effect,
        sibling_order: rootMeta?.sibling_order,
        sibling_count: rootMetrics?.sibling_count,
        residual_path_count: rootMetrics?.residual_path_count,
      };
      return { ...base, searchCorpus: buildSearchCorpus(base) };
    });
  }, [allFindingsRaw, findingLinksBySlug, chainLinksByFindingSlug, rootCauseBySibling, rootCauseMetricsByRoot]);

  const derivedBySlug = useMemo(() => {
    const m = new Map<string, Derived>();
    for (const d of derivedList) m.set(d.slug, d);
    return m;
  }, [derivedList]);

  const chainsByKey = useMemo(() => {
    const m = new Map<string, AssessmentAttackChainDetail>();
    for (const c of chains) m.set(c.chain_key, c);
    return m;
  }, [chains]);

  const chainMembersByKey = useMemo(() => {
    const m = new Map<string, Derived[]>();
    for (const d of derivedList) {
      for (const l of d.links) {
        if (l.target_kind === "chain") {
          if (!m.has(l.target_ref)) m.set(l.target_ref, []);
          m.get(l.target_ref)!.push(d);
        }
      }
    }
    return m;
  }, [derivedList]);

  // ── Filtering ──
  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (d: Derived, parsed: ParsedQuery): boolean => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "severity":
            if ((d.severity || "").toLowerCase() !== v) return false;
            break;
          case "status":
          case "workflow":
            if ((d.workflow_status || "").toLowerCase() !== v) return false;
            break;
          case "verification":
            if ((d.verificationKey || "").toLowerCase() !== v) return false;
            break;
          case "cwe":
            if (!(d.cwe_id || "").toLowerCase().includes(v)) return false;
            break;
          case "owasp":
            if (!(d.owasp_category || "").toLowerCase().includes(v)) return false;
            break;
          case "cve": {
            const refs = d.references
              .map((r) => (typeof r === "string" ? r : `${r.title || ""} ${r.url || ""}`))
              .join(" ");
            const linkCves = d.links
              .filter((l) => l.target_kind === "cve")
              .map((l) => l.target_ref)
              .join(" ");
            if (!(refs + " " + linkCves).toLowerCase().includes(v)) return false;
            break;
          }
          case "source":
            if (!(d.source_name || "").toLowerCase().includes(v)) return false;
            break;
          case "agent": {
            const hay =
              (d.discovered_by || "") + " " + (d.provenance?.agent_name || "");
            if (!hay.toLowerCase().includes(v)) return false;
            break;
          }
          case "auth":
            if (!(d.auth_context || "").toLowerCase().includes(v)) return false;
            break;
          case "method":
            if (!(d.request_method || "").toLowerCase().includes(v)) return false;
            break;
          case "slug":
            if (!(d.slug || "").toLowerCase().includes(v)) return false;
            break;
          case "family":
            if (!(d.defect_family || "").toLowerCase().includes(v)) return false;
            break;
          case "chain": {
            const hay = d.links
              .filter((l) => l.target_kind === "chain")
              .map((l) => l.target_ref)
              .join(" ");
            if (!hay.toLowerCase().includes(v)) return false;
            break;
          }
          case "location":
            if (!(d.canonical_location || "").toLowerCase().includes(v)) return false;
            break;
        }
      }
      if (parsed.freeTerms.length) {
        for (const t of parsed.freeTerms) if (!d.searchCorpus.includes(t)) return false;
      }
      return true;
    },
    [],
  );

  const sort = sortByView[view];
  // Date sorts flatten the grouped view into one date-ordered list.
  const flatDateList = view === "grouped" && sort !== "severity";
  const filtered = useMemo(() => {
    const list = derivedList.filter((d) => {
      if (sevFilters.size && !sevFilters.has(d.severity)) return false;
      if (workflowFilters.size && !workflowFilters.has(d.workflow_status)) return false;
      if (verifFilters.size && !verifFilters.has(d.verificationKey)) return false;
      if (!matchesRecency(d, recencyFilter, nowMs, lastVisitMs)) return false;
      if (!matchesQuery(d, parsedQuery)) return false;
      return true;
    });
    list.sort((a, b) => sort === "severity" ? compareSeverityThenTitle(a, b) : compareByRecency(a, b, sort));
    return list;
  }, [derivedList, sevFilters, workflowFilters, verifFilters, recencyFilter, nowMs, lastVisitMs, parsedQuery, matchesQuery, sort]);

  const filteredSlugs = useMemo(() => new Set(filtered.map((d) => d.slug)), [filtered]);
  const groupedFiltered = useMemo(() => {
    const groups = new Map<string, { root: Derived; siblings: Derived[]; highestSeverity: string }>();
    const standalone: Derived[] = [];

    function ensureGroup(rootSlug: string): { root: Derived; siblings: Derived[]; highestSeverity: string } | null {
      const root = derivedBySlug.get(rootSlug);
      if (!root) return null;
      if (!groups.has(rootSlug)) {
        groups.set(rootSlug, { root, siblings: [], highestSeverity: root.severity });
      }
      return groups.get(rootSlug)!;
    }

    for (const d of filtered) {
      if (d.root_cause_role === "sibling" && d.root_cause_slug) {
        const group = ensureGroup(d.root_cause_slug);
        if (group) {
          group.siblings.push(d);
          if ((SEV_RANK[d.severity] ?? 99) < (SEV_RANK[group.highestSeverity] ?? 99)) {
            group.highestSeverity = d.severity;
          }
          continue;
        }
      }
      if (d.root_cause_role === "root" && d.sibling_count) {
        ensureGroup(d.slug);
        continue;
      }
      standalone.push(d);
    }

    for (const group of groups.values()) {
      group.siblings = group.siblings
        .filter((sibling) => filteredSlugs.has(sibling.slug))
        .sort((a, b) => {
          const aOrder = a.sibling_order ?? 999999;
          const bOrder = b.sibling_order ?? 999999;
          if (aOrder !== bOrder) return aOrder - bOrder;
          const severityDelta = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
          if (severityDelta !== 0) return severityDelta;
          return a.title.localeCompare(b.title);
        });
    }

    const groupList = [...groups.values()]
      .filter((group) => group.siblings.length > 0 || filteredSlugs.has(group.root.slug))
      .sort((a, b) => {
        const severityDelta = (SEV_RANK[a.highestSeverity] ?? 99) - (SEV_RANK[b.highestSeverity] ?? 99);
        if (severityDelta !== 0) return severityDelta;
        return a.root.title.localeCompare(b.root.title);
      });
    return { groups: groupList, standalone };
  }, [filtered, filteredSlugs, derivedBySlug]);

  // ── Grouped-view pagination ──
  // Flatten the grouped render into the EXACT order it draws: every group (in
  // its sorted order) is one top-level entry, then every standalone finding (in
  // its sorted order) is one top-level entry. Each entry is one "page item".
  type GroupEntry = { kind: "group"; group: (typeof groupedFiltered.groups)[number] };
  type StandaloneEntry = { kind: "standalone"; finding: Derived };
  type DisplayEntry = GroupEntry | StandaloneEntry;
  const displayEntries = useMemo<DisplayEntry[]>(() => {
    // A date sort lists every finding on its own, in date order.
    if (flatDateList) return filtered.map((finding) => ({ kind: "standalone", finding }));
    const entries: DisplayEntry[] = [];
    for (const group of groupedFiltered.groups) entries.push({ kind: "group", group });
    for (const finding of groupedFiltered.standalone) entries.push({ kind: "standalone", finding });
    return entries;
  }, [flatDateList, filtered, groupedFiltered]);

  const pageCount = Math.max(1, Math.ceil(displayEntries.length / GROUPED_PAGE_SIZE));
  const [groupedPage, setGroupedPage] = useState(queueContext.page);

  // Clamp if the page count shrinks (e.g. WebSocket refresh drops entries)
  // without otherwise changing identity in a way that resets the page.
  const safePage = Math.min(groupedPage, pageCount - 1);
  useEffect(() => {
    try {
      window.sessionStorage.setItem(`findings.queue.${engagementKey}`, JSON.stringify({ query, severity: [...sevFilters], workflow: [...workflowFilters], verification: [...verifFilters], recency: recencyFilter, sort: sortByView, page: safePage }));
    } catch { /* Browser storage may be unavailable. */ }
  }, [engagementKey, query, sevFilters, workflowFilters, verifFilters, recencyFilter, sortByView, safePage]);

  // Window the entry list for the current page, then split the contiguous slice
  // back into { groups, standalone } so GroupedFindingsList renders unchanged.
  // Because groups always precede standalones in displayEntries, a contiguous
  // window holds trailing groups then leading standalones — no reordering.
  const pagedGrouped = useMemo(() => {
    const start = safePage * GROUPED_PAGE_SIZE;
    const slice = displayEntries.slice(start, start + GROUPED_PAGE_SIZE);
    const groups: typeof groupedFiltered.groups = [];
    const standalone: Derived[] = [];
    for (const entry of slice) {
      if (entry.kind === "group") groups.push(entry.group);
      else standalone.push(entry.finding);
    }
    return { groups, standalone };
  }, [displayEntries, safePage, groupedFiltered.groups]);

  // Windowed range for the "Showing a–b of N" label (1-based, inclusive).
  const pageRangeStart = displayEntries.length === 0 ? 0 : safePage * GROUPED_PAGE_SIZE + 1;
  const pageRangeEnd = Math.min((safePage + 1) * GROUPED_PAGE_SIZE, displayEntries.length);

  // Keep selection valid — if the persisted slug no longer exists in
  // the filtered set, fall through to the first row so j/k still has
  // an anchor. We no longer auto-select the first row on mount: the
  // modal opens only on an explicit user click / keypress.
  useEffect(() => {
    if (selected && !derivedBySlug.has(selected)) {
      setSelected(derivedList[0]?.slug ?? null);
      setDetailOpen(false);
    }
  }, [derivedList, derivedBySlug, selected]);

  const selectedDerived = selected ? derivedBySlug.get(selected) ?? null : null;

  // Incoming selection and section are authoritative for browser history.
  useEffect(() => {
    const routeIdentity = `${resolvedInitialSlug ?? ""}:${initialDrawerTab ?? "overview"}`;
    if (consumedInitialSlugRef.current === routeIdentity) return;
    if (!resolvedInitialSlug) {
      if (consumedInitialSlugRef.current !== null) setDetailOpen(false);
      consumedInitialSlugRef.current = routeIdentity;
      return;
    }
    const target = derivedBySlug.get(resolvedInitialSlug);
    if (!target) { consumedInitialSlugRef.current = null; setDetailOpen(false); return; }
    consumedInitialSlugRef.current = routeIdentity;
    setReviewSection(isDrawerTabId(initialDrawerTab) ? initialDrawerTab : "overview");
    setSelected(resolvedInitialSlug);
    setDetailOpen(true);
  }, [resolvedInitialSlug, initialDrawerTab, derivedBySlug]);

  // Transition history for the selected finding. Keyed by engagement AND
  // slug, so one finding's history is never shown under another's title.
  const transitionsLoad = useCoalescedLoad(
    selected ? JSON.stringify([engagementKey, selected]) : null,
    assessmentRefreshVersion,
    () => (selected ? listAssessmentFindingTransitions(engagementKey, selected) : Promise.resolve(NO_TRANSITIONS)),
    NO_TRANSITIONS,
  );

  const openFinding = useCallback((slug: string) => {
    if (!detailOpen) returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const target = derivedBySlug.get(slug);
    const section = target && drawerTabVisible(target, reviewSection) ? reviewSection : "overview";
    setReviewSection(section);
    setSelected(slug);
    setDetailOpen(true);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "findings", finding: slug, dtab: section === "overview" ? undefined : section }));
  }, [engagementKey, detailOpen, derivedBySlug, reviewSection]);
  const closeFinding = useCallback(() => {
    setDetailOpen(false);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "findings" }));
  }, [engagementKey]);
  const reviewFindings = useMemo(() => {
    if (view === "table") {
      const bySlug = new Map(filtered.map((item) => [item.slug, item]));
      if (tableOrder === null) return filtered;
      return tableOrder.flatMap((slug) => { const item = bySlug.get(slug); return item ? [item] : []; });
    }
    return displayEntries.flatMap((entry) => entry.kind === "standalone" ? [entry.finding] : [entry.group.root, ...entry.group.siblings]).filter((item) => filteredSlugs.has(item.slug));
  }, [view, filtered, filteredSlugs, displayEntries, tableOrder]);
  const reviewSlugs = useMemo(() => reviewFindings.map((item) => item.slug), [reviewFindings]);
  const reviewNavigation = listNavigation(reviewSlugs, selected, openFinding);
  const investigating = detailOpen && selectedDerived !== null;
  const resultsRef = useRef<HTMLDivElement | null>(null);
  // Back to results lands on the record last shown (after Previous / Next or
  // a deep link): the table scrolls its row into view, the grouped list turns
  // to the page that holds it.
  const gridRevealRef = useRef<((slug: string) => void) | null>(null);
  const displayEntriesRef = useRef(displayEntries);
  displayEntriesRef.current = displayEntries;
  const revealFinding = useCallback((slug: string) => {
    if (view === "table") {
      gridRevealRef.current?.(slug);
      return;
    }
    const index = displayEntriesRef.current.findIndex((entry) => entry.kind === "standalone"
      ? entry.finding.slug === slug
      : entry.group.root.slug === slug || entry.group.siblings.some((sibling) => sibling.slug === slug));
    if (index >= 0) setGroupedPage(Math.floor(index / GROUPED_PAGE_SIZE));
  }, [view]);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: investigating ? selected : null, reveal: revealFinding });

  // ── Keyboard ──
  const filteredRef = useRef(reviewFindings);
  filteredRef.current = reviewFindings;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const detailOpenRef = useRef(detailOpen);
  detailOpenRef.current = detailOpen;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target instanceof HTMLElement ? e.target : null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = Boolean(target?.closest("input, textarea, select, [contenteditable]:not([contenteditable='false'])"));
      const isInteractive = isTyping || Boolean(target?.closest("button, a, [role='button'], [role='combobox'], [role='listbox']"));
      const selectFinding = openFinding;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openCommandPalette();
        return;
      }
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        if (detailOpenRef.current) closeFinding();
        // After the results (and their scroll position) are back, bring the
        // search box into view: it is what the operator asked for.
        queueMicrotask(() => {
          searchRef.current?.focus({ preventScroll: true });
          searchRef.current?.scrollIntoView?.({ block: "center" });
        });
        return;
      }
      if (e.key === "Escape") {
        if (isTyping) {
          searchRef.current?.blur();
          return;
        }
        // The open record handles its own Escape (back to results).
        if (!detailOpenRef.current) setSelected(null);
        return;
      }
      if (!isInteractive && !detailOpenRef.current && (e.key === "[" || e.key === "]")) {
        e.preventDefault();
        const list = filteredRef.current;
        if (!list.length) return;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.slug === cur);
        if (idx < 0) {
          if (list[0]) selectFinding(list[0].slug);
          return;
        }
        const next =
          e.key === "[" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        selectFinding(list[next].slug);
      }
      if (!isInteractive && (e.key === "j" || e.key === "k")) {
        e.preventDefault();
        const list = filteredRef.current;
        if (!list.length) return;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.slug === cur);
        if (idx < 0 && list[0]) {
          selectFinding(list[0].slug);
          return;
        }
        const next =
          e.key === "k" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        selectFinding(list[next].slug);
      }
      if (!isTyping && tag !== "button" && tag !== "a" && e.key === "Enter" && selectedRef.current != null) {
        e.preventDefault();
        openFinding(selectedRef.current);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openFinding, closeFinding, openCommandPalette]);

  // ── Counters ──
  const severityCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) c[d.severity] = (c[d.severity] || 0) + 1;
    return c;
  }, [derivedList]);
  const workflowCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) c[d.workflow_status] = (c[d.workflow_status] || 0) + 1;
    return c;
  }, [derivedList]);
  const verifCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) c[d.verificationKey] = (c[d.verificationKey] || 0) + 1;
    return c;
  }, [derivedList]);
  const recencyCounts = useMemo(() => countRecency(derivedList, nowMs, lastVisitMs), [derivedList, nowMs, lastVisitMs]);
  // "Current" matches the rail badge and the assessment summary's
  // finding_count: everything except merged and false-positive findings.
  const currentCount = useMemo(() => derivedList.filter((d) => !RETIRED_WORKFLOWS.has(d.workflow_status)).length, [derivedList]);
  const recentChanges = useMemo(() => summarizeRecentChanges(derivedList, nowMs, lastVisitMs), [derivedList, nowMs, lastVisitMs]);

  // Record the last-visit mark once the loaded ledger has been on screen for
  // LAST_VISIT_DWELL_MS while the page is visible (lib/findingRecency.ts
  // defines the mark). The summary fallback is not the ledger and never
  // counts; hiding the browser tab restarts the dwell.
  const ledgerShown = findings.length > 0 && isDetail(findings[0]) && !ledgerLoading && !ledgerError;
  const ledgerRef = useRef(findings);
  ledgerRef.current = findings;
  const visitRecordedRef = useRef<string | null>(null);
  useEffect(() => {
    if (!ledgerShown || visitRecordedRef.current === engagementKey) return;
    let timer: number | undefined;
    const arm = () => {
      window.clearTimeout(timer);
      timer = undefined;
      if (document.visibilityState === "hidden") return;
      timer = window.setTimeout(() => {
        const mark = newestLedgerTime(ledgerRef.current.map((f) => ({ slug: f.slug, created_at: listRow(f).created_at, changed_at: findingChangedAt(listRow(f)) })));
        if (mark == null) return;
        writeLastVisit(engagementKey, mark);
        visitRecordedRef.current = engagementKey;
      }, LAST_VISIT_DWELL_MS);
    };
    arm();
    document.addEventListener("visibilitychange", arm);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", arm);
    };
  }, [ledgerShown, engagementKey]);

  const toggle = (
    set: Set<string>,
    setter: (s: Set<string>) => void,
    val: string,
  ) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
    setGroupedPage(0);
  };

  const changeQuery = (value: string) => {
    setQuery(value);
    setGroupedPage(0);
  };

  const clearAll = () => {
    setSevFilters(new Set());
    setWorkflowFilters(new Set());
    setVerifFilters(new Set());
    setRecencyFilter(null);
    setQuery("");
    setGroupedPage(0);
  };

  const chooseRecency = (filter: RecencyFilter | null) => {
    setRecencyFilter(filter);
    setGroupedPage(0);
  };
  // In the table a header click can sort by any column. The grid reports it
  // back: a named order updates the control; any other column order leaves the
  // control showing no named sort and the results line names that column.
  // (`tableSortRequest` lets re-choosing a named sort re-apply it to the grid.)
  const [tableCustomSort, setTableCustomSort] = useState(false);
  const [tableColumnSort, setTableColumnSort] = useState<TableColumnSort | null>(null);
  const [tableSortRequest, setTableSortRequest] = useState(0);
  const chooseSort = (next: FindingsSort) => {
    setSortByView((current) => current[view] === next ? current : { ...current, [view]: next });
    if (view === "table") {
      setTableCustomSort(false);
      setTableColumnSort(null);
      setTableSortRequest((value) => value + 1);
    }
    setGroupedPage(0);
  };
  const reportTableSort = useCallback((next: FindingsSort | null, column: TableColumnSort | null) => {
    setTableCustomSort(next === null);
    setTableColumnSort(next === null ? column : null);
    if (next) setSortByView((current) => current.table === next ? current : { ...current, table: next });
  }, []);
  const activeSort: FindingsSort | null = view === "table" && tableCustomSort ? null : sort;
  // After a recorded visit, narrow to what is unseen; on a first visit, put
  // the newest changes first without hiding anything.
  const reviewRecent = () => {
    chooseRecency(recentChanges.filter);
    chooseSort("changed");
  };

  const activeFilterCount =
    sevFilters.size + workflowFilters.size + verifFilters.size + (recencyFilter ? 1 : 0) + (query ? 1 : 0);

  const ledgerPending = derivedList.length === 0 && (ledgerLoading || Boolean(ledgerError));
  // Nothing recorded: the page explains that instead of showing empty filters.
  const ledgerEmpty = derivedList.length === 0 && !ledgerPending;
  // An unsorted grid shows the rows in the named order they arrive in.
  const orderDescription = view === "table"
    ? activeSort ? SORT_DESCRIPTIONS[activeSort] : tableColumnSort ? describeSort(tableColumnSort.label, tableColumnSort.direction, tableColumnSort.kind) : SORT_DESCRIPTIONS[sort]
    : sort === "severity" ? `${SORT_DESCRIPTIONS.severity}, root-cause groups first` : SORT_DESCRIPTIONS[sort];
  const workflowValues = [...new Set([...Object.keys(workflowCounts), ...workflowFilters])].sort((a, b) => compareStatus("finding-workflow", a, b));
  const verificationValues = [...new Set([...Object.keys(verifCounts), ...verifFilters])].sort((a, b) => compareStatus("finding-verification", a, b));
  const pageRange = flatDateList
    ? `findings ${pageRangeStart}–${pageRangeEnd} of ${displayEntries.length}`
    : `${pageRangeStart}–${pageRangeEnd} of ${displayEntries.length} entries (${plural(groupedFiltered.groups.length, "root-cause group")}, ${plural(groupedFiltered.standalone.length, "ungrouped finding")})`;
  const showPager = view === "grouped" && pageCount > 1 && filtered.length > 0;
  const turnPage = (page: number, fromEnd: boolean) => {
    setGroupedPage(Math.max(0, Math.min(pageCount - 1, page)));
    // From the pager under the list, start the next page at its top.
    if (fromEnd) resultsRef.current?.scrollIntoView?.({ block: "start" });
  };

  return (
    <div className="findings-redesign findings-workspace">
      <PageHeader
        title="Findings"
        purpose="Every security claim recorded for this engagement. Review what is new or changed, then open a finding to check its evidence."
        hidden={investigating}
        stats={ledgerPending || ledgerEmpty ? [] : [
          { value: currentCount, label: "current", title: "Findings that are not merged or false positive; the rail and Overview count these" },
          { value: derivedList.length, label: "recorded", title: "Every finding in the ledger, including merged and false-positive ones" },
        ]}
        status={ledgerLoading && derivedList.length > 0 ? "Updating…" : null}
        actions={ledgerPending || ledgerEmpty ? null : <SevSpark counts={severityCounts} />}
      />

      {routeLookupLoading && !routedSlugListed && <p className="meta-text" role="status">Loading finding {initialFindingSlug}…</p>}
      {routeLookupError && !routedSlugListed && <p className="error-text" role="alert">Finding {initialFindingSlug} unavailable: {routeLookupError} <button type="button" className="ghost-button" onClick={() => setRouteLookupAttempt((value) => value + 1)}>Retry finding lookup</button></p>}
      <SlowLoadHint active={ledgerLoading} what="the finding ledger" detail="Large ledgers can take several seconds." />
      {ledgerError && <p className="error-text" role="alert">Finding ledger unavailable: {ledgerError}{derivedList.length > 0 ? " Showing previously loaded records; this list may be stale." : ""}</p>}
      {!investigating && !ledgerPending && derivedList.length > 0 && (
        <section className="intel-workbar findings-recent-bar" aria-label="Recent finding changes">
          <div className="intel-workbar-title">
            <span className="sev-dot" />
            <span>Recent changes</span>
          </div>
          <span className="intel-workbar-stat">
            {recentChanges.created} new · {recentChanges.changed} changed {recentChanges.sinceVisit ? "since you last looked" : "in the last 24 hours"}
          </span>
          {lastVisitMs != null && (
            // The mark is the newest change on screen last time, not a clock time.
            <span className="intel-workbar-stat">
              last change you saw <TimeStamp value={new Date(lastVisitMs).toISOString()} />
            </span>
          )}
          {recentChanges.created + recentChanges.changed > 0 && (
            <button
              type="button"
              className="intel-workbar-review"
              aria-label={lastVisitMs != null ? "Review findings new or changed since your last visit" : "Review the most recently changed findings first"}
              onClick={reviewRecent}
            >
              Review first <span aria-hidden="true">›</span>
            </button>
          )}
        </section>
      )}
      <div className="panel findings-toolbar-panel" hidden={investigating || ledgerEmpty}>
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              aria-label="Search findings"
              placeholder="Search any field — title, CWE, slug, payload, endpoint… (try severity:high cwe:79)"
              value={query}
              onChange={(e) => changeQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => changeQuery("")}
                title="Clear"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
          <div className="toolbar-right">
            {/* The grouped root-cause list is the default; Table is the
                optional flat ag-grid view over the same filtered rows. */}
            <SegmentedControl<FindingsView>
              label="Findings view"
              value={view}
              onChange={setView}
              options={[
                { value: "grouped", label: <><List size={14} aria-hidden /> Grouped</> },
                { value: "table", label: <><Table2 size={14} aria-hidden /> Table</> },
              ]}
            />
            <button
              type="button"
              className="qa-btn"
              onClick={(event) => openCommandPalette(event.currentTarget)}
            >
              Jump to…{" "}
              <span className="search-kbd" style={{ marginLeft: 4 }}>
                ⌘K
              </span>
            </button>
          </div>
        </div>
        <div className="findings-order-row">
          <FilterGroup label="Recency">
            {RECENCY_FILTERS.map((filter) => {
              const unavailable = filter === "sinceVisit" && lastVisitMs == null;
              return (
                <FilterChip
                  key={filter}
                  label={RECENCY_LABELS[filter]}
                  count={recencyCounts[filter]}
                  selected={recencyFilter === filter}
                  disabled={unavailable && recencyFilter !== filter}
                  description={unavailable ? "No earlier visit to this engagement's findings is recorded in this browser." : RECENCY_HINTS[filter]}
                  onToggle={() => chooseRecency(recencyFilter === filter ? null : filter)}
                />
              );
            })}
          </FilterGroup>
          <div className="findings-sort">
            <span className="ui-filter-label" aria-hidden="true">Sort</span>
            <SegmentedControl<FindingsSort | "column">
              label="Sort findings"
              value={activeSort ?? "column"}
              onChange={(next) => { if (next !== "column") chooseSort(next); }}
              options={FINDINGS_SORTS.map((option) => ({ value: option, label: SORT_LABELS[option], description: SORT_HINTS[option] }))}
            />
          </div>
        </div>
        <div className="filter-row">
          <FilterGroup label="Severity">
            {SEVERITY_ORDER.filter((s) => severityCounts[s] || sevFilters.has(s)).map((s) => (
              <FilterChip
                key={s}
                label={severityLabel(s)}
                color={severityColor(s)}
                count={severityCounts[s] ?? 0}
                selected={sevFilters.has(s)}
                onToggle={() => toggle(sevFilters, setSevFilters, s)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Workflow">
            {workflowValues.map((s) => (
              <FilterChip
                key={s}
                label={statusLabel("finding-workflow", s)}
                status={{ domain: "finding-workflow", value: s }}
                count={workflowCounts[s] ?? 0}
                selected={workflowFilters.has(s)}
                onToggle={() => toggle(workflowFilters, setWorkflowFilters, s)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Verification">
            {verificationValues.map((s) => (
              <FilterChip
                key={s}
                label={statusLabel("finding-verification", s)}
                status={{ domain: "finding-verification", value: s }}
                count={verifCounts[s] ?? 0}
                selected={verifFilters.has(s)}
                onToggle={() => toggle(verifFilters, setVerifFilters, s)}
              />
            ))}
          </FilterGroup>
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
        </div>
      </div>

      <div ref={resultsRef} className="findings-shell" hidden={investigating}>
        <section className="list-panel panel" aria-label="Finding queue" hidden={investigating}>
          {ledgerPending && ledgerLoading && <TableSkeleton rows={8} columns={["4%", "52%", "16%", "12%"]} showHeader={false} />}
          {ledgerEmpty && (
            <EmptyState variant="empty" title="No findings recorded yet.">
              Findings appear here as agents record security claims for this engagement.
            </EmptyState>
          )}
          {!ledgerPending && !ledgerEmpty && <>
          <div className="grouping-status">
            <ResultsSummary shown={filtered.length} total={derivedList.length} noun={derivedList.length === 1 ? "finding" : "findings"} sort={orderDescription} />
            <div className="grouping-status-meta">
              {!findingGroupsLoad.loaded ? (
                <span className="tag">Loading groups</span>
              ) : findingGroupsError ? (
                <span className="tag warning">Grouping unavailable</span>
              ) : allFindingGroups.length > 0 ? (
                <span className="tag root">{plural(allFindingGroups.length, "engagement root-cause group")}</span>
              ) : (
                <span className="tag">No root-cause groups</span>
              )}
            </div>
          </div>
          {(findingGroupsError || findingLinksError) && (
            <div className="grouping-warning" role="status">
              {findingGroupsError && (
                <p>
                  Root-cause grouping could not be loaded. Findings are still shown, but root/sibling
                  grouping may be incomplete. Error: {findingGroupsError}
                </p>
              )}
              {findingLinksError && (
                <p>
                  Finding links could not be loaded. Findings are still shown, but relationship and CVE
                  links may be incomplete. Error: {findingLinksError}
                </p>
              )}
            </div>
          )}
          {showPager && <ResultPager position="top" page={safePage} pageCount={pageCount} range={pageRange} onPage={(page) => turnPage(page, false)} />}
          {filtered.length === 0 ? (
            <EmptyState variant="filtered" title="No findings match these filters." onClearFilters={clearAll}>
              {recencyFilter ? `${RECENCY_LABELS[recencyFilter]} shows findings ${RECENCY_HINTS[recencyFilter].toLowerCase()}.` : null}
            </EmptyState>
          ) : view === "table" ? (
            <Suspense fallback={<TableSkeleton rows={10} showHeader={false} />}>
              <FindingsGrid rows={filtered} selected={selected} onOpen={openFinding} onOrderChange={reportTableOrder} sort={sortByView.table} sortRequest={tableSortRequest} onSortChange={reportTableSort} revealRef={gridRevealRef} />
            </Suspense>
          ) : (
            <GroupedFindingsList
              groups={pagedGrouped.groups}
              standalone={pagedGrouped.standalone}
              selected={selected}
              onOpen={openFinding}
              freeTerms={parsedQuery.freeTerms}
              matchingSlugs={filteredSlugs}
              timeKind={sort === "newest" ? "created" : "changed"}
              flat={flatDateList}
              paged={pageCount > 1}
            />
          )}
          {showPager && <ResultPager position="bottom" page={safePage} pageCount={pageCount} range={pageRange} onPage={(page) => turnPage(page, true)} />}
          </>}
        </section>
      </div>
      {detailOpen && selectedDerived && (
        <RecordView
          label="Finding investigation"
          noun="finding"
          navigation={reviewNavigation}
          onBack={closeFinding}
          titleId="finding-investigation-title"
          returnFocusRef={returnFocusRef}
        >
          <Drawer
            key={selectedDerived.slug}
            engagementKey={engagementKey}
            refreshVersion={assessmentRefreshVersion}
            d={selectedDerived}
            derivedBySlug={derivedBySlug}
            chainsByKey={chainsByKey}
            chainMembersByKey={chainMembersByKey}
            transitions={transitionsLoad.data}
            transitionsLoading={!transitionsLoad.loaded}
            transitionsError={transitionsLoad.error}
            onSelect={(slug) => { if (slug) openFinding(slug); }}
            onSectionChange={setReviewSection}
            onDetailLoaded={acceptFindingDetail}
            detailLookupPending={routeLookupLoading && selectedDerived.slug === initialFindingSlug}
            renderRuntimeProof={renderRuntimeProof}
            initialTab={drawerTabVisible(selectedDerived, reviewSection) ? reviewSection : "overview"}
            titleId="finding-investigation-title"
          />
        </RecordView>
      )}

      {!ledgerEmpty && <div className="findings-shortcuts" hidden={investigating}>
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>⌘K</code> jump to finding
        </span>
        <span>
          <code>j / k</code> move
        </span>
        <span>
          <code>[ / ]</code> prev / next
        </span>
        <span>
          <code>Enter</code> open detail
        </span>
        <span>
          <code>Esc</code> close detail
        </span>
      </div>}

      {cmdOpen && (
        <CommandPalette
          derivedList={derivedList}
          returnFocusRef={commandInvokerRef}
          onSelect={(slug) => {
            setCmdOpen(false);
            openFinding(slug);
            if (!detailOpen) returnFocusRef.current = commandInvokerRef.current;
          }}
          onClose={() => setCmdOpen(false)}
        />
      )}
    </div>
  );
}

// One pager row; the grouped list shows it above and below its page.
function ResultPager({ position, page, pageCount, range, onPage }: { position: "top" | "bottom"; page: number; pageCount: number; range: string; onPage: (page: number) => void }) {
  return (
    <nav className={`pager pager-${position}`} aria-label={`Result pages (${position === "top" ? "above" : "below"} the list)`}>
      <button type="button" className="pager-button" disabled={page === 0} onClick={() => onPage(page - 1)}>
        Prev
      </button>
      <span className="meta-text">Page {page + 1} of {pageCount} · {range}</span>
      <button type="button" className="pager-button" disabled={page >= pageCount - 1} onClick={() => onPage(page + 1)}>
        Next
      </button>
    </nav>
  );
}

// ── SevSpark ──────────────────────────────────────────────────────────

// The ledger's severity mix: one named bar per severity, its count above it.
function SevSpark({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  const summary = SEVERITY_ORDER.map((s) => `${severityLabel(s)} ${counts[s] || 0}`).join(", ");
  return (
    <div className="findings-sev-mix" role="img" aria-label={`Severity mix: ${summary}`}>
      {SEVERITY_ORDER.map((s) => {
        const c = counts[s] || 0;
        const h = Math.max(4, (c / max) * 26);
        return (
          <div key={s} className="findings-sev-column" title={`${severityLabel(s)}: ${c}`}>
            <span className="findings-sev-count">{c}</span>
            <span className="findings-sev-bar" style={{ height: `${h}px`, background: severityColor(s), opacity: c ? 1 : 0.25 }} />
            <span className="findings-sev-name">{severityLabel(s)}</span>
          </div>
        );
      })}
    </div>
  );
}

type RowTimeKind = "created" | "changed";

function GroupedFindingsList({
  groups,
  standalone,
  selected,
  onOpen,
  freeTerms,
  matchingSlugs,
  timeKind,
  flat,
  paged,
}: {
  groups: { root: Derived; siblings: Derived[]; highestSeverity: string }[];
  standalone: Derived[];
  selected: string | null;
  onOpen: (slug: string) => void;
  freeTerms: string[];
  matchingSlugs: Set<string>;
  timeKind: RowTimeKind;
  // A date-sorted page: one list in date order, no root-cause cards.
  flat: boolean;
  paged: boolean;
}) {
  if (flat) {
    return (
      <div className="grouped-findings findings-flat-list">
        <section className="standalone-group">
          <div className="group-siblings">
            {standalone.map((d) => (
              <FindingMiniRow
                key={d.slug}
                d={d}
                selected={selected === d.slug}
                onOpen={() => onOpen(d.slug)}
                freeTerms={freeTerms}
                timeKind={timeKind}
                showRootCause
              />
            ))}
          </div>
        </section>
      </div>
    );
  }
  return (
    <div className="grouped-findings">
      {groups.map((group) => (
        <RootCauseGroupCard
          key={group.root.slug}
          group={group}
          selected={selected}
          onOpen={onOpen}
          freeTerms={freeTerms}
          rootContext={!matchingSlugs.has(group.root.slug)}
          timeKind={timeKind}
        />
      ))}
      {standalone.length > 0 && (
        <section className="standalone-group">
          <div className="group-card-head">
            <div>
              <p className="eyebrow">Standalone Findings</p>
              <h3>{plural(standalone.length, "ungrouped finding")}{paged ? " on this page" : ""}</h3>
            </div>
          </div>
          <div className="group-siblings">
            {standalone.map((d) => (
              <FindingMiniRow
                key={d.slug}
                d={d}
                selected={selected === d.slug}
                onOpen={() => onOpen(d.slug)}
                freeTerms={freeTerms}
                timeKind={timeKind}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

// Right-aligned row time: when the finding was recorded under the Newest
// sort, otherwise when it last changed. Absolute UTC is on hover.
function RowTime({ d, kind }: { d: Derived; kind: RowTimeKind }) {
  const value = kind === "created" ? d.created_at : d.changed_at;
  if (!value) return <span className="finding-row-time" aria-hidden="true" />;
  return (
    <span className="finding-row-time">
      <span className="finding-row-time-label">{kind === "created" ? "Created" : "Changed"}</span>
      <TimeStamp value={value} />
    </span>
  );
}

function RootCauseGroupCard({
  group,
  selected,
  onOpen,
  freeTerms,
  rootContext,
  timeKind,
}: {
  group: { root: Derived; siblings: Derived[]; highestSeverity: string };
  selected: string | null;
  onOpen: (slug: string) => void;
  freeTerms: string[];
  rootContext: boolean;
  timeKind: RowTimeKind;
}) {
  const residualCount = group.siblings.filter((d) => d.root_cause_effect === "eliminates_attack_path").length;
  // The card sorts by its most severe member; the badge is the root's own
  // severity, and a more severe sibling is named separately.
  const siblingOutranksRoot = compareSeverity(group.highestSeverity, group.root.severity) < 0;
  return (
    <section className="root-group-card">
      <div className="group-card-head">
        <div>
          <p className="eyebrow">Root Cause</p>
          {rootContext && <p className="meta-text">Root context outside current filters</p>}
          <button
            type="button"
            className={`group-root-title ${selected === group.root.slug ? "is-selected" : ""}`}
            data-record-key={group.root.slug}
            onClick={() => onOpen(group.root.slug)}
          >
            {highlight(group.root.title, freeTerms)}
          </button>
          <p className="meta-text">
            <code>{group.root.slug}</code> · {group.root.canonical_location || "No location recorded"}
          </p>
        </div>
        <div className="group-card-metrics">
          <SeverityTag severity={group.root.severity} title={`Root severity: ${severityLabel(group.root.severity)}`} />
          {siblingOutranksRoot && <span className="meta-text group-highest-severity">Highest in group: {severityLabel(group.highestSeverity)}</span>}
          {group.root.code_snapshot_status && group.root.code_snapshot_status !== "not_applicable" && (
            <SourceSnapshotPill status={group.root.code_snapshot_status} />
          )}
          <span className="tag root">{plural(group.siblings.length, "sibling")}</span>
          {residualCount > 0 && <span className="tag chain">{plural(residualCount, "residual path")}</span>}
          <RowTime d={group.root} kind={timeKind} />
        </div>
      </div>
      <div className="group-siblings">
        {group.siblings.map((d) => (
          <FindingMiniRow
            key={d.slug}
            d={d}
            selected={selected === d.slug}
            onOpen={() => onOpen(d.slug)}
            freeTerms={freeTerms}
            timeKind={timeKind}
          />
        ))}
      </div>
    </section>
  );
}

function FindingMiniRow({
  d,
  selected,
  onOpen,
  freeTerms,
  timeKind,
  showRootCause = false,
}: {
  d: Derived;
  selected: boolean;
  onOpen: () => void;
  freeTerms: string[];
  timeKind: RowTimeKind;
  // Flat date lists have no group cards, so each row names its root cause.
  showRootCause?: boolean;
}) {
  return (
    <button type="button" className={`mini-finding-row ${selected ? "is-selected" : ""}`} data-record-key={d.slug} onClick={onOpen}>
      <SeverityTag severity={d.severity} size="sm" />
      <span className="mini-main">
        <strong>{highlight(d.title, freeTerms)}</strong>
        <span className="meta-text">
          <code>{d.slug}</code>
          {d.canonical_location ? ` · ${d.canonical_location}` : ""}
        </span>
        {d.root_cause_note && <span className="meta-text">{d.root_cause_note}</span>}
      </span>
      <span className="mini-badges">
        {showRootCause && d.root_cause_role === "root" && (d.sibling_count ?? 0) > 0 && <span className="tag root">Root · {plural(d.sibling_count ?? 0, "sibling")}</span>}
        {showRootCause && d.root_cause_role === "sibling" && d.root_cause_slug && <span className="tag root">Sibling of {d.root_cause_slug}</span>}
        {d.root_cause_effect === "eliminates_attack_path" && <span className="tag chain">Residual path</span>}
        {d.code_snapshot_status && d.code_snapshot_status !== "not_applicable" && (
          <SourceSnapshotPill status={d.code_snapshot_status} size="sm" />
        )}
        <StatusPill domain="finding-workflow" value={d.workflow_status} size="sm" />
        {hasSubmissionStatus(d.submission_status) && (
          <StatusPill domain="finding-submission" value={d.submission_status} size="sm" title={`External submission: ${d.submissionLabel}`} />
        )}
      </span>
      <RowTime d={d} kind={timeKind} />
    </button>
  );
}

// ── Drawer ────────────────────────────────────────────────────────────

type DrawerProps = {
  engagementKey: string;
  refreshVersion: number;
  d: Derived;
  derivedBySlug: Map<string, Derived>;
  chainsByKey: Map<string, AssessmentAttackChainDetail>;
  chainMembersByKey: Map<string, Derived[]>;
  transitions: AssessmentFindingTransitionSummary[];
  transitionsLoading: boolean;
  transitionsError: string | null;
  onSelect: (slug: string | null) => void;
  onSectionChange: (tab: TabId) => void;
  onDetailLoaded: (finding: AssessmentFindingDetail) => void;
  // The route's own lookup of this finding is still running; its point read
  // becomes this record's detail, so the record does not read it again.
  detailLookupPending?: boolean;
  renderRuntimeProof?: (finding: RuntimeProofSlotFinding) => React.ReactNode;
  // The parent owns review-section context and validates conditional tabs.
  initialTab?: TabId;
  titleId: string;
};

type TabId = "overview" | "submission" | "work" | "relationships" | "code" | "history";

const DRAWER_TAB_IDS: readonly TabId[] = [
  "overview",
  "submission",
  "work",
  "relationships",
  "code",
  "history",
] as const;

function isDrawerTabId(value: string | undefined): value is TabId {
  return value != null && (DRAWER_TAB_IDS as readonly string[]).includes(value);
}

// Which drawer tabs are visible for a finding. Code is the only conditional
// workspace; the five core reading modes stay stable across findings. Used to
// validate a deep-linked ?dtab= so we
// only honor a tab that actually exists for the finding.
function drawerTabVisible(d: Derived, tab: TabId): boolean {
  switch (tab) {
    case "code":
      return !!(d.slot_type || d.entry_point || d.sink || d.provenance?.code_snapshot || d.canonical_location.startsWith("file:"));
    default:
      return true;
  }
}

// ProseMode + the prose primitives (CopyChip / SectionHead / Prose / KV /
// ProseModeToggle) now live in ./drawer/DrawerKit and are shared verbatim
// with the Intel + Surface drawers.

function Drawer({
  engagementKey,
  refreshVersion,
  d,
  derivedBySlug,
  chainsByKey,
  chainMembersByKey,
  transitions,
  transitionsLoading,
  transitionsError,
  onSelect,
  onSectionChange,
  onDetailLoaded,
  detailLookupPending = false,
  renderRuntimeProof,
  initialTab,
  titleId,
}: DrawerProps) {
  const { toast } = useToast();
  const deepLinkTab: TabId = initialTab ?? "overview";
  const [tab, setTabState] = useState<TabId>(deepLinkTab);
  const [proseMode, setProseMode] = useState<ProseMode>("rendered");
  // The finding's point read (verification audit, current receipts). It is
  // keyed by the claim's identity, not by the row object: the ledger hands
  // over new objects on every refresh, and each used to re-read the finding.
  // One read per open, one per live refresh, one when the claim changes; a
  // point read already in hand (a deep link) is not read again. A failed
  // refresh keeps the evidence loaded for the same claim.
  const reviewKey = JSON.stringify([engagementKey, d.slug, isDetail(d.finding) ? d.finding.row_version : null, d.verification_status]);
  const detailLoad = useCoalescedLoad<AssessmentFindingDetail | null>(
    detailLookupPending ? null : reviewKey,
    refreshVersion,
    () => getAssessmentFinding(engagementKey, d.slug).then((finding) => {
      if (finding.slug !== d.slug) throw new Error("Finding detail returned a different identity");
      return finding;
    }),
    null,
    d.verification_audit && isDetail(d.finding) ? d.finding : null,
  );
  const claimFinding = detailLoad.data;
  const detailRequestPending = detailLookupPending || !detailLoad.loaded;
  const verificationAuditUnavailable = detailLoad.error !== null;
  const reviewFinding = claimFinding && (!isDetail(d.finding) || (claimFinding.row_version === d.finding.row_version && claimFinding.verification_status === d.verification_status)) ? claimFinding : null;
  const currentAudit = reviewFinding ? reviewFinding.verification_audit : d.verification_audit;
  const reviewRequestPending = detailRequestPending || (claimFinding !== null && reviewFinding === null);
  // A newer or fuller read replaces the ledger row it came from.
  const onDetailLoadedRef = useRef(onDetailLoaded);
  onDetailLoadedRef.current = onDetailLoaded;
  useEffect(() => {
    if (claimFinding && claimFinding !== d.finding) onDetailLoadedRef.current(claimFinding);
    // Only a new read is news; the row it replaced changing identity is not.
  }, [claimFinding]);
  const setTab = (next: TabId) => {
    setTabState(next);
    onSectionChange(next);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "findings", finding: d.slug, dtab: next === "overview" ? undefined : next }));
  };
  useEffect(() => {
    setTabState(deepLinkTab);
  }, [deepLinkTab]);

  const owesRuntimeProof = d.verification_status === "pending_runtime_proof" && d.workflow_status !== "merged";
  const runtimeProof = owesRuntimeProof && renderRuntimeProof && isDetail(d.finding)
    ? renderRuntimeProof({
        engagementKey,
        slug: d.slug,
        title: d.title,
        severity: d.severity,
        workflow_status: d.workflow_status,
        verification_status: d.verification_status,
        next_test: (reviewFinding ?? d.finding).next_test,
      })
    : null;

  const linkedFindings = d.links.filter((l) => l.target_kind === "finding");
  const linkedChains = d.links
    .filter((l) => l.target_kind === "chain")
    .map((l) => chainsByKey.get(l.target_ref))
    .filter((c): c is AssessmentAttackChainDetail => Boolean(c));

  // Counts describe meaningful records, not every field rendered in a pane.
  const hasStepsForCount = (d.steps_to_reproduce ?? []).join("").trim().length > 0;
  const submissionCount =
    [d.poc_code, d.poc_request, d.poc_response, d.evidence].filter(Boolean)
      .length + (hasStepsForCount ? 1 : 0);
  const codeCount = drawerTabVisible(d, "code") ? 1 : 0;
  const relationshipsCount =
    linkedFindings.length +
    linkedChains.length +
    (d.references?.length ?? 0) +
    (d.related_intel_ids?.length ?? 0);
  const historyCount = transitions.length;

  const tabs: { id: TabId; label: string; count?: number; hidden?: boolean }[] = [
    { id: "overview", label: "Claim & evidence" },
    { id: "submission", label: "Submission", count: submissionCount || undefined },
    { id: "work", label: "Work" },
    { id: "relationships", label: "Relationships", count: relationshipsCount || undefined },
    { id: "code", label: "Code", count: codeCount, hidden: !codeCount },
    { id: "history", label: "History", count: transitionsLoading || transitionsError ? undefined : historyCount },
  ];

  return (
    <>
      <RecordHeader
        id={d.slug}
        copyId={d.slug}
        copyIdLabel="Copy slug"
        title={d.title}
        titleId={titleId}
        accent={`var(--sev-${d.severity})`}
        actions={
          <>
            <RecordCopyButton
              label="Copy submission as Markdown"
              text={() => findingToMarkdown(d)}
              successMessage="Copied submission as Markdown"
              failureMessage="Could not copy submission. Use the submission fields to copy manually."
              disabled={!isDetail(d.finding)}
            />
            <RecordCopyLinkButton noun="finding" />
            {/* Merged and false-positive findings are not submission candidates. */}
            {!RETIRED_WORKFLOWS.has(d.workflow_status) && (
              <a className="finding-record-action" href={engagementHref(engagementKey, { tab: "submissions", submission: d.slug })}>Open in Submissions</a>
            )}
          </>
        }
        pills={
          <>
            <SeverityTag severity={d.severity} />
            {d.cvss_score != null && (
              <span className="cvss-chip">
                CVSS <span className="cvss-num">{d.cvss_score.toFixed(1)}</span>
              </span>
            )}
            <StatusPill domain="finding-workflow" value={d.workflow_status} />
            <StatusPill domain="finding-verification" value={d.verificationKey} />
            {!reviewRequestPending && <span className="finding-evidence-mode">{reviewFinding?.evidence_type?.replace(/-/g, " ") || "Evidence mode unrecorded"}</span>}
            {d.code_snapshot_status && d.code_snapshot_status !== "not_applicable" && (
              <SourceSnapshotPill status={d.code_snapshot_status} />
            )}
            {hasSubmissionStatus(d.submission_status) && (
              <StatusPill domain="finding-submission" value={d.submission_status} title={`External submission: ${d.submissionLabel}`} />
            )}
            {d.cwe_id && <span className="tag cwe">{d.cwe_id}</span>}
          </>
        }
        datesLabel="Finding dates"
        dates={[
          { label: "Created", value: d.created_at },
          {
            label: "Last changed",
            value: d.changed_at,
            detail: d.last_transition_action
              ? <> · {d.last_transition_action.replace(/_/g, " ")}{d.last_transition_actor ? ` by ${d.last_transition_actor}` : ""}</>
              : undefined,
          },
        ]}
      >
        {verificationAuditUnavailable && !reviewRequestPending && (
          <div className="submission-blockers" role="status">{reviewFinding && (reviewFinding.proof_receipts !== undefined || currentAudit !== undefined) ? "Claim review refresh unavailable; showing previously loaded evidence for this unchanged claim." : "Claim review status unavailable"}</div>
        )}
        {currentAudit?.claim_review_pending && (
          <div className="submission-blockers" role="status" aria-label="Claim review pending">
            <strong>Claim review pending</strong>
            <span>Independent review is required for this claim.</span>
            <details className="detail-disclosure"><summary>Claim review details</summary>
              <p>Independent review required for claim transition {currentAudit.claim_transition_id ?? "unknown"}.</p>
              {currentAudit.current_claim_sha256 && <code>Current claim SHA-256: {currentAudit.current_claim_sha256}</code>}
            </details>
          </div>
        )}
      </RecordHeader>
      <FindingRemediation key={d.slug} engagementKey={engagementKey} findingSlug={d.slug} refreshVersion={refreshVersion} />
      <RecordTabs
        tabs={tabs}
        active={tab}
        onChange={setTab}
        label="Finding sections"
        trailing={
          // One record-wide prose view mode (Eye = rendered markdown, Code =
          // raw mono <pre>), shown on the tabs that render prose.
          (tab === "overview" || tab === "submission" || tab === "work" || tab === "relationships") && (
            <>
              <span className="prose-mode-label">View</span>
              <ProseModeToggle mode={proseMode} onChange={setProseMode} />
            </>
          )
        }
      />
      <RecordBody>
        {detailRequestPending && !isDetail(d.finding) && <p role="status">Loading finding detail…</p>}
        {!detailRequestPending && !isDetail(d.finding) && verificationAuditUnavailable && <p role="status">Finding detail unavailable. The ledger summary remains visible; reopen this finding to retry.</p>}
        {tab === "overview" && isDetail(d.finding) && <OverviewPane engagementKey={engagementKey} d={d} receipts={reviewFinding?.proof_receipts} receiptsLoading={reviewRequestPending} proseMode={proseMode} toast={toast} runtimeProof={runtimeProof} />}
        {tab === "submission" && isDetail(d.finding) && <SubmissionPane d={d} proseMode={proseMode} toast={toast} />}
        {tab === "work" && isDetail(d.finding) && <WorkPane d={d} proseMode={proseMode} toast={toast} />}
        {tab === "code" && isDetail(d.finding) && <CodePane d={d} toast={toast} />}
        {tab === "relationships" && isDetail(d.finding) && (
          <RelationshipsPane
            engagementKey={engagementKey}
            d={d}
            derivedBySlug={derivedBySlug}
            linkedFindings={linkedFindings}
            linkedChains={linkedChains}
            chainMembersByKey={chainMembersByKey}
            onSelect={(slug) => onSelect(slug)}
            toast={toast}
            proseMode={proseMode}
          />
        )}
        {tab === "history" && (
          <HistoryPane
            engagementKey={engagementKey}
            findingSlug={d.slug}
            transitions={transitions}
            loading={transitionsLoading}
            error={transitionsError}
          />
        )}
      </RecordBody>
    </>
  );
}

// ── Panes ─────────────────────────────────────────────────────────────
//
// CopyChip / SectionHead / Prose / KV + the ToastFn / ProseMode types are
// imported from ./drawer/DrawerKit (shared with the Intel + Surface drawers).

function previewWords(text: string, limit: number): { text: string; truncated: boolean } {
  const words = text.trim().split(/\s+/).filter(Boolean);
  if (words.length <= limit) return { text: text.trim(), truncated: false };
  return { text: `${words.slice(0, limit).join(" ")}…`, truncated: true };
}

function OverviewPane({ engagementKey, d, receipts, receiptsLoading, proseMode, toast, runtimeProof }: { engagementKey: string; d: Derived; receipts?: AssessmentProofReceipt[]; receiptsLoading: boolean; proseMode: ProseMode; toast: ToastFn; runtimeProof?: React.ReactNode }) {
  const followupCount = d.required_followup?.length ?? 0;
  const runtimeLocation = d.canonical_location && !d.canonical_location.startsWith("file:") ? d.canonical_location : "";
  const hasSource = Boolean(d.entry_point || d.sink || d.provenance?.code_snapshot || d.canonical_location.startsWith("file:"));
  const request = d.poc_request ? formatHttp(d.poc_request, "req") : "";
  const response = d.poc_response ? formatHttp(d.poc_response, "resp") : "";
  return (
    <>
      {/* What the claim still needs comes first: the proof work that would
          settle it, ahead of the claim and impact prose. */}
      {d.verification_status === "pending_runtime_proof" && d.workflow_status !== "merged" && (
        <p className="finding-proof-gap" role="status">Runtime proof outstanding</p>
      )}
      {runtimeProof && <section className="finding-runtime-proof" aria-label="Runtime proof">{runtimeProof}</section>}
      {d.summary && (
        <div className="section">
          <SectionHead title="Security claim" copyText={d.summary} toast={toast} />
          <Prose text={d.summary} mode={proseMode} />
        </div>
      )}
      {d.impact && <section className="section"><div className="section-head-row"><h3 className="section-title">Impact</h3><CopyChip text={d.impact} toast={toast} label="Copy impact" /></div><Prose text={d.impact} mode={proseMode} /></section>}
      <div className="finding-evidence-contributions">
        <section className="finding-contribution">
          <h3>Runtime observation</h3>
          {runtimeLocation || request || response ? (
            <>
              <KV k="Recorded location" v={runtimeLocation} mono toast={toast} />
              <KV k="Auth context" v={d.auth_context} />
              <KV k="Method" v={d.request_method} />
              <KV k="Parameter" v={d.parameter} mono />
              {request && <details className="detail-disclosure" open><summary>Recorded request</summary><CodeBlock text={request} onCopied={() => toast("Copied", "success")} /></details>}
              {response && <details className="detail-disclosure"><summary>Recorded response</summary><CodeBlock text={response} onCopied={() => toast("Copied", "success")} /></details>}
            </>
          ) : <p className="finding-gap">No runtime observation recorded.</p>}
        </section>
        <section className="finding-contribution">
          <h3>Source & root cause</h3>
          {hasSource ? (
            <>
              {d.canonical_location.startsWith("file:") && <KV k="Source location" v={d.canonical_location} mono toast={toast} />}
              <KV k="Entry point" v={d.entry_point} mono toast={toast} />
              <KV k="Sink" v={d.sink} mono toast={toast} />
              <KV k="Snapshot state" v={d.code_snapshot_status || "Unrecorded"} />
              {d.taint_path?.length ? <details className="detail-disclosure"><summary>Recorded source path</summary><TaintFlow steps={d.taint_path} /></details> : <p className="finding-gap">No source path recorded.</p>}
              <a className="finding-relation-link" href={engagementHref(engagementKey, { tab: "code" })}>Open code workspace ↗</a>
            </>
          ) : <p className="finding-gap">No source contribution recorded.</p>}
          <KV k="Defect family" v={d.defect_family} />
        </section>
      </div>
      <section className="section finding-current-proof">
        <h3>Current verification evidence</h3>
        <p className="section-hint">Receipts supporting the current {d.verificationLabel.toLowerCase()} state. Earlier decisions remain in History.</p>
        {receiptsLoading && receipts === undefined ? <p className="finding-gap" role="status">Loading current proof receipts…</p> : receipts === undefined ? <p className="finding-gap">Current proof receipts unavailable.</p> : receipts.length === 0 ? <p className="finding-gap">No proof receipts support the current verification state.</p> : (
          <ul className="finding-receipts">
            {receipts.map((receipt) => (
              <li key={receipt.id}>
                <a className="finding-receipt-link" href={engagementHref(engagementKey, { tab: "runs", run: receipt.run_id, section: "proof-receipts", object: receipt.id })}>
                  <strong>Receipt #{receipt.id}</strong>
                  <span>{receipt.evidence_kind.replace(/_/g, " ")}</span>
                  <StatusPill domain="receipt-health" value={receipt.evidence_health} size="sm" />
                  <span>Run #{receipt.run_id} ↗</span>
                </a>
                <details className="finding-receipt-record"><summary>Exact receipt record</summary><JsonView value={receipt} /></details>
              </li>
            ))}
          </ul>
        )}
      </section>
      {d.evidence && <details className="detail-disclosure"><summary>Recorded evidence</summary><SectionHead title="Evidence" copyText={d.evidence} toast={toast} /><pre className="pre resp">{d.evidence}</pre></details>}
      {(d.block_reason || followupCount > 0 || d.root_cause_role) && (
        <div className="overview-attention" aria-label="Current attention">
          <p className="section-title">Current attention</p>
          <div className="attention-items">
            {d.block_reason && <StatusPill value="blocked" tone="danger" label="Blocked" title="A blocker is recorded; see Work" />}
            {followupCount > 0 && (
              <StatusPill value="follow-up" tone="warning" label={plural(followupCount, "follow-up")} title="Required follow-up is recorded; see Work" />
            )}
            {d.root_cause_role === "root" && (
              <StatusPill value="root" tone="neutral" label={`Root · ${plural(d.sibling_count ?? 0, "sibling")}`} />
            )}
            {d.root_cause_role === "sibling" && (
              <StatusPill value="sibling" tone="neutral" label={`Linked to ${d.root_cause_slug}`} />
            )}
          </div>
        </div>
      )}
      <details className="detail-disclosure">
        <summary>Advanced metadata</summary>
        <div className="kv-grid">
          <KV k="Discovered by" v={d.discovered_by} mono />
          {/* updated_at moves on every re-record, so it is not "changed". */}
          <KVTime k="Last re-recorded" v={d.updated_at} />
          <KV k="Deduplication key" v={d.root_cause_key} mono />
          <KV k="Merged into" v={d.merged_into_slug ?? undefined} mono />
          <KV k="Evidence ref" v={d.evidence_ref} mono />
          <KV k="Source binding" v={d.code_snapshot_status} />
          <KV k="Source repo" v={d.provenance?.code_snapshot?.repo_id} mono />
          <KV k="Source generation" v={d.provenance?.code_snapshot?.repo_generation} mono />
          <KV k="Source manifest" v={d.provenance?.code_snapshot?.source_manifest_digest} mono toast={toast} />
          <KV k="CVSS vector" v={d.cvss_vector} mono />
        </div>
      </details>
    </>
  );
}

function WorkPane({ d, proseMode, toast }: { d: Derived; proseMode: ProseMode; toast: ToastFn }) {
  const additionalDetailKeys = Object.keys(d.details).filter((key) => !KNOWN_DETAIL_KEYS.has(key));
  const unblockRequirements = d.unblock_requirements && Object.keys(d.unblock_requirements).length
    ? d.unblock_requirements
    : null;
  const hasWork = Boolean(
    d.required_followup?.length || d.block_reason || unblockRequirements || d.attempts_summary ||
    d.notes || d.chain_rationale || d.kill_reason || additionalDetailKeys.length,
  );
  return (
    <>
      {d.required_followup && d.required_followup.length > 0 && (
        <div className="section">
          <SectionHead title="Required follow-up" copyText={d.required_followup.join("\n")} toast={toast} />
          <ul className="steps">
            {d.required_followup.map((step, i) => <li key={i}>{step}</li>)}
          </ul>
        </div>
      )}
      {d.block_reason && (
        <div className="callout kill">
          <SectionHead title="Blocker" copyText={d.block_reason} toast={toast} />
          <Prose text={d.block_reason} mode={proseMode} />
        </div>
      )}
      {unblockRequirements && (
        <div className="section">
          <p className="section-title">Unblock requirements</p>
          <div className="kv-grid">
            {Object.entries(unblockRequirements).map(([key, value]) => (
              <KV key={key} k={key.replace(/_/g, " ")} v={String(value)} />
            ))}
          </div>
        </div>
      )}
      {d.attempts_summary && (
        <div className="section">
          <SectionHead title="Attempts summary" copyText={d.attempts_summary} toast={toast} />
          <Prose text={d.attempts_summary} mode={proseMode} />
        </div>
      )}
      {(d.chain_required !== undefined || d.chain_rationale) && (
        <div className="section">
          <p className="section-title">Chain context</p>
          {d.chain_required !== undefined && (
            <p><StatusPill value={d.chain_required ? "chain-required" : "standalone"} tone={d.chain_required ? "warning" : "neutral"} label={d.chain_required ? "Chain required" : "Standalone"} /></p>
          )}
          {d.chain_rationale && <Prose text={d.chain_rationale} mode={proseMode} />}
        </div>
      )}
      {d.notes && (
        <div className="section">
          <SectionHead title="Operational replay log" copyText={d.notes} toast={toast} />
          <Prose text={d.notes} mode={proseMode} />
        </div>
      )}
      {d.kill_reason && (
        <div className="callout kill">
          <p className="section-title">Kill reason · check {d.kill_check ?? "?"}</p>
          <Prose text={d.kill_reason} mode={proseMode} />
        </div>
      )}
      {additionalDetailKeys.length > 0 && (
        <details className="detail-disclosure">
          <summary>Additional working details</summary>
          <div className="json-children">
            {additionalDetailKeys.map((key) => (
              <JsonTree key={key} label={key} value={toJsonValue(d.details[key])} defaultOpen />
            ))}
          </div>
        </details>
      )}
      {!hasWork && <p className="empty">No open work recorded for this finding.</p>}
    </>
  );
}

// Exported for focused tests: this pane owns the canonical submission order and
// renders authored narrative as Markdown and supporting captures byte-for-byte.
export function SubmissionPane({
  d,
  proseMode,
  toast,
}: { d: Derived; proseMode: ProseMode; toast: ToastFn }) {
  // A single authored block arrives as one element; a list arrives as several.
  // Joining on a newline reproduces either shape as written, so what is copied
  // out of here is byte-identical to what the finding holds.
  const stepsText = (d.steps_to_reproduce ?? []).join("\n").trim();
  const hasSteps = stepsText.length > 0;
  const hasCaptures = Boolean(d.poc_code || d.poc_request || d.poc_response);
  const pocCodeIsCurl = isCurlLike(d.poc_code);
  const reqText = d.poc_request ? formatHttp(d.poc_request, "req") : "";
  const respText = d.poc_response ? formatHttp(d.poc_response, "resp") : "";

  // Evidence is authored Markdown. Raw HTTP and whitespace-sensitive legacy
  // captures still use <pre>; new raw request/response bytes belong in the
  // supporting-capture fields below. The copy chip always returns the stored
  // bytes unchanged.
  const ev = d.evidence || "";
  // Pick a render mode for evidence: raw HTTP exchanges get the mono
  // .pre treatment; authored narrative uses the shared Markdown renderer. The probe is
  // trimmed because LAYOUT is all it decides — a capture that opens with a
  // blank line is still an HTTP exchange — but nothing rendered or copied is.
  const evProbe = ev.trim();
  const looksLikeHttp =
    /^HTTP\/\d\.\d\b/i.test(evProbe) ||
    /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d/i.test(evProbe);
  const preservesBoundaryWhitespace = ev !== evProbe;
  // A capture that is nothing but whitespace takes the <pre> too: it is the
  // only renderer here that shows the bytes rather than swallowing them.
  const evidenceMode: "http" | "prose" = looksLikeHttp || evProbe.length === 0 || preservesBoundaryWhitespace
    ? "http"
    : "prose";

  return (
    <>
      {d.summary && (
        <div className="section">
          <SectionHead title="Summary" copyText={d.summary} toast={toast} />
          <Prose text={d.summary} mode={proseMode} />
        </div>
      )}
      {hasSteps && (
        <div className="section">
          <SectionHead title="Steps to reproduce" copyText={stepsText} toast={toast} />
          <Prose text={stepsText} mode={proseMode} />
        </div>
      )}
      {(ev || hasCaptures) && (
        // Evidence ("how we know") gets a callout so it reads as distinct
        // from Steps-to-reproduce ("how to reproduce"), which keep .section.
        <div className="callout evidence">
          <SectionHead title="Evidence" copyText={ev} toast={toast} />
          {ev && (evidenceMode === "http" || proseMode === "raw" ? (
              <pre className="pre resp">{ev}</pre>
            ) : (
              <Prose text={ev} mode={proseMode} />
            ))}
          {hasCaptures && (
            <details className="detail-disclosure supporting-captures">
              <summary>Supporting captures</summary>
              <div className="supporting-captures-body">
                {d.poc_code && (
                  <div className="section">
                    <p className="section-title">
                      Payload
                      {d.poc_language && <span className="count">{d.poc_language}</span>}
                      {pocCodeIsCurl && <span className="count">curl</span>}
                    </p>
                    <CodeBlock text={d.poc_code} onCopied={() => toast("Copied", "success")} />
                  </div>
                )}
                {reqText && (
                  <div className="section">
                    <SectionHead title="Request" copyText={reqText} toast={toast} />
                    <pre className="pre req">{reqText}</pre>
                  </div>
                )}
                {respText && (
                  <div className="section">
                    <SectionHead title="Response" copyText={respText} toast={toast} />
                    <pre className="pre resp">{respText}</pre>
                  </div>
                )}
              </div>
            </details>
          )}
        </div>
      )}
      {d.attack_scenario && (
        <div className="section">
          <SectionHead title="Attack scenario" copyText={d.attack_scenario} toast={toast} />
          <Prose text={d.attack_scenario} mode={proseMode} />
        </div>
      )}
      {d.impact && (
        <div className="callout impact">
          <SectionHead title="Impact" copyText={d.impact} toast={toast} />
          <Prose text={d.impact} mode={proseMode} />
        </div>
      )}
      {d.remediation && (
        <div className="callout remediation">
          <SectionHead title="Remediation" copyText={d.remediation} toast={toast} />
          <Prose text={d.remediation} mode={proseMode} />
        </div>
      )}
      {!d.summary && !hasSteps && !ev && !hasCaptures && !d.attack_scenario && !d.impact && !d.remediation && (
        <p className="empty">No submission content recorded for this finding.</p>
      )}
    </>
  );
}

// One step row in the taint flow: a numbered bubble (IN / index / ⚠ sink)
// plus the step text, with a connector below every row but the last.
function TaintStep({
  step,
  i,
  total,
}: {
  step: string;
  i: number;
  total: number;
}) {
  const isFirst = i === 0;
  const isLast = i === total - 1;
  return (
    <div style={{ display: "contents" }}>
      <div className={`taint-row ${isFirst ? "taint-first" : ""} ${isLast ? "taint-last" : ""}`}>
        <span className="taint-bubble">{isFirst ? "IN" : isLast ? "⚠" : i}</span>
        <span className="taint-line">{step}</span>
      </div>
      {!isLast && <div className="taint-link" />}
    </div>
  );
}

// Renders the taint flow over discrete steps. Caps very long paths: when
// there are more than ~12 steps, show the first 5, a "… N more" expander,
// then the last 2 (entry + sink) so an 18-step path can't overflow the
// drawer body. The expander reveals the elided middle in place.
const TAINT_CAP = 12;
const TAINT_HEAD = 5;
const TAINT_TAIL = 2;
function TaintFlow({ steps }: { steps: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const total = steps.length;
  const capped = total > TAINT_CAP && !expanded;
  if (!capped) {
    return (
      <div className="taint">
        {steps.map((step, i) => (
          <TaintStep key={i} step={step} i={i} total={total} />
        ))}
      </div>
    );
  }
  const hiddenCount = total - TAINT_HEAD - TAINT_TAIL;
  const head = steps.slice(0, TAINT_HEAD);
  const tail = steps.slice(total - TAINT_TAIL);
  return (
    <div className="taint">
      {head.map((step, i) => (
        <TaintStep key={`h-${i}`} step={step} i={i} total={total} />
      ))}
      <div className="taint-link" />
      <div className="taint-row taint-more-row">
        <span className="taint-bubble taint-more-bubble">⋯</span>
        <button
          type="button"
          className="taint-more"
          onClick={() => setExpanded(true)}
        >
          … {hiddenCount} more {hiddenCount === 1 ? "step" : "steps"}
        </button>
      </div>
      <div className="taint-link" />
      {tail.map((step, i) => {
        const realIdx = total - TAINT_TAIL + i;
        return <TaintStep key={`t-${i}`} step={step} i={realIdx} total={total} />;
      })}
    </div>
  );
}

function CodePane({ d, toast }: { d: Derived; toast: ToastFn }) {
  // taint_path arrives (via toStringArray) often as a SINGLE-element array
  // whose one string is a ` -> `-delimited path. Split that case into real
  // steps so the bubble/flow visualization works; otherwise use the array
  // as-is (already a per-step list).
  const taintSteps =
    d.taint_path && d.taint_path.length === 1 && d.taint_path[0].includes(" -> ")
      ? d.taint_path[0].split(" -> ").map((s) => s.trim()).filter(Boolean)
      : d.taint_path ?? [];

  return (
    <>
      <div className="section">
        <p className="section-title">Slot</p>
        {/* slot_type stays a compact mono line; entry_point / sink are long
            prose so they get their own section + copy affordance below. */}
        {d.slot_type && (
          <p className="mono code-slot-type">{d.slot_type}</p>
        )}
      </div>
      {d.entry_point && (
        <div className="section">
          <SectionHead title="Entry point" copyText={d.entry_point} toast={toast} />
          <pre className="pre">{d.entry_point}</pre>
        </div>
      )}
      {d.sink && (
        <div className="section">
          <SectionHead title="Sink" copyText={d.sink} toast={toast} />
          <pre className="pre">{d.sink}</pre>
        </div>
      )}
      {taintSteps.length > 0 && (
        <div className="section">
          <SectionHead
            title="Taint path"
            copyText={taintSteps.join("\n")}
            toast={toast}
          />
          <TaintFlow steps={taintSteps} />
        </div>
      )}
      {d.guards_evaluated != null && (
        <div className="section">
          {(() => {
            const guards = d.guards_evaluated!;
            const guardsCopyText = Array.isArray(guards)
              ? guards.map((g) => (typeof g === "string" ? g : JSON.stringify(g))).join("\n")
              : typeof guards === "string"
                ? guards
                : JSON.stringify(guards, null, 2);
            return (
              <>
                <SectionHead title="Guards evaluated" copyText={guardsCopyText} toast={toast} />
                {Array.isArray(guards) ? (
                  <ul className="steps mono">
                    {guards.map((g, i) => (
                      <li key={i}>
                        {typeof g === "string" ? g : JSON.stringify(g)}
                      </li>
                    ))}
                  </ul>
                ) : typeof guards === "string" ? (
                  <pre className="pre">{guards}</pre>
                ) : (
                  <JsonTree value={toJsonValue(guards)} defaultOpen />
                )}
              </>
            );
          })()}
        </div>
      )}
    </>
  );
}

function RelationshipsPane({
  engagementKey,
  d,
  derivedBySlug,
  linkedFindings,
  linkedChains,
  chainMembersByKey,
  onSelect,
  toast,
  proseMode,
}: {
  engagementKey: string;
  d: Derived;
  derivedBySlug: Map<string, Derived>;
  linkedFindings: DerivedLink[];
  linkedChains: AssessmentAttackChainDetail[];
  chainMembersByKey: Map<string, Derived[]>;
  onSelect: (slug: string) => void;
  toast: ToastFn;
  proseMode: ProseMode;
}) {
  return (
    <>
      {d.root_cause_role && (
        <div className="section root-cause-section">
          <p className="section-title">Root cause relationship</p>
          {d.root_cause_role === "root" ? (
            <p>
              Root finding with {plural(d.sibling_count ?? 0, "linked sibling outcome")}
              {d.residual_path_count ? `; ${d.residual_path_count} ${d.residual_path_count === 1 ? "retains" : "retain"} a residual remediation path` : ""}.
            </p>
          ) : (
            <>
              <p>
                Sibling of <code>{d.root_cause_slug}</code>.{" "}
                {d.root_cause_effect === "eliminates_attack_path"
                  ? "Fixing the root eliminates the attack path; this remains a residual remediation item."
                  : "Fixing the root eliminates this finding."}
              </p>
              {d.root_cause_note && <Prose text={d.root_cause_note} mode={proseMode} />}
            </>
          )}
        </div>
      )}
      {(d.variant_of || d.original_pattern) && (
        <div className="section">
          <SectionHead title="Variant relationship" copyText={d.original_pattern || d.variant_of || ""} toast={toast} />
          {d.variant_of && <p>Variant of <code>{d.variant_of}</code></p>}
          {d.original_pattern && <pre className="pre">{d.original_pattern}</pre>}
        </div>
      )}
      {linkedFindings.length > 0 && (
        <div className="section">
          <p className="section-title">
            Linked findings <span className="count">{linkedFindings.length}</span>
          </p>
          <div className="link-grid">
            {linkedFindings.map((l, i) => {
              const target = derivedBySlug.get(l.target_ref);
              return (
                <button
                  key={`${i}-${l.target_ref}`}
                  type="button"
                  className="link-card"
                  onClick={() => target && onSelect(target.slug)}
                  disabled={!target}
                >
                  <span className="link-kind">
                    {(l.link_kind || "").replace(/_/g, " ")}
                  </span>
                  <span>
                    <span className="link-title">
                      {target ? target.title : l.target_ref}
                    </span>
                    <br />
                    <span className="link-sub">
                      {target ? `${target.slug} · ${severityLabel(target.severity)}` : "external"}
                    </span>
                  </span>
                  {target && (
                    <span
                      className="sev-dot"
                      style={{ background: severityColor(target.severity) }}
                    />
                  )}
                  <span className="link-go">›</span>
                  {l.notes && <span className="link-notes">{l.notes}</span>}
                </button>
              );
            })}
          </div>
        </div>
      )}
      {linkedChains.length > 0 && (
        <div className="section">
          <p className="section-title">
            Attack chains <span className="count">{linkedChains.length}</span>
          </p>
          {linkedChains.map((chain) => {
            const members = chainMembersByKey.get(chain.chain_key) || [];
            return (
              <div key={chain.chain_key} className="chain-card">
                <div
                  style={{
                    display: "flex",
                    gap: "8px",
                    alignItems: "baseline",
                    flexWrap: "wrap",
                  }}
                >
                  <SeverityTag severity={chain.severity} size="sm" />
                  <strong style={{ fontSize: "0.94rem" }}>{chain.title}</strong>
                  <StatusPill value={chain.status} tone="neutral" label={humanizeStatus(chain.status)} size="sm" />
                  <span
                    className="tag"
                    style={{ fontFamily: "'Source Code Pro', monospace" }}
                  >
                    {chain.chain_key}
                  </span>
                </div>
                {chain.narrative && (
                  <p
                    style={{
                      fontSize: "0.86rem",
                      color: "var(--ink-2)",
                      margin: 0,
                    }}
                  >
                    {chain.narrative}
                  </p>
                )}
                {members.length > 0 && (
                  <div className="chain-flow">
                    {members.map((m, i) => (
                      <div key={m.slug} style={{ display: "contents" }}>
                        <button
                          type="button"
                          className="chain-node"
                          onClick={() => onSelect(m.slug)}
                          style={
                            m.slug === d.slug
                              ? {
                                  borderColor: "var(--accent)",
                                  background: "var(--accent-muted)",
                                }
                              : undefined
                          }
                        >
                          <span
                            className="sev-dot"
                            style={{ background: severityColor(m.severity) }}
                          />
                          {m.slug.split("-").slice(0, 2).join("-")}
                        </button>
                        {i < members.length - 1 && (
                          <span className="chain-arrow">→</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      <IntelPane d={d} toast={toast} />
      {!!d.related_intel_ids?.length && (
        <RelatedIntelSection engagementKey={engagementKey} ids={d.related_intel_ids} />
      )}
      {!d.root_cause_role && !d.variant_of && linkedFindings.length === 0 &&
        linkedChains.length === 0 && d.references.length === 0 &&
        !d.related_intel_ids?.length && !hasFindingProvenance(d.provenance) && (
          <p className="empty">No relationships recorded for this finding.</p>
      )}
    </>
  );
}

export function RelatedIntelSection({
  engagementKey,
  ids,
}: {
  engagementKey: string;
  ids: Array<string | number>;
}) {
  const [results, setResults] = useState<IntelResolutionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    resolveIntelIds(engagementKey, ids)
      .then((rows) => {
        if (!cancelled) setResults(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setResults([]);
          setError(err instanceof Error ? err.message : "Failed to resolve linked intel");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, ids]);

  return (
    <div className="section">
      <p className="section-title">
        Linked intel <span className="count">{ids.length}</span>
      </p>
      {loading && <Skeleton width="70%" height={12} />}
      {error && <p className="empty" role="alert">{error}</p>}
      {!loading && !error && (
        <div className="intel-resolution-list">
          {results.map((result, resultIndex) => (
            <div key={`${result.requested_id}:${resultIndex}`} className={`intel-resolution resolution-${result.resolution}`}>
              {result.resolution !== "resolved" && (
                <p className="intel-resolution-state">
                  Intel #{result.requested_id} is {result.resolution}
                </p>
              )}
              {result.matches.map((match) => {
                const label = match.title || match.summary || `${match.entity_type} #${match.id}`;
                if (match.status === "dangling") {
                  return (
                    <div key={`${match.entity_type}:${match.id}`} className="intel-resolution-card is-dangling">
                      <strong>{match.entity_type.replace(/_/g, " ")} #{match.id}</strong>
                      <span>Index entry has no source record</span>
                    </div>
                  );
                }
                const query = new URLSearchParams({
                  tab: "intel",
                  intel_type: match.entity_type,
                  intel_id: String(match.id),
                });
                return (
                  <a
                    key={`${match.entity_type}:${match.id}`}
                    className="intel-resolution-card"
                    href={`#/engagements/${encodeURIComponent(engagementKey)}?${query.toString()}`}
                  >
                    <span className="intel-resolution-main">
                      <strong>{label}</strong>
                      {match.summary && match.summary !== label && <span>{match.summary}</span>}
                    </span>
                    <span className="intel-resolution-meta">
                      {match.entity_type.replace(/_/g, " ")} · {match.status}
                    </span>
                  </a>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type HistoryListItem = AssessmentFindingTransitionSummary | AssessmentFindingTransition;

function isTransitionSummary(t: HistoryListItem): t is AssessmentFindingTransitionSummary {
  return "reason_preview" in t;
}

function hasVerificationAudit(audit: AssessmentVerificationAudit | undefined): boolean {
  return Boolean(
    audit &&
    (audit.proof_receipt_total || audit.counter_check_total || audit.severity_variance_total),
  );
}

function parseConfirmCheck(metadataJson: string): AssessmentConfirmCheck | null {
  try {
    const metadata: unknown = JSON.parse(metadataJson);
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
    const value = (metadata as Record<string, unknown>).confirm_check;
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const check = value as Record<string, unknown>;
    const textFields = [
      "method", "attempted_falsification", "expected_result", "observed_result",
    ] as const;
    if (textFields.some((field) => typeof check[field] !== "string")) return null;
    if (typeof check.completed !== "boolean" || !Array.isArray(check.proof_receipt_ids)) return null;
    if (!check.proof_receipt_ids.every((id) => Number.isInteger(id) && Number(id) > 0)) return null;
    return {
      method: check.method as string,
      attempted_falsification: check.attempted_falsification as string,
      expected_result: check.expected_result as string,
      observed_result: check.observed_result as string,
      completed: check.completed,
      proof_receipt_ids: check.proof_receipt_ids as number[],
    };
  } catch {
    return null;
  }
}

function HistoryRow({
  transition,
  engagementKey,
  findingSlug,
}: {
  transition: HistoryListItem;
  engagementKey?: string;
  findingSlug?: string;
}) {
  const [detail, setDetail] = useState<AssessmentFindingTransition | null>(
    isTransitionSummary(transition) ? null : transition,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const preview = isTransitionSummary(transition)
    ? transition.reason_preview
    : previewWords(transition.reason_text, 100).text.replace(/…$/, "");
  const wordCount = isTransitionSummary(transition)
    ? transition.reason_word_count
    : transition.reason_text.trim().split(/\s+/).filter(Boolean).length;
  const truncated = isTransitionSummary(transition)
    ? transition.reason_truncated
    : wordCount > 100;
  const hasSnapshot = isTransitionSummary(transition)
    ? transition.has_snapshot
    : [transition.details_before_json, transition.details_after_json, transition.notes_before_json, transition.notes_after_json].some(Boolean);
  const confirmCheck = detail ? parseConfirmCheck(detail.metadata_json) : null;
  // The compact projection deliberately omits verification-audit bodies and
  // counts. Keep every summary row drill-downable so an audit-only transition
  // cannot disappear merely because it has no narrative or content snapshot.
  const canExpand = isTransitionSummary(transition) || Boolean(
    preview || hasSnapshot || hasVerificationAudit(detail?.verification_audit) || confirmCheck,
  );

  const loadDetail = (open: boolean) => {
    if (!open || detail || loading || !engagementKey || !findingSlug) return;
    setLoading(true);
    setError(null);
    getAssessmentFindingTransition(engagementKey, findingSlug, transition.id)
      .then(setDetail)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load transition detail");
      })
      .finally(() => setLoading(false));
  };

  const isCreation = transition.action === "created" || !transition.from_workflow_status;
  const sevChanged = transition.from_severity && transition.from_severity !== transition.to_severity;
  const workflowChanged = transition.from_workflow_status && transition.from_workflow_status !== transition.to_workflow_status;
  const verifChanged = transition.from_verification_status && transition.from_verification_status !== transition.to_verification_status;

  return (
    <div className={`tl-row action-${transition.action}`}>
      <div className="tl-head">
        <span className="tl-action">{transition.action.replace(/_/g, " ")}</span>
        <span className="tl-actor">{transition.actor || "system"}</span>
        <TimeStamp className="tl-time" value={transition.created_at} />
      </div>
      <div className="tl-detail">
        {(isCreation || workflowChanged) && (
          <span className="tl-change">
            <span className="tl-change-label">Workflow</span>
            {!isCreation && (
              <>
                <StatusPill domain="finding-workflow" value={transition.from_workflow_status} size="sm" />
                <span className="transition-arrow"> → </span>
              </>
            )}
            <StatusPill domain="finding-workflow" value={transition.to_workflow_status} size="sm" />
          </span>
        )}
        {sevChanged && (
          <span className="tl-change">
            <span className="tl-change-label">Severity</span>
            <SeverityTag severity={transition.from_severity ?? ""} size="sm" />
            <span className="transition-arrow"> → </span>
            <SeverityTag severity={transition.to_severity} size="sm" />
          </span>
        )}
        {verifChanged && (
          <span className="tl-change">
            <span className="tl-change-label">Verification</span>
            <StatusPill domain="finding-verification" value={transition.from_verification_status} size="sm" />
            <span className="transition-arrow"> → </span>
            <StatusPill domain="finding-verification" value={transition.to_verification_status} size="sm" />
          </span>
        )}
      </div>
      {canExpand && (
        <details className="history-reason" onToggle={(event) => loadDetail(event.currentTarget.open)}>
          <summary>
            {preview && <span className="history-reason-preview">{preview}{truncated ? "…" : ""}</span>}
            <span className="history-reason-action">{preview ? "Read full reason" : "View details"}</span>
            {wordCount > 0 && <span className="history-word-count">{wordCount} words</span>}
          </summary>
          <div className="history-reason-body">
            {loading && <Skeleton width="80%" height={12} />}
            {error && <p className="empty">{error}</p>}
            {detail?.reason_text && <Prose text={detail.reason_text} mode="rendered" />}
            {!detail && !loading && !error && !engagementKey && !isTransitionSummary(transition) && (
              <Prose text={transition.reason_text} mode="rendered" />
            )}
            {detail?.verification_audit && <VerificationAudit audit={detail.verification_audit} />}
            {confirmCheck && <ConfirmCheckAudit check={confirmCheck} />}
            {detail && [detail.details_before_json, detail.details_after_json, detail.notes_before_json, detail.notes_after_json].some(Boolean) && (
              <details className="detail-disclosure history-snapshot">
                <summary>Changed content</summary>
                {detail.details_before_json && <div><p className="snapshot-label">Details before</p><pre className="pre">{detail.details_before_json}</pre></div>}
                {detail.details_after_json && <div><p className="snapshot-label">Details after</p><pre className="pre">{detail.details_after_json}</pre></div>}
                {detail.notes_before_json && <div><p className="snapshot-label">Notes before</p><pre className="pre">{detail.notes_before_json}</pre></div>}
                {detail.notes_after_json && <div><p className="snapshot-label">Notes after</p><pre className="pre">{detail.notes_after_json}</pre></div>}
              </details>
            )}
          </div>
        </details>
      )}
    </div>
  );
}

function ConfirmCheckAudit({ check }: { check: AssessmentConfirmCheck }) {
  return (
    <div className="tl-audit-record">
      <div className="tl-audit-title">Structured confirmation check</div>
      <dl>
        <dt>Completed</dt><dd>{check.completed ? "Yes" : "No"}</dd>
        <dt>Method</dt><dd>{check.method}</dd>
        <dt>Attempted falsification</dt><dd>{check.attempted_falsification}</dd>
        <dt>Expected</dt><dd>{check.expected_result}</dd>
        <dt>Observed</dt><dd>{check.observed_result}</dd>
        <dt>Proof receipts</dt><dd>{check.proof_receipt_ids.join(", ")}</dd>
      </dl>
    </div>
  );
}

export function HistoryPane({
  transitions,
  loading,
  error,
  engagementKey,
  findingSlug,
}: {
  transitions: HistoryListItem[];
  loading: boolean;
  error: string | null;
  engagementKey?: string;
  findingSlug?: string;
}) {
  if (loading)
    return (
      <div className="timeline" aria-busy="true">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} style={{ display: "grid", gap: 6, marginBottom: 12 }}>
            <Skeleton width="35%" height={10} />
            <Skeleton width="70%" height={9} />
          </div>
        ))}
      </div>
    );
  if (error) return <p className="empty">{error}</p>;
  if (!transitions.length)
    return <p className="empty">No transition history recorded.</p>;
  return (
    <div className="timeline">
      {transitions.map((transition) => (
        <HistoryRow
          key={transition.id}
          transition={transition}
          engagementKey={engagementKey}
          findingSlug={findingSlug}
        />
      ))}
    </div>
  );
}

function VerificationAudit({ audit }: { audit: AssessmentVerificationAudit }) {
  if (
    !audit.proof_receipt_ids.length &&
    !audit.counter_checks.length &&
    !audit.severity_variances.length
  ) return null;
  return (
    <div className="tl-audit">
      {!!audit.proof_receipt_ids.length && (
        <div className="tl-audit-record">
          <div className="tl-audit-title">Decision proof receipts</div>
          <p>{audit.proof_receipt_ids.join(", ")}</p>
        </div>
      )}
      {audit.counter_checks.map((record) => (
        <div key={`counter-${record.id}`} className="tl-audit-record">
          <div className="tl-audit-title">Structured counter-check #{record.id}</div>
          <dl>
            <dt>Verifier dispatch</dt><dd>{record.verifier_dispatch_id}</dd>
            <dt>Completed</dt><dd>{record.completed ? "Yes" : "No"}</dd>
            <dt>Method</dt><dd>{record.method}</dd>
            <dt>Expected</dt><dd>{record.expected_result}</dd>
            <dt>Observed</dt><dd>{record.observed_result}</dd>
            <dt>Falsified claim</dt><dd>{record.falsified_claim}</dd>
            <dt>Proof receipts</dt><dd>{record.proof_receipt_ids.join(", ")}</dd>
          </dl>
        </div>
      ))}
      {audit.severity_variances.map((record) => (
        <div key={`variance-${record.id}`} className="tl-audit-record">
          <div className="tl-audit-title">Attributed severity variance #{record.id}</div>
          <dl>
            <dt>Band</dt><dd>{record.normal_band} → {record.chosen_severity}</dd>
            <dt>Actor</dt><dd>{record.actor}</dd>
            <dt>Reason</dt><dd>{record.reason}</dd>
            <dt>Proof receipt</dt><dd>{record.proof_receipt_id}</dd>
          </dl>
        </div>
      ))}
    </div>
  );
}

function IntelPane({ d, toast }: { d: Derived; toast: ToastFn }) {
  const refs = d.references;
  // Match the Drawer's tab-count logic exactly: a provenance object
  // only counts when at least one of the surfaced fields is present.
  // If the pane has nothing to show, the Intel tab is hidden upstream.
  const prov = d.provenance;
  const provFieldCount = prov
    ? [prov.agent_name, prov.captured_at, prov.artifact_ref, prov.evidence_quote].filter(
        Boolean,
      ).length
    : 0;
  const hasProvenance = provFieldCount > 0;
  return (
    <>
      {refs.length > 0 && (
        <div className="section">
          <p className="section-title">
            External references <span className="count">{refs.length}</span>
          </p>
          <div className="ref-grid">
            {refs.map((r, i) => {
              const { label, href } = normalizeReference(r);
              const host = href ? extractHost(href) : "";
              // Lead with a human label (title, else hostname) in normal ink;
              // demote the full URL to muted, truncated secondary text.
              const primary = href ? (label && label !== href ? label : host || href) : label;
              return href ? (
                <a key={i} className="ref-card" href={href} target="_blank" rel="noopener noreferrer">
                  <span className="ref-card-title">
                    {primary}
                    <IconExternal />
                  </span>
                  <span className="ref-card-url" title={href}>
                    {href}
                  </span>
                </a>
              ) : (
                <div key={i} className="ref-card">
                  <span className="ref-card-title">{label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
      {hasProvenance && prov && provFieldCount > 1 && (
        <div className="section">
          <p className="section-title">Provenance</p>
          {/* Mirror the Overview Metadata box exactly (kv-grid card) so the
              tabs share one visual rhythm; the evidence quote sits beneath. */}
          <div className="kv-grid">
            <KV k="Agent" v={prov.agent_name} mono />
            <KVTime k="Captured" v={prov.captured_at} />
            <KV k="Artifact" v={prov.artifact_ref} mono toast={toast} />
          </div>
          {prov.evidence_quote && (
            <blockquote className="prov-quote">{prov.evidence_quote}</blockquote>
          )}
        </div>
      )}
      {/* Single-field provenance (only agent_name) reads as a heavy,
          mostly-empty "PROVENANCE" section. Render it as a compact
          one-line footer instead; keep the full block when 2+ fields
          exist. */}
      {hasProvenance && prov && provFieldCount === 1 && prov.agent_name && (
        <p className="prov-footer">
          Discovered by <span className="agent-chip">{prov.agent_name}</span>
        </p>
      )}
    </>
  );
}

// ── Command palette ───────────────────────────────────────────────────

// Matches listed at once; the palette says how many more there are.
const PALETTE_LIMIT = 30;

function CommandPalette({
  derivedList,
  onSelect,
  onClose,
  returnFocusRef,
}: {
  derivedList: Derived[];
  onSelect: (slug: string) => void;
  onClose: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
}) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  useBodyScrollLock();
  useModalFocus(panelRef, onClose, true, returnFocusRef);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const { results, matchCount } = useMemo(() => {
    const parsed = parseQuery(q);
    const list = derivedList.filter((d) => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "severity":
            if ((d.severity || "").toLowerCase() !== v) return false;
            break;
          case "status":
          case "workflow":
            if ((d.workflow_status || "").toLowerCase() !== v) return false;
            break;
          case "verification":
            if ((d.verificationKey || "").toLowerCase() !== v) return false;
            break;
          case "cwe":
            if (!(d.cwe_id || "").toLowerCase().includes(v)) return false;
            break;
          case "owasp":
            if (!(d.owasp_category || "").toLowerCase().includes(v)) return false;
            break;
          case "source":
            if (!(d.source_name || "").toLowerCase().includes(v)) return false;
            break;
          case "slug":
            if (!(d.slug || "").toLowerCase().includes(v)) return false;
            break;
          case "family":
            if (!(d.defect_family || "").toLowerCase().includes(v)) return false;
            break;
          case "location":
            if (!(d.canonical_location || "").toLowerCase().includes(v)) return false;
            break;
          default: {
            if (!d.searchCorpus.includes(v)) return false;
          }
        }
      }
      for (const t of parsed.freeTerms) {
        if (!d.searchCorpus.includes(t)) return false;
      }
      return true;
    });
    // A typed slug is a request for that finding: an exact slug first, then
    // slugs that start with the text, then titles that contain it, then
    // anything that only mentions it. Severity orders each tier.
    const text = parsed.freeTerms.join(" ");
    const tier = (d: Derived) => {
      if (!text) return 0;
      const slug = d.slug.toLowerCase();
      if (slug === text) return 0;
      if (slug.startsWith(text)) return 1;
      if (d.title.toLowerCase().includes(text)) return 2;
      return 3;
    };
    list.sort((a, b) => tier(a) - tier(b) || compareSeverity(a.severity, b.severity));
    return { results: list.slice(0, PALETTE_LIMIT), matchCount: list.length };
  }, [q, derivedList]);

  useEffect(() => {
    setIdx(0);
  }, [q]);

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIdx((i) => Math.min(results.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (results[idx]) onSelect(results[idx].slug);
    }
  };

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <div ref={panelRef} className="cmd-box" role="dialog" aria-modal="true" aria-label="Jump to finding" tabIndex={-1} onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input-row">
          <IconSearch />
          <input
            ref={inputRef}
            className="cmd-input"
            aria-label="Search findings to jump to"
            placeholder="Jump to finding · try 'severity:critical xss' or a slug"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <span className="search-kbd">esc</span>
        </div>
        {matchCount > results.length && (
          <p className="cmd-more" role="status">Showing {results.length} of {matchCount} matches. Type more of a title or slug to narrow them.</p>
        )}
        <div className="cmd-list">
          {results.length === 0 ? (
            <div className="cmd-empty">No findings match.</div>
          ) : (
            results.map((d, i) => (
              <button
                key={d.slug}
                type="button"
                className={`cmd-item ${i === idx ? "is-active" : ""}`}
                onFocus={() => setIdx(i)}
                onMouseEnter={() => setIdx(i)}
                onClick={() => onSelect(d.slug)}
              >
                <span
                  className="sev-dot"
                  style={{ background: severityColor(d.severity) }}
                />
                <span>
                  <span className="cmd-title">{d.title}</span>
                  <span className="cmd-sub">
                    {[d.slug, severityLabel(d.severity), d.cwe_id].filter(Boolean).join(" · ")}
                  </span>
                </span>
                <span className="cmd-sub">{d.canonical_location || ""}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
