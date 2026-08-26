import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentFindingGroup,
  AssessmentFindingLink,
  AssessmentFindingTransition,
  FindingDetails,
  FindingPocRequest,
  FindingPocResponse,
  FindingProvenance,
  FindingReference,
} from "../lib/api";
import { Check, Copy, Link as LinkIcon, List, Table2 } from "lucide-react";
import { listAssessmentFindingGroups, listAssessmentFindingLinks, listAssessmentFindingTransitions } from "../lib/api";
import { JsonTree } from "./ArtifactViewer";
import { JsonView } from "./JsonView";
import { useBodyScrollLock } from "../lib/modalScrollLock";
import { CodeBlock, NotesBody, isCurlLike } from "./formatting";
import { KV, Prose, ProseModeToggle, SectionHead } from "./drawer/DrawerKit";
import type { ProseMode, ToastFn } from "./drawer/DrawerKit";
import { Skeleton, TableSkeleton } from "./Skeletons";

// Optional flat table view — lazy-loaded ag-grid (code-split chunk).
// The grouped root-cause list remains the default and is NOT lazy.
const FindingsGrid = lazy(() => import("./FindingsGrid"));

// Grouped-view pagination. One "page item" is a top-level entry: a root-cause
// group (root + its siblings) OR a standalone finding. Only the grouped view
// paginates — the Table view is ag-grid, which virtualizes its own rows.
const GROUPED_PAGE_SIZE = 25;

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
import { useToast } from "../contexts/ToastContext";
import { findingToMarkdown } from "../lib/findingMarkdown";

// ── Types & helpers ───────────────────────────────────────────────────

type FindingLike = AssessmentFinding | AssessmentFindingDetail;

type FindingsTabProps = {
  engagementKey: string;
  findings: FindingLike[];
  fallbackFindings: AssessmentFinding[];
  chains: AssessmentAttackChainDetail[];
  chainLinks: AssessmentAttackChainLink[];
  assessmentRefreshVersion: number;
  // Deep-link entry: slug to auto-select + open once findings load. Unknown
  // slugs are silently ignored. Honored once per slug value (see effect).
  initialFindingSlug?: string;
  // Deep-link entry: which drawer tab (?dtab=…) to open the auto-opened
  // finding on. Validated against the finding's visible tabs; falls back to
  // "overview" when absent / invalid / hidden. Only applies to the deep-link
  // auto-open, not to later manual drawer navigation.
  initialDrawerTab?: string;
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITY_ORDER)[number];
const SEV_RANK: Record<string, number> = Object.fromEntries(
  SEVERITY_ORDER.map((s, i) => [s, i]),
);
const SEV_COLORS: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

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
  "cvss_vector",
  "cvss_score",
  "remediation",
  "steps_to_reproduce",
  "chain_required",
  "chain_rationale",
  "required_followup",
  "poc_code",
  "poc_language",
  "poc_request",
  "poc_response",
  "references",
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

function parseDetails(finding: FindingLike): FindingDetails {
  if (!isDetail(finding)) return {};
  try {
    return JSON.parse(finding.details_json || "{}") as FindingDetails;
  } catch {
    return {};
  }
}

function parseProvenance(raw: string | undefined | null): FindingProvenance | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as FindingProvenance;
    }
  } catch {
    // ignore
  }
  return null;
}

function verificationKey(finding: FindingLike): string {
  if (finding.verification_state === "disputed") return "disputed";
  if (finding.verification_disposition && finding.verification_disposition !== "none") {
    return finding.verification_disposition;
  }
  return finding.verification_state;
}

// Human-readable labels shared across pill text, filter chip text, and
// command-palette subtitles. Keep these maps together so a rename (e.g.
// the old "Suppressed" → "False positive") lands everywhere at once.
const WORKFLOW_LABELS: Record<string, string> = {
  reported: "Reported",
  merged: "Merged",
  active: "Active",
  exploited: "Exploited",
  blocked: "Blocked",
  false_positive: "False positive",
};

const VERIFICATION_LABELS: Record<string, string> = {
  confirmed: "Verified",
  downgraded: "Downgraded",
  false_positive: "False positive",
  disputed: "Disputed",
  unreviewed: "Unreviewed",
};

// External-program submission state — a SEPARATE axis from workflow_status.
// "none" is the default (never submitted externally) and is intentionally
// absent here: rows with submission_status=none render no submission pill at
// all, so this map only covers the meaningful, displayable states.
const SUBMISSION_LABELS: Record<string, string> = {
  submitted: "Submitted",
  accepted: "Accepted",
  needs_info: "Needs info",
  rejected: "Rejected",
  duplicate: "Duplicate",
};

function verificationLabel(finding: FindingLike): string {
  const k = verificationKey(finding);
  return VERIFICATION_LABELS[k] || k;
}

function workflowLabel(finding: FindingLike): string {
  return WORKFLOW_LABELS[finding.workflow_status] || finding.workflow_status;
}

function submissionLabel(finding: FindingLike): string {
  return SUBMISSION_LABELS[finding.submission_status] || finding.submission_status;
}

// A submission_status is worth surfacing only when it is set to something
// other than the "none" default — otherwise every never-submitted finding
// would carry a noisy pill. Tolerates older payloads where the field is
// absent (treated as none / not meaningful).
function hasSubmissionStatus(status: string | undefined | null): boolean {
  return !!status && status !== "none";
}

export function relTime(iso: string | undefined | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const diffMin = Math.round((now.getTime() - d.getTime()) / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const h = Math.round(diffMin / 60);
  if (h < 24) return `${h}h ago`;
  const day = Math.round(h / 24);
  if (day < 7) return `${day}d ago`;
  return d.toISOString().slice(0, 10);
}

export function sevDotColor(sev: string): string {
  return SEV_COLORS[sev] || "var(--sev-info)";
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
    lines.push(`${(req.method || "GET").toUpperCase()} ${req.url || ""}`.trim());
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
  verification_state: string;
  verification_disposition: string;
  verificationKey: string;
  verificationLabel: string;
  workflowLabel: string;
  submissionLabel: string;
  canonical_location: string;
  summary: string;
  source_name: string;
  updated_at: string;
  // details_json-derived
  cwe_id?: string;
  owasp_category?: string;
  cvss_vector?: string;
  cvss_score?: number;
  impact?: string;
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
  chain_required?: boolean;
  chain_rationale?: string;
  required_followup?: string[];
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
    d.remediation,
    d.evidence,
    d.kill_reason,
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
    JSON.stringify(d.poc_request || ""),
    JSON.stringify(d.poc_response || ""),
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
const IconCopy = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <rect x={9} y={9} width={13} height={13} rx={2} />
    <path d="M5 15V5a2 2 0 012-2h10" />
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
// ── DetailModal ──────────────────────────────────────────────────────
// Shared modal shell used across tabs. See CommandsTab.tsx for design
// notes on focus trap, aria roles, and the z-index relationship with
// the Cmd/Ctrl-K palette.
function DetailModal({
  children,
  onClose,
  titleId,
}: {
  children: React.ReactNode;
  onClose: () => void;
  titleId?: string;
}) {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    queueMicrotask(() => panelRef.current?.focus());
  }, []);
  useBodyScrollLock();
  return (
    <div
      className="detail-modal-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="presentation"
    >
      <div
        ref={panelRef}
        className="detail-modal-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <button
          type="button"
          className="detail-modal-close"
          onClick={onClose}
          aria-label="Close detail"
          title="Close (Esc)"
        >
          <IconClose />
        </button>
        {children}
      </div>
    </div>
  );
}

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
}: FindingsTabProps) {
  const allFindingsRaw = findings.length > 0 ? findings : fallbackFindings;
  const { toast } = useToast();
  // The active drawer-tab is owned by the Drawer, but FindingsTab needs it to
  // write the deep-link hash, so the Drawer reports it up via onTabChange.
  const [drawerTab, setDrawerTab] = useState<TabId>("overview");

  const [allFindingLinks, setAllFindingLinks] = useState<AssessmentFindingLink[]>([]);
  const [allFindingGroups, setAllFindingGroups] = useState<AssessmentFindingGroup[]>([]);
  const [findingLinksError, setFindingLinksError] = useState<string | null>(null);
  const [findingGroupsLoading, setFindingGroupsLoading] = useState(false);
  const [findingGroupsError, setFindingGroupsError] = useState<string | null>(null);
  const [transitions, setTransitions] = useState<AssessmentFindingTransition[]>([]);
  const [transitionsLoading, setTransitionsLoading] = useState(false);
  const [transitionsError, setTransitionsError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [sevFilters, setSevFilters] = useState<Set<string>>(new Set());
  const [workflowFilters, setWorkflowFilters] = useState<Set<string>>(new Set());
  const [verifFilters, setVerifFilters] = useState<Set<string>>(new Set());
  const [cmdOpen, setCmdOpen] = useState(false);

  const [selected, setSelected] = useState<string | null>(() => {
    try {
      return window.localStorage.getItem("findings.selected");
    } catch {
      return null;
    }
  });
  // Grouped (default) vs flat table view. Persisted via the same
  // localStorage idiom as findings.selected below.
  const [view, setView] = useState<FindingsView>(() => readFindingsView());
  // Detail-modal open state. See CommandsTab.tsx for design notes.
  // Intentionally does NOT mirror the persisted `selected` — we don't
  // want the modal to pop open automatically on a page refresh.
  const [detailOpen, setDetailOpen] = useState(false);
  const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const lastFocusSlugRef = useRef<string | null>(null);

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Persist selection
  useEffect(() => {
    try {
      if (selected) window.localStorage.setItem("findings.selected", selected);
      else window.localStorage.removeItem("findings.selected");
    } catch {
      // ignore
    }
  }, [selected]);

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
  // The drawer-tab the deep-link auto-open should land on (resolved against the
  // finding's visible tabs) plus the slug it applies to. Handed to the Drawer
  // so it opens that finding on the intended pane; null = overview / no pending
  // deep-link. Cleared on manual open + close so it can't leak.
  const pendingDrawerTabRef = useRef<{ slug: string; tab: TabId } | null>(null);

  // Fetch finding links
  useEffect(() => {
    let cancelled = false;
    listAssessmentFindingLinks(engagementKey)
      .then((rows) => {
        if (!cancelled) {
          setAllFindingLinks(rows);
          setFindingLinksError(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setAllFindingLinks([]);
          setFindingLinksError(error instanceof Error ? error.message : String(error));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, assessmentRefreshVersion]);

  useEffect(() => {
    let cancelled = false;
    setFindingGroupsLoading(true);
    setFindingGroupsError(null);
    listAssessmentFindingGroups(engagementKey)
      .then((rows) => {
        if (!cancelled) {
          setAllFindingGroups(rows);
          setFindingGroupsError(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setAllFindingGroups([]);
          setFindingGroupsError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setFindingGroupsLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, assessmentRefreshVersion]);

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
      const provenance = isDetail(f) ? parseProvenance(f.provenance_json) : null;

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
        verification_state: f.verification_state,
        verification_disposition: f.verification_disposition,
        verificationKey: verificationKey(f),
        verificationLabel: verificationLabel(f),
        workflowLabel: workflowLabel(f),
        submissionLabel: submissionLabel(f),
        canonical_location: f.canonical_location,
        summary: f.summary,
        source_name: f.source_name,
        updated_at: f.updated_at,
        cwe_id: details.cwe_id,
        owasp_category: details.owasp_category,
        cvss_vector: details.cvss_vector,
        cvss_score: typeof details.cvss_score === "number" ? details.cvss_score : undefined,
        impact: details.impact,
        remediation: details.remediation,
        evidence: details.evidence,
        kill_reason: details.kill_reason,
        kill_check: typeof details.kill_check === "number" ? details.kill_check : undefined,
        // Coerce list-typed detail fields: agents occasionally record these as
        // a single string instead of an array (e.g. a numbered multi-step block).
        // Without coercion the search-corpus builder's `(x || []).join(...)` and
        // the PoC pane's `.map(...)` throw on a truthy non-array, which crashes
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
        chain_required: details.chain_required,
        chain_rationale: details.chain_rationale,
        required_followup: toStringArray(details.required_followup),
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
        }
      }
      if (parsed.freeTerms.length) {
        for (const t of parsed.freeTerms) if (!d.searchCorpus.includes(t)) return false;
      }
      return true;
    },
    [],
  );

  const filtered = useMemo(() => {
    const list = derivedList.filter((d) => {
      if (sevFilters.size && !sevFilters.has(d.severity)) return false;
      if (workflowFilters.size && !workflowFilters.has(d.workflow_status)) return false;
      if (verifFilters.size && !verifFilters.has(d.verificationKey)) return false;
      if (!matchesQuery(d, parsedQuery)) return false;
      return true;
    });
    list.sort((a, b) => {
      const dRank = (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99);
      if (dRank !== 0) return dRank;
      return a.title.localeCompare(b.title);
    });
    return list;
  }, [derivedList, sevFilters, workflowFilters, verifFilters, parsedQuery, matchesQuery]);

  const groupedFiltered = useMemo(() => {
    const filteredSlugs = new Set(filtered.map((d) => d.slug));
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
  }, [filtered, derivedBySlug]);

  // ── Grouped-view pagination ──
  // Flatten the grouped render into the EXACT order it draws: every group (in
  // its sorted order) is one top-level entry, then every standalone finding (in
  // its sorted order) is one top-level entry. Each entry is one "page item".
  type GroupEntry = { kind: "group"; group: (typeof groupedFiltered.groups)[number] };
  type StandaloneEntry = { kind: "standalone"; finding: Derived };
  type DisplayEntry = GroupEntry | StandaloneEntry;
  const displayEntries = useMemo<DisplayEntry[]>(() => {
    const entries: DisplayEntry[] = [];
    for (const group of groupedFiltered.groups) entries.push({ kind: "group", group });
    for (const finding of groupedFiltered.standalone) entries.push({ kind: "standalone", finding });
    return entries;
  }, [groupedFiltered]);

  // Map every finding slug (a group's root + siblings, or a standalone) to the
  // index of its top-level entry, so a deep-linked / keyboard-selected finding
  // can be paged into view no matter which entry it lives in.
  const entryIndexBySlug = useMemo(() => {
    const m = new Map<string, number>();
    displayEntries.forEach((entry, i) => {
      if (entry.kind === "group") {
        m.set(entry.group.root.slug, i);
        for (const sib of entry.group.siblings) m.set(sib.slug, i);
      } else {
        m.set(entry.finding.slug, i);
      }
    });
    return m;
  }, [displayEntries]);

  const pageCount = Math.max(1, Math.ceil(displayEntries.length / GROUPED_PAGE_SIZE));
  const [groupedPage, setGroupedPage] = useState(0);

  // Reset to the first page whenever the filtered result set changes (search /
  // chips). Depending on `displayEntries` identity ties the reset to the same
  // memo the render reads, so it fires exactly when the visible list changes.
  useEffect(() => {
    setGroupedPage(0);
  }, [displayEntries]);

  // Clamp if the page count shrinks (e.g. WebSocket refresh drops entries)
  // without otherwise changing identity in a way that resets the page.
  const safePage = Math.min(groupedPage, pageCount - 1);

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

  // Auto-jump the grouped page to keep the selected finding reachable. This is
  // the single guarantee that (a) a deep-linked / clicked finding's source row
  // is on the visible page so the drawer has an anchor, and (b) keyboard nav
  // (j/k/[/]) — which walks the flat `filtered` order, not the paged grouped
  // order — never lands on an off-page row the user can't see: we follow it to
  // its page instead of clamping. No-ops in Table view (ag-grid is unpaged) and
  // when the selected slug isn't a visible grouped entry.
  useEffect(() => {
    if (view !== "grouped" || !selected) return;
    const entryIdx = entryIndexBySlug.get(selected);
    if (entryIdx == null) return;
    const targetPage = Math.floor(entryIdx / GROUPED_PAGE_SIZE);
    setGroupedPage((cur) => (cur === targetPage ? cur : targetPage));
  }, [selected, view, entryIndexBySlug]);

  // Deep-link auto-open: when arriving with ?finding={slug}, select + open
  // that finding's drawer once it exists in the loaded set. We track the
  // last-consumed slug VALUE (not a boolean) so closing the drawer doesn't
  // immediately re-open it, while re-deep-linking to a DIFFERENT finding
  // (a new slug) while still mounted re-arms and re-opens. Unknown slugs are
  // ignored silently. The drawer-tab is resolved from ?dtab= against the
  // finding's visible tabs (invalid/hidden → overview) and handed to the
  // Drawer via pendingDrawerTabRef so it opens on the intended pane.
  useEffect(() => {
    if (!initialFindingSlug) return;
    if (consumedInitialSlugRef.current === initialFindingSlug) return;
    const target = derivedBySlug.get(initialFindingSlug);
    if (!target) return; // wait for load / ignore unknown
    consumedInitialSlugRef.current = initialFindingSlug;
    const resolvedDrawerTab =
      isDrawerTabId(initialDrawerTab) && drawerTabVisible(target, initialDrawerTab)
        ? initialDrawerTab
        : "overview";
    pendingDrawerTabRef.current = { slug: initialFindingSlug, tab: resolvedDrawerTab };
    setSelected(initialFindingSlug);
    lastFocusSlugRef.current = initialFindingSlug;
    setDrawerTab(resolvedDrawerTab);
    setDetailOpen(true);
  }, [initialFindingSlug, initialDrawerTab, derivedBySlug]);

  // Reflect drawer open-state + active drawer-tab in the URL via
  // history.replaceState (silent — no `hashchange`, so App never re-routes
  // and there is no loop). On close we drop the `finding`/`dtab` params but
  // keep the findings tab. Back/forward still work because we never pushState.
  useEffect(() => {
    const base = `#/engagements/${encodeURIComponent(engagementKey)}`;
    const params = new URLSearchParams();
    params.set("tab", "findings");
    if (detailOpen && selected) {
      params.set("finding", selected);
      if (drawerTab !== "overview") params.set("dtab", drawerTab);
    }
    const next = `${base}?${params.toString()}`;
    if (window.location.hash !== next) {
      window.history.replaceState(null, "", next);
    }
  }, [engagementKey, detailOpen, selected, drawerTab]);

  // Transitions fetch
  useEffect(() => {
    if (!selected) {
      setTransitions([]);
      setTransitionsLoading(false);
      setTransitionsError(null);
      return;
    }
    let cancelled = false;
    setTransitionsLoading(true);
    setTransitionsError(null);
    listAssessmentFindingTransitions(engagementKey, selected)
      .then((rows) => {
        if (!cancelled) setTransitions(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setTransitions([]);
          setTransitionsError(
            err instanceof Error ? err.message : "Failed to load transition history",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setTransitionsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, selected, assessmentRefreshVersion]);

  // ── Keyboard ──
  const filteredRef = useRef(filtered);
  filteredRef.current = filtered;
  const selectedRef = useRef(selected);
  selectedRef.current = selected;

  const detailOpenRef = useRef(detailOpen);
  detailOpenRef.current = detailOpen;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea";
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setDetailOpen(false);
        setCmdOpen(true);
        return;
      }
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
        return;
      }
      if (e.key === "Escape") {
        if (isTyping) {
          searchRef.current?.blur();
          return;
        }
        if (detailOpenRef.current) {
          setDetailOpen(false);
        } else {
          setSelected(null);
        }
        return;
      }
      if (!isTyping && (e.key === "[" || e.key === "]")) {
        e.preventDefault();
        const list = filteredRef.current;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.slug === cur);
        if (idx < 0) {
          if (list[0]) setSelected(list[0].slug);
          return;
        }
        const next =
          e.key === "[" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelected(list[next].slug);
      }
      if (!isTyping && (e.key === "j" || e.key === "k")) {
        e.preventDefault();
        const list = filteredRef.current;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.slug === cur);
        if (idx < 0 && list[0]) {
          setSelected(list[0].slug);
          return;
        }
        const next =
          e.key === "k" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelected(list[next].slug);
      }
      if (!isTyping && e.key === "Enter" && selectedRef.current != null) {
        e.preventDefault();
        setDetailOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

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

  const toggle = (
    set: Set<string>,
    setter: (s: Set<string>) => void,
    val: string,
  ) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
  };

  const clearAll = () => {
    setSevFilters(new Set());
    setWorkflowFilters(new Set());
    setVerifFilters(new Set());
    setQuery("");
  };

  const activeFilterCount =
    sevFilters.size + workflowFilters.size + verifFilters.size + (query ? 1 : 0);

  // Shared open-drawer handler used by BOTH the grouped list and the flat
  // table view, so the drawer / deep-link flow is identical in either view.
  const openFinding = useCallback((slug: string) => {
    // A manual open always lands on Overview — drop any pending deep-link
    // drawer-tab so it can't leak into a hand-clicked finding.
    pendingDrawerTabRef.current = null;
    setSelected(slug);
    lastFocusSlugRef.current = slug;
    setDetailOpen(true);
  }, []);

  return (
    <div className="findings-redesign">
      <div className="page-head">
        <div>
          <h1 className="page-title">Findings</h1>
          <div className="page-crumbs">
            Engagement <code>{engagementKey}</code> ·{" "}
            <span>
              {filtered.length} of {derivedList.length} findings
            </span>
          </div>
        </div>
        <SevSpark counts={severityCounts} />
      </div>

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search any field — title, CWE, slug, payload, endpoint… (try severity:high cwe:79)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
          <div className="toolbar-right">
            {/* Grouped (default) | Table view toggle. The grouped root-cause
                list is the differentiator we keep; Table is the optional
                flat ag-grid view over the same filtered rows. */}
            <div className="view-toggle" role="group" aria-label="Findings view">
              <button
                type="button"
                className={view === "grouped" ? "is-active" : ""}
                aria-pressed={view === "grouped"}
                onClick={() => setView("grouped")}
                title="Grouped by root cause"
              >
                <List aria-hidden /> Grouped
              </button>
              <button
                type="button"
                className={view === "table" ? "is-active" : ""}
                aria-pressed={view === "table"}
                onClick={() => setView("table")}
                title="Flat table"
              >
                <Table2 aria-hidden /> Table
              </button>
            </div>
            <button
              type="button"
              className="qa-btn"
              onClick={() => setCmdOpen(true)}
            >
              Jump to…{" "}
              <span className="search-kbd" style={{ marginLeft: 4 }}>
                ⌘K
              </span>
            </button>
          </div>
        </div>
        <div className="filter-row">
          <div className="filter-group">
            <span className="filter-label">Severity</span>
            {SEVERITY_ORDER.filter((s) => severityCounts[s]).map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip sev-${s} ${sevFilters.has(s) ? "is-active" : ""}`}
                onClick={() => toggle(sevFilters, setSevFilters, s)}
              >
                <span className="sev-dot" style={{ background: sevDotColor(s) }} />
                {s}
                <span className="filter-count">{severityCounts[s]}</span>
              </button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-label">Workflow</span>
            {Object.keys(workflowCounts).map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip ${workflowFilters.has(s) ? "is-active" : ""}`}
                onClick={() => toggle(workflowFilters, setWorkflowFilters, s)}
              >
                {/*
                  Use the same human-readable map as the row pills
                  (e.g. "false_positive" -> "False positive" rather
                  than the old "Suppressed"). Falls back to a
                  _-stripped value for statuses we don't label.
                */}
                {WORKFLOW_LABELS[s] || s.replace(/_/g, " ")}
                <span className="filter-count">{workflowCounts[s]}</span>
              </button>
            ))}
          </div>
          <div className="filter-group">
            <span className="filter-label">Verification</span>
            {Object.keys(verifCounts).map((s) => (
              <button
                key={s}
                type="button"
                className={`filter-chip ${verifFilters.has(s) ? "is-active" : ""}`}
                onClick={() => toggle(verifFilters, setVerifFilters, s)}
              >
                {VERIFICATION_LABELS[s] || s.replace(/_/g, " ")}
                <span className="filter-count">{verifCounts[s]}</span>
              </button>
            ))}
          </div>
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {/* List (detail renders as a centred modal below) */}
      <div className="findings-shell">
        <section className="list-panel panel">
          <div className="grouping-status">
            <div>
              <strong>{filtered.length}</strong> of <strong>{derivedList.length}</strong> findings visible
              {activeFilterCount > 0 || query.trim() ? (
                <span className="meta-text"> · filtered by the current search or chips</span>
              ) : (
                <span className="meta-text"> · all findings shown</span>
              )}
            </div>
            <div className="grouping-status-meta">
              {findingGroupsLoading ? (
                <span className="tag">Loading groups</span>
              ) : findingGroupsError ? (
                <span className="tag warning">Grouping unavailable</span>
              ) : allFindingGroups.length > 0 ? (
                <span className="tag root">{allFindingGroups.length} root-cause groups</span>
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
          {view === "grouped" && pageCount > 1 ? (
            <div className="pager">
              <button
                type="button"
                className="pager-button"
                disabled={safePage === 0}
                onClick={() => setGroupedPage(Math.max(0, safePage - 1))}
              >
                Prev
              </button>
              <span className="meta-text">
                Page {safePage + 1} of {pageCount} · Showing {pageRangeStart}–{pageRangeEnd} of{" "}
                {displayEntries.length}
              </span>
              <button
                type="button"
                className="pager-button"
                disabled={safePage >= pageCount - 1}
                onClick={() => setGroupedPage(Math.min(pageCount - 1, safePage + 1))}
              >
                Next
              </button>
            </div>
          ) : null}
          {view === "table" ? (
            <Suspense fallback={<TableSkeleton rows={10} showHeader={false} />}>
              <FindingsGrid rows={filtered} selected={selected} onOpen={openFinding} />
            </Suspense>
          ) : (
            <GroupedFindingsList
              groups={pagedGrouped.groups}
              standalone={pagedGrouped.standalone}
              selected={selected}
              onOpen={openFinding}
              freeTerms={parsedQuery.freeTerms}
            />
          )}
        </section>
      </div>

      {detailOpen && selectedDerived && (
        <DetailModal
          onClose={() => {
            setDetailOpen(false);
            // Reset the drawer-tab so a stale `dtab` doesn't linger in the
            // URL/state after close (the URL effect drops it once detailOpen
            // is false, but keeping state honest avoids a flash on re-open).
            setDrawerTab("overview");
            // Drop any consumed deep-link drawer-tab so a re-open lands on
            // Overview rather than the previously deep-linked pane.
            pendingDrawerTabRef.current = null;
            const el =
              lastFocusSlugRef.current != null
                ? rowRefs.current.get(lastFocusSlugRef.current)
                : null;
            queueMicrotask(() => el?.focus());
          }}
          titleId="findings-detail-modal-title"
        >
          <Drawer
            d={selectedDerived}
            derivedBySlug={derivedBySlug}
            chainsByKey={chainsByKey}
            chainMembersByKey={chainMembersByKey}
            transitions={transitions}
            transitionsLoading={transitionsLoading}
            transitionsError={transitionsError}
            onSelect={(slug) => {
              // Cross-link selection (e.g. from LinksPane). Keep the
              // modal open so the operator can navigate through related
              // findings without re-clicking.
              setSelected(slug);
              if (slug) lastFocusSlugRef.current = slug;
            }}
            onTabChange={setDrawerTab}
            initialTab={pendingDrawerTabRef.current?.tab}
            initialTabSlug={pendingDrawerTabRef.current?.slug}
            titleId="findings-detail-modal-title"
          />
        </DetailModal>
      )}

      <div className="findings-shortcuts">
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
      </div>

      {cmdOpen && (
        <CommandPalette
          derivedList={derivedList}
          onSelect={(slug) => {
            // Manual jump-to-finding lands on Overview; drop any pending
            // deep-link drawer-tab so it can't leak into this open.
            pendingDrawerTabRef.current = null;
            setSelected(slug);
            lastFocusSlugRef.current = slug;
            setCmdOpen(false);
            setDetailOpen(true);
          }}
          onClose={() => setCmdOpen(false)}
        />
      )}
    </div>
  );
}

// ── SevSpark ──────────────────────────────────────────────────────────

function SevSpark({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="sev-sparkline-wrap">
      <span className="sev-label">Severity</span>
      <div className="sev-sparkline">
        {SEVERITY_ORDER.map((s) => {
          const c = counts[s] || 0;
          const h = Math.max(4, (c / max) * 26);
          return (
            <div
              key={s}
              className="sev-bar"
              style={{
                height: `${h}px`,
                background: SEV_COLORS[s],
                opacity: c ? 1 : 0.2,
              }}
              title={`${s}: ${c}`}
            >
              <span>{c}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GroupedFindingsList({
  groups,
  standalone,
  selected,
  onOpen,
  freeTerms,
}: {
  groups: { root: Derived; siblings: Derived[]; highestSeverity: string }[];
  standalone: Derived[];
  selected: string | null;
  onOpen: (slug: string) => void;
  freeTerms: string[];
}) {
  if (groups.length === 0 && standalone.length === 0) {
    return <div className="empty">No findings match.</div>;
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
        />
      ))}
      {standalone.length > 0 && (
        <section className="standalone-group">
          <div className="group-card-head">
            <div>
              <p className="eyebrow">Standalone Findings</p>
              <h3>{standalone.length} ungrouped findings</h3>
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
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function RootCauseGroupCard({
  group,
  selected,
  onOpen,
  freeTerms,
}: {
  group: { root: Derived; siblings: Derived[]; highestSeverity: string };
  selected: string | null;
  onOpen: (slug: string) => void;
  freeTerms: string[];
}) {
  const residualCount = group.siblings.filter((d) => d.root_cause_effect === "eliminates_attack_path").length;
  return (
    <section className="root-group-card">
      <div className="group-card-head">
        <div>
          <p className="eyebrow">Root Cause</p>
          <button
            type="button"
            className={`group-root-title ${selected === group.root.slug ? "is-selected" : ""}`}
            onClick={() => onOpen(group.root.slug)}
          >
            <span className="sev-dot" style={{ background: sevDotColor(group.root.severity) }} />
            {highlight(group.root.title, freeTerms)}
          </button>
          <p className="meta-text">
            <code>{group.root.slug}</code> · {group.root.canonical_location || "No location recorded"}
          </p>
        </div>
        <div className="group-card-metrics">
          <span className={`badge severity-${group.highestSeverity}`}>{group.highestSeverity}</span>
          {group.root.code_snapshot_status && group.root.code_snapshot_status !== "not_applicable" && (
            <span className={`pill pill-source-${group.root.code_snapshot_status}`}>
              source {group.root.code_snapshot_status}
            </span>
          )}
          <span className="tag root">{group.siblings.length} siblings</span>
          {residualCount > 0 && <span className="tag chain">{residualCount} residual paths</span>}
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
}: {
  d: Derived;
  selected: boolean;
  onOpen: () => void;
  freeTerms: string[];
}) {
  return (
    <button type="button" className={`mini-finding-row ${selected ? "is-selected" : ""}`} onClick={onOpen}>
      <span className="sev-dot" style={{ background: sevDotColor(d.severity) }} />
      <span className="mini-main">
        <strong>{highlight(d.title, freeTerms)}</strong>
        <span className="meta-text">
          <code>{d.slug}</code>
          {d.canonical_location ? ` · ${d.canonical_location}` : ""}
        </span>
        {d.root_cause_note && <span className="meta-text">{d.root_cause_note}</span>}
      </span>
      {d.root_cause_effect === "eliminates_attack_path" && <span className="tag chain">Residual path</span>}
      {d.code_snapshot_status && d.code_snapshot_status !== "not_applicable" && (
        <span className={`pill pill-source-${d.code_snapshot_status}`}>
          source {d.code_snapshot_status}
        </span>
      )}
      <span className={`pill pill-${d.workflow_status}`}>{d.workflowLabel}</span>
      {hasSubmissionStatus(d.submission_status) && (
        <span
          className={`pill submission-pill submission-${d.submission_status}`}
          title={`External submission: ${d.submissionLabel}`}
        >
          {d.submissionLabel}
        </span>
      )}
    </button>
  );
}

// ── Drawer ────────────────────────────────────────────────────────────

type DrawerProps = {
  d: Derived;
  derivedBySlug: Map<string, Derived>;
  chainsByKey: Map<string, AssessmentAttackChainDetail>;
  chainMembersByKey: Map<string, Derived[]>;
  transitions: AssessmentFindingTransition[];
  transitionsLoading: boolean;
  transitionsError: string | null;
  onSelect: (slug: string | null) => void;
  // Report the active drawer-tab up so FindingsTab can mirror it in the URL.
  onTabChange?: (tab: TabId) => void;
  // Deep-link (?dtab=…) drawer-tab + the finding slug it applies to. Already
  // validated by the caller. The drawer opens on `initialTab` whenever its
  // current finding is `initialTabSlug` (mount OR a same-mount re-deep-link to
  // that finding); every other finding resets to "overview".
  initialTab?: TabId;
  initialTabSlug?: string;
  titleId?: string;
};

type TabId = "overview" | "poc" | "code" | "links" | "history" | "intel";

const DRAWER_TAB_IDS: readonly TabId[] = [
  "overview",
  "poc",
  "code",
  "links",
  "history",
  "intel",
] as const;

function isDrawerTabId(value: string | undefined): value is TabId {
  return value != null && (DRAWER_TAB_IDS as readonly string[]).includes(value);
}

// Which drawer tabs are visible for a finding. Mirrors the `hidden` rules in
// Drawer's `tabs` array (code/links/intel are conditionally hidden; overview /
// poc / history are always shown). Used to validate a deep-linked ?dtab= so we
// only honor a tab that actually exists for the finding.
function drawerTabVisible(d: Derived, tab: TabId): boolean {
  switch (tab) {
    case "code":
      return !!d.slot_type;
    case "links": {
      const count =
        d.links.filter((l) => l.target_kind === "finding").length +
        d.links.filter((l) => l.target_kind === "chain").length;
      return count > 0;
    }
    case "intel": {
      const hasProvenance = !!(
        d.provenance &&
        (d.provenance.agent_name ||
          d.provenance.captured_at ||
          d.provenance.artifact_ref ||
          d.provenance.evidence_quote)
      );
      return (d.references?.length ?? 0) + (hasProvenance ? 1 : 0) > 0;
    }
    default:
      // overview / poc / history are always visible.
      return true;
  }
}

// ProseMode + the prose primitives (CopyChip / SectionHead / Prose / KV /
// ProseModeToggle) now live in ./drawer/DrawerKit and are shared verbatim
// with the Intel + Surface drawers.

function Drawer({
  d,
  derivedBySlug,
  chainsByKey,
  chainMembersByKey,
  transitions,
  transitionsLoading,
  transitionsError,
  onSelect,
  onTabChange,
  initialTab,
  initialTabSlug,
  titleId,
}: DrawerProps) {
  const { toast } = useToast();
  // The drawer-tab for the deep-linked finding. Already validated by the
  // caller against this finding's visible tabs, so an invalid/hidden value
  // never reaches here. Applies only when the current finding IS the
  // deep-linked one (mount OR same-mount re-deep-link); else "overview".
  const deepLinkTab: TabId =
    initialTab && d?.slug === initialTabSlug ? initialTab : "overview";
  const [tab, setTabState] = useState<TabId>(deepLinkTab);
  const [proseMode, setProseMode] = useState<ProseMode>("rendered");
  const [mdCopied, setMdCopied] = useState(false);
  const [linkCopied, setLinkCopied] = useState(false);
  const setTab = (next: TabId) => {
    setTabState(next);
    onTabChange?.(next);
  };
  useEffect(() => {
    // On each finding change, land on the deep-linked tab if this is the
    // deep-linked finding, otherwise reset to "overview". Mirror it up so the
    // URL stays in sync. (deepLinkTab is recomputed per render from the props.)
    setTabState(deepLinkTab);
    onTabChange?.(deepLinkTab);
    // Reset prose mode per finding so a raw-mode toggle doesn't leak across
    // navigations. (onTabChange identity is stable from the parent.)
    setProseMode("rendered");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d?.slug]);

  const linkedFindings = d.links.filter((l) => l.target_kind === "finding");
  const linkedChains = d.links
    .filter((l) => l.target_kind === "chain")
    .map((l) => chainsByKey.get(l.target_ref))
    .filter((c): c is AssessmentAttackChainDetail => Boolean(c));

  // Steps to reproduce moved from Overview to PoC (Issue 3b): the tab
  // count mirrors what PocPane actually renders so the badge stays
  // honest. Count a non-empty steps_to_reproduce array as one section.
  // Non-empty after joining, so an authored block that is only whitespace does
  // not inflate the PoC badge.
  const hasStepsForCount = (d.steps_to_reproduce ?? []).join("").trim().length > 0;
  const pocCount =
    [d.poc_code, d.poc_request, d.poc_response, d.evidence].filter(Boolean)
      .length + (hasStepsForCount ? 1 : 0);
  const codeCount = d.slot_type ? 1 : 0;
  const linksCount = linkedFindings.length + linkedChains.length;
  const historyCount = transitions.length;
  // The Intel tab is VISIBLE when there are references OR any provenance
  // field (so a provenance-only finding still gets the tab). The empty
  // provenance object is dropped here too (fixes VA-004, which used to show
  // an Intel tab for an empty provenance object with no refs).
  const hasProvenance = !!(
    d.provenance &&
    (d.provenance.agent_name ||
      d.provenance.captured_at ||
      d.provenance.artifact_ref ||
      d.provenance.evidence_quote)
  );
  const intelVisible = (d.references?.length ?? 0) > 0 || hasProvenance;
  // The badge counts ONLY references — provenance is a single supplementary
  // block, not an "intel item", so folding it in made the badge misleading
  // (e.g. "Intel 3" for 2 refs + provenance).
  const intelBadge = d.references?.length ?? 0;

  const tabs: { id: TabId; label: string; count?: number; hidden?: boolean }[] = [
    { id: "overview", label: "Overview" },
    // "PoC" rather than "Proof of Concept": the audience knows the acronym
    // and the long label crowds the tab bar at ~1100px.
    { id: "poc", label: "PoC", count: pocCount },
    { id: "code", label: "Code", count: codeCount, hidden: !d.slot_type },
    { id: "links", label: "Links", count: linksCount, hidden: linksCount === 0 },
    { id: "history", label: "History", count: historyCount },
    { id: "intel", label: "Intel", count: intelBadge || undefined, hidden: !intelVisible },
  ];
  const visibleTabs = tabs.filter((t) => !t.hidden);

  const copySlug = () => {
    try {
      void navigator.clipboard?.writeText(d.slug);
      toast("Copied", "success");
    } catch {
      // ignore
    }
  };

  // Copy-finding-as-markdown (reference-project ReportView pattern, adapted to our
  // fields via lib/findingMarkdown). Flips the icon to a Check for 1.5s.
  const copyMarkdown = () => {
    try {
      void navigator.clipboard?.writeText(findingToMarkdown(d));
      setMdCopied(true);
      window.setTimeout(() => setMdCopied(false), 1500);
      toast("Copied finding as Markdown", "success");
    } catch {
      // ignore
    }
  };

  // Copy the deep-link URL. The parent's replaceState effect has already
  // rewritten location.hash to include ?finding={slug}, so window.location.href
  // is the canonical link to this finding's open drawer.
  const copyLink = () => {
    try {
      void navigator.clipboard?.writeText(window.location.href);
      setLinkCopied(true);
      window.setTimeout(() => setLinkCopied(false), 1500);
      toast("Link copied", "success");
    } catch {
      // ignore
    }
  };

  return (
    <aside className="drawer-panel panel">
      <div className={`drawer-hero sev-${d.severity}`}>
        <div className="drawer-top">
          <div className="drawer-slug">
            <span>{d.slug}</span>
            <button
              type="button"
              className="copy-btn"
              onClick={copySlug}
              title="Copy slug"
            >
              <IconCopy />
            </button>
          </div>
          <div className="drawer-header-actions">
            <button
              type="button"
              className="copy-btn"
              onClick={copyMarkdown}
              title="Copy finding as Markdown"
              aria-label="Copy finding as Markdown"
            >
              {mdCopied ? <Check size={13} /> : <Copy size={13} />}
            </button>
            <button
              type="button"
              className="copy-btn"
              onClick={copyLink}
              title="Copy link to this finding"
              aria-label="Copy link to this finding"
            >
              {linkCopied ? <Check size={13} /> : <LinkIcon size={13} />}
            </button>
          </div>
        </div>
        <h2 id={titleId} className="drawer-title">{d.title}</h2>
        <div className="hero-meta">
          <span className={`hero-sev ${d.severity}`}>
            <span className="sev-dot" style={{ background: sevDotColor(d.severity) }} />
            {d.severity}
          </span>
          {d.cvss_score != null && (
            <span className="cvss-chip">
              CVSS <span className="cvss-num">{d.cvss_score.toFixed(1)}</span>
            </span>
          )}
          <span className={`pill pill-${d.workflow_status}`}>{d.workflowLabel}</span>
          {d.verificationKey !== "unreviewed" && (
            <span className={`pill pill-${d.verificationKey}`}>
              {d.verificationLabel}
            </span>
          )}
          {d.code_snapshot_status && d.code_snapshot_status !== "not_applicable" && (
            <span
              className={`pill pill-source-${d.code_snapshot_status}`}
              title="Binding to the repository generation currently under review"
            >
              source {d.code_snapshot_status}
            </span>
          )}
          {hasSubmissionStatus(d.submission_status) && (
            <span
              className={`pill submission-pill submission-${d.submission_status}`}
              title={`External submission: ${d.submissionLabel}`}
            >
              {d.submissionLabel}
            </span>
          )}
          {d.cwe_id && <span className="tag cwe">{d.cwe_id}</span>}
        </div>
      </div>
      <div className="drawer-tabs">
        {visibleTabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`drawer-tab ${tab === t.id ? "is-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count != null && <span className="count">{t.count}</span>}
          </button>
        ))}
        {/* Prose view-mode toggle — a single drawer-wide control (Eye =
            rendered markdown, Code = raw mono <pre>) applied to every prose
            section. Only meaningful on tabs that render prose. */}
        {(tab === "overview" || tab === "poc") && (
          <div className="prose-mode-wrap">
            <span className="prose-mode-label">View</span>
            <ProseModeToggle mode={proseMode} onChange={setProseMode} />
          </div>
        )}
      </div>
      <div className="drawer-body">
        {tab === "overview" && <OverviewPane d={d} proseMode={proseMode} toast={toast} />}
        {tab === "poc" && <PocPane d={d} proseMode={proseMode} toast={toast} />}
        {tab === "code" && <CodePane d={d} toast={toast} />}
        {tab === "links" && (
          <LinksPane
            d={d}
            derivedBySlug={derivedBySlug}
            linkedFindings={linkedFindings}
            linkedChains={linkedChains}
            chainMembersByKey={chainMembersByKey}
            onSelect={(slug) => onSelect(slug)}
          />
        )}
        {tab === "history" && (
          <HistoryPane
            transitions={transitions}
            loading={transitionsLoading}
            error={transitionsError}
          />
        )}
        {tab === "intel" && <IntelPane d={d} toast={toast} />}
      </div>
    </aside>
  );
}

// ── Panes ─────────────────────────────────────────────────────────────
//
// CopyChip / SectionHead / Prose / KV + the ToastFn / ProseMode types are
// imported from ./drawer/DrawerKit (shared with the Intel + Surface drawers).

function OverviewPane({ d, proseMode, toast }: { d: Derived; proseMode: ProseMode; toast: ToastFn }) {
  const additionalDetailKeys = Object.keys(d.details).filter(
    (key) => !KNOWN_DETAIL_KEYS.has(key),
  );
  return (
    <>
      {d.summary && (
        <div className="section">
          <SectionHead title="Summary" copyText={d.summary} toast={toast} />
          <Prose text={d.summary} mode={proseMode} />
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
      {/* Notes is analyst commentary — it belongs near Summary/Impact/
          Remediation, not buried after admin Metadata. Render it right
          after Remediation, ahead of Root Cause Group / Metadata. */}
      {d.notes && (
        <div className="section">
          <SectionHead title="Notes" copyText={d.notes} toast={toast} />
          {/* Notes follow the drawer-wide prose toggle: rendered markdown by
              default, raw mono <pre> when toggled. NotesBody is retained for
              non-drawer usages (e.g. IntelTab). */}
          <Prose text={d.notes} mode={proseMode} />
        </div>
      )}
      {d.root_cause_role && (
        <div className="section root-cause-section">
          <p className="section-title">Root Cause Group</p>
          {d.root_cause_role === "root" ? (
            <p>
              Root finding with {d.sibling_count ?? 0} linked sibling outcomes
              {d.residual_path_count ? `, including ${d.residual_path_count} residual paths` : ""}.
            </p>
          ) : (
            <>
              <p>
                Sibling of <code>{d.root_cause_slug}</code>.{" "}
                {d.root_cause_effect === "eliminates_attack_path"
                  ? "Fixing the root eliminates this attack path, but this finding remains a residual remediation item."
                  : "Fixing the root eliminates this finding."}
              </p>
              {d.root_cause_note && <p className="meta-text">{d.root_cause_note}</p>}
            </>
          )}
        </div>
      )}
      {d.kill_reason && (
        <div className="callout kill">
          <p className="section-title">
            Kill reason · check {d.kill_check ?? "?"}
          </p>
          <p>{d.kill_reason}</p>
        </div>
      )}
      <div className="section">
        <p className="section-title">Metadata</p>
        <div className="kv-grid">
          <KV k="Location" v={d.canonical_location} mono toast={toast} />
          <KV k="Method" v={d.request_method} />
          <KV k="Parameter" v={d.parameter} mono />
          <KV k="Auth context" v={d.auth_context} />
          <KV k="Source" v={d.source_name} />
          <KV k="Discovered by" v={d.discovered_by} mono />
          <KV k="Defect family" v={d.defect_family} />
          <KV k="Dedupe key" v={d.root_cause_key} mono />
          {/* OWASP stays — it's not in the hero. CWE / CVSS score / CVSS
              vector are dropped here: the hero already surfaces cwe_id (tag)
              and cvss_score (cvss-chip), so repeating them is duplication. */}
          <KV k="OWASP" v={d.owasp_category} />
          {d.merged_into_slug && (
            <KV k="Merged into" v={d.merged_into_slug} mono />
          )}
          <KV k="Evidence ref" v={d.evidence_ref} mono />
          <KV k="Source binding" v={d.code_snapshot_status} />
          <KV k="Source repo" v={d.provenance?.code_snapshot?.repo_id} mono />
          <KV k="Source generation" v={d.provenance?.code_snapshot?.repo_generation} mono />
          <KV
            k="Source manifest"
            v={d.provenance?.code_snapshot?.source_manifest_digest}
            mono
            toast={toast}
          />
        </div>
      </div>
      {(d.chain_required !== undefined || d.chain_rationale) && (
        <div className="section">
          <p className="section-title">Chain context</p>
          {d.chain_required !== undefined && (
            <p>
              <span
                className={`pill ${d.chain_required ? "pill-active" : "pill-unreviewed"}`}
              >
                {d.chain_required ? "Chain required" : "Standalone"}
              </span>
            </p>
          )}
          {d.chain_rationale && <p>{d.chain_rationale}</p>}
        </div>
      )}
      {/* Steps to reproduce now live in the Proof of Concept pane so
       * reproduction steps read contiguously with Evidence / Payload /
       * Request / Response. Required follow-up stays here because it's
       * a remediation pointer, not a reproduction artifact. */}
      {d.required_followup && d.required_followup.length > 0 && (
        <div className="section">
          <SectionHead
            title="Required follow-up"
            copyText={d.required_followup.map((s, i) => `${i + 1}. ${s}`).join("\n")}
            toast={toast}
          />
          <ul className="steps">
            {d.required_followup.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
        </div>
      )}
      {(d.variant_of || d.original_pattern) && (
        <div className="section">
          <SectionHead
            title="Variant"
            copyText={d.original_pattern || d.variant_of || ""}
            toast={toast}
          />
          {d.variant_of && (
            <p>
              <span style={{ color: "var(--muted)", fontSize: "0.82rem" }}>
                Variant of:{" "}
              </span>
              <span className="mono">{d.variant_of}</span>
            </p>
          )}
          {d.original_pattern && (
            <pre className="pre">{d.original_pattern}</pre>
          )}
        </div>
      )}
      {additionalDetailKeys.length > 0 && (
        <div className="section">
          <p className="section-title">Additional details</p>
          <div className="json-children">
            {additionalDetailKeys.map((key) => (
              <JsonTree
                key={key}
                label={key}
                value={toJsonValue((d.details as Record<string, unknown>)[key])}
                defaultOpen
              />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function PocPane({ d, proseMode, toast }: { d: Derived; proseMode: ProseMode; toast: ToastFn }) {
  // A single authored block arrives as one element; a list arrives as several.
  // Joining on a newline reproduces either shape as written, so what is copied
  // out of here is byte-identical to what the finding holds.
  const stepsText = (d.steps_to_reproduce ?? []).join("\n").trim();
  const hasSteps = stepsText.length > 0;
  const hasAny =
    hasSteps ||
    d.evidence ||
    d.poc_code ||
    d.poc_request ||
    d.poc_response;
  const pocCodeIsCurl = isCurlLike(d.poc_code);
  const reqText = d.poc_request ? formatHttp(d.poc_request, "req") : "";
  const respText = d.poc_response ? formatHttp(d.poc_response, "resp") : "";

  // Pick a render mode for evidence: raw HTTP exchanges get the mono
  // .pre treatment; short prose gets a compact blockquote; longer
  // prose keeps NotesBody's paragraph layout but inside a callout.
  const ev = (d.evidence || "").trim();
  const looksLikeHttp =
    /^HTTP\/\d\.\d\b/i.test(ev) ||
    /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d/i.test(ev);
  const evidenceMode: "http" | "quote" | "prose" = looksLikeHttp
    ? "http"
    : ev.length > 0 && ev.length < 200 && !ev.includes("\n\n")
    ? "quote"
    : "prose";

  return (
    <>
      {hasSteps && (
        <div className="section">
          {/* Steps render exactly as authored — no imposed counter, no list
              marker. Numbering belongs to whoever wrote the finding: prose in
              Impact or Summary cites step numbers, and an `<ol>` counter would
              disagree with those citations the moment the author's own numbering
              is non-sequential or sub-stepped. `white-space: pre-wrap` keeps the
              line breaks of a single authored block. */}
          <SectionHead title="Steps to reproduce" copyText={stepsText} toast={toast} />
          <div className="steps-verbatim">{stepsText}</div>
        </div>
      )}
      {ev && (
        // Evidence ("how we know") gets a callout so it reads as distinct
        // from Steps-to-reproduce ("how to reproduce"), which keep .section.
        <div className="callout evidence">
          <SectionHead title="Evidence" copyText={ev} toast={toast} />
          {evidenceMode === "http" || proseMode === "raw" ? (
            <pre className="pre resp">{ev}</pre>
          ) : evidenceMode === "quote" ? (
            <blockquote className="evidence-inline">{ev}</blockquote>
          ) : (
            <Prose text={ev} mode={proseMode} />
          )}
        </div>
      )}
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
      {!hasAny && (
        <p className="empty">No proof-of-concept captured for this finding.</p>
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

function LinksPane({
  d,
  derivedBySlug,
  linkedFindings,
  linkedChains,
  chainMembersByKey,
  onSelect,
}: {
  d: Derived;
  derivedBySlug: Map<string, Derived>;
  linkedFindings: DerivedLink[];
  linkedChains: AssessmentAttackChainDetail[];
  chainMembersByKey: Map<string, Derived[]>;
  onSelect: (slug: string) => void;
}) {
  return (
    <>
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
                      {target ? `${target.slug} · ${target.severity}` : "external"}
                    </span>
                  </span>
                  {target && (
                    <span
                      className="sev-dot"
                      style={{ background: sevDotColor(target.severity) }}
                    />
                  )}
                  <span className="link-go">›</span>
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
                  <span
                    className={`hero-sev ${chain.severity}`}
                    style={{ fontSize: "0.7rem", padding: "2px 8px" }}
                  >
                    {chain.severity}
                  </span>
                  <strong style={{ fontSize: "0.94rem" }}>{chain.title}</strong>
                  <span className={`pill pill-${chain.status}`}>{chain.status}</span>
                  <span
                    className="tag"
                    style={{ fontFamily: "'IBM Plex Mono', monospace" }}
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
                            style={{ background: sevDotColor(m.severity) }}
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
    </>
  );
}

function HistoryPane({
  transitions,
  loading,
  error,
}: {
  transitions: AssessmentFindingTransition[];
  loading: boolean;
  error: string | null;
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
      {transitions.map((t) => {
        const isCreation = t.action === "created" || !t.from_workflow_status;
        const sevChanged =
          t.from_severity && t.from_severity !== t.to_severity;
        const workflowChanged =
          t.from_workflow_status && t.from_workflow_status !== t.to_workflow_status;
        const verifChanged =
          t.from_verification_state &&
          t.from_verification_state !== t.to_verification_state;
        return (
          <div key={t.id} className={`tl-row action-${t.action}`}>
            <div className="tl-head">
              <span className="tl-action">{t.action}</span>
              <span className="tl-actor">{t.actor || "system"}</span>
              <span className="tl-time">{relTime(t.created_at)}</span>
            </div>
            <div className="tl-detail">
              {(isCreation || workflowChanged) && (
                <span className="tl-change">
                  <span className="tl-change-label">Workflow</span>
                  {!isCreation && (
                    <>
                      <span className={`pill pill-${t.from_workflow_status}`}>
                        {t.from_workflow_status}
                      </span>
                      <span className="transition-arrow"> → </span>
                    </>
                  )}
                  <span className={`pill pill-${t.to_workflow_status}`}>
                    {t.to_workflow_status}
                  </span>
                </span>
              )}
              {sevChanged && (
                <span className="tl-change">
                  <span className="tl-change-label">Severity</span>
                  <span
                    className={`hero-sev ${t.from_severity}`}
                    style={{ fontSize: "0.65rem", padding: "1px 7px" }}
                  >
                    {t.from_severity}
                  </span>
                  <span className="transition-arrow"> → </span>
                  <span
                    className={`hero-sev ${t.to_severity}`}
                    style={{ fontSize: "0.65rem", padding: "1px 7px" }}
                  >
                    {t.to_severity}
                  </span>
                </span>
              )}
              {verifChanged && (
                <span className="tl-change">
                  <span className="tl-change-label">Verification</span>
                  <span className={`pill pill-${t.from_verification_state}`}>
                    {t.from_verification_state}
                  </span>
                  <span className="transition-arrow"> → </span>
                  <span className={`pill pill-${t.to_verification_state}`}>
                    {t.to_verification_state}
                  </span>
                </span>
              )}
            </div>
            {t.reason_text && (
              <p className="tl-reason">&ldquo;{t.reason_text}&rdquo;</p>
            )}
          </div>
        );
      })}
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
            References <span className="count">{refs.length}</span>
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
            <KV k="Captured" v={prov.captured_at ? relTime(prov.captured_at) : undefined} />
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
      {refs.length === 0 && !hasProvenance && (
        <p className="empty">No intel captured for this finding.</p>
      )}
    </>
  );
}

// ── Command palette ───────────────────────────────────────────────────

function CommandPalette({
  derivedList,
  onSelect,
  onClose,
}: {
  derivedList: Derived[];
  onSelect: (slug: string) => void;
  onClose: () => void;
}) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const results = useMemo(() => {
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
    list.sort(
      (a, b) => (SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99),
    );
    return list.slice(0, 30);
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
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <div className="cmd-box" onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input-row">
          <IconSearch />
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Jump to finding · try 'severity:critical xss' or a slug"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <span className="search-kbd">esc</span>
        </div>
        <div className="cmd-list">
          {results.length === 0 ? (
            <div className="cmd-empty">No findings match.</div>
          ) : (
            results.map((d, i) => (
              <div
                key={d.slug}
                className={`cmd-item ${i === idx ? "is-active" : ""}`}
                onMouseEnter={() => setIdx(i)}
                onClick={() => onSelect(d.slug)}
              >
                <span
                  className="sev-dot"
                  style={{ background: sevDotColor(d.severity) }}
                />
                <span>
                  <div className="cmd-title">{d.title}</div>
                  <div className="cmd-sub">
                    {d.slug} · {d.severity} · {d.cwe_id || ""}
                  </div>
                </span>
                <span className="cmd-sub">{d.canonical_location || ""}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
