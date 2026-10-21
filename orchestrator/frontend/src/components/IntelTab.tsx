// ── IntelTab ──────────────────────────────────────────────────────────
// What Vigil learned about the target, one list across every intel type
// (tech stack, people, emails, domains, credentials, CVEs, DNS, social,
// breaches, org facts, notes and leads). The list filters in the browser
// (type, status per vocabulary, source, search) and sorts by priority
// (active leads first, then newest) or by a column; a full-text search and a
// by-URL lookup ask the server. Each type loads on its own and re-reads when
// the workspace says intel changed. Opening a record replaces the list with
// the shared record view; Back, Escape and browser Back return to the list.

import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import type {
  IntelByUrlResponse,
  IntelEntityType,
  IntelReadiness,
  IntelSearchHit,
  IntelSummary,
  ListIntelResponse,
} from "../lib/api";
import {
  getIntelReadiness,
  intelByUrl,
  listIntel,
  listIntelCredentials,
  searchIntel,
} from "../lib/api";
import { useCoalescedRunner } from "../lib/useCoalescedRequest";
import { useResizableColumns } from "../lib/useResizableColumns";
import { JsonTree } from "./ArtifactViewer";
import { JsonView } from "./JsonView";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { ProvenanceBlock, TimeStamp } from "./formatting";
import { compareServerTime } from "../lib/serverTime";
import {
  KV,
  KVTime,
  ProseModeToggle,
  ProseSection,
  SectionHead,
} from "./drawer/DrawerKit";
import type { ProseMode, ToastFn } from "./drawer/DrawerKit";
import { useToast } from "../contexts/ToastContext";
import { SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FacetChipGroup,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  SortIndicator,
  StatusPill,
  ariaSort,
  describeSort,
  severityColor,
  statusLabel,
  statusOrder,
  type Scope,
  type SortDirection,
  type SortKind,
  type StatusDomain,
} from "./ui";
import {
  RecordBody,
  RecordCopyLinkButton,
  RecordHeader,
  RecordTabs,
  RecordView,
  useResultsScrollMemory,
  type RecordDate,
  type RecordNavigation,
} from "./record/RecordView";
import { listNavigation } from "./record/recordNavigation";
import "../styles/intel.css";

// ── Props ────────────────────────────────────────────────────────────
type IntelTabProps = {
  engagementKey: string;
  summary: IntelSummary | null;
  /** Bumped by the workspace when intel changed; a change re-reads the records in the background. */
  refreshVersion?: number;
  initialIntelType?: string;
  initialIntelId?: number;
  initialDrawerTab?: string;
};

// ── Entity types ─────────────────────────────────────────────────────
type EntityFilter = IntelEntityType | "credentials";

type FilterSpec = {
  key: EntityFilter;
  summaryKey?: string;
  label: string;
  singular: string;
};

// Ordering mirrors the original sidebar in §3a.
const ENTITY_FILTERS: FilterSpec[] = [
  { key: "tech_component", summaryKey: "tech_components", label: "Tech stack", singular: "tech component" },
  { key: "person", summaryKey: "people", label: "People", singular: "person" },
  { key: "email", summaryKey: "emails", label: "Emails", singular: "email" },
  { key: "domain", summaryKey: "domains", label: "Domains", singular: "domain" },
  { key: "credentials", label: "Credentials", singular: "credential" },
  { key: "cve", summaryKey: "cves", label: "CVEs", singular: "CVE" },
  { key: "dns_record", summaryKey: "dns_records", label: "DNS", singular: "DNS record" },
  { key: "social_profile", summaryKey: "social_profiles", label: "Social", singular: "social profile" },
  { key: "breach_record", summaryKey: "breach_records", label: "Breach", singular: "breach record" },
  { key: "org_fact", summaryKey: "org_facts", label: "Org", singular: "org fact" },
  { key: "note", summaryKey: "notes", label: "Notes", singular: "note" },
];

function isEntityFilter(value: string | undefined): value is EntityFilter {
  return Boolean(value && ENTITY_FILTERS.some((spec) => spec.key === value));
}

const ENTITY_LABEL = new Map<string, string>(
  ENTITY_FILTERS.map((spec) => [spec.key, spec.label]),
);

const PAGE_SIZE = 40;
// A burst of intel events re-reads the ledger at most this often (with a trailing read).
const LIVE_REFRESH_MIN_MS = 5000;

// The list's order: priority (active leads first, then most recently
// updated) unless the operator sorts by a column.
type IntelSortKey = "priority" | "type" | "title" | "location" | "status";
type IntelSort = { key: IntelSortKey; dir: SortDirection };
const PRIORITY_SORT: IntelSort = { key: "priority", dir: "desc" };
const SORT_COLUMNS: Record<Exclude<IntelSortKey, "priority">, { label: string; kind: SortKind }> = {
  type: { label: "Type", kind: "text" },
  title: { label: "Title", kind: "text" },
  location: { label: "Location", kind: "text" },
  status: { label: "Status", kind: "status" },
};

// Column widths for the Intel list. Order matches the columns rendered
// in the list-header / IntelRow below: [sev-bar, type, title, location,
// tags, status]. Persisted under its own key so the Findings and Intel
// tabs don't trample each other.
const INTEL_LIST_DEFAULTS = [10, 110, 320, 200, 180, 130];
const INTEL_LIST_MINS = [8, 80, 200, 120, 140, 100];

// Severity-ish palette reused for CVE chips (CVSS buckets) and credential
// status. These are purely visual; we map to the same pill/hero-sev classes
// the Findings tab uses so colors stay consistent.
function cvssBucket(score: number | null | undefined): string | null {
  if (score == null) return null;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

// Per-entity accent colors used when a row has no CVSS-derived severity
// (i.e. everything except CVE). Keeps the Intel list visually distinguishable
// by category instead of painting every row the default gray.
const ITYPE_COLORS: Record<string, string> = {
  tech_component: "var(--chip-navy)",
  person: "var(--chip-purple)",
  email: "var(--chip-green)",
  domain: "var(--chip-teal)",
  credentials: "var(--chip-orange)",
  cve: "var(--chip-red)",
  dns_record: "var(--chip-slate)",
  social_profile: "var(--chip-pink)",
  breach_record: "var(--chip-maroon)",
  org_fact: "var(--chip-ochre)",
  note: "var(--chip-muted)",
};

// Each type's status speaks its own vocabulary (components/ui/statusTones):
// a lead's status, a CVE's validation, a technology's confidence, a domain's
// liveness, a credential's state. They are filtered and labelled per
// vocabulary, never mixed in one row of chips.
const STATUS_GROUPS: { domain: StatusDomain; label: string }[] = [
  { domain: "intel-lead", label: "Lead status" },
  { domain: "intel-cve", label: "CVE validation" },
  { domain: "intel-confidence", label: "Confidence" },
  { domain: "liveness", label: "Liveness" },
  { domain: "credential", label: "Credential state" },
];

/** Status filter key: the vocabulary and the value (`intel-lead:open`). */
function statusKey(domain: StatusDomain, value: string): string {
  return `${domain}:${value}`;
}

// ── Helpers ──────────────────────────────────────────────────────────
function fmtCell(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function truncate(text: string, max: number): string {
  if (!text) return "";
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

/** An http(s) address, the only scheme rendered as a link (ADR 0018). */
function isWebUrl(value: unknown): value is string {
  return typeof value === "string" && /^https?:\/\//i.test(value);
}

function extractHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

// ── JsonTree value safety ────────────────────────────────────────────
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

// ── Search tokenizer ─────────────────────────────────────────────────
const SCOPES = [
  "type",
  "kind",
  "source",
  "agent",
  "status",
  "host",
  "value",
  "component",
  "confidence",
  "platform",
  "cve",
  "cvss",
  "cwe",
  "record",
  "tag",
] as const;
type QueryScope = (typeof SCOPES)[number];

type ParsedQuery = {
  tokens: { scope: QueryScope; value: string }[];
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
        tokens.push({ scope: scope as QueryScope, value: tok.slice(idx + 1).toLowerCase() });
        continue;
      }
    }
    freeTerms.push(tok.toLowerCase());
  }
  return { tokens, freeTerms };
}

// ── Derived row (per entity) ─────────────────────────────────────────
type Derived = {
  id: string; // stable React key — entity:key or entity:index
  entity: EntityFilter;
  entityLabel: string;
  title: string;
  subtitle: string;
  location: string;
  status: string | null;
  /** The vocabulary `status` belongs to (lead status, CVE validation, confidence, liveness, credential state). */
  statusDomain: StatusDomain | null;
  sev: string | null; // sev-* tier for coloring, or null
  sevLabel: string | null;
  source: string;
  host: string;
  tags: string[];
  updated_at: string;
  created_at: string;
  // Populated when the row was superseded via `vigil assess supersede-intel`.
  // The IntelRow uses this to render the row distinctly (struck-through, badge).
  supersededById: number | null;
  supersededAt: string | null;
  raw: Record<string, unknown>;
  searchCorpus: string;
};

// Determine the intel type label (used as the "type:" filter key & chip).
function entityTypeSlug(e: EntityFilter): string {
  // normalized lowercase single-word tokens for scope matching
  switch (e) {
    case "tech_component":
      return "tech";
    case "person":
      return "person";
    case "email":
      return "email";
    case "domain":
      return "domain";
    case "credentials":
      return "credential";
    case "cve":
      return "cve";
    case "dns_record":
      return "dns";
    case "social_profile":
      return "social";
    case "breach_record":
      return "breach";
    case "org_fact":
      return "org";
    case "note":
      return "note";
  }
}

function activeLeadRank(d: Derived): number {
  if (d.entity !== "note") return 2;
  if (d.status === "in_progress") return 0;
  if (d.status === "open") return 1;
  return 2;
}

function derive(entity: EntityFilter, raw: Record<string, unknown>, index: number): Derived {
  const id = `${entity}:${raw.id ?? raw.identity ?? raw.address ?? raw.cve_id ?? raw.name ?? index}`;
  const source = (raw.source_name as string) || "";
  const provenance = (raw.provenance as Record<string, unknown>) || {};
  const agent = (provenance.agent_name as string) || "";
  const tags: string[] = [];
  let title = "";
  let subtitle = "";
  let location = "";
  let status: string | null = null;
  let statusDomain: StatusDomain | null = null;
  let sev: string | null = null;
  let sevLabel: string | null = null;
  let host = "";

  switch (entity) {
    case "tech_component": {
      const component = (raw.component as string) || "";
      const version = (raw.version as string) || "";
      title = version ? `${component} ${version}` : component;
      subtitle = (raw.evidence_ref as string) || "";
      location = (raw.evidence_ref as string) || "";
      const conf = (raw.confidence as string) || "";
      status = conf || null;
      statusDomain = conf ? "intel-confidence" : null;
      break;
    }
    case "person": {
      const name = (raw.name as string) || "";
      const role = (raw.role as string) || "";
      const org = (raw.organization as string) || "";
      title = name;
      subtitle = [role, org].filter(Boolean).join(" · ");
      location = (raw.email as string) || "";
      break;
    }
    case "email": {
      title = (raw.address as string) || "";
      subtitle = (raw.role_hint as string) || "";
      location = title;
      host = title.includes("@") ? title.slice(title.indexOf("@") + 1) : "";
      break;
    }
    case "domain": {
      title = (raw.identity as string) || (raw.value as string) || "";
      const kind = (raw.kind as string) || "";
      const value = (raw.value as string) || "";
      subtitle = [kind, value].filter(Boolean).join(" · ");
      location = value || title;
      host = title;
      const live = (raw.live_status as string) || "";
      status = live || null;
      statusDomain = live ? "liveness" : null;
      if (kind) tags.push(kind);
      break;
    }
    case "credentials": {
      const identity = (raw.identity as string) || (raw.username as string) || "";
      const endpoint =
        (raw.endpoint as string) ||
        (raw.target_descriptor as string) ||
        (raw.host as string) ||
        "";
      title = identity || endpoint || "credential";
      subtitle = endpoint && identity ? endpoint : "";
      location = endpoint;
      host = endpoint ? extractHost(endpoint) || endpoint : "";
      const st =
        (raw.status as string) || (raw.state as string) || (raw.disposition as string) || "";
      status = st || null;
      statusDomain = st ? "credential" : null;
      const secretKind = (raw.secret_kind as string) || (raw.kind as string) || "";
      if (secretKind) tags.push(secretKind);
      break;
    }
    case "cve": {
      const cveId = (raw.cve_id as string) || "";
      const component = (raw.affected_component as string) || "";
      const vRange = (raw.affected_version_range as string) || "";
      title = cveId;
      subtitle = [component, vRange].filter(Boolean).join(" ");
      location = component;
      const score = (raw.cvss_score as number | null) ?? null;
      sev = cvssBucket(score);
      sevLabel = score != null ? `CVSS ${score.toFixed(1)}` : null;
      const valStatus = (raw.validation_status as string) || "";
      status = valStatus || null;
      statusDomain = valStatus ? "intel-cve" : null;
      if (cveId) tags.push(cveId);
      const cwe = (raw.cwe_id as string) || "";
      if (cwe) tags.push(cwe);
      if ((raw.poc_available as boolean) === true) tags.push("PoC");
      break;
    }
    case "dns_record": {
      const recType = (raw.record_type as string) || "";
      const name = (raw.name as string) || "";
      const value = (raw.value as string) || "";
      title = name;
      subtitle = [recType, value].filter(Boolean).join(" ");
      location = value;
      host = name;
      if (recType) tags.push(recType);
      break;
    }
    case "social_profile": {
      const platform = (raw.platform as string) || "";
      const handle = (raw.handle as string) || "";
      title = handle ? `${platform ? platform + ":" : ""}${handle}` : platform;
      subtitle = (raw.subject_ref as string) || "";
      location = (raw.url as string) || "";
      host = location ? extractHost(location) : "";
      if (platform) tags.push(platform);
      const subjectKind = (raw.subject_kind as string) || "";
      if (subjectKind) tags.push(subjectKind);
      break;
    }
    case "breach_record": {
      title = (raw.breach_name as string) || "";
      subtitle = (raw.subject as string) || "";
      location = (raw.breach_date as string) || "";
      const dataTypes = (raw.data_types as string) || "";
      if (dataTypes) tags.push(dataTypes);
      break;
    }
    case "org_fact": {
      title = (raw.fact_key as string) || "";
      subtitle = (raw.fact_value as string) || "";
      break;
    }
    case "note": {
      title = (raw.title as string) || "";
      subtitle = truncate((raw.body_markdown as string) || "", 160);
      const leadStatus = (raw.lead_status as string) || "";
      status = leadStatus || null;
      statusDomain = leadStatus ? "intel-lead" : null;
      const sourceAgent = (raw.source_agent as string) || "";
      if (sourceAgent) tags.push(sourceAgent);
      const raw_tags = raw.tags;
      if (Array.isArray(raw_tags)) {
        for (const t of raw_tags) if (typeof t === "string") tags.push(t);
      }
      break;
    }
  }

  const updated_at = (raw.updated_at as string) || (raw.last_seen as string) || "";
  const created_at = (raw.created_at as string) || (raw.first_seen as string) || "";

  const corpusParts: (string | undefined)[] = [
    title,
    subtitle,
    location,
    status || "",
    status && statusDomain ? statusLabel(statusDomain, status) : "",
    sev || "",
    source,
    agent,
    host,
    ...tags,
    entityTypeSlug(entity),
    JSON.stringify(raw),
  ];

  const supersededByRaw = raw.superseded_by_id;
  const supersededById =
    typeof supersededByRaw === "number" && Number.isFinite(supersededByRaw)
      ? supersededByRaw
      : null;
  const supersededAt =
    typeof raw.superseded_at === "string" && raw.superseded_at ? (raw.superseded_at as string) : null;

  return {
    id,
    entity,
    entityLabel: ENTITY_LABEL.get(entity) || entity,
    title: title || "(untitled)",
    subtitle,
    location,
    status,
    statusDomain,
    sev,
    sevLabel,
    source,
    host,
    // A tag can arrive twice (the source agent is often also a tag).
    tags: tags.filter((tag, index) => tags.findIndex((other) => other.toLowerCase() === tag.toLowerCase()) === index),
    updated_at,
    created_at,
    supersededById,
    supersededAt,
    raw,
    searchCorpus: corpusParts.filter(Boolean).join(" \n ").toLowerCase(),
  };
}

// ── Sorting ──────────────────────────────────────────────────────────

/** Urgency order: by vocabulary (lead, CVE, confidence, liveness, credential), then lifecycle; none last. */
function statusRank(d: Derived): number | null {
  if (!d.statusDomain || !d.status) return null;
  const group = STATUS_GROUPS.findIndex((entry) => entry.domain === d.statusDomain);
  const order = statusOrder(d.statusDomain);
  const index = order.indexOf(d.status);
  return group * 100 + (index < 0 ? order.length : index);
}

function compareIntel(sort: IntelSort): (a: Derived, b: Derived) => number {
  const newest = (a: Derived, b: Derived) => compareServerTime(a.updated_at || a.created_at, b.updated_at || b.created_at, "desc");
  return (a, b) => {
    if (sort.key === "priority") {
      // Active leads are the operator's current work queue; keep them first
      // without filtering out reference notes or historical knowledge.
      return activeLeadRank(a) - activeLeadRank(b) || newest(a, b) || a.title.localeCompare(b.title);
    }
    let delta = 0;
    if (sort.key === "type") delta = a.entityLabel.localeCompare(b.entityLabel);
    else if (sort.key === "title") delta = a.title.localeCompare(b.title, undefined, { sensitivity: "base" });
    else if (sort.key === "location") delta = (a.location || "\uffff").localeCompare(b.location || "\uffff");
    else if (sort.key === "status") {
      const rankA = statusRank(a);
      const rankB = statusRank(b);
      // Records without a status sort last in both directions.
      if ((rankA === null) !== (rankB === null)) return rankA === null ? 1 : -1;
      // Ascending runs from the least urgent; descending puts the most urgent first.
      delta = (rankB ?? 0) - (rankA ?? 0);
    }
    if (sort.dir === "desc") delta = -delta;
    return delta || newest(a, b) || a.title.localeCompare(b.title);
  };
}

function describeIntelSort(sort: IntelSort): string {
  if (sort.key === "priority") return "Priority, active leads first, then most recently updated";
  const column = SORT_COLUMNS[sort.key];
  return describeSort(column.label, sort.dir, column.kind);
}

// ── Highlight helper ─────────────────────────────────────────────────
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

// ── Icons ────────────────────────────────────────────────────────────
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
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" width={11} height={11}>
    <path d="M14 4h6v6" />
    <path d="M10 14L21 3" />
    <path d="M19 14v6H4V4h6" />
  </svg>
);
// ── Saved view ───────────────────────────────────────────────────────
// Scope, search, filters and sort survive leaving the tab (sessionStorage,
// per engagement).

const ATTENTION_RULE = "Open leads: current (not superseded) notes whose lead status is open or in progress.";

/** A lead still to follow up: the readiness rule for open leads. */
function isOpenLead(d: Derived): boolean {
  return d.entity === "note" && d.supersededById == null && (d.status === "open" || d.status === "in_progress");
}

type IntelView = {
  scope: Scope;
  query: string;
  entity: EntityFilter[];
  status: string[];
  source: string[];
  hideSuperseded: boolean;
  sort: IntelSort;
};

const viewKey = (engagementKey: string) => `intel.view.${engagementKey}`;
const SORT_KEYS: readonly IntelSortKey[] = ["priority", "type", "title", "location", "status"];

function readView(engagementKey: string): IntelView {
  const strings = (value: unknown) => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : []);
  let value: Record<string, unknown> = {};
  try {
    value = JSON.parse(window.sessionStorage.getItem(viewKey(engagementKey)) || "{}") as Record<string, unknown>;
  } catch {
    // Browser storage may be unavailable or hold something else; start fresh.
  }
  const sort = (value.sort ?? {}) as Record<string, unknown>;
  return {
    scope: value.scope === "attention" ? "attention" : "all",
    query: typeof value.query === "string" ? value.query : "",
    entity: strings(value.entity).filter(isEntityFilter),
    status: strings(value.status),
    source: strings(value.source),
    hideSuperseded: value.hideSuperseded === true,
    sort: SORT_KEYS.includes(sort.key as IntelSortKey) && (sort.dir === "asc" || sort.dir === "desc")
      ? { key: sort.key as IntelSortKey, dir: sort.dir }
      : PRIORITY_SORT,
  };
}

// ── Component ────────────────────────────────────────────────────────
export function IntelTab(props: IntelTabProps) {
  // Each engagement keeps its own caches and saved view.
  return <IntelWorkspace key={props.engagementKey} {...props} />;
}

function IntelWorkspace({
  engagementKey,
  summary,
  refreshVersion,
  initialIntelType,
  initialIntelId,
  initialDrawerTab,
}: IntelTabProps) {
  // Per-entity caches: each type loads, and refreshes, on its own.
  const [cache, setCache] = useState<Map<EntityFilter, Record<string, unknown>[]>>(
    () => new Map(),
  );
  // Types whose first read has not answered yet.
  const [loading, setLoading] = useState<Set<EntityFilter>>(() => new Set(ENTITY_FILTERS.map((spec) => spec.key)));
  const [errors, setErrors] = useState<Map<EntityFilter, string>>(new Map());
  const [readiness, setReadiness] = useState<IntelReadiness | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);

  const [savedView] = useState(() => readView(engagementKey));
  const [scope, setScope] = useState<Scope>(savedView.scope);
  const [query, setQuery] = useState(savedView.query);
  const [entityFilters, setEntityFilters] = useState<Set<EntityFilter>>(() => new Set(savedView.entity));
  // `${vocabulary}:${value}` keys (statusKey), so equal values of different vocabularies stay apart.
  const [statusFilters, setStatusFilters] = useState<Set<string>>(() => new Set(savedView.status));
  const [sourceFilters, setSourceFilters] = useState<Set<string>>(() => new Set(savedView.source));
  const [sort, setSort] = useState<IntelSort>(savedView.sort);
  const [page, setPage] = useState(0);
  const [cmdOpen, setCmdOpen] = useState(false);
  const commandInvokerRef = useRef<HTMLElement | null>(null);
  // When true, rows whose ``superseded_by_id`` is set are filtered out
  // client-side. Default off so the audit trail remains visible by default;
  // operators flip this on to mirror the report-writer view.
  const [hideSuperseded, setHideSuperseded] = useState(savedView.hideSuperseded);
  useEffect(() => {
    const view: IntelView = {
      scope,
      query,
      entity: [...entityFilters],
      status: [...statusFilters],
      source: [...sourceFilters],
      hideSuperseded,
      sort,
    };
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(view));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, scope, query, entityFilters, statusFilters, sourceFilters, hideSuperseded, sort]);

  // Secondary lookups (full-text search + by-URL).
  const [fts, setFts] = useState<IntelSearchHit[] | null>(null);
  const [ftsQuery, setFtsQuery] = useState("");
  const [ftsError, setFtsError] = useState<string | null>(null);
  const [ftsLoading, setFtsLoading] = useState(false);
  const [ftsVisibleCount, setFtsVisibleCount] = useState(PAGE_SIZE);

  const [urlQuery, setUrlQuery] = useState("");
  const [urlResults, setUrlResults] = useState<IntelByUrlResponse | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);

  // `selectedId` is the highlighted row (j / k move it); `detailOpen` says
  // whether its record replaces the list.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [recordTab, setRecordTab] = useState<IntelRecordTab>(isIntelRecordTab(initialDrawerTab) ? initialDrawerTab : "overview");
  // Each row's open button (the row's focus target).
  const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  // The element that opened the record; focus returns to it on Back.
  const invokerRef = useRef<HTMLElement | null>(null);
  const appliedRouteRecordRef = useRef<string | null>(null);

  // Column widths for the Intel list. Separate storage key from the
  // Findings list so the two don't collide.
  const {
    widths: listWidths,
    startResize: startListResize,
    resetColumn: resetListColumn,
  } = useResizableColumns(
    "intel.col-widths",
    INTEL_LIST_DEFAULTS,
    INTEL_LIST_MINS,
  );
  // The title column takes the room the others leave (never below its set width).
  const listGridTemplate = listWidths
    .map((width, index) => (index === 2 ? `minmax(${width}px, 1fr)` : `${width}px`))
    .join(" ");

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Each type loads on its own (a slow or failing type never holds up the
  // rest). Every load goes through one coalesced runner (lib/coalesce): a
  // refresh that arrives while a pass runs queues exactly one more pass after
  // it, so a burst never cancels the pass in flight. Each answer clears its
  // type's loading mark whichever pass it belongs to; rows already shown stay
  // until their type answers.
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  const runLoad = useCoalescedRunner(useCallback(async () => {
    const key = engagementKey;
    const current = () => mountedRef.current;
    const reads = ENTITY_FILTERS.map((spec) => {
      const read: Promise<Record<string, unknown>[]> =
        spec.key === "credentials"
          ? listIntelCredentials(key)
          : listIntel(key, spec.key as IntelEntityType).then(
              (payload: ListIntelResponse) => payload.items as unknown as Record<string, unknown>[],
            );
      return read
        .then((items) => {
          if (!current()) return;
          setCache((prev) => new Map(prev).set(spec.key, items));
          setErrors((prev) => {
            if (!prev.has(spec.key)) return prev;
            const next = new Map(prev);
            next.delete(spec.key);
            return next;
          });
        })
        .catch((err: unknown) => {
          if (!current()) return;
          // A failed refresh keeps the rows already shown; a failed first read shows none.
          setCache((prev) => (prev.has(spec.key) ? prev : new Map(prev).set(spec.key, [])));
          setErrors((prev) => new Map(prev).set(spec.key, err instanceof Error ? err.message : "Failed to load"));
        })
        .finally(() => {
          if (!current()) return;
          setLoading((prev) => {
            if (!prev.has(spec.key)) return prev;
            const next = new Set(prev);
            next.delete(spec.key);
            return next;
          });
        });
    });
    const readinessRead = getIntelReadiness(key)
      .then((payload) => {
        if (!current()) return;
        setReadiness(payload);
        setReadinessError(null);
      })
      .catch((err: unknown) => {
        if (current()) setReadinessError(err instanceof Error ? err.message : "Readiness unavailable");
      });
    await Promise.allSettled([...reads, readinessRead]);
  }, [engagementKey]));

  // The first load; StrictMode's repeated mount joins the pass in flight.
  useEffect(() => {
    void runLoad("join");
  }, [runLoad]);

  // Live refresh: a burst of intel events re-reads at most once per
  // LIVE_REFRESH_MIN_MS, with a trailing read; the runner coalesces a signal
  // that lands while a pass runs.
  const refreshTimerRef = useRef(0);
  const lastRefreshRef = useRef(0);
  const firstRefreshVersion = useRef(refreshVersion);
  useEffect(() => {
    if (refreshVersion === firstRefreshVersion.current || refreshTimerRef.current) return;
    const fire = () => {
      refreshTimerRef.current = 0;
      lastRefreshRef.current = Date.now();
      void runLoad("refresh");
    };
    const wait = lastRefreshRef.current + LIVE_REFRESH_MIN_MS - Date.now();
    if (wait <= 0) fire();
    else refreshTimerRef.current = window.setTimeout(fire, wait);
  }, [refreshVersion, runLoad]);
  useEffect(() => () => window.clearTimeout(refreshTimerRef.current), []);

  // Derived list across all entities. A refresh replaces one type's rows at a
  // time; only that type is derived again.
  const derivedByRows = useRef(new WeakMap<Record<string, unknown>[], Derived[]>());
  const derivedList = useMemo<Derived[]>(() => {
    const out: Derived[] = [];
    for (const spec of ENTITY_FILTERS) {
      const rows = cache.get(spec.key);
      if (!rows) continue;
      let derived = derivedByRows.current.get(rows);
      if (!derived) {
        derived = rows.map((row, i) => derive(spec.key, row, i));
        derivedByRows.current.set(rows, derived);
      }
      out.push(...derived);
    }
    return out;
  }, [cache]);

  const derivedById = useMemo(() => {
    const m = new Map<string, Derived>();
    for (const d of derivedList) m.set(d.id, d);
    return m;
  }, [derivedList]);

  // The URL names the open record (`intel_type` + `intel_id`) and its
  // section (`dtab`). A record without a stored id cannot be linked to, so it
  // opens without a route.
  const writeIntelHash = useCallback((record?: Derived, tab?: IntelRecordTab) => {
    const routable = record !== undefined && record.raw.id != null;
    writeWorkspaceHash(engagementHref(engagementKey, {
      tab: "intel",
      intel_type: routable ? record.entity : undefined,
      intel_id: routable ? String(record.raw.id) : undefined,
      dtab: routable && tab && tab !== "overview" ? tab : undefined,
    }));
  }, [engagementKey]);

  const detailOpenRef = useRef(detailOpen);
  detailOpenRef.current = detailOpen;
  const recordTabRef = useRef(recordTab);
  recordTabRef.current = recordTab;

  // Opening from the results remembers the opener for the return trip and
  // starts on Overview; moving between records while one is open (Previous /
  // Next, j / k, the palette) keeps the open section when the next record has it.
  const openRecord = useCallback((record: Derived, invoker?: HTMLElement | null) => {
    const stepping = detailOpenRef.current;
    if (!stepping) {
      const active = document.activeElement;
      invokerRef.current = invoker
        ?? (active instanceof HTMLElement && active !== document.body ? active : null)
        ?? searchRef.current;
    }
    const tab = stepping && intelTabVisible(record, recordTabRef.current) ? recordTabRef.current : "overview";
    // A record without a stored id has no link: the URL leaving the routed
    // record must not close it.
    if (record.raw.id == null) appliedRouteRecordRef.current = null;
    setSelectedId(record.id);
    setRecordTab(tab);
    setDetailOpen(true);
    writeIntelHash(record, tab);
  }, [writeIntelHash]);

  const closeRecord = useCallback(() => {
    setDetailOpen(false);
    appliedRouteRecordRef.current = null;
    writeIntelHash();
  }, [writeIntelHash]);

  const chooseRecordTab = useCallback((next: IntelRecordTab) => {
    setRecordTab(next);
    const record = selectedId ? derivedById.get(selectedId) : undefined;
    if (record) writeIntelHash(record, next);
  }, [derivedById, selectedId, writeIntelHash]);

  const openHydratedRecord = useCallback((entity: IntelEntityType, raw: Record<string, unknown>, invoker?: HTMLElement | null) => {
    const sourceId = raw.id;
    const currentRows = cache.get(entity) || [];
    const existing = currentRows.find((row) => row.id === sourceId);
    const hydrated = { ...(existing || {}), ...raw };
    const record = derive(entity, hydrated, currentRows.length);
    setCache((prev) => {
      const next = new Map(prev);
      const rows = next.get(entity) || [];
      const index = rows.findIndex((row) => row.id === sourceId);
      if (index >= 0) {
        const updated = [...rows];
        updated[index] = { ...updated[index], ...raw };
        next.set(entity, updated);
      } else {
        next.set(entity, [...rows, raw]);
      }
      return next;
    });
    openRecord(record, invoker);
  }, [cache, openRecord]);

  useEffect(() => {
    if (!isEntityFilter(initialIntelType) || initialIntelId == null) {
      if (appliedRouteRecordRef.current !== null) {
        appliedRouteRecordRef.current = null;
        setDetailOpen(false);
      }
      return;
    }
    const key = intelRouteKey(initialIntelType, initialIntelId);
    if (appliedRouteRecordRef.current === key) return;
    const target = derivedById.get(key);
    if (!target) {
      // The link names a record the ledger does not hold (or not yet): the
      // record on screen no longer answers it, so the results show instead.
      if (detailOpenRef.current) setDetailOpen(false);
      appliedRouteRecordRef.current = null;
      return;
    }
    if (!detailOpenRef.current) invokerRef.current = rowRefs.current.get(target.id) ?? searchRef.current;
    appliedRouteRecordRef.current = key;
    setSelectedId(target.id);
    setCmdOpen(false);
    setDetailOpen(true);
  }, [initialIntelType, initialIntelId, derivedById]);
  useEffect(() => {
    setRecordTab(isIntelRecordTab(initialDrawerTab) ? initialDrawerTab : "overview");
  }, [initialDrawerTab]);

  // Filtering.
  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (d: Derived, parsed: ParsedQuery): boolean => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "type":
            if (entityTypeSlug(d.entity) !== v && d.entity !== (v as EntityFilter)) return false;
            break;
          case "kind": {
            const kind = fmtCell(d.raw.kind).toLowerCase();
            if (!kind.includes(v)) return false;
            break;
          }
          case "source":
            if (!d.source.toLowerCase().includes(v)) return false;
            break;
          case "agent": {
            const prov = (d.raw.provenance as Record<string, unknown>) || {};
            const agent = fmtCell(prov.agent_name).toLowerCase();
            const sourceAgent = fmtCell(d.raw.source_agent).toLowerCase();
            if (!agent.includes(v) && !sourceAgent.includes(v)) return false;
            break;
          }
          case "status":
            if ((d.status || "").toLowerCase() !== v && !(d.status || "").toLowerCase().includes(v)) return false;
            break;
          case "host":
            if (!d.host.toLowerCase().includes(v)) return false;
            break;
          case "value": {
            const value = fmtCell(d.raw.value).toLowerCase();
            if (!value.includes(v)) return false;
            break;
          }
          case "component": {
            const component = fmtCell(d.raw.component).toLowerCase();
            const affected = fmtCell(d.raw.affected_component).toLowerCase();
            if (!component.includes(v) && !affected.includes(v)) return false;
            break;
          }
          case "confidence":
            if (!fmtCell(d.raw.confidence).toLowerCase().includes(v)) return false;
            break;
          case "platform":
            if (!fmtCell(d.raw.platform).toLowerCase().includes(v)) return false;
            break;
          case "cve":
            if (!fmtCell(d.raw.cve_id).toLowerCase().includes(v)) return false;
            break;
          case "cvss": {
            const score = d.raw.cvss_score;
            if (typeof score !== "number") return false;
            const bucket = cvssBucket(score);
            if (bucket !== v && String(score) !== v) return false;
            break;
          }
          case "cwe":
            if (!fmtCell(d.raw.cwe_id).toLowerCase().includes(v)) return false;
            break;
          case "record":
            if (!fmtCell(d.raw.record_type).toLowerCase().includes(v)) return false;
            break;
          case "tag":
            if (!d.tags.map((t) => t.toLowerCase()).some((t) => t.includes(v))) return false;
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

  // Search and the superseded switch narrow everything; each chip group then
  // counts the rows the OTHER groups leave, so a chip never offers a value
  // that cannot match. Statuses OR together across vocabularies.
  const searched = useMemo(
    () => derivedList.filter((d) => (scope === "all" || isOpenLead(d))
      && !(hideSuperseded && d.supersededById != null)
      && matchesQuery(d, parsedQuery)),
    [derivedList, scope, hideSuperseded, parsedQuery, matchesQuery],
  );
  const passes = useCallback((d: Derived, skip: "entity" | "status" | "source" | null) => (
    (skip === "entity" || !entityFilters.size || entityFilters.has(d.entity))
    && (skip === "status" || !statusFilters.size
      || (d.statusDomain !== null && d.status !== null && statusFilters.has(statusKey(d.statusDomain, d.status))))
    && (skip === "source" || !sourceFilters.size || sourceFilters.has(d.source))
  ), [entityFilters, statusFilters, sourceFilters]);
  const filtered = useMemo(() => {
    const list = searched.filter((d) => passes(d, null));
    list.sort(compareIntel(sort));
    return list;
  }, [searched, passes, sort]);

  // Reset page when filters change.
  useEffect(() => {
    setPage(0);
  }, [scope, entityFilters, statusFilters, sourceFilters, hideSuperseded, query, sort]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  useEffect(() => {
    setPage((p) => Math.min(p, totalPages - 1));
  }, [totalPages]);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // The page follows the highlighted row: j / k, [ / ], the palette and a
  // record's Previous / Next can move past the shown page.
  const filteredRef = useRef(filtered);
  filteredRef.current = filtered;
  const showRow = useCallback((id: string) => {
    const index = filteredRef.current.findIndex((d) => d.id === id);
    if (index >= 0) setPage(Math.floor(index / PAGE_SIZE));
  }, []);
  useEffect(() => {
    if (selectedId) showRow(selectedId);
  }, [selectedId, showRow]);
  useEffect(() => {
    if (!selectedId || detailOpen) return;
    rowRefs.current.get(selectedId)?.scrollIntoView?.({ block: "nearest" });
  }, [selectedId, page, detailOpen]);

  // Keep selection valid — if the record leaves the ledger, fall through to
  // the first row. Nothing opens on mount without a route.
  useEffect(() => {
    if (selectedId && !derivedById.has(selectedId)) {
      setSelectedId(derivedList[0]?.id ?? null);
      setDetailOpen(false);
    }
  }, [derivedList, derivedById, selectedId]);

  const selectedDerived = selectedId ? derivedById.get(selectedId) ?? null : null;
  const investigating = detailOpen && selectedDerived !== null;

  // Previous / Next walk the results as shown: current filters, the list's
  // order, across every page. Each entity type loads on its own, so until
  // every one has arrived the record's place in the results is not known.
  const reviewIds = useMemo(() => filtered.map((d) => d.id), [filtered]);
  const stepToRecord = useCallback((id: string) => {
    const record = derivedById.get(id);
    if (record) openRecord(record);
  }, [derivedById, openRecord]);
  const reviewNavigation: RecordNavigation = loading.size > 0
    ? { index: undefined, total: undefined, pending: true }
    : listNavigation(reviewIds, selectedId, stepToRecord);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  // Back to results lands on the record last shown, on its page.
  useResultsScrollMemory(resultsRef, investigating, { recordKey: investigating ? selectedId : null, reveal: showRow });

  // Keyboard shortcuts (same as FindingsTab).
  const selectedRef = useRef(selectedId);
  selectedRef.current = selectedId;
  const derivedByIdRef = useRef(derivedById);
  derivedByIdRef.current = derivedById;
  const navigationRef = useRef<RecordNavigation>(reviewNavigation);
  navigationRef.current = reviewNavigation;

  // The palette opens over whatever is on screen, the open record included.
  const openCommandPalette = useCallback((invoker?: HTMLElement) => {
    if (cmdOpen) return;
    const origin = invoker ?? document.activeElement;
    commandInvokerRef.current = origin instanceof HTMLElement && origin.isConnected && origin !== document.body ? origin : searchRef.current;
    setCmdOpen(true);
  }, [cmdOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target instanceof HTMLElement ? e.target : null;
      const isTyping = Boolean(target?.closest("input, textarea, select, [contenteditable]:not([contenteditable='false'])"));
      const isInteractive = isTyping || Boolean(target?.closest("button, a, [role='button'], [role='combobox'], [role='listbox']"));
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openCommandPalette();
        return;
      }
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        if (detailOpenRef.current) closeRecord();
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
        if (!detailOpenRef.current) setSelectedId(null);
        return;
      }
      // The open record handles [ / ] itself.
      if (!isInteractive && !detailOpenRef.current && (e.key === "[" || e.key === "]")) {
        e.preventDefault();
        const list = filteredRef.current;
        if (!list.length) return;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.id === cur);
        if (idx < 0) {
          if (list[0]) setSelectedId(list[0].id);
          return;
        }
        const next = e.key === "[" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      if (!isInteractive && (e.key === "j" || e.key === "k")) {
        e.preventDefault();
        if (detailOpenRef.current) {
          const { onPrevious, onNext, pending } = navigationRef.current;
          const step = e.key === "k" ? onPrevious : onNext;
          if (step && !pending) step();
          return;
        }
        const list = filteredRef.current;
        if (!list.length) return;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.id === cur);
        if (idx < 0 && list[0]) {
          setSelectedId(list[0].id);
          return;
        }
        const next = e.key === "k" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      if (!isInteractive && !detailOpenRef.current && e.key === "Enter" && selectedRef.current != null) {
        const record = derivedByIdRef.current.get(selectedRef.current);
        if (!record) return;
        e.preventDefault();
        openRecord(record, rowRefs.current.get(record.id));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openCommandPalette, closeRecord, openRecord]);

  // Counts, each within what the other filters leave.
  const entityCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of searched) if (passes(d, "entity")) c[d.entity] = (c[d.entity] || 0) + 1;
    return c;
  }, [searched, passes]);
  // Per vocabulary, in urgency order.
  const statusGroups = useMemo(() => {
    const counts = new Map<StatusDomain, Map<string, number>>();
    for (const d of searched) {
      if (!d.statusDomain || !d.status || !passes(d, "status")) continue;
      const group = counts.get(d.statusDomain) ?? new Map<string, number>();
      group.set(d.status, (group.get(d.status) ?? 0) + 1);
      counts.set(d.statusDomain, group);
    }
    return STATUS_GROUPS.map(({ domain, label }) => {
      const group = counts.get(domain) ?? new Map<string, number>();
      const order = statusOrder(domain);
      const rank = (value: string) => (order.indexOf(value) < 0 ? order.length : order.indexOf(value));
      const values = [...group].sort((a, b) => rank(a[0]) - rank(b[0]) || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
      // A selected status with no rows left stays visible so it can be cleared.
      const selected = new Set([...statusFilters].filter((key) => key.startsWith(`${domain}:`)).map((key) => key.slice(domain.length + 1)));
      return { domain, label, values, selected };
    }).filter((group) => group.values.length > 0 || group.selected.size > 0);
  }, [searched, passes, statusFilters]);
  const sourceValues = useMemo(() => {
    const c = new Map<string, number>();
    for (const d of searched) if (d.source && passes(d, "source")) c.set(d.source, (c.get(d.source) ?? 0) + 1);
    return [...c].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
  }, [searched, passes]);
  const openLeadRows = useMemo(() => derivedList.reduce((acc, d) => acc + (isOpenLead(d) ? 1 : 0), 0), [derivedList]);
  const supersededCount = useMemo(
    () => derivedList.reduce((acc, d) => acc + (d.supersededById != null ? 1 : 0), 0),
    [derivedList],
  );
  const summaryCounts = summary?.counts ?? {};

  const toggle = <T,>(set: Set<T>, setter: (s: Set<T>) => void, val: T) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
  };

  const clearAll = () => {
    setEntityFilters(new Set());
    setStatusFilters(new Set());
    setSourceFilters(new Set());
    setHideSuperseded(false);
    setQuery("");
  };

  const activeFilterCount =
    entityFilters.size + statusFilters.size + sourceFilters.size + (hideSuperseded ? 1 : 0) + (query ? 1 : 0);

  const loadingAny = loading.size > 0;
  const firstReadinessLead = readiness?.open_leads[0];
  const firstReadinessCve = readiness?.open_high_cves[0]
    ?? readiness?.exploited_unlinked_cves[0]
    ?? readiness?.dangling_links[0];

  // FTS search and the by-URL lookup. Only the latest request of each may
  // answer: an older one that lands late is dropped.
  const ftsRequestRef = useRef(0);
  const runSearch = () => {
    const request = ++ftsRequestRef.current;
    const q = query.trim();
    if (!q) {
      setFts(null);
      setFtsError(null);
      setFtsLoading(false);
      setFtsVisibleCount(PAGE_SIZE);
      return;
    }
    setFtsLoading(true);
    setFtsError(null);
    setFtsQuery(q);
    setFtsVisibleCount(PAGE_SIZE);
    searchIntel(engagementKey, { q })
      .then((rows) => {
        if (request === ftsRequestRef.current) setFts(rows);
      })
      .catch((err: unknown) => {
        if (request !== ftsRequestRef.current) return;
        setFts([]);
        setFtsError(err instanceof Error ? err.message : "Search failed");
      })
      .finally(() => {
        if (request === ftsRequestRef.current) setFtsLoading(false);
      });
  };

  const urlRequestRef = useRef(0);
  const runUrlSearch = () => {
    const request = ++urlRequestRef.current;
    const u = urlQuery.trim();
    if (!u) {
      setUrlResults(null);
      setUrlError(null);
      setUrlLoading(false);
      return;
    }
    setUrlLoading(true);
    setUrlError(null);
    intelByUrl(engagementKey, u)
      .then((resp) => {
        if (request === urlRequestRef.current) setUrlResults(resp);
      })
      .catch((err: unknown) => {
        if (request !== urlRequestRef.current) return;
        setUrlResults(null);
        setUrlError(err instanceof Error ? err.message : "By-URL lookup failed");
      })
      .finally(() => {
        if (request === urlRequestRef.current) setUrlLoading(false);
      });
  };
  const clearUrlLookup = () => {
    urlRequestRef.current += 1;
    setUrlQuery("");
    setUrlResults(null);
    setUrlError(null);
    setUrlLoading(false);
  };

  const routeKey = isEntityFilter(initialIntelType) && initialIntelId != null ? intelRouteKey(initialIntelType, initialIntelId) : null;
  const routeMissing = routeKey !== null && !loadingAny && !derivedById.has(routeKey);

  const empty = !loadingAny && derivedList.length === 0 && errors.size === 0;
  const openLeadCount = readiness?.applicable ? readiness.open_leads.length : null;
  const ftsStale = fts !== null && ftsQuery !== query.trim();
  const sortHeader = (key: Exclude<IntelSortKey, "priority">, label: string, columnIndex?: number, className?: string) => {
    const direction = sort.key === key ? sort.dir : null;
    return (
      <span role="columnheader" aria-sort={ariaSort(direction)} className={className}>
        <button
          type="button"
          className="intel-sort-button"
          onClick={() => setSort((current) => (current.key === key
            ? { key, dir: current.dir === "asc" ? "desc" : "asc" }
            // A status column starts with the most urgent first; text columns A to Z.
            : { key, dir: SORT_COLUMNS[key].kind === "status" ? "desc" : "asc" }))}
          title={`Sort by ${label.toLowerCase()}`}
        >
          {label}
          <SortIndicator direction={direction} />
        </button>
        {columnIndex !== undefined && (
          <span
            className="col-resize-handle"
            onPointerDown={(e) => startListResize(columnIndex, e)}
            onDoubleClick={() => resetListColumn(columnIndex)}
          />
        )}
      </span>
    );
  };

  return (
    <div className="findings-redesign intel-page">
      <PageHeader
        title="Intel"
        purpose="What Vigil learned about the target: tech stack, people, domains, credentials, CVEs and notes. Open leads are the follow-ups still to do."
        stats={[
          { value: loadingAny && derivedList.length === 0 ? null : derivedList.length, label: "records" },
          {
            value: openLeadCount,
            label: openLeadCount === 1 ? "open lead" : "open leads",
            tone: openLeadCount ? "warning" : undefined,
            title: "Current (not superseded) notes whose lead status is open or in progress",
          },
        ]}
        status={loadingAny && derivedList.length > 0 ? `${loading.size} of ${ENTITY_FILTERS.length} types still loading` : null}
        actions={(
          <button type="button" className="ui-button" onClick={(event) => openCommandPalette(event.currentTarget)}>
            Jump to… <span className="search-kbd">⌘K</span>
          </button>
        )}
        hidden={investigating}
      >
        {!empty && (
          <ScopeToggle
            scope={scope}
            onChange={setScope}
            attentionCount={loadingAny && derivedList.length === 0 ? null : openLeadRows}
            allCount={loadingAny && derivedList.length === 0 ? null : derivedList.length}
            partial={loadingAny}
            attentionRule={ATTENTION_RULE}
            label="Intel scope"
          />
        )}
        {readiness?.applicable && (
          <section className="intel-workbar" aria-label="Intel active work readiness">
            <div className="intel-workbar-title">
              <span className="sev-dot" />
              <span>Active work</span>
            </div>
            <button
              type="button"
              className="intel-workbar-stat"
              title="Show these leads: current notes whose lead status is open or in progress"
              onClick={() => {
                // Exactly the leads readiness counts: the Needs attention scope, unfiltered.
                clearAll();
                setScope("attention");
              }}
            >
              {readiness.open_leads.length} open {readiness.open_leads.length === 1 ? "lead" : "leads"}
            </button>
            <span className="intel-workbar-stat" title="CVSS 7 or higher with a public proof of concept, not yet ruled out or exploited">
              {readiness.open_high_cves.length} high-risk {readiness.open_high_cves.length === 1 ? "CVE" : "CVEs"}
            </span>
            <span className="intel-workbar-stat" title="Exploited CVEs with no linked finding">
              {readiness.exploited_unlinked_cves.length} unlinked exploited
            </span>
            <span className="intel-workbar-stat" title="CVEs linked to a finding that is missing, a false positive, or merged">
              {readiness.dangling_links.length} dangling {readiness.dangling_links.length === 1 ? "link" : "links"}
            </span>
            {firstReadinessLead && (
              <button
                type="button"
                className="intel-workbar-review"
                aria-label={`Review ${firstReadinessLead.title}`}
                onClick={(event) => openHydratedRecord("note", { ...firstReadinessLead }, event.currentTarget)}
              >
                Review first <span aria-hidden="true">›</span>
              </button>
            )}
            {!firstReadinessLead && firstReadinessCve && (
              <button
                type="button"
                className="intel-workbar-review"
                aria-label={`Review ${firstReadinessCve.cve_id}`}
                onClick={(event) => openHydratedRecord("cve", { ...firstReadinessCve }, event.currentTarget)}
              >
                Review first <span aria-hidden="true">›</span>
              </button>
            )}
          </section>
        )}
        {readiness && !readiness.applicable && (
          <div className="intel-workbar intel-workbar-muted">
            Intel closure readiness is not applicable to this {readiness.engagement_type} engagement.
          </div>
        )}
        {readinessError && (
          <div className="intel-workbar intel-workbar-muted">Intel readiness unavailable: {readinessError}</div>
        )}
      </PageHeader>

      {routeMissing && (
        <p className="intel-route-missing error-text" role="alert">
          Intel record {initialIntelType} #{initialIntelId} was not found in this engagement.
        </p>
      )}

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel" hidden={investigating}>
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              type="search"
              className="search-input"
              aria-label="Search intel"
              placeholder="Filter any field — name, host, tag, value… (try type:cve cvss:high status:open). Enter searches full text."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  runSearch();
                }
              }}
            />
            {query && (
              <button
                type="button"
                className="icon-btn"
                onClick={() => setQuery("")}
                title="Clear"
                aria-label="Clear intel search"
                style={{ width: 22, height: 22 }}
              >
                <IconClose />
              </button>
            )}
            <span className="search-kbd">/</span>
          </div>
          <div className="toolbar-right">
            <button
              type="button"
              className="ui-button"
              onClick={runSearch}
              disabled={ftsLoading || !query.trim()}
              title="Ask the server's full-text index (word matches, ranked by relevance). The list below filters as you type."
            >
              {ftsLoading ? "Searching…" : "Full-text search"}
            </button>
          </div>
        </div>
        <div className="filter-row intel-filter-row">
          <FilterGroup label="Type">
            {ENTITY_FILTERS.map((spec) => {
              const loaded = cache.has(spec.key);
              const count = loaded ? entityCounts[spec.key] ?? 0 : summaryCounts[spec.summaryKey || spec.key] ?? 0;
              if (!count && !entityFilters.has(spec.key)) return null;
              return (
                <FilterChip
                  key={spec.key}
                  label={spec.label}
                  count={count}
                  color={ITYPE_COLORS[spec.key]}
                  selected={entityFilters.has(spec.key)}
                  onToggle={() => toggle(entityFilters, setEntityFilters, spec.key)}
                />
              );
            })}
          </FilterGroup>
          {statusGroups.map((group) => (
            <FacetChipGroup
              key={group.domain}
              label={group.label}
              values={group.values}
              selected={group.selected}
              onToggle={(value) => toggle(statusFilters, setStatusFilters, statusKey(group.domain, value))}
              labelFor={(value) => statusLabel(group.domain, value)}
              statusDomain={group.domain}
            />
          ))}
          {(sourceValues.length > 0 || sourceFilters.size > 0) && (
            <FacetChipGroup
              label="Source"
              values={sourceValues}
              selected={sourceFilters}
              onToggle={(value) => toggle(sourceFilters, setSourceFilters, value)}
            />
          )}
          {supersededCount > 0 && (
            <FilterChip
              label="Hide superseded"
              count={supersededCount}
              selected={hideSuperseded}
              onToggle={() => setHideSuperseded((current) => !current)}
              description="Hide records replaced by a newer one, so the list mirrors the report-writer view."
            />
          )}
          <ClearFiltersButton count={activeFilterCount} onClear={clearAll} />
        </div>

        {/* Secondary by-URL lookup. */}
        <div className="filter-row">
          <div className="filter-group intel-by-url">
            <span className="filter-label">By URL</span>
            <input
              type="search"
              className="intel-url-input"
              aria-label="Look up intel by URL"
              placeholder="Look up everything recorded for a URL…"
              value={urlQuery}
              onChange={(e) => setUrlQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runUrlSearch();
              }}
            />
            <button type="button" className="ui-button" onClick={runUrlSearch} disabled={urlLoading}>
              {urlLoading ? "Looking up…" : "Go"}
            </button>
            {(urlResults || urlError) && (
              <button type="button" className="ui-clear-filters" onClick={clearUrlLookup}>
                Clear lookup
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Full-text / by-URL results (only render when in use). */}
      {(fts !== null || ftsError || urlResults || urlError) && (
        <div className="panel findings-toolbar-panel intel-lookups" hidden={investigating}>
          {fts !== null && (
            <div>
              <p className="section-title">
                Full-text matches for “{ftsQuery}” <span className="count">{fts.length}</span>
              </p>
              <p className="meta-text intel-lookup-note">
                From the server's full-text index: whole-word matches across every intel body, ranked by relevance. The list
                below filters by substring as you type{ftsStale ? `; it now shows “${query.trim() || "everything"}”, press Enter to search that` : ""}.
              </p>
              {ftsError && <p className="error-text" role="alert">{ftsError}</p>}
              {fts.length === 0 && !ftsError && <EmptyState variant="empty" compact title="No full-text matches." />}
              {fts.length > 0 && (
                <div className="intel-lookup-list">
                  {fts.slice(0, ftsVisibleCount).map((hit, i) => (
                    <button
                      key={`${hit.entity_type}:${hit.source_id}:${i}`}
                      type="button"
                      className="link-card"
                      onClick={(event) => {
                        const match = derivedList.find(
                          (d) =>
                            d.entity === (hit.entity_type as EntityFilter) &&
                            ((d.raw.id as number | undefined) === hit.source_id),
                        );
                        if (match) openRecord(match, event.currentTarget);
                        else openHydratedRecord(hit.entity_type, {
                          ...hit.record,
                          id: hit.source_id,
                          source_name: hit.record.source_name ?? hit.source_name,
                        }, event.currentTarget);
                      }}
                    >
                      <span className="link-kind">{ENTITY_LABEL.get(hit.entity_type) ?? hit.entity_type}</span>
                      <span className="intel-lookup-text">
                        <span className="link-title">{hit.key}</span>
                        <span className="link-sub">{truncate(hit.body, 180)}</span>
                      </span>
                      <span className="link-sub">{hit.source_name}</span>
                      <span className="link-go" aria-hidden="true">›</span>
                    </button>
                  ))}
                  {ftsVisibleCount < fts.length && (
                    <div className="list-footer">
                      <span>
                        Showing {ftsVisibleCount} of {fts.length} matches
                      </span>
                      <button
                        type="button"
                        className="pager-btn"
                        onClick={() => setFtsVisibleCount((count) => Math.min(count + PAGE_SIZE, fts.length))}
                      >
                        Show next {Math.min(PAGE_SIZE, fts.length - ftsVisibleCount)}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
          {urlError && <p className="error-text" role="alert">By-URL lookup failed: {urlError}</p>}
          {urlResults !== null && (
            <div>
              <p className="section-title">
                Recorded for <code>{urlQuery}</code>
              </p>
              {urlResults.domains.length + urlResults.services.length + urlResults.surfaces.length + urlResults.request_variants.length === 0 && (
                <EmptyState variant="empty" compact title="Nothing recorded for this URL." />
              )}
              <UrlResultBlock
                label="Domains"
                rows={urlResults.domains as unknown as Record<string, unknown>[]}
                onOpen={(row, invoker) => openHydratedRecord("domain", row, invoker)}
              />
              <UrlResultBlock
                label="Services"
                rows={urlResults.services}
                note={<>Services have no record view; their coverage shows under <a href={engagementHref(engagementKey, { tab: "coverage" })}>Coverage</a>.</>}
              />
              <UrlResultBlock
                label="Surfaces"
                rows={urlResults.surfaces}
                hrefFor={(row) => (typeof row.id === "number" ? engagementHref(engagementKey, { tab: "surfaces", surface: row.id }) : undefined)}
              />
              <UrlResultBlock
                label="Request variants"
                rows={urlResults.request_variants}
                hrefFor={(row) => (typeof row.id === "number" ? engagementHref(engagementKey, { tab: "http", request: row.id }) : undefined)}
              />
            </div>
          )}
        </div>
      )}

      {/* List (an open record replaces it; the list keeps its state behind) */}
      <div ref={resultsRef} className="findings-shell" hidden={investigating}>
        <section className="list-panel panel intel-list-panel">
          {!empty && (
            <div className="intel-list-head">
              <ResultsSummary
                shown={filtered.length}
                total={derivedList.length}
                noun="intel records"
                sort={describeIntelSort(sort)}
                partial={loadingAny}
              />
              {sort.key !== "priority" && (
                <button type="button" className="ui-clear-filters" onClick={() => setSort(PRIORITY_SORT)}>
                  Sort by priority
                </button>
              )}
            </div>
          )}
          <div className="list-scroll-x">
            {/* A table of records: each row's title is the button that opens it. */}
            <div role="table" aria-label="Intel records" className="intel-table">
              <div
                className="list-header"
                role="row"
                style={{ gridTemplateColumns: listGridTemplate, minWidth: "fit-content" }}
              >
                <span aria-hidden="true" />
                {sortHeader("type", "Type", 1)}
                {sortHeader("title", "Title / subtitle", 2)}
                {sortHeader("location", "Location", 3)}
                <span role="columnheader">
                  Tags
                  <span
                    className="col-resize-handle"
                    aria-hidden="true"
                    onPointerDown={(e) => startListResize(4, e)}
                    onDoubleClick={() => resetListColumn(4)}
                  />
                </span>
                {sortHeader("status", "Status", undefined, "intel-status-head")}
              </div>
              <div className="list-scroll" role="rowgroup">
                {pageRows.map((d) => (
                  <IntelRow
                    key={d.id}
                    d={d}
                    selected={selectedId === d.id}
                    onOpen={(invoker) => openRecord(d, invoker)}
                    freeTerms={parsedQuery.freeTerms}
                    gridTemplate={listGridTemplate}
                    registerRef={(id, el) => {
                      if (el) rowRefs.current.set(id, el);
                      else rowRefs.current.delete(id);
                    }}
                  />
                ))}
              </div>
            </div>
            {pageRows.length === 0 && loadingAny ? (
              <TableSkeleton
                rows={8}
                showHeader={false}
                columns={["12%", "18%", "34%", "20%", "16%"]}
              />
            ) : empty ? (
              <EmptyState variant="empty" title="No intel recorded yet.">
                Agents record what they learn here: the tech stack, people, domains, credentials, CVEs, and notes with leads to follow up.
              </EmptyState>
            ) : pageRows.length === 0 && activeFilterCount > 0 ? (
              <EmptyState variant="filtered" title="No intel records match these filters." onClearFilters={clearAll} />
            ) : pageRows.length === 0 && scope === "attention" ? (
              <EmptyState
                variant="empty"
                title="No open leads."
                action={<button type="button" className="ui-button" onClick={() => setScope("all")}>Show all {derivedList.length.toLocaleString()}</button>}
              >
                Every current lead is resolved or ruled out.
              </EmptyState>
            ) : pageRows.length === 0 ? (
              <EmptyState variant="empty" title="No intel records to show." />
            ) : null}
          </div>
          <SlowLoadHint active={loadingAny} what="intel records" />
          {!empty && (
            <div className="list-footer">
              <span>
                {filtered.length} records · page {page + 1} / {totalPages}
              </span>
              <div className="pager-group">
                <button
                  type="button"
                  className="pager-btn"
                  disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Prev
                </button>
                <button
                  type="button"
                  className="pager-btn"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </button>
              </div>
            </div>
          )}
          {errors.size > 0 && (
            <div className="intel-load-errors" role="alert">
              {Array.from(errors.entries()).map(([k, v]) => (
                <div key={k}>
                  {ENTITY_LABEL.get(k) ?? k} unavailable: {v}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {investigating && (
        <RecordView
          label="Intel record"
          noun="intel record"
          navigation={reviewNavigation}
          onBack={closeRecord}
          titleId="intel-record-title"
          returnFocusRef={invokerRef}
        >
          <IntelRecord
            key={selectedDerived.id}
            d={selectedDerived}
            engagementKey={engagementKey}
            tab={intelTabVisible(selectedDerived, recordTab) ? recordTab : "overview"}
            onTabChange={chooseRecordTab}
            titleId="intel-record-title"
          />
        </RecordView>
      )}

      <div className="findings-shortcuts" hidden={investigating}>
        <span><code>/</code> focus search</span>
        <span><code>Enter</code> full-text search (in the search box)</span>
        <span><code>⌘K</code> jump to record</span>
        <span><code>j / k</code> move</span>
        <span><code>[ / ]</code> prev / next</span>
        <span><code>Esc</code> close detail</span>
      </div>

      {cmdOpen && (
        <CommandPalette
          derivedList={derivedList}
          returnFocusRef={commandInvokerRef}
          onSelect={(id) => {
            const record = derivedById.get(id);
            setCmdOpen(false);
            if (record) openRecord(record, commandInvokerRef.current);
          }}
          onClose={() => setCmdOpen(false)}
        />
      )}
    </div>
  );
}

/** A CVE whose CVSS score gives it a severity colour. */
function isCveWithSeverity(d: Derived): boolean {
  return d.entity === "cve" && d.sev != null;
}

// ── IntelRow ─────────────────────────────────────────────────────────
// One table row. The title is the row's button (keyboard and assistive
// technology open the record through it); a click anywhere on the row opens
// it too, unless the operator is selecting text.
function IntelRow({
  d,
  selected,
  onOpen,
  freeTerms,
  gridTemplate,
  registerRef,
}: {
  d: Derived;
  selected: boolean;
  onOpen: (invoker: HTMLElement | null) => void;
  freeTerms: string[];
  gridTemplate?: string;
  registerRef?: (id: string, el: HTMLButtonElement | null) => void;
}) {
  const openRef = useRef<HTMLButtonElement | null>(null);
  const isCveWithSev = isCveWithSeverity(d);
  const barClass = isCveWithSev ? `sevbar-${d.sev}` : `ibar-${d.entity}`;
  const pillClass = isCveWithSev ? String(d.sev) : `itype-${d.entity}`;
  const superseded = d.supersededById != null;
  // Struck-through styling + dim opacity flags the row as historical.
  // The superseder id is rendered as a tag so the operator can tell at a
  // glance which canonical row replaced it.
  const supersededStyle: React.CSSProperties | undefined = superseded
    ? { textDecoration: "line-through", opacity: 0.55 }
    : undefined;
  return (
    <div
      role="row"
      className={`frow ${selected ? "is-selected" : ""} ${superseded ? "is-superseded" : ""}`}
      onClick={() => {
        const selection = window.getSelection?.();
        if (selection && selection.type === "Range" && selection.toString().length > 0) return;
        onOpen(openRef.current);
      }}
      data-id={d.id}
      data-record-key={d.id}
      data-superseded={superseded ? "true" : undefined}
      style={gridTemplate ? { gridTemplateColumns: gridTemplate, minWidth: "fit-content" } : { minWidth: "fit-content" }}
    >
      <span className={`frow-sevbar ${barClass}`} aria-hidden="true" />
      <span role="cell" className={`frow-sev ${pillClass}`}>{d.entityLabel}</span>
      <span role="cell" className="frow-main">
        <button
          type="button"
          className="frow-title intel-row-open"
          style={supersededStyle}
          ref={(el) => {
            openRef.current = el;
            registerRef?.(d.id, el);
          }}
        >
          {highlight(d.title, freeTerms)}
        </button>
        <span className="frow-meta">
          {d.subtitle && <span className="mono" style={supersededStyle}>{truncate(d.subtitle, 80)}</span>}
          {d.source && (
            <>
              <span className="dot" />
              <span>{d.source}</span>
            </>
          )}
          {d.updated_at && (
            <>
              <span className="dot" />
              <TimeStamp value={d.updated_at} />
            </>
          )}
        </span>
      </span>
      <span role="cell" className="frow-loc" style={supersededStyle}>{d.location || ""}</span>
      <span role="cell" className="frow-tags">
        {superseded && (
          <span className="tag" title={`Replaced by intel id=${d.supersededById}`}>
            superseded → #{d.supersededById}
          </span>
        )}
        {d.sevLabel && <span className="tag cve">{d.sevLabel}</span>}
        {d.tags.slice(0, 4).map((t, i) => (
          <span key={`t-${i}-${t}`} className="tag">{t}</span>
        ))}
      </span>
      <span role="cell" className="frow-status">
        {d.status && d.statusDomain ? <StatusPill domain={d.statusDomain} value={d.status} size="sm" /> : null}
      </span>
    </div>
  );
}

// ── Record ───────────────────────────────────────────────────────────
// One intel record inside the shared RecordView (IntelTab owns the view, the
// list order and the URL). Sections: Overview (the entity's fields, body,
// notes, provenance), Links & tags, Provenance (fields beyond the canonical
// four) and Raw.

type IntelRecordTab = "overview" | "references" | "provenance" | "raw";
const INTEL_RECORD_TABS: readonly IntelRecordTab[] = ["overview", "references", "provenance", "raw"];

function isIntelRecordTab(value: string | undefined): value is IntelRecordTab {
  return (INTEL_RECORD_TABS as readonly string[]).includes(value ?? "");
}

/** The route identity of a record: `intel_type` + `intel_id`. */
function intelRouteKey(entity: EntityFilter, id: unknown): string {
  return `${entity}:${String(id)}`;
}

// The canonical provenance block (agent / captured / artifact / evidence)
// renders on Overview. The Provenance section only appears when there are
// EXTRA provenance fields, so nothing is dropped and nothing is shown twice.
const PROVENANCE_CANONICAL = ["agent_name", "captured_at", "artifact_ref", "evidence_quote"];

function provenanceExtraCount(d: Derived): number {
  const provenance = (d.raw.provenance as Record<string, unknown>) || {};
  return Object.keys(provenance).filter((k) => !PROVENANCE_CANONICAL.includes(k)).length;
}

// Links & tags: tags + a record URL + a linked-finding deep link (CVE).
function referenceCount(d: Derived): number {
  return (Array.isArray(d.raw.tags) ? (d.raw.tags as unknown[]).length : 0)
    + (d.raw.url ? 1 : 0)
    + (d.raw.linked_finding_slug ? 1 : 0);
}

function intelTabVisible(d: Derived, tab: IntelRecordTab): boolean {
  if (tab === "references") return referenceCount(d) > 0;
  if (tab === "provenance") return provenanceExtraCount(d) > 0;
  return true;
}

/** "CVE", "Tech component", "DNS record": one record of the entity type. */
function entityNoun(entity: EntityFilter): string {
  const singular = ENTITY_FILTERS.find((spec) => spec.key === entity)?.singular ?? entity;
  return singular.charAt(0).toUpperCase() + singular.slice(1);
}

function recordIdLabel(d: Derived): string {
  const noun = entityNoun(d.entity);
  return d.raw.id != null ? `${noun} #${String(d.raw.id)}` : noun;
}

type IntelRecordProps = {
  d: Derived;
  engagementKey: string;
  tab: IntelRecordTab;
  onTabChange: (tab: IntelRecordTab) => void;
  titleId: string;
};

function IntelRecord({ d, engagementKey, tab, onTabChange, titleId }: IntelRecordProps) {
  const { toast } = useToast();
  const [proseMode, setProseMode] = useState<ProseMode>("rendered");

  const refCount = referenceCount(d);
  const provExtraCount = provenanceExtraCount(d);
  const isCveWithSev = isCveWithSeverity(d);
  const sevClass = d.sev || "info";
  const heroPillClass = isCveWithSev ? sevClass : `itype-${d.entity}`;
  const heroDotColor = isCveWithSev ? severityColor(sevClass) : ITYPE_COLORS[d.entity];
  const dates: RecordDate[] = [
    { label: "Created", value: d.created_at || null },
    { label: "Updated", value: d.updated_at || null },
  ];
  if (d.supersededAt) dates.push({ label: "Superseded", value: d.supersededAt });

  return (
    <>
      <RecordHeader
        id={recordIdLabel(d)}
        copyId={d.id}
        copyIdLabel="Copy intel ID"
        title={d.title}
        titleId={titleId}
        accent={heroDotColor}
        actions={<RecordCopyLinkButton noun="intel record" />}
        pills={
          <>
            <span className={`hero-sev ${heroPillClass}`}>
              <span className="sev-dot" style={{ background: heroDotColor }} />
              {entityNoun(d.entity)}
            </span>
            {d.sevLabel && <span className="tag cve">{d.sevLabel}</span>}
            {d.status && d.statusDomain && (
              <StatusPill
                domain={d.statusDomain}
                value={d.status}
                reason={d.supersededById != null ? `Superseded by #${d.supersededById}` : undefined}
              />
            )}
            {(!d.status || !d.statusDomain) && d.supersededById != null && (
              <span className="record-pill-reason">Superseded by #{d.supersededById}</span>
            )}
            {d.source && <span className="tag">{d.source}</span>}
          </>
        }
        datesLabel="Intel record dates"
        dates={dates}
      />
      <RecordTabs
        label="Intel record sections"
        active={tab}
        onChange={onTabChange}
        tabs={[
          { id: "overview", label: "Overview" },
          { id: "references", label: "Links & tags", count: refCount, hidden: refCount === 0 },
          { id: "provenance", label: "Provenance", count: provExtraCount, hidden: provExtraCount === 0 },
          { id: "raw", label: "Raw" },
        ]}
        // Prose (the note body, free-form notes) renders on Overview only.
        trailing={tab === "overview" ? <ProseModeToggle mode={proseMode} onChange={setProseMode} /> : undefined}
      />
      <RecordBody>
        {tab === "overview" && <OverviewPane d={d} proseMode={proseMode} toast={toast} />}
        {tab === "references" && <ReferencesPane d={d} engagementKey={engagementKey} toast={toast} />}
        {tab === "provenance" && <ProvenancePane d={d} />}
        {tab === "raw" && <RawPane d={d} />}
      </RecordBody>
    </>
  );
}

// ── Panes ────────────────────────────────────────────────────────────
// KV is imported from ./drawer/DrawerKit (shared with Findings + Surface).
// It accepts an optional `toast` (renders a copy chip next to the label) and
// an optional `href` (renders the value as an external link).

// Detect whether a value reads as an identifier/hash/URL worth making
// monospace + copyable in the Overview KV grid.
function isCopyableRef(key: string): boolean {
  return /id|key|hash|url|endpoint|token|ref|cve|cvss|vector|address|identity|handle|value|component|version/i.test(
    key,
  );
}

// Keys handled explicitly in OverviewPane per-entity — the rest fall into
// the "Additional details" JsonTree so nothing is ever dropped.
const BASE_KEYS_HANDLED = new Set<string>([
  "id",
  "engagement_id",
  "source_name",
  "notes",
  "provenance",
  "superseded_by_id",
  "superseded_at",
  "created_at",
  "updated_at",
]);

function OverviewPane({
  d,
  proseMode,
  toast,
}: {
  d: Derived;
  proseMode: ProseMode;
  toast: ToastFn;
}) {
  const raw = d.raw;
  const known = new Set<string>(BASE_KEYS_HANDLED);
  const add = (k: string) => known.add(k);

  // URL of the record (social profile, etc.) — rendered as an external link
  // in the KV grid when present.
  const recordUrl = isWebUrl(raw.url) ? raw.url : undefined;

  let specific: React.ReactNode = null;
  switch (d.entity) {
    case "tech_component":
      ["component", "version", "confidence", "evidence_ref", "first_seen_at", "last_seen_at"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Component" v={raw.component} mono toast={toast} />
          <KV k="Version" v={raw.version} mono toast={toast} />
          <KV k="Confidence" v={raw.confidence} />
          <KV k="Evidence ref" v={raw.evidence_ref} mono toast={toast} />
          <KVTime k="First seen" v={fmtCell(raw.first_seen_at)} />
          <KVTime k="Last seen" v={fmtCell(raw.last_seen_at)} />
        </div>
      );
      break;
    case "person":
      ["name", "role", "organization", "email"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Name" v={raw.name} />
          <KV k="Role" v={raw.role} />
          <KV k="Organization" v={raw.organization} />
          <KV k="Email" v={raw.email} mono toast={toast} />
        </div>
      );
      break;
    case "email":
      ["address", "role_hint", "linked_person_id"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Address" v={raw.address} mono toast={toast} />
          <KV k="Role hint" v={raw.role_hint} />
          <KV k="Linked person" v={raw.linked_person_id} mono />
        </div>
      );
      break;
    case "domain":
      ["identity", "kind", "value", "live_status"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Identity" v={raw.identity} mono toast={toast} />
          <KV k="Kind" v={raw.kind} />
          <KV k="Value" v={raw.value} mono toast={toast} />
          <KV k="Live status" v={raw.live_status} />
        </div>
      );
      break;
    case "credentials":
      // Credentials are loose dicts; surface every scalar field explicitly.
      Object.keys(raw).forEach(add);
      specific = (
        <div className="kv-grid">
          {Object.entries(raw)
            .filter(([k]) => !BASE_KEYS_HANDLED.has(k) && typeof raw[k] !== "object")
            .map(([k, v]) => {
              const mono = isCopyableRef(k);
              return (
                <KV
                  key={k}
                  k={k.replace(/_/g, " ")}
                  v={v}
                  mono={mono}
                  toast={mono ? toast : undefined}
                />
              );
            })}
        </div>
      );
      break;
    case "cve":
      [
        "cve_id",
        "affected_component",
        "affected_version_range",
        "cvss_score",
        "cvss_vector",
        "cwe_id",
        "poc_available",
        "validation_status",
        "linked_finding_slug",
      ].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="CVE" v={raw.cve_id} mono toast={toast} />
          <KV k="Affected component" v={raw.affected_component} mono toast={toast} />
          <KV k="Affected versions" v={raw.affected_version_range} mono toast={toast} />
          <KV k="CVSS score" v={raw.cvss_score} />
          <KV k="CVSS vector" v={raw.cvss_vector} mono toast={toast} />
          <KV k="CWE" v={raw.cwe_id} mono toast={toast} />
          <KV k="PoC available" v={raw.poc_available} />
          <KV k="Validation" v={raw.validation_status} />
          <KV k="Linked finding" v={raw.linked_finding_slug} mono toast={toast} />
        </div>
      );
      break;
    case "dns_record":
      ["record_type", "name", "value", "first_seen", "last_seen"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Type" v={raw.record_type} mono />
          <KV k="Name" v={raw.name} mono toast={toast} />
          <KV k="Value" v={raw.value} mono toast={toast} />
          <KVTime k="First seen" v={fmtCell(raw.first_seen)} />
          <KVTime k="Last seen" v={fmtCell(raw.last_seen)} />
        </div>
      );
      break;
    case "social_profile":
      ["subject_kind", "subject_ref", "platform", "handle", "url"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Platform" v={raw.platform} />
          <KV k="Handle" v={raw.handle} mono toast={toast} />
          <KV k="Subject" v={raw.subject_ref} mono toast={toast} />
          <KV k="Subject kind" v={raw.subject_kind} />
          <KV k="URL" v={raw.url} mono toast={toast} href={recordUrl} />
        </div>
      );
      break;
    case "breach_record":
      ["subject", "breach_name", "breach_date", "data_types"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Breach" v={raw.breach_name} />
          <KV k="Subject" v={raw.subject} mono toast={toast} />
          <KV k="Date" v={raw.breach_date} />
          <KV k="Data types" v={raw.data_types} />
        </div>
      );
      break;
    case "org_fact":
      ["fact_key", "fact_value", "authored_by", "scope", "validity_context"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Key" v={raw.fact_key} mono toast={toast} />
          <KV k="Value" v={raw.fact_value} />
          <KV k="Authored by" v={raw.authored_by} mono toast={toast} />
          <KV k="Scope" v={raw.scope} />
          <KV k="Validity" v={raw.validity_context} />
        </div>
      );
      break;
    case "note":
      [
        "title",
        "body_markdown",
        "source_agent",
        "tags",
        "lead_status",
        "authored_by",
        "scope",
        "validity_context",
      ].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Title" v={raw.title} />
          <KV k="Source agent" v={raw.source_agent} mono toast={toast} />
          <KV k="Tags" v={Array.isArray(raw.tags) ? (raw.tags as string[]).join(", ") : ""} />
          <KV k="Lead status" v={raw.lead_status ? statusLabel("intel-lead", fmtCell(raw.lead_status)) : ""} />
          <KV k="Authored by" v={raw.authored_by} mono toast={toast} />
          <KV k="Scope" v={raw.scope} />
          <KV k="Validity" v={raw.validity_context} />
        </div>
      );
      break;
  }

  const bodyMarkdown = (raw.body_markdown as string | undefined) || "";
  const notes = (raw.notes as string | undefined) || "";
  const prov = (raw.provenance as Record<string, unknown>) || {};
  const hasProvenance = !!(
    prov.agent_name ||
    prov.captured_at ||
    prov.artifact_ref ||
    prov.evidence_quote
  );
  const additional = Object.keys(raw).filter((k) => !known.has(k));

  return (
    <>
      <section className="section">
        <h3 className="section-title">{entityNoun(d.entity)}</h3>
        {specific}
      </section>
      {/* Created / Updated / Superseded times are in the record header. */}
      <section className="section">
        <h3 className="section-title">Metadata</h3>
        <div className="kv-grid">
          <KV k="Source" v={d.source} toast={d.source ? toast : undefined} />
          <KV k="Record ID" v={raw.id} mono toast={raw.id != null ? toast : undefined} />
          {d.supersededById != null && <KV k="Superseded by" v={`#${d.supersededById}`} mono />}
        </div>
      </section>
      {/* Note body + free-form notes render through the shared prose
          renderer (rendered markdown by default, raw text when toggled) with
          a copy chip, matching the Findings record. */}
      <ProseSection title="Body" text={bodyMarkdown} mode={proseMode} toast={toast} />
      <ProseSection title="Notes" text={notes} mode={proseMode} toast={toast} />
      {hasProvenance && (
        <section className="section">
          <h3 className="section-title">Provenance</h3>
          <ProvenanceBlock
            agent={prov.agent_name as string | undefined}
            captured={prov.captured_at as string | undefined}
            artifactRef={prov.artifact_ref as string | undefined}
            evidenceQuote={prov.evidence_quote as string | undefined}
          />
        </section>
      )}
      {additional.length > 0 && (
        <section className="section">
          <h3 className="section-title">Additional details</h3>
          <div className="json-children">
            {additional.map((key) => (
              <JsonTree key={key} label={key} value={toJsonValue(raw[key])} defaultOpen />
            ))}
          </div>
        </section>
      )}
    </>
  );
}

function ReferencesPane({
  d,
  engagementKey,
  toast,
}: {
  d: Derived;
  engagementKey: string;
  toast: ToastFn;
}) {
  const raw = d.raw;
  const url = (raw.url as string) || "";
  const tags = Array.isArray(raw.tags) ? (raw.tags as string[]) : [];
  const linkedFindingSlug = (raw.linked_finding_slug as string) || "";

  if (!url && tags.length === 0 && !linkedFindingSlug) {
    return <EmptyState variant="empty" compact title="No links or tags recorded." />;
  }
  return (
    <>
      {tags.length > 0 && (
        <section className="section inline-row">
          <h3 className="section-title section-title--inline">Tags</h3>
          <div className="tag-row tag-row--inline">
            {tags.map((t, i) => (
              <span key={`${i}-${t}`} className="tag">{t}</span>
            ))}
          </div>
        </section>
      )}
      {linkedFindingSlug && (
        <section className="section">
          <SectionHead title="Linked finding" copyText={linkedFindingSlug} toast={toast} />
          <ul className="ref-list">
            <li>
              <a className="mono" href={engagementHref(engagementKey, { tab: "findings", finding: linkedFindingSlug })}>{linkedFindingSlug}</a>
            </li>
          </ul>
        </section>
      )}
      {url && (
        <section className="section">
          <SectionHead title="URL" copyText={url} toast={toast} />
          <ul className="ref-list">
            <li>
              {/* Target-recorded text: only a web address becomes a link. */}
              {isWebUrl(url) ? (
                <a href={url} target="_blank" rel="noopener noreferrer">
                  {url}
                  <IconExternal />
                  <span className="host">{extractHost(url)}</span>
                </a>
              ) : (
                <span className="mono">{url}</span>
              )}
            </li>
          </ul>
        </section>
      )}
    </>
  );
}

function ProvenancePane({ d }: { d: Derived }) {
  const prov = (d.raw.provenance as Record<string, unknown>) || {};
  if (Object.keys(prov).length === 0)
    return <EmptyState variant="empty" compact title="No provenance recorded." />;
  const extras = Object.entries(prov).filter(([k]) => !PROVENANCE_CANONICAL.includes(k));
  return (
    <section className="section">
      <h3 className="section-title">Provenance</h3>
      <ProvenanceBlock
        agent={prov.agent_name as string | undefined}
        captured={prov.captured_at as string | undefined}
        artifactRef={prov.artifact_ref as string | undefined}
        evidenceQuote={prov.evidence_quote as string | undefined}
      />
      {extras.length > 0 && (
        <div className="json-children" style={{ marginTop: 8 }}>
          {extras.map(([k, v]) => (
            <JsonTree key={k} label={k} value={toJsonValue(v)} defaultOpen />
          ))}
        </div>
      )}
    </section>
  );
}

function RawPane({ d }: { d: Derived }) {
  return (
    <section className="section">
      <h3 className="section-title">Raw record</h3>
      <JsonView value={d.raw} />
    </section>
  );
}

// ── By-URL summary block ─────────────────────────────────────────────
// One kind of record the URL matched. Domains open their intel record,
// surfaces and request variants link to their own record view, and kinds
// without a record view (services) list what they are and say so.
function UrlResultBlock({
  label,
  rows,
  hrefFor,
  onOpen,
  note,
}: {
  label: string;
  rows: Record<string, unknown>[];
  hrefFor?: (row: Record<string, unknown>) => string | undefined;
  onOpen?: (row: Record<string, unknown>, invoker: HTMLElement) => void;
  note?: React.ReactNode;
}) {
  // Long lists show a page at a time; every row stays one click away.
  const [visible, setVisible] = useState(PAGE_SIZE);
  if (!rows || rows.length === 0) return null;
  return (
    <div className="intel-url-block">
      <p className="section-title">
        {label} <span className="count">{rows.length}</span>
      </p>
      {note && <p className="meta-text intel-lookup-note">{note}</p>}
      <div className="intel-lookup-list">
        {rows.slice(0, visible).map((row, i) => {
          const key = String(row.id ?? i);
          const content = (go: boolean) => (
            <>
              <span className="link-kind">{label.toLowerCase()}</span>
              <span className="link-title mono">{truncate(summarizeRow(row), 220)}</span>
              {go ? <span className="link-go" aria-hidden="true">›</span> : <span />}
            </>
          );
          if (onOpen) {
            return (
              <button key={key} type="button" className="link-card" onClick={(event) => onOpen(row, event.currentTarget)}>
                {content(true)}
              </button>
            );
          }
          const href = hrefFor?.(row);
          if (href) {
            return (
              <a key={key} className="link-card" href={href}>
                {content(true)}
              </a>
            );
          }
          return (
            <div key={key} className="link-card intel-static-card">
              {content(false)}
            </div>
          );
        })}
        {visible < rows.length && (
          <div className="list-footer">
            <span>
              Showing {visible.toLocaleString()} of {rows.length.toLocaleString()} {label.toLowerCase()}
            </span>
            <button
              type="button"
              className="pager-btn"
              onClick={() => setVisible((count) => Math.min(count + PAGE_SIZE, rows.length))}
            >
              Show next {Math.min(PAGE_SIZE, rows.length - visible)}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function summarizeRow(row: Record<string, unknown>): string {
  for (const key of ["identity", "endpoint", "target_descriptor", "canonical_url", "host", "name", "address", "url"]) {
    const v = row[key];
    if (typeof v === "string" && v) return v;
  }
  return fmtCell(row);
}

// ── Command palette ──────────────────────────────────────────────────
function CommandPalette({
  derivedList,
  onSelect,
  onClose,
  returnFocusRef,
}: {
  derivedList: Derived[];
  onSelect: (id: string) => void;
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

  const results = useMemo(() => {
    const parsed = parseQuery(q);
    const list = derivedList.filter((d) => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "type":
            if (entityTypeSlug(d.entity) !== v && d.entity !== (v as EntityFilter)) return false;
            break;
          case "source":
            if (!d.source.toLowerCase().includes(v)) return false;
            break;
          case "status":
            if ((d.status || "").toLowerCase() !== v) return false;
            break;
          case "host":
            if (!d.host.toLowerCase().includes(v)) return false;
            break;
          case "cve":
            if (!fmtCell(d.raw.cve_id).toLowerCase().includes(v)) return false;
            break;
          default: {
            if (!d.searchCorpus.includes(v)) return false;
          }
        }
      }
      for (const t of parsed.freeTerms) if (!d.searchCorpus.includes(t)) return false;
      return true;
    });
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
      if (results[idx]) onSelect(results[idx].id);
    }
  };

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <div ref={panelRef} className="cmd-box" role="dialog" aria-modal="true" aria-label="Jump to intel" tabIndex={-1} onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input-row">
          <IconSearch />
          <input
            ref={inputRef}
            className="cmd-input"
            aria-label="Search intel to jump to"
            placeholder="Jump to intel · try 'type:cve exploited' or a host"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <span className="search-kbd">esc</span>
        </div>
        <div className="cmd-list">
          {results.length === 0 ? (
            <div className="cmd-empty">No records match.</div>
          ) : (
            results.map((d, i) => (
              <button
                type="button"
                key={d.id}
                className={`cmd-item ${i === idx ? "is-active" : ""}`}
                onMouseEnter={() => setIdx(i)}
                onFocus={() => setIdx(i)}
                onClick={() => onSelect(d.id)}
              >
                <span
                  className="sev-dot"
                  aria-hidden="true"
                  style={{ background: isCveWithSeverity(d) ? severityColor(d.sev) : ITYPE_COLORS[d.entity] }}
                />
                <span>
                  <span className="cmd-title">{d.title}</span>
                  <span className="cmd-sub">
                    {d.entityLabel}
                    {d.sevLabel ? ` · ${d.sevLabel}` : ""}
                    {d.source ? ` · ${d.source}` : ""}
                    {d.status && d.statusDomain ? ` · ${statusLabel(d.statusDomain, d.status)}` : ""}
                  </span>
                </span>
                <span className="cmd-sub">{d.location || ""}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
