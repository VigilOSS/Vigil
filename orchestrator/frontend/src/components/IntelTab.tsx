import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  IntelByUrlResponse,
  IntelEntityType,
  IntelRecord,
  IntelSearchHit,
  IntelSummary,
  ListIntelResponse,
} from "../lib/api";
import {
  intelByUrl,
  listIntel,
  listIntelCredentials,
  searchIntel,
} from "../lib/api";
import { useResizableColumns } from "../lib/useResizableColumns";
import { JsonTree } from "./ArtifactViewer";
import { JsonView } from "./JsonView";
import { useBodyScrollLock } from "../lib/modalScrollLock";
import { NotesBody, ProvenanceBlock } from "./formatting";

// ── Props ────────────────────────────────────────────────────────────
type IntelTabProps = {
  engagementKey: string;
  summary: IntelSummary | null;
};

// ── Entity types ─────────────────────────────────────────────────────
type EntityFilter = IntelEntityType | "credentials";

type FilterSpec = {
  key: EntityFilter;
  label: string;
  singular: string;
};

// Ordering mirrors the original sidebar in §3a.
const ENTITY_FILTERS: FilterSpec[] = [
  { key: "tech_component", label: "Tech stack", singular: "tech component" },
  { key: "person", label: "People", singular: "person" },
  { key: "email", label: "Emails", singular: "email" },
  { key: "domain", label: "Domains", singular: "domain" },
  { key: "credentials", label: "Credentials", singular: "credential" },
  { key: "cve", label: "CVEs", singular: "CVE" },
  { key: "dns_record", label: "DNS", singular: "DNS record" },
  { key: "social_profile", label: "Social", singular: "social profile" },
  { key: "breach_record", label: "Breach", singular: "breach record" },
  { key: "org_fact", label: "Org", singular: "org fact" },
  { key: "note", label: "Notes", singular: "note" },
];

const ENTITY_LABEL = new Map<string, string>(
  ENTITY_FILTERS.map((spec) => [spec.key, spec.label]),
);

const PAGE_SIZE = 40;

// Column widths for the Intel list. Order matches the columns rendered
// in the list-header / IntelRow below: [sev-bar, type, title, location,
// tags, status]. Persisted under its own key so the Findings and Intel
// tabs don't trample each other.
const INTEL_LIST_DEFAULTS = [10, 120, 480, 260, 260, 140];
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

const SEV_COLORS: Record<string, string> = {
  critical: "#991b1b",
  high: "#c64d15",
  medium: "#a16207",
  low: "#17354c",
  info: "#9a988d",
};
function sevDotColor(sev: string): string {
  return SEV_COLORS[sev] || "#9a988d";
}

// Per-entity accent colors used when a row has no CVSS-derived severity
// (i.e. everything except CVE). Keeps the Intel list visually distinguishable
// by category instead of painting every row the default gray.
const ITYPE_COLORS: Record<string, string> = {
  tech_component: "#17354c",
  person: "#7c3aed",
  email: "#2f7f52",
  domain: "#0d6b6b",
  credentials: "#c64d15",
  cve: "#991b1b",
  dns_record: "#4b5563",
  social_profile: "#be185d",
  breach_record: "#6b0d0d",
  org_fact: "#a16207",
  note: "#8c7b62",
};

// Status color buckets. Arbitrary status strings from different intel types
// (domain live_status, credential state, CVE validation_status, etc.) collapse
// into a small semantic palette so the Status filter chips read consistently.
const STATUS_COLORS: Record<string, string> = {
  active: "#2f7f52",
  blocked: "#991b1b",
  exploited: "#6b0d0d",
  false_positive: "#8c7b62",
  unreviewed: "#9a988d",
};
function statusColorKey(s: string): string {
  const v = s.toLowerCase();
  if (v === "active" || v === "live" || v === "up" || v === "valid" || v === "version_match") return "active";
  if (v === "blocked" || v === "down" || v === "dead" || v === "revoked" || v === "invalid") return "blocked";
  if (v === "exploited") return "exploited";
  if (v === "ruled_out" || v === "false_positive") return "false_positive";
  return "unreviewed";
}

// ── Helpers ──────────────────────────────────────────────────────────
function relTime(iso: string | undefined | null): string {
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

// ── Derived row (per entity) ─────────────────────────────────────────
type Derived = {
  id: string; // stable React key — entity:key or entity:index
  entity: EntityFilter;
  entityLabel: string;
  title: string;
  subtitle: string;
  location: string;
  status: string | null;
  statusLabel: string;
  statusPill: string | null; // css pill class (e.g. "pill-active") or null
  sev: string | null; // sev-* tier for coloring, or null
  sevLabel: string | null;
  source: string;
  host: string;
  tags: string[];
  updated_at: string;
  created_at: string;
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
  let statusLabel = "";
  let statusPill: string | null = null;
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
      statusLabel = conf;
      statusPill = conf ? "pill-unreviewed" : null;
      if (conf) tags.push(conf);
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
      statusLabel = live;
      if (live) tags.push(live);
      if (live === "live" || live === "up" || live === "active") statusPill = "pill-active";
      else if (live === "down" || live === "dead") statusPill = "pill-blocked";
      else if (live) statusPill = "pill-unreviewed";
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
      statusLabel = st;
      if (st === "active" || st === "valid") statusPill = "pill-active";
      else if (st === "blocked" || st === "revoked" || st === "invalid") statusPill = "pill-blocked";
      else if (st) statusPill = "pill-unreviewed";
      if (st) tags.push(st);
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
      statusLabel = valStatus.replace(/_/g, " ");
      if (valStatus === "exploited") statusPill = "pill-exploited";
      else if (valStatus === "version_match") statusPill = "pill-active";
      else if (valStatus === "ruled_out") statusPill = "pill-false_positive";
      else if (valStatus === "unverified") statusPill = "pill-unreviewed";
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
    sev || "",
    source,
    agent,
    host,
    ...tags,
    entityTypeSlug(entity),
    JSON.stringify(raw),
  ];

  return {
    id,
    entity,
    entityLabel: ENTITY_LABEL.get(entity) || entity,
    title: title || "(untitled)",
    subtitle,
    location,
    status,
    statusLabel,
    statusPill,
    sev,
    sevLabel,
    source,
    host,
    tags,
    updated_at,
    created_at,
    raw,
    searchCorpus: corpusParts.filter(Boolean).join(" \n ").toLowerCase(),
  };
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

// ── Component ────────────────────────────────────────────────────────
export function IntelTab({ engagementKey, summary }: IntelTabProps) {
  // Per-entity caches (each entity is loaded lazily). Using a Map means we
  // only refetch an entity when its cache is cold.
  const [cache, setCache] = useState<Map<EntityFilter, Record<string, unknown>[]>>(
    () => new Map(),
  );
  const [loading, setLoading] = useState<Set<EntityFilter>>(new Set());
  const [errors, setErrors] = useState<Map<EntityFilter, string>>(new Map());

  // Which entities have been fetched / are in-flight (as refs for mutable
  // access inside async callbacks).
  const inflight = useRef<Set<EntityFilter>>(new Set());
  const fetchedRef = useRef<Set<EntityFilter>>(new Set());

  const [query, setQuery] = useState("");
  const [entityFilters, setEntityFilters] = useState<Set<EntityFilter>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<string>>(new Set());
  const [sourceFilters, setSourceFilters] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);
  const [cmdOpen, setCmdOpen] = useState(false);

  // Secondary lookups (FTS search + by-URL).
  const [fts, setFts] = useState<IntelSearchHit[] | null>(null);
  const [ftsError, setFtsError] = useState<string | null>(null);
  const [ftsLoading, setFtsLoading] = useState(false);

  const [urlQuery, setUrlQuery] = useState("");
  const [urlResults, setUrlResults] = useState<IntelByUrlResponse | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);
  const [urlLoading, setUrlLoading] = useState(false);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Detail-modal open state. See CommandsTab.tsx for design notes.
  const [detailOpen, setDetailOpen] = useState(false);
  const rowRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const lastFocusIdRef = useRef<string | null>(null);

  // Column widths for the Intel list. Separate storage key from the
  // Findings list so the two don't collide.
  const {
    gridTemplate: listGridTemplate,
    startResize: startListResize,
    resetColumn: resetListColumn,
  } = useResizableColumns(
    "intel.col-widths",
    INTEL_LIST_DEFAULTS,
    INTEL_LIST_MINS,
  );

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Fetch each entity on mount; skip if already loaded. The engagementKey
  // change invalidates the whole cache.
  useEffect(() => {
    // Reset caches when the engagement changes.
    setCache(new Map());
    setErrors(new Map());
    fetchedRef.current = new Set();
    inflight.current = new Set();

    let cancelled = false;

    const fetchOne = (spec: FilterSpec) => {
      if (fetchedRef.current.has(spec.key) || inflight.current.has(spec.key)) return;
      inflight.current.add(spec.key);
      setLoading((prev) => new Set(prev).add(spec.key));

      const p: Promise<Record<string, unknown>[]> =
        spec.key === "credentials"
          ? listIntelCredentials(engagementKey)
          : listIntel(engagementKey, spec.key as IntelEntityType).then(
              (payload: ListIntelResponse) =>
                payload.items as unknown as Record<string, unknown>[],
            );

      p.then((items) => {
        if (cancelled) return;
        setCache((prev) => {
          const next = new Map(prev);
          next.set(spec.key, items);
          return next;
        });
        fetchedRef.current.add(spec.key);
      })
        .catch((err: unknown) => {
          if (cancelled) return;
          setCache((prev) => {
            const next = new Map(prev);
            next.set(spec.key, []);
            return next;
          });
          setErrors((prev) => {
            const next = new Map(prev);
            next.set(spec.key, err instanceof Error ? err.message : "Failed to load");
            return next;
          });
          fetchedRef.current.add(spec.key);
        })
        .finally(() => {
          if (cancelled) return;
          inflight.current.delete(spec.key);
          setLoading((prev) => {
            const next = new Set(prev);
            next.delete(spec.key);
            return next;
          });
        });
    };

    for (const spec of ENTITY_FILTERS) fetchOne(spec);

    return () => {
      cancelled = true;
    };
  }, [engagementKey]);

  // Derived list across all entities.
  const derivedList = useMemo<Derived[]>(() => {
    const out: Derived[] = [];
    for (const spec of ENTITY_FILTERS) {
      const rows = cache.get(spec.key) || [];
      rows.forEach((row, i) => {
        out.push(derive(spec.key, row as Record<string, unknown>, i));
      });
    }
    return out;
  }, [cache]);

  const derivedById = useMemo(() => {
    const m = new Map<string, Derived>();
    for (const d of derivedList) m.set(d.id, d);
    return m;
  }, [derivedList]);

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

  const filtered = useMemo(() => {
    const list = derivedList.filter((d) => {
      if (entityFilters.size && !entityFilters.has(d.entity)) return false;
      if (statusFilters.size && !statusFilters.has(d.status || "__none__")) return false;
      if (sourceFilters.size && !sourceFilters.has(d.source || "__none__")) return false;
      if (!matchesQuery(d, parsedQuery)) return false;
      return true;
    });
    // Sort: newest first by updated_at, then title.
    list.sort((a, b) => {
      const aT = a.updated_at || a.created_at;
      const bT = b.updated_at || b.created_at;
      if (aT && bT && aT !== bT) return bT.localeCompare(aT);
      return a.title.localeCompare(b.title);
    });
    return list;
  }, [derivedList, entityFilters, statusFilters, sourceFilters, parsedQuery, matchesQuery]);

  // Reset page when filters change.
  useEffect(() => {
    setPage(0);
  }, [entityFilters, statusFilters, sourceFilters, query]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  useEffect(() => {
    setPage((p) => Math.min(p, totalPages - 1));
  }, [totalPages]);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Keep selection valid — if filters drop the currently selected row,
  // fall through to the first filtered row. No auto-open-modal on mount.
  useEffect(() => {
    if (selectedId && !derivedById.has(selectedId)) {
      setSelectedId(derivedList[0]?.id ?? null);
      setDetailOpen(false);
    }
  }, [derivedList, derivedById, selectedId]);

  const selectedDerived = selectedId ? derivedById.get(selectedId) ?? null : null;

  // Keyboard shortcuts (same as FindingsTab).
  const filteredRef = useRef(filtered);
  filteredRef.current = filtered;
  const selectedRef = useRef(selectedId);
  selectedRef.current = selectedId;
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
          setSelectedId(null);
        }
        return;
      }
      if (!isTyping && (e.key === "[" || e.key === "]")) {
        e.preventDefault();
        const list = filteredRef.current;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.id === cur);
        if (idx < 0) {
          if (list[0]) setSelectedId(list[0].id);
          return;
        }
        const next = e.key === "[" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      if (!isTyping && (e.key === "j" || e.key === "k")) {
        e.preventDefault();
        const list = filteredRef.current;
        const cur = selectedRef.current;
        const idx = list.findIndex((f) => f.id === cur);
        if (idx < 0 && list[0]) {
          setSelectedId(list[0].id);
          return;
        }
        const next = e.key === "k" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      if (!isTyping && e.key === "Enter" && selectedRef.current != null) {
        e.preventDefault();
        setDetailOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Counts.
  const entityCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) c[d.entity] = (c[d.entity] || 0) + 1;
    return c;
  }, [derivedList]);
  const statusCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      if (!d.status) continue;
      c[d.status] = (c[d.status] || 0) + 1;
    }
    return c;
  }, [derivedList]);
  const sourceCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      if (!d.source) continue;
      c[d.source] = (c[d.source] || 0) + 1;
    }
    return c;
  }, [derivedList]);
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
    setQuery("");
  };

  const activeFilterCount =
    entityFilters.size + statusFilters.size + sourceFilters.size + (query ? 1 : 0);

  const loadingAny = loading.size > 0;

  // FTS search.
  const runSearch = () => {
    const q = query.trim();
    if (!q) {
      setFts(null);
      setFtsError(null);
      return;
    }
    setFtsLoading(true);
    setFtsError(null);
    searchIntel(engagementKey, { q })
      .then((rows) => setFts(rows))
      .catch((err: unknown) => {
        setFts([]);
        setFtsError(err instanceof Error ? err.message : "Search failed");
      })
      .finally(() => setFtsLoading(false));
  };

  const runUrlSearch = () => {
    const u = urlQuery.trim();
    if (!u) {
      setUrlResults(null);
      setUrlError(null);
      return;
    }
    setUrlLoading(true);
    setUrlError(null);
    intelByUrl(engagementKey, u)
      .then((resp) => setUrlResults(resp))
      .catch((err: unknown) => {
        setUrlResults(null);
        setUrlError(err instanceof Error ? err.message : "By-URL lookup failed");
      })
      .finally(() => setUrlLoading(false));
  };

  return (
    <div className="findings-redesign">
      <div className="page-head">
        <div>
          <h1 className="page-title">Intel</h1>
          <div className="page-crumbs">
            Engagement <code>{engagementKey}</code> ·{" "}
            <span>
              {filtered.length} of {derivedList.length} records
              {loadingAny && " · loading…"}
            </span>
          </div>
        </div>
        <EntitySpark counts={entityCounts} />
      </div>

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search any field — name, host, tag, value… (try type:cve cvss:high status:active)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) runSearch();
              }}
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
            <button type="button" className="qa-btn" onClick={runSearch} disabled={ftsLoading}>
              {ftsLoading ? "Searching…" : "FTS"}
            </button>
            <button type="button" className="qa-btn" onClick={() => setCmdOpen(true)}>
              Jump to… <span className="search-kbd" style={{ marginLeft: 4 }}>⌘K</span>
            </button>
          </div>
        </div>
        <div className="filter-row">
          <div className="filter-group">
            <span className="filter-label">Type</span>
            {ENTITY_FILTERS.map((spec) => {
              const count = entityCounts[spec.key] ?? summaryCounts[spec.key] ?? 0;
              if (!count && !entityFilters.has(spec.key)) return null;
              return (
                <button
                  key={spec.key}
                  type="button"
                  className={`filter-chip itype-${spec.key} ${entityFilters.has(spec.key) ? "is-active" : ""}`}
                  onClick={() => toggle(entityFilters, setEntityFilters, spec.key)}
                >
                  <span className="sev-dot" style={{ background: ITYPE_COLORS[spec.key] }} />
                  {spec.label}
                  <span className="filter-count">{count}</span>
                </button>
              );
            })}
          </div>
          {Object.keys(statusCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Status</span>
              {Object.entries(statusCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 12)
                .map(([s, n]) => (
                  <button
                    key={s}
                    type="button"
                    className={`filter-chip istatus-${statusColorKey(s)} ${statusFilters.has(s) ? "is-active" : ""}`}
                    onClick={() => toggle(statusFilters, setStatusFilters, s)}
                  >
                    <span className="sev-dot" style={{ background: STATUS_COLORS[statusColorKey(s)] }} />
                    {s.replace(/_/g, " ")}
                    <span className="filter-count">{n}</span>
                  </button>
                ))}
            </div>
          )}
          {Object.keys(sourceCounts).length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Source</span>
              {Object.entries(sourceCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([s, n]) => (
                  <button
                    key={s}
                    type="button"
                    className={`filter-chip isource ${sourceFilters.has(s) ? "is-active" : ""}`}
                    onClick={() => toggle(sourceFilters, setSourceFilters, s)}
                  >
                    <span className="sev-dot" style={{ background: "#0d6b6b" }} />
                    {s}
                    <span className="filter-count">{n}</span>
                  </button>
                ))}
            </div>
          )}
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>

        {/* Secondary by-URL input (preserves original IntelTab capability). */}
        <div className="filter-row">
          <div className="filter-group" style={{ flex: "1 1 auto" }}>
            <span className="filter-label">By URL</span>
            <input
              type="search"
              className="search-input"
              placeholder="Lookup anything from this URL…"
              value={urlQuery}
              onChange={(e) => setUrlQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runUrlSearch();
              }}
              style={{
                border: "1px solid var(--border)",
                borderRadius: 6,
                padding: "6px 10px",
                fontSize: "0.82rem",
                minWidth: 260,
                flex: "1 1 260px",
              }}
            />
            <button type="button" className="qa-btn" onClick={runUrlSearch} disabled={urlLoading}>
              {urlLoading ? "Looking up…" : "Go"}
            </button>
            {(urlResults || urlError) && (
              <button
                type="button"
                className="filter-clear"
                onClick={() => {
                  setUrlQuery("");
                  setUrlResults(null);
                  setUrlError(null);
                }}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      </div>

      {/* FTS / by-URL side panels (only render when in use). */}
      {(fts !== null || ftsError || urlResults || urlError) && (
        <div className="panel findings-toolbar-panel" style={{ padding: 14, display: "grid", gap: 14 }}>
          {fts !== null && (
            <div>
              <p className="section-title">
                FTS results <span className="count">{fts.length}</span>
              </p>
              {ftsError && <p className="empty" style={{ padding: 8 }}>{ftsError}</p>}
              {fts.length === 0 && !ftsError && <p className="empty" style={{ padding: 8 }}>No hits.</p>}
              {fts.length > 0 && (
                <div style={{ display: "grid", gap: 4 }}>
                  {fts.slice(0, 40).map((hit, i) => (
                    <button
                      key={`${hit.entity_type}:${hit.source_id}:${i}`}
                      type="button"
                      className="link-card"
                      onClick={() => {
                        // Best-effort: try to find the corresponding derived
                        // row in local cache so the drawer can open.
                        const match = derivedList.find(
                          (d) =>
                            d.entity === (hit.entity_type as EntityFilter) &&
                            ((d.raw.id as number | undefined) === hit.source_id),
                        );
                        if (match) setSelectedId(match.id);
                      }}
                    >
                      <span className="link-kind">{hit.entity_type}</span>
                      <span>
                        <span className="link-title">{hit.key}</span>
                        <br />
                        <span className="link-sub">{truncate(hit.body, 180)}</span>
                      </span>
                      <span className="link-sub">{hit.source_name}</span>
                      <span className="link-go">›</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
          {urlResults !== null && (
            <div>
              <p className="section-title">
                By-URL: <code>{urlQuery}</code>
              </p>
              {urlError && <p className="empty" style={{ padding: 8 }}>{urlError}</p>}
              <UrlResultBlock label="Domains" rows={urlResults.domains as unknown as Record<string, unknown>[]} />
              <UrlResultBlock label="Services" rows={urlResults.services} />
              <UrlResultBlock label="Surfaces" rows={urlResults.surfaces} />
              <UrlResultBlock label="Request variants" rows={urlResults.request_variants} />
            </div>
          )}
        </div>
      )}

      {/* List (detail renders as a centred modal below) */}
      <div className="findings-shell">
        <section className="list-panel panel">
          <div className="list-scroll-x">
            <div
              className="list-header"
              style={{ gridTemplateColumns: listGridTemplate, minWidth: "fit-content" }}
            >
              <span />
              <span>
                Type
                <span
                  className="col-resize-handle"
                  onPointerDown={(e) => startListResize(1, e)}
                  onDoubleClick={() => resetListColumn(1)}
                />
              </span>
              <span>
                Title / subtitle
                <span
                  className="col-resize-handle"
                  onPointerDown={(e) => startListResize(2, e)}
                  onDoubleClick={() => resetListColumn(2)}
                />
              </span>
              <span>
                Location
                <span
                  className="col-resize-handle"
                  onPointerDown={(e) => startListResize(3, e)}
                  onDoubleClick={() => resetListColumn(3)}
                />
              </span>
              <span>
                Tags
                <span
                  className="col-resize-handle"
                  onPointerDown={(e) => startListResize(4, e)}
                  onDoubleClick={() => resetListColumn(4)}
                />
              </span>
              <span style={{ textAlign: "right" }}>Status</span>
            </div>
            <div className="list-scroll">
              {pageRows.length === 0 ? (
                <div className="empty">
                  {loadingAny ? "Loading intel…" : "No intel records match."}
                  <div style={{ marginTop: 10 }}>
                    <button type="button" className="qa-btn" onClick={clearAll}>
                      Clear filters
                    </button>
                  </div>
                </div>
              ) : (
                pageRows.map((d) => (
                  <IntelRow
                    key={d.id}
                    d={d}
                    selected={selectedId === d.id}
                    onClick={() => {
                      setSelectedId(d.id);
                      lastFocusIdRef.current = d.id;
                      setDetailOpen(true);
                    }}
                    freeTerms={parsedQuery.freeTerms}
                    gridTemplate={listGridTemplate}
                    registerRef={(id, el) => {
                      if (el) rowRefs.current.set(id, el);
                      else rowRefs.current.delete(id);
                    }}
                  />
                ))
              )}
            </div>
          </div>
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
          {errors.size > 0 && (
            <div
              className="empty"
              style={{ textAlign: "left", padding: "10px 14px", fontSize: "0.78rem" }}
            >
              {Array.from(errors.entries()).map(([k, v]) => (
                <div key={k}>
                  <code>{k}</code>: {v}
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {detailOpen && selectedDerived && (
        <DetailModal
          onClose={() => {
            setDetailOpen(false);
            const el =
              lastFocusIdRef.current != null
                ? rowRefs.current.get(lastFocusIdRef.current)
                : null;
            queueMicrotask(() => el?.focus());
          }}
          titleId="intel-detail-modal-title"
        >
          <Drawer d={selectedDerived} titleId="intel-detail-modal-title" />
        </DetailModal>
      )}

      <div className="findings-shortcuts">
        <span><code>/</code> focus search</span>
        <span><code>⌘K</code> jump to record</span>
        <span><code>j / k</code> move</span>
        <span><code>[ / ]</code> prev / next</span>
        <span><code>Enter</code> open detail</span>
        <span><code>Esc</code> close detail</span>
      </div>

      {cmdOpen && (
        <CommandPalette
          derivedList={derivedList}
          onSelect={(id) => {
            setSelectedId(id);
            lastFocusIdRef.current = id;
            setCmdOpen(false);
            setDetailOpen(true);
          }}
          onClose={() => setCmdOpen(false)}
        />
      )}
    </div>
  );
}

// ── EntitySpark ──────────────────────────────────────────────────────
function EntitySpark({ counts }: { counts: Record<string, number> }) {
  const entries = ENTITY_FILTERS.filter((s) => counts[s.key]);
  if (entries.length === 0) return null;
  const max = Math.max(1, ...entries.map((s) => counts[s.key]));
  return (
    <div className="sev-sparkline-wrap">
      <span className="sev-label">By type</span>
      <div className="sev-sparkline">
        {entries.map((s) => {
          const c = counts[s.key] || 0;
          const h = Math.max(4, (c / max) * 26);
          return (
            <div
              key={s.key}
              className="sev-bar"
              style={{ height: `${h}px`, background: "var(--accent)", opacity: c ? 0.85 : 0.2 }}
              title={`${s.label}: ${c}`}
            >
              <span>{c}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── IntelRow ─────────────────────────────────────────────────────────
function IntelRow({
  d,
  selected,
  onClick,
  freeTerms,
  gridTemplate,
  registerRef,
}: {
  d: Derived;
  selected: boolean;
  onClick: () => void;
  freeTerms: string[];
  gridTemplate?: string;
  registerRef?: (id: string, el: HTMLButtonElement | null) => void;
}) {
  const isCveWithSev = d.entity === "cve" && d.sev != null;
  const barClass = isCveWithSev ? `sevbar-${d.sev}` : `ibar-${d.entity}`;
  const pillClass = isCveWithSev ? String(d.sev) : `itype-${d.entity}`;
  return (
    <button
      type="button"
      className={`frow ${selected ? "is-selected" : ""}`}
      onClick={onClick}
      data-id={d.id}
      ref={(el) => registerRef?.(d.id, el)}
      style={gridTemplate ? { gridTemplateColumns: gridTemplate, minWidth: "fit-content" } : { minWidth: "fit-content" }}
    >
      <span className={`frow-sevbar ${barClass}`} />
      <span className={`frow-sev ${pillClass}`}>{d.entityLabel}</span>
      <span className="frow-main">
        <span className="frow-title">{highlight(d.title, freeTerms)}</span>
        <span className="frow-meta">
          {d.subtitle && <span className="mono">{truncate(d.subtitle, 80)}</span>}
          {d.source && (
            <>
              <span className="dot" />
              <span>{d.source}</span>
            </>
          )}
          {d.updated_at && (
            <>
              <span className="dot" />
              <span>{relTime(d.updated_at)}</span>
            </>
          )}
        </span>
      </span>
      <span className="frow-loc">{d.location || ""}</span>
      <span className="frow-tags">
        {d.sevLabel && <span className="tag cve">{d.sevLabel}</span>}
        {d.tags.slice(0, 4).map((t, i) => (
          <span key={`t-${i}-${t}`} className="tag">{t}</span>
        ))}
      </span>
      <span className="frow-status">
        {d.statusPill && d.status ? (
          <span className={`pill ${d.statusPill}`}>{d.statusLabel || d.status}</span>
        ) : d.status ? (
          <span className="pill pill-unreviewed">{d.statusLabel || d.status}</span>
        ) : null}
      </span>
    </button>
  );
}

// ── Drawer ───────────────────────────────────────────────────────────
type DrawerProps = {
  d: Derived;
  titleId?: string;
};

type TabId = "overview" | "references" | "provenance" | "raw";

function Drawer({ d, titleId }: DrawerProps) {
  const [tab, setTab] = useState<TabId>("overview");
  useEffect(() => {
    setTab("overview");
  }, [d?.id]);

  const provenance = (d.raw.provenance as Record<string, unknown>) || {};
  const hasProvenance = Object.keys(provenance).length > 0;
  const notes = (d.raw.notes as string) || "";

  // Count fields (rough heuristic for tab badge).
  const refCount =
    (Array.isArray((d.raw as Record<string, unknown>).tags) ? (d.raw.tags as unknown[]).length : 0) +
    (d.raw.url ? 1 : 0) +
    (notes ? 1 : 0);

  const tabs: { id: TabId; label: string; count?: number; hidden?: boolean }[] = [
    { id: "overview", label: "Overview" },
    { id: "references", label: "Notes & tags", count: refCount, hidden: refCount === 0 },
    { id: "provenance", label: "Provenance", count: hasProvenance ? 1 : 0, hidden: !hasProvenance },
    { id: "raw", label: "Raw" },
  ];
  const visibleTabs = tabs.filter((t) => !t.hidden);
  const isCveWithSev = d.entity === "cve" && d.sev != null;
  const sevClass = d.sev || "info";
  const heroAccentClass = isCveWithSev ? `sev-${d.sev}` : `itype-${d.entity}`;
  const heroPillClass = isCveWithSev ? sevClass : `itype-${d.entity}`;
  const heroDotColor = isCveWithSev ? sevDotColor(sevClass) : ITYPE_COLORS[d.entity];

  const copyId = () => {
    try {
      void navigator.clipboard?.writeText(d.id);
    } catch {
      // ignore
    }
  };

  return (
    <aside className="drawer-panel panel">
      <div className={`drawer-hero ${heroAccentClass}`}>
        <div className="drawer-top">
          <div className="drawer-slug">
            <span>{d.id}</span>
            <button type="button" className="copy-btn" onClick={copyId} title="Copy id">
              id
            </button>
          </div>
          {/* Maximize retired with the move to a centred modal. The
              modal's own × close button handles dismissal. */}
        </div>
        <h2 id={titleId} className="drawer-title">{d.title}</h2>
        <div className="hero-meta">
          <span className={`hero-sev ${heroPillClass}`}>
            <span className="sev-dot" style={{ background: heroDotColor }} />
            {d.entityLabel}
          </span>
          {d.sevLabel && <span className="tag cve">{d.sevLabel}</span>}
          {d.statusPill && d.status && (
            <span className={`pill ${d.statusPill}`}>{d.statusLabel || d.status}</span>
          )}
          {d.source && <span className="tag">{d.source}</span>}
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
            {t.count != null && t.count > 0 && <span className="count">{t.count}</span>}
          </button>
        ))}
      </div>
      <div className="drawer-body">
        {tab === "overview" && <OverviewPane d={d} />}
        {tab === "references" && <ReferencesPane d={d} />}
        {tab === "provenance" && <ProvenancePane d={d} />}
        {tab === "raw" && <RawPane d={d} />}
      </div>
    </aside>
  );
}

// ── Panes ────────────────────────────────────────────────────────────
function KV({ k, v, mono }: { k: string; v: unknown; mono?: boolean }) {
  if (v === undefined || v === null || v === "") return null;
  const str = typeof v === "string" ? v : fmtCell(v);
  if (!str) return null;
  return (
    <div className="kv">
      <p className="k">{k}</p>
      <p className={`v ${mono ? "mono" : ""}`}>{str}</p>
    </div>
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
  "created_at",
  "updated_at",
]);

function OverviewPane({ d }: { d: Derived }) {
  const raw = d.raw;
  const known = new Set<string>(BASE_KEYS_HANDLED);
  const add = (k: string) => known.add(k);

  let specific: React.ReactNode = null;
  switch (d.entity) {
    case "tech_component":
      ["component", "version", "confidence", "evidence_ref", "first_seen_at", "last_seen_at"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Component" v={raw.component} mono />
          <KV k="Version" v={raw.version} mono />
          <KV k="Confidence" v={raw.confidence} />
          <KV k="Evidence ref" v={raw.evidence_ref} mono />
          <KV k="First seen" v={raw.first_seen_at} />
          <KV k="Last seen" v={raw.last_seen_at} />
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
          <KV k="Email" v={raw.email} mono />
        </div>
      );
      break;
    case "email":
      ["address", "role_hint", "linked_person_id"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Address" v={raw.address} mono />
          <KV k="Role hint" v={raw.role_hint} />
          <KV k="Linked person" v={raw.linked_person_id} mono />
        </div>
      );
      break;
    case "domain":
      ["identity", "kind", "value", "live_status"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Identity" v={raw.identity} mono />
          <KV k="Kind" v={raw.kind} />
          <KV k="Value" v={raw.value} mono />
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
            .map(([k, v]) => (
              <KV key={k} k={k.replace(/_/g, " ")} v={v} mono={/id|key|host|url|endpoint|token|hash/i.test(k)} />
            ))}
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
          <KV k="CVE" v={raw.cve_id} mono />
          <KV k="Affected component" v={raw.affected_component} mono />
          <KV k="Affected versions" v={raw.affected_version_range} mono />
          <KV k="CVSS score" v={raw.cvss_score} />
          <KV k="CVSS vector" v={raw.cvss_vector} mono />
          <KV k="CWE" v={raw.cwe_id} mono />
          <KV k="PoC available" v={raw.poc_available} />
          <KV k="Validation" v={raw.validation_status} />
          <KV k="Linked finding" v={raw.linked_finding_slug} mono />
        </div>
      );
      break;
    case "dns_record":
      ["record_type", "name", "value", "first_seen", "last_seen"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Type" v={raw.record_type} mono />
          <KV k="Name" v={raw.name} mono />
          <KV k="Value" v={raw.value} mono />
          <KV k="First seen" v={raw.first_seen} />
          <KV k="Last seen" v={raw.last_seen} />
        </div>
      );
      break;
    case "social_profile":
      ["subject_kind", "subject_ref", "platform", "handle", "url"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Platform" v={raw.platform} />
          <KV k="Handle" v={raw.handle} mono />
          <KV k="Subject" v={raw.subject_ref} mono />
          <KV k="Subject kind" v={raw.subject_kind} />
          <KV k="URL" v={raw.url} mono />
        </div>
      );
      break;
    case "breach_record":
      ["subject", "breach_name", "breach_date", "data_types"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Breach" v={raw.breach_name} />
          <KV k="Subject" v={raw.subject} mono />
          <KV k="Date" v={raw.breach_date} />
          <KV k="Data types" v={raw.data_types} />
        </div>
      );
      break;
    case "org_fact":
      ["fact_key", "fact_value"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Key" v={raw.fact_key} mono />
          <KV k="Value" v={raw.fact_value} />
        </div>
      );
      break;
    case "note":
      ["title", "body_markdown", "source_agent", "tags"].forEach(add);
      specific = (
        <div className="kv-grid">
          <KV k="Title" v={raw.title} />
          <KV k="Source agent" v={raw.source_agent} mono />
          <KV k="Tags" v={Array.isArray(raw.tags) ? (raw.tags as string[]).join(", ") : ""} />
        </div>
      );
      break;
  }

  const bodyMarkdown = (raw.body_markdown as string | undefined) || "";
  const additional = Object.keys(raw).filter((k) => !known.has(k));

  return (
    <>
      <div className="section">
        <p className="section-title">{d.entityLabel}</p>
        {specific}
      </div>
      <div className="section">
        <p className="section-title">Metadata</p>
        <div className="kv-grid">
          <KV k="Source" v={d.source} />
          <KV k="Record ID" v={raw.id} mono />
          <KV k="Created" v={d.created_at || raw.created_at} />
          <KV k="Updated" v={d.updated_at || raw.updated_at} />
        </div>
      </div>
      {bodyMarkdown && (
        <div className="section">
          <p className="section-title">Body</p>
          <NotesBody text={bodyMarkdown} />
        </div>
      )}
      {additional.length > 0 && (
        <div className="section">
          <p className="section-title">Additional details</p>
          <div className="json-children">
            {additional.map((key) => (
              <JsonTree key={key} label={key} value={toJsonValue(raw[key])} defaultOpen />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function ReferencesPane({ d }: { d: Derived }) {
  const raw = d.raw;
  const notes = (raw.notes as string) || "";
  const url = (raw.url as string) || "";
  const tags = Array.isArray(raw.tags) ? (raw.tags as string[]) : [];

  if (!notes && !url && tags.length === 0) {
    return <p className="empty">No notes or tags recorded.</p>;
  }
  return (
    <>
      {tags.length > 0 && (
        <div className="section inline-row">
          <p className="section-title section-title--inline">Tags</p>
          <div className="tag-row tag-row--inline">
            {tags.map((t, i) => (
              <span key={`${i}-${t}`} className="tag">{t}</span>
            ))}
          </div>
        </div>
      )}
      {notes && (
        <div className="section">
          <p className="section-title">Notes</p>
          <NotesBody text={notes} />
        </div>
      )}
      {url && (
        <div className="section">
          <p className="section-title">URL</p>
          <ul className="ref-list">
            <li>
              <a href={url} target="_blank" rel="noopener noreferrer">
                {url}
                <IconExternal />
                <span className="host">{extractHost(url)}</span>
              </a>
            </li>
          </ul>
        </div>
      )}
    </>
  );
}

function ProvenancePane({ d }: { d: Derived }) {
  const prov = (d.raw.provenance as Record<string, unknown>) || {};
  if (Object.keys(prov).length === 0)
    return <p className="empty">No provenance recorded.</p>;
  const extras = Object.entries(prov).filter(
    ([k]) =>
      !["agent_name", "captured_at", "artifact_ref", "evidence_quote"].includes(k),
  );
  return (
    <div className="section">
      <p className="section-title">Provenance</p>
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
    </div>
  );
}

function RawPane({ d }: { d: Derived }) {
  return (
    <div className="section">
      <p className="section-title">Raw record</p>
      <JsonView value={d.raw} />
    </div>
  );
}

// ── By-URL summary block ─────────────────────────────────────────────
function UrlResultBlock({
  label,
  rows,
}: {
  label: string;
  rows: Record<string, unknown>[];
}) {
  if (!rows || rows.length === 0) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <p className="section-title">
        {label} <span className="count">{rows.length}</span>
      </p>
      <div style={{ display: "grid", gap: 4 }}>
        {rows.map((row, i) => (
          <div key={i} className="link-card" style={{ cursor: "default" }}>
            <span className="link-kind">{label.toLowerCase()}</span>
            <span className="link-title mono">{truncate(summarizeRow(row), 220)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function summarizeRow(row: Record<string, unknown>): string {
  for (const key of ["identity", "endpoint", "target_descriptor", "host", "name", "address", "url"]) {
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
}: {
  derivedList: Derived[];
  onSelect: (id: string) => void;
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
              <div
                key={d.id}
                className={`cmd-item ${i === idx ? "is-active" : ""}`}
                onMouseEnter={() => setIdx(i)}
                onClick={() => onSelect(d.id)}
              >
                <span
                  className="sev-dot"
                  style={{ background: sevDotColor(d.sev || "info") }}
                />
                <span>
                  <div className="cmd-title">{d.title}</div>
                  <div className="cmd-sub">
                    {d.entityLabel}
                    {d.source ? ` · ${d.source}` : ""}
                    {d.status ? ` · ${d.status}` : ""}
                  </div>
                </span>
                <span className="cmd-sub">{d.location || ""}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
