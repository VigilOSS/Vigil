import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type RefObject } from "react";
import type {
  AssessmentCommandRun,
  AssessmentCommandRunDetail,
} from "../lib/api";
import {
  getAssessmentCommandRun,
  listAssessmentCommandRuns,
} from "../lib/api";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { Skeleton, TableSkeleton } from "./Skeletons";
import { UntrustedDataNotice } from "./drawer/DrawerKit";

// ag-grid is heavy (~470 kB). Lazy-load the grid so it lands in a
// code-split chunk and never bloats the main entry bundle. The Suspense
// fallback reuses the existing TableSkeleton gate.
const CommandsGrid = lazy(() => import("./CommandsGrid"));

// ── Props ─────────────────────────────────────────────────────────────
type CommandsTabProps = {
  engagementKey: string;
};

// ── Constants ─────────────────────────────────────────────────────────
// Initial fetch cap. Findings/Intel follow the same approach: pull a
// page wide enough to cover every realistic engagement and filter
// client-side. Anything past this cap is lost to the initial view;
// in practice a single engagement's command-run count lives well under.
const INITIAL_FETCH_LIMIT = 1000;

// Status color map — drives the row-left bar, status pill, filter chips,
// and sparkline bars. Trust failures stay distinct from ordinary tool failure.
export const STATUS_COLORS: Record<string, string> = {
  success: "var(--chip-green)",
  failed: "var(--chip-red)",
  timed_out: "var(--chip-orange)",
  suppressed: "var(--chip-muted)",
  artifact: "var(--chip-teal)",
  untrusted: "var(--chip-red)",
};
const STATUS_ORDER = ["success", "failed", "timed_out", "suppressed", "artifact", "untrusted"] as const;
type StatusBucket = (typeof STATUS_ORDER)[number];
const INCOMPLETE_OUTPUT_RETENTION = new Set([
  "measurement_conflict",
  "partially_measured",
  "preview_only",
  "unmeasured",
]);

// Tool color map. Keep the bin name keyed so it also works for short-tail
// tools the operator might pipe through. Anything missing falls back to
// a hash-derived color so colors are stable across reloads.
const TOOL_COLORS: Record<string, string> = {
  nmap: "var(--chip-teal)",
  curl: "var(--chip-navy)",
  wget: "var(--chip-navy)",
  sqlmap: "var(--chip-red)",
  ffuf: "var(--chip-orange)",
  gobuster: "var(--chip-orange)",
  dirb: "var(--chip-orange)",
  katana: "var(--chip-purple)",
  gau: "var(--chip-purple)",
  nikto: "var(--chip-pink)",
  hydra: "var(--chip-maroon)",
  john: "var(--chip-maroon)",
  wpscan: "var(--chip-green)",
  enum4linux: "var(--chip-ochre)",
  dig: "var(--chip-slate)",
  host: "var(--chip-slate)",
  whois: "var(--chip-slate)",
  trufflehog: "var(--chip-ochre)",
  git: "var(--chip-slate)",
  bash: "var(--chip-muted-grey)",
  sh: "var(--chip-muted-grey)",
  python: "var(--chip-green)",
  python3: "var(--chip-green)",
};

// Small hand-tuned palette for the hash fallback so colors stay within the
// existing design language.
const TOOL_HASH_PALETTE = [
  "var(--chip-navy)",
  "var(--chip-teal)",
  "var(--chip-green)",
  "var(--chip-purple)",
  "var(--chip-orange)",
  "var(--chip-ochre)",
  "var(--chip-red)",
  "var(--chip-pink)",
  "var(--chip-slate)",
  "var(--chip-maroon)",
];

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) {
    h = (h * 31 + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

export function toolColor(bin: string): string {
  const key = (bin || "").toLowerCase();
  if (TOOL_COLORS[key]) return TOOL_COLORS[key];
  if (!key) return "var(--chip-muted-grey)";
  return TOOL_HASH_PALETTE[hashString(key) % TOOL_HASH_PALETTE.length];
}

// Agent role color map. Keyed on a substring of the agent name so renames
// to `recon-analyst`, `recon-v2`, etc. still get the recon hue.
const AGENT_ROLE_COLORS: { key: string; color: string }[] = [
  { key: "recon", color: "var(--chip-navy)" },
  { key: "surface", color: "var(--chip-teal)" },
  { key: "vuln", color: "var(--chip-orange)" },
  { key: "exploit", color: "var(--chip-red)" },
  { key: "fuzz", color: "var(--chip-purple)" },
  { key: "osint", color: "var(--chip-green)" },
  { key: "operator", color: "var(--chip-muted-grey)" },
  { key: "code", color: "var(--chip-ochre)" },
];

export function agentColor(name: string): string {
  const n = (name || "").toLowerCase();
  for (const { key, color } of AGENT_ROLE_COLORS) {
    if (n.includes(key)) return color;
  }
  if (!n) return "var(--chip-muted-grey)";
  return TOOL_HASH_PALETTE[hashString(n) % TOOL_HASH_PALETTE.length];
}

// ── Technique color map ───────────────────────────────────────────────
// Five tiers, grouped by vulnerability family. Follows the inline-style
// + CSS-class pattern used for TOOL_COLORS / AGENT_ROLE_COLORS /
// ITYPE_COLORS in IntelTab. Unknown values fall back to a hash-derived
// color from TOOL_HASH_PALETTE — the enum may grow at the server side
// without needing a frontend redeploy.
const TECHNIQUE_COLORS: Record<string, string> = {
  // Red tier — classic high-severity web/app injection + exec.
  SSRF: "var(--chip-red)",
  XSS: "var(--chip-red)",
  XXE: "var(--chip-red)",
  SSTI: "var(--chip-red)",
  CMDI: "var(--chip-red)",
  RCE: "var(--chip-red)",
  // Orange tier — injection + smuggling + redirect families.
  SQLI: "var(--chip-orange)",
  NOSQLI: "var(--chip-orange)",
  LFI: "var(--chip-orange)",
  RFI: "var(--chip-orange)",
  "REQUEST-SMUGGLING": "var(--chip-orange)",
  "OPEN-REDIRECT": "var(--chip-orange)",
  // Purple tier — authz / session / CSRF-family.
  IDOR: "var(--chip-purple)",
  AUTH: "var(--chip-purple)",
  JWT: "var(--chip-purple)",
  CSRF: "var(--chip-purple)",
  CORS: "var(--chip-purple)",
  // Teal tier — discovery / validation (non-attack probes).
  RECON: "var(--chip-teal)",
  DISCOVERY: "var(--chip-teal)",
  OSINT: "var(--chip-teal)",
  FUZZ: "var(--chip-teal)",
  "CVE-VALIDATION": "var(--chip-teal)",
  // Muted tier — catch-all / miscellaneous.
  "INFO-DISCLOSURE": "var(--chip-muted-grey)",
  "RATE-LIMIT": "var(--chip-muted-grey)",
  "EXPLOIT-CHAIN": "var(--chip-muted-grey)",
  OTHER: "var(--chip-muted-grey)",
};

function techniqueColor(t: string | null | undefined): string {
  if (!t) return "var(--chip-muted-grey)";
  const up = t.toUpperCase();
  if (TECHNIQUE_COLORS[up]) return TECHNIQUE_COLORS[up];
  return TOOL_HASH_PALETTE[hashString(up) % TOOL_HASH_PALETTE.length];
}

// Probe_kind is a closed 6-value enum — no hash fallback needed.
const PROBE_KIND_ORDER = [
  "fingerprint",
  "baseline",
  "payload",
  "exploit",
  "replay",
  "cleanup",
] as const;
type ProbeKind = (typeof PROBE_KIND_ORDER)[number];

const PROBE_KIND_COLORS: Record<ProbeKind, string> = {
  fingerprint: "var(--chip-teal)",    // teal — low-touch recon probes
  baseline: "var(--chip-slate)",      // slate — control requests
  payload: "var(--chip-orange)",      // orange — attack payload
  exploit: "var(--chip-red)",         // red — attacker-outcome proof
  replay: "var(--chip-purple)",       // purple — lateral primitive use
  cleanup: "var(--chip-muted-grey)",  // muted — post-op tidy
};

function probeKindColor(pk: string | null | undefined): string {
  if (!pk) return "var(--chip-muted-grey)";
  const k = pk.toLowerCase() as ProbeKind;
  return PROBE_KIND_COLORS[k] || "var(--chip-muted-grey)";
}

// ── Helpers ───────────────────────────────────────────────────────────
// Build a translucent tint from a CSS var color token without appending
// hex-alpha digits (which break when the value is var(--chip-*)).
// pct ≈ 10 reproduces the old "1a" alpha; pct ≈ 13 reproduces "22".
function tint(color: string, pct = 10): string {
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}

export function relTime(iso: string | undefined | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const diffSec = Math.max(0, Math.round((now.getTime() - d.getTime()) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const min = Math.round(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.round(min / 60);
  if (h < 24) return `${h}h ago`;
  const day = Math.round(h / 24);
  if (day < 7) return `${day}d ago`;
  return d.toISOString().slice(0, 10);
}

export function fmtDuration(ms: number): string {
  if (!ms || ms <= 0) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s - m * 60);
  return `${m}m ${r}s`;
}

// Mid-truncate a string. Keeps the head + a "…" + tail so the most
// signalful parts of a long command (binary up front, target at the end)
// both stay visible.
function midTruncate(text: string, max: number): string {
  if (!text) return "";
  if (text.length <= max) return text;
  const head = Math.max(1, Math.floor((max - 1) * 0.6));
  const tail = Math.max(1, max - 1 - head);
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}

// ── Status bucket ─────────────────────────────────────────────────────
// One bucket per row. Pending/deferred suppression remains visibly suppressed;
// evidence-integrity failures never inherit a success-looking process status.
function statusBucket(row: AssessmentCommandRun): StatusBucket {
  const retention = (row.output_retention_status || "").toLowerCase();
  const integrity = (row.output_integrity_status || "").toLowerCase();
  if (integrity === "pending" || integrity === "warning") return "untrusted";
  if (retention === "suppressed" || retention.startsWith("suppression_")) return "suppressed";
  if (retention === "artifact") return "artifact";
  if (
    retention === "untrusted"
    || retention === "integrity_failure"
    || INCOMPLETE_OUTPUT_RETENTION.has(retention)
  ) return "untrusted";
  if (row.timed_out) return "timed_out";
  if (row.success) return "success";
  return "failed";
}

function statusLabel(bucket: StatusBucket): string {
  if (bucket === "timed_out") return "timed out";
  return bucket;
}

// ── Target extraction ────────────────────────────────────────────────
// Best-effort "what did this command hit?" for at-a-glance row rendering
// and the target: filter scope. Strategy:
//   1. First http(s):// URL in the command string wins — return its host.
//   2. Else, parse argv for common target flags (-u/--url/--target/-t).
//      Skip -d (curl POST body conflict).
//   3. Else, tool-specific heuristics: nmap takes the last positional
//      argv; ffuf/sqlmap/katana use -u.
//   4. Else, bare FQDN in positional argv.
//   5. Else "" — rendered as an em-dash.
const FQDN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;
const URL_RE = /(https?:\/\/[^\s"']+)/i;

function extractTarget(row: AssessmentCommandRun): string {
  // 1. URL in the command string.
  const urlMatch = (row.command || "").match(URL_RE);
  if (urlMatch) {
    const raw = urlMatch[1].replace(/[),.;'"]+$/, "");
    try {
      return new URL(raw).host;
    } catch {
      return raw;
    }
  }

  const argv = Array.isArray(row.argv) ? row.argv : [];
  const lower = argv.map((a) => a.toLowerCase());

  // 2. Common target flags. Skip -d on purpose (curl body conflict).
  const TARGET_FLAGS = new Set(["-u", "--url", "--target", "-t"]);
  for (let i = 0; i < argv.length - 1; i += 1) {
    if (TARGET_FLAGS.has(lower[i])) {
      const val = argv[i + 1];
      if (val) {
        if (URL_RE.test(val)) {
          try {
            return new URL(val).host;
          } catch {
            return val;
          }
        }
        return val;
      }
    }
    // Support `--url=value` / `-u=value`.
    for (const flag of TARGET_FLAGS) {
      if (lower[i].startsWith(`${flag}=`)) {
        const val = argv[i].slice(flag.length + 1);
        if (val) {
          if (URL_RE.test(val)) {
            try {
              return new URL(val).host;
            } catch {
              return val;
            }
          }
          return val;
        }
      }
    }
  }

  // 3. Tool-specific fallbacks.
  const bin = (row.tool_bin || "").toLowerCase();
  if (bin === "nmap") {
    // Last positional argv — skip flags and their obvious values.
    for (let i = argv.length - 1; i >= 1; i -= 1) {
      const a = argv[i];
      if (!a.startsWith("-")) return a;
    }
  }

  // 4. Any bare FQDN in argv.
  for (const a of argv.slice(1)) {
    if (!a.startsWith("-") && FQDN_RE.test(a)) return a;
  }
  return "";
}

// ── Search tokenizer ─────────────────────────────────────────────────
// Scopes recognised in the search box. The new scopes (technique / probe /
// intent / destructive / write) match against the four command-metadata
// audit fields added in 2026-04. `write` is an intentional alias for
// `destructive` — reads naturally for operators ("show me every write").
const SCOPES = [
  "tool",
  "agent",
  "phase",
  "rc",
  "status",
  "target",
  "hash",
  "technique",
  "probe",
  "intent",
  "destructive",
  "write",
] as const;
type Scope = (typeof SCOPES)[number];

type ParsedQuery = {
  tokens: { scope: Scope; value: string }[];
  freeTerms: string[];
};

// Pull one whitespace-delimited token from the input, but allow a quoted
// string on the value side of a `scope:"multi word"` pair so the intent
// scope can do substring matches on phrases. Quotes are stripped from
// the returned value.
const TOKEN_RE = /(\S+?:"[^"]*"|"[^"]*"|\S+)/g;

function parseQuery(q: string): ParsedQuery {
  const tokens: ParsedQuery["tokens"] = [];
  const freeTerms: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = TOKEN_RE.exec(q || "")) !== null) {
    let tok = m[1];
    // Bare quoted phrase → free term (with quotes stripped).
    if (tok.startsWith('"') && tok.endsWith('"')) {
      const inner = tok.slice(1, -1).toLowerCase();
      if (inner) freeTerms.push(inner);
      continue;
    }
    const idx = tok.indexOf(":");
    if (idx > 0) {
      const scope = tok.slice(0, idx).toLowerCase();
      let value = tok.slice(idx + 1);
      // scope:"multi word" — strip the quotes, preserve spaces.
      if (value.startsWith('"') && value.endsWith('"')) {
        value = value.slice(1, -1);
      }
      if ((SCOPES as readonly string[]).includes(scope)) {
        tokens.push({ scope: scope as Scope, value: value.toLowerCase() });
        continue;
      }
    }
    freeTerms.push(tok.toLowerCase());
  }
  return { tokens, freeTerms };
}

// ── Derived row ──────────────────────────────────────────────────────
// One-pass normalisation keyed by row id. Computed once per fetch and
// re-used by every filter / render / duplicate-detection pass.
//
// Design choice for search: we do NOT round-trip free terms to the
// backend `q` FTS param for the live list. Instead, a single initial
// fetch pulls all command runs and free terms narrow client-side via
// `searchCorpus.includes()`. Rationale:
//   - Scope filters (status, rc, target) require computed fields the
//     backend doesn't index (status bucket, derived target), so we'd
//     still need a client-side pass anyway.
//   - Duplicate detection + sparkline need the unfiltered set too.
//   - Typing in the search box becomes instant (no re-fetch).
//   - Tradeoff: stdout/stderr preview matches only kick in after the
//     drawer pulls the detail fetch. That's acceptable for v1.
export type Derived = {
  row: AssessmentCommandRun;
  id: number;
  bucket: StatusBucket;
  bucketLabel: string;
  target: string;
  commandPreview: string;
  toolBin: string;
  agentName: string;
  phase: string;
  rcBucket: "zero" | "nonzero" | "timeout" | "none";
  // Command-metadata audit fields, normalised for filtering. Values stay
  // nullable; consumers must render null as "—", not "null".
  techniqueKey: string; // upper-cased match key, "" when absent
  probeKind: string; // lower-cased match key, "" when absent
  intent: string; // verbatim, trimmed — may be ""
  destructive: boolean | null;
  searchCorpus: string;
};

function derive(row: AssessmentCommandRun): Derived {
  const bucket = statusBucket(row);
  const target = extractTarget(row);
  const rcBucket: Derived["rcBucket"] = row.timed_out
    ? "timeout"
    : row.return_code === 0
    ? "zero"
    : row.return_code == null
    ? "none"
    : "nonzero";
  const techniqueKey = (row.technique || "").trim().toUpperCase();
  const probeKind = (row.probe_kind || "").trim().toLowerCase();
  const intent = (row.intent || "").trim();
  const destructive = row.destructive == null ? null : Boolean(row.destructive);
  const corpusParts = [
    row.command,
    (row.argv || []).join(" "),
    row.tool_name,
    row.tool_bin,
    row.agent_name,
    row.phase,
    row.route,
    target,
    row.stdout_suppression_reason,
    row.stderr_suppression_reason,
    row.notes,
    // Include the metadata fields in the free-term corpus so typing a bare
    // term like "ssrf" still matches — the scope: tokens are exact-match.
    techniqueKey,
    probeKind,
    intent,
  ];
  return {
    row,
    id: row.id,
    bucket,
    bucketLabel: statusLabel(bucket),
    target,
    commandPreview: row.command || "",
    toolBin: row.tool_bin || row.tool_name || "",
    agentName: row.agent_name || "",
    phase: row.phase || "",
    rcBucket,
    techniqueKey,
    probeKind,
    intent,
    destructive,
    searchCorpus: corpusParts.filter(Boolean).join(" \n ").toLowerCase(),
  };
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
function copyToClipboard(text: string): void {
  try {
    void navigator.clipboard?.writeText(text);
  } catch {
    // ignore
  }
}

// ── DetailModal ───────────────────────────────────────────────────────
// Centred modal that hosts the per-row Drawer. Shared shell: three tabs
// (Commands / Intel / Findings) reuse the same .detail-modal-* CSS.
// Backdrop click + Esc + × button all close; focus moves into the panel
// on open so keyboard users land inside the dialog, then restores the
// explicit row/palette invoker supplied by the caller.
function DetailModal({
  children,
  onClose,
  titleId,
  returnFocusRef,
}: {
  children: React.ReactNode;
  onClose: () => void;
  titleId?: string;
  returnFocusRef: RefObject<HTMLElement | null>;
}) {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useModalFocus(panelRef, onClose, true, returnFocusRef);
  // Lock body scroll while the modal is mounted so wheel / trackpad /
  // PageUp/PageDown never bubble to the page behind. Reference-counted
  // via modalScrollLock so stacked or rapidly re-opened modals never
  // leave the lock stuck on.
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
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
        {children}
      </div>
    </div>
  );
}

// ── Component ────────────────────────────────────────────────────────
export function CommandsTab({ engagementKey }: CommandsTabProps) {
  const [rows, setRows] = useState<AssessmentCommandRun[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [toolFilters, setToolFilters] = useState<Set<string>>(new Set());
  const [agentFilters, setAgentFilters] = useState<Set<string>>(new Set());
  const [statusFilters, setStatusFilters] = useState<Set<StatusBucket>>(new Set());
  const [techniqueFilters, setTechniqueFilters] = useState<Set<string>>(new Set());
  const [probeKindFilters, setProbeKindFilters] = useState<Set<string>>(new Set());
  const [cmdOpen, setCmdOpen] = useState(false);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  // Detail-modal open state. Separate from `selectedId` so j/k can walk
  // the list without forcing the modal open, and so the modal closes on
  // Escape without discarding the keyboard-navigation cursor.
  const [detailOpen, setDetailOpen] = useState(false);
  const detailInvokerRef = useRef<HTMLElement | null>(null);

  // Detail cache for full stdout/stderr. Keyed by command-run id and
  // populated lazily when the drawer's stdout/stderr tab is opened.
  const [detailCache, setDetailCache] = useState<Map<number, AssessmentCommandRunDetail>>(
    () => new Map(),
  );
  const [detailLoading, setDetailLoading] = useState<Set<number>>(() => new Set());

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Fetch — no server filters, pull enough to show everything. See the
  // `Derived` doc block for why we don't round-trip free terms through FTS
  // as the user types. `showSpinner=false` is used for background refreshes
  // (poll tick, tab revisit) so the list doesn't flicker to a loading state.
  const reloadInFlightRef = useRef(false);
  const reloadQueuedRef = useRef<{ engagementKey: string; showSpinner: boolean } | null>(null);
  const activeEngagementKeyRef = useRef(engagementKey);
  activeEngagementKeyRef.current = engagementKey;
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) {
        const queued = reloadQueuedRef.current;
        reloadQueuedRef.current = {
          engagementKey,
          showSpinner: showSpinner || queued?.showSpinner === true,
        };
        return;
      }
      reloadInFlightRef.current = true;
      try {
        let next: { engagementKey: string; showSpinner: boolean } | null = {
          engagementKey,
          showSpinner,
        };
        while (next) {
          const request = next;
          reloadQueuedRef.current = null;
          if (request.showSpinner && activeEngagementKeyRef.current === request.engagementKey) {
            setLoading(true);
          }
          try {
            const items = await listAssessmentCommandRuns(request.engagementKey, {
              limit: INITIAL_FETCH_LIMIT,
              offset: 0,
            });
            if (activeEngagementKeyRef.current === request.engagementKey) {
              setRows(items);
              setLoadError(null);
            }
          } catch (err) {
            if (
              request.showSpinner
              && activeEngagementKeyRef.current === request.engagementKey
            ) {
              setRows([]);
            }
            if (activeEngagementKeyRef.current === request.engagementKey) {
              setLoadError(err instanceof Error ? err.message : "Failed to load command runs");
            }
          } finally {
            if (
              request.showSpinner
              && activeEngagementKeyRef.current === request.engagementKey
            ) {
              setLoading(false);
            }
          }
          next = reloadQueuedRef.current;
        }
      } finally {
        reloadInFlightRef.current = false;
      }
    },
    [engagementKey],
  );

  // Initial load on mount + engagement change.
  useEffect(() => {
    void reload(true);
  }, [reload]);

  // Periodic refresh while the tab is mounted (30s) plus an immediate
  // refresh when the tab regains visibility. The parent `EngagementPage`
  // deliberately does not refetch command runs on WS ticks to avoid
  // pulling a large list on every event, so the tab owns its own cadence.
  useEffect(() => {
    const POLL_MS = 30_000;
    const interval = window.setInterval(() => void reload(false), POLL_MS);
    const onVisible = () => {
      if (document.visibilityState === "visible") void reload(false);
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [reload]);

  // Equality proves only that the client reached its requested boundary,
  // not that an older row exists. Report the uncertainty without claiming
  // that the server definitely truncated the ledger.
  const limitReached = rows.length >= INITIAL_FETCH_LIMIT;

  const derivedList = useMemo<Derived[]>(() => rows.map(derive), [rows]);

  const derivedById = useMemo(() => {
    const m = new Map<number, Derived>();
    for (const d of derivedList) m.set(d.id, d);
    return m;
  }, [derivedList]);

  // Tool counts (global, for chip rendering + "top 10" slicing).
  const toolCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      const key = d.toolBin || d.row.tool_name || "(unknown)";
      c[key] = (c[key] || 0) + 1;
    }
    return c;
  }, [derivedList]);

  const agentCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      if (!d.agentName) continue;
      c[d.agentName] = (c[d.agentName] || 0) + 1;
    }
    return c;
  }, [derivedList]);

  const statusCounts = useMemo(() => {
    const c: Record<StatusBucket, number> = {
      success: 0,
      failed: 0,
      timed_out: 0,
      suppressed: 0,
      artifact: 0,
      untrusted: 0,
    };
    for (const d of derivedList) c[d.bucket] += 1;
    return c;
  }, [derivedList]);

  // Technique counts over the full fetched set (rendered chips are top-10
  // by count, the rest are addressable via the `technique:` search scope).
  // Blank-technique rows don't render a chip — they show up under the
  // "absent" bucket in the drawer, not in the filter bar.
  const techniqueCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      if (!d.techniqueKey) continue;
      c[d.techniqueKey] = (c[d.techniqueKey] || 0) + 1;
    }
    return c;
  }, [derivedList]);

  // Probe-kind counts. Closed 6-value enum — render all six present
  // buckets in fixed order so the chip row is stable across result sets.
  const probeKindCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const d of derivedList) {
      if (!d.probeKind) continue;
      c[d.probeKind] = (c[d.probeKind] || 0) + 1;
    }
    return c;
  }, [derivedList]);

  // ── Filtering ────
  const parsedQuery = useMemo(() => parseQuery(query), [query]);

  const matchesQuery = useCallback(
    (d: Derived, parsed: ParsedQuery): boolean => {
      for (const tok of parsed.tokens) {
        const v = tok.value;
        switch (tok.scope) {
          case "tool": {
            const a = (d.toolBin || "").toLowerCase();
            const b = (d.row.tool_name || "").toLowerCase();
            if (a !== v && b !== v) return false;
            break;
          }
          case "agent":
            if ((d.agentName || "").toLowerCase() !== v) return false;
            break;
          case "phase":
            if ((d.phase || "").toLowerCase() !== v) return false;
            break;
          case "rc": {
            if (v === "0" && d.rcBucket !== "zero") return false;
            else if (v === "!0" && d.rcBucket !== "nonzero") return false;
            else if (v === "timeout" && d.rcBucket !== "timeout") return false;
            else if (!["0", "!0", "timeout"].includes(v)) return false;
            break;
          }
          case "status": {
            if (v === "retained") {
              const r = (d.row.output_retention_status || "").toLowerCase();
              if (r !== "retained") return false;
            } else if (v === "empty") {
              const r = (d.row.output_retention_status || "").toLowerCase();
              if (r !== "empty") return false;
            } else if (v !== d.bucket) {
              return false;
            }
            break;
          }
          case "target":
            if (!(d.target || "").toLowerCase().includes(v)) return false;
            break;
          case "hash":
            if (!(d.row.command_hash || "").toLowerCase().startsWith(v)) return false;
            break;
          case "technique": {
            // Exact match on the normalised upper-case key. Tokenizer lower-
            // cased v; compare against the lower-cased technique key.
            if ((d.techniqueKey || "").toLowerCase() !== v) return false;
            break;
          }
          case "probe": {
            if ((d.probeKind || "") !== v) return false;
            break;
          }
          case "intent": {
            // Substring match — intent is free-form, operators search for
            // phrases like intent:"verify token leak" via the quoted form.
            if (!d.intent.toLowerCase().includes(v)) return false;
            break;
          }
          case "destructive":
          case "write": {
            // Boolean match with common spellings. NULL destructive never
            // matches either true or false (intentional — NULL = undeclared,
            // not "not destructive").
            const want =
              v === "true" || v === "1" || v === "yes"
                ? true
                : v === "false" || v === "0" || v === "no"
                ? false
                : null;
            if (want == null) return false;
            if (d.destructive !== want) return false;
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
      const toolKey = d.toolBin || d.row.tool_name || "(unknown)";
      if (toolFilters.size && !toolFilters.has(toolKey)) return false;
      if (agentFilters.size && !agentFilters.has(d.agentName)) return false;
      if (statusFilters.size && !statusFilters.has(d.bucket)) return false;
      if (techniqueFilters.size && !techniqueFilters.has(d.techniqueKey)) return false;
      if (probeKindFilters.size && !probeKindFilters.has(d.probeKind)) return false;
      if (!matchesQuery(d, parsedQuery)) return false;
      return true;
    });
    // Newest first — the command runs table already orders this way on the
    // backend, but scope filters can reshuffle the page so enforce again.
    list.sort((a, b) => {
      const aT = a.row.created_at || a.row.started_at;
      const bT = b.row.created_at || b.row.started_at;
      if (aT && bT && aT !== bT) return bT.localeCompare(aT);
      return b.id - a.id;
    });
    return list;
  }, [
    derivedList,
    toolFilters,
    agentFilters,
    statusFilters,
    techniqueFilters,
    probeKindFilters,
    parsedQuery,
    matchesQuery,
  ]);

  // Duplicate detection — compute a count map keyed by command_hash on
  // the *filtered* rows so operators see cluster density of what's
  // currently on screen, not the full engagement.
  const dupCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const d of filtered) {
      const h = d.row.command_hash;
      if (!h) continue;
      m.set(h, (m.get(h) || 0) + 1);
    }
    return m;
  }, [filtered]);

  // Keep selection valid — if the current selected row drops out of the
  // filtered set (filters changed, rows removed), pick the first
  // filtered row so j/k still has something to anchor on. We do NOT
  // auto-select on first mount any more; the modal should only open on
  // an explicit user click.
  useEffect(() => {
    if (selectedId != null && !derivedById.has(selectedId)) {
      setSelectedId(filtered[0]?.id ?? null);
      setDetailOpen(false);
    }
  }, [filtered, derivedById, selectedId]);

  const selectedDerived = selectedId != null ? derivedById.get(selectedId) ?? null : null;

  // ── Detail fetch for drawer stdout/stderr ────
  const ensureDetail = useCallback(
    (id: number) => {
      if (detailCache.has(id)) return;
      if (detailLoading.has(id)) return;
      setDetailLoading((s) => {
        const next = new Set(s);
        next.add(id);
        return next;
      });
      getAssessmentCommandRun(engagementKey, id)
        .then((detail) => {
          setDetailCache((m) => {
            const next = new Map(m);
            next.set(id, detail);
            return next;
          });
        })
        .catch(() => {
          // Swallow — the drawer will keep showing the preview-less state.
        })
        .finally(() => {
          setDetailLoading((s) => {
            const next = new Set(s);
            next.delete(id);
            return next;
          });
        });
    },
    [detailCache, detailLoading, engagementKey],
  );

  // ── Keyboard ────
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
        // Cmd/Ctrl-K closes the detail modal before opening the palette
        // so the palette sits cleanly on top of the table, not the modal.
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
        // Escape closes the modal without clearing selection so j/k keeps
        // its anchor. A second Escape (modal already closed) un-selects.
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
        const idx = list.findIndex((d) => d.id === cur);
        if (idx < 0) {
          if (list[0]) setSelectedId(list[0].id);
          return;
        }
        const next =
          e.key === "[" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      if (!isTyping && (e.key === "j" || e.key === "k")) {
        e.preventDefault();
        const list = filteredRef.current;
        const cur = selectedRef.current;
        const idx = list.findIndex((d) => d.id === cur);
        if (idx < 0 && list[0]) {
          setSelectedId(list[0].id);
          return;
        }
        const next =
          e.key === "k" ? Math.max(0, idx - 1) : Math.min(list.length - 1, idx + 1);
        setSelectedId(list[next].id);
      }
      // Enter opens the modal for the currently selected row (handy when
      // j/k has moved the cursor but the modal is closed).
      if (!isTyping && e.key === "Enter" && selectedRef.current != null) {
        e.preventDefault();
        setDetailOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // ── Chip toggle helpers ────
  const toggle = <T,>(set: Set<T>, setter: (s: Set<T>) => void, val: T) => {
    const next = new Set(set);
    if (next.has(val)) next.delete(val);
    else next.add(val);
    setter(next);
  };

  const clearAll = () => {
    setToolFilters(new Set());
    setAgentFilters(new Set());
    setStatusFilters(new Set());
    setTechniqueFilters(new Set());
    setProbeKindFilters(new Set());
    setQuery("");
  };

  const activeFilterCount =
    toolFilters.size +
    agentFilters.size +
    statusFilters.size +
    techniqueFilters.size +
    probeKindFilters.size +
    (query ? 1 : 0);

  // Top 10 tools by count for the chip bar. Everything else is accessible
  // via the free-text `tool:` scope.
  const topTools = useMemo(() => {
    return Object.entries(toolCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [toolCounts]);

  const topAgents = useMemo(() => {
    return Object.entries(agentCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [agentCounts]);

  // Top 10 techniques by count. Everything else is accessible via the
  // free-text `technique:` scope — same approach as the tool chip group.
  const topTechniques = useMemo(() => {
    return Object.entries(techniqueCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
  }, [techniqueCounts]);

  // Probe-kind chips render in the canonical PROBE_KIND_ORDER (not count
  // order) so operators scan them in the same place every time. Buckets
  // with 0 count drop out unless they're currently an active filter.
  const probeKindChips = useMemo(() => {
    return PROBE_KIND_ORDER.map((k) => [k, probeKindCounts[k] || 0] as const).filter(
      ([k, n]) => n > 0 || probeKindFilters.has(k),
    );
  }, [probeKindCounts, probeKindFilters]);

  return (
    <div className="findings-redesign">
      <div className="page-head">
        <div>
          <h1 className="page-title">Commands</h1>
          <div className="page-crumbs">
            Engagement <code>{engagementKey}</code> ·{" "}
            <span>
              {filtered.length} of {derivedList.length} runs
              {loading && " · loading…"}
              {limitReached && (
                <>
                  {" · "}
                  <span
                    className="pill pill-unreviewed"
                    title={`The request returned ${INITIAL_FETCH_LIMIT} rows. More rows may exist. Filters only narrow this loaded snapshot; they do not fetch hidden rows.`}
                  >
                    command limit reached — results may be incomplete
                  </span>
                </>
              )}
            </span>
          </div>
        </div>
        <StatusSpark counts={statusCounts} />
      </div>

      {/* Toolbar */}
      <div className="panel findings-toolbar-panel">
        <div className="toolbar">
          <div className="search-wrap">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              placeholder="Search command / argv / notes… (try tool:curl technique:ssrf probe:exploit write:true)"
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
            <button type="button" className="qa-btn" onClick={() => setCmdOpen(true)}>
              Jump to…{" "}
              <span className="search-kbd" style={{ marginLeft: 4 }}>
                ⌘K
              </span>
            </button>
          </div>
        </div>

        <div className="filter-row">
          {topTools.length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Tool</span>
              {topTools.map(([bin, n]) => {
                const color = toolColor(bin);
                return (
                  <button
                    key={`tool:${bin}`}
                    type="button"
                    className={`filter-chip ctool ${toolFilters.has(bin) ? "is-active" : ""}`}
                    onClick={() => toggle(toolFilters, setToolFilters, bin)}
                    style={
                      toolFilters.has(bin)
                        ? { borderColor: color, background: tint(color), color }
                        : undefined
                    }
                  >
                    <span className="sev-dot" style={{ background: color }} />
                    {bin}
                    <span className="filter-count">{n}</span>
                  </button>
                );
              })}
            </div>
          )}
          {topAgents.length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Agent</span>
              {topAgents.map(([name, n]) => {
                const color = agentColor(name);
                return (
                  <button
                    key={`agent:${name}`}
                    type="button"
                    className={`filter-chip cagent ${agentFilters.has(name) ? "is-active" : ""}`}
                    onClick={() => toggle(agentFilters, setAgentFilters, name)}
                    style={
                      agentFilters.has(name)
                        ? { borderColor: color, background: tint(color), color }
                        : undefined
                    }
                  >
                    <span className="sev-dot" style={{ background: color }} />
                    {name}
                    <span className="filter-count">{n}</span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="filter-group">
            <span className="filter-label">Status</span>
            {STATUS_ORDER.map((s) => {
              const count = statusCounts[s];
              if (!count && !statusFilters.has(s)) return null;
              return (
                <button
                  key={`status:${s}`}
                  type="button"
                  className={`filter-chip cstatus-${s} ${statusFilters.has(s) ? "is-active" : ""}`}
                  onClick={() => toggle(statusFilters, setStatusFilters, s)}
                >
                  <span className="sev-dot" style={{ background: STATUS_COLORS[s] }} />
                  {statusLabel(s)}
                  <span className="filter-count">{count}</span>
                </button>
              );
            })}
          </div>
          {topTechniques.length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Technique</span>
              {topTechniques.map(([tech, n]) => {
                const color = techniqueColor(tech);
                return (
                  <button
                    key={`tech:${tech}`}
                    type="button"
                    className={`filter-chip ctech ${techniqueFilters.has(tech) ? "is-active" : ""}`}
                    onClick={() => toggle(techniqueFilters, setTechniqueFilters, tech)}
                    style={
                      techniqueFilters.has(tech)
                        ? { borderColor: color, background: tint(color), color }
                        : undefined
                    }
                  >
                    <span className="sev-dot" style={{ background: color }} />
                    {tech}
                    <span className="filter-count">{n}</span>
                  </button>
                );
              })}
            </div>
          )}
          {probeKindChips.length > 0 && (
            <div className="filter-group">
              <span className="filter-label">Kind</span>
              {probeKindChips.map(([pk, n]) => {
                const color = probeKindColor(pk);
                const active = probeKindFilters.has(pk);
                return (
                  <button
                    key={`pk:${pk}`}
                    type="button"
                    className={`filter-chip cpk-${pk} ${active ? "is-active" : ""}`}
                    onClick={() => toggle(probeKindFilters, setProbeKindFilters, pk)}
                  >
                    <span className="sev-dot" style={{ background: color }} />
                    {pk}
                    <span className="filter-count">{n}</span>
                  </button>
                );
              })}
            </div>
          )}
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
          <p className="error-text" role="alert" style={{ textAlign: "left" }}>
            {loadError}
          </p>
        </div>
      )}

      {/* List (detail renders as a centred modal below) */}
      {loadError && rows.length === 0 ? null : <div className="findings-shell">
        <section className="list-panel panel">
          {loading ? (
            <TableSkeleton
              rows={8}
              showHeader={false}
              columns={["8%", "10%", "30%", "12%", "12%", "10%", "8%", "10%"]}
            />
          ) : (
            <Suspense
              fallback={
                <TableSkeleton
                  rows={8}
                  showHeader={false}
                  columns={["8%", "10%", "30%", "12%", "12%", "10%", "8%", "10%"]}
                />
              }
            >
              <CommandsGrid
                rows={filtered}
                dupCounts={dupCounts}
                selectedId={selectedId}
                onRowOpen={(id, invoker) => {
                  setSelectedId(id);
                  detailInvokerRef.current = invoker ?? searchRef.current;
                  setDetailOpen(true);
                }}
                onTargetClick={(target) => setQuery(`target:${target}`)}
                onDupClick={(hash) => setQuery(`hash:${hash.slice(0, 12)}`)}
              />
            </Suspense>
          )}
          <div className="list-footer">
            <span>{filtered.length} runs</span>
          </div>
        </section>

      </div>}

      {detailOpen && selectedDerived && (
        <DetailModal
          onClose={() => setDetailOpen(false)}
          titleId="commands-detail-modal-title"
          returnFocusRef={detailInvokerRef}
        >
          <Drawer
            d={selectedDerived}
            detail={detailCache.get(selectedDerived.id) ?? null}
            detailLoading={detailLoading.has(selectedDerived.id)}
            onRequestDetail={ensureDetail}
            titleId="commands-detail-modal-title"
          />
        </DetailModal>
      )}

      <div className="findings-shortcuts">
        <span>
          <code>/</code> focus search
        </span>
        <span>
          <code>⌘K</code> jump to command
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
          onSelect={(id) => {
            setSelectedId(id);
            detailInvokerRef.current = searchRef.current;
            setCmdOpen(false);
            setDetailOpen(true);
          }}
          onClose={() => setCmdOpen(false)}
        />
      )}
    </div>
  );
}

// ── StatusSpark ───────────────────────────────────────────────────────
function StatusSpark({ counts }: { counts: Record<StatusBucket, number> }) {
  const max = Math.max(1, ...Object.values(counts));
  return (
    <div className="sev-sparkline-wrap">
      <span className="sev-label">By status</span>
      <div className="sev-sparkline">
        {STATUS_ORDER.map((s) => {
          const c = counts[s] || 0;
          const h = Math.max(4, (c / max) * 26);
          return (
            <div
              key={s}
              className="sev-bar"
              style={{
                height: `${h}px`,
                background: STATUS_COLORS[s],
                opacity: c ? 1 : 0.2,
              }}
              title={`${statusLabel(s)}: ${c}`}
            >
              <span>{c}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Drawer ────────────────────────────────────────────────────────────
type DrawerTabId = "overview" | "stdout" | "stderr" | "audit";

function Drawer({
  d,
  detail,
  detailLoading,
  onRequestDetail,
  titleId,
}: {
  d: Derived;
  detail: AssessmentCommandRunDetail | null;
  detailLoading: boolean;
  onRequestDetail: (id: number) => void;
  titleId?: string;
}) {
  const [tab, setTab] = useState<DrawerTabId>("overview");
  useEffect(() => {
    setTab("overview");
  }, [d?.id]);

  // Lazily pull the detail fetch when switching to stdout/stderr.
  useEffect(() => {
    if (!d) return;
    if (tab === "stdout" || tab === "stderr") {
      onRequestDetail(d.id);
    }
  }, [tab, d, onRequestDetail]);

  const color = STATUS_COLORS[d.bucket];
  const tabs: { id: DrawerTabId; label: string; count?: number }[] = [
    { id: "overview", label: "Overview" },
    {
      id: "stdout",
      label: "Stdout",
      count:
        detail?.stdout_preview.length ||
        d.row.stdout_preview_chars ||
        (d.row.stdout_bytes > 0 ? 1 : 0),
    },
    {
      id: "stderr",
      label: "Stderr",
      count:
        detail?.stderr_preview.length ||
        d.row.stderr_preview_chars ||
        (d.row.stderr_bytes > 0 ? 1 : 0),
    },
    { id: "audit", label: "Audit" },
  ];

  const copyRunUuid = () => copyToClipboard(d.row.run_uuid);

  return (
    <aside className="drawer-panel panel">
      <div
        className="drawer-hero"
        style={{ ["--drawer-accent" as string]: color }}
      >
        <span
          aria-hidden
          style={{
            position: "absolute",
            left: 0,
            top: 0,
            bottom: 0,
            width: 4,
            background: color,
            borderRadius: "2px 0 0 2px",
          }}
        />
        <div className="drawer-top">
          <div className="drawer-slug">
            <span className="mono">{d.row.run_uuid}</span>
            <button
              type="button"
              className="copy-btn"
              onClick={copyRunUuid}
              title="Copy run_uuid"
            >
              uuid
            </button>
          </div>
          {/* Maximize was retired with the move to a centred modal — it
              already fills the viewport, so there's no "expand" left; the
              modal's own × (upper-right) handles dismiss. */}
        </div>
        <h2
          id={titleId}
          className="drawer-title mono"
          style={{ color: toolColor(d.toolBin) }}
        >
          {d.toolBin || "(unknown)"}
        </h2>
        <div className="hero-meta">
          <span
            className="hero-sev"
            style={{ background: tint(color, 13), color }}
          >
            <span className="sev-dot" style={{ background: color }} />
            {d.bucketLabel}
          </span>
          {d.agentName && (
            <span
              className="tag"
              style={{ color: agentColor(d.agentName), background: tint(agentColor(d.agentName)) }}
            >
              {d.agentName}
            </span>
          )}
          {d.phase && <span className="tag">{d.phase}</span>}
          {d.row.audit_source && (
            <span className="tag">{d.row.audit_source}</span>
          )}
        </div>
      </div>
      <div className="drawer-tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`drawer-tab ${tab === t.id ? "is-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count != null && t.count > 0 && (
              <span className="count">{t.count}</span>
            )}
          </button>
        ))}
      </div>
      <div className="drawer-body">
        <UntrustedDataNotice />
        {tab === "overview" && <OverviewPane d={d} />}
        {tab === "stdout" && (
          <StreamPane
            d={d}
            kind="stdout"
            detail={detail}
            detailLoading={detailLoading}
          />
        )}
        {tab === "stderr" && (
          <StreamPane
            d={d}
            kind="stderr"
            detail={detail}
            detailLoading={detailLoading}
          />
        )}
        {tab === "audit" && <AuditPane d={d} />}
      </div>
    </aside>
  );
}

// ── Drawer panes ─────────────────────────────────────────────────────
function KV({ k, v, mono, onCopy }: { k: string; v: unknown; mono?: boolean; onCopy?: () => void }) {
  if (v === undefined || v === null || v === "") return null;
  const str = typeof v === "string" ? v : String(v);
  if (!str) return null;
  return (
    <div className="kv">
      <p className="k">{k}</p>
      <p className={`v ${mono ? "mono" : ""}`} style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{str}</span>
        {onCopy && (
          <button type="button" className="copy-btn" onClick={onCopy} title="Copy">
            copy
          </button>
        )}
      </p>
    </div>
  );
}

// ── Command-metadata KV cells ────────────────────────────────────────
// Unlike the generic `KV` helper, these always render a row even when
// the value is null — the rule is "null → em-dash", never a missing row
// or the string "null". Shapes match the existing .kv / .k / .v classes
// so they slot into .kv-grid without CSS churn.
const MUTED_DASH = "—";

function MutedValue() {
  return (
    <p className="v" style={{ color: "var(--muted)" }}>
      {MUTED_DASH}
    </p>
  );
}

function TechniqueKV({ technique }: { technique: string }) {
  if (!technique) {
    return (
      <div className="kv">
        <p className="k">Technique</p>
        <MutedValue />
      </div>
    );
  }
  const color = techniqueColor(technique);
  return (
    <div className="kv">
      <p className="k">Technique</p>
      <p className="v">
        <span
          className="pill"
          style={{ background: tint(color), color, letterSpacing: "0.06em" }}
        >
          <span className="sev-dot" style={{ background: color }} />
          {technique}
        </span>
      </p>
    </div>
  );
}

function ProbeKindKV({ probeKind }: { probeKind: string }) {
  if (!probeKind) {
    return (
      <div className="kv">
        <p className="k">Probe kind</p>
        <MutedValue />
      </div>
    );
  }
  const color = probeKindColor(probeKind);
  return (
    <div className="kv">
      <p className="k">Probe kind</p>
      <p className="v">
        <span
          className={`pill cpk-${probeKind}`}
          style={{ background: tint(color), color }}
        >
          <span className="sev-dot" style={{ background: color }} />
          {probeKind}
        </span>
      </p>
    </div>
  );
}

function IntentKV({ intent }: { intent: string }) {
  if (!intent) {
    return (
      <div className="kv">
        <p className="k">Intent</p>
        <MutedValue />
      </div>
    );
  }
  // Intent is free-form ≤200 chars. Render as a soft-accent pill so it's
  // visually distinct from the mono technical fields around it — operators
  // scan for it as prose, not as a code token.
  return (
    <div className="kv">
      <p className="k">Intent</p>
      <p className="v" style={{ whiteSpace: "normal" }}>
        <span
          className="pill"
          style={{
            background: "var(--count-bg)",
            color: "var(--accent)",
            textTransform: "none",
            letterSpacing: 0,
            fontWeight: 400,
            fontSize: "0.78rem",
          }}
        >
          {intent}
        </span>
      </p>
    </div>
  );
}

function DestructiveKV({ destructive }: { destructive: boolean | null }) {
  if (destructive == null) {
    return (
      <div className="kv">
        <p className="k">Destructive</p>
        <MutedValue />
      </div>
    );
  }
  // True gets the warn-tinted pill (amber/red) so operators can scan a
  // drawer and immediately see "this touched target state". False gets
  // the ok-tinted pill — still a positive signal, just reversed.
  const pillClass = destructive ? "pill-active" : "pill-reported";
  return (
    <div className="kv">
      <p className="k">Destructive</p>
      <p className="v">
        <span className={`pill ${pillClass}`}>
          {destructive ? "yes — writes target state" : "no"}
        </span>
      </p>
    </div>
  );
}

function OverviewPane({ d }: { d: Derived }) {
  const row = d.row;
  return (
    <>
      <div className="section">
        <p className="section-title">Command</p>
        <pre className="pre" style={{ maxHeight: 180 }}>{row.command}</pre>
      </div>
      {row.argv && row.argv.length > 0 && (
        <div className="section">
          <p className="section-title">
            Argv <span className="count">{row.argv.length}</span>
          </p>
          <ol className="steps mono">
            {row.argv.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ol>
        </div>
      )}
      <div className="section">
        <p className="section-title">Metadata</p>
        <div className="kv-grid">
          <KV k="Started" v={row.started_at} mono />
          <KV k="Completed" v={row.completed_at} mono />
          <KV k="Output recovery baseline" v={row.output_recovery_observed_at || "—"} mono />
          <KV k="Duration" v={fmtDuration(row.duration_ms)} />
          <KV k="Return code" v={row.return_code == null ? "—" : String(row.return_code)} />
          <KV k="Timed out" v={row.timed_out ? "yes" : "no"} />
          <KV k="Success" v={row.success ? "yes" : "no"} />
          <KV k="Agent" v={row.agent_name} />
          <KV k="Phase" v={row.phase} />
          <KV k="Tool name" v={row.tool_name} mono />
          <KV k="Tool bin" v={row.tool_bin} mono />
          <KV k="Route" v={row.route} mono />
          <KV k="Audit source" v={row.audit_source} />
          <KV
            k="Command hash"
            v={row.command_hash ? `${row.command_hash.slice(0, 12)}…` : ""}
            mono
            onCopy={() => copyToClipboard(row.command_hash)}
          />
          <KV
            k="Run UUID"
            v={row.run_uuid}
            mono
            onCopy={() => copyToClipboard(row.run_uuid)}
          />
          {d.target && <KV k="Target" v={d.target} mono />}
          {/* Command-metadata audit fields. Always render the row even when
              null so operators see "field is absent" vs. "field is missing
              from the UI". Null renders as the em-dash muted — a deliberate
              choice for rows posted before the 2026-04 schema migration. */}
          <TechniqueKV technique={d.techniqueKey} />
          <ProbeKindKV probeKind={d.probeKind} />
          <IntentKV intent={d.intent} />
          <DestructiveKV destructive={d.destructive} />
        </div>
      </div>
      {row.notes && (
        <div className="callout">
          <p className="section-title">Notes</p>
          <p>{row.notes}</p>
        </div>
      )}
    </>
  );
}

function StreamPane({
  d,
  kind,
  detail,
  detailLoading,
}: {
  d: Derived;
  kind: "stdout" | "stderr";
  detail: AssessmentCommandRunDetail | null;
  detailLoading: boolean;
}) {
  const row = d.row;
  const retention = (row.output_retention_status || "").toLowerCase();
  const integrity = (row.output_integrity_status || "").toLowerCase();
  const preview = detail
    ? kind === "stdout"
      ? detail.stdout_preview
      : detail.stderr_preview
    : "";
  const suppressionReason =
    kind === "stdout" ? row.stdout_suppression_reason : row.stderr_suppression_reason;
  const artifactRef =
    kind === "stdout" ? row.stdout_artifact_ref : row.stderr_artifact_ref;
  const sha = kind === "stdout" ? row.stdout_sha256 : row.stderr_sha256;
  const bytes = kind === "stdout" ? row.stdout_bytes : row.stderr_bytes;
  const previewChars =
    (kind === "stdout" ? row.stdout_preview_chars : row.stderr_preview_chars) ?? 0;

  if (integrity === "pending" || integrity === "warning") {
    return (
      <div className="section">
        <div className="callout" style={{ borderLeft: "4px solid var(--chip-red)" }}>
          <p className="section-title">Output integrity is {integrity}</p>
          <p>
            Captured output is shown below, but it has not passed integrity verification.
            {" "}{row.output_integrity_warning || "Vigil has not proved that this artifact stayed stable; treat it as untrusted evidence."}
          </p>
        </div>
        {detailLoading && !detail ? (
          <div aria-busy="true" aria-label={`Loading ${kind}`} style={{ display: "grid", gap: 6, marginTop: 10 }}>
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} width={i === 3 ? "55%" : "90%"} height={9} />
            ))}
          </div>
        ) : detail ? (
          <pre className="pre" style={{ marginTop: 10 }}>{preview || "(empty preview)"}</pre>
        ) : previewChars > 0 ? (
          <p className="empty" style={{ marginTop: 10, textAlign: "left" }}>
            A preview is recorded but has not loaded yet.
          </p>
        ) : null}
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="Preview chars" v={previewChars} />
          <KV k="Retention" v={retention || "unknown"} />
          <KV k="Integrity" v={integrity} />
          <KV k="SHA-256" v={sha} mono onCopy={() => copyToClipboard(sha)} />
        </div>
      </div>
    );
  }

  if (retention === "suppressed" || retention.startsWith("suppression_")) {
    const spillMayRemain = retention !== "suppressed";
    return (
      <div className="section">
        <div className="callout" style={{ borderLeft: "4px solid var(--pending)" }}>
          <p className="section-title">{spillMayRemain ? "Suppression incomplete" : "Suppressed"}</p>
          <p>{suppressionReason || "Output was suppressed by the capture layer."}</p>
          {spillMayRemain && (
            <p>{row.output_cleanup_warning || "Raw spill bytes may remain in the private host-exec directory and are blocked from artifact indexing."}</p>
          )}
        </div>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="SHA-256" v={sha} mono onCopy={() => copyToClipboard(sha)} />
        </div>
      </div>
    );
  }

  if (
    retention === "untrusted"
    || retention === "integrity_failure"
    || INCOMPLETE_OUTPUT_RETENTION.has(retention)
  ) {
    const incompleteMeasurement = INCOMPLETE_OUTPUT_RETENTION.has(retention);
    return (
      <div className="section">
        <div className="callout" style={{ borderLeft: "4px solid var(--chip-red)" }}>
          <p className="section-title">{incompleteMeasurement ? "Output measurement is incomplete" : "Output is not trustworthy"}</p>
          <p>{row.output_integrity_warning || (incompleteMeasurement
            ? "Vigil could not establish complete byte totals for this output; do not treat zero-valued storage defaults as proof of no output."
            : "Vigil could not prove that this output stayed stable.")}</p>
        </div>
        <div className="kv-grid">
          <KV k="Retention" v={retention} />
          <KV k="Integrity" v={row.output_integrity_status || "warning"} />
        </div>
        {preview ? (
          <pre className="pre" style={{ marginTop: 10 }}>{preview}</pre>
        ) : previewChars > 0 ? (
          <p className="empty" style={{ marginTop: 10, textAlign: "left" }}>
            A preview is recorded but has not loaded yet.
          </p>
        ) : null}
      </div>
    );
  }

  if (retention === "empty" || (bytes === 0 && previewChars === 0 && !preview)) {
    return (
      <div className="section">
        <p className="empty" style={{ textAlign: "left" }}>No output.</p>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="Retention" v={retention || "empty"} />
        </div>
      </div>
    );
  }

  return (
    <div className="section">
      {detailLoading && !detail ? (
        <div aria-busy="true" aria-label={`Loading ${kind}`} style={{ display: "grid", gap: 6 }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} width={i === 3 ? "55%" : "90%"} height={9} />
          ))}
        </div>
      ) : detail ? (
        <pre className="pre">{preview || "(empty preview)"}</pre>
      ) : (
        <p className="empty" style={{ textAlign: "left" }}>
          Preview not loaded yet. Re-open this tab to fetch.
        </p>
      )}
      {retention === "artifact" && artifactRef && (
        <div className="callout" style={{ marginTop: 10 }}>
          <p className="section-title">Artifact</p>
          <p>
            Full output spilled to{" "}
            <span className="mono">{artifactRef}</span>
          </p>
          <div style={{ display: "flex", gap: 6 }}>
            <button
              type="button"
              className="qa-btn"
              onClick={() => copyToClipboard(artifactRef)}
            >
              Copy ref
            </button>
          </div>
        </div>
      )}
      <div className="kv-grid" style={{ marginTop: 10 }}>
        <KV k="Bytes captured" v={bytes} />
        <KV k="Preview chars" v={previewChars} />
        <KV k="Retention" v={retention || "retained"} />
        <KV k="SHA-256" v={sha} mono onCopy={() => copyToClipboard(sha)} />
      </div>
    </div>
  );
}

function AuditPane({ d }: { d: Derived }) {
  const row = d.row;
  return (
    <>
      <div className="section">
        <p className="section-title">Identifiers</p>
        <div className="kv-grid">
          <KV k="ID" v={row.id} mono />
          <KV
            k="Run UUID"
            v={row.run_uuid}
            mono
            onCopy={() => copyToClipboard(row.run_uuid)}
          />
          <KV
            k="Command hash"
            v={row.command_hash}
            mono
            onCopy={() => copyToClipboard(row.command_hash)}
          />
          <KV k="Engagement ID" v={row.engagement_id} mono />
        </div>
      </div>
      <div className="section">
        <p className="section-title">Output hashes</p>
        <div className="kv-grid">
          <KV
            k="Stdout SHA-256"
            v={row.stdout_sha256}
            mono
            onCopy={() => copyToClipboard(row.stdout_sha256)}
          />
          <KV k="Stdout bytes" v={row.stdout_bytes} />
          <KV
            k="Stderr SHA-256"
            v={row.stderr_sha256}
            mono
            onCopy={() => copyToClipboard(row.stderr_sha256)}
          />
          <KV k="Stderr bytes" v={row.stderr_bytes} />
        </div>
      </div>
      <div className="section">
        <p className="section-title">Retention & source</p>
        <div className="kv-grid">
          <KV k="Retention" v={row.output_retention_status} />
          <KV k="Audit source" v={row.audit_source} />
          <KV k="Stdout artifact ref" v={row.stdout_artifact_ref} mono />
          <KV k="Stderr artifact ref" v={row.stderr_artifact_ref} mono />
          <KV
            k="Stdout suppression"
            v={row.stdout_suppression_reason}
          />
          <KV
            k="Stderr suppression"
            v={row.stderr_suppression_reason}
          />
          <KV k="Indexed at" v={row.indexed_for_embeddings_at} mono />
        </div>
      </div>
    </>
  );
}

// ── Command palette ──────────────────────────────────────────────────
function CommandPalette({
  derivedList,
  onSelect,
  onClose,
}: {
  derivedList: Derived[];
  onSelect: (id: number) => void;
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
          case "tool": {
            const a = (d.toolBin || "").toLowerCase();
            const b = (d.row.tool_name || "").toLowerCase();
            if (a !== v && b !== v) return false;
            break;
          }
          case "agent":
            if ((d.agentName || "").toLowerCase() !== v) return false;
            break;
          case "phase":
            if ((d.phase || "").toLowerCase() !== v) return false;
            break;
          case "status":
            if (v !== d.bucket) return false;
            break;
          case "target":
            if (!(d.target || "").toLowerCase().includes(v)) return false;
            break;
          case "hash":
            if (!(d.row.command_hash || "").toLowerCase().startsWith(v)) return false;
            break;
          case "rc":
            if (v === "0" && d.rcBucket !== "zero") return false;
            else if (v === "!0" && d.rcBucket !== "nonzero") return false;
            else if (v === "timeout" && d.rcBucket !== "timeout") return false;
            break;
          case "technique":
            if ((d.techniqueKey || "").toLowerCase() !== v) return false;
            break;
          case "probe":
            if ((d.probeKind || "") !== v) return false;
            break;
          case "intent":
            if (!d.intent.toLowerCase().includes(v)) return false;
            break;
          case "destructive":
          case "write": {
            const want =
              v === "true" || v === "1" || v === "yes"
                ? true
                : v === "false" || v === "0" || v === "no"
                ? false
                : null;
            if (want == null) return false;
            if (d.destructive !== want) return false;
            break;
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
            placeholder="Jump to command · try 'tool:curl target:example.com' or a run_uuid prefix"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <span className="search-kbd">esc</span>
        </div>
        <div className="cmd-list">
          {results.length === 0 ? (
            <div className="cmd-empty">No command runs match.</div>
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
                  style={{ background: STATUS_COLORS[d.bucket] }}
                />
                <span>
                  <div className="cmd-title mono">
                    {midTruncate(d.commandPreview, 96)}
                  </div>
                  <div className="cmd-sub">
                    {d.toolBin}
                    {d.agentName ? ` · ${d.agentName}` : ""}
                    {d.phase ? ` · ${d.phase}` : ""}
                    {d.target ? ` · ${d.target}` : ""}
                  </div>
                </span>
                <span className="cmd-sub">
                  {d.bucketLabel}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
