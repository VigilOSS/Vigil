import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AssessmentCommandRun,
  AssessmentCommandRunDetail,
} from "../lib/api";
import {
  getAssessmentCommandRun,
  listAssessmentCommandRuns,
} from "../lib/api";
import { useResizableColumns } from "../lib/useResizableColumns";

// ── Props ─────────────────────────────────────────────────────────────
type CommandsTabProps = {
  engagementKey: string;
};

// ── Constants ─────────────────────────────────────────────────────────
const PAGE_SIZE = 40;

// Initial fetch cap. Findings/Intel follow the same approach: pull a
// page wide enough to cover every realistic engagement and filter
// client-side. Anything past this cap is lost to the initial view;
// in practice a single engagement's command-run count lives well under.
const INITIAL_FETCH_LIMIT = 1000;

// Default column widths (px). Order matches the list-header / row below:
//   [color-bar, time, tool, agent, phase, target, command, duration, dup, rc]
const CMDS_LIST_DEFAULTS = [10, 80, 100, 140, 100, 160, 1, 70, 50, 50];
const CMDS_LIST_MINS = [8, 60, 60, 80, 60, 100, 200, 50, 40, 40];
// Wrinkle: one column holds fr units in the header. useResizableColumns
// emits pure px, so we hard-code the command column's base px width too.
const CMDS_LIST_DEFAULTS_PX = [10, 80, 100, 140, 100, 160, 520, 70, 50, 50];

// Status color map — drives the row-left bar, status pill, filter chips,
// and sparkline bars. Five buckets: success (green), failed (red),
// timed_out (amber), suppressed (muted), artifact (teal).
const STATUS_COLORS: Record<string, string> = {
  success: "#2f7f52",
  failed: "#991b1b",
  timed_out: "#c64d15",
  suppressed: "#8c7b62",
  artifact: "#0d6b6b",
};
const STATUS_ORDER = ["success", "failed", "timed_out", "suppressed", "artifact"] as const;
type StatusBucket = (typeof STATUS_ORDER)[number];

// Tool color map. Keep the bin name keyed so it also works for short-tail
// tools the operator might pipe through. Anything missing falls back to
// a hash-derived color so colors are stable across reloads.
const TOOL_COLORS: Record<string, string> = {
  nmap: "#0d6b6b",
  curl: "#17354c",
  wget: "#17354c",
  sqlmap: "#991b1b",
  ffuf: "#c64d15",
  gobuster: "#c64d15",
  dirb: "#c64d15",
  katana: "#7c3aed",
  gau: "#7c3aed",
  nikto: "#be185d",
  hydra: "#6b0d0d",
  john: "#6b0d0d",
  metasploit: "#991b1b",
  wpscan: "#2f7f52",
  enum4linux: "#a16207",
  dig: "#4b5563",
  host: "#4b5563",
  whois: "#4b5563",
  trufflehog: "#a16207",
  git: "#4b5563",
  bash: "#6b685d",
  sh: "#6b685d",
  python: "#2f7f52",
  python3: "#2f7f52",
};

// Small hand-tuned palette for the hash fallback so colors stay within the
// existing design language.
const TOOL_HASH_PALETTE = [
  "#17354c",
  "#0d6b6b",
  "#2f7f52",
  "#7c3aed",
  "#c64d15",
  "#a16207",
  "#991b1b",
  "#be185d",
  "#4b5563",
  "#6b0d0d",
];

function hashString(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i += 1) {
    h = (h * 31 + s.charCodeAt(i)) >>> 0;
  }
  return h;
}

function toolColor(bin: string): string {
  const key = (bin || "").toLowerCase();
  if (TOOL_COLORS[key]) return TOOL_COLORS[key];
  if (!key) return "#6b685d";
  return TOOL_HASH_PALETTE[hashString(key) % TOOL_HASH_PALETTE.length];
}

// Agent role color map. Keyed on a substring of the agent name so renames
// to `recon-analyst`, `recon-v2`, etc. still get the recon hue.
const AGENT_ROLE_COLORS: { key: string; color: string }[] = [
  { key: "recon", color: "#17354c" },
  { key: "surface", color: "#0d6b6b" },
  { key: "vuln", color: "#c64d15" },
  { key: "exploit", color: "#991b1b" },
  { key: "fuzz", color: "#7c3aed" },
  { key: "osint", color: "#2f7f52" },
  { key: "operator", color: "#6b685d" },
  { key: "code", color: "#a16207" },
];

function agentColor(name: string): string {
  const n = (name || "").toLowerCase();
  for (const { key, color } of AGENT_ROLE_COLORS) {
    if (n.includes(key)) return color;
  }
  if (!n) return "#6b685d";
  return TOOL_HASH_PALETTE[hashString(n) % TOOL_HASH_PALETTE.length];
}

// ── Helpers ───────────────────────────────────────────────────────────
function relTime(iso: string | undefined | null): string {
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

function fmtDuration(ms: number): string {
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
// One bucket per row: suppressed/artifact when the retention status says
// so, otherwise success/failed/timed_out. Used for sparkline, color bar,
// chip coloring. Matches the spec's rollup rule.
function statusBucket(row: AssessmentCommandRun): StatusBucket {
  const retention = (row.output_retention_status || "").toLowerCase();
  if (retention === "suppressed") return "suppressed";
  if (retention === "artifact") return "artifact";
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
const SCOPES = [
  "tool",
  "agent",
  "phase",
  "rc",
  "status",
  "target",
  "hash",
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
type Derived = {
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
const IconMaximize = () => (
  <svg
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M4 9V4h5" />
    <path d="M20 9V4h-5" />
    <path d="M4 15v5h5" />
    <path d="M20 15v5h-5" />
  </svg>
);

function copyToClipboard(text: string): void {
  try {
    void navigator.clipboard?.writeText(text);
  } catch {
    // ignore
  }
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
  const [page, setPage] = useState(0);
  const [cmdOpen, setCmdOpen] = useState(false);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [maximized, setMaximized] = useState(false);
  useEffect(() => {
    setMaximized(false);
  }, [selectedId]);

  // Detail cache for full stdout/stderr. Keyed by command-run id and
  // populated lazily when the drawer's stdout/stderr tab is opened.
  const [detailCache, setDetailCache] = useState<Map<number, AssessmentCommandRunDetail>>(
    () => new Map(),
  );
  const [detailLoading, setDetailLoading] = useState<Set<number>>(() => new Set());

  const {
    gridTemplate: listGridTemplate,
    startResize: startListResize,
    resetColumn: resetListColumn,
  } = useResizableColumns(
    "commands.col-widths",
    CMDS_LIST_DEFAULTS_PX,
    CMDS_LIST_MINS,
  );

  const searchRef = useRef<HTMLInputElement | null>(null);

  // Fetch — no server filters, pull enough to show everything. See the
  // `Derived` doc block for why we don't round-trip free terms through FTS
  // as the user types. `showSpinner=false` is used for background refreshes
  // (poll tick, tab revisit) so the list doesn't flicker to a loading state.
  const reloadInFlightRef = useRef(false);
  const reload = useCallback(
    async (showSpinner = true) => {
      if (reloadInFlightRef.current) return;
      reloadInFlightRef.current = true;
      if (showSpinner) setLoading(true);
      try {
        const items = await listAssessmentCommandRuns(engagementKey, {
          limit: INITIAL_FETCH_LIMIT,
          offset: 0,
        });
        setRows(items);
        setLoadError(null);
      } catch (err) {
        if (showSpinner) setRows([]);
        setLoadError(err instanceof Error ? err.message : "Failed to load command runs");
      } finally {
        reloadInFlightRef.current = false;
        if (showSpinner) setLoading(false);
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

  // Backend caps list at 1000 rows per request. If we got back exactly
  // INITIAL_FETCH_LIMIT, assume there are older runs we didn't fetch —
  // surface it so the operator doesn't silently audit an incomplete slice.
  const truncated = rows.length >= INITIAL_FETCH_LIMIT;

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
    };
    for (const d of derivedList) c[d.bucket] += 1;
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
  }, [derivedList, toolFilters, agentFilters, statusFilters, parsedQuery, matchesQuery]);

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

  // Reset page when filters/search change.
  useEffect(() => {
    setPage(0);
  }, [toolFilters, agentFilters, statusFilters, query]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  useEffect(() => {
    setPage((p) => Math.min(p, totalPages - 1));
  }, [totalPages]);
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  // Auto-select first row when one's needed / when the current selection
  // falls out of the filtered view.
  useEffect(() => {
    if (!selectedId && filtered.length > 0) {
      setSelectedId(filtered[0].id);
    }
    if (selectedId != null && !derivedById.has(selectedId)) {
      setSelectedId(filtered[0]?.id ?? null);
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

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = (target?.tagName || "").toLowerCase();
      const isTyping = tag === "input" || tag === "textarea";
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
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
    setQuery("");
  };

  const activeFilterCount =
    toolFilters.size + agentFilters.size + statusFilters.size + (query ? 1 : 0);

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
              {truncated && (
                <>
                  {" · "}
                  <span
                    className="pill pill-unreviewed"
                    title={`Backend capped the list at ${INITIAL_FETCH_LIMIT} newest runs. Narrow with filters (tool:, agent:, phase:) to see older rows.`}
                  >
                    showing newest {INITIAL_FETCH_LIMIT} — older runs hidden
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
              placeholder="Search command / argv / notes… (try tool:curl status:failed target:example.com)"
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
                        ? { borderColor: color, background: `${color}1a`, color }
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
                        ? { borderColor: color, background: `${color}1a`, color }
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
          {activeFilterCount > 0 && (
            <button type="button" className="filter-clear" onClick={clearAll}>
              Clear all ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      {loadError && (
        <div className="panel findings-toolbar-panel" style={{ padding: 12 }}>
          <p className="empty" style={{ textAlign: "left" }}>
            {loadError}
          </p>
        </div>
      )}

      {/* List + drawer */}
      <div className={`findings-shell ${maximized && selectedDerived ? "is-maximized" : ""}`}>
        <section className="list-panel panel">
          <div
            className="list-header"
            style={{ gridTemplateColumns: listGridTemplate }}
          >
            <span />
            <span>
              Time
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(1, e)}
                onDoubleClick={() => resetListColumn(1)}
              />
            </span>
            <span>
              Tool
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(2, e)}
                onDoubleClick={() => resetListColumn(2)}
              />
            </span>
            <span>
              Agent
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(3, e)}
                onDoubleClick={() => resetListColumn(3)}
              />
            </span>
            <span>
              Phase
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(4, e)}
                onDoubleClick={() => resetListColumn(4)}
              />
            </span>
            <span>
              Target
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(5, e)}
                onDoubleClick={() => resetListColumn(5)}
              />
            </span>
            <span>
              Command
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(6, e)}
                onDoubleClick={() => resetListColumn(6)}
              />
            </span>
            <span>
              Dur
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(7, e)}
                onDoubleClick={() => resetListColumn(7)}
              />
            </span>
            <span>
              Dup
              <span
                className="col-resize-handle"
                onPointerDown={(e) => startListResize(8, e)}
                onDoubleClick={() => resetListColumn(8)}
              />
            </span>
            <span style={{ textAlign: "right" }}>RC</span>
          </div>
          <div className="list-scroll">
            {loading ? (
              <div className="empty">Loading command runs…</div>
            ) : pageRows.length === 0 ? (
              <div className="empty">
                No command runs match.
                <div style={{ marginTop: 10 }}>
                  <button type="button" className="qa-btn" onClick={clearAll}>
                    Clear filters
                  </button>
                </div>
              </div>
            ) : (
              pageRows.map((d) => (
                <CommandRow
                  key={d.id}
                  d={d}
                  selected={selectedId === d.id}
                  onClick={() => setSelectedId(d.id)}
                  onTargetClick={(target) => setQuery(`target:${target}`)}
                  onDupClick={(hash) => setQuery(`hash:${hash.slice(0, 12)}`)}
                  dupCount={dupCounts.get(d.row.command_hash) || 0}
                  freeTerms={parsedQuery.freeTerms}
                  gridTemplate={listGridTemplate}
                />
              ))
            )}
          </div>
          <div className="list-footer">
            <span>
              {filtered.length} runs · page {page + 1} / {totalPages}
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
        </section>

        <Drawer
          d={selectedDerived}
          detail={selectedDerived ? detailCache.get(selectedDerived.id) ?? null : null}
          detailLoading={selectedDerived ? detailLoading.has(selectedDerived.id) : false}
          onRequestDetail={ensureDetail}
          maximized={maximized}
          onToggleMaximize={() => setMaximized((m) => !m)}
        />
      </div>

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
          <code>Esc</code> close drawer
        </span>
      </div>

      {cmdOpen && (
        <CommandPalette
          derivedList={derivedList}
          onSelect={(id) => {
            setSelectedId(id);
            setCmdOpen(false);
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

// ── CommandRow ────────────────────────────────────────────────────────
function CommandRow({
  d,
  selected,
  onClick,
  onTargetClick,
  onDupClick,
  dupCount,
  freeTerms,
  gridTemplate,
}: {
  d: Derived;
  selected: boolean;
  onClick: () => void;
  onTargetClick: (target: string) => void;
  onDupClick: (hash: string) => void;
  dupCount: number;
  freeTerms: string[];
  gridTemplate?: string;
}) {
  const bucket = d.bucket;
  const color = STATUS_COLORS[bucket];
  const toolClr = toolColor(d.toolBin);
  const agentClr = agentColor(d.agentName);
  const command = midTruncate(d.commandPreview, 160);
  const rc = d.row.return_code;
  const rcBucket = d.rcBucket;
  return (
    <button
      type="button"
      className={`frow ${selected ? "is-selected" : ""}`}
      onClick={onClick}
      data-id={d.id}
      style={gridTemplate ? { gridTemplateColumns: gridTemplate } : undefined}
    >
      <span className={`frow-sevbar cbar-${bucket}`} style={{ background: color }} />
      <span className="frow-main" style={{ gridTemplateColumns: "unset" }}>
        <span className="mono" style={{ fontSize: "0.76rem", color: "var(--muted)" }}>
          {relTime(d.row.created_at || d.row.started_at)}
        </span>
      </span>
      <span className="mono" style={{ color: toolClr, fontWeight: 600, fontSize: "0.84rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {d.toolBin || "(unknown)"}
      </span>
      <span style={{ color: agentClr, fontSize: "0.84rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {d.agentName}
      </span>
      <span style={{ fontSize: "0.82rem", color: "var(--ink-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {d.phase}
      </span>
      <span
        className="mono"
        style={{ fontSize: "0.78rem", color: "var(--ink-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: d.target ? "pointer" : "default" }}
        onClick={(e) => {
          if (!d.target) return;
          e.stopPropagation();
          onTargetClick(d.target);
        }}
        title={d.target ? `Filter by target:${d.target}` : undefined}
      >
        {d.target || "—"}
      </span>
      <span
        className="mono"
        style={{ fontSize: "0.78rem", color: "var(--ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={d.commandPreview}
      >
        {highlight(command, freeTerms)}
      </span>
      <span className="mono" style={{ fontSize: "0.76rem", color: "var(--muted)", whiteSpace: "nowrap" }}>
        {fmtDuration(d.row.duration_ms)}
      </span>
      <span style={{ display: "flex", justifyContent: "flex-start" }}>
        {dupCount > 1 && (
          <span
            className="tag"
            onClick={(e) => {
              e.stopPropagation();
              if (d.row.command_hash) onDupClick(d.row.command_hash);
            }}
            style={{ cursor: "pointer", background: "rgba(23,53,76,0.08)", color: "var(--accent)" }}
            title={`${dupCount} rows share this command_hash — click to filter`}
          >
            ×{dupCount}
          </span>
        )}
      </span>
      <span style={{ display: "flex", justifyContent: "flex-end" }}>
        <span
          className="tag"
          style={{
            background:
              rcBucket === "zero"
                ? "rgba(47,127,82,0.16)"
                : rcBucket === "timeout"
                ? "rgba(198,77,21,0.14)"
                : rcBucket === "nonzero"
                ? "rgba(153,27,27,0.14)"
                : "rgba(140,123,98,0.12)",
            color:
              rcBucket === "zero"
                ? "#2f7f52"
                : rcBucket === "timeout"
                ? "#c64d15"
                : rcBucket === "nonzero"
                ? "#991b1b"
                : "#6b685d",
          }}
        >
          {rcBucket === "timeout" ? "t/o" : rc == null ? "—" : String(rc)}
        </span>
      </span>
    </button>
  );
}

// ── Drawer ────────────────────────────────────────────────────────────
type DrawerTabId = "overview" | "stdout" | "stderr" | "audit";

function Drawer({
  d,
  detail,
  detailLoading,
  onRequestDetail,
  maximized,
  onToggleMaximize,
}: {
  d: Derived | null;
  detail: AssessmentCommandRunDetail | null;
  detailLoading: boolean;
  onRequestDetail: (id: number) => void;
  maximized: boolean;
  onToggleMaximize: () => void;
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

  if (!d) {
    return (
      <aside className="drawer-panel panel">
        <div className="empty" style={{ padding: "60px 20px" }}>
          <p style={{ fontSize: "0.9rem", margin: 0 }}>
            Select a command run to see details.
          </p>
          <p style={{ fontSize: "0.78rem", color: "var(--muted)", marginTop: 10 }}>
            Tip: press <code>⌘K</code> or <code>/</code> to search.
          </p>
        </div>
      </aside>
    );
  }

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
          <div className="drawer-nav">
            <button
              type="button"
              className="icon-btn"
              onClick={onToggleMaximize}
              title={maximized ? "Restore drawer" : "Maximize drawer"}
              aria-pressed={maximized}
            >
              {maximized ? <IconClose /> : <IconMaximize />}
            </button>
          </div>
        </div>
        <h2 className="drawer-title mono" style={{ color: toolColor(d.toolBin) }}>
          {d.toolBin || "(unknown)"}
        </h2>
        <div className="hero-meta">
          <span
            className="hero-sev"
            style={{ background: `${color}22`, color }}
          >
            <span className="sev-dot" style={{ background: color }} />
            {d.bucketLabel}
          </span>
          {d.agentName && (
            <span
              className="tag"
              style={{ color: agentColor(d.agentName), background: `${agentColor(d.agentName)}1a` }}
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

  if (retention === "suppressed") {
    return (
      <div className="section">
        <div className="callout" style={{ borderLeft: "4px solid var(--pending)" }}>
          <p className="section-title">Suppressed</p>
          <p>{suppressionReason || "Output was suppressed by the capture layer."}</p>
        </div>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="SHA-256" v={sha} mono onCopy={() => copyToClipboard(sha)} />
        </div>
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
        <p className="empty" style={{ textAlign: "left" }}>Loading {kind}…</p>
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
