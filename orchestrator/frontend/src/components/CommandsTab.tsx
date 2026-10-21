// ── CommandsTab ───────────────────────────────────────────────────────
// Every tool command agents ran through Vigil. The tab reads the operator
// command ledger (lib/commandsApi.ts): engagement and filter counts
// (`/command-runs/facets`), server-paged rows (`/page`, via the grid), one
// run's full record (`/command-runs/{id}`) and its place in the paged order
// (`/position`) for the record's Previous / Next. Search, filters, sort and
// the "needs attention" rule all run on the server, so counts and stepping
// cover the whole ledger, never a loaded slice. Opening a run replaces the
// list with the shared record view; Back, Escape and browser Back return to
// the list with its filters, sort and scroll intact. Scope, chips, search and
// sort also survive leaving the tab (sessionStorage, per engagement).

import { lazy, Suspense, useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode, type RefObject } from "react";
import {
  DEFAULT_COMMAND_FILTERS,
  DEFAULT_COMMAND_SORT,
  COMMAND_SORT_LABELS,
  activeCommandFilterCount,
  commandFiltersKey,
  commandStatusReason,
  commandViewKey,
  fetchCommandFacets,
  fetchCommandPage,
  fetchCommandPosition,
  getCommandRunRecord,
  parseCommandView,
  searchToken,
  type CommandView,
  type CommandFacet,
  type CommandFilters,
  type CommandLedgerRow,
  type CommandScope,
  type CommandSort,
} from "../lib/commandsApi";
import type { AssessmentCommandRunDetail } from "../lib/api";
import { formatDuration } from "../lib/serverTime";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { useBodyScrollLock, useModalFocus } from "../lib/modalScrollLock";
import { CopyInline } from "./formatting";
import { KVTime } from "./drawer/DrawerKit";
import { JsonView } from "./JsonView";
import { CardSkeleton, Skeleton, SlowLoadHint, TableSkeleton } from "./Skeletons";
import {
  RecordBody,
  RecordCopyButton,
  RecordCopyLinkButton,
  RecordHeader,
  RecordTabs,
  RecordView,
  useResultsScrollMemory,
} from "./record/RecordView";
import { useRecordPosition } from "./record/recordNavigation";
import { useCoalescedRequest, useCoalescedRunner } from "../lib/useCoalescedRequest";
import { useLiveRefreshToken } from "../lib/useLiveRefreshToken";
import {
  ClearFiltersButton,
  EmptyState,
  FacetChipGroup,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  StatusPill,
  compareStatus,
  describeSort,
  statusLabel,
  statusTone,
} from "./ui";
import type { CommandsGridHandle } from "./CommandsGrid";
import "../styles/commands.css";

// ag-grid is heavy (~470 kB): the grid lands in a code-split chunk.
const CommandsGrid = lazy(() => import("./CommandsGrid"));

type CommandsTabProps = {
  engagementKey: string;
  /** Bumped by EngagementPage on live updates (WebSocket / polling). */
  refreshVersion?: number;
  /** `command=<id>` from the route: opens that run's record (links from run receipts). */
  commandId?: number;
  /** `dtab=` from the route: the open record's section. */
  initialDrawerTab?: string;
  /** Reports the ledger's "needs attention" total from each counts read, for the rail badge while open. */
  onAttentionCount?: (count: number) => void;
};

const SEARCH_DEBOUNCE_MS = 300;
// A burst of live updates reloads counts and rows at most this often (with a trailing reload).
const LIVE_RELOAD_MIN_MS = 10_000;
// Facet values the server returns; the chip rows show the top few and expand to the rest.
const FACET_LIMIT = 200;
const CHIPS_SHOWN = 10;
// The chip text for runs that declared no technique or probe kind.
const NONE_DECLARED = "None declared";
const PALETTE_LIMIT = 30;

const ATTENTION_RULE =
  "Runs that did not plainly complete or succeed, returned partial results, were superseded, or whose output is unsettled, untrusted, suppressed or only partly measured.";

// ── Colors ────────────────────────────────────────────────────────────
// Tool, agent, technique and probe-kind hues (tags and chip dots). Unknown
// values fall back to a hash-derived color so colors stay stable across reloads.
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

const HASH_PALETTE = [
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
  for (let i = 0; i < s.length; i += 1) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h;
}

export function toolColor(bin: string | null | undefined): string {
  const key = (bin || "").toLowerCase();
  if (TOOL_COLORS[key]) return TOOL_COLORS[key];
  if (!key) return "var(--chip-muted-grey)";
  return HASH_PALETTE[hashString(key) % HASH_PALETTE.length];
}

// Keyed on a substring so `recon-analyst`, `recon-v2` keep the recon hue.
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

export function agentColor(name: string | null | undefined): string {
  const n = (name || "").toLowerCase();
  for (const { key, color } of AGENT_ROLE_COLORS) if (n.includes(key)) return color;
  if (!n) return "var(--chip-muted-grey)";
  return HASH_PALETTE[hashString(n) % HASH_PALETTE.length];
}

// Five tiers by vulnerability family; the enum may grow server-side.
const TECHNIQUE_COLORS: Record<string, string> = {
  SSRF: "var(--chip-red)",
  XSS: "var(--chip-red)",
  XXE: "var(--chip-red)",
  SSTI: "var(--chip-red)",
  CMDI: "var(--chip-red)",
  RCE: "var(--chip-red)",
  SQLI: "var(--chip-orange)",
  NOSQLI: "var(--chip-orange)",
  LFI: "var(--chip-orange)",
  RFI: "var(--chip-orange)",
  "REQUEST-SMUGGLING": "var(--chip-orange)",
  "OPEN-REDIRECT": "var(--chip-orange)",
  IDOR: "var(--chip-purple)",
  AUTH: "var(--chip-purple)",
  JWT: "var(--chip-purple)",
  CSRF: "var(--chip-purple)",
  CORS: "var(--chip-purple)",
  RECON: "var(--chip-teal)",
  DISCOVERY: "var(--chip-teal)",
  OSINT: "var(--chip-teal)",
  FUZZ: "var(--chip-teal)",
  "CVE-VALIDATION": "var(--chip-teal)",
  "INFO-DISCLOSURE": "var(--chip-muted-grey)",
  "RATE-LIMIT": "var(--chip-muted-grey)",
  "EXPLOIT-CHAIN": "var(--chip-muted-grey)",
  OTHER: "var(--chip-muted-grey)",
};

function techniqueColor(t: string | null | undefined): string {
  if (!t) return "var(--chip-muted-grey)";
  const up = t.toUpperCase();
  return TECHNIQUE_COLORS[up] ?? HASH_PALETTE[hashString(up) % HASH_PALETTE.length];
}

// Probe kind is a closed six-value enum.
const PROBE_KIND_COLORS: Record<string, string> = {
  fingerprint: "var(--chip-teal)",
  baseline: "var(--chip-slate)",
  payload: "var(--chip-orange)",
  exploit: "var(--chip-red)",
  replay: "var(--chip-purple)",
  cleanup: "var(--chip-muted-grey)",
};

function probeKindColor(pk: string | null | undefined): string {
  return PROBE_KIND_COLORS[(pk || "").toLowerCase()] ?? "var(--chip-muted-grey)";
}

function tint(color: string, pct = 10): string {
  return `color-mix(in srgb, ${color} ${pct}%, transparent)`;
}

// Mid-truncate: keep the binary up front and the target at the end.
function midTruncate(text: string, max: number): string {
  if (!text || text.length <= max) return text || "";
  const head = Math.max(1, Math.floor((max - 1) * 0.6));
  const tail = Math.max(1, max - 1 - head);
  return `${text.slice(0, head)}…${text.slice(text.length - tail)}`;
}

const INCOMPLETE_OUTPUT_RETENTION = new Set(["measurement_conflict", "partially_measured", "preview_only", "unmeasured"]);

// ── Record sections ──────────────────────────────────────────────────
// `dtab` in the URL; the record opens on "command".
type CommandSection = "command" | "stdout" | "stderr" | "context" | "audit";
const COMMAND_SECTIONS: readonly CommandSection[] = ["command", "stdout", "stderr", "context", "audit"];

function isCommandSection(value: string | null | undefined): value is CommandSection {
  return typeof value === "string" && (COMMAND_SECTIONS as readonly string[]).includes(value);
}

function sectionParam(section: CommandSection): CommandSection | undefined {
  return section === "command" ? undefined : section;
}

/** The open record: its id, and its list row once known (a deep link starts without one). */
type OpenRun = { id: number; row: CommandLedgerRow | null };

type RecordRead = { id: number; record: AssessmentCommandRunDetail | null; error: string | null };

function readSavedView(engagementKey: string): CommandView {
  try {
    return parseCommandView(window.sessionStorage.getItem(commandViewKey(engagementKey)));
  } catch {
    return parseCommandView(null);
  }
}

const IconSearch = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="search-icon" aria-hidden="true">
    <circle cx={11} cy={11} r={7} />
    <path d="M21 21l-4.3-4.3" />
  </svg>
);
const IconClose = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);

const SEARCH_TOKENS: Array<[string, string]> = [
  ["tool:curl", "derived tool or tool name"],
  ["agent:recon-specialist", "agent name"],
  ["phase:consume-test", "phase"],
  ["status:failed", "lifecycle status; status:retained / status:empty match output retention"],
  ["rc:0  rc:!0  rc:timeout", "exit outcome"],
  ["target:app.example.com", "stored or inferred target"],
  ["hash:7a2e47", "command hash prefix (runs of the same command)"],
  ["technique:ssrf  probe:exploit", "command metadata"],
  ['intent:"token leak"', "intent text"],
  ["write:true", "runs that declared they change target state"],
  ["3f2a91c4  #1024", "run_uuid prefix or run id"],
];

// ── Component ────────────────────────────────────────────────────────
// Each engagement gets its own workspace state (and its own saved view).
export function CommandsTab(props: CommandsTabProps) {
  return <CommandsWorkspace key={props.engagementKey} {...props} />;
}

function CommandsWorkspace({ engagementKey, refreshVersion = 0, commandId, initialDrawerTab, onAttentionCount }: CommandsTabProps) {
  const [saved] = useState(() => readSavedView(engagementKey));
  const [filters, setFilters] = useState<CommandFilters>(saved.filters);
  const [searchText, setSearchText] = useState(saved.filters.q);
  const [sort, setSort] = useState<CommandSort>(saved.sort);
  const [open, setOpen] = useState<OpenRun | null>(commandId !== undefined ? { id: commandId, row: null } : null);
  const [cursorId, setCursorId] = useState<number | null>(commandId ?? null);
  const [section, setSection] = useState<CommandSection>(isCommandSection(initialDrawerTab) ? initialDrawerTab : "command");
  const [gridWindow, setGridWindow] = useState<{ total: number | null; first: number; last: number }>({ total: null, first: 0, last: 0 });
  const [gridError, setGridError] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const searchRef = useRef<HTMLInputElement | null>(null);
  const invokerRef = useRef<HTMLElement | null>(null);
  const paletteInvokerRef = useRef<HTMLElement | null>(null);
  const gridHandleRef = useRef<CommandsGridHandle | null>(null);
  const cursorIndexRef = useRef<number | null>(null);

  // Typing updates the box at once; the server sees it after a pause.
  useEffect(() => {
    if (searchText === filters.q) return;
    const timer = window.setTimeout(() => setFilters((current) => ({ ...current, q: searchText })), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [searchText, filters.q]);

  useEffect(() => {
    try {
      window.sessionStorage.setItem(commandViewKey(engagementKey), JSON.stringify({ filters, sort } satisfies CommandView));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, filters, sort]);

  // Live updates: a burst reloads at most once per window, plus a trailing reload.
  const refreshToken = useLiveRefreshToken(refreshVersion, LIVE_RELOAD_MIN_MS);

  const filtersKey = useMemo(() => commandFiltersKey(filters), [filters]);
  const facetsKey = `${engagementKey}\u0000${filtersKey}`;
  const facets = useCoalescedRequest(
    facetsKey,
    useCallback(() => fetchCommandFacets(engagementKey, filters, FACET_LIMIT), [engagementKey, filters]),
    refreshToken,
  );
  const counts = facets.dataKey === facetsKey ? facets.data : null;
  const lastCounts = facets.data;
  const ledgerAttention = counts?.engagement_totals.attention;
  useEffect(() => {
    if (ledgerAttention != null) onAttentionCount?.(ledgerAttention);
  }, [ledgerAttention, onAttentionCount]);

  // ── The open run ────
  // The URL owns which run is open and which section it shows.
  useEffect(() => {
    if (commandId === undefined) {
      setOpen(null);
      return;
    }
    setOpen((current) => (current?.id === commandId ? current : { id: commandId, row: null }));
    setCursorId(commandId);
  }, [commandId]);
  useEffect(() => {
    setSection(isCommandSection(initialDrawerTab) ? initialDrawerTab : "command");
  }, [initialDrawerTab]);

  // The record reads the full run (command, argv, output previews) by id; a
  // live refresh re-reads it so a running command's outcome appears in place.
  // Reads coalesce: one in flight, one trailing re-read after a refresh burst.
  const openId = open?.id ?? null;
  const [read, setRead] = useState<RecordRead | null>(null);
  const openIdRef = useRef(openId);
  openIdRef.current = openId;
  const readRecord = useCoalescedRunner(async () => {
    const id = openIdRef.current;
    if (id === null) return;
    try {
      const fresh = await getCommandRunRecord(engagementKey, id);
      if (openIdRef.current === id) setRead({ id, record: fresh, error: null });
    } catch (error) {
      if (openIdRef.current !== id) return;
      const message = error instanceof Error ? error.message : "request failed";
      setRead((current) => (current?.id === id && current.record ? { ...current, error: message } : { id, record: null, error: message }));
    }
  });
  useEffect(() => {
    if (openId !== null) void readRecord();
  }, [openId, refreshToken, readRecord]);
  const record = read?.id === openId ? read.record : null;
  const readError = read?.id === openId ? read.error : null;
  const linkError = openId !== null && !record && !open?.row ? readError : null;
  const investigating = open !== null && (record !== null || open.row !== null);
  // A deep-linked run shows its record's shape until the first read lands.
  const recordLoading = openId !== null && !investigating && !linkError;

  // A run opened from outside the list (a receipt link, the palette) that
  // needs no attention widens the default scope so it sits in the results.
  const widenedFor = useRef<number | null>(null);
  useEffect(() => {
    if (!record || widenedFor.current === record.id) return;
    widenedFor.current = record.id;
    if (record.needs_attention === false) setFilters((current) => (current.scope === "attention" ? { ...current, scope: "all" } : current));
  }, [record]);

  // ── Open, step, close ────
  const openRun = useCallback((row: CommandLedgerRow, invoker: HTMLElement | null) => {
    invokerRef.current = invoker ?? searchRef.current;
    cursorIndexRef.current = gridHandleRef.current?.indexOf(row.id) ?? cursorIndexRef.current;
    setOpen({ id: row.id, row });
    setCursorId(row.id);
    setSection("command");
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "commands", command: row.id }));
  }, [engagementKey]);
  // Stepping keeps the open section, like the Findings record.
  const stepTo = useCallback((row: CommandLedgerRow) => {
    setOpen({ id: row.id, row });
    setCursorId(row.id);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "commands", command: row.id, dtab: sectionParam(section) }));
  }, [engagementKey, section]);
  const closeRecord = useCallback(() => {
    setOpen(null);
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "commands" }));
  }, [engagementKey]);
  const chooseSection = useCallback((next: CommandSection) => {
    setSection(next);
    if (openId !== null) writeWorkspaceHash(engagementHref(engagementKey, { tab: "commands", command: openId, dtab: sectionParam(next) }));
  }, [engagementKey, openId]);

  // Previous / Next walk the paged list in the grid's order: the server
  // locates the open run under the current filters and sort, so stepping
  // crosses block boundaries the grid has not loaded.
  const navigation = useRecordPosition<CommandLedgerRow>({
    key: openId === null ? null : String(openId),
    identity: JSON.stringify([engagementKey, filtersKey, sort.sort, sort.dir, refreshToken]),
    load: () => fetchCommandPosition(engagementKey, openId as number, filters, sort),
    keyOf: (row) => String(row.id),
    open: stepTo,
  });
  if (typeof navigation.index === "number") cursorIndexRef.current = navigation.index;

  // Back to results lands on the run last shown: scroll its position into
  // view (loading its block) so the row can take focus and the highlight.
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const revealRun = useCallback((key: string) => {
    const handle = gridHandleRef.current;
    if (!handle) return;
    const index = handle.indexOf(Number(key)) ?? cursorIndexRef.current;
    if (index != null) handle.reveal(index);
  }, []);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: openId, reveal: revealRun });

  // ── Filters ────
  const setScope = useCallback((scope: CommandScope) => setFilters((current) => ({ ...current, scope })), []);
  const toggleValue = useCallback((dimension: "status" | "tool" | "agent" | "technique" | "probe_kind", value: string) => {
    setFilters((current) => {
      const values = current[dimension];
      return { ...current, [dimension]: values.includes(value) ? values.filter((item) => item !== value) : [...values, value] };
    });
  }, []);
  const clearFilters = useCallback(() => {
    setSearchText("");
    setFilters((current) => ({ ...DEFAULT_COMMAND_FILTERS, scope: current.scope }));
  }, []);
  // A search typed elsewhere (a target cell, a record action) replaces the box at once.
  const search = useCallback((q: string) => {
    setSearchText(q);
    setFilters((current) => ({ ...current, q }));
  }, []);
  const searchFromRecord = useCallback((q: string) => {
    search(q);
    closeRecord();
  }, [search, closeRecord]);

  const activeFilters = activeCommandFilterCount({ ...filters, q: searchText });

  // ── Palette ────
  const openPalette = useCallback((invoker?: HTMLElement) => {
    if (paletteOpen) return;
    const origin = invoker ?? document.activeElement;
    paletteInvokerRef.current = origin instanceof HTMLElement && origin.isConnected ? origin : searchRef.current;
    setPaletteOpen(true);
  }, [paletteOpen]);
  const jumpTo = useCallback((row: CommandLedgerRow) => {
    setPaletteOpen(false);
    if (investigatingRef.current) stepTo(row);
    else openRun(row, paletteInvokerRef.current);
  }, [openRun, stepTo]);

  // ── Keyboard ────
  const investigatingRef = useRef(investigating);
  investigatingRef.current = investigating;
  const navigationRef = useRef(navigation);
  navigationRef.current = navigation;
  const totalRef = useRef(gridWindow.total);
  totalRef.current = gridWindow.total;
  const cursorRef = useRef(cursorId);
  cursorRef.current = cursorId;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target instanceof HTMLElement ? e.target : null;
      const isTyping = Boolean(target?.closest("input, textarea, select, [contenteditable]:not([contenteditable='false'])"));
      const isInteractive = isTyping || Boolean(target?.closest("button, a, [role='button'], [role='combobox'], [role='listbox']"));
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openPalette();
        return;
      }
      // The palette handles its own keys.
      if (document.querySelector('[aria-modal="true"]')) return;
      if (!isTyping && e.key === "/") {
        e.preventDefault();
        if (investigatingRef.current) closeRecord();
        queueMicrotask(() => {
          searchRef.current?.focus({ preventScroll: true });
          searchRef.current?.scrollIntoView?.({ block: "center" });
        });
        return;
      }
      if (e.key === "Escape" && isTyping && target === searchRef.current) {
        searchRef.current?.blur();
        return;
      }
      if (isInteractive || e.metaKey || e.ctrlKey || e.altKey) return;
      const back = e.key === "k";
      const forward = e.key === "j";
      if (investigatingRef.current) {
        // [ / ] belong to the record view; j / k step the same way.
        if (!back && !forward) return;
        const { onPrevious, onNext, pending } = navigationRef.current;
        const step = back ? onPrevious : onNext;
        if (!step || pending) return;
        e.preventDefault();
        step();
        return;
      }
      if (back || forward) {
        // j / k move the list cursor (and keyboard focus) a row; Enter opens it.
        const handle = gridHandleRef.current;
        const total = totalRef.current;
        if (!handle || !total) return;
        e.preventDefault();
        const from = cursorRef.current != null ? handle.indexOf(cursorRef.current) ?? cursorIndexRef.current : cursorIndexRef.current;
        const next = from == null ? 0 : Math.min(total - 1, Math.max(0, from + (forward ? 1 : -1)));
        cursorIndexRef.current = next;
        handle.reveal(next, true);
        const row = handle.rowAt(next);
        if (row) setCursorId(row.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openPalette, closeRecord]);

  // ── Derived view ────
  const scopeTotals = lastCounts?.scope_totals ?? null;
  const engagementTotals = lastCounts?.engagement_totals ?? null;
  const matching = counts?.total ?? gridWindow.total;
  const sortLabel = COMMAND_SORT_LABELS[sort.sort];
  const empty = counts !== null && counts.total === 0;
  const firstLoad = lastCounts === null && !facets.error;
  const updating = facets.loading && lastCounts !== null;
  const recordHeader = record ?? open?.row ?? null;
  // An engagement with no runs at all has nothing to search or filter.
  const nothingRecorded = engagementTotals?.all === 0;

  return (
    <div className="findings-redesign commands-page">
      <PageHeader
        title="Commands"
        purpose="Every tool command agents ran through Vigil, newest first. Open a run for its full command, output and outcome."
        stats={[
          { value: engagementTotals?.all, label: "runs" },
          { value: engagementTotals?.all ? engagementTotals.attention : null, label: "need attention", tone: "warning", title: ATTENTION_RULE },
        ]}
        status={updating ? "Updating…" : null}
        actions={nothingRecorded ? null : (
          <button type="button" className="ui-button commands-jump" onClick={(event) => openPalette(event.currentTarget)}>
            Jump to… <kbd>⌘K</kbd>
          </button>
        )}
        hidden={investigating}
      >
        {!nothingRecorded && <ScopeToggle
          label="Command run scope"
          scope={filters.scope}
          onChange={setScope}
          attentionCount={scopeTotals?.attention}
          allCount={scopeTotals?.all}
          attentionRule={ATTENTION_RULE}
        />}
      </PageHeader>

      <section className="panel commands-filters" aria-label="Search and filters" hidden={investigating || nothingRecorded}>
        <div className="commands-search-row">
          <div className="search-wrap commands-search">
            <IconSearch />
            <input
              ref={searchRef}
              className="search-input"
              type="search"
              aria-label="Search command runs"
              placeholder="Search commands, targets, intent, run IDs… or tool:curl rc:!0"
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") setFilters((current) => ({ ...current, q: searchText }));
              }}
            />
            {searchText && (
              <button type="button" className="icon-btn" onClick={() => search("")} aria-label="Clear command search" title="Clear" style={{ width: 22, height: 22 }}>
                <IconClose />
              </button>
            )}
            <span className="search-kbd" aria-hidden="true">/</span>
          </div>
          <details className="commands-syntax">
            <summary>Search syntax</summary>
            <dl>
              {SEARCH_TOKENS.map(([token, meaning]) => (
                <div key={token}>
                  <dt><code>{token}</code></dt>
                  <dd>{meaning}</dd>
                </div>
              ))}
            </dl>
            <p className="meta-text">Free words match the command, tool, agent, phase, target, intent and notes. Every term must match.</p>
          </details>
        </div>
        <div className="commands-chip-rows">
          <CommandFacetChips
            label="Status"
            facet={lastCounts?.facets.status ?? null}
            selected={filters.status}
            onToggle={(value) => toggleValue("status", value)}
            order={(a, b) => compareStatus("command", a, b)}
            statusDomain="command"
            labelFor={(value) => statusLabel("command", value)}
            showAll
          />
          <CommandFacetChips
            label="Tool"
            facet={lastCounts?.facets.tool ?? null}
            selected={filters.tool}
            onToggle={(value) => toggleValue("tool", value)}
            labelFor={(value) => value || "(unknown)"}
            colorFor={toolColor}
            scope="tool"
          />
          <CommandFacetChips
            label="Agent"
            facet={lastCounts?.facets.agent ?? null}
            selected={filters.agent}
            onToggle={(value) => toggleValue("agent", value)}
            labelFor={(value) => value || "(no agent)"}
            colorFor={agentColor}
            scope="agent"
          />
          <CommandFacetChips
            label="Technique"
            facet={lastCounts?.facets.technique ?? null}
            selected={filters.technique}
            onToggle={(value) => toggleValue("technique", value)}
            labelFor={(value) => value || NONE_DECLARED}
            colorFor={techniqueColor}
            scope="technique"
          />
          <CommandFacetChips
            label="Kind"
            facet={lastCounts?.facets.probe_kind ?? null}
            selected={filters.probe_kind}
            onToggle={(value) => toggleValue("probe_kind", value)}
            labelFor={(value) => value || NONE_DECLARED}
            colorFor={probeKindColor}
            scope="probe"
          />
          <ClearFiltersButton count={activeFilters} onClear={clearFilters} />
        </div>
      </section>

      {facets.error && (
        <p className="error-text commands-banner" role="alert">
          Command counts unavailable: {facets.error}{lastCounts ? " · Showing the last counts read." : ""}
        </p>
      )}
      {gridError && (
        <p className="error-text commands-banner" role="alert">Command runs could not be loaded: {gridError}</p>
      )}
      {recordLoading && (
        <section className="commands-record-loading" aria-label={`Loading command run #${openId}`} aria-busy="true">
          <CardSkeleton lines={4} />
          <SlowLoadHint active what={`command run #${openId}`} />
        </section>
      )}
      {linkError && (
        <p className="error-text commands-banner" role="alert">Command run #{openId} could not be opened: {linkError}</p>
      )}

      <div ref={resultsRef} className="commands-results" hidden={investigating || recordLoading}>
        <div className="commands-results-head" hidden={nothingRecorded}>
          {matching != null ? (
            <ResultsSummary
              shown={matching}
              total={engagementTotals?.all ?? null}
              noun="command runs"
              sort={describeSort(sortLabel.column, sort.dir, sortLabel.kind)}
            />
          ) : (
            <Skeleton width={260} height={12} />
          )}
          {!empty && gridWindow.total != null && gridWindow.total > 0 && gridWindow.last > 0 && (
            <span className="meta-text commands-range">
              Rows {gridWindow.first.toLocaleString()}–{gridWindow.last.toLocaleString()} in view
            </span>
          )}
        </div>
        <SlowLoadHint active={firstLoad} what="the command ledger" />
        {counts && counts.total === 0 ? (
          <CommandsEmpty
            filters={filters}
            activeFilters={activeFilters}
            ledgerTotal={counts.engagement_totals.all}
            allInScope={counts.scope_totals.all}
            onClearFilters={clearFilters}
            onShowAll={() => setScope("all")}
          />
        ) : (
          <section className="panel commands-grid-panel" aria-label="Command runs" aria-busy={facets.loading}>
            <Suspense fallback={<TableSkeleton rows={10} showHeader={false} />}>
              <CommandsGrid
                engagementKey={engagementKey}
                filters={filters}
                filtersKey={filtersKey}
                refreshToken={refreshToken}
                initialSort={sort}
                selectedId={cursorId}
                onRowOpen={openRun}
                onWindow={setGridWindow}
                onError={setGridError}
                onSortChange={setSort}
                onTargetClick={(target) => search(searchToken("target", target))}
                onHandle={(handle) => { gridHandleRef.current = handle; }}
              />
            </Suspense>
          </section>
        )}
        <div className="findings-shortcuts" hidden={nothingRecorded}>
          <span><code>/</code> search</span>
          <span><code>⌘K</code> jump to a run</span>
          <span><code>j / k</code> move</span>
          <span><code>Enter</code> open</span>
          <span><code>[ / ]</code> previous / next in a record</span>
          <span><code>Esc</code> back to results</span>
        </div>
      </div>

      {investigating && open && recordHeader && (
        <RecordView
          label="Command run record"
          noun="command run"
          navigation={navigation}
          onBack={closeRecord}
          titleId="command-record-title"
          returnFocusRef={invokerRef}
          className="commands-record"
        >
          <CommandRecord
            key={open.id}
            id={open.id}
            header={recordHeader}
            record={record}
            readError={readError}
            engagementKey={engagementKey}
            section={section}
            onSectionChange={chooseSection}
            onSearch={searchFromRecord}
            titleId="command-record-title"
          />
        </RecordView>
      )}

      {paletteOpen && (
        <CommandPalette
          engagementKey={engagementKey}
          returnFocusRef={paletteInvokerRef}
          onSelect={jumpTo}
          onClose={() => setPaletteOpen(false)}
        />
      )}
    </div>
  );
}

// ── Facet chips ──────────────────────────────────────────────────────
// One labelled chip row per dimension with the server's counts (each facet
// ignores its own filter, so a chip shows what choosing it gives), through the
// shared FacetChipGroup. Values past the server's facet limit are named with
// the search token that still finds them.
function CommandFacetChips({
  label,
  facet,
  selected,
  onToggle,
  order,
  showAll = false,
  scope,
  ...look
}: {
  label: string;
  facet: CommandFacet | null;
  selected: string[];
  onToggle: (value: string) => void;
  order?: (a: string, b: string) => number;
  /** Every value is shown (a short, fixed vocabulary such as the statuses). */
  showAll?: boolean;
  /** The search scope that finds an unlisted value (`tool:name`). */
  scope?: string;
  labelFor: (value: string) => string;
  colorFor?: (value: string) => string | undefined;
  statusDomain?: "command";
}) {
  if (!facet) {
    return (
      <FilterGroup label={label}>
        {[0, 1, 2].map((index) => <Skeleton key={index} width={84} height={24} rounded />)}
      </FilterGroup>
    );
  }
  const values = order ? [...facet.values].sort((a, b) => order(a.value, b.value)) : facet.values;
  if (values.length === 0 && selected.length === 0) return null;
  return (
    <FacetChipGroup
      label={label}
      values={values}
      selected={new Set(selected)}
      onToggle={onToggle}
      collapsedLimit={showAll ? Number.POSITIVE_INFINITY : CHIPS_SHOWN}
      unlistedCount={facet.distinct - facet.values.length}
      unlistedHint={scope && (
        <>they cover {facet.omitted_count.toLocaleString("en-US")} runs; search <code>{scope}:name</code></>
      )}
      {...look}
    />
  );
}

function CommandsEmpty({
  filters,
  activeFilters,
  ledgerTotal,
  allInScope,
  onClearFilters,
  onShowAll,
}: {
  filters: CommandFilters;
  activeFilters: number;
  ledgerTotal: number;
  allInScope: number;
  onClearFilters: () => void;
  onShowAll: () => void;
}) {
  if (ledgerTotal === 0) {
    return (
      <EmptyState variant="empty" title="No command runs recorded yet.">
        Agents record every tool command they run through Vigil here, with its output and outcome.
      </EmptyState>
    );
  }
  const showAll = filters.scope === "attention" && allInScope > 0
    ? <button type="button" className="ui-button" onClick={onShowAll}>Show all {allInScope.toLocaleString()} runs</button>
    : undefined;
  if (activeFilters === 0) {
    return (
      <EmptyState variant="empty" title="No command runs need attention." action={showAll}>
        Every recorded run completed cleanly and kept its output.
      </EmptyState>
    );
  }
  return (
    <EmptyState variant="filtered" title="No command runs match these filters." onClearFilters={onClearFilters} action={showAll}>
      {filters.scope === "attention" ? "Only runs that need attention are searched." : null}
    </EmptyState>
  );
}

// ── CommandRecord ─────────────────────────────────────────────────────
// One command run inside the shared record view (CommandsTab owns the view,
// the list order and the URL). The header shows from the list row at once;
// the sections wait for the full record read.
type HeaderFields = {
  status: CommandLedgerRow["status"];
  return_code: number | null;
  timeout_seconds_requested?: number | null;
  tool_bin: string;
  tool_name: string;
  agent_name: string;
  phase: string;
  technique?: string | null;
  probe_kind?: string | null;
  destructive?: boolean | null;
  intent?: string | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_ms: number;
  attention_reasons?: string[];
  command?: string;
  command_preview?: string;
};

function CommandRecord({
  id,
  header,
  record,
  readError,
  engagementKey,
  section,
  onSectionChange,
  onSearch,
  titleId,
}: {
  id: number;
  header: HeaderFields;
  record: AssessmentCommandRunDetail | null;
  readError: string | null;
  engagementKey: string;
  section: CommandSection;
  onSectionChange: (section: CommandSection) => void;
  onSearch: (q: string) => void;
  titleId: string;
}) {
  const tool = header.tool_bin || header.tool_name || "";
  const toolHue = toolColor(tool);
  const command = record?.command ?? header.command_preview ?? "";
  const running = header.status === "running" || header.status === "queued";
  const technique = (header.technique || "").trim().toUpperCase();
  const probeKind = (header.probe_kind || "").trim().toLowerCase();
  const intent = (header.intent || "").trim();
  return (
    <>
      <RecordHeader
        id={`Command run #${id}`}
        copyId={String(id)}
        copyIdLabel="Copy command run ID"
        title={intent || <span className="mono">{midTruncate(command, 160) || "(no command recorded)"}</span>}
        titleId={titleId}
        tone={statusTone("command", header.status)}
        actions={
          <>
            <RecordCopyButton
              label="Copy command"
              text={() => record?.command ?? ""}
              successMessage="Command copied"
              failureMessage="Could not copy the command. Select it in the Command section instead."
              disabled={!record?.command}
            />
            <RecordCopyLinkButton noun="command run" />
          </>
        }
        pills={
          <>
            <StatusPill domain="command" value={header.status} reason={commandStatusReason({ status: header.status, return_code: header.return_code, timeout_seconds_requested: header.timeout_seconds_requested ?? null, attention_reasons: header.attention_reasons }) || undefined} />
            <span className="tag" style={{ color: toolHue, background: tint(toolHue) }} title="Tool">{tool || "(unknown tool)"}</span>
            {header.agent_name && (
              <span className="tag" style={{ color: agentColor(header.agent_name), background: tint(agentColor(header.agent_name)) }} title="Agent">
                {header.agent_name}
              </span>
            )}
            {header.phase && <span className="tag" title="Phase">{header.phase}</span>}
            {technique && (
              <span className="tag" style={{ color: techniqueColor(technique), background: tint(techniqueColor(technique)) }} title="Technique">{technique}</span>
            )}
            {probeKind && (
              <span className="tag" style={{ color: probeKindColor(probeKind), background: tint(probeKindColor(probeKind)) }} title="Probe kind">{probeKind}</span>
            )}
            {header.destructive && <span className="tag warning">writes target state</span>}
          </>
        }
        datesLabel="Command run dates"
        dates={[
          { label: "Started", value: header.started_at || header.created_at },
          {
            label: "Finished",
            value: header.completed_at,
            fallback: running ? "still running" : "not recorded",
            detail: header.completed_at && header.duration_ms > 0 ? <> · ran {formatDuration(header.duration_ms)}</> : undefined,
          },
        ]}
      />
      <RecordTabs
        label="Command run sections"
        active={section}
        onChange={onSectionChange}
        tabs={[
          { id: "command", label: "Command", count: record?.argv?.length || undefined },
          { id: "stdout", label: "Stdout" },
          { id: "stderr", label: "Stderr" },
          { id: "context", label: "Context" },
          { id: "audit", label: "Audit" },
        ]}
      />
      <RecordBody busy={!record && !readError}>
        {readError && (
          <p className="error-text" role="alert">
            {record ? `Showing the last read of this run. Refresh failed: ${readError}` : `Command run details unavailable: ${readError}`}
          </p>
        )}
        {!record ? (
          readError ? null : (
            <div className="commands-preview-skeleton" aria-label="Loading command run" role="status">
              {Array.from({ length: 5 }).map((_, index) => <Skeleton key={index} width={index === 4 ? "55%" : "90%"} height={10} />)}
            </div>
          )
        ) : (
          <>
            {section === "command" && <CommandPane record={record} engagementKey={engagementKey} />}
            {(section === "stdout" || section === "stderr") && <StreamPane key={section} record={record} kind={section} />}
            {section === "context" && <ContextPane record={record} engagementKey={engagementKey} onSearch={onSearch} />}
            {section === "audit" && <AuditPane record={record} onSearch={onSearch} />}
          </>
        )}
      </RecordBody>
    </>
  );
}

// ── Record panes ─────────────────────────────────────────────────────
function KV({ k, v, mono, copyText }: { k: string; v: unknown; mono?: boolean; copyText?: string }) {
  if (v === undefined || v === null || v === "") return null;
  const str = typeof v === "string" ? v : String(v);
  if (!str) return null;
  return (
    <div className="kv">
      <p className="k">{k}</p>
      <p className={`v commands-kv-value ${mono ? "mono" : ""}`}>
        <span className="commands-kv-text">{str}</span>
        {copyText && <CopyInline text={copyText} ariaLabel={`Copy ${k}`}>copy</CopyInline>}
      </p>
    </div>
  );
}

// Command-metadata rows always render: a null field reads "—" (posted before
// the metadata existed), never a missing row.
function MetaKV({ k, children }: { k: string; children?: ReactNode }) {
  return (
    <div className="kv">
      <p className="k">{k}</p>
      <p className="v">{children ?? <span className="commands-muted">—</span>}</p>
    </div>
  );
}

function SearchTag({ scope, value, color, onSearch, label }: { scope: string; value: string; color: string; onSearch: (q: string) => void; label?: string }) {
  return (
    <button
      type="button"
      className="tag commands-search-tag"
      style={{ color, background: tint(color) }}
      onClick={() => onSearch(searchToken(scope, value))}
      title={`Show runs with ${searchToken(scope, value)}`}
      aria-label={`Show runs with ${scope} ${value}`}
    >
      {label ?? value}
    </button>
  );
}

function LinkedFindingKV({ record, engagementKey }: { record: AssessmentCommandRunDetail; engagementKey: string }) {
  if (record.finding_id == null) return null;
  return (
    <div className="kv">
      <p className="k">Linked finding</p>
      <p className="v">
        {record.finding_slug
          ? <a className="mono" href={engagementHref(engagementKey, { tab: "findings", finding: record.finding_slug })}>{record.finding_slug}</a>
          : <>Finding #{record.finding_id} (no slug recorded)</>}
      </p>
    </div>
  );
}

function targetLabel(record: AssessmentCommandRunDetail, stored: string) {
  return record.target_source === "inferred" ? "Target (inferred from command)" : stored;
}

function CommandPane({ record, engagementKey }: { record: AssessmentCommandRunDetail; engagementKey: string }) {
  return (
    <>
      <div className="kv-grid" aria-label="Command run facts">
        <KV k="Tool" v={record.tool_bin || record.tool_name || "(unknown)"} mono />
        <KV k="Agent" v={record.agent_name || "Not recorded"} />
        <KV k={targetLabel(record, "Target")} v={record.target || "Not recorded"} mono={Boolean(record.target)} />
        <KV k="Duration" v={formatDuration(record.duration_ms)} />
        <LinkedFindingKV record={record} engagementKey={engagementKey} />
      </div>
      <section className="section">
        <h3 className="section-title">Command</h3>
        <pre className="pre">{record.command || "(no command recorded)"}</pre>
      </section>
      {record.argv && record.argv.length > 0 && (
        <section className="section">
          <h3 className="section-title">
            Argv <span className="count">{record.argv.length}</span>
          </h3>
          <ol className="steps mono">
            {record.argv.map((arg, index) => <li key={index}>{arg}</li>)}
          </ol>
        </section>
      )}
      {record.superseded_by_id != null && (
        <div className="callout">
          <p className="section-title">Superseded by run {record.superseded_by_id}</p>
          <p>
            This row remains in the immutable command ledger for audit history.{" "}
            <a href={engagementHref(engagementKey, { tab: "commands", command: record.superseded_by_id })}>Open command run #{record.superseded_by_id}</a>
          </p>
        </div>
      )}
      {record.notes && (
        <div className="callout">
          <p className="section-title">Notes</p>
          <p className="commands-prewrap">{record.notes}</p>
        </div>
      )}
    </>
  );
}

function ContextPane({ record, engagementKey, onSearch }: { record: AssessmentCommandRunDetail; engagementKey: string; onSearch: (q: string) => void }) {
  const technique = (record.technique || "").trim().toUpperCase();
  const probeKind = (record.probe_kind || "").trim().toLowerCase();
  const intent = (record.intent || "").trim();
  return (
    <>
      <section className="section">
        <h3 className="section-title">Outcome</h3>
        <div className="kv-grid">
          <KV k="Lifecycle status" v={statusLabel("command", record.status)} />
          <KV k="Return code" v={record.return_code == null ? "—" : String(record.return_code)} />
          <KV k="Timed out" v={record.timed_out ? "yes" : "no"} />
          <KV k="Timeout requested" v={record.timeout_seconds_requested ? `${record.timeout_seconds_requested}s` : undefined} />
          <KV k="Success" v={record.success ? "yes" : "no"} />
          <KV k="Results" v={record.partial_results ? "partial" : "complete"} />
          <KV k="Needs attention" v={record.attention_reasons?.length ? record.attention_reasons.join(" · ") : "no"} />
          <KV k="Duration" v={formatDuration(record.duration_ms)} />
          <KVTime k="Started" v={record.started_at} />
          <KVTime k="Completed" v={record.completed_at} />
          <KVTime k="Recorded" v={record.created_at} />
          {record.output_recovery_observed_at
            ? <KVTime k="Output recovery baseline" v={record.output_recovery_observed_at} />
            : <KV k="Output recovery baseline" v="—" />}
        </div>
      </section>
      <section className="section">
        <h3 className="section-title">Who ran it, where</h3>
        <div className="kv-grid">
          <KV k="Agent" v={record.agent_name} />
          <KV k="Phase" v={record.phase} />
          <KV k="Tool name" v={record.tool_name} mono />
          <KV k="Tool bin" v={record.tool_bin} mono />
          <KV k="Route" v={record.route} mono />
          <KV k="Audit source" v={record.audit_source} />
          {record.target && <KV k={targetLabel(record, "Target (stored)")} v={record.target} mono />}
          <KV k="Auth context" v={record.auth_context} mono />
          <KV k="Scope version" v={record.scope_version} mono />
          <KV k="Working directory" v={record.working_dir} mono />
          <KV k="Finding ID" v={record.finding_id} mono />
          <LinkedFindingKV record={record} engagementKey={engagementKey} />
        </div>
      </section>
      <section className="section">
        <h3 className="section-title">What it was for</h3>
        <div className="kv-grid">
          <MetaKV k="Technique">
            {technique ? <SearchTag scope="technique" value={technique} color={techniqueColor(technique)} onSearch={onSearch} /> : undefined}
          </MetaKV>
          <MetaKV k="Probe kind">
            {probeKind ? <SearchTag scope="probe" value={probeKind} color={probeKindColor(probeKind)} onSearch={onSearch} /> : undefined}
          </MetaKV>
          <MetaKV k="Intent">{intent ? <span className="commands-intent">{intent}</span> : undefined}</MetaKV>
          <MetaKV k="Destructive">
            {record.destructive == null ? undefined : (
              <StatusPill
                tone={record.destructive ? "warning" : "neutral"}
                value={record.destructive ? "destructive" : "read-only"}
                label={record.destructive ? "Yes, writes target state" : "No"}
                size="sm"
              />
            )}
          </MetaKV>
        </div>
      </section>
    </>
  );
}

function StreamPane({ record, kind }: { record: AssessmentCommandRunDetail; kind: "stdout" | "stderr" }) {
  const retention = (record.output_retention_status || "").toLowerCase();
  const integrity = (record.output_integrity_status || "").toLowerCase();
  const preview = kind === "stdout" ? record.stdout_preview : record.stderr_preview;
  const suppressionReason = kind === "stdout" ? record.stdout_suppression_reason : record.stderr_suppression_reason;
  const artifactRef = kind === "stdout" ? record.stdout_artifact_ref : record.stderr_artifact_ref;
  const sha = kind === "stdout" ? record.stdout_sha256 : record.stderr_sha256;
  const bytes = kind === "stdout" ? record.stdout_bytes : record.stderr_bytes;

  if (integrity === "pending" || integrity === "warning") {
    return (
      <section className="section">
        <div className="callout commands-callout-danger">
          <p className="section-title">Output integrity is {integrity}</p>
          <p>
            Captured output is shown below, but it has not passed integrity verification.
            {" "}{record.output_integrity_warning || "Vigil has not proved that this artifact stayed stable; treat it as untrusted evidence."}
          </p>
        </div>
        <h3 className="section-title">Captured output preview</h3>
        <pre className="pre commands-output">{preview || "(empty preview)"}</pre>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="Retention" v={retention || "unknown"} />
          <KV k="Integrity" v={integrity} />
          <KV k="SHA-256" v={sha} mono copyText={sha} />
        </div>
      </section>
    );
  }

  if (retention === "suppressed" || retention.startsWith("suppression_")) {
    const spillMayRemain = retention !== "suppressed";
    return (
      <section className="section">
        <div className="callout commands-callout-pending">
          <p className="section-title">{spillMayRemain ? "Suppression incomplete" : "Suppressed"}</p>
          <p>{suppressionReason || "Output was suppressed by the capture layer."}</p>
          {spillMayRemain && (
            <p>{record.output_cleanup_warning || "Raw spill bytes may remain in the private host-exec directory and are blocked from artifact indexing."}</p>
          )}
        </div>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="SHA-256" v={sha} mono copyText={sha} />
        </div>
      </section>
    );
  }

  if (retention === "untrusted" || retention === "integrity_failure" || INCOMPLETE_OUTPUT_RETENTION.has(retention)) {
    const incompleteMeasurement = INCOMPLETE_OUTPUT_RETENTION.has(retention);
    return (
      <section className="section">
        <div className="callout commands-callout-danger">
          <p className="section-title">{incompleteMeasurement ? "Output measurement is incomplete" : "Output is not trustworthy"}</p>
          <p>{record.output_integrity_warning || (incompleteMeasurement
            ? "Vigil could not establish complete byte totals for this output; do not treat zero-valued storage defaults as proof of no output."
            : "Vigil could not prove that this output stayed stable.")}</p>
        </div>
        <div className="kv-grid">
          <KV k="Retention" v={retention} />
          <KV k="Integrity" v={record.output_integrity_status || "warning"} />
        </div>
        {preview ? <pre className="pre commands-output">{preview}</pre> : null}
      </section>
    );
  }

  if (retention === "empty" || (bytes === 0 && !preview)) {
    return (
      <section className="section">
        <p className="meta-text">No output.</p>
        <div className="kv-grid">
          <KV k="Bytes captured" v={bytes} />
          <KV k="Retention" v={retention || "empty"} />
        </div>
      </section>
    );
  }

  return (
    <section className="section">
      <h3 className="section-title">Captured output preview</h3>
      <pre className="pre commands-output">{preview || "(empty preview)"}</pre>
      {retention === "artifact" && artifactRef && (
        <div className="callout">
          <p className="section-title">Full output artifact</p>
          <p>
            Full output spilled to <span className="mono">{artifactRef}</span>
          </p>
          <div className="commands-callout-actions">
            <CopyInline text={artifactRef} ariaLabel="Copy artifact reference">Copy artifact reference</CopyInline>
          </div>
        </div>
      )}
      <div className="kv-grid">
        <KV k="Bytes captured" v={bytes} />
        <KV k="Retention" v={retention || "retained"} />
        <KV k="SHA-256" v={sha} mono copyText={sha} />
      </div>
    </section>
  );
}

function AuditPane({ record, onSearch }: { record: AssessmentCommandRunDetail; onSearch: (q: string) => void }) {
  return (
    <>
      <section className="section">
        <h3 className="section-title">Identifiers</h3>
        <div className="kv-grid">
          <KV k="ID" v={record.id} mono />
          <KV k="Run UUID" v={record.run_uuid} mono copyText={record.run_uuid} />
          <KV k="Command hash" v={record.command_hash} mono copyText={record.command_hash} />
          <KV k="Engagement ID" v={record.engagement_id} mono />
        </div>
        {record.command_hash && (
          <button type="button" className="ui-button commands-same-command" onClick={() => onSearch(searchToken("hash", record.command_hash.slice(0, 12)))}>
            Show runs with this command
          </button>
        )}
      </section>
      <section className="section">
        <h3 className="section-title">Output hashes</h3>
        <div className="kv-grid">
          <KV k="Stdout SHA-256" v={record.stdout_sha256} mono copyText={record.stdout_sha256} />
          <KV k="Stdout bytes" v={record.stdout_bytes} />
          <KV k="Stderr SHA-256" v={record.stderr_sha256} mono copyText={record.stderr_sha256} />
          <KV k="Stderr bytes" v={record.stderr_bytes} />
        </div>
      </section>
      <section className="section">
        <h3 className="section-title">Retention &amp; source</h3>
        <div className="kv-grid">
          <KV k="Retention" v={record.output_retention_status} />
          <KV k="Integrity" v={record.output_integrity_status} />
          <KV k="Integrity warning" v={record.output_integrity_warning} />
          <KV k="Cleanup" v={record.output_cleanup_status} />
          <KV k="Cleanup warning" v={record.output_cleanup_warning} />
          <KV k="Audit source" v={record.audit_source} />
          <KV k="Stdout artifact ref" v={record.stdout_artifact_ref} mono />
          <KV k="Stderr artifact ref" v={record.stderr_artifact_ref} mono />
          <KV k="Stdout suppression" v={record.stdout_suppression_reason} />
          <KV k="Stderr suppression" v={record.stderr_suppression_reason} />
          <KVTime k="Indexed at" v={record.indexed_for_embeddings_at} />
        </div>
      </section>
      <section className="section">
        <h3 className="section-title">Raw record</h3>
        <JsonView value={record} label={`command run #${record.id}`} />
      </section>
    </>
  );
}

// ── Jump palette ─────────────────────────────────────────────────────
// Searches the whole ledger on the server (every scope, no chip filters):
// the same grammar as the search box, so a run_uuid prefix or `#id` finds
// any run, not just the loaded rows.
function CommandPalette({
  engagementKey,
  onSelect,
  onClose,
  returnFocusRef,
}: {
  engagementKey: string;
  onSelect: (row: CommandLedgerRow) => void;
  onClose: () => void;
  returnFocusRef: RefObject<HTMLElement | null>;
}) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const [answer, setAnswer] = useState<{ q: string; total: number; items: CommandLedgerRow[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  useBodyScrollLock();
  useModalFocus(panelRef, onClose, true, returnFocusRef);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      fetchCommandPage(engagementKey, { ...DEFAULT_COMMAND_FILTERS, scope: "all", q }, { ...DEFAULT_COMMAND_SORT, limit: PALETTE_LIMIT, offset: 0 })
        .then((page) => {
          if (!active) return;
          setAnswer({ q, total: page.total, items: page.items });
          setError(null);
          setIdx(0);
        })
        .catch((cause: unknown) => {
          if (active) setError(cause instanceof Error ? cause.message : "Search failed");
        });
    }, q ? 200 : 0);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [engagementKey, q]);

  const results = answer?.items ?? [];
  const listId = useId();
  const optionId = (id: number) => `${listId}-run-${id}`;
  const onKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIdx((i) => Math.min(results.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIdx((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (results[idx]) onSelect(results[idx]);
    }
  };

  return (
    <div className="cmd-overlay" onClick={onClose}>
      <div ref={panelRef} className="cmd-box" role="dialog" aria-modal="true" aria-label="Jump to command" tabIndex={-1} onClick={(e) => e.stopPropagation()}>
        <div className="cmd-input-row">
          <IconSearch />
          <input
            ref={inputRef}
            className="cmd-input"
            role="combobox"
            aria-expanded={results.length > 0}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={results[idx] ? optionId(results[idx].id) : undefined}
            aria-label="Search commands to jump to"
            placeholder="Jump to a run · a run_uuid prefix, #id, tool:curl target:app.example.com"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          <span className="search-kbd" aria-hidden="true">esc</span>
        </div>
        <p className="meta-text commands-palette-count" role="status">
          {error
            ? `Search failed: ${error}`
            : answer === null
              ? "Searching…"
              : answer.total === 0
                ? "No command runs match."
                : `${answer.total.toLocaleString()} ${answer.total === 1 ? "match" : "matches"}${answer.total > results.length ? ` · showing the newest ${results.length}` : ""}${answer.q ? "" : " · newest runs"}`}
        </p>
        <div className="cmd-list" id={listId} role="listbox" aria-label="Matching command runs">
          {results.map((row, i) => (
            <button
              type="button"
              key={row.id}
              id={optionId(row.id)}
              role="option"
              aria-selected={i === idx}
              tabIndex={-1}
              className={`cmd-item ${i === idx ? "is-active" : ""}`}
              onMouseEnter={() => setIdx(i)}
              onFocus={() => setIdx(i)}
              onClick={() => onSelect(row)}
            >
              <StatusPill domain="command" value={row.status} size="sm" />
              <span>
                <span className="cmd-title mono">{row.intent?.trim() || midTruncate(row.command_preview, 96)}</span>
                <span className="cmd-sub">
                  #{row.id} · {row.tool || "(unknown tool)"}
                  {row.agent_name ? ` · ${row.agent_name}` : ""}
                  {row.target ? ` · ${row.target}` : ""}
                </span>
              </span>
              <span className="cmd-sub mono">{row.run_uuid.slice(0, 8)}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
