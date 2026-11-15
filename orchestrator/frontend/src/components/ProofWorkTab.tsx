// ── ProofWorkTab ──────────────────────────────────────────────────────
// The proof queue: parked findings that each need one concrete test, one
// row per finding, plus findings that need re-verification (links to
// Findings). It opens on the shared "Needs attention" scope (the rail badge's
// rule), sorted by what each finding asks first, with state chips and search.
// Opening a row replaces the list with the shared record view, which hosts
// that finding's ProofWorkCard; Back, Escape and browser Back return to the
// list. The open record lives in the URL (`proof=`), and a `work=` link from
// Runs opens the record that holds that test and highlights it. Reads
// coalesce like every workspace tab and live refresh keeps it current; writes
// are the existing proof-work endpoints and are never retried with an
// uncertain outcome. Scope, state chip and search survive leaving the tab
// (sessionStorage); unsaved input in a record (the prepare form, revoke and
// release reasons) is held here per finding for the visit, so closing or
// stepping away from a record does not lose it.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Search, X } from "lucide-react";

import "../styles/proof-work.css";
import { listProofWork, type ProofReverification, type ProofWorkList, type ProofWorkQueueState } from "../lib/api";
import {
  PROOF_ATTENTION_RULE,
  compareProofCards,
  proofCardForFinding,
  proofNeedsAttention,
  proofNeedsAttentionCount,
} from "../lib/proofWorkApi";
import { createCoalescedRunner } from "../lib/coalesce";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { CardSkeleton, SlowLoadHint } from "./Skeletons";
import { ProofWorkCard, QueueStatePill, proofCardState, type ProofCardDrafts, type ProofWorkCardProps } from "./ProofWorkCard";
import {
  RecordBody,
  RecordCopyLinkButton,
  RecordHeader,
  RecordView,
  useResultsScrollMemory,
  type RecordNavigation,
} from "./record/RecordView";
import { useListNavigation } from "./record/recordNavigation";
import {
  ClearFiltersButton,
  EmptyState,
  FilterChip,
  FilterGroup,
  PageHeader,
  ResultsSummary,
  ScopeToggle,
  SeverityTag,
  describeSort,
  severityColor,
  statusLabel,
  statusOrder,
  type Scope,
} from "./ui";

type ProofWorkTabProps = {
  engagementKey: string;
  refreshVersion?: number;
  /**
   * `work=<id>` from the route (links from Runs): one prepared test. Its
   * finding's record opens with the test highlighted.
   */
  workId?: number;
  /** `proof=<slug>` from the route: the finding whose proof-work record is open. */
  initialProofSlug?: string;
  /**
   * Reports the "Needs attention" count of each queue read (the page's own
   * `proofNeedsAttentionCount`), for the rail badge while the view is open.
   */
  onQueueCounts?: (counts: { needs_attention: number }) => void;
};

/** A state chip: one queue state, or the findings that need re-verification. */
type StateFilter = ProofWorkQueueState | "reverify";

type ProofView = { scope: Scope; state: StateFilter | null; query: string };

/** One finding's proof work, as the queue holds it. */
type ProofCard = NonNullable<ReturnType<typeof proofCardForFinding>>;

/** What the address named that the queue does not hold. */
type RouteMiss = { finding: string } | { work: number };

const RECORD_TITLE_ID = "proof-record-title";
const NO_DRAFTS: ProofCardDrafts = {};

const EXPLAINER_KEY = "vigil.proofWork.explainerCollapsed";
const STATE_ORDER = statusOrder("proof-work") as ProofWorkQueueState[];
// Approvals and blockers first (the proof-work status order), then severity.
const SORT_TEXT = `${describeSort("Status", "desc", "status")}, then severity`;
const DEFAULT_VIEW: ProofView = { scope: "attention", state: null, query: "" };

function readExplainerCollapsed(): boolean {
  try {
    return window.localStorage.getItem(EXPLAINER_KEY) === "1";
  } catch {
    return false;
  }
}

function writeExplainerCollapsed(collapsed: boolean): void {
  try {
    window.localStorage.setItem(EXPLAINER_KEY, collapsed ? "1" : "0");
  } catch {
    // Storage can be unavailable (private mode); the explainer just reopens.
  }
}

const viewKey = (engagementKey: string) => `proof.queue.${engagementKey}`;

function readView(engagementKey: string): ProofView {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(viewKey(engagementKey)) || "{}") as Record<string, unknown>;
    const state = value.state === "reverify" || STATE_ORDER.includes(value.state as ProofWorkQueueState) ? value.state as StateFilter : null;
    return {
      scope: value.scope === "all" ? "all" : "attention",
      state,
      query: typeof value.query === "string" ? value.query : "",
    };
  } catch {
    return DEFAULT_VIEW;
  }
}

function matchesQuery(query: string, ...fields: (string | undefined)[]): boolean {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return true;
  const text = fields.filter(Boolean).join("\n").toLowerCase();
  return terms.every((term) => text.includes(term));
}

/** The first line of a parked reason, for a list row; the record shows all of it. */
function reasonPreview(reason: string): string {
  const lines = reason.split("\n").map((line) => line.trim()).filter(Boolean);
  return lines.length > 1 ? `${lines[0]} …` : lines[0] ?? "";
}

/** One finding in the results: opens its record. */
function ProofRow({ card, onOpen }: { card: ProofCard; onOpen: (slug: string, invoker: HTMLElement) => void }) {
  const preview = card.owed
    ? reasonPreview(card.owed.parked_reason ?? "") || "The parking decision recorded no reason."
    : `${card.items.length} prepared test${card.items.length === 1 ? "" : "s"} kept as history`;
  return (
    <li>
      <button type="button" className="proof-row" data-record-key={card.slug} onClick={(event) => onOpen(card.slug, event.currentTarget)}>
        <span className="proof-row-id">
          {card.severity && <SeverityTag severity={card.severity} size="sm" />}
          <span className="proof-slug">{card.slug}</span>
        </span>
        <span className="proof-row-main">
          <span className="proof-row-title">{card.title}</span>
          <span className="proof-row-reason" title={card.owed?.parked_reason || undefined}>{preview}</span>
        </span>
        <QueueStatePill state={proofCardState(card.owed, card.items)} />
      </button>
    </li>
  );
}

type ProofRecordProps = Pick<ProofWorkCardProps, "busy" | "writesDisabled" | "onAction" | "actionError" | "onDismissActionError" | "highlightWorkId" | "drafts" | "onDraftsChange"> & {
  engagementKey: string;
  slug: string;
  /** The finding's proof work; null until the queue has been read. */
  card: ProofCard | null;
  /** The queue is being (re)read; the record shown stays visible. */
  loading: boolean;
  /** The first queue read failed, so there is nothing to show yet. */
  loadError: string | null;
  onRetry: () => void;
  /** Why writes are off, when the last re-read of the queue failed. */
  queueNotice: ReactNode;
};

/** One finding's proof work inside the shared RecordView (ProofWorkTab owns the view, the list and the address). */
function ProofRecord({ engagementKey, slug, card, loading, loadError, onRetry, queueNotice, ...cardProps }: ProofRecordProps) {
  return (
    <>
      <RecordHeader
        id={slug}
        copyId={slug}
        copyIdLabel="Copy finding ID"
        title={card?.title ?? slug}
        titleId={RECORD_TITLE_ID}
        accent={card?.severity ? severityColor(card.severity) : undefined}
        actions={<RecordCopyLinkButton noun="finding" />}
        pills={card ? (
          <>
            {card.severity && <SeverityTag severity={card.severity} />}
            <QueueStatePill state={proofCardState(card.owed, card.items)} />
          </>
        ) : undefined}
        dates={card?.owed ? [{ label: "Parked", value: card.owed.parked_at }] : undefined}
        datesLabel="Proof work dates"
      >
        <p className="proof-record-links">
          <a href={engagementHref(engagementKey, { tab: "findings", finding: slug })}>Review finding</a>
        </p>
        {card && !card.owed && (
          <p className="proof-help">This finding is no longer parked. Its proof work is kept as history; runs and evidence stay linked.</p>
        )}
        {queueNotice}
      </RecordHeader>
      <RecordBody busy={loading}>
        {card ? (
          <ProofWorkCard
            engagementKey={engagementKey}
            severity={card.severity}
            owed={card.owed}
            items={card.items}
            {...cardProps}
          />
        ) : loadError ? (
          <div className="proof-load-error" role="alert">
            <p className="error-text">{loadError}</p>
            <button type="button" className="ui-button" onClick={onRetry}>Try again</button>
          </div>
        ) : (
          <div className="proof-skeletons">
            <CardSkeleton lines={4} />
            <SlowLoadHint active what="the proof queue" />
          </div>
        )}
      </RecordBody>
    </>
  );
}

export function ProofWorkTab(props: ProofWorkTabProps) {
  return <ProofWorkWorkspace key={props.engagementKey} {...props} />;
}

function ProofWorkWorkspace({ engagementKey, refreshVersion = 0, workId, initialProofSlug, onQueueCounts }: ProofWorkTabProps) {
  const [data, setData] = useState<ProofWorkList | null>(null);
  // A failed read leaves the queue state unknown, so writes stay off until a
  // read succeeds; a failed write is reported on its own and, once the
  // follow-up read lands, never blocks the next action.
  const [error, setError] = useState<string | null>(null);
  // The finding whose write failed, and why (shown in that finding's record).
  const [writeError, setWriteError] = useState<{ slug: string; message: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<ProofView>(() => readView(engagementKey));
  // Set when the view fell back to All because nothing needed attention on
  // arrival: that fallback is not saved, so the next visit opens on Needs
  // attention again. Any scope choice by the operator clears it.
  const scopeFellBack = useRef(false);
  const [explainerCollapsed, setExplainerCollapsed] = useState(readExplainerCollapsed);
  // The finding whose record is open; null while the list shows.
  const [openSlug, setOpenSlug] = useState<string | null>(initialProofSlug ?? null);
  const openRef = useRef<string | null>(openSlug);
  openRef.current = openSlug;
  // The prepared test a `work=` link named: highlighted in its finding's record.
  const [linkedWorkId, setLinkedWorkId] = useState(workId);
  const [routeMiss, setRouteMiss] = useState<RouteMiss | null>(null);
  // Unsaved input per finding. It outlives the record body, which remounts
  // per finding, so Escape, stepping and browser Back keep what was typed.
  const [drafts, setDrafts] = useState<Record<string, ProofCardDrafts>>({});
  const [historyOpen, setHistoryOpen] = useState(false);
  // The `proof=` and `work=` values the tab last followed (or wrote).
  const appliedRoute = useRef({ proof: initialProofSlug, work: workId });
  // The row a record was opened from: focus returns there when it closes.
  const invokerRef = useRef<HTMLElement | null>(null);
  const resultsRef = useRef<HTMLDivElement | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    try {
      const stored = scopeFellBack.current && view.scope === "all" ? { ...view, scope: "attention" } : view;
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(stored));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, view]);

  const load = useMemo(() => createCoalescedRunner(async () => {
    setLoading(true);
    try {
      const result = await listProofWork(engagementKey);
      if (!mounted.current) return;
      setData(result);
      setError(null);
    } catch (failure) {
      if (mounted.current) setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }), [engagementKey]);

  useEffect(() => {
    void load("join");
  }, [load]);

  useEffect(() => {
    if (data) onQueueCounts?.({ needs_attention: proofNeedsAttentionCount(data) });
  }, [data, onQueueCounts]);

  const seenVersion = useRef(refreshVersion);
  useEffect(() => {
    if (seenVersion.current === refreshVersion) return;
    seenVersion.current = refreshVersion;
    void load("refresh");
  }, [load, refreshVersion]);

  const act = useCallback(async (slug: string, operation: () => Promise<unknown>): Promise<boolean> => {
    setBusy(true);
    setWriteError(null);
    try {
      await operation();
      if (!mounted.current) return false;
      await load("refresh");
      return true;
    } catch (failure) {
      if (!mounted.current) return false;
      // Never retry a write with an uncertain outcome. Refresh is a read.
      await load("refresh");
      if (mounted.current) setWriteError({ slug, message: failure instanceof Error ? failure.message : String(failure) });
      return false;
    } finally {
      if (mounted.current) setBusy(false);
    }
  }, [load]);

  const writeHash = useCallback((slug: string | null, work?: number, mode: "push" | "replace" = "push") => {
    appliedRoute.current = { proof: slug ?? undefined, work: slug ? work : undefined };
    writeWorkspaceHash(engagementHref(engagementKey, { tab: "proof", proof: appliedRoute.current.proof, work: appliedRoute.current.work }), mode);
  }, [engagementKey]);

  // Opening from the list remembers the row; stepping from an open record
  // keeps the row the first one was opened from. A record opened this way
  // carries no linked test.
  const openRecord = useCallback((slug: string, invoker?: HTMLElement | null) => {
    if (openRef.current === null) invokerRef.current = invoker ?? null;
    setRouteMiss(null);
    setOpenSlug(slug);
    setLinkedWorkId(undefined);
    writeHash(slug);
  }, [writeHash]);

  const closeRecord = useCallback(() => {
    setOpenSlug(null);
    setLinkedWorkId(undefined);
    writeHash(null);
  }, [writeHash]);

  // The URL changing under the tab (Back / Forward, a link) opens its record
  // and linked test; neither `proof=` nor `work=` shows the list.
  useEffect(() => {
    const applied = appliedRoute.current;
    if (applied.proof === initialProofSlug && applied.work === workId) return;
    const stepping = openRef.current !== null && initialProofSlug !== undefined;
    appliedRoute.current = { proof: initialProofSlug, work: workId };
    setRouteMiss(null);
    if (!stepping) invokerRef.current = null;
    openRef.current = initialProofSlug ?? null;
    setOpenSlug(initialProofSlug ?? null);
    setLinkedWorkId(workId);
  }, [initialProofSlug, workId]);

  const cards = useMemo(() => {
    if (!data) return [];
    const slugs = [
      ...data.owed.map((entry) => entry.finding_slug),
      ...data.items.map((work) => work.finding_slug),
    ];
    return [...new Set(slugs)]
      .map((slug) => proofCardForFinding(data, slug))
      .filter((card): card is NonNullable<typeof card> => card !== null);
  }, [data]);
  const parked = useMemo(
    () => cards
      .filter((card) => card.owed)
      .sort((a, b) => compareProofCards(STATE_ORDER, { ...a, state: a.owed?.queue_state }, { ...b, state: b.owed?.queue_state })),
    [cards],
  );
  const history = cards.filter((card) => !card.owed);
  const reverification = data?.reverification_required ?? [];

  const { scope, state: stateFilter, query } = view;
  const cardMatchesQuery = (card: (typeof cards)[number]) => matchesQuery(query, card.slug, card.title, card.owed?.parked_reason, ...card.items.map((work) => work.objective));
  const reverifyMatchesQuery = (item: ProofReverification) => matchesQuery(query, item.finding_slug, item.title, item.next_action);
  const searchedParked = parked.filter(cardMatchesQuery);
  const searchedReverify = reverification.filter(reverifyMatchesQuery);
  // Chip counts honour scope and search but not the chip itself.
  const scopedParked = searchedParked.filter((card) => scope === "all" || proofNeedsAttention(card.owed?.queue_state));
  const stateCounts = new Map<StateFilter, number>();
  for (const card of scopedParked) {
    const key = card.owed?.queue_state;
    if (key) stateCounts.set(key, (stateCounts.get(key) ?? 0) + 1);
  }
  stateCounts.set("reverify", searchedReverify.length);
  const scopeCounts = {
    attention: searchedParked.filter((card) => proofNeedsAttention(card.owed?.queue_state)).length + searchedReverify.length,
    // "All" also lists the findings no longer parked, so it counts them.
    all: searchedParked.length + searchedReverify.length + history.filter(cardMatchesQuery).length,
  };
  // The states there are to filter by; with none, the group is not shown as a bare label.
  const stateChips = STATE_ORDER.filter((state) => (stateCounts.get(state) ?? 0) > 0 || stateFilter === state);
  const showReverifyChip = reverification.length > 0 || stateFilter === "reverify";
  const attentionTotal = data ? proofNeedsAttentionCount(data) : 0;

  const visibleParked = stateFilter === "reverify" ? [] : scopedParked.filter((card) => !stateFilter || card.owed?.queue_state === stateFilter);
  const visibleReverify = stateFilter === null || stateFilter === "reverify" ? searchedReverify : [];
  const visibleHistory = scope === "all" && stateFilter === null ? history.filter(cardMatchesQuery) : [];
  const nothingRecorded = data !== null && parked.length === 0 && reverification.length === 0 && history.length === 0;
  const filteredEmpty = data !== null && !nothingRecorded && visibleParked.length === 0 && visibleReverify.length === 0 && visibleHistory.length === 0;
  const activeFilters = (stateFilter ? 1 : 0) + (query.trim() ? 1 : 0);

  // A work queue opens on Needs attention, or on All when nothing needs
  // attention on arrival (decided once, on the first loaded queue).
  const scopeDecided = useRef(false);
  useEffect(() => {
    if (!data || scopeDecided.current) return;
    scopeDecided.current = true;
    if (view.scope === "attention" && view.state === null && attentionTotal === 0 && !nothingRecorded) {
      scopeFellBack.current = true;
      setView((current) => ({ ...current, scope: "all" }));
    }
  }, [attentionTotal, data, nothingRecorded, view.scope, view.state]);

  const setScope = (next: Scope) => {
    scopeFellBack.current = false;
    setScopeView(next);
  };
  const setScopeView = (next: Scope) => setView((current) => ({
    ...current,
    scope: next,
    // Narrowing the scope drops a chip it excludes.
    state: next === "attention" && current.state && current.state !== "reverify" && !proofNeedsAttention(current.state) ? null : current.state,
  }));
  const toggleState = (next: StateFilter) => setView((current) => {
    const selected = current.state === next ? null : next;
    // A chip outside the scope widens it, so the list never silently shows nothing.
    const widen = selected && selected !== "reverify" && !proofNeedsAttention(selected);
    if (widen) scopeFellBack.current = false;
    return { ...current, state: selected, scope: widen ? "all" : current.scope };
  });
  const clearFilters = () => setView((current) => ({ ...current, state: null, query: "" }));

  // Previous / Next walk the results as shown: parked findings, then the
  // findings no longer parked.
  const order = [...visibleParked, ...visibleHistory].map((card) => card.slug);

  // A linked work item (from Runs) lands once per link: the view widens if
  // the saved scope, chip or search would hide its finding, and that
  // finding's record opens. The address then names the record as well
  // (replacing the bare link), so a reload or Back to it reopens the record
  // with the test highlighted.
  const landedWorkId = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (linkedWorkId === undefined) {
      landedWorkId.current = undefined;
      return;
    }
    if (!data || landedWorkId.current === linkedWorkId) return;
    landedWorkId.current = linkedWorkId;
    const linked = cards.find((card) => card.items.some((work) => work.id === linkedWorkId));
    if (!linked) {
      if (openRef.current === null) setRouteMiss({ work: linkedWorkId });
      return;
    }
    if (!order.includes(linked.slug)) setView({ scope: "all", state: null, query: "" });
    if (openRef.current !== null) return;
    openRef.current = linked.slug;
    setOpenSlug(linked.slug);
    writeHash(linked.slug, linkedWorkId, "replace");
  });

  // A finding the queue does not hold cannot stay open: the list shows and
  // says why.
  useEffect(() => {
    if (!data || openSlug === null || cards.some((card) => card.slug === openSlug)) return;
    setRouteMiss({ finding: openSlug });
    setOpenSlug(null);
    setLinkedWorkId(undefined);
    invokerRef.current = null;
    writeHash(null, undefined, "replace");
  }, [cards, data, openSlug, writeHash]);

  // Scroll to a linked item once per link, not on every refresh.
  const scrolledWorkId = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (linkedWorkId === undefined) {
      scrolledWorkId.current = undefined;
      return;
    }
    if (!data || scrolledWorkId.current === linkedWorkId) return;
    const target = document.getElementById(`proof-work-${linkedWorkId}`);
    if (!target) return;
    scrolledWorkId.current = linkedWorkId;
    target.scrollIntoView?.({ block: "center", behavior: "smooth" });
  });

  const investigating = openSlug !== null;
  const listed = useListNavigation(order, openSlug, openRecord);
  // Until the queue has been read, the open record's place in it is not known.
  const navigation: RecordNavigation = data
    ? listed
    : { index: undefined, total: undefined, error: error ?? undefined };
  const historySlugs = history.map((card) => card.slug);
  useResultsScrollMemory(resultsRef, investigating, {
    recordKey: openSlug,
    // A finding no longer parked sits behind a disclosure: open it for the return.
    reveal: (slug) => { if (historySlugs.includes(slug)) setHistoryOpen(true); },
  });
  const openCard = openSlug === null ? null : cards.find((card) => card.slug === openSlug) ?? null;

  const toggleExplainer = () => {
    setExplainerCollapsed((collapsed) => {
      writeExplainerCollapsed(!collapsed);
      return !collapsed;
    });
  };

  const queueNotice = error && data ? (
    <div className="proof-banner" role="alert">
      <p>{error} · Showing the last loaded queue; actions stay off until it reloads.</p>
      <button type="button" className="ui-button" onClick={() => void load("refresh")} disabled={loading}>Reload queue</button>
    </div>
  ) : null;

  return (
    <div className="findings-redesign proof-page">
      <PageHeader
        title="Proof work"
        purpose="Findings that need one concrete test before a verifier can confirm or drop them."
        stats={data ? [
          { value: parked.length, label: "parked" },
          { value: attentionTotal, label: "need attention", tone: attentionTotal > 0 ? "warning" : undefined, title: PROOF_ATTENTION_RULE },
          { value: reverification.length || null, label: "to re-verify" },
        ] : []}
        status={loading && data ? "Updating…" : null}
        hidden={investigating}
      >
        {data && !nothingRecorded && (
          <ScopeToggle
            scope={scope}
            onChange={setScope}
            attentionCount={scopeCounts.attention}
            allCount={scopeCounts.all}
            attentionRule={PROOF_ATTENTION_RULE}
          />
        )}
      </PageHeader>

      {/* The results (an open record replaces them; they stay mounted behind) */}
      <div ref={resultsRef} className="proof-results" hidden={investigating}>
      <section className={`panel proof-explainer ${explainerCollapsed ? "is-collapsed" : ""}`}>
        <button type="button" className="proof-explainer-toggle" aria-expanded={!explainerCollapsed} onClick={toggleExplainer}>
          <strong>How proof work works</strong>
          <span aria-hidden="true">{explainerCollapsed ? "+" : "−"}</span>
        </button>
        {!explainerCollapsed && (
          <p>
            Some findings look real but still need one concrete test to prove it. Vigil parks them here instead of
            reporting or discarding them. Each item is one bounded test — a local reproduction or a live request to
            approved hosts. Finishing a test does not confirm the finding; an independent verifier still decides.
          </p>
        )}
      </section>

      {queueNotice}

      {routeMiss && (
        <p className="proof-warning" role="status">
          <strong>{"finding" in routeMiss ? `${routeMiss.finding} has no proof work.` : `Proof #${routeMiss.work} is not in the proof queue.`}</strong>{" "}
          The proof queue is shown.
        </p>
      )}

      {!data && !error && (
        <div className="proof-skeletons" aria-busy="true">
          <CardSkeleton lines={4} />
          <CardSkeleton lines={4} />
          <SlowLoadHint active what="the proof queue" />
        </div>
      )}

      {!data && error && (
        <div className="panel proof-load-error" role="alert">
          <p className="error-text">{error}</p>
          <button type="button" className="ui-button" onClick={() => void load("refresh")}>Try again</button>
        </div>
      )}

      {nothingRecorded && (
        <EmptyState variant="empty" title="No findings await runtime proof.">
          Verifiers park a finding here when it looks real but needs one concrete test before a verdict.
        </EmptyState>
      )}

      {data && !nothingRecorded && (
        <>
          <div className="panel findings-toolbar-panel proof-toolbar">
            <div className="filter-row proof-filter-row">
              <div className="search-wrap proof-search">
                <Search className="search-icon" aria-hidden="true" />
                <input
                  className="search-input"
                  type="search"
                  aria-label="Search proof work"
                  placeholder="Search slug, title, reason, objective…"
                  value={query}
                  onChange={(event) => setView((current) => ({ ...current, query: event.target.value }))}
                />
                {query && (
                  <button type="button" className="icon-btn" onClick={() => setView((current) => ({ ...current, query: "" }))} aria-label="Clear proof work search">
                    <X size={14} />
                  </button>
                )}
              </div>
              {(stateChips.length > 0 || showReverifyChip) && <FilterGroup label="State">
                {stateChips.map((state) => (
                  <FilterChip
                    key={state}
                    label={statusLabel("proof-work", state)}
                    status={{ domain: "proof-work", value: state }}
                    count={stateCounts.get(state) ?? 0}
                    selected={stateFilter === state}
                    onToggle={() => toggleState(state)}
                  />
                ))}
                {showReverifyChip && (
                  <FilterChip
                    label="Needs re-verification"
                    status={{ domain: "proof-work", value: "stale" }}
                    description="Findings that changed after runtime evidence was recorded; a verifier must decide them again."
                    count={stateCounts.get("reverify") ?? 0}
                    selected={stateFilter === "reverify"}
                    onToggle={() => toggleState("reverify")}
                  />
                )}
              </FilterGroup>}
              <ClearFiltersButton count={activeFilters} onClear={clearFilters} />
            </div>
          </div>

          {filteredEmpty && (
            <EmptyState
              variant="filtered"
              title={activeFilters > 0 ? "No proof work matches these filters." : "Nothing in the proof queue needs your attention."}
              onClearFilters={activeFilters > 0 ? clearFilters : () => setScope("all")}
              clearLabel={activeFilters > 0 ? "Clear filters" : "Show all proof work"}
              action={activeFilters > 0 && scope === "attention" ? (
                <button type="button" className="ui-button" onClick={() => setScope("all")}>Show all proof work</button>
              ) : undefined}
            >
              {scope === "attention" && activeFilters === 0 ? "Everything parked is waiting on a verifier, not on you." : undefined}
            </EmptyState>
          )}

          {visibleReverify.length > 0 && (
            <section id="proof-reverification" className="panel proof-section" aria-labelledby="proof-reverification-title">
              <h2 id="proof-reverification-title">Needs re-verification</h2>
              <p className="proof-help">
                These findings changed after runtime evidence was recorded, so their verdict was reset. A verifier must
                decide them again before any new proof work is prepared.
              </p>
              <ul className="proof-reverify-list">
                {visibleReverify.map((item) => (
                  <li key={item.finding_id}>
                    {item.severity && <SeverityTag severity={item.severity} size="sm" />}
                    <a href={engagementHref(engagementKey, { tab: "findings", finding: item.finding_slug })}>
                      {item.title || item.finding_slug}
                    </a>
                    <span className="proof-slug">{item.finding_slug}</span>
                    <span className="proof-muted">{item.next_action}</span>
                    {item.work_ids.length > 0 && <span className="proof-muted">Earlier proof: {item.work_ids.map((id) => `#${id}`).join(", ")}</span>}
                  </li>
                ))}
              </ul>
            </section>
          )}

          {visibleParked.length > 0 && (
            <section className="panel proof-section" aria-labelledby="proof-parked-title">
              <div className="proof-section-head">
                <h2 id="proof-parked-title" className="proof-section-title">Parked findings</h2>
                <ResultsSummary shown={visibleParked.length} total={parked.length} noun="parked findings" sort={SORT_TEXT} />
              </div>
              <ul className="proof-rows">
                {visibleParked.map((card) => <ProofRow key={card.slug} card={card} onOpen={openRecord} />)}
              </ul>
            </section>
          )}

          {visibleHistory.length > 0 && (
            <details className="panel proof-section proof-history-section" open={historyOpen} onToggle={(event) => setHistoryOpen(event.currentTarget.open)}>
              <summary>
                <h2 className="proof-section-title">Findings no longer parked <span className="filter-count">{visibleHistory.length}</span></h2>
              </summary>
              <p className="proof-help">Their proof work is kept as history; runs and evidence stay linked.</p>
              <ul className="proof-rows">
                {visibleHistory.map((card) => <ProofRow key={card.slug} card={card} onOpen={openRecord} />)}
              </ul>
            </details>
          )}

          {!filteredEmpty && <div className="findings-shortcuts">
            <span><code>Enter</code> open</span>
            <span><code>[ / ]</code> previous / next in a record</span>
            <span><code>Esc</code> back to results</span>
          </div>}
        </>
      )}
      </div>

      {openSlug !== null && (
        <RecordView
          label="Proof work"
          noun="finding"
          navigation={navigation}
          onBack={closeRecord}
          titleId={RECORD_TITLE_ID}
          returnFocusRef={invokerRef}
        >
          <ProofRecord
            key={openSlug}
            engagementKey={engagementKey}
            slug={openSlug}
            card={openCard}
            loading={loading}
            loadError={data ? null : error}
            onRetry={() => void load("refresh")}
            queueNotice={queueNotice}
            busy={busy}
            writesDisabled={Boolean(error)}
            onAction={(operation) => act(openSlug, operation)}
            actionError={writeError?.slug === openSlug ? writeError.message : null}
            onDismissActionError={() => setWriteError(null)}
            highlightWorkId={linkedWorkId}
            drafts={drafts[openSlug] ?? NO_DRAFTS}
            onDraftsChange={(update) => setDrafts((all) => ({ ...all, [openSlug]: update(all[openSlug] ?? NO_DRAFTS) }))}
          />
        </RecordView>
      )}
    </div>
  );
}
