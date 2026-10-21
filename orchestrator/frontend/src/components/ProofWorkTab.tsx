// ── ProofWorkTab ──────────────────────────────────────────────────────
// The proof queue: parked findings that each need one concrete test, one
// card per finding, plus findings that need re-verification. It opens on the
// shared "Needs attention" scope (the rail badge's rule), sorted by what each
// card asks first, with state chips and search. Reads coalesce like every
// workspace tab and live refresh keeps it current; writes are the existing
// proof-work endpoints and are never retried with an uncertain outcome.
// Scope, state chip and search survive leaving the tab (sessionStorage).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { engagementHref } from "../lib/workspaceRoutes";
import { CardSkeleton, SlowLoadHint } from "./Skeletons";
import { ProofWorkCard } from "./ProofWorkCard";
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
  statusLabel,
  statusOrder,
  type Scope,
} from "./ui";

type ProofWorkTabProps = {
  engagementKey: string;
  refreshVersion?: number;
  /** `work=<id>` from the route: highlights one prepared test (links from Runs). */
  workId?: number;
  /**
   * Reports the "Needs attention" count of each queue read (the page's own
   * `proofNeedsAttentionCount`), for the rail badge while the view is open.
   */
  onQueueCounts?: (counts: { needs_attention: number }) => void;
};

/** A state chip: one queue state, or the findings that need re-verification. */
type StateFilter = ProofWorkQueueState | "reverify";

type ProofView = { scope: Scope; state: StateFilter | null; query: string };

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

export function ProofWorkTab(props: ProofWorkTabProps) {
  return <ProofWorkWorkspace key={props.engagementKey} {...props} />;
}

function ProofWorkWorkspace({ engagementKey, refreshVersion = 0, workId: highlightWorkId, onQueueCounts }: ProofWorkTabProps) {
  const [data, setData] = useState<ProofWorkList | null>(null);
  // A failed read leaves the queue state unknown, so writes stay off until a
  // read succeeds; a failed write is reported on its own and, once the
  // follow-up read lands, never blocks the next action.
  const [error, setError] = useState<string | null>(null);
  // The card whose write failed, and why (shown on that card).
  const [writeError, setWriteError] = useState<{ slug: string; message: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<ProofView>(() => readView(engagementKey));
  // Set when the view fell back to All because nothing needed attention on
  // arrival: that fallback is not saved, so the next visit opens on Needs
  // attention again. Any scope choice by the operator clears it.
  const scopeFellBack = useRef(false);
  const [explainerCollapsed, setExplainerCollapsed] = useState(readExplainerCollapsed);
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
    all: searchedParked.length + searchedReverify.length,
  };
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

  // A linked work item (from Runs) is always shown: widen the view once if
  // the saved scope, chip or search would hide it.
  const revealedWorkId = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (highlightWorkId === undefined || !data || revealedWorkId.current === highlightWorkId) return;
    revealedWorkId.current = highlightWorkId;
    const linked = cards.find((card) => card.items.some((work) => work.id === highlightWorkId));
    if (!linked) return;
    const shown = linked.owed
      ? visibleParked.includes(linked)
      : visibleHistory.includes(linked);
    if (!shown) setView({ scope: "all", state: null, query: "" });
  }, [cards, data, highlightWorkId, visibleHistory, visibleParked]);

  // Scroll to a linked item once per link, not on every refresh.
  const scrolledWorkId = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (highlightWorkId === undefined) {
      scrolledWorkId.current = undefined;
      return;
    }
    if (!data || scrolledWorkId.current === highlightWorkId) return;
    const target = document.getElementById(`proof-work-${highlightWorkId}`);
    if (!target) return;
    scrolledWorkId.current = highlightWorkId;
    target.scrollIntoView?.({ block: "center", behavior: "smooth" });
  });

  const toggleExplainer = () => {
    setExplainerCollapsed((collapsed) => {
      writeExplainerCollapsed(!collapsed);
      return !collapsed;
    });
  };

  const renderCard = (card: (typeof cards)[number]) => (
    <ProofWorkCard
      key={card.slug}
      engagementKey={engagementKey}
      slug={card.slug}
      title={card.title}
      severity={card.severity}
      owed={card.owed}
      items={card.items}
      busy={busy}
      writesDisabled={Boolean(error)}
      onAction={(operation) => act(card.slug, operation)}
      actionError={writeError?.slug === card.slug ? writeError.message : null}
      onDismissActionError={() => setWriteError(null)}
      highlightWorkId={highlightWorkId}
    />
  );

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

      {error && data && (
        <div className="proof-banner" role="alert">
          <p>{error} · Showing the last loaded queue; actions stay off until it reloads.</p>
          <button type="button" className="ui-button" onClick={() => void load("refresh")} disabled={loading}>Reload queue</button>
        </div>
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
              <FilterGroup label="State">
                {STATE_ORDER.filter((state) => (stateCounts.get(state) ?? 0) > 0 || stateFilter === state).map((state) => (
                  <FilterChip
                    key={state}
                    label={statusLabel("proof-work", state)}
                    status={{ domain: "proof-work", value: state }}
                    count={stateCounts.get(state) ?? 0}
                    selected={stateFilter === state}
                    onToggle={() => toggleState(state)}
                  />
                ))}
                {(reverification.length > 0 || stateFilter === "reverify") && (
                  <FilterChip
                    label="Needs re-verification"
                    status={{ domain: "proof-work", value: "stale" }}
                    description="Findings that changed after runtime evidence was recorded; a verifier must decide them again."
                    count={stateCounts.get("reverify") ?? 0}
                    selected={stateFilter === "reverify"}
                    onToggle={() => toggleState("reverify")}
                  />
                )}
              </FilterGroup>
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
            <section className="proof-section" aria-labelledby="proof-parked-title">
              <div className="proof-section-head">
                <h2 id="proof-parked-title" className="proof-section-title">Parked findings</h2>
                <ResultsSummary shown={visibleParked.length} total={parked.length} noun="parked findings" sort={SORT_TEXT} />
              </div>
              <div className="proof-cards">{visibleParked.map(renderCard)}</div>
            </section>
          )}

          {visibleHistory.length > 0 && (
            <details className="proof-section proof-history-section" open={visibleHistory.some((card) => card.items.some((work) => work.id === highlightWorkId))}>
              <summary>
                <h2 className="proof-section-title">Findings no longer parked <span className="filter-count">{visibleHistory.length}</span></h2>
              </summary>
              <p className="proof-help">Their proof work is kept as history; runs and evidence stay linked.</p>
              <div className="proof-cards">{visibleHistory.map(renderCard)}</div>
            </details>
          )}
        </>
      )}
    </div>
  );
}
