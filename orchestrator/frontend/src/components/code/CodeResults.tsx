// The Results section: every current analysis result (one per file review),
// paged on the server with faceted filters and search. Scope, filters, search,
// page and the open result all live in the URL (useCodeRoute). Opening a
// result replaces the list with the shared record view; Previous / Next walk
// the server's order across pages, and Back returns to the page holding the
// record last shown.

import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";

import {
  getCodeAnalysisResultPosition,
  listCodeAnalysisResultPage,
  type CodeAnalysisResultPage,
  type CodeAnalysisResultQuery,
} from "../../lib/codeApi";
import type { CodeAnalysisResult } from "../../lib/api";
import { engagementHref } from "../../lib/workspaceRoutes";
import { useCoalescedRequest } from "../../lib/useCoalescedRequest";
import { TimeStamp } from "../formatting";
import { RecordView, useResultsScrollMemory } from "../record/RecordView";
import { useRecordPosition } from "../record/recordNavigation";
import { CardSkeleton, Skeleton, SlowLoadHint } from "../Skeletons";
import {
  ClearFiltersButton,
  EmptyState,
  FilterChip,
  FilterGroup,
  ResultsSummary,
  ScopeToggle,
  StatusPill,
  compareStatus,
  describeSort,
  humanizeStatus,
  statusLabel,
  type Scope,
} from "../ui";
import { CodeResultRecord, isCodeResultSection, type CodeResultSection } from "./CodeResultRecord";
import type { CodeRoute, CodeRouteTarget } from "./useCodeRoute";

type Props = { engagementKey: string; refreshVersion: number; route: CodeRoute };

export const RESULT_PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 300;
const CONFIDENCE_ORDER = ["high", "medium", "low"];
const SCOPES = ["disposition", "confidence", "status", "workflow", "cwe", "agent", "slot", "file", "function"] as const;
type SearchScope = (typeof SCOPES)[number];

/** The order the server lists results in (`ANALYSIS_RESULT_DISPOSITION_ORDER`, then newest). */
const RESULT_ORDER = `${describeSort("Result", "desc", "status")}, newest first within each`;

export const NEEDS_ATTENTION_RULE =
  "Suspicious results whose file still awaits a verdict: the file's latest review is suspicious, and no finding or later clean review has settled it.";

/** Split the search box into server filters: `scope:value` tokens and free terms. */
export function parseResultSearch(text: string): CodeAnalysisResultQuery {
  const query: CodeAnalysisResultQuery = {};
  const terms: string[] = [];
  for (const token of text.split(/\s+/).filter(Boolean)) {
    const index = token.indexOf(":");
    const scope = index > 0 ? (token.slice(0, index).toLowerCase() as SearchScope) : null;
    const value = index > 0 ? token.slice(index + 1) : "";
    if (!scope || !SCOPES.includes(scope) || !value) {
      terms.push(token);
      continue;
    }
    if (scope === "disposition") query.disposition = [...(query.disposition ?? []), value.toLowerCase()];
    else if (scope === "confidence") query.confidence = [...(query.confidence ?? []), value.toLowerCase()];
    else if (scope === "status" || scope === "workflow") query.workflow_status = [...(query.workflow_status ?? []), value.toLowerCase()];
    else query[scope as "cwe" | "agent" | "slot" | "file" | "function"] = value;
  }
  if (terms.length) query.q = terms;
  return query;
}

const unique = (values: string[]) => [...new Set(values)];

/** Facet values in display order; selected values stay listed (at zero) so the row never reshuffles. */
function facetValues(counts: Record<string, number> | undefined, selected: string[], order: (a: string, b: string) => number) {
  const values = unique([...Object.keys(counts ?? {}), ...selected]);
  return values.sort(order);
}

const byOrder = (order: string[]) => (a: string, b: string) => {
  const rank = (value: string) => (order.includes(value) ? order.indexOf(value) : order.length);
  return rank(a) - rank(b) || a.localeCompare(b);
};

export function CodeResults({ engagementKey, refreshVersion, route }: Props) {
  const { scope, disposition, confidence, workflow, q, page: pageNumber } = route;
  const recordId = route.view === "results" ? route.result ?? null : null;
  const recordOpen = recordId !== null;
  const section: CodeResultSection = isCodeResultSection(route.dtab) ? route.dtab : "review";

  // The current list state; navigation keeps whatever a call does not change.
  const state: CodeRouteTarget = useMemo(
    () => ({ view: "results", scope, disposition, confidence, workflow, q, page: pageNumber }),
    [scope, disposition, confidence, workflow, q, pageNumber],
  );
  const stateRef = useRef(state);
  stateRef.current = state;
  const go = useCallback(
    (patch: Partial<CodeRouteTarget>, mode: "push" | "replace" = "push") => route.navigate({ ...stateRef.current, ...patch }, mode),
    [route.navigate],
  );

  // The search box types freely; the URL (and the server) see it after a pause.
  const [text, setText] = useState(q);
  const textRef = useRef(text);
  textRef.current = text;
  useEffect(() => {
    if (textRef.current.trim() !== q) setText(q);
  }, [q]);
  useEffect(() => {
    if (text.trim() === q) return undefined;
    const timer = window.setTimeout(() => go({ q: text.trim(), page: 1 }, "replace"), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [text, q, go]);

  const query = useMemo<Omit<CodeAnalysisResultQuery, "limit" | "offset">>(() => {
    const parsed = parseResultSearch(q);
    return {
      ...parsed,
      ...(scope === "attention" ? { scope: "awaiting_verdict" as const } : {}),
      disposition: unique([...(parsed.disposition ?? []), ...disposition]),
      confidence: unique([...(parsed.confidence ?? []), ...confidence]),
      workflow_status: unique([...(parsed.workflow_status ?? []), ...workflow]),
    };
  }, [q, scope, disposition, confidence, workflow]);
  const queryKey = JSON.stringify(query);
  const offset = (pageNumber - 1) * RESULT_PAGE_SIZE;
  const filterCount = disposition.length + confidence.length + workflow.length + (q ? 1 : 0);
  const narrowed = filterCount > 0 || scope === "attention";

  const [retry, setRetry] = useState(0);
  const results = useCoalescedRequest<CodeAnalysisResultPage>(
    `${engagementKey}\u0000${queryKey}\u0000${offset}`,
    useCallback(
      () => listCodeAnalysisResultPage(engagementKey, { ...query, limit: RESULT_PAGE_SIZE, offset }),
      // `queryKey` is the identity of `query`, so `query` itself is not a dependency.
      [engagementKey, queryKey, offset],
    ),
    refreshVersion + retry,
  );
  // "All N" counts every current result whatever the filters; the page holds it when nothing narrows it.
  const everything = useCoalescedRequest<CodeAnalysisResultPage>(
    `${engagementKey}\u0000all`,
    useCallback(() => listCodeAnalysisResultPage(engagementKey, { limit: 1 }), [engagementKey]),
    refreshVersion,
    narrowed,
  );
  const page = results.data;
  const allCount = narrowed ? everything.data?.total ?? null : page?.total ?? null;
  const awaitingCount = page?.awaiting_verdict.results ?? everything.data?.awaiting_verdict.results ?? null;

  // A page past the end (filters changed under a bookmarked page) moves to the last page.
  useEffect(() => {
    if (!page || recordOpen || page.items.length > 0 || page.total === 0 || results.dataKey !== `${engagementKey}\u0000${queryKey}\u0000${offset}`) return;
    go({ page: Math.max(1, Math.ceil(page.total / RESULT_PAGE_SIZE)) }, "replace");
  }, [page, recordOpen, results.dataKey, engagementKey, queryKey, offset, go]);

  // Rows the record can show at once: the page, and neighbours the position read returned.
  const knownRows = useRef(new Map<number, CodeAnalysisResult>());
  for (const item of page?.items ?? []) knownRows.current.set(item.id, item);

  const open = useCallback((row: CodeAnalysisResult) => {
    knownRows.current.set(row.id, row);
    go({ result: row.id });
  }, [go]);
  const step = useCallback((row: CodeAnalysisResult) => {
    knownRows.current.set(row.id, row);
    go({ result: row.id, dtab: section === "review" ? undefined : section });
  }, [go, section]);
  const close = useCallback(() => go({}), [go]);
  const chooseSection = useCallback(
    (next: CodeResultSection) => go({ result: recordId ?? undefined, dtab: next === "review" ? undefined : next }),
    [go, recordId],
  );

  const navigation = useRecordPosition<CodeAnalysisResult>({
    key: recordId === null ? null : String(recordId),
    identity: JSON.stringify([engagementKey, queryKey, refreshVersion]),
    load: () => getCodeAnalysisResultPosition(engagementKey, recordId as number, query),
    keyOf: (row) => String(row.id),
    open: step,
  });
  // The hidden list follows the record, so Back lands on the page that holds it.
  useEffect(() => {
    if (recordId === null || typeof navigation.index !== "number" || navigation.pending) return;
    const holding = Math.floor(navigation.index / RESULT_PAGE_SIZE) + 1;
    if (holding !== pageNumber) go({ page: holding, result: recordId, dtab: section === "review" ? undefined : section }, "replace");
  }, [recordId, navigation.index, navigation.pending, pageNumber, section, go]);

  const resultsRef = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(resultsRef, recordOpen, { recordKey: recordId });

  // Paging brings the top of the list into view (not the bottom of the old page).
  const listTop = useRef<HTMLDivElement | null>(null);
  const goToPage = (next: number) => {
    go({ page: next });
    listTop.current?.scrollIntoView?.({ block: "start" });
  };

  const searchRef = useRef<HTMLInputElement | null>(null);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing = ["input", "textarea", "select"].includes((target?.tagName ?? "").toLowerCase()) || target?.isContentEditable;
      if (!typing && !recordOpen && event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [recordOpen]);

  const toggle = (key: "disposition" | "confidence" | "workflow", value: string) => {
    const current = state[key] ?? [];
    go({ [key]: current.includes(value) ? current.filter((entry) => entry !== value) : [...current, value], page: 1 });
  };
  const clearFilters = () => {
    setText("");
    go({ disposition: [], confidence: [], workflow: [], q: "", page: 1 });
  };

  const facets = page?.facets;
  // A dimension with no values (and none selected) is not offered at all.
  const dispositionValues = facetValues(facets?.disposition, disposition, (a, b) => compareStatus("code-disposition", a, b));
  const confidenceValues = facetValues(facets?.confidence, confidence, byOrder(CONFIDENCE_ORDER));
  const workflowValues = facetValues(facets?.workflow_status, workflow, (a, b) => compareStatus("finding-workflow", a, b));
  const total = page?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / RESULT_PAGE_SIZE));
  const first = total === 0 ? 0 : offset + 1;
  const last = Math.min(offset + RESULT_PAGE_SIZE, total);
  const pager = (position: "top" | "bottom") =>
    page && total > RESULT_PAGE_SIZE ? (
      <div className={`cv-pager cv-pager-${position}`} role="group" aria-label={position === "top" ? "Results pages" : "Results pages (bottom)"}>
        <span className="meta-text">Page {pageNumber.toLocaleString()} of {pages.toLocaleString()}</span>
        <button
          type="button"
          className="ui-button"
          aria-label={position === "top" ? "Previous analysis results page" : "Previous analysis results page (bottom)"}
          disabled={pageNumber <= 1}
          onClick={() => goToPage(pageNumber - 1)}
        >
          ← Previous
        </button>
        <button
          type="button"
          className="ui-button"
          aria-label={position === "top" ? "Next analysis results page" : "Next analysis results page (bottom)"}
          disabled={!page.has_more}
          onClick={() => goToPage(pageNumber + 1)}
        >
          Next →
        </button>
      </div>
    ) : null;

  return (
    <>
      <div ref={resultsRef} hidden={recordOpen} className="cv-results-host">
        <section className="panel cv-section" aria-labelledby="cv-results-title">
          <header className="cv-section-head cv-section-head-row">
            <div>
              <h3 id="cv-results-title">Analysis results</h3>
              <p className="meta-text">
                One result per file review: what the reviewer checked, what they found, and the finding it produced.
                Findings come first, then suspicious and needs-context results, then clean and skipped ones.
              </p>
            </div>
            <ScopeToggle
              label="Results scope"
              scope={scope}
              onChange={(next: Scope) => go({ scope: next, page: 1 })}
              attentionCount={awaitingCount}
              allCount={allCount}
              attentionRule={NEEDS_ATTENTION_RULE}
            />
          </header>

          <div className="cv-results-tools">
            <input
              ref={searchRef}
              type="search"
              className="cv-search"
              aria-label="Search analysis results"
              placeholder="Search file, function, evidence…  (try disposition:finding cwe:79 file:auth)"
              value={text}
              onChange={(event) => setText(event.target.value)}
              onKeyDown={(event) => {
                // Enter commits the search at once instead of waiting out the pause.
                if (event.key === "Enter" && text.trim() !== q) go({ q: text.trim(), page: 1 }, "replace");
              }}
            />
            {dispositionValues.length + confidenceValues.length + workflowValues.length > 0 || filterCount > 0 ? (
              <div className={`cv-facets${results.loading && page ? " is-refreshing" : ""}`}>
                {dispositionValues.length > 0 ? (
                  <FilterGroup label="Result">
                    {dispositionValues.map((value) => (
                      <FilterChip
                        key={value}
                        label={statusLabel("code-disposition", value)}
                        status={{ domain: "code-disposition", value }}
                        count={facets ? facets.disposition[value] ?? 0 : null}
                        selected={disposition.includes(value)}
                        onToggle={() => toggle("disposition", value)}
                      />
                    ))}
                  </FilterGroup>
                ) : null}
                {confidenceValues.length > 0 ? (
                  <FilterGroup label="Confidence">
                    {confidenceValues.map((value) => (
                      <FilterChip
                        key={value}
                        label={humanizeStatus(value)}
                        count={facets ? facets.confidence[value] ?? 0 : null}
                        selected={confidence.includes(value)}
                        onToggle={() => toggle("confidence", value)}
                      />
                    ))}
                  </FilterGroup>
                ) : null}
                {workflowValues.length > 0 ? (
                  <FilterGroup label="Finding status">
                    {workflowValues.map((value) => (
                      <FilterChip
                        key={value}
                        label={statusLabel("finding-workflow", value)}
                        status={{ domain: "finding-workflow", value }}
                        count={facets ? facets.workflow_status[value] ?? 0 : null}
                        selected={workflow.includes(value)}
                        onToggle={() => toggle("workflow", value)}
                      />
                    ))}
                  </FilterGroup>
                ) : null}
                <ClearFiltersButton count={filterCount} onClear={clearFilters} />
              </div>
            ) : null}
          </div>

          <div className="cv-results-summary" ref={listTop}>
            {page ? (
              <ResultsSummary
                shown={total}
                total={narrowed && allCount != null && allCount !== total ? allCount : null}
                noun={total === 1 && (allCount == null || allCount === 1) ? "result" : "results"}
                sort={RESULT_ORDER}
              />
            ) : results.error ? null : (
              <Skeleton width={260} height={12} />
            )}
            {page && total > 0 ? (
              <span className="cv-results-range" role="status">
                {`Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}`}
              </span>
            ) : null}
            {results.loading && page ? <span className="ui-page-status">Updating…</span> : null}
            {pager("top")}
          </div>
          {scope === "attention" && page && page.file_total !== total ? (
            <p className="meta-text">These results come from {page.file_total.toLocaleString()} files awaiting a verdict.</p>
          ) : null}
          {page && total > 0 && page.not_listed.length > 0 ? (
            <ul className="cv-not-listed" aria-label="Results not listed">
              {page.not_listed.map((gap) => <li key={gap.code}>{gap.message}</li>)}
            </ul>
          ) : null}
          {results.error ? (
            <p className="error-text" role="alert">
              Results unavailable: {results.error}{" "}
              <button type="button" className="ui-clear-filters" onClick={() => setRetry((value) => value + 1)}>
                Try again
              </button>
            </p>
          ) : null}

          {!page && results.loading ? (
            <div aria-label="Loading results">
              <CardSkeleton lines={5} />
              <SlowLoadHint active={results.loading} what="analysis results" />
            </div>
          ) : null}

          {page && total === 0 ? (
            filterCount > 0 ? (
              <EmptyState variant="filtered" title="No results match these filters." onClearFilters={clearFilters} />
            ) : scope === "attention" ? (
              <EmptyState
                variant="empty"
                title="No results await a verdict."
                action={<button type="button" className="ui-button" onClick={() => go({ scope: "all", page: 1 })}>Show all results</button>}
              >
                Every suspicious review has been settled by a finding or a later clean review.
              </EmptyState>
            ) : (
              <EmptyState variant="empty" title="No current analysis results.">
                {page.not_listed.length > 0 ? (
                  page.not_listed.map((gap) => <p key={gap.code}>{gap.message}</p>)
                ) : (
                  <p>Reviewers record one result per file review; results appear here as the review queue is worked.</p>
                )}
              </EmptyState>
            )
          ) : null}

          {page && total > 0 ? (
            <ol className={`cv-results${results.loading ? " is-refreshing" : ""}`} aria-label="Analysis results">
              {page.items.map((row) => (
                <ResultRow key={row.id} engagementKey={engagementKey} row={row} onOpen={open} />
              ))}
            </ol>
          ) : null}
          {pager("bottom")}
        </section>
      </div>

      {recordId !== null ? (
        <RecordView
          label="Analysis result record"
          noun="analysis result"
          navigation={navigation}
          onBack={close}
          titleId="cv-result-record-title"
          className="cv-record"
        >
          <CodeResultRecord
            key={recordId}
            engagementKey={engagementKey}
            resultId={recordId}
            row={knownRows.current.get(recordId) ?? null}
            section={section}
            onSectionChange={chooseSection}
            titleId="cv-result-record-title"
            refreshVersion={refreshVersion}
          />
        </RecordView>
      ) : null}
    </>
  );
}

function ResultRow({
  engagementKey,
  row,
  onOpen,
}: {
  engagementKey: string;
  row: CodeAnalysisResult;
  onOpen: (row: CodeAnalysisResult) => void;
}) {
  const path = row.file_path ?? `file #${row.file_id}`;
  // The whole row opens the result; links inside it keep their own target.
  const onRowClick = (event: MouseEvent<HTMLLIElement>) => {
    if ((event.target as HTMLElement).closest("a, button")) return;
    const selection = window.getSelection?.();
    if (selection && selection.type === "Range" && selection.toString().length > 0) return;
    onOpen(row);
  };
  return (
    <li
      className={`cv-result${row.finding_workflow_status === "false_positive" ? " is-suppressed" : ""}`}
      data-record-key={row.id}
      onClick={onRowClick}
    >
      <StatusPill domain="code-disposition" value={row.disposition} size="sm" />
      <button type="button" className="cv-result-open" aria-label={`Open result #${row.id}: ${path}`} onClick={() => onOpen(row)}>
        <span className="cv-path" title={path}>{path}</span>
        {row.function_name ? <span className="cv-result-fn">{row.function_name}</span> : null}
      </button>
      <span className="cv-result-meta">
        {row.awaiting_verdict ? <StatusPill tone="warning" value="awaiting_verdict" label="Awaiting a verdict" size="sm" title={NEEDS_ATTENTION_RULE} /> : null}
        {row.cwe_id ? <span className="cv-chip">{row.cwe_id}</span> : null}
        {row.slot_type ? <span title="Input type">{humanizeStatus(row.slot_type.toLowerCase())}</span> : null}
        {row.confidence ? <span>{humanizeStatus(row.confidence).toLowerCase()} confidence</span> : null}
        {row.finding_slug ? (
          <a href={engagementHref(engagementKey, { tab: "findings", finding: row.finding_slug })}>{row.finding_slug}</a>
        ) : null}
        {row.finding_workflow_status ? <StatusPill domain="finding-workflow" value={row.finding_workflow_status} size="sm" /> : null}
        <TimeStamp value={row.created_at} />
      </span>
    </li>
  );
}
