// The Files view's file list: every code file, paged on the server
// (`GET code/files`), with what the architect recorded for it — risk tier,
// role, input types and context tags. Its filters, path search and page live
// in the URL (useCodeRoute), so a reload, a shared link and Back restore them. A file whose classification recorded no
// context tags reads "Not recorded", never as "none apply"; the coverage
// summary's pointer to those files sits above the list and narrows it to them,
// as does its pointer to the client-bundle files whose server-only
// vulnerability types are optional.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { CodeContextTagsUnrecorded, CodeCoverage, CodeOptionalFamilies, CodeRepo } from "../../lib/api";
import { listCodeFiles, type CodeFilePage } from "../../lib/codeApi";
import { useCoalescedRequest } from "../../lib/useCoalescedRequest";
import { CardSkeleton } from "../Skeletons";
import { ClearFiltersButton, EmptyState, FilterChip, FilterGroup, StatusPill, humanizeStatus } from "../ui";
import { CLASSIFICATION_LABELS, familyLabel } from "./codeLabels";
import { isReference, repoLabel } from "./codeModel";
import { RiskTag } from "./RiskTag";
import type { CodeRoute, CodeRouteTarget } from "./useCodeRoute";

export const FILE_PAGE_SIZE = 25;
const SEARCH_DEBOUNCE_MS = 300;
const TIER_ORDER = ["critical", "high", "medium", "low", "skip"];

type Props = {
  engagementKey: string;
  coverage: CodeCoverage | null;
  repos: CodeRepo[];
  /** The view's repository filter (`repo` in the URL), once it names a known repository. */
  repoId?: number;
  refreshVersion: number;
  /** The list's filters, path search and page live in the URL (`risk`, `tags`, `q`, `page`). */
  route: CodeRoute;
  /** The tables above the list have their data, so the list's place on the page is settled. */
  ready: boolean;
};

export function CodeFileList({ engagementKey, coverage, repos, repoId, refreshVersion, route, ready }: Props) {
  const unrecorded = coverage?.gate.context_tags_unrecorded ?? null;
  const tier = route.risk ?? null;
  const optional = coverage?.gate.optional_families ?? null;
  const untagged = route.tags === "unrecorded";
  const bundled = route.tags === "client-bundle";
  const search = route.q.trim();
  const pageNumber = route.page;

  // The current list state; navigation keeps whatever a call does not change.
  // A table marked by a blocker link (`focus`) is left behind once the list is used.
  const state: CodeRouteTarget = useMemo(
    () => ({ view: "files", repo: route.repo, risk: tier ?? undefined, tags: route.tags, q: search, page: pageNumber }),
    [route.repo, tier, route.tags, search, pageNumber],
  );
  const stateRef = useRef(state);
  stateRef.current = state;
  const go = useCallback(
    (patch: Partial<CodeRouteTarget>, mode: "push" | "replace" = "push") => route.navigate({ ...stateRef.current, ...patch }, mode),
    [route.navigate],
  );

  // The path filter types freely; the URL (and the server) see it after a pause.
  const [text, setText] = useState(search);
  const textRef = useRef(text);
  textRef.current = text;
  useEffect(() => {
    if (textRef.current.trim() !== search) setText(search);
  }, [search]);
  useEffect(() => {
    if (text.trim() === search) return undefined;
    const timer = window.setTimeout(() => go({ q: text.trim(), page: 1 }, "replace"), SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [text, search, go]);

  const [retry, setRetry] = useState(0);
  const offset = (pageNumber - 1) * FILE_PAGE_SIZE;
  const key = JSON.stringify([engagementKey, repoId ?? null, tier, route.tags ?? null, search, offset]);
  const files = useCoalescedRequest<CodeFilePage>(
    key,
    useCallback(
      () =>
        listCodeFiles(engagementKey, {
          repo_id: repoId,
          classification: tier ?? undefined,
          search: search || undefined,
          context_tags_recorded: untagged ? false : undefined,
          context_tag: bundled ? "client-bundle" : undefined,
          limit: FILE_PAGE_SIZE,
          offset,
        }),
      [engagementKey, repoId, tier, untagged, bundled, search, offset],
    ),
    refreshVersion + retry,
  );
  // The last loaded page stays on screen (and keeps the pager, so keyboard
  // focus) while the next one loads; `current` says it answers this request.
  const page = files.data;
  const current = files.dataKey === key;
  const total = page?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / FILE_PAGE_SIZE));
  // A page past the end (a bookmarked page of a list that shrank) moves to the last page.
  useEffect(() => {
    if (!page || !current || page.items.length > 0 || page.total === 0) return;
    go({ page: Math.max(1, Math.ceil(page.total / FILE_PAGE_SIZE)) }, "replace");
  }, [page, current, go]);

  // A link that names the list's filters or page lands on the list, once the
  // tables above it and its first page are in place.
  const sectionRef = useRef<HTMLElement | null>(null);
  const linked = useRef(route.focus == null && (tier != null || route.tags != null || search !== "" || pageNumber > 1)).current;
  const landed = useRef(false);
  const loaded = page !== null;
  useEffect(() => {
    if (!linked || landed.current || !ready || !loaded) return;
    landed.current = true;
    sectionRef.current?.scrollIntoView?.({ block: "start" });
  }, [linked, ready, loaded]);

  // The button leaves with the error it sits in; focus moves to the section first so it is not dropped.
  const retryLoad = () => {
    sectionRef.current?.focus({ preventScroll: true });
    setRetry((value) => value + 1);
  };
  const filterCount = (tier ? 1 : 0) + (route.tags ? 1 : 0) + (search ? 1 : 0);
  const clearFilters = () => {
    setText("");
    go({ risk: undefined, tags: undefined, q: "", page: 1 });
  };
  const applySearch = () => {
    if (text.trim() !== search) go({ q: text.trim(), page: 1 }, "replace");
  };
  // Tier counts cover the repositories under review; with a repository filter they would overstate it.
  const tierCount = (value: string) => (repoId == null ? coverage?.by_classification[value]?.count ?? null : null);
  const tiers = [
    ...TIER_ORDER.filter((value) => value === tier || (coverage ? value in coverage.by_classification : value !== "skip")),
    // A tier named by the URL that the summary does not know stays listed, so it can be cleared.
    ...(tier && !TIER_ORDER.includes(tier) ? [tier] : []),
  ];
  const showRepo = repos.length > 1 && repoId == null;
  const first = page ? page.offset + 1 : 0;
  const last = page ? page.offset + page.items.length : 0;

  return (
    <section ref={sectionRef} tabIndex={-1} className={`panel cv-section cv-focusable${linked ? " is-focused" : ""}`} aria-labelledby="cv-files-title">
      <header className="cv-section-head">
        <h3 id="cv-files-title">All files</h3>
        <p className="meta-text">
          Every code file with what the architect recorded for it, highest review priority first. Input types and
          context tags decide which vulnerability types a file's review owes.
        </p>
      </header>

      {unrecorded ? (
        <ContextTagsUnrecorded pointer={unrecorded} listed={untagged} onList={() => go({ tags: "unrecorded", page: 1 })} />
      ) : null}
      {optional ? (
        <OptionalFamilies pointer={optional} listed={bundled} onList={() => go({ tags: "client-bundle", page: 1 })} />
      ) : null}

      <div className="cv-results-tools">
        <input
          type="search"
          className="cv-search"
          aria-label="Filter files by path"
          placeholder="Filter by path…"
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            // Enter commits the filter at once instead of waiting out the pause.
            if (event.key === "Enter") applySearch();
          }}
        />
        <div className="cv-facets">
          <FilterGroup label="Risk">
            {tiers.map((value) => (
              <FilterChip
                key={value}
                label={CLASSIFICATION_LABELS[value] ?? humanizeStatus(value)}
                color={`var(--sev-${TIER_ORDER.includes(value) && value !== "skip" ? value : "info"})`}
                count={tierCount(value)}
                selected={tier === value}
                onToggle={() => go({ risk: tier === value ? undefined : value, page: 1 })}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Context tags">
            <FilterChip
              label="Not recorded"
              description="Classified files of the repositories under review whose classification recorded no context tags."
              count={repoId == null ? unrecorded?.count ?? (coverage ? 0 : null) : null}
              selected={untagged}
              onToggle={() => go({ tags: untagged ? undefined : "unrecorded", page: 1 })}
            />
            {/* Offered once the coverage summary names such files, or while a link applies it, so it can be cleared. */}
            {optional || bundled ? (
              <FilterChip
                label="Client bundle"
                description="Files tagged client-bundle: their server-only vulnerability types are optional."
                selected={bundled}
                onToggle={() => go({ tags: bundled ? undefined : "client-bundle", page: 1 })}
              />
            ) : null}
          </FilterGroup>
          <ClearFiltersButton count={filterCount} onClear={clearFilters} />
        </div>
      </div>

      {files.error ? (
        <p className="error-text" role="alert">
          Files unavailable: {files.error}{page ? " · Showing the last loaded page." : ""}{" "}
          <button type="button" className="ui-clear-filters" onClick={retryLoad}>
            Try again
          </button>
        </p>
      ) : null}

      {!page || (total === 0 && !current && files.loading) ? (
        files.error ? null : (
          <div aria-label="Loading files">
            <CardSkeleton lines={5} title={false} />
          </div>
        )
      ) : total === 0 ? (
        filterCount > 0 ? (
          <EmptyState variant="filtered" compact title="No files match these filters." onClearFilters={clearFilters} />
        ) : (
          <EmptyState variant="empty" compact title="No code files recorded yet.">
            Files appear here once a repository is ingested.
          </EmptyState>
        )
      ) : (
        <>
          <div className="cv-results-summary">
            <p className="ui-results-summary" role="status">
              <strong>{total.toLocaleString()}</strong> {total === 1 ? "file" : "files"} · Sorted by review priority, highest first
            </p>
            {page.items.length > 0 ? (
              <span className="cv-results-range" role="status">
                {`Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()}`}
              </span>
            ) : null}
            {files.loading ? <span className="ui-page-status">Updating…</span> : null}
            {total > FILE_PAGE_SIZE ? (
              <div className="cv-pager" role="group" aria-label="File pages">
                <span className="meta-text">Page {pageNumber.toLocaleString()} of {pages.toLocaleString()}</span>
                <button type="button" className="ui-button" aria-label="Previous files page" disabled={pageNumber <= 1} onClick={() => go({ page: pageNumber - 1 })}>
                  ← Previous
                </button>
                <button
                  type="button"
                  className="ui-button"
                  aria-label="Next files page"
                  disabled={current ? !page.has_more : pageNumber >= pages}
                  onClick={() => go({ page: pageNumber + 1 })}
                >
                  Next →
                </button>
              </div>
            ) : null}
          </div>
          <div className="cv-table-scroll">
            <table className={`cv-table cv-file-table${files.loading ? " is-refreshing" : ""}`}>
              <thead>
                <tr>
                  <th scope="col">File</th>
                  <th scope="col">Risk</th>
                  <th scope="col">Review</th>
                  <th scope="col">Role</th>
                  <th scope="col">Input types</th>
                  <th scope="col">Context tags</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((file) => {
                  const repo = repos.find((entry) => entry.id === file.repo_id);
                  return (
                    <tr key={file.id}>
                      <th scope="row" className="cv-file-path">
                        <span className="cv-mono">{file.file_path}</span>
                        {showRepo && (
                          <span className="meta-text cv-file-repo">
                            {repo ? repoLabel(repo, repos) : `Repository #${file.repo_id}`}
                            {repo && isReference(repo) ? " (reference)" : ""}
                          </span>
                        )}
                      </th>
                      <td><RiskTag classification={file.classification || "unclassified"} /></td>
                      <td><StatusPill domain="code-file" value={file.analysis_status} size="sm" /></td>
                      <td className="cv-file-role">{file.role || <span className="meta-text">—</span>}</td>
                      <td><TagList values={file.slot_types} empty="—" /></td>
                      <td>
                        {file.context_tags_recorded ? (
                          <TagList values={file.context_tags} empty="None apply" />
                        ) : (
                          <span className="meta-text" title="The classification recorded no context tags; that is not the same as none applying.">Not recorded</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

/**
 * The coverage summary's pointer to the server-only vulnerability types a
 * `client-bundle` tag makes optional. It counts every such file and type, and
 * names a sample of the files, so it says how many it left out and how to
 * list them all: the list below, narrowed to the tag, or the reads the
 * backend names.
 */
function OptionalFamilies({ pointer, listed, onList }: { pointer: CodeOptionalFamilies; listed: boolean; onList: () => void }) {
  const families = Object.entries(pointer.by_family);
  return (
    <div className="cv-inline-note" role="note" aria-label="Vulnerability types optional on client-bundle files">
      <p>
        <strong>
          {pointer.files.toLocaleString()} client-bundle {pointer.files === 1 ? "file leaves" : "files leave"} server-only
          vulnerability types optional
        </strong>
        . This is advice and blocks nothing: {pointer.detail}.
      </p>
      <ul className="cv-tag-list" aria-label="Optional vulnerability types">
        {families.map(([family, count]) => (
          <li key={family} className="cv-chip" title={family}>
            {familyLabel(family)} · {count.toLocaleString()} {count === 1 ? "file" : "files"}
          </li>
        ))}
      </ul>
      <p>
        {listed ? (
          "The list below shows every client-bundle file."
        ) : (
          <button type="button" className="ui-clear-filters" onClick={onList}>
            List the client-bundle files below
          </button>
        )}
        {" · "}From the command line: <code className="cv-mono">{pointer.full_list}</code>
      </p>
      {pointer.sample_paths.length > 0 ? (
        <details className="cv-raw">
          <summary>
            {pointer.sample_paths.length.toLocaleString()} {pointer.sample_paths.length === 1 ? "example" : "examples"}
            {pointer.omitted > 0 ? ` (${pointer.omitted.toLocaleString()} more not shown here)` : ""}
          </summary>
          <ul>
            {pointer.sample_paths.map((path) => <li key={path} className="cv-mono">{path}</li>)}
          </ul>
        </details>
      ) : null}
    </div>
  );
}

function TagList({ values, empty }: { values: string[]; empty: string }) {
  if (values.length === 0) return <span className="meta-text">{empty}</span>;
  return (
    <span className="cv-tag-list">
      {values.map((value) => (
        <span key={value} className="cv-chip" title={value}>{humanizeStatus(value.toLowerCase())}</span>
      ))}
    </span>
  );
}

/**
 * The coverage summary's pointer to files classified without context tags.
 * It names a sample, so it says how many it left out and how to list them all:
 * the list below, narrowed, or the read the backend names.
 */
function ContextTagsUnrecorded({ pointer, listed, onList }: { pointer: CodeContextTagsUnrecorded; listed: boolean; onList: () => void }) {
  const tiers = TIER_ORDER.filter((tier) => (pointer.by_classification[tier] ?? 0) > 0)
    .map((tier) => `${pointer.by_classification[tier].toLocaleString()} ${(CLASSIFICATION_LABELS[tier] ?? tier).toLowerCase()}`);
  return (
    <div className="cv-inline-note is-warn" role="note" aria-label="Files with no context tags recorded">
      <p>
        <strong>
          {pointer.count.toLocaleString()} {pointer.count === 1 ? "file has" : "files have"} no context tags recorded
        </strong>
        {tiers.length > 0 ? ` (${tiers.join(" · ")})` : ""}. This is advice for the architect and blocks nothing.
      </p>
      <p>To record them: {pointer.fix}.</p>
      <p>
        {listed ? (
          "The list below shows them all."
        ) : (
          <button type="button" className="ui-clear-filters" onClick={onList}>
            List all {pointer.count.toLocaleString()} below
          </button>
        )}
        {" · "}From the command line: <code className="cv-mono">{pointer.full_list}</code>
      </p>
      {pointer.sample_paths.length > 0 ? (
        <details className="cv-raw">
          <summary>
            {pointer.sample_paths.length.toLocaleString()} {pointer.sample_paths.length === 1 ? "example" : "examples"}
            {pointer.omitted > 0 ? ` (${pointer.omitted.toLocaleString()} more not shown here)` : ""}
          </summary>
          <ul>
            {pointer.sample_paths.map((path) => <li key={path} className="cv-mono">{path}</li>)}
          </ul>
        </details>
      ) : null}
    </div>
  );
}
