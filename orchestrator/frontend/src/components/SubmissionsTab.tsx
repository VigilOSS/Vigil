// ── SubmissionsTab ────────────────────────────────────────────────────
// The submission desk: a server-filtered queue of findings beside the one
// finding's submission document (body, notes, package, versions, readiness)
// with its single primary action pinned in the document header. Export is
// the only irreversible action and always goes through ExportDialog.
//
// The shared "Needs attention" scope is the backend's "To do" listing; a
// state chip narrows it (a chip outside the scope widens it). The selected
// finding and document section live in the address (`submission=`, `dtab=`)
// and, with the filters, survive leaving the tab (sessionStorage).

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { RefreshCcw, Search, X } from "lucide-react";

import { exportSubmissionVersion, recoverSubmissionExports } from "../lib/api";
import type { SubmissionRecoveryResult } from "../lib/api";
import {
  SUBMISSION_MAX_PAGE_SIZE,
  SUBMISSION_PAGE_SIZE,
  getSubmissionDesk,
  getSubmissionReadiness,
  listSubmissionDesk,
} from "../lib/submissionsApi";
import type {
  SubmissionAttachmentRow,
  SubmissionDeskDetail,
  SubmissionDeskListing,
  SubmissionDeskRow,
  SubmissionListingFilter,
  SubmissionReadiness,
} from "../lib/submissionsApi";
import { useToast } from "../contexts/ToastContext";
import { createCoalescedRunner } from "../lib/coalesce";
import { useViewportPane } from "../lib/viewportPane";
import { engagementHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import type { AttachmentMeta } from "./submissions/AttachmentPicker";
import { ExportDialog } from "./submissions/ExportDialog";
import {
  ATTENTION_STATES,
  RECENCY_OPTIONS,
  SEVERITY_ORDER,
  STATE_FILTER_ORDER,
  listingFilterFor,
  listingFilterHint,
  listingFilterLabel,
  nextVersionNumber,
  parseDeskView,
  platformLabel,
  sameIdSet,
  sortedIds,
  type DeskView,
} from "./submissions/model";
import { DOCUMENT_TABS, PendingVersionRows, SubmissionDocument, type DocumentTab } from "./submissions/SubmissionDocument";
import { SubmissionQueue } from "./submissions/SubmissionQueue";
import {
  ClearFiltersButton,
  FilterChip,
  FilterGroup,
  PageHeader,
  ScopeToggle,
  humanizeStatus,
  type Scope,
} from "./ui";
import "../styles/submissions.css";

type SubmissionsTabProps = {
  engagementKey: string;
  refreshVersion?: number;
  /** `submission=` in the URL: the finding whose submission document is open. */
  initialSubmissionSlug?: string;
  /** `dtab=` in the URL: the open document tab. */
  initialDrawerTab?: string;
  /** Reports the engagement's "to do" count from each listing read, for the rail badge while open. */
  onToDoCount?: (count: number) => void;
};

const SEARCH_DEBOUNCE_MS = 250;
const READINESS_DEBOUNCE_MS = 350;
// Pane height floor: below this the page scrolls and the panes stay sticky.
const MIN_PANE_HEIGHT = 300;

const viewKey = (engagementKey: string) => `submissions.queue.${engagementKey}`;

function readDeskView(engagementKey: string): DeskView {
  try {
    return parseDeskView(window.sessionStorage.getItem(viewKey(engagementKey)));
  } catch {
    return parseDeskView(null);
  }
}

function documentTab(value: string | undefined): DocumentTab | null {
  return value && (DOCUMENT_TABS as readonly string[]).includes(value) ? value as DocumentTab : null;
}

function errorMessage(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

function metaFromRow(row: SubmissionAttachmentRow): AttachmentMeta {
  return {
    id: row.id,
    relative_path: row.relative_path,
    size_bytes: row.size_bytes,
    kind: row.kind,
    updated_at: row.updated_at,
    internal: row.internal,
  };
}

function metaFromDetail(detail: SubmissionDeskDetail): AttachmentMeta[] {
  const rows: AttachmentMeta[] = [];
  for (const version of [detail.latest_version, ...detail.versions]) {
    const manifest = version?.manifest;
    if (manifest && "attachments" in manifest && Array.isArray(manifest.attachments)) {
      for (const item of manifest.attachments) {
        rows.push({ id: item.artifact_id, relative_path: item.original_relative_path, size_bytes: item.size_bytes });
      }
    }
  }
  for (const item of detail.blind_triage.attachments) {
    if (item.artifact_id != null) {
      rows.push({ id: item.artifact_id, relative_path: item.source_path || item.packet_path, size_bytes: item.bytes });
    }
  }
  rows.push(...detail.eligible_attachments.map(metaFromRow), ...detail.default_attachments.map(metaFromRow));
  return rows;
}

export function SubmissionsTab(props: SubmissionsTabProps) {
  return <SubmissionDesk key={props.engagementKey} {...props} />;
}

function SubmissionDesk({ engagementKey, refreshVersion = 0, initialSubmissionSlug, initialDrawerTab, onToDoCount }: SubmissionsTabProps) {
  const { toast } = useToast();
  const [saved] = useState(() => readDeskView(engagementKey));

  // ── Filters (server-side) ───────────────────────────────────────────
  const [scope, setScope] = useState<Scope>(saved.scope);
  // Set when the desk fell back to All because nothing needed attention on
  // arrival: the fallback is not saved, so the next visit opens on Needs
  // attention again. Any scope choice by the operator clears it.
  const scopeFellBack = useRef(false);
  const [stateFilter, setStateFilter] = useState<SubmissionListingFilter | null>(saved.state);
  const readinessFilter = listingFilterFor(scope, stateFilter);
  const [severityFilter, setSeverityFilter] = useState<string[]>(saved.severity);
  const [platformFilter, setPlatformFilter] = useState<string[]>(saved.platform);
  const [recency, setRecency] = useState<number | null>(saved.recency);
  const [searchText, setSearchText] = useState(saved.search);
  const [query, setQuery] = useState(saved.search.trim());
  useEffect(() => {
    const timer = setTimeout(() => setQuery(searchText.trim()), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [searchText]);
  const filterParams = useMemo(() => ({
    readiness: readinessFilter,
    severity: severityFilter,
    platform: platformFilter,
    q: query,
    changedWithinHours: recency,
  }), [readinessFilter, severityFilter, platformFilter, query, recency]);

  // ── Listing ─────────────────────────────────────────────────────────
  const [listing, setListing] = useState<SubmissionDeskListing | null>(null);
  const [listingLoading, setListingLoading] = useState(true);
  const [listingError, setListingError] = useState("");
  const [loadingMoreFindings, setLoadingMoreFindings] = useState(false);
  const listingRef = useRef<SubmissionDeskListing | null>(null);
  listingRef.current = listing;

  // ── Selection + detail ──────────────────────────────────────────────
  // A link names the finding; otherwise the one open when the tab was left.
  const [selectedSlug, setSelectedSlug] = useState(initialSubmissionSlug ?? saved.slug);
  const selectedSlugRef = useRef(selectedSlug);
  selectedSlugRef.current = selectedSlug;
  const selectedRowRef = useRef<SubmissionDeskRow | null>(null);
  // Set by an operator filter change: the next listing moves the selection
  // onto it when the open finding falls outside.
  const followFilterRef = useRef(false);
  const [detail, setDetail] = useState<SubmissionDeskDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const detailCache = useRef(new Map<string, SubmissionDeskDetail>());
  const detailGeneration = useRef(0);
  const [tab, setTab] = useState<DocumentTab>(documentTab(initialDrawerTab) ?? (initialSubmissionSlug ? "body" : documentTab(saved.tab) ?? "body"));
  const [loadingMoreVersions, setLoadingMoreVersions] = useState(false);
  const [loadingMorePending, setLoadingMorePending] = useState(false);

  // ── Attachment selection + readiness ────────────────────────────────
  const [selection, setSelection] = useState<number[]>([]);
  const selectionTouched = useRef(false);
  const [meta, setMeta] = useState<Map<number, AttachmentMeta>>(new Map());
  const [readinessOverride, setReadinessOverride] = useState<{
    slug: string;
    ids: number[];
    value: SubmissionReadiness;
  } | null>(null);
  const readinessGeneration = useRef(0);

  // ── Actions ─────────────────────────────────────────────────────────
  const [exportOpen, setExportOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");
  const [recovering, setRecovering] = useState(false);
  const [recoveryIssues, setRecoveryIssues] = useState<SubmissionRecoveryResult | null>(null);
  const locked = exporting || recovering;

  const rememberMeta = useCallback((rows: AttachmentMeta[]) => {
    if (rows.length === 0) return;
    setMeta((current) => {
      const next = new Map(current);
      for (const row of rows) {
        const known = next.get(row.id);
        next.set(row.id, { ...known, ...row, internal: row.internal ?? known?.internal });
      }
      return next;
    });
  }, []);

  // Listing loads coalesce through the shared runner (lib/coalesce): a refresh
  // while one is in flight runs once more after it settles, so bursts never
  // starve and later pages are re-read. Each filter set (and each Retry) gets
  // its own runner, which starts at once; a superseded runner's results and
  // queued passes are dropped.
  const [listingAttempt, setListingAttempt] = useState(0);
  const listingRunner = useMemo(() => {
    let first = true;
    const runner = createCoalescedRunner(async () => {
      const current = () => listingRunnerRef.current === runner;
      if (!current()) return;
      const replace = first;
      first = false;
      setListingLoading(true);
      const loaded = listingRef.current?.findings.length ?? 0;
      const limit = replace ? SUBMISSION_PAGE_SIZE : Math.min(SUBMISSION_MAX_PAGE_SIZE, Math.max(SUBMISSION_PAGE_SIZE, loaded));
      try {
        const next = await listSubmissionDesk(engagementKey, {
          ...filterParams,
          findingOffset: 0,
          findingLimit: limit,
        });
        if (!current()) return;
        if (replace && followFilterRef.current) {
          followFilterRef.current = false;
          if (!next.findings.some((item) => item.slug === selectedSlugRef.current)) {
            const firstRow = next.findings[0] ?? null;
            selectedRowRef.current = firstRow;
            setSelectedSlug(firstRow?.slug ?? "");
          }
        }
        const previous = listingRef.current;
        const tail = !replace && previous && loaded > limit
          ? previous.findings.slice(limit).filter((row) => !next.findings.some((item) => item.slug === row.slug))
          : [];
        setListing(tail.length ? { ...next, findings: [...next.findings, ...tail] } : next);
        setListingError("");
      } catch (cause) {
        if (current()) setListingError(errorMessage(cause, "Submission queue unavailable"));
      }
    }, () => {
      if (listingRunnerRef.current === runner) setListingLoading(false);
    });
    return runner;
  }, [engagementKey, filterParams, listingAttempt]);
  const listingRunnerRef = useRef(listingRunner);
  listingRunnerRef.current = listingRunner;
  const loadListing = useCallback((mode: "join" | "refresh") => listingRunner(mode), [listingRunner]);

  useEffect(() => {
    void loadListing("join");
  }, [loadListing]);

  // Live refresh bumps re-read the loaded window; filter changes replace above.
  const lastRefreshVersion = useRef(refreshVersion);
  useEffect(() => {
    if (lastRefreshVersion.current === refreshVersion) return;
    lastRefreshVersion.current = refreshVersion;
    void loadListing("refresh");
  }, [refreshVersion, loadListing]);

  // An operator filter change (not a live refresh or a link) lets the
  // selection follow the filter; the first render is not a change.
  const filtersSeen = useRef(filterParams);
  useEffect(() => {
    if (filtersSeen.current === filterParams) return;
    filtersSeen.current = filterParams;
    followFilterRef.current = true;
  }, [filterParams]);

  // Select the first queued finding until the operator picks one (only on a
  // fresh visit: a filter that empties the list leaves nothing selected). A
  // pick that lands before this effect runs wins over the first row.
  const autoSelected = useRef(Boolean(selectedSlug));
  useEffect(() => {
    if (autoSelected.current || selectedSlug || !listing?.findings.length) return;
    autoSelected.current = true;
    const first = listing.findings[0].slug;
    setSelectedSlug((current) => current || first);
  }, [listing, selectedSlug]);

  // Browser Back / Forward between findings: the address names the finding.
  useEffect(() => {
    if (initialSubmissionSlug && initialSubmissionSlug !== selectedSlugRef.current) setSelectedSlug(initialSubmissionSlug);
  }, [initialSubmissionSlug]);
  useEffect(() => {
    const next = documentTab(initialDrawerTab);
    if (next) setTab(next);
  }, [initialDrawerTab]);

  // The address and the saved view follow the open finding and section.
  useEffect(() => {
    const href = selectedSlug
      ? engagementHref(engagementKey, { tab: "submissions", submission: selectedSlug, dtab: tab === "body" ? undefined : tab })
      : engagementHref(engagementKey, { tab: "submissions" });
    writeWorkspaceHash(href, "replace");
  }, [engagementKey, selectedSlug, tab]);
  useEffect(() => {
    const view: DeskView = {
      scope: scopeFellBack.current && scope === "all" ? "attention" : scope,
      state: stateFilter, severity: severityFilter, platform: platformFilter, recency, search: searchText, slug: selectedSlug, tab,
    };
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(view));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, scope, stateFilter, severityFilter, platformFilter, recency, searchText, selectedSlug, tab]);

  const selectedRow = useMemo(() => {
    const fresh = listing?.findings.find((row) => row.slug === selectedSlug) ?? null;
    if (fresh) selectedRowRef.current = fresh;
    return fresh ?? (selectedRowRef.current?.slug === selectedSlug ? selectedRowRef.current : null);
  }, [listing, selectedSlug]);

  const applyDetail = useCallback((next: SubmissionDeskDetail, resetSelection: boolean) => {
    detailCache.current.set(`${engagementKey}\n${next.finding.slug}`, next);
    // A new detail invalidates any readiness computed against the previous one
    // (for example an export that just captured this selection).
    readinessGeneration.current += 1;
    setReadinessOverride(null);
    setDetail(next);
    rememberMeta(metaFromDetail(next));
    if (resetSelection || !selectionTouched.current) {
      selectionTouched.current = false;
      setSelection(sortedIds(next.default_attachment_ids));
    }
  }, [engagementKey, rememberMeta]);

  const loadDetail = useCallback(async (slug: string, resetSelection: boolean) => {
    const generation = ++detailGeneration.current;
    setDetailLoading(true);
    setDetailError("");
    try {
      const next = await getSubmissionDesk(engagementKey, slug);
      if (generation !== detailGeneration.current) return;
      applyDetail(next, resetSelection);
    } catch (cause) {
      if (generation !== detailGeneration.current) return;
      setDetailError(errorMessage(cause, "Submission detail unavailable"));
    } finally {
      if (generation === detailGeneration.current) setDetailLoading(false);
    }
  }, [engagementKey, applyDetail]);

  // Switching findings shows the selected title at once, any cached state
  // dimmed, and never another finding's document.
  useEffect(() => {
    readinessGeneration.current += 1;
    setReadinessOverride(null);
    setLoadingMoreVersions(false);
    setLoadingMorePending(false);
    if (!selectedSlug) {
      detailGeneration.current += 1;
      setDetail(null);
      setDetailLoading(false);
      return;
    }
    const cached = detailCache.current.get(`${engagementKey}\n${selectedSlug}`) ?? null;
    setDetail(cached);
    selectionTouched.current = false;
    setSelection(cached ? sortedIds(cached.default_attachment_ids) : []);
    void loadDetail(selectedSlug, true);
  }, [engagementKey, selectedSlug, loadDetail]);

  // Readiness for the current selection: the detail already evaluated its
  // default set; any other selection asks the read-only readiness endpoint.
  const detailMatchesSelection = Boolean(
    detail && sameIdSet(detail.readiness.attachment_ids, selection),
  );
  const overrideMatches = Boolean(
    detail
    && readinessOverride
    && readinessOverride.slug === detail.finding.slug
    && sameIdSet(readinessOverride.ids, selection),
  );
  const readiness: SubmissionReadiness | null = !detail
    ? null
    : detailMatchesSelection
      ? detail.readiness
      : overrideMatches && readinessOverride
        ? readinessOverride.value
        : null;
  const checkingReadiness = Boolean(detail) && readiness == null;

  useEffect(() => {
    if (!detail || detailMatchesSelection || overrideMatches) return undefined;
    const slug = detail.finding.slug;
    const ids = [...selection];
    const generation = ++readinessGeneration.current;
    const timer = setTimeout(() => {
      void getSubmissionReadiness(engagementKey, slug, ids)
        .then((value) => {
          if (generation === readinessGeneration.current) setReadinessOverride({ slug, ids, value });
        })
        .catch((cause: unknown) => {
          if (generation !== readinessGeneration.current) return;
          const message = errorMessage(cause, "Export readiness unavailable");
          setReadinessOverride({
            slug,
            ids,
            value: {
              ...detail.readiness,
              attachment_ids: ids,
              final_ready: false,
              blockers: [message],
              items: [{ message, fix: "Retry, or reselect the attachments.", command: "" }],
              existing_version_number: null,
            },
          });
        });
    }, READINESS_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [engagementKey, detail, selection, detailMatchesSelection, overrideMatches]);

  const toggleAttachment = (id: number) => {
    selectionTouched.current = true;
    setSelection((current) => (
      current.includes(id) ? current.filter((value) => value !== id) : sortedIds([...current, id])
    ));
  };
  const replaceAttachments = (ids: number[]) => {
    selectionTouched.current = true;
    setSelection(sortedIds(ids));
  };

  const previewOutdated = Boolean(
    selectedRow
    && detail
    && selectedRow.id === detail.finding.id
    && selectedRow.row_version !== detail.finding.row_version,
  );

  const selectFinding = (row: SubmissionDeskRow) => {
    if (locked) return;
    selectedRowRef.current = row;
    // A pick is navigation: one history entry, so Back returns to the last finding.
    if (row.slug !== selectedSlug) {
      writeWorkspaceHash(engagementHref(engagementKey, { tab: "submissions", submission: row.slug, dtab: tab === "body" ? undefined : tab }));
    }
    setSelectedSlug(row.slug);
  };

  const handleLoadMoreFindings = async () => {
    const page = listing?.findings_page;
    if (!listing || !page?.has_more || page.next_offset == null || loadingMoreFindings) return;
    const runner = listingRunnerRef.current;
    setLoadingMoreFindings(true);
    try {
      const next = await listSubmissionDesk(engagementKey, {
        ...filterParams,
        findingOffset: page.next_offset,
        findingLimit: page.limit,
      });
      if (runner !== listingRunnerRef.current) return;
      setListing((current) => {
        if (!current) return next;
        const known = new Set(current.findings.map((row) => row.slug));
        return {
          ...next,
          findings: [...current.findings, ...next.findings.filter((row) => !known.has(row.slug))],
        };
      });
    } catch (cause) {
      toast(errorMessage(cause, "More findings could not be loaded"), "error");
    } finally {
      setLoadingMoreFindings(false);
    }
  };

  const loadMoreDetail = async (kind: "versions" | "pending") => {
    if (!detail) return;
    const page = kind === "versions" ? detail.versions_page : detail.pending_versions_page;
    if (!page.has_more || page.next_offset == null) return;
    const slug = detail.finding.slug;
    const generation = detailGeneration.current;
    const setBusy = kind === "versions" ? setLoadingMoreVersions : setLoadingMorePending;
    setBusy(true);
    try {
      const next = await getSubmissionDesk(engagementKey, slug, kind === "versions"
        ? { versionOffset: page.next_offset, versionLimit: page.limit }
        : { pendingVersionOffset: page.next_offset, pendingVersionLimit: page.limit });
      if (generation !== detailGeneration.current) return;
      setDetail((current) => {
        if (!current || current.finding.slug !== slug) return current;
        if (kind === "versions") {
          const versions = new Map(current.versions.map((version) => [version.id, version]));
          for (const version of next.versions) versions.set(version.id, version);
          return { ...current, versions: [...versions.values()], versions_page: next.versions_page };
        }
        const pending = new Map(current.pending_versions.map((version) => [version.id, version]));
        for (const version of next.pending_versions) pending.set(version.id, version);
        return {
          ...current,
          pending_versions: [...pending.values()],
          pending_versions_page: next.pending_versions_page,
        };
      });
    } catch (cause) {
      toast(errorMessage(cause, `More ${kind === "versions" ? "versions" : "incomplete exports"} could not be loaded`), "error");
    } finally {
      setBusy(false);
    }
  };

  const openExport = () => {
    setExportError("");
    setExportOpen(true);
  };

  const handleExport = async () => {
    if (!detail || !readiness?.final_ready || locked) return;
    const platform = readiness.platform ?? detail.platform;
    if (!platform) {
      setExportError("The rendered submission names no supported platform.");
      return;
    }
    const slug = detail.finding.slug;
    setExporting(true);
    setExportError("");
    try {
      const version = await exportSubmissionVersion(engagementKey, slug, {
        platform,
        submission_path: detail.workspace.submission_path,
        context_path: detail.workspace.context_path,
        attachment_ids: [...selection],
        actor_surface: "web-ui",
      });
      setExportOpen(false);
      toast(
        version.idempotent_replay
          ? `v${version.version_number} already captured these exact sources; nothing new was written.`
          : `Sealed immutable v${version.version_number} of ${slug}. Nothing was submitted to ${platformLabel(platform)}.`,
        "success",
      );
      await Promise.all([loadDetail(slug, false), loadListing("refresh")]);
    } catch (cause) {
      const message = errorMessage(cause, "Submission export failed");
      setExportError(message);
      toast(`Export of ${slug} failed: ${message}`, "error");
    } finally {
      setExporting(false);
    }
  };

  const handleRecovery = async () => {
    if (locked) return;
    setRecovering(true);
    setRecoveryIssues(null);
    try {
      let page = await recoverSubmissionExports(engagementKey, "web-ui");
      const recoveredIds = [...page.recovered_version_ids];
      const failedVersions = [...page.failed_versions];
      const orphanedPaths = [...page.orphaned_staging_paths];
      const seenCursors = new Set<string>();
      while (page.failed_versions_page.has_more || page.orphaned_staging_page.has_more) {
        const failedVersionOffset = page.failed_versions_page.has_more
          ? page.failed_versions_page.next_offset
          : page.failed_versions_page.offset + page.failed_versions_page.returned;
        const orphanAfter = page.orphaned_staging_page.has_more
          ? page.orphaned_staging_page.next_after
          : page.orphaned_staging_paths.at(-1) ?? "";
        if (failedVersionOffset == null || orphanAfter == null) {
          throw new Error("Recovery diagnostics returned an invalid continuation cursor");
        }
        const cursor = `${failedVersionOffset}\n${orphanAfter}`;
        if (seenCursors.has(cursor)) throw new Error("Recovery diagnostic pagination made no progress");
        seenCursors.add(cursor);
        page = await recoverSubmissionExports(engagementKey, "web-ui", { failedVersionOffset, orphanAfter });
        recoveredIds.push(...page.recovered_version_ids);
        failedVersions.push(...page.failed_versions);
        orphanedPaths.push(...page.orphaned_staging_paths);
      }
      const result: SubmissionRecoveryResult = {
        ...page,
        recovered_version_ids: [...new Set(recoveredIds)],
        failed_version_ids: [...new Set(failedVersions.map((version) => version.id))],
        failed_versions: [...new Map(failedVersions.map((version) => [version.id, version])).values()],
        orphaned_staging_paths: [...new Set(orphanedPaths)],
      };
      if (result.failed_versions.length > 0 || result.orphaned_staging_paths.length > 0) {
        setRecoveryIssues(result);
      }
      toast(
        result.recovered_version_ids.length > 0
          ? `Recovered ${result.recovered_version_ids.length} staged export${result.recovered_version_ids.length === 1 ? "" : "s"}.`
          : "No staged export could be completed.",
        result.recovered_version_ids.length > 0 ? "success" : "info",
      );
      await Promise.all([
        selectedSlug ? loadDetail(selectedSlug, false) : Promise.resolve(),
        loadListing("refresh"),
      ]);
    } catch (cause) {
      toast(errorMessage(cause, "Submission recovery failed"), "error");
    } finally {
      setRecovering(false);
    }
  };

  const counts = listing?.counts;
  // The listing counts cover the whole engagement whatever the filters.
  const actionable = counts?.actionable;
  useEffect(() => {
    if (actionable != null) onToDoCount?.(actionable);
  }, [actionable, onToDoCount]);
  const needWork = counts ? counts.blocked + counts.needs_draft : null;
  const shellRef = useRef<HTMLDivElement | null>(null);
  const { height: paneHeight, stickyTop } = useViewportPane(shellRef, MIN_PANE_HEIGHT, [
    Boolean(listing), recoveryIssues, listing?.staging_count, listing?.failed_count,
  ]);
  const toggleFacet = (current: string[], value: string, set: (next: string[]) => void) => {
    set(current.includes(value) ? current.filter((item) => item !== value) : [...current, value]);
  };
  const severityFacet = listing?.facets.severity ?? {};
  const platformFacet = listing?.facets.platform ?? {};
  const severities = [...new Set([...SEVERITY_ORDER.filter((value) => severityFacet[value]), ...severityFilter])];
  const platforms = [...new Set([...Object.keys(platformFacet), ...platformFilter])].sort();
  const activeFilterCount = (stateFilter ? 1 : 0) + severityFilter.length + platformFilter.length + (recency ? 1 : 0) + (query ? 1 : 0);
  const clearFilters = () => {
    setStateFilter(null);
    setSeverityFilter([]);
    setPlatformFilter([]);
    setRecency(null);
    setSearchText("");
  };
  // A work queue opens on Needs attention, or on All when nothing needs
  // attention on arrival (decided once, on the first listing).
  const scopeDecided = useRef(false);
  useEffect(() => {
    if (!listing || scopeDecided.current) return;
    scopeDecided.current = true;
    if (scope === "attention" && stateFilter === null && listing.counts.actionable === 0 && listing.counts.all > 0) {
      scopeFellBack.current = true;
      setScope("all");
    }
  }, [listing, scope, stateFilter]);
  // A state chip outside the scope widens it; narrowing drops a chip it excludes.
  const toggleState = (state: SubmissionListingFilter) => {
    const next = stateFilter === state ? null : state;
    if (next && scope === "attention" && !ATTENTION_STATES.has(next)) {
      scopeFellBack.current = false;
      setScope("all");
    }
    setStateFilter(next);
  };
  const chooseScope = (next: Scope) => {
    scopeFellBack.current = false;
    setScope(next);
    if (next === "attention" && stateFilter && !ATTENTION_STATES.has(stateFilter)) setStateFilter(null);
  };
  const chooseTab = (next: DocumentTab) => setTab(next);
  const exportReadiness = readiness && detail && readiness.final_ready && readiness.existing_version_number == null
    ? readiness
    : null;
  const selectedOutsideList = Boolean(
    listing && selectedSlug && !listingLoading && !listing.findings.some((item) => item.slug === selectedSlug),
  );

  return (
    <div className="findings-redesign subm-page">
      <PageHeader
        title="Submissions"
        purpose="Turn confirmed findings into immutable, exportable write-ups. Exporting never submits anything to the platform."
        stats={counts ? [
          { value: counts.ready, label: "ready", title: listingFilterHint("ready") },
          { value: needWork, label: "need work", tone: needWork ? "warning" : undefined, title: "Blocked or still needing a rendered draft." },
          { value: counts.exported, label: "exported", title: listingFilterHint("exported") },
          { value: counts.filed, label: "filed", title: listingFilterHint("filed") },
        ] : []}
        status={listingLoading ? (listing ? "Updating…" : "Loading queue…") : null}
        actions={listing && listing.staging_count > 0 ? (
          <button
            type="button"
            className="ui-button subm-recover"
            onClick={handleRecovery}
            disabled={locked}
            title="Verify and complete staged exports (writes only completed versions)"
          >
            <RefreshCcw size={13} aria-hidden="true" />
            {recovering ? "Recovering…" : `Recover ${listing.staging_count} staged export${listing.staging_count === 1 ? "" : "s"}`}
          </button>
        ) : undefined}
      >
        <ScopeToggle
          scope={scope}
          onChange={chooseScope}
          attentionCount={counts?.actionable}
          allCount={counts?.all}
          attentionRule={listingFilterHint("actionable")}
        />
      </PageHeader>

      {recoveryIssues && (
        <div className="subm-callout is-danger subm-recovery" role="alert">
          <div className="subm-recovery-head">
            <strong>Recovery incomplete.</strong>
            <button type="button" className="icon-btn" aria-label="Dismiss recovery details" onClick={() => setRecoveryIssues(null)}>
              <X size={14} aria-hidden="true" />
            </button>
          </div>
          {recoveryIssues.failed_versions.length > 0 && <PendingVersionRows versions={recoveryIssues.failed_versions} />}
          {recoveryIssues.orphaned_staging_paths.length > 0 && (
            <div>
              <p>Orphaned staging path{recoveryIssues.orphaned_staging_paths.length === 1 ? "" : "s"}:</p>
              <ul>
                {recoveryIssues.orphaned_staging_paths.map((path) => <li key={path}><code>{path}</code></li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="panel findings-toolbar-panel subm-toolbar">
        <div className="filter-row">
          <div className="search-wrap subm-search">
            <Search className="search-icon" aria-hidden="true" />
            <input
              className="search-input"
              type="search"
              placeholder="Search findings by slug or title…"
              aria-label="Search submissions"
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
            />
            {searchText && (
              <button type="button" className="icon-btn" onClick={() => setSearchText("")} aria-label="Clear submission search">
                <X size={14} />
              </button>
            )}
          </div>
          <FilterGroup label="State">
            {STATE_FILTER_ORDER.filter((state) => state !== "incomplete_exports" || (counts?.incomplete_exports ?? 0) > 0 || stateFilter === state).map((state) => (
              <FilterChip
                key={state}
                label={state === "incomplete_exports" ? "Failed or staged exports" : listingFilterLabel(state)}
                status={state === "incomplete_exports" ? { domain: "submission-version", value: "failed" } : { domain: "submission", value: state }}
                description={listingFilterHint(state)}
                count={counts ? counts[state] : null}
                selected={stateFilter === state}
                onToggle={() => toggleState(state)}
              />
            ))}
          </FilterGroup>
        </div>
        <div className="filter-row subm-facet-row">
          <FilterGroup label="Severity">
            {severities.length === 0 && <span className="subm-muted">None in this list</span>}
            {severities.map((value) => (
              <FilterChip
                key={value}
                label={humanizeStatus(value)}
                color={`var(--sev-${value})`}
                count={severityFacet[value] ?? 0}
                selected={severityFilter.includes(value)}
                onToggle={() => toggleFacet(severityFilter, value, setSeverityFilter)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Platform">
            {platforms.length === 0 && <span className="subm-muted">None in this list</span>}
            {platforms.map((value) => (
              <FilterChip
                key={value}
                label={value === "none" ? "Not set" : platformLabel(value)}
                count={platformFacet[value] ?? 0}
                selected={platformFilter.includes(value)}
                onToggle={() => toggleFacet(platformFilter, value, setPlatformFilter)}
              />
            ))}
          </FilterGroup>
          <FilterGroup label="Changed">
            {RECENCY_OPTIONS.map((option) => (
              <FilterChip
                key={option.label}
                label={option.label}
                selected={recency === option.hours}
                onToggle={() => setRecency(option.hours)}
              />
            ))}
          </FilterGroup>
          <ClearFiltersButton count={activeFilterCount} onClear={clearFilters} />
        </div>
      </div>

      <div
        ref={shellRef}
        className="subm-shell"
        style={paneHeight ? { height: paneHeight, top: stickyTop } : undefined}
      >
        <SubmissionQueue
          listing={listing}
          loading={listingLoading}
          error={listingError}
          selectedSlug={selectedSlug}
          locked={locked}
          loadingMore={loadingMoreFindings}
          filterLabel={listingFilterLabel(readinessFilter)}
          filtersActive={activeFilterCount > 0}
          scope={scope}
          onClearFilters={clearFilters}
          onShowAll={() => { chooseScope("all"); setStateFilter(null); }}
          onSelect={selectFinding}
          onLoadMore={handleLoadMoreFindings}
          onRetry={() => setListingAttempt((attempt) => attempt + 1)}
        />
        <SubmissionDocument
          engagementKey={engagementKey}
          row={selectedRow}
          detail={detail}
          detailLoading={detailLoading}
          detailError={detailError}
          readiness={readiness}
          checkingReadiness={checkingReadiness}
          selection={selection}
          meta={meta}
          tab={tab}
          locked={locked}
          exporting={exporting}
          previewOutdated={previewOutdated}
          outsideList={selectedOutsideList ? listingFilterLabel(readinessFilter) : null}
          emptyList={listing && listing.findings.length === 0 ? (listing.counts.all === 0 ? "nothing-recorded" : "filtered") : null}
          loadingMoreVersions={loadingMoreVersions}
          loadingMorePending={loadingMorePending}
          onTab={chooseTab}
          onRefresh={() => selectedSlug && void loadDetail(selectedSlug, false)}
          onExport={openExport}
          onToggleAttachment={toggleAttachment}
          onReplaceAttachments={replaceAttachments}
          onAttachmentRows={(rows) => rememberMeta(rows.map(metaFromRow))}
          onLoadMoreVersions={() => void loadMoreDetail("versions")}
          onLoadMorePending={() => void loadMoreDetail("pending")}
        />
      </div>

      {exportOpen && detail && exportReadiness && (
        <ExportDialog
          detail={detail}
          readiness={exportReadiness}
          selection={selection}
          meta={meta}
          nextVersion={nextVersionNumber(detail)}
          exporting={exporting}
          error={exportError}
          onConfirm={() => void handleExport()}
          onClose={() => setExportOpen(false)}
        />
      )}
    </div>
  );
}
