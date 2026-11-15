// ── SubmissionsTab ────────────────────────────────────────────────────
// The submission desk: a server-filtered queue of findings. Opening a finding
// replaces the queue with the shared record view on its submission document
// (body, notes, package, versions, readiness), whose header carries the single
// primary action; Back, Escape and browser Back return to the queue. Export
// is the only irreversible action and always goes through ExportDialog.
//
// The shared "Needs attention" scope is the backend's "To do" listing; a
// state chip narrows it (a chip outside the scope widens it). The open
// finding and its section live in the address (`submission=`, `dtab=`); the
// filters and the loaded depth survive leaving the tab (sessionStorage).
// Attachment selections the operator changed are kept per finding for the
// visit, so stepping away from a record and back does not drop them.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Search, X } from "lucide-react";

import { ApiError, exportSubmissionVersion, recoverSubmissionExports } from "../lib/api";
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
import {
  DOCUMENT_TABS,
  RecoverExportsButton,
  RecoveryIssues,
  SubmissionDocument,
  type DocumentTab,
  type ViewMode,
} from "./submissions/SubmissionDocument";
import { RecordView, useResultsScrollMemory, type RecordNavigation } from "./record/RecordView";
import { useWindowedNavigation } from "./record/recordNavigation";
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
  /** `submission=` in the URL: the finding whose submission record is open. */
  initialSubmissionSlug?: string;
  /** `dtab=` in the URL: the open record's section (the body is the default). */
  initialDrawerTab?: string;
  /** Reports the engagement's "to do" count from each listing read, for the rail badge while open. */
  onToDoCount?: (count: number) => void;
  /** Called with the engagement's ready-to-export count from every listing read. */
  onReadyCount?: (count: number) => void;
};

const SEARCH_DEBOUNCE_MS = 250;
const READINESS_DEBOUNCE_MS = 350;
const RECORD_TITLE_ID = "submission-finding-title";

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

function SubmissionDesk({ engagementKey, refreshVersion = 0, initialSubmissionSlug, initialDrawerTab, onToDoCount, onReadyCount }: SubmissionsTabProps) {
  const { toast } = useToast();
  const [saved] = useState(() => readDeskView(engagementKey));
  const initialWindow = useRef(saved.loadedCount ?? SUBMISSION_PAGE_SIZE);

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
  const [loadMoreError, setLoadMoreError] = useState<string | null>(null);
  const loadingMoreRef = useRef(false);
  const listingRef = useRef<SubmissionDeskListing | null>(null);
  listingRef.current = listing;

  // ── Open record + detail ────────────────────────────────────────────
  // The finding whose record is open; null while the queue shows.
  const [openSlug, setOpenSlug] = useState<string | null>(initialSubmissionSlug || null);
  const openSlugRef = useRef(openSlug);
  openSlugRef.current = openSlug;
  // The open finding's last known queue row, kept when a refresh drops it from the list.
  const openRowRef = useRef<SubmissionDeskRow | null>(null);
  // The `submission=` and `dtab=` values the open record last followed (or wrote).
  const appliedRoute = useRef({ slug: initialSubmissionSlug, section: initialDrawerTab });
  // The row a record was opened from: focus returns there when it closes.
  const invokerRef = useRef<HTMLElement | null>(null);
  // A finding the address named that the engagement does not have.
  const [routeMiss, setRouteMiss] = useState<string | null>(null);
  const [detail, setDetail] = useState<SubmissionDeskDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const detailCache = useRef(new Map<string, SubmissionDeskDetail>());
  const detailGeneration = useRef(0);
  const [tab, setTab] = useState<DocumentTab>(documentTab(initialDrawerTab) ?? "body");
  const tabRef = useRef(tab);
  tabRef.current = tab;
  // Reading choices for the body and the notes; they hold across records.
  const [mode, setMode] = useState<ViewMode>("rendered");
  const [showWholeWorkspace, setShowWholeWorkspace] = useState(false);
  const [loadingMoreVersions, setLoadingMoreVersions] = useState(false);
  const [loadingMorePending, setLoadingMorePending] = useState(false);

  // ── Attachment selection + readiness ────────────────────────────────
  const [selection, setSelection] = useState<number[]>([]);
  const selectionRef = useRef(selection);
  selectionRef.current = selection;
  const selectionTouched = useRef(false);
  // Selections the operator changed, by finding: reopening a record or
  // stepping back to it restores the selection instead of the default set.
  const keptSelections = useRef(new Map<string, number[]>());
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
      const limit = Math.min(SUBMISSION_MAX_PAGE_SIZE, Math.max(SUBMISSION_PAGE_SIZE, replace ? initialWindow.current : loaded));
      initialWindow.current = SUBMISSION_PAGE_SIZE;
      try {
        const next = await listSubmissionDesk(engagementKey, {
          ...filterParams,
          findingOffset: 0,
          findingLimit: limit,
        });
        if (!current()) return;
        if (replace) setLoadMoreError(null);
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

  const writeHash = useCallback((slug: string | null, section: DocumentTab = "body", mode: "push" | "replace" = "push") => {
    appliedRoute.current = { slug: slug ?? undefined, section: slug && section !== "body" ? section : undefined };
    writeWorkspaceHash(
      engagementHref(engagementKey, { tab: "submissions", submission: slug ?? undefined, dtab: appliedRoute.current.section }),
      mode,
    );
  }, [engagementKey]);

  // The URL changing under the tab (Back / Forward, a link) opens its finding
  // and section; no `submission=` shows the queue.
  useEffect(() => {
    const applied = appliedRoute.current;
    if (applied.slug === initialSubmissionSlug && applied.section === initialDrawerTab) return;
    const slug = initialSubmissionSlug || null;
    const stepping = openSlugRef.current !== null && slug !== null;
    appliedRoute.current = { slug: initialSubmissionSlug, section: initialDrawerTab };
    if (!stepping) invokerRef.current = null;
    setRouteMiss(null);
    openSlugRef.current = slug;
    setOpenSlug(slug);
    setTab(documentTab(initialDrawerTab) ?? "body");
  }, [initialSubmissionSlug, initialDrawerTab]);

  // The filters and the loaded depth survive leaving the tab.
  useEffect(() => {
    const view: DeskView = {
      scope: scopeFellBack.current && scope === "all" ? "attention" : scope,
      state: stateFilter, severity: severityFilter, platform: platformFilter, recency, search: searchText,
      loadedCount: listing?.findings.length ?? saved.loadedCount,
    };
    try {
      window.sessionStorage.setItem(viewKey(engagementKey), JSON.stringify(view));
    } catch {
      // Browser storage may be unavailable; the view just resets next visit.
    }
  }, [engagementKey, scope, stateFilter, severityFilter, platformFilter, recency, searchText, listing, saved.loadedCount]);

  const openRow = useMemo(() => {
    const fresh = listing?.findings.find((row) => row.slug === openSlug) ?? null;
    if (fresh) openRowRef.current = fresh;
    return fresh ?? (openRowRef.current?.slug === openSlug ? openRowRef.current : null);
  }, [listing, openSlug]);

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
      if (cause instanceof ApiError && cause.status === 404 && openSlugRef.current === slug) {
        // No such finding: a record cannot stay open on it, so the queue shows and says why.
        setRouteMiss(slug);
        invokerRef.current = null;
        setOpenSlug(null);
        writeHash(null, "body", "replace");
        return;
      }
      setDetailError(errorMessage(cause, "Submission detail unavailable"));
    } finally {
      if (generation === detailGeneration.current) setDetailLoading(false);
    }
  }, [engagementKey, applyDetail, writeHash]);

  // Opening a finding shows its title at once, any cached state dimmed, and
  // never another finding's document. A selection the operator changed for
  // it earlier in the visit comes back; otherwise the default set applies.
  useEffect(() => {
    readinessGeneration.current += 1;
    setReadinessOverride(null);
    setLoadingMoreVersions(false);
    setLoadingMorePending(false);
    setExportOpen(false);
    setDetailError("");
    if (!openSlug) {
      detailGeneration.current += 1;
      setDetail(null);
      setDetailLoading(false);
      return;
    }
    const cached = detailCache.current.get(`${engagementKey}\n${openSlug}`) ?? null;
    setDetail(cached);
    const kept = keptSelections.current.get(openSlug);
    selectionTouched.current = kept !== undefined;
    setSelection(kept ?? (cached ? sortedIds(cached.default_attachment_ids) : []));
    void loadDetail(openSlug, kept === undefined);
  }, [engagementKey, openSlug, loadDetail]);

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

  const chooseAttachments = (ids: number[]) => {
    const slug = openSlugRef.current;
    if (!slug) return;
    const next = sortedIds(ids);
    selectionTouched.current = true;
    selectionRef.current = next;
    keptSelections.current.set(slug, next);
    setSelection(next);
  };
  const toggleAttachment = (id: number) => {
    const current = selectionRef.current;
    chooseAttachments(current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  };

  const previewOutdated = Boolean(
    openRow
    && detail
    && openRow.id === detail.finding.id
    && openRow.row_version !== detail.finding.row_version,
  );

  // Opening from the queue remembers the row and starts on the body;
  // stepping from an open record keeps the row the first one was opened from
  // and the open section, like the Findings record.
  const openFinding = (row: SubmissionDeskRow, invoker: HTMLElement) => {
    if (locked) return;
    invokerRef.current = invoker;
    setRouteMiss(null);
    openRowRef.current = row;
    setOpenSlug(row.slug);
    setTab("body");
    writeHash(row.slug);
  };
  const stepToFinding = useCallback((slug: string) => {
    setOpenSlug(slug);
    writeHash(slug, tabRef.current);
  }, [writeHash]);
  const closeFinding = useCallback(() => {
    setOpenSlug(null);
    writeHash(null);
  }, [writeHash]);
  const chooseTab = (next: DocumentTab) => {
    setTab(next);
    if (openSlugRef.current) writeHash(openSlugRef.current, next);
  };

  // Reads the next page of the queue: the "Load more" button, a step past
  // the loaded edge, or a linked finding further down the list.
  const filterParamsRef = useRef(filterParams);
  filterParamsRef.current = filterParams;
  const loadMoreFindings = useCallback(async () => {
    const page = listingRef.current?.findings_page;
    if (!page?.has_more || page.next_offset == null || loadingMoreRef.current) return;
    const runner = listingRunnerRef.current;
    loadingMoreRef.current = true;
    setLoadingMoreFindings(true);
    setLoadMoreError(null);
    try {
      const next = await listSubmissionDesk(engagementKey, {
        ...filterParamsRef.current,
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
      if (runner === listingRunnerRef.current) setLoadMoreError(errorMessage(cause, "More findings could not be loaded"));
    } finally {
      loadingMoreRef.current = false;
      setLoadingMoreFindings(false);
    }
  }, [engagementKey]);

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
      await Promise.all([
        openSlugRef.current === slug ? loadDetail(slug, false) : Promise.resolve(),
        loadListing("refresh"),
      ]);
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
        openSlugRef.current ? loadDetail(openSlugRef.current, false) : Promise.resolve(),
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
  const ready = counts?.ready;
  useEffect(() => {
    if (ready != null) onReadyCount?.(ready);
  }, [ready, onReadyCount]);
  const needWork = counts ? counts.blocked + counts.needs_draft : null;
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
  const exportReadiness = readiness && detail && readiness.final_ready && readiness.existing_version_number == null
    ? readiness
    : null;

  // Previous / Next walk the queue as loaded: a step past its edge reads the
  // next page, and a linked finding further down is read up to. A merged or
  // false-positive finding is in no list, so the queue is not read for it.
  const investigating = openSlug !== null;
  const order = useMemo(() => (listing?.findings ?? []).map((row) => row.slug), [listing]);
  const inNoList = detail?.finding.slug === openSlug
    && (detail?.finding.workflow_status === "merged" || detail?.finding.workflow_status === "false_positive");
  const queuePosition = useWindowedNavigation({
    order,
    current: openSlug,
    loaded: openSlug !== null && (order.includes(openSlug) || inNoList),
    window: {
      rows: listing?.findings ?? null,
      complete: listing ? !listing.findings_page.has_more : false,
      extending: loadingMoreFindings,
      extendError: loadMoreError,
      loadOlder: loadMoreFindings,
    },
    growsAt: "end",
    open: stepToFinding,
  });
  // An export or a recovery re-reads the open finding when it ends, so
  // stepping waits for it; Back stays live.
  const navigation: RecordNavigation = !listing && listingError
    ? { index: undefined, total: undefined, error: listingError }
    : locked
      ? { ...queuePosition, onPrevious: undefined, onNext: undefined }
      : queuePosition;
  const resultsRef = useRef<HTMLDivElement | null>(null);
  useResultsScrollMemory(resultsRef, investigating, { recordKey: openSlug });
  const stagingCount = listing?.staging_count ?? 0;

  return (
    <div className="findings-redesign subm-page">
      <PageHeader
        title="Submissions"
        purpose="Turn confirmed findings into immutable, exportable write-ups. Exporting never submits anything to the platform."
        stats={counts ? [
          { value: counts.all, label: "findings", title: "Every finding in the disclosure queue, including those not yet eligible" },
          { value: counts.not_candidate, label: "not eligible", title: "Verification or workflow state does not permit an export; review the finding first" },
          { value: counts.ready, label: "ready to export", title: listingFilterHint("ready") },
          { value: needWork, label: "need work", tone: needWork ? "warning" : undefined, title: "Blocked or still needing a rendered draft." },
          { value: counts.exported, label: "exported", title: listingFilterHint("exported") },
          { value: counts.filed, label: "filed", title: listingFilterHint("filed") },
        ] : []}
        status={listingLoading ? (listing ? "Updating…" : "Loading queue…") : null}
        actions={stagingCount > 0 ? (
          <RecoverExportsButton count={stagingCount} recovering={recovering} disabled={locked} onRecover={() => void handleRecovery()} />
        ) : undefined}
        hidden={investigating}
      >
        <ScopeToggle
          scope={scope}
          onChange={chooseScope}
          attentionCount={counts?.actionable}
          allCount={counts?.all}
          attentionRule={listingFilterHint("actionable")}
        />
      </PageHeader>

      {/* The queue (an open record replaces it; it stays mounted behind) */}
      <div ref={resultsRef} className="subm-results" hidden={investigating}>
        {routeMiss && (
          <p className="subm-header-notice" role="status">
            <span><strong>{routeMiss} is not one of this engagement&apos;s findings.</strong> The submission queue is shown.</span>
          </p>
        )}
        {recoveryIssues && !investigating && <RecoveryIssues issues={recoveryIssues} onDismiss={() => setRecoveryIssues(null)} />}
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

        <SubmissionQueue
          listing={listing}
          loading={listingLoading}
          error={listingError}
          locked={locked}
          loadingMore={loadingMoreFindings}
          loadMoreError={loadMoreError}
          filterLabel={listingFilterLabel(readinessFilter)}
          filtersActive={activeFilterCount > 0}
          scope={scope}
          onClearFilters={clearFilters}
          onShowAll={() => { chooseScope("all"); setStateFilter(null); }}
          onOpen={openFinding}
          onLoadMore={() => void loadMoreFindings()}
          onRetry={() => setListingAttempt((attempt) => attempt + 1)}
        />
        {listing && listing.findings.length > 0 && <div className="findings-shortcuts">
          <span><code>Enter</code> open</span>
          <span><code>[ / ]</code> previous / next in a record</span>
          <span><code>Esc</code> back to results</span>
        </div>}
      </div>

      {openSlug !== null && (
        <RecordView
          label="Submission"
          noun="submission"
          navigation={navigation}
          onBack={closeFinding}
          titleId={RECORD_TITLE_ID}
          returnFocusRef={invokerRef}
        >
          <SubmissionDocument
            key={openSlug}
            engagementKey={engagementKey}
            slug={openSlug}
            titleId={RECORD_TITLE_ID}
            row={openRow}
            // The detail held belongs to the finding it was read for: the one
            // just stepped to starts from its own (cached or loading) state.
            detail={detail?.finding.slug === openSlug ? detail : null}
            detailLoading={detailLoading}
            detailError={detailError}
            readiness={readiness}
            checkingReadiness={checkingReadiness}
            selection={selection}
            meta={meta}
            tab={tab}
            mode={mode}
            showWholeWorkspace={showWholeWorkspace}
            locked={locked}
            exporting={exporting}
            previewOutdated={previewOutdated}
            stagingCount={stagingCount}
            recovering={recovering}
            recoveryIssues={recoveryIssues}
            loadingMoreVersions={loadingMoreVersions}
            loadingMorePending={loadingMorePending}
            onTab={chooseTab}
            onMode={setMode}
            onShowWholeWorkspace={setShowWholeWorkspace}
            onRefresh={() => void loadDetail(openSlug, false)}
            onExport={openExport}
            onRecover={() => void handleRecovery()}
            onDismissRecoveryIssues={() => setRecoveryIssues(null)}
            onToggleAttachment={toggleAttachment}
            onReplaceAttachments={chooseAttachments}
            onAttachmentRows={(rows) => rememberMeta(rows.map(metaFromRow))}
            onLoadMoreVersions={() => void loadMoreDetail("versions")}
            onLoadMorePending={() => void loadMoreDetail("pending")}
          />
        </RecordView>
      )}

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
