import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download, FileArchive, RefreshCcw, ShieldCheck } from "lucide-react";

import {
  exportSubmissionVersion,
  getSubmissionDetail,
  listSubmissions,
  recoverSubmissionExports,
  submissionVersionDownloadUrl,
} from "../lib/api";
import type {
  SubmissionDetail,
  SubmissionFindingSummary,
  SubmissionListing,
  SubmissionPendingVersion,
  SubmissionRecoveryResult,
} from "../lib/api";
import { MarkdownBlock } from "./Markdown";


type SubmissionsTabProps = {
  engagementKey: string;
  refreshVersion?: number;
};

type ReviewMode = "preview" | "raw";
type FindingScope = "candidates" | "all";
type SubmissionPlatform = "bugcrowd" | "hackerone" | "direct";

const PLATFORM_LABELS: Record<SubmissionPlatform, string> = {
  bugcrowd: "Bugcrowd",
  hackerone: "HackerOne",
  direct: "Direct disclosure",
};

function formatBytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTimestamp(value: string | null): string {
  if (!value) return "pending";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function safeExternalHref(value: string): string | null {
  const candidate = value.trim();
  if (!candidate) return null;
  try {
    const url = new URL(candidate);
    return url.protocol === "https:" || url.protocol === "http:" ? candidate : null;
  } catch {
    return null;
  }
}

function isSubmissionPlatform(value: unknown): value is SubmissionPlatform {
  return value === "bugcrowd" || value === "hackerone" || value === "direct";
}

function isFilingCandidate(finding: SubmissionFindingSummary): boolean {
  return (
    (finding.verification_status === "confirmed" || finding.verification_status === "downgraded")
    && finding.submission_status === "none"
  );
}

function workspacePlatform(
  detail: SubmissionDetail | null,
  finding: SubmissionFindingSummary | null,
): SubmissionPlatform {
  const renderedPlatform = detail?.workspace.context.platform;
  if (isSubmissionPlatform(renderedPlatform)) return renderedPlatform;
  const recordedPlatform = finding?.submission_platform;
  return isSubmissionPlatform(recordedPlatform) ? recordedPlatform : "bugcrowd";
}

function PendingVersionRows({ versions }: { versions: SubmissionPendingVersion[] }) {
  return (
    <div className="submission-pending-list">
      {versions.map((version) => (
        <div className="submission-pending-row" key={version.id}>
          <strong>
            <code>{version.finding_slug}</code> · {version.status === "failed" ? "Failed" : "Staged"} version {version.version_number} (#{version.id})
          </strong>
          {version.failure_reason && <p>{version.failure_reason}</p>}
          <dl>
            <div>
              <dt>Staging</dt>
              <dd><code>{version.staging_relative_path}</code></dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd><code>{version.relative_path}</code></dd>
            </div>
          </dl>
        </div>
      ))}
    </div>
  );
}

export function SubmissionsTab({ engagementKey, refreshVersion = 0 }: SubmissionsTabProps) {
  const [listing, setListing] = useState<SubmissionListing | null>(null);
  const [selectedSlug, setSelectedSlug] = useState("");
  const [detail, setDetail] = useState<SubmissionDetail | null>(null);
  const [reviewMode, setReviewMode] = useState<ReviewMode>("preview");
  const [findingScope, setFindingScope] = useState<FindingScope>("candidates");
  const [selectedAttachments, setSelectedAttachments] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loadingMoreFindings, setLoadingMoreFindings] = useState(false);
  const [loadingMoreAttachments, setLoadingMoreAttachments] = useState(false);
  const [loadingMoreVersions, setLoadingMoreVersions] = useState(false);
  const [loadingMorePendingVersions, setLoadingMorePendingVersions] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [recoveryIssues, setRecoveryIssues] = useState<SubmissionRecoveryResult | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const listingRequestGeneration = useRef(0);
  const loadedListingEngagement = useRef("");
  const detailCache = useRef(new Map<string, SubmissionDetail>());
  const selectedFindingRef = useRef<{
    engagementKey: string;
    finding: SubmissionFindingSummary;
  } | null>(null);

  const refreshListing = useCallback(async () => {
    const requestGeneration = ++listingRequestGeneration.current;
    const next = await listSubmissions(engagementKey);
    if (requestGeneration !== listingRequestGeneration.current) return;
    const previousSelection = selectedFindingRef.current?.engagementKey === engagementKey
      ? selectedFindingRef.current.finding
      : null;
    const refreshedSelection = next.findings.find(
      (finding) => finding.slug === previousSelection?.slug,
    );
    const retainedSelection = !refreshedSelection && previousSelection && next.findings_page.has_more
      ? previousSelection
      : null;
    const filingCandidates = next.findings.filter(isFilingCandidate);
    if (filingCandidates.length === 0) setFindingScope("all");
    const selectedFinding = refreshedSelection
      ?? retainedSelection
      ?? filingCandidates[0]
      ?? next.findings[0]
      ?? null;
    const findings = retainedSelection ? [...next.findings, retainedSelection] : next.findings;
    selectedFindingRef.current = selectedFinding
      ? { engagementKey, finding: selectedFinding }
      : null;
    setListing({ ...next, findings });
    setSelectedSlug(selectedFinding?.slug ?? "");
  }, [engagementKey]);

  const refreshDetail = useCallback(async () => {
    if (!selectedSlug) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    try {
      const next = await getSubmissionDetail(engagementKey, selectedSlug);
      detailCache.current.set(`${engagementKey}\n${selectedSlug}`, next);
      setDetail(next);
    } finally {
      setDetailLoading(false);
    }
  }, [engagementKey, selectedSlug]);

  useEffect(() => {
    let cancelled = false;
    const initialLoad = loadedListingEngagement.current !== engagementKey;
    if (initialLoad) setLoading(true);
    setError("");
    void refreshListing()
      .then(() => {
        if (!cancelled) loadedListingEngagement.current = engagementKey;
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "Submission data unavailable");
      })
      .finally(() => {
        if (!cancelled && initialLoad) setLoading(false);
      });
    return () => {
      cancelled = true;
      listingRequestGeneration.current += 1;
    };
  }, [refreshListing, refreshVersion]);

  useEffect(() => {
    let cancelled = false;
    setSelectedAttachments(new Set());
    setNotice("");
    setError("");
    if (!selectedSlug) {
      setDetail(null);
      return () => {
        cancelled = true;
      };
    }
    const cacheKey = `${engagementKey}\n${selectedSlug}`;
    setDetail(detailCache.current.get(cacheKey) ?? null);
    setDetailLoading(true);
    void getSubmissionDetail(engagementKey, selectedSlug)
      .then((next) => {
        if (!cancelled) {
          detailCache.current.set(cacheKey, next);
          setDetail(next);
        }
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "Submission detail unavailable");
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, selectedSlug]);

  const selectedFinding = useMemo(
    () => listing?.findings.find((finding) => finding.slug === selectedSlug) ?? null,
    [listing, selectedSlug],
  );
  const filingCandidates = useMemo(
    () => listing?.findings.filter(isFilingCandidate) ?? [],
    [listing],
  );
  const visibleFindings = findingScope === "candidates"
    ? filingCandidates
    : listing?.findings ?? [];
  const platform = workspacePlatform(detail, selectedFinding);
  const externalHref = safeExternalHref(selectedFinding?.submission_url ?? "");
  const hasExternalRecord = Boolean(
    selectedFinding
    && (
      (selectedFinding.submission_status && selectedFinding.submission_status !== "none")
      || selectedFinding.submission_platform
      || selectedFinding.submission_ref
      || selectedFinding.submission_url
    ),
  );
  const latestVersion = detail?.versions.reduce(
    (latest, version) => (
      !latest || version.version_number > latest.version_number ? version : latest
    ),
    detail.versions[0] ?? null,
  ) ?? null;
  const latestVersionMatchesMarkdown = Boolean(
    latestVersion
    && detail?.workspace.present
    && latestVersion.submission_sha256 === detail.workspace.submission_sha256,
  );
  const previewOutdated = Boolean(
    selectedFinding
    && detail
    && selectedFinding.id === detail.finding.id
    && selectedFinding.row_version !== detail.finding.row_version,
  );
  const selectedCount = selectedAttachments.size;
  const detailedFailedVersionIds = new Set(
    detail?.pending_versions
      .filter((version) => version.status === "failed")
      .map((version) => version.id) ?? [],
  );
  const responseOnlyRecoveryFailures = recoveryIssues?.failed_versions.filter(
    (version) => !detailedFailedVersionIds.has(version.id),
  ) ?? [];
  const showRecoveryIssues = responseOnlyRecoveryFailures.length > 0
    || (recoveryIssues?.orphaned_staging_paths.length ?? 0) > 0;

  const toggleAttachment = (artifactId: number) => {
    setSelectedAttachments((current) => {
      const next = new Set(current);
      if (next.has(artifactId)) next.delete(artifactId);
      else next.add(artifactId);
      return next;
    });
  };

  const handleRefreshPreview = () => {
    setError("");
    void refreshDetail().catch((cause: unknown) => {
      setError(cause instanceof Error ? cause.message : "Submission detail unavailable");
    });
  };

  const selectFindingScope = (scope: FindingScope) => {
    setFindingScope(scope);
    if (scope === "candidates" && !filingCandidates.some((finding) => finding.slug === selectedSlug)) {
      const nextFinding = filingCandidates[0];
      if (nextFinding) {
        selectedFindingRef.current = { engagementKey, finding: nextFinding };
        setSelectedSlug(nextFinding.slug);
      }
    }
  };

  const handleLoadMoreFindings = async () => {
    const page = listing?.findings_page;
    // `page` is captured before the guard, so it needs its own null check for the
    // narrowing to hold; `!listing` already made this unreachable at runtime.
    if (!listing || !page || loadingMoreFindings || !page.has_more || page.next_offset == null) return;
    setLoadingMoreFindings(true);
    setError("");
    const requestGeneration = ++listingRequestGeneration.current;
    try {
      const next = await listSubmissions(engagementKey, {
        findingOffset: page.next_offset,
        findingLimit: page.limit,
      });
      if (requestGeneration !== listingRequestGeneration.current) return;
      setListing((current) => {
        if (!current) return current;
        const findings = new Map(current.findings.map((finding) => [finding.id, finding]));
        for (const finding of next.findings) findings.set(finding.id, finding);
        return { ...next, findings: [...findings.values()] };
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "More findings could not be loaded");
    } finally {
      setLoadingMoreFindings(false);
    }
  };

  const handleLoadMoreAttachments = async () => {
    const page = detail?.eligible_attachments_page;
    if (
      !detail
      || !page
      || loadingMoreAttachments
      || exporting
      || recovering
      || !page.has_more
      || page.next_offset == null
    ) return;
    const findingSlug = selectedSlug;
    setLoadingMoreAttachments(true);
    setError("");
    try {
      const next = await getSubmissionDetail(engagementKey, findingSlug, {
        attachmentOffset: page.next_offset,
        attachmentLimit: page.limit,
      });
      setDetail((current) => {
        if (!current || current.finding.slug !== findingSlug) return current;
        const candidates = new Map(
          current.eligible_attachments.map((artifact) => [artifact.id, artifact]),
        );
        for (const artifact of next.eligible_attachments) candidates.set(artifact.id, artifact);
        return {
          ...current,
          eligible_attachments: [...candidates.values()],
          eligible_attachments_page: next.eligible_attachments_page,
        };
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "More attachments could not be loaded");
    } finally {
      setLoadingMoreAttachments(false);
    }
  };

  const handleLoadMoreVersions = async () => {
    const page = detail?.versions_page;
    if (!detail || !page || loadingMoreVersions || !page.has_more || page.next_offset == null) return;
    const findingSlug = selectedSlug;
    setLoadingMoreVersions(true);
    setError("");
    try {
      const next = await getSubmissionDetail(engagementKey, findingSlug, {
        versionOffset: page.next_offset,
        versionLimit: page.limit,
      });
      setDetail((current) => {
        if (!current || current.finding.slug !== findingSlug) return current;
        const versions = new Map(current.versions.map((version) => [version.id, version]));
        for (const version of next.versions) versions.set(version.id, version);
        return {
          ...current,
          versions: [...versions.values()],
          versions_page: next.versions_page,
        };
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "More versions could not be loaded");
    } finally {
      setLoadingMoreVersions(false);
    }
  };

  const handleLoadMorePendingVersions = async () => {
    const page = detail?.pending_versions_page;
    if (!detail || !page || loadingMorePendingVersions || !page.has_more || page.next_offset == null) return;
    const findingSlug = selectedSlug;
    setLoadingMorePendingVersions(true);
    setError("");
    try {
      const next = await getSubmissionDetail(engagementKey, findingSlug, {
        pendingVersionOffset: page.next_offset,
        pendingVersionLimit: page.limit,
      });
      setDetail((current) => {
        if (!current || current.finding.slug !== findingSlug) return current;
        const versions = new Map(current.pending_versions.map((version) => [version.id, version]));
        for (const version of next.pending_versions) versions.set(version.id, version);
        return {
          ...current,
          pending_versions: [...versions.values()],
          pending_versions_page: next.pending_versions_page,
        };
      });
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "More incomplete exports could not be loaded",
      );
    } finally {
      setLoadingMorePendingVersions(false);
    }
  };

  const handleExport = async () => {
    if (!detail?.workspace.final_ready || exporting || recovering || loadingMoreAttachments) return;
    setExporting(true);
    setError("");
    setNotice("");
    try {
      const version = await exportSubmissionVersion(engagementKey, selectedSlug, {
        platform,
        submission_path: detail.workspace.submission_path,
        context_path: detail.workspace.context_path,
        attachment_ids: [...selectedAttachments].sort((a, b) => a - b),
        actor_surface: "web-ui",
      });
      setNotice(
        version.idempotent_replay
          ? `Version ${version.version_number} already captured these exact sources.`
          : `Immutable version ${version.version_number} exported.`,
      );
      await Promise.all([refreshDetail(), refreshListing()]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Submission export failed");
    } finally {
      setExporting(false);
    }
  };

  const handleRecovery = async () => {
    if (recovering || exporting || loadingMoreAttachments) return;
    setRecovering(true);
    setRecoveryIssues(null);
    setError("");
    setNotice("");
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
        if (seenCursors.has(cursor)) {
          throw new Error("Recovery diagnostic pagination made no progress");
        }
        seenCursors.add(cursor);
        page = await recoverSubmissionExports(engagementKey, "web-ui", {
          failedVersionOffset,
          orphanAfter,
        });
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
      setNotice(
        result.recovered_version_ids.length > 0
          ? `Recovered ${result.recovered_version_ids.length} staged export.`
          : "No staged export could be completed.",
      );
      await refreshDetail();
      await refreshListing();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Submission recovery failed");
    } finally {
      setRecovering(false);
    }
  };

  if (loading) {
    return <section className="submission-loading panel" aria-busy="true">Loading submission workspace…</section>;
  }

  if (error && !listing) {
    return (
      <section className="submission-empty panel">
        <p className="eyebrow">Submission workspace</p>
        <h2>Submission data unavailable</h2>
        <p className="submission-message is-error" role="alert">{error}</p>
      </section>
    );
  }

  if (!listing?.findings.length) {
    return (
      <section className="submission-empty panel">
        <p className="eyebrow">Submission workspace</p>
        <h2>No findings to review</h2>
        <p>Verified findings will appear here without changing the operator CLI workflow.</p>
      </section>
    );
  }

  return (
    <section className="submissions-workspace">
      <aside className="submission-rail panel" aria-label="Submission findings">
        <div className="submission-rail-heading">
          <div>
            <p className="eyebrow">Filing desk</p>
            <h2>Submissions</h2>
          </div>
          <div className="submission-rail-actions">
            {listing.failed_count > 0 && (
              <span
                className="submission-failed-count"
                role="status"
                aria-label={`${listing.failed_count} failed export reservation${listing.failed_count === 1 ? "" : "s"}`}
              >
                {listing.failed_count} failed
              </span>
            )}
            {listing.staging_count > 0 && (
              <button
                type="button"
                className="submission-recover-button"
                onClick={handleRecovery}
                disabled={recovering || exporting || loadingMoreAttachments}
                title="Verify and complete recoverable staged exports"
              >
                <RefreshCcw size={14} aria-hidden="true" />
                {recovering ? "Recovering…" : "Recover staged exports"}
              </button>
            )}
          </div>
        </div>
        <div className="submission-finding-scopes" role="group" aria-label="Submission queue scope">
          <button
            type="button"
            aria-pressed={findingScope === "candidates"}
            className={findingScope === "candidates" ? "is-active" : ""}
            onClick={() => selectFindingScope("candidates")}
            disabled={filingCandidates.length === 0 || exporting || recovering || loadingMoreAttachments}
          >
            Candidates <span>{filingCandidates.length}</span>
          </button>
          <button
            type="button"
            aria-pressed={findingScope === "all"}
            className={findingScope === "all" ? "is-active" : ""}
            onClick={() => selectFindingScope("all")}
            disabled={exporting || recovering || loadingMoreAttachments}
          >
            All / history <span>{listing.findings_page.total}</span>
          </button>
        </div>
        <div className="submission-finding-list">
          {visibleFindings.map((finding: SubmissionFindingSummary) => (
            <button
              type="button"
              key={finding.slug}
              className={`submission-finding ${finding.slug === selectedSlug ? "is-selected" : ""}`}
              onClick={() => {
                selectedFindingRef.current = { engagementKey, finding };
                setSelectedSlug(finding.slug);
              }}
              disabled={exporting || recovering || loadingMoreAttachments}
            >
              <span className={`submission-severity severity-${finding.severity}`} aria-hidden="true" />
              <span className="submission-finding-copy">
                <strong title={finding.title}>{finding.title}</strong>
                <span>
                  <code>{finding.slug}</code>
                  <span>{finding.verification_status.replace(/_/g, " ")}</span>
                </span>
              </span>
              <span className="submission-finding-counts">
                {finding.failed_version_count > 0 && (
                  <span className="submission-finding-failed-count">
                    {finding.failed_version_count} failed
                  </span>
                )}
                <span
                  className="submission-version-count"
                  aria-label={`${finding.version_count} immutable version${finding.version_count === 1 ? "" : "s"}`}
                >
                  {finding.version_count}
                </span>
              </span>
            </button>
          ))}
        </div>
        {listing.findings_page.has_more && (
          <button
            type="button"
            onClick={handleLoadMoreFindings}
            disabled={loadingMoreFindings || exporting || recovering}
          >
            {loadingMoreFindings ? "Loading findings…" : "Load more findings"}
          </button>
        )}
      </aside>

      <div className="submission-main">
        <header className="submission-titlebar">
          <div>
            <p className="eyebrow">{selectedFinding?.slug ?? selectedSlug}</p>
            <h2 title={selectedFinding?.title}>{selectedFinding?.title ?? "Submission review"}</h2>
            <p>
              {PLATFORM_LABELS[platform]} · backend finding row {selectedFinding?.row_version ?? "—"}
            </p>
          </div>
          <div className="submission-title-status">
            <span className={detail?.workspace.final_ready ? "is-ready" : "is-blocked"}>
              <ShieldCheck size={14} aria-hidden="true" />
              {detailLoading
                ? "Checking draft readiness…"
                : detail?.workspace.final_ready
                  ? "Draft final-ready"
                  : "Draft review required"}
            </span>
            <span className={latestVersionMatchesMarkdown ? "is-ready" : "is-stale"}>
              <FileArchive size={14} aria-hidden="true" />
              {detailLoading
                ? "Checking immutable version…"
                : !latestVersion
                  ? "No immutable version yet"
                  : !detail?.workspace.present
                    ? `Latest v${latestVersion.version_number}; no current Markdown`
                  : latestVersionMatchesMarkdown
                    ? `Latest v${latestVersion.version_number} matches current Markdown`
                    : `Latest v${latestVersion.version_number} differs from current Markdown`}
            </span>
          </div>
        </header>

        {selectedFinding && hasExternalRecord && (
          <section
            className="submission-external-record"
            aria-label="External submission record"
          >
            {selectedFinding.submission_status !== "none" && (
              <div>
                <span>Status</span>
                <strong>{selectedFinding.submission_status.replace(/_/g, " ")}</strong>
              </div>
            )}
            {selectedFinding.submission_platform.trim() && (
              <div>
                <span>Platform</span>
                <strong>{selectedFinding.submission_platform}</strong>
              </div>
            )}
            {selectedFinding.submission_ref.trim() && (
              <div>
                <span>Reference</span>
                <code>{selectedFinding.submission_ref}</code>
              </div>
            )}
            {selectedFinding.submission_url.trim() && (
              <div>
                <span>Submission URL</span>
                {externalHref ? (
                  <a href={externalHref} target="_blank" rel="noopener noreferrer">
                    {selectedFinding.submission_url}
                  </a>
                ) : (
                  <code>{selectedFinding.submission_url}</code>
                )}
              </div>
            )}
          </section>
        )}

        {error && <div className="submission-message is-error" role="alert">{error}</div>}
        {notice && <div className="submission-message is-notice" role="status">{notice}</div>}
        {previewOutdated && (
          <div className="submission-message is-update" role="status">
            <span>The finding changed while you were reviewing this preview.</span>
            <button type="button" onClick={handleRefreshPreview} disabled={detailLoading}>
              {detailLoading ? "Refreshing preview…" : "Refresh preview"}
            </button>
          </div>
        )}
        {recoveryIssues && showRecoveryIssues && (
          <div className="submission-message is-error submission-recovery-issues" role="alert">
            <strong>Recovery incomplete.</strong>
            {responseOnlyRecoveryFailures.length > 0 && (
              <PendingVersionRows versions={responseOnlyRecoveryFailures} />
            )}
            {recoveryIssues.orphaned_staging_paths.length > 0 && (
              <div>
                <p>
                  Orphaned staging path{recoveryIssues.orphaned_staging_paths.length === 1 ? "" : "s"}:
                </p>
                <ul>
                  {recoveryIssues.orphaned_staging_paths.map((path) => <li key={path}><code>{path}</code></li>)}
                </ul>
              </div>
            )}
          </div>
        )}

        {detailLoading && !detail ? (
          <div className="submission-document panel" aria-busy="true">Loading reviewed document…</div>
        ) : !detail ? (
          <div className="submission-document panel">Submission detail unavailable.</div>
        ) : (
          <div className="submission-review-grid">
            <article className="submission-document panel">
              <div className="submission-document-toolbar">
                <div role="group" aria-label="Submission document view">
                  <button
                    type="button"
                    aria-pressed={reviewMode === "preview"}
                    className={reviewMode === "preview" ? "is-active" : ""}
                    onClick={() => setReviewMode("preview")}
                  >
                    Rendered preview
                  </button>
                  <button
                    type="button"
                    aria-pressed={reviewMode === "raw"}
                    className={reviewMode === "raw" ? "is-active" : ""}
                    onClick={() => setReviewMode("raw")}
                  >
                    Raw Markdown
                  </button>
                </div>
                <code>{detail.workspace.submission_sha256.slice(0, 12)}</code>
              </div>
              {!detail.workspace.present ? (
                <div className="submission-no-draft">
                  <h3>No rendered workspace</h3>
                  <p>Run the existing CLI renderer for this finding, then return here to review it.</p>
                  <code>vigil assess export submission {selectedSlug} --platform {platform} --draft</code>
                  <p>After addressing its diagnostics, rerun without <code>--draft</code> to make it final-ready.</p>
                </div>
              ) : reviewMode === "preview" ? (
                <div className="submission-markdown">
                  <MarkdownBlock text={detail.workspace.markdown} />
                </div>
              ) : (
                <pre className="submission-raw">{detail.workspace.markdown}</pre>
              )}
            </article>

            <aside className="submission-ledger">
              <section className="submission-ledger-section panel">
                <div className="submission-ledger-heading">
                  <div>
                    <p className="eyebrow">Package</p>
                    <h3>Attachments</h3>
                  </div>
                  <span>{selectedCount === 0 ? "No attachments selected" : `${selectedCount} attachment${selectedCount === 1 ? "" : "s"} selected`}</span>
                </div>
                <p className="submission-help">Only registered, present artifacts are offered. Every selected file is re-hashed at export.</p>
                <p className="submission-attachment-page-count">
                  Showing {detail.eligible_attachments.length} of {detail.eligible_attachments_page.total} eligible artifacts.
                </p>
                <div className="submission-attachment-list">
                  {detail.eligible_attachments.length === 0 ? (
                    <p className="submission-muted">No eligible artifacts are registered.</p>
                  ) : detail.eligible_attachments.map((artifact) => (
                    <label key={artifact.id} className="submission-attachment">
                      <input
                        type="checkbox"
                        aria-label={`Attach ${artifact.relative_path}`}
                        checked={selectedAttachments.has(artifact.id)}
                        onChange={() => toggleAttachment(artifact.id)}
                      />
                      <span>
                        <strong>{artifact.relative_path}</strong>
                        <small>#{artifact.id} · {formatBytes(artifact.size_bytes)} · {artifact.kind}</small>
                      </span>
                    </label>
                  ))}
                </div>
                {detail.eligible_attachments_page.has_more && (
                  <div className="submission-attachment-pagination">
                    <p>The bounded attachment page is truncated.</p>
                    <button
                      type="button"
                      onClick={handleLoadMoreAttachments}
                      disabled={loadingMoreAttachments || exporting || recovering}
                    >
                      {loadingMoreAttachments ? "Loading attachments…" : "Load more attachments"}
                    </button>
                  </div>
                )}
                {detail.workspace.blockers.length > 0 && (
                  <div className="submission-blockers">
                    {detail.workspace.blockers.map((blocker) => <p key={blocker}>{blocker}</p>)}
                  </div>
                )}
                <button
                  type="button"
                  className="primary-button submission-export-button"
                  disabled={
                    !detail.workspace.final_ready
                    || exporting
                    || recovering
                    || loadingMoreAttachments
                  }
                  onClick={handleExport}
                >
                  <FileArchive size={15} aria-hidden="true" />
                  {exporting ? "Verifying and staging…" : "Export immutable version"}
                </button>
              </section>

              {detail.pending_versions.length > 0 && (
                <section
                  className="submission-ledger-section panel submission-pending-versions"
                  aria-label="Incomplete export reservations"
                >
                  <div className="submission-ledger-heading">
                    <div>
                      <p className="eyebrow">Needs attention</p>
                      <h3>Incomplete exports</h3>
                    </div>
                    <span>{detail.pending_version_count}</span>
                  </div>
                  <PendingVersionRows versions={detail.pending_versions} />
                  {detail.pending_versions_page.has_more && (
                    <button
                      type="button"
                      onClick={handleLoadMorePendingVersions}
                      disabled={loadingMorePendingVersions || exporting || recovering}
                    >
                      {loadingMorePendingVersions
                        ? "Loading incomplete exports…"
                        : "Load more incomplete exports"}
                    </button>
                  )}
                </section>
              )}

              <section className="submission-ledger-section panel">
                <div className="submission-ledger-heading">
                  <div>
                    <p className="eyebrow">Append-only</p>
                    <h3>Version history</h3>
                  </div>
                  <span>{detail.versions_page.total}</span>
                </div>
                {detail.versions.length === 0 ? (
                  <p className="submission-muted">No immutable exports yet.</p>
                ) : (
                  <div className="submission-history">
                    {detail.versions.map((version) => (
                      <div className="submission-history-row" key={version.id}>
                        <div>
                          <strong>Version {version.version_number}</strong>
                          {version.stale && <span className="submission-stale">stale</span>}
                          <small>
                            {version.package_format.toUpperCase()} · {version.attachment_count} attachment{version.attachment_count === 1 ? "" : "s"}
                          </small>
                          <small>{formatTimestamp(version.completed_at)} · {version.actor_surface}</small>
                        </div>
                        <a
                          href={submissionVersionDownloadUrl(engagementKey, selectedSlug, version.version_number)}
                          download
                        >
                          <Download size={14} aria-hidden="true" /> Download v{version.version_number}
                        </a>
                      </div>
                    ))}
                  </div>
                )}
                {detail.versions_page.has_more && (
                  <button
                    type="button"
                    onClick={handleLoadMoreVersions}
                    disabled={loadingMoreVersions || exporting || recovering}
                  >
                    {loadingMoreVersions ? "Loading versions…" : "Load more versions"}
                  </button>
                )}
              </section>
            </aside>
          </div>
        )}
      </div>
    </section>
  );
}
