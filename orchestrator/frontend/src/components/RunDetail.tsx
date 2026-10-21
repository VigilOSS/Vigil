// ── RunDetail ─────────────────────────────────────────────────────────
// One run's record, rendered inside the shared RecordView (RunsTab owns the
// view, the list order and the URL). Sections follow what an operator asks:
// what was this run for and which findings it supports (Overview), what
// evidence it recorded (Evidence), what still blocks it (Blockers), and the
// full audit record (Audit details).
//
// The run itself comes from the list row (the backend serializes the same
// projection for both), so opening a run costs nothing until a section that
// pages its child records is shown.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  ApiError,
  getAssessmentRunComparison,
  listAssessmentRunChildren,
  type AssessmentRun,
  type AssessmentRunChild,
  type RunComparison,
} from "../lib/api";
import { createCoalescedRunner } from "../lib/coalesce";
import {
  AUDIT_RECORD_SECTIONS,
  EVIDENCE_KIND_LABELS,
  EVIDENCE_SECTIONS,
  appendAuditPage,
  blockerDestination,
  currentBlockers,
  dispatchProvenance,
  elapsedLabel,
  evidenceMixLabel,
  isEvidenceSection,
  lifecyclePresentation,
  normalizedComparison,
  runClientModel,
  runFindingLinks,
  runHealth,
  statusText,
  type RunAuditSection,
  type RunFindingRelation,
} from "../lib/runAudit";
import { formatDuration, parseServerTime } from "../lib/serverTime";
import { engagementHref } from "../lib/workspaceRoutes";
import { JsonView } from "./JsonView";
import { CardSkeleton } from "./Skeletons";
import { TimeStamp } from "./formatting";
import { RecordBody, RecordCopyLinkButton, RecordHeader, RecordTabs } from "./record/RecordView";
import { RunHealthChip } from "./RunHealthChip";
import { EmptyState, SegmentedControl, StatusPill, humanizeStatus, statusLabel, statusTone } from "./ui";

const CHILD_PAGE_SIZE = 50;
// The child-record endpoints' largest page; a refresh re-reads more in steps.
const MAX_CHILD_READ = 1000;

const RELATION_LABELS: Record<RunFindingRelation, string> = {
  cited: "the finding's verification cites this run's evidence",
  associated: "run started to verify it",
  dispatched: "the agent was dispatched for it",
};

const COUNT_LABELS: Record<string, string> = {
  inventory_total: "Sources inventoried",
  inventory_included: "Sources included",
  inventory_excluded: "Sources excluded",
  inventory_missing: "Sources missing",
  source_reads: "Source reads",
  obligations: "Obligations",
  open_hard_obligations: "Open hard obligations",
  candidates: "Candidates",
  open_candidates: "Open candidates",
  tool_signals: "Tool signals",
  discovery_passes: "Discovery passes",
  code_receipt_links: "Code receipt links",
  findings: "Findings citing evidence",
  proof_receipts: "Evidence receipts",
};

export function rowDomId(section: RunAuditSection, id: number | string | undefined): string | undefined {
  return id === undefined ? undefined : `run-audit-${section}-${String(id).replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

// ── Paged child records ───────────────────────────────────────────────

type ChildPage = {
  identity: string;
  items: AssessmentRunChild[];
  total: number;
  nextOffset: number;
  hasMore: boolean;
};

/**
 * One section's records for one run. Every read goes through one coalesced
 * queue (one request in flight, one trailing pass): a live refresh re-reads
 * every row already loaded, so "Load more" pages survive it, and "Load more"
 * waits for an in-flight refresh instead of racing it. The previous rows stay
 * visible meanwhile; a failed read keeps the last recorded ledger beside the
 * error.
 */
function useRunChildren(
  engagementKey: string,
  runId: number,
  section: RunAuditSection,
  enabled: boolean,
  refreshVersion: number,
) {
  const identity = `${engagementKey}:${runId}:${section}`;
  const [page, setPage] = useState<ChildPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const identityRef = useRef(identity);
  identityRef.current = identity;
  const pageRef = useRef<ChildPage | null>(null);
  pageRef.current = page;
  // What the next pass owes: a re-read of everything loaded, and/or one more page.
  const wanted = useRef({ refresh: false, more: false });

  const runner = useMemo(() => createCoalescedRunner(async () => {
    const { refresh, more } = wanted.current;
    wanted.current = { refresh: false, more: false };
    const loaded = pageRef.current?.identity === identity ? pageRef.current : null;
    if (!refresh && !(more && loaded?.hasMore) && loaded) return;
    setLoading(true);
    try {
      let next: ChildPage;
      if (!refresh && loaded) {
        const read = await listAssessmentRunChildren(engagementKey, runId, section, { limit: CHILD_PAGE_SIZE, offset: loaded.nextOffset });
        const merged = appendAuditPage(loaded.items, read);
        next = { identity, items: merged.items, total: read.total, nextOffset: merged.nextOffset, hasMore: merged.hasMore };
      } else {
        // Re-read from the top as many rows as are shown (plus the page asked for).
        const want = Math.max(CHILD_PAGE_SIZE, (loaded?.items.length ?? 0) + (more && loaded?.hasMore ? CHILD_PAGE_SIZE : 0));
        next = { identity, items: [], total: 0, nextOffset: 0, hasMore: true };
        // Further steps only when a step was capped at the endpoint's largest page.
        for (let full = true; full && next.hasMore && next.items.length < want;) {
          const limit = Math.min(MAX_CHILD_READ, want - next.items.length);
          const read = await listAssessmentRunChildren(engagementKey, runId, section, { limit, offset: next.nextOffset });
          if (identityRef.current !== identity) return;
          const merged = appendAuditPage(next.items, read);
          next = { identity, items: merged.items, total: read.total, nextOffset: merged.nextOffset, hasMore: merged.hasMore };
          full = read.items.length === limit;
        }
      }
      if (identityRef.current !== identity) return;
      pageRef.current = next;
      setPage(next);
      setError(null);
    } catch (failure) {
      if (identityRef.current !== identity) return;
      setError(failure instanceof Error ? failure.message : "Failed to load run records");
    } finally {
      if (identityRef.current === identity) setLoading(false);
    }
  }), [engagementKey, runId, section, identity]);

  useEffect(() => {
    if (!enabled) return;
    setError(null);
    // Shown again with rows already loaded: re-read them. A first load joins
    // (StrictMode repeats it) and needs no flag: a pass with nothing loaded reads.
    if (pageRef.current?.identity === identity) {
      wanted.current.refresh = true;
      void runner("refresh");
    } else {
      void runner("join");
    }
  }, [enabled, identity, runner]);

  const seenVersion = useRef(refreshVersion);
  useEffect(() => {
    if (seenVersion.current === refreshVersion) return;
    seenVersion.current = refreshVersion;
    if (!enabled) return;
    wanted.current.refresh = true;
    void runner("refresh");
  }, [enabled, refreshVersion, runner]);

  const loadMore = useCallback(async () => {
    if (page?.identity !== identity) return;
    wanted.current.more = true;
    await runner("refresh");
  }, [identity, page, runner]);

  const current = page?.identity === identity ? page : null;
  return {
    items: current?.items ?? [],
    total: current?.total ?? 0,
    hasMore: current?.hasMore ?? false,
    loaded: current !== null,
    loading,
    error,
    loadMore,
  };
}

type ChildStream = ReturnType<typeof useRunChildren>;

// Scroll to a deep-linked record, paging forward until it appears.
function useFocusedRecord(stream: ChildStream, section: RunAuditSection, focusedObject: string | undefined) {
  const scrolledTo = useRef("");
  useEffect(() => {
    if (!focusedObject || !stream.loaded || stream.loading || stream.error) return;
    const target = `${section}:${focusedObject}`;
    const element = document.getElementById(rowDomId(section, focusedObject) ?? "");
    if (element) {
      // Once per link: later refreshes must not yank the operator's scroll.
      if (scrolledTo.current !== target) element.scrollIntoView?.({ block: "center", behavior: "smooth" });
      scrolledTo.current = target;
      return;
    }
    if (stream.hasMore) void stream.loadMore();
  }, [focusedObject, section, stream]);
  return Boolean(
    focusedObject
      && stream.loaded
      && !stream.loading
      && !stream.error
      && !stream.hasMore
      && !stream.items.some((row) => String(row.id) === focusedObject),
  );
}

function StreamStatus({ stream, noun }: { stream: ChildStream; noun: string }) {
  return (
    <>
      {stream.error && (
        <p className="error-text" role="alert">
          {stream.error}{stream.items.length > 0 && " · Showing last recorded ledger."}
        </p>
      )}
      {!stream.loaded && !stream.error && <CardSkeleton lines={3} />}
      {stream.loaded && stream.items.length === 0 && !stream.error && (
        <EmptyState variant="empty" compact title={`No ${noun} recorded for this run.`} />
      )}
    </>
  );
}

function LoadMore({ stream }: { stream: ChildStream }) {
  if (!stream.hasMore) return null;
  return (
    <button type="button" className="qa-btn run-page-more" disabled={stream.loading} onClick={() => void stream.loadMore()}>
      {stream.loading ? "Loading…" : `Load more · ${Math.max(0, stream.total - stream.items.length)} remaining`}
    </button>
  );
}

// ── Evidence receipts ─────────────────────────────────────────────────

function ReceiptCard({
  engagementKey,
  receipt,
  runId,
  section,
  focused,
}: {
  engagementKey: string;
  receipt: AssessmentRunChild;
  runId: number;
  section: RunAuditSection;
  focused: boolean;
}) {
  const kind = String(receipt.evidence_kind ?? "");
  const health = String(receipt.evidence_health ?? "healthy");
  const unhealthy = health !== "healthy";
  const command = receipt.command && typeof receipt.command === "object"
    ? receipt.command as Record<string, unknown>
    : null;
  const originRun = typeof receipt.origin_run_id === "number" ? receipt.origin_run_id : null;
  const integrity = [
    ["Evidence SHA-256", receipt.evidence_sha256],
    ["Command hash", command?.command_hash],
    ["Stdout SHA-256", command?.stdout_sha256],
    ["Stderr SHA-256", command?.stderr_sha256],
    ["Tombstone reason", receipt.tombstone_reason],
    ["Legacy provenance", receipt.legacy_derivative_provenance],
  ].filter(([, value]) => scalarText(value)) as [string, unknown][];
  return (
    <article
      id={rowDomId(section, receipt.id)}
      className={["run-receipt", focused ? "is-focused" : null, unhealthy ? "is-unhealthy" : null].filter(Boolean).join(" ")}
    >
      <header>
        <strong>{EVIDENCE_KIND_LABELS[kind]?.long ?? humanizeStatus(kind)}</strong>
        <StatusPill domain="receipt-health" value={health} size="sm" />
        {originRun !== null && originRun !== runId && (
          <a href={engagementHref(engagementKey, { tab: "runs", run: originRun })}>from run #{originRun}</a>
        )}
        <span className="run-receipt-meta">
          <TimeStamp value={scalarText(receipt.created_at)} mode="both" fallback="Time not recorded" />
          {receipt.id !== undefined && <> · #{String(receipt.id)}</>}
        </span>
      </header>
      <div className="run-receipt-compare">
        <div>
          <h5>Expected</h5>
          <p>{scalarText(receipt.expected_result) || <span className="run-cell-muted">Not stated</span>}</p>
        </div>
        <div>
          <h5>Observed</h5>
          <p>{scalarText(receipt.observed_result) || <span className="run-cell-muted">Not stated</span>}</p>
        </div>
      </div>
      {command && (
        <div className="run-receipt-source">
          <span>
            Command #{scalarText(command.id)} · {statusLabel("command", scalarText(command.status))}
            {command.return_code !== undefined && command.return_code !== null && ` · exit ${scalarText(command.return_code)}`}
          </span>
          <code>{scalarText(command.command)}</code>
          <a href={engagementHref(engagementKey, { tab: "commands", command: scalarText(command.id) || undefined })}>Open command</a>
        </div>
      )}
      {scalarText(receipt.artifact_relative_path) && (
        <div className="run-receipt-source">
          <span>Artifact</span>
          <code>{scalarText(receipt.artifact_relative_path)}</code>
          <a href={engagementHref(engagementKey, { tab: "artifacts" })}>Open Files</a>
        </div>
      )}
      {receipt.source_read_id != null && (
        <div className="run-receipt-source"><span>Source read #{scalarText(receipt.source_read_id)}</span></div>
      )}
      {integrity.length > 0 && (
        <details className="run-receipt-integrity">
          <summary>Integrity details</summary>
          <dl className="run-kv">
            {integrity.map(([label, value]) => (
              <div key={label}><dt>{label}</dt><dd className="mono">{scalarText(value)}</dd></div>
            ))}
          </dl>
        </details>
      )}
    </article>
  );
}

const UNHEALTHY_RECEIPT_STATES = ["stale", "missing", "tombstoned"] as const;

/**
 * Names the receipts whose evidence is no longer intact (the run's
 * proof_* blockers point here) and links to each loaded one; the cards
 * themselves are marked too.
 */
function UnhealthyEvidence({ run, stream, section }: { run: AssessmentRun; stream: ChildStream; section: RunAuditSection }) {
  const counts = UNHEALTHY_RECEIPT_STATES
    .map((state) => [state, Number(run.proof_health?.[state] ?? 0)] as const)
    .filter(([, count]) => count > 0);
  if (counts.length === 0) return null;
  const loaded = stream.items.filter((receipt) => String(receipt.evidence_health ?? "healthy") !== "healthy");
  const total = counts.reduce((sum, [, count]) => sum + count, 0);
  return (
    <div className="run-unhealthy" role="status" aria-label="Unhealthy evidence">
      <strong>{counts.map(([state, count]) => `${count} ${state} receipt${count === 1 ? "" : "s"}`).join(" · ")}</strong>
      <span>
        {" "}— the evidence no longer matches what was recorded; restore or replace it before the run can complete.
      </span>
      {loaded.length > 0 && (
        <span className="run-unhealthy-links">
          {loaded.map((receipt) => (
            <a key={String(receipt.id)} href={`#${rowDomId(section, receipt.id as number | string)}`} onClick={(event) => {
              event.preventDefault();
              document.getElementById(rowDomId(section, receipt.id as number | string) ?? "")?.scrollIntoView?.({ block: "center", behavior: "smooth" });
            }}>
              #{String(receipt.id)} {EVIDENCE_KIND_LABELS[String(receipt.evidence_kind ?? "")]?.long ?? humanizeStatus(String(receipt.evidence_kind ?? ""))}
            </a>
          ))}
        </span>
      )}
      {stream.loaded && loaded.length < total && stream.hasMore && (
        <span className="meta-text"> More may be on later pages; load more below.</span>
      )}
    </div>
  );
}

// ── Audit record tables ───────────────────────────────────────────────

const PREFERRED_COLUMNS: Partial<Record<RunAuditSection, string[]>> = {
  sources: ["id", "target_key", "path", "inventory_status", "parser_status", "byte_size", "line_count"],
  "source-reads": ["id", "path", "source_path", "line_start", "line_end", "attempt", "created_at"],
  dispatches: ["id", "agent_id", "agent_role", "status", "client_name", "dispatched_at"],
  "decision-history": ["created_at", "object_type", "object_id", "from_status", "to_status", "detail"],
  obligations: ["id", "identity_key", "obligation_kind", "object_key", "hard", "status", "resolution"],
  candidates: ["id", "identity_key", "vulnerability_family", "source_anchor", "state", "finding_slug"],
  "tool-signals": ["id", "signal_kind", "observed_signature", "source_anchor", "created_at"],
  "discovery-passes": ["id", "identity_key", "terminal_reason", "created_at"],
  "code-receipts": ["id", "receipt_kind", "target_key", "obligation_status"],
  comparisons: ["id", "selection", "baseline_run_id", "created_at"],
};

// Timestamps read as dates; nested objects (a client binding, a seal) stay
// whole behind a disclosure instead of a cut-off JSON string.
function AuditValue({ column, value }: { column: string; value: unknown }) {
  if (value === null || value === undefined) return <span className="run-cell-muted">{value === null ? "null" : ""}</span>;
  if (typeof value === "object") {
    const size = Array.isArray(value) ? value.length : Object.keys(value as Record<string, unknown>).length;
    if (size === 0) return <span className="run-cell-muted mono">{Array.isArray(value) ? "[]" : "{}"}</span>;
    return (
      <details className="run-audit-object">
        <summary>{Array.isArray(value) ? `${size} item${size === 1 ? "" : "s"}` : `${size} field${size === 1 ? "" : "s"}`}</summary>
        <JsonView value={value} copyable={false} />
      </details>
    );
  }
  if (typeof value === "string" && (column.endsWith("_at") || column === "created" || column === "updated") && parseServerTime(value)) {
    return <TimeStamp value={value} mode="both" precision="second" />;
  }
  return <>{scalarText(value)}</>;
}

function RecordTable({
  rows,
  section,
  focusedObject,
  label,
}: {
  rows: Record<string, unknown>[];
  section: RunAuditSection;
  focusedObject?: string;
  label: string;
}) {
  const columns = useMemo(() => {
    const preferred = PREFERRED_COLUMNS[section] ?? ["id"];
    const seen = new Set<string>();
    for (const row of rows) for (const key of Object.keys(row)) seen.add(key);
    return [
      ...preferred.filter((key) => seen.has(key)),
      ...[...seen].filter((key) => !preferred.includes(key)).sort(),
    ];
  }, [rows, section]);
  if (rows.length === 0) return null;
  // One record reads as a list of its fields, not a one-row table forty columns wide.
  if (rows.length === 1) {
    const row = rows[0];
    const id = typeof row.id === "number" || typeof row.id === "string" ? row.id : undefined;
    return (
      <dl
        id={rowDomId(section, id)}
        className={`run-kv run-record-single${focusedObject != null && String(id) === focusedObject ? " is-focused" : ""}`}
        aria-label={label}
      >
        {columns.map((column) => (
          <div key={column}>
            <dt>{statusText(column)}</dt>
            <dd className={typeof row[column] === "object" && row[column] !== null ? undefined : "run-record-value"}>
              <AuditValue column={column} value={row[column]} />
            </dd>
          </div>
        ))}
      </dl>
    );
  }
  return (
    <div className="run-record-scroll">
      <table className="run-record-table" aria-label={label}>
        <thead>
          <tr>{columns.map((column) => <th key={column} scope="col">{statusText(column)}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const id = typeof row.id === "number" || typeof row.id === "string" ? row.id : undefined;
            return (
            <tr
              key={id === undefined ? `${section}-${index}` : String(id)}
              id={rowDomId(section, id)}
              className={focusedObject != null && String(id) === focusedObject ? "is-focused" : undefined}
            >
              {columns.map((column) => (
                <td key={column}>
                  <AuditValue column={column} value={row[column]} />
                </td>
              ))}
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function KeyValues({ entries, label }: { entries: [string, unknown][]; label: string }) {
  const visible = entries.filter(([, value]) => value !== undefined);
  if (visible.length === 0) return <p className="run-empty">Not recorded.</p>;
  return (
    <dl className="run-kv" aria-label={label}>
      {visible.map(([key, value]) => (
        <div key={key}>
          <dt>{statusText(key)}</dt>
          <dd className={typeof value === "object" && value !== null ? "mono" : undefined}>
            {value === null ? <span className="run-cell-muted">null</span> : scalarText(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function flattenProvenance(value: Record<string, unknown>): [string, unknown][] {
  const entries: [string, unknown][] = [];
  for (const [key, item] of Object.entries(value)) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      for (const [inner, innerValue] of Object.entries(item as Record<string, unknown>)) {
        entries.push([`${key} ${inner}`, innerValue]);
      }
    } else {
      entries.push([key, item]);
    }
  }
  return entries;
}

// ── Comparison (scan runs only) ───────────────────────────────────────

function ScanComparison({
  engagementKey,
  run,
  runs,
  refreshVersion,
}: {
  engagementKey: string;
  run: AssessmentRun;
  runs: AssessmentRun[];
  refreshVersion: number;
}) {
  const [baseline, setBaseline] = useState("");
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "none" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const baselineId = baseline ? Number(baseline) : undefined;
  const identity = `${run.id}:${baseline}`;
  const identityRef = useRef(identity);
  identityRef.current = identity;

  const runner = useMemo(() => createCoalescedRunner(async () => {
    try {
      const next = await getAssessmentRunComparison(engagementKey, run.id, baselineId);
      if (identityRef.current !== identity) return;
      setComparison(next);
      setState("ready");
      setError(null);
    } catch (failure) {
      if (identityRef.current !== identity) return;
      if (failure instanceof ApiError && failure.status === 404) {
        setComparison(null);
        setState("none");
      } else {
        setState("error");
        setError(failure instanceof Error ? failure.message : "Comparison unavailable");
      }
    }
  }), [baselineId, engagementKey, identity, run.id]);

  useEffect(() => { void runner("join"); }, [runner]);
  const seenVersion = useRef(refreshVersion);
  useEffect(() => {
    if (seenVersion.current === refreshVersion) return;
    seenVersion.current = refreshVersion;
    void runner("refresh");
  }, [refreshVersion, runner]);

  const compatibility = comparison
    ? comparison.target_compatible === true && comparison.source_compatible === true
      ? "compatible"
      : comparison.target_compatible === null || comparison.source_compatible === null
        ? "unknown"
        : "drift"
    : null;
  const candidates = runs.filter((other) => other.id !== run.id && other.run_purpose === "scan");

  return (
    <section className="section run-section">
      <div className="run-section-head">
        <h3 className="section-title">Comparison with an earlier scan</h3>
        <label className="run-inline-field">
          Baseline
          <select value={baseline} onChange={(event) => setBaseline(event.target.value)}>
            <option value="">Latest compatible</option>
            {candidates.map((other) => (
              <option key={other.id} value={other.id}>{other.run_uuid} · {statusLabel("run", other.status)}</option>
            ))}
          </select>
        </label>
      </div>
      <p className="run-help">Deterministic: compares recorded identities, no model call.</p>
      {state === "loading" && <CardSkeleton lines={2} title={false} />}
      {state === "none" && <p className="run-empty">No earlier compatible scan run to compare with.</p>}
      {state === "error" && <p className="error-text" role="alert">{error}</p>}
      {comparison && state !== "none" && (
        <>
          <p className={`run-scan-compat is-${compatibility}`}>
            {compatibility === "compatible"
              ? `Target and source compatible with run ${comparison.baseline_run_id}`
              : compatibility === "unknown"
                ? `Compatibility with run ${comparison.baseline_run_id} is unknown because target or source identity was not recorded`
                : `Target or source drift from run ${comparison.baseline_run_id}; unresolved prior records remain unknown`}
          </p>
          <div className="run-scan-compare-grid">
            {normalizedComparison(comparison).map((group) => (
              <section key={group.key}>
                <h5>{humanizeStatus(group.key)} <span className="filter-count">{group.items.length}</span></h5>
                {group.items.length === 0 ? <p className="run-empty">None</p> : (
                  <ul>{group.items.map((item) => <li key={item}>{item}</li>)}</ul>
                )}
              </section>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

// ── Record ────────────────────────────────────────────────────────────

/** The run record's sections (`dtab` in the URL). */
export type RunRecordTab = "overview" | "evidence" | "blockers" | "audit";

const RUN_RECORD_TABS: readonly RunRecordTab[] = ["overview", "evidence", "blockers", "audit"];

export function isRunRecordTab(value: string | null | undefined): value is RunRecordTab {
  return typeof value === "string" && (RUN_RECORD_TABS as readonly string[]).includes(value);
}

/** The section a ledger deep link (`section=`) belongs to. */
export function runRecordTabForSection(section: RunAuditSection): RunRecordTab {
  return isEvidenceSection(section) ? "evidence" : "audit";
}

function RecordSection({ title, children, count, className }: { title: string; children: ReactNode; count?: number; className?: string }) {
  return (
    <section className={`section run-section${className ? ` ${className}` : ""}`}>
      <h3 className="section-title">
        {title}
        {count !== undefined && <span className="count">{count.toLocaleString()}</span>}
      </h3>
      {children}
    </section>
  );
}

export type RunDetailProps = {
  engagementKey: string;
  run: AssessmentRun;
  runs: AssessmentRun[];
  /** Open record section. */
  tab: RunRecordTab;
  /** Ledger shown in the Evidence or Audit section. */
  section: RunAuditSection;
  focusedObject?: string;
  refreshVersion: number;
  titleId: string;
  onTabChange: (tab: RunRecordTab) => void;
  onSectionChange: (section: RunAuditSection) => void;
};

export function RunDetail({
  engagementKey,
  run,
  runs,
  tab,
  section,
  focusedObject,
  refreshVersion,
  titleId,
  onTabChange,
  onSectionChange,
}: RunDetailProps) {
  const evidenceSection: RunAuditSection = isEvidenceSection(section) ? section : "proof-receipts";
  const auditSection: RunAuditSection = isEvidenceSection(section)
    ? (run.run_purpose === "scan" ? "sources" : "dispatches")
    : section;

  // Child records page in only for the section on screen.
  const evidence = useRunChildren(engagementKey, run.id, evidenceSection, tab === "evidence", refreshVersion);
  const records = useRunChildren(engagementKey, run.id, auditSection, tab === "audit", refreshVersion);
  const evidenceFocus = focusedObject && tab === "evidence" && section === evidenceSection ? focusedObject : undefined;
  const recordFocus = focusedObject && tab === "audit" && section === auditSection ? focusedObject : undefined;
  const evidenceMissing = useFocusedRecord(evidence, evidenceSection, evidenceFocus);
  const recordMissing = useFocusedRecord(records, auditSection, recordFocus);

  const health = runHealth(run);
  const blockers = currentBlockers(run);
  const findings = runFindingLinks(run);
  const { client, model } = runClientModel(run);
  const startedAt = run.started_at ?? run.created_at;
  const duration = run.elapsed_seconds != null ? formatDuration(run.elapsed_seconds * 1000) : elapsedLabel(startedAt, run.finished_at);
  const lifecycle = lifecyclePresentation(run.lifecycle_history ?? []);
  const provenance = flattenProvenance(dispatchProvenance(run) as Record<string, unknown>);
  const counts = Object.entries(run.counts ?? {});
  const targetIdentity = Object.entries(run.target_identity ?? {});
  const task = run.producer_dispatch_task ?? "";
  const purposeIsScan = run.run_purpose === "scan";
  const receiptCount = run.counts?.proof_receipts ?? (evidence.loaded ? evidence.total : undefined);
  const evidenceMix = evidenceMixLabel(run.evidence_kind_counts);
  const auditLabel = AUDIT_RECORD_SECTIONS.find((entry) => entry.key === auditSection)?.label ?? humanizeStatus(auditSection);

  return (
    <>
      <RecordHeader
        id={`Run #${run.id}`}
        copyId={String(run.id)}
        copyIdLabel="Copy run ID"
        title={run.run_uuid}
        titleId={titleId}
        tone={statusTone("run-health", health.key)}
        actions={<RecordCopyLinkButton noun="run" />}
        pills={
          <>
            <RunHealthChip health={health} />
            {health.reason && <span className="record-pill-reason">{health.reason}</span>}
            <span className={`run-track-tag run-track-${run.run_kind}`}>{run.run_kind}</span>
            {purposeIsScan && <span className="run-track-tag run-purpose-scan">scan</span>}
          </>
        }
        datesLabel="Run dates"
        dates={[
          { label: "Started", value: startedAt },
          {
            label: "Finished",
            value: run.finished_at,
            fallback: run.status === "running" || run.status === "queued" ? "still running" : "not recorded",
            detail: run.finished_at ? <> · ran {duration}</> : undefined,
          },
        ]}
      />
      <RecordTabs
        label="Run sections"
        active={tab}
        onChange={onTabChange}
        tabs={[
          { id: "overview", label: "Overview", count: findings.length || undefined },
          { id: "evidence", label: "Evidence", count: receiptCount },
          { id: "blockers", label: "Blockers", count: blockers.length, hidden: blockers.length === 0 },
          { id: "audit", label: "Audit details" },
        ]}
      />
      <RecordBody>
        {tab === "overview" && (
          <>
            <div className="kv-grid" aria-label="Run facts">
              <div className="kv"><p className="k">Agent</p><p className="v">{[run.producer_dispatch_agent_role, run.producer_dispatch_agent_id].filter(Boolean).join(" · ") || "Not recorded"}</p></div>
              <div className="kv"><p className="k">Client · model</p><p className="v">{[client, model].filter(Boolean).join(" · ") || "Not recorded"}</p></div>
              <div className="kv"><p className="k">Duration</p><p className="v">{duration}</p></div>
              <div className="kv"><p className="k">Evidence</p><p className="v">{evidenceMix}</p></div>
              {run.resumed_from_run_id && (
                <div className="kv"><p className="k">Continues</p><p className="v"><a href={engagementHref(engagementKey, { tab: "runs", run: run.resumed_from_run_id })}>run #{run.resumed_from_run_id}</a></p></div>
              )}
              {(run.proof_work_ids ?? []).length > 0 && (
                <div className="kv">
                  <p className="k">Proof task</p>
                  <p className="v run-link-list">
                    {(run.proof_work_ids ?? []).map((workId) => (
                      <a key={workId} href={engagementHref(engagementKey, { tab: "proof", work: workId })}>Proof #{workId}</a>
                    ))}
                  </p>
                </div>
              )}
            </div>

            <RecordSection title="What this run was for">
              {task
                ? <p className="run-task-text">{task}</p>
                : <p className="run-empty">The dispatch that produced this run recorded no task.</p>}
            </RecordSection>

            <RecordSection title="Findings it supports" count={findings.length}>
              {findings.length === 0 ? (
                <p className="run-empty">No finding cites, was verified by, or dispatched this run.</p>
              ) : (
                <ul className="run-finding-list">
                  {findings.map((finding) => (
                    <li key={finding.slug}>
                      <a className="run-finding-chip" href={engagementHref(engagementKey, { tab: "findings", finding: finding.slug })}>{finding.slug}</a>
                      <span>{finding.relations.map((relation) => RELATION_LABELS[relation]).join(" · ")}</span>
                    </li>
                  ))}
                </ul>
              )}
            </RecordSection>
          </>
        )}

        {tab === "evidence" && (
          <RecordSection title="Evidence receipts" count={receiptCount}>
            <SegmentedControl<RunAuditSection>
              label="Evidence kind"
              className="run-section-switch"
              value={evidenceSection}
              onChange={onSectionChange}
              options={EVIDENCE_SECTIONS.map((entry) => ({ value: entry.key, label: entry.label }))}
            />
            <UnhealthyEvidence run={run} stream={evidence} section={evidenceSection} />
            {evidenceMissing && (
              <p className="error-text" role="alert">Requested record #{evidenceFocus} is not present in this run's recorded ledger.</p>
            )}
            <StreamStatus stream={evidence} noun="evidence" />
            <div className={`run-receipt-list ${evidence.loading && evidence.loaded ? "is-refreshing" : ""}`}>
              {evidence.items.map((receipt, index) => (
                <ReceiptCard
                  key={receipt.id === undefined ? index : String(receipt.id)}
                  engagementKey={engagementKey}
                  receipt={receipt}
                  runId={run.id}
                  section={evidenceSection}
                  focused={evidenceFocus != null && String(receipt.id) === evidenceFocus}
                />
              ))}
            </div>
            <LoadMore stream={evidence} />
          </RecordSection>
        )}

        {tab === "blockers" && (
          <RecordSection title="Blockers" count={blockers.length}>
            {blockers.length === 0 ? <p className="run-empty">Nothing blocks this run.</p> : (
              <>
                <p className="run-help">Each blocker names the record and what would settle it.</p>
                <ul className="run-blockers">
                  {blockers.map((blocker, index) => (
                    <li key={`${String(blocker.code)}-${String(blocker.object_id)}-${index}`}>
                      <span className="run-blocker-code">{humanizeStatus(blocker.code)}</span>
                      <div>
                        <strong>{blocker.message || `${statusText(blocker.object_type)} ${String(blocker.object_id ?? "")}`}</strong>
                        <p>{blocker.action || "Inspect and settle this recorded blocker."}</p>
                      </div>
                      <a href={blockerDestination(engagementKey, run.id, blocker)}>Open record</a>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </RecordSection>
        )}

        {tab === "audit" && (
          <>
            <RecordSection title="Dispatch provenance">
              <KeyValues entries={provenance} label="Dispatch provenance" />
              {(run.warnings ?? []).length > 0 && (
                <ul className="run-warnings">{(run.warnings ?? []).map((warning) => <li key={warning}>{warning}</li>)}</ul>
              )}
            </RecordSection>
            <RecordSection title="Lifecycle">
              {lifecycle.length === 0 ? <p className="run-empty">No lifecycle events recorded.</p> : (
                <ol className="run-timeline">
                  {lifecycle.map(({ key, transition, event }) => (
                    <li key={key}>
                      <strong>{transition.split(" → ").map((status) => statusLabel("run", status)).join(" → ")}</strong>
                      <span><TimeStamp value={event.created_at} mode="both" fallback="Not recorded" />{event.actor ? ` · ${String(event.actor)}` : ""}</span>
                      {event.reason && <p>{event.reason}</p>}
                    </li>
                  ))}
                </ol>
              )}
            </RecordSection>
            <RecordSection title="Terminal seal">
              {run.seal ? (
                <>
                  <KeyValues
                    label="Terminal seal"
                    entries={[
                      ["seal sha256", run.seal_sha256 ?? null],
                      ["requested status", run.seal.requested_status],
                      ["effective status", run.seal.effective_status],
                    ]}
                  />
                  <details className="run-raw">
                    <summary>Raw seal JSON</summary>
                    <pre>{JSON.stringify(run.seal, null, 2)}</pre>
                  </details>
                </>
              ) : <p className="run-empty">Not sealed yet; a run is sealed when it ends.</p>}
            </RecordSection>
            <RecordSection title="Recorded counts">
              <dl className="run-count-grid" aria-label="Recorded counts">
                {counts.map(([name, value]) => (
                  <div key={name}><dt>{COUNT_LABELS[name] ?? statusText(name)}</dt><dd>{value}</dd></div>
                ))}
              </dl>
              {Object.keys(run.proof_health ?? {}).length > 0 && (
                <dl className="run-count-grid" aria-label="Evidence health">
                  {Object.entries(run.proof_health ?? {}).map(([name, value]) => (
                    <div key={name}><dt>{`${statusText(name)} receipts`}</dt><dd>{String(value)}</dd></div>
                  ))}
                </dl>
              )}
            </RecordSection>
            <RecordSection title="Target identity">
              <KeyValues entries={targetIdentity} label="Target identity" />
              {(run.source_generations ?? []).length > 0 && (
                <>
                  <h4 className="run-subhead">Source generations</h4>
                  <RecordTable rows={run.source_generations ?? []} section="sources" label="Source generations" />
                </>
              )}
              {(run.exclusions ?? []).length > 0 && (
                <>
                  <h4 className="run-subhead">Exclusions</h4>
                  <RecordTable rows={run.exclusions ?? []} section="sources" label="Exclusions" />
                </>
              )}
            </RecordSection>
            {purposeIsScan && (
              <ScanComparison engagementKey={engagementKey} run={run} runs={runs} refreshVersion={refreshVersion} />
            )}
            <RecordSection title="Recorded ledgers">
              <SegmentedControl<RunAuditSection>
                label="Run records"
                className="run-section-switch"
                value={auditSection}
                onChange={onSectionChange}
                options={AUDIT_RECORD_SECTIONS.map((entry) => ({
                  value: entry.key,
                  label: entry.label,
                  count: entry.countKey ? run.counts?.[entry.countKey] : undefined,
                }))}
              />
              {recordMissing && (
                <p className="error-text" role="alert">Requested record #{recordFocus} is not present in this run's recorded ledger.</p>
              )}
              <StreamStatus stream={records} noun={auditLabel.toLowerCase()} />
              <div className={records.loading && records.loaded ? "is-refreshing" : undefined}>
                <RecordTable rows={records.items} section={auditSection} focusedObject={recordFocus} label={`${auditLabel} records`} />
              </div>
              <LoadMore stream={records} />
            </RecordSection>
          </>
        )}
      </RecordBody>
    </>
  );
}
