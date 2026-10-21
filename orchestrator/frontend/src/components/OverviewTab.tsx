import { memo, useEffect, useMemo, useRef, useState } from "react";
import type {
  AssessmentAttackChain,
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentSummary,
  Engagement,
  PerHostCoverage,
  PerHostCoverageHost,
  PerHostOutcome,
  ReportReadiness,
  ReportReadinessCoverage,
} from "../lib/api";
import { getReportReadiness } from "../lib/api";
import { listActivityFeed, type ActivityFeedPage } from "../lib/activityApi";
import { createCoalescedRunner } from "../lib/coalesce";
import { compareServerTime } from "../lib/serverTime";
import { engagementHref } from "../lib/workspaceRoutes";
import { EntityChips } from "./activity/ActivityEntries";
import { compareSeverity, RETIRED_WORKFLOWS } from "./FindingsTab";
import { TimeStamp } from "./formatting";
import { PhaseWaterfall } from "./PhaseWaterfall";
import { CardSkeleton, ChartSkeleton, Skeleton, SlowLoadHint } from "./Skeletons";
import { EmptyState, PageHeader, SeverityTag, StatusPill, humanizeStatus, statusLabel, type StatusTone } from "./ui";
import { SeverityDonut } from "./charts/SeverityDonut";
import { SummaryStatBar } from "./charts/SummaryStatBar";
import type { SummaryStatBarItem } from "./charts/SummaryStatBar";
import "../styles/overview.css";

// Verification states that still need a verifier's decision. The attention
// count, the Finding queue and the filtered Findings link all use this set.
const AWAITING_VERIFICATION = ["unreviewed", "disputed", "pending_runtime_proof", "blocked"] as const;
const QUEUE_LIMIT = 5;

// Below-the-fold list caps (scroll-length reduction). Lists render up to the
// cap by default with a "Show all N" expander revealing the rest in place; no
// data is removed — everything stays reachable. Latest activity reads only
// the newest few entries; the Activity view holds the full record.
const ATTACK_CHAIN_CAP = 8;
const LATEST_ACTIVITY_LIMIT = 5;
// Report blockers listed per kind before that kind's "Show all" expander.
const REPORT_BLOCKER_CAP = 10;
const REPORT_BLOCKERS_ID = "report-blockers";

// Per-host coverage matrix: cap visible rows and collapse the whole section
// when the host count is large. Both are scroll-length controls; all hosts
// stay reachable via the in-place expanders.
const PER_HOST_ROW_CAP = 12;

// Persisted collapse preference for the per-host matrix section. Mirrors the
// FindingsTab localStorage idiom (a key constant + a guarded reader). Survives
// the 2s WebSocket refresh and full reloads. Stored value is "1" (collapsed)
// or "0" (expanded); absent → use the size-based default the caller passes.
const PER_HOST_COLLAPSE_KEY = "overview.perHostMatrix.collapsed";
function readPerHostCollapsed(defaultCollapsed: boolean): boolean {
  try {
    const raw = window.localStorage.getItem(PER_HOST_COLLAPSE_KEY);
    if (raw === "1") return true;
    if (raw === "0") return false;
  } catch {
    // ignore — fall through to the size-based default
  }
  return defaultCollapsed;
}

type OverviewTabProps = {
  engagementKey: string;
  assessmentSummary: AssessmentSummary | null;
  findings: (AssessmentFindingDetail | AssessmentFinding)[];
  findingsLoading?: boolean;
  findingsLoadError?: string | null;
  chains: (AssessmentAttackChainDetail | AssessmentAttackChain)[];
  chainLinks: AssessmentAttackChainLink[];
  currentPhase: string;
  trackState?: Engagement["track_state"];
  aggregateComplete?: boolean;
  /** Advances on every change; the latest activity follows it. */
  assessmentRefreshVersion: number;
  /** Advances only when report readiness can have changed; readiness re-reads on it. */
  readinessRefreshVersion: number;
};

type QueueFinding = AssessmentFindingDetail | AssessmentFinding;

function lastChange(finding: QueueFinding): string | null | undefined {
  return "last_transition_at" in finding ? finding.last_transition_at || finding.updated_at : finding.updated_at;
}

// The findings whose verification is unsettled: current findings first, then
// the most severe, then the most recently changed.
function verificationQueue(findings: QueueFinding[]): QueueFinding[] {
  return findings
    .filter((finding) => (AWAITING_VERIFICATION as readonly string[]).includes(finding.verification_status))
    .sort((left, right) =>
      Number(RETIRED_WORKFLOWS.has(left.workflow_status)) - Number(RETIRED_WORKFLOWS.has(right.workflow_status))
      || compareSeverity(left.severity, right.severity)
      || compareServerTime(lastChange(left), lastChange(right), "desc")
      || left.title.localeCompare(right.title));
}

const formatCount = (value: number | null | undefined) => (value ?? 0).toLocaleString("en-US");

/** Scroll to an Overview section and move focus to it (in-page; the hash is the route). */
function revealSection(id: string) {
  const section = document.getElementById(id);
  if (!section) return;
  section.scrollIntoView?.({ block: "start" });
  section.focus({ preventScroll: true });
}

// C58 — labels for the five C40 per-host objectives. The map is the only
// place the user-facing copy lives; backend objective names are the keys.
const OBJECTIVE_LABELS: Record<string, string> = {
  waf_tier: "WAF tier",
  service_inventory: "Service inventory",
  directory_fuzz: "Directory-fuzz coverage",
  tech_fingerprint: "Tech fingerprint",
  osint: "OSINT",
};

function objectiveLabel(objective: string): string {
  return OBJECTIVE_LABELS[objective] ?? objective.replace(/_/g, " ");
}

// Matrix marks are WARN-only objective outcomes, not severities.
function outcomeTone(outcome: PerHostOutcome | undefined): StatusTone {
  if (!outcome) return "neutral";
  if (outcome.deferred) return "paused";
  if (outcome.met) return "success";
  return "warning";
}

function outcomeMarker(outcome: PerHostOutcome | undefined): string {
  if (!outcome) return "—";
  if (outcome.deferred) return "D";
  if (outcome.met) return "Y";
  return "N";
}

function describeDeferralPayload(payload: Record<string, unknown>): string {
  const objectives = Array.isArray(payload.deferred_objectives)
    ? payload.deferred_objectives.filter((v) => typeof v === "string").join(", ")
    : "";
  const reason = typeof payload.reason === "string" ? payload.reason : "";
  if (objectives && reason) return `${objectives} — ${reason}`;
  if (objectives) return objectives;
  if (reason) return reason;
  return JSON.stringify(payload);
}

export function OverviewTab(props: OverviewTabProps) {
  return <OverviewWorkspace key={props.engagementKey} {...props} />;
}

function OverviewWorkspace({ engagementKey, assessmentSummary, findings, findingsLoading = false, findingsLoadError = null, chains, chainLinks, currentPhase, trackState, aggregateComplete, assessmentRefreshVersion, readinessRefreshVersion }: OverviewTabProps) {
  const s = assessmentSummary;
  const [readiness, setReadiness] = useState<ReportReadiness | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const [activity, setActivity] = useState<ActivityFeedPage | null>(null);
  const [activityError, setActivityError] = useState<string | null>(null);
  const mounted = useRef(true);
  // Memoized so a live refresh that leaves `findings` unchanged does not re-sort.
  const queue = useMemo(() => verificationQueue(findings), [findings]);
  const awaitingHref = engagementHref(engagementKey, { tab: "findings", verification: AWAITING_VERIFICATION.join(",") });

  // Each chain's linked findings, in chainLinks order: slug/id indexes are
  // built once, then finding-kind links are bucketed by chain_key in one pass.
  const linkedFindingsByChain = useMemo(() => {
    const bySlug = new Map<string, AssessmentFindingDetail | AssessmentFinding>();
    const byId = new Map<number, AssessmentFindingDetail | AssessmentFinding>();
    for (const f of findings) {
      bySlug.set(f.slug, f);
      if ("id" in f) byId.set(f.id, f);
    }
    const out = new Map<string, { slug: string | null; title: string }[]>();
    for (const link of chainLinks) {
      if (link.entity_kind !== "finding") continue;
      const match =
        (link.entity_ref ? bySlug.get(link.entity_ref) : undefined) ??
        (link.entity_id != null ? byId.get(link.entity_id) : undefined);
      const entry = { slug: match?.slug ?? link.entity_ref ?? null, title: match ? match.title : link.entity_ref || `finding #${link.entity_id}` };
      const list = out.get(link.chain_key);
      if (list) list.push(entry);
      else out.set(link.chain_key, [entry]);
    }
    return out;
  }, [chainLinks, findings]);

  // Attack-chains list cap + expander. Collapsed by default once the chain
  // count exceeds the cap; the expander reveals the full list in place.
  const [chainsExpanded, setChainsExpanded] = useState(false);
  const visibleChains = useMemo(
    () => (chainsExpanded ? chains : chains.slice(0, ATTACK_CHAIN_CAP)),
    [chains, chainsExpanded],
  );

  const vendorSaasPending = s?.vendor_saas_hosts_pending_decision ?? [];
  const egressStatus = s?.egress_status;
  const egressBlockedPct = egressStatus?.blocked_pct ?? 0;
  const egressBannerVisible = egressBlockedPct > 50;

  // Tier 1b overview charts. The summary is still loading while `s` is null;
  // `finding_severities` is absent on older backends (it is optional on the
  // type), so the donut row hides gracefully when the field is missing.
  const summaryLoading = s === null;
  const findingSeverities = s?.finding_severities;
  const critHigh = (findingSeverities?.critical ?? 0) + (findingSeverities?.high ?? 0);
  const statBarItems: SummaryStatBarItem[] = [
    { label: "Current findings", value: s?.finding_count ?? 0 },
    { label: "Crit/High", value: critHigh, tone: critHigh > 0 ? "danger" : "ok" },
    { label: "Open surfaces", value: s?.open_surface_count ?? 0 },
    { label: "Services", value: s?.service_count ?? 0 },
    { label: "Attack chains", value: s?.attack_chain_count ?? 0 },
    { label: "Exploit candidates", value: s?.exploit_candidate_count ?? 0 },
  ];

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // Readiness re-reads when a change can move it (`readinessRefreshVersion`);
  // the latest activity on every change. Each keeps one request in flight and
  // re-runs once afterwards if more bumps arrived, so refresh bursts never
  // starve a slow read; the last loaded value stays on screen meanwhile.
  const loadReadiness = useMemo(() => createCoalescedRunner(async () => {
    try {
      const row = await getReportReadiness(engagementKey);
      if (!mounted.current) return;
      setReadiness(row);
      setReadinessError(null);
    } catch (error) {
      if (mounted.current) setReadinessError(error instanceof Error ? error.message : String(error));
    }
  }), [engagementKey]);
  const loadActivity = useMemo(() => createCoalescedRunner(async () => {
    try {
      const page = await listActivityFeed(engagementKey, { limit: LATEST_ACTIVITY_LIMIT });
      if (!mounted.current) return;
      setActivity(page);
      setActivityError(null);
    } catch (error) {
      if (mounted.current) setActivityError(error instanceof Error ? error.message : String(error));
    }
  }), [engagementKey]);
  const seenReadinessVersion = useRef<number | null>(null);
  useEffect(() => {
    const mode = seenReadinessVersion.current === null ? "join" : "refresh";
    if (seenReadinessVersion.current === readinessRefreshVersion) return;
    seenReadinessVersion.current = readinessRefreshVersion;
    void loadReadiness(mode);
  }, [loadReadiness, readinessRefreshVersion]);
  const seenActivityVersion = useRef<number | null>(null);
  useEffect(() => {
    const mode = seenActivityVersion.current === null ? "join" : "refresh";
    if (seenActivityVersion.current === assessmentRefreshVersion) return;
    seenActivityVersion.current = assessmentRefreshVersion;
    void loadActivity(mode);
  }, [loadActivity, assessmentRefreshVersion]);

  const awaitingCount = s ? AWAITING_VERIFICATION.reduce((total, status) => total + (s.finding_verification_statuses?.[status] ?? 0), 0) : null;
  return (
    <>
      <PageHeader
        className="overview-page-header"
        title="Overview"
        purpose="Where this engagement stands: what needs you now, the findings awaiting verification, track progress and report readiness."
        stats={[{ value: s?.finding_count, label: "current findings", title: "Findings that are not merged or false positive" }]}
      />
      <section className="panel overview-attention" aria-labelledby="attention-title">
        <div className="panel-header"><h2 id="attention-title">Needs attention</h2></div>
        {s === null ? (
          <div className="attention-row" role="status" aria-busy="true" aria-label="Loading engagement summary">
            <Skeleton width={200} height={14} />
            <Skeleton width={130} height={14} />
            <Skeleton width={220} height={14} />
            <SlowLoadHint active what="the engagement summary" />
          </div>
        ) : <div className="attention-row">
          {/* Each count opens exactly the records it counts. The coverage and
              report gates are listed, with their causes, under Report blockers. */}
          <button type="button" className="overview-attention-link" onClick={() => revealSection(REPORT_BLOCKERS_ID)} title="The report gate's surface coverage check: discovered or partially covered surfaces on hosts with active findings, and deferred high-risk surfaces">
            <strong>{formatCount(s.coverage_blocker_count)}</strong> surfaces block the coverage check
          </button>
          <button type="button" className="overview-attention-link" onClick={() => revealSection(REPORT_BLOCKERS_ID)} title="Everything that stops a final report export; listed under Report blockers">
            <strong>{formatCount(s.report_blocker_count)}</strong> report blockers
          </button>
          <a href={awaitingHref} title="Unreviewed, disputed, pending runtime proof or blocked verification">
            <strong>{formatCount(awaitingCount)}</strong> findings awaiting verification
          </a>
        </div>}
      </section>

      <section className="panel overview-finding-queue" aria-labelledby="finding-queue-title">
        <div className="panel-header"><h2 id="finding-queue-title">Finding queue</h2><a href={engagementHref(engagementKey, { tab: "findings" })}>All findings</a></div>
        <p className="meta-text overview-queue-purpose">Findings whose verification is not settled: current findings first, most severe first, then the most recently changed.</p>
        <div className="finding-queue-list">
          {queue.slice(0, QUEUE_LIMIT).map((f) => <div className="finding-queue-row overview-queue-row" key={f.slug}>
            <SeverityTag severity={f.severity} size="sm" />
            <a className="overview-queue-title" href={engagementHref(engagementKey, { tab: "findings", finding: f.slug })}>{f.title}</a>
            <StatusPill domain="finding-workflow" value={f.workflow_status} size="sm" />
            <StatusPill domain="finding-verification" value={f.verification_status} size="sm" />
          </div>)}
          {/* The first ledger read shows placeholder rows; a reload keeps the
              rows already shown. Until the summary arrives an empty ledger is
              not yet known to be empty. */}
          {!findingsLoadError && findings.length === 0 && (findingsLoading || s === null) && (
            <CardSkeleton lines={QUEUE_LIMIT} title={false} />
          )}
          <SlowLoadHint active={findingsLoading} what="the finding ledger" />
          {findingsLoadError && <p className="error-text" role="status">{findings.length > 0 ? "Finding ledger refresh failed. Showing last available finding records: " : "Finding ledger unavailable: "}{findingsLoadError}</p>}
          {!findingsLoading && !findingsLoadError && findings.length === 0 && s !== null && (
            <EmptyState variant="empty" compact title="No findings recorded yet." />
          )}
          {!findingsLoading && !findingsLoadError && findings.length > 0 && queue.length === 0 && (
            <EmptyState variant="empty" compact title="No finding is awaiting verification.">Every finding's verification is settled.</EmptyState>
          )}
          {queue.length > 0 && (
            <p className="meta-text overview-queue-footer">
              Showing {Math.min(QUEUE_LIMIT, queue.length)} of {queue.length.toLocaleString("en-US")} {queue.length === 1 ? "finding" : "findings"} awaiting verification.{" "}
              <a href={awaitingHref}>Review them in Findings</a>
            </p>
          )}
        </div>
      </section>

      <PhaseWaterfall currentPhase={currentPhase} trackState={trackState} aggregateComplete={aggregateComplete} />

      {egressBannerVisible && (
        <section className="panel" data-testid="egress-reputation-banner">
          <div className="panel-header">
            <h2>Egress reputation block detected</h2>
          </div>
          <p>
            <strong>{egressBlockedPct}%</strong> of representative live hosts returned 403 / 000-status from
            the runtime egress IP (pattern: <code>{egressStatus?.pattern ?? "unknown"}</code>).
            Review mitigation options with the operator:
          </p>
          <ol>
            <li>
              Request IP allowlisting from the program.
            </li>
            <li>
              Route through a residential proxy or clean-IP VPS.
            </li>
            <li>
              Use a browser-based tool inside the runtime.
            </li>
            <li>
              Accept the limited coverage and document the gap.
            </li>
          </ol>
          <p className="meta-text">
            Record the operator decision in the engagement workflow. Review existing evidence in <a href={engagementHref(engagementKey, { tab: "http" })}>HTTP traffic</a> or <a href={engagementHref(engagementKey, { tab: "activity" })}>the activity record</a>.
          </p>
          <p className="meta-text">
            Detail: <code>agent/references/runtime-guides/cdn-ip-blocking.md</code>
          </p>
        </section>
      )}

      {vendorSaasPending.length > 0 && (
        <section className="panel" data-testid="vendor-saas-pending-panel">
          <div className="panel-header">
            <h2>Vendor-SaaS hosts pending scope decision</h2>
          </div>
          <ul>
            {vendorSaasPending.map((row) => (
              <li key={row.host}>
                <span className="badge" data-testid={`vendor-saas-badge-${row.host}`}>
                  vendor-saas: {row.vendor}
                </span>
                <code style={{ marginLeft: "8px" }}>{row.host}</code>
              </li>
            ))}
          </ul>
          <p className="meta-text">
            Surface the numbered checkpoint when recon identifies vendor-managed SaaS; record the
            choice as a backend scope_decision row with{" "}
            <code>vigil assess agent decision --kind scope_decision</code>.
          </p>
        </section>
      )}

      <section className="panel overview-charts" data-testid="overview-charts">
        <div className="panel-header">
          <h2>At a glance</h2>
        </div>
        <p className="meta-text">Current findings exclude merged and false-positive records.</p>
        <div className="overview-charts-row">
          {summaryLoading ? (
            <div className="overview-charts-donut">
              <ChartSkeleton variant="donut" height={140} label="Severity mix" />
            </div>
          ) : (
            // Older backends omit finding_severities — skip the donut column and
            // let the stat bar take the full row.
            findingSeverities && (
              <div className="overview-charts-donut">
                {/* No centerLabel: the donut's own total (sum of segments) is
                    guaranteed to equal finding_count by the mirrored backend
                    WHERE clause, so it stays self-consistent with the ring. */}
                <SeverityDonut counts={findingSeverities} size={140} legend />
              </div>
            )
          )}
          <div className="overview-charts-stats">
            {summaryLoading ? <ChartSkeleton variant="bar" height={80} label="Engagement summary" /> : <SummaryStatBar items={statBarItems} />}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Coverage</h2>
          <a href={engagementHref(engagementKey, { tab: "coverage" })}>Full coverage ledger</a>
        </div>
        {s === null ? <ChartSkeleton variant="bar" height={48} label="Coverage summary" /> : <SummaryStatBar items={[
          { label: "Targets", value: s.target_count },
          { label: "Probe runs", value: s.probe_count },
        ]} />}
      </section>

      {readiness && (
        <ReadinessPanel readiness={readiness} />
      )}

      {readiness && !readiness.ready && (
        <ReportBlockers engagementKey={engagementKey} blockers={readiness.blockers} coverage={readiness.coverage} />
      )}
      {readinessError && (
        <section className="panel">
          <p className="meta-text">Report readiness unavailable: {readinessError}</p>
        </section>
      )}
      {!readiness && !readinessError && (
        <section className="panel" aria-labelledby="report-checks-title">
          <div className="panel-header"><h2 id="report-checks-title">Report checks</h2></div>
          <CardSkeleton lines={3} title={false} />
          <SlowLoadHint active what="report readiness" />
        </section>
      )}

      <section className="panel overview-chains" aria-labelledby="attack-chains-title">
        <div className="panel-header"><h2 id="attack-chains-title">Attack chains</h2></div>
        <div className="overview-chain-list">
            {visibleChains.map((c) => {
              const linkedFindings = linkedFindingsByChain.get(c.chain_key) ?? [];
              return (
                <article key={c.chain_key} className="overview-chain">
                  <div className="overview-chain-head">
                    <SeverityTag severity={c.severity} size="sm" />
                    <strong>{c.title}</strong>
                    <StatusPill value={c.status} tone="neutral" label={humanizeStatus(c.status)} size="sm" />
                  </div>
                  {linkedFindings.length > 0 && (
                    <p className="meta-text overview-chain-findings">
                      Findings:{" "}
                      {linkedFindings.map((linked, index) => (
                        <span key={`${linked.slug ?? linked.title}-${index}`}>
                          {index > 0 && ", "}
                          {linked.slug
                            ? <a href={engagementHref(engagementKey, { tab: "findings", finding: linked.slug })} title={linked.title}><code>{linked.slug}</code></a>
                            : linked.title}
                        </span>
                      ))}
                    </p>
                  )}
                  {/* Narratives run long; the chain reads by its title and findings. */}
                  {c.narrative && (
                    <details className="detail-disclosure overview-chain-narrative">
                      <summary>Narrative</summary>
                      <p>{c.narrative}</p>
                    </details>
                  )}
                </article>
              );
            })}
            {chains.length === 0 && <EmptyState variant="empty" compact title="No attack chains linked yet." />}
            {chains.length > ATTACK_CHAIN_CAP && (
              <button
                type="button"
                className="timeline-show-more overview-show-more"
                onClick={() => setChainsExpanded((v) => !v)}
                aria-expanded={chainsExpanded}
              >
                {chainsExpanded
                  ? "Show fewer"
                  : `Show all ${chains.length} chains`}
              </button>
            )}
        </div>
      </section>

      <LatestActivity engagementKey={engagementKey} page={activity} error={activityError} />
    </>
  );
}


// Report blockers grouped by kind, largest kind first and open; each kind
// lists its blockers as one compact line each, with every blocker one click
// away. The coverage blocker names the surfaces behind the coverage check.
function ReportBlockers({ engagementKey, blockers, coverage }: { engagementKey: string; blockers: ReportReadiness["blockers"]; coverage?: ReportReadinessCoverage }) {
  const kinds = useMemo(() => {
    const byKind = new Map<string, ReportReadiness["blockers"]>();
    for (const blocker of blockers) {
      const list = byKind.get(blocker.kind);
      if (list) list.push(blocker);
      else byKind.set(blocker.kind, [blocker]);
    }
    return [...byKind.entries()].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  }, [blockers]);
  return (
    <section className="panel report-blockers-panel" id={REPORT_BLOCKERS_ID} tabIndex={-1} aria-labelledby="report-blockers-title">
      <div className="panel-header">
        <h2 id="report-blockers-title">Report blockers</h2>
        <span className="meta-text">{blockers.length.toLocaleString("en-US")} {blockers.length === 1 ? "blocker" : "blockers"} in {kinds.length} {kinds.length === 1 ? "kind" : "kinds"}</span>
      </div>
      <p className="meta-text">Everything that stops a final report export, grouped by kind. Open a kind to see each blocker and the findings it names.</p>
      <div className="report-blocker-groups">
        {kinds.map(([kind, items], index) => (
          <ReportBlockerKind key={kind} engagementKey={engagementKey} kind={kind} items={items} coverage={coverage} defaultOpen={index === 0} />
        ))}
      </div>
    </section>
  );
}

function ReportBlockerKind({ engagementKey, kind, items, coverage, defaultOpen }: { engagementKey: string; kind: string; items: ReportReadiness["blockers"]; coverage?: ReportReadinessCoverage; defaultOpen: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? items : items.slice(0, REPORT_BLOCKER_CAP);
  return (
    <details className="report-blocker-kind" open={defaultOpen}>
      <summary>
        <span className="report-blocker-kind-label">{humanizeStatus(kind)}</span>
        <span className="report-blocker-kind-count">{items.length.toLocaleString("en-US")}</span>
      </summary>
      <div className="blocker-list">
        {visible.map((blocker, index) => {
          const affected = blocker.slug ? [blocker.slug] : blocker.slugs || [];
          return (
            <article key={`${kind}-${index}`} className="blocker-row">
              {affected.length > 0 && (
                <span className="blocker-findings">
                  {affected.map((slug, slugIndex) => <span key={slug}>{slugIndex > 0 && ", "}<a href={engagementHref(engagementKey, { tab: "findings", finding: slug })}><code>{slug}</code></a></span>)}
                </span>
              )}
              <span className="blocker-detail">
                {kind === "coverage" && coverage ? <CoverageGateDetail engagementKey={engagementKey} coverage={coverage} /> : <BlockerDetail detail={blocker.detail} />}
              </span>
            </article>
          );
        })}
      </div>
      {items.length > REPORT_BLOCKER_CAP && (
        <button
          type="button"
          className="timeline-show-more overview-show-more"
          onClick={() => setExpanded((value) => !value)}
          aria-expanded={expanded}
        >
          {expanded ? "Show fewer" : `Show all ${items.length} ${humanizeStatus(kind).toLowerCase()} blockers`}
        </button>
      )}
    </details>
  );
}

// Report gates name some causes as one stored `field=value` pair
// ("verification_status=unreviewed"). Show those as a label and the value's
// operator wording; the exact stored text stays on hover. Prose details
// render verbatim.
const BLOCKER_FIELD_LABELS: Record<string, { label: string; domain?: "finding-verification" | "finding-workflow" }> = {
  verification_status: { label: "Verification", domain: "finding-verification" },
  workflow_status: { label: "Workflow", domain: "finding-workflow" },
};

function readableBlockerDetail(detail: string): string | null {
  const match = /^([a-z][a-z0-9_]*)=(\S+)$/.exec(detail.trim());
  if (!match) return null;
  const [, field, value] = match;
  const known = BLOCKER_FIELD_LABELS[field];
  if (known?.domain) return `${known.label}: ${statusLabel(known.domain, value)}`;
  return `${known?.label ?? humanizeStatus(field)}: ${value}`;
}

function BlockerDetail({ detail }: { detail?: string | null }) {
  if (!detail) return <>No detail provided.</>;
  const readable = readableBlockerDetail(detail);
  return readable ? <span title={detail}>{readable}</span> : <>{detail}</>;
}

function CoverageGateDetail({ engagementKey, coverage }: { engagementKey: string; coverage: ReportReadinessCoverage }) {
  const count = (rows: unknown[] | undefined) => (rows?.length ?? 0).toLocaleString("en-US");
  return (
    <>
      {(coverage.blocker_count ?? 0).toLocaleString("en-US")} surfaces block the coverage check:{" "}
      {count(coverage.unresolved_surfaces)} discovered surfaces on hosts with active findings,{" "}
      {count(coverage.partially_covered_surfaces)} partially covered, {count(coverage.high_risk_deferred_surfaces)} deferred high-risk.{" "}
      <a href={engagementHref(engagementKey, { tab: "surfaces" })}>Open surfaces</a>
    </>
  );
}

// The newest few Activity entries as plain sentences with links to the
// records they name; the Activity view holds the full, filterable record.
function LatestActivity({ engagementKey, page, error }: { engagementKey: string; page: ActivityFeedPage | null; error: string | null }) {
  const categoryLabels = useMemo(
    () => new Map((page?.categories ?? []).map((category) => [category.key, category.label])),
    [page?.categories],
  );
  return (
    <section className="panel overview-latest-activity" aria-labelledby="latest-activity-title">
      <div className="panel-header">
        <h2 id="latest-activity-title">Latest activity</h2>
        <a href={engagementHref(engagementKey, { tab: "activity" })}>All activity</a>
      </div>
      {error && <p className="error-text" role="status">{page ? "Activity refresh failed. Showing the last loaded entries: " : "Activity unavailable: "}{error}</p>}
      {!page && !error && <div aria-busy="true"><CardSkeleton lines={LATEST_ACTIVITY_LIMIT} /></div>}
      {page && page.items.length === 0 && <EmptyState variant="empty" compact title="No activity recorded yet." />}
      {page && page.items.length > 0 && (
        <ol className="timeline">
          {page.items.map((item) => (
            <li key={item.id} className="timeline-row">
              <div className="timeline-pill">{categoryLabels.get(item.category) ?? item.category}</div>
              <div className="timeline-body">
                <div className="timeline-title-row">
                  <strong>{item.actor.name || item.actor.kind}</strong>
                  <TimeStamp value={item.occurred_at} mode="relative" className="meta-text" />
                </div>
                <p>{item.summary}</p>
                <EntityChips engagementKey={engagementKey} entities={item.entities} />
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

type ReadinessPanelProps = {
  readiness: ReportReadiness;
};

// C58 — Readiness panel renders:
//  1. Report checks (ready/blocked indicator + blocker count)
//  2. The C40 per-host outcome matrix (5 objectives × N hosts)
//  3. Active coverage_deferral decision rows surfaced inline so operators
//     can audit which objectives were intentionally skipped.
//
// P1#3 adds a scope-literals-only toggle on the per-host matrix so
// wildcard-heavy engagements (a scope.json *.example.com that recon
// expands into hundreds of subdomains) stay readable. Default matches
// the CLI's `vigil assess check-scope-coverage --by-host` behavior: hide
// wildcard-discovered hosts, summarize them inline.
//
// The panel is read-only. Operators dispatch missing work from the CLI; the
// UI reports state, it does not fix it. That mirrors the prevailing pattern
// in this codebase: backend tables are canonical, the UI is a view onto them.

function isWildcardScopeEntry(raw: string): boolean {
  // Mirror the backend scope classifier (agent/scripts/assess/lib/scope.py:
  // `classify_scope_entry`): only the `*.<host>` shape is treated as a
  // wildcard. The previous heuristic flagged any `?` as a wildcard, which
  // misclassified URL scope entries like `https://app.example.com/path?x=1`
  // — those would then drop out of `scopeLiterals`, leaving an in-scope
  // literal host hidden from the matrix under the default filter.
  return raw.trim().startsWith("*.");
}

// Classify scope.json `hosts` entries into the set of explicit literal
// hostnames (bare hosts + URL hosts), lowercased for matching against
// per-host coverage row hostnames. Wildcard entries are excluded — those
// expand to subdomains the operator did not author by hand.
// Per WHATWG URL spec, `URL.hostname` returns IPv6 literals wrapped in
// brackets (`[2001:db8::1]`). Per-host coverage rows emit the same hosts
// WITHOUT brackets because the backend's `_coverage_endpoint_host`
// (state_manager.py) calls `.strip("[]")`. Match that normalization here so
// IPv6 scope entries actually pair up with per-host rows under the
// "scope literals only" filter.
function stripIpv6Brackets(host: string): string {
  if (host.length >= 2 && host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

function deriveScopeLiterals(scopeHosts: string[] | undefined): Set<string> {
  const out = new Set<string>();
  if (!scopeHosts) return out;
  for (const raw of scopeHosts) {
    const entry = raw.trim();
    if (!entry || isWildcardScopeEntry(entry)) continue;
    let host = entry.toLowerCase();
    // URL entries (https://www.example.com[/path]) → extract hostname.
    // Bare hosts pass through unchanged.
    try {
      const url = new URL(entry.includes("://") ? entry : `https://${entry}`);
      host = url.hostname.toLowerCase();
    } catch {
      // not a URL — keep the raw lowercased value
    }
    host = stripIpv6Brackets(host);
    if (host) out.add(host);
  }
  return out;
}

function ReadinessPanel({ readiness }: ReadinessPanelProps) {
  const perHost = readiness.per_host_coverage;
  const totalUnmet = perHost
    ? perHost.hosts.reduce((sum, row) => sum + row.unmet_objectives.length, 0)
    : 0;
  const totalDeferrals = perHost
    ? perHost.hosts.reduce((sum, row) => sum + row.deferrals.length, 0)
    : 0;

  // P1#3 scope-literal filter state. Default = ON (matches CLI default).
  // Disabled when scope.json had no literal entries (wildcard-only scope)
  // because the filter would hide every row.
  const scopeLiterals = useMemo(
    () => deriveScopeLiterals(perHost?.scope_hosts),
    [perHost?.scope_hosts],
  );
  const filterAvailable = scopeLiterals.size > 0;
  const [scopeLiteralsOnly, setScopeLiteralsOnly] = useState(true);
  const effectiveFilter = filterAvailable && scopeLiteralsOnly;

  return (
    <section className="panel" data-testid="readiness-panel" aria-labelledby="report-checks-title">
      <div className="panel-header">
        <h2 id="report-checks-title">Report checks</h2>
        <span data-testid="readiness-overall-badge">
          <StatusPill
            value={readiness.ready ? "ready" : "blocked"}
            tone={readiness.ready ? "success" : "danger"}
            label={readiness.ready ? "Ready" : `Blocked · ${readiness.blocker_count.toLocaleString("en-US")} ${readiness.blocker_count === 1 ? "blocker" : "blockers"}`}
            title={readiness.ready ? "Every report check passes" : "A final report export is blocked; see Report blockers"}
          />
        </span>
      </div>

      <div className="stats-grid">
        <article className="stat-card">
          <span className="stat-value">{readiness.blocker_count}</span>
          <span className="meta-text">Report blockers</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{perHost?.hosts.length ?? "Unknown"}</span>
          <span className="meta-text">Hosts with signal</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{perHost ? totalUnmet : "Unknown"}</span>
          <span className="meta-text">Per-host objectives unmet (WARN)</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{perHost ? totalDeferrals : "Unknown"}</span>
          <span className="meta-text">Active coverage deferrals</span>
        </article>
      </div>

      <PerHostCoverageMatrix
        perHost={perHost}
        scopeLiterals={scopeLiterals}
        filterEnabled={effectiveFilter}
        filterAvailable={filterAvailable}
        onToggleFilter={() => setScopeLiteralsOnly((v) => !v)}
      />

      <EngagementSignalsCard perHost={perHost} />

      <ActiveDeferralsList perHost={perHost} />
    </section>
  );
}

// FU4 — engagement-level signal counts shipped by `per_host_coverage()` but
// not previously rendered. waf_intel_count satisfies the WAF tier objective
// engagement-wide (CDN WAFs typically front the whole property);
// tech_scan_intel_count powers the tech_fingerprint objective; osint_intel_total
// is the OSINT objective. Surfacing them makes the matrix Y/D/N marks
// self-explanatory — operators can see why a row went green at engagement
// level even when no host-specific intel was recorded.
const ENGAGEMENT_SIGNAL_LABELS: Record<string, string> = {
  waf_intel_count: "WAF intel rows (engagement-wide)",
  tech_scan_intel_count: "Tech-scan intel rows",
  osint_intel_total: "OSINT intel rows",
};

function EngagementSignalsCard({ perHost }: { perHost: PerHostCoverage | undefined }) {
  if (!perHost) return null;
  const signals = perHost.engagement_signals ?? {};
  const entries = Object.entries(ENGAGEMENT_SIGNAL_LABELS);
  // Render even when every value is 0/undefined — a row of zeros is itself
  // useful operator signal ("OSINT hasn't run yet").
  return (
    <div className="readiness-engagement-signals" data-testid="readiness-engagement-signals">
      <h3>Engagement-level signals</h3>
      <div className="stats-grid">
        {entries.map(([key, label]) => {
          const value = typeof signals[key] === "number" ? (signals[key] as number) : 0;
          return (
            <article className="stat-card" key={key} data-testid={`readiness-signal-${key}`}>
              <span className="stat-value">{value}</span>
              <span className="meta-text">{label}</span>
            </article>
          );
        })}
      </div>
      <p className="meta-text">
        Engagement-wide intel feeds matrix objectives without per-host
        evidence: WAF-class intel satisfies <code>waf_tier</code> for every
        host, OSINT intel satisfies <code>osint</code> engagement-wide.
      </p>
    </div>
  );
}

function PerHostCoverageMatrix({
  perHost,
  scopeLiterals,
  filterEnabled,
  filterAvailable,
  onToggleFilter,
}: {
  perHost: PerHostCoverage | undefined;
  scopeLiterals: Set<string>;
  filterEnabled: boolean;
  filterAvailable: boolean;
  onToggleFilter: () => void;
}) {
  if (!perHost) {
    return (
      <p className="meta-text" data-testid="readiness-no-per-host">
        Per-host coverage projection unavailable.
      </p>
    );
  }
  if (perHost.hosts.length === 0) {
    return (
      <p className="meta-text" data-testid="readiness-no-hosts">
        No per-host coverage signals are recorded.
      </p>
    );
  }

  return <PerHostCoverageMatrixBody
    perHost={perHost}
    scopeLiterals={scopeLiterals}
    filterEnabled={filterEnabled}
    filterAvailable={filterAvailable}
    onToggleFilter={onToggleFilter}
  />;
}

// Split out of PerHostCoverageMatrix so the early-return guards above can stay
// hook-free while the body owns collapse/expander state (hooks must run
// unconditionally). perHost is guaranteed non-empty here.
function PerHostCoverageMatrixBody({
  perHost,
  scopeLiterals,
  filterEnabled,
  filterAvailable,
  onToggleFilter,
}: {
  perHost: PerHostCoverage;
  scopeLiterals: Set<string>;
  filterEnabled: boolean;
  filterAvailable: boolean;
  onToggleFilter: () => void;
}) {
  // Partition rows into scope literals vs wildcard-discovered when the
  // filter is on. Matches FU1's CLI behavior in
  // agent/scripts/assess/commands/check_scope_coverage.py.
  // Memoized so the partition (and the uncovered-first ordering below) is not
  // recomputed on a no-op WebSocket refresh: deps are exactly the inputs read.
  const { visibleRows, hiddenRows } = useMemo(() => {
    const visible = filterEnabled
      ? perHost.hosts.filter((row) => scopeLiterals.has(row.host.toLowerCase()))
      : perHost.hosts;
    const hidden = filterEnabled
      ? perHost.hosts.filter((row) => !scopeLiterals.has(row.host.toLowerCase()))
      : [];
    return { visibleRows: visible, hiddenRows: hidden };
  }, [perHost.hosts, scopeLiterals, filterEnabled]);
  const hiddenWithUnmet = hiddenRows.filter((row) => row.unmet_objectives.length > 0).length;
  const hiddenWithDeferral = hiddenRows.filter((row) => row.deferrals.length > 0).length;

  // Section-collapse: default collapsed only when the matrix is large
  // (host count over the row cap). The localStorage preference, when set,
  // overrides the size-based default and survives WS refreshes / reloads.
  const sectionDefaultCollapsed = visibleRows.length > PER_HOST_ROW_CAP;
  const [collapsed, setCollapsed] = useState(() =>
    readPerHostCollapsed(sectionDefaultCollapsed),
  );
  useEffect(() => {
    try {
      window.localStorage.setItem(PER_HOST_COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      // ignore
    }
  }, [collapsed]);

  // Row cap with uncovered-first ordering in the capped view, so the most
  // actionable hosts (those with unmet objectives) are the ones shown before
  // the operator expands. Stable sort preserves backend order within each
  // group. Only reorders the capped slice; the expanded view keeps full order.
  const [rowsExpanded, setRowsExpanded] = useState(false);
  const cappedRows = useMemo(() => {
    if (rowsExpanded || visibleRows.length <= PER_HOST_ROW_CAP) return visibleRows;
    const uncovered = visibleRows.filter((row) => row.unmet_objectives.length > 0);
    const covered = visibleRows.filter((row) => row.unmet_objectives.length === 0);
    return [...uncovered, ...covered].slice(0, PER_HOST_ROW_CAP);
  }, [visibleRows, rowsExpanded]);
  const rowsHidden = visibleRows.length - cappedRows.length;

  return (
    <div className="readiness-matrix" data-testid="readiness-matrix">
      <button
        type="button"
        className="sessions-toggle readiness-matrix-collapse"
        onClick={() => setCollapsed((v) => !v)}
        aria-expanded={!collapsed}
        data-testid="readiness-matrix-collapse"
      >
        <span>Per-host coverage</span>
        <span className="sessions-count">{visibleRows.length}</span>
        <span>{collapsed ? "▾" : "▴"}</span>
      </button>
      {!collapsed && (
        <>
          <div className="readiness-matrix-controls">
            <button
              type="button"
              className={`filter-chip ${filterEnabled ? "is-active" : ""}`}
              disabled={!filterAvailable}
              onClick={onToggleFilter}
              data-testid="readiness-scope-literal-toggle"
              title={
                filterAvailable
                  ? "Toggle between scope.json literals only and the full discovered-host matrix"
                  : "Scope-literal filter unavailable — scope.json has no explicit literal hosts"
              }
            >
              Scope literals only
            </button>
          </div>
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {perHost.objectives.map((obj) => (
                  <th key={obj} title={obj}>
                    {objectiveLabel(obj)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cappedRows.map((row) => (
                <ReadinessMatrixRow key={row.host} row={row} objectives={perHost.objectives} />
              ))}
            </tbody>
          </table>
          {rowsHidden > 0 && (
            <button
              type="button"
              className="timeline-show-more overview-show-more"
              onClick={() => setRowsExpanded(true)}
              data-testid="readiness-matrix-show-all"
            >
              Show all {visibleRows.length} hosts ({rowsHidden} more)
            </button>
          )}
          {rowsExpanded && visibleRows.length > PER_HOST_ROW_CAP && (
            <button
              type="button"
              className="timeline-show-more overview-show-more"
              onClick={() => setRowsExpanded(false)}
              data-testid="readiness-matrix-show-fewer"
            >
              Show fewer
            </button>
          )}
          {filterEnabled && hiddenRows.length > 0 && (
            <p className="meta-text" data-testid="readiness-discovered-summary">
              {hiddenRows.length} discovered host{hiddenRows.length === 1 ? "" : "s"} from
              wildcard expansion hidden: {hiddenWithUnmet} unmet, {hiddenWithDeferral} with
              deferrals. Click <strong>Scope literals only</strong> above to show the full
              matrix.
            </p>
          )}
          <p className="meta-text">
            Cells: <strong>Y</strong> objective met, <strong>D</strong> intentionally
            deferred via <code>coverage_deferral</code>, <strong>N</strong> unmet
            (WARN-only — does not block phase advance).
          </p>
        </>
      )}
    </div>
  );
}

// React.memo: the matrix tbody re-renders on every WS refresh (parent
// ReadinessPanel re-renders) and on the scope-literal filter toggle. Memoizing
// the row means unchanged hosts skip re-render — only rows whose `row` /
// `objectives` reference actually changes repaint. `row` and `objectives` are
// stable references off the fetched `per_host_coverage` between refreshes that
// don't touch coverage, so this is a real cache hit, not just shallow-equal
// churn. The default shallow prop comparison is exactly right here.
const ReadinessMatrixRow = memo(function ReadinessMatrixRow({
  row,
  objectives,
}: {
  row: PerHostCoverageHost;
  objectives: string[];
}) {
  return (
    <tr data-testid={`readiness-row-${row.host}`}>
      <th scope="row">
        <code>{row.host}</code>
      </th>
      {objectives.map((obj) => {
        const outcome = row.outcomes[obj];
        const evidence = outcome?.evidence?.length
          ? outcome.evidence.join(", ")
          : "";
        return (
          <td key={obj} className="readiness-cell">
            <span data-testid={`readiness-cell-${row.host}-${obj}`}>
              <StatusPill value={outcomeMarker(outcome)} tone={outcomeTone(outcome)} label={outcomeMarker(outcome)} title={evidence || undefined} size="sm" />
            </span>
          </td>
        );
      })}
    </tr>
  );
});

function ActiveDeferralsList({ perHost }: { perHost: PerHostCoverage | undefined }) {
  if (!perHost) return null;
  const allDeferrals = perHost.hosts.flatMap((row) =>
    row.deferrals.map((d) => ({ host: row.host, deferral: d })),
  );
  if (allDeferrals.length === 0) return null;
  return (
    <div className="readiness-deferrals" data-testid="readiness-deferrals">
      <h3>Active coverage deferrals</h3>
      <ul>
        {allDeferrals.map((entry, idx) => (
          <li key={`${entry.host}-${entry.deferral.id}-${idx}`}>
            <code>{entry.host}</code>
            <span className="meta-text">
              {" "}
              — {describeDeferralPayload(entry.deferral.payload)}
            </span>
          </li>
        ))}
      </ul>
      <p className="meta-text">
        Record new deferrals via{" "}
        <code>
          vigil assess agent decision --kind coverage_deferral --payload-json
          '&#123;...&#125;'
        </code>
        . The payload requires <code>deferred_objectives</code> (one or more
        of <code>waf_tier</code>, <code>service_inventory</code>,{" "}
        <code>directory_fuzz</code>, <code>tech_fingerprint</code>,{" "}
        <code>osint</code>), <code>reason</code>, and either a host field
        (<code>host</code> / <code>target</code> / <code>hostname</code> /{" "}
        <code>hosts[]</code>) or <code>engagement_wide: true</code> for an
        engagement-level skip. Resolve via{" "}
        <code>
          PATCH /engagements/&lt;key&gt;/assessment/dispatch-decisions/&lt;id&gt;
        </code>{" "}
        with <code>{`{"resolved": true}`}</code> when the deferred work is done.
      </p>
    </div>
  );
}
