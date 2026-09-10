import { memo, useEffect, useMemo, useState } from "react";
import type {
  AssessmentAttackChain,
  AssessmentAttackChainDetail,
  AssessmentAttackChainLink,
  AssessmentFinding,
  AssessmentFindingDetail,
  AssessmentSummary,
  EventRecord,
  PerHostCoverage,
  PerHostCoverageHost,
  PerHostOutcome,
  ReportReadiness,
} from "../lib/api";
import { getReportReadiness } from "../lib/api";
import { PhaseWaterfall } from "./PhaseWaterfall";
import { ChartSkeleton } from "./Skeletons";
import { SeverityDonut } from "./charts/SeverityDonut";
import { SummaryStatBar } from "./charts/SummaryStatBar";
import type { SummaryStatBarItem } from "./charts/SummaryStatBar";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

// Below-the-fold list caps (scroll-length reduction). Lists render up to the
// cap by default with a "Show all N" expander revealing the rest in place; no
// data is removed — everything stays reachable. Activity is already capped to
// the last 5 events at the source (latestEvents slice).
const ATTACK_CHAIN_CAP = 8;

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
  events: EventRecord[];
  assessmentSummary: AssessmentSummary | null;
  findings: (AssessmentFindingDetail | AssessmentFinding)[];
  chains: (AssessmentAttackChainDetail | AssessmentAttackChain)[];
  chainLinks: AssessmentAttackChainLink[];
  currentPhase: string;
  assessmentRefreshVersion: number;
};

function sortFindings(findings: (AssessmentFindingDetail | AssessmentFinding)[]) {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
    if (severityDelta !== 0) return severityDelta;
    return left.title.localeCompare(right.title);
  });
}

function verificationSummary(finding: AssessmentFindingDetail | AssessmentFinding) {
  return finding.verification_status;
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

function outcomeBadgeClass(outcome: PerHostOutcome | undefined): string {
  if (!outcome) return "badge severity-info";
  if (outcome.deferred) return "badge severity-medium";
  if (outcome.met) return "badge severity-low";
  return "badge severity-high";
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

export function OverviewTab({ engagementKey, events, assessmentSummary, findings, chains, chainLinks, currentPhase, assessmentRefreshVersion }: OverviewTabProps) {
  const s = assessmentSummary;
  const [readiness, setReadiness] = useState<ReportReadiness | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  // Memoize the per-render derivations so the 2s WebSocket refresh doesn't
  // re-sort / re-filter when the underlying arrays are unchanged (cache hit).
  // Deps are exactly the source arrays each derivation reads, so live updates
  // still flow through: a new `findings` / `events` identity recomputes.
  const sortedFindings = useMemo(() => sortFindings(findings), [findings]);
  const latestEvents = useMemo(
    () => events.filter((e) => e.event_type !== "artifact.updated").slice(-5),
    [events],
  );

  // Per-chain linked-finding titles. Previously recomputed on EVERY render as
  // O(chains × links × findings) — for each chain it filtered all chainLinks
  // then did a linear findings.find() per link. Here we build slug/id finding
  // indexes once, then bucket the finding-kind links by chain_key in a single
  // pass, preserving chainLinks' original order (so the joined string matches
  // today exactly). Result: a Map<chain_key, string[]> resolved lazily.
  const linkedFindingsByChain = useMemo(() => {
    const bySlug = new Map<string, AssessmentFindingDetail | AssessmentFinding>();
    const byId = new Map<number, AssessmentFindingDetail | AssessmentFinding>();
    for (const f of findings) {
      bySlug.set(f.slug, f);
      if ("id" in f) byId.set(f.id, f);
    }
    const out = new Map<string, string[]>();
    for (const link of chainLinks) {
      if (link.entity_kind !== "finding") continue;
      const match =
        (link.entity_ref ? bySlug.get(link.entity_ref) : undefined) ??
        (link.entity_id != null ? byId.get(link.entity_id) : undefined);
      const title = match ? match.title : link.entity_ref || `finding #${link.entity_id}`;
      const list = out.get(link.chain_key);
      if (list) list.push(title);
      else out.set(link.chain_key, [title]);
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
    { label: "Findings", value: s?.finding_count ?? 0 },
    { label: "Crit/High", value: critHigh, tone: critHigh > 0 ? "danger" : "ok" },
    { label: "Surfaces", value: s?.open_surface_count ?? 0 },
    { label: "Services", value: s?.service_count ?? 0 },
    { label: "Chains", value: s?.attack_chain_count ?? 0 },
    { label: "Exploitable", value: s?.exploit_candidate_count ?? 0 },
    {
      label: "Report blockers",
      value: s?.report_blocker_count ?? 0,
      tone: (s?.report_blocker_count ?? 0) > 0 ? "danger" : "ok",
    },
  ];

  useEffect(() => {
    let cancelled = false;
    getReportReadiness(engagementKey)
      .then((row) => {
        if (!cancelled) {
          setReadiness(row);
          setReadinessError(null);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) setReadinessError(error instanceof Error ? error.message : String(error));
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, assessmentRefreshVersion]);

  return (
    <>
      <PhaseWaterfall events={events} currentPhase={currentPhase} />

      {egressBannerVisible && (
        <section className="panel" data-testid="egress-reputation-banner">
          <div className="panel-header">
            <h2>Egress reputation block detected</h2>
          </div>
          <p>
            <strong>{egressBlockedPct}%</strong> of representative live hosts returned 403 / 000-status from
            the runtime egress IP (pattern: <code>{egressStatus?.pattern ?? "unknown"}</code>). Choose a
            mitigation before continuing Phase 3 dispatch:
          </p>
          <ol>
            <li>
              <button type="button" data-testid="egress-choice-allowlist">
                Request IP allowlisting from the program
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-proxy">
                Route through a residential proxy or clean-IP VPS
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-browser">
                Use a browser-based tool inside the runtime
              </button>
            </li>
            <li>
              <button type="button" data-testid="egress-choice-accept">
                Accept the limited coverage and document the gap
              </button>
            </li>
          </ol>
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
        <div className="overview-charts-row">
          {summaryLoading ? (
            <div className="overview-charts-donut">
              <ChartSkeleton variant="donut" height={140} label="Severity mix" />
            </div>
          ) : (
            // Older backends omit finding_severities — hide the donut column
            // gracefully and let the stat bar take the full row.
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
            <SummaryStatBar items={statBarItems} />
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Coverage</h2>
        </div>
        <div className="stats-grid">
          <article className="stat-card">
            <span className="stat-value">{s?.finding_count ?? 0}</span>
            <span className="meta-text">Findings</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.attack_chain_count ?? 0}</span>
            <span className="meta-text">Attack chains</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.probe_count ?? 0}</span>
            <span className="meta-text">Probe runs</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.target_count ?? 0}</span>
            <span className="meta-text">Targets</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.service_count ?? 0}</span>
            <span className="meta-text">Services</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.open_surface_count ?? 0}</span>
            <span className="meta-text">Open surfaces</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.exploit_candidate_count ?? 0}</span>
            <span className="meta-text">Exploit candidates</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.coverage_blocker_count ?? 0}</span>
            <span className="meta-text">Coverage blockers</span>
          </article>
          <article className="stat-card">
            <span className="stat-value">{s?.report_blocker_count ?? 0}</span>
            <span className="meta-text">Report blockers</span>
          </article>
        </div>
      </section>

      {readiness && (
        <ReadinessPanel readiness={readiness} />
      )}

      {readiness && !readiness.ready && (
        <section className="panel report-blockers-panel">
          <div className="panel-header">
            <h2>Report blockers</h2>
          </div>
          <div className="blocker-list">
            {readiness.blockers.map((blocker, index) => {
              const affected = blocker.slug ? [blocker.slug] : blocker.slugs || [];
              return (
                <article key={`${blocker.kind}-${index}`} className="blocker-row">
                  <span className="badge severity-high">{blocker.kind.replace(/_/g, " ")}</span>
                  <div>
                    {affected.length > 0 && (
                      <p className="meta-text">
                        Findings: {affected.map((slug) => <code key={slug}>{slug}</code>)}
                      </p>
                    )}
                    <p>{blocker.detail || "No detail provided."}</p>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      )}
      {readinessError && (
        <section className="panel">
          <p className="meta-text">Report readiness unavailable: {readinessError}</p>
        </section>
      )}

      <section className="engagement-grid">
        <article className="panel">
          <p className="eyebrow">Findings</p>
          <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
            {sortedFindings.slice(0, 5).map((f) => (
              <div key={f.slug} style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                <strong>{f.title}</strong>
                <span className={`badge severity-${f.severity}`}>{f.severity}</span>
                <span className="meta-text">{f.workflow_status}</span>
                <span className="meta-text">{verificationSummary(f)}</span>
              </div>
            ))}
            {sortedFindings.length > 5 && (
              <p className="meta-text">+{sortedFindings.length - 5} more</p>
            )}
            {sortedFindings.length === 0 && <p className="meta-text">No findings recorded yet.</p>}
          </div>
        </article>

        <article className="panel">
          <p className="eyebrow">Attack chains</p>
          <div style={{ display: "grid", gap: "12px", marginTop: "8px" }}>
            {visibleChains.map((c) => {
              const linkedFindings = linkedFindingsByChain.get(c.chain_key) ?? [];
              return (
                <div key={c.chain_key} style={{ display: "grid", gap: "4px" }}>
                  <div style={{ display: "flex", alignItems: "baseline", gap: "8px", flexWrap: "wrap" }}>
                    <span className={`badge severity-${c.severity}`}>{c.severity}</span>
                    <strong>{c.title}</strong>
                    <span className="meta-text">{c.status}</span>
                  </div>
                  {c.narrative && <p className="meta-text">{c.narrative}</p>}
                  {linkedFindings.length > 0 && (
                    <p className="meta-text">Findings: {linkedFindings.join(", ")}</p>
                  )}
                </div>
              );
            })}
            {chains.length === 0 && <p className="meta-text">No attack chains linked yet.</p>}
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
        </article>
      </section>

      {latestEvents.length > 0 && (
        <section className="panel">
          <div className="panel-header">
            <h2>Latest activity</h2>
          </div>
          <div className="timeline">
            {latestEvents.map((event) => (
              <article key={event.id} className="timeline-row">
                <div className="timeline-pill">{event.phase}</div>
                <div className="timeline-body">
                  <div className="timeline-title-row">
                    <strong>{event.task_name}</strong>
                    <span className="meta-text">{event.agent_name}</span>
                  </div>
                  <p>{event.summary}</p>
                </div>
              </article>
            ))}
          </div>
        </section>
      )}
    </>
  );
}


type ReadinessPanelProps = {
  readiness: ReportReadiness;
};

// C58 — Readiness panel renders:
//  1. The Definition-of-Done summary (overall ready/blocked indicator + blocker count)
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
  const hasHosts = !!perHost && perHost.hosts.length > 0;
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
    <section className="panel" data-testid="readiness-panel">
      <div className="panel-header">
        <h2>Readiness</h2>
        <span
          className={`badge ${readiness.ready ? "severity-low" : "severity-high"}`}
          data-testid="readiness-overall-badge"
        >
          {readiness.ready ? "READY" : `BLOCKED (${readiness.blocker_count})`}
        </span>
      </div>

      <div className="stats-grid">
        <article className="stat-card">
          <span className="stat-value">{readiness.blocker_count}</span>
          <span className="meta-text">Definition-of-Done blockers</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{hasHosts ? perHost!.hosts.length : 0}</span>
          <span className="meta-text">Hosts with signal</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{totalUnmet}</span>
          <span className="meta-text">Per-host objectives unmet (WARN)</span>
        </article>
        <article className="stat-card">
          <span className="stat-value">{totalDeferrals}</span>
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
        No hosts have backend signal yet. Dispatch recon-specialist to populate
        services / surfaces / intel tables before re-checking.
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
            <span
              className={outcomeBadgeClass(outcome)}
              title={evidence}
              data-testid={`readiness-cell-${row.host}-${obj}`}
            >
              {outcomeMarker(outcome)}
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
