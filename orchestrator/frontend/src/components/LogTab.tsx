import { useEffect, useMemo, useRef, useState } from "react";
import type { ActivityEntry } from "../lib/api";
import { listActivityEntries } from "../lib/api";

type LogTabProps = { engagementKey: string; refreshVersion?: number };

const ACTOR_KINDS = [
  ["", "All actors"], ["operator", "Operator"], ["agent", "Agent"],
  ["hook", "Hook"], ["system", "System"],
] as const;
const TIME_RANGES = [
  ["", "All time"], ["1h", "Last hour"], ["24h", "Last 24h"],
  ["7d", "Last 7 days"], ["30d", "Last 30 days"],
] as const;
const PAGE_SIZE = 100;
const FINDING_SLUG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function rangeToSince(range: string): string | undefined {
  if (!range) return undefined;
  const amount = Number.parseInt(range, 10);
  const ms = range.endsWith("h") ? amount * 3_600_000 : range.endsWith("d") ? amount * 86_400_000 : 0;
  return ms ? new Date(Date.now() - ms).toISOString() : undefined;
}

function isMeaningful(entry: ActivityEntry): boolean {
  if (/\b(error|fail|failed|warning|blocked)\b/i.test(entry.result || "")) return true;
  if (entry.actor_kind === "hook") return false;
  return !/\bbash\b/i.test(`${entry.title || ""} ${entry.action || ""}`);
}

function copyText(value: string) {
  try { void navigator.clipboard?.writeText(value); } catch { /* value stays visible */ }
}

function linkTo(engagementKey: string, tab: string, params: Record<string, string | number> = {}) {
  const query = new URLSearchParams({ tab });
  Object.entries(params).forEach(([key, value]) => query.set(key, String(value)));
  return `#/engagements/${encodeURIComponent(engagementKey)}?${query.toString()}`;
}

function Labeled({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return <div><span className="filter-label">{label}</span>{" "}<span className={mono ? "finding-mono" : "meta-text"}>{value}</span></div>;
}

function MetadataDetails({ entry, engagementKey }: { entry: ActivityEntry; engagementKey: string }) {
  const metadata = entry.metadata && typeof entry.metadata === "object" ? entry.metadata : {};
  if (!Object.keys(metadata).length) return null;
  const raw = JSON.stringify(metadata, null, 2);
  const slug = typeof metadata.finding_slug === "string" && FINDING_SLUG.test(metadata.finding_slug)
    ? metadata.finding_slug : null;
  const requestId = typeof metadata.request_variant_id === "number"
    && Number.isSafeInteger(metadata.request_variant_id) && metadata.request_variant_id > 0
    ? metadata.request_variant_id : null;
  const typed = Boolean(slug || requestId);
  return (
    <div style={{ marginTop: 8 }}>
      <div className="timeline-title-row" style={{ justifyContent: "flex-start", gap: 8 }}>
        <span className="filter-label">Metadata provenance</span>
        <span className="meta-text">{typed ? "Verified typed relation fields" : "Raw metadata; no verified relation shape"}</span>
        <button type="button" className="copy-btn" aria-label={`Copy metadata for entry ${entry.id}`} onClick={() => copyText(raw)}>copy metadata</button>
      </div>
      {typed && <div className="timeline-title-row" style={{ justifyContent: "flex-start", gap: 10, marginTop: 6 }}>
        {slug && <a href={linkTo(engagementKey, "findings", { finding: slug })}>Finding {slug}</a>}
        {requestId && <a href={linkTo(engagementKey, "http", { request: requestId })}>Request variant {requestId}</a>}
      </div>}
      <pre className="finding-notes" style={{ whiteSpace: "pre-wrap", marginTop: 6 }}>{raw}</pre>
    </div>
  );
}

export function LogTab({ engagementKey, refreshVersion = 0 }: LogTabProps) {
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [actorKind, setActorKind] = useState("");
  const [range, setRange] = useState("");
  const [lens, setLens] = useState<"meaningful" | "all">("meaningful");
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedIds, setExpandedIds] = useState<Record<number, boolean>>({});
  const generationRef = useRef(0);

  useEffect(() => {
    let cancelled = false;
    const generation = ++generationRef.current;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    listActivityEntries(engagementKey, {
      q: submittedQuery || undefined,
      actor_kind: actorKind || undefined,
      since: rangeToSince(range),
      limit: PAGE_SIZE,
    }).then((response) => {
      if (cancelled || generation !== generationRef.current) return;
      setEntries(response.items);
      setTotal(response.total);
    }).catch((cause: unknown) => {
      if (!cancelled && generation === generationRef.current) {
        setError(cause instanceof Error ? cause.message : "Failed to load activity log");
      }
    }).finally(() => {
      if (!cancelled && generation === generationRef.current) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [engagementKey, submittedQuery, actorKind, range, refreshVersion]);

  async function loadMore() {
    if (loading || loadingMore || entries.length >= total) return;
    const generation = generationRef.current;
    setLoadingMore(true);
    setError(null);
    try {
      const response = await listActivityEntries(engagementKey, {
        q: submittedQuery || undefined,
        actor_kind: actorKind || undefined,
        since: rangeToSince(range), limit: PAGE_SIZE, offset: entries.length,
      });
      if (generation !== generationRef.current) return;
      setEntries((current) => {
        const merged = new Map(current.map((entry) => [entry.id, entry]));
        response.items.forEach((entry) => merged.set(entry.id, entry));
        return [...merged.values()];
      });
      setTotal(response.total);
    } catch (cause) {
      if (generation === generationRef.current) setError(cause instanceof Error ? cause.message : "More activity could not be loaded");
    } finally {
      if (generation === generationRef.current) setLoadingMore(false);
    }
  }

  const visibleEntries = useMemo(() => {
    const visible = lens === "meaningful" ? entries.filter(isMeaningful) : entries;
    return [...visible].sort((a, b) => (b.occurred_at || b.created_at || "").localeCompare(a.occurred_at || a.created_at || ""));
  }, [entries, lens]);

  return <>
    <section className="panel" style={{ padding: 14 }}>
      <p className="section-title">Narrative activity</p>
      <p className="meta-text">This append-only log records operator and agent narrative. Events owns structured state changes. <a href={linkTo(engagementKey, "activity")}>View structured Events</a>.</p>
    </section>

    <section className="panel filter-bar-panel">
      <div className="filter-bar" style={{ gap: 12, flexWrap: "wrap" }}>
        <div role="group" aria-label="Activity lens" style={{ display: "flex", gap: 6 }}>
          <button type="button" className={`filter-chip ${lens === "meaningful" ? "filter-active" : ""}`} aria-pressed={lens === "meaningful"} onClick={() => setLens("meaningful")}>Meaningful activity</button>
          <button type="button" className={`filter-chip ${lens === "all" ? "filter-active" : ""}`} aria-pressed={lens === "all"} onClick={() => setLens("all")}>All raw activity</button>
        </div>
        <input type="search" className="filter-select" aria-label="Search activity log" placeholder="Search narrative activity…" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") setSubmittedQuery(query.trim()); }} style={{ flex: "1 1 240px", minWidth: 200 }} />
        <button type="button" className="ghost-button" onClick={() => setSubmittedQuery(query.trim())}>Search</button>
        <div className="filter-select-group">
          <label className="filter-label" htmlFor="activity-actor">Actor</label>
          <select id="activity-actor" className="filter-select" value={actorKind} onChange={(event) => setActorKind(event.target.value)}>{ACTOR_KINDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
        </div>
        <div className="filter-select-group">
          <label className="filter-label" htmlFor="activity-time">Time</label>
          <select id="activity-time" className="filter-select" value={range} onChange={(event) => setRange(event.target.value)}>{TIME_RANGES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
        </div>
        {(submittedQuery || actorKind || range) && <button type="button" className="filter-chip filter-active" onClick={() => { setQuery(""); setSubmittedQuery(""); setActorKind(""); setRange(""); }}>Clear filters</button>}
      </div>
    </section>

    <section className="panel">
      <div className="panel-header">
        <h2>Activity log</h2>
        <p className="meta-text">{loading ? "Refreshing…" : `${visibleEntries.length} shown · ${entries.length} loaded · ${total} total`}</p>
      </div>
      {error && <p className="error-text" role="alert" style={{ padding: "0 14px" }}>{error}</p>}
      {!loading && visibleEntries.length === 0 && !error && <p className="empty-state" style={{ padding: 20 }}>{lens === "meaningful" && entries.length ? "No meaningful activity in the loaded page. All raw activity remains available." : "No activity entries yet."}</p>}
      {visibleEntries.length > 0 && <div className="timeline" style={{ marginTop: 8 }}>
        {visibleEntries.map((entry) => {
          const open = expandedIds[entry.id] ?? false;
          const hasBody = Boolean(entry.body_markdown?.trim());
          const bodyId = `activity-body-${entry.id}`;
          return <article key={entry.id} className="timeline-row">
            <div className="timeline-pill">{entry.actor_kind || "system"}</div>
            <div className="timeline-body" style={{ minWidth: 0 }}>
              <div className="timeline-title-row" style={{ alignItems: "baseline", flexWrap: "wrap" }}><strong>{entry.title || "(untitled)"}</strong><span className="meta-text">Entry #{entry.id}</span></div>
              <div className="timeline-title-row" style={{ justifyContent: "flex-start", gap: "6px 14px", flexWrap: "wrap", marginTop: 4 }}>
                <Labeled label="Actor" value={`${entry.actor_kind || "system"} · ${entry.actor_name || "unknown"}`} />
                <Labeled label="Occurred" value={entry.occurred_at || "unknown"} mono />
                <Labeled label="Recorded" value={entry.created_at || "unknown"} mono />
              </div>
              {(entry.action || entry.result) && <div style={{ display: "grid", gap: 4, marginTop: 8 }}><Labeled label="Action" value={entry.action} mono /><Labeled label="Result" value={entry.result} mono /></div>}
              {entry.artifact_ref && <div style={{ marginTop: 6 }}><Labeled label="Artifact reference" value={entry.artifact_ref} mono /><button type="button" className="copy-btn" aria-label={`Copy artifact reference for entry ${entry.id}`} onClick={() => copyText(entry.artifact_ref)}>copy</button></div>}
              <MetadataDetails entry={entry} engagementKey={engagementKey} />
              {hasBody && <button type="button" className="ghost-button" style={{ marginTop: 8 }} aria-expanded={open} aria-controls={bodyId} aria-label={`${open ? "Hide" : "Show"} body details for entry ${entry.id}`} onClick={() => setExpandedIds((current) => ({ ...current, [entry.id]: !current[entry.id] }))}>{open ? "Hide body" : "Show body"}</button>}
              {hasBody && open && <div id={bodyId} style={{ marginTop: 8 }}><span className="filter-label">Body</span><pre className="finding-notes" style={{ whiteSpace: "pre-wrap", marginTop: 4 }}>{entry.body_markdown}</pre><button type="button" className="copy-btn" aria-label={`Copy body for entry ${entry.id}`} onClick={() => copyText(entry.body_markdown)}>copy body</button></div>}
            </div>
          </article>;
        })}
      </div>}
      {entries.length < total && <button type="button" className="ghost-button" onClick={() => void loadMore()} disabled={loadingMore} style={{ marginTop: 14 }}>{loadingMore ? "Loading more activity…" : "Load more activity"}</button>}
    </section>
  </>;
}
