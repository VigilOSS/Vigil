import { useEffect, useMemo, useRef, useState } from "react";
import type { ActivityEntry } from "../lib/api";
import { listActivityEntries } from "../lib/api";

type LogTabProps = {
  engagementKey: string;
};

const ACTOR_KINDS: { value: string; label: string }[] = [
  { value: "", label: "All actors" },
  { value: "operator", label: "Operator" },
  { value: "agent", label: "Agent" },
  { value: "hook", label: "Hook" },
  { value: "system", label: "System" },
];

const TIME_RANGES: { value: string; label: string }[] = [
  { value: "", label: "All time" },
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

function rangeToSince(range: string): string | undefined {
  if (!range) return undefined;
  const now = Date.now();
  let ms = 0;
  if (range.endsWith("h")) ms = Number.parseInt(range, 10) * 60 * 60 * 1000;
  else if (range.endsWith("d")) ms = Number.parseInt(range, 10) * 24 * 60 * 60 * 1000;
  if (!ms) return undefined;
  return new Date(now - ms).toISOString();
}

const PAGE_SIZE = 100;

export function LogTab({ engagementKey }: LogTabProps) {
  const [query, setQuery] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [actorKind, setActorKind] = useState("");
  const [range, setRange] = useState("");
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedIds, setExpandedIds] = useState<Record<number, boolean>>({});
  const requestGeneration = useRef(0);

  useEffect(() => {
    let cancelled = false;
    const generation = ++requestGeneration.current;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    const since = rangeToSince(range);
    listActivityEntries(engagementKey, {
      q: submittedQuery || undefined,
      actor_kind: actorKind || undefined,
      since,
      limit: PAGE_SIZE,
    })
      .then((resp) => {
        if (cancelled || generation !== requestGeneration.current) return;
        setEntries(resp.items);
        setTotal(resp.total);
      })
      .catch((err: unknown) => {
        if (cancelled || generation !== requestGeneration.current) return;
        setEntries([]);
        setTotal(0);
        setError(err instanceof Error ? err.message : "Failed to load activity log");
      })
      .finally(() => {
        if (!cancelled && generation === requestGeneration.current) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [engagementKey, submittedQuery, actorKind, range]);

  async function loadMore() {
    if (loading || loadingMore || entries.length >= total) return;
    const generation = requestGeneration.current;
    setLoadingMore(true);
    setError(null);
    try {
      const response = await listActivityEntries(engagementKey, {
        q: submittedQuery || undefined,
        actor_kind: actorKind || undefined,
        since: rangeToSince(range),
        limit: PAGE_SIZE,
        offset: entries.length,
      });
      if (generation !== requestGeneration.current) return;
      setEntries((current) => {
        const merged = new Map(current.map((entry) => [entry.id, entry]));
        for (const item of response.items) merged.set(item.id, item);
        return [...merged.values()];
      });
      setTotal(response.total);
    } catch (cause) {
      if (generation !== requestGeneration.current) return;
      setError(cause instanceof Error ? cause.message : "More activity could not be loaded");
    } finally {
      if (generation === requestGeneration.current) setLoadingMore(false);
    }
  }

  const sortedEntries = useMemo(() => {
    return [...entries].sort((a, b) => {
      // Descending by occurred_at; fall back to created_at.
      const left = a.occurred_at || a.created_at || "";
      const right = b.occurred_at || b.created_at || "";
      return right.localeCompare(left);
    });
  }, [entries]);

  function toggleExpanded(id: number) {
    setExpandedIds((current) => ({ ...current, [id]: !current[id] }));
  }

  return (
    <>
      <section className="panel filter-bar-panel">
        <div className="filter-bar" style={{ gap: "12px", flexWrap: "wrap" }}>
          <input
            type="search"
            className="filter-select"
            placeholder="Search log (FTS)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") setSubmittedQuery(query.trim());
            }}
            style={{ flex: "1 1 240px", minWidth: "200px" }}
          />
          <button type="button" className="ghost-button" onClick={() => setSubmittedQuery(query.trim())}>
            Search
          </button>

          <div className="filter-select-group">
            <label className="filter-label">Actor</label>
            <select className="filter-select" value={actorKind} onChange={(e) => setActorKind(e.target.value)}>
              {ACTOR_KINDS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          <div className="filter-select-group">
            <label className="filter-label">Time</label>
            <select className="filter-select" value={range} onChange={(e) => setRange(e.target.value)}>
              {TIME_RANGES.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>

          {(submittedQuery || actorKind || range) && (
            <button
              type="button"
              className="filter-chip filter-active"
              onClick={() => {
                setQuery("");
                setSubmittedQuery("");
                setActorKind("");
                setRange("");
              }}
            >
              Clear all
            </button>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Activity log</h2>
          <p className="meta-text">
            {loading ? "Loading…" : `${sortedEntries.length} of ${total} entr${total === 1 ? "y" : "ies"}`}
          </p>
        </div>

        {error && <p className="error-text" role="alert" style={{ padding: "0 14px" }}>{error}</p>}

        {!loading && sortedEntries.length === 0 && !error && (
          <p className="empty-state" style={{ padding: "20px" }}>No activity entries yet.</p>
        )}

        {sortedEntries.length > 0 && (
          <div className="timeline" style={{ marginTop: "14px" }}>
            {sortedEntries.map((entry) => {
              const isOpen = expandedIds[entry.id] ?? false;
              const hasBody = Boolean(entry.body_markdown && entry.body_markdown.trim());
              return (
                <article key={entry.id} className="timeline-row">
                  <div className="timeline-pill">{entry.actor_kind || "system"}</div>
                  <div className="timeline-body">
                    <div className="timeline-title-row" style={{ alignItems: "baseline", flexWrap: "wrap" }}>
                      <strong>{entry.title || "(untitled)"}</strong>
                      <span className="meta-text">{entry.actor_name || "unknown"}</span>
                      <span className="meta-text">{entry.occurred_at || entry.created_at}</span>
                    </div>
                    {(entry.action || entry.result) && (
                      <p className="meta-text">
                        {entry.action}
                        {entry.action && entry.result ? " → " : ""}
                        {entry.result}
                      </p>
                    )}
                    {entry.artifact_ref && (
                      <p className="meta-text finding-mono">{entry.artifact_ref}</p>
                    )}
                    {hasBody && (
                      <button
                        type="button"
                        className="ghost-button"
                        style={{ marginTop: "6px" }}
                        onClick={() => toggleExpanded(entry.id)}
                      >
                        {isOpen ? "Hide details" : "Show details"}
                      </button>
                    )}
                    {hasBody && isOpen && (
                      <pre className="finding-notes" style={{ whiteSpace: "pre-wrap", marginTop: "8px" }}>
                        {entry.body_markdown}
                      </pre>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
        {entries.length < total ? (
          <button
            type="button"
            className="ghost-button"
            onClick={() => void loadMore()}
            disabled={loadingMore}
            style={{ marginTop: "14px" }}
          >
            {loadingMore ? "Loading more activity…" : "Load more activity"}
          </button>
        ) : null}
      </section>
    </>
  );
}
