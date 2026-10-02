import { useMemo, useState } from "react";
import { engagementHref } from "../lib/workspaceRoutes";
import type { EventRecord } from "../lib/api";

const PAGE_SIZE = 20;

type TaskTimelineProps = {
  engagementKey: string;
  events: EventRecord[];
};

function eventTypeLabel(eventType: string): string {
  switch (eventType) {
    case "finding.created": return "finding";
    case "finding.merged": return "merge";
    case "chain.created": return "chain";
    case "surface.updated": return "surface";
    case "artifact.updated": return "artifact";
    case "phase.started": return "phase";
    case "phase.completed": return "phase";
    case "task.started": return "task";
    case "task.completed": return "task";
    default: return eventType.split(".")[0] ?? eventType;
  }
}

function isOperationalActivity(event: EventRecord): boolean {
  return event.id < 0 || event.event_type.startsWith("task.") || event.event_type === "artifact.updated";
}

export function TaskTimeline({ engagementKey, events }: TaskTimelineProps) {
  const [page, setPage] = useState(0);
  const [includeOperationalActivity, setIncludeOperationalActivity] = useState(false);

  const activityEvents = useMemo(
    () => events.filter((event) => includeOperationalActivity || !isOperationalActivity(event)),
    [events, includeOperationalActivity],
  );

  const totalPages = Math.max(1, Math.ceil(activityEvents.length / PAGE_SIZE));
  // Clamp page if data shrinks
  const safePage = Math.min(page, totalPages - 1);

  // Show most recent first: last page = newest events
  const lastPage = totalPages - 1;
  const displayPage = lastPage - safePage;
  const pageEvents = activityEvents.slice(displayPage * PAGE_SIZE, (displayPage + 1) * PAGE_SIZE);

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Recent events</h2>
        <p className="meta-text">
          {activityEvents.length} shown · {events.length} loaded
        </p>
      </div>
      <div className="event-timeline-controls" role="group" aria-label="Event timeline view">
        <button
          type="button"
          className={`filter-chip ${!includeOperationalActivity ? "is-active" : ""}`}
          aria-label="Lifecycle and decisions only"
          aria-pressed={!includeOperationalActivity}
          onClick={() => {
            setIncludeOperationalActivity(false);
            setPage(0);
          }}
        >
          Lifecycle + decisions
        </button>
        <button
          type="button"
          className={`filter-chip ${includeOperationalActivity ? "is-active" : ""}`}
          aria-label="Include operational activity"
          aria-pressed={includeOperationalActivity}
          onClick={() => {
            setIncludeOperationalActivity(true);
            setPage(0);
          }}
        >
          Include operational activity
        </button>
      </div>
      <p className="event-history-boundary" role="note">
        Events shows at most the latest 200 rows; earlier history may exist. {" "}
        <a href={engagementHref(engagementKey, { tab: "log" })}>
          Open complete Audit log
        </a>
      </p>
      <div className="timeline" style={{ display: "flex", flexDirection: "column" }}>
        {pageEvents.map((event) => (
          <article key={event.id} className="timeline-row">
            <div className="timeline-pill">{event.phase}</div>
            <div className="timeline-body">
              <div className="timeline-title-row">
                <strong>{event.task_name}</strong>
                <span className="meta-text">{event.agent_name}</span>
              </div>
              <div className="event-provenance">
                <span className={`badge ${event.id < 0 ? "event-source-inferred" : "event-source-persisted"}`}>
                  {event.id < 0 ? "Inferred from activity" : "Persisted structured event"}
                </span>
                <time className="meta-text" dateTime={event.created_at}>{event.created_at}</time>
              </div>
              <p>
                <span className={`badge event-type-${eventTypeLabel(event.event_type)}`}>{eventTypeLabel(event.event_type)}</span>
                {" "}{event.summary}
              </p>
            </div>
          </article>
        ))}
        {activityEvents.length === 0 ? <p className="empty-state">{events.length === 0 || includeOperationalActivity ? "No events in the loaded history." : "No lifecycle or decision events in the loaded history."}</p> : null}
      </div>
      {totalPages > 1 && (
        <div className="pager">
          <button type="button" className="pager-button" aria-label="Older event page" disabled={safePage >= lastPage} onClick={() => setPage(safePage + 1)}>Older</button>
          <span className="meta-text">Page {safePage + 1} of {totalPages}</span>
          <button type="button" className="pager-button" aria-label="Newer event page" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>Newer</button>
        </div>
      )}
    </section>
  );
}
