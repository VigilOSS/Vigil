import { useMemo, useState } from "react";
import type { EventRecord } from "../lib/api";

const PAGE_SIZE = 20;

type TaskTimelineProps = {
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

export function TaskTimeline({ events }: TaskTimelineProps) {
  const [page, setPage] = useState(0);

  const activityEvents = useMemo(
    () => events.filter((event) => event.event_type !== "artifact.updated"),
    [events],
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
        <h2>Activity log</h2>
        <p className="meta-text">{activityEvents.length} event{activityEvents.length !== 1 ? "s" : ""}</p>
      </div>
      <div className="timeline" style={{ display: "flex", flexDirection: "column" }}>
        {pageEvents.map((event) => (
          <article key={event.id} className="timeline-row">
            <div className="timeline-pill">{event.phase}</div>
            <div className="timeline-body">
              <div className="timeline-title-row">
                <strong>{event.task_name}</strong>
                <span className="meta-text">{event.agent_name}</span>
              </div>
              <p>
                <span className={`badge event-type-${eventTypeLabel(event.event_type)}`}>{eventTypeLabel(event.event_type)}</span>
                {" "}{event.summary}
              </p>
            </div>
          </article>
        ))}
        {activityEvents.length === 0 ? <p className="empty-state">No activity yet.</p> : null}
      </div>
      {totalPages > 1 && (
        <div className="pager">
          <button type="button" className="pager-button" disabled={safePage >= lastPage} onClick={() => setPage(safePage + 1)}>Older</button>
          <span className="meta-text">Page {safePage + 1} of {totalPages}</span>
          <button type="button" className="pager-button" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>Newer</button>
        </div>
      )}
    </section>
  );
}
