import { useState } from "react";
import type { EventRecord } from "../lib/api";

const DEFAULT_VISIBLE = 10;

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
  const [showAll, setShowAll] = useState(false);

  const activityEvents = events.filter((event) => event.event_type !== "artifact.updated");
  const visible = showAll ? activityEvents : activityEvents.slice(-DEFAULT_VISIBLE);
  const hidden = activityEvents.length - DEFAULT_VISIBLE;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Activity log</h2>
        <p className="meta-text">{activityEvents.length} event{activityEvents.length !== 1 ? "s" : ""}</p>
      </div>
      <div className="timeline" style={{ display: "flex", flexDirection: "column" }}>
        {!showAll && hidden > 0 && (
          <button className="timeline-show-more" type="button" onClick={() => setShowAll(true)}>
            Show {hidden} earlier event{hidden !== 1 ? "s" : ""}
          </button>
        )}
        {visible.map((event) => (
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
        {showAll && hidden > 0 && (
          <button className="timeline-show-more" type="button" onClick={() => setShowAll(false)}>
            Show less
          </button>
        )}
        {activityEvents.length === 0 ? <p className="empty-state">No activity yet.</p> : null}
      </div>
    </section>
  );
}
