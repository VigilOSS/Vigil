import { useState } from "react";
import type { EventRecord } from "../lib/api";

const DEFAULT_VISIBLE = 10;

type TaskTimelineProps = {
  events: EventRecord[];
};

export function TaskTimeline({ events }: TaskTimelineProps) {
  const [showAll, setShowAll] = useState(false);

  const taskEvents = events.filter((event) => event.event_type.startsWith("task."));
  const visible = showAll ? taskEvents : taskEvents.slice(-DEFAULT_VISIBLE);
  const hidden = taskEvents.length - DEFAULT_VISIBLE;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Activity log</h2>
        <p className="meta-text">{taskEvents.length} task event{taskEvents.length !== 1 ? "s" : ""}</p>
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
              <p>{event.summary}</p>
            </div>
          </article>
        ))}
        {showAll && hidden > 0 && (
          <button className="timeline-show-more" type="button" onClick={() => setShowAll(false)}>
            Show less
          </button>
        )}
        {taskEvents.length === 0 ? <p className="empty-state">No task events yet.</p> : null}
      </div>
    </section>
  );
}
