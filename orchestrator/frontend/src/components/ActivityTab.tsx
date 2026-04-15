import { useState } from "react";
import type { EngagementSession, EventRecord } from "../lib/api";
import { TaskTimeline } from "./TaskTimeline";

type ActivityTabProps = {
  events: EventRecord[];
  sessions: EngagementSession[];
};

export function ActivityTab({ events, sessions }: ActivityTabProps) {
  const [sessionsOpen, setSessionsOpen] = useState(false);

  return (
    <>
      <TaskTimeline events={events} />

      <section className="panel">
        <button
          type="button"
          className="sessions-toggle"
          onClick={() => setSessionsOpen((o) => !o)}
          aria-expanded={sessionsOpen}
        >
          <span>Sessions</span>
          <span className="sessions-count">{sessions.length}</span>
          <span>{sessionsOpen ? "▴" : "▾"}</span>
        </button>
        {sessionsOpen && (
          <div className="timeline" style={{ marginTop: "14px" }}>
            {sessions.map((session) => (
              <article key={session.id} className="timeline-row">
                <div className="timeline-pill">{session.merge_state}</div>
                <div className="timeline-body">
                  <div className="timeline-title-row">
                    <strong>{session.session_id}</strong>
                    <span className="meta-text">{session.status}</span>
                  </div>
                  {session.assigned_targets.length > 0 && (
                    <p className="meta-text">{session.assigned_targets.join(", ")}</p>
                  )}
                </div>
              </article>
            ))}
            {sessions.length === 0 && <p className="empty-state">No sessions recorded yet.</p>}
          </div>
        )}
      </section>
    </>
  );
}
