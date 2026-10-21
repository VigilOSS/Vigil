import type { Engagement } from "../lib/api";
import { StatusPill } from "./ui";

type PhaseWaterfallProps = {
  currentPhase?: string;
  trackState?: Engagement["track_state"];
  aggregateComplete?: boolean;
};

export function PhaseWaterfall({ trackState, aggregateComplete, currentPhase }: PhaseWaterfallProps) {
  const tracks = Object.entries(trackState ?? {});
  return (
    <section className="panel track-state-panel" aria-labelledby="enabled-tracks-title">
      <div className="panel-header">
        <h2 id="enabled-tracks-title">Enabled tracks</h2>
        {tracks.length > 0 && <span className="meta-text">{aggregateComplete === true ? "All tracks complete" : aggregateComplete === false ? "Tracks in progress" : "Aggregate state unavailable"}</span>}
      </div>
      {tracks.length === 0 ? (
        <p className="meta-text">Track state unavailable.{currentPhase && <> Legacy phase: <code>{currentPhase}</code></>}</p>
      ) : (
        <div className="track-lanes">
          {tracks.map(([track, state]) => (
            <div key={track} className="track-lane">
              <strong className="track-name">{track}</strong>
              <code>{state.phase || "unknown"}</code>
              {state.repair_required ? (
                <StatusPill value="repair_required" tone="danger" label="Repair required" size="sm" />
              ) : state.complete ? (
                <StatusPill value="complete" tone="success" label="Complete" size="sm" />
              ) : (
                <StatusPill value="in_progress" tone="progress" label="In progress" size="sm" />
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
