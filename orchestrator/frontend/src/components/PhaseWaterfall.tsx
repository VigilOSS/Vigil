import { useMemo } from "react";
import type { EventRecord } from "../lib/api";

// The canonical web-track roster, in order, with the ONE place a phase is
// displayed differently from the value the backend stores. Mirrors
// `agent/scripts/assess/lib/phases.py:WEB_PHASES`; the terminal `complete`
// state is not a card (it marks every card completed instead).
// `orchestrator/backend/tests/test_phase_roster.py` pins this literal against
// that roster, so a new phase cannot land without a card here.
const PHASES = [
  { key: "recon", label: "Recon" },
  { key: "collect", label: "Collect" },
  { key: "consume-test", label: "Consume & Test" },
  { key: "verify", label: "Verify" },
  { key: "exploit", label: "Exploit" },
  { key: "report", label: "Report" },
] as const;

const TERMINAL_PHASE = "complete";

const PHASE_KEYS: readonly string[] = PHASES.map((phase) => phase.key);

type PhaseWaterfallProps = {
  events: EventRecord[];
  currentPhase: string;
};

function phaseState(events: EventRecord[], phase: string, currentPhase: string) {
  const relevant = events.filter((event) => event.phase === phase);
  if (relevant.some((event) => event.event_type === "phase.completed")) {
    return "completed";
  }
  if (relevant.some((event) => event.event_type === "phase.started")) {
    return "active";
  }

  if (currentPhase === TERMINAL_PHASE) {
    return "completed";
  }

  const currentIndex = PHASE_KEYS.indexOf(currentPhase);
  const phaseIndex = PHASE_KEYS.indexOf(phase);
  if (currentIndex >= 0 && phaseIndex >= 0) {
    if (phaseIndex < currentIndex) return "completed";
    if (phaseIndex === currentIndex) return "active";
  }

  return "pending";
}

export function PhaseWaterfall({ events, currentPhase }: PhaseWaterfallProps) {
  // Memoize the multi-pass scans of the whole events array (hasStructuredEvents
  // + a phaseState() filter per phase), so on the 2s WebSocket refresh these
  // only recompute when `events` / `currentPhase` actually change identity.
  const { hasStructuredEvents, phaseStates } = useMemo(
    () => ({
      hasStructuredEvents: events.some((event) => event.event_type.startsWith("task.")),
      phaseStates: PHASES.map((phase) => phaseState(events, phase.key, currentPhase)),
    }),
    [events, currentPhase],
  );
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Phase waterfall</h2>
        <p className="meta-text">
          {hasStructuredEvents ? `${PHASES.length}-phase autonomous workflow` : "Using workflow state because no structured task events were recorded"}
        </p>
      </div>
      <div className="waterfall">
        {PHASES.map((phase, i) => {
          const state = phaseStates[i];
          return (
            <article key={phase.key} className={`phase-card phase-${state}`}>
              <p className="eyebrow">{state}</p>
              <h3>{phase.label}</h3>
            </article>
          );
        })}
      </div>
    </section>
  );
}
