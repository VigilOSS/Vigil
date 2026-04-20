import type { EventRecord } from "../lib/api";

const PHASES = ["recon", "collect", "consume-test", "exploit", "report"];

type PhaseWaterfallProps = {
  events: EventRecord[];
  currentPhase: string;
};

function phaseLabel(phase: string) {
  switch (phase) {
    case "consume-test":
      return "Consume & Test";
    default:
      return phase.charAt(0).toUpperCase() + phase.slice(1);
  }
}

function phaseState(events: EventRecord[], phase: string, currentPhase: string) {
  const relevant = events.filter((event) => event.phase === phase);
  if (relevant.some((event) => event.event_type === "phase.completed")) {
    return "completed";
  }
  if (relevant.some((event) => event.event_type === "phase.started")) {
    return "active";
  }

  if (currentPhase === "complete") {
    return "completed";
  }

  const currentIndex = PHASES.indexOf(currentPhase);
  const phaseIndex = PHASES.indexOf(phase);
  if (currentIndex >= 0 && phaseIndex >= 0) {
    if (phaseIndex < currentIndex) return "completed";
    if (phaseIndex === currentIndex) return "active";
  }

  return "pending";
}

export function PhaseWaterfall({ events, currentPhase }: PhaseWaterfallProps) {
  const hasStructuredEvents = events.some((event) => event.event_type.startsWith("task."));
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Phase waterfall</h2>
        <p className="meta-text">
          {hasStructuredEvents ? "Five-phase autonomous workflow" : "Using workflow state because no structured task events were recorded"}
        </p>
      </div>
      <div className="waterfall">
        {PHASES.map((phase) => {
          const state = phaseState(events, phase, currentPhase);
          return (
            <article key={phase} className={`phase-card phase-${state}`}>
              <p className="eyebrow">{state}</p>
              <h3>{phaseLabel(phase)}</h3>
            </article>
          );
        })}
      </div>
    </section>
  );
}
