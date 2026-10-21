import type { RunHealth } from "../lib/runAudit";
import { StatusPill, statusLabel, statusTone } from "./ui";

// A run's status: the recorded status in words, toned and shaped by its
// health, so a completed run with open work never reads as green. The
// health and its reason are in the hover title; callers show the reason as
// text next to the pill.
export function RunHealthChip({ health, size }: { health: RunHealth; size?: "sm" | "md" }) {
  return (
    <span className="run-health">
      <StatusPill
        domain="run"
        value={health.status}
        tone={statusTone("run-health", health.key)}
        title={`${statusLabel("run-health", health.key)}${health.reason ? `: ${health.reason}` : ""}`}
        size={size}
      />
      <span className="sr-only">, {statusLabel("run-health", health.key).toLowerCase()}</span>
    </span>
  );
}
