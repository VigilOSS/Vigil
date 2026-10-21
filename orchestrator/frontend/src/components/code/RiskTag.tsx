import { humanizeStatus } from "../ui";
import { CLASSIFICATION_LABELS } from "./codeLabels";

const SEVERITY_TIERS = new Set(["critical", "high", "medium", "low"]);

/**
 * A file's risk tier in sentence case with its severity color as a marker
 * (text carries the meaning; the color only groups).
 */
export function RiskTag({ classification }: { classification: string }) {
  const tier = SEVERITY_TIERS.has(classification) ? classification : "other";
  return (
    <span className={`cv-risk cv-risk-${tier}`}>
      {CLASSIFICATION_LABELS[classification] ?? humanizeStatus(classification || "unclassified")}
    </span>
  );
}
