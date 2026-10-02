import { useEffect, useRef, useState } from "react";
import {
  createRemediationFromFinding,
  getFindingRemediationCases,
  listEngagements,
  type Engagement,
  type FindingRemediationSummary,
} from "../lib/api";
import { remediationHref, writeWorkspaceHash } from "../lib/workspaceRoutes";

export function FindingRemediation({ engagementKey, findingSlug, refreshVersion }: { engagementKey: string; findingSlug: string; refreshVersion: number }) {
  const [cases, setCases] = useState<FindingRemediationSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [creating, setCreating] = useState(false);
  const [destinations, setDestinations] = useState<Engagement[] | null>(null);
  const [destination, setDestination] = useState("");
  const [destinationError, setDestinationError] = useState<string | null>(null);
  const [destinationAttempt, setDestinationAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const activeCreationRef = useRef<object | null>(null);

  useEffect(() => {
    const identity = {};
    activeCreationRef.current = identity;
    return () => { if (activeCreationRef.current === identity) activeCreationRef.current = null; };
  }, [engagementKey, findingSlug]);

  useEffect(() => {
    let active = true;
    getFindingRemediationCases(engagementKey, findingSlug).then((rows) => {
      if (active) { setCases(rows); setError(null); }
    }).catch((failure: unknown) => {
      if (active) setError(failure instanceof Error ? failure.message : "Could not load remediation relationships");
    });
    return () => { active = false; };
  }, [engagementKey, findingSlug, refreshVersion, attempt]);

  useEffect(() => {
    if (!creating) return;
    let active = true;
    setDestinationError(null);
    listEngagements().then((rows) => {
      if (active) setDestinations(rows.filter((row) => row.engagement_type === "remediation"));
    }).catch((failure: unknown) => {
      if (active) setDestinationError(failure instanceof Error ? failure.message : "Could not load remediation workspaces");
    });
    return () => { active = false; };
  }, [creating, destinationAttempt]);

  async function createCase() {
    if (!destination || busy) return;
    setBusy(true);
    setDestinationError(null);
    const identity = activeCreationRef.current;
    try {
      const created = await createRemediationFromFinding(engagementKey, findingSlug, { remediation_engagement_key: destination });
      if (identity !== null && activeCreationRef.current === identity) writeWorkspaceHash(remediationHref(created.engagement_key, created.id));
    } catch (failure) {
      if (identity !== null && activeCreationRef.current === identity) setDestinationError(failure instanceof Error ? failure.message : "Could not create remediation case");
    } finally { if (identity !== null && activeCreationRef.current === identity) setBusy(false); }
  }

  return (
    <section className="finding-remediation" aria-label="Finding remediation">
      <div className="finding-remediation-heading">
        <span className="section-title">Remediation</span>
        {cases !== null && !error && <button type="button" className="finding-text-action" onClick={() => setCreating((value) => !value)} disabled={busy}>{creating ? "Cancel" : "Create remediation case"}</button>}
      </div>
      {error && <p role="status">{cases !== null ? "Remediation relationships are stale. " : "Remediation relationships unavailable. "}{error} <button type="button" className="finding-text-action" onClick={() => setAttempt((value) => value + 1)}>Retry</button></p>}
      {cases === null ? !error && <p className="meta-text">Loading remediation relationships…</p> : cases.length === 0 ? !error && <p className="meta-text">No remediation case linked.</p> : <ul className="finding-remediation-cases">{cases.map((item) => <li key={item.id}>
        <a href={remediationHref(item.engagement_key, item.id)}><strong>{item.title}</strong><span>{item.status.replace(/_/g, " ")} ↗</span></a>
        {item.worktree_revision && <p className="meta-text">Patch revision <code>{item.worktree_revision}</code></p>}
        {item.latest_deployment && <p className="meta-text">{item.latest_deployment.environment} deployment · <code>{item.latest_deployment.observed_revision}</code> · {item.latest_deployment.workflow} / {item.latest_deployment.run_id}</p>}
      </li>)}</ul>}
      {creating && <div className="finding-remediation-intake">
        <label htmlFor="finding-remediation-destination">Remediation workspace</label>
        {destinations === null && !destinationError ? <p className="meta-text">Loading available workspaces…</p> : destinations?.length === 0 ? <p className="meta-text">No remediation workspace exists. Create one through Vigil before opening a case.</p> : destinations && <select id="finding-remediation-destination" value={destination} onChange={(event) => setDestination(event.target.value)} disabled={busy}>
          <option value="">Choose a workspace</option>{destinations.map((item) => <option key={item.key} value={item.key}>{item.target} · {item.key}</option>)}
        </select>}
        {destinationError && <p role="alert">{destinationError} <button type="button" className="finding-text-action" disabled={busy} onClick={() => setDestinationAttempt((value) => value + 1)}>Retry workspaces</button></p>}
        <button type="button" className="ghost-button" onClick={createCase} disabled={busy || !destination || !destinations?.some((item) => item.key === destination)}>{busy ? "Creating case…" : "Create & open case"}</button>
      </div>}
    </section>
  );
}
