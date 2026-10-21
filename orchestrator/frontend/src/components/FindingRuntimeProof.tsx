// ── FindingRuntimeProof ───────────────────────────────────────────────
// The Proof work card for one finding, embedded in the Findings drawer
// while that finding still owes runtime proof. The proof queue is read only
// while this section is mounted (an open drawer that needs it) and re-read
// on every workspace refresh bump; reads coalesce like the Proof work tab.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { listProofWork, type ProofWorkList } from "../lib/api";
import { proofCardForFinding } from "../lib/proofWorkApi";
import { createCoalescedRunner } from "../lib/coalesce";
import { engagementHref } from "../lib/workspaceRoutes";
import { CardSkeleton } from "./Skeletons";
import { ProofWorkCard } from "./ProofWorkCard";

type FindingRuntimeProofProps = {
  engagementKey: string;
  slug: string;
  /** Bumped by the workspace on each live refresh. */
  refreshVersion?: number;
};

function errorText(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "Proof work could not be loaded";
}

export function FindingRuntimeProof({ engagementKey, slug, refreshVersion = 0 }: FindingRuntimeProofProps) {
  const [queue, setQueue] = useState<ProofWorkList | null>(null);
  // A failed read blocks writes until a read succeeds; a failed write is
  // reported apart and does not block the next action once the queue re-reads.
  const [error, setError] = useState<string | null>(null);
  const [writeError, setWriteError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useMemo(() => createCoalescedRunner(async () => {
    setLoading(true);
    try {
      const next = await listProofWork(engagementKey);
      if (!mounted.current) return;
      setQueue(next);
      setError(null);
    } catch (failure) {
      if (mounted.current) setError(errorText(failure));
    } finally {
      if (mounted.current) setLoading(false);
    }
  }), [engagementKey]);

  useEffect(() => {
    void load("join");
  }, [load]);

  const seenVersion = useRef(refreshVersion);
  useEffect(() => {
    if (seenVersion.current === refreshVersion) return;
    seenVersion.current = refreshVersion;
    void load("refresh");
  }, [load, refreshVersion]);

  // Same contract as the Proof work tab: one write, then a read; a write with
  // an uncertain outcome is never retried.
  const act = useCallback(async (operation: () => Promise<unknown>): Promise<boolean> => {
    setBusy(true);
    setWriteError(null);
    try {
      await operation();
      if (!mounted.current) return false;
      await load("refresh");
      return true;
    } catch (failure) {
      if (!mounted.current) return false;
      await load("refresh");
      if (mounted.current) setWriteError(errorText(failure));
      return false;
    } finally {
      if (mounted.current) setBusy(false);
    }
  }, [load]);

  const proofHref = engagementHref(engagementKey, { tab: "proof" });
  const reload = (
    <button type="button" className="ui-button" onClick={() => void load("refresh")} disabled={loading}>Reload proof work</button>
  );
  if (!queue) {
    return error
      ? <div className="proof-banner" role="alert"><p>Proof work unavailable: {error}</p>{reload}</div>
      : <div aria-busy="true"><CardSkeleton lines={3} /></div>;
  }
  const card = proofCardForFinding(queue, slug);
  return (
    <>
      {error && (
        <div className="proof-banner" role="alert">
          <p>{error} · Showing the last loaded proof work; actions stay off until it reloads.</p>
          {reload}
        </div>
      )}
      {card ? (
        <ProofWorkCard
          engagementKey={engagementKey}
          slug={card.slug}
          title={card.title}
          severity={card.severity}
          owed={card.owed}
          items={card.items}
          busy={busy}
          writesDisabled={Boolean(error)}
          onAction={act}
          actionError={writeError}
          onDismissActionError={() => setWriteError(null)}
          showFindingLink={false}
          showFindingHeader={false}
        />
      ) : (
        <p className="meta-text">This finding is not in the proof queue yet. <a href={proofHref}>Open proof work</a></p>
      )}
    </>
  );
}
