import { useCallback, useEffect, useRef, useState } from "react";
import { approveProofWork, listProofWork, prepareProofWork, reconcileProofWork, releaseProofWork, type ProofWorkList } from "../lib/api";
import { engagementHref } from "../lib/workspaceRoutes";

type ProofWorkTabProps = {engagementKey: string; refreshVersion?: number};

export function ProofWorkTab(props: ProofWorkTabProps) {
  return <ProofWorkWorkspace key={props.engagementKey} {...props} />;
}

function ProofWorkWorkspace({engagementKey, refreshVersion = 0}: ProofWorkTabProps) {
  const [data, setData] = useState<ProofWorkList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [slug, setSlug] = useState("");
  const [route, setRoute] = useState<"code" | "web">("code");
  const [objective, setObjective] = useState("");
  const [hosts, setHosts] = useState("");
  const [recoveryReasons, setRecoveryReasons] = useState<Record<number, string>>({});
  const requestVersion = useRef(0);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const refresh = useCallback(async () => {
    const version = ++requestVersion.current;
    try {
      const result = await listProofWork(engagementKey);
      if (version !== requestVersion.current) return;
      setData(result);
      setError(null);
      setSlug(previous => result.owed.some(item => item.finding_slug === previous) ? previous : result.owed[0]?.finding_slug ?? "");
    } catch (failure) {
      if (version === requestVersion.current) setError(failure instanceof Error ? failure.message : String(failure));
    }
  }, [engagementKey]);
  useEffect(() => {
    void refresh();
    return () => { ++requestVersion.current; };
  }, [refresh, refreshVersion]);

  async function act(operation: () => Promise<unknown>) {
    setBusy(true);
    try {
      await operation();
      if (!mounted.current) return;
      await refresh();
    } catch (failure) {
      if (!mounted.current) return;
      // Never retry a write with an uncertain outcome. Refresh is a read.
      await refresh();
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally { if (mounted.current) setBusy(false); }
  }

  return <section className="panel proof-workspace">
    <div className="section-heading"><h2>Proof work</h2><button type="button" className="ghost-button" onClick={() => void refresh()} disabled={busy}>Refresh proof work</button></div>
    <p>Challenge source-backed candidates with a supported local reproduction or a live test. Preparing or finishing work does not confirm a finding.</p>
    {error && <p role="alert">{error}</p>}
    {!data && !error && <p role="status">Loading proof work…</p>}
    {data && <>
      <h3>Runtime proof owed</h3>
      {data.owed.length === 0 ? <p>No findings currently await runtime proof.</p> : <>
        <ul>{data.owed.map(item => <li key={item.finding_slug}><a href={engagementHref(engagementKey, {tab: "findings", finding: item.finding_slug})}>{item.title}</a> <span className="muted">{item.finding_slug} · {item.work_ids.length} prepared</span></li>)}</ul>
        <form className="proof-preparation" onSubmit={event => {
          event.preventDefault();
          void act(() => prepareProofWork(engagementKey, {finding_slug: slug, route, objective: objective.trim(), target_hosts: route === "web" ? hosts.split(/[\s,]+/).filter(Boolean) : []}));
        }}>
          <label>Candidate<select value={slug} onChange={event => setSlug(event.target.value)}>{data.owed.map(item => <option key={item.finding_slug} value={item.finding_slug}>{item.finding_slug}</option>)}</select></label>
          <label>Proof route<select value={route} onChange={event => setRoute(event.target.value as "code" | "web")}><option value="code">Local code reproduction in Kali</option><option value="web">Live application test</option></select></label>
          <label>Proof objective<textarea value={objective} onChange={event => setObjective(event.target.value)} required placeholder="What would confirm, disprove, or narrow this claim?" /></label>
          {route === "web" && <label>Admitted target hosts<input value={hosts} onChange={event => setHosts(event.target.value)} required placeholder="app.example.com" /></label>}
          <button type="submit" disabled={busy || !!error || !slug || !objective.trim() || (route === "web" && !hosts.trim())}>Prepare proof</button>
        </form>
      </>}
      <h3>Prepared investigations</h3>
      {data.items.length === 0 && <p>No proof work prepared. The operator can prepare and dispatch it from the current conversation.</p>}
      {data.items.map(work => <article className="proof-work-item" key={work.id}>
        <h4><a href={engagementHref(engagementKey, {tab: "findings", finding: work.finding_slug})}>{work.finding_slug}</a> · Proof {work.id}</h4>
        <p className="proof-objective">{work.objective}</p>
        <dl><dt>Route</dt><dd>{work.route === "code" ? "Local code reproduction in Kali" : "Live application test"}</dd><dt>Status</dt><dd>{work.status}</dd><dt>Owner</dt><dd>{work.owner_agent_id || "Unclaimed"}{work.owner_dispatch_status ? ` (${work.owner_dispatch_status})` : ""}</dd>
          <dt>Approval</dt><dd>{!work.current ? "Context changed; approval cannot authorize execution" : work.route === "code" ? "Local sandbox work" : work.approval_required ? "Live proof approval required" : "Approved for this work"}</dd>
          {work.target_hosts.length > 0 && <><dt>Targets</dt><dd>{work.target_hosts.join(", ")}</dd></>}
        </dl>
        {!work.current && <p role="status">Stale context — prepare against current evidence</p>}
        {work.blocker && <p className="finding-proof-gap">{work.blocker}</p>}
        {work.run_ids.length > 0 && <p>Evidence: {work.run_ids.map(id => <a className="proof-run-link" key={id} href={engagementHref(engagementKey, {tab: "runs", run: id})}>Run {id}</a>)}</p>}
        <div className="proof-actions">
          {work.route === "web" && <button type="button" className="ghost-button" aria-label={`${work.approved ? "Revoke" : "Approve"} live proof ${work.id}`} disabled={busy || !!error || !work.current || !work.owed} onClick={() => void act(() => approveProofWork(engagementKey, work.id, !work.approved))}>{work.approved ? "Revoke work approval" : "Approve this live proof"}</button>}
          <button type="button" className="ghost-button" aria-label={`Reconcile proof ${work.id}`} disabled={busy} onClick={() => void act(() => reconcileProofWork(engagementKey, work.id))}>Reconcile recorded state</button>
        </div>
        {work.owner_agent_id && ["completed", "failed", "aborted", "blocked"].includes(work.owner_dispatch_status ?? "") && <div className="proof-recovery">
          <p>Release ownership only after the worker has ended. The backend also checks for active runs, commands, and supervised jobs; releasing does not launch another worker.</p>
          <label>Recovery reason<input aria-label={`Recovery reason for proof ${work.id}`} value={recoveryReasons[work.id] ?? ""} onChange={event => setRecoveryReasons(previous => ({...previous, [work.id]: event.target.value}))} /></label>
          <button type="button" className="ghost-button" aria-label={`Release proof ${work.id}`} disabled={busy || !!error || !recoveryReasons[work.id]?.trim()} onClick={() => void act(() => releaseProofWork(engagementKey, work.id, recoveryReasons[work.id].trim()))}>Release ended ownership</button>
        </div>}
      </article>)}
    </>}
  </section>;
}
