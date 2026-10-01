import { useEffect, useState } from "react";

import {
  ApiError,
  approveRemediationCase,
  getRemediationCase,
  getRemediationDiff,
  listRemediationCases,
  remediationEvidenceFileUrl,
  recordRemediationHumanVerification,
  updateRemediationBaseline,
  updateRemediationReleasePlan,
  updateRemediationVerificationPlan,
  type RemediationCase,
  type RemediationCaseSummary,
  type RemediationEvidence,
  type RemediationHumanVerificationInput,
  type RemediationDiff,
  type RemediationBaseline,
  type RemediationReleasePlan,
} from "../lib/api";
import { ThemeToggle } from "../components/ThemeToggle";

type Props = { engagementKey: string; onBack: () => void; initialCaseId?: number };

function textValue(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function snapshotText(snapshot: Record<string, unknown>): string {
  return Object.entries(snapshot)
    .map(([key, value]) => `${key.replace(/_/g, " ")}: ${typeof value === "string" ? value : JSON.stringify(value, null, 2)}`)
    .join("\n\n");
}

function evidenceIsImage(evidence: RemediationEvidence): boolean {
  return /\.(png|jpe?g|webp|gif)$/i.test(evidence.artifact_path || "");
}

function detailLabel(evidence: RemediationEvidence): string {
  return evidence.artifact_path?.split("/").pop() || evidence.kind.replace(/_/g, " ");
}

export function RemediationPage(props: Props) {
  return <RemediationWorkspace key={`${props.engagementKey}:${props.initialCaseId ?? ""}`} {...props} />;
}

function RemediationWorkspace({ engagementKey, onBack, initialCaseId }: Props) {
  const [cases, setCases] = useState<RemediationCaseSummary[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(initialCaseId ?? null);
  const [selected, setSelected] = useState<RemediationCase | null>(null);
  const [plan, setPlan] = useState("");
  const [baseline, setBaseline] = useState<Partial<RemediationBaseline>>({});
  const [releasePlan, setReleasePlan] = useState<Partial<RemediationReleasePlan>>({});
  const [reviewer, setReviewer] = useState("");
  const [humanActor, setHumanActor] = useState("");
  const [humanResult, setHumanResult] = useState<RemediationHumanVerificationInput["result"]>("blocked");
  const [humanNotes, setHumanNotes] = useState("");
  const [diff, setDiff] = useState<RemediationDiff | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [listAttempt, setListAttempt] = useState(0);
  const [caseAttempt, setCaseAttempt] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setListError(null);
    listRemediationCases(engagementKey).then((next) => {
      if (!active) return;
      setCases(next);
      setSelectedId((current) => current ?? next[0]?.id ?? null);
    }).catch((failure: unknown) => {
      if (active) setListError(failure instanceof Error ? failure.message : "Could not load cases");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [engagementKey, listAttempt]);

  useEffect(() => {
    if (selectedId == null) {
      setSelected(null);
      return;
    }
    let active = true;
    setCaseError(null);
    setDiff(null);
    setDiffError(null);
    getRemediationCase(engagementKey, selectedId).then((next) => {
      if (!active) return;
      setSelected(next);
      setPlan(next.verification_plan || "");
      setBaseline(next.baseline || {});
      setReleasePlan(next.release_plan || {});
    }).catch((failure: unknown) => {
      if (active) setCaseError(failure instanceof Error ? failure.message : "Could not load case");
    });
    getRemediationDiff(engagementKey, selectedId).then((next) => {
      if (active) setDiff(next);
    }).catch((failure: unknown) => {
      if (active) setDiffError(failure instanceof Error ? failure.message : "Could not load code diff");
    });
    return () => { active = false; };
  }, [engagementKey, selectedId, caseAttempt]);

  function chooseCase(caseId: number) {
    setSelectedId(caseId);
    setSelected(null);
    setDiff(null);
    setNotice(null);
    window.history.replaceState(null, "", `#/remediation/${encodeURIComponent(engagementKey)}?case=${caseId}`);
  }

  async function savePlan() {
    if (!selected || busy) return;
    setBusy(true);
    setNotice(null);
    setDiff(null);
    try {
      const next = await updateRemediationVerificationPlan(engagementKey, selected.id, plan);
      setSelected(next);
      setPlan(next.verification_plan || "");
      setCases((current) => current.map((item) => item.id === next.id ? next : item));
      try {
        setDiff(await getRemediationDiff(engagementKey, next.id));
        setDiffError(null);
      } catch (failure) {
        setDiffError(failure instanceof Error ? failure.message : "Could not refresh code diff");
      }
      setNotice("Verification plan saved. Review the new snapshot before approval.");
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save plan");
    } finally {
      setBusy(false);
    }
  }

  async function saveBaseline() {
    if (!selected || busy || !baseline.outcome || !baseline.method?.trim() || !baseline.proved?.trim()) return;
    setBusy(true);
    setDiff(null);
    try {
      const next = await updateRemediationBaseline(engagementKey, selected.id, baseline as RemediationBaseline);
      setSelected(next);
      setBaseline(next.baseline || {});
      setError(null);
      setNotice("Baseline saved. Review the updated snapshot before approval.");
      try {
        setDiff(await getRemediationDiff(engagementKey, next.id));
        setDiffError(null);
      } catch (failure) {
        setDiffError(failure instanceof Error ? failure.message : "Could not refresh code diff");
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save baseline");
    } finally {
      setBusy(false);
    }
  }

  async function saveReleasePlan() {
    if (!selected || busy || !releasePlan.production_canary_decision || !releasePlan.production_canary_rationale?.trim() || !releasePlan.coralogix_monitoring?.trim()) return;
    if (releasePlan.production_canary_decision === "required" && !releasePlan.safe_procedure?.trim()) return;
    setBusy(true);
    setDiff(null);
    try {
      const next = await updateRemediationReleasePlan(engagementKey, selected.id, {
        production_canary_decision: releasePlan.production_canary_decision,
        production_canary_rationale: releasePlan.production_canary_rationale,
        safe_procedure: releasePlan.safe_procedure || "",
        coralogix_monitoring: releasePlan.coralogix_monitoring,
      });
      setSelected(next);
      setReleasePlan(next.release_plan || {});
      setError(null);
      setNotice("Release plan saved. Review the updated snapshot before approval.");
      try {
        setDiff(await getRemediationDiff(engagementKey, next.id));
        setDiffError(null);
      } catch (failure) {
        setDiffError(failure instanceof Error ? failure.message : "Could not refresh code diff");
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save release plan");
    } finally {
      setBusy(false);
    }
  }

  async function refreshCase() {
    if (!selected || busy || plan !== (selected.verification_plan || "")) return;
    setBusy(true);
    setDiff(null);
    try {
      const [next, nextDiff] = await Promise.all([
        getRemediationCase(engagementKey, selected.id),
        getRemediationDiff(engagementKey, selected.id),
      ]);
      setSelected(next);
      setCases((current) => current.map((item) => item.id === next.id ? next : item));
      setPlan(next.verification_plan || "");
      setBaseline(next.baseline || {});
      setReleasePlan(next.release_plan || {});
      setDiff(nextDiff);
      setError(null);
      setDiffError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not refresh case");
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!selected || busy || plan !== selected.verification_plan || !reviewer.trim() || !selected.review_evidence_ready || !diff || diff.truncated || diff.review_digest !== selected.review_digest) return;
    setBusy(true);
    setNotice(null);
    try {
      await approveRemediationCase(engagementKey, selected.id, reviewer.trim(), diff.review_digest, "ui");
      const next = await getRemediationCase(engagementKey, selected.id);
      setSelected(next);
      setCases((current) => current.map((item) => item.id === next.id ? next : item));
      setNotice("Reviewed snapshot approved. Any later code or plan change requires a new approval.");
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not approve case");
      if (failure instanceof ApiError && failure.status === 409) {
        setDiff(null);
        try {
          const next = await getRemediationCase(engagementKey, selected.id);
          setSelected(next);
          setPlan(next.verification_plan || "");
          setBaseline(next.baseline || {});
          setReleasePlan(next.release_plan || {});
          setDiff(await getRemediationDiff(engagementKey, selected.id));
        } catch {
          setDiffError("Refresh the case to inspect the latest review snapshot.");
        }
      }
    } finally {
      setBusy(false);
    }
  }

  async function recordHumanVerification() {
    if (!selected || !deployedRevision || !revisionMatches || !humanActor.trim() || !humanNotes.trim() || busy) return;
    setBusy(true);
    setNotice(null);
    try {
      await recordRemediationHumanVerification(engagementKey, selected.id, {
        actor: humanActor.trim(), result: humanResult, observed_revision: deployedRevision, notes: humanNotes.trim(),
      });
      setSelected(await getRemediationCase(engagementKey, selected.id));
      setNotice("Human development verification recorded against the deployed revision.");
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not record human verification");
    } finally {
      setBusy(false);
    }
  }

  const planDirty = selected != null && plan !== (selected.verification_plan || "");
  const baselineDirty = selected != null && JSON.stringify(baseline) !== JSON.stringify(selected.baseline || {});
  const releasePlanDirty = selected != null && JSON.stringify(releasePlan) !== JSON.stringify(selected.release_plan || {});
  const deployment = selected?.deployment ?? null;
  const deployedRevision = textValue(deployment?.observed_revision);
  const revisionMatches = Boolean(selected?.worktree_revision && deployedRevision && selected.worktree_revision === deployedRevision);
  const reviewDiffCurrent = Boolean(selected && diff && !diff.truncated && diff.review_digest === selected.review_digest && diff.head_revision === selected.worktree_revision);

  return (
    <div className="remediation-page">
      <header className="remediation-header">
        <div className="remediation-header-title">
          <button type="button" className="remediation-back" onClick={onBack}>← Engagements</button>
          <div><span className="remediation-eyebrow">{engagementKey} / Remediation</span><h1>Case workspace</h1></div>
        </div>
        <ThemeToggle />
      </header>
      {error && <div className="remediation-message remediation-error" role="alert">{error}</div>}
      {notice && <div className="remediation-message" role="status">{notice}</div>}
      <div className="remediation-layout">
        <aside className="remediation-queue" aria-label="Case queue">
          <div className="remediation-section-heading"><h2>Cases</h2><span>{cases.length}</span></div>
          {loading ? <p>Loading cases…</p> : listError ? <><p role="alert">{listError}</p><button type="button" onClick={() => setListAttempt((attempt) => attempt + 1)}>Retry loading cases</button></> : cases.length === 0 ? <p>No remediation cases imported yet.</p> : (
            <ul>
              {cases.map((item) => (
                <li key={item.id}>
                  <button type="button" className={selectedId === item.id ? "is-selected" : ""} onClick={() => chooseCase(item.id)} aria-current={selectedId === item.id ? "page" : undefined}>
                    <span className="remediation-case-key">{item.source_key}</span>
                    <strong>{item.title}</strong>
                    <span className="remediation-case-status">{item.status.replace(/_/g, " ")}</span>
                    {item.duplicate_hints?.length > 0 && <span className="remediation-case-status">{item.duplicate_hints.length} possible duplicate{item.duplicate_hints.length === 1 ? "" : "s"}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>

        <main className="remediation-workspace">
          {!selected ? (caseError ? <><p role="alert">{caseError}</p><button type="button" onClick={() => setCaseAttempt((attempt) => attempt + 1)}>Retry loading case</button></> : selectedId == null ? <p>Select a case to begin.</p> : <p>Loading case…</p>) : (
            <>
              <div className="remediation-title-row">
                <div><p className="remediation-eyebrow">{selected.source_type} · {selected.source_key}</p><h2>{selected.title}</h2></div>
                <div className="remediation-title-actions"><span className="remediation-state">{selected.status.replace(/_/g, " ")}</span><button type="button" onClick={refreshCase} disabled={busy || planDirty || baselineDirty || releasePlanDirty}>Refresh case</button></div>
              </div>

              <div className="remediation-meta">
                <div><span>Worktree</span><strong>{selected.worktree_path || "Not recorded"}</strong></div>
                <div><span>Code revision</span><strong>{selected.worktree_revision || "Not recorded"}</strong></div>
                <div><span>Development deployment</span><strong>{deployedRevision || "Not recorded"}</strong></div>
                <div><span>Revision check</span><strong className={revisionMatches ? "remediation-ok" : "remediation-caution"}>{revisionMatches ? "Matches code revision" : "Unconfirmed"}</strong></div>
              </div>
              {deployment && <p className="remediation-deployment-link">Workflow: {deployment.workflow} · run {deployment.run_id} · expected {deployment.expected_revision}</p>}

              <section className="remediation-section">
                <div className="remediation-section-heading"><h3>Issue snapshot</h3><span>Imported evidence</span></div>
                <pre className="remediation-snapshot">{snapshotText(selected.snapshot || {})}</pre>
                {selected.linked_finding_slug && <p>Linked Vigil finding: {selected.linked_finding_slug}</p>}
                {selected.duplicate_hints.length > 0 && (
                  <div className="remediation-duplicates"><strong>Likely duplicates · review manually</strong><ul>{selected.duplicate_hints.map((hint) => <li key={hint}>Case #{hint}{selected.duplicate_hint_details?.find((item) => item.case_id === hint)?.reasons.map((reason) => ` · ${reason}`).join("")}</li>)}</ul></div>
                )}
              </section>

              <section className="remediation-section remediation-review">
                <div className="remediation-section-heading"><h3>Baseline</h3><span>{selected.baseline?.outcome ? selected.baseline.outcome.replace(/_/g, " ") : "Not recorded"}</span></div>
                <p>Record what actually reproduced and what the evidence proved. If runtime reproduction was unavailable, the case owner decides whether to proceed.</p>
                <div className="remediation-field-grid">
                  <div><label htmlFor="remediation-baseline-outcome">Baseline outcome</label><select id="remediation-baseline-outcome" value={baseline.outcome || ""} onChange={(event) => setBaseline({ ...baseline, outcome: event.target.value as RemediationBaseline["outcome"] })}><option value="">Choose outcome</option><option value="runtime_reproduced">Runtime reproduced</option><option value="code_test_confirmed">Code and failing test confirmed</option><option value="unreproduced">Unreproduced</option></select></div>
                  <div><label htmlFor="remediation-baseline-method">Baseline method</label><input id="remediation-baseline-method" value={baseline.method || ""} onChange={(event) => setBaseline({ ...baseline, method: event.target.value })} placeholder="HTTP request, Laravel test, browser…" /></div>
                </div>
                <label htmlFor="remediation-baseline-proved">Baseline proved</label><textarea id="remediation-baseline-proved" value={baseline.proved || ""} onChange={(event) => setBaseline({ ...baseline, proved: event.target.value })} rows={3} />
                {baseline.outcome && baseline.outcome !== "runtime_reproduced" && <div className="remediation-owner-decision">
                  <p className="remediation-caution">Runtime reproduction was not established. The owner must record a decision before the review can advance.</p>
                  <div className="remediation-field-grid">
                    <div><label htmlFor="remediation-owner-decision">Owner decision</label><select id="remediation-owner-decision" value={baseline.owner_decision || ""} onChange={(event) => setBaseline({ ...baseline, owner_decision: event.target.value as RemediationBaseline["owner_decision"] })}><option value="">Choose decision</option><option value="proceed">Proceed</option><option value="pause">Pause</option></select></div>
                    <div><label htmlFor="remediation-owner-actor">Owner actor</label><input id="remediation-owner-actor" value={baseline.owner_actor || ""} onChange={(event) => setBaseline({ ...baseline, owner_actor: event.target.value })} /></div>
                  </div>
                  <label htmlFor="remediation-owner-reason">Owner reason</label><textarea id="remediation-owner-reason" value={baseline.owner_reason || ""} onChange={(event) => setBaseline({ ...baseline, owner_reason: event.target.value })} rows={2} />
                </div>}
                <div className="remediation-plan-actions"><span>{baselineDirty ? "Unsaved baseline changes" : "Baseline saved"}</span><button type="button" onClick={saveBaseline} disabled={!baselineDirty || busy || !baseline.outcome || !baseline.method?.trim() || !baseline.proved?.trim() || (baseline.outcome !== "runtime_reproduced" && (!baseline.owner_decision || !baseline.owner_actor?.trim() || !baseline.owner_reason?.trim()))}>Save baseline</button></div>
              </section>

              <section className="remediation-section">
                <div className="remediation-section-heading"><h3>Evidence and test results</h3><span>{selected.evidence.length} records</span></div>
                {selected.evidence.length === 0 ? <p>No evidence registered.</p> : (
                  <div className="remediation-evidence-grid">
                    {selected.evidence.map((item) => {
                      const url = remediationEvidenceFileUrl(engagementKey, selected.id, item.id);
                      const label = detailLabel(item);
                      return <figure key={item.id} className="remediation-evidence">
                        {evidenceIsImage(item) && <a href={url} target="_blank" rel="noreferrer"><img src={url} alt={label} loading="lazy" /></a>}
                        <figcaption><strong>{label}</strong><span>{item.kind.replace(/_/g, " ")} · {item.method}{item.outcome ? ` · ${item.outcome.replace(/_/g, " ")}` : ""}</span><span>Environment: {item.environment ?? "unknown (historical record)"}</span><span>{item.proved}</span>{item.command && <code>{item.command}</code>}<span>Observed: {item.observed}</span>{item.revision && <span>Revision: {item.revision}</span>}{item.artifact_path && <a href={url} target="_blank" rel="noreferrer">Open evidence ↗</a>}</figcaption>
                      </figure>;
                    })}
                  </div>
                )}
              </section>

              <section className="remediation-section remediation-review">
                <div className="remediation-section-heading"><h3>Human verification plan</h3><span>Only rehearsed steps</span></div>
                <label htmlFor="remediation-plan">Human verification plan</label>
                <textarea id="remediation-plan" value={plan} onChange={(event) => setPlan(event.target.value)} rows={9} />
                <div className="remediation-plan-actions"><span>{planDirty ? "Unsaved changes invalidate the reviewed plan." : "Plan saved"}</span><button type="button" onClick={savePlan} disabled={!planDirty || busy}>Save plan</button></div>
              </section>

              <section className="remediation-section remediation-review">
                <div className="remediation-section-heading"><h3>Release plan</h3><span>Production canary and monitoring</span></div>
                <label htmlFor="remediation-canary-decision">Production canary decision</label>
                <select id="remediation-canary-decision" value={releasePlan.production_canary_decision || ""} onChange={(event) => setReleasePlan({ ...releasePlan, production_canary_decision: event.target.value as RemediationReleasePlan["production_canary_decision"] })}><option value="">Choose decision</option><option value="required">Required</option><option value="not_required">Not required</option><option value="defer">Defer decision</option></select>
                <label htmlFor="remediation-canary-rationale">Canary rationale</label>
                <textarea id="remediation-canary-rationale" value={releasePlan.production_canary_rationale || ""} onChange={(event) => setReleasePlan({ ...releasePlan, production_canary_rationale: event.target.value })} rows={3} />
                <label htmlFor="remediation-safe-procedure">Safe canary procedure</label>
                <textarea id="remediation-safe-procedure" value={releasePlan.safe_procedure || ""} onChange={(event) => setReleasePlan({ ...releasePlan, safe_procedure: event.target.value })} rows={3} placeholder="Required when a production canary is needed" />
                <label htmlFor="remediation-coralogix">Coralogix monitoring</label>
                <textarea id="remediation-coralogix" value={releasePlan.coralogix_monitoring || ""} onChange={(event) => setReleasePlan({ ...releasePlan, coralogix_monitoring: event.target.value })} rows={3} />
                <div className="remediation-plan-actions"><span>{releasePlanDirty ? "Unsaved release decision" : "Release plan saved"}</span><button type="button" onClick={saveReleasePlan} disabled={!releasePlanDirty || busy || !releasePlan.production_canary_decision || !releasePlan.production_canary_rationale?.trim() || !releasePlan.coralogix_monitoring?.trim() || (releasePlan.production_canary_decision === "required" && !releasePlan.safe_procedure?.trim())}>Save release plan</button></div>
              </section>

              <section className="remediation-section remediation-review">
                <div className="remediation-section-heading"><h3>Human development verification</h3><span>{selected.human_verifications?.length || 0} results</span></div>
                <p>Execute the saved plan in development and record the observed outcome. The record is tied to the confirmed deployment revision.</p>
                {selected.human_verifications?.length > 0 && <ul className="remediation-human-history">{selected.human_verifications.map((item) => <li key={item.id}><strong>{item.result}</strong> · {item.actor} · {item.observed_revision}<p>{item.notes}</p></li>)}</ul>}
                {selected.status === "development" && (
                  <div className="remediation-human-form">
                    <label htmlFor="remediation-human-actor">Human verification actor</label>
                    <input id="remediation-human-actor" value={humanActor} onChange={(event) => setHumanActor(event.target.value)} placeholder="Security Developer" />
                    <label htmlFor="remediation-human-result">Human verification result</label>
                    <select id="remediation-human-result" value={humanResult} onChange={(event) => setHumanResult(event.target.value as RemediationHumanVerificationInput["result"])}><option value="blocked">Blocked</option><option value="passed">Passed</option><option value="failed">Failed</option></select>
                    <label htmlFor="remediation-human-notes">Human verification notes</label>
                    <textarea id="remediation-human-notes" value={humanNotes} onChange={(event) => setHumanNotes(event.target.value)} rows={4} placeholder="What was observed using the saved steps?" />
                    <p>Deployed revision: {deployedRevision || "Unconfirmed"}</p>
                    <button type="button" onClick={recordHumanVerification} disabled={busy || !revisionMatches || !humanActor.trim() || !humanNotes.trim()}>Record human verification</button>
                  </div>
                )}
              </section>

              <section className="remediation-section remediation-review">
                <div className="remediation-section-heading"><h3>Review approval</h3><span>{selected.approval_current ? "Current" : "Needs approval"}</span></div>
                <p>Review the code diff, baseline, tests, screenshots, and human plan before approving. Approval applies to this exact code and plan snapshot.</p>
                {selected.review_evidence_ready ? <p className="remediation-ok">Required red/green Laravel and Stagehand happy-path evidence is registered.</p> : <div className="remediation-evidence-gate"><strong>Required evidence is missing</strong><ul>{selected.review_evidence_missing.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                <p className="remediation-digest">Review snapshot: <code>{selected.review_digest || "Unavailable"}</code></p>
                <div className="remediation-diff">
                  <div className="remediation-section-heading"><h3>Code diff</h3><span>{diff ? `${diff.base_revision} → ${diff.head_revision}` : ""}</span></div>
                  {diffError ? <p role="alert">Diff unavailable: {diffError}</p> : !diff ? <p>Loading code diff…</p> : <>
                    {diff.truncated && <p className="remediation-caution">Diff truncated because it exceeds the 1 MiB review limit. Open the worktree to review all changes.</p>}
                    {diff.review_digest !== selected.review_digest && <p className="remediation-caution">The diff no longer matches the case snapshot. Refresh the case before approval.</p>}
                    <pre>{diff.text || "No code changes in this review snapshot."}</pre>
                  </>}
                </div>
                {selected.approvals.length > 0 && <div className="remediation-history"><p>{selected.approval_current ? "Latest approval matches this snapshot." : "Earlier approval is stale after a change."}</p><ul>{selected.approvals.map((item, index) => <li key={textValue(item.id) || index}>Approved by {textValue(item.reviewer)} · revision {textValue(item.approved_revision)} · snapshot {textValue(item.review_digest)}</li>)}</ul></div>}
                <div className="remediation-approval-actions">
                  <label htmlFor="remediation-reviewer">Reviewer</label>
                  <input id="remediation-reviewer" value={reviewer} onChange={(event) => setReviewer(event.target.value)} placeholder="Case owner name" />
                  <button type="button" onClick={approve} disabled={busy || planDirty || baselineDirty || releasePlanDirty || !selected.review_evidence_ready || !selected.baseline?.outcome || !selected.release_plan?.production_canary_decision || !reviewer.trim() || !reviewDiffCurrent || selected.approval_current || selected.status !== "review"}>Approve reviewed snapshot</button>
                </div>
              </section>
              {selected.transitions.length > 0 && <section className="remediation-section remediation-history"><div className="remediation-section-heading"><h3>Case history</h3><span>{selected.transitions.length} transitions</span></div><ol>{selected.transitions.map((item, index) => <li key={textValue(item.id) || index}>{textValue(item.from_status)} → {textValue(item.to_status)} · {textValue(item.actor)} · {textValue(item.reason)}</li>)}</ol></section>}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
