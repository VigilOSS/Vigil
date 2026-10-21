import { useEffect, useRef, useState, type MutableRefObject } from "react";

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
  getAssessmentFinding,
  getEngagement,
  listEngagements,
  updateRemediationFindings,
  type Engagement,
  type LinkedRemediationFinding,
  type RemediationCase,
  type RemediationCaseSummary,
  type RemediationEvidence,
  type RemediationHumanVerificationInput,
  type RemediationDiff,
  type RemediationBaseline,
  type RemediationReleasePlan,
} from "../lib/api";
import { ThemeToggle } from "../components/ThemeToggle";
import { Skeleton } from "../components/Skeletons";
import { EmptyState, SeverityTag, StatusPill, statusLabel } from "../components/ui";
import { JsonView } from "../components/JsonView";
import { CodeBlock } from "../components/formatting";
import { engagementHref, remediationHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { InvalidRemediationDraftError, readRemediationDrafts, writeRemediationDrafts, type RemediationDrafts, type RemediationDraftValues } from "../lib/remediationDrafts";
import "../styles/workspace.css";
import "../styles/remediation.css";

type Props = { engagementKey: string; onBack: () => void; initialCaseId?: number };

function textValue(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function intakeSummary(snapshot: Record<string, unknown>): string {
  const record = snapshot.finding && typeof snapshot.finding === "object"
    ? snapshot.finding as Record<string, unknown> : snapshot;
  if (typeof record.description === "string" && record.description) return record.description;
  return typeof record.summary === "string" ? record.summary : "";
}

function evidenceIsImage(evidence: RemediationEvidence): boolean {
  return /\.(png|jpe?g|webp|gif)$/i.test(evidence.artifact_path || "");
}

function detailLabel(evidence: RemediationEvidence): string {
  return evidence.artifact_path?.split("/").pop() || evidence.kind.replace(/_/g, " ");
}

function LinkedFindings({ selected, disabled, onSave }: {
  selected: RemediationCase; disabled: boolean; onSave: (ids: number[]) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [sources, setSources] = useState<Engagement[]>([]);
  const [source, setSource] = useState("");
  const [slug, setSlug] = useState("");
  const [candidate, setCandidate] = useState<LinkedRemediationFinding | null>(null);
  const [lookingUp, setLookingUp] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const lookup = useRef(0);
  const active = useRef(true);
  const mutationPending = useRef(false);

  useEffect(() => {
    active.current = true;
    return () => { active.current = false; };
  }, []);

  useEffect(() => {
    if (!editing) return;
    let active = true;
    listEngagements().then((values) => {
      if (active) setSources(values.filter((item) => !["remediation", "blue"].includes(item.engagement_type || "")));
    }).catch((failure: unknown) => {
      if (active) setError(failure instanceof Error ? failure.message : "Could not load source engagements");
    });
    return () => { active = false; lookup.current += 1; };
  }, [editing]);

  async function find() {
    if (!source || !slug.trim() || lookingUp || saving || disabled) return;
    const requestId = ++lookup.current;
    setLookingUp(true);
    setCandidate(null);
    setError(null);
    try {
      const finding = await getAssessmentFinding(source, slug.trim());
      if (requestId !== lookup.current) return;
      setCandidate({ id: finding.id, engagement_key: source, slug: finding.slug, title: finding.title, severity: finding.severity, verification_status: finding.verification_status, root_cause_key: finding.root_cause_key });
    } catch (failure) {
      if (requestId === lookup.current) setError(failure instanceof Error ? failure.message : "Could not find finding");
    } finally {
      if (requestId === lookup.current) setLookingUp(false);
    }
  }

  async function save(ids: number[]) {
    if (lookingUp || mutationPending.current || disabled) return;
    mutationPending.current = true;
    setSaving(true);
    setError(null);
    try {
      await onSave(ids);
      if (!active.current) return;
      setCandidate(null);
      setSlug("");
      setEditing(false);
    } catch (failure) {
      if (active.current) setError(failure instanceof Error ? failure.message : "Could not update linked findings");
    } finally {
      mutationPending.current = false;
      if (active.current) setSaving(false);
    }
  }

  function invalidate() { lookup.current += 1; setCandidate(null); setLookingUp(false); setError(null); }
  const busy = lookingUp || saving;

  return <section className="remediation-section remediation-linked" aria-label="Linked findings">
    <div className="remediation-section-heading"><div><h3>Linked findings</h3><p>Current assessment state · {selected.linked_findings.length} linked</p></div><button type="button" onClick={() => { setEditing(!editing); setError(null); }} disabled={disabled || busy}>{editing ? "Cancel linking" : "Link finding"}</button></div>
    {selected.linked_findings.length ? <ul className="remediation-finding-list">{selected.linked_findings.map((finding) => <li key={finding.id}>
      <a href={engagementHref(finding.engagement_key, { tab: "findings", finding: finding.slug })} aria-disabled={saving || undefined} onClick={(event) => { if (saving) event.preventDefault(); }}><span className="remediation-finding-key">{finding.engagement_key} / {finding.slug}</span><strong>{finding.title}</strong>{finding.root_cause_key && <span className="remediation-finding-key">Root cause: {finding.root_cause_key}</span>}</a>
      <SeverityTag severity={finding.severity} size="sm" /><StatusPill domain="finding-verification" value={finding.verification_status} size="sm" />
      <button type="button" className="remediation-text-button" onClick={() => save(selected.linked_findings.filter((item) => item.id !== finding.id).map((item) => item.id))} disabled={disabled || busy} aria-label={`Unlink ${finding.slug}`}>Unlink</button>
    </li>)}</ul> : <p>No Vigil findings linked to this case.</p>}
    {editing && <div className="remediation-link-editor">
      <div className="remediation-field-grid"><div><label htmlFor="remediation-link-source">Source engagement</label><select id="remediation-link-source" value={source} disabled={saving || disabled} onChange={(event) => { if (saving || disabled) return; invalidate(); setSource(event.target.value); }}><option value="">Select engagement</option>{sources.map((item) => <option key={item.key} value={item.key}>{item.key} · {item.target}</option>)}</select></div>
      <div><label htmlFor="remediation-link-slug">Finding slug</label><input id="remediation-link-slug" value={slug} disabled={saving || disabled} onChange={(event) => { if (saving || disabled) return; invalidate(); setSlug(event.target.value); }} placeholder="SEC-001" /></div></div>
      <button type="button" onClick={find} disabled={!source || !slug.trim() || busy || disabled}>Find finding</button>
      {candidate && <div className="remediation-link-candidate"><div><strong>{candidate.title}</strong><p>{candidate.slug} · <SeverityTag severity={candidate.severity} size="sm" /> · {statusLabel("finding-verification", candidate.verification_status)}</p></div><button type="button" onClick={() => save([...selected.linked_findings.map((item) => item.id), candidate.id])} disabled={busy || disabled || selected.linked_findings.some((item) => item.id === candidate.id)}>{selected.linked_findings.some((item) => item.id === candidate.id) ? "Already linked" : "Add to case"}</button></div>}
      <p className="remediation-help">Link findings that share this fix. Changing links requires a new review approval.</p>
    </div>}
    {error && <p role="alert">{error}</p>}
  </section>;
}

export function RemediationPage(props: Props) {
  return <RemediationWorkspace key={props.engagementKey} {...props} />;
}

function caseMatches(item: RemediationCaseSummary, query: string): boolean {
  return `${item.title} ${item.source_key} ${item.source_type} ${item.status} ${item.linked_findings.map((finding) => `${finding.slug} ${finding.title}`).join(" ")}`.toLowerCase().includes(query.toLowerCase());
}

// The page: header, case queue and the open case. The queue (its search,
// scroll and loaded list) lives here and survives choosing a case; only the
// open case's workspace remounts per case, so nothing from one case's edits
// or in-flight saves can land on another.
function RemediationWorkspace({ engagementKey, onBack, initialCaseId }: Props) {
  const [cases, setCases] = useState<RemediationCaseSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [listAttempt, setListAttempt] = useState(0);
  const [query, setQuery] = useState("");
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  // The open case's busy state and its synchronous link-mutation lock.
  const [busy, setBusy] = useState(false);
  const navigationLock = useRef(false);
  const selectedId = initialCaseId ?? cases[0]?.id ?? null;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setListError(null);
    listRemediationCases(engagementKey).then((next) => {
      if (active) setCases(next);
    }).catch((failure: unknown) => {
      if (active) setListError(failure instanceof Error ? failure.message : "Could not load cases");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [engagementKey, listAttempt]);

  // Header identity and lifecycle; the page works without them.
  useEffect(() => {
    let active = true;
    Promise.resolve().then(() => getEngagement(engagementKey)).then((value) => { if (active) setEngagement(value); }).catch(() => undefined);
    return () => { active = false; };
  }, [engagementKey]);

  function chooseCase(caseId: number) {
    if (caseId === selectedId || busy || navigationLock.current) return;
    writeWorkspaceHash(remediationHref(engagementKey, caseId));
  }

  // The open case's latest record replaces its queue entry.
  function acceptCase(next: RemediationCase) {
    setCases((values) => values.map((item) => item.id === next.id ? next : item));
  }

  const visibleCases = cases.filter((item) => caseMatches(item, query));

  return (
    <div className="remediation-page">
      <header className="dashboard-header workspace-header remediation-header">
        <div>
          <p className="eyebrow">Vigil / {engagementKey} · Remediation</p>
          <h1>{engagement?.target || engagementKey}</h1>
        </div>
        <div className="page-actions">
          <div className="status-summary">
            <div className="status-summary-row">
              <span className="status-summary-label">Engagement lifecycle</span>
              {engagement ? <StatusPill domain="engagement" value={engagement.status || "unknown"} /> : <Skeleton width={84} height={20} rounded />}
            </div>
          </div>
          <ThemeToggle />
          <button type="button" className="ghost-button" onClick={onBack} disabled={busy} title="Back to engagements">Back</button>
        </div>
      </header>
      <div className="remediation-layout">
        <aside className="remediation-queue" aria-label="Case queue">
          <div className="remediation-section-heading"><h2>Cases</h2><span>{visibleCases.length} / {cases.length}</span></div>
          <div className="remediation-queue-search"><label className="sr-only" htmlFor="remediation-search">Search cases</label><input id="remediation-search" placeholder="Search cases…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
          {loading && cases.length === 0 ? <p>Loading cases…</p> : listError ? <><p role="alert">{listError}</p><button type="button" onClick={() => setListAttempt((attempt) => attempt + 1)}>Retry loading cases</button></> : cases.length === 0 ? <p>No remediation cases imported yet.</p> : (
            <ul>
              {visibleCases.map((item) => (
                <li key={item.id}>
                  <button type="button" className={selectedId === item.id ? "is-selected" : ""} onClick={() => chooseCase(item.id)} disabled={busy} aria-current={selectedId === item.id ? "page" : undefined}>
                    <span className="remediation-case-key"><span>{item.source_type === "finding" ? `Finding #${item.source_key}` : item.source_key}</span><span>#{item.id}</span></span>
                    <strong>{item.title}</strong>
                    <span className="remediation-case-status"><StatusPill domain="remediation" value={item.status} size="sm" /> · {item.linked_findings.length} finding{item.linked_findings.length === 1 ? "" : "s"}</span>
                    {item.linked_findings.map((finding) => <span key={finding.id} className="remediation-case-finding"><span>{finding.title}</span><span>{finding.slug} · <SeverityTag severity={finding.severity} size="sm" /> · {statusLabel("finding-verification", finding.verification_status)}</span>{finding.root_cause_key && <span>Root cause: {finding.root_cause_key}</span>}</span>)}
                    {item.duplicate_hints?.length > 0 && <span className="remediation-case-status">{item.duplicate_hints.length} possible duplicate{item.duplicate_hints.length === 1 ? "" : "s"}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {!listError && cases.length > 0 && !visibleCases.length && <p>No cases match your search.</p>}
        </aside>

        <RemediationCaseWorkspace
          key={selectedId ?? "none"}
          engagementKey={engagementKey}
          caseId={selectedId}
          listState={listError ? "failed" : loading && cases.length === 0 ? "loading" : cases.length === 0 ? "empty" : "ready"}
          onCase={acceptCase}
          onBusyChange={setBusy}
          navigationLock={navigationLock}
        />
      </div>
    </div>
  );
}

type CaseWorkspaceProps = {
  engagementKey: string;
  caseId: number | null;
  listState: "loading" | "failed" | "empty" | "ready";
  onCase: (next: RemediationCase) => void;
  onBusyChange: (busy: boolean) => void;
  navigationLock: MutableRefObject<boolean>;
};

function RemediationCaseWorkspace({ engagementKey, caseId: selectedId, listState, onCase, onBusyChange, navigationLock: linkMutationPending }: CaseWorkspaceProps) {
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
  const [caseError, setCaseError] = useState<string | null>(null);
  const [caseAttempt, setCaseAttempt] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [activePane, setActivePane] = useState("overview");
  const [drafts, setDrafts] = useState<RemediationDrafts>({});
  const [draftStorageError, setDraftStorageError] = useState<string | null>(null);
  const [invalidDraftRecord, setInvalidDraftRecord] = useState<string | null>(null);
  const [discardFailed, setDiscardFailed] = useState(false);
  const workspaceActive = useRef(true);
  const caseReads = useRef(0);
  const onCaseRef = useRef(onCase);
  onCaseRef.current = onCase;

  useEffect(() => {
    workspaceActive.current = true;
    return () => { workspaceActive.current = false; };
  }, []);

  // The queue shows this case's latest record; the page locks the queue and Back while it is busy.
  useEffect(() => {
    if (selected) onCaseRef.current(selected);
  }, [selected]);
  useEffect(() => {
    onBusyChange(busy);
  }, [busy, onBusyChange]);
  useEffect(() => () => onBusyChange(false), [onBusyChange]);

  useEffect(() => {
    if (selectedId == null) {
      setSelected(null);
      return;
    }
    let active = true;
    const requestId = ++caseReads.current;
    setCaseError(null);
    setDiff(null);
    setDiffError(null);
    getRemediationCase(engagementKey, selectedId).then((next) => {
      if (!active || requestId !== caseReads.current) return;
      setSelected(next);
      let restored: RemediationDrafts = {};
      try {
        restored = readRemediationDrafts(engagementKey, next.id);
        setDraftStorageError(null);
        setInvalidDraftRecord(null);
      } catch (failure) {
        setDraftStorageError(failure instanceof Error ? failure.message : "Could not restore drafts");
        setInvalidDraftRecord(failure instanceof InvalidRemediationDraftError ? failure.rawRecord : null);
      }
      const values = savedDraftValues(next);
      const pending = { ...restored };
      for (const field of Object.keys(pending) as (keyof RemediationDraftValues)[]) {
        if (JSON.stringify(pending[field]?.value) === JSON.stringify(values[field])) delete pending[field];
      }
      if (Object.keys(pending).length !== Object.keys(restored).length) storeDrafts(pending, next.id);
      setDrafts(pending);
      applyDraftValues(next, pending);
    }).catch((failure: unknown) => {
      if (active && requestId === caseReads.current) setCaseError(failure instanceof Error ? failure.message : "Could not load case");
    });
    getRemediationDiff(engagementKey, selectedId).then((next) => {
      if (active && requestId === caseReads.current) setDiff(next);
    }).catch((failure: unknown) => {
      if (active && requestId === caseReads.current) setDiffError(failure instanceof Error ? failure.message : "Could not load code diff");
    });
    return () => { active = false; };
  }, [engagementKey, selectedId, caseAttempt]);

  function savedDraftValues(value: RemediationCase): RemediationDraftValues {
    return { plan: value.verification_plan || "", baseline: value.baseline || {}, releasePlan: value.release_plan || {} };
  }

  function applyDraftValues(value: RemediationCase, retained: RemediationDrafts) {
    const saved = savedDraftValues(value);
    setPlan(retained.plan?.value ?? saved.plan);
    setBaseline(retained.baseline?.value ?? saved.baseline);
    setReleasePlan(retained.releasePlan?.value ?? saved.releasePlan);
  }

  function storeDrafts(value: RemediationDrafts, caseId: number, discardInvalid = false) {
    if (invalidDraftRecord !== null && !discardInvalid) return false;
    try {
      writeRemediationDrafts(engagementKey, caseId, value);
      setDraftStorageError(null);
      setInvalidDraftRecord(null);
      setDiscardFailed(false);
      return true;
    } catch (failure) {
      setDraftStorageError(failure instanceof Error ? failure.message : "Could not store drafts");
      setDiscardFailed(discardInvalid);
      return false;
    }
  }

  function retainDraft<K extends keyof RemediationDraftValues>(field: K, value: RemediationDraftValues[K]) {
    if (!selected || selected.status === "closed" || busy) return false;
    const base = savedDraftValues(selected)[field];
    const next: RemediationDrafts = { ...drafts };
    if (JSON.stringify(value) === JSON.stringify(base)) delete next[field];
    else Object.assign(next, { [field]: { ...(drafts[field] ?? { base_value: base, review_digest: selected.review_digest ?? null, worktree_revision: selected.worktree_revision }), value } });
    setDrafts(next);
    storeDrafts(next, selected.id);
    return true;
  }

  function editPlan(value: string) { if (retainDraft("plan", value)) setPlan(value); }
  function editBaseline(value: Partial<RemediationBaseline>) { if (retainDraft("baseline", value)) setBaseline(value); }
  function editReleasePlan(value: Partial<RemediationReleasePlan>) { if (retainDraft("releasePlan", value)) setReleasePlan(value); }

  function clearDraft<K extends keyof RemediationDraftValues>(field: K, caseId: number, submitted: RemediationDraftValues[K]) {
    try {
      const stored = readRemediationDrafts(engagementKey, caseId);
      const next = workspaceActive.current ? { ...stored, ...drafts } : stored;
      if (JSON.stringify(next[field]?.value) === JSON.stringify(submitted)) delete next[field];
      storeDrafts(next, caseId);
      if (workspaceActive.current) setDrafts(next);
    } catch (failure) {
      const next = { ...drafts };
      delete next[field];
      if (workspaceActive.current) {
        setDrafts(next);
        setDraftStorageError(failure instanceof Error ? failure.message : "Could not clear saved draft");
      }
    }
  }

  function discardDrafts() {
    if (!selected || busy) return;
    if (!storeDrafts({}, selected.id, true)) return;
    setDrafts({});
    applyDraftValues(selected, {});
  }

  async function saveFindings(ids: number[]) {
    if (!selected || busy || linkMutationPending.current) return;
    linkMutationPending.current = true;
    const caseId = selected.id;
    const requestId = ++caseReads.current;
    const current = () => workspaceActive.current && requestId === caseReads.current;
    setBusy(true);
    setNotice(null);
    try {
      const next = await updateRemediationFindings(engagementKey, caseId, ids);
      if (!current()) return;
      setSelected(next);
      setDiff(null);
      setNotice("Linked findings updated. Review approval must match the new case snapshot.");
      try {
        const nextDiff = await getRemediationDiff(engagementKey, caseId);
        if (current()) { setDiff(nextDiff); setDiffError(null); }
      } catch (failure) {
        if (current()) setDiffError(failure instanceof Error ? failure.message : "Could not refresh code diff");
      }
    } finally {
      linkMutationPending.current = false;
      if (current()) setBusy(false);
    }
  }

  async function savePlan() {
    if (!selected || busy || !selected.verification_plan?.trim() || !plan.trim()) return;
    caseReads.current += 1;
    setBusy(true);
    setNotice(null);
    setDiff(null);
    try {
      const next = await updateRemediationVerificationPlan(engagementKey, selected.id, plan);
      clearDraft("plan", selected.id, plan);
      setSelected(next);
      setPlan(next.verification_plan || "");
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
    caseReads.current += 1;
    setBusy(true);
    setDiff(null);
    try {
      const next = await updateRemediationBaseline(engagementKey, selected.id, baseline as RemediationBaseline);
      clearDraft("baseline", selected.id, baseline);
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
    if (!selected || busy || !releasePlan.production_canary_decision || !releasePlan.production_canary_rationale?.trim() || !releasePlan.monitoring?.trim()) return;
    if (releasePlan.production_canary_decision === "required" && !releasePlan.safe_procedure?.trim()) return;
    caseReads.current += 1;
    setBusy(true);
    setDiff(null);
    try {
      const next = await updateRemediationReleasePlan(engagementKey, selected.id, {
        production_canary_decision: releasePlan.production_canary_decision,
        production_canary_rationale: releasePlan.production_canary_rationale,
        safe_procedure: releasePlan.safe_procedure || "",
        monitoring: releasePlan.monitoring,
      });
      clearDraft("releasePlan", selected.id, releasePlan);
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
    if (!selected || busy) return;
    caseReads.current += 1;
    setBusy(true);
    setDiff(null);
    try {
      const next = await getRemediationCase(engagementKey, selected.id);
      setSelected(next);
      applyDraftValues(next, drafts);
      setError(null);
      try {
        setDiff(await getRemediationDiff(engagementKey, selected.id));
        setDiffError(null);
      } catch (failure) {
        setDiffError(failure instanceof Error ? failure.message : "Could not refresh code diff");
      }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not refresh case");
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!selected || busy || plan !== selected.verification_plan || !reviewer.trim() || !selected.review_evidence_ready || !diff || diff.truncated || diff.review_digest !== selected.review_digest) return;
    caseReads.current += 1;
    setBusy(true);
    setNotice(null);
    try {
      await approveRemediationCase(engagementKey, selected.id, reviewer.trim(), diff.review_digest, "ui");
      const next = await getRemediationCase(engagementKey, selected.id);
      setSelected(next);
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
    caseReads.current += 1;
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
  const staleDrafts = selected != null && (Object.keys(drafts) as (keyof RemediationDraftValues)[]).some((field) => {
    const draft = drafts[field];
    return draft != null && (draft.review_digest !== (selected.review_digest ?? null) || draft.worktree_revision !== selected.worktree_revision || JSON.stringify(draft.base_value) !== JSON.stringify(savedDraftValues(selected)[field]));
  });
  return (
        <main className="remediation-workspace">
          {error && <div className="remediation-message remediation-error" role="alert">{error}</div>}
          {notice && <div className="remediation-message" role="status">{notice}</div>}
          {!selected ? (caseError ? <><p role="alert">{caseError}</p><button type="button" onClick={() => setCaseAttempt((attempt) => attempt + 1)}>Retry loading case</button></>
            : selectedId != null ? <p>Loading case…</p>
            : listState === "empty" ? <EmptyState variant="empty" title="No remediation cases yet.">Import a finding or a ticket as a case; it appears in the queue on the left.</EmptyState>
            : listState === "loading" ? <p>Loading cases…</p>
            : listState === "failed" ? <p>Cases could not be loaded; retry from the queue.</p>
            : <p>Select a case to begin.</p>) : (
            <fieldset className="remediation-case-controls" disabled={busy}>
              <div className="remediation-title-row">
                <div><p className="remediation-eyebrow">Case #{selected.id} · {selected.source_type === "finding" ? `Vigil finding #${selected.source_key} intake` : `${selected.source_type} · ${selected.source_key}`}</p><h2>{selected.title}</h2></div>
                <div className="remediation-title-actions"><StatusPill domain="remediation" value={selected.status} /><button type="button" onClick={refreshCase} disabled={busy}>Refresh case</button></div>
              </div>
              {selected.status === "closed" && <p className="remediation-help">This case is closed. Its plans and evidence are read-only.</p>}
              {(Object.keys(drafts).length > 0 || draftStorageError) && <div className="remediation-draft-status" role="status">
                <p>{discardFailed ? `Could not discard stored drafts: ${draftStorageError}. Current edits were kept; stored drafts may still return on navigation.` : draftStorageError ? `Draft storage unavailable: ${draftStorageError}. Unsaved edits remain only in this page and may be lost on navigation.` : "Drafts retained for this browser session. They are not saved to the case."}</p>
                {staleDrafts && <p className="remediation-caution">Server snapshot changed since these drafts began. Review retained edits against current records before saving.</p>}
                {invalidDraftRecord !== null && <p>The unreadable draft record is preserved in History until you discard it. New edits remain page-local.</p>}
                <button type="button" onClick={discardDrafts} disabled={busy}>Discard local drafts</button>
              </div>}

              <div className="remediation-meta">
                <div><span>Worktree</span><strong>{selected.worktree_path || "Not recorded"}</strong></div>
                <div><span>Code revision</span><strong>{selected.worktree_revision || "Not recorded"}</strong></div>
                <div><span>Development deployment</span><strong>{deployedRevision || "Not recorded"}</strong></div>
                <div><span>Revision check</span><strong className={revisionMatches ? "remediation-ok" : "remediation-caution"}>{revisionMatches ? "Matches code revision" : "Unconfirmed"}</strong></div>
              </div>
              <nav className="remediation-pane-nav" aria-label="Case sections">{[["overview", "Overview"], ["evidence", "Evidence"], ["review", "Review"], ["delivery", "Delivery"], ["history", "History"]].map(([value, label]) => <button type="button" key={value} disabled={busy} aria-current={activePane === value ? "page" : undefined} onClick={() => setActivePane(value)}>{label}{value === "evidence" && <span>{selected.evidence.length}</span>}</button>)}</nav>
              {activePane === "overview" && <LinkedFindings key={selected.id} selected={selected} disabled={busy || planDirty || baselineDirty || releasePlanDirty || selected.status === "closed"} onSave={saveFindings} />}

              <section className="remediation-section" hidden={activePane !== "overview"}>
                <div className="remediation-section-heading"><h3>Intake snapshot</h3><span>Captured at intake</span></div>
                {selected.source_type === "finding" && <p className="remediation-help">Original proof receipts were not captured in this intake snapshot. Linked findings show the current claim and verification evidence.</p>}
                <p className="remediation-intake-summary">{intakeSummary(selected.snapshot) || "No source summary captured."}</p>
                <details className="remediation-record"><summary>Original intake record</summary><JsonView value={selected.snapshot} /></details>
                {selected.duplicate_hints.length > 0 && (
                  <div className="remediation-duplicates"><strong>Likely duplicates · review manually</strong><ul>{selected.duplicate_hints.map((hint) => <li key={hint}>Case #{hint}{selected.duplicate_hint_details?.find((item) => item.case_id === hint)?.reasons.map((reason) => ` · ${reason}`).join("")}</li>)}</ul></div>
                )}
              </section>

              <section className="remediation-section remediation-review" hidden={activePane !== "overview"}>
                <div className="remediation-section-heading"><h3>Baseline</h3><span>{selected.baseline?.outcome ? selected.baseline.outcome.replace(/_/g, " ") : "Not recorded"}</span></div>
                <p>Record what actually reproduced and what the evidence proved. If runtime reproduction was unavailable, the case owner decides whether to proceed.</p>
                <fieldset className="remediation-case-controls" disabled={selected.status === "closed"}>
                <div className="remediation-field-grid">
                  <div><label htmlFor="remediation-baseline-outcome">Baseline outcome</label><select id="remediation-baseline-outcome" value={baseline.outcome || ""} onChange={(event) => editBaseline({ ...baseline, outcome: event.target.value as RemediationBaseline["outcome"] })}><option value="">Choose outcome</option><option value="runtime_reproduced">Runtime reproduced</option><option value="code_test_confirmed">Code and failing test confirmed</option><option value="unreproduced">Unreproduced</option></select></div>
                  <div><label htmlFor="remediation-baseline-method">Baseline method</label><input id="remediation-baseline-method" value={baseline.method || ""} onChange={(event) => editBaseline({ ...baseline, method: event.target.value })} placeholder="HTTP request, unit test, browser…" /></div>
                </div>
                <label htmlFor="remediation-baseline-proved">Baseline proved</label><textarea id="remediation-baseline-proved" value={baseline.proved || ""} onChange={(event) => editBaseline({ ...baseline, proved: event.target.value })} rows={3} />
                {baseline.outcome && baseline.outcome !== "runtime_reproduced" && <div className="remediation-owner-decision">
                  <p className="remediation-caution">Runtime reproduction was not established. The owner must record a decision before the review can advance.</p>
                  <div className="remediation-field-grid">
                    <div><label htmlFor="remediation-owner-decision">Owner decision</label><select id="remediation-owner-decision" value={baseline.owner_decision || ""} onChange={(event) => editBaseline({ ...baseline, owner_decision: event.target.value as RemediationBaseline["owner_decision"] })}><option value="">Choose decision</option><option value="proceed">Proceed</option><option value="pause">Pause</option></select></div>
                    <div><label htmlFor="remediation-owner-actor">Owner actor</label><input id="remediation-owner-actor" value={baseline.owner_actor || ""} onChange={(event) => editBaseline({ ...baseline, owner_actor: event.target.value })} /></div>
                  </div>
                  <label htmlFor="remediation-owner-reason">Owner reason</label><textarea id="remediation-owner-reason" value={baseline.owner_reason || ""} onChange={(event) => editBaseline({ ...baseline, owner_reason: event.target.value })} rows={2} />
                </div>}
                <div className="remediation-plan-actions"><span>{baselineDirty ? "Unsaved baseline changes" : "Baseline saved"}</span><button type="button" onClick={saveBaseline} disabled={!baselineDirty || busy || !baseline.outcome || !baseline.method?.trim() || !baseline.proved?.trim() || (baseline.outcome !== "runtime_reproduced" && (!baseline.owner_decision || !baseline.owner_actor?.trim() || !baseline.owner_reason?.trim()))}>Save baseline</button></div>
                </fieldset>
              </section>

              <section className="remediation-section" hidden={activePane !== "evidence"}>
                <div className="remediation-section-heading"><h3>Evidence and test results</h3><span>{selected.evidence.length} records</span></div>
                {selected.evidence.length === 0 ? <p>No evidence registered.</p> : (
                  <div className="remediation-evidence-grid">
                    {selected.evidence.map((item) => {
                      const url = remediationEvidenceFileUrl(engagementKey, selected.id, item.id);
                      const label = detailLabel(item);
                      return <figure key={item.id} className="remediation-evidence">
                        {evidenceIsImage(item) && <a href={url} target="_blank" rel="noreferrer"><img src={url} alt={label} loading="lazy" /></a>}
                        <figcaption><strong>{label}</strong><span>{item.kind.replace(/_/g, " ")} · {item.method}{item.outcome ? ` · ${item.outcome.replace(/_/g, " ")}` : ""}</span><span>Environment: {item.environment ?? "unknown (historical record)"}</span>{item.execution && <span>{item.execution === "executed" ? "Executed evidence" : item.execution === "reasoned" ? "Reasoned evidence" : "Execution unavailable"}</span>}<span>{item.proved}</span>{item.command && <code>{item.command}</code>}<span>Observed: {item.observed}</span>{item.revision && <span>Revision: {item.revision}</span>}{item.runtime_revision && <span>Confirmed runtime revision: {item.runtime_revision}</span>}{item.artifact_path && <a href={url} target="_blank" rel="noreferrer">Open evidence ↗</a>}</figcaption>
                      </figure>;
                    })}
                  </div>
                )}
              </section>

              <section className="remediation-section remediation-review" hidden={activePane !== "review"}>
                <div className="remediation-section-heading"><h3>Human verification plan</h3><span>Only rehearsed steps</span></div>
                <fieldset className="remediation-case-controls" disabled={selected.status === "closed"}>
                <label htmlFor="remediation-plan">Human verification plan</label>
                {!selected.verification_plan?.trim() && <p className="remediation-help">Ask the case developer to record the initial plan and required evidence before saving changes here.</p>}
                <textarea id="remediation-plan" value={plan} onChange={(event) => editPlan(event.target.value)} rows={9} />
                <div className="remediation-plan-actions"><span>{planDirty ? "Unsaved changes invalidate the reviewed plan." : selected.verification_plan?.trim() ? "Plan saved" : "Initial plan not recorded"}</span><button type="button" onClick={savePlan} disabled={!planDirty || busy || !selected.verification_plan?.trim() || !plan.trim()}>Save plan</button></div>
                </fieldset>
              </section>

              <section className="remediation-section remediation-review" hidden={activePane !== "delivery"}>
                <div className="remediation-section-heading"><h3>Release plan</h3><span>Production canary and monitoring</span></div>
                <fieldset className="remediation-case-controls" disabled={selected.status === "closed"}>
                <label htmlFor="remediation-canary-decision">Production canary decision</label>
                <select id="remediation-canary-decision" value={releasePlan.production_canary_decision || ""} onChange={(event) => editReleasePlan({ ...releasePlan, production_canary_decision: event.target.value as RemediationReleasePlan["production_canary_decision"] })}><option value="">Choose decision</option><option value="required">Required</option><option value="not_required">Not required</option><option value="defer">Defer decision</option></select>
                <label htmlFor="remediation-canary-rationale">Canary rationale</label>
                <textarea id="remediation-canary-rationale" value={releasePlan.production_canary_rationale || ""} onChange={(event) => editReleasePlan({ ...releasePlan, production_canary_rationale: event.target.value })} rows={3} />
                <label htmlFor="remediation-safe-procedure">Safe canary procedure</label>
                <textarea id="remediation-safe-procedure" value={releasePlan.safe_procedure || ""} onChange={(event) => editReleasePlan({ ...releasePlan, safe_procedure: event.target.value })} rows={3} placeholder="Required when a production canary is needed" />
                <label htmlFor="remediation-monitoring">Monitoring plan</label>
                <textarea id="remediation-monitoring" value={releasePlan.monitoring ?? ""} onChange={(event) => editReleasePlan({ ...releasePlan, monitoring: event.target.value })} rows={3} />
                <div className="remediation-plan-actions"><span>{releasePlanDirty ? "Unsaved release decision" : "Release plan saved"}</span><button type="button" onClick={saveReleasePlan} disabled={!releasePlanDirty || busy || !releasePlan.production_canary_decision || !releasePlan.production_canary_rationale?.trim() || !releasePlan.monitoring?.trim() || (releasePlan.production_canary_decision === "required" && !releasePlan.safe_procedure?.trim())}>Save release plan</button></div>
                </fieldset>
              </section>

              {deployment && <section className="remediation-section" hidden={activePane !== "delivery"}><div className="remediation-section-heading"><h3>Development deployment</h3></div><p className="remediation-deployment-link">Workflow: {deployment.workflow} · run {deployment.run_id} · expected {deployment.expected_revision}</p></section>}

              <section className="remediation-section remediation-review" hidden={activePane !== "delivery"}>
                <div className="remediation-section-heading"><h3>Human development verification</h3><span>{selected.human_verifications?.length || 0} {selected.human_verifications?.length === 1 ? "result" : "results"}</span></div>
                <p>Execute the saved plan in development and record the observed outcome. The record is tied to the confirmed deployment revision.</p>
                {selected.human_verifications?.length > 0 && <ul className="remediation-human-history">{selected.human_verifications.map((item) => <li key={item.id}><StatusPill domain="remediation-verification" value={item.result} size="sm" /> · {item.actor} · {item.observed_revision}<p>{item.notes}</p></li>)}</ul>}
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

              <section className="remediation-section remediation-review" hidden={activePane !== "review"}>
                <div className="remediation-section-heading"><h3>Review approval</h3><span>{selected.approval_current ? "Current" : "Needs approval"}</span></div>
                {selected.verification_requirements && <div className="remediation-verification-requirements">
                  <h4>Verification alternatives</h4>
                  <p>{selected.verification_requirements.alternatives_reason}</p>
                  <ul>{selected.verification_requirements.requirements.map((requirement, index) => <li key={index}>{requirement.kind} · {requirement.methods.join(", ")} · {requirement.execution} · {requirement.revision} revision{requirement.browser_purpose ? ` · ${requirement.browser_purpose}` : ""}{requirement.legitimate_use_control ? " · legitimate-use control" : ""}{requirement.rationale ? ` · ${requirement.rationale}` : ""}</li>)}</ul>
                </div>}
                <p>Review the code diff, baseline, tests, screenshots, and human plan before approving. Approval applies to this exact code and plan snapshot.</p>
                {selected.review_evidence_ready ? <p className="remediation-ok">The case’s required verification evidence is registered.</p> : <div className="remediation-evidence-gate"><strong>Required evidence is missing</strong><ul>{selected.review_evidence_missing.map((item, index) => <li key={index}>{item}</li>)}</ul></div>}
                <div className="remediation-diff">
                  <div className="remediation-section-heading"><h3>Code diff</h3><span>{diff ? `${diff.base_revision} → ${diff.head_revision}` : ""}</span></div>
                  {diffError ? <p role="alert">Diff unavailable: {diffError}</p> : !diff ? <p>Loading code diff…</p> : <>
                    {diff.truncated && <p className="remediation-caution">Diff truncated because it exceeds the 1 MiB review limit. Open the worktree to review all changes.</p>}
                    {diff.review_digest !== selected.review_digest && <p className="remediation-caution">The diff no longer matches the case snapshot. Refresh the case before approval.</p>}
                    <pre>{diff.text || "No code changes in this review snapshot."}</pre>
                  </>}
                </div>
                <div className="remediation-approval-actions">
                  <label htmlFor="remediation-reviewer">Reviewer</label>
                  <input id="remediation-reviewer" value={reviewer} onChange={(event) => setReviewer(event.target.value)} placeholder="Case owner name" disabled={selected.status !== "review"} />
                  <button type="button" onClick={approve} disabled={busy || planDirty || baselineDirty || releasePlanDirty || !selected.review_evidence_ready || !selected.baseline?.outcome || !selected.release_plan?.production_canary_decision || !reviewer.trim() || !reviewDiffCurrent || selected.approval_current || selected.status !== "review"}>Approve reviewed snapshot</button>
                </div>
              </section>
              {activePane === "history" && <section className="remediation-section remediation-history" aria-label="Case history">
                <div className="remediation-section-heading"><h3>Case history</h3><span>{selected.transitions.length} transitions</span></div>
                {selected.transitions.length ? <ol>{selected.transitions.map((item, index) => <li key={textValue(item.id) || index}>{textValue(item.from_status)} → {textValue(item.to_status)} · {textValue(item.actor)} · {textValue(item.reason)}</li>)}</ol> : <p>No case transitions recorded.</p>}
                {selected.approvals.length > 0 && <><h3>Review approvals</h3><p>{selected.approval_current ? "Latest approval matches this snapshot." : "Earlier approval is stale after a change."}</p><ul>{selected.approvals.map((item, index) => <li key={textValue(item.id) || index}>Approved by {textValue(item.reviewer)} · revision {textValue(item.approved_revision)}</li>)}</ul></>}
                <details className="remediation-record"><summary>Raw case record</summary><JsonView value={selected} /></details>
                {Object.keys(drafts).length > 0 && <details className="remediation-record"><summary>Local unsaved drafts</summary><JsonView value={drafts} /></details>}
                {invalidDraftRecord !== null && <details className="remediation-record"><summary>Unreadable local draft record</summary><CodeBlock text={invalidDraftRecord} /></details>}
              </section>}
            </fieldset>
          )}
        </main>
  );
}
