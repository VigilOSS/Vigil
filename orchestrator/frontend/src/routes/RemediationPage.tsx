import { useEffect, useRef, useState } from "react";

import {
  ApiError,
  approveRemediationCase,
  getRemediationCase,
  getBackendReadiness,
  getRemediationEvidencePage,
  getRemediationEvidence,
  getRemediationHistoryPage,
  readRemediationEvidenceText,
  getRemediationDiff,
  listRemediationCases,
  remediationEvidenceFileUrl,
  recordRemediationHumanVerification,
  updateRemediationBaseline,
  updateRemediationReleasePlan,
  updateRemediationVerificationPlan,
  getAssessmentFinding,
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
import { JsonView } from "../components/JsonView";
import { CodeBlock } from "../components/formatting";
import { engagementHref, remediationHref, writeWorkspaceHash } from "../lib/workspaceRoutes";
import { InvalidRemediationDraftError, readRemediationDrafts, writeRemediationDrafts, type RemediationDrafts, type RemediationDraftValues } from "../lib/remediationDrafts";
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

function caseSummary(value: RemediationCase): RemediationCaseSummary {
  return {
    id: value.id,
    source_type: value.source_type,
    source_key: value.source_key,
    title: value.title,
    status: value.status,
    linked_findings: value.linked_findings,
    duplicate_hints: value.duplicate_hints,
    duplicate_hint_details: value.duplicate_hint_details,
    worktree_revision: value.worktree_revision,
    baseline_outcome: value.baseline.outcome ?? "pending",
    approval_recorded: value.approvals.length > 0,
  };
}

function initialCasePage(value: RemediationCase): RemediationCase {
  return { ...value, evidence_total: value.evidence_total ?? value.evidence.length, history_total: value.history_total ?? value.transitions.length, evidence: value.evidence.slice(0, 20), transitions: value.transitions.slice(0, 20) };
}

function safeHttpUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch { return undefined; }
}

function evidenceIsImage(evidence: RemediationEvidence): boolean {
  return /\.(png|jpe?g|webp|gif)$/i.test(evidence.artifact_path || "");
}

function detailLabel(evidence: RemediationEvidence): string {
  return evidence.artifact_path?.split("/").pop() || evidence.kind.replace(/_/g, " ");
}

function EvidencePreview({ engagementKey, caseId, item }: { engagementKey: string; caseId: number; item: RemediationEvidence }) {
  const [opened, setOpened] = useState(false);
  const [preview, setPreview] = useState<{ text: string; truncated: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!opened || preview) return;
    const controller = new AbortController();
    setError(null);
    readRemediationEvidenceText(engagementKey, caseId, item.id, controller.signal).then((value) => {
      if (!controller.signal.aborted) setPreview(value);
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "Could not preview artifact");
    });
    return () => controller.abort();
  }, [opened, preview, engagementKey, caseId, item.id]);
  if (!item.artifact_path || evidenceIsImage(item) || !/\.(txt|log|json|jsonl|md|csv|xml|html?|yaml|yml|diff|patch)$/i.test(item.artifact_path)) return null;
  return <div className="remediation-artifact-preview"><button type="button" aria-expanded={opened} onClick={() => setOpened(!opened)}>{opened ? "Hide" : "Preview"} {detailLabel(item)}</button>{opened && (error ? <p role="alert">{error}</p> : !preview ? <p>Loading artifact…</p> : <>{preview.truncated && <p className="remediation-caution">Preview limited to 128 KiB. Open evidence to inspect the complete artifact.</p>}<pre>{preview.text}</pre></>)}</div>;
}

function BackendDriftWarning() {
  const [restartRequired, setRestartRequired] = useState(false);
  useEffect(() => {
    let active = true;
    async function check() {
      try {
        const ready = await getBackendReadiness();
        if (active) setRestartRequired(ready.backend_runtime.restart_required);
      } catch { /* A transient readiness failure must not clear an observed drift warning. */ }
    }
    void check();
    const timer = window.setInterval(() => { void check(); }, 30000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);
  return restartRequired ? <div className="remediation-message remediation-caution" role="status"><strong>Backend restart required.</strong> Source inputs changed; the running backend still uses earlier code. Restart the backend for this workspace on its owning host, then refresh this case.</div> : null;
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
      <span className={`remediation-severity remediation-severity-${finding.severity}`}>{finding.severity}</span><span>{finding.verification_status.replace(/_/g, " ")}</span>
      <button type="button" className="remediation-text-button" onClick={() => save(selected.linked_findings.filter((item) => item.id !== finding.id).map((item) => item.id))} disabled={disabled || busy} aria-label={`Unlink ${finding.slug}`}>Unlink</button>
    </li>)}</ul> : <p>No Vigil findings linked to this case.</p>}
    {editing && <div className="remediation-link-editor">
      <div className="remediation-field-grid"><div><label htmlFor="remediation-link-source">Source engagement</label><select id="remediation-link-source" value={source} disabled={saving || disabled} onChange={(event) => { if (saving || disabled) return; invalidate(); setSource(event.target.value); }}><option value="">Select engagement</option>{sources.map((item) => <option key={item.key} value={item.key}>{item.key} · {item.target}</option>)}</select></div>
      <div><label htmlFor="remediation-link-slug">Finding slug</label><input id="remediation-link-slug" value={slug} disabled={saving || disabled} onChange={(event) => { if (saving || disabled) return; invalidate(); setSlug(event.target.value); }} placeholder="SEC-001" /></div></div>
      <button type="button" onClick={find} disabled={!source || !slug.trim() || busy || disabled}>Find finding</button>
      {candidate && <div className="remediation-link-candidate"><div><strong>{candidate.title}</strong><p>{candidate.slug} · {candidate.severity} · {candidate.verification_status.replace(/_/g, " ")}</p></div><button type="button" onClick={() => save([...selected.linked_findings.map((item) => item.id), candidate.id])} disabled={busy || disabled || selected.linked_findings.some((item) => item.id === candidate.id)}>{selected.linked_findings.some((item) => item.id === candidate.id) ? "Already linked" : "Add to case"}</button></div>}
      <p className="remediation-help">Link findings that share this fix. Changing links requires a new review approval.</p>
    </div>}
    {error && <p role="alert">{error}</p>}
  </section>;
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
  const [query, setQuery] = useState("");
  const [activePane, setActivePane] = useState("overview");
  const [drafts, setDrafts] = useState<RemediationDrafts>({});
  const [draftStorageError, setDraftStorageError] = useState<string | null>(null);
  const [invalidDraftRecord, setInvalidDraftRecord] = useState<string | null>(null);
  const [discardFailed, setDiscardFailed] = useState(false);
  const workspaceActive = useRef(true);
  const caseReads = useRef(0);
  const evidenceReads = useRef(0);
  const linkMutationPending = useRef(false);
  const [pageBusy, setPageBusy] = useState(false);
  const [pageError, setPageError] = useState<string | null>(null);
  const [focusedEvidence, setFocusedEvidence] = useState<RemediationEvidence | null>(null);
  const [rawCaseOpen, setRawCaseOpen] = useState(false);

  useEffect(() => {
    workspaceActive.current = true;
    return () => { workspaceActive.current = false; };
  }, []);

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
    const requestId = beginCaseRead();
    setCaseError(null);
    setFocusedEvidence(null);
    setPageError(null);
    setDiff(null);
    setDiffError(null);
    getRemediationCase(engagementKey, selectedId).then((next) => {
      if (!active || requestId !== caseReads.current) return;
      setSelected(initialCasePage(next));
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
    return () => { active = false; };
  }, [engagementKey, selectedId, caseAttempt]);

  useEffect(() => {
    if (activePane !== "review" || !selected || busy || diff) return;
    let active = true;
    setDiffError(null);
    getRemediationDiff(engagementKey, selected.id).then((next) => {
      if (active) setDiff(next);
    }).catch((failure: unknown) => {
      if (active) setDiffError(failure instanceof Error ? failure.message : "Could not load code diff");
    });
    return () => { active = false; };
  }, [activePane, selected, busy, diff, engagementKey]);

  function beginCaseRead() {
    evidenceReads.current += 1;
    setPageBusy(false);
    setPageError(null);
    setFocusedEvidence(null);
    return ++caseReads.current;
  }

  async function viewEvidence(id: number) {
    if (!selected) return;
    const readId = caseReads.current;
    const evidenceReadId = ++evidenceReads.current;
    const current = () => workspaceActive.current && readId === caseReads.current && evidenceReadId === evidenceReads.current;
    setActivePane("evidence");
    setFocusedEvidence(null);
    setPageError(null);
    if (!selected.evidence.some((item) => item.id === id)) {
      try {
        const item = await getRemediationEvidence(engagementKey, selected.id, id);
        if (!current()) return;
        setFocusedEvidence(item);
      } catch (failure) {
        if (current()) setPageError(failure instanceof Error ? failure.message : "Could not load matching evidence");
      }
    }
    window.setTimeout(() => { if (current()) document.getElementById(`remediation-evidence-${id}`)?.scrollIntoView?.({ block: "center" }); }, 0);
  }

  async function loadMore(section: "evidence" | "history") {
    if (!selected || pageBusy) return;
    const snapshot = selected;
    const readId = caseReads.current;
    setPageBusy(true);
    setPageError(null);
    try {
      const page = section === "evidence"
        ? await getRemediationEvidencePage(engagementKey, snapshot.id, snapshot.evidence.length)
        : await getRemediationHistoryPage(engagementKey, snapshot.id, snapshot.transitions.length);
      if (!workspaceActive.current || readId !== caseReads.current) return;
      setSelected((current) => !current || current.id !== snapshot.id ? current : section === "evidence"
        ? { ...current, evidence: [...current.evidence, ...page.items as RemediationEvidence[]], evidence_total: page.total }
        : { ...current, transitions: [...current.transitions, ...page.items], history_total: page.total });
    } catch (failure) {
      if (workspaceActive.current && readId === caseReads.current) setPageError(failure instanceof Error ? failure.message : "Could not load more records");
    } finally { if (workspaceActive.current && readId === caseReads.current) setPageBusy(false); }
  }

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

  function chooseCase(caseId: number) {
    if (caseId === selectedId || busy || linkMutationPending.current) return;
    beginCaseRead();
    setSelectedId(caseId);
    setSelected(null);
    setDiff(null);
    setNotice(null);
    setActivePane("overview");
    writeWorkspaceHash(remediationHref(engagementKey, caseId));
  }

  async function saveFindings(ids: number[]) {
    if (!selected || busy || linkMutationPending.current) return;
    linkMutationPending.current = true;
    const caseId = selected.id;
    const requestId = beginCaseRead();
    const current = () => workspaceActive.current && requestId === caseReads.current;
    setBusy(true);
    setNotice(null);
    try {
      const next = await updateRemediationFindings(engagementKey, caseId, ids);
      if (!current()) return;
      setSelected(initialCasePage(next));
      setCases((values) => values.map((item) => item.id === next.id ? caseSummary(next) : item));
      setDiff(null);
      setNotice("Linked findings updated. Review approval must match the new case snapshot.");
    } finally {
      linkMutationPending.current = false;
      if (current()) setBusy(false);
    }
  }

  async function savePlan() {
    if (!selected || busy || !selected.verification_plan?.trim() || !plan.trim()) return;
    beginCaseRead();
    setBusy(true);
    setNotice(null);
    setDiff(null);
    try {
      const next = await updateRemediationVerificationPlan(engagementKey, selected.id, plan);
      clearDraft("plan", selected.id, plan);
      setSelected(initialCasePage(next));
      setPlan(next.verification_plan || "");
      setCases((current) => current.map((item) => item.id === next.id ? caseSummary(next) : item));
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
    beginCaseRead();
    setBusy(true);
    setDiff(null);
    try {
      const next = await updateRemediationBaseline(engagementKey, selected.id, baseline as RemediationBaseline);
      clearDraft("baseline", selected.id, baseline);
      setSelected(initialCasePage(next));
      setBaseline(next.baseline || {});
      setError(null);
      setNotice("Baseline saved. Review the updated snapshot before approval.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save baseline");
    } finally {
      setBusy(false);
    }
  }

  async function saveReleasePlan() {
    if (!selected || busy || !releasePlan.production_canary_decision || !releasePlan.production_canary_rationale?.trim() || !releasePlan.monitoring?.trim()) return;
    if (releasePlan.production_canary_decision === "required" && !releasePlan.safe_procedure?.trim()) return;
    beginCaseRead();
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
      setSelected(initialCasePage(next));
      setReleasePlan(next.release_plan || {});
      setError(null);
      setNotice("Release plan saved. Review the updated snapshot before approval.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not save release plan");
    } finally {
      setBusy(false);
    }
  }

  async function refreshCase() {
    if (!selected || busy) return;
    beginCaseRead();
    setBusy(true);
    setDiff(null);
    try {
      const next = await getRemediationCase(engagementKey, selected.id);
      setSelected(initialCasePage(next));
      setCases((current) => current.map((item) => item.id === next.id ? caseSummary(next) : item));
      applyDraftValues(next, drafts);
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not refresh case");
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    if (!selected || busy || plan !== selected.verification_plan || !reviewer.trim() || !selected.review_evidence_ready || !diff || diff.truncated || diff.review_digest !== selected.review_digest) return;
    beginCaseRead();
    setBusy(true);
    setNotice(null);
    try {
      await approveRemediationCase(engagementKey, selected.id, reviewer.trim(), diff.review_digest, "ui");
      const next = await getRemediationCase(engagementKey, selected.id);
      setSelected(initialCasePage(next));
      setCases((current) => current.map((item) => item.id === next.id ? caseSummary(next) : item));
      setNotice("Reviewed snapshot approved. Any later code or plan change requires a new approval.");
      setError(null);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Could not approve case");
      if (failure instanceof ApiError && failure.status === 409) {
        setDiff(null);
        try {
          const next = await getRemediationCase(engagementKey, selected.id);
          setSelected(initialCasePage(next));
          setPlan(next.verification_plan || "");
          setBaseline(next.baseline || {});
          setReleasePlan(next.release_plan || {});
          setDiffError(null);
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
    beginCaseRead();
    setBusy(true);
    setNotice(null);
    try {
      await recordRemediationHumanVerification(engagementKey, selected.id, {
        actor: humanActor.trim(), result: humanResult, observed_revision: deployedRevision, notes: humanNotes.trim(),
      });
      setSelected(initialCasePage(await getRemediationCase(engagementKey, selected.id)));
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
  const visibleCases = cases.map((item) => item.id === selected?.id ? selected : item).filter((item) => `${item.title} ${item.source_key} ${item.source_type} ${item.status} ${item.linked_findings.map((finding) => `${finding.slug} ${finding.title}`).join(" ")}`.toLowerCase().includes(query.toLowerCase()));

  return (
    <div className="remediation-page">
      <header className="remediation-header">
        <div className="remediation-header-title">
          <button type="button" className="remediation-back" onClick={onBack} disabled={busy}>← Engagements</button>
          <div><span className="remediation-eyebrow">Vigil / Remediation</span><h1>{engagementKey}</h1></div>
        </div>
        <ThemeToggle />
      </header>
      {error && <div className="remediation-message remediation-error" role="alert">{error}</div>}
      {notice && <div className="remediation-message" role="status">{notice}</div>}
      <BackendDriftWarning />
      <div className="remediation-layout">
        <aside className="remediation-queue" aria-label="Case queue">
          <div className="remediation-section-heading"><h2>Cases</h2><span>{visibleCases.length} / {cases.length}</span></div>
          <div className="remediation-queue-search"><label className="sr-only" htmlFor="remediation-search">Search cases</label><input id="remediation-search" placeholder="Search cases…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
          {loading ? <p>Loading cases…</p> : listError ? <><p role="alert">{listError}</p><button type="button" onClick={() => setListAttempt((attempt) => attempt + 1)}>Retry loading cases</button></> : cases.length === 0 ? <p>No remediation cases imported yet.</p> : (
            <ul>
              {visibleCases.map((item) => (
                <li key={item.id}>
                  <button type="button" className={selectedId === item.id ? "is-selected" : ""} onClick={() => chooseCase(item.id)} disabled={busy} aria-current={selectedId === item.id ? "page" : undefined}>
                    <span className="remediation-case-key"><span>{item.source_type === "finding" ? `Finding #${item.source_key}` : item.source_key}</span><span>#{item.id}</span></span>
                    <strong>{item.title}</strong>
                    <span className="remediation-case-status"><span className="remediation-status-dot" />{item.status.replace(/_/g, " ")} · {item.linked_findings.length} finding{item.linked_findings.length === 1 ? "" : "s"}</span>
                    {item.linked_findings.map((finding) => <span key={finding.id} className="remediation-case-finding"><span>{finding.title}</span><span>{finding.slug} · {finding.severity} · {finding.verification_status.replace(/_/g, " ")}</span>{finding.root_cause_key && <span>Root cause: {finding.root_cause_key}</span>}</span>)}
                    {item.duplicate_hints?.length > 0 && <span className="remediation-case-status">{item.duplicate_hints.length} possible duplicate{item.duplicate_hints.length === 1 ? "" : "s"}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
          {!loading && !listError && cases.length > 0 && !visibleCases.length && <p>No cases match your search.</p>}
        </aside>

        <main className="remediation-workspace">
          {!selected ? (caseError ? <><p role="alert">{caseError}</p><button type="button" onClick={() => setCaseAttempt((attempt) => attempt + 1)}>Retry loading case</button></> : selectedId == null ? <p>Select a case to begin.</p> : <p>Loading case…</p>) : (
            <fieldset className="remediation-case-controls" disabled={busy}>
              <div className="remediation-title-row">
                <div><p className="remediation-eyebrow">Case #{selected.id} · {selected.source_type === "finding" ? `Vigil finding #${selected.source_key} intake` : `${selected.source_type} · ${selected.source_key}`}</p><h2>{selected.title}</h2></div>
                <div className="remediation-title-actions"><span className="remediation-state">{selected.status.replace(/_/g, " ")}</span><button type="button" onClick={refreshCase} disabled={busy}>Refresh case</button></div>
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
              <nav className="remediation-pane-nav" aria-label="Case sections">{[["overview", "Overview"], ["evidence", "Evidence"], ["review", "Review"], ["delivery", "Delivery"], ["history", "History"]].map(([value, label]) => <button type="button" key={value} disabled={busy} aria-current={activePane === value ? "page" : undefined} onClick={() => setActivePane(value)}>{label}{value === "evidence" && <span>{(selected.evidence_total ?? selected.evidence.length)}</span>}</button>)}</nav>
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

              {activePane === "evidence" && <section className="remediation-section">
                <div className="remediation-section-heading"><h3>Evidence and test results</h3><span>{selected.evidence_total ?? selected.evidence.length} records</span></div>
                {selected.evidence.length === 0 ? <p>No evidence registered.</p> : (
                  <div className="remediation-evidence-grid">
                    {(focusedEvidence && !selected.evidence.some((item) => item.id === focusedEvidence.id) ? [focusedEvidence, ...selected.evidence] : selected.evidence).map((item) => {
                      const url = remediationEvidenceFileUrl(engagementKey, selected.id, item.id);
                      const label = detailLabel(item);
                      return <figure key={item.id} id={`remediation-evidence-${item.id}`} className="remediation-evidence">
                        {evidenceIsImage(item) && <a href={url} target="_blank" rel="noreferrer"><img src={url} alt={label} loading="lazy" /></a>}
                        <figcaption><strong>{label}</strong><span>{item.kind.replace(/_/g, " ")} · {item.method}{item.outcome ? ` · ${item.outcome.replace(/_/g, " ")}` : ""}</span><span>Environment: {item.environment ?? "unknown (historical record)"}</span>{item.execution && <span>{item.execution === "executed" ? "Executed evidence" : item.execution === "reasoned" ? "Reasoned evidence" : "Execution unavailable"}</span>}<span>{item.proved}</span>{item.command && <code>{item.command}</code>}<span>Observed: {item.observed}</span>{item.revision && <span>Recorded revision: {item.revision}</span>}{selected.evidence_carries?.filter((carry) => carry.evidence_id === item.id && carry.to_revision === selected.worktree_revision).map((carry) => <span className="remediation-ok" key={`${carry.evidence_id}:${carry.to_revision}`}>Evidence carried from {carry.from_revision} to {carry.to_revision}: same tree.</span>)}{item.runtime_revision && <span>Confirmed runtime revision: {item.runtime_revision}</span>}{item.artifact_path && <a href={url} target="_blank" rel="noreferrer">Open evidence ↗</a>}{item.scratch_proof_json && <details className="remediation-record"><summary>Regression execution proof</summary><CodeBlock text={item.scratch_proof_json} /></details>}<EvidencePreview key={selected.review_digest} engagementKey={engagementKey} caseId={selected.id} item={item} /></figcaption>
                      </figure>;
                    })}
                  </div>
                )}
              </section>}

              {activePane === "evidence" && <>
                {pageError && <p role="alert">{pageError}</p>}
                {selected.evidence.length < (selected.evidence_total ?? 0) && <button type="button" disabled={pageBusy} onClick={() => loadMore("evidence")}>{pageBusy ? "Loading evidence…" : "Load more evidence"}</button>}
              </>}
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

              <section className="remediation-section" hidden={activePane !== "delivery"}>
                <div className="remediation-section-heading"><h3>Pull request</h3><span>{selected.pull_request ? selected.pull_request.current ? "Matches current review" : "Earlier publication" : "Not recorded"}</span></div>
                {selected.pull_request ? <>
                  <p>{selected.pull_request.branch} → {selected.pull_request.base_branch} · revision {selected.pull_request.revision}</p>
                  {safeHttpUrl(selected.pull_request.url) ? <a href={safeHttpUrl(selected.pull_request.url)} target="_blank" rel="noreferrer">Open recorded PR ↗</a> : <p>{selected.pull_request.url}</p>}
                  {!selected.pull_request.current && <p className="remediation-caution">The recorded publication does not match the current reviewed snapshot.</p>}
                  <div className="remediation-requirement-result"><button type="button" onClick={() => viewEvidence(selected.pull_request!.evidence_id)}>View publication evidence #{selected.pull_request.evidence_id}</button></div>
                </> : <p>No verified PR publication receipt recorded.</p>}
              </section>
              <section className="remediation-section" hidden={activePane !== "delivery"}>
                <div className="remediation-section-heading"><h3>Shared environments</h3></div>
                {selected.environment_leases?.length ? <ul className="remediation-human-history">{selected.environment_leases.map((lease) => <li key={lease.token}><strong>{lease.environment} · {lease.released_at ? "Released" : "Held"}</strong> · {lease.actor}<p>Expected revision: {lease.revision} · observed: {lease.observed_revision || "Unconfirmed"}</p><p>Acquired {lease.acquired_at}{lease.released_at ? ` · released ${lease.released_at} by ${lease.released_by}` : ""}</p></li>)}</ul> : <p>No shared environment leases recorded.</p>}
              </section>
              {deployment && <section className="remediation-section" hidden={activePane !== "delivery"}><div className="remediation-section-heading"><h3>Development deployment</h3></div><p className="remediation-deployment-link">Workflow: {deployment.workflow} · run {deployment.run_id} · expected {deployment.expected_revision}</p></section>}

              <section className="remediation-section remediation-review" hidden={activePane !== "delivery"}>
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

              <section className="remediation-section" hidden={activePane !== "review"}>
                <div className="remediation-section-heading"><h3>Automated checks</h3><span>{selected.checks?.length || 0} configured</span></div>
                {selected.checks?.length ? <ul className="remediation-check-list">{selected.checks.map((check) => <li key={check.name}><div><strong>{check.name}</strong><code>{check.command}</code></div><div className="remediation-requirement-result"><strong className={check.missing ? "remediation-caution" : "remediation-ok"}>{check.missing || "Passed"}</strong>{check.evidence_ids.map((id) => <button type="button" key={id} onClick={() => viewEvidence(id)}>View check evidence #{id}</button>)}</div></li>)}</ul> : <p>No project check commands configured. Review the case’s verification requirements below.</p>}
              </section>
              <section className="remediation-section remediation-review" hidden={activePane !== "review"}>
                <div className="remediation-section-heading"><h3>Review approval</h3><span>{selected.approval_current ? "Current" : "Needs approval"}</span></div>
                {selected.approvals.length > 0 && <p className="remediation-help">Latest approval: {textValue(selected.approvals.at(-1)?.reviewer)} · revision {textValue(selected.approvals.at(-1)?.approved_revision)} · {textValue(selected.approvals.at(-1)?.created_at)}</p>}
                {selected.verification_requirements && <div className="remediation-verification-requirements">
                  <h4>Verification requirements</h4>
                  <p>{selected.verification_requirements.alternatives_reason}</p>
                  <ul>{selected.verification_requirements.requirements.map((requirement, index) => <li key={index}>{requirement.kind} · {requirement.methods.join(", ")} · {requirement.execution} · {requirement.revision} revision{requirement.fix_paths?.length ? ` · reverted fix paths: ${requirement.fix_paths.join(", ")}` : ""}{requirement.browser_purpose ? ` · ${requirement.browser_purpose}` : ""}{requirement.legitimate_use_control ? " · legitimate-use control" : ""}{requirement.rationale ? ` · ${requirement.rationale}` : ""}{(() => {
                    const match = selected.verification_matches?.find((item) => item.requirement_index === index);
                    return match ? <div className="remediation-requirement-result"><strong className={match.missing ? "remediation-caution" : "remediation-ok"}>{match.missing || "Satisfied"}</strong>{match.evidence_ids.map((id) => <button type="button" key={id} onClick={() => viewEvidence(id)}>View evidence #{id}</button>)}</div> : null;
                  })()}</li>)}</ul>
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
                <div className="remediation-section-heading"><h3>Case history</h3><span>{selected.history_total ?? selected.transitions.length} events</span></div>
                {selected.transitions.length ? <ol>{selected.transitions.map((item, index) => <li key={textValue(item.id) || index}>{textValue(item.from_status)} → {textValue(item.to_status)} · {textValue(item.actor)} · {textValue(item.reason)}</li>)}</ol> : <p>No case transitions recorded.</p>}
                {pageError && <p role="alert">{pageError}</p>}
                {selected.transitions.length < (selected.history_total ?? 0) && <button type="button" disabled={pageBusy} onClick={() => loadMore("history")}>{pageBusy ? "Loading history…" : "Load more history"}</button>}
                {selected.approvals.length > 0 && <><h3>Review approvals</h3><p>{selected.approval_current ? "Latest approval matches this snapshot." : "Earlier approval is stale after a change."}</p><ul>{selected.approvals.map((item, index) => <li key={textValue(item.id) || index}>Approved by {textValue(item.reviewer)} · revision {textValue(item.approved_revision)}</li>)}</ul></>}
                <details className="remediation-record" onToggle={(event) => setRawCaseOpen(event.currentTarget.open)}><summary>Raw case record</summary>{rawCaseOpen && <JsonView value={selected} />}</details>
                {Object.keys(drafts).length > 0 && <details className="remediation-record"><summary>Local unsaved drafts</summary><JsonView value={drafts} /></details>}
                {invalidDraftRecord !== null && <details className="remediation-record"><summary>Unreadable local draft record</summary><CodeBlock text={invalidDraftRecord} /></details>}
              </section>}
            </fieldset>
          )}
        </main>
      </div>
    </div>
  );
}
