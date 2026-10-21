// ── ProofWorkCard ─────────────────────────────────────────────────────
// One parked finding's proof work: why it is parked, the verifier's plan,
// each prepared test with its single next action, and the runs that
// recorded evidence for it. Reusable: the Proof work tab renders one per
// finding, and the Findings drawer can embed the same card
// (see `proofCardForFinding`).
//
// Every mutation is the existing proof-work endpoint, called through
// `onAction` so the owner refreshes afterwards; reads (audit history) go
// straight to the API and never refresh the queue. Approval always asks for
// an explicit confirmation that names the exact hosts and objective.

import { useEffect, useId, useRef, useState } from "react";

import "../styles/proof-work.css";
import {
  approveProofWork,
  getProofWork,
  prepareProofWork,
  reconcileProofWork,
  releaseProofWork,
  type ProofNextTest,
  type ProofOwedEntry,
  type ProofWork,
  type ProofWorkEvent,
  type ProofWorkQueueState,
} from "../lib/api";
import {
  approvalText,
  defaultProofRoute,
  nextFindingAction,
  nextWorkAction,
  type ProofAction,
  type ProofRoute,
} from "../lib/proofWorkApi";
import { engagementHref } from "../lib/workspaceRoutes";
import { TimeStamp } from "./formatting";
import { SeverityTag, StatusPill, humanizeStatus } from "./ui";

const ROUTE_LABELS: Record<ProofRoute, string> = {
  code: "Local code reproduction in Kali",
  web: "Live application test",
};

const ROUTE_HINT_LABELS: Record<ProofNextTest["route_hint"], string> = {
  local: "Local reproduction",
  live: "Live target",
  unknown: "Unknown",
};

export type ProofWorkCardProps = {
  engagementKey: string;
  slug: string;
  title: string;
  severity?: string;
  // The finding's current park, when it still owes runtime proof.
  owed: ProofOwedEntry | null;
  // Every work item prepared for this finding (current and earlier parks).
  items: ProofWork[];
  busy: boolean;
  // Blocks writes while the queue state is unknown (for example after a failed read).
  writesDisabled?: boolean;
  // Runs one mutation, then refreshes; resolves true when the write succeeded.
  onAction: (operation: () => Promise<unknown>) => Promise<boolean>;
  // The last failed write on this card, shown at the card's foot beside its
  // actions (the queue was re-read after it, so actions stay available).
  actionError?: string | null;
  onDismissActionError?: () => void;
  highlightWorkId?: number;
  // The Findings drawer already names the finding; it can hide the link.
  showFindingLink?: boolean;
  // Inside a finding's record the card can drop its own title, slug and
  // severity (the record header already shows them) and keep only the state.
  showFindingHeader?: boolean;
};

export function QueueStatePill({ state }: { state: ProofWorkQueueState | undefined }) {
  if (!state) return null;
  return <StatusPill domain="proof-work" value={state} />;
}

// Verifier-authored text renders as plain React text nodes only (ADR 0018).
export function NextTestPlan({ nextTest }: { nextTest: ProofNextTest | null | undefined }) {
  if (!nextTest) {
    return (
      <p className="proof-plan-missing">
        No plan recorded. Ask the verifier to record the next test (hypothesis, what confirms it, what falsifies it).
      </p>
    );
  }
  return (
    <dl className="proof-plan">
      <div><dt>Hypothesis</dt><dd>{nextTest.hypothesis}</dd></div>
      <div><dt>Confirms if</dt><dd>{nextTest.confirm_if}</dd></div>
      <div><dt>Falsifies if</dt><dd>{nextTest.falsify_if}</dd></div>
      <div><dt>Route hint</dt><dd>{ROUTE_HINT_LABELS[nextTest.route_hint] ?? nextTest.route_hint}</dd></div>
      {nextTest.prerequisites && <div><dt>Prerequisites</dt><dd>{nextTest.prerequisites}</dd></div>}
    </dl>
  );
}

function PrepareForm({
  engagementKey,
  owed,
  busy,
  writesDisabled,
  onAction,
  onDone,
}: {
  engagementKey: string;
  owed: ProofOwedEntry;
  busy: boolean;
  writesDisabled: boolean;
  onAction: ProofWorkCardProps["onAction"];
  onDone: () => void;
}) {
  const formId = useId();
  const defaultRoute = defaultProofRoute(owed);
  const [route, setRoute] = useState<ProofRoute>(defaultRoute);
  const [objective, setObjective] = useState("");
  const [hosts, setHosts] = useState("");
  const suggestions = owed.suggested_hosts ?? [];
  const chosenHosts = hosts.split(/[\s,]+/).filter(Boolean);
  // A suggestion chip toggles: a second click takes the host back out.
  const toggleHost = (host: string) => {
    setHosts((chosenHosts.includes(host) ? chosenHosts.filter((value) => value !== host) : [...chosenHosts, host]).join(", "));
  };
  const hintRoute = owed.next_test?.route_hint && owed.next_test.route_hint !== "unknown" ? owed.next_test.route_hint : null;
  return (
    <form
      className="proof-prepare"
      aria-label={`Prepare a test for ${owed.finding_slug}`}
      onSubmit={(event) => {
        event.preventDefault();
        void onAction(() => prepareProofWork(engagementKey, {
          finding_slug: owed.finding_slug,
          route,
          objective: objective.trim(),
          target_hosts: route === "web" ? chosenHosts : [],
        })).then((ok) => { if (ok) onDone(); });
      }}
    >
      <div className="proof-field">
        <label htmlFor={`${formId}-route`}>Proof route</label>
        <select id={`${formId}-route`} value={route} onChange={(event) => setRoute(event.target.value as ProofRoute)}>
          <option value="code">{ROUTE_LABELS.code}</option>
          <option value="web">{ROUTE_LABELS.web}</option>
        </select>
        <small>
          {route !== defaultRoute
            ? `You chose this route; the suggested route was “${ROUTE_LABELS[defaultRoute]}”.`
            : hintRoute
              ? `Defaulted from the verifier's route hint (${ROUTE_HINT_LABELS[hintRoute]}).`
              : `Defaulted from the finding's ${route === "code" ? "source location" : "live location"}.`}
          {" "}The route grants no scope or approval.
        </small>
      </div>
      <div className="proof-field">
        <label htmlFor={`${formId}-objective`}>Proof objective</label>
        <textarea
          id={`${formId}-objective`}
          value={objective}
          onChange={(event) => setObjective(event.target.value)}
          required
          maxLength={4096}
          placeholder="What single observation would confirm, disprove, or narrow this claim?"
        />
      </div>
      {route === "web" && (
        <div className="proof-field">
          <label htmlFor={`${formId}-host-input`}>Admitted target hosts</label>
          <input
            id={`${formId}-host-input`}
            value={hosts}
            onChange={(event) => setHosts(event.target.value)}
            required
            list={`${formId}-hosts`}
            placeholder="app.example.com"
          />
          <datalist id={`${formId}-hosts`}>
            {suggestions.map((host) => <option key={host} value={host} />)}
          </datalist>
          {suggestions.length > 0 && (
            <span className="proof-host-suggestions">
              <small>In scope:</small>
              {suggestions.slice(0, 6).map((host) => (
                <button key={host} type="button" className="ui-chip" aria-pressed={chosenHosts.includes(host)} onClick={() => toggleHost(host)}>
                  <span className="ui-chip-label">{host}</span>
                </button>
              ))}
            </span>
          )}
          <small>Only these hosts are bound to the test; preparation re-checks each against scope.</small>
        </div>
      )}
      <div className="proof-form-actions">
        <button
          type="submit"
          className="qa-btn primary"
          disabled={busy || writesDisabled || !objective.trim() || (route === "web" && chosenHosts.length === 0)}
        >
          Prepare proof
        </button>
        <button type="button" className="qa-btn" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

function ApproveControl({
  engagementKey,
  work,
  busy,
  writesDisabled,
  onAction,
}: {
  engagementKey: string;
  work: ProofWork;
  busy: boolean;
  writesDisabled: boolean;
  onAction: ProofWorkCardProps["onAction"];
}) {
  const [confirming, setConfirming] = useState(false);
  const blocked = busy || writesDisabled || !work.current || !work.owed;
  if (!confirming) {
    return (
      <button
        type="button"
        className="qa-btn primary"
        aria-label={`Approve live proof ${work.id}`}
        disabled={blocked}
        onClick={() => setConfirming(true)}
      >
        Approve this live proof…
      </button>
    );
  }
  return (
    <div className="proof-confirm" role="group" aria-label={`Confirm approval for proof ${work.id}`}>
      <p>
        Approving lets the verifier that claims proof #{work.id} for {work.finding_slug} send live requests
        to <strong>{work.target_hosts.join(", ") || "no hosts"}</strong> for this objective only:
      </p>
      <blockquote>{work.objective}</blockquote>
      <p>Changing the finding, plan, or hosts later requires a fresh approval.</p>
      <div className="proof-form-actions">
        <button
          type="button"
          className="qa-btn primary"
          disabled={blocked}
          onClick={() => void onAction(() => approveProofWork(engagementKey, work.id, true)).then((ok) => { if (ok) setConfirming(false); })}
        >
          Confirm approval
        </button>
        <button type="button" className="qa-btn" onClick={() => setConfirming(false)}>Cancel</button>
      </div>
    </div>
  );
}

// Long verifier prose shows three lines first; the full text is one click away.
function ClampedText({ text }: { text: string }) {
  const [expanded, setExpanded] = useState(false);
  const long = text.length > 280 || text.split("\n").length > 3;
  return (
    <div className="proof-reason">
      <p className={long && !expanded ? "is-clamped" : undefined}>{text}</p>
      {long && (
        <button type="button" className="proof-link-button" aria-expanded={expanded} onClick={() => setExpanded((open) => !open)}>
          {expanded ? "Show less" : "Show full reason"}
        </button>
      )}
    </div>
  );
}

const ACTION_HINTS: Partial<Record<ProofAction, string>> = {
  reconcile: "Re-check the recorded state against the current finding, plan, source, and scope.",
  release: "The owning worker ended. Release ownership only after confirming no execution remains.",
  revoke: "Live work is authorized. Revoke to stop further live requests for this test.",
};

function WorkItem({
  engagementKey,
  work,
  busy,
  writesDisabled,
  onAction,
  highlighted,
}: {
  engagementKey: string;
  work: ProofWork;
  busy: boolean;
  writesDisabled: boolean;
  onAction: ProofWorkCardProps["onAction"];
  highlighted: boolean;
}) {
  const [revokeReason, setRevokeReason] = useState("");
  const [recoveryReason, setRecoveryReason] = useState("");
  const [history, setHistory] = useState<ProofWorkEvent[] | null>(null);
  const [historyState, setHistoryState] = useState<"idle" | "loading" | "error">("idle");
  const [historyError, setHistoryError] = useState("");
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  // A read: no busy flag, no queue refresh, and it works while writes are blocked.
  const loadHistory = async () => {
    setHistoryState("loading");
    try {
      const detail = await getProofWork(engagementKey, work.id);
      if (!mounted.current) return;
      setHistory(detail.events);
      setHistoryState("idle");
    } catch (failure) {
      if (!mounted.current) return;
      setHistoryError(failure instanceof Error ? failure.message : String(failure));
      setHistoryState("error");
    }
  };
  const action = nextWorkAction(work);
  const ownerEnded = Boolean(work.owner_agent_id)
    && ["completed", "failed", "aborted", "blocked"].includes(work.owner_dispatch_status ?? "");
  const runs = work.runs ?? work.run_ids.map((id) => ({ id, run_uuid: `Run ${id}`, run_kind: "", status: "", started_at: null, finished_at: null, proof_receipts: 0 }));

  const revoke = work.route === "web" && (
    <div className="proof-inline-field">
      <label>
        Revocation reason
        <textarea
          aria-label={`Revocation reason for proof ${work.id}`}
          maxLength={8192}
          value={revokeReason}
          onChange={(event) => setRevokeReason(event.target.value)}
        />
      </label>
      <button
        type="button"
        className={`qa-btn ${action === "revoke" ? "primary" : ""}`}
        aria-label={`Revoke live proof ${work.id}`}
        disabled={busy || writesDisabled || !revokeReason.trim()}
        onClick={() => void onAction(() => approveProofWork(engagementKey, work.id, false, revokeReason))}
      >
        Revoke work approval
      </button>
    </div>
  );
  const release = ownerEnded && (
    <div className="proof-inline-field">
      <p className="proof-help">
        Release ownership only after the worker has ended. The backend also checks for active runs, commands, and
        supervised jobs; releasing does not launch another worker.
      </p>
      <label>
        Recovery reason
        <input
          aria-label={`Recovery reason for proof ${work.id}`}
          value={recoveryReason}
          onChange={(event) => setRecoveryReason(event.target.value)}
        />
      </label>
      <button
        type="button"
        className={`qa-btn ${action === "release" ? "primary" : ""}`}
        aria-label={`Release proof ${work.id}`}
        disabled={busy || writesDisabled || !recoveryReason.trim()}
        onClick={() => void onAction(() => releaseProofWork(engagementKey, work.id, recoveryReason.trim()))}
      >
        Release ended ownership
      </button>
    </div>
  );
  const reconcile = (
    <button
      type="button"
      className={`qa-btn ${action === "reconcile" ? "primary" : ""}`}
      aria-label={`Reconcile proof ${work.id}`}
      disabled={busy || writesDisabled}
      onClick={() => void onAction(() => reconcileProofWork(engagementKey, work.id))}
    >
      Reconcile recorded state
    </button>
  );

  return (
    <article id={`proof-work-${work.id}`} className={`proof-item ${highlighted ? "is-highlighted" : ""}`}>
      <header>
        <strong>Proof #{work.id}</strong>
        <QueueStatePill state={work.queue_state} />
        <span className="proof-route">{ROUTE_LABELS[work.route]}</span>
        <span className="proof-muted">Prepared <TimeStamp value={work.created_at} fallback="—" /></span>
      </header>
      <p className="proof-item-objective">{work.objective}</p>
      <dl className="proof-facts">
        <div><dt>Status</dt><dd><StatusPill domain="proof-work-status" value={work.status} size="sm" /></dd></div>
        <div><dt>Owner</dt><dd>{work.owner_agent_id || "Unclaimed"}{work.owner_dispatch_status ? ` (${work.owner_dispatch_status})` : ""}</dd></div>
        <div><dt>Approval</dt><dd>{approvalText(work)}</dd></div>
        {work.target_hosts.length > 0 && <div><dt>Targets</dt><dd>{work.target_hosts.join(", ")}</dd></div>}
      </dl>
      {!work.current && <p className="proof-warning" role="status">Stale context — prepare against current evidence</p>}
      {work.blocker && <p className="proof-warning">{work.blocker}</p>}
      {work.queue_state === "ready" && (
        <p className="proof-help">
          Ready for a verifier. The operator dispatches one from the conversation; it claims this test with
          {" "}<code>vigil assess proof-work claim {work.id}</code>.
        </p>
      )}

      <div className="proof-runs">
        <h5>Evidence runs</h5>
        {runs.length === 0 ? (
          <p className="proof-muted">No runs recorded for this test yet.</p>
        ) : (
          <ul>
            {runs.map((run) => (
              <li key={run.id}>
                <a href={engagementHref(engagementKey, { tab: "runs", run: run.id })} aria-label={`Run ${run.id}`}>
                  {run.run_uuid}
                </a>
                {run.status && <StatusPill domain="run" value={run.status} size="sm" />}
                {run.started_at && <TimeStamp value={run.started_at} className="proof-muted" />}
                <span className="proof-muted">{run.proof_receipts} receipt{run.proof_receipts === 1 ? "" : "s"}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="proof-next-actions">
        {action === "approve" && (
          <ApproveControl engagementKey={engagementKey} work={work} busy={busy} writesDisabled={writesDisabled} onAction={onAction} />
        )}
        {action !== "approve" && action !== "none" && ACTION_HINTS[action] && <p className="proof-help">{ACTION_HINTS[action]}</p>}
        {action === "reconcile" && reconcile}
        {action === "release" && release}
        {action === "revoke" && revoke}
      </div>

      <details className="proof-more">
        <summary>More actions and history</summary>
        <div className="proof-more-body">
          {action !== "approve" && work.route === "web" && work.approval_required && (
            <ApproveControl engagementKey={engagementKey} work={work} busy={busy} writesDisabled={writesDisabled} onAction={onAction} />
          )}
          {action !== "revoke" && revoke}
          {action !== "reconcile" && reconcile}
          {action !== "release" && release}
          <button
            type="button"
            className="qa-btn"
            aria-label={`Show audit history for proof ${work.id}`}
            disabled={historyState === "loading"}
            onClick={() => void loadHistory()}
          >
            {historyState === "loading" ? "Loading audit history…" : history ? "Reload audit history" : "Show audit history"}
          </button>
          {historyState === "error" && <p className="error-text" role="alert">Audit history could not be read: {historyError}</p>}
          {history && history.length === 0 && (
            <p className="proof-muted">No audit events recorded for this proof work yet.</p>
          )}
          {history && history.length > 0 && (
            <ol className="proof-history" aria-label={`Audit history for proof ${work.id}`}>
              {history.map((event) => (
                <li key={event.id}>
                  <span><TimeStamp value={event.created_at} mode="both" fallback="Time not recorded" /> · {humanizeStatus(event.action)}</span>
                  <pre>{event.details_json}</pre>
                </li>
              ))}
            </ol>
          )}
        </div>
      </details>
    </article>
  );
}

export function ProofWorkCard({
  engagementKey,
  slug,
  title,
  severity,
  owed,
  items,
  busy,
  writesDisabled = false,
  onAction,
  highlightWorkId,
  showFindingLink = true,
  showFindingHeader = true,
  actionError = null,
  onDismissActionError,
}: ProofWorkCardProps) {
  const [preparing, setPreparing] = useState(false);
  const errorRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (actionError) errorRef.current?.scrollIntoView?.({ block: "nearest" });
  }, [actionError]);
  const headingId = useId();
  const currentIds = new Set(owed?.work_ids ?? []);
  const current = items.filter((work) => currentIds.has(work.id));
  const earlier = items.filter((work) => !currentIds.has(work.id));
  const findingAction = owed ? nextFindingAction(owed, current) : "none";
  const state = owed?.queue_state ?? (items.length ? items[items.length - 1].queue_state : undefined);
  const findingHref = engagementHref(engagementKey, { tab: "findings", finding: slug });

  return (
    <section className={`proof-card sev-${severity ?? "unknown"}`} aria-labelledby={headingId}>
      <header className="proof-card-head">
        {showFindingHeader ? (
          <div className="proof-card-title">
            <p className="proof-eyebrow">
              {severity && <SeverityTag severity={severity} size="sm" />}
              <span className="proof-slug">{slug}</span>
            </p>
            <h3 id={headingId}>
              {showFindingLink ? <a href={findingHref}>{title}</a> : title}
            </h3>
          </div>
        ) : <h3 id={headingId} className="proof-card-compact-title">Runtime proof</h3>}
        <QueueStatePill state={state} />
      </header>

      {owed && (
        <div className="proof-why">
          <h4>Why it is parked</h4>
          {owed.parked_reason
            ? <ClampedText text={owed.parked_reason} />
            : <p className="proof-muted">The parking decision recorded no reason.</p>}
          {owed.parked_at && <p className="proof-muted">Parked <TimeStamp value={owed.parked_at} mode="both" /></p>}
        </div>
      )}

      {owed && (
        <div className="proof-next">
          <h4>Next test</h4>
          <NextTestPlan nextTest={owed.next_test} />
        </div>
      )}

      {owed && findingAction === "prepare" && (
        preparing ? (
          <PrepareForm
            engagementKey={engagementKey}
            owed={owed}
            busy={busy}
            writesDisabled={writesDisabled}
            onAction={onAction}
            onDone={() => setPreparing(false)}
          />
        ) : (
          <div className="proof-next-actions">
            <button type="button" className="qa-btn primary" onClick={() => setPreparing(true)} disabled={writesDisabled || busy}>
              Prepare a test…
            </button>
            <p className="proof-help">
              {current.length ? "Earlier preparations no longer match this finding; prepare one against current evidence." : "Choose a route and the single observation that would settle the claim."}
            </p>
          </div>
        )
      )}

      {current.map((work) => (
        <WorkItem
          key={work.id}
          engagementKey={engagementKey}
          work={work}
          busy={busy}
          writesDisabled={writesDisabled}
          onAction={onAction}
          highlighted={work.id === highlightWorkId}
        />
      ))}

      {earlier.length > 0 && (
        <details className="proof-earlier" open={earlier.some((work) => work.id === highlightWorkId) || !owed}>
          <summary>{owed ? `Earlier preparations (${earlier.length})` : `Proof work (${earlier.length})`}</summary>
          {earlier.map((work) => (
            <WorkItem
              key={work.id}
              engagementKey={engagementKey}
              work={work}
              busy={busy}
              writesDisabled={writesDisabled}
              onAction={onAction}
              highlighted={work.id === highlightWorkId}
            />
          ))}
        </details>
      )}

      {actionError && (
        <div ref={errorRef} className="proof-banner" role="alert">
          <p>{actionError} · The queue was re-read; check the current state before trying again.</p>
          {onDismissActionError && <button type="button" className="ui-button" onClick={onDismissActionError}>Dismiss</button>}
        </div>
      )}
    </section>
  );
}
