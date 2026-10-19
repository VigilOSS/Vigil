"""vigil assess transition-phase — guarded scope.json phase transition.

Validates preconditions before writing the new phase to scope.json.
Exits non-zero and prints blockers when preconditions fail.
Pass --force to override ordinary intermediate-phase blockers. Code completion
never overrides unresolved durable debt; source-identity integrity blockers
remain hard on every edge.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import re
import sys

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import Config, load_config
from assess.lib.phases import (
    BLUE_TRANSITION_PHASES as BLUE_PHASES,
    CODE_TRANSITION_PHASES as CODE_PHASES,
    WEB_TRANSITION_PHASES as WEB_PHASES,
)
from assess.lib.scope import mutate_scope
from assess.lib.tracks import track_phases

# The three ordered rosters (terminal `complete` included) come from
# `assess.lib.phases`, the single source of truth for phase vocabulary.

WEB_TRANSITION_ORDER = {phase: i for i, phase in enumerate(WEB_PHASES)}
CODE_TRANSITION_ORDER = {phase: i for i, phase in enumerate(CODE_PHASES)}
BLUE_TRANSITION_ORDER = {phase: i for i, phase in enumerate(BLUE_PHASES)}

# Canonical finding slugs look like ``FIND-001``, ``VA-003``, ``EX-032``: an
# all-caps prefix followed by digits/hyphens/underscores. The fallback
# extractor in ``_blue_check_respond_to_report`` uses this to lift slugs out of
# free-form ``no_containment_required`` activity rows when the operator did
# not pass ``metadata.finding_slug`` — but only matches that also appear in
# the engagement findings list are accepted, so unrelated all-caps tokens
# (``EOF``, ``VPN``, ``NL``) don't accidentally close findings.
_CANONICAL_SLUG_RE = re.compile(r"\b([A-Z][A-Z0-9_-]{2,})\b")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "transition-phase",
        help="Guarded phase transition for scope.json",
    )
    p.add_argument("target_phase", help="Phase to transition to")
    p.add_argument(
        "--force",
        action="store_true",
        help=(
            "Override ordinary blockers. Integrity blockers remain non-overrideable "
            "on every edge, and `--track code` + `complete` cannot be forced at all: "
            "a completed code scan asserts zero durable debt."
        ),
    )
    p.add_argument(
        "--reason",
        default="",
        help=(
            "Stated reason for a deliberate backward transition (regression) or "
            "for overriding blockers. A backward transition is allowed with "
            "--reason WITHOUT --force, and the reason is recorded as a durable "
            "decision row. With --force, the reason is attached to the override "
            "decision so the deferral/override rate stays auditable."
        ),
    )
    p.add_argument(
        "--track",
        choices=("auto", "web", "code", "blue"),
        default="auto",
        help="Enabled phase track (default: infer from target phase when unambiguous).",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir

    scope_path = os.path.join(engagement_dir, "scope.json")
    if not os.path.isfile(scope_path):
        print(f"transition-phase: {scope_path} not found", file=sys.stderr)
        sys.exit(2)

    with open(scope_path) as f:
        scope = json.load(f)

    target_phase = args.target_phase
    engagement_type = scope.get("engagement_type", "web")
    track = _phase_track(scope, target_phase, getattr(args, "track", "auto"))

    if engagement_type == "both" and track == "code":
        raw_code_phase = scope.get("code_phase")
        if not isinstance(raw_code_phase, str) or not raw_code_phase.strip():
            print(
                "transition-phase: both-track engagement is missing `code_phase`; "
                "refusing to assume ingest. Run `vigil engagement repair-tracks "
                f"{cfg.engagement_key}` to record the legacy-state repair first.",
                file=sys.stderr,
            )
            sys.exit(2)

    if track == "code":
        order = CODE_TRANSITION_ORDER
        phases = CODE_PHASES
    elif track == "blue":
        order = BLUE_TRANSITION_ORDER
        phases = BLUE_PHASES
    else:
        order = WEB_TRANSITION_ORDER
        phases = WEB_PHASES
    phase_key = "code_phase" if engagement_type == "both" and track == "code" else "current_phase"
    current_phase = track_phases(scope).get(track, "")

    if target_phase not in order:
        print(
            f"transition-phase: unknown phase '{target_phase}' "
            f"for engagement type '{engagement_type}' track '{track}'. "
            f"Valid phases: {', '.join(phases)}",
            file=sys.stderr,
        )
        sys.exit(2)

    reason = (getattr(args, "reason", "") or "").strip()
    is_backward = bool(
        current_phase and current_phase in order
        and order[target_phase] < order[current_phase]
    )
    if is_backward:
        if not args.force and not reason:
            print(
                f"transition-phase: refusing backward transition "
                f"'{current_phase}' -> '{target_phase}'. Pass --reason \"<why>\" "
                "for a deliberate regression, or --force.",
                file=sys.stderr,
            )
            sys.exit(1)
        _record_transition_decision(
            cfg,
            kind="phase_regression",
            current_phase=current_phase,
            target_phase=target_phase,
            track=track,
            reason=reason or "(no reason given; --force)",
            blockers=[],
        )
        print(
            f"transition-phase: deliberate backward transition "
            f"'{current_phase}' -> '{target_phase}' recorded "
            f"({'reason: ' + reason if reason else 'via --force'}).",
            file=sys.stderr,
        )

    blockers: list[dict[str, str]] = []
    for phase_to_check in _precondition_targets_for_transition(
        current_phase=current_phase,
        target_phase=target_phase,
        track=track,
        order=order,
    ):
        blockers.extend(
            _check_preconditions(
                phase_to_check, track, engagement_dir, args, cfg,
            )
        )

    hard = [b for b in blockers if b.get("severity", "block") != "advisory"]
    advisory = [b for b in blockers if b.get("severity", "block") == "advisory"]
    nonoverrideable = [b for b in hard if b.get("overrideable") is False]

    if advisory:
        print(
            f"transition-phase: {len(advisory)} advisory note(s) for "
            f"'{target_phase}' (steering, not blocking):",
            file=sys.stderr,
        )
        for b in advisory:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)

    if nonoverrideable:
        print(
            f"transition-phase: {len(nonoverrideable)} integrity blocker(s) for "
            f"'{target_phase}' cannot be overridden:",
            file=sys.stderr,
        )
        for b in nonoverrideable:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)
        sys.exit(1)

    if hard and track == "code" and target_phase == "complete":
        # The one edge --force cannot open. A completed code scan asserts zero
        # durable debt in its terminal seal, so an override here would make the
        # seal claim coverage that was never achieved. Ordinary intermediate-phase
        # blockers stay overrideable; this edge does not.
        print(
            "transition-phase: code cannot be forced to complete while durable "
            f"debt remains ({len(hard)} blocker(s)):",
            file=sys.stderr,
        )
        for blocker in hard:
            print(
                f"  - [{blocker['kind']}] {blocker['detail']}",
                file=sys.stderr,
            )
        print(
            "transition-phase: --force does not apply to this edge. Resolve each "
            "blocker above and re-run; `vigil assess code-coverage "
            "--require-transition-ready complete` re-checks the same backend "
            "contract and names what is still outstanding. If the remaining work "
            "is genuinely out of scope, leave the engagement in its current phase "
            "— `complete` is not the state for a scan with open debt.",
            file=sys.stderr,
        )
        sys.exit(1)

    if hard and not args.force:
        print(f"transition-phase: {len(hard)} blocker(s) for '{target_phase}':", file=sys.stderr)
        for b in hard:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)
        sys.exit(1)

    if hard and args.force:
        _record_transition_decision(
            cfg,
            kind="forced_transition_override",
            current_phase=current_phase,
            target_phase=target_phase,
            track=track,
            reason=reason or "(no reason given; --force)",
            blockers=hard,
        )
        print(f"transition-phase: overriding {len(hard)} blocker(s) with --force:", file=sys.stderr)
        for b in hard:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)

    def update(latest_scope):
        prior_phase = track_phases(latest_scope).get(track)
        if isinstance(latest_scope.get("tracks"), dict):
            latest_scope["tracks"][track]["phase"] = target_phase
            latest_scope["status"] = (
                "completed"
                if all(phase == "complete" for phase in track_phases(latest_scope).values())
                else "in_progress"
            )
        elif engagement_type == "both":
            latest_scope[phase_key] = target_phase
            latest_scope["status"] = (
                "completed"
                if latest_scope.get("current_phase") == "complete"
                and latest_scope.get("code_phase") == "complete"
                else "in_progress"
            )
        else:
            latest_scope[phase_key] = target_phase
            latest_scope["status"] = (
                "completed" if target_phase == "complete" else "in_progress"
            )

        if prior_phase != target_phase:
            latest_scope["phase_changed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    mutate_scope(engagement_dir, update)

    print(f"Phase transitioned ({track}): {current_phase or '(none)'} -> {target_phase}")


def _precondition_targets_for_transition(
    *,
    current_phase: str,
    target_phase: str,
    track: str,
    order: dict[str, int],
) -> list[str]:
    """Return every phase gate that must pass for this transition.

    A direct FORWARD jump that skips intermediate phases (e.g. web
    ``recon -> exploit`` or code ``ingest -> complete``) must still satisfy
    EVERY skipped phase's preconditions — otherwise a non-adjacent transition
    silently bypasses gates (S1/R-H4). This walk used to be blue-only; it now
    applies to ALL tracks, because the same bypass existed on web and code
    (incident work was simply the case where it had already been noticed).

    Backward or same-phase transitions check only the target phase; the
    backward move itself is gated separately (by --reason/--force in ``run``).
    """
    if not current_phase or current_phase not in order:
        return [target_phase]
    start = order[current_phase]
    end = order[target_phase]
    if end <= start:
        return [target_phase]
    ordered_phases = sorted(order, key=order.get)
    return ordered_phases[start + 1 : end + 1]


def _phase_track(scope: dict, target_phase: str, requested_track: str) -> str:
    enabled = track_phases(scope)
    if requested_track != "auto":
        if requested_track not in enabled:
            print(f"transition-phase: track '{requested_track}' is not enabled", file=sys.stderr)
            sys.exit(2)
        return requested_track
    if len(enabled) == 1:
        return next(iter(enabled))
    in_web = target_phase in WEB_TRANSITION_ORDER
    in_code = target_phase in CODE_TRANSITION_ORDER
    if "web" in enabled and "code" in enabled and in_web and in_code:
        print(
            f"transition-phase: phase '{target_phase}' is valid for both tracks; pass --track web or --track code",
            file=sys.stderr,
        )
        sys.exit(2)
    if "code" in enabled and in_code:
        return "code"
    if "web" in enabled and in_web:
        return "web"
    print(f"transition-phase: cannot infer enabled track for phase '{target_phase}'; pass --track", file=sys.stderr)
    sys.exit(2)


def _record_transition_decision(
    cfg: Config,
    *,
    kind: str,
    current_phase: str,
    target_phase: str,
    track: str,
    reason: str,
    blockers: list[dict[str, str]],
) -> None:
    """Record a durable decision row for a forced/backward transition (S3/L1-6).

    Best-effort: a telemetry failure must NEVER block the operator's
    transition. The row makes override/regression rates auditable via the
    existing ``GET /dispatch-decisions`` endpoint, feeding the deferral-rate
    visibility doctrine (the "option D" write-off becomes a recorded decision,
    not a silent one).
    """
    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            client.record_decision({
                "kind": kind,
                "payload": {
                    "track": track,
                    "from_phase": current_phase or "(none)",
                    "to_phase": target_phase,
                    "reason": reason,
                    "overridden_blockers": [
                        {"kind": b.get("kind", ""), "detail": b.get("detail", "")}
                        for b in blockers
                    ],
                },
                "surfaced_to_user": True,
            })
    except Exception as exc:  # noqa: BLE001
        print(
            f"WARN transition-phase: could not record {kind} decision "
            f"({type(exc).__name__}: {exc}); transition still proceeds.",
            file=sys.stderr,
        )


def _check_preconditions(
    target_phase: str,
    track: str,
    engagement_dir: str,
    args,
    cfg: Config | None = None,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    cfg = cfg or load_config(engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if track == "code":
            blockers.extend(_check_code_preconditions(target_phase, client))
        elif track == "blue":
            blockers.extend(_check_blue_preconditions(target_phase, client, engagement_dir))
        else:
            blockers.extend(_check_web_preconditions(target_phase, client))

    return blockers


def _precondition_check_failed(check_name: str, exc: Exception) -> dict[str, str]:
    message = str(exc) or exc.__class__.__name__
    return {
        "kind": "precondition_check_failed",
        "detail": f"{check_name} check failed: {message}",
    }


def _require_dict_rows(value: object) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError("backend returned a non-list response")
    if any(not isinstance(row, dict) for row in value):
        raise ValueError("backend returned a list containing a non-object row")
    return value


def _consumption_advisory(client: AssessmentClient) -> dict[str, str] | None:
    """Advisory (never a block) when the consume-test buffer still has genuinely
    un-consumed work at verify time (S2).

    Counts only ``pending`` rows with NO ``terminal_reason`` — i.e. items that
    were neither tested nor explicitly deferred/inert — to match the consume
    gate's honest semantics. Reads the backend work buffer; returns None when the
    buffer is essentially worked down. A backend fetch failure surfaces (the
    client raises) rather than silently reporting "worked down".
    """
    pending = sum(
        1
        for row in client.get_all_pages("work-items?status=pending")
        if isinstance(row, dict) and str(row.get("terminal_reason") or "") == ""
    )
    if pending <= 0:
        return None
    return {
        "kind": "consumption_incomplete",
        "severity": "advisory",
        "detail": (
            f"{pending} un-consumed work item(s) still pending in the work buffer — "
            "verify is being entered over an unfinished consume-test buffer. "
            "Not blocking; finish consumption (or defer those items with a "
            "reason) so verification reflects real testing."
        ),
    }


def _check_web_preconditions(
    target_phase: str,
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    if target_phase == "collect":
        try:
            services = client.get("services")
            if isinstance(services, list) and len(services) == 0:
                blockers.append({
                    "kind": "no_services",
                    "detail": "No live services discovered — recon may be incomplete",
                })
        except Exception as exc:
            blockers.append(_precondition_check_failed("collect services", exc))

    elif target_phase == "consume-test":
        try:
            count = len(client.get_all_pages("work-items?status=pending"))
            if count == 0:
                blockers.append({
                    "kind": "empty_work_buffer",
                    "detail": "No pending work items in the work buffer — nothing to consume",
                })
        except Exception as exc:
            blockers.append(_precondition_check_failed("consume-test work buffer", exc))

    elif target_phase == "verify":
        try:
            findings = _require_dict_rows(client.get("findings"))
            active = [f for f in findings if f.get("workflow_status") == "active"]
            if len(active) == 0:
                blockers.append({
                    "kind": "no_active_findings",
                    "detail": "No active findings to verify",
                })
        except Exception as exc:
            blockers.append(_precondition_check_failed("verify findings", exc))
        consumption = _consumption_advisory(client)
        if consumption is not None:
            blockers.append(consumption)

    elif target_phase == "exploit":
        try:
            findings = _require_dict_rows(client.get("findings"))
            unverified_high = [
                f for f in findings
                if f.get("severity") in ("critical", "high")
                and f.get("verification_status") not in {"confirmed", "downgraded"}
                and f.get("workflow_status") == "active"
            ]
            if unverified_high:
                slugs = [f.get("slug", "?") for f in unverified_high[:5]]
                blockers.append({
                    "kind": "unverified_high_findings",
                    "detail": (
                        f"{len(unverified_high)} high/critical finding(s) unverified: "
                        f"{', '.join(slugs)}"
                        + (" ..." if len(unverified_high) > 5 else "")
                    ),
                })

            # variant / rotation hunting before the engagement advances to exploit.
            # Skipping the variant pass is the single most common way real findings
            confirmed_high = [
                f for f in findings
                if f.get("severity") in ("critical", "high")
                and f.get("verification_status") in {"confirmed", "downgraded"}
                and f.get("workflow_status") == "active"
            ]
            if confirmed_high:
                # Filter by role server-side and request the max page size
                # so engagements with many dispatches don't drop older
                # variant-pass runs behind the default limit=100.
                try:
                    dispatches = _require_dict_rows(client.get(
                        "dispatches?role=vulnerability-analyst&limit=1000"
                    ))
                except Exception as exc:
                    blockers.append(
                        _precondition_check_failed("exploit variant dispatches", exc)
                    )
                    return blockers
                completed_variant_dispatches = [
                    d for d in dispatches
                    if str(d.get("status") or "").lower() == "completed"
                    and str(d.get("dispatch_mode") or "").lower() == "variant-rotation"
                ]
                missing_variant: list[str] = []
                for finding in confirmed_high:
                    slug = finding.get("slug", "?")
                    hit = any(
                        slug in (d.get("finding_slugs") or [])
                        for d in completed_variant_dispatches
                    )
                    if not hit:
                        missing_variant.append(slug)
                if missing_variant:
                    sample = ", ".join(missing_variant[:5])
                    blockers.append({
                        "kind": "missing_variant_pass",
                        "detail": (
                            f"{len(missing_variant)} confirmed high/critical finding(s) "
                            f"have no COMPLETED variant-rotation vulnerability-analyst "
                            f"dispatch listing them in finding_slugs: "
                            f"{sample}"
                            + (" ..." if len(missing_variant) > 5 else "")
                            + " — run the variant/sibling hunt as a "
                            "--dispatch-mode variant-rotation dispatch and let it "
                            "complete before advancing (skipping it is the most "
                            "common way real findings are missed). Pass --force "
                            "--reason \"...\" to override with an audited decision."
                        ),
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("exploit findings", exc))

    elif target_phase == "report":
        try:
            readiness = client.get("report-readiness")
            if isinstance(readiness, dict) and not readiness.get("ready", False):
                for b in readiness.get("blockers", []):
                    if isinstance(b, dict):
                        blockers.append({
                            "kind": b.get("kind", "report_readiness"),
                            "detail": b.get("detail", str(b)),
                        })
        except Exception as exc:
            blockers.append(_precondition_check_failed("report readiness", exc))
        blockers.extend(_blind_triage_blockers(client))
        blockers.extend(_chain_construction_blockers(client))
        blockers.extend(_depth_backstop_blockers(client))

    elif target_phase == "complete":
        try:
            readiness = client.get("report-readiness")
            if isinstance(readiness, dict) and not readiness.get("ready", False):
                blockers.append({
                    "kind": "report_not_ready",
                    "detail": "Report readiness check has blockers",
                })
        except Exception as exc:
            blockers.append(_precondition_check_failed("complete readiness", exc))
        blockers.extend(_blind_triage_blockers(client))
        blockers.extend(_chain_construction_blockers(client))
        blockers.extend(_depth_backstop_blockers(client))

    return blockers


def _chain_construction_blockers(client: AssessmentClient) -> list[dict[str, str]]:
    """Gate the terminal report/complete edge on a completed cross-finding
    chain-construction pass — the second Mandatory Phase-Exit Pass (Exploit ->
    Report).

    Mirrors the structural shape of ``_blind_triage_blockers`` /
    ``missing_variant_pass``: it enumerates the at-risk state (here: confirmed
    high/critical ACTIVE findings, the same ``confirmed_high`` predicate the
    Verify->Exploit variant gate uses) and then checks a structured durable
    signal rather than prose — the existence of a COMPLETED
    ``exploit-developer`` dispatch. The chain pass enumerates A->B candidates
    *across* the confirmed set, so it is only meaningful, and only blocks, when
    there are at least TWO confirmed high/critical findings to chain between;
    0 or 1 leaves nothing to chain across and never blocks (conservative — this
    only ever fires when the prose pass was genuinely owed).

    The signal is intentionally coarse: role=exploit-developer + status=completed.
    Unlike the variant gate (which mandates ``--dispatch-mode variant-rotation``
    in operator-core), the chain prose does NOT mandate a specific dispatch_mode
    for the chain pass (exploit-developer defaults to ``deep-manual``), so keying
    on a mode the operator was never told to set would be a false gate. As with
    the variant gate, only the operator can confirm the chains were *genuinely*
    sought; a completed dispatch row is the deterministic floor, the rest stays
    prose in the Definition of Done.

    A non-empty unsatisfied set appends ONE hard ``missing_chain_construction``
    blocker at the DEFAULT ``severity="block"`` — the same enforcement level as
    ``missing_variant_pass`` / ``missing_blind_triage`` — so the existing
    ``--force``/``--reason`` override (and its audited override-decision row)
    already covers it. Best-effort on read failure: a backend error degrades to
    a single ``precondition_check_failed`` blocker rather than wedging the
    transition.
    """
    blockers: list[dict[str, str]] = []
    try:
        findings = _require_dict_rows(client.get("findings"))
    except Exception as exc:
        blockers.append(_precondition_check_failed("chain-construction findings", exc))
        return blockers

    confirmed_high = [
        f for f in findings
        if f.get("severity") in ("critical", "high")
        and f.get("verification_status") in {"confirmed", "downgraded"}
        and f.get("workflow_status") == "active"
    ]
    # The chain pass runs ACROSS the confirmed set: nothing to chain with fewer
    # than two confirmed high/critical findings, so never block in that case.
    if len(confirmed_high) < 2:
        return blockers

    # Filter to completed exploit-developer dispatches server-side and request
    # the max page size so long engagements don't drop the chain pass behind
    # the default limit=100 (same shape as the variant-pass dispatch read).
    try:
        dispatches = _require_dict_rows(client.get(
            "dispatches?role=exploit-developer&status=completed&limit=1000"
        ))
    except Exception as exc:
        blockers.append(
            _precondition_check_failed("chain-construction dispatches", exc)
        )
        return blockers
    completed_chain_dispatches = [
        d for d in dispatches
        if isinstance(d, dict)
        and str(d.get("status") or "").lower() == "completed"
    ]
    if completed_chain_dispatches:
        return blockers

    sample = ", ".join(f.get("slug", "?") for f in confirmed_high[:5])
    blockers.append({
        "kind": "missing_chain_construction",
        "detail": (
            f"{len(confirmed_high)} confirmed high/critical finding(s) and NO "
            f"completed exploit-developer dispatch on record: {sample}"
            + (" ..." if len(confirmed_high) > 5 else "")
            + " — the cross-finding chain-construction pass (Exploit -> Report) "
            "was not run. Dispatch one exploit-developer pass that enumerates "
            "A->B candidates across the confirmed set (info-disclosure + "
            "open-redirect, SSRF + token leak, IDOR + impersonation) and let it "
            "complete before advancing (it is what turns a list of mediums into "
            "a high). Pass --force --reason \"...\" to override with an audited "
            "decision."
        ),
    })
    return blockers


# Workflow states a finding can actually be submitted from — the same set
# ``export_submission._REPORTABLE_STATUSES`` gates on. ``draft`` / ``merged`` /
# ``false_positive`` are not submissions and never carry a triage obligation.
_SUBMITTABLE_WORKFLOW_STATUSES = frozenset(
    {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
)


def _blind_triage_blockers(client: AssessmentClient) -> list[dict[str, str]]:
    """Gate the terminal report/complete edge on a recorded blind-triage Accept
    verdict for every Medium-or-above SUBMITTABLE finding (FIX E3).

    Mirrors the ``missing_variant_pass`` Verify->Exploit gate exactly: it
    enumerates the at-risk findings — severity in {medium,high,critical} in a
    SUBMITTABLE workflow state — then checks a structured durable signal rather
    than prose. "Submittable" is ``export_submission``'s own reportable set, not
    ``active`` alone: a finding an exploit-developer drove to ``exploited`` is
    the most over-claimable submission there is, and ``reported`` has to be in
    the set or the ``complete`` edge is vacuous, because publication moves a
    finding to ``reported`` before that edge is ever reached. The signal
    is a ``kind='blind_triage_verdict'`` decision row (written by the operator
    via ``vigil assess agent decision --kind blind_triage_verdict
    --payload-json {finding_slug, verdict, ...}``) whose ``verdict`` starts
    ``Accept`` for that slug. Any qualifying finding with no such row appends a
    hard ``missing_blind_triage`` blocker at the DEFAULT ``severity="block"`` —
    the same enforcement level as ``missing_variant_pass`` — so the existing
    ``--force``/``--reason`` override (and its audited override-decision row)
    already covers it. The blind-triage skill is the operator-run Pass-2 review;
    this is its durable backend gate, not a roster role.

    Best-effort on read failure: a backend error degrades to a single
    ``precondition_check_failed`` blocker rather than wedging the transition.
    """
    blockers: list[dict[str, str]] = []
    try:
        findings = _require_dict_rows(client.get("findings"))
    except Exception as exc:
        blockers.append(_precondition_check_failed("blind-triage findings", exc))
        return blockers

    medium_or_above = [
        f for f in findings
        if f.get("severity") in ("medium", "high", "critical")
        and str(f.get("workflow_status") or "").strip().lower()
        in _SUBMITTABLE_WORKFLOW_STATUSES
        and f.get("verification_status") in ("confirmed", "downgraded")
    ]
    if not medium_or_above:
        return blockers

    # Rows are newest-first. Keep only the first verdict for each finding: a
    # later miss must revoke an earlier Accept. Page until every finding has a
    # verdict or the decision ledger ends, rather than trusting the first 1000.
    target_slugs = {str(f.get("slug") or "") for f in medium_or_above}
    latest: dict[str, dict] = {}
    offset = 0
    try:
        while target_slugs - latest.keys():
            decisions = _require_dict_rows(client.get(
                f"dispatch-decisions?kind=blind_triage_verdict&limit=1000&offset={offset}"
            ))
            for row in decisions:
                payload = row.get("payload")
                if not isinstance(payload, dict):
                    continue
                slug = str(payload.get("finding_slug") or "").strip()
                if slug in target_slugs and slug not in latest:
                    latest[slug] = payload
            if len(decisions) < 1000:
                break
            offset += len(decisions)
    except Exception as exc:
        blockers.append(_precondition_check_failed("blind-triage decisions", exc))
        return blockers
    accepted_slugs = {
        slug for slug, payload in latest.items()
        if re.fullmatch(r"Accept@P[1-5]", str(payload.get("verdict") or ""))
        and re.fullmatch(r"[0-9a-f]{64}", str(payload.get("packet_id") or ""))
    }

    missing = [
        f.get("slug", "?") for f in medium_or_above
        if f.get("slug", "?") not in accepted_slugs
    ]
    if missing:
        sample = ", ".join(missing[:5])
        blockers.append({
            "kind": "missing_blind_triage",
            "detail": (
                f"{len(missing)} Medium-or-above submittable finding(s) have no recorded "
                f"blind-triage Accept verdict: {sample}"
                + (" ..." if len(missing) > 5 else "")
                + " — run blind-triage Pass 2 (agent/skills/blind-triage/SKILL.md) "
                "and record the Accept verdict with `vigil assess agent decision "
                "--kind blind_triage_verdict --payload-json "
                "'{\"finding_slug\":\"<slug>\",\"packet_id\":\"<packet id>\",\"reviewer_dispatch_agent_id\":\"<reviewer-id>\",\"writer_dispatch_agent_id\":\"<writer-id>\",\"verdict\":\"Accept@P3\"}'` "
                "before publish (skipping the blind pass is how false-positive / "
                "over-severity submissions ship). Pass --force --reason \"...\" to "
                "override with an audited decision."
            ),
        })

    return blockers


def _depth_backstop_blockers(client: AssessmentClient) -> list[dict[str, str]]:
    """The terminal depth backstop (coverage-grain unbundle / ADR 0012):
    the report/complete edge
    cannot pass with a high-value app unit that is left deep-untested.

    Calls the read-only ``application-units/terminal-block`` endpoint (mirroring
    how the report branch calls ``report-readiness``). The ``blocking`` set spans
    two grains of the SAME gate, split here into two ``severity="block"`` blockers
    that both clear via the same ``depth_deferral`` / ``--force --reason`` valves:

      * ``depth_unsatisfied_units`` (grain ``"family"``) — the historical block:
        a decisive/high-confidence unit left unsatisfied AND undeferred AND
        UNTOUCHED (names the uncovered BLOCK_HIGH families).
      * ``depth_uncovered_classes`` (grain ``"class"``) — the coverage-grain
        block: a decisive/high-confidence unit whose gf coverage_items flagged a
        specific BLOCK_HIGH *class* never class-specifically covered, which fires
        even when the family looks covered/touched (the single-class blind spot).
        The reason names the uncovered classes and the deferral escape.

    The ``warned_under_observed`` units are appended as an ``severity="advisory"``
    blocker so they are surfaced but NEVER block. The deferral rate is visible in
    all. WEB-ONLY: the endpoint returns ``skipped=True`` (empty blocking) for
    code/blue, so this never blocks those tracks even when reached. This extends
    the ONE gate — it does not add a parallel one.
    """
    out: list[dict[str, str]] = []
    try:
        result = client.get("application-units/terminal-block")
        if not isinstance(result, dict):
            raise ValueError("backend returned a non-object response")
    except Exception as exc:
        out.append(_precondition_check_failed("terminal depth backstop", exc))
        return out
    skipped = result.get("skipped")
    if not isinstance(skipped, bool):
        out.append(_precondition_check_failed(
            "terminal depth backstop",
            ValueError("backend response omitted a boolean skipped field"),
        ))
        return out
    if skipped:
        return out
    try:
        deferral_count = int(result.get("deferral_count") or 0)
        blocking = _require_dict_rows(result.get("blocking"))
        warned = _require_dict_rows(result.get("warned_under_observed"))
        if any(not isinstance(row.get("unit"), dict) for row in blocking + warned):
            raise ValueError("backend depth response contained a malformed unit")
        if any(
            row.get("block_grain") == "class"
            and not isinstance(row.get("uncovered_classes"), list)
            for row in blocking
        ):
            raise ValueError(
                "backend depth response contained malformed uncovered_classes"
            )
    except Exception as exc:
        out.append(_precondition_check_failed("terminal depth backstop", exc))
        return out

    # The block set carries two grains (depth_ledger.terminal_depth_block):
    #   * "family" — the historical block: a decisive/high-confidence unit left
    #     untested/undeferred/untouched (names the uncovered BLOCK_HIGH families);
    #   * "class"  — the coverage-grain-unbundle block (ADR 0012): a decisive/
    #     high-confidence unit whose gf coverage_items flagged a specific
    #     BLOCK_HIGH *class* that was never class-specifically covered (a sibling
    #     class covered the family, so the family gate would pass). Both are ONE
    #     gate (severity="block") on this same edge — the --force/--reason override
    #     and the depth_deferral valve clear either.
    family_blocking = [b for b in blocking if b.get("block_grain") != "class"]
    class_blocking = [b for b in blocking if b.get("block_grain") == "class"]

    if family_blocking:
        names = [_unit_label(b.get("unit", {})) for b in family_blocking]
        sample = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
        out.append({
            "kind": "depth_unsatisfied_units",
            "severity": "block",
            "detail": (
                f"{len(family_blocking)} high-value app unit(s) are untested, "
                f"undeferred, and untouched (the engagement never went deep on "
                f"them): {sample}. "
                "These carry a high-confidence deep_required tier or a decisive risk "
                "surface (auth_entry / object_reference / privileged_write / "
                "api_documentation). Either go deep on them, OR defer with "
                "`vigil assess agent decision --kind depth_deferral --surfaced-to-user "
                "--payload-json '{\"host\":\"<host>\",\"path_prefix\":\"<prefix>\","
                "\"vuln_classes\":[...],\"reason\":\"<why>\"}'` (bounded, recorded), "
                "OR override with `transition-phase ... --force --reason \"<why>\"`. "
                f"({deferral_count} depth_deferral(s) already recorded.)"
            ),
        })

    if class_blocking:
        parts = [
            f"{_unit_label(b.get('unit', {}))} "
            f"[{', '.join(str(c) for c in (b.get('uncovered_classes') or [])) or '?'}]"
            for b in class_blocking
        ]
        sample = "; ".join(parts[:6]) + (" ..." if len(parts) > 6 else "")
        all_classes = sorted({
            str(c) for b in class_blocking for c in (b.get("uncovered_classes") or [])
        })
        out.append({
            "kind": "depth_uncovered_classes",
            "severity": "block",
            "detail": (
                f"{len(class_blocking)} decisive / high-confidence app unit(s) have a "
                f"BLOCK_HIGH vuln CLASS that was flagged but never class-specifically "
                f"tested — a sibling class covered the family, but the specific "
                f"class(es) are still uncovered: {sample}. Uncovered class(es): "
                f"{', '.join(all_classes)}. Either drain each class with a "
                "class-specific covering probe / evidence-bearing coverage-item "
                "(result_status tested/signal — `status=completed` alone never "
                "counts), OR defer the class(es) with `vigil assess agent decision "
                "--kind depth_deferral --surfaced-to-user --payload-json "
                "'{\"host\":\"<host>\",\"path_prefix\":\"<prefix>\","
                "\"vuln_classes\":[<classes>],\"reason\":\"<why>\"}'` (bounded, "
                "recorded), OR override with `transition-phase ... --force --reason "
                f"\"<why>\"`. ({deferral_count} depth_deferral(s) already recorded.)"
            ),
        })

    if warned:
        names = [_unit_label(w.get("unit", {})) for w in warned]
        sample = ", ".join(names[:6]) + (" ..." if len(names) > 6 else "")
        out.append({
            "kind": "depth_under_observed_units",
            "severity": "advisory",
            "detail": (
                f"{len(warned)} deep_required app unit(s) are under-observed or "
                f"started-but-unfinished and could not be confidently scored as "
                f"deep-tested: {sample}. Not blocking; consider more collection / a "
                "dedicated deep pass, or record a depth_deferral if intentionally "
                f"out of scope. ({deferral_count} depth_deferral(s) recorded.)"
            ),
        })
    return out


def _unit_label(unit: dict) -> str:
    host = str(unit.get("host") or "?")
    prefix = str(unit.get("path_prefix") or "/")
    pc = str(unit.get("port_class") or "")
    base = f"{host}{prefix}"
    return f"{base} [{pc}]" if pc and pc != "web" else base


def _check_code_preconditions(
    target_phase: str,
    client: AssessmentClient,
) -> list[dict[str, str]]:
    """Consume the backend-owned, target-specific code readiness contract.

    Source identity and generation currency are backend facts. Keeping their
    decision logic behind one endpoint prevents the CLI and UI from blessing a
    stale snapshot differently. A malformed or unavailable readiness response
    therefore fails closed and is non-overrideable.
    """
    # ``ingest`` is the reset/source-establishment phase, not a destination with
    # backend readiness requirements. In particular, a deliberate backward
    # transition must remain possible so the operator can replace stale source
    # identity before any later-phase gate could become satisfiable again.
    if target_phase == "ingest":
        return []

    blockers: list[dict[str, str]] = []
    try:
        readiness = client.get(f"code/readiness?target_phase={target_phase}")
    except Exception as exc:  # noqa: BLE001 - readiness transport failures must fail closed
        blocker = _precondition_check_failed("code readiness", exc)
        blocker["overrideable"] = False
        blockers.append(blocker)
        return blockers
    if not isinstance(readiness, dict):
        blockers.append({
            "kind": "invalid_code_readiness",
            "severity": "block",
            "detail": "Backend returned a non-object code readiness response",
            "overrideable": False,
        })
        return blockers

    if readiness.get("target_phase") != target_phase:
        blockers.append({
            "kind": "invalid_code_readiness",
            "severity": "block",
            "detail": (
                "Backend readiness response was bound to "
                f"{readiness.get('target_phase')!r}, expected {target_phase!r}"
            ),
            "overrideable": False,
        })
        return blockers

    raw_blockers = readiness.get("blockers")
    if not isinstance(raw_blockers, list):
        blockers.append({
            "kind": "invalid_code_readiness",
            "severity": "block",
            "detail": "Backend readiness response omitted its blocker list",
            "overrideable": False,
        })
        return blockers

    for raw in raw_blockers:
        if not isinstance(raw, dict) or not raw.get("code") or not raw.get("message"):
            blockers.append({
                "kind": "invalid_code_readiness",
                "severity": "block",
                "detail": "Backend readiness response contained a malformed blocker",
                "overrideable": False,
            })
            continue
        blockers.append({
            "kind": str(raw["code"]),
            "severity": "block",
            "detail": str(raw["message"]),
            # Missing override metadata is treated as an integrity constraint.
            "overrideable": raw.get("overrideable") is True,
        })

    if readiness.get("transition_ready") is not True and not raw_blockers:
        blockers.append({
            "kind": "invalid_code_readiness",
            "severity": "block",
            "detail": "Backend marked the transition unready without naming a blocker",
            "overrideable": False,
        })

    quality_gate = readiness.get("quality_gate", {})
    if isinstance(quality_gate, dict):
        warnings = quality_gate.get("warnings", [])
        if isinstance(warnings, list):
            for warning in warnings:
                blockers.append({
                    "kind": "code_quality_warning",
                    "severity": "advisory",
                    "detail": str(warning),
                    "overrideable": True,
                })

    return blockers


def _check_blue_preconditions(
    target_phase: str,
    client: AssessmentClient,
    engagement_dir: str,
) -> list[dict[str, str]]:
    """Blue-track phase-exit gates.

    Blue IR has no host-coverage table, no work-buffer, no scope_host —
    gates check IR primitives instead: alert recorded, findings drafted by
    L1, telemetry pulled + artifact-linked by L2, verifier dispositions
    present, containment closure on verified-high findings, and a final
    report or closeout artifact.

    All backend failures degrade gracefully — a single
    ``backend_query_failed`` blocker is emitted per failed query so the
    operator can ``--force`` through a transient outage rather than be
    wedged.
    """
    blockers: list[dict[str, str]] = []
    if target_phase == "triage":
        blockers.extend(_blue_check_intake_to_triage(client, engagement_dir))
    elif target_phase == "investigate":
        blockers.extend(_blue_check_triage_to_investigate(client))
    elif target_phase == "verify":
        blockers.extend(_blue_check_investigate_to_verify(client))
    elif target_phase == "respond":
        blockers.extend(_blue_check_verify_to_respond(client))
    elif target_phase == "report":
        blockers.extend(_blue_check_respond_to_report(client))
    elif target_phase == "complete":
        blockers.extend(_blue_check_report_to_complete(client))
    return blockers


def _blue_backend_failure(query_name: str, exc: Exception) -> dict[str, str]:
    message = str(exc) or exc.__class__.__name__
    # Cap the rendered detail so a stack of validation errors doesn't blow
    # past the operator-facing line budget.
    if len(message) > 160:
        message = message[:157] + "..."
    return {
        "kind": "backend_query_failed",
        "detail": f"backend query failed for {query_name}: {message}",
    }


def _blue_load_scope(engagement_dir: str) -> tuple[dict, str | None]:
    """Read scope.json; return (scope, error_message)."""
    scope_path = os.path.join(engagement_dir, "scope.json")
    try:
        with open(scope_path) as f:
            return json.load(f), None
    except FileNotFoundError:
        return {}, f"scope.json not found at {scope_path}"
    except (OSError, json.JSONDecodeError) as exc:
        return {}, f"could not read scope.json: {exc}"


def _blue_list_activity_entries(client: AssessmentClient) -> list[dict]:
    """Return all activity_entries rows for this engagement.

    The endpoint lives under /engagements/{key}/activity-entries (NOT
    /assessment/...), so we use client.get_engagement().
    """
    page_size = 1000
    offset = 0
    rows: list[dict] = []
    while True:
        result = client.get_engagement(
            "activity-entries",
            query=f"limit={page_size}&offset={offset}",
        )
        if not isinstance(result, dict):
            return rows
        items = result.get("items") or []
        if not isinstance(items, list):
            return rows
        rows.extend(item for item in items if isinstance(item, dict))
        if len(items) < page_size:
            return rows
        offset += page_size


def _blue_list_findings(client: AssessmentClient) -> list[dict]:
    rows = client.get("findings")
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict)]
    return []


def _blue_active_findings(findings: list[dict]) -> list[dict]:
    return [
        f for f in findings
        if f.get("workflow_status") in ("active", "draft")
    ]


def _blue_finding_is_false_positive(finding: dict) -> bool:
    return str(finding.get("verification_status") or "") == "false_positive"


def _blue_finding_has_completed_counter_check(finding: dict) -> bool:
    counter_check = finding.get("counter_check")
    if not isinstance(counter_check, dict) or counter_check.get("completed") is not True:
        return False
    if not all(
        str(counter_check.get(key) or "").strip()
        for key in ("method", "expected_result", "observed_result", "falsified_claim")
    ):
        return False
    receipt_ids = counter_check.get("proof_receipt_ids")
    return (
        isinstance(receipt_ids, list)
        and bool(receipt_ids)
        and all(isinstance(receipt_id, int) and receipt_id > 0 for receipt_id in receipt_ids)
    )


def _blue_all_findings_independently_closed(findings: list[dict]) -> bool:
    return bool(findings) and all(
        _blue_finding_is_false_positive(finding)
        and _blue_finding_has_completed_counter_check(finding)
        for finding in findings
    )


def _blue_list_completed_dispatches(client: AssessmentClient) -> list[dict]:
    page_size = 1000
    offset = 0
    rows: list[dict] = []
    while True:
        page = client.get(f"dispatches?status=completed&limit={page_size}&offset={offset}")
        if not isinstance(page, list):
            return []
        rows.extend(row for row in page if isinstance(row, dict))
        if len(page) < page_size:
            return rows
        offset += page_size


def _blue_count_completed_dispatches(client: AssessmentClient, tier: str, role: str) -> int:
    """Count dispatches with the given tier, role, and status='completed'.

    The GET /dispatches endpoint filters by status server-side but not by
    tier/role together, so we page through completed dispatches and filter
    client-side. Returns 0 on backend error (caller emits the blocker).
    """
    rows = _blue_list_completed_dispatches(client)
    expected_role = role.strip()
    return sum(
        1 for row in rows
        if isinstance(row, dict)
        and str(row.get("tier") or "").upper() == tier.upper()
        and str(row.get("agent_role") or row.get("role") or "").strip() == expected_role
    )


def _blue_list_artifacts(client: AssessmentClient, *, finding: str = "") -> list[dict]:
    from urllib.parse import quote

    page_size = 1000
    offset = 0
    rows: list[dict] = []
    finding_query = f"finding={quote(finding, safe='')}&" if finding else ""
    while True:
        page = client.get(
            f"artifacts/search?{finding_query}limit={page_size}&offset={offset}"
        )
        if not isinstance(page, list):
            raise AssessError(
                "blue phase artifact audit returned a malformed page; phase "
                "evidence is incomplete"
            )
        if any(not isinstance(row, dict) for row in page):
            raise AssessError(
                "blue phase artifact audit returned a malformed row; phase "
                "evidence is incomplete"
            )
        rows.extend(page)
        if len(page) < page_size:
            return rows
        offset += page_size


def _blue_artifacts_for_finding(client: AssessmentClient, slug: str) -> list[dict]:
    """Artifacts whose related_finding_slug == slug.

    Uses /artifacts/search?finding=<slug> which both filters server-side
    and orders by finding link. Defensive: filter client-side as well in
    case the FTS expansion widens the match.
    """
    rows = _blue_list_artifacts(client, finding=slug)
    direct: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("related_finding_slug") or "") == slug:
            direct.append(row)
    return direct


def _blue_check_intake_to_triage(
    client: AssessmentClient,
    engagement_dir: str,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    scope, scope_error = _blue_load_scope(engagement_dir)
    if scope_error:
        blockers.append({
            "kind": "scope_unreadable",
            "detail": scope_error,
        })
        return blockers

    tenant_refs = scope.get("tenant_reference_paths") or []
    if not isinstance(tenant_refs, list) or len(tenant_refs) == 0:
        blockers.append({
            "kind": "no_tenant_reference_paths",
            "detail": (
                "scope.json:tenant_reference_paths[] is empty — L1 has no tenant "
                "context. Populate via `vigil blue tenant init` or edit scope.json."
            ),
        })
    else:
        for ref in tenant_refs:
            if not isinstance(ref, str) or not ref.strip():
                continue
            ref_path = ref if os.path.isabs(ref) else os.path.join(engagement_dir, ref)
            if not os.path.exists(ref_path):
                blockers.append({
                    "kind": "missing_tenant_reference_file",
                    "severity": "advisory",
                    "detail": (
                        f"tenant_reference_paths entry not found on disk: {ref!r} "
                        f"(resolved to {ref_path}). L1 will halt at first lookup — "
                        "fix the path or re-run `vigil blue tenant init`."
                    ),
                })

    try:
        alert_artifacts = client.get(
            "artifacts/search?kind=alert_intake&limit=1&offset=0"
        )
        if not isinstance(alert_artifacts, list):
            raise AssessError("alert artifact search returned a malformed response")
    except Exception as exc:  # noqa: BLE001 - degrade to blocker
        blockers.append(_blue_backend_failure("alert intake artifact", exc))
    else:
        if not alert_artifacts:
            blockers.append({
                "kind": "no_alert_intake_artifact",
                "detail": (
                    "no registered artifact with kind='alert_intake' — the raw alert "
                    "file may exist locally, but intake evidence is not indexed yet. "
                    "Retry `vigil assess artifact register <raw-alert-path> --kind "
                    "alert_intake` before transitioning to triage."
                ),
            })

    try:
        entries = _blue_list_activity_entries(client)
    except Exception as exc:  # noqa: BLE001 - degrade to blocker
        blockers.append(_blue_backend_failure("activity-entries", exc))
    else:
        has_intake = any(
            str(entry.get("action") or "") == "alert_intake"
            for entry in entries
        )
        if not has_intake:
            blockers.append({
                "kind": "no_alert_intake_audit",
                "detail": (
                    "no activity_entries row with action='alert_intake' — the "
                    "alert record wrapper did not log the intake. Record the alert "
                    "with `vigil blue alert record --body-file <path>` so the audit "
                    "row lands before transitioning to triage."
                ),
            })

    return blockers


def _blue_check_triage_to_investigate(
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    try:
        findings = _blue_list_findings(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("findings", exc))
        return blockers

    if not findings:
        blockers.append({
            "kind": "no_findings_drafted",
            "detail": (
                "no assessment_findings rows — L1 neither drafted a finding nor "
                "auto-closed the alert. Run alert-triage-specialist before advancing."
            ),
        })
        return blockers

    # A terminal false-positive decision may skip later investigation work only
    # when the backend exposes its completed structured independent counter-check.
    if _blue_all_findings_independently_closed(findings):
        return blockers

    drafts = [f for f in findings if str(f.get("workflow_status") or "") == "draft"]
    fps = [f for f in findings if _blue_finding_is_false_positive(f)]
    if drafts and not fps:
        # All findings still draft and no FP closures: maybe L1 dispatched
        # them to L2 (draft is fine in that case) — but we still demand a
        # completed L1 dispatch (handled below).
        pass

    try:
        l1_completed = _blue_count_completed_dispatches(client, "L1", "alert-triage-specialist")
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("dispatches (L1)", exc))
        l1_completed = -1  # don't double-blame on the next check

    if l1_completed == 0:
        blockers.append({
            "kind": "no_completed_l1_dispatch",
            "detail": (
                "no completed L1 dispatch (alert-triage-specialist) found — "
                "L1 work was not done. Dispatch via "
                "`vigil assess agent start --role alert-triage-specialist --tier L1 "
                "--rate-budget '<authored tenant query budget>' --prompt-context-json "
                "dispatch-context.json --emit-prompt`."
            ),
        })

    return blockers


def _blue_check_investigate_to_verify(
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    try:
        findings = _blue_list_findings(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("findings", exc))
        return blockers

    active = _blue_active_findings(findings)

    if _blue_all_findings_independently_closed(findings):
        return blockers

    skeleton_drafts = [
        f for f in active
        if str(f.get("workflow_status") or "") == "draft"
    ]
    if skeleton_drafts:
        slugs = [str(f.get("slug") or "?") for f in skeleton_drafts[:5]]
        blockers.append({
            "kind": "findings_still_draft",
            "detail": (
                f"{len(skeleton_drafts)} finding(s) still in draft after investigate: "
                f"{', '.join(slugs)}"
                + (" ..." if len(skeleton_drafts) > 5 else "")
                + " — L2 must promote each skeleton to a full finding "
                "(workflow_status='active') before verify."
            ),
        })

    missing_mitre: list[str] = []
    missing_artifacts: list[str] = []
    for finding in active:
        slug = str(finding.get("slug") or "?")
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
        mitre = details.get("mitre_techniques")
        if not isinstance(mitre, list) or not mitre:
            missing_mitre.append(slug)

        try:
            artifacts = _blue_artifacts_for_finding(client, slug)
        except Exception as exc:  # noqa: BLE001
            blockers.append(_blue_backend_failure(f"artifacts for {slug}", exc))
            continue
        if not artifacts:
            missing_artifacts.append(slug)

    if missing_mitre:
        sample = ", ".join(missing_mitre[:5])
        blockers.append({
            "kind": "missing_mitre_techniques",
            "severity": "advisory",
            "detail": (
                f"{len(missing_mitre)} active finding(s) missing "
                f"details.mitre_techniques: {sample}"
                + (" ..." if len(missing_mitre) > 5 else "")
                + " — triage.md rule 11 asks for MITRE tagging; add it before "
                "report for a complete ATT&CK mapping."
            ),
        })

    if missing_artifacts:
        sample = ", ".join(missing_artifacts[:5])
        blockers.append({
            "kind": "missing_evidence_artifacts",
            "detail": (
                f"{len(missing_artifacts)} active finding(s) have zero artifacts "
                f"linked: {sample}"
                + (" ..." if len(missing_artifacts) > 5 else "")
                + " — ir-evidence.md requires an evidence trail "
                "(register artifacts with --finding <slug>)."
            ),
        })

    try:
        l2_completed = _blue_count_completed_dispatches(client, "L2", "investigator")
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("dispatches (L2)", exc))
        l2_completed = -1

    if l2_completed == 0:
        blockers.append({
            "kind": "no_completed_l2_dispatch",
            "detail": (
                "no completed L2 dispatch (investigator) found — L2 work was "
                "not done. Dispatch via "
                "`vigil assess agent start --role investigator --tier L2 "
                "--rate-budget '<authored tenant query budget>' --prompt-context-json "
                "dispatch-context.json --emit-prompt`."
            ),
        })

    return blockers


def _blue_check_verify_to_respond(
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    try:
        findings = _blue_list_findings(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("findings", exc))
        return blockers

    unreviewed = [
        f for f in _blue_active_findings(findings)
        if str(f.get("verification_status") or "unreviewed") == "unreviewed"
    ]
    if unreviewed:
        slugs = [str(f.get("slug") or "?") for f in unreviewed[:5]]
        blockers.append({
            "kind": "unreviewed_findings",
            "detail": (
                f"{len(unreviewed)} active finding(s) still verification_status="
                f"'unreviewed': {', '.join(slugs)}"
                + (" ..." if len(unreviewed) > 5 else "")
                + " — verifier must disposition each via "
                "`vigil blue verify <slug> --status ...`."
            ),
        })

    try:
        l3_completed = _blue_count_completed_dispatches(client, "L3", "incident-verifier")
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("dispatches (L3)", exc))
        l3_completed = -1

    if l3_completed == 0:
        blockers.append({
            "kind": "no_completed_l3_dispatch",
            "detail": (
                "no completed L3 dispatch (incident-verifier) found — verifier "
                "did not run. Dispatch via "
                "`vigil assess agent start --role incident-verifier --tier L3 "
                "--rate-budget '<authored tenant query budget>' --prompt-context-json "
                "dispatch-context.json --emit-prompt`."
            ),
        })

    return blockers


def _blue_check_respond_to_report(
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    try:
        findings = _blue_list_findings(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("findings", exc))
        return blockers

    # Verified high/critical findings need actual containment closure
    # (finding status, containment activity/proof) OR an explicit
    # no_containment_required activity log entry. Proposal approval alone is
    # not closure; `vigil blue contain` records the action after host-exec.
    confirmed_high = [
        f for f in findings
        if str(f.get("verification_status") or "") == "confirmed"
        and str(f.get("severity") or "") in ("high", "critical")
        and str(f.get("workflow_status") or "") not in (
            "false_positive", "merged", "reported",
        )
    ]
    if not confirmed_high:
        # Auto-close / no-high-confirmed path: nothing to gate on.
        return blockers

    try:
        entries = _blue_list_activity_entries(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("activity-entries", exc))
        entries = []

    # Build the set of real finding slugs once so the fallback extractor below
    # only ever silences findings the engagement actually knows about.
    known_finding_slugs: set[str] = {
        str(f.get("slug") or "").strip()
        for f in findings
        if str(f.get("slug") or "").strip()
    }

    no_containment_slugs: set[str] = set()
    containment_activity_slugs: set[str] = set()
    saw_no_containment_required = False
    for entry in entries:
        action = str(entry.get("action") or "")
        meta = entry.get("metadata")
        if not isinstance(meta, dict):
            meta = entry.get("metadata_json")
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except (TypeError, ValueError):
                    meta = {}
        if not isinstance(meta, dict):
            meta = {}
        if action in {"contain", "containment_executed"} or meta.get("containment_action"):
            meta_slug = str(meta.get("finding_slug") or "").strip()
            if meta_slug:
                containment_activity_slugs.add(meta_slug)
                continue
            for key in ("artifact_ref", "title", "result", "action"):
                value = str(entry.get(key) or "")
                for match in _CANONICAL_SLUG_RE.findall(value):
                    if match in known_finding_slugs:
                        containment_activity_slugs.add(match)
        if action != "no_containment_required":
            continue
        saw_no_containment_required = True
        # Preferred path: operator passes ``metadata.finding_slug`` in the
        # ``vigil assess log`` invocation. When present, that single value is
        # the only slug closed by this row — no free-form parsing of titles.
        meta_slug = str(meta.get("finding_slug") or "").strip()
        if meta_slug:
            no_containment_slugs.add(meta_slug)
            continue
        # Fallback: pull canonical slug-shaped tokens (e.g. ``FIND-001``,
        # ``VA-003``) out of artifact_ref/title/result, but only add tokens
        # that match a known finding slug. This prevents accidental closure
        # from prose like "no containment needed for SLUG-A because ..."
        # silently silencing tokens like ``no``, ``containment``, ``needed``.
        for key in ("artifact_ref", "title", "result", "action"):
            value = str(entry.get(key) or "")
            for match in _CANONICAL_SLUG_RE.findall(value):
                if match in known_finding_slugs:
                    no_containment_slugs.add(match)

    single_finding_no_containment = (
        len(confirmed_high) == 1 and saw_no_containment_required
    )

    missing: list[str] = []
    for finding in confirmed_high:
        slug = str(finding.get("slug") or "?")
        # Already at workflow_status contained/eradicated/recovered counts
        # as closed without re-checking the decision row.
        if str(finding.get("workflow_status") or "") in (
            "contained", "eradicated", "recovered",
        ):
            continue
        if slug in containment_activity_slugs:
            continue
        if slug in no_containment_slugs:
            continue
        if single_finding_no_containment:
            continue
        try:
            artifacts = _blue_artifacts_for_finding(client, slug)
        except Exception as exc:  # noqa: BLE001
            blockers.append(_blue_backend_failure(f"artifacts for {slug}", exc))
            artifacts = []
        if any(str(artifact.get("kind") or "") == "containment_proof" for artifact in artifacts):
            continue
        missing.append(slug)

    if missing:
        sample = ", ".join(missing[:5])
        blockers.append({
            "kind": "missing_containment_closure",
            "detail": (
                f"{len(missing)} verified high/critical finding(s) lack "
                f"containment closure: {sample}"
                + (" ..." if len(missing) > 5 else "")
                + " — for each slug do one of: (1) propose+approve+contain "
                "(vigil blue propose-contain / vigil assess approve-proposal / "
                "vigil blue contain), or (2) if already mitigated by other "
                "controls, log `vigil assess log operator <title> "
                "no_containment_required <slug> --actor-kind operator` naming "
                "the finding slug (a single-finding closure may omit the slug)."
            ),
        })

    return blockers


def _blue_check_report_to_complete(
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    try:
        # Use the search endpoint to fetch artifacts; filter by kind
        # client-side since the search verb only filters by finding + text.
        artifacts = _blue_list_artifacts(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("artifacts", exc))
        artifacts = None  # signal: skip the report-artifact check

    if artifacts is not None:
        has_report = False
        for art in artifacts:
            if not isinstance(art, dict):
                continue
            kind = str(art.get("kind") or "").lower()
            rel = str(art.get("relative_path") or "").lower()
            if (kind == "ir_evidence" and "report" in rel) or (kind == "ir_closeout" and "closeout" in rel):
                has_report = True
                break
        if not has_report:
            blockers.append({
                "kind": "no_report_artifact",
                "detail": (
                    "no registered final artifact found — expected either "
                    "kind='ir_evidence' with a report path or kind='ir_closeout' "
                    "with a closeout path. Run `vigil blue report` for incidents "
                    "or `vigil blue closeout` for false-positive/no-incident "
                    "closure, then register the output."
                ),
            })

    try:
        findings = _blue_list_findings(client)
    except Exception as exc:  # noqa: BLE001
        blockers.append(_blue_backend_failure("findings", exc))
        return blockers

    terminal_statuses = {
        "reported", "false_positive", "contained", "eradicated", "recovered",
        # 'merged' findings collapse into the canonical row and don't need a
        # separate terminal — treat as closed.
        "merged",
    }
    open_findings = [
        f for f in findings
        if str(f.get("workflow_status") or "") not in terminal_statuses
    ]
    if open_findings:
        slugs = [str(f.get("slug") or "?") for f in open_findings[:5]]
        blockers.append({
            "kind": "findings_not_closed",
            "detail": (
                f"{len(open_findings)} finding(s) not in a terminal status "
                f"(reported/false_positive/contained/eradicated/recovered): "
                f"{', '.join(slugs)}"
                + (" ..." if len(open_findings) > 5 else "")
                + " — close each via report/verify/contain before complete."
            ),
        })

    return blockers
