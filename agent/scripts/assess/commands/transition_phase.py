"""aith assess transition-phase — guarded scope.json phase transition.

Validates preconditions before writing the new phase to scope.json.
Exits non-zero and prints blockers when preconditions fail.
Pass --force to override blockers (logged but not blocked).
"""
from __future__ import annotations

import json
import os
import re
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import Config, load_config


WEB_PHASES = [
    "recon",
    "collect",
    "consume-test",
    "verify",
    "exploit",
    "report",
    "complete",
]

CODE_PHASES = [
    "ingest",
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
    "complete",
]

BLUE_PHASES = [
    "intake",
    "triage",
    "investigate",
    "verify",
    "respond",
    "report",
    "complete",
]

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
        help="Override blockers (transition proceeds with warnings)",
    )
    p.add_argument(
        "--track",
        choices=("auto", "web", "code", "blue"),
        default="auto",
        help="Phase track for `both` engagements (default: infer from target phase).",
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
    track = _phase_track(engagement_type, target_phase, getattr(args, "track", "auto"))

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
    current_phase = scope.get(phase_key, "ingest" if phase_key == "code_phase" else "")

    if target_phase not in order:
        print(
            f"transition-phase: unknown phase '{target_phase}' "
            f"for engagement type '{engagement_type}' track '{track}'. "
            f"Valid phases: {', '.join(phases)}",
            file=sys.stderr,
        )
        sys.exit(2)

    if current_phase and current_phase in order:
        if order[target_phase] < order[current_phase]:
            print(
                f"transition-phase: refusing backward transition "
                f"'{current_phase}' -> '{target_phase}'. "
                f"Use --force to override.",
                file=sys.stderr,
            )
            if not args.force:
                sys.exit(1)

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

    if blockers and not args.force:
        print(f"transition-phase: {len(blockers)} blocker(s) for '{target_phase}':", file=sys.stderr)
        for b in blockers:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)
        sys.exit(1)

    if blockers and args.force:
        print(f"transition-phase: overriding {len(blockers)} blocker(s) with --force:", file=sys.stderr)
        for b in blockers:
            print(f"  - [{b['kind']}] {b['detail']}", file=sys.stderr)

    scope[phase_key] = target_phase
    if track == "blue" and target_phase == "complete":
        scope["status"] = "completed"
    tmp_path = scope_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(scope, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, scope_path)

    print(f"Phase transitioned ({track}): {current_phase or '(none)'} -> {target_phase}")


def _precondition_targets_for_transition(
    *,
    current_phase: str,
    target_phase: str,
    track: str,
    order: dict[str, int],
) -> list[str]:
    """Return every phase gate that must pass for this transition.

    Blue incident work is frequently non-linear in operator conversation, but
    durable state cannot skip intake, triage, verification, or closeout gates.
    A direct jump such as intake -> report therefore checks every intermediate
    blue target phase in order.
    """
    if track != "blue":
        return [target_phase]
    if not current_phase or current_phase not in order:
        return [target_phase]
    start = order[current_phase]
    end = order[target_phase]
    if end <= start:
        return [target_phase]
    ordered_phases = sorted(order, key=order.get)
    return ordered_phases[start + 1 : end + 1]


def _phase_track(engagement_type: str, target_phase: str, requested_track: str) -> str:
    if engagement_type == "blue":
        return "blue"
    if engagement_type == "code":
        return "code"
    if engagement_type != "both":
        return "web"
    if requested_track in {"web", "code"}:
        return requested_track
    in_web = target_phase in WEB_TRANSITION_ORDER
    in_code = target_phase in CODE_TRANSITION_ORDER
    if in_web and in_code:
        print(
            f"transition-phase: phase '{target_phase}' is valid for both tracks; pass --track web or --track code",
            file=sys.stderr,
        )
        sys.exit(2)
    if in_code:
        return "code"
    return "web"


def _check_preconditions(
    target_phase: str,
    track: str,
    engagement_dir: str,
    args,
    cfg: Config | None = None,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    cfg = cfg or load_config(engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    try:
        if track == "code":
            blockers.extend(_check_code_preconditions(target_phase, client))
        elif track == "blue":
            blockers.extend(_check_blue_preconditions(target_phase, client, engagement_dir))
        else:
            blockers.extend(_check_web_preconditions(target_phase, engagement_dir, client))
    finally:
        client.close()

    return blockers


def _precondition_check_failed(check_name: str, exc: Exception) -> dict[str, str]:
    message = str(exc) or exc.__class__.__name__
    return {
        "kind": "precondition_check_failed",
        "detail": f"{check_name} check failed: {message}",
    }


def _check_web_preconditions(
    target_phase: str,
    engagement_dir: str,
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
        db_path = os.path.join(engagement_dir, "cases.db")
        if not os.path.isfile(db_path):
            blockers.append({
                "kind": "no_work_buffer",
                "detail": "cases.db not found — collection may not have run",
            })
        else:
            try:
                import sqlite3
                conn = sqlite3.connect(db_path)
                count = conn.execute(
                    "SELECT COUNT(*) FROM work_items WHERE status = 'pending'"
                ).fetchone()[0]
                conn.close()
                if count == 0:
                    blockers.append({
                        "kind": "empty_work_buffer",
                        "detail": "No pending work items in cases.db — nothing to consume",
                    })
            except Exception as exc:
                blockers.append(_precondition_check_failed("consume-test work buffer", exc))

    elif target_phase == "verify":
        try:
            findings = client.get("findings")
            if isinstance(findings, list):
                active = [f for f in findings if f.get("workflow_status") == "active"]
                if len(active) == 0:
                    blockers.append({
                        "kind": "no_active_findings",
                        "detail": "No active findings to verify",
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("verify findings", exc))

    elif target_phase == "exploit":
        try:
            findings = client.get("findings")
            if isinstance(findings, list):
                unverified_high = [
                    f for f in findings
                    if f.get("severity") in ("critical", "high")
                    and f.get("verification_state") != "verified"
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

                # Variant-pass gate: every confirmed high/critical finding should have
                # at least one vulnerability-analyst dispatch dedicated to sibling /
                # variant / rotation hunting before the engagement advances to exploit.
                # Skipping the variant pass is the single most common way real findings
                # are missed. The check is permissive — task-text match on
                # variant|sibling|rotat — so any reasonable phrasing satisfies it.
                # --force overrides if the operator has a stated reason.
                confirmed_high = [
                    f for f in findings
                    if f.get("severity") in ("critical", "high")
                    and f.get("verification_state") == "verified"
                    and f.get("workflow_status") == "active"
                ]
                if confirmed_high:
                    # Filter by role server-side and request the max page size
                    # so engagements with many dispatches don't drop older
                    # variant-pass runs behind the default limit=100.
                    try:
                        dispatches = client.get(
                            "dispatches?role=vulnerability-analyst&limit=1000"
                        ) or []
                    except Exception:
                        dispatches = []
                    variant_tasks = [
                        d for d in dispatches
                        if any(
                            kw in (d.get("task") or "").lower()
                            for kw in ("variant", "sibling", "rotat")
                        )
                    ]
                    missing_variant: list[str] = []
                    for finding in confirmed_high:
                        slug = finding.get("slug", "?")
                        hit = False
                        for d in variant_tasks:
                            slugs = d.get("finding_slugs") or []
                            task = (d.get("task") or "").lower()
                            if slug in slugs or slug.lower() in task:
                                hit = True
                                break
                        if not hit:
                            missing_variant.append(slug)
                    if missing_variant:
                        sample = ", ".join(missing_variant[:5])
                        blockers.append({
                            "kind": "missing_variant_pass",
                            "detail": (
                                f"{len(missing_variant)} confirmed high/critical finding(s) "
                                f"have no vulnerability-analyst variant/sibling pass: "
                                f"{sample}"
                                + (" ..." if len(missing_variant) > 5 else "")
                                + " — dispatch the variant hunt before advancing "
                                "(skipping is the most common way real findings are missed). "
                                "Pass --force only with a stated reason."
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

    return blockers


def _check_code_preconditions(
    target_phase: str,
    client: AssessmentClient,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    if target_phase == "classify-map":
        try:
            coverage = client.get("code/coverage")
            if isinstance(coverage, dict):
                total = coverage.get("total_files", 0)
                if total == 0:
                    blockers.append({
                        "kind": "no_indexed_files",
                        "detail": "No files indexed — ingest may be incomplete",
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("classify-map coverage", exc))

    elif target_phase == "hunt":
        try:
            coverage = client.get("code/coverage")
            if isinstance(coverage, dict):
                by_class = coverage.get("by_classification", {})
                classified = sum(
                    v.get("count", 0) if isinstance(v, dict) else int(v)
                    for k, v in by_class.items()
                    if k != "skip"
                )
                if classified == 0:
                    blockers.append({
                        "kind": "no_classified_files",
                        "detail": "No files classified — classify-map may be incomplete",
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("hunt coverage", exc))

    elif target_phase == "verify-variant":
        try:
            findings = client.get("findings")
            if isinstance(findings, list):
                code_findings = [
                    f for f in findings
                    if str(f.get("canonical_location", "")).startswith("file:")
                    and f.get("workflow_status") == "active"
                ]
                if len(code_findings) == 0:
                    blockers.append({
                        "kind": "no_code_findings",
                        "detail": "No active code findings to verify — hunt may be incomplete",
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("verify-variant findings", exc))

    elif target_phase == "complete":
        try:
            findings = client.get("findings")
            if isinstance(findings, list):
                unverified = [
                    f for f in findings
                    if str(f.get("canonical_location", "")).startswith("file:")
                    and f.get("severity") in ("critical", "high")
                    and f.get("verification_state") != "verified"
                    and f.get("workflow_status") == "active"
                ]
                if unverified:
                    slugs = [f.get("slug", "?") for f in unverified[:5]]
                    blockers.append({
                        "kind": "unverified_code_findings",
                        "detail": (
                            f"{len(unverified)} high/critical code finding(s) unverified: "
                            f"{', '.join(slugs)}"
                            + (" ..." if len(unverified) > 5 else "")
                        ),
                    })
        except Exception as exc:
            blockers.append(_precondition_check_failed("complete code findings", exc))

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
    result = client.get_engagement("activity-entries", query="limit=1000")
    if isinstance(result, dict):
        items = result.get("items") or []
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


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
    return (
        str(finding.get("workflow_status") or "") == "false_positive"
        or str(finding.get("verification_disposition") or "") == "false_positive"
    )


def _blue_finding_has_kill_reason(finding: dict) -> bool:
    details = finding.get("details_json")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except (TypeError, ValueError):
            details = {}
    if not isinstance(details, dict):
        return False
    return bool(str(details.get("kill_reason") or "").strip())


def _blue_all_findings_auto_closed(findings: list[dict]) -> bool:
    return bool(findings) and all(
        _blue_finding_is_false_positive(finding)
        and _blue_finding_has_kill_reason(finding)
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


def _blue_artifacts_for_finding(client: AssessmentClient, slug: str) -> list[dict]:
    """Artifacts whose related_finding_slug == slug.

    Uses /artifacts/search?finding=<slug> which both filters server-side
    and orders by finding link. Defensive: filter client-side as well in
    case the FTS expansion widens the match.
    """
    from urllib.parse import quote
    rows = client.get(f"artifacts/search?finding={quote(slug, safe='')}&limit=200")
    if not isinstance(rows, list):
        return []
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

    alert_md = scope.get("alert_metadata") or {}
    raw_body = str(alert_md.get("raw_body") or "").strip()
    parsed = alert_md.get("parsed")
    if not raw_body and parsed is None:
        blockers.append({
            "kind": "no_alert_intake",
            "detail": (
                "scope.json:alert_metadata is empty — paste the alert into the "
                "operator chat, save it under ir/alerts/, then record it with "
                "`aith blue alert record --body-file <path>` before "
                "transitioning to triage."
            ),
        })

    tenant_refs = scope.get("tenant_reference_paths") or []
    if not isinstance(tenant_refs, list) or len(tenant_refs) == 0:
        blockers.append({
            "kind": "no_tenant_reference_paths",
            "detail": (
                "scope.json:tenant_reference_paths[] is empty — L1 has no tenant "
                "context. Populate via `aith blue tenant init` or edit scope.json."
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
                    "detail": (
                        f"tenant_reference_paths entry not found on disk: {ref!r} "
                        f"(resolved to {ref_path}). L1 will halt at first lookup."
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
                    "alert record wrapper did not log the intake. Re-run "
                    "`aith blue alert record --body-file <path>` so the audit row lands."
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

    # Auto-close-only path: every finding is FP with a kill_reason. The
    # blue verify command stores kill_reason inside details_json; the
    # workflow_status flips to 'false_positive'. Accept either signal.
    if _blue_all_findings_auto_closed(findings):
        # Auto-close-only path — skip the rest of the gate, operator can
        # transition straight to report.
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
                "`aith blue dispatch --role alert-triage-specialist --tier L1`."
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

    if _blue_all_findings_auto_closed(findings):
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
        details = finding.get("details_json")
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (TypeError, ValueError):
                details = {}
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
            "detail": (
                f"{len(missing_mitre)} active finding(s) missing "
                f"details_json.mitre_techniques: {sample}"
                + (" ..." if len(missing_mitre) > 5 else "")
                + " — triage.md rule 11 requires MITRE tagging."
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
                "`aith blue dispatch --role investigator --tier L2`."
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
        if str(f.get("verification_state") or "unreviewed") == "unreviewed"
    ]
    if unreviewed:
        slugs = [str(f.get("slug") or "?") for f in unreviewed[:5]]
        blockers.append({
            "kind": "unreviewed_findings",
            "detail": (
                f"{len(unreviewed)} active finding(s) still verification_state="
                f"'unreviewed': {', '.join(slugs)}"
                + (" ..." if len(unreviewed) > 5 else "")
                + " — verifier must disposition each via "
                "`aith blue verify <slug> --disposition ...`."
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
                "`aith blue dispatch --role incident-verifier --tier L3`."
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
    # not closure; `aith blue contain` records the action after host-exec.
    confirmed_high = [
        f for f in findings
        if str(f.get("verification_state") or "") == "verified"
        and str(f.get("verification_disposition") or "") == "confirmed"
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
        # Preferred path: operator passes ``metadata.finding_slug`` in the
        # ``aith assess log`` invocation. When present, that single value is
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
                + " — either propose+approve+contain (aith blue propose-contain "
                "/ aith assess approve-proposal / aith blue contain) OR log "
                "`aith assess log operator <title> no_containment_required <slug> "
                "--actor-kind operator` if the threat is already mitigated by "
                "other controls."
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
        artifacts = client.get("artifacts/search?limit=1000")
        if not isinstance(artifacts, list):
            artifacts = []
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
                    "with a closeout path. Run `aith blue report` for incidents "
                    "or `aith blue closeout` for false-positive/no-incident "
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
