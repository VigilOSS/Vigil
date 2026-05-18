"""aith assess transition-phase — guarded scope.json phase transition.

Validates preconditions before writing the new phase to scope.json.
Exits non-zero and prints blockers when preconditions fail.
Pass --force to override blockers (logged but not blocked).
"""
from __future__ import annotations

import json
import os
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

WEB_TRANSITION_ORDER = {phase: i for i, phase in enumerate(WEB_PHASES)}
CODE_TRANSITION_ORDER = {phase: i for i, phase in enumerate(CODE_PHASES)}


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
        choices=("auto", "web", "code"),
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

    blockers = _check_preconditions(
        target_phase, track, engagement_dir, args, cfg,
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
    tmp_path = scope_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(scope, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, scope_path)

    print(f"Phase transitioned ({track}): {current_phase or '(none)'} -> {target_phase}")


def _phase_track(engagement_type: str, target_phase: str, requested_track: str) -> str:
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
                    try:
                        dispatches = client.get("dispatches") or []
                    except Exception:
                        dispatches = []
                    variant_tasks = [
                        d for d in dispatches
                        if d.get("agent_role") == "vulnerability-analyst"
                        and any(
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
