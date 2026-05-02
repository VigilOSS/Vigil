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
from assess.lib.config import load_config


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
    p.set_defaults(func=run)


def run(args) -> None:
    engagement_dir = args.engagement_dir
    if not engagement_dir:
        engagement_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if not engagement_dir:
        print("transition-phase: ENGAGEMENT_DIR not set", file=sys.stderr)
        sys.exit(2)

    scope_path = os.path.join(engagement_dir, "scope.json")
    if not os.path.isfile(scope_path):
        print(f"transition-phase: {scope_path} not found", file=sys.stderr)
        sys.exit(2)

    with open(scope_path) as f:
        scope = json.load(f)

    current_phase = scope.get("current_phase", "")
    target_phase = args.target_phase
    engagement_type = scope.get("engagement_type", "web")

    if engagement_type == "code":
        order = CODE_TRANSITION_ORDER
        phases = CODE_PHASES
    else:
        order = WEB_TRANSITION_ORDER
        phases = WEB_PHASES

    if target_phase not in order:
        print(
            f"transition-phase: unknown phase '{target_phase}' "
            f"for engagement type '{engagement_type}'. "
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
        target_phase, engagement_type, engagement_dir, args,
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

    scope["current_phase"] = target_phase
    tmp_path = scope_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(scope, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp_path, scope_path)

    print(f"Phase transitioned: {current_phase or '(none)'} -> {target_phase}")


def _check_preconditions(
    target_phase: str,
    engagement_type: str,
    engagement_dir: str,
    args,
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []

    cfg = load_config(engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    try:
        if engagement_type == "code":
            blockers.extend(_check_code_preconditions(target_phase, client))
        else:
            blockers.extend(_check_web_preconditions(target_phase, engagement_dir, client))
    finally:
        client.close()

    return blockers


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
        except Exception:
            pass

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
            except Exception:
                pass

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
        except Exception:
            pass

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
        except Exception:
            pass

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
        except Exception:
            pass

    elif target_phase == "complete":
        try:
            readiness = client.get("report-readiness")
            if isinstance(readiness, dict) and not readiness.get("ready", False):
                blockers.append({
                    "kind": "report_not_ready",
                    "detail": "Report readiness check has blockers",
                })
        except Exception:
            pass

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
        except Exception:
            pass

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
        except Exception:
            pass

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
        except Exception:
            pass

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
        except Exception:
            pass

    return blockers
