"""vigil assess check-coverage — query backend coverage readiness."""
from __future__ import annotations

import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("check-coverage", help="Check surface coverage status")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        readiness = client.get("coverage-readiness")

    if not isinstance(readiness, dict):
        print("check-coverage: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    unresolved = readiness.get("unresolved_surfaces") or []
    partially_covered = readiness.get("partially_covered_surfaces") or []
    blocked_deferred = readiness.get("high_risk_deferred_surfaces") or []

    if not readiness.get("ready", False):
        if unresolved:
            print("Uncovered surfaces remain:", file=sys.stderr)
            for item in unresolved:
                print(f"  - {item.get('surface_type')} | {item.get('target_descriptor')}", file=sys.stderr)
        if partially_covered:
            print("Partially covered surfaces need follow-up:", file=sys.stderr)
            for item in partially_covered:
                print(
                    f"  - {item.get('surface_type')} | {item.get('target_descriptor')} | {item.get('followup_condition')}",
                    file=sys.stderr,
                )
        if blocked_deferred:
            print("High-risk surfaces cannot remain deferred:", file=sys.stderr)
            for item in blocked_deferred:
                print(f"  - {item.get('surface_type')} | {item.get('target_descriptor')}", file=sys.stderr)
            print("Resolve them as covered or not_applicable before finishing Test/Report.", file=sys.stderr)
        sys.exit(1)

    print("surface coverage: ok")
