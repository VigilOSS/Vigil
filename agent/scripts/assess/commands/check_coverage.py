"""assess.py check-coverage — query backend surfaces, report unresolved."""
from __future__ import annotations

import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


_STRICT_DEFERRED_TYPES = frozenset({
    "account_recovery",
    "dynamic_render",
    "object_reference",
    "privileged_write",
})


def register(subparsers) -> None:
    p = subparsers.add_parser("check-coverage", help="Check surface coverage status")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        surfaces = client.get("surfaces")
    finally:
        client.close()

    if not isinstance(surfaces, list):
        print("check-coverage: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    unresolved = []
    blocked_deferred = []

    for row in surfaces:
        surface_type = row.get("surface_type")
        target = row.get("target_descriptor")
        status = row.get("status")

        if status == "discovered":
            unresolved.append(f"{surface_type} | {target}")
        elif status == "deferred" and surface_type in _STRICT_DEFERRED_TYPES:
            blocked_deferred.append(f"{surface_type} | {target}")

    if unresolved or blocked_deferred:
        if unresolved:
            print("Uncovered surfaces remain:", file=sys.stderr)
            for item in unresolved:
                print(f"  - {item}", file=sys.stderr)
        if blocked_deferred:
            print("High-risk surfaces cannot remain deferred:", file=sys.stderr)
            for item in blocked_deferred:
                print(f"  - {item}", file=sys.stderr)
            print("Resolve them as covered or not_applicable before finishing Test/Report.", file=sys.stderr)
        sys.exit(1)

    print("surface coverage: ok")
