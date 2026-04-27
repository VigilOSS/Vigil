"""aith assess resolve-surface — PATCH a surface by id.

Backend lifecycle states already exist (``covered``, ``not_applicable``,
``deferred``, ``discovered``); this helper drives ``PATCH /assessment/
surfaces/{id}`` so operators don't fall back to direct SQL when they need
to resolve a discovered surface after triage.

Usage::

    aith assess resolve-surface <id> --status covered --rationale "..."

The reason for the patch is appended to the existing rationale rather than
overwriting it, so the audit trail accumulates context across multiple
resolution attempts.
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.surfaces import RESOLVABLE_STATUSES, validate_resolution_status


def register(subparsers) -> None:
    valid_statuses = ", ".join(sorted(RESOLVABLE_STATUSES))
    p = subparsers.add_parser(
        "resolve-surface",
        help="PATCH an assessment surface by id (set status + rationale)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  aith assess resolve-surface 42 --status covered --rationale \"vulnerability-analyst confirmed coverage\"\n"
            "  aith assess resolve-surface 99 --status not_applicable --rationale \"static asset, no input vector\"\n"
            "  aith assess resolve-surface 17 --status deferred --rationale \"low-signal, revisit after Phase 5\"\n"
            f"\nValid statuses: {valid_statuses}"
        ),
    )
    p.add_argument("surface_id", type=int, help="Backend id of the surface row")
    p.add_argument(
        "--status",
        required=True,
        help=f"New surface status ({valid_statuses})",
    )
    p.add_argument(
        "--rationale",
        default="",
        help="Reason for the resolution; appended to existing rationale for the audit trail",
    )
    p.add_argument(
        "--source-name",
        default="",
        help="Optional override for source_name (defaults to keeping the existing value)",
    )
    p.add_argument(
        "--evidence-ref",
        default="",
        help="Optional new evidence reference (e.g. command-run id, scan path)",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    validate_resolution_status(args.status)

    payload: dict = {"status": args.status}
    if args.rationale:
        payload["rationale"] = args.rationale
    if args.source_name:
        payload["source_name"] = args.source_name
    if args.evidence_ref:
        payload["evidence_ref"] = args.evidence_ref

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        record = client.patch(f"surfaces/{args.surface_id}", payload)
    finally:
        client.close()

    if not isinstance(record, dict) or "id" not in record:
        print("resolve-surface: backend returned an unexpected response", file=sys.stderr)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        sys.exit(1)

    print(json.dumps(record, indent=2, ensure_ascii=False))
