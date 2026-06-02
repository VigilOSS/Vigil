"""vigil assess resolve-surface — PATCH a surface by id.

Backend lifecycle states already exist (``covered``, ``not_applicable``,
``deferred``, ``discovered``); this helper drives ``PATCH /assessment/
surfaces/{id}`` so operators don't fall back to direct SQL when they need
to resolve a discovered surface after triage.

Usage::

    vigil assess resolve-surface <id> --status covered --rationale "..."

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
            "  vigil assess resolve-surface 42 --status covered --rationale \"vulnerability-analyst confirmed coverage\"\n"
            "  vigil assess resolve-surface 99 --status not_applicable --rationale \"static asset, no input vector\"\n"
            "  vigil assess resolve-surface 17 --status deferred --rationale \"low-signal, revisit after Phase 5\"\n"
            "  vigil assess resolve-surface 31 --status partially-covered --rationale \"unauth path tested\" --followup-condition \"needs auth re-test\"\n"
            f"\nValid statuses: {valid_statuses}"
        ),
    )
    p.add_argument("surface_id", type=int, help="Backend id of the surface row")
    p.add_argument(
        "--status",
        required=True,
        choices=sorted(RESOLVABLE_STATUSES),
        type=lambda s: s.lower(),
        help=f"New surface status ({valid_statuses}). Case-insensitive.",
    )
    p.add_argument(
        "--rationale",
        required=True,
        help="Reason for the resolution; appended to existing rationale for the audit trail. Required.",
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
    p.add_argument(
        "--followup-condition",
        default="",
        help=(
            "Required when --status=partially-covered: one-line description of the "
            "condition the follow-up coverage pass must satisfy (e.g., 'needs auth re-test')."
        ),
    )
    p.set_defaults(func=run)


def run(args) -> None:
    validate_resolution_status(args.status)
    if not args.rationale.strip():
        sys.exit("--rationale must be non-empty")

    if args.status == "partially-covered" and not args.followup_condition.strip():
        sys.exit(
            "--followup-condition is required when --status=partially-covered "
            "(one-line description of what the follow-up coverage pass must satisfy)"
        )

    payload: dict = {"status": args.status, "rationale": args.rationale}
    if args.source_name:
        payload["source_name"] = args.source_name
    if args.evidence_ref:
        payload["evidence_ref"] = args.evidence_ref
    if args.followup_condition:
        payload["followup_condition"] = args.followup_condition

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        record = client.patch(f"surfaces/{args.surface_id}", payload)

    if not isinstance(record, dict) or "id" not in record:
        print("resolve-surface: backend returned an unexpected response", file=sys.stderr)
        print(json.dumps(record, indent=2, ensure_ascii=False))
        sys.exit(1)

    print(json.dumps(record, indent=2, ensure_ascii=False))
