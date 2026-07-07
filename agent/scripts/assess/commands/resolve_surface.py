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
            "  vigil assess resolve-surface 42 99 17 --status covered --rationale \"same triage verdict for all three\"\n"
            f"\nValid statuses: {valid_statuses}"
        ),
    )
    p.add_argument(
        "surface_id",
        type=int,
        nargs="+",
        help="One or more backend surface-row ids. Batch: every listed surface gets the same "
             "--status/--rationale/flags (resilient loop with a per-id failure tally).",
    )
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

    surface_ids = args.surface_id if isinstance(args.surface_id, list) else [args.surface_id]
    cfg = load_config(args.engagement_dir)
    records: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for surface_id in surface_ids:
            try:
                record = client.patch(f"surfaces/{surface_id}", payload)
            except Exception as exc:  # noqa: BLE001 - one bad id must not drop the rest
                failed += 1
                print(f"resolve-surface: surface {surface_id} failed: {exc}", file=sys.stderr)
                continue
            if not isinstance(record, dict) or "id" not in record:
                failed += 1
                print(
                    f"resolve-surface: surface {surface_id} returned an unexpected response",
                    file=sys.stderr,
                )
                continue
            records.append(record)

    if len(surface_ids) == 1 and records:
        print(json.dumps(records[0], indent=2, ensure_ascii=False))
    else:
        for record in records:
            print(json.dumps(record, ensure_ascii=False))
        print(
            f"[resolve-surface] resolved {len(records)} surface(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
