"""vigil assess resolve-coverage-item — PATCH a coverage item by id.

The class-typed coverage items are seeded ``pending`` by the gf-bucket bridge at
ingest (one per implied vuln-class on a surface). A specialist advances a
coverage item's status once it has tested (or ruled out) that class on that
surface. This drives ``PATCH /assessment/coverage-items/{id}`` — the dedicated
typed verb for resolving a coverage item.

Statuses mirror the backend ``CoverageStatus`` vocabulary (source of truth:
``orchestrator/backend/app/services/state_manager/coverage.py``): ``covered`` /
``not_applicable`` are the resolved-positive verdicts; ``deferred`` / ``blocked``
/ ``queued`` / ``pending`` carry the item's workflow state. ``--rationale`` is
required for EVERY resolution (the audit trail — a resolution with no stated
reason, including a reasonless deferral, is the unaccountable state this ledger
exists to prevent) and is appended to the item's existing notes. The backend
independently rejects an empty rationale for ``covered`` / ``not_applicable``.

Usage::

    vigil assess resolve-coverage-item <id> --status covered --rationale "..."
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import add_contract_subparser, render_contract_epilog

# Mirrors backend CoverageStatus (coverage.py). The CLI cannot import the
# backend, so this list is kept in sync by test (test_coverage_probe_cli_sync in
# the backend suite) rather than shared code — same pattern as lib/surfaces.py
# for surface statuses.
COVERAGE_STATUSES = ("pending", "queued", "deferred", "covered", "not_applicable", "blocked")


def register(subparsers) -> None:
    valid_statuses = ", ".join(COVERAGE_STATUSES)
    p = add_contract_subparser(
        subparsers,
        "resolve-coverage-item",
        contract_name="resolve-coverage-item",
        help="PATCH a coverage item by id (set status + rationale).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("resolve-coverage-item"),
    )
    p.add_argument(
        "coverage_item_id",
        type=int,
        nargs="+",
        help="One or more backend coverage-item ids. Batch: every listed item gets the same "
             "--status/--rationale (resilient loop with a per-id failure tally).",
    )
    p.add_argument(
        "--status",
        required=True,
        choices=list(COVERAGE_STATUSES),
        type=lambda s: s.lower().replace("-", "_"),
        help=f"New coverage-item status ({valid_statuses}). Case-insensitive.",
    )
    p.add_argument(
        "--rationale",
        required=True,
        help="Reason for the resolution; appended to existing notes for the audit trail. Required for every status.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.rationale.strip():
        sys.exit("--rationale must be non-empty")

    payload = {"status": args.status, "notes": args.rationale}

    item_ids = args.coverage_item_id if isinstance(args.coverage_item_id, list) else [args.coverage_item_id]
    cfg = load_config(args.engagement_dir)
    records: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for item_id in item_ids:
            try:
                record = client.patch(f"coverage-items/{item_id}", payload)
            except Exception as exc:  # noqa: BLE001 - one bad id must not drop the rest
                failed += 1
                print(f"resolve-coverage-item: item {item_id} failed: {exc}", file=sys.stderr)
                continue
            if not isinstance(record, dict) or "id" not in record:
                failed += 1
                print(
                    f"resolve-coverage-item: item {item_id} returned an unexpected response",
                    file=sys.stderr,
                )
                continue
            records.append(record)

    if len(item_ids) == 1 and records:
        print(json.dumps(records[0], indent=2, ensure_ascii=False))
    else:
        for record in records:
            print(json.dumps(record, ensure_ascii=False))
        print(
            f"[resolve-coverage-item] resolved {len(records)} item(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
