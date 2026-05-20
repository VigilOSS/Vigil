"""aith assess approve-proposal — operator-approval ledger PATCH.

Marks a containment-proposal decision row (kind=``containment_proposal``)
as ``resolved=1`` with ``resolution_json={"approved_by": <name>,
"approved_at": <utc-iso>}``. ``aith blue contain`` refuses to execute
unless the proposal it references is approved here first.

Backend endpoint: PATCH /engagements/{key}/dispatch-decisions/{id} with
``{"resolved": true, "resolution": {...}}`` (see
orchestrator/backend/app/api/assessment.py:1980).
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "approve-proposal",
        help="Mark a containment-proposal decision row as approved.",
    )
    p.add_argument(
        "decision_id",
        type=int,
        help="dispatch-decisions row id (printed by `aith blue propose-contain`)",
    )
    p.add_argument(
        "--approved-by",
        default="operator",
        help="Name of the human approver (recorded in resolution_json).",
    )
    p.add_argument(
        "--note",
        default=None,
        help="Optional free-form note attached to the approval.",
    )
    p.set_defaults(func=run)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    resolution: dict[str, str] = {
        "approved_by": str(args.approved_by or "operator"),
        "approved_at": _utcnow_iso(),
    }
    if args.note:
        resolution["note"] = args.note

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        decisions = client.list_all_decisions(kind="containment_proposal")
        decision = next(
            (row for row in decisions if isinstance(row, dict) and int(row.get("id") or -1) == int(args.decision_id)),
            None,
        )
        if decision is None:
            print(
                f"approve-proposal: decision id {args.decision_id} not found",
                file=sys.stderr,
            )
            sys.exit(1)
        if decision.get("kind") != "containment_proposal":
            print(
                f"approve-proposal: decision id {args.decision_id} has kind={decision.get('kind')!r}; "
                "expected 'containment_proposal'",
                file=sys.stderr,
            )
            sys.exit(1)
        row = client.update_decision(
            int(args.decision_id),
            {"resolved": True, "resolution": resolution},
        )
    finally:
        client.close()

    if not isinstance(row, dict):
        print("approve-proposal: unexpected response shape from backend", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(row, ensure_ascii=False, indent=2))
