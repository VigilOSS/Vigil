"""vigil assess approve-proposal — operator-approval ledger PATCH.

Marks a containment-proposal decision row (kind=``containment_proposal``)
as ``resolved=true`` with ``resolution={"approved_by": <name>,
"approved_at": <utc-iso>}``. ``vigil blue contain`` refuses to execute
unless the proposal it references is approved here first.

Backend endpoint: PATCH /engagements/{key}/assessment/dispatch-decisions/{id}
with ``{"resolved": true, "resolution": {...}}`` (see ``patch_decision`` in
orchestrator/backend/app/api/assessment.py).
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
        nargs="+",
        help="One or more dispatch-decisions row ids (printed by `vigil blue propose-contain`). "
             "Batch: every listed proposal is approved by the same --approved-by/--note (resilient "
             "loop with a per-id failure tally).",
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

    decision_ids = args.decision_id if isinstance(args.decision_id, list) else [args.decision_id]
    rows: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        decisions = client.list_all_decisions(kind="containment_proposal")
        by_id = {int(row.get("id") or -1): row for row in decisions if isinstance(row, dict)}
        for decision_id in decision_ids:
            decision = by_id.get(int(decision_id))
            if decision is None:
                failed += 1
                print(
                    f"approve-proposal: decision id {decision_id} not found",
                    file=sys.stderr,
                )
                continue
            if decision.get("kind") != "containment_proposal":
                failed += 1
                print(
                    f"approve-proposal: decision id {decision_id} has kind={decision.get('kind')!r}; "
                    "expected 'containment_proposal'",
                    file=sys.stderr,
                )
                continue
            row = client.update_decision(
                int(decision_id),
                {"resolved": True, "resolution": resolution},
            )
            if not isinstance(row, dict):
                failed += 1
                print(
                    f"approve-proposal: unexpected response shape from backend for id {decision_id}",
                    file=sys.stderr,
                )
                continue
            rows.append(row)

    if len(decision_ids) == 1 and rows:
        print(json.dumps(rows[0], ensure_ascii=False, indent=2))
    else:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
        print(
            f"[approve-proposal] approved {len(rows)} proposal(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
