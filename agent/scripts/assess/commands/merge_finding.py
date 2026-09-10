"""vigil assess finding merge — POST merge + emit event."""
from __future__ import annotations

import os
import sys

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("merge", help="Merge one finding into another")
    p.add_argument("source_slug", help="Source finding slug (will be merged away)")
    p.add_argument("target_slug", help="Target finding slug (will absorb source)")
    p.add_argument("reason", help="Reason for the merge")
    p.add_argument("--expected-source-row-version", type=int)
    p.add_argument("--expected-target-row-version", type=int)
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    payload = {
        "source_slug": args.source_slug,
        "target_slug": args.target_slug,
        "reason": args.reason,
        "source_name": "operator",
        "expected_source_row_version": getattr(args, "expected_source_row_version", None),
        "expected_target_row_version": getattr(args, "expected_target_row_version", None),
    }
    payload = {key: value for key, value in payload.items() if value is not None}

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = require_write_result(
            client.post("findings/merge", payload),
            operation="merge findings",
            expected={"slug": args.target_slug},
        )

    # Emit event
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": "finding.merged",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": args.source_slug,
            "agent_name": "operator",
            "summary": f"Merged {args.source_slug} into {args.target_slug}: {args.reason}",
        })

    # A merge that inherited a contradictory CVSS pair still completes (refusing
    # would strand two duplicates the agent correctly identified), so the backend
    # reports the defect instead. Relay it: the API and websocket consumers see
    # `warnings`, and a CLI agent would otherwise only learn about it much later,
    # from a blocked report-readiness check.
    for warning in (result or {}).get("warnings") or []:
        print(f"finding merge: {warning}", file=sys.stderr)

    print(f"Merged {args.source_slug} into {args.target_slug}")
