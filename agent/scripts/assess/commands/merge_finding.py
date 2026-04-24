"""aith assess merge-finding — POST merge + emit event."""
from __future__ import annotations

import os
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("merge-finding", help="Merge one finding into another")
    p.add_argument("source_slug", help="Source finding slug (will be merged away)")
    p.add_argument("target_slug", help="Target finding slug (will absorb source)")
    p.add_argument("reason", help="Reason for the merge")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    payload = {
        "source_slug": args.source_slug,
        "target_slug": args.target_slug,
        "reason": args.reason,
        "source_name": "operator",
    }

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post("findings/merge", payload)
    finally:
        client.close()

    # Emit event
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post_event({
            "event_type": "finding.merged",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": args.source_slug,
            "agent_name": "operator",
            "summary": f"Merged {args.source_slug} into {args.target_slug}: {args.reason}",
        })
    finally:
        client.close()

    print(f"Merged {args.source_slug} into {args.target_slug}")
