"""assess.py record-surface — POST surface + jsonl sync + emit event."""
from __future__ import annotations

import json
import os
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.surfaces import upsert_surface_record


def register(subparsers) -> None:
    p = subparsers.add_parser("record-surface", help="Record a surface candidate")
    p.add_argument("type", help="Surface type (e.g. auth_entry, object_reference)")
    p.add_argument("target", help="Target descriptor (URL or identifier)")
    p.add_argument("source", help="Source agent or process name")
    p.add_argument("--rationale", default="", help="Rationale for the surface")
    p.add_argument("--evidence-ref", default="", help="Evidence reference")
    p.add_argument("--status", default="discovered", help="Surface status")
    p.set_defaults(func=run)


def run(args) -> None:
    from assess.lib.surfaces import validate_surface_type, validate_surface_status
    validate_surface_type(args.type)
    validate_surface_status(args.status)

    cfg = load_config(args.engagement_dir)

    payload = {
        "surface_type": args.type,
        "target_descriptor": args.target,
        "source_name": args.source,
        "rationale": args.rationale,
        "evidence_ref": args.evidence_ref,
        "status": args.status,
    }

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        response = client.post("surfaces", payload)
    finally:
        client.close()

    # Validate response
    if not response.get("surface_type") or not response.get("target_descriptor"):
        print("record-surface: orchestrator backend did not return a canonical surface record", file=sys.stderr)
        sys.exit(1)

    # Sync to surfaces.jsonl
    upsert_surface_record(
        cfg.engagement_dir,
        args.type,
        args.target,
        args.source,
        args.rationale,
        args.evidence_ref,
        args.status,
    )

    # Emit event
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post_event({
            "event_type": "surface.updated",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": args.type,
            "agent_name": args.source,
            "summary": f"{args.type} {args.status}: {args.target}",
        })
    finally:
        client.close()

    print(f"Recorded surface: {args.type} {args.target}")
