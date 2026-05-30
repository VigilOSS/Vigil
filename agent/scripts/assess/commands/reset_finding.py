"""aith assess reset-finding — reopen a finding for re-triage."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "reset-finding",
        help="Reset a finding out of false_positive/verified state back into the workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("reset-finding"),
    )
    p.add_argument("finding_slug", help="Canonical finding slug")
    p.add_argument("--workflow-status", "--status", dest="workflow_status", default="draft")
    p.add_argument("--severity")
    p.add_argument("--reason", dest="reason_text", required=True, help="Why the finding is being reset")
    p.add_argument("--reason-code", default="")
    p.add_argument("--artifact-ref", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--source-name", default="")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance")
    p.set_defaults(func=run)


def run(args) -> None:
    try:
        provenance = parse_optional_inline_json(
            args.provenance_inline,
            default=None,
            description="provenance JSON",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if provenance is not None and not isinstance(provenance, dict):
        print("provenance JSON must be an object", file=sys.stderr)
        sys.exit(1)

    payload = {
        "workflow_status": args.workflow_status,
        "severity": args.severity,
        "reason_code": args.reason_code,
        "reason_text": args.reason_text,
        "artifact_ref": args.artifact_ref,
        "notes": args.notes,
        "source_name": args.source_name,
        "provenance": provenance,
    }
    payload = {key: value for key, value in payload.items() if value is not None}

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.patch(f"findings/{args.finding_slug}", payload)

    print(json.dumps(result, indent=2, ensure_ascii=False))
