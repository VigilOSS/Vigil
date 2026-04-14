"""assess.py kill-finding — false-positive verification helper."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "kill-finding",
        help="Verify a finding as false_positive without writing a JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("kill-finding"),
    )
    p.add_argument("finding_slug", help="Canonical finding slug")
    p.add_argument("payload", nargs="?", help="Path to a JSON verification payload or inline JSON object")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON verification payload")
    p.add_argument("--reason", dest="reason_text", help="Why the finding is a false positive")
    p.add_argument("--reason-code", default="")
    p.add_argument("--kill-reason", help="Stored as details.kill_reason")
    p.add_argument("--kill-check", type=int, help="Stored as details.kill_check")
    p.add_argument("--evidence-ref", default="")
    p.add_argument("--artifact-ref", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--source-name", default="")
    p.add_argument("--details-inline", help="Inline JSON object merged into details")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance")
    p.set_defaults(func=run)


def run(args) -> None:
    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=args.inline_payload is not None,
                description="false-positive verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.reason_text or not args.kill_reason or args.kill_check is None:
            print(
                "kill-finding requires --reason, --kill-reason, and --kill-check unless you supply a payload",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            details = parse_optional_inline_json(
                args.details_inline,
                default={},
                description="details JSON",
            )
            provenance = parse_optional_inline_json(
                args.provenance_inline,
                default={},
                description="provenance JSON",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
        if not isinstance(details, dict):
            print("details JSON must be an object", file=sys.stderr)
            sys.exit(1)
        if not isinstance(provenance, dict):
            print("provenance JSON must be an object", file=sys.stderr)
            sys.exit(1)
        details["kill_reason"] = args.kill_reason
        details["kill_check"] = args.kill_check
        payload = {
            "disposition": "false_positive",
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "evidence_ref": args.evidence_ref,
            "artifact_ref": args.artifact_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
        }

    if not isinstance(payload, dict):
        print("kill-finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if payload.get("disposition") != "false_positive":
        print("kill-finding payload disposition must be false_positive", file=sys.stderr)
        sys.exit(1)
    details = payload.get("details") or {}
    if not isinstance(details, dict) or not details.get("kill_reason") or details.get("kill_check") is None:
        print("kill-finding requires details.kill_reason and details.kill_check", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post(f"findings/{args.finding_slug}/verify", payload)
    finally:
        client.close()

    print(json.dumps(result, indent=2, ensure_ascii=False))
