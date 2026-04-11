"""assess.py verify-finding — dedicated verifier flow for canonical findings."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.findings import sync_finding_markdown, update_finding_count
from assess.lib.json_inputs import parse_json_argument, parse_optional_inline_json


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "verify-finding",
        help="Verify a finding with a JSON payload file, inline JSON, or explicit flags",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("verify-finding"),
    )
    p.add_argument("finding_slug", help="Canonical finding slug to verify")
    p.add_argument("payload", nargs="?", help="Path to JSON verification payload or inline JSON object")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON verification payload")
    p.add_argument(
        "--disposition",
        choices=("confirmed", "downgraded", "false_positive", "disputed"),
        help="Verification disposition when building the payload from flags",
    )
    p.add_argument("--reason", dest="reason_text", help="Required verification rationale when building payload from flags")
    p.add_argument("--reason-code", default="", help="Optional machine-readable reason code")
    p.add_argument("--new-severity", help="Required for downgraded verification")
    p.add_argument("--evidence-ref", default="", help="Optional evidence reference")
    p.add_argument("--artifact-ref", default="", help="Optional artifact reference")
    p.add_argument("--notes", default="", help="Optional verification notes")
    p.add_argument("--source-name", default="", help="Optional source/agent name")
    p.add_argument("--details-inline", help="Inline JSON object merged into the details payload")
    p.add_argument("--provenance-inline", help="Inline JSON object for provenance metadata")
    p.add_argument("--kill-reason", help="False-positive kill reason; stored as details.kill_reason")
    p.add_argument("--kill-check", type=int, help="False-positive kill check index; stored as details.kill_check")
    p.set_defaults(func=run)


def run(args) -> None:
    inline_payload = getattr(args, "inline_payload", None)
    raw_payload = inline_payload if inline_payload is not None else getattr(args, "payload", getattr(args, "json_file", None))
    if raw_payload is not None:
        try:
            payload, _ = parse_json_argument(
                raw_payload,
                inline=inline_payload is not None,
                description="verification payload",
            )
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(1)
    else:
        if not args.disposition or not args.reason_text:
            print(
                "verify-finding requires a payload file, --inline JSON, or both --disposition and --reason",
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
        if args.kill_reason:
            details["kill_reason"] = args.kill_reason
        if args.kill_check is not None:
            details["kill_check"] = args.kill_check
        payload = {
            "disposition": args.disposition,
            "reason_code": args.reason_code,
            "reason_text": args.reason_text,
            "new_severity": args.new_severity,
            "evidence_ref": args.evidence_ref,
            "artifact_ref": args.artifact_ref,
            "notes": args.notes,
            "source_name": args.source_name,
            "details": details,
            "provenance": provenance,
        }

    if not isinstance(payload, dict):
        print("verification payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if payload.get("disposition") == "false_positive":
        details = payload.get("details") or {}
        if not isinstance(details, dict):
            print("false_positive verification details must be a JSON object", file=sys.stderr)
            sys.exit(1)
        if not details.get("kill_reason") or details.get("kill_check") is None:
            print(
                "false_positive verification requires details.kill_reason and details.kill_check",
                file=sys.stderr,
            )
            sys.exit(1)
    if payload.get("disposition") == "downgraded" and not payload.get("new_severity"):
        print("downgraded verification requires new_severity", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post(f"findings/{args.finding_slug}/verify", payload)
    finally:
        client.close()

    findings_file = Path(cfg.engagement_dir) / "findings.md"
    finding = result.get("finding")
    if isinstance(finding, dict) and findings_file.is_file():
        sync_finding_markdown(str(findings_file), finding)
        update_finding_count(str(findings_file))

    print(json.dumps(result, indent=2, ensure_ascii=False))
