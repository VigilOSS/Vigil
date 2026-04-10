"""assess.py patch — generic PATCH for findings, coverage items, and similar endpoints."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import raw_endpoint_error
from assess.lib.findings import sync_finding_markdown, update_finding_count
from assess.lib.json_inputs import parse_json_argument


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "patch",
        help="PATCH /assessment/{endpoint} with a JSON file or inline JSON payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  assess.py patch coverage-items/42 payload.json\n"
            "  assess.py patch coverage-items/42 --inline '{\"status\":\"covered\"}'"
        ),
    )
    p.add_argument("endpoint", help="e.g. coverage-items/42 or findings/FINDING-VA-001")
    p.add_argument("payload", nargs="?", help="Path to JSON payload file or inline JSON object")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON payload text")
    p.set_defaults(func=run)


def run(args) -> None:
    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print("PATCH requires a JSON payload file or --inline JSON text", file=sys.stderr)
        sys.exit(1)
    try:
        payload, _ = parse_json_argument(
            raw_payload,
            inline=args.inline_payload is not None,
            description="JSON payload",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("PATCH payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    error = raw_endpoint_error("PATCH", args.endpoint, payload)
    if error:
        print(error, file=sys.stderr)
        sys.exit(1)
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.patch(args.endpoint, payload)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()

    if args.endpoint.startswith("findings/") and isinstance(result, dict):
        finding = result.get("finding")
        findings_file = Path(cfg.engagement_dir) / "findings.md"
        if isinstance(finding, dict) and findings_file.is_file():
            sync_finding_markdown(str(findings_file), finding)
            update_finding_count(str(findings_file))
