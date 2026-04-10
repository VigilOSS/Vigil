"""assess.py post — generic POST for low-frequency endpoints."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import raw_endpoint_error
from assess.lib.json_inputs import parse_json_argument


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "post",
        help="POST /assessment/{endpoint} with a JSON file or inline JSON payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  assess.py post credentials payload.json\n"
            "  assess.py post blocked-techniques payload.json"
        ),
    )
    p.add_argument("endpoint", help="e.g. credentials, credential-tests, access-records, blocked-techniques, probe-runs")
    p.add_argument("payload", nargs="?", help="Path to JSON payload file or inline JSON object/array")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON payload text")
    p.set_defaults(func=run)


def run(args) -> None:
    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print("POST requires a JSON payload file or --inline JSON text", file=sys.stderr)
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
    error = raw_endpoint_error("POST", args.endpoint, payload)
    if error:
        print(error, file=sys.stderr)
        sys.exit(1)
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post(args.endpoint, payload)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()
