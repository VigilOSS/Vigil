"""vigil assess patch — generic PATCH for findings, coverage items, and similar endpoints."""
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
        "patch",
        help="PATCH /assessment/{endpoint} with a JSON file or inline JSON payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Generic PATCH escape hatch for endpoints without a dedicated verb.\n"
            "Dedicated verbs own the common targets — use those, not raw patch:\n"
            "  coverage items  -> vigil assess resolve-coverage-item <id> --status covered --rationale \"...\"\n"
            "  surfaces        -> vigil assess resolve-surface <id> --status covered --rationale \"...\"\n"
            "  findings        -> vigil assess update-finding <slug> ...\n"
            "(raw patch to coverage-items/{id} and findings/{slug} is redirected to those verbs)"
        ),
    )
    p.add_argument("endpoint", help="e.g. intel/42 — an endpoint without a dedicated verb (coverage-items/findings/surfaces have dedicated verbs)")
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
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.patch(args.endpoint, payload)
        print(json.dumps(result, indent=2, ensure_ascii=False))
