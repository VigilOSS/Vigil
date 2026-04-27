"""aith assess update-intel — patch an intel row by id.

Mirrors ``update-finding`` for intel rows. Use this when an existing intel
row needs an in-place metadata update (severity refinement, new
``evidence_ref`` after re-investigation, etc.) — the backend keeps a
single canonical row and refreshes the FTS shadow so search reflects the
new body.

Use ``supersede-intel`` instead when you want to keep the old record for
audit and insert a wholly new row that replaces it.

Usage::

    aith assess update-intel <type> <id> <patch-json-file>
    aith assess update-intel <type> <id> --inline '{"...": "..."}'
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.intel_types import INTEL_TYPES
from assess.lib.json_inputs import parse_json_argument


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "update-intel",
        help="PATCH an intel row by id (in-place update)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  aith assess update-intel tech-component 42 patch.json\n"
            "  aith assess update-intel cve 17 --inline '{\"validation_status\": \"exploited\"}'\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument("intel_id", type=int, help="Backend id of the intel row to patch")
    p.add_argument(
        "payload",
        nargs="?",
        help="Path to JSON patch payload or inline JSON object",
    )
    p.add_argument(
        "--inline",
        dest="inline_payload",
        help="Raw JSON patch payload as a string",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    if args.intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{args.intel_type}'. Valid: {', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)
    _, endpoint_segment = INTEL_TYPES[args.intel_type]

    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print(
            "update-intel: provide a JSON patch file path or --inline JSON payload",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        patch_payload, _ = parse_json_argument(
            raw_payload,
            inline=args.inline_payload is not None,
            description="intel patch payload",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(patch_payload, dict) or not patch_payload:
        print("update-intel: payload must be a non-empty JSON object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        # Engagement-scoped patch: hand-craft the path because the
        # AssessmentClient.patch helper is hardwired to /assessment.
        from urllib.parse import quote

        path = (
            f"{client._engagement_prefix}/intel/{quote(endpoint_segment)}/{int(args.intel_id)}"
        )
        body = json.dumps({"payload": patch_payload}, ensure_ascii=True).encode("utf-8")
        _, resp_body = client._request("PATCH", path, body=body)
        try:
            record = json.loads(resp_body)
        except json.JSONDecodeError:
            record = {"raw": resp_body}
    finally:
        client.close()

    print(json.dumps(record, indent=2, ensure_ascii=False))
