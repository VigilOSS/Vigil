"""aith assess supersede-intel — replace an intel row with a new one.

The old row stays in the table for audit but gets ``superseded_by_id``
populated so report-writer's filter excludes it from output. Use this
when an existing intel row is wrong but the operator wants to retain the
prior observation (because changing the natural key would lose history).

Use ``update-intel`` instead for in-place edits where the prior shape was
correct and only metadata changed.

Usage::

    aith assess supersede-intel <type> <id> <new-payload-json-file> --rationale "..."
    aith assess supersede-intel <type> <id> --inline '{...}' --rationale "..."
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.intel_types import INTEL_TYPES
from assess.lib.json_inputs import parse_json_argument
from assess.lib.schema_validation import collect_validation_errors, load_schema


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "supersede-intel",
        help="Replace an intel row with a new payload; old row marked superseded",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  aith assess supersede-intel tech-component 42 new.json --rationale \"banner re-fingerprinted\"\n"
            "  aith assess supersede-intel cve 17 --inline '{\"cve_id\":\"CVE-2025-1\",\"affected_component\":\"x\"}' --rationale \"prior CVE was a false match\"\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument("intel_id", type=int, help="Backend id of the intel row being superseded")
    p.add_argument(
        "payload",
        nargs="?",
        help="Path to the new intel JSON payload, or inline JSON object",
    )
    p.add_argument(
        "--inline",
        dest="inline_payload",
        help="Raw JSON payload string for the new intel record",
    )
    p.add_argument(
        "--rationale",
        default="",
        help="Reason for supersede; appended to the old row's notes for audit",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    if args.intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{args.intel_type}'. Valid: {', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)
    schema_name, endpoint_segment = INTEL_TYPES[args.intel_type]

    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print(
            "supersede-intel: provide a JSON payload file path or --inline JSON",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        new_payload, _ = parse_json_argument(
            raw_payload,
            inline=args.inline_payload is not None,
            description="supersede payload",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(new_payload, dict) or not new_payload:
        print("supersede-intel: payload must be a non-empty JSON object", file=sys.stderr)
        sys.exit(1)

    schema = load_schema(schema_name)
    errors = collect_validation_errors(new_payload, schema)
    if errors:
        print(f"supersede-intel {args.intel_type}: payload failed schema validation:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        from urllib.parse import quote

        path = (
            f"{client._engagement_prefix}/intel/{quote(endpoint_segment)}/{int(args.intel_id)}/supersede"
        )
        body = json.dumps(
            {"payload": new_payload, "rationale": args.rationale},
            ensure_ascii=True,
        ).encode("utf-8")
        _, resp_body = client._request("POST", path, body=body)
        try:
            record = json.loads(resp_body)
        except json.JSONDecodeError:
            record = {"raw": resp_body}
    finally:
        client.close()

    print(json.dumps(record, indent=2, ensure_ascii=False))
