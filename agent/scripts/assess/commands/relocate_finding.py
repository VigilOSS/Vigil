"""vigil assess finding relocate — audited canonical-location relocation."""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import quote

from assess.lib.client import AssessmentClient, require_finding_write_response
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_optional_inline_json


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "relocate",
        help="Relocate a finding's canonical location with audited invalidation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding relocate"),
    )
    parser.add_argument("finding_slug", help="Canonical finding slug")
    parser.add_argument(
        "--canonical-location",
        required=True,
        help="New canonical location, including file: source locations",
    )
    parser.add_argument(
        "--reason",
        dest="reason_text",
        required=True,
        help="Why the canonical defect location changed",
    )
    parser.add_argument(
        "--source-name",
        default="operator",
        help="Actor authoring the relocation (default: operator)",
    )
    parser.add_argument(
        "--expected-row-version",
        required=True,
        type=int,
        help="Reject the relocation if the finding changed after this row version",
    )
    parser.add_argument(
        "--provenance-inline",
        help=(
            "Optional JSON provenance object; relocation into file: requires the "
            "current code_snapshot binding"
        ),
    )
    parser.set_defaults(func=run)


def _fail(message: str) -> None:
    print(f"finding relocate: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(args) -> None:
    canonical_location = str(args.canonical_location).strip()
    reason_text = str(args.reason_text).strip()
    source_name = str(args.source_name).strip()
    if not canonical_location:
        _fail("--canonical-location must not be empty")
    if not reason_text:
        _fail("--reason must not be empty")
    if not source_name:
        _fail("--source-name must not be empty")
    if args.expected_row_version < 1:
        _fail("--expected-row-version must be a positive integer")

    try:
        provenance = parse_optional_inline_json(
            args.provenance_inline,
            default=None,
            description="provenance JSON",
        )
    except ValueError as exc:
        _fail(str(exc))
    if provenance is not None and not isinstance(provenance, dict):
        _fail("provenance JSON must be an object")

    payload: dict[str, object] = {
        "canonical_location": canonical_location,
        "reason_text": reason_text,
        "source_name": source_name,
        "expected_row_version": args.expected_row_version,
    }
    if provenance is not None:
        payload["provenance"] = provenance

    cfg = load_config(args.engagement_dir)
    finding_slug = str(args.finding_slug)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        response = require_finding_write_response(
            client.put(
                f"findings/{quote(finding_slug, safe='')}/canonical-location",
                payload,
            ),
            finding_slug=finding_slug,
            operation="finding relocate",
        )
    print(json.dumps(response, indent=2, ensure_ascii=False))
