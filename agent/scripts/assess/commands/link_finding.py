"""aith assess link-finding — root-cause/sibling finding grouping helper."""
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
        "link-finding",
        help="Link a finding to a root-cause finding, or clear that link",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("link-finding"),
    )
    p.add_argument("finding_slug", help="Sibling finding slug to link")
    p.add_argument("--root-cause", dest="root_cause_slug", help="Root-cause finding slug")
    p.add_argument("--order", dest="sibling_order", type=int, help="Display order within the root-cause group")
    p.add_argument(
        "--effect",
        dest="root_cause_effect",
        choices=["eliminates_finding", "eliminates_attack_path"],
        default="eliminates_finding",
        help="Whether fixing the root fully resolves the finding or only this attack path",
    )
    p.add_argument("--note", default="", help="One-sentence relationship note")
    p.add_argument("--source-name", default="operator")
    p.add_argument("--provenance-inline", help="Inline JSON object merged into link provenance")
    p.add_argument("--clear-root-cause", action="store_true", help="Remove the root-cause link from this finding")
    p.set_defaults(func=run)


def run(args) -> None:
    if args.clear_root_cause and args.root_cause_slug:
        print("link-finding: --clear-root-cause cannot be combined with --root-cause", file=sys.stderr)
        sys.exit(1)
    if not args.clear_root_cause and not args.root_cause_slug:
        print("link-finding requires --root-cause <slug> or --clear-root-cause", file=sys.stderr)
        sys.exit(1)
    try:
        provenance = parse_optional_inline_json(
            args.provenance_inline,
            default={},
            description="provenance JSON",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(provenance, dict):
        print("provenance JSON must be an object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        if args.clear_root_cause:
            result = client.delete(f"findings/{args.finding_slug}/root-cause")
        else:
            payload = {
                "root_cause_slug": args.root_cause_slug,
                "sibling_order": args.sibling_order,
                "root_cause_effect": args.root_cause_effect,
                "note": args.note,
                "source_name": args.source_name,
                "provenance": provenance,
            }
            result = client.put(f"findings/{args.finding_slug}/root-cause", payload)
    finally:
        client.close()

    print(json.dumps(result, indent=2, ensure_ascii=False))
