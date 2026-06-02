"""vigil assess list-finding-group — inspect a root-cause finding group."""
from __future__ import annotations

import argparse
import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-finding-group",
        help="Show a root-cause finding and its linked sibling findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("list-finding-group"),
    )
    p.add_argument("root_slug", help="Root-cause finding slug")
    p.add_argument("--json", action="store_true", help="Print the full JSON projection")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        group = client.get(f"finding-groups/{args.root_slug}")

    if args.json:
        print(json.dumps(group, indent=2, ensure_ascii=False))
        return

    root = group.get("root", {})
    print(f"Root: {root.get('slug', args.root_slug)} [{root.get('severity', 'info')}] {root.get('title', '')}")
    print(f"Siblings: {group.get('sibling_count', 0)}")
    for sibling in group.get("siblings", []):
        order = sibling.get("sibling_order")
        prefix = f"{order}. " if order is not None else "- "
        effect = sibling.get("root_cause_effect", "eliminates_finding")
        residual = " residual path" if effect == "eliminates_attack_path" else ""
        print(
            f"{prefix}{sibling.get('slug', '')} [{sibling.get('severity', 'info')}]"
            f"{residual} - {sibling.get('title', '')}"
        )
        note = sibling.get("root_cause_note", "")
        if note:
            print(f"   note: {note}")
