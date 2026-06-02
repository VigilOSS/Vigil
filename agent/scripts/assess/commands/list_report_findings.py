"""vigil assess list-report-findings - grouped report finding projection."""
from __future__ import annotations

import argparse
import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-report-findings",
        help="Show grouped findings exactly as report-writer should consume them",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("list-report-findings"),
    )
    p.add_argument("--mode", choices=["final", "draft"], default="final")
    p.add_argument("--json", action="store_true", help="Print the full grouped JSON projection")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        report = client.get(f"report-findings?mode={args.mode}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    groups = report.get("groups", []) if isinstance(report, dict) else []
    standalone = report.get("standalone", []) if isinstance(report, dict) else []
    print(
        f"Report findings ({args.mode}): "
        f"{len(groups)} root-cause groups, {len(standalone)} standalone findings"
    )
    for group in groups:
        root = group.get("root", {})
        print(
            f"- {root.get('report_id', '---')} {root.get('slug', '')} "
            f"[{group.get('highest_severity', root.get('severity', 'info'))}] "
            f"{root.get('title', '')}"
        )
        for sibling in group.get("siblings", []):
            effect = sibling.get("root_cause_effect", "eliminates_finding")
            marker = "residual" if effect == "eliminates_attack_path" else "resolved-by-root"
            print(
                f"  - {sibling.get('slug', '')} [{sibling.get('severity', 'info')}] "
                f"{marker}: {sibling.get('title', '')}"
            )
    if standalone:
        print("Standalone:")
        for finding in standalone:
            print(
                f"- {finding.get('report_id', '---')} {finding.get('slug', '')} "
                f"[{finding.get('severity', 'info')}] {finding.get('title', '')}"
            )
