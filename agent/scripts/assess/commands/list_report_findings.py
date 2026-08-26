"""vigil assess finding report - grouped report finding projection."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "report",
        help="Show grouped findings; final mode is report-readiness gated, draft mode is for inspection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding report"),
    )
    p.add_argument(
        "--mode",
        choices=["final", "draft"],
        default="final",
        help="final enforces report-readiness and may exit non-zero; draft always returns the grouped inspection view",
    )
    p.add_argument("--json", action="store_true", help="Print the full grouped JSON projection")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            report = client.get(f"report-findings?mode={args.mode}")
    except AssessError as exc:
        if args.mode == "final" and _is_report_readiness_conflict(exc):
            _print_readiness_conflict(exc)
            sys.exit(1)
        raise

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


def _is_report_readiness_conflict(exc: AssessError) -> bool:
    return str(exc).startswith("HTTP 409:")


def _readiness_detail(exc: AssessError) -> dict:
    _, _, body = str(exc).partition("\n")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {}
    detail = payload.get("detail") if isinstance(payload, dict) else {}
    return detail if isinstance(detail, dict) else {}


def _print_readiness_conflict(exc: AssessError) -> None:
    detail = _readiness_detail(exc)
    blockers = detail.get("blockers") if isinstance(detail.get("blockers"), list) else []
    blocker_count = detail.get("blocker_count", len(blockers))
    print("Final report blockers remain:", file=sys.stderr)
    print(f"  blocker_count: {blocker_count}", file=sys.stderr)
    for blocker in blockers[:10]:
        if not isinstance(blocker, dict):
            continue
        kind = blocker.get("kind", "blocker")
        slug = blocker.get("slug")
        text = blocker.get("detail") or blocker.get("title") or blocker.get("message") or ""
        count = blocker.get("blocker_count")
        suffix = f" ({count})" if count is not None else ""
        if slug:
            print(f"  - {kind} | {slug}: {text}{suffix}", file=sys.stderr)
        else:
            print(f"  - {kind}: {text}{suffix}", file=sys.stderr)
    if len(blockers) > 10:
        print(f"  - ... and {len(blockers) - 10} more", file=sys.stderr)
    print(
        "Run `vigil assess check-phase-readiness --phase report` for full blockers, or "
        "`vigil assess finding report --mode draft` to inspect grouped output before final readiness passes.",
        file=sys.stderr,
    )
