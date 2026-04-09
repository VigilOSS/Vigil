"""assess.py list-findings — filtered finding listing."""
from __future__ import annotations

import argparse
import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-findings",
        help="List findings with common CLI-side filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  assess.py list-findings --severity high --status active\n"
            "  assess.py list-findings --verification-disposition false_positive --json\n"
            "  assess.py list-findings --search parser --source-name vulnerability-analyst"
        ),
    )
    p.add_argument("--severity")
    p.add_argument("--workflow-status", "--status", dest="workflow_status")
    p.add_argument("--verification-state")
    p.add_argument("--verification-disposition")
    p.add_argument("--source-name")
    p.add_argument("--slug")
    p.add_argument("--search", help="Case-insensitive search over slug, title, summary, and location")
    p.add_argument("--json", action="store_true", help="Print filtered findings as JSON instead of a table")
    p.set_defaults(func=run)


def _matches_search(finding: dict, search: str) -> bool:
    haystack = " ".join(
        str(finding.get(key, ""))
        for key in ("slug", "title", "summary", "canonical_location", "source_name")
    ).lower()
    return search in haystack


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        findings = client.get("findings")
    finally:
        client.close()

    if not isinstance(findings, list):
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return

    filtered = findings
    if args.severity:
        filtered = [item for item in filtered if str(item.get("severity", "")).lower() == args.severity.lower()]
    if args.workflow_status:
        filtered = [
            item for item in filtered if str(item.get("workflow_status", "")).lower() == args.workflow_status.lower()
        ]
    if args.verification_state:
        filtered = [
            item
            for item in filtered
            if str(item.get("verification_state", "")).lower() == args.verification_state.lower()
        ]
    if args.verification_disposition:
        filtered = [
            item
            for item in filtered
            if str(item.get("verification_disposition", "")).lower() == args.verification_disposition.lower()
        ]
    if args.source_name:
        filtered = [item for item in filtered if str(item.get("source_name", "")).lower() == args.source_name.lower()]
    if args.slug:
        filtered = [item for item in filtered if str(item.get("slug", "")).lower() == args.slug.lower()]
    if args.search:
        needle = args.search.lower()
        filtered = [item for item in filtered if _matches_search(item, needle)]

    if args.json:
        print(json.dumps(filtered, indent=2, ensure_ascii=False))
        return

    if not filtered:
        print("No findings matched.")
        return

    for item in filtered:
        print(
            f"{item.get('slug', '')} | "
            f"{item.get('severity', '')} | "
            f"{item.get('workflow_status', '')} | "
            f"{item.get('verification_state', '')}/{item.get('verification_disposition', '')} | "
            f"{item.get('title', '')}"
        )
