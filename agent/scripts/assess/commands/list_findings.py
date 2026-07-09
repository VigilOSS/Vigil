"""vigil assess list-findings — filtered finding listing."""
from __future__ import annotations

import argparse
import json
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.finding_render import blocked_reason_summary


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list-findings",
        help="List findings with common CLI-side filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess list-findings --severity high --status active\n"
            "  vigil assess list-findings --root-cause auth-bypass-root\n"
            "  vigil assess list-findings --verification-disposition false_positive --json\n"
            "  vigil assess list-findings --search parser --source-name vulnerability-analyst\n"
            "  vigil assess list-findings --all --json  # explicit unbounded fetch"
        ),
    )
    p.add_argument("--severity")
    p.add_argument("--workflow-status", "--status", dest="workflow_status")
    p.add_argument("--verification-state")
    p.add_argument("--verification-disposition")
    p.add_argument("--source-name")
    p.add_argument("--slug")
    p.add_argument("--root-cause", dest="root_cause_slug", help="Show the root finding and linked siblings")
    p.add_argument(
        "--search",
        "--q",
        dest="search",
        help="Case-insensitive search over slug, title, summary, location, and source_name "
             "(--q is an alias for cross-verb consistency)",
    )
    p.add_argument(
        "--holding",
        action="store_true",
        help=(
            "Show only the theoretical holding area: findings with "
            "evidence_type=theoretical OR verification_disposition="
            "pending_runtime_proof (strong-but-unproven, awaiting runtime proof)."
        ),
    )
    p.add_argument("--limit", type=int, default=100, help="Maximum rows to fetch from the backend (default: 100)")
    p.add_argument("--offset", type=int, default=0, help="Backend result offset for pagination")
    p.add_argument("--all", action="store_true", help="Fetch all matching findings instead of applying the default limit")
    p.add_argument("--json", action="store_true", help="Print filtered findings as JSON instead of a table")
    p.set_defaults(func=run)


def _finding_row(item: dict) -> str:
    """Render one finding as a pipe-delimited list-findings row.

    A blocked-for-provisioning finding (verification_disposition='blocked') gets
    a trailing ``BLOCKED[(kind)]: <reason>`` cell so the operator reads WHY it is
    held out of the report without opening the finding. The disposition cell
    already shows ``.../blocked``; this adds the reason that used to live only in
    the finding's ``details_json``.
    """
    row = (
        f"{item.get('slug', '')} | "
        f"{item.get('severity', '')} | "
        f"{item.get('workflow_status', '')} | "
        f"{item.get('verification_state', '')}/{item.get('verification_disposition', '')} | "
        f"{item.get('root_cause_role', '')} | "
        f"{item.get('title', '')}"
    )
    blocked = blocked_reason_summary(item)
    if blocked:
        row += f" | {blocked}"
    return row


def _matches_search(finding: dict, search: str) -> bool:
    haystack = " ".join(
        str(finding.get(key, ""))
        for key in ("slug", "title", "summary", "canonical_location", "source_name")
    ).lower()
    return search in haystack


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        root_cause_slug = getattr(args, "root_cause_slug", None)
        if root_cause_slug:
            group = client.get(f"finding-groups/{root_cause_slug}")
            root = dict(group.get("root", {}))
            root["root_cause_role"] = "root"
            findings = [root]
            for sibling in group.get("siblings", []):
                item = dict(sibling)
                item["root_cause_role"] = "sibling"
                findings.append(item)
        else:
            params: list[tuple[str, str]] = []
            for attr, key in (
                ("severity", "severity"),
                ("workflow_status", "workflow_status"),
                ("verification_state", "verification_state"),
                ("verification_disposition", "verification_disposition"),
                ("source_name", "source_name"),
                ("slug", "slug"),
                ("search", "search"),
            ):
                value = getattr(args, attr, None)
                if value:
                    params.append((key, str(value)))
            if getattr(args, "holding", False):
                params.append(("holding", "true"))
            if not getattr(args, "all", False):
                params.append(("limit", str(int(getattr(args, "limit", 100)))))
                params.append(("offset", str(int(getattr(args, "offset", 0)))))
            endpoint = "findings"
            if params:
                endpoint += "?" + urlencode(params, quote_via=quote)
            findings = client.get(endpoint)

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
    if getattr(args, "holding", False):
        filtered = [
            item
            for item in filtered
            if str(item.get("evidence_type", "")).lower() == "theoretical"
            or str(item.get("verification_disposition", "")).lower() == "pending_runtime_proof"
        ]
    if not getattr(args, "all", False):
        limit = int(getattr(args, "limit", 100))
        if len(filtered) > limit:
            offset = int(getattr(args, "offset", 0))
            filtered = filtered[offset : offset + limit]

    if args.json:
        print(json.dumps(filtered, indent=2, ensure_ascii=False))
        return

    if not filtered:
        print("No findings matched.")
        return

    for item in filtered:
        print(_finding_row(item))
