"""vigil assess finding list — filtered finding listing."""
from __future__ import annotations

import argparse
import json
import shlex
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import (
    FINDING_SEVERITIES,
    FINDING_WORKFLOW_STATUSES,
    VERIFICATION_STATUSES,
)
from assess.lib.finding_render import blocked_reason_summary, warn_untrusted_data
from assess.lib.list_output import (
    RemovedOptionAction,
    lookahead_limit,
    page_from_backend,
    page_from_complete,
    report_page,
)


_MAX_BACKEND_LIMIT = 1000
_JSON_LIST_FIELDS = (
    "id",
    "slug",
    "title",
    "severity",
    "workflow_status",
    "verification_status",
    "defect_family",
    "root_cause_key",
    "root_cause_role",
    "canonical_location",
    "auth_context",
    "source_name",
    "evidence_type",
    "submission_status",
    "submission_platform",
    "submission_ref",
    "merged_into_slug",
    "code_snapshot_status",
    "row_version",
    "updated_at",
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list",
        help="List findings with common CLI-side filters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess finding list --severity high --status active\n"
            "  vigil assess finding list --root-cause auth-bypass-root\n"
            "  vigil assess finding list --verification-status false_positive --json\n"
            "  vigil assess finding list --search parser --source-name vulnerability-analyst\n"
            "  vigil assess finding list --limit 100 --offset 100"
        ),
    )
    p.add_argument("--severity", choices=FINDING_SEVERITIES)
    p.add_argument(
        "--workflow-status", "--status", dest="workflow_status",
        choices=FINDING_WORKFLOW_STATUSES,
    )
    p.add_argument(
        "--verification-status",
        choices=VERIFICATION_STATUSES,
        help=(
            "One-axis verification state. The confirmed-finding set is "
            "--verification-status confirmed; the retired two-axis value "
            "`verified` does not exist on either side of the contract."
        ),
    )
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
            "evidence_type=theoretical OR verification_status is pending_runtime_proof "
            "or blocked."
        ),
    )
    p.add_argument("--limit", type=int, default=100, help="Maximum rows to fetch from the backend (default: 100)")
    p.add_argument("--offset", type=int, default=0, help="Backend result offset for pagination")
    p.add_argument(
        "--all",
        action=RemovedOptionAction,
        nargs=0,
        const=(
            "finding list --all was removed to keep output bounded; page with "
            "--limit/--offset and use `finding get <slug>` for complete rows"
        ),
        help=argparse.SUPPRESS,
    )
    p.add_argument("--json", action="store_true", help="Print filtered findings as JSON instead of a table")
    p.set_defaults(func=run)


def _finding_row(item: dict) -> str:
    """Render one finding as a pipe-delimited finding-list row.

    A blocked-for-provisioning finding (verification_status='blocked') gets
    a trailing ``BLOCKED[(kind)]: <reason>`` cell so the operator reads WHY it is
    held out of the report without opening the finding. The disposition cell
    already shows ``.../blocked``; this adds the reason that used to live only in
    the finding's ``details_json``.
    """
    row = (
        f"{item.get('slug', '')} | "
        f"{item.get('severity', '')} | "
        f"{item.get('workflow_status', '')} | "
        f"{item.get('verification_status', '')} | "
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


def compact_finding_list_row(item: dict) -> dict:
    row = {key: item[key] for key in _JSON_LIST_FIELDS if key in item}
    slug = str(item.get("slug") or "")
    if slug:
        row["_point_read"] = f"vigil assess finding get {shlex.quote(slug)}"
    return row


def _continuation_command(args, offset: int) -> str:
    parts = ["vigil", "assess", "finding", "list"]
    for attr, flag in (
        ("severity", "--severity"),
        ("workflow_status", "--workflow-status"),
        ("verification_status", "--verification-status"),
        ("source_name", "--source-name"),
        ("slug", "--slug"),
        ("root_cause_slug", "--root-cause"),
        ("search", "--search"),
    ):
        value = getattr(args, attr, None)
        if value:
            parts.extend((flag, shlex.quote(str(value))))
    if getattr(args, "holding", False):
        parts.append("--holding")
    parts.extend(("--limit", str(int(args.limit)), "--offset", str(offset)))
    return " ".join(parts)


def _print_root_cause_group(group: dict, root_slug: str) -> None:
    """Render a root-cause finding group with sibling effect/order detail.

    Ported from the retired ``list-finding-group`` verb: the root header, the
    sibling count, and per-sibling ``sibling_order`` / ``root_cause_effect`` /
    ``root_cause_note`` columns that the plain ``finding list`` row does not
    surface.
    """
    root = group.get("root", {})
    print(
        f"Root: {root.get('slug', root_slug)} [{root.get('severity', 'info')}] "
        f"{root.get('title', '')}"
    )
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


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        root_cause_slug = getattr(args, "root_cause_slug", None)
        if root_cause_slug:
            group = client.get(f"finding-groups/{root_cause_slug}")
            # Non-JSON root-cause listing renders the dedicated group view with
            # sibling effect/order/note detail (folded-in list-finding-group);
            # --json still emits the flattened root+siblings finding list below.
            if not args.json:
                siblings = list(group.get("siblings", []))
                page = page_from_complete(
                    siblings,
                    limit=int(args.limit),
                    offset=int(args.offset),
                )
                paged_group = {**group, "siblings": page.rows}
                if page.rows or group.get("root"):
                    warn_untrusted_data()
                _print_root_cause_group(paged_group, root_cause_slug)
                report_page(
                    page,
                    noun="root-cause siblings",
                    continuation_command=_continuation_command(
                        args, page.offset + len(page.rows)
                    ),
                    point_read_hint="`vigil assess finding get <slug>`",
                )
                return
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
                ("verification_status", "verification_status"),
                ("source_name", "source_name"),
                ("slug", "slug"),
                ("search", "search"),
            ):
                value = getattr(args, attr, None)
                if value:
                    params.append((key, str(value)))
            if getattr(args, "holding", False):
                params.append(("holding", "true"))
            request_limit, used_lookahead = lookahead_limit(
                int(getattr(args, "limit", 100)), maximum=_MAX_BACKEND_LIMIT
            )
            params.append(("limit", str(request_limit)))
            params.append(("offset", str(int(getattr(args, "offset", 0)))))
            endpoint = "findings"
            if params:
                endpoint += "?" + urlencode(params, quote_via=quote)
            findings = client.get(endpoint)

    if not isinstance(findings, list):
        raise AssessError("finding list: expected a JSON array from the backend")

    filtered = findings
    if root_cause_slug:
        # The dedicated group endpoint returns the complete root + sibling set,
        # so its flattened JSON view still applies the common list filters here.
        # The ordinary findings endpoint already owns these predicates; applying
        # them again in the CLI creates a second, drift-prone source of truth.
        if args.severity:
            filtered = [
                item
                for item in filtered
                if str(item.get("severity", "")).lower() == args.severity.lower()
            ]
        if args.workflow_status:
            filtered = [
                item
                for item in filtered
                if str(item.get("workflow_status", "")).lower()
                == args.workflow_status.lower()
            ]
        if args.verification_status:
            filtered = [
                item
                for item in filtered
                if str(item.get("verification_status", "")).lower()
                == args.verification_status.lower()
            ]
        if args.source_name:
            filtered = [
                item
                for item in filtered
                if str(item.get("source_name", "")).lower()
                == args.source_name.lower()
            ]
        if args.slug:
            filtered = [
                item
                for item in filtered
                if str(item.get("slug", "")).lower() == args.slug.lower()
            ]
        if args.search:
            needle = args.search.lower()
            filtered = [item for item in filtered if _matches_search(item, needle)]
        if getattr(args, "holding", False):
            filtered = [
                item
                for item in filtered
                if str(item.get("evidence_type", "")).lower() == "theoretical"
                or str(item.get("verification_status", "")).lower()
                in {"pending_runtime_proof", "blocked"}
            ]
    limit = int(getattr(args, "limit", 100))
    offset = int(getattr(args, "offset", 0))
    if root_cause_slug:
        page = page_from_complete(filtered, limit=limit, offset=offset)
    else:
        page = page_from_backend(
            filtered,
            limit=limit,
            offset=offset,
            used_lookahead=used_lookahead,
        )
    filtered = page.rows
    report_page(
        page,
        noun="findings",
        continuation_command=_continuation_command(
            args, page.offset + len(page.rows)
        ),
        point_read_hint="`vigil assess finding get <slug>`",
    )

    if filtered:
        warn_untrusted_data()

    if args.json:
        print(
            json.dumps(
                [compact_finding_list_row(item) for item in filtered],
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    if not filtered:
        print("No findings matched.")
        return

    for item in filtered:
        print(_finding_row(item))
