"""vigil assess finding list — filtered finding listing."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
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
    page_with_total,
    report_page,
)


# Mirrors the backend cap on GET /findings (MAX_ASSESSMENT_LIST_LIMIT in
# orchestrator/backend/app/services/state_manager/coverage.py). Naming a lower
# ceiling here silently truncates a listing the backend would have served whole.
_MAX_BACKEND_LIMIT = 5000
# The unfiltered page size. A filtered listing defaults to every match up to
# _MAX_BACKEND_LIMIT, so "the highs" or "the confirmed set" is never a page.
_DEFAULT_UNFILTERED_LIMIT = 100
# (args attribute, backend query key) for the filters GET /findings and
# GET /findings/count both apply server-side over the whole ledger.
_BACKEND_FILTERS = (
    ("severity", "severity"),
    ("workflow_status", "workflow_status"),
    ("verification_status", "verification_status"),
    ("source_name", "source_name"),
    ("slug", "slug"),
    ("search", "search"),
)
# The finding ledger's list projection (``GET /findings?view=list``): every list
# field this verb prints, without each finding's details, notes or evidence.
FINDING_LIST_VIEW = ("view", "list")
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
    "created_at",
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
    p.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            f"Rows per page (maximum {_MAX_BACKEND_LIMIT}). Default: every match up to "
            f"{_MAX_BACKEND_LIMIT} when any filter is set, else {_DEFAULT_UNFILTERED_LIMIT}. "
            "A page that leaves matches unshown says INCOMPLETE with exact totals and "
            "the continuation command"
        ),
    )
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


def _finding_row(item: dict, chain_keys: list[str] | None = None) -> str:
    """Render one finding as a pipe-delimited finding-list row.

    A blocked-for-provisioning finding (verification_status='blocked') gets
    a trailing ``BLOCKED[(kind)]: <reason>`` cell so the operator reads WHY it is
    held out of the report without opening the finding. The disposition cell
    already shows ``.../blocked``; this adds the reason that used to live only in
    the finding's ``details_json``. A finding that is a step of a recorded
    attack chain ends with ``CHAIN[<chain_key>,...]``.
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
    if chain_keys:
        row += f" | CHAIN[{','.join(chain_keys)}]"
    return row


def _chain_keys_by_finding(links: object) -> tuple[dict[str, list[str]], dict[int, list[str]]]:
    """Chain keys each finding is a step of, keyed by slug and by id.

    ``attack-chain-links`` is the complete chain-link ledger in one response, so
    a row on any page resolves against every chain. A link names its finding by
    slug, or by id when it carries no slug.
    """
    if not isinstance(links, list):
        raise AssessError("finding list: attack-chain-links did not return a JSON array")
    by_slug: dict[str, list[str]] = {}
    by_id: dict[int, list[str]] = {}
    for link in sorted(
        (link for link in links if isinstance(link, dict)),
        key=lambda link: str(link.get("chain_key") or ""),
    ):
        if link.get("entity_kind") != "finding" or not link.get("chain_key"):
            continue
        key = str(link["chain_key"])
        ref = str(link.get("entity_ref") or "")
        if ref:
            bucket = by_slug.setdefault(ref, [])
        elif type(link.get("entity_id")) is int:
            bucket = by_id.setdefault(int(link["entity_id"]), [])
        else:
            continue
        if key not in bucket:
            bucket.append(key)
    return by_slug, by_id


def _matches_search(finding: dict, search: str) -> bool:
    haystack = " ".join(
        str(finding.get(key, ""))
        for key in ("slug", "title", "summary", "canonical_location", "source_name")
    ).lower()
    return search in haystack


def _filter_group_rows(rows: list[dict], args) -> list[dict]:
    """Apply the common list filters to a root-cause group's complete rows."""
    severity = getattr(args, "severity", None)
    workflow_status = getattr(args, "workflow_status", None)
    verification_status = getattr(args, "verification_status", None)
    source_name = getattr(args, "source_name", None)
    slug = getattr(args, "slug", None)
    search = getattr(args, "search", None)
    filtered = rows
    if severity:
        filtered = [
            item
            for item in filtered
            if str(item.get("severity", "")).lower() == severity.lower()
        ]
    if workflow_status:
        filtered = [
            item
            for item in filtered
            if str(item.get("workflow_status", "")).lower()
            == workflow_status.lower()
        ]
    if verification_status:
        filtered = [
            item
            for item in filtered
            if str(item.get("verification_status", "")).lower()
            == verification_status.lower()
        ]
    if source_name:
        filtered = [
            item
            for item in filtered
            if str(item.get("source_name", "")).lower() == source_name.lower()
        ]
    if slug:
        filtered = [
            item
            for item in filtered
            if str(item.get("slug", "")).lower() == slug.lower()
        ]
    if search:
        needle = search.lower()
        filtered = [item for item in filtered if _matches_search(item, needle)]
    if getattr(args, "holding", False):
        filtered = [
            item
            for item in filtered
            if str(item.get("evidence_type", "")).lower() == "theoretical"
            or str(item.get("verification_status", "")).lower()
            in {"pending_runtime_proof", "blocked"}
        ]
    return filtered


# `root_cause_role` is stamped by the --root-cause group view only; the ledger
# listing's rows never carry it.
_GROUP_ONLY_LIST_FIELDS = frozenset({"root_cause_role"})


def _json_omitted_notice(*, root_cause_group: bool) -> str:
    """What every --json row of this listing mode carries and leaves out."""
    fields = [
        field
        for field in _JSON_LIST_FIELDS
        if root_cause_group or field not in _GROUP_ONLY_LIST_FIELDS
    ]
    return (
        "finding list --json: each row carries only "
        + ", ".join(fields)
        + " and _point_read; every other finding field is omitted, including summary, "
        "details (block_reason, chain_required, poc_request, poc_response, ...), notes, "
        "provenance, evidence_ref, proof_receipts, reproduction_basis, next_test and "
        "verification_audit. Read the complete record with "
        "`vigil assess finding get <slug>` (each row's _point_read)."
    )


def compact_finding_list_row(item: dict) -> dict:
    row = {key: item[key] for key in _JSON_LIST_FIELDS if key in item}
    slug = str(item.get("slug") or "")
    if slug:
        row["_point_read"] = f"vigil assess finding get {shlex.quote(slug)}"
    return row


def _has_filter(args) -> bool:
    """Whether the listing selects a subset (a root-cause group counts as one)."""
    return bool(
        getattr(args, "holding", False)
        or getattr(args, "root_cause_slug", None)
        or any(getattr(args, attr, None) for attr, _key in _BACKEND_FILTERS)
    )


def _effective_limit(args) -> int:
    """The page size: the explicit --limit, else the filter-aware default."""
    limit = getattr(args, "limit", None)
    if limit is not None:
        return int(limit)
    return _MAX_BACKEND_LIMIT if _has_filter(args) else _DEFAULT_UNFILTERED_LIMIT


def _filter_params(args) -> list[tuple[str, str]]:
    params = [
        (key, str(value))
        for attr, key in _BACKEND_FILTERS
        if (value := getattr(args, attr, None))
    ]
    if getattr(args, "holding", False):
        params.append(("holding", "true"))
    return params


def _endpoint(path: str, params: list[tuple[str, str]]) -> str:
    return f"{path}?{urlencode(params, quote_via=quote)}" if params else path


def _matching_counts(client, args) -> tuple[int, dict[str, int]]:
    """Exact total and per-severity counts of every finding the filters match."""
    counts = client.get(_endpoint("findings/count", _filter_params(args)))
    total = counts.get("total") if isinstance(counts, dict) else None
    by_severity = counts.get("by_severity") if isinstance(counts, dict) else None
    if (
        type(total) is not int
        or total < 0
        or not isinstance(by_severity, dict)
        or any(type(value) is not int for value in by_severity.values())
    ):
        raise AssessError(
            "finding list: findings/count did not return an integer total and "
            "by_severity counts"
        )
    return total, by_severity


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
    parts.extend(("--limit", str(_effective_limit(args)), "--offset", str(offset)))
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
    total = group.get("sibling_count", 0)
    matching = group.get("matching_sibling_count", total)
    print(
        f"Siblings: {total}"
        + (f" ({matching} match the filters)" if matching != total else "")
    )
    for sibling in group.get("siblings", []):
        order = sibling.get("sibling_order")
        prefix = f"{order}. " if order is not None else "- "
        effect = sibling.get("root_cause_effect", "eliminates_attack_path")
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
    by_severity: dict[str, int] | None = None
    chains_by_slug: dict[str, list[str]] = {}
    chains_by_id: dict[int, list[str]] = {}
    chain_read_error: str | None = None
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        root_cause_slug = getattr(args, "root_cause_slug", None)
        if root_cause_slug:
            group = client.get(f"finding-groups/{root_cause_slug}")
            # Non-JSON root-cause listing renders the dedicated group view with
            # sibling effect/order/note detail (folded-in list-finding-group);
            # --json still emits the flattened root+siblings finding list below.
            if not args.json:
                # The group header always names its root; the common filters
                # select which siblings the group view lists.
                siblings = _filter_group_rows(list(group.get("siblings", [])), args)
                page = page_from_complete(
                    siblings,
                    limit=_effective_limit(args),
                    offset=int(getattr(args, "offset", 0)),
                )
                paged_group = {
                    **group,
                    "siblings": page.rows,
                    "matching_sibling_count": len(siblings),
                }
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
                    file=sys.stdout,
                )
                return
            root = dict(group.get("root", {}))
            root["root_cause_role"] = "root"
            findings = [root]
            for sibling in group.get("siblings", []):
                item = dict(sibling)
                item["root_cause_role"] = "sibling"
                findings.append(item)
            # The dedicated group endpoint returns the complete root + sibling
            # set, so its flattened JSON view applies the common list filters
            # here. The ordinary findings endpoint owns these predicates;
            # applying them again in the CLI would be a second source of truth.
            page = page_from_complete(
                _filter_group_rows(findings, args),
                limit=_effective_limit(args),
                offset=int(getattr(args, "offset", 0)),
            )
        else:
            limit = _effective_limit(args)
            offset = int(getattr(args, "offset", 0))
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_BACKEND_LIMIT
            )
            findings = client.get(
                _endpoint(
                    "findings",
                    [
                        FINDING_LIST_VIEW,
                        *_filter_params(args),
                        ("limit", str(request_limit)),
                        ("offset", str(offset)),
                    ],
                )
            )
            if not isinstance(findings, list):
                raise AssessError("finding list: expected a JSON array from the backend")
            page = page_from_backend(
                findings,
                limit=limit,
                offset=offset,
                used_lookahead=used_lookahead,
            )
            if page.has_more or page.total is None:
                # One page cannot say how much it leaves out; the count can.
                total, by_severity = _matching_counts(client, args)
                page = page_with_total(page, total)
            if not args.json and page.rows:
                # CHAIN cells annotate the table; a failed chain read drops the
                # cells, says so, and still prints the findings.
                try:
                    chains_by_slug, chains_by_id = _chain_keys_by_finding(
                        client.get("attack-chain-links")
                    )
                except AssessError as exc:
                    chain_read_error = str(exc)

    rows = page.rows
    notice = {
        "noun": "findings",
        "continuation_command": _continuation_command(args, page.offset + len(rows)),
        "point_read_hint": "`vigil assess finding get <slug>`",
        "breakdown": by_severity,
    }
    if args.json:
        report_page(page, **notice)
        if rows:
            print(
                _json_omitted_notice(root_cause_group=bool(getattr(args, "root_cause_slug", None))),
                file=sys.stderr,
            )
            warn_untrusted_data()
        print(
            json.dumps(
                [compact_finding_list_row(item) for item in rows],
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    # The table carries its own notice on stdout, above the rows and, when the
    # page leaves matches out, again below them, so a reader that keeps only
    # one end of the output still learns the listing is partial.
    report_page(page, file=sys.stdout, **notice)
    if rows:
        warn_untrusted_data()
    if not rows:
        print("No findings matched.")
        return
    if chain_read_error is not None:
        print(
            f"CHAIN cells omitted: the chain-link read failed ({chain_read_error}); "
            "run `vigil assess chain list` for chain membership."
        )
    for item in rows:
        finding_id = item.get("id")
        keys = [
            *chains_by_slug.get(str(item.get("slug") or ""), []),
            *(chains_by_id.get(finding_id, []) if type(finding_id) is int else []),
        ]
        print(_finding_row(item, list(dict.fromkeys(keys))))
    if page.has_more:
        report_page(page, file=sys.stdout, **notice)
