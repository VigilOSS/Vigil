"""vigil assess fetch — GET assessment endpoint and print JSON.

Special-case: ``fetch intel`` hits ``/engagements/{key}/intel/summary`` (the
engagement-scoped intel summary lives outside ``/assessment/``). ``fetch
intel/<sub>`` reaches arbitrary intel routes (e.g. ``intel/tech-components``,
``intel/search``, ``intel/by-url``). ``fetch activity-entries`` follows the
same pattern for the activity log.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import parse_qsl, urlencode

from assess.commands.list_findings import compact_finding_list_row
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import MAX_VARIANT_RECEIPT_PAGE
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.intel_types import INTEL_TYPES


_ENGAGEMENT_SCOPED_PREFIXES = ("intel", "activity-entries")
_DEFAULT_PAGE_SIZE = 100
_PAGED_ASSESSMENT_ENDPOINTS = {
    "code/variant-checks": MAX_VARIANT_RECEIPT_PAGE,
    "coverage-items": 5000,
    "findings": 5000,
    "probe-runs": 5000,
    "request-observations": 5000,
    "request-variants": 5000,
    "surfaces": 5000,
}
_PAGED_ENGAGEMENT_LIST_ENDPOINTS = {
    *(f"intel/{metadata[1]}" for metadata in INTEL_TYPES.values()),
    "intel/credentials",
    "intel/search",
}
_ACTIVITY_LIST_ENDPOINT = "activity-entries"


def register(subparsers) -> None:
    p = subparsers.add_parser("fetch", help="GET /assessment/{endpoint} or engagement-scoped routes")
    p.add_argument(
        "endpoint",
        help=(
            "e.g. findings, report-findings, credentials, summary, coverage-items, "
            "intel (→ intel/summary), intel/tech-components, activity-entries"
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="No-op: fetch always returns JSON. Accepted for symmetry with list-* commands.",
    )
    p.add_argument(
        "--compact",
        action="store_true",
        help="One-line JSON output (indent=None) for piping to jq/jsonl tooling.",
    )
    p.add_argument(
        "--paginate",
        action="store_true",
        help=(
            "Explicitly fetch every page for known paginated list endpoints. "
            "Without this flag, fetch returns one bounded page."
        ),
    )
    p.add_argument(
        "--jq",
        default="",
        help="Optional jq expression to apply to the JSON response. "
        "Requires `jq` on $PATH; emits the post-jq text directly so the operator "
        "can pipeline filters without a shell pipe (e.g. --jq '.[] | select(.severity==\"high\")').",
    )
    p.set_defaults(func=run)


def _is_engagement_scoped(endpoint: str) -> bool:
    head = endpoint.strip("/").split("/", 1)[0]
    return head in _ENGAGEMENT_SCOPED_PREFIXES


def _point_read_hint(endpoint: str) -> str | None:
    """Return the canonical command for common singular point-route mistakes.

    ``fetch findings/<slug>`` and the plural intel REST paths remain valid for
    compatibility. The diagnostics cover only shapes that cannot name a backend
    route, so the generic fetch escape hatch stays generic.
    """
    path = endpoint.partition("?")[0].strip("/")
    parts = path.split("/")
    if len(parts) == 2 and parts[0] == "finding" and parts[1]:
        return f"vigil assess finding get {parts[1]}"
    if (
        len(parts) == 3
        and parts[0] == "intel"
        and parts[1] in INTEL_TYPES
        and parts[2].isdigit()
    ):
        return f"vigil assess intel get {parts[1]} {parts[2]}"
    return None


def _fetch_assessment_endpoint(
    client: AssessmentClient,
    endpoint: str,
    *,
    paginate: bool = False,
) -> Any:
    path, _sep, raw_query = endpoint.partition("?")
    normalized_path = path.strip("/")
    page_limit = _PAGED_ASSESSMENT_ENDPOINTS.get(normalized_path)
    if page_limit is None:
        return client.get(endpoint)

    query_items = parse_qsl(raw_query, keep_blank_values=True)
    has_limit = any(key == "limit" for key, _value in query_items)
    has_offset = any(key == "offset" for key, _value in query_items)
    if paginate and (has_limit or has_offset):
        limit_values = [value for key, value in query_items if key == "limit"]
        offset_values = [value for key, value in query_items if key == "offset"]
        try:
            if len(limit_values) > 1 or len(offset_values) > 1:
                raise ValueError
            requested_page_size = (
                int(limit_values[0]) if limit_values else int(page_limit)
            )
            next_offset = int(offset_values[0]) if offset_values else 0
        except ValueError as exc:
            raise AssessError(
                f"fetch {normalized_path}: limit and offset must each be one integer"
            ) from exc
        if not 1 <= requested_page_size <= page_limit or next_offset < 0:
            raise AssessError(
                f"fetch {normalized_path}: limit must be 1..{page_limit} and offset non-negative"
            )
        base_query = [
            item for item in query_items if item[0] not in {"limit", "offset"}
        ]
        rows: list[Any] = []
        print(
            f"fetch: auto-paging {normalized_path} with "
            f"page_size={requested_page_size} from offset={next_offset}; "
            "stdout will be one combined JSON array.",
            file=sys.stderr,
        )
        while True:
            page_query = urlencode(
                [
                    *base_query,
                    ("limit", str(requested_page_size)),
                    ("offset", str(next_offset)),
                ]
            )
            page = _require_assessment_list(
                client.get(f"{normalized_path}?{page_query}"), normalized_path
            )
            rows.extend(page)
            if len(page) < requested_page_size:
                break
            next_offset += len(page)
        print(
            f"fetch: fetched {len(rows)} {normalized_path} row(s) across all pages.",
            file=sys.stderr,
        )
        return rows
    if has_limit:
        rows = _require_assessment_list(client.get(endpoint), normalized_path)
        return rows
    if paginate and not has_offset:
        paged_endpoint = normalized_path if not raw_query else endpoint
        print(
            f"fetch: auto-paging {normalized_path} with page_size={page_limit}; "
            "stdout will be one combined JSON array.",
            file=sys.stderr,
        )
        rows = _require_assessment_list(
            client.get_all_pages(paged_endpoint, page_size=page_limit),
            normalized_path,
        )
        print(
            f"fetch: fetched {len(rows)} {normalized_path} row(s) across all pages.",
            file=sys.stderr,
        )
        return rows

    bounded_query = [*query_items, ("limit", str(_DEFAULT_PAGE_SIZE))]
    if not has_offset:
        bounded_query.append(("offset", "0"))
    bounded_endpoint = f"{normalized_path}?{urlencode(bounded_query)}"
    rows = _require_assessment_list(client.get(bounded_endpoint), normalized_path)
    if normalized_path == "findings":
        rows = [
            compact_finding_list_row(row) if isinstance(row, dict) else row
            for row in rows
        ]
    print(
        f"fetch: returned one bounded page of up to {_DEFAULT_PAGE_SIZE} "
        f"{normalized_path} row(s); use --paginate to fetch every page or set "
        "?limit=N&offset=M explicitly.",
        file=sys.stderr,
    )
    return rows


def _require_assessment_list(result: Any, endpoint: str) -> list[Any]:
    if not isinstance(result, list):
        raise AssessError(f"fetch {endpoint} expected a JSON array")
    if endpoint == "findings" and any(
        not isinstance(row, dict)
        or not isinstance(row.get("slug"), str)
        or not row["slug"].strip()
        for row in result
    ):
        raise AssessError("fetch findings received a finding row without a slug")
    return result


def _fetch_engagement_endpoint(
    client: AssessmentClient,
    endpoint: str,
    *,
    paginate: bool = False,
    page_size: int | None = None,
) -> Any:
    path, _sep, raw_query = endpoint.partition("?")
    normalized_path = path.strip("/")
    is_bare_list = normalized_path in _PAGED_ENGAGEMENT_LIST_ENDPOINTS
    is_activity = normalized_path == _ACTIVITY_LIST_ENDPOINT
    if not is_bare_list and not is_activity:
        return client.get_engagement(endpoint)

    query_items = parse_qsl(raw_query, keep_blank_values=True)
    if any(key in {"limit", "offset"} for key, _value in query_items):
        return client.get_engagement(normalized_path, query=urlencode(query_items))

    if not paginate:
        bounded_query = urlencode(
            [*query_items, ("limit", _DEFAULT_PAGE_SIZE), ("offset", 0)]
        )
        result = client.get_engagement(normalized_path, query=bounded_query)
        print(
            f"fetch: returned one bounded page of up to {_DEFAULT_PAGE_SIZE} "
            f"{normalized_path} row(s); use --paginate to fetch every page or "
            "set ?limit=N&offset=M explicitly.",
            file=sys.stderr,
        )
        return result

    effective_page_size = int(page_size or (1000 if is_activity else 500))
    offset = 0
    combined: list[Any] = []
    first_activity: dict[str, Any] | None = None
    while True:
        query = urlencode(
            [*query_items, ("limit", effective_page_size), ("offset", offset)]
        )
        page = client.get_engagement(normalized_path, query=query)
        if is_activity:
            if not isinstance(page, dict) or not isinstance(page.get("items"), list):
                raise AssessError(
                    "fetch activity-entries expected an object with an items array"
                )
            if first_activity is None:
                first_activity = dict(page)
            page_rows = page["items"]
            total = page.get("total")
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise AssessError(
                    "fetch activity-entries expected a non-negative total"
                )
        else:
            if not isinstance(page, list):
                raise AssessError(f"fetch {normalized_path} expected a JSON array")
            page_rows = page
            total = None
        combined.extend(page_rows)
        offset += len(page_rows)
        if len(page_rows) < effective_page_size or (
            total is not None and offset >= total
        ):
            break
    print(
        f"fetch: fetched {len(combined)} {normalized_path} row(s) across all pages.",
        file=sys.stderr,
    )
    if is_activity:
        assert first_activity is not None
        return {**first_activity, "total": len(combined), "items": combined}
    return combined


_JQ_AVAILABLE: bool | None = None


def _jq_is_installed() -> bool:
    """Cache jq's presence so repeated --jq calls don't re-fork ``jq --version``."""
    global _JQ_AVAILABLE
    if _JQ_AVAILABLE is not None:
        return _JQ_AVAILABLE
    if not shutil.which("jq"):
        _JQ_AVAILABLE = False
        return False
    try:
        completed = subprocess.run(
            ["jq", "--version"], capture_output=True, text=True, check=False
        )
        _JQ_AVAILABLE = completed.returncode == 0
    except OSError:
        _JQ_AVAILABLE = False
    return _JQ_AVAILABLE


def _apply_jq(expression: str, json_text: str, *, compact: bool = False) -> str:
    """Run ``jq <expression>`` against ``json_text`` and return jq's stdout."""
    if not _jq_is_installed():
        print(
            "fetch --jq: `jq` not installed; install with "
            "`brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu)",
            file=sys.stderr,
        )
        sys.exit(1)
    argv = ["jq"]
    if compact:
        argv.append("-c")
    argv.append(expression)
    try:
        completed = subprocess.run(
            argv,
            input=json_text,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        print(f"fetch --jq: failed to invoke jq: {exc}", file=sys.stderr)
        sys.exit(1)
    if completed.returncode != 0:
        if completed.stderr:
            print(completed.stderr.rstrip(), file=sys.stderr)
        sys.exit(completed.returncode or 1)
    return completed.stdout


def run(args) -> None:
    endpoint = args.endpoint.strip("/")
    point_read_hint = _point_read_hint(endpoint)
    if point_read_hint:
        print(
            f"fetch: '{endpoint}' is not a valid API route. "
            f"Did you mean `{point_read_hint}`?",
            file=sys.stderr,
        )
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if _is_engagement_scoped(endpoint):
            # Shorthand: `fetch intel` → `fetch intel/summary`. Users who want
            # the raw list of routes can still call e.g. `intel/tech-components`.
            if endpoint == "intel":
                endpoint = "intel/summary"
            result = _fetch_engagement_endpoint(
                client,
                endpoint,
                paginate=getattr(args, "paginate", False),
            )
        else:
            result = _fetch_assessment_endpoint(
                client,
                endpoint,
                paginate=getattr(args, "paginate", False),
            )

    # Raw fetch is an escape hatch across engagement-owned routes. Even
    # apparently structural projections can embed target names, excerpts, or
    # tool output, so mark the trust boundary on stderr without changing JSON.
    warn_untrusted_data()

    if isinstance(result, str):
        if args.jq:
            print(_apply_jq(args.jq, result, compact=args.compact), end="")
        else:
            print(result)
        return

    indent = None if args.compact else 2
    json_text = json.dumps(result, indent=indent, ensure_ascii=False)
    if args.jq:
        # jq accepts both compact and pretty input; always feed the result
        # as serialised JSON so the expression sees a uniform shape.
        compact_input = json.dumps(result, ensure_ascii=False)
        print(_apply_jq(args.jq, compact_input, compact=args.compact), end="")
    else:
        print(json_text)
