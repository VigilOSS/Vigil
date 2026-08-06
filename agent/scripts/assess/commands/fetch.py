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

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import MAX_VARIANT_RECEIPT_PAGE


_ENGAGEMENT_SCOPED_PREFIXES = ("intel", "activity-entries")
_PAGED_ASSESSMENT_ENDPOINTS = {
    "code/variant-checks": MAX_VARIANT_RECEIPT_PAGE,
    "coverage-items": 5000,
    "probe-runs": 5000,
    "request-observations": 5000,
    "request-variants": 5000,
    "surfaces": 5000,
}


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


def _fetch_assessment_endpoint(client: AssessmentClient, endpoint: str) -> Any:
    path, _sep, raw_query = endpoint.partition("?")
    normalized_path = path.strip("/")
    page_limit = _PAGED_ASSESSMENT_ENDPOINTS.get(normalized_path)
    if page_limit is None:
        return client.get(endpoint)

    if raw_query and any(
        item.startswith("limit=") or item.startswith("offset=")
        for item in raw_query.split("&")
    ):
        return client.get(endpoint)
    paged_endpoint = normalized_path if not raw_query else endpoint
    print(
        f"fetch: auto-paging {normalized_path} with page_size={page_limit}; "
        "stdout will be one combined JSON array. Add ?limit=N&offset=M to fetch "
        "one page.",
        file=sys.stderr,
    )
    rows = client.get_all_pages(paged_endpoint, page_size=page_limit)
    print(f"fetch: fetched {len(rows)} {normalized_path} row(s) across all pages.", file=sys.stderr)
    return rows


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
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        endpoint = args.endpoint.strip("/")
        if _is_engagement_scoped(endpoint):
            # Shorthand: `fetch intel` → `fetch intel/summary`. Users who want
            # the raw list of routes can still call e.g. `intel/tech-components`.
            if endpoint == "intel":
                endpoint = "intel/summary"
            result = client.get_engagement(endpoint)
        else:
            result = _fetch_assessment_endpoint(client, endpoint)

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
