"""aith assess fetch — GET assessment endpoint and print JSON.

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

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


_ENGAGEMENT_SCOPED_PREFIXES = ("intel", "activity-entries")


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


def _apply_jq(expression: str, json_text: str) -> str:
    """Run ``jq <expression>`` against ``json_text`` and return jq's stdout."""
    if not shutil.which("jq"):
        print(
            "fetch --jq: `jq` not found on $PATH; install jq or drop --jq",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        completed = subprocess.run(
            ["jq", expression],
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
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        endpoint = args.endpoint.strip("/")
        if _is_engagement_scoped(endpoint):
            # Shorthand: `fetch intel` → `fetch intel/summary`. Users who want
            # the raw list of routes can still call e.g. `intel/tech-components`.
            if endpoint == "intel":
                endpoint = "intel/summary"
            result = client.get_engagement(endpoint)
        else:
            result = client.get(endpoint)
    finally:
        client.close()

    if isinstance(result, str):
        if args.jq:
            print(_apply_jq(args.jq, result), end="")
        else:
            print(result)
        return

    indent = None if args.compact else 2
    json_text = json.dumps(result, indent=indent, ensure_ascii=False)
    if args.jq:
        # jq accepts both compact and pretty input; always feed the result
        # as serialised JSON so the expression sees a uniform shape.
        compact_input = json.dumps(result, ensure_ascii=False)
        print(_apply_jq(args.jq, compact_input), end="")
    else:
        print(json_text)
