"""aith assess fetch — GET assessment endpoint and print JSON.

Special-case: ``fetch intel`` hits ``/engagements/{key}/intel/summary`` (the
engagement-scoped intel summary lives outside ``/assessment/``). ``fetch
intel/<sub>`` reaches arbitrary intel routes (e.g. ``intel/tech-components``,
``intel/search``, ``intel/by-url``). ``fetch activity-entries`` follows the
same pattern for the activity log.
"""
from __future__ import annotations

import json

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
    p.set_defaults(func=run)


def _is_engagement_scoped(endpoint: str) -> bool:
    head = endpoint.strip("/").split("/", 1)[0]
    return head in _ENGAGEMENT_SCOPED_PREFIXES


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
        if isinstance(result, str):
            print(result)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()
