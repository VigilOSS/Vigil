"""assess.py list-intel — read-only intel listing / search.

If ``<type>`` is given, list rows of that type (backed by
``GET /engagements/{key}/intel/{type-plural}``). If ``<type>`` is omitted,
list the per-type counts via ``GET /engagements/{key}/intel/summary``.

``--q`` forwards to ``GET /engagements/{key}/intel/search?q=...`` and
mixes results across tables, narrowed by ``--entity-type`` if given.
"""
from __future__ import annotations

import argparse
import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.commands.record_intel import INTEL_TYPES


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "list-intel",
        help="List intel records (per-type or FTS search)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  assess.py list-intel                           # counts per type (summary)\n"
            "  assess.py list-intel tech-component            # all tech components\n"
            "  assess.py list-intel --q 'nginx'               # FTS search across all intel\n"
            "  assess.py list-intel cve --q '2024'            # FTS search narrowed to cves\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", nargs="?", default=None, help=f"Optional intel type ({types_list})")
    p.add_argument("--q", dest="q", default="", help="FTS search query (uses /intel/search)")
    p.add_argument("--limit", type=int, default=50, help="Result limit for search mode")
    p.add_argument("--json", dest="as_json", action="store_true", help="Print raw JSON")
    p.set_defaults(func=run)


def _format_row(row: dict) -> str:
    # Compact display that works across intel types — prefer identifying key.
    id_val = row.get("id", "?")
    for key in (
        "component",
        "name",
        "address",
        "identity",
        "cve_id",
        "handle",
        "fact_key",
        "title",
        "record_type",
        "breach_name",
    ):
        value = row.get(key)
        if value:
            return f"{id_val} | {key}={value} | source={row.get('source_name', '')}"
    return json.dumps(row, ensure_ascii=False)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)

    try:
        if args.q:
            # FTS search across intel tables.
            from urllib.parse import urlencode

            params = {"q": args.q, "limit": args.limit}
            if args.intel_type:
                if args.intel_type not in INTEL_TYPES:
                    print(
                        f"unknown intel type '{args.intel_type}'. Valid: "
                        f"{', '.join(sorted(INTEL_TYPES))}"
                    )
                    return
                # entity_type is the plural endpoint segment (matches backend convention).
                params["entity_type"] = INTEL_TYPES[args.intel_type][1]
            result = client.get_engagement("intel/search", query=urlencode(params))
        elif args.intel_type:
            if args.intel_type not in INTEL_TYPES:
                print(
                    f"unknown intel type '{args.intel_type}'. Valid: "
                    f"{', '.join(sorted(INTEL_TYPES))}"
                )
                return
            _, endpoint_segment = INTEL_TYPES[args.intel_type]
            result = client.get_engagement(f"intel/{endpoint_segment}")
        else:
            result = client.get_engagement("intel/summary")
    finally:
        client.close()

    if args.as_json or not isinstance(result, list):
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if not result:
        print("No intel records matched.")
        return

    for row in result:
        if isinstance(row, dict):
            print(_format_row(row))
        else:
            print(row)
