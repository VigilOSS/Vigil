"""vigil assess intel get — fetch one complete typed intel row by id."""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.intel_types import INTEL_TYPES


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES))
    p = subparsers.add_parser(
        "get",
        help="Fetch one complete typed intel row by id",
    )
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument(
        "intel_id",
        type=int,
        help="Backend id from `vigil assess intel list <type>`",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="No-op: `intel get` always emits JSON.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    intel_type = args.intel_type
    if intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{intel_type}'. Valid: "
            f"{', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)

    _, endpoint_segment = INTEL_TYPES[intel_type]
    requested_id = int(args.intel_id)
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        row = client.get_engagement(f"intel/{endpoint_segment}/{requested_id}")
    returned_id = row.get("id") if isinstance(row, dict) else None
    if (
        not isinstance(returned_id, int)
        or isinstance(returned_id, bool)
        or returned_id != requested_id
    ):
        raise AssessError(
            f"intel get: backend response did not identify requested "
            f"{intel_type} {requested_id}"
        )
    warn_untrusted_data()
    print(json.dumps(row, indent=2, ensure_ascii=False))
