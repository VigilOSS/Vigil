"""vigil assess finding get — fetch one complete finding row by slug."""
from __future__ import annotations

import json
from urllib.parse import quote

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "get",
        help="Fetch one complete finding row by slug",
    )
    p.add_argument(
        "finding_slug",
        help="Canonical finding slug from `vigil assess finding list`",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="No-op: `finding get` always emits JSON.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    requested_slug = str(args.finding_slug)
    slug = quote(requested_slug, safe="")
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        row = client.get(f"findings/{slug}")
    if not isinstance(row, dict) or row.get("slug") != requested_slug:
        raise AssessError(
            f"finding get: backend response did not identify requested finding "
            f"{requested_slug}"
        )
    warn_untrusted_data()
    print(json.dumps(row, indent=2, ensure_ascii=False))
