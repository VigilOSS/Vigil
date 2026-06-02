"""vigil assess check-report-readiness — query backend report readiness blockers."""
from __future__ import annotations

import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("check-report-readiness", help="Check final report readiness")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        readiness = client.get("report-readiness")

    if not isinstance(readiness, dict):
        print("check-report-readiness: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    if readiness.get("ready", False):
        print("report readiness: ok")
        return

    print("Final report blockers remain:", file=sys.stderr)
    for blocker in readiness.get("blockers") or []:
        if not isinstance(blocker, dict):
            continue
        slug = blocker.get("slug")
        slugs = blocker.get("slugs")
        detail = blocker.get("detail", "")
        prefix = f"{blocker.get('kind', 'blocker')}"
        if slug:
            prefix = f"{prefix} | {slug}"
        elif isinstance(slugs, list) and slugs:
            prefix = f"{prefix} | {', '.join(str(item) for item in slugs)}"
        print(f"  - {prefix}: {detail}", file=sys.stderr)
    sys.exit(1)
