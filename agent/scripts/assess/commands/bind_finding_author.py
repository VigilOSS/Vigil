"""Repair missing or invalid legacy author provenance with an audited binding."""
from __future__ import annotations

import json
from urllib.parse import quote

from assess.lib.client import AssessmentClient, require_finding_write_response
from assess.lib.config import load_config


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "bind-author",
        help=(
            "Repair a missing or unresolvable legacy finding author with an existing "
            "dispatch"
        ),
    )
    parser.add_argument("finding_slug", help="Canonical finding slug")
    parser.add_argument("--agent-id", required=True, help="Authoring dispatch agent_id")
    parser.add_argument("--actor", default="operator", help="Actor performing the repair")
    parser.add_argument("--reason", required=True, help="Evidence supporting the repaired binding")
    parser.add_argument(
        "--expected-row-version",
        required=True,
        type=int,
        help="Reject the repair if the finding changed after this row version",
    )
    parser.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    finding_slug = str(args.finding_slug)
    payload = {
        "agent_id": str(args.agent_id),
        "actor": str(args.actor),
        "reason": str(args.reason),
        "expected_row_version": int(args.expected_row_version),
    }
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        response = require_finding_write_response(
            client.put(f"findings/{quote(finding_slug, safe='')}/author", payload),
            finding_slug=finding_slug,
            operation="finding bind-author",
        )
    print(json.dumps(response, indent=2, ensure_ascii=False))
