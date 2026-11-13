"""vigil assess finding corroborate — record that another lane re-derived a finding."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient, require_write_result, verdict_effect_line
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog

# Backend owner: state_manager._common.CORROBORATION_LINK_KIND. The backend
# validates the target (a recorded dispatch that neither authored nor edited
# the finding); this verb only spells the one shape that route accepts.
CORROBORATION_LINK_KIND = "corroborated_by"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "corroborate",
        help="Record that a dispatch independently re-derived an existing finding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding corroborate"),
    )
    p.add_argument(
        "finding_slug",
        help="Slug of the existing finding the lane re-derived",
    )
    p.add_argument(
        "--dispatch",
        dest="dispatch_agent_id",
        required=True,
        help="agent_id of the recorded dispatch that re-derived it (not its author or an editor)",
    )
    p.add_argument(
        "--reason",
        dest="reason_text",
        default="",
        help="One sentence on how the lane reached the same finding",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    slug = str(args.finding_slug)
    agent_id = str(args.dispatch_agent_id).strip()
    payload = {
        "link_kind": CORROBORATION_LINK_KIND,
        "target_kind": "dispatch",
        "target_ref": agent_id,
        "notes": args.reason_text or "",
        "provenance": {"dispatch_agent_id": agent_id, "source_name": agent_id},
    }
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = require_write_result(
            client.post(f"findings/{slug}/links", payload),
            operation=f"corroborate finding {slug}",
            expected={
                "link_kind": CORROBORATION_LINK_KIND,
                "target_kind": "dispatch",
                "target_ref": agent_id,
            },
            positive_ids=("id",),
        )
    print(
        f"finding corroborate: {slug} corroborated by dispatch {agent_id} "
        f"(link {result['id']}); retire it with `vigil assess finding link {slug} "
        f"--link-id {result['id']} --retire`",
        file=sys.stderr,
    )
    effect = verdict_effect_line("finding corroborate", slug, result)
    if effect:
        print(effect, file=sys.stderr)
    print(json.dumps(result, indent=2, ensure_ascii=False))
