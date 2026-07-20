"""vigil assess app-unit — inspect and override depth app-units.

An "app unit" is an application boundary keyed (host, port-class, path-prefix)
scored by the depth-gate (§5.2). This command surfaces the stored, advisory
scores and lets an operator manually force the deep verdict:

    vigil assess app-unit list
    vigil assess app-unit score              # (re)run the scorer (idempotent)
    vigil assess app-unit depth-ledger       # read-only, advisory depth ledger
    vigil assess app-unit mark-deep <id> --reason "tenant admin app"
    vigil assess app-unit clear-deep <id> --reason "static mirror, no input"

`mark-deep` / `clear-deep` set a durable manual override that ALWAYS wins over
the scorer (depth-gate §5.2). `clear` removes the override and reverts to the
pure scorer verdict on the next pass.

The detector is WARN-FIRST: scores are an advisory signal, never a hard block.
The scorer is WEB-ONLY — `score` is a no-op on code/blue engagements.
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "app-unit",
        help="Inspect / score / override depth app-units (host, port-class, path-prefix)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Actions:\n"
            "  list                       List scored app units (advisory).\n"
            "  score                      Re-run prefix discovery + scorer (idempotent, web-only).\n"
            "  depth-ledger               Show the read-only, advisory depth ledger (§5.3).\n"
            "  mark-deep <id> --reason R  Force deep_required=true (manual override wins).\n"
            "  clear-deep <id> --reason R Force deep_required=false.\n"
            "  clear <id>                 Remove the manual override (revert to scorer).\n"
        ),
    )
    p.add_argument(
        "action",
        choices=("list", "score", "depth-ledger", "mark-deep", "clear-deep", "clear"),
        help="What to do.",
    )
    p.add_argument("unit_id", nargs="?", type=int, default=None,
                   help="App-unit id (required for mark-deep/clear-deep/clear).")
    p.add_argument("--reason", default="", help="Reason recorded with the override.")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="Emit raw JSON (list/score always emit JSON).")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if args.action == "list":
            rows = client.get("application-units")
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return
        if args.action == "score":
            result = client.post("application-units/score", {})
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return
        if args.action == "depth-ledger":
            result = client.get("application-units/depth-ledger")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return

        if args.unit_id is None:
            sys.exit(f"app-unit {args.action}: a unit id is required")
        override_map = {
            "mark-deep": "mark-deep",
            "clear-deep": "clear-deep",
            "clear": None,
        }
        payload: dict = {"override": override_map[args.action]}
        if args.reason.strip():
            payload["reason"] = args.reason.strip()
        record = client.patch(f"application-units/{args.unit_id}", payload)
        print(json.dumps(record, indent=2, ensure_ascii=False))
