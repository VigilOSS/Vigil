"""vigil assess get-command-run — fetch a single command-run record with full previews."""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "get-command-run",
        help="Fetch a single `vigil assess kali` command-run record by id, including previews and artifact refs",
    )
    p.add_argument("command_run_id", type=int, help="numeric id from list-command-runs")
    p.add_argument("--json", dest="as_json", action="store_true", help="No-op: get-command-run always emits JSON.")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        row = client.get(f"command-runs/{int(args.command_run_id)}")
    print(json.dumps(row, indent=2, ensure_ascii=False))
