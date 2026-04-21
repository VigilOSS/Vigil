"""assess.py get-command-run — fetch a single command-run record with full previews."""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "get-command-run",
        help="Fetch a single Kali MCP command-run record by id, including previews and artifact refs",
    )
    p.add_argument("command_run_id", type=int, help="numeric id from list-command-runs")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        row = client.get(f"command-runs/{int(args.command_run_id)}")
    finally:
        client.close()
    print(json.dumps(row, indent=2, ensure_ascii=False))
