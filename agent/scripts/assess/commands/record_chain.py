"""assess.py record-chain — POST attack chain + emit event."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("record-chain", help="Record an attack chain")
    p.add_argument("agent_name", help="Agent name")
    p.add_argument("json_file", help="Path to chain JSON file")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"chain json file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    chain = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(chain, dict):
        print("chain payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    if not chain.get("title"):
        print("chain payload must have a non-empty title", file=sys.stderr)
        sys.exit(1)

    # Inject provenance defaults
    prov = chain.get("provenance") or {}
    prov.setdefault("agent_name", args.agent_name)
    chain["provenance"] = prov

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        response = client.post("attack-chains", chain)
    finally:
        client.close()

    chain_key = ""
    try:
        chain_key = response["chain"]["chain_key"]
    except (KeyError, TypeError):
        pass

    if not chain_key:
        print("record-chain: backend did not return a valid chain", file=sys.stderr)
        sys.exit(1)

    # Emit event
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.post_event({
            "event_type": "chain.created",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": chain_key,
            "agent_name": args.agent_name,
            "summary": f"Attack chain recorded: {chain_key}",
        })
    finally:
        client.close()

    print(chain_key)
