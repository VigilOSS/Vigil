"""vigil assess record-chain — POST attack chain + emit event."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config

# Backend activity-event field cap (CreateEventRequest.task_name max_length at
# orchestrator/backend/app/api/events.py). The backend derives the chain_key as
# `_slugify(title)` with no length cap and accepts titles up to 512 chars, so a
# long title yields a chain_key well over this cap. The chain row persists, but
# the event emit would 422 and silently drop the activity-feed event — so we
# truncate the chain_key used in the event CLI-side (I-18).
EVENT_TASK_NAME_MAX = 128


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
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        response = client.post("attack-chains", chain)

    chain_key = ""
    try:
        chain_key = response["chain"]["chain_key"]
    except (KeyError, TypeError):
        pass

    if not chain_key:
        print("record-chain: backend did not return a valid chain", file=sys.stderr)
        sys.exit(1)

    # Emit event. Truncate the chain_key used in the event to the backend
    # task_name cap so a long title does not 422 the activity-feed emit (which
    # would silently drop the event even though the chain row persisted). Bound
    # the summary the same way so it stays under its own cap. The FULL chain_key
    # is still printed below for downstream consumers.
    event_chain_key = chain_key[:EVENT_TASK_NAME_MAX]
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": "chain.created",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": event_chain_key,
            "agent_name": args.agent_name,
            "summary": f"Attack chain recorded: {event_chain_key}",
        })

    print(chain_key)
