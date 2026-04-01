"""assess.py post — generic POST for low-frequency endpoints."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("post", help="POST /assessment/{endpoint} with JSON file payload")
    p.add_argument("endpoint", help="e.g. credentials, credential-tests, access-records, blocked-techniques, probe-runs")
    p.add_argument("json_file", help="Path to JSON payload file")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"JSON file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post(args.endpoint, payload)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()
