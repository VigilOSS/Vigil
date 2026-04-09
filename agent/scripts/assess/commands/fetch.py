"""assess.py fetch — GET assessment endpoint and print JSON."""
from __future__ import annotations

import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("fetch", help="GET /assessment/{endpoint}")
    p.add_argument("endpoint", help="e.g. findings, report-findings, credentials, summary, coverage-items")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.get(args.endpoint)
        if isinstance(result, str):
            print(result)
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()
