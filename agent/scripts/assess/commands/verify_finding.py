"""assess.py verify-finding — dedicated verifier flow for canonical findings."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.findings import sync_finding_markdown, update_finding_count


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "verify-finding",
        help="POST /assessment/findings/<slug>/verify with JSON payload",
    )
    p.add_argument("finding_slug", help="Canonical finding slug to verify")
    p.add_argument("json_file", help="Path to JSON verification payload")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"JSON file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("verification payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post(f"findings/{args.finding_slug}/verify", payload)
    finally:
        client.close()

    findings_file = Path(cfg.engagement_dir) / "findings.md"
    finding = result.get("finding")
    if isinstance(finding, dict) and findings_file.is_file():
        sync_finding_markdown(str(findings_file), finding)
        update_finding_count(str(findings_file))

    print(json.dumps(result, indent=2, ensure_ascii=False))
