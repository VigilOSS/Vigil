"""assess.py patch — generic PATCH for findings, coverage items, and similar endpoints."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.findings import sync_finding_markdown, update_finding_count


def register(subparsers) -> None:
    p = subparsers.add_parser("patch", help="PATCH /assessment/{endpoint} with JSON file payload")
    p.add_argument("endpoint", help="e.g. coverage-items/42 or findings/FINDING-VA-001")
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
        result = client.patch(args.endpoint, payload)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    finally:
        client.close()

    if args.endpoint.startswith("findings/") and isinstance(result, dict):
        finding = result.get("finding")
        findings_file = Path(cfg.engagement_dir) / "findings.md"
        if isinstance(finding, dict) and findings_file.is_file():
            sync_finding_markdown(str(findings_file), finding)
            update_finding_count(str(findings_file))
