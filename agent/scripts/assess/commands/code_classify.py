"""assess.py code-classify — bulk-classify code files by tier and role."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-classify", help="Bulk-classify code files for analysis prioritization")
    p.add_argument("classifications_json", help="Path to JSON file with array of classification objects")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.classifications_json)
    if not json_path.is_file():
        print(f"Classifications JSON file not found: {args.classifications_json}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        print("Classifications file must contain a JSON array", file=sys.stderr)
        sys.exit(1)

    if not payload:
        print("No classifications to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate required fields
    for i, item in enumerate(payload):
        if not isinstance(item, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        if 'file_id' not in item:
            print(f"Item {i} missing required field 'file_id'", file=sys.stderr)
            sys.exit(1)
        if 'classification' not in item:
            print(f"Item {i} missing required field 'classification'", file=sys.stderr)
            sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/files/bulk-classify', {'classifications': payload})
    finally:
        client.close()

    classified_count = result.get('updated', len(payload))

    # Compute tier breakdown
    tier_counts: dict[str, int] = {}
    for item in payload:
        tier = item.get('classification', 'unknown')
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    print(f"=== Code Classification Summary ===")
    print(f"Total classified: {classified_count}")
    print(f"\nBreakdown by tier:")
    for tier in sorted(tier_counts.keys()):
        print(f"  {tier}: {tier_counts[tier]}")
