"""assess.py code-record-contexts — POST context slices for code analysis."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-record-contexts", help="Record context slices for code analysis")
    p.add_argument("contexts_json", help="Path to JSON file with array of context slice objects")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.contexts_json)
    if not json_path.is_file():
        print(f"Contexts JSON file not found: {args.contexts_json}", file=sys.stderr)
        sys.exit(1)

    contexts = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(contexts, list):
        print("Contexts file must contain a JSON array", file=sys.stderr)
        sys.exit(1)

    if not contexts:
        print("No contexts to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate each item is a dict
    for i, ctx in enumerate(contexts):
        if not isinstance(ctx, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/contexts', {'contexts': contexts})
    finally:
        client.close()

    if isinstance(result, dict):
        inserted = result.get('inserted', 0)
        skipped = result.get('skipped', 0)
        print(f"=== Code Contexts Summary ===")
        print(f"Contexts inserted: {inserted} (skipped: {skipped})")
    else:
        print(f"=== Code Contexts Summary ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))
