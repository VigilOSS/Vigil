"""assess.py code-record-modules — POST module definitions for a code repository."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-record-modules", help="Record module definitions for a code repository")
    p.add_argument("repo_id", help="Repository ID")
    p.add_argument("modules_json", help="Path to JSON file with array of module objects")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.modules_json)
    if not json_path.is_file():
        print(f"Modules JSON file not found: {args.modules_json}", file=sys.stderr)
        sys.exit(1)

    modules = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(modules, list):
        print("Modules file must contain a JSON array", file=sys.stderr)
        sys.exit(1)

    if not modules:
        print("No modules to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate required fields
    for i, mod in enumerate(modules):
        if not isinstance(mod, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        if 'module_key' not in mod:
            print(f"Item {i} missing required field 'module_key'", file=sys.stderr)
            sys.exit(1)

    payload = {
        'repo_id': args.repo_id,
        'modules': modules,
    }

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/modules', payload)
    finally:
        client.close()

    created_count = result.get('created', len(modules))
    print(f"=== Code Modules Summary ===")
    print(f"Modules created: {created_count}")
    print(json.dumps(result, indent=2, ensure_ascii=False))
