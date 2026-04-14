"""assess.py code-record-modules — POST module definitions for a code repository."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def _derive_module_key(name: str) -> str:
    """Slugify a module name into a valid module_key."""
    key = name.strip().lower()
    key = re.sub(r"[^a-z0-9]+", "_", key)
    return key.strip("_") or "unknown"


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

    # Validate and normalize required fields
    for i, mod in enumerate(modules):
        if not isinstance(mod, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        if 'module_key' not in mod:
            name = mod.get('name', '')
            if not name:
                print(f"Item {i} missing both 'module_key' and 'name'", file=sys.stderr)
                sys.exit(1)
            mod['module_key'] = _derive_module_key(name)
            print(f"Auto-derived module_key '{mod['module_key']}' from name '{name}'", file=sys.stderr)

    payload = {
        'repo_id': int(args.repo_id),
        'modules': modules,
    }

    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post('code/modules', payload)
    finally:
        client.close()

    if isinstance(result, list):
        print(f"=== Code Modules Summary ===")
        print(f"Modules created: {len(result)}")
        for mod in result:
            print(f"  [{mod.get('id', '?')}] {mod.get('module_key', '?')}: {mod.get('name', '?')}")
    else:
        print(f"=== Code Modules Summary ===")
        print(json.dumps(result, indent=2, ensure_ascii=False))
