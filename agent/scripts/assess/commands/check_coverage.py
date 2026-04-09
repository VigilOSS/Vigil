"""assess.py check-coverage — read surfaces.jsonl, report unresolved surfaces."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.config import load_config
from assess.lib.surfaces import surface_file_path


_STRICT_DEFERRED_TYPES = frozenset({
    "account_recovery",
    "dynamic_render",
    "object_reference",
    "privileged_write",
})


def register(subparsers) -> None:
    p = subparsers.add_parser("check-coverage", help="Check surface coverage status")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    sf = Path(surface_file_path(cfg.engagement_dir))

    if not sf.is_file():
        print(f"surfaces.jsonl not found in {cfg.engagement_dir}", file=sys.stderr)
        sys.exit(1)

    unresolved = []
    blocked_deferred = []

    for line in sf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        surface_type = row.get("surface_type")
        target = row.get("target")
        status = row.get("status")

        if status == "discovered":
            unresolved.append(f"{surface_type} | {target}")
        elif status == "deferred" and surface_type in _STRICT_DEFERRED_TYPES:
            blocked_deferred.append(f"{surface_type} | {target}")

    if unresolved or blocked_deferred:
        if unresolved:
            print("Uncovered surfaces remain:", file=sys.stderr)
            for item in unresolved:
                print(f"  - {item}", file=sys.stderr)
        if blocked_deferred:
            print("High-risk surfaces cannot remain deferred:", file=sys.stderr)
            for item in blocked_deferred:
                print(f"  - {item}", file=sys.stderr)
            print("Resolve them as covered or not_applicable before finishing Test/Report.", file=sys.stderr)
        sys.exit(1)

    print("surface coverage: ok")
