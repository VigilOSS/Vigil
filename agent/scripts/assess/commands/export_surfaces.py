"""vigil assess export surfaces — generate surfaces.jsonl from backend state on demand."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("surfaces", help="Generate surfaces.jsonl from backend state")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        surfaces = _get_all_pages(client, "surfaces")

    if not isinstance(surfaces, list):
        print("export-surfaces: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    out_path = Path(cfg.engagement_dir) / "surfaces.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for surface in surfaces:
            f.write(json.dumps(surface, ensure_ascii=True) + "\n")

    print(f"Exported {len(surfaces)} surfaces to {out_path}")


def _get_all_pages(client: AssessmentClient, endpoint: str) -> Any:
    pager = getattr(client, "get_all_pages", None)
    if callable(pager):
        return pager(endpoint)
    return client.get(endpoint)
