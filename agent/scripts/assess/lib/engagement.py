"""Engagement dir resolution — replaces lib/engagement.sh for Python callers."""
from __future__ import annotations

import os
from pathlib import Path


def resolve_engagement_dir(root: str | None = None) -> str | None:
    """Resolve engagement directory. Returns None if not found.

    Resolution order:
    1. ENGAGEMENT_DIR env var if it points to a real directory
    2. root argument / cwd if it contains scope.json
    """
    env_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return str(Path(env_dir).resolve())

    if root is None:
        root = os.getcwd()

    if Path(root).is_dir() and (Path(root) / "scope.json").is_file():
        return str(Path(root).resolve())

    return None
