"""Deprecated engagement-dir resolver — thin delegating shim.

Historically this module carried a *second*, divergent precedence
(``$ENGAGEMENT_DIR`` before cwd, no walk-up). It has no importers, but is kept
as a delegating shim so a third precedence can never drift back in: the single
source of truth is :func:`assess.lib.config.resolve_engagement_dir` (flag →
cwd walk-up → active pointer → ``$ENGAGEMENT_DIR`` → error).
"""
from __future__ import annotations

from .config import resolve_engagement_dir as _resolve_engagement_dir


def resolve_engagement_dir(root: str | None = None) -> str | None:
    """Return the resolved engagement dir, or None when it cannot be resolved.

    Delegates to the unified resolver in :mod:`assess.lib.config`. The legacy
    ``root`` argument (an explicit directory to prefer) maps onto the flag tier.
    Returns None instead of raising to preserve this module's historical
    Optional contract.
    """
    try:
        return _resolve_engagement_dir(root)
    except SystemExit:
        return None
