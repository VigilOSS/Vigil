"""Backend bridge to the canonical vuln-class taxonomy.

The single source of truth for vuln classes + families is
``agent/scripts/assess/lib/vuln_taxonomy.py``. The depth ledger (§5.3) must
derive class/family names from THAT module rather than fork the vocabulary, so
this bridge locates the agent ``assess`` package on disk and re-exports the
taxonomy. Importing it as the proper ``assess.lib.vuln_taxonomy`` package makes
``build_class_to_skills`` (which does a relative import of ``frontmatter``)
resolve correctly.

This is the ONE place that reaches across the repo tree, kept tiny and explicit
so the depth ledger imports a stable symbol regardless of CWD. If the agent
tree is ever unavailable (e.g. a backend-only deployment), the import raises at
ledger-call time, never at module import — the caller treats it as "taxonomy
unavailable" rather than crashing the API process.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[5]
_AGENT_SCRIPTS = _REPO_ROOT / "agent" / "scripts"


def _ensure_on_path() -> None:
    p = str(_AGENT_SCRIPTS)
    if _AGENT_SCRIPTS.is_dir() and p not in sys.path:
        sys.path.insert(0, p)


_ensure_on_path()

try:
    from assess.lib import vuln_taxonomy  # noqa: E402
except Exception:
    vuln_taxonomy = None  # type: ignore[assignment]


def available() -> bool:
    """True when the canonical taxonomy resolved (agent tree present)."""
    return vuln_taxonomy is not None


__all__ = ["vuln_taxonomy", "available"]
