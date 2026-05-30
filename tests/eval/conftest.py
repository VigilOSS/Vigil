"""Eval harness conftest — puts agent/scripts on sys.path so that
``assess.lib.schema_validation`` and ``assess.lib.contracts`` are
importable without installing anything extra.

This is the minimal approach: a single sys.path.insert in conftest.py,
mirroring the pattern used in orchestrator/backend/tests/test_aith_cli.py
where ``sys.path.insert(0, str(scripts_root))`` is the only wiring needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS_ROOT = _REPO_ROOT / "agent" / "scripts"

if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))
