"""Shared pytest setup for the assess CLI test suite.

These tests exercise the host-side ``vigil assess`` CLI in isolation: no
FastAPI backend, no live runtime container. ``agent/scripts`` is placed on
``sys.path`` so ``import assess.*`` resolves to the source tree, and assess
modules are force-reloaded per test so a ``monkeypatch`` of e.g.
``assess.commands.kali_sweep.kali_exec`` cannot leak across tests.
"""
from __future__ import annotations

import sys
from pathlib import Path


# conftest.py is imported by pytest BEFORE any test module is collected, and a
# conftest at this location is always loaded for tests under tests/. Insert
# `agent/scripts` on sys.path here (at import time, not in a fixture) so the
# top-level `import assess.*` in each test module resolves during collection.
_SCRIPTS_ROOT = Path(__file__).resolve().parents[2]  # agent/scripts
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))
