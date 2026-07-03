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

import pytest


# conftest.py is imported by pytest BEFORE any test module is collected, and a
# conftest at this location is always loaded for tests under tests/. Insert
# `agent/scripts` on sys.path here (at import time, not in a fixture) so the
# top-level `import assess.*` in each test module resolves during collection.
_SCRIPTS_ROOT = Path(__file__).resolve().parents[2]  # agent/scripts
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))


@pytest.fixture(autouse=True)
def _isolate_vigil_config(tmp_path, monkeypatch):
    """Point $VIGIL_CONFIG at a per-test, non-existent temp file so the
    engagement resolver never reads the developer's real
    ~/.config/vigil/config.json.

    The active-engagement pointer (resolver tier 3) lives in that file and now
    out-ranks $ENGAGEMENT_DIR (tier 4); without this isolation a real pointer on
    the developer's machine would silently win over an $ENGAGEMENT_DIR-based test
    and flip its result. A test that needs a pointer writes to this same path.
    """
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "vigil-config.json"))
