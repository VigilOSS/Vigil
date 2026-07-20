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

# The tests directory is on sys.path (pytest prepend import mode; no __init__.py
# here), so the shared, backend-less fake for AssessmentClient imports as a
# top-level module. Re-exported here so `from conftest import FakeAssessmentClient`
# also resolves and so the module is always loaded for the suite.
from _fake_client import FakeAssessmentClient  # noqa: E402,F401


@pytest.fixture(autouse=True)
def _isolate_vigil_config(tmp_path, monkeypatch):
    """Point $VIGIL_CONFIG at a per-test, non-existent temp file so the
    engagement resolver never reads the developer's real
    ~/.config/vigil/config.json.

    Assessment state no longer resolves through the active pointer, but other
    helpers still read this config and must not observe the developer's state.
    """
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "vigil-config.json"))
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)
