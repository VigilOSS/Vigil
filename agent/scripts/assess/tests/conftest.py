"""Shared pytest setup for the assess CLI test suite.

These tests exercise the host-side ``vigil assess`` CLI in isolation: no
FastAPI backend, no live runtime container. This file owns two pieces of
suite-wide setup: the import roots, so that both ``import assess.*`` and the
``vigil_cli`` imports inside assess modules resolve to the source tree, and the
per-test ``$VIGIL_CONFIG`` isolation below. A test that patches module state —
e.g. ``assess.commands.kali_sweep.kali_exec`` — owns undoing it, through
``monkeypatch`` rather than a bare assignment, because the assess modules are
imported once for the whole session.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


# conftest.py is imported by pytest BEFORE any test module is collected, and a
# conftest at this location is always loaded for tests under tests/. Set the
# roots here (at import time, not in a fixture) so the top-level
# `import assess.*` in each test module resolves during collection.
#
# Every assess test selection gets the same canonical import roots, exactly as
# `orchestrator/backend/tests/conftest.py` does for its own scope. Individual
# modules must not depend on a previously collected test mutating `sys.path`:
# `vigil_cli` is not installed in the backend venv, assess modules import it
# (`assess/lib/code_structural_identity.py` -> `vigil_cli.image_freshness`,
# reached through the bootstrap in `assess/lib/scope.py`), and leaving `src` to
# whichever module happened to be collected first made focused commands, `-k`
# filters and reordered runs fail while a full-suite run happened to pass.
_REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [
    str(_REPO_ROOT / "agent" / "scripts"),
    str(_REPO_ROOT / "src"),
]

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
