"""Shared fixtures for the root ``tests/`` suite (the installable ``vigil`` CLI
and the bench harness).

Three concerns live here, all about running this suite hermetically from a fresh
checkout without the operator's shell environment leaking in:

1. **Importability.** Modules like ``test_active_engagement_pointer`` import
   ``vigil_cli`` directly. The package lives under the repo's ``src/`` and is
   not installed into the collection interpreter, so we put ``src/`` on
   ``sys.path`` at import time — this makes ``pytest tests/`` collect without a
   ``PYTHONPATH=src`` prefix.

2. **Config/pointer isolation.** The active-engagement pointer is persisted in
   ``~/.config/vigil/config.json`` (``$VIGIL_CONFIG`` overrides the path — see
   ``vigil_cli.config`` and ``assess.lib.config``). On an operator's machine
   that file holds a real ``active_engagement_dir``; without isolation it wins
   the resolver's pointer tier and silently steers pointer-sensitive tests at a
   live engagement. The autouse fixture redirects ``$VIGIL_CONFIG`` at a fresh
   per-test temp path so the persisted pointer reads empty. It deliberately does
   NOT touch ``$ENGAGEMENT_DIR`` — the tests that exercise the env tier set (or
   clear) it themselves via monkeypatch, and blanket-unsetting it would defeat
   those cases.

3. **Runtime data isolation.** An exported ``VIGIL_RUNTIME_DATA_DIR`` (or
   ``KALI_MCP_DATA_DIR``) relocates every install's runtime state, so the
   autouse fixture clears both; tests that exercise the override set it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src"

if _SRC_ROOT.is_dir() and str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))


@pytest.fixture(autouse=True)
def _isolate_vigil_config(tmp_path, monkeypatch):
    """Point ``$VIGIL_CONFIG`` at a fresh temp file so no persisted
    active-engagement pointer from the operator's ``~/.config/vigil`` leaks into
    resolution. The file is intentionally absent (the loaders treat a missing
    config as empty), so the pointer tier is empty unless a test writes it."""
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "vigil-config.json"))


@pytest.fixture(autouse=True)
def _isolate_runtime_data_dir(monkeypatch):
    """Keep runtime state under each test's own install root. OOB relay records
    follow the runtime data directory, so an exported ``VIGIL_RUNTIME_DATA_DIR``
    would aim allocations at the operator's real ``/data`` mount."""
    monkeypatch.delenv("VIGIL_RUNTIME_DATA_DIR", raising=False)
    monkeypatch.delenv("KALI_MCP_DATA_DIR", raising=False)


@pytest.fixture(autouse=True)
def _isolate_default_backend_listener(monkeypatch):
    """A unit test must never contact the operator's managed service on port 18000.

    Protocol tests provide fake connections; real server tests allocate an isolated
    ephemeral port. Unmocked default-endpoint probes therefore see an offline host.
    """
    import socket
    connect = socket.socket.connect
    def isolated_connect(sock, address):
        if isinstance(address, tuple) and len(address) >= 2 and address[1] == 18000:
            raise ConnectionRefusedError('isolated test backend is offline')
        return connect(sock, address)
    monkeypatch.setattr(socket.socket, 'connect', isolated_connect)
