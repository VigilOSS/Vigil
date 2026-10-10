"""Process birth checks keep release guards precise and fail closed."""
from __future__ import annotations

import subprocess

import pytest

from vigil_cli import client_sessions


def test_zombie_process_does_not_block_a_new_release(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setattr(client_sessions.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "Z Fri Oct  9 10:00:00 2026\n", ""))
    assert client_sessions._process_identity(42) is None


def test_unavailable_birth_identity_of_live_process_fails_closed(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setattr(client_sessions.os, "kill", lambda *_: None)

    def unavailable(*args, **kwargs):
        raise OSError("ps is unavailable")

    monkeypatch.setattr(client_sessions.subprocess, "run", unavailable)
    with pytest.raises(SystemExit, match="birth identity"):
        client_sessions._process_identity(42)


def test_process_birth_identity_does_not_depend_on_operator_timezone(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setenv("TZ", "America/New_York")

    def inspect(*args, **kwargs):
        assert kwargs["env"].get("TZ") == "UTC"
        return subprocess.CompletedProcess(args, 0, "S Fri Oct  9 10:00:00 2026\n", "")

    monkeypatch.setattr(client_sessions.subprocess, "run", inspect)
    assert client_sessions._process_identity(42) == "ps:Fri Oct  9 10:00:00 2026"
