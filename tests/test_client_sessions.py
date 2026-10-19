"""Process birth checks keep release guards precise and fail closed."""
from __future__ import annotations

import subprocess

import pytest

from vigil_cli import client_sessions, process_identity


def test_zombie_process_does_not_block_a_new_release(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setattr(process_identity.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "Z Fri Oct  9 10:00:00 2026\n", ""))
    assert client_sessions._process_identity(42) is None


def test_unavailable_birth_identity_of_live_process_fails_closed(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setattr(client_sessions.os, "kill", lambda *_: None)

    def unavailable(*args, **kwargs):
        raise OSError("ps is unavailable")

    monkeypatch.setattr(process_identity.subprocess, "run", unavailable)
    with pytest.raises(SystemExit, match="birth identity"):
        client_sessions._process_identity(42)


def test_process_birth_identity_does_not_depend_on_operator_timezone(monkeypatch):
    monkeypatch.setattr(client_sessions.Path, "is_dir", lambda *_: False)
    monkeypatch.setenv("TZ", "America/New_York")

    def inspect(*args, **kwargs):
        assert kwargs["env"].get("TZ") == "UTC"
        return subprocess.CompletedProcess(args, 0, "S Fri Oct  9 10:00:00 2026\n", "")

    monkeypatch.setattr(process_identity.subprocess, "run", inspect)
    assert client_sessions._process_identity(42) == "ps:Fri Oct  9 10:00:00 2026"


@pytest.mark.parametrize('client', ['claude', 'codex', 'opencode', 'goose', 'kimi', 'pi'])
def test_retained_session_summary_explains_optional_adoption_for_actual_client(tmp_path, monkeypatch, client):
    from vigil_cli import application, restart_manifest
    monkeypatch.setattr(application, 'application_root_for_workspace', lambda _: tmp_path)
    monkeypatch.setattr(application, 'application_provenance', lambda _: {
        'version': '1.2.6', 'content_sha256': 'b' * 64,
    })
    monkeypatch.setattr(client_sessions, 'active_client_sessions', lambda _: ({
        'pid': 123, 'engagement': str(tmp_path / 'engagements/acme'), 'client': client,
        'mode': 'code', 'application': {'version': '1.2.6', 'content_sha256': 'a' * 64},
    },))
    state = restart_manifest.client_sessions_state(tmp_path)
    assert state.state == 'stale'
    assert client in state.detail.lower()
    assert 'can continue' in state.remedy.lower()
    assert 'when ready' in state.remedy.lower()
    assert f'--client {client}' in state.remedy
    assert 'updated prompts and helpers' in state.remedy


def test_no_live_sessions_has_no_adoption_action(tmp_path, monkeypatch):
    from vigil_cli import restart_manifest
    monkeypatch.setattr(client_sessions, 'active_client_sessions', lambda _: ())
    state = restart_manifest.client_sessions_state(tmp_path)
    assert state.state == 'not-running'
    assert state.remedy == ''
