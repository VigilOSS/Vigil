"""Operator `vigil auth status --probe --identity` per-session verdict persistence
(WS4).

Two levels, both network-free:
  1. `auth.persist_liveness` POSTs the classified verdict to the backend
     `/credentials/{identity}/liveness` route (via the module's `_api`).
  2. The `main._auth` status branch persists ONLY when a specific `--identity`
     is probed; an active-identity probe (no --identity) stays read-only.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vigil_cli import auth  # noqa: E402
from vigil_cli import main as main_mod  # noqa: E402


def test_persist_liveness_posts_verdict_to_route(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    calls: list[tuple] = []

    def fake_api(engagement_dir, method, path="", payload=None):
        calls.append((method, path, payload))
        return {"identity_name": "cap-x", "liveness_verdict": payload["verdict"]}

    monkeypatch.setattr(auth, "_api", fake_api)

    result = auth.persist_liveness(eng, "cap-x", "dead", "2026-07-03T12:00:00Z")
    assert calls == [("POST", "/cap-x/liveness", {
        "verdict": "dead",
        "probed_at": "2026-07-03T12:00:00Z",
        "scope_key": "",
        "ttl_seconds": 900,
        "source": "auth-status",
        "reason": "",
    })]
    assert result["liveness_verdict"] == "dead"


def test_persist_liveness_defaults_probed_at_to_now(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    captured: dict = {}

    def fake_api(engagement_dir, method, path="", payload=None):
        captured["payload"] = payload
        return {}

    monkeypatch.setattr(auth, "_api", fake_api)
    auth.persist_liveness(eng, "cap-x", "live")
    # probed_at is populated (UTC ISO) when omitted so the store records a time.
    assert captured["payload"]["verdict"] == "live"
    assert captured["payload"]["probed_at"]
    assert captured["payload"]["probed_at"].endswith("Z")


def _status_args(identity=None):
    return argparse.Namespace(
        command="auth",
        auth_command="status",
        engagement=None,
        select=False,
        identity=identity,
        probe=True,
        probe_url="https://portal.example.com/home",
        scope="",
    )


def _wire_status(monkeypatch, eng, verdict="live"):
    persisted: list[tuple] = []
    monkeypatch.setattr(main_mod, "_resolve_command_engagement", lambda _root, _args: eng)
    monkeypatch.setattr(main_mod.auth_module, "status_line", lambda _eng: "status-line")
    monkeypatch.setattr(
        main_mod.auth_module,
        "probe_liveness",
        lambda _eng, _url, _identity, **_kwargs: {
            "liveness": verdict,
            "reason": "stubbed",
            "http_status": 200,
            "error": None,
            "identity_name": _identity,
        },
    )

    def fake_persist(_eng, identity, v, probed_at=None, **_kwargs):
        persisted.append((identity, v))
        return {"ok": True}

    monkeypatch.setattr(main_mod.auth_module, "persist_liveness", fake_persist)
    return persisted


def test_status_probe_with_identity_persists(tmp_path, monkeypatch, capsys):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    persisted = _wire_status(monkeypatch, eng, verdict="dead")
    main_mod._auth(_status_args(identity="cap-target"), tmp_path)
    out = capsys.readouterr().out
    assert persisted == [("cap-target", "dead")]
    assert "liveness=dead" in out
    assert "persisted=True" in out


def test_status_probe_active_identity_does_not_persist(tmp_path, monkeypatch, capsys):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    persisted = _wire_status(monkeypatch, eng, verdict="live")
    main_mod._auth(_status_args(identity=None), tmp_path)
    out = capsys.readouterr().out
    assert persisted == []  # active-identity probe stays read-only
    assert "persisted=" not in out
    assert "liveness=live" in out


def test_status_probe_missing_alias_does_not_persist_to_alias_name(
    tmp_path, monkeypatch, capsys
):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    persisted = _wire_status(monkeypatch, eng, verdict="unknown")
    monkeypatch.setattr(
        main_mod.auth_module,
        "probe_liveness",
        lambda *_args, **_kwargs: {
            "liveness": "unknown",
            "reason": "identity alias did not resolve",
            "http_status": None,
            "error": "missing identity",
            "identity_name": None,
        },
    )

    main_mod._auth(_status_args(identity="member"), tmp_path)

    assert persisted == []
    assert "persisted=False" in capsys.readouterr().out
