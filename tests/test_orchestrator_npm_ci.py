"""Behavior tests for `_npm_ci`'s recovery from a half-removed `node_modules`.

An interrupted `npm ci` can leave `node_modules` in a state npm itself cannot
clear (`ENOTEMPTY` on rmdir), which wedges every later build. `_npm_ci` removes
the tree and retries once; these tests pin that retry and pin that a failure
with nothing to clear still surfaces.
"""
from __future__ import annotations

import subprocess

import pytest

from vigil_cli import orchestrator


def _stub_runs(monkeypatch, returncodes):
    """Stub `subprocess.run`, returning `returncodes` in order; record calls."""
    calls: list[list[str]] = []
    codes = iter(returncodes)

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        code = next(codes)
        if code and kwargs.get("check"):
            raise subprocess.CalledProcessError(code, cmd)
        return subprocess.CompletedProcess(cmd, code)

    monkeypatch.setattr(orchestrator.subprocess, "run", fake_run)
    return calls


def test_npm_ci_clears_stale_node_modules_and_retries(tmp_path, monkeypatch, capsys):
    node_modules = tmp_path / "node_modules"
    (node_modules / "lucide-react" / "dist").mkdir(parents=True)
    calls = _stub_runs(monkeypatch, [-66, 0])

    orchestrator._npm_ci(tmp_path)

    assert calls == [["npm", "ci"], ["npm", "ci"]]
    assert not node_modules.exists()
    assert "clearing" in capsys.readouterr().out


def test_npm_ci_returns_after_a_clean_install(tmp_path, monkeypatch):
    (tmp_path / "node_modules").mkdir()
    calls = _stub_runs(monkeypatch, [0])

    orchestrator._npm_ci(tmp_path)

    assert calls == [["npm", "ci"]]
    assert (tmp_path / "node_modules").exists()


def test_npm_ci_raises_when_the_retry_also_fails(tmp_path, monkeypatch):
    (tmp_path / "node_modules").mkdir()
    _stub_runs(monkeypatch, [1, 1])

    with pytest.raises(subprocess.CalledProcessError):
        orchestrator._npm_ci(tmp_path)


def test_npm_ci_raises_when_there_is_no_tree_to_clear(tmp_path, monkeypatch):
    calls = _stub_runs(monkeypatch, [1])

    with pytest.raises(subprocess.CalledProcessError):
        orchestrator._npm_ci(tmp_path)

    assert calls == [["npm", "ci"]]
