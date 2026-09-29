"""Active-engagement pointer for the top-level `vigil` verbs.

Covers the `vigil use` verb (write pointer + `.active` mirror, and `--clear`),
the launcher pointer refresh (`start_engagement`), the unified `vigil`-verb
resolver (cwd walk-up > active pointer > $ENGAGEMENT_DIR), the stale/invalid
pointer skip, and the `vigil engagement current` diagnostic's winning-tier
report.

Isolation: $VIGIL_CONFIG is redirected to a per-test temp file, $ENGAGEMENT_DIR
is cleared, and cwd is pinned to a neutral dir — so nothing touches the
developer's real ~/.config/vigil/config.json, `.active` mirror, or cwd.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from vigil_cli import config as config_module
from vigil_cli import engagements
from vigil_cli import main as main_module

POINTER_KEY = "active_engagement_dir"


def _make_install(base: Path) -> Path:
    (base / "agent" / "engagements").mkdir(parents=True, exist_ok=True)
    (base / "agent" / "AGENTS.md").write_text("web operator\n")
    return base


def _make_engagement(root: Path, name: str) -> Path:
    eng = root / name
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "hostname": f"{name}.example.com", "status": "active"})
    )
    return eng


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.chdir(neutral)


@pytest.fixture
def install(tmp_path):
    return _make_install(tmp_path / "install")


def test_set_active_engagement_writes_pointer_and_mirror(install):
    eng = _make_engagement(engagements.engagements_root(install), "eng-1")
    resolved = engagements.set_active_engagement(install, eng)
    assert resolved == eng.resolve()
    assert config_module.get_config_value(POINTER_KEY) == str(eng.resolve())
    mirror = engagements.engagements_root(install) / ".active"
    assert mirror.read_text().strip() == "eng-1"


def test_clear_active_engagement_removes_pointer_and_mirror(install):
    eng = _make_engagement(engagements.engagements_root(install), "eng-1")
    engagements.set_active_engagement(install, eng)
    engagements.clear_active_engagement(install)
    assert config_module.get_config_value(POINTER_KEY) is None
    assert not (engagements.engagements_root(install) / ".active").exists()


def test_set_active_rejects_non_engagement(install, tmp_path):
    noteng = tmp_path / "noteng"
    noteng.mkdir()
    with pytest.raises(SystemExit):
        engagements.set_active_engagement(install, noteng)


def test_resolve_current_cwd_beats_pointer_and_env(install, monkeypatch):
    root = engagements.engagements_root(install)
    engB = _make_engagement(root, "engB")
    engagements.set_active_engagement(install, _make_engagement(root, "engC"))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(_make_engagement(root, "engA")))
    sub = engB / "scans"
    sub.mkdir()
    monkeypatch.chdir(sub)
    assert engagements.resolve_current_engagement() == (engB.resolve(), "cwd")


def test_resolve_current_pointer_beats_env(install, monkeypatch):
    root = engagements.engagements_root(install)
    engC = _make_engagement(root, "engC")
    engagements.set_active_engagement(install, engC)
    monkeypatch.setenv("ENGAGEMENT_DIR", str(_make_engagement(root, "engA")))
    assert engagements.resolve_current_engagement() == (engC.resolve(), "pointer")


def test_resolve_current_env_last(install, monkeypatch):
    root = engagements.engagements_root(install)
    engA = _make_engagement(root, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    assert engagements.resolve_current_engagement() == (engA.resolve(), "env")


def test_resolve_current_none_when_unresolvable():
    assert engagements.resolve_current_engagement() is None
    assert engagements.current_engagement_path() is None


def test_stale_invalid_pointer_skipped(install, tmp_path, monkeypatch, capsys):
    dead = tmp_path / "dead"
    dead.mkdir()
    config_module.set_config_value(POINTER_KEY, str(dead))
    root = engagements.engagements_root(install)
    engA = _make_engagement(root, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    assert engagements.resolve_current_engagement() == (engA.resolve(), "env")
    assert "active engagement pointer" in capsys.readouterr().err


def test_stale_env_loses_to_cwd_behavioral(install, monkeypatch, capsys):
    root = engagements.engagements_root(install)
    stale = _make_engagement(root, "acme-telco")
    here = _make_engagement(root, "acme-planner")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(stale))
    monkeypatch.chdir(here)
    assert engagements.resolve_current_engagement() == (here.resolve(), "cwd")
    assert "$ENGAGEMENT_DIR points at" in capsys.readouterr().err


def test_start_engagement_refreshes_pointer(install, monkeypatch):
    root = engagements.engagements_root(install)
    eng = _make_engagement(root, "eng-1")
    (eng / "start_claude.sh").write_text("#!/usr/bin/env bash\n")
    calls: dict[str, object] = {}
    monkeypatch.setattr(engagements.os, "chdir", lambda p: calls.__setitem__("chdir", p))
    monkeypatch.setattr(engagements.os, "execv", lambda p, a: calls.__setitem__("execv", (p, a)))
    engagements.start_engagement(install, eng, "claude", [])
    assert config_module.get_config_value(POINTER_KEY) == str(eng.resolve())
    assert (root / ".active").read_text().strip() == "eng-1"
    assert "execv" in calls


def test_use_cli_sets_pointer(install, capsys):
    root = engagements.engagements_root(install)
    eng = _make_engagement(root, "eng-1")
    args = argparse.Namespace(key="eng-1", select=False, clear=False)
    main_module._use(args, install)
    assert config_module.get_config_value(POINTER_KEY) == str(eng.resolve())
    assert str(eng.resolve()) in capsys.readouterr().out


def test_use_cli_clear(install):
    root = engagements.engagements_root(install)
    eng = _make_engagement(root, "eng-1")
    engagements.set_active_engagement(install, eng)
    args = argparse.Namespace(key=None, select=False, clear=True)
    main_module._use(args, install)
    assert config_module.get_config_value(POINTER_KEY) is None


def test_use_cli_requires_key_or_select(install):
    args = argparse.Namespace(key=None, select=False, clear=False)
    with pytest.raises(SystemExit):
        main_module._use(args, install)


def test_engagement_current_reports_pointer_tier(install, capsys):
    root = engagements.engagements_root(install)
    eng = _make_engagement(root, "eng-1")
    engagements.set_active_engagement(install, eng)
    main_module._engagement_current(install)
    captured = capsys.readouterr()
    assert str(eng.resolve()) in captured.out
    assert "active pointer" in captured.err


def test_engagement_current_none_errors(install):
    with pytest.raises(SystemExit):
        main_module._engagement_current(install)
