"""Unified engagement-dir resolver: precedence table + stale-env/pointer guards.

Covers the 5-tier precedence (flag > cwd walk-up > active pointer >
$ENGAGEMENT_DIR > error), the stale/invalid-pointer skip, the `scans/`
basename-trap guards, and the $ENGAGEMENT_DIR mismatch warning.

Isolation: $VIGIL_CONFIG is redirected to a per-test temp file (the conftest
autouse fixture), $ENGAGEMENT_DIR is cleared per test, and cwd is pinned to a
neutral dir with no scope.json ancestor — so no assertion depends on the
developer's real ~/.config/vigil/config.json or working directory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from assess.lib import config


def _make_engagement(root: Path, name: str) -> Path:
    eng = root / name
    eng.mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(json.dumps({"hostname": f"{name}.example.com"}))
    return eng


def _write_pointer(path: str | None) -> None:
    """Write (or clear) active_engagement_dir into the isolated $VIGIL_CONFIG."""
    cfg = Path(os.environ["VIGIL_CONFIG"])
    payload: dict[str, str] = {}
    if path is not None:
        payload["active_engagement_dir"] = path
    cfg.write_text(json.dumps(payload))


@pytest.fixture
def neutral_cwd(tmp_path, monkeypatch):
    """cwd with no scope.json up the tree, and no $ENGAGEMENT_DIR set."""
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    return neutral


def test_flag_beats_all_tiers(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    engB = _make_engagement(tmp_path, "engB")
    _write_pointer(str(_make_engagement(tmp_path, "engC")))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engB))
    resolved, tier = config.resolve_engagement_dir_with_tier(str(engA))
    assert Path(resolved) == engA.resolve()
    assert tier == "flag"


def test_cwd_walkup_beats_pointer_and_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    engB = _make_engagement(tmp_path, "engB")
    _write_pointer(str(_make_engagement(tmp_path, "engC")))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(_make_engagement(tmp_path, "engA")))
    deep = engB / "scans" / "web-discovery"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"


def test_pointer_beats_env(tmp_path, neutral_cwd, monkeypatch):
    engC = _make_engagement(tmp_path, "engC")
    _write_pointer(str(engC))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(_make_engagement(tmp_path, "engA")))
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engC.resolve()
    assert tier == "pointer"


def test_env_used_when_no_higher_tier(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    _write_pointer(None)
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engA.resolve()
    assert tier == "env"


def test_error_when_nothing_resolves(neutral_cwd):
    with pytest.raises(SystemExit) as exc:
        config.resolve_engagement_dir_with_tier()
    assert "Cannot resolve engagement directory" in str(exc.value)


def test_scans_trap_flag_without_scope(tmp_path, neutral_cwd):
    engA = _make_engagement(tmp_path, "engA")
    scans = engA / "scans"
    scans.mkdir()
    with pytest.raises(SystemExit) as exc:
        config.resolve_engagement_dir_with_tier(str(scans))
    msg = str(exc.value)
    assert "has no scope.json" in msg
    assert "not an engagement root" in msg


def test_scans_trap_env_without_scope(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    scans = engA / "scans"
    scans.mkdir()
    monkeypatch.setenv("ENGAGEMENT_DIR", str(scans))
    with pytest.raises(SystemExit) as exc:
        config.resolve_engagement_dir_with_tier()
    msg = str(exc.value)
    assert "$ENGAGEMENT_DIR" in msg
    assert "has no scope.json" in msg


def test_cwd_walkup_fixes_scans_trap(tmp_path, monkeypatch):
    # `cd scans/` then rely on resolution: walk-up lands on the parent that
    # actually holds scope.json instead of erroring on the `scans` basename.
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    engB = _make_engagement(tmp_path, "engB")
    scans = engB / "scans"
    scans.mkdir()
    monkeypatch.chdir(scans)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"


def test_stale_invalid_pointer_skipped_with_warning(tmp_path, neutral_cwd, monkeypatch, capsys):
    dead = tmp_path / "dead-eng"
    dead.mkdir()
    _write_pointer(str(dead))
    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engA.resolve()
    assert tier == "env"
    err = capsys.readouterr().err
    assert "active engagement pointer" in err
    assert "not an engagement root" in err


def test_flag_nonexistent_falls_through(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    resolved, tier = config.resolve_engagement_dir_with_tier("/no/such/dir")
    assert Path(resolved) == engA.resolve()
    assert tier == "env"


def test_stale_env_loses_to_cwd_and_warns(tmp_path, monkeypatch, capsys):
    """THE BUG FIX: a stale $ENGAGEMENT_DIR=<A> loses to a cwd inside <B>, and
    the resolver warns naming both paths."""
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    stale = _make_engagement(tmp_path, "acme-telco")
    here = _make_engagement(tmp_path, "Acme")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(stale))
    monkeypatch.chdir(here)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == here.resolve()
    assert tier == "cwd"
    err = capsys.readouterr().err
    assert "$ENGAGEMENT_DIR points at" in err
    assert str(stale) in err
    assert str(here.resolve()) in err


def test_no_warning_when_env_agrees(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    engB = _make_engagement(tmp_path, "engB")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engB))
    monkeypatch.chdir(engB)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"
    assert "$ENGAGEMENT_DIR points at" not in capsys.readouterr().err


def test_resolve_engagement_dir_thin_wrapper_returns_str(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    assert Path(config.resolve_engagement_dir()) == engA.resolve()


def test_dead_shim_delegates_to_unified_resolver(tmp_path, neutral_cwd, monkeypatch):
    # The thinned lib/engagement.py must delegate (no third precedence) and
    # return None instead of raising when nothing resolves.
    from assess.lib import engagement as shim

    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("ENGAGEMENT_DIR", str(engA))
    assert shim.resolve_engagement_dir() == str(engA.resolve())
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    assert shim.resolve_engagement_dir() is None
