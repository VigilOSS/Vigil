"""Fail-closed assessment session binding.

Assessment state resolves from an explicit flag, the engagement tree containing
CWD, or the launcher-owned session variable. Global/legacy selectors never
retarget backend reads or writes.
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


@pytest.fixture
def neutral_cwd(tmp_path, monkeypatch):
    """CWD with no engagement ancestor."""
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    return neutral


def test_valid_explicit_flag_is_authoritative(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    engB = _make_engagement(tmp_path, "engB")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engB))
    resolved, tier = config.resolve_engagement_dir_with_tier(str(engA))
    assert Path(resolved) == engA.resolve()
    assert tier == "flag"


def test_cwd_walkup_used_when_session_absent(tmp_path, monkeypatch):
    engB = _make_engagement(tmp_path, "engB")
    deep = engB / "scans" / "web-discovery"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"


def test_session_used_outside_engagement_tree(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engA))
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engA.resolve()
    assert tier == "session"


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


def test_scans_trap_session_without_scope(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    scans = engA / "scans"
    scans.mkdir()
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(scans))
    with pytest.raises(SystemExit) as exc:
        config.resolve_engagement_dir_with_tier()
    msg = str(exc.value)
    assert "$VIGIL_SESSION_ENGAGEMENT_DIR" in msg
    assert "has no scope.json" in msg


def test_cwd_walkup_fixes_scans_trap(tmp_path, monkeypatch):
    # `cd scans/` then rely on resolution: walk-up lands on the parent that
    # actually holds scope.json instead of erroring on the `scans` basename.
    engB = _make_engagement(tmp_path, "engB")
    scans = engB / "scans"
    scans.mkdir()
    monkeypatch.chdir(scans)
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"


def test_nonexistent_explicit_flag_never_falls_through(tmp_path, neutral_cwd, monkeypatch):
    monkeypatch.setenv(
        "VIGIL_SESSION_ENGAGEMENT_DIR", str(_make_engagement(tmp_path, "engA"))
    )
    with pytest.raises(SystemExit, match="does not exist"):
        config.resolve_engagement_dir_with_tier("/no/such/dir")


def test_empty_explicit_flag_never_falls_through(tmp_path, neutral_cwd, monkeypatch):
    monkeypatch.setenv(
        "VIGIL_SESSION_ENGAGEMENT_DIR", str(_make_engagement(tmp_path, "engA"))
    )
    with pytest.raises(SystemExit, match="must not be empty"):
        config.resolve_engagement_dir_with_tier("")


def test_cwd_session_disagreement_fails_closed(tmp_path, monkeypatch):
    session = _make_engagement(tmp_path, "acme-telco")
    here = _make_engagement(tmp_path, "acme-planner")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(session))
    monkeypatch.chdir(here)
    with pytest.raises(SystemExit) as exc:
        config.resolve_engagement_dir_with_tier()
    message = str(exc.value)
    assert "conflicts" in message
    assert str(session.resolve()) in message
    assert str(here.resolve()) in message


def test_cwd_session_agreement_uses_cwd(tmp_path, monkeypatch):
    engB = _make_engagement(tmp_path, "engB")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engB))
    (engB / "scans").mkdir(exist_ok=True)
    monkeypatch.chdir(engB / "scans")
    resolved, tier = config.resolve_engagement_dir_with_tier()
    assert Path(resolved) == engB.resolve()
    assert tier == "cwd"


def test_pointer_and_legacy_env_do_not_select_assessment_state(
    tmp_path, neutral_cwd, monkeypatch
):
    pointer = _make_engagement(tmp_path, "pointer")
    legacy = _make_engagement(tmp_path, "legacy")
    # Write the isolated config directly; ENGAGEMENT_DIR remains a path variable only.
    config_file = Path(os.environ["VIGIL_CONFIG"])
    config_file.write_text(json.dumps({"active_engagement_dir": str(pointer)}))
    monkeypatch.setenv("ENGAGEMENT_DIR", str(legacy))
    with pytest.raises(SystemExit, match="Cannot resolve engagement directory"):
        config.resolve_engagement_dir_with_tier()


def test_legacy_env_mismatch_warns_but_does_not_select_assessment_state(
    tmp_path, monkeypatch, capsys
):
    cwd_engagement = _make_engagement(tmp_path, "cwd-engagement")
    legacy_engagement = _make_engagement(tmp_path, "legacy-engagement")
    monkeypatch.chdir(cwd_engagement)
    monkeypatch.setenv("ENGAGEMENT_DIR", str(legacy_engagement))

    resolved, tier = config.resolve_engagement_dir_with_tier()

    assert Path(resolved) == cwd_engagement.resolve()
    assert tier == "cwd"
    warning = capsys.readouterr().err
    assert "$ENGAGEMENT_DIR is only an artifact-path variable" in warning
    assert str(cwd_engagement.resolve()) in warning
    assert str(legacy_engagement.resolve()) in warning


def test_resolve_engagement_dir_thin_wrapper_returns_str(tmp_path, neutral_cwd, monkeypatch):
    engA = _make_engagement(tmp_path, "engA")
    monkeypatch.setenv("VIGIL_SESSION_ENGAGEMENT_DIR", str(engA))
    assert Path(config.resolve_engagement_dir()) == engA.resolve()
