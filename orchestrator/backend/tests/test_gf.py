"""Tests for the `vigil assess kali gf` maintenance verb.

gf is a non-target local filter: it runs no audit-flag set and shells out to
``docker exec gf`` (mirroring tool-help). These tests monkeypatch the container
helpers so no real docker call fires, and assert registration + the
no-audit-flag maintenance posture + the bucketing behaviour.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"


@pytest.fixture(scope="module", autouse=True)
def _scripts_on_path():
    if str(_SCRIPTS_ROOT) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS_ROOT))
    yield


@pytest.fixture(autouse=True)
def _reload_assess_modules():
    for mod in list(sys.modules):
        if mod == "assess" or mod.startswith("assess."):
            sys.modules.pop(mod, None)
    yield


def _import(name: str) -> ModuleType:
    return importlib.import_module(name)


def test_gf_registered_and_in_maint_roster(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])
    assert "gf" in capsys.readouterr().out
    contracts = _import("assess.lib.contracts")
    # gf is a NON-target maintenance verb — it must NOT be a target verb.
    assert "gf" in contracts.KALI_MAINT_VERBS
    assert "gf" not in contracts.KALI_TARGET_VERBS
    assert contracts.get_contract("kali gf") is not None


def test_gf_runs_without_audit_flags(monkeypatch, tmp_path, capsys):
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)

    corpus = tmp_path / "urls.txt"
    corpus.write_text(
        "https://x/?url=1\nhttps://x/static.js\nhttps://x/?redirect=2\n",
        encoding="utf-8",
    )
    out = tmp_path / "ssrf.txt"

    captured: dict = {}

    def fake_run_gf(container, pattern, corpus_text):
        captured["container"] = container
        captured["pattern"] = pattern
        captured["corpus"] = corpus_text
        # gf returns the ssrf-bucketed lines on stdout.
        return SimpleNamespace(returncode=0, stdout="https://x/?url=1\n", stderr="")

    monkeypatch.setattr(gf, "_run_gf", fake_run_gf)

    # No --technique/--intent/... required: must NOT raise SystemExit.
    _import("assess.cli").main(
        ["kali", "gf", "ssrf", "-i", str(corpus), "-o", str(out)]
    )
    assert captured["pattern"] == "ssrf"
    assert "https://x/?url=1" in captured["corpus"]
    assert out.read_text(encoding="utf-8").strip() == "https://x/?url=1"
    # The JSON summary lands on stderr (matched_count).
    err = capsys.readouterr().err
    assert '"matched_count": 1' in err


def test_gf_to_stdout_when_no_output(monkeypatch, tmp_path, capsys):
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)
    corpus = tmp_path / "urls.txt"
    corpus.write_text("https://x/?id=1\n", encoding="utf-8")
    monkeypatch.setattr(
        gf, "_run_gf",
        lambda c, p, t: SimpleNamespace(returncode=0, stdout="https://x/?id=1\n", stderr=""),
    )
    _import("assess.cli").main(["kali", "gf", "idor", "-i", str(corpus)])
    out = capsys.readouterr().out
    assert "https://x/?id=1" in out


def test_gf_list_patterns(monkeypatch, capsys):
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)
    monkeypatch.setattr(
        gf, "_list_runtime_patterns",
        lambda c: SimpleNamespace(returncode=0, stdout="ssrf\nidor\nsqli\n", stderr=""),
    )
    _import("assess.cli").main(["kali", "gf", "--list"])
    out = capsys.readouterr().out
    assert "ssrf" in out and "idor" in out


def test_gf_rejects_unsafe_pattern_name(monkeypatch, tmp_path):
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)
    corpus = tmp_path / "urls.txt"
    corpus.write_text("https://x/\n", encoding="utf-8")
    # cli.main catches the AssessError and exits non-zero.
    with pytest.raises(SystemExit):
        _import("assess.cli").main(
            ["kali", "gf", "ssrf; rm -rf /", "-i", str(corpus)]
        )


def test_gf_missing_input_errors(monkeypatch):
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)
    with pytest.raises(SystemExit):
        _import("assess.cli").main(["kali", "gf", "ssrf"])


def test_gf_empty_bucket_is_not_an_error(monkeypatch, tmp_path, capsys):
    """gf exits 1 when grep finds nothing — that is an empty bucket, not failure."""
    gf = _import("assess.commands.kali_gf")
    monkeypatch.setattr(gf, "_check_container_running", lambda c: None)
    corpus = tmp_path / "urls.txt"
    corpus.write_text("https://x/static.js\n", encoding="utf-8")
    out = tmp_path / "ssrf.txt"
    monkeypatch.setattr(
        gf, "_run_gf",
        lambda c, p, t: SimpleNamespace(returncode=1, stdout="", stderr=""),
    )
    _import("assess.cli").main(["kali", "gf", "ssrf", "-i", str(corpus), "-o", str(out)])
    err = capsys.readouterr().err
    assert '"matched_count": 0' in err
    assert out.read_text(encoding="utf-8") == ""
