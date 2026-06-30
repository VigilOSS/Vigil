"""Tests for the `vigil assess kali robots` pre-crawl known-file fetch wrapper.

Argv-construction + registration unit tests (no live execution): ``kali_exec``
is monkeypatched to capture the built argv. The engine is httpx, so the audit
``tool_name`` must stay ``httpx`` (required-header injection + scope posture are
inherited from the httpx classification).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

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


_AUDIT = [
    "--technique", "RECON", "--intent", "x",
    "--probe-kind", "fingerprint", "--phase", "recon", "--timeout", "300",
]


def _capture(monkeypatch) -> dict:
    kali = _import("assess.lib.kali")
    captured: dict = {}

    def fake_kali_exec(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        return kali.KaliResult(
            run_id=1, status="completed", return_code=0,
            stdout_path="/tmp/x.out", stderr_path="/tmp/x.err",
            duration_ms=1, peak_rss_bytes=None, stdout_preview="",
            stderr_preview="", timed_out=False, partial_results=False,
        )

    monkeypatch.setattr(_import("assess.commands.kali_robots"), "kali_exec", fake_kali_exec)
    return captured


def _val_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_robots_registered_and_in_roster(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])
    assert "robots" in capsys.readouterr().out
    contracts = _import("assess.lib.contracts")
    assert "robots" in contracts.KALI_TARGET_VERBS
    assert contracts.get_contract("kali robots") is not None


def test_robots_requires_audit_flags():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "robots", "-u", "https://x"])
    assert exc.value.code != 0


def test_robots_requires_target_or_list():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "robots", *_AUDIT])


def test_robots_default_known_paths_and_match_codes(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(["kali", "robots", "-l", "hosts.txt", *_AUDIT])
    cmd = captured["cmd"]
    # Engine is httpx; tool_name stays httpx so it inherits header injection.
    assert cmd[0] == "httpx"
    assert captured["kwargs"]["tool_name"] == "httpx"
    assert _val_after(cmd, "-l") == "hosts.txt"
    paths = _val_after(cmd, "-path")
    assert "/robots.txt" in paths
    assert "/sitemap.xml" in paths
    assert "/.well-known/security.txt" in paths
    # 401/403 kept so a gated-but-present file still surfaces.
    mc = _val_after(cmd, "-mc")
    assert "401" in mc and "403" in mc and "200" in mc
    assert "-silent" in cmd


def test_robots_positional_target_maps_to_dash_u(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(["kali", "robots", "https://x.example", *_AUDIT])
    assert _val_after(captured["cmd"], "-u") == "https://x.example"


def test_robots_paths_override(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "robots", "-u", "https://x", "--paths", "/robots.txt,/ads.txt", *_AUDIT]
    )
    assert _val_after(captured["cmd"], "-path") == "/robots.txt,/ads.txt"
