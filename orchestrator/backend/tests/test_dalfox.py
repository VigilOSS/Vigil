"""Tests for the `vigil assess kali dalfox` wrapper.

Argv-construction + registration unit tests (no live execution): ``kali_exec``
is monkeypatched to capture the built argv.
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
    "--technique", "XSS", "--intent", "x",
    "--probe-kind", "payload", "--phase", "consume-test", "--timeout", "1800",
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

    monkeypatch.setattr(_import("assess.commands.kali_dalfox"), "kali_exec", fake_kali_exec)
    return captured


def _val_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_dalfox_registered_and_in_roster(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])
    assert "dalfox" in capsys.readouterr().out
    contracts = _import("assess.lib.contracts")
    assert "dalfox" in contracts.KALI_TARGET_VERBS
    assert contracts.get_contract("kali dalfox") is not None


def test_dalfox_requires_audit_flags():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "dalfox", "-u", "https://x/?q=1"])
    assert exc.value.code != 0


def test_dalfox_requires_url_or_list():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "dalfox", *_AUDIT])


def test_dalfox_url_mode_and_param_focus(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "dalfox", "-u", "https://x/search?q=1", "-p", "q", "--skip-bav", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert cmd[0] == "dalfox"
    # mode subcommand `url <target>` comes first.
    assert cmd[1] == "url" and cmd[2] == "https://x/search?q=1"
    assert _val_after(cmd, "-p") == "q"
    assert "--skip-bav" in cmd
    assert captured["kwargs"]["tool_name"] == "dalfox"


def test_dalfox_file_mode(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "dalfox", "-i", "/eng/scans/xss_candidates.txt", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert cmd[1] == "file" and cmd[2] == "/eng/scans/xss_candidates.txt"


def test_dalfox_reflective_by_default_no_blind(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(["kali", "dalfox", "-u", "https://x/?q=1", *_AUDIT])
    # No blind flag unless the operator opts in.
    assert "-b" not in captured["cmd"]


def test_dalfox_blind_opt_in_emits_b_flag(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "dalfox", "-u", "https://x/?q=1", "--blind", "https://oob.example", *_AUDIT]
    )
    assert _val_after(captured["cmd"], "-b") == "https://oob.example"


def test_dalfox_timeout_renamed_to_avoid_audit_collision(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "dalfox", "-u", "https://x/?q=1", "--dalfox-timeout", "7",
         "-w", "30", "--delay", "100", "--waf-evasion", *_AUDIT]
    )
    cmd = captured["cmd"]
    # the wrapper flag is --dalfox-timeout but dalfox gets its real --timeout
    assert _val_after(cmd, "--timeout") == "7"
    assert _val_after(cmd, "-w") == "30"
    assert _val_after(cmd, "--delay") == "100"
    assert "--waf-evasion" in cmd


def test_dalfox_is_required_header_injectable():
    """dalfox sends active XSS payloads — the program marker must ride via -H."""
    kali = _import("assess.lib.kali")
    cmd = ["dalfox", "url", "https://target.example/?q=1"]
    status = kali._apply_required_headers(cmd, "dalfox", {"X-Bug-Bounty": "h"})
    assert status == "injected"
    assert cmd[-2:] == ["-H", "X-Bug-Bounty: h"]
