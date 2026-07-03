"""Tests for the `vigil assess kali tlsx` wrapper.

Argv-construction + registration unit tests, mirroring test_kali_cli.py /
test_kali_wrapper_promotions.py: the real ``docker exec`` never fires —
``kali_exec`` is monkeypatched to capture the built argv.
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
    "--probe-kind", "fingerprint", "--phase", "recon", "--timeout", "600",
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

    monkeypatch.setattr(_import("assess.commands.kali_tlsx"), "kali_exec", fake_kali_exec)
    return captured


def _val_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_tlsx_registered_in_kali_help(capsys):
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "--help"])
    assert "tlsx" in capsys.readouterr().out


def test_tlsx_is_a_target_verb_in_roster():
    contracts = _import("assess.lib.contracts")
    assert "tlsx" in contracts.KALI_TARGET_VERBS
    assert contracts.get_contract("kali tlsx") is not None


def test_tlsx_requires_audit_flags():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "tlsx", "-l", "hosts.txt"])
    assert exc.value.code != 0


def test_tlsx_requires_a_target_or_list():
    cli = _import("assess.cli")
    with pytest.raises(SystemExit):
        cli.main(["kali", "tlsx", *_AUDIT])


def test_tlsx_default_profile_is_san_cn_resp_only_silent(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(["kali", "tlsx", "-l", "hosts.txt", *_AUDIT])
    cmd = captured["cmd"]
    assert cmd[0] == "tlsx"
    assert _val_after(cmd, "-l") == "hosts.txt"
    assert "-san" in cmd and "-cn" in cmd
    assert "-resp-only" in cmd
    assert "-silent" in cmd
    assert captured["kwargs"]["tool_name"] == "tlsx"


def test_tlsx_positional_target_maps_to_dash_u(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(["kali", "tlsx", "origin.example", *_AUDIT])
    assert _val_after(captured["cmd"], "-u") == "origin.example"


def test_tlsx_explicit_fields_replace_default_profile(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "tlsx", "-u", "x", "-cert", "-jarm", "-json", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert "-cert" in cmd and "-jarm" in cmd and "-json" in cmd
    # JSON form: no -resp-only, no implicit -silent.
    assert "-resp-only" not in cmd
    assert "-silent" not in cmd
    # The default SAN/CN profile must NOT be force-added when a field was named.
    assert "-san" not in cmd and "-cn" not in cmd


def test_tlsx_ports_and_concurrency_passthrough(monkeypatch):
    captured = _capture(monkeypatch)
    _import("assess.cli").main(
        ["kali", "tlsx", "-l", "ips.txt", "-p", "443,8443", "-c", "100", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert _val_after(cmd, "-p") == "443,8443"
    assert _val_after(cmd, "-c") == "100"


def test_tlsx_is_required_header_skip_classified():
    """tlsx speaks raw TLS (no HTTP header) — it must be SKIP, not refused."""
    kali = _import("assess.lib.kali")
    cmd = ["tlsx", "-l", "hosts.txt"]
    original = list(cmd)
    status = kali._apply_required_headers(cmd, "tlsx", {"X-Bug-Bounty": "h"})
    assert status == "skipped"
    assert cmd == original
