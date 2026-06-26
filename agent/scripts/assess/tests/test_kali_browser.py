"""W1 — `vigil assess kali browser` headless-render verb.

The browser verb drives headless chromium (selenium) inside the runtime to render
a URL and return the origin HTTP status + final DOM + screenshot path. It is the
trustworthy-signal recovery for a curl/httpx run that the WAF-challenge detector
flagged. These tests pin the host-side CLI glue WITHOUT a live container:

  - register() wires the audit-flag set + the url positional and the render flags;
  - run() builds a ``python3 -c <selenium-driver> <url> <screenshot> <dom> ...``
    argv, derives default engagement-relative output paths under scans/browser/,
    honours explicit --screenshot/--dom-out/--wait-selector, attributes the run as
    tool_name='browser', and threads the audit flags through to kali_exec;
  - a missing url is rejected before exec;
  - the verb is a registered, contract-discoverable KALI_TARGET_VERBS member.
"""
from __future__ import annotations

import argparse
import contextlib
import io
from types import SimpleNamespace

import pytest

from assess.commands import kali_browser as kb
from assess.lib import contracts
from assess.lib.client import AssessError
from assess.lib.kali_output import KaliResult


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mk_result() -> KaliResult:
    return KaliResult(
        run_id=1,
        status="completed",
        return_code=0,
        stdout_path="scans/kali/abc.out",
        stderr_path="scans/kali/abc.err",
        duration_ms=10,
        peak_rss_bytes=None,
        stdout_preview='{"http_status": 200, "screenshot": "scans/browser/x.png"}',
        stderr_preview="",
        timed_out=False,
        partial_results=False,
    )


def _browser_args(**overrides) -> SimpleNamespace:
    base = dict(
        url="https://api.example.com/login",
        screenshot="",
        dom_out="",
        wait_selector="",
        page_timeout=30.0,
        settle=2.0,
        technique="RECON",
        intent="render flagged surface",
        probe_kind="baseline",
        phase="recon",
        destructive=False,
        timeout=120,
        force=False,
        kali_agent_name=None,
        kali_agent_id=None,
        identity=None,
        container_name="vigil",
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _capture_run(monkeypatch, args) -> dict:
    captured: dict = {}

    def recorder(cmd, *, tool_name, **kwargs):
        captured["cmd"] = list(cmd)
        captured["tool_name"] = tool_name
        captured["kwargs"] = kwargs
        return _mk_result()

    monkeypatch.setattr(kb, "kali_exec", recorder)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        kb.run(args)
    captured["stdout"] = out.getvalue()
    return captured


# --------------------------------------------------------------------------- #
# register()
# --------------------------------------------------------------------------- #


def test_register_wires_url_and_audit_flags():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kb.register(sub)
    args = parser.parse_args(
        [
            "browser",
            "https://t.example/x",
            "--technique",
            "RECON",
            "--intent",
            "render",
            "--probe-kind",
            "baseline",
            "--phase",
            "recon",
            "--timeout",
            "120",
        ]
    )
    assert args.url == "https://t.example/x"
    assert args.func is kb.run


# --------------------------------------------------------------------------- #
# run() — argv construction
# --------------------------------------------------------------------------- #


def test_run_builds_python_selenium_driver_argv(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(url="https://api.example.com/login"))
    cmd = cap["cmd"]
    # python3 -c <driver> <url> <screenshot> <dom> <page_timeout> <settle> <wait_selector>
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert cmd[2] == kb._BROWSER_DRIVER
    assert cmd[3] == "https://api.example.com/login"
    assert cmd[4].startswith("scans/browser/") and cmd[4].endswith(".png")
    assert cmd[5].startswith("scans/browser/") and cmd[5].endswith(".html")
    assert cmd[6] == "30.0"
    assert cmd[7] == "2.0"
    assert cmd[8] == ""  # no wait selector
    assert cap["tool_name"] == "browser"


def test_run_threads_audit_flags(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args())
    kwargs = cap["kwargs"]
    assert kwargs["technique"] == "RECON"
    assert kwargs["probe_kind"] == "baseline"
    assert kwargs["phase"] == "recon"
    assert kwargs["timeout"] == 120


def test_run_default_paths_derive_from_host(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(url="https://shop.example.com/cart"))
    cmd = cap["cmd"]
    assert "shop.example.com" in cmd[4]
    assert "shop.example.com" in cmd[5]
    # Screenshot and DOM share the same slug/token stem.
    assert cmd[4][: -len(".png")] == cmd[5][: -len(".html")]


def test_run_honours_explicit_screenshot_and_dom(monkeypatch):
    cap = _capture_run(
        monkeypatch,
        _browser_args(screenshot="scans/browser/custom.png", dom_out="scans/browser/custom.html"),
    )
    cmd = cap["cmd"]
    assert cmd[4] == "scans/browser/custom.png"
    assert cmd[5] == "scans/browser/custom.html"


def test_run_passes_wait_selector_and_timings(monkeypatch):
    cap = _capture_run(
        monkeypatch,
        _browser_args(wait_selector="#app", page_timeout=45.0, settle=5.0),
    )
    cmd = cap["cmd"]
    assert cmd[6] == "45.0"
    assert cmd[7] == "5.0"
    assert cmd[8] == "#app"


def test_run_missing_url_raises(monkeypatch):
    monkeypatch.setattr(kb, "kali_exec", lambda *a, **k: _mk_result())
    with pytest.raises(AssessError):
        kb.run(_browser_args(url=""))


# --------------------------------------------------------------------------- #
# contract discoverability
# --------------------------------------------------------------------------- #


def test_browser_is_a_target_verb():
    assert "browser" in contracts.KALI_TARGET_VERBS


def test_browser_contract_resolves():
    contract = contracts.get_contract("kali browser")
    assert contract is not None
    assert contract.name == "kali browser"
    # Target-facing verb carries the audit-flag author fields.
    joined = " ".join(contract.author_supplied_fields)
    assert "--technique" in joined
    rendered = contracts.render_contract("kali browser")
    assert "browser" in rendered.lower()
