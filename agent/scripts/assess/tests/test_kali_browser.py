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
import json
from pathlib import Path
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
        eval_js="",
        extra_headers=[],
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
# run() — program attribution headers (required_headers) reach chromium via CDP
# --------------------------------------------------------------------------- #


def _write_scope(eng_dir: Path, **fields) -> None:
    """Write a minimal scope.json (an engagement root) under ``eng_dir``."""
    eng_dir.mkdir(parents=True, exist_ok=True)
    payload = {"engagement_type": "web", "hosts": ["api.example.com"]}
    payload.update(fields)
    (eng_dir / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def test_run_threads_required_headers_into_driver_argv(tmp_path, monkeypatch):
    # An engagement with required_headers must have those headers reach the
    # headless-chromium navigation. kali_exec's -H injector cannot reach a
    # Selenium driver (tool_name='browser' has no -H flag), so the browser verb
    # threads them in as a JSON positional that the driver wires onto chromium
    # via CDP (Network.setExtraHTTPHeaders) before driver.get().
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    cmd = cap["cmd"]
    # JSON-encoded header map rides as the positional after the wait-selector.
    assert json.loads(cmd[9]) == {"X-Bug-Bounty": "vigiloss"}
    # The generated driver actually sets the headers on chromium over CDP.
    assert "execute_cdp_cmd" in kb._BROWSER_DRIVER
    assert "Network.setExtraHTTPHeaders" in kb._BROWSER_DRIVER


def test_run_no_headers_when_scope_has_none(tmp_path, monkeypatch):
    # No required_headers configured → an empty header map (no header is set).
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    cmd = cap["cmd"]
    assert json.loads(cmd[9]) == {}


def test_run_no_headers_when_engagement_unresolvable(monkeypatch, tmp_path):
    # An unresolvable engagement (no --engagement-dir, no scope.json reachable)
    # degrades quietly to an empty header map rather than failing the render.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=None))
    cmd = cap["cmd"]
    assert json.loads(cmd[9]) == {}


def test_run_required_headers_drop_malformed_pairs(tmp_path, monkeypatch):
    # Only str->str pairs survive (mirrors the shared _required_headers reader),
    # so a malformed scope can never inject a non-header value into the driver.
    eng_dir = tmp_path / "eng"
    _write_scope(
        eng_dir,
        required_headers={"X-Bug-Bounty": "vigiloss", "X-Bad": 5, "": "blank"},
    )
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    cmd = cap["cmd"]
    assert json.loads(cmd[9]) == {"X-Bug-Bounty": "vigiloss"}


# --------------------------------------------------------------------------- #
# run() — operator --header merge and --eval threading (LLM-friendly additions)
# --------------------------------------------------------------------------- #


def test_parse_header_args_splits_first_colon_and_trims():
    got = kb._parse_header_args(
        ["X-Debug: 1", "X-Trace:abc", "Authorization: Bearer a:b:c"]
    )
    assert got == {"X-Debug": "1", "X-Trace": "abc", "Authorization": "Bearer a:b:c"}


def test_parse_header_args_skips_malformed():
    assert kb._parse_header_args(["no-colon", "", ": empty-name", "  : x"]) == {}


def test_run_merges_operator_headers_into_driver_argv(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(
        monkeypatch,
        _browser_args(engagement_dir=str(eng_dir), extra_headers=["X-Debug: 1"]),
    )
    assert json.loads(cap["cmd"][9]) == {"X-Bug-Bounty": "vigiloss", "X-Debug": "1"}


def test_run_required_header_wins_over_operator_same_name(tmp_path, monkeypatch):
    # An operator --header must NEVER strip/override a program attribution header
    # of the same name — required headers win the merge.
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(
        monkeypatch,
        _browser_args(
            engagement_dir=str(eng_dir), extra_headers=["X-Bug-Bounty: attacker"]
        ),
    )
    assert json.loads(cap["cmd"][9])["X-Bug-Bounty"] == "vigiloss"


def test_run_threads_eval_js_as_final_argv(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(eval_js="return document.title"))
    cmd = cap["cmd"]
    # eval rides AFTER the headers positional (list index 9); the driver reads it
    # as sys.argv[8] (list index 10).
    assert cmd[10] == "return document.title"
    assert cmd[-1] == "return document.title"


def test_run_eval_js_defaults_empty(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args())
    assert cap["cmd"][10] == ""


def test_register_wires_eval_and_header_flags():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kb.register(sub)
    args = parser.parse_args(
        [
            "browser", "https://t.example/x",
            "--technique", "RECON", "--intent", "render",
            "--probe-kind", "baseline", "--phase", "recon", "--timeout", "120",
            "--eval", "window.__xss_fired",
            "--header", "X-Debug: 1", "--header", "X-Trace: 2",
        ]
    )
    assert args.eval_js == "window.__xss_fired"
    assert args.extra_headers == ["X-Debug: 1", "X-Trace: 2"]


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
