"""Tests for the kali-wrapper flag-promotion + ergonomics refactor.

Covers the safe-by-default doctrine baked into the typed wrappers (katana depth/
scope/rate/disk defaults, nuclei WAF-resilience flags), the resolved_argv
surfacing, the no-audit tool-help verb, and the composed arjun-sweep flow. Like
test_kali_cli.py, the real ``docker exec`` is never invoked — ``kali_exec`` is
monkeypatched to capture its call shape.
"""

from __future__ import annotations

import importlib
import json
import re
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


_AUDIT = [
    "--technique", "DISCOVERY", "--intent", "x",
    "--probe-kind", "fingerprint", "--phase", "recon", "--timeout", "60",
]


def _capture_kali_exec(monkeypatch, module_name: str) -> dict:
    """Patch kali_exec on a command module; return a dict that captures cmd/kwargs."""
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

    mod = _import(module_name)
    monkeypatch.setattr(mod, "kali_exec", fake_kali_exec)
    return captured


def _val_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


# ── katana defaults ────────────────────────────────────────────────────────

def test_katana_bakes_in_deep_safe_defaults(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    cli = _import("assess.cli")
    cli.main(["kali", "katana", "-u", "https://x.example", *_AUDIT])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-d") == "5"          # deep by default
    assert _val_after(cmd, "-fs") == "fqdn"      # scope-safe by default
    assert _val_after(cmd, "-rl") == "10"        # politely rated by default
    assert _val_after(cmd, "-c") == "5"
    assert "-or" in cmd and "-ob" in cmd         # disk-bounded by default
    assert "-ef" in cmd                          # static assets excluded by default
    assert "-jc" in cmd and "-jsl" in cmd        # JS-aware by default


def test_katana_accepts_legacy_positive_js_flags(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    cli = _import("assess.cli")
    cli.main(["kali", "katana", "-u", "https://x.example", "-jc", "-jsl", *_AUDIT])

    cmd = captured["cmd"]
    assert cmd.count("-jc") == 1
    assert cmd.count("-jsl") == 1


def test_katana_help_hides_legacy_positive_js_flags(capsys):
    cli = _import("assess.cli")

    with pytest.raises(SystemExit) as exc:
        cli.main(["kali", "katana", "-h"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--no-jc" in out
    assert "--no-jsl" in out
    assert re.search(r"(^|\s)-jc($|[\s,])", out) is None
    assert re.search(r"(^|\s)-jsl($|[\s,])", out) is None


def test_katana_rate_hard_caps_at_20_and_allow_fast_overrides(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    cli = _import("assess.cli")
    cli.main(["kali", "katana", "-u", "https://x", "-rl", "80", *_AUDIT])
    assert _val_after(captured["cmd"], "-rl") == "20"  # clamped to the safety cap

    captured2 = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(
        ["kali", "katana", "-u", "https://x", "-rl", "80", "--allow-fast-crawl", *_AUDIT]
    )
    assert _val_after(captured2["cmd"], "-rl") == "80"  # opt-in override


def test_katana_keep_bodies_and_include_static_toggles(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(
        ["kali", "katana", "-u", "https://x", "--keep-bodies", "--include-static", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert "-or" not in cmd and "-ob" not in cmd  # bodies kept
    assert "-ef" not in cmd                        # static included


def test_katana_no_jsl_and_rdn_overrides(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(
        ["kali", "katana", "-u", "https://x", "--no-jsl", "-fs", "rdn", *_AUDIT]
    )
    cmd = captured["cmd"]
    assert "-jsl" not in cmd
    assert _val_after(cmd, "-fs") == "rdn"


# ── nuclei WAF-resilience ──────────────────────────────────────────────────

def test_nuclei_injects_mhe_default(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_nuclei")
    _import("assess.cli").main(
        ["kali", "nuclei", "-l", "hosts.txt", "-t", "http/cves/", *_AUDIT]
    )
    assert _val_after(captured["cmd"], "-mhe") == "50"


def test_nuclei_waf_flags_passthrough(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_nuclei")
    _import("assess.cli").main([
        "kali", "nuclei", "-u", "https://x", "-t", "http/cves/",
        "-mhe", "100", "-random-agent", "-H", "Cookie: s=1", *_AUDIT,
    ])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-mhe") == "100"
    assert "-random-agent" in cmd
    assert _val_after(cmd, "-H") == "Cookie: s=1"


# ── remaining thin wrappers ────────────────────────────────────────────────

def test_httpx_promoted_transport_flags(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_httpx")
    _import("assess.cli").main([
        "kali", "httpx", "-u", "https://x", "-threads", "10", "-rate-limit", "5",
        "-timeout", "8", "-H", "X-Test: 1", "-mc", "200", *_AUDIT,
    ])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-threads") == "10"
    assert _val_after(cmd, "-rate-limit") == "5"
    assert _val_after(cmd, "-timeout") == "8"
    assert _val_after(cmd, "-H") == "X-Test: 1"
    assert _val_after(cmd, "-mc") == "200"


def test_ffuf_promoted_filter_flags(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_ffuf")
    _import("assess.cli").main([
        "kali", "ffuf", "-u", "https://x/FUZZ", "-w", "/w.txt",
        "-t", "40", "-timeout", "5", "-fw", "10", "-ac", "-recursion", *_AUDIT,
    ])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-t") == "40"
    assert _val_after(cmd, "-fw") == "10"
    assert "-ac" in cmd and "-recursion" in cmd


def test_nikto_evasion_and_useragent(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_nikto")
    _import("assess.cli").main([
        "kali", "nikto", "--host", "https://x", "-evasion", "1", "-useragent", "moz", *_AUDIT,
    ])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-evasion") == "1"
    assert _val_after(cmd, "-useragent") == "moz"


def test_gau_timeout_renamed_to_avoid_audit_collision(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_gau")
    _import("assess.cli").main([
        "kali", "gau", "example.com", "--gau-timeout", "30", "--mc", "200", *_AUDIT,
    ])
    cmd = captured["cmd"]
    # the wrapper flag is --gau-timeout but the tool gets gau's real --timeout
    assert _val_after(cmd, "--timeout") == "30"
    assert _val_after(cmd, "--mc") == "200"


# ── resolved_argv surfacing ────────────────────────────────────────────────

def test_emit_result_includes_resolved_argv(capsys):
    kali = _import("assess.lib.kali")
    result = kali.KaliResult(
        run_id=1, status="completed", return_code=0,
        stdout_path="/tmp/x.out", stderr_path="/tmp/x.err", duration_ms=1,
        peak_rss_bytes=None, stdout_preview="", stderr_preview="",
        timed_out=False, partial_results=False,
        resolved_argv=["katana", "-d", "5", "-H", "X-Bug-Bounty: h"],
    )
    kali.emit_result(result)
    obj = json.loads(capsys.readouterr().out)
    assert obj["resolved_argv"] == ["katana", "-d", "5", "-H", "X-Bug-Bounty: h"]


# ── tool-help (no audit flags) ─────────────────────────────────────────────

def test_tool_help_runs_without_audit_flags(monkeypatch, capsys):
    th = _import("assess.commands.kali_tool_help")
    monkeypatch.setattr(th, "_check_container_running", lambda c: None)
    monkeypatch.setattr(
        th, "_run_help",
        lambda container, tool, flag: SimpleNamespace(returncode=0, stdout="KATANA HELP\n", stderr=""),
    )
    # No --technique/--intent/... required: this must NOT raise SystemExit.
    _import("assess.cli").main(["kali", "tool-help", "katana"])
    assert "KATANA HELP" in capsys.readouterr().out


def test_tool_help_rejects_unsafe_tool_name(monkeypatch):
    th = _import("assess.commands.kali_tool_help")
    monkeypatch.setattr(th, "_check_container_running", lambda c: None)
    # cli.main catches the AssessError and exits non-zero.
    with pytest.raises(SystemExit):
        _import("assess.cli").main(["kali", "tool-help", "katana; rm -rf /"])


# ── arjun-sweep composition ────────────────────────────────────────────────

def test_arjun_sweep_scans_each_method_and_ingests(monkeypatch, tmp_path):
    db = tmp_path / "cases.db"
    db.write_text("")  # just needs to exist for the is_file() gate

    sweep = _import("assess.commands.arjun_sweep")
    kali = _import("assess.lib.kali")

    monkeypatch.setattr(sweep, "anchor_engagement_relative", lambda p, d: str(db))
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [("GET", "https://x/a"), ("POST", "https://x/b")],
    )
    # db_query is imported inside run(); patch at the source module.
    monkeypatch.setattr(_import("assess.lib.db"), "db_query", lambda *a, **k: [])

    exec_cmds: list[list[str]] = []

    def fake_exec(cmd, **kwargs):
        exec_cmds.append(list(cmd))
        return kali.KaliResult(
            run_id=1, status="completed", return_code=0, stdout_path="", stderr_path="",
            duration_ms=1, peak_rss_bytes=None, stdout_preview="", stderr_preview="",
            timed_out=False, partial_results=False,
        )

    ingested: list[str] = []
    monkeypatch.setattr(sweep, "kali_exec", fake_exec)
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: ingested.append(ns.default_method))

    _import("assess.cli").main(["arjun-sweep", str(db), *_AUDIT])

    # one arjun call per method, each under its OWN -m, and an ingest per method.
    methods = {c[c.index("-m") + 1] for c in exec_cmds if "-m" in c}
    assert methods == {"GET", "POST"}
    assert set(ingested) == {"GET", "POST"}
    # sized-to-finish defaults: --stable is opt-in (off), -T fast-fail is on.
    for c in exec_cmds:
        assert "--stable" not in c
        assert "-T" in c


def test_arjun_sweep_caps_max_targets_and_flags_incomplete(monkeypatch, tmp_path, capsys):
    db = tmp_path / "cases.db"
    db.write_text("")
    sweep = _import("assess.commands.arjun_sweep")
    monkeypatch.setattr(sweep, "anchor_engagement_relative", lambda p, d: str(db))
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )
    # 5 GET targets; cap to 2 -> 3 deferred.
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [("GET", f"https://x/{i}") for i in range(5)],
    )
    monkeypatch.setattr(_import("assess.lib.db"), "db_query", lambda *a, **k: [])

    cmds: list[list[str]] = []

    class _Timed:
        timed_out, return_code, status = True, 143, "timed_out"
        stdout_preview, stderr_preview, run_id = "Scanning 1/2", "", 1

    monkeypatch.setattr(sweep, "kali_exec", lambda cmd, **k: (cmds.append(list(cmd)), _Timed())[1])
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: None)

    _import("assess.cli").main(["arjun-sweep", str(db), "--max-targets", "2", *_AUDIT])
    out = capsys.readouterr()
    # the cap deferred 3 of 5, and the timed-out run was flagged INCOMPLETE.
    assert "deferring 3" in out.err
    assert "INCOMPLETE" in out.err
    # only the capped 2 targets were written into the scanned list file.
    listfile = tmp_path / "scans" / "arjun-sweep" / "GET.txt"
    assert len([ln for ln in listfile.read_text().splitlines() if ln.strip()]) == 2


def test_arjun_sweep_zero_targets_does_not_scan(monkeypatch, tmp_path, capsys):
    db = tmp_path / "cases.db"
    db.write_text("")
    sweep = _import("assess.commands.arjun_sweep")
    monkeypatch.setattr(sweep, "anchor_engagement_relative", lambda p, d: str(db))
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )
    monkeypatch.setattr(sweep.arjun_select, "select_targets", lambda rows, **kw: [])
    monkeypatch.setattr(_import("assess.lib.db"), "db_query", lambda *a, **k: [{"url": "x"}])
    called: list[int] = []
    monkeypatch.setattr(sweep, "kali_exec", lambda *a, **k: called.append(1))
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: called.append(1))
    _import("assess.cli").main(["arjun-sweep", str(db), *_AUDIT])
    out = capsys.readouterr().out
    assert not called  # no scan, no ingest on an empty target set
    assert '"selected": 0' in out


def test_arjun_sweep_maps_body_verbs_to_post(monkeypatch, tmp_path):
    db = tmp_path / "cases.db"
    db.write_text("")
    sweep = _import("assess.commands.arjun_sweep")
    kali = _import("assess.lib.kali")
    monkeypatch.setattr(sweep, "anchor_engagement_relative", lambda p, d: str(db))
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )
    # arjun only accepts GET/POST/XML/JSON: PUT/PATCH/DELETE -> POST, HEAD -> GET.
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [
            ("PUT", "https://x/a"), ("PATCH", "https://x/b"),
            ("DELETE", "https://x/c"), ("HEAD", "https://x/d"),
        ],
    )
    monkeypatch.setattr(_import("assess.lib.db"), "db_query", lambda *a, **k: [])
    cmds: list[list[str]] = []

    def fake_exec(cmd, **k):
        cmds.append(list(cmd))
        return kali.KaliResult(
            run_id=1, status="completed", return_code=0, stdout_path="", stderr_path="",
            duration_ms=1, peak_rss_bytes=None, stdout_preview="", stderr_preview="",
            timed_out=False, partial_results=False,
        )

    monkeypatch.setattr(sweep, "kali_exec", fake_exec)
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: None)
    _import("assess.cli").main(["arjun-sweep", str(db), *_AUDIT])
    modes = {c[c.index("-m") + 1] for c in cmds if "-m" in c}
    assert modes == {"POST", "GET"}  # no raw PUT/PATCH/DELETE reaches arjun


def test_nuclei_timeout_and_retries_passthrough(monkeypatch):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_nuclei")
    _import("assess.cli").main([
        "kali", "nuclei", "-u", "https://x", "-t", "http/cves/",
        "-timeout", "8", "-retries", "3", *_AUDIT,
    ])
    cmd = captured["cmd"]
    assert _val_after(cmd, "-timeout") == "8"
    assert _val_after(cmd, "-retries") == "3"


def test_tool_help_falls_back_to_double_dash_help(monkeypatch, capsys):
    th = _import("assess.commands.kali_tool_help")
    monkeypatch.setattr(th, "_check_container_running", lambda c: None)
    calls: list[str] = []

    def fake_run_help(container, tool, flag):
        calls.append(flag)
        if flag == "-h":  # first attempt yields nothing -> fall through to --help
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout="REAL HELP\n", stderr="")

    monkeypatch.setattr(th, "_run_help", fake_run_help)
    _import("assess.cli").main(["kali", "tool-help", "katana"])
    assert calls == ["-h", "--help"]
    assert "REAL HELP" in capsys.readouterr().out


def test_resolve_crawl_rate_limit_precedence():
    f = _import("assess.lib.kali").resolve_crawl_rate_limit
    assert f("", rate_cap=None) == 10                       # unset -> safe default
    assert f("80", rate_cap=None) == 20                     # above hard cap -> clamp to 20
    assert f("80", rate_cap=None, allow_fast=True) == 80    # opt-in override of the cap
    assert f("", rate_cap=5.0) == 5                         # program ceiling clamps DOWN
    assert f("80", rate_cap=5.0, allow_fast=True) == 5      # ceiling beats allow_fast
    assert f("0", rate_cap=None) == 10                      # <1 -> default
    assert f("bad", rate_cap=None) == 10                    # non-numeric -> default
