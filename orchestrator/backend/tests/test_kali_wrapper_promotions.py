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


def _patch_work_items_client(monkeypatch, sweep, rows):
    """Patch arjun-sweep's ``AssessmentClient`` so ``run()`` reads the work buffer
    from the backend (``client.get_all_pages("work-items")``) instead of a local
    cases.db. ``select_targets`` is monkeypatched per-test, so ``rows`` is only
    consumed by ``run()``'s empty-target-set messaging."""

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def get_all_pages(self, endpoint):
            assert endpoint == "work-items"
            return rows

        def close(self):
            return None

    monkeypatch.setattr(sweep, "AssessmentClient", _FakeClient)


def test_arjun_sweep_scans_each_method_and_ingests(monkeypatch, tmp_path):
    sweep = _import("assess.commands.arjun_sweep")
    kali = _import("assess.lib.kali")

    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(
            engagement_dir=str(tmp_path), engagement_key="eng", base_url="http://x"
        ),
    )
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [("GET", "https://x/a"), ("POST", "https://x/b")],
    )
    # The work buffer now comes from the backend, not a local cases.db.
    _patch_work_items_client(monkeypatch, sweep, [])

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

    _import("assess.cli").main(["arjun-sweep", *_AUDIT])

    # one arjun call per method, each under its OWN -m, and an ingest per method.
    methods = {c[c.index("-m") + 1] for c in exec_cmds if "-m" in c}
    assert methods == {"GET", "POST"}
    assert set(ingested) == {"GET", "POST"}
    # sized-to-finish defaults: --stable is opt-in (off), -T fast-fail is on.
    for c in exec_cmds:
        assert "--stable" not in c
        assert "-T" in c


def test_arjun_sweep_caps_max_targets_and_flags_incomplete(monkeypatch, tmp_path, capsys):
    sweep = _import("assess.commands.arjun_sweep")
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(
            engagement_dir=str(tmp_path), engagement_key="eng", base_url="http://x"
        ),
    )
    # 5 GET targets; cap to 2 -> 3 deferred.
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [("GET", f"https://x/{i}") for i in range(5)],
    )
    _patch_work_items_client(monkeypatch, sweep, [])

    cmds: list[list[str]] = []

    class _Timed:
        timed_out, return_code, status = True, 143, "timed_out"
        stdout_preview, stderr_preview, run_id = "Scanning 1/2", "", 1

    monkeypatch.setattr(sweep, "kali_exec", lambda cmd, **k: (cmds.append(list(cmd)), _Timed())[1])
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: None)

    _import("assess.cli").main(["arjun-sweep", "--max-targets", "2", *_AUDIT])
    out = capsys.readouterr()
    # the cap deferred 3 of 5, and the timed-out run was flagged INCOMPLETE.
    assert "deferring 3" in out.err
    assert "INCOMPLETE" in out.err
    # only the capped 2 targets were written into the scanned list file.
    listfile = tmp_path / "scans" / "arjun-sweep" / "GET.txt"
    assert len([ln for ln in listfile.read_text().splitlines() if ln.strip()]) == 2


def test_arjun_sweep_zero_targets_does_not_scan(monkeypatch, tmp_path, capsys):
    sweep = _import("assess.commands.arjun_sweep")
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(
            engagement_dir=str(tmp_path), engagement_key="eng", base_url="http://x"
        ),
    )
    monkeypatch.setattr(sweep.arjun_select, "select_targets", lambda rows, **kw: [])
    # A non-empty work buffer that yields 0 selected targets still triggers the
    # "no live_status?" hint, but must NOT scan or ingest.
    _patch_work_items_client(monkeypatch, sweep, [{"url": "x"}])
    called: list[int] = []
    monkeypatch.setattr(sweep, "kali_exec", lambda *a, **k: called.append(1))
    monkeypatch.setattr(sweep.ingest_arjun, "run", lambda ns: called.append(1))
    _import("assess.cli").main(["arjun-sweep", *_AUDIT])
    out = capsys.readouterr().out
    assert not called  # no scan, no ingest on an empty target set
    assert '"selected": 0' in out


def test_arjun_sweep_maps_body_verbs_to_post(monkeypatch, tmp_path):
    sweep = _import("assess.commands.arjun_sweep")
    kali = _import("assess.lib.kali")
    monkeypatch.setattr(
        sweep, "load_config",
        lambda d: SimpleNamespace(
            engagement_dir=str(tmp_path), engagement_key="eng", base_url="http://x"
        ),
    )
    # arjun only accepts GET/POST/XML/JSON: PUT/PATCH/DELETE -> POST, HEAD -> GET.
    monkeypatch.setattr(
        sweep.arjun_select, "select_targets",
        lambda rows, **kw: [
            ("PUT", "https://x/a"), ("PATCH", "https://x/b"),
            ("DELETE", "https://x/c"), ("HEAD", "https://x/d"),
        ],
    )
    _patch_work_items_client(monkeypatch, sweep, [])
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
    _import("assess.cli").main(["arjun-sweep", *_AUDIT])
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


# ── pre-flight internal-budget vs --timeout guard (I-9b#1 + I-20(b)) ─────────


def _audit(timeout):
    """Required audit flags with an explicit --timeout (overrides the shared
    _AUDIT default so a per-test wall-clock budget can be asserted)."""
    return [
        "--technique", "DISCOVERY", "--intent", "x",
        "--probe-kind", "fingerprint", "--phase", "recon",
        "--timeout", str(timeout),
    ]


def test_preflight_timeout_guard_autoraises_exact_budget():
    cli = _import("assess.lib.kali_cli")
    msgs: list[str] = []
    out = cli.preflight_timeout_guard(
        verb="katana", internal_budget_s=600, timeout=180,
        warn=msgs.append, auto_raise=True, exact=True,
    )
    assert out == 600                       # boost-only raise to fit the budget
    assert msgs and "180" in msgs[0] and "600" in msgs[0]


def test_preflight_timeout_guard_warn_only_leaves_timeout_unchanged():
    cli = _import("assess.lib.kali_cli")
    msgs: list[str] = []
    out = cli.preflight_timeout_guard(
        verb="arjun", internal_budget_s=600, timeout=180, warn=msgs.append,
    )
    assert out == 180                       # warn-only: never silently changes the budget
    assert msgs


def test_preflight_timeout_guard_silent_when_budget_fits():
    cli = _import("assess.lib.kali_cli")
    msgs: list[str] = []
    out = cli.preflight_timeout_guard(
        verb="katana", internal_budget_s=100, timeout=180,
        warn=msgs.append, auto_raise=True, exact=True,
    )
    assert out == 180
    assert not msgs


def test_preflight_timeout_guard_tolerates_missing_timeout():
    cli = _import("assess.lib.kali_cli")
    msgs: list[str] = []
    # A unit-test namespace may carry no --timeout; the guard must not raise.
    out = cli.preflight_timeout_guard(
        verb="arjun", internal_budget_s=600, timeout=None, warn=msgs.append,
    )
    assert out is None and not msgs


def test_estimate_list_sweep_seconds_floors_and_skips_single():
    cli = _import("assess.lib.kali_cli")
    # I-20 shape: 134 targets × 2 (--stable) passes × 12s/req ÷ 5 workers ≈ 643s.
    est = cli.estimate_list_sweep_seconds(
        targets=134, passes=2, per_request_seconds=12, workers=5, rate_limit=6,
    )
    assert est > 600
    # A low rate-limit caps effective parallelism BELOW the worker pool.
    slow = cli.estimate_list_sweep_seconds(
        targets=134, passes=2, per_request_seconds=12, workers=5, rate_limit=2,
    )
    assert slow > est
    # A single target is a different (already-visible) problem -> skipped.
    assert cli.estimate_list_sweep_seconds(
        targets=1, passes=2, per_request_seconds=99, workers=1, rate_limit=1,
    ) == 0


def test_katana_crawl_budget_autoraises_timeout_and_emits_crawl_duration(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(
        ["kali", "katana", "-u", "https://x", "--crawl-budget", "600", *_audit(180)]
    )
    err = capsys.readouterr().err
    cmd = captured["cmd"]
    # the declared crawl budget is passed to katana so it self-stops at 600s ...
    assert _val_after(cmd, "-crawl-duration") == "600"
    # ... and --timeout is auto-raised to fit it (was 180) so it is not truncated.
    assert captured["kwargs"]["timeout"] >= 600
    assert "WARN" in err and "600" in err and "180" in err


def test_katana_crawl_budget_within_timeout_keeps_timeout(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(
        ["kali", "katana", "-u", "https://x", "--crawl-budget", "120", *_audit(1800)]
    )
    err = capsys.readouterr().err
    assert _val_after(captured["cmd"], "-crawl-duration") == "120"
    assert captured["kwargs"]["timeout"] == 1800     # budget fits -> unchanged
    assert "WARN" not in err


def test_katana_without_crawl_budget_emits_no_crawl_duration(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_katana")
    _import("assess.cli").main(["kali", "katana", "-u", "https://x", *_audit(180)])
    assert "-crawl-duration" not in captured["cmd"]
    assert "WARN" not in capsys.readouterr().err


def test_ffuf_maxtime_autoraises_timeout(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_ffuf")
    _import("assess.cli").main(
        ["kali", "ffuf", "-u", "https://x/FUZZ", "-w", "/w.txt",
         "-maxtime", "600", *_audit(120)]
    )
    err = capsys.readouterr().err
    assert _val_after(captured["cmd"], "-maxtime") == "600"
    assert captured["kwargs"]["timeout"] >= 600
    assert "WARN" in err and "ffuf" in err


def test_arjun_preflight_warns_when_list_cannot_finish(monkeypatch, capsys, tmp_path):
    listfile = tmp_path / "targets.txt"
    listfile.write_text("\n".join(f"https://x/{i}" for i in range(50)) + "\n")
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_arjun")
    _import("assess.cli").main([
        "kali", "arjun", "-i", str(listfile),
        "--rate-limit", "6", "--stable", "-T", "12", *_audit(120),
    ])
    err = capsys.readouterr().err
    # 50 × 2 (stable) × 12 ÷ 5 = 240s worst-case >> 120s wall-clock.
    assert "WARN" in err and "arjun" in err
    assert "120" in err
    # an ESTIMATE never silently changes the budget — warn-only.
    assert captured["kwargs"]["timeout"] == 120


def test_arjun_preflight_silent_when_sized_to_finish(monkeypatch, capsys, tmp_path):
    listfile = tmp_path / "targets.txt"
    listfile.write_text("\n".join(f"https://x/{i}" for i in range(3)) + "\n")
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_arjun")
    _import("assess.cli").main(
        ["kali", "arjun", "-i", str(listfile), *_audit(1800)]
    )
    assert "WARN" not in capsys.readouterr().err
    assert captured["kwargs"]["timeout"] == 1800


def test_nuclei_preflight_warns_on_undersized_list_sweep(monkeypatch, capsys, tmp_path):
    listfile = tmp_path / "hosts.txt"
    listfile.write_text("\n".join(f"https://h{i}" for i in range(100)) + "\n")
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_nuclei")
    _import("assess.cli").main([
        "kali", "nuclei", "-l", str(listfile), "-t", "http/cves/",
        "-rate-limit", "5", "-timeout", "10", *_audit(120),
    ])
    err = capsys.readouterr().err
    # 100 hosts × 10s/req ÷ min(25 conc, 5 rl)=5 = 200s worst-case > 120s.
    assert "WARN" in err and "nuclei" in err
    assert captured["kwargs"]["timeout"] == 120     # estimate -> warn-only


def test_sqlmap_preflight_warns_on_heavy_config_under_short_timeout(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_sqlmap")
    _import("assess.cli").main([
        "kali", "sqlmap", "-u", "https://x/?id=1",
        "--level", "5", "--risk", "3", "--batch", *_audit(120),
    ])
    err = capsys.readouterr().err
    assert "WARN" in err and "sqlmap" in err
    assert captured["kwargs"]["timeout"] == 120     # heuristic -> warn-only


def test_sqlmap_preflight_silent_on_light_config(monkeypatch, capsys):
    captured = _capture_kali_exec(monkeypatch, "assess.commands.kali_sqlmap")
    _import("assess.cli").main(
        ["kali", "sqlmap", "-u", "https://x/?id=1", "--batch", *_audit(120)]
    )
    assert "WARN" not in capsys.readouterr().err
    assert captured["kwargs"]["timeout"] == 120     # budget passes through unchanged
