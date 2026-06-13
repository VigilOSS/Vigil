"""Focused unit tests for the convergent dns-discovery / web-discovery pipeline
wiring (CR-3/4/5/6/8/9/16/17/18/19/20/21/23).

Everything that shells out (kali_exec, the host-exec path, runtime detection) is
mocked — NO real tools run. These tests assert the *wiring decisions*: wordlist
HEAD capping (CR-19), productive-parent re-brute selection (CR-20), runtime-route
branch (CR-4) + host-exec dispatch, the resolver-IP guard call (CR-3), the
convergence stop rule (CR-6), the two-tier resolver defaults (CR-8/CR-18), the
network-heavy lock (CR-9), the budget WARN (CR-23), and the httpx clamp (CR-5).

A distinctly-named module so it does not collide with test_discovery_pipelines.py.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


# --------------------------------------------------------------------------- #
# Module loading (mirror test_discovery_pipelines.py so the import path matches).
# --------------------------------------------------------------------------- #


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load(name: str, rel: str):
    root = str(_scripts_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    module_path = Path(__file__).resolve().parents[3] / rel
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENG_KEY = "eng"


def _cfg(tmp_path):
    return SimpleNamespace(base_url="http://example.test", engagement_key=ENG_KEY,
                           engagement_dir=str(tmp_path))


def _container_to_host(path: str, tmp_path) -> str:
    return path.replace(f"/engagements/{ENG_KEY}/", str(tmp_path) + "/")


def _make_fake_exec(tmp_path, canned: dict):
    """Fake kali_exec: records calls and writes canned[tool] to the stage -o path
    (host or /engagements container path) or the sh -c redirect target."""
    calls: list[dict] = []

    def fake(cmd, **kwargs):
        tool = kwargs.get("tool_name", "")
        calls.append({"cmd": list(cmd), "kwargs": kwargs, "tool": tool})
        out = None
        if "-o" in cmd:
            out = cmd[cmd.index("-o") + 1]
        elif cmd[:2] == ["sh", "-c"] and "> " in cmd[2]:
            out = cmd[2].rsplit("> ", 1)[1].strip().strip("'\"")
        if out and tool in canned:
            host = Path(_container_to_host(out, tmp_path)) if out.startswith("/engagements/") else Path(out)
            host.parent.mkdir(parents=True, exist_ok=True)
            host.write_text(canned[tool], encoding="utf-8")
        return SimpleNamespace(return_code=0)

    return fake, calls


def _base_dns_args(tmp_path, **over):
    """A fully-populated dns-discovery args namespace (argparse-equivalent)."""
    ns = SimpleNamespace(
        engagement_dir=str(tmp_path), apexes=["example.com"],
        no_passive=False, no_ct=True, recursive=False, subfinder_threads="20",
        brute=False, wordlist="/wl.txt", wordlist_head=500_000, deep_tail=False,
        dns_rate="1500", dnsx_profile="polite-cdn", resolver_profile="public-tcp",
        dnsx_extra_args="", stage_timeout=600, runtime="container",
        resolvers="", resolvers_trusted="", no_default_resolvers=True,
        max_passes=3, no_converge=False, no_parent_recursion=False,
        parent_min_children=5, no_wildcard_strip=True, quiet_brute=False,
        js_host_mining=False, bbot=False, query_budget=5_000_000, per_resolver_qps=1_500,
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def _stub_runtime(dns, monkeypatch, *, route="container", desktop=False):
    """Force the routing + guard helpers to deterministic values (no docker shell-out)."""
    monkeypatch.setattr(dns, "_route_for", lambda args, tool: route)
    rt = SimpleNamespace(platform="linux", is_docker_desktop=desktop, recommended=route)
    monkeypatch.setattr(dns.runtime_route, "detect_runtime", lambda **kw: rt)


# --------------------------------------------------------------------------- #
# CR-19 — wordlist HEAD capping.
# --------------------------------------------------------------------------- #


def test_wordlist_head_caps_large_list_and_warns(monkeypatch, tmp_path, capsys):
    dns = _load("dns_ut_head", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    _stub_runtime(dns, monkeypatch)

    # 12 host-visible lines, cap at 5 → expect a 5-line capped copy + a WARN.
    wl = tmp_path / "big.txt"
    wl.write_text("\n".join(f"l{i}" for i in range(12)) + "\n", encoding="utf-8")
    args = _base_dns_args(tmp_path, wordlist=str(wl), wordlist_head=5, brute=True)

    capped = dns._capped_wordlist(args, _cfg(tmp_path), "host")
    lines = Path(capped).read_text().splitlines()
    assert lines == [f"l{i}" for i in range(5)]            # HEAD only, order preserved
    assert "truncated to first 5 of 12" in capsys.readouterr().err


def test_wordlist_head_deep_tail_keeps_full_list(monkeypatch, tmp_path):
    dns = _load("dns_ut_tail", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    wl = tmp_path / "big.txt"
    wl.write_text("\n".join(f"l{i}" for i in range(12)) + "\n", encoding="utf-8")
    args = _base_dns_args(tmp_path, wordlist=str(wl), wordlist_head=5, deep_tail=True)
    # --deep-tail → original path returned untouched.
    assert dns._capped_wordlist(args, _cfg(tmp_path), "host") == str(wl)


def test_wordlist_head_under_cap_is_identity(monkeypatch, tmp_path):
    dns = _load("dns_ut_under", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    wl = tmp_path / "small.txt"
    wl.write_text("a\nb\nc\n", encoding="utf-8")
    args = _base_dns_args(tmp_path, wordlist=str(wl), wordlist_head=500_000)
    # Under-cap → no HEAD copy is written, but the container route must still
    # receive a CONTAINER-visible path (defect #3): a wordlist already under the
    # engagement dir is translated to its /engagements path, not returned as a
    # bare host path that won't exist in-container.
    assert (dns._capped_wordlist(args, _cfg(tmp_path), "container")
            == f"/engagements/{ENG_KEY}/small.txt")
    # Host route is unchanged (path-as-is).
    assert dns._capped_wordlist(args, _cfg(tmp_path), "host") == str(wl)


# --------------------------------------------------------------------------- #
# CR-20 — productive-parent re-brute selection.
# --------------------------------------------------------------------------- #


def test_select_parent_targets_picks_productive_parents(monkeypatch, tmp_path):
    dns = _load("dns_ut_parents", "agent/scripts/assess/commands/dns_discovery.py")
    resolved = {
        # origin.api.example.com has 5 children → productive (>=5).
        "a.origin.api.example.com", "b.origin.api.example.com", "c.origin.api.example.com",
        "d.origin.api.example.com", "e.origin.api.example.com",
        # lonely.example.com has 1 child → not productive.
        "only.lonely.example.com",
    }
    args = _base_dns_args(tmp_path, brute=True, parent_min_children=5, no_parent_recursion=False)
    parents = dns._select_parent_targets(args, resolved, bruted_apexes={"example.com"})
    assert "origin.api.example.com" in parents
    assert "lonely.example.com" not in parents


def test_select_parent_targets_empty_without_brute(monkeypatch, tmp_path):
    dns = _load("dns_ut_parents2", "agent/scripts/assess/commands/dns_discovery.py")
    resolved = {f"h{i}.origin.example.com" for i in range(10)}
    # No --brute → recursion has nothing to re-brute → empty (also the convergence gate).
    args = _base_dns_args(tmp_path, brute=False)
    assert dns._select_parent_targets(args, resolved, bruted_apexes=set()) == []
    # --no-parent-recursion also yields empty.
    args2 = _base_dns_args(tmp_path, brute=True, no_parent_recursion=True)
    assert dns._select_parent_targets(args2, resolved, bruted_apexes=set()) == []


# --------------------------------------------------------------------------- #
# CR-4 — runtime routing branch + host-exec dispatch reuse.
# --------------------------------------------------------------------------- #


def test_route_for_default_auto_is_container(monkeypatch, tmp_path):
    dns = _load("dns_ut_route", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.delenv("VIGIL_RECON_RUNTIME", raising=False)
    # auto with no env opt-in → safe default container (no docker shell-out).
    args = _base_dns_args(tmp_path, runtime="auto")
    assert dns._route_for(args, "puredns") == "container"


def test_route_for_env_auto_selects_by_platform(monkeypatch, tmp_path):
    dns = _load("dns_ut_route2", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setenv("VIGIL_RECON_RUNTIME", "auto")
    captured = {}

    def fake_resolve(requested, *, tool, **kw):
        captured["requested"] = requested
        captured["tool"] = tool
        return "host"

    monkeypatch.setattr(dns.runtime_route, "resolve_runtime", fake_resolve)
    args = _base_dns_args(tmp_path, runtime="auto")
    assert dns._route_for(args, "dnsx") == "host"
    assert captured == {"requested": "auto", "tool": "dnsx"}


def test_route_for_explicit_container_beats_env(monkeypatch, tmp_path):
    dns = _load("dns_ut_route3", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setenv("VIGIL_RECON_RUNTIME", "host")
    monkeypatch.setattr(dns.runtime_route, "resolve_runtime",
                        lambda requested, *, tool, **kw: requested)
    args = _base_dns_args(tmp_path, runtime="container")
    # explicit --runtime container wins over the env override.
    assert dns._route_for(args, "puredns") == "container"


def test_host_dispatch_reuses_host_exec_audit(monkeypatch, tmp_path):
    dns = _load("dns_ut_hostexec", "agent/scripts/assess/commands/dns_discovery.py")
    seen = {}

    def fake_host_run(ns):
        # host_exec.run() always sys.exit(rc); emulate a clean exit.
        seen["argv"] = ns.command
        seen["tool"] = ns.tool
        seen["intent"] = ns.intent
        seen["technique"] = ns.technique
        seen["phase"] = ns.phase
        raise SystemExit(0)

    monkeypatch.setattr(dns.host_exec, "run", fake_host_run)
    res = dns._host_dispatch(["puredns", "bruteforce", "/wl", "example.com"],
                             intent="brute", tool_name="puredns", technique="RECON",
                             phase="recon", timeout=600, engagement_dir=str(tmp_path))
    assert res.return_code == 0
    assert seen["tool"] == "puredns" and seen["technique"] == "RECON" and seen["phase"] == "recon"
    assert seen["argv"][0] == "puredns"


# --------------------------------------------------------------------------- #
# CR-3 — resolver-IP guard is called before the brute.
# CR-9 — network-heavy lock wraps the brute. CR-23 — budget WARN.
# --------------------------------------------------------------------------- #


def test_brute_calls_resolver_ip_guard_and_lock(monkeypatch, tmp_path):
    dns = _load("dns_ut_guard", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    _stub_runtime(dns, monkeypatch, route="container")
    fake_exec, _calls = _make_fake_exec(tmp_path, {})
    monkeypatch.setattr(dns, "kali_exec", fake_exec)

    guard_calls = {}
    monkeypatch.setattr(dns.runtime_route, "warn_excessive_resolver_ips",
                        lambda n, **kw: guard_calls.update(n=n, route=kw.get("route")) or True)
    monkeypatch.setattr(dns, "_resolver_count_for_guard", lambda args, cfg: 99)
    # Disable the stall watchdog (no real process) and assert the lock is entered.
    monkeypatch.setattr(dns, "_brute_exec_with_stall", lambda *a, **k: False)

    lock_entered = {}
    import contextlib

    @contextlib.contextmanager
    def fake_lock(engagement_dir, *, label, **kw):
        lock_entered["label"] = label
        yield True

    monkeypatch.setattr(dns, "network_heavy_lock", fake_lock)

    cfg = _cfg(tmp_path)
    args = _base_dns_args(tmp_path, brute=True)
    dns._puredns_brute(args, cfg, ["example.com"], route="container", brute_r="",
                       trusted="", wordlist="/wl.txt", wordlist_lines=1000,
                       produced=[], label="pass1")
    assert guard_calls == {"n": 99, "route": "container"}     # CR-3 guard fired
    assert "puredns brute" in lock_entered["label"]           # CR-9 lock entered


def test_budget_warn_fires_when_planned_exceeds_budget(monkeypatch, tmp_path, capsys):
    dns = _load("dns_ut_budget", "agent/scripts/assess/commands/dns_discovery.py")
    args = _base_dns_args(tmp_path, query_budget=100, per_resolver_qps=10, dns_rate="1500")
    dns._budget_warn(args, wordlist_lines=1000, target_count=2, resolver_count=5)
    err = capsys.readouterr().err
    assert "exceeds the per-engagement budget" in err          # 2000 > 100 (CR-23)
    assert "per-resolver qps" in err                            # 1500/5=300 > 10 (CR-23)


# --------------------------------------------------------------------------- #
# CR-8/CR-18 — two-tier resolver defaults injected when unset.
# --------------------------------------------------------------------------- #


def test_default_resolvers_inject_shipped_lists(monkeypatch, tmp_path):
    dns = _load("dns_ut_resolvers", "agent/scripts/assess/commands/dns_discovery.py")
    premium = tmp_path / "premium.txt"
    premium.write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")
    trusted = tmp_path / "trusted.txt"
    trusted.write_text("1.1.1.1\n", encoding="utf-8")
    monkeypatch.setattr(dns.runtime_route, "premium_anycast_path", lambda: premium)
    monkeypatch.setattr(dns.runtime_route, "trusted_anycast_path", lambda: trusted)

    cfg = _cfg(tmp_path)
    args = _base_dns_args(tmp_path, no_default_resolvers=False, resolvers="", resolvers_trusted="")
    brute_r, trust = dns._resolve_resolver_args(args, cfg, "host")
    # Host route → the shipped HOST paths are used as-is (CR-8/CR-18 defaults).
    assert brute_r == str(premium) and trust == str(trusted)


def test_operator_resolver_override_is_respected(monkeypatch, tmp_path):
    dns = _load("dns_ut_resolvers2", "agent/scripts/assess/commands/dns_discovery.py")
    # An explicit -r path must pass through untouched even when defaults exist.
    monkeypatch.setattr(dns.runtime_route, "premium_anycast_path", lambda: tmp_path / "premium.txt")
    monkeypatch.setattr(dns.runtime_route, "trusted_anycast_path", lambda: tmp_path / "trusted.txt")
    cfg = _cfg(tmp_path)
    args = _base_dns_args(tmp_path, resolvers="/my/resolvers.txt", no_default_resolvers=False)
    brute_r, _ = dns._resolve_resolver_args(args, cfg, "host")
    assert brute_r == "/my/resolvers.txt"


# --------------------------------------------------------------------------- #
# CR-6 — convergence loop: stops after 2 consecutive zero-net-new passes.
# --------------------------------------------------------------------------- #


def test_convergence_stops_after_two_zero_net_new(monkeypatch, tmp_path):
    dns = _load("dns_ut_converge", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))

    # Pass 1 finds 2 hosts; later passes find nothing new → converge after 2 zeros.
    passes = {"n": 0}

    def fake_once(args, cfg, apexes, seed, pass_no):
        passes["n"] = pass_no
        if pass_no == 1:
            return {"a.example.com", "b.example.com"}, ["example.com"]
        return set(), ["origin.example.com"]   # parents bruted, no NEW resolved

    monkeypatch.setattr(dns, "_discover_once", fake_once)
    # Always offer a productive parent so the loop would keep going if not for the
    # zero-net-new stop rule (proves CR-6 convergence, not just "ran out of work").
    monkeypatch.setattr(dns, "_select_parent_targets",
                        lambda args, resolved, bruted: ["origin.example.com"])

    args = _base_dns_args(tmp_path, brute=True, max_passes=10, no_converge=False)
    dns.run(args)   # returns normally on success (only sys.exit on zero resolved)
    # pass1 (+2), pass2 (0, streak=1), pass3 (0, streak=2 → stop). Never reaches 10.
    assert passes["n"] == 3
    resolved = (tmp_path / "scans" / "dns-discovery" / "resolved_hosts.txt").read_text()
    assert "a.example.com" in resolved and "b.example.com" in resolved


def test_no_converge_runs_single_pass(monkeypatch, tmp_path):
    dns = _load("dns_ut_single", "agent/scripts/assess/commands/dns_discovery.py")
    monkeypatch.setattr(dns, "load_config", lambda flag: _cfg(tmp_path))
    passes = {"n": 0}

    def fake_once(args, cfg, apexes, seed, pass_no):
        passes["n"] = pass_no
        return {"a.example.com"}, ["example.com"]

    monkeypatch.setattr(dns, "_discover_once", fake_once)
    monkeypatch.setattr(dns, "_select_parent_targets",
                        lambda args, resolved, bruted: ["origin.example.com"])
    args = _base_dns_args(tmp_path, brute=True, max_passes=10, no_converge=True)
    dns.run(args)
    assert passes["n"] == 1     # --no-converge → exactly one pass


# --------------------------------------------------------------------------- #
# CR-5 — bulk httpx thread clamp on macOS Docker Desktop.
# --------------------------------------------------------------------------- #


def test_httpx_threads_clamped_on_docker_desktop(monkeypatch, tmp_path, capsys):
    web = _load("web_ut_clamp", "agent/scripts/assess/commands/web_discovery.py")
    rt = SimpleNamespace(platform="darwin", is_docker_desktop=True, recommended="host")
    monkeypatch.setattr(web.runtime_route, "detect_runtime", lambda **kw: rt)
    args = SimpleNamespace(httpx_threads="50", no_thread_clamp=False)
    assert web._clamp_httpx_threads(args) == 25
    assert "clamped bulk httpx -threads 50 -> 25" in capsys.readouterr().err


def test_httpx_threads_not_clamped_with_override(monkeypatch, tmp_path):
    web = _load("web_ut_clamp2", "agent/scripts/assess/commands/web_discovery.py")
    rt = SimpleNamespace(platform="darwin", is_docker_desktop=True, recommended="host")
    monkeypatch.setattr(web.runtime_route, "detect_runtime", lambda **kw: rt)
    args = SimpleNamespace(httpx_threads="50", no_thread_clamp=True)
    assert web._clamp_httpx_threads(args) == 50          # operator override honored


def test_httpx_threads_unclamped_on_native_linux(monkeypatch, tmp_path):
    web = _load("web_ut_clamp3", "agent/scripts/assess/commands/web_discovery.py")
    rt = SimpleNamespace(platform="linux", is_docker_desktop=False, recommended="container")
    monkeypatch.setattr(web.runtime_route, "detect_runtime", lambda **kw: rt)
    args = SimpleNamespace(httpx_threads="50", no_thread_clamp=False)
    assert web._clamp_httpx_threads(args) == 50          # transparent no-op off Docker Desktop


def test_web_route_for_default_auto_is_container(monkeypatch, tmp_path):
    web = _load("web_ut_route", "agent/scripts/assess/commands/web_discovery.py")
    monkeypatch.delenv("VIGIL_RECON_RUNTIME", raising=False)
    args = SimpleNamespace(runtime="auto")
    assert web._route_for(args, "httpx") == "container"

    monkeypatch.setenv("VIGIL_RECON_RUNTIME", "host")
    monkeypatch.setattr(web.runtime_route, "resolve_runtime",
                        lambda requested, *, tool, **kw: requested)
    assert web._route_for(args, "httpx") == "host"


def test_web_host_route_dispatches_via_host_exec(monkeypatch, tmp_path):
    web = _load("web_ut_hostexec", "agent/scripts/assess/commands/web_discovery.py")
    monkeypatch.setattr(web, "load_config", lambda flag: _cfg(tmp_path))
    monkeypatch.setattr(web, "_route_for", lambda args, tool: "host")
    # _clamp_httpx_threads now takes the resolved route (defect #6); accept it.
    monkeypatch.setattr(web, "_clamp_httpx_threads", lambda args, route="container": 25)

    hosts = tmp_path / "hosts.txt"
    hosts.write_text("a.example.com\n", encoding="utf-8")

    host_calls = {}

    def fake_host_run(ns):
        host_calls["argv"] = ns.command
        host_calls["tool"] = ns.tool
        # Emulate httpx writing its -o output, then host_exec exiting.
        out = ns.command[ns.command.index("-o") + 1]
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text("", encoding="utf-8")
        raise SystemExit(0)

    monkeypatch.setattr(web.host_exec, "run", fake_host_run)
    # kali_exec must NOT be called for the bulk httpx stage when host-routed.
    def boom(*a, **k):
        raise AssertionError("kali_exec called but stage should route host")
    monkeypatch.setattr(web, "kali_exec", boom)
    monkeypatch.setattr(web, "ingest_httpx_results",
                        lambda path, **kw: {"upserted": 0, "rows": 0, "by_class": {}, "parse_errors": 0})

    class _Client:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *e): return False

    monkeypatch.setattr(web, "AssessmentClient", _Client)

    web.run(SimpleNamespace(
        engagement_dir=str(tmp_path), hosts_file=str(hosts), ports="443",
        httpx_threads="50", httpx_rate_limit="150", tech_detect=False,
        no_crawl=True, katana_depth="2", katana_extra_args="", db_path="",
        stage_timeout=600, runtime="host", no_thread_clamp=False,
    ))
    assert host_calls["tool"] == "httpx"
    assert "-threads" in host_calls["argv"] and "25" in host_calls["argv"]   # clamp applied


# --------------------------------------------------------------------------- #
# CR-21 — stall window scales with input size.
# --------------------------------------------------------------------------- #


def test_stall_window_scales_with_input_size(monkeypatch, tmp_path):
    dns = _load("dns_ut_stall", "agent/scripts/assess/commands/dns_discovery.py")
    base = dns._stall_window(0)
    big = dns._stall_window(500_000)
    assert base == dns._STALL_BASE_SECONDS
    assert big == dns._STALL_BASE_SECONDS + 5 * dns._STALL_PER_100K_LINES
    assert big > base       # large warm-up gets a wider window (no false STALL kill)
