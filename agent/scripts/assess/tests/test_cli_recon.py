"""Phase 1 — the supervised `vigil assess recon` orchestrator + recon-status.

Covers the orchestration logic in isolation from the dns/web sub-commands
(their `run()` is replaced by stubs that write the canonical artifact): stage
sequencing, per-stage checkpoint + `--resume` skip, fail-fast on a stage error,
the recon-status digest projection, the enforce-host-routing preflight, and the
detached `--background` launch (job row + child argv construction).
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import recon, recon_status
from assess.lib import runtime_route
from assess.lib.client import AssessError


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _args(tmp_path: Path, **over) -> SimpleNamespace:
    # js-mining is default-ON in production; the dns/web/gau-ordering tests below
    # opt OUT (no_js_mining=True) so they stay focused on the original three
    # stages. The js stage gets its own dedicated tests further down.
    base = dict(
        apexes=["example.com"], engagement_dir=str(tmp_path), brute=False,
        runtime="container", no_crawl=False, no_gau=False, no_js_mining=True,
        resume=False, stage_timeout=1800, background=False, foreground=False,
        job_id=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _stub_runners(tmp_path: Path, ran: list, *, dns_rc=0, web_rc=0, dns_hosts=2):
    def dns(args, cfg):
        ran.append("dns")
        d = Path(cfg.engagement_dir) / "scans" / "dns-discovery"
        d.mkdir(parents=True, exist_ok=True)
        (d / "resolved_hosts.txt").write_text(
            "".join(f"h{i}.example.com\n" for i in range(dns_hosts)), encoding="utf-8"
        )
        return dns_rc

    def web(args, cfg):
        ran.append("web")
        d = Path(cfg.engagement_dir) / "scans" / "web-discovery"
        d.mkdir(parents=True, exist_ok=True)
        (d / "httpx_live.jsonl").write_text('{"url":"https://h0.example.com"}\n', encoding="utf-8")
        return web_rc

    def gau(args, cfg):
        ran.append("gau")
        d = Path(cfg.engagement_dir) / "scans" / "recon"
        d.mkdir(parents=True, exist_ok=True)
        (d / "gau.done").write_text("example.com\n", encoding="utf-8")
        return 0

    return {"dns": dns, "web": web, "gau": gau}


# --------------------------------------------------------------------------- #
# 1. sequencing + status emission
# --------------------------------------------------------------------------- #


def test_recon_runs_stages_in_order_and_writes_status(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran))

    recon.run(_args(tmp_path))

    assert ran == ["dns", "web", "gau"]  # gau is ON by default
    status = json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))
    assert status["overall_state"] == "done"
    assert [s["state"] for s in status["stages"]] == ["done", "done", "done"]
    assert status["stages"][0]["counts"]["resolved_hosts"] == 2
    assert status["stages"][1]["counts"]["live_probes"] == 1


def test_recon_no_gau_drops_the_gau_stage(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran))

    recon.run(_args(tmp_path, no_gau=True))

    assert ran == ["dns", "web"]  # gau dropped
    status = json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))
    assert [s["label"] for s in status["stages"]] == ["dns-discovery", "web-discovery"]


# --------------------------------------------------------------------------- #
# 2. --resume skips fresh checkpoints
# --------------------------------------------------------------------------- #


def test_recon_resume_skips_fresh_stages(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)

    ran1: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran1))
    recon.run(_args(tmp_path))
    assert ran1 == ["dns", "web", "gau"]

    # Second run with --resume: all checkpoints are fresh+valid → no stage runs.
    ran2: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran2))
    recon.run(_args(tmp_path, resume=True))
    assert ran2 == []
    status = json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))
    assert [s["state"] for s in status["stages"]] == ["skipped", "skipped", "skipped"]


def test_recon_resume_reruns_on_changed_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran1: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran1))
    recon.run(_args(tmp_path))

    # Different apex set → fingerprint mismatch → resume cannot reuse → re-runs.
    ran2: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran2))
    recon.run(_args(tmp_path, apexes=["other.com"], resume=True))
    assert ran2 == ["dns", "web", "gau"]


# --------------------------------------------------------------------------- #
# 3. fail-fast on stage error
# --------------------------------------------------------------------------- #


def test_recon_stage_failure_stops_pipeline(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, ran, dns_rc=2))

    with pytest.raises(SystemExit) as exc:
        recon.run(_args(tmp_path))
    assert exc.value.code == 2
    assert ran == ["dns"]  # web + gau never ran
    status = json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))
    assert status["overall_state"] == "failed"
    assert status["stages"][0]["state"] == "failed"
    assert [s["state"] for s in status["stages"][1:]] == ["pending", "pending"]


# --------------------------------------------------------------------------- #
# 4. recon-status digest
# --------------------------------------------------------------------------- #


def test_recon_status_digest(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners(tmp_path, []))
    recon.run(_args(tmp_path))

    monkeypatch.setattr(recon_status, "load_config", lambda d: _cfg(tmp_path))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        recon_status.run(SimpleNamespace(engagement_dir=str(tmp_path), job_id=None, as_json=True))
    digest = json.loads(out.getvalue())
    assert digest["overall_state"] == "done"
    assert digest["percent_complete"] == 100
    assert digest["next"] is None
    assert [s["label"] for s in digest["stages"]] == ["dns-discovery", "web-discovery", "gau-endpoints"]


def test_recon_status_missing_run_exits_1(monkeypatch, tmp_path):
    monkeypatch.setattr(recon_status, "load_config", lambda d: _cfg(tmp_path))
    with pytest.raises(SystemExit) as exc:
        recon_status.run(SimpleNamespace(engagement_dir=str(tmp_path), job_id=None, as_json=False))
    assert exc.value.code == 1


# --------------------------------------------------------------------------- #
# 5. enforce host routing
# --------------------------------------------------------------------------- #


def test_resolve_runtime_enforce_raises_when_host_binary_missing(monkeypatch):
    monkeypatch.setattr(runtime_route, "_host_binary_available", lambda tool: False)
    # Explicit host + enforce + missing binary → raise (no silent degrade).
    with pytest.raises(runtime_route.HostRoutingRequired):
        runtime_route.resolve_runtime("host", tool="puredns", enforce=True)
    # Without enforce → WARN + fallback to container (legacy behavior, no raise).
    assert runtime_route.resolve_runtime("host", tool="puredns", enforce=False) == "container"
    # Explicit container is caller-forced isolation — never enforced.
    assert runtime_route.resolve_runtime("container", tool="puredns", enforce=True) == "container"


def test_recon_enforce_translates_to_assess_error(monkeypatch):
    monkeypatch.setattr(runtime_route, "_host_binary_available", lambda tool: False)
    # Enforce only bites when the RESOLVED route is host.
    with pytest.raises(AssessError):
        recon._enforce_host_routing(SimpleNamespace(runtime="host", brute=False), "host")
    # A container route is never enforced (no raise), even with binaries missing.
    recon._enforce_host_routing(SimpleNamespace(runtime="auto", brute=False), "container")


def test_effective_runtime_resolves_auto_by_platform(monkeypatch):
    # recon's auto → host on Docker Desktop (its whole purpose), container elsewhere.
    monkeypatch.setattr(runtime_route, "detect_runtime",
                        lambda: SimpleNamespace(is_docker_desktop=True))
    assert recon._effective_runtime(SimpleNamespace(runtime="auto")) == "host"
    monkeypatch.setattr(runtime_route, "detect_runtime",
                        lambda: SimpleNamespace(is_docker_desktop=False))
    assert recon._effective_runtime(SimpleNamespace(runtime="auto")) == "container"
    # Explicit values pass through regardless of platform.
    assert recon._effective_runtime(SimpleNamespace(runtime="host")) == "host"
    assert recon._effective_runtime(SimpleNamespace(runtime="container")) == "container"


def test_run_web_supplies_full_arg_surface(monkeypatch, tmp_path):
    """Regression for the BLOCKER: recon._run_web must build a namespace that
    web_discovery.run can fully consume (it reads httpx_threads/ports/etc. that
    web_discovery._apply_arg_defaults now backfills). Drives the REAL _run_web
    with web_discovery's execution seams stubbed — no AttributeError allowed."""
    from assess.commands import web_discovery

    cfg = _cfg(tmp_path)
    dns_dir = tmp_path / "scans" / "dns-discovery"
    dns_dir.mkdir(parents=True, exist_ok=True)
    (dns_dir / "resolved_hosts.txt").write_text("h0.example.com\n", encoding="utf-8")

    monkeypatch.setattr(web_discovery, "load_config", lambda d: cfg)
    monkeypatch.setattr(web_discovery, "kali_exec",
                        lambda *a, **k: SimpleNamespace(return_code=0, status="completed"))
    monkeypatch.setattr(web_discovery, "ingest_httpx_results",
                        lambda *a, **k: {"upserted": 0, "by_class": {}})

    class _Client:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(web_discovery, "AssessmentClient", lambda *a, **k: _Client())

    rc = recon._run_web(_args(tmp_path, runtime="container"), cfg)
    assert rc == 0  # would have been an AttributeError before the _ARG_DEFAULTS fix


def test_recon_auto_routes_host_on_docker_desktop_and_enforces(monkeypatch, tmp_path):
    # On Docker Desktop with auto, the stages must route host AND a missing host
    # binary must fail the preflight (not silently degrade to the wedge path).
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(runtime_route, "detect_runtime",
                        lambda: SimpleNamespace(is_docker_desktop=True))
    monkeypatch.setattr(runtime_route, "_host_binary_available", lambda tool: False)
    seen_runtime: list[str] = []

    def dns(args, cfg):
        seen_runtime.append(args.runtime)
        (Path(cfg.engagement_dir) / "scans" / "dns-discovery").mkdir(parents=True, exist_ok=True)
        (Path(cfg.engagement_dir) / "scans" / "dns-discovery" / "resolved_hosts.txt").write_text("h\n")
        return 0

    monkeypatch.setattr(recon, "_STAGE_RUNNERS", {"dns": dns, "web": dns, "gau": dns})
    # Missing host binary on Docker Desktop + auto → preflight raises.
    with pytest.raises(AssessError):
        recon.run(_args(tmp_path, runtime="auto"))
    # With host binaries present, auto resolves to host and the stages get it.
    monkeypatch.setattr(runtime_route, "_host_binary_available", lambda tool: True)
    recon.run(_args(tmp_path, runtime="auto", no_gau=True))
    assert seen_runtime and all(r == "host" for r in seen_runtime)


# --------------------------------------------------------------------------- #
# 6. --background detached launch
# --------------------------------------------------------------------------- #


class _BgClient:
    def __init__(self):
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return {"id": 9}

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {"id": 9, **payload}

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_recon_background_records_job_and_spawns_detached(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    # Pretend the assess entrypoint exists.
    fake_entry = tmp_path / "assess.py"
    fake_entry.write_text("# stub", encoding="utf-8")
    monkeypatch.setattr(recon, "_assess_entrypoint", lambda: fake_entry)
    fake = _BgClient()
    monkeypatch.setattr(recon, "AssessmentClient", lambda *a, **k: fake)
    captured: dict = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = kwargs
        return SimpleNamespace(pid=4321)

    monkeypatch.setattr(recon.subprocess, "Popen", fake_popen)

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        recon.run(_args(tmp_path, background=True, brute=True))

    # Job row posted queued, then patched running with started_at.
    assert fake.posts and fake.posts[0][0] == "jobs"
    assert fake.posts[0][1]["status"] == "queued"
    running = [p for _, p in fake.patches if p.get("status") == "running"]
    assert running and running[-1].get("started_at")
    # Detached child runs in-band against the same job id.
    argv = captured["argv"]
    assert "recon" in argv and "--foreground" in argv
    assert argv[argv.index("--job-id") + 1] == "9"
    assert "--brute" in argv
    assert "--no-js-mining" in argv  # base _args opts out; the flag must propagate
    assert captured["kwargs"].get("start_new_session") is True
    # Caller gets the job id immediately (non-blocking).
    payload = json.loads(out.getvalue())
    assert payload["job_id"] == 9


# --------------------------------------------------------------------------- #
# 7. js-mining stage (default-on) + OOS scope filtering between dns and web
# --------------------------------------------------------------------------- #


def _stub_runners_with_js(tmp_path: Path, ran: list, *, dns_hosts=2):
    base = _stub_runners(tmp_path, ran, dns_hosts=dns_hosts)

    def js(args, cfg):
        ran.append("js")
        d = Path(cfg.engagement_dir) / "scans" / "web-discovery" / "js-mining"
        d.mkdir(parents=True, exist_ok=True)
        (d / "js-mining.done").write_text("0\n1\n", encoding="utf-8")
        return 0

    base["js"] = js
    return base


def test_recon_runs_js_stage_by_default(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners_with_js(tmp_path, ran))

    # Do NOT opt out of js-mining → it runs AFTER web, BEFORE gau.
    recon.run(_args(tmp_path, no_js_mining=False))

    assert ran == ["dns", "web", "js", "gau"]
    status = json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))
    assert [s["label"] for s in status["stages"]] == [
        "dns-discovery", "web-discovery", "js-mining", "gau-endpoints"
    ]
    js_stage = next(s for s in status["stages"] if s["key"] == "js")
    assert js_stage["counts"]["js_mined"] == 2


def test_recon_no_js_mining_drops_the_js_stage(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    ran: list[str] = []
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", _stub_runners_with_js(tmp_path, ran))

    recon.run(_args(tmp_path, no_js_mining=True))
    assert ran == ["dns", "web", "gau"]  # js dropped


def _write_scope(tmp_path: Path, hosts, out_of_scope=None):
    payload = {"engagement_type": "web", "hosts": hosts}
    if out_of_scope is not None:
        payload["out_of_scope"] = out_of_scope
    (tmp_path / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def test_scope_filter_drops_out_of_scope_hosts_between_stages(tmp_path):
    # resolved_hosts.txt carries an in-scope host, an out_of_scope carve-out, and
    # a host outside the allowlist; only the in-scope one survives the filter.
    _write_scope(tmp_path, ["*.example.com"], out_of_scope=["bad.example.com"])
    dns = tmp_path / "scans" / "dns-discovery"
    dns.mkdir(parents=True, exist_ok=True)
    resolved = dns / "resolved_hosts.txt"
    resolved.write_text(
        "good.example.com\nbad.example.com\nunrelated.othercorp.com\n", encoding="utf-8"
    )

    cfg = _cfg(tmp_path)
    out = recon._apply_scope_filter(cfg, resolved)

    # A separate filtered file is produced (drops occurred).
    assert out != resolved
    kept = out.read_text(encoding="utf-8").split()
    assert kept == ["good.example.com"]


def test_scope_filter_passes_through_when_all_in_scope(tmp_path):
    _write_scope(tmp_path, ["*.example.com"])
    dns = tmp_path / "scans" / "dns-discovery"
    dns.mkdir(parents=True, exist_ok=True)
    resolved = dns / "resolved_hosts.txt"
    resolved.write_text("a.example.com\nb.example.com\n", encoding="utf-8")

    out = recon._apply_scope_filter(_cfg(tmp_path), resolved)
    assert out == resolved  # nothing dropped → original path returned


def test_scope_filter_degrades_on_missing_scope(tmp_path):
    # No scope.json → load_scope SystemExits; the filter must NOT abort the stage,
    # it returns the unfiltered resolved file.
    dns = tmp_path / "scans" / "dns-discovery"
    dns.mkdir(parents=True, exist_ok=True)
    resolved = dns / "resolved_hosts.txt"
    resolved.write_text("a.example.com\n", encoding="utf-8")

    out = recon._apply_scope_filter(_cfg(tmp_path), resolved)
    assert out == resolved


def test_scope_filter_degrades_when_no_allowlist(tmp_path):
    # An empty host allowlist must NOT drop everything (admitting on an empty
    # allowlist would reject every host) — pass through unfiltered.
    _write_scope(tmp_path, [])
    dns = tmp_path / "scans" / "dns-discovery"
    dns.mkdir(parents=True, exist_ok=True)
    resolved = dns / "resolved_hosts.txt"
    resolved.write_text("a.example.com\n", encoding="utf-8")

    out = recon._apply_scope_filter(_cfg(tmp_path), resolved)
    assert out == resolved


def test_run_web_feeds_scope_filtered_hosts(monkeypatch, tmp_path):
    # Drive the REAL _run_web: it must scope-filter resolved_hosts.txt and hand
    # web_discovery the filtered file (the out-of-scope host must not reach it).
    from assess.commands import web_discovery

    _write_scope(tmp_path, ["*.example.com"], out_of_scope=["bad.example.com"])
    dns = tmp_path / "scans" / "dns-discovery"
    dns.mkdir(parents=True, exist_ok=True)
    (dns / "resolved_hosts.txt").write_text(
        "good.example.com\nbad.example.com\n", encoding="utf-8"
    )

    seen_hosts_file: dict = {}

    def fake_web_run(ns):
        seen_hosts_file["path"] = ns.hosts_file

    monkeypatch.setattr(web_discovery, "run", fake_web_run)

    rc = recon._run_web(_args(tmp_path, runtime="container"), _cfg(tmp_path))
    assert rc == 0
    fed = Path(seen_hosts_file["path"]).read_text(encoding="utf-8").split()
    assert fed == ["good.example.com"]  # bad.example.com filtered out before web


def test_run_js_is_best_effort_and_writes_sentinel(monkeypatch, tmp_path):
    # _run_js must never fail the pipeline even when js_mining.run raises, and it
    # always writes the checkpoint sentinel.
    from assess.commands import js_mining

    def boom(ns):
        raise RuntimeError("jsluice exploded")

    monkeypatch.setattr(js_mining, "run", boom)
    rc = recon._run_js(_args(tmp_path), _cfg(tmp_path))
    assert rc == 0
    sentinel = tmp_path / "scans" / "web-discovery" / "js-mining" / "js-mining.done"
    assert sentinel.is_file()
