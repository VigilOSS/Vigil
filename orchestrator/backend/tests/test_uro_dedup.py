"""Tests for the shared uro dedup helper and its wiring into the gau pipelines.

uro is finished as a SHARED stage (not a standalone verb): `gau_pipeline.
run_uro_dedup` is the single source, and all three gau pipelines dedupe through
it. These tests cover the pure argv builder, the runner (monkeypatched
``kali_exec``), and the wiring into gau-secrets / gau-endpoints / gau-js-endpoints
— no container, no backend.
"""
from __future__ import annotations

import importlib
import sys
import time
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


def _make_paths(tmp_path: Path, *, target: str = "example.com"):
    lib = _import("assess.lib.gau_pipeline")
    eng = tmp_path / "2026-06-30-eng"
    eng.mkdir()
    (eng / "scans").mkdir()
    cfg = SimpleNamespace(engagement_dir=str(eng), engagement_key=eng.name)
    key = lib.gau_cache_key(subs=False)
    paths = lib.resolve_pipeline_paths(cfg, target=target, cache_key=key)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    return lib, cfg, paths


# ── pure argv builder ──────────────────────────────────────────────────────


def test_build_uro_command_shape(tmp_path):
    lib, _cfg, paths = _make_paths(tmp_path)
    cmd = lib.build_uro_command(
        paths, source_path=paths.work_dir / "in.txt", dest_path=paths.work_dir / "out.txt"
    )
    assert cmd[:2] == ["bash", "-lc"]
    script = cmd[2]
    assert "uro -i" in script and " -o " in script
    # both names resolve against the namespaced container work dir.
    assert paths.container_work_dir in script
    assert "in.txt" in script and "out.txt" in script


def test_build_uro_command_quotes_paths(tmp_path):
    lib, _cfg, paths = _make_paths(tmp_path)
    cmd = lib.build_uro_command(
        paths, source_path=paths.work_dir / "weird name.txt", dest_path=paths.work_dir / "o.txt"
    )
    assert "'" in cmd[2]  # shlex.quote wrapped the spaced filename


# ── runner ─────────────────────────────────────────────────────────────────


def test_run_uro_dedup_happy_returns_count(monkeypatch, tmp_path):
    lib, cfg, paths = _make_paths(tmp_path)
    kali = _import("assess.lib.kali")
    captured: dict = {}

    def fake_exec(cmd, **kw):
        captured["cmd"] = list(cmd)
        captured["kw"] = kw
        (paths.work_dir / "out.txt").write_text("a\nb\nc\n", encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(kali, "kali_exec", fake_exec)
    n = lib.run_uro_dedup(
        paths, cfg=cfg, phase="recon", timeout=900, target="example.com",
        source_path=paths.work_dir / "in.txt", dest_path=paths.work_dir / "out.txt",
    )
    assert n == 3
    assert captured["kw"]["tool_name"] == "uro"
    assert captured["kw"]["phase"] == "recon"
    assert captured["kw"]["technique"] == "RECON"
    assert captured["cmd"][0] == "bash"


def test_run_uro_dedup_raises_on_nonzero(monkeypatch, tmp_path):
    lib, cfg, paths = _make_paths(tmp_path)
    kali = _import("assess.lib.kali")
    from assess.lib.client import AssessError

    monkeypatch.setattr(
        kali, "kali_exec",
        lambda cmd, **kw: SimpleNamespace(return_code=2, stderr_path="/e.err"),
    )
    with pytest.raises(AssessError):
        lib.run_uro_dedup(
            paths, cfg=cfg, phase="recon", timeout=900, target="example.com",
            source_path=paths.work_dir / "in.txt", dest_path=paths.work_dir / "out.txt",
        )


# ── wiring: gau-secrets delegates to the shared helper ──────────────────────


def test_gau_secrets_run_uro_delegates(monkeypatch, tmp_path):
    gs = _import("assess.commands.gau_secrets")
    seen: dict = {}

    def fake_dedup(paths, *, cfg, phase, timeout, target, source_path, dest_path):
        seen["phase"] = phase
        seen["target"] = target
        seen["dest"] = dest_path
        return 7

    monkeypatch.setattr(gs, "run_uro_dedup", fake_dedup)
    paths = SimpleNamespace(container_work_dir="/c", work_dir=tmp_path)
    args = SimpleNamespace(target="t", phase="recon", timeout=900)
    n = gs._run_uro(
        paths, cfg=SimpleNamespace(), args=args,
        source_path=tmp_path / "a.txt", dest_path=tmp_path / "b.txt",
    )
    assert n == 7
    assert seen["phase"] == "recon" and seen["target"] == "t"


# ── wiring: gau-endpoints dedups before ingest, falls back on failure ───────


def _seed_reused_cache(ge, lib, monkeypatch, tmp_path):
    """Wire gau-endpoints so decide_cache_reuse short-circuits (no gau exec)."""
    eng = tmp_path / "2026-06-30-eng"
    eng.mkdir()
    (eng / "scans").mkdir()
    cfg = SimpleNamespace(engagement_dir=str(eng), engagement_key=eng.name)
    monkeypatch.setattr(ge, "load_config", lambda d: cfg)
    key = lib.gau_cache_key(subs=False)
    paths = lib.resolve_pipeline_paths(cfg, target="example.com", cache_key=key)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    paths.output_path.write_text("https://x/?id=1\nhttps://x/?id=2\n", encoding="utf-8")
    decision = lib.GauCacheDecision(True, "reused", SimpleNamespace(line_count=2), 1.0)
    monkeypatch.setattr(ge, "decide_cache_reuse", lambda paths, **k: decision)
    monkeypatch.setattr(ge, "announce_cache_decision", lambda d, **k: None)
    monkeypatch.setattr(ge, "_summarize_work_buffer", lambda db, src: {})
    # db file must exist so the db_init branch is skipped.
    (eng / "cases.db").write_text("", encoding="utf-8")
    return cfg, paths


def _ge_args(eng_dir):
    return SimpleNamespace(
        engagement_dir=eng_dir, target="example.com", source="gau", subs=False,
        providers="", refresh=False, max_cache_age_hours=24, phase="recon",
        timeout=900, db_override=None,
    )


def test_gau_endpoints_ingests_deduped_file(monkeypatch, tmp_path):
    ge = _import("assess.commands.gau_endpoints")
    lib = _import("assess.lib.gau_pipeline")
    cfg, paths = _seed_reused_cache(ge, lib, monkeypatch, tmp_path)

    def fake_dedup(paths, *, cfg, phase, timeout, target, source_path, dest_path):
        dest_path.write_text("https://x/?id=1\n", encoding="utf-8")  # collapsed
        return 1

    monkeypatch.setattr(ge, "run_uro_dedup", fake_dedup)
    ingested: dict = {}
    monkeypatch.setattr(
        ge, "_run_ingest_endpoints",
        lambda **kw: ingested.update(kw) or {"returncode": 0},
    )
    ge.run(_ge_args(cfg.engagement_dir))
    # ingest received the DEDUPED file, not the raw gau output.
    assert ingested["input_file"].name == "gau_deduped.txt"


def test_gau_endpoints_falls_back_to_raw_on_uro_failure(monkeypatch, tmp_path):
    ge = _import("assess.commands.gau_endpoints")
    lib = _import("assess.lib.gau_pipeline")
    from assess.lib.client import AssessError
    cfg, paths = _seed_reused_cache(ge, lib, monkeypatch, tmp_path)

    def boom(*a, **k):
        raise AssessError("uro blew up")

    monkeypatch.setattr(ge, "run_uro_dedup", boom)
    ingested: dict = {}
    monkeypatch.setattr(
        ge, "_run_ingest_endpoints",
        lambda **kw: ingested.update(kw) or {"returncode": 0},
    )
    ge.run(_ge_args(cfg.engagement_dir))
    # fall back to the undeduped gau corpus rather than losing it.
    assert ingested["input_file"].name == "gau_output.txt"


# ── wiring: gau-js-endpoints dedups the .js list before body-fetch ──────────


def test_gau_js_fetch_dedups_js_list(monkeypatch, tmp_path):
    gj = _import("assess.commands.gau_js_endpoints")
    lib = _import("assess.lib.gau_pipeline")
    eng = tmp_path / "2026-06-30-eng"
    eng.mkdir()
    (eng / "scans").mkdir()
    cfg = SimpleNamespace(engagement_dir=str(eng), engagement_key=eng.name)
    key = lib.gau_cache_key(subs=False)
    paths = lib.resolve_pipeline_paths(cfg, target="example.com", cache_key=key)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    paths.output_path.write_text(
        "https://example.com/app.js?v=1\n"
        "https://example.com/app.js?v=2\n"
        "https://example.com/page\n",
        encoding="utf-8",
    )
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=3, output_path=str(paths.output_path),
        gau_argv=[], cache_key=key,
    ))
    args = SimpleNamespace(target="example.com", phase="recon", timeout=900,
                           engagement_dir=str(eng))

    dedup_calls: list = []

    def fake_dedup(paths, *, cfg, phase, timeout, target, source_path, dest_path):
        dedup_calls.append(source_path.name)
        dest_path.write_text("https://example.com/app.js?v=1\n", encoding="utf-8")
        return 1

    monkeypatch.setattr(gj, "run_uro_dedup", fake_dedup)
    exec_cmds: list = []
    monkeypatch.setattr(
        gj, "kali_exec",
        lambda cmd, **k: (exec_cmds.append(list(cmd)), SimpleNamespace(return_code=0))[1],
    )

    kept = gj._fetch_js_bodies(paths, cfg=cfg, args=args)
    assert dedup_calls == ["js_targets.txt"]  # uro ran on the .js list
    # httpx body-fetch targets the DEDUPED list.
    httpx_script = exec_cmds[0][-1]
    assert "js_targets_deduped.txt" in httpx_script
    assert kept == 1
