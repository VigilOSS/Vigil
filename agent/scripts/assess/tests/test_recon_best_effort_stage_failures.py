"""A best-effort recon stage that fails says so instead of reading ``done``.

gau-endpoints and js-mining never stop the pipeline, but a failed ingest inside
them used to leave the stage ``done apexes_mined=0`` and the job ``completed``,
so the operator's status surface hid that thousands of URLs never reached the
work buffer. The stage now reads ``failed`` with its exit code, per-unit counts
and the error, the later stages still run, and the pipeline reads ``partial``:
some stages failed while the rest succeeded. Only a failed fatal stage (dns,
web), which stops the pipeline, makes it read ``failed``.

Rows the backend refused inside an otherwise clean ingest are not a failed
stage either: the stage reads ``partial`` with a ``backend_refused`` count and
an error naming the apex and where each refused row is listed.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import gau_endpoints, js_mining, recon, recon_status


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _args(tmp_path: Path, **over) -> SimpleNamespace:
    base = dict(
        apexes=["acme.example", "acme-two.example"], engagement_dir=str(tmp_path), brute=False,
        runtime="container", no_crawl=False, no_gau=False, no_js_mining=False,
        resume=False, stage_timeout=1800, background=False, foreground=False, job_id=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _ok_stage(artifact: str):
    def runner(args, cfg):
        path = Path(cfg.engagement_dir) / artifact
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
        return 0
    return runner


def _gau_one_apex_fails(ns):
    if ns.target == "acme-two.example":
        print(
            "ERROR: HTTP 422 body.items.280.queue_key: String should have at most 512 characters",
            file=sys.stderr,
        )
        print("gau-endpoints: ingest-endpoints exited 1", file=sys.stderr)
        sys.exit(1)


def _status(tmp_path: Path) -> dict:
    return json.loads(recon.status_path(_cfg(tmp_path)).read_text(encoding="utf-8"))


def test_gau_ingest_failure_marks_the_stage_failed_with_the_error(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    monkeypatch.setattr(gau_endpoints, "run", _gau_one_apex_fails)
    monkeypatch.setattr(
        recon,
        "_STAGE_RUNNERS",
        {
            "dns": _ok_stage("scans/dns-discovery/resolved_hosts.txt"),
            "web": _ok_stage("scans/web-discovery/httpx_live.jsonl"),
            "gau": recon._run_gau,
        },
    )

    with pytest.raises(SystemExit) as exc:
        recon.run(_args(tmp_path, no_js_mining=True))
    assert exc.value.code == 1

    status = _status(tmp_path)
    gau = next(s for s in status["stages"] if s["key"] == "gau")
    assert gau["state"] == "failed"
    assert gau["exit_code"] == 1
    assert gau["counts"] == {"apexes_mined": 1, "apexes_failed": 1}
    assert len(gau["errors"]) == 1
    assert gau["errors"][0].startswith("acme-two.example: gau-endpoints exited 1")
    assert "HTTP 422" in gau["errors"][0]
    assert status["overall_state"] == "partial"
    meta = json.loads((tmp_path / "scans" / "recon" / "gau.meta.json").read_text())
    assert meta["done"] is False  # --resume re-runs the stage

    monkeypatch.setattr(recon_status, "load_config", lambda d: _cfg(tmp_path))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        recon_status.run(SimpleNamespace(engagement_dir=str(tmp_path), job_id=None, as_json=False))
    text = out.getvalue()
    assert "[failed  ] gau-endpoints rc=1" in text
    assert "apexes_failed=1" in text
    assert "acme-two.example: gau-endpoints exited 1" in text

    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        recon_status.run(SimpleNamespace(engagement_dir=str(tmp_path), job_id=None, as_json=True))
    digest = json.loads(out.getvalue())
    assert digest["next"] == "gau-endpoints"
    assert digest["stages"][-1]["errors"] == gau["errors"]


def test_js_mining_failure_is_recorded_and_later_stages_still_run(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)

    def boom(ns):
        raise RuntimeError("jsluice exploded")

    ran: list[str] = []

    def gau(args, cfg):
        ran.append("gau")
        return _ok_stage("scans/recon/gau.done")(args, cfg)

    monkeypatch.setattr(js_mining, "run", boom)
    monkeypatch.setattr(
        recon,
        "_STAGE_RUNNERS",
        {
            "dns": _ok_stage("scans/dns-discovery/resolved_hosts.txt"),
            "web": _ok_stage("scans/web-discovery/httpx_live.jsonl"),
            "js": recon._run_js,
            "gau": gau,
        },
    )

    with pytest.raises(SystemExit):
        recon.run(_args(tmp_path))

    assert ran == ["gau"]
    status = _status(tmp_path)
    js = next(s for s in status["stages"] if s["key"] == "js")
    assert js["state"] == "failed"
    assert js["errors"] == ["js-mining errored (RuntimeError: jsluice exploded)"]
    assert next(s for s in status["stages"] if s["key"] == "gau")["state"] == "done"
    assert status["overall_state"] == "partial"


def test_js_mining_ingest_failure_and_undecodable_bodies_reach_the_stage(monkeypatch, tmp_path):
    def summary_with_errors(ns):
        return {
            "undecodable_bodies": 2,
            "errors": ["ingest-endpoints exited 1; endpoints written to x but not ingested"],
        }

    monkeypatch.setattr(js_mining, "run", summary_with_errors)
    outcome = recon._run_js(_args(tmp_path), _cfg(tmp_path))
    assert outcome.rc == 1
    assert outcome.counts == {"undecodable_bodies": 2}
    assert outcome.errors == (
        "ingest-endpoints exited 1; endpoints written to x but not ingested",
    )


def _gau_with_refused_rows(ns):
    refused = 3 if ns.target == "acme-two.example" else 0
    return {"verb": "gau-endpoints", "target": ns.target, "backend_refused": refused,
            "write_uncertain": 0}


def test_gau_rows_the_backend_refused_make_the_stage_partial(monkeypatch, tmp_path):
    monkeypatch.setattr(recon, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    monkeypatch.setattr(gau_endpoints, "run", _gau_with_refused_rows)
    monkeypatch.setattr(
        recon,
        "_STAGE_RUNNERS",
        {
            "dns": _ok_stage("scans/dns-discovery/resolved_hosts.txt"),
            "web": _ok_stage("scans/web-discovery/httpx_live.jsonl"),
            "gau": recon._run_gau,
        },
    )

    recon.run(_args(tmp_path, no_js_mining=True))  # no failed stage, so exit 0

    status = _status(tmp_path)
    gau = next(s for s in status["stages"] if s["key"] == "gau")
    assert gau["state"] == "partial"
    assert gau["exit_code"] == 0
    assert gau["counts"] == {"apexes_mined": 2, "backend_refused": 3}
    assert len(gau["errors"]) == 1
    assert gau["errors"][0].startswith("acme-two.example: 3 row(s) the backend refused")
    assert status["overall_state"] == "partial"

    monkeypatch.setattr(recon_status, "load_config", lambda d: _cfg(tmp_path))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        recon_status.run(SimpleNamespace(engagement_dir=str(tmp_path), job_id=None, as_json=False))
    text = out.getvalue()
    assert text.startswith("recon-status: partial")
    assert "[partial ] gau-endpoints" in text
    assert "backend_refused=3" in text


def test_gau_endpoints_reports_the_ingest_refused_counts(monkeypatch, tmp_path):
    from assess.lib import gau_pipeline

    eng = tmp_path / "acme-eng"
    (eng / "scans").mkdir(parents=True)
    cfg = SimpleNamespace(engagement_dir=str(eng), engagement_key=eng.name,
                          base_url="http://127.0.0.1:18000")
    monkeypatch.setattr(gau_endpoints, "load_config", lambda d: cfg)
    key = gau_pipeline.gau_cache_key(subs=False)
    paths = gau_pipeline.resolve_pipeline_paths(cfg, target="acme.example", cache_key=key)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    paths.output_path.write_text("https://acme.example/a\n", encoding="utf-8")
    decision = gau_pipeline.GauCacheDecision(True, "reused", SimpleNamespace(line_count=1), 1.0)
    monkeypatch.setattr(gau_endpoints, "decide_cache_reuse", lambda paths, **k: decision)
    monkeypatch.setattr(gau_endpoints, "announce_cache_decision", lambda d, **k: None)
    monkeypatch.setattr(gau_endpoints, "_summarize_work_buffer", lambda c, src: {})

    def no_dedup(*a, **k):
        raise gau_endpoints.AssessError("uro unavailable")

    monkeypatch.setattr(gau_endpoints, "run_uro_dedup", no_dedup)
    from assess.commands import ingest_endpoints

    monkeypatch.setattr(
        ingest_endpoints, "run",
        lambda ns: {"ingested": 4, "backend_refused": 2, "write_uncertain": 1},
    )
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        summary = gau_endpoints.run(SimpleNamespace(
            engagement_dir=str(eng), target="acme.example", source="gau", subs=False,
            providers="", refresh=False, max_cache_age_hours=24, phase="recon",
            timeout=900, db_override=None,
        ))

    printed = json.loads(out.getvalue())
    assert summary == printed
    assert (summary["ingested"], summary["backend_refused"], summary["write_uncertain"]) == (4, 2, 1)
