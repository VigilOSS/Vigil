"""Repeated advisories print once per run and say they will not repeat.

The target-concurrency advisory printed before every recon stage, and the
"attribution headers could not be injected" warning printed for every run of
the same tool. Inside one run (a recon job, including any child process
it spawns) each line now prints once; the concurrency advisory prints again
only when its reading changes, because a newly active foreign lane is news.
Outside a run scope every call still prints, as before.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from assess.commands import recon
from assess.lib import execution_recency, kali, run_notices


class _RecencyClient:
    def __init__(self, count: int, latest: str) -> None:
        self.reading = {"foreign_count": count, "latest_started_at": latest}

    def get(self, endpoint):
        return dict(self.reading)


_NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def _advise(client) -> None:
    execution_recency.emit_foreign_lane_recency(client, current_agent="operator", now=_NOW)


def test_concurrency_advisory_prints_once_per_run_until_the_reading_changes(capsys):
    client = _RecencyClient(5774, "2026-11-04T00:00:00Z")
    with run_notices.notice_scope():
        _advise(client)
        _advise(client)
        _advise(client)
        first = capsys.readouterr().err
        client.reading = {"foreign_count": 5775, "latest_started_at": "2026-11-14T11:59:50Z"}
        _advise(client)
        changed = capsys.readouterr().err

    assert first.count("target concurrency advisory:") == 1
    assert "5774 foreign-lane" in first
    assert "not repeated for the rest of this run unless the reading changes" in first
    assert changed.count("target concurrency advisory:") == 1
    assert "5775 foreign-lane" in changed and "latest 10s ago" in changed


def test_without_a_run_scope_every_call_still_prints(capsys):
    client = _RecencyClient(2, "2026-11-14T11:59:30Z")
    _advise(client)
    _advise(client)
    err = capsys.readouterr().err
    assert err.count("target concurrency advisory:") == 2
    assert "not repeated" not in err


def test_header_warning_prints_once_per_tool_per_run(tmp_path, capsys):
    headers = {"X-Acme-Research": "acme-team"}

    def warn(tool: str) -> None:
        kali._verify_required_headers_in_script(
            ["bash", "-lc", f"{tool} --version"],
            engagement_dir=tmp_path,
            headers=headers,
            tool_name=tool,
        )

    with run_notices.notice_scope():
        warn("wafw00f")
        warn("wafw00f")
        warn("acme-scanner")
    err = capsys.readouterr().err

    assert err.count("could not be injected into tool 'wafw00f'") == 1
    assert err.count("could not be injected into tool 'acme-scanner'") == 1
    assert "Not repeated for this tool for the rest of this run" in err
    assert "required_header_status" in err


def test_child_processes_inherit_what_the_run_already_printed():
    with run_notices.notice_scope():
        assert run_notices.emit_once("acme-notice", "acme notice")
        script = (
            "import sys; sys.path.insert(0, sys.argv[1]);"
            "from assess.lib import run_notices;"
            "print(run_notices.emit_once('acme-notice', 'acme notice'))"
        )
        scripts_root = str(Path(run_notices.__file__).resolve().parents[2])
        child = subprocess.run(
            [sys.executable, "-c", script, scripts_root],
            capture_output=True, text=True, env=dict(os.environ), check=True,
        )
    assert child.stdout.strip() == "False"
    assert run_notices.ENV_VAR not in os.environ


def test_recon_job_opens_one_run_scope_for_every_stage(monkeypatch, tmp_path, capsys):
    cfg = SimpleNamespace(base_url="http://127.0.0.1:18000", engagement_key="eng",
                          engagement_dir=str(tmp_path))
    client = _RecencyClient(5774, "2026-11-04T00:00:00Z")

    def stage(artifact: str):
        def runner(args, cfg):
            _advise(client)
            path = Path(cfg.engagement_dir) / artifact
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x\n", encoding="utf-8")
            return 0
        return runner

    monkeypatch.setattr(recon, "load_config", lambda d: cfg)
    monkeypatch.setattr(recon, "_enforce_host_routing", lambda *a, **k: None)
    monkeypatch.setattr(recon, "_STAGE_RUNNERS", {
        "dns": stage("scans/dns-discovery/resolved_hosts.txt"),
        "web": stage("scans/web-discovery/httpx_live.jsonl"),
        "gau": stage("scans/recon/gau.done"),
    })
    recon.run(SimpleNamespace(
        apexes=["acme.example"], engagement_dir=str(tmp_path), brute=False,
        runtime="container", no_crawl=False, no_gau=False, no_js_mining=True,
        resume=False, stage_timeout=60, background=False, foreground=False, job_id=None,
    ))

    assert capsys.readouterr().err.count("target concurrency advisory:") == 1
    assert run_notices.ENV_VAR not in os.environ
