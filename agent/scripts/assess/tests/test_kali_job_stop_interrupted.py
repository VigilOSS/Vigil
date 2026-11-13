"""A job that was still running when stop was requested is recorded ``killed``.

A tool that traps SIGTERM and exits 0 (ffuf prints "Caught keyboard interrupt"
and returns 0) used to be finalized ``completed`` with exit code 0, so a reader
took a partial sweep for a complete one. Whether the job finished on its own is
decided BEFORE signalling, from the exit marker: absent marker → stop request
recorded → whatever exit code the tool then publishes, the job (and its paired
command-run) read ``killed`` with the tool's real exit code. Every marker reader
(job status/list, sweep-orphans) honours the recorded stop request.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from _fake_client import StubClient

from assess.commands import kali_sweep_orphans as kso
from assess.lib import kali_jobs


class _Client(StubClient):
    def __init__(self, record: dict) -> None:
        self.record = dict(record)
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint):
        if endpoint.startswith("jobs?"):
            return [dict(self.record)]
        return dict(self.record)

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, dict(payload)))
        if endpoint.startswith("jobs/"):
            self.record.update(payload)
            return dict(self.record)
        return {"id": int(endpoint.split("/")[-1]), **payload}


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key=tmp_path.name, engagement_dir=str(tmp_path)
    )


def _record(tmp_path: Path, uuid: str) -> dict:
    jobs = tmp_path / "scans" / "kali" / "jobs"
    jobs.mkdir(parents=True, exist_ok=True)
    return {
        "id": 203,
        "status": "running",
        "started_at": "2026-11-14T02:35:24Z",
        "stdout_path": str(jobs / f"{uuid}.out"),
        "stderr_path": str(jobs / f"{uuid}.err"),
        "dtach_socket_path": f"/tmp/vigil-jobs/{uuid}.sock",
        "parent_command_run_id": 77933,
    }


def _install(monkeypatch, client, *, on_signal) -> None:
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(kali_jobs, "_check_container_running", lambda *_: None)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 4242)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: on_signal())
    monkeypatch.setattr(kali_jobs, "_wait_for_pid_exit", lambda *a, **k: True)


def test_tool_that_traps_sigterm_and_exits_zero_is_recorded_killed(monkeypatch, tmp_path):
    record = _record(tmp_path, "ffuf-trap")
    exit_marker = Path(record["stdout_path"]).with_suffix(".exit")
    client = _Client(record)
    # The tool catches SIGTERM, prints its interrupt banner and exits 0.
    _install(monkeypatch, client, on_signal=lambda: exit_marker.write_text("0", encoding="utf-8"))

    out = kali_jobs.job_stop(203, container_name="vigil", config=_cfg(tmp_path))

    assert out["status"] == "killed"
    assert out["exit_code"] == 0
    job_patch = [p for endpoint, p in client.patches if endpoint == "jobs/203"][-1]
    assert job_patch["status"] == "killed" and job_patch["exit_code"] == 0
    run_patch = [p for endpoint, p in client.patches if endpoint == "command-runs/77933"][-1]
    assert run_patch["status"] == "killed"
    assert run_patch["return_code"] == 0


def test_marker_readers_honour_a_recorded_stop_request(monkeypatch, tmp_path):
    # The stop was requested but the marker landed only after job_stop returned
    # without finalizing (e.g. docker became unreachable): the lazy finalizer and
    # the sweeper must still read the job as interrupted, not completed.
    record = _record(tmp_path, "late-marker")
    kali_jobs._record_stop_request(record)
    Path(record["stdout_path"]).with_suffix(".exit").write_text("0", encoding="utf-8")
    client = _Client(record)

    finalized = kali_jobs._finalize_if_marker_present(client, record)

    assert finalized["status"] == "killed"
    assert finalized["exit_code"] == 0


def test_sweep_orphans_honours_a_recorded_stop_request(monkeypatch, tmp_path):
    record = _record(tmp_path, "swept")
    record["started_at"] = "2026-01-01T00:00:00Z"
    record["created_at"] = "2026-01-01T00:00:00Z"
    kali_jobs._record_stop_request(record)
    Path(record["stdout_path"]).with_suffix(".exit").write_text("0", encoding="utf-8")

    class _SweepClient(_Client):
        def get(self, endpoint):
            if "status=running" in endpoint and "offset=0" in endpoint:
                return [dict(self.record)]
            return []

    client = _SweepClient(record)
    monkeypatch.setattr(kso, "load_config", lambda _flag: _cfg(tmp_path))
    monkeypatch.setattr(kso, "AssessmentClient", lambda *a, **k: client)
    kso.run(SimpleNamespace(
        scope="jobs", engagement_dir=str(tmp_path), max_age_seconds=3600,
        container_name="vigil", dry_run=False,
    ))

    job_patch = [p for endpoint, p in client.patches if endpoint == "jobs/203"][-1]
    assert job_patch["status"] == "killed" and job_patch["exit_code"] == 0
    run_patch = [p for endpoint, p in client.patches if endpoint == "command-runs/77933"][-1]
    assert run_patch["status"] == "killed"


def test_job_that_finished_before_stop_keeps_its_natural_outcome(monkeypatch, tmp_path):
    record = _record(tmp_path, "finished-first")
    client = _Client(record)
    marker = Path(record["stdout_path"]).with_suffix(".exit")
    signalled: list[bool] = []
    _install(monkeypatch, client, on_signal=lambda: signalled.append(True))
    # The marker lands between job_status's read and the stop decision.
    original = kali_jobs.job_status

    def status_then_finish(job_id, *, config=None):
        row = original(job_id, config=config)
        marker.write_text("3", encoding="utf-8")
        return row

    monkeypatch.setattr(kali_jobs, "job_status", status_then_finish)

    out = kali_jobs.job_stop(203, container_name="vigil", config=_cfg(tmp_path))

    assert out["status"] == "failed"
    assert out["exit_code"] == 3
    assert signalled == [], "a finished job must not be signalled"
    assert not kali_jobs._stop_requested(record)
