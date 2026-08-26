"""Phase 0 — async-job finalization, lazy reconciliation, and bulk reap.

The dtach worker is fire-and-forget (`dtach -n`) with no watcher, so the only
place a job's real exit code is observable is an in-band capture: the wrapper
publishes `$?` to a host-readable marker, and any host-side reader
(job_status / job_list / sweep-orphans) converges the backend row by reading it.
These tests pin:

  - the wrapper records the *tool* PID (`$!`) and publishes the exit marker
    atomically, and `started_at` is stamped on the running PATCH;
  - job_status / job_list lazy-finalize a stale `running` row when the marker
    is present (completed on rc=0, failed otherwise), and leave it alone when
    the marker is absent;
  - job_stop finalizes via the marker (completed, NOT killed) when the process
    finished in the kill window, records killed+ended_at when the PID is gone
    with no marker, and stop_failed (no ended_at) when docker is unreachable;
  - reap_jobs (`job stop --all`) walks in-flight rows and classifies each
    outcome without aborting on a single failure.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import kali_sweep_orphans as kso
from assess.lib import kali_jobs
from assess.lib.client import AssessError


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


class FakeClient:
    """Minimal AssessmentClient stand-in capturing post/patch/get calls.

    ``get_value`` is returned from every get(); ``post_value`` from every
    post(). patch() echoes the payload merged onto the row id so callers see
    the finalized fields.
    """

    def __init__(self, *, get_value=None, post_value=None):
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []
        self.gets: list[str] = []
        self._get_value = get_value if get_value is not None else {}
        self._post_value = post_value if post_value is not None else {"id": 1}

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        return dict(self._post_value)

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        row = {"id": int(endpoint.split("/")[-1])}
        row.update(payload)
        return row

    def get(self, endpoint):
        self.gets.append(endpoint)
        val = self._get_value
        if callable(val):
            return val(endpoint)
        if isinstance(val, list):
            return [dict(r) for r in val]
        return dict(val)

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000",
        engagement_key=tmp_path.name,
        engagement_dir=str(tmp_path),
    )


def _jobs_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scans" / "kali" / "jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _running_record(tmp_path: Path, *, job_id: int = 5, uuid: str = "deadbeef") -> dict:
    """A backend job row as job_status would GET it: running, with the
    host-side stdout_path that _exit_marker_host_path keys off."""
    stdout = _jobs_dir(tmp_path) / f"{uuid}.out"
    return {
        "id": job_id,
        "status": "running",
        "started_at": "2026-06-23T00:00:00Z",
        "stdout_path": str(stdout),
        "stderr_path": str(stdout).replace(".out", ".err"),
        "dtach_socket_path": f"/tmp/vigil-jobs/{uuid}.sock",
    }


def _write_marker(tmp_path: Path, uuid: str, rc: int) -> None:
    (_jobs_dir(tmp_path) / f"{uuid}.exit").write_text(str(rc), encoding="utf-8")


# --------------------------------------------------------------------------- #
# 1. start_job: wrapper captures the tool PID + publishes the marker; running
#    PATCH stamps started_at.
# --------------------------------------------------------------------------- #


def test_start_job_wrapper_and_started_at(monkeypatch, tmp_path):
    fake = FakeClient(post_value={"id": 7})
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kali_jobs.subprocess, "run", fake_run)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)

    kali_jobs.start_job(
        ["echo", "hi"],
        audit_meta={"technique": "RECON"},
        engagement_dir=tmp_path,
        container_name="vigil",
        config=_cfg(tmp_path),
        execution_policy={"target_facing": True},
    )

    wrapped_shell = captured["argv"][-1]
    # Tool PID recorded via $! (G1), not the wrapper's $$.
    assert "__child=$!" in wrapped_shell
    assert 'echo "$__child" >' in wrapped_shell
    assert 'wait "$__child"' in wrapped_shell
    # Exit code captured and published atomically to the .exit marker.
    assert "__rc=$?" in wrapped_shell
    assert ".exit.tmp" in wrapped_shell
    assert "mv -f" in wrapped_shell
    assert f"/engagements/{tmp_path.name}/scans/kali/jobs/" in wrapped_shell
    # The tool is exec'd inside the backgrounded inner sh so $! IS the tool PID
    # (B1): the recorded PID must be the tool, not an idle supervisor sh.
    assert "exec echo hi" in wrapped_shell

    running_patches = [p for _, p in fake.patches if p.get("status") == "running"]
    assert running_patches, "expected a running PATCH"
    assert running_patches[-1].get("started_at"), "running PATCH must stamp started_at"


def test_start_job_acquires_rate_lease_before_dtach_and_persists_token(
    monkeypatch, tmp_path
):
    fake = FakeClient(post_value={"id": 17})
    events: list[str] = []
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        kali_jobs,
        "acquire_target_rate_lease",
        lambda **kwargs: events.append("lease") or {"lease_token": "rate-17"},
    )
    monkeypatch.setattr(
        kali_jobs.subprocess,
        "run",
        lambda *a, **k: events.append("spawn") or SimpleNamespace(returncode=0),
    )

    kali_jobs.start_job(
        ["httpx", "-u", "https://example.com", "-rate-limit", "5"],
        audit_meta={
            "technique": "RECON",
            "agent_name": "recon-specialist",
            "timeout_seconds_requested": 120,
            "effective_rate_rps": 5,
            "rate_override_reason": "",
        },
        engagement_dir=tmp_path,
        container_name="vigil",
        config=_cfg(tmp_path),
        execution_policy={"target_facing": True},
    )

    assert events.index("lease") < events.index("spawn")
    metadata_patches = [
        payload for _, payload in fake.patches if "audit_metadata" in payload
    ]
    assert metadata_patches[-1]["audit_metadata"]["rate_lease_token"] == "rate-17"


def test_start_job_creates_command_audit_before_linked_job_and_spawn(
    monkeypatch, tmp_path
):
    events: list[str] = []

    class LifecycleClient(FakeClient):
        def post(self, endpoint, payload):
            events.append(f"post:{endpoint}")
            self.posts.append((endpoint, payload))
            if endpoint == "command-runs":
                return {"id": 41, "status": "running"}
            return {"id": 17, "status": "queued"}

    fake = LifecycleClient()
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(
        kali_jobs.subprocess,
        "run",
        lambda *a, **k: events.append("spawn") or SimpleNamespace(returncode=0),
    )

    kali_jobs.start_job(
        ["nuclei", "-u", "https://example.com"],
        audit_meta={
            "technique": "RECON",
            "intent": "background scan",
            "probe_kind": "fingerprint",
            "phase": "recon",
            "agent_name": "recon-specialist",
            "timeout_seconds_requested": 60,
            "scope_version": "scope-v1",
            "auth_context": "anonymous",
            "target_facing": True,
        },
        engagement_dir=tmp_path,
        container_name="vigil",
        config=_cfg(tmp_path),
        execution_policy={"target_facing": True},
    )

    assert events[:3] == ["post:command-runs", "post:jobs", "spawn"]
    job_payload = next(payload for endpoint, payload in fake.posts if endpoint == "jobs")
    assert job_payload["parent_command_run_id"] == 41
    command_payload = next(
        payload for endpoint, payload in fake.posts if endpoint == "command-runs"
    )
    assert command_payload["status"] == "running"
    assert command_payload["stdout_path"].endswith(".out")
    assert command_payload["notes"]


def test_wrapper_records_tool_pid_not_supervisor(tmp_path):
    """B1 regression: the recorded PID must be the TOOL, not the wrapper sh, so
    job_stop's exact-PID kill hits the tool (else the tool is orphaned). Runs the
    REAL wrapper through the host sh (no docker) and inspects the recorded PID's
    process name — this is the one behavior unit mocks cannot fake."""
    jobs = _jobs_dir(tmp_path)
    pid_file = str(jobs / "t.pid")
    wrapper = kali_jobs._build_job_wrapper(
        "sleep 2",
        pid_file=pid_file,
        stdout_path=str(jobs / "t.out"),
        stderr_path=str(jobs / "t.err"),
        exit_path=str(jobs / "t.exit"),
    )
    proc = subprocess.Popen(["sh", "-c", wrapper], start_new_session=True)  # noqa: S603,S607
    try:
        pid = None
        for _ in range(60):
            try:
                pid = int(Path(pid_file).read_text(encoding="utf-8").strip())
                break
            except (OSError, ValueError):
                time.sleep(0.05)
        assert pid is not None, "wrapper never wrote a pid file"
        comm = subprocess.run(  # noqa: S603,S607
            ["ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True
        ).stdout.strip()
        # The recorded PID must be the tool (sleep) — NOT a shell. Pre-fix this was
        # the wrapper's `sh`, so kill -TERM <recorded> killed the supervisor and
        # left `sleep` orphaned.
        assert "sleep" in comm, f"recorded PID {pid} is {comm!r}, expected the tool (sleep) — B1"
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait(timeout=5)


def test_wrapper_marker_captures_real_tool_exit(tmp_path):
    """The marker holds the TOOL's real exit code (via the wrapper's wait), not
    the supervisor's. Exercised end-to-end through the host sh."""
    jobs = _jobs_dir(tmp_path)
    exit_path = jobs / "e.exit"
    wrapper = kali_jobs._build_job_wrapper(
        "sh -c 'exit 42'",
        pid_file=str(jobs / "e.pid"),
        stdout_path=str(jobs / "e.out"),
        stderr_path=str(jobs / "e.err"),
        exit_path=str(exit_path),
    )
    subprocess.run(["sh", "-c", wrapper], timeout=10, check=False)  # noqa: S603,S607
    marker = ""
    for _ in range(60):
        try:
            marker = exit_path.read_text(encoding="utf-8").strip()
        except OSError:
            marker = ""
        if marker:
            break
        time.sleep(0.05)
    assert marker == "42"


# --------------------------------------------------------------------------- #
# 1b. Hard deadline + finalize-on-death (I-19): the async dtach worker has no
#     hard deadline, so a hung run (nuclei stuck on template load, 0-byte output
#     for hours) survives until a manual sweep-orphans. The wrapper now arms a
#     budget-sized watchdog that kills the tool AT the deadline and self-
#     finalizes via the marker, mirroring the sync exec path's --timeout cascade.
# --------------------------------------------------------------------------- #


def test_build_job_wrapper_embeds_deadline_watchdog():
    """The constructed wrapper carries a hard-deadline watchdog sized from the
    requested timeout: SIGTERM the TOOL pid at the budget, escalate to SIGKILL
    after the fixed grace (sync-path parity). A hung run is killed at the
    deadline instead of surviving until sweep-orphans (I-19)."""
    wrapper = kali_jobs._build_job_wrapper(
        "nuclei -l targets.txt",
        pid_file="/tmp/j.pid",
        stdout_path="/e/j.out",
        stderr_path="/e/j.err",
        exit_path="/e/j.exit",
        timeout_seconds=1800,
    )
    # Budget sized from the requested timeout; grace from the sync-path constant.
    assert "1800" in wrapper
    assert str(kali_jobs._JOB_KILL_GRACE_SECONDS) in wrapper
    # The cascade targets the TOOL pid ($__child) — the same exact-PID target
    # job_stop signals, never a supervisor — TERM then escalate to KILL.
    assert 'kill -TERM "$__child"' in wrapper
    assert 'kill -KILL "$__child"' in wrapper
    # B1 preserved: the recorded/awaited pid is still the tool, not the watchdog.
    assert "__child=$!" in wrapper
    assert 'wait "$__child"' in wrapper


def test_build_job_wrapper_no_deadline_when_timeout_absent():
    """Backward-compatible: with no requested timeout the wrapper is the plain
    no-watchdog form, so callers that do not size a budget keep today's exact
    behavior (the existing real-sh B1 tests rely on this path)."""
    wrapper = kali_jobs._build_job_wrapper(
        "echo hi",
        pid_file="/tmp/j.pid",
        stdout_path="/e/j.out",
        stderr_path="/e/j.err",
        exit_path="/e/j.exit",
    )
    assert "kill -TERM" not in wrapper
    assert "kill -KILL" not in wrapper
    assert "__watch" not in wrapper


@pytest.mark.parametrize("bad", [None, 0, -5, "", "nope"])
def test_build_job_wrapper_omits_deadline_for_nonpositive_budget(bad):
    """A missing / non-positive / unparseable budget arms no watchdog rather than
    a zero/negative deadline that would kill the tool immediately."""
    wrapper = kali_jobs._build_job_wrapper(
        "echo hi",
        pid_file="/tmp/j.pid",
        stdout_path="/e/j.out",
        stderr_path="/e/j.err",
        exit_path="/e/j.exit",
        timeout_seconds=bad,
    )
    assert "__watch" not in wrapper


def test_start_job_sizes_deadline_from_requested_timeout(monkeypatch, tmp_path):
    """start_job threads audit_metadata['timeout_seconds_requested'] into the
    wrapper as the hard deadline, so `kali job start --timeout N` actually bounds
    the async run (it was audit-only metadata before I-19)."""
    fake = FakeClient(post_value={"id": 8})
    captured: dict = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(kali_jobs.subprocess, "run", fake_run)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_check_dtach_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_ensure_dtach_dir", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)

    kali_jobs.start_job(
        ["sleep", "9000"],
        audit_meta={"technique": "RECON", "timeout_seconds_requested": 600},
        engagement_dir=tmp_path,
        container_name="vigil",
        config=_cfg(tmp_path),
    )
    wrapped_shell = captured["argv"][-1]
    assert "600" in wrapped_shell
    assert 'kill -TERM "$__child"' in wrapped_shell


def test_wrapper_deadline_kills_hung_tool_and_finalizes(tmp_path):
    """End-to-end through the host sh: a tool that would hang well past its budget
    is SIGTERM'd by the watchdog AT the deadline, the wrapper publishes the kill
    wait-status to the marker, and the marker-finalize path drives the row
    terminal (failed). This is the finalize-on-death guarantee (I-19): a hung run
    no longer survives to a manual sweep-orphans."""
    jobs = _jobs_dir(tmp_path)
    exit_path = jobs / "hung.exit"
    wrapper = kali_jobs._build_job_wrapper(
        "sleep 30",
        pid_file=str(jobs / "hung.pid"),
        stdout_path=str(jobs / "hung.out"),
        stderr_path=str(jobs / "hung.err"),
        exit_path=str(exit_path),
        timeout_seconds=1,
    )
    start = time.monotonic()
    subprocess.run(["sh", "-c", wrapper], timeout=30, check=False)  # noqa: S603,S607
    elapsed = time.monotonic() - start
    # Killed at ~budget (1s) + a poll tick — NOT after the tool's natural 30s.
    assert elapsed < 15, f"watchdog did not enforce the deadline (took {elapsed:.1f}s)"
    marker = ""
    for _ in range(60):
        try:
            marker = exit_path.read_text(encoding="utf-8").strip()
        except OSError:
            marker = ""
        if marker:
            break
        time.sleep(0.05)
    rc = int(marker)
    # A deadline kill is observed as a 128+signal wait status (SIGTERM=143).
    assert rc >= 128, f"expected a kill wait-status >=128, got {rc}"
    # finalize-on-death: the marker drives the backend row terminal (failed, not
    # left hanging at running until sweep-orphans).
    rec = {"id": 99, "status": "running", "stdout_path": str(jobs / "hung.out")}
    client = FakeClient()
    out = kali_jobs._finalize_if_marker_present(client, rec)
    assert out["status"] == "failed"
    assert out["exit_code"] == rc
    assert out["ended_at"]


def test_marker_finalization_also_finalizes_parent_command_run(tmp_path):
    _write_marker(tmp_path, "parented", 0)
    record = _running_record(tmp_path, job_id=51, uuid="parented")
    record["parent_command_run_id"] = 91
    client = FakeClient()

    out = kali_jobs._finalize_if_marker_present(client, record)

    assert out["status"] == "completed"
    parent_patches = [
        payload for endpoint, payload in client.patches
        if endpoint == "command-runs/91"
    ]
    assert parent_patches
    assert parent_patches[-1]["status"] == "completed"
    assert parent_patches[-1]["return_code"] == 0


def test_wrapper_natural_exit_is_prompt_under_deadline(tmp_path):
    """A tool that finishes well within its budget is NOT delayed by the watchdog:
    the poll-loop watchdog exits the instant the tool is gone (no long sleep
    lingers), so the marker publishes its real exit code right away."""
    jobs = _jobs_dir(tmp_path)
    exit_path = jobs / "quick.exit"
    wrapper = kali_jobs._build_job_wrapper(
        "sh -c 'exit 0'",
        pid_file=str(jobs / "quick.pid"),
        stdout_path=str(jobs / "quick.out"),
        stderr_path=str(jobs / "quick.err"),
        exit_path=str(exit_path),
        timeout_seconds=600,
    )
    start = time.monotonic()
    subprocess.run(["sh", "-c", wrapper], timeout=30, check=False)  # noqa: S603,S607
    elapsed = time.monotonic() - start
    # Returns in ~a poll tick, not the 600s budget — the watchdog never lingers.
    assert elapsed < 10, f"natural exit was delayed by the watchdog (took {elapsed:.1f}s)"
    marker = ""
    for _ in range(60):
        try:
            marker = exit_path.read_text(encoding="utf-8").strip()
        except OSError:
            marker = ""
        if marker:
            break
        time.sleep(0.05)
    assert marker == "0"


# --------------------------------------------------------------------------- #
# 2. _read_exit_marker / _finalize_if_marker_present
# --------------------------------------------------------------------------- #


def test_read_exit_marker(tmp_path):
    rec = _running_record(tmp_path, uuid="aaaa")
    assert kali_jobs._read_exit_marker(rec) is None  # no marker yet
    _write_marker(tmp_path, "aaaa", 0)
    assert kali_jobs._read_exit_marker(rec) == 0
    _write_marker(tmp_path, "aaaa", 3)
    assert kali_jobs._read_exit_marker(rec) == 3


def test_finalize_marker_completed_and_failed(tmp_path):
    # rc=0 → completed
    rec = _running_record(tmp_path, job_id=11, uuid="bbbb")
    _write_marker(tmp_path, "bbbb", 0)
    client = FakeClient()
    out = kali_jobs._finalize_if_marker_present(client, rec)
    assert out["status"] == "completed"
    assert out["exit_code"] == 0
    assert out["ended_at"]
    assert client.patches[0][0] == "jobs/11"

    # rc!=0 → failed
    rec2 = _running_record(tmp_path, job_id=12, uuid="cccc")
    _write_marker(tmp_path, "cccc", 2)
    client2 = FakeClient()
    out2 = kali_jobs._finalize_if_marker_present(client2, rec2)
    assert out2["status"] == "failed"
    assert out2["exit_code"] == 2


def test_finalize_no_marker_is_noop(tmp_path):
    rec = _running_record(tmp_path, uuid="dddd")  # no marker written
    client = FakeClient()
    out = kali_jobs._finalize_if_marker_present(client, rec)
    assert out is rec
    assert client.patches == []


def test_finalize_skips_terminal_rows(tmp_path):
    rec = _running_record(tmp_path, uuid="eeee")
    rec["status"] = "completed"
    _write_marker(tmp_path, "eeee", 0)
    client = FakeClient()
    out = kali_jobs._finalize_if_marker_present(client, rec)
    assert out is rec
    assert client.patches == []  # already terminal — never re-PATCH


def test_finalize_reconciles_stop_failed_when_marker_arrives(tmp_path):
    rec = _running_record(tmp_path, job_id=14, uuid="attention")
    rec["status"] = "stop_failed"
    _write_marker(tmp_path, "attention", 0)
    client = FakeClient()

    out = kali_jobs._finalize_if_marker_present(client, rec)

    assert out["status"] == "completed"
    assert client.patches[-1][1]["exit_code"] == 0


def test_finalize_releases_persisted_rate_lease(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=15, uuid="leased")
    rec["audit_metadata"] = {"rate_lease_token": "rate-15"}
    _write_marker(tmp_path, "leased", 0)
    client = FakeClient()
    released: list[str] = []
    monkeypatch.setattr(
        kali_jobs,
        "release_target_rate_lease",
        lambda token, **kwargs: released.append(token),
    )

    kali_jobs._finalize_if_marker_present(client, rec)

    assert released == ["rate-15"]


# --------------------------------------------------------------------------- #
# 3. job_status / job_list lazy-finalize on read
# --------------------------------------------------------------------------- #


def test_job_status_lazy_finalizes(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=5, uuid="ffff")
    _write_marker(tmp_path, "ffff", 0)
    fake = FakeClient(get_value=rec)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)

    out = kali_jobs.job_status(5, config=_cfg(tmp_path))
    assert out["status"] == "completed"
    assert out["exit_code"] == 0
    assert ("jobs/5" in p[0] for p in fake.patches)


def test_job_list_lazy_finalizes(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=9, uuid="1234")
    _write_marker(tmp_path, "1234", 1)
    fake = FakeClient(get_value=[rec])
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)

    rows = kali_jobs.job_list(status_value="running", config=_cfg(tmp_path))
    assert len(rows) == 1
    assert rows[0]["status"] == "failed"
    assert rows[0]["exit_code"] == 1


# --------------------------------------------------------------------------- #
# 4. job_stop: marker → completed (not killed); no-marker+PID-gone → killed;
#    docker unreachable → stop_failed.
# --------------------------------------------------------------------------- #


def test_job_stop_completed_via_marker(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=20, uuid="5678")
    _write_marker(tmp_path, "5678", 0)
    fake = FakeClient(get_value=rec)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)

    # job_status (called inside job_stop) finalizes via the marker → the row is
    # terminal=completed → job_stop refuses to overwrite, never recording killed.
    with pytest.raises(AssessError) as exc:
        kali_jobs.job_stop(20, container_name="vigil", config=_cfg(tmp_path))
    assert "already terminal" in str(exc.value)
    assert "completed" in str(exc.value)
    # The marker finalize PATCHed completed; no killed PATCH was ever sent.
    assert any(p.get("status") == "completed" for _, p in fake.patches)
    assert not any(p.get("status") == "killed" for _, p in fake.patches)


def test_job_stop_killed_when_pid_gone_no_marker(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=21, uuid="9abc")  # no marker
    rec["parent_command_run_id"] = 121
    fake = FakeClient(get_value=rec)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 1234)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_wait_for_pid_exit", lambda *a, **k: True)

    out = kali_jobs.job_stop(21, container_name="vigil", config=_cfg(tmp_path))
    assert out["status"] == "killed"
    killed = [p for _, p in fake.patches if p.get("status") == "killed"]
    assert killed and killed[-1].get("ended_at"), "killed PATCH must stamp ended_at"
    parent = [p for endpoint, p in fake.patches if endpoint == "command-runs/121"]
    assert parent and parent[-1]["status"] == "killed"


def test_job_stop_stop_failed_when_docker_unreachable(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=22, uuid="def0")  # no marker
    fake = FakeClient(get_value=rec)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 1234)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: None)
    # None == docker unreachable / liveness unknown for both probe rounds.
    monkeypatch.setattr(kali_jobs, "_wait_for_pid_exit", lambda *a, **k: None)

    with pytest.raises(AssessError) as exc:
        kali_jobs.job_stop(22, container_name="vigil", config=_cfg(tmp_path))
    assert "stop_failed" in str(exc.value) or "unreachable" in str(exc.value)
    sf = [p for _, p in fake.patches if p.get("status") == "stop_failed"]
    assert sf, "expected a stop_failed PATCH"
    # stop_failed must NOT stamp ended_at — the process may still be alive.
    assert "ended_at" not in sf[-1]


def test_job_stop_retries_attention_required_stop_failed(monkeypatch, tmp_path):
    rec = _running_record(tmp_path, job_id=23, uuid="retry-stop")
    rec["status"] = "stop_failed"
    fake = FakeClient(get_value=rec)
    monkeypatch.setattr(kali_jobs, "AssessmentClient", lambda *a, **k: fake)
    monkeypatch.setattr(kali_jobs, "_container_running", lambda *a, **k: True)
    monkeypatch.setattr(kali_jobs, "_read_job_pid", lambda *a, **k: 9001)
    monkeypatch.setattr(kali_jobs, "_signal_job_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali_jobs, "_wait_for_pid_exit", lambda *a, **k: True)

    out = kali_jobs.job_stop(23, container_name="vigil", config=_cfg(tmp_path))

    assert out["status"] == "killed"


# --------------------------------------------------------------------------- #
# 5. reap_jobs (`job stop --all`) classification
# --------------------------------------------------------------------------- #


def test_reap_jobs_stops_all_inflight(monkeypatch, tmp_path):
    def fake_job_list(*, status_value, config):
        if status_value == "running":
            return [{"id": 1, "status": "running"}, {"id": 2, "status": "running"}]
        if status_value == "queued":
            return [{"id": 3, "status": "queued"}]
        return []

    stopped: list[int] = []

    def fake_job_stop(job_id, *, container_name, config):
        stopped.append(job_id)
        return {"id": job_id, "status": "killed"}

    monkeypatch.setattr(kali_jobs, "job_list", fake_job_list)
    monkeypatch.setattr(kali_jobs, "job_stop", fake_job_stop)

    out = kali_jobs.reap_jobs(container_name="vigil", config=_cfg(tmp_path))
    assert sorted(stopped) == [1, 2, 3]
    assert {r["id"] for r in out["stopped"]} == {1, 2, 3}
    assert out["already_terminal"] == []


def test_reap_jobs_includes_stop_failed_attention_rows(monkeypatch, tmp_path):
    queried: list[str] = []

    def fake_list(*, status_value, parent_run_id=None, config=None):
        queried.append(status_value)
        if status_value == "stop_failed":
            return [{"id": 8, "status": "stop_failed"}]
        return []

    monkeypatch.setattr(kali_jobs, "job_list", fake_list)
    monkeypatch.setattr(
        kali_jobs,
        "job_stop",
        lambda job_id, **kwargs: {"id": job_id, "status": "killed"},
    )

    out = kali_jobs.reap_jobs(container_name="vigil", config=_cfg(tmp_path))

    assert "stop_failed" in queried
    assert out["stopped"] == [{"id": 8, "status": "killed"}]
    assert out["failed"] == []


def test_reap_jobs_classifies_terminal_and_failures(monkeypatch, tmp_path):
    def fake_job_list(*, status_value, config):
        if status_value == "running":
            # id=4 was marker-finalized by job_list before reap saw it.
            return [{"id": 4, "status": "completed"}, {"id": 5, "status": "running"}]
        return []

    def fake_job_stop(job_id, *, container_name, config):
        raise AssessError(f"job {job_id}: SIGTERM + SIGKILL both failed; status=stop_failed")

    monkeypatch.setattr(kali_jobs, "job_list", fake_job_list)
    monkeypatch.setattr(kali_jobs, "job_stop", fake_job_stop)

    out = kali_jobs.reap_jobs(container_name="vigil", config=_cfg(tmp_path))
    # id=4 is already terminal → skipped without calling job_stop.
    assert {r["id"] for r in out["already_terminal"]} == {4}
    # id=5 stop raised a non-terminal error → failed bucket.
    assert {r["id"] for r in out["failed"]} == {5}
    assert out["stopped"] == []


# --------------------------------------------------------------------------- #
# 6. sweep-orphans --scope jobs reconciliation
# --------------------------------------------------------------------------- #


class FakeJobsSweepClient:
    """get() routes by the ?status= filter so a sweep can fetch running and
    queued rows separately; patch() records finalize calls."""

    def __init__(self, *, running=None, queued=None, stop_failed=None):
        self._running = list(running or [])
        self._queued = list(queued or [])
        self._stop_failed = list(stop_failed or [])
        self.gets: list[str] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint):
        self.gets.append(endpoint)
        if "status=running" in endpoint:
            return list(self._running)
        if "status=queued" in endpoint:
            return list(self._queued)
        if "status=stop_failed" in endpoint:
            return list(self._stop_failed)
        return []

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {"id": int(endpoint.split("/")[-1]), **payload}

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_sweep_lists_every_job_page_beyond_one_thousand() -> None:
    class PagedClient:
        def __init__(self):
            self.gets: list[str] = []

        def get(self, endpoint):
            self.gets.append(endpoint)
            offset = int(endpoint.split("offset=")[1].split("&")[0])
            status = endpoint.split("status=")[1].split("&")[0]
            if status != "running":
                return []
            if offset == 0:
                return [{"id": index} for index in range(1000)]
            if offset == 1000:
                return [{"id": index} for index in range(1000, 1005)]
            return []

    client = PagedClient()

    rows = kso._list_running_jobs(client)

    assert len(rows) == 1005
    running_gets = [value for value in client.gets if "status=running" in value]
    assert any("offset=0" in value for value in running_gets)
    assert any("offset=1000" in value for value in running_gets)


def _job_row(tmp_path, *, job_id, uuid, status="running", age_seconds=7200, started=True):
    stdout = _jobs_dir(tmp_path) / f"{uuid}.out"
    started_at = None
    if started:
        ts = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=age_seconds)
        started_at = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    created_at = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=age_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": job_id,
        "status": status,
        "started_at": started_at,
        "created_at": created_at,
        "stdout_path": str(stdout),
        "dtach_socket_path": f"/tmp/vigil-jobs/{uuid}.sock",
    }


def _run_jobs_sweep(monkeypatch, tmp_path, fake, *, dry_run=False):
    monkeypatch.setattr(kso, "load_config", lambda _flag: _cfg(tmp_path))
    monkeypatch.setattr(kso, "AssessmentClient", lambda *a, **k: fake)
    kso.run(
        SimpleNamespace(
            scope="jobs",
            engagement_dir=str(tmp_path),
            max_age_seconds=3600,
            container_name="vigil",
            dry_run=dry_run,
        )
    )


def test_jobs_sweep_marker_finalizes_completed(monkeypatch, tmp_path):
    row = _job_row(tmp_path, job_id=1, uuid="m000")
    row["parent_command_run_id"] = 101
    row["audit_metadata"] = {"rate_lease_token": "rate-sweep"}
    fake = FakeJobsSweepClient(running=[row])
    released: list[str] = []
    monkeypatch.setattr(
        kso,
        "release_target_rate_lease",
        lambda token, **kwargs: released.append(token),
    )
    _write_marker(tmp_path, "m000", 0)
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    job_patch = next(payload for endpoint, payload in fake.patches if endpoint == "jobs/1")
    assert job_patch["status"] == "completed"
    assert job_patch["exit_code"] == 0
    assert job_patch["ended_at"]
    parent_patch = next(
        payload for endpoint, payload in fake.patches
        if endpoint == "command-runs/101"
    )
    assert parent_patch["status"] == "completed"
    assert parent_patch["return_code"] == 0
    assert released == ["rate-sweep"]


def test_jobs_sweep_marker_finalizes_failed(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(running=[_job_row(tmp_path, job_id=2, uuid="m001")])
    _write_marker(tmp_path, "m001", 7)
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    assert fake.patches[0][1]["status"] == "failed"
    assert fake.patches[0][1]["exit_code"] == 7


def test_jobs_sweep_reconciles_stop_failed_marker(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(
        stop_failed=[
            _job_row(tmp_path, job_id=12, uuid="attention", status="stop_failed")
        ]
    )
    _write_marker(tmp_path, "attention", 0)

    _run_jobs_sweep(monkeypatch, tmp_path, fake)

    assert any("status=stop_failed" in endpoint for endpoint in fake.gets)
    assert fake.patches[0][1]["status"] == "completed"


def test_jobs_sweep_pid_dead_no_marker_is_lost(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(running=[_job_row(tmp_path, job_id=3, uuid="m002")])
    # No marker; pid file reads a pid, but the PID is gone.
    monkeypatch.setattr(kso, "_cat_container_pid_file", lambda *a, **k: (4242, "ok"))
    monkeypatch.setattr(kso, "_pid_alive_in_container", lambda *a, **k: False)
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    assert fake.patches[0][1]["status"] == "lost"
    assert fake.patches[0][1]["ended_at"]


def test_jobs_sweep_alive_left_running(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(running=[_job_row(tmp_path, job_id=4, uuid="m003")])
    monkeypatch.setattr(kso, "_cat_container_pid_file", lambda *a, **k: (4242, "ok"))
    monkeypatch.setattr(kso, "_pid_alive_in_container", lambda *a, **k: True)
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    assert fake.patches == []  # still-running → never finalized


def test_jobs_sweep_docker_unreachable_is_skipped(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(running=[_job_row(tmp_path, job_id=5, uuid="m004")])
    monkeypatch.setattr(kso, "_cat_container_pid_file", lambda *a, **k: (4242, "ok"))
    monkeypatch.setattr(kso, "_pid_alive_in_container", lambda *a, **k: None)
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    assert fake.patches == []  # liveness unknown → never falsely finalized


def test_sweep_all_includes_precise_host_process_registry(monkeypatch, tmp_path, capsys):
    fake = FakeJobsSweepClient()
    monkeypatch.setattr(kso, "load_config", lambda _flag: _cfg(tmp_path))
    monkeypatch.setattr(kso, "AssessmentClient", lambda *a, **k: fake)
    called: list[tuple[str, int, bool]] = []
    monkeypatch.setattr(
        kso,
        "reap_registered_processes",
        lambda engagement_dir, *, max_age_seconds, dry_run: (
            called.append((str(engagement_dir), max_age_seconds, dry_run))
            or {"checked": 1, "reaped": 1}
        ),
    )

    kso.run(
        SimpleNamespace(
            scope="all",
            engagement_dir=str(tmp_path),
            max_age_seconds=60,
            container_name="vigil",
            dry_run=False,
        )
    )

    payload = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert called == [(str(tmp_path), 60, False)]
    assert payload["host_processes_summary"]["reaped"] == 1


def test_jobs_sweep_queued_without_started_at_ages_from_created_at(monkeypatch, tmp_path):
    fake = FakeJobsSweepClient(
        queued=[_job_row(tmp_path, job_id=6, uuid="m005", status="queued", started=False)]
    )
    _run_jobs_sweep(monkeypatch, tmp_path, fake)
    assert fake.patches[0][0] == "jobs/6"
    assert fake.patches[0][1]["status"] == "lost"


def test_jobs_sweep_dry_run_does_not_patch(monkeypatch, tmp_path, capsys):
    fake = FakeJobsSweepClient(running=[_job_row(tmp_path, job_id=7, uuid="m006")])
    _write_marker(tmp_path, "m006", 0)
    _run_jobs_sweep(monkeypatch, tmp_path, fake, dry_run=True)
    assert fake.patches == []
    out = capsys.readouterr().out
    assert "would-finalize job id=7" in out
    assert "new_status=completed" in out
