"""Async-job helpers for `vigil assess kali job ...`.

Backed by the orchestrator backend's `assessment_jobs` table via
``AssessmentClient``. dtach is the supervisor inside the runtime container
— sessions parented by tini survive the calling shell.
"""
from __future__ import annotations

import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .client import AssessError, AssessmentClient, default_runtime_container
from .config import Config, load_config
from .kali_runtime_exec import _cat_container_pid_file, _container_running

_DEFAULT_DTACH_DIR = "/tmp/vigil-jobs"
_JOB_PID_DIR = "/tmp/vigil-jobs"
_JOB_TERMINAL_STATUSES = {"completed", "failed", "killed", "lost", "stop_failed"}

# ``_container_running`` is imported at module level so tests can patch it via
# ``monkeypatch.setattr(kali_jobs, "_container_running", ...)``.



def _job_pid_file(job_uuid: str) -> str:
    return f"{_JOB_PID_DIR}/{job_uuid}.pid"


def _check_dtach_in_container(container_name: str) -> None:
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "which", "dtach"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise AssessError(f"docker exec failed: {exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise AssessError(
            "dtach is not installed inside the runtime container. "
            "The job worker depends on dtach as its supervisor (Phase 3 ensures "
            "this is in the runtime image)."
        )


def _ensure_dtach_dir(container_name: str, dtach_dir: str) -> None:
    subprocess.run(
        ["docker", "exec", container_name, "mkdir", "-p", dtach_dir],
        check=False,
        capture_output=True,
        timeout=5,
    )


def _job_paths(engagement_dir: Path, job_uuid: str) -> tuple[Path, Path]:
    out_dir = engagement_dir / "scans" / "kali" / "jobs"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{job_uuid}.out", out_dir / f"{job_uuid}.err"


def start_job(
    cmd: list[str],
    *,
    audit_meta: dict[str, Any],
    engagement_dir: Path | None = None,
    container_name: str | None = None,
    dtach_socket_dir: str = _DEFAULT_DTACH_DIR,
    parent_command_run_id: int | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    """POST a queued row, persist job paths, spawn dtach, mark it running.

    Returns the backend job record (with `dtach_socket_path` populated).
    """
    # Resolve the container name at call time so VIGIL_RUNTIME_CONTAINER is read
    # now, not when this module was imported. Default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = Path(engagement_dir).resolve() if engagement_dir is not None else Path(cfg.engagement_dir).resolve()
    if not _container_running(container_name):
        raise AssessError(
            f"runtime container '{container_name}' is not running. "
            "Run `vigil runtime start` first."
        )
    _check_dtach_in_container(container_name)
    _ensure_dtach_dir(container_name, dtach_socket_dir)

    job_uuid = uuid.uuid4().hex
    socket_path = f"{dtach_socket_dir}/{job_uuid}.sock"
    pid_file = _job_pid_file(job_uuid)
    stdout_path, stderr_path = _job_paths(eng_dir, job_uuid)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    spawned = False
    job_id: int | None = None
    try:
        created = client.post(
            "jobs",
            {
                "parent_command_run_id": parent_command_run_id,
                "status": "queued",
                "audit_metadata": audit_meta,
            },
        )
        job_id = int(created["id"])

        # Translate host-side stdout paths into container paths via the
        # /engagements bind mount: ${ENGAGEMENT_DIR} is mounted at
        # /engagements/${ENGAGEMENT_KEY} inside the runtime.
        container_stdout = (
            f"/engagements/{cfg.engagement_key}/scans/kali/jobs/{stdout_path.name}"
        )
        container_stderr = (
            f"/engagements/{cfg.engagement_key}/scans/kali/jobs/{stderr_path.name}"
        )
        client.patch(
            f"jobs/{job_id}",
            {
                "dtach_socket_path": socket_path,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
        joined = " ".join(shlex.quote(part) for part in cmd)
        # Record the user-command PID before exec so `job_stop` can address
        # the process across the container PID namespace boundary. ``exec``
        # in POSIX shells reuses the calling shell's PID, so $$ is the PID
        # of the user command itself once exec runs.
        # Redirect the user command's stdin from /dev/null. This is the
        # in-container analogue of the synchronous exec path's
        # ``stdin=subprocess.DEVNULL`` (kali.py). ProjectDiscovery tools
        # (httpx/katana/nuclei/dnsx/naabu) read targets from stdin whenever
        # fd 0 is not a TTY and block on EOF that never arrives — so a
        # backgrounded probe hangs at 0% CPU even with ``-l <file>``. The
        # ``</dev/null`` is tool-agnostic (no katana ``-no-stdin`` arg-parse
        # problem) and harmless to a tool that reads its targets from a flag.
        wrapped_shell = (
            f"echo $$ > {shlex.quote(pid_file)}; "
            f"exec sh -c {shlex.quote(f'{joined} >>{shlex.quote(container_stdout)} 2>>{shlex.quote(container_stderr)} </dev/null')}"
        )
        # ENGAGEMENT_KEY env mirrors the sync exec path in
        # ``kali_runtime_exec._build_docker_exec`` so skill commands launched as
        # background jobs see ``$ENGAGEMENT_KEY`` expand to the engagement name
        # rather than the empty string.
        dtach_argv = [
            "docker",
            "exec",
            "-d",
            "--env",
            f"ENGAGEMENT_KEY={cfg.engagement_key}",
            "-w",
            f"/engagements/{cfg.engagement_key}",
            container_name,
            "dtach",
            "-n",
            socket_path,
            "sh",
            "-c",
            wrapped_shell,
        ]
        try:
            subprocess.run(dtach_argv, check=True, capture_output=True, text=True, timeout=10)
            spawned = True
        except subprocess.CalledProcessError as exc:
            client.patch(
                f"jobs/{job_id}",
                {"status": "failed", "exit_code": exc.returncode},
            )
            raise AssessError(
                f"dtach spawn failed: {exc.stderr or exc.stdout}"
            ) from exc

        updated = client.patch(
            f"jobs/{job_id}",
            {"status": "running"},
        )
        return updated
    except Exception:
        if spawned:
            _cleanup_spawned_job(container_name, socket_path, pid_file)
        # Mark the backend row 'failed' before re-raising whenever it was already
        # created — otherwise ANY failure after the POST leaves it stuck at
        # 'queued' forever (no sweeper covers assessment_jobs). This covers the
        # status=running PATCH (spawned=True), but ALSO the failures that escape
        # the inner CalledProcessError handler with spawned still False: the paths
        # PATCH raising, a dtach spawn TimeoutExpired, or docker missing
        # (FileNotFoundError). A spawn timeout may leave an orphaned dtach process;
        # that is reconciled separately by kali_sweep_orphans. Best-effort: a
        # failing PATCH here must not mask the original error.
        if job_id is not None:
            try:
                client.patch(f"jobs/{job_id}", {"status": "failed"})
            except Exception:
                pass
        raise
    finally:
        client.close()


def job_status(job_id: int, *, config: Config | None = None) -> dict[str, Any]:
    cfg = config or load_config(None)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        return client.get(f"jobs/{int(job_id)}")
    finally:
        client.close()


def job_list(
    *,
    status_value: str | None = None,
    parent_run_id: int | None = None,
    config: Config | None = None,
) -> list[dict[str, Any]]:
    cfg = config or load_config(None)
    params: list[str] = []
    if status_value:
        params.append(f"status={status_value}")
    if parent_run_id is not None:
        params.append(f"parent_command_run_id={int(parent_run_id)}")
    query = "jobs"
    if params:
        query = "jobs?" + "&".join(params)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        rows = client.get(query)
    finally:
        client.close()
    if not isinstance(rows, list):
        return []
    return rows


def job_tail(job_id: int, *, follow: bool = False, config: Config | None = None) -> None:
    cfg = config or load_config(None)
    record = job_status(job_id, config=cfg)
    stdout_path = record.get("stdout_path") or ""
    if not stdout_path:
        raise AssessError(f"job {job_id} has no stdout_path recorded yet")
    path = Path(stdout_path)
    if follow:
        try:
            subprocess.run(["tail", "-f", str(path)], check=False)
        except FileNotFoundError as exc:
            raise AssessError(f"tail not available: {exc}") from exc
    else:
        if not path.is_file():
            raise AssessError(f"stdout file not found: {path}")
        sys.stdout.write(path.read_text(encoding="utf-8", errors="replace"))


def _read_job_pid(container_name: str, pid_file: str) -> int | None:
    """Thin wrapper over the shared ``docker exec cat`` core in
    kali_runtime_exec; preserves this call site's ``int | None`` semantics
    (the diagnostic ``reason`` tag is dropped — only the job-stop dry-run path
    in kali_sweep_orphans needs it)."""
    return _cat_container_pid_file(container_name, pid_file)[0]


def _job_pid_alive(container_name: str, pid: int) -> bool | None:
    """Three-state liveness probe via ``docker exec kill -0``.

    Returns True when the PID is alive (rc=0), False when the in-container kill
    reports the PID is gone (rc=1), and None when Docker probing itself failed
    (docker unreachable / timeout / any other rc). The None case must NOT be
    collapsed to False: a transient docker blip during ``job_stop`` would
    otherwise mark a still-running job 'killed'. Mirrors
    ``kali_sweep_orphans._pid_alive_in_container``."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "kill", "-0", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def _signal_job_pid(container_name: str, pid: int, signal_name: str) -> None:
    try:
        subprocess.run(
            ["docker", "exec", container_name, "kill", f"-{signal_name}", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _wait_for_pid_exit(
    container_name: str,
    pid: int,
    *,
    timeout_seconds: float,
    poll_interval: float = 0.25,
) -> bool | None:
    """Poll ``kill -0 pid`` inside the container until the PID is gone or the
    deadline passes.

    Three-state result so a docker blip is never mistaken for a confirmed exit:
    - ``True``  — the PID was observed gone (``kill -0`` rc=1). Confirmed dead.
    - ``False`` — deadline reached with the PID still alive (last probe rc=0).
    - ``None``  — deadline reached but the last probe could not reach docker, so
      liveness is unknown. Callers must not finalize a definitive ``killed`` on
      ``None`` (see ``job_stop``)."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        alive = _job_pid_alive(container_name, pid)
        if alive is False:
            return True
        if time.monotonic() >= deadline:
            # alive is True (still running) or None (probe unreachable): surface
            # the distinction so the caller knows whether the PID is verified
            # alive or merely unverifiable.
            return False if alive is True else None
        time.sleep(poll_interval)


def _interrupt_dtach_session(container_name: str, socket_path: str) -> None:
    try:
        subprocess.run(
            [
                "docker",
                "exec",
                container_name,
                "sh",
                "-c",
                f"printf '\\003' | dtach -p {shlex.quote(socket_path)} || true",
            ],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _cleanup_spawned_job(container_name: str, socket_path: str, pid_file: str) -> None:
    """Best-effort cleanup for a just-spawned dtach job before start_job re-raises."""
    pid = _read_job_pid(container_name, pid_file)
    if pid is None:
        _interrupt_dtach_session(container_name, socket_path)
        return

    _signal_job_pid(container_name, pid, "TERM")
    if _wait_for_pid_exit(container_name, pid, timeout_seconds=2.0):
        return
    _signal_job_pid(container_name, pid, "KILL")
    _wait_for_pid_exit(container_name, pid, timeout_seconds=2.0)


def job_stop(
    job_id: int,
    *,
    container_name: str | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    # Resolve the container name at call time so VIGIL_RUNTIME_CONTAINER is read
    # now, not when this module was imported. Default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    cfg = config or load_config(None)
    record = job_status(job_id, config=cfg)
    current_status = str(record.get("status") or "").strip()
    if current_status in _JOB_TERMINAL_STATUSES:
        raise AssessError(
            f"job {job_id} is already terminal with status={current_status}; stop will not overwrite it"
        )
    socket_path = record.get("dtach_socket_path") or ""
    if not socket_path:
        raise AssessError(f"job {job_id} has no dtach_socket_path recorded; cannot stop")

    # Derive the pid-file path from the socket: both share the job_uuid stem.
    sock = Path(socket_path)
    job_uuid_stem = sock.stem  # `<uuid>` from `<uuid>.sock`
    pid_file = _job_pid_file(job_uuid_stem)

    final_status = "lost"
    failure_message: str | None = None
    if _container_running(container_name):
        pid = _read_job_pid(container_name, pid_file)
        if pid is None:
            # No pid file → fall back to the dtach Ctrl-C path so trapped
            # foreground tools at least get a SIGINT, but do not report
            # killed because there is no PID to verify.
            _interrupt_dtach_session(container_name, socket_path)
            final_status = "stop_failed"
            failure_message = (
                f"job {job_id}: PID file {pid_file} is not available; sent a best-effort "
                "dtach interrupt but could not verify process exit. status=stop_failed "
                "recorded. Investigate the runtime."
            )
        else:
            _signal_job_pid(container_name, pid, "TERM")
            # _wait_for_pid_exit is three-state: True=confirmed gone,
            # False=still alive at deadline, None=docker unreachable (liveness
            # unknown). Escalate to SIGKILL unless already confirmed dead.
            wait_result = _wait_for_pid_exit(container_name, pid, timeout_seconds=10.0)
            if wait_result is not True:
                _signal_job_pid(container_name, pid, "KILL")
                wait_result = _wait_for_pid_exit(container_name, pid, timeout_seconds=5.0)
            if wait_result is True:
                final_status = "killed"
            elif wait_result is None:
                # Docker became unreachable mid-stop: we cannot confirm the PID
                # exited, so do NOT finalize a definitive 'killed' on a transient
                # blip against a possibly-still-running job. Record stop_failed
                # so the operator re-checks rather than trusting a false kill.
                final_status = "stop_failed"
                failure_message = (
                    f"job {job_id}: docker became unreachable while verifying the in-container "
                    "process exit; liveness is unknown so status=stop_failed was recorded rather "
                    "than a false 'killed'. Re-run stop or investigate the runtime."
                )
            else:
                final_status = "stop_failed"
                failure_message = (
                    f"job {job_id}: SIGTERM + SIGKILL both failed to terminate the in-container "
                    "process; status=stop_failed recorded. Investigate the runtime."
                )

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        record_out = client.patch(f"jobs/{int(job_id)}", {"status": final_status})
    finally:
        client.close()
    if final_status == "stop_failed":
        raise AssessError(failure_message or f"job {job_id}: stop failed")
    return record_out
