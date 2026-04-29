"""Async-job helpers for `aith assess kali job ...`.

Backed by the orchestrator backend's `assessment_jobs` table plus a local
transient queue in `cases.db` (kali_jobs) so the operator has an offline
record of jobs the local CLI dispatched. dtach is the supervisor inside the
runtime container — sessions parented by tini survive the calling shell.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .client import AssessError, AssessmentClient
from .config import Config, load_config


_DEFAULT_CONTAINER_NAME = "security-research"
_DEFAULT_DTACH_DIR = "/tmp/aith-jobs"
_JOB_PID_DIR = "/tmp/aith-jobs"


def _job_pid_file(job_uuid: str) -> str:
    return f"{_JOB_PID_DIR}/{job_uuid}.pid"


def _container_running(container_name: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container_name}$"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return container_name in (result.stdout or "").splitlines()


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
    container_name: str = _DEFAULT_CONTAINER_NAME,
    dtach_socket_dir: str = _DEFAULT_DTACH_DIR,
    parent_command_run_id: int | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    """POST a queued `assessment_jobs` row, spawn the dtach session, mark it running.

    Returns the backend job record (with `dtach_socket_path` populated).
    """
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = Path(engagement_dir).resolve() if engagement_dir is not None else Path(cfg.engagement_dir).resolve()
    if not _container_running(container_name):
        raise AssessError(
            f"runtime container '{container_name}' is not running. "
            "Run `aith runtime start` first."
        )
    _check_dtach_in_container(container_name)
    _ensure_dtach_dir(container_name, dtach_socket_dir)

    job_uuid = uuid.uuid4().hex
    socket_path = f"{dtach_socket_dir}/{job_uuid}.sock"
    pid_file = _job_pid_file(job_uuid)
    stdout_path, stderr_path = _job_paths(eng_dir, job_uuid)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
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
        joined = " ".join(shlex.quote(part) for part in cmd)
        # Record the user-command PID before exec so `job_stop` can address
        # the process across the container PID namespace boundary. ``exec``
        # in POSIX shells reuses the calling shell's PID, so $$ is the PID
        # of the user command itself once exec runs.
        wrapped_shell = (
            f"echo $$ > {shlex.quote(pid_file)}; "
            f"exec sh -c {shlex.quote(f'{joined} >>{shlex.quote(container_stdout)} 2>>{shlex.quote(container_stderr)}')}"
        )
        dtach_argv = [
            "docker",
            "exec",
            "-d",
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
            {
                "status": "running",
                "dtach_socket_path": socket_path,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
        return updated
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
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", pid_file],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = (result.stdout or "").strip().splitlines()
    if not raw:
        return None
    try:
        return int(raw[0])
    except ValueError:
        return None


def _job_pid_alive(container_name: str, pid: int) -> bool:
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "kill", "-0", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


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
) -> bool:
    """Poll ``kill -0 pid`` inside the container until the PID is gone or the
    deadline passes. Returns True if the process is confirmed dead."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        if not _job_pid_alive(container_name, pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)


def job_stop(
    job_id: int,
    *,
    container_name: str = _DEFAULT_CONTAINER_NAME,
    config: Config | None = None,
) -> dict[str, Any]:
    cfg = config or load_config(None)
    record = job_status(job_id, config=cfg)
    socket_path = record.get("dtach_socket_path") or ""
    if not socket_path:
        raise AssessError(f"job {job_id} has no dtach_socket_path recorded; cannot stop")

    # Derive the pid-file path from the socket: both share the job_uuid stem.
    sock = Path(socket_path)
    job_uuid_stem = sock.stem  # `<uuid>` from `<uuid>.sock`
    pid_file = _job_pid_file(job_uuid_stem)

    confirmed_dead = False
    final_status = "killed"
    if _container_running(container_name):
        pid = _read_job_pid(container_name, pid_file)
        if pid is None:
            # No pid file → fall back to the dtach Ctrl-C path so trapped
            # foreground tools at least get a SIGINT.
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
            confirmed_dead = True  # best-effort: we can't verify without a PID
        else:
            _signal_job_pid(container_name, pid, "TERM")
            confirmed_dead = _wait_for_pid_exit(container_name, pid, timeout_seconds=10.0)
            if not confirmed_dead:
                _signal_job_pid(container_name, pid, "KILL")
                confirmed_dead = _wait_for_pid_exit(container_name, pid, timeout_seconds=5.0)
            if not confirmed_dead:
                final_status = "stop_failed"

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        record_out = client.patch(f"jobs/{int(job_id)}", {"status": final_status})
    finally:
        client.close()
    if final_status == "stop_failed":
        raise AssessError(
            f"job {job_id}: SIGTERM + SIGKILL both failed to terminate the in-container "
            "process; status=stop_failed recorded. Investigate the runtime."
        )
    return record_out
