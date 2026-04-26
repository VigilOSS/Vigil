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
import uuid
from pathlib import Path
from typing import Any

from .client import AssessError, AssessmentClient
from .config import Config, load_config


_DEFAULT_CONTAINER_NAME = "security-research"
_DEFAULT_DTACH_DIR = "/tmp/aith-jobs"


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
    cfg = config or load_config(None)
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
        wrapped_shell = f"{joined} >>{shlex.quote(container_stdout)} 2>>{shlex.quote(container_stderr)}"
        dtach_argv = [
            "docker",
            "exec",
            "-d",
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
    if _container_running(container_name):
        # Ctrl-C through dtach: \x03 = SIGINT to the foreground process.
        # Then send SIGTERM to the session leader as belt-and-braces.
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
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        return client.patch(f"jobs/{int(job_id)}", {"status": "killed"})
    finally:
        client.close()
