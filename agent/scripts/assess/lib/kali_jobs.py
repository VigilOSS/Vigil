"""Async-job helpers for `vigil assess kali job ...`.

Backed by the orchestrator backend's `assessment_jobs` table via
``AssessmentClient``. dtach is the supervisor inside the runtime container
— sessions parented by tini survive the calling shell.
"""
from __future__ import annotations

import datetime as _dt
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .client import AssessError, AssessmentClient, default_runtime_container
from .config import Config, load_config
from .kali_audit import _patch_finalize, _post_pre_exec_row, _resolve_engagement_dir
from .kali_output import _scope_version
from .execution_recency import emit_foreign_lane_recency
from .kali_tool_naming import _derive_tool_name
from .kali_runtime_exec import (
    _cat_container_pid_file,
    _container_running,
    _engagement_env_args,
    _env_args,
)

_DEFAULT_DTACH_DIR = "/tmp/vigil-jobs"
_JOB_PID_DIR = "/tmp/vigil-jobs"
_JOB_TERMINAL_STATUSES = {"completed", "failed", "killed", "lost"}
_JOB_IN_FLIGHT_STATUSES = ("running", "queued", "stop_failed")

# Grace between the deadline SIGTERM and the escalation SIGKILL in the async
# job watchdog. Mirrors the synchronous exec path's `process.wait(timeout=5)`
# window between SIGTERM and SIGKILL in kali.py, so both paths give a hung tool
# the same 5s to unwind on its own before being force-killed.
_JOB_KILL_GRACE_SECONDS = 5

# ``_container_running`` is imported at module level so tests can patch it via
# ``monkeypatch.setattr(kali_jobs, "_container_running", ...)``.



def _job_pid_file(job_uuid: str) -> str:
    return f"{_JOB_PID_DIR}/{job_uuid}.pid"


def _utcnow_iso() -> str:
    """UTC timestamp in the ``YYYY-MM-DDTHH:MM:SSZ`` shape the backend and the
    sweep-orphans reconciler both parse (see
    ``kali_sweep_orphans._parse_started_at``)."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exit_marker_host_path(record: dict[str, Any]) -> Path | None:
    """Host-side path of the job's exit-code marker, derived from the recorded
    ``stdout_path`` (``<dir>/<uuid>.out`` → ``<dir>/<uuid>.exit``). The marker
    lives under the ``/engagements`` bind mount, so it is the same inode the
    in-container wrapper writes — read it with a plain filesystem read, never a
    ``docker exec cat`` poll loop (I-012, docker-desktop-network-hazards.md)."""
    stdout_path = record.get("stdout_path")
    if not stdout_path:
        return None
    return Path(str(stdout_path)).with_suffix(".exit")


def _read_exit_marker(record: dict[str, Any]) -> int | None:
    """Return the integer exit code the in-container wrapper published on
    completion, or None when the marker is absent/empty/unparseable (the job is
    still running, or it was killed before it could publish)."""
    marker = _exit_marker_host_path(record)
    if marker is None:
        return None
    try:
        text = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _read_job_preview(path_value: Any, *, limit: int = 16_384) -> str:
    if not path_value:
        return ""
    try:
        data = Path(str(path_value)).read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


def _job_duration_ms(record: dict[str, Any], ended_at_iso: str) -> int:
    started_raw = str(record.get("started_at") or "").strip()
    if not started_raw:
        return 0
    try:
        started = _dt.datetime.fromisoformat(started_raw.replace("Z", "+00:00"))
        ended = _dt.datetime.fromisoformat(ended_at_iso.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((ended - started).total_seconds() * 1000))


def finalize_parent_command_run(
    client: AssessmentClient,
    record: dict[str, Any],
    *,
    status_value: str,
    return_code: int | None,
    ended_at_iso: str | None = None,
    run_uuid: str | None = None,
) -> None:
    """Converge the command-run paired with a terminal async job.

    Command-run finalization is idempotent through ``accept_409``. A failed
    patch is left for a later status/list/sweep reconciliation rather than
    changing the already-observed job outcome.
    """
    parent_id = record.get("parent_command_run_id")
    if parent_id is None or status_value not in _JOB_TERMINAL_STATUSES:
        return
    resolved_run_uuid = str(run_uuid or "").strip()
    if not resolved_run_uuid:
        output_path = str(record.get("stdout_path") or "").strip()
        resolved_run_uuid = Path(output_path).stem if output_path else ""
    if not resolved_run_uuid:
        print(
            f"warning: could not finalize parent command run id={parent_id}: "
            "job record has neither run_uuid nor stdout_path",
            file=sys.stderr,
        )
        return
    ended = ended_at_iso or str(record.get("ended_at") or "").strip() or _utcnow_iso()
    stdout_preview = _read_job_preview(record.get("stdout_path"))
    stderr_preview = _read_job_preview(record.get("stderr_path"))
    try:
        _patch_finalize(
            client,
            run_id=int(parent_id),
            run_uuid=resolved_run_uuid,
            status=status_value,
            return_code=return_code,
            ended_at_iso=ended,
            duration_ms=_job_duration_ms(record, ended),
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            timed_out=False,
            partial_results=bool(stdout_preview or stderr_preview)
            and status_value != "completed",
            peak_rss_bytes=None,
            cpu_user_seconds=None,
            cpu_system_seconds=None,
            # Same host paths the paired command-run row was opened with
            # (``start_job`` writes one ``_job_paths`` pair to both rows), so
            # the audit row records the byte count and digest of the spill it
            # names rather than keeping the pre-exec placeholders. The previews
            # read above are head+tail truncations and cannot supply them.
            stdout_path=record.get("stdout_path"),
            stderr_path=record.get("stderr_path"),
        )
    except AssessError:
        return


def _finalize_if_marker_present(
    client: AssessmentClient, record: dict[str, Any]
) -> dict[str, Any]:
    """Lazily finalize a non-terminal job row when its exit marker is present.

    The dtach worker is detached (``dtach -n``) so nothing watches it exit; the
    wrapper instead publishes the real exit code to a host-readable marker. Any
    host-side reader (``job_status`` / ``job_list`` / the sweeper) converges the
    backend row by reading that marker. ``accept_409`` tolerates a racing
    finalizer; a failing PATCH falls back to the unfinalized record."""
    status_val = str(record.get("status") or "").strip()
    if status_val in _JOB_TERMINAL_STATUSES:
        finalize_parent_command_run(
            client,
            record,
            status_value=status_val,
            return_code=record.get("exit_code"),
        )
        return record
    rc = _read_exit_marker(record)
    if rc is None:
        return record
    job_id = record.get("id")
    if job_id is None:
        return record
    final_status = "completed" if rc == 0 else "failed"
    try:
        finalized = client.patch(
            f"jobs/{int(job_id)}",
            {"status": final_status, "exit_code": rc, "ended_at": _utcnow_iso()},
            accept_409=True,
        )
        finalize_parent_command_run(
            client,
            record,
            status_value=final_status,
            return_code=rc,
            ended_at_iso=str(finalized.get("ended_at") or "") or None,
        )
        return finalized
    except AssessError:
        return record


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


def _coerce_timeout_budget(value: Any) -> int | None:
    """Return a positive integer second-budget, or ``None`` when the caller did
    not request a deadline (or requested a non-positive / unparseable value — in
    which case the wrapper omits the watchdog rather than arming a zero/negative
    deadline that would kill the tool immediately)."""
    if value is None:
        return None
    try:
        budget = int(value)
    except (TypeError, ValueError):
        return None
    return budget if budget > 0 else None


def _deadline_watchdog(budget_seconds: int) -> str:
    """Background poll-loop watchdog shell that enforces a hard deadline on the
    in-container TOOL pid (``$__child``).

    Mirrors the synchronous exec path's cascade (kali.py): once ``budget_seconds``
    elapse, SIGTERM the tool, then SIGKILL after ``_JOB_KILL_GRACE_SECONDS`` if it
    ignored the term. Liveness is polled in 1s ticks so the watchdog exits the
    instant the tool finishes on its own — no long ``sleep`` lingers after a
    natural exit — and each signal is gated on a fresh ``kill -0`` so a tool that
    dies in the poll window is never signalled at a pid the kernel has recycled.
    It signals exactly ``$__child`` (the recorded tool pid), the same exact-PID
    target ``job_stop`` uses, so the deadline kill and an operator stop converge
    on identical semantics. ``$__watch`` records the watchdog pid so the wrapper
    can reap it once the tool is gone."""
    grace = _JOB_KILL_GRACE_SECONDS
    return (
        "( __i=0; "
        f'while [ "$__i" -lt {int(budget_seconds)} ]; do '
        'kill -0 "$__child" 2>/dev/null || exit 0; sleep 1; __i=$((__i+1)); done; '
        'kill -0 "$__child" 2>/dev/null && kill -TERM "$__child" 2>/dev/null; '
        "__i=0; "
        f'while [ "$__i" -lt {int(grace)} ]; do '
        'kill -0 "$__child" 2>/dev/null || exit 0; sleep 1; __i=$((__i+1)); done; '
        'kill -0 "$__child" 2>/dev/null && kill -KILL "$__child" 2>/dev/null '
        ") & __watch=$!;"
    )


def _build_job_wrapper(
    joined: str,
    *,
    pid_file: str,
    stdout_path: str,
    stderr_path: str,
    exit_path: str,
    timeout_seconds: int | None = None,
) -> str:
    """Build the dtach worker shell.

    The tool runs as ``sh -c 'exec <joined> >redirs' &`` — the inner sh sets up
    the redirections and then ``exec``-replaces itself with the tool, so the PID
    captured via ``$!`` IS the tool's PID. This is load-bearing: ``job_stop`` and
    any reaper send their signal to exactly this recorded PID, so it MUST be the
    tool or the tool is orphaned while an idle wrapper is killed (QA finding B1).
    Without ``exec`` the inline redirections defeat the shell's exec-in-place
    optimization and ``$!`` is the wrapper sh, not the tool — verified on dash.

    The wrapper then OUTLIVES the tool to ``wait`` for its real exit status — the
    only place a detached (``dtach -n``) job's exit code is observable — and
    publishes it atomically (``.tmp`` + ``mv``) to a host-readable marker on the
    ``/engagements`` bind mount, so a host-side reader (job_status / sweep) can
    finalize the backend row with a plain filesystem read, never a docker-exec
    poll loop (I-012). A kill is observed as a 128+signal wait status (SIGTERM=143
    / SIGKILL=137); job_stop treats rc>=128 as 'killed', rc<128 as a natural exit.

    When ``timeout_seconds`` is a positive budget the wrapper also arms a hard-
    deadline watchdog (the in-container analogue of the sync path's ``--timeout``
    SIGTERM→SIGKILL cascade): the watchdog SIGTERMs the tool pid at the budget and
    escalates to SIGKILL after the grace, so a hung run (e.g. nuclei stuck on
    template load, 0-byte output for hours) is killed AT the deadline and self-
    finalizes via the marker (the kill wait-status, which the lazy finalizer maps
    to ``failed``) instead of surviving until a manual sweep-orphans (I-19). The
    marker is published BEFORE the watchdog is reaped so the disposition lands
    promptly; the trailing ``wait`` then reaps the watchdog so it never lingers.

    stdin is redirected from /dev/null — the in-container analogue of the sync
    exec path's ``stdin=subprocess.DEVNULL``: PD tools (httpx/katana/nuclei/dnsx/
    naabu) block on a non-EOF stdin when fd 0 is not a TTY, hanging at 0% CPU even
    with ``-l <file>``. ``</dev/null`` is tool-agnostic and harmless to a flag-fed
    tool.
    """
    inner = (
        f"exec {joined} >>{shlex.quote(stdout_path)} "
        f"2>>{shlex.quote(stderr_path)} </dev/null"
    )
    exit_tmp = f"{exit_path}.tmp"
    publish = (
        f"printf '%s' \"$__rc\" > {shlex.quote(exit_tmp)} "
        f"&& mv -f {shlex.quote(exit_tmp)} {shlex.quote(exit_path)}"
    )
    spawn = (
        f"sh -c {shlex.quote(inner)} & "
        f"__child=$!; echo \"$__child\" > {shlex.quote(pid_file)}; "
    )
    budget = _coerce_timeout_budget(timeout_seconds)
    if budget is None:
        return f"{spawn}wait \"$__child\"; __rc=$?; {publish}"
    return (
        f"{spawn}{_deadline_watchdog(budget)} "
        f"wait \"$__child\"; __rc=$?; "
        f"{publish}; wait \"$__watch\" 2>/dev/null"
    )


def start_job(
    cmd: list[str],
    *,
    audit_meta: dict[str, Any],
    engagement_dir: Path | None = None,
    container_name: str | None = None,
    dtach_socket_dir: str = _DEFAULT_DTACH_DIR,
    parent_command_run_id: int | None = None,
    execution_policy: dict[str, Any] | None = None,
    tool_name: str | None = None,
    config: Config | None = None,
    env_pairs=None,
) -> dict[str, Any]:
    """Pre-audit the command, POST its linked job, then spawn and mark running.

    Returns the backend job record (with `dtach_socket_path` populated).
    """
    if parent_command_run_id is not None:
        raise AssessError(
            "parent_command_run_id is system-owned for async jobs; callers must not supply it"
        )

    # Resolve the container name at call time so VIGIL_RUNTIME_CONTAINER is read
    # now, not when this module was imported. Default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = _resolve_engagement_dir(engagement_dir, cfg)
    eng_key = eng_dir.name
    job_uuid = uuid.uuid4().hex
    socket_path = f"{dtach_socket_dir}/{job_uuid}.sock"
    pid_file = _job_pid_file(job_uuid)
    stdout_path, stderr_path = _job_paths(eng_dir, job_uuid)

    client = AssessmentClient(cfg.base_url, eng_key)
    spawned = False
    job_id: int | None = None
    command_run_id: int | None = None
    try:
        command_row = _post_pre_exec_row(
            client,
            cmd=cmd,
            technique=str(audit_meta.get("technique") or "RECON"),
            intent=str(audit_meta.get("intent") or "async job"),
            probe_kind=str(audit_meta.get("probe_kind") or "fingerprint"),
            phase=str(audit_meta.get("phase") or "recon"),
            destructive=bool(audit_meta.get("destructive")),
            agent_name=str(audit_meta.get("agent_name") or "operator"),
            engagement_dir=eng_dir,
            container_name=container_name,
            timeout=int(audit_meta.get("timeout_seconds_requested") or 0),
            force=False,
            started_at_iso=_utcnow_iso(),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            working_dir=f"/engagements/{eng_key}",
            scope_version=str(audit_meta.get("scope_version") or _scope_version(eng_dir)),
            auth_context=str(audit_meta.get("auth_context") or "anonymous"),
            tool_name=tool_name or _derive_tool_name(cmd),
            run_uuid=job_uuid,
            execution_policy=execution_policy,
        )
        command_run_id = int(command_row["id"])
        if (execution_policy or {}).get("target_facing"):
            emit_foreign_lane_recency(
                client,
                current_agent=str(audit_meta.get("agent_name") or "operator"),
            )

        if not _container_running(container_name):
            raise AssessError(
                f"runtime container '{container_name}' is not running. "
                "Run `vigil runtime start` first."
            )
        _check_dtach_in_container(container_name)
        _ensure_dtach_dir(container_name, dtach_socket_dir)

        created = client.post(
            "jobs",
            {
                "parent_command_run_id": command_run_id,
                "status": "queued",
                "audit_metadata": audit_meta,
            },
        )
        job_id = int(created["id"])

        # Translate host-side stdout paths into container paths via the
        # /engagements bind mount: ${ENGAGEMENT_DIR} is mounted at
        # /engagements/${ENGAGEMENT_KEY} inside the runtime.
        container_stdout = (
            f"/engagements/{eng_key}/scans/kali/jobs/{stdout_path.name}"
        )
        container_stderr = (
            f"/engagements/{eng_key}/scans/kali/jobs/{stderr_path.name}"
        )
        container_exit = (
            f"/engagements/{eng_key}/scans/kali/jobs/{job_uuid}.exit"
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
        wrapped_shell = _build_job_wrapper(
            joined,
            pid_file=pid_file,
            stdout_path=container_stdout,
            stderr_path=container_stderr,
            exit_path=container_exit,
            # Hard deadline for the async run, sized from the operator's
            # --timeout (carried in audit_metadata by `kali job start`). Without
            # this the dtach worker had no deadline and a hung tool survived
            # until a manual sweep-orphans (I-19).
            timeout_seconds=audit_meta.get("timeout_seconds_requested"),
        )
        # ENGAGEMENT_KEY env mirrors the sync exec path in
        # ``kali_runtime_exec._build_docker_exec`` (shared via
        # ``_engagement_env_args`` so the two cannot drift) so skill commands
        # launched as background jobs see ``$ENGAGEMENT_KEY`` expand to the
        # engagement name rather than the empty string.
        dtach_argv = [
            "docker",
            "exec",
            "-d",
            *_engagement_env_args(eng_key),
            # --identity-env material, carried into the dtach worker exactly as
            # the sync lane carries it (shared _env_args, so the two cannot drift).
            *_env_args(env_pairs or []),
            "-w",
            f"/engagements/{eng_key}",
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
            {"status": "running", "started_at": _utcnow_iso()},
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
        if command_run_id is not None:
            finalize_parent_command_run(
                client,
                {
                    "parent_command_run_id": command_run_id,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                },
                status_value="failed",
                return_code=None,
            )
        raise
    finally:
        client.close()


def job_status(job_id: int, *, config: Config | None = None) -> dict[str, Any]:
    cfg = config or load_config(None)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        record = client.get(f"jobs/{int(job_id)}")
        return _finalize_if_marker_present(client, record)
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
        if not isinstance(rows, list):
            return []
        # Lazy-finalize any non-terminal row whose exit marker is now present
        # (same convergence as job_status), so `job list` reflects completed
        # jobs without requiring a separate reconcile pass.
        return [_finalize_if_marker_present(client, row) for row in rows]
    finally:
        client.close()


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
    final_exit_code: int | None = None
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
                # PID gone. The wrapper publishes the tool's wait()-status as the
                # marker. A natural exit (rc < 128) means the tool finished on its
                # own in the kill window — record its real code. A 128+signal
                # status (rc >= 128: our SIGTERM=143 / SIGKILL=137) means WE
                # terminated it → 'killed'. No marker yet (we won the race) → also
                # 'killed'.
                rc = _read_exit_marker(record)
                if rc is not None and rc < 128:
                    final_status = "completed" if rc == 0 else "failed"
                    final_exit_code = rc
                else:
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

    patch_payload: dict[str, Any] = {"status": final_status}
    if final_exit_code is not None:
        patch_payload["exit_code"] = final_exit_code
    # Stamp ended_at on any confirmed terminal outcome. stop_failed is excluded:
    # the process may still be alive, so an ended_at would be misleading.
    if final_status in {"completed", "failed", "killed", "lost"}:
        patch_payload["ended_at"] = _utcnow_iso()
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        # accept_409 tolerates a concurrent finalizer (job_status/sweeper) that
        # converged the row via the marker during the kill window — we then
        # return the existing terminal record rather than raising a false error.
        record_out = client.patch(f"jobs/{int(job_id)}", patch_payload, accept_409=True)
        if final_status != "stop_failed":
            finalize_parent_command_run(
                client,
                record,
                status_value=final_status,
                return_code=final_exit_code,
                ended_at_iso=str(record_out.get("ended_at") or "") or None,
            )
    finally:
        client.close()
    if final_status == "stop_failed":
        raise AssessError(failure_message or f"job {job_id}: stop failed")
    return record_out


def reap_jobs(
    *,
    container_name: str | None = None,
    config: Config | None = None,
) -> dict[str, Any]:
    """Stop every in-flight (running/queued) job for the engagement.

    The operator-explicit reap after an agent dies leaving dtach jobs alive:
    it walks the in-flight rows and runs the same PID-targeted, marker-aware
    ``job_stop`` on each — so a job that already finished finalizes
    ``completed`` rather than ``killed``. Per-job failures are classified, not
    fatal, so one wedged job never aborts the whole reap. Returns an
    outcome summary keyed by disposition."""
    container_name = container_name or default_runtime_container()
    cfg = config or load_config(None)

    in_flight: list[dict[str, Any]] = []
    seen: set[int] = set()
    for state in _JOB_IN_FLIGHT_STATUSES:
        for row in job_list(status_value=state, config=cfg):
            jid = row.get("id")
            if jid is None:
                continue
            jid = int(jid)
            if jid in seen:
                continue
            seen.add(jid)
            in_flight.append(row)

    results: dict[str, list[dict[str, Any]]] = {
        "stopped": [],
        "already_terminal": [],
        "failed": [],
    }
    for row in in_flight:
        jid = int(row["id"])
        # job_list lazy-finalizes via the exit marker, so a row returned here
        # may already be terminal (it completed before the agent died). Skip the
        # stop attempt for those — they are already reconciled.
        if str(row.get("status") or "").strip() in _JOB_TERMINAL_STATUSES:
            results["already_terminal"].append({"id": jid, "status": row.get("status")})
            continue
        try:
            out = job_stop(jid, container_name=container_name, config=cfg)
            results["stopped"].append({"id": jid, "status": out.get("status")})
        except AssessError as exc:
            msg = str(exc)
            if "already terminal" in msg:
                results["already_terminal"].append({"id": jid, "error": msg})
            else:
                results["failed"].append({"id": jid, "error": msg})
        except Exception as exc:  # noqa: BLE001 — one wedged job must not abort the reap
            results["failed"].append({"id": jid, "error": f"{type(exc).__name__}: {exc}"})
    return results
