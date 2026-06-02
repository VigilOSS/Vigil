"""Docker-exec wrapping and two-namespace kill cascade for kali runs.

Owns the side-effect-heavy plumbing that sits between the host helper and
the runtime container: building the wrapper shell that records the in-
container PID, reading that PID back through ``docker exec``, and exact-PID
cleanup that has to cross the PID namespace boundary on timeout. The
host-side ``os.killpg`` cascade in the orchestrator complements these
helpers when the PID file is unavailable.
"""
from __future__ import annotations

import subprocess

from .client import AssessError, default_runtime_container


_DEFAULT_CONTAINER_NAME = default_runtime_container()


def _container_pid_file(run_uuid: str) -> str:
    """Path inside the container where the wrapper shell records the user
    command's PID. Sharing the engagement-wide ``run_uuid`` here means the
    audit row and this pid file key on the same identifier — the operator
    can grep one ID across both."""
    return f"/tmp/vigil-pid-{run_uuid}.pid"


def _build_docker_exec(
    cmd: list[str],
    *,
    container_name: str,
    run_uuid: str,
    working_dir: str | None = None,
    engagement_key: str | None = None,
) -> list[str]:
    """Wrap the user command in a tiny shell that records the in-container
    PID before ``exec``-ing the real command.

    The captured PID is the user command's PID because ``exec`` in POSIX
    shells reuses the calling shell's PID when replacing the process image.
    On wall-clock timeout the host helper reads this file via ``docker exec
    cat`` and issues ``docker exec kill -TERM/-KILL`` against the captured
    PID — that crosses the PID namespace boundary that ``os.killpg`` cannot.
    Without this, tools that trap SIGTERM (sqlmap, nuclei) survive the
    host-side process-group kill because they never see a signal."""
    pid_file = _container_pid_file(run_uuid)
    # Two-prong wrapper: try to record the in-container PID for the timeout
    # cascade, but never let a pid-write failure (ENOSPC, read-only /tmp,
    # missing dir) stop the user command from running. If the write fails,
    # surface the reason on stderr so orphan analysis isn't a silent guess.
    #
    # B1 race fix: ``sync`` after the pid-file write forces the kernel to flush
    # the file's directory entry before ``exec`` swaps the shell out. Without
    # the sync, the host helper's ``docker exec cat <pid_file>`` can race and
    # see an empty file even though the in-container process is alive — the
    # wrapper has written the bytes but the dirent has not been published yet.
    # ``sync`` here is cheap (one page-cache flush against a 6-byte file) and
    # eliminates the race deterministically; the alternative ``fsync`` is not
    # available without a Python helper and POSIX ``sh`` cannot fsync an FD
    # opened by ``>``. We do not gate the ``exec`` on sync's exit because
    # ``sync`` cannot fail in any way that should block the user command.
    tail = 'exec "$@"'
    wrapper = (
        f'echo $$ > {pid_file} && sync && {tail} || '
        f'(echo "vigil: PID write to {pid_file} failed (errno=$?); proceeding without pid-file" >&2; {tail})'
    )
    docker_argv = [
        "docker",
        "exec",
    ]
    # Surface ENGAGEMENT_KEY inside the runtime so skill examples like
    # `nuclei -l /engagements/$ENGAGEMENT_KEY/scans/...` expand correctly
    # under the wrapper shell. Without this, the variable expanded to the
    # empty string and output landed at `/engagements//scans/...`.
    if engagement_key:
        docker_argv.extend(["--env", f"ENGAGEMENT_KEY={engagement_key}"])
    if working_dir:
        docker_argv.extend(["-w", working_dir])
    docker_argv.extend(
        [
            container_name,
            "sh",
            "-c",
            wrapper,
            "sh",
            *cmd,
        ]
    )
    return docker_argv


def _read_container_pid(container_name: str, run_uuid: str) -> int | None:
    """Best-effort fetch of the wrapper-recorded PID from inside the container.
    Returns ``None`` for any failure mode — empty file, container gone, race
    where the wrapper exec'd but hadn't yet written the file. Callers should
    fall back to host-side ``os.killpg`` when this returns ``None``."""
    pid_file = _container_pid_file(run_uuid)
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


def _kill_in_container(container_name: str, pid: int, signal_name: str) -> None:
    """Issue ``docker exec kill`` against the captured in-container PID. All
    failure modes are swallowed: the process may have already exited, the
    container may be gone, docker may not be reachable. Caller still has the
    host-side process-group kill as belt-and-braces."""
    try:
        subprocess.run(
            ["docker", "exec", container_name, "kill", f"-{signal_name}", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _cleanup_container_pid_file(container_name: str, run_uuid: str) -> None:
    pid_file = _container_pid_file(run_uuid)
    try:
        subprocess.run(
            ["docker", "exec", container_name, "rm", "-f", pid_file],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _check_container_running(container_name: str) -> None:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container_name}$"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise AssessError(f"docker not reachable: {exc}") from exc
    if result.returncode != 0:
        raise AssessError(f"docker ps failed: {result.stderr.strip() or result.stdout.strip()}")
    if container_name not in (result.stdout or "").splitlines():
        raise AssessError(
            f"runtime container '{container_name}' is not running. "
            "Run `vigil runtime start` first."
        )
