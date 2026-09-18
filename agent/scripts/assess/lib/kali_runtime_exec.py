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

from .client import AssessError


def _container_pid_file(run_uuid: str) -> str:
    """Path inside the container where the wrapper shell records the user
    command's PID. Sharing the engagement-wide ``run_uuid`` here means the
    audit row and this pid file key on the same identifier — the operator
    can grep one ID across both.

    Canonical home for the pid-file path formula — ``kali_jobs`` and
    ``kali_sweep_orphans`` import this rather than re-deriving the literal."""
    return f"/tmp/vigil-pid-{run_uuid}.pid"


def _docker_ps_names_filter_argv(container_name: str) -> list[str]:
    """Canonical ``docker ps`` exact-name filter argv.

    Single source of truth for the ``--filter name=^<name>$`` idiom shared by
    the raising :func:`_check_container_running` and the boolean
    :func:`_container_running`. Returning the argv (not running it) lets each
    caller keep its own error handling — raise vs bool — without duplicating
    the literal command."""
    return ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container_name}$"]


def _container_running(container_name: str) -> bool:
    """Boolean liveness check: True iff the exact-named container is in
    ``docker ps`` output. Swallows docker-unreachable as ``False`` (callers
    that need to distinguish unreachable from absent use
    :func:`_check_container_running`, which raises)."""
    try:
        result = subprocess.run(
            _docker_ps_names_filter_argv(container_name),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return container_name in (result.stdout or "").splitlines()


def _cat_container_pid_file(container_name: str, pid_file: str) -> tuple[int | None, str]:
    """Core ``docker exec cat <pid_file>`` reader shared by every pid-read
    helper. Returns ``(pid, reason)`` where ``pid`` is ``None`` for any failure
    mode and ``reason`` is a stable diagnostic tag:

    - ``pid-probe-failed:<ExcName>`` — docker unreachable (FileNotFound/Timeout)
    - ``pid-file-missing``           — rc!=0 and stderr names a missing file
    - ``pid-probe-failed``           — rc!=0 for any other reason
    - ``pid-file-empty``             — file read but empty
    - ``pid-file-invalid``           — contents not an int
    - ``pid-read``                   — success

    Callers that only need ``int | None`` take ``[0]``; ``kali_sweep_orphans``
    maps the full tuple into its ``_PidReadResult`` so its richer dry-run
    reason strings are preserved."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", pid_file],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return None, f"pid-probe-failed:{exc.__class__.__name__}"
    if result.returncode != 0:
        stderr = (result.stderr or "").lower()
        if "no such file" in stderr or "cannot open" in stderr:
            return None, "pid-file-missing"
        return None, "pid-probe-failed"
    raw = (result.stdout or "").strip().splitlines()
    if not raw:
        return None, "pid-file-empty"
    try:
        return int(raw[0]), "pid-read"
    except ValueError:
        return None, "pid-file-invalid"


def _env_args(pairs) -> list[str]:
    """``--env NAME=value`` docker-exec argument pairs, in the given order.

    Single source for the env mirror shared by the synchronous exec wrapper
    (:func:`_build_docker_exec`) and the async dtach job argv
    (``kali_jobs.start_job``) — CODE-MAP flags this as a deliberate coupling, so
    they must not drift. Anything routed through here reaches BOTH lanes for
    free, which is why identity material for script-driven runs is carried as
    env rather than as an argv rewrite: env crosses into a script FILE, where an
    appended ``-H`` would only become the script's ``$1``.

    Values are passed to ``docker exec`` as a single argv token, so no shell
    quoting is applied or needed — but a NAME containing ``=`` would silently
    truncate the value, so callers must validate names (see
    ``kali.resolve_identity_env``).
    """
    args: list[str] = []
    for name, value in pairs:
        if not name:
            continue
        args.extend(["--env", f"{name}={value}"])
    return args


def _engagement_env_args(engagement_key: str | None) -> list[str]:
    """Canonical ``--env ENGAGEMENT_KEY=<key>`` docker-exec argument pair.

    Surfacing ``ENGAGEMENT_KEY`` inside the runtime lets skill examples like
    ``nuclei -l /engagements/$ENGAGEMENT_KEY/scans/...`` expand to the engagement
    name rather than the empty string. Returns ``[]`` for an empty key so the
    sync path's prior ``if engagement_key`` guard is preserved verbatim."""
    if not engagement_key:
        return []
    return _env_args([("ENGAGEMENT_KEY", engagement_key)])


def _build_docker_exec(
    cmd: list[str],
    *,
    container_name: str,
    run_uuid: str,
    working_dir: str | None = None,
    engagement_key: str | None = None,
    env_pairs=None,
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
    # See _engagement_env_args: without this, output lands at
    # `/engagements//scans/...` instead of the engagement path.
    docker_argv.extend(_engagement_env_args(engagement_key))
    # Identity material for --identity-env, carried the one way that reaches a
    # shell SCRIPT FILE's own requests.
    docker_argv.extend(_env_args(env_pairs or []))
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
    return _cat_container_pid_file(container_name, _container_pid_file(run_uuid))[0]


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
            _docker_ps_names_filter_argv(container_name),
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
