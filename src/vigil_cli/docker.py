from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True, slots=True)
class DockerResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[..., DockerResult]
HOST_GATEWAY_ARG = "--add-host=host.docker.internal:host-gateway"

# Metadata queries (image/container inspects, ``docker info``, ``docker ps``)
# and a DETACHED ``docker run -d`` start all return promptly against a healthy
# daemon. When the daemon/VM is wedged — a common Docker Desktop failure mode
# on macOS — an unbounded ``subprocess.run`` blocks forever, hanging ``vigil
# runtime start``/``status``, ``vigil up`` and ``vigil doctor`` with no output.
# Bounding every such call turns an unresponsive daemon into a clear error
# (I-02). Image BUILDS route through ``run_command_streaming`` (NO timeout) —
# a cold build legitimately runs for minutes — so this bound never touches them.
_DEFAULT_TIMEOUT_SECONDS = 20.0
# Distinct from Docker's own exit codes (125 run-failure / 126 not-executable /
# 127 not-found) and mirrors coreutils ``timeout(1)`` so callers can recognise a
# timeout specifically rather than confusing it with a real docker failure.
TIMEOUT_RETURNCODE = 124


def _resolve_timeout() -> float | None:
    """Per-call timeout (seconds) for fast Docker metadata queries.

    Overridable via ``VIGIL_DOCKER_TIMEOUT``. A value of ``0`` (or a negative /
    unparseable value) disables the bound entirely — the escape hatch for an
    operator on a slow box whose legitimate metadata query needs longer than the
    default. An unset/blank env var uses ``_DEFAULT_TIMEOUT_SECONDS``.
    """
    raw = os.environ.get("VIGIL_DOCKER_TIMEOUT")
    if raw is None or not raw.strip():
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return _DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else None


def run_command(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> DockerResult:
    timeout = _resolve_timeout()
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        return DockerResult(127, "", str(exc))
    except subprocess.TimeoutExpired:
        # Never surface a hang: a wedged daemon becomes a non-zero result that
        # every metadata helper already treats as "unavailable/empty", and that
        # callers can recognise as a timeout via ``TIMEOUT_RETURNCODE``.
        return DockerResult(
            TIMEOUT_RETURNCODE,
            "",
            f"docker command timed out after {timeout:g}s (daemon unresponsive?): {' '.join(argv)}",
        )
    return DockerResult(completed.returncode, completed.stdout, completed.stderr)


def run_command_streaming(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> DockerResult:
    """Run a command with stdout/stderr inherited so output streams to the terminal."""
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        return DockerResult(127, "", str(exc))
    return DockerResult(completed.returncode, "", "")


def require_success(result: DockerResult, argv: list[str]) -> None:
    if result.returncode != 0:
        command = " ".join(argv)
        raise SystemExit(f"Command failed ({result.returncode}): {command}\n{result.stderr or result.stdout}")


def run_with_host_gateway_fallback(argv: list[str], *, runner: Runner = run_command) -> None:
    result = runner(argv)
    if result.returncode == 0:
        return
    if HOST_GATEWAY_ARG in argv:
        retry_argv = [item for item in argv if item != HOST_GATEWAY_ARG]
        retry_result = runner(retry_argv)
        require_success(retry_result, retry_argv)
        return
    require_success(result, argv)


def image_exists(image: str, *, runner: Runner = run_command) -> bool:
    for argv in (
        ["docker", "image", "inspect", image],
        ["docker", "inspect", "--type", "image", image],
    ):
        if runner(argv).returncode == 0:
            return True
    result = runner(["docker", "images", "-q", image])
    return bool(result.stdout.strip())


def docker_info(*, runner: Runner = run_command) -> dict:
    """Return parsed ``docker info`` as a dict, or {} when unavailable/unparseable.

    On Docker Desktop (macOS/Windows) the ``MemTotal`` (bytes) and ``NCPU`` fields
    report the *VM's* capacity — the shared allocation the runtime actually
    competes for — which is the correct number for a shared-VM sizing preflight.
    """
    result = runner(["docker", "info", "--format", "{{json .}}"])
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def container_names(*, all_containers: bool = False, runner: Runner = run_command) -> set[str]:
    argv = ["docker", "ps"]
    if all_containers:
        argv.append("-a")
    argv.extend(["--format", "{{.Names}}"])
    result = runner(argv)
    if result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def container_running(name: str, *, runner: Runner = run_command) -> bool:
    return name in container_names(runner=runner)


def container_exists(name: str, *, runner: Runner = run_command) -> bool:
    return name in container_names(all_containers=True, runner=runner)


def image_id(image: str, *, runner: Runner = run_command) -> str:
    result = runner(["docker", "image", "inspect", "-f", "{{.Id}}", image])
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def container_image_id(name: str, *, runner: Runner = run_command) -> str:
    result = runner(["docker", "inspect", "-f", "{{.Image}}", name])
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


@dataclass(frozen=True, slots=True)
class DaemonStatus:
    """Health of the Docker daemon from a single ``docker info`` probe.

    ``responsive`` is True only when ``docker info`` returned rc=0. ``timed_out``
    separates a wedged/unresponsive daemon (our bounded ``run_command`` timeout
    fired) from a daemon that is simply not running or a missing CLI, so callers
    can print a targeted recovery hint. ``detail`` carries the probe's stderr for
    diagnostics (empty on the healthy path — ``docker info``'s success output is
    large and unused).
    """
    responsive: bool
    timed_out: bool
    detail: str


def daemon_status(*, runner: Runner = run_command) -> DaemonStatus:
    """Probe the daemon once and classify the result. Cheap enough to gate a
    ``runtime start`` / ``runtime status`` on, and bounded by ``run_command`` so
    it degrades instead of hanging when the daemon is unresponsive."""
    result = runner(["docker", "info"])
    if result.returncode == 0:
        return DaemonStatus(True, False, "")
    return DaemonStatus(
        False,
        result.returncode == TIMEOUT_RETURNCODE,
        (result.stderr or result.stdout or "").strip(),
    )


def daemon_available(*, runner: Runner = run_command) -> bool:
    return daemon_status(runner=runner).responsive


def require_daemon(operation: str, *, runner: Runner = run_command) -> None:
    """Fail with an actionable diagnostic before an unbounded Docker operation."""
    health = daemon_status(runner=runner)
    if health.responsive:
        return
    headline = (
        "Docker is not responding (the daemon/VM appears wedged)"
        if health.timed_out
        else "Docker does not appear to be running"
    )
    detail = f"\n  {health.detail}" if health.detail else ""
    raise SystemExit(
        f"{headline} — cannot {operation}.{detail}\n"
        "  Start or restart Docker (on macOS: launch Docker Desktop, or quit and reopen it "
        "if it is hung), then retry. Confirm with `docker info`.\n"
        "  Set VIGIL_DOCKER_TIMEOUT (seconds) if a slow-but-healthy daemon needs longer to respond."
    )


def container_mounts(name: str, *, runner: Runner = run_command) -> dict[str, str]:
    template = '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
    result = runner(["docker", "inspect", "-f", template, name])
    if result.returncode != 0:
        return {}
    mounts: dict[str, str] = {}
    for raw_line in result.stdout.splitlines():
        source, sep, destination = raw_line.partition(" -> ")
        if sep:
            mounts[destination.strip()] = source.strip()
    return mounts


def volume_exists(name: str, *, runner: Runner = run_command) -> bool:
    return runner(["docker", "volume", "inspect", name]).returncode == 0
