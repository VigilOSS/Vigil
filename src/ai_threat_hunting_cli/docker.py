from __future__ import annotations

import json
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


def run_command(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> DockerResult:
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return DockerResult(127, "", str(exc))
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


def daemon_available(*, runner: Runner = run_command) -> bool:
    return runner(["docker", "info"]).returncode == 0


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
