from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .paths import container_host_url, resolve_orchestrator_base_url


@dataclass(frozen=True, slots=True)
class RuntimeOptions:
    install_root: Path
    image: str = "security-research:latest"
    container_name: str = "security-research"
    recreate: bool = False


def build_runtime(install_root: Path, *, variant: str = "full", dev: bool = False, runner: docker.Runner = docker.run_command) -> None:
    if variant == "lightweight" and not dev:
        raise SystemExit("The lightweight runtime is development-only. Re-run with --dev to build it.")
    dockerfile = install_root / "agent" / "docker" / ("runtime-lightweight" if variant == "lightweight" else "runtime-full") / "Dockerfile"
    image = "security-research-lightweight:latest" if variant == "lightweight" else "security-research:latest"
    argv = ["docker", "build", "-t", image, "-f", str(dockerfile), str(install_root)]
    docker.require_success(runner(argv), argv)


def start_runtime(options: RuntimeOptions, *, runner: docker.Runner = docker.run_command, validate_tools: bool = True) -> None:
    install_root = options.install_root.expanduser().resolve()
    data_dir = Path(os.environ.get("KALI_MCP_DATA_DIR", install_root / ".runtime-data"))
    engagements_dir = install_root / "agent" / "engagements"
    data_dir.mkdir(parents=True, exist_ok=True)
    engagements_dir.mkdir(parents=True, exist_ok=True)

    if not docker.image_exists(options.image, runner=runner):
        raise SystemExit(f"Missing runtime image: {options.image}. Run `aith runtime build` first.")

    if docker.container_running(options.container_name, runner=runner) and not options.recreate:
        _validate_image_current(options, runner=runner)
        _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
        if validate_tools:
            _validate_tools(options.container_name, runner=runner)
        return

    if docker.container_exists(options.container_name, runner=runner):
        runner(["docker", "rm", "-f", options.container_name])

    env_file = install_root / ".env"
    base_url = container_host_url(resolve_orchestrator_base_url(install_root))
    argv = [
        "docker",
        "run",
        "-d",
        "--name",
        options.container_name,
        "--restart",
        "unless-stopped",
        "--cap-add=NET_RAW",
        "--cap-add=NET_ADMIN",
        "-v",
        f"{data_dir}:/data",
        "-v",
        f"{engagements_dir}:/engagements",
        docker.HOST_GATEWAY_ARG,
    ]
    if env_file.exists():
        argv.extend(["--env-file", str(env_file)])
    argv.extend(["-e", f"ORCHESTRATOR_BASE_URL={base_url}", options.image])
    docker.run_with_host_gateway_fallback(argv, runner=runner)
    _validate_image_current(options, runner=runner)
    _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
    if validate_tools:
        _validate_tools(options.container_name, runner=runner)


def stop_runtime(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> None:
    if docker.container_exists(container_name, runner=runner):
        runner(["docker", "rm", "-f", container_name])


def runtime_status(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> str:
    return "running" if docker.container_running(container_name, runner=runner) else "stopped"


def runtime_mounts_ok(install_root: Path, container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> bool:
    install_root = install_root.expanduser().resolve()
    data_dir = Path(os.environ.get("KALI_MCP_DATA_DIR", install_root / ".runtime-data"))
    engagements_dir = install_root / "agent" / "engagements"
    try:
        _validate_mounts(container_name, data_dir, engagements_dir, runner=runner)
    except SystemExit:
        return False
    return True


def _validate_image_current(options: RuntimeOptions, *, runner: docker.Runner) -> None:
    container_id = docker.container_image_id(options.container_name, runner=runner)
    configured_id = docker.image_id(options.image, runner=runner)
    if container_id and configured_id and container_id != configured_id:
        raise SystemExit(
            "Runtime container image drift detected. Recreate with `aith runtime restart`."
        )


def _validate_tools(container_name: str, *, runner: docker.Runner) -> None:
    required_tools = ["mcp-server", "ping", "katana", "gau", "nuclei", "httpx", "trufflehog", "gf", "uro"]
    for tool in required_tools:
        result = runner(["docker", "exec", container_name, "sh", "-lc", f"command -v '{tool}' >/dev/null"])
        if result.returncode != 0:
            raise SystemExit(f"Runtime tool validation failed; missing {tool}")
    result = runner(["docker", "exec", container_name, "test", "-d", "/engagements"])
    if result.returncode != 0:
        raise SystemExit("Runtime /engagements mount missing. Recreate with `aith runtime restart`.")


def _validate_mounts(container_name: str, data_dir: Path, engagements_dir: Path, *, runner: docker.Runner) -> None:
    mounts = docker.container_mounts(container_name, runner=runner)
    expected = {
        "/data": data_dir.expanduser().resolve(),
        "/engagements": engagements_dir.expanduser().resolve(),
    }
    for destination, expected_source in expected.items():
        actual_source = mounts.get(destination)
        if not actual_source:
            raise SystemExit(f"Runtime mount drift detected: missing {destination}. Recreate with `aith runtime restart`.")
        if Path(actual_source).expanduser().resolve() != expected_source:
            raise SystemExit(
                f"Runtime mount drift detected for {destination}: {actual_source} != {expected_source}. "
                "Recreate with `aith runtime restart`."
            )
