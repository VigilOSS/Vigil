from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .paths import container_host_url, resolve_orchestrator_base_url


@dataclass(frozen=True, slots=True)
class MitmproxyOptions:
    install_root: Path
    engagement_dir: Path
    mode: str = "docker"
    port: int = 8080
    image: str = "security-research-proxy:latest"
    container_name: str = "security-research-proxy"
    volume_name: str = "mitmproxy-ca"


def start_proxy(options: MitmproxyOptions, *, runner: docker.Runner = docker.run_command, verify_port: bool = True) -> None:
    if options.mode != "docker":
        raise SystemExit("Only Docker mitmproxy mode is managed by the CLI. Use host mitmproxy directly for --host workflows.")
    install_root = options.install_root.expanduser().resolve()
    engagement_dir = options.engagement_dir.expanduser().resolve()
    if not (engagement_dir / "scope.json").exists():
        raise SystemExit(f"Not an engagement directory: {engagement_dir}")

    if not docker.image_exists(options.image, runner=runner):
        dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
        argv = ["docker", "build", "-t", options.image, "-f", str(dockerfile), str(install_root / "agent")]
        docker.require_success(runner(argv), argv)

    if docker.container_running(options.container_name, runner=runner):
        runner(["docker", "stop", options.container_name])
    if docker.container_exists(options.container_name, runner=runner):
        runner(["docker", "rm", options.container_name])

    runner(["docker", "volume", "create", options.volume_name])
    base_url = container_host_url(resolve_orchestrator_base_url(install_root, engagement_dir))
    argv = [
        "docker",
        "run",
        "-d",
        "--name",
        options.container_name,
        docker.HOST_GATEWAY_ARG,
        "-p",
        f"127.0.0.1:{options.port}:8080",
        "-v",
        f"{engagement_dir}:/engagement",
        "-v",
        f"{options.volume_name}:/root/.mitmproxy",
        "-e",
        f"ORCHESTRATOR_BASE_URL={base_url}",
        "-e",
        f"ENGAGEMENT_KEY={engagement_dir.name}",
        options.image,
        "--set",
        "engagement_dir=/engagement",
        "--set",
        "block_global=false",
    ]
    docker.run_with_host_gateway_fallback(argv, runner=runner)
    if verify_port and not _port_open("127.0.0.1", options.port):
        raise SystemExit(f"mitmproxy container started but port {options.port} is not reachable on 127.0.0.1")


def stop_proxy(container_name: str = "security-research-proxy", *, runner: docker.Runner = docker.run_command) -> None:
    if docker.container_exists(container_name, runner=runner):
        runner(["docker", "rm", "-f", container_name])


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False
