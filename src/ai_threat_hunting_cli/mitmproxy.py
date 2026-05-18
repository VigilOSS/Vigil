from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .paths import container_host_url, resolve_orchestrator_base_url

_PORT_WAIT_ATTEMPTS = 30
_PORT_WAIT_DELAY_SECONDS = 0.2

_CONTAINER_NAME = "security-research-proxy"
_RELOAD_SENTINEL = ".mitmproxy-reload-requested"
_ROUTES_CACHE = ".mitmproxy-routes.json"


@dataclass(frozen=True, slots=True)
class MitmproxyOptions:
    install_root: Path
    engagements_root: Path
    mode: str = "docker"
    port: int = 8080
    image: str = "security-research-proxy:latest"
    container_name: str = _CONTAINER_NAME
    volume_name: str = "mitmproxy-ca"


def start_proxy(options: MitmproxyOptions, *, runner: docker.Runner = docker.run_command, verify_port: bool = True) -> None:
    if options.mode != "docker":
        raise SystemExit("Only Docker mitmproxy mode is managed by the CLI. Use host mitmproxy directly for --host workflows.")
    install_root = options.install_root.expanduser().resolve()
    engagements_root = options.engagements_root.expanduser().resolve()
    if not engagements_root.is_dir():
        raise SystemExit(f"Engagements root does not exist: {engagements_root}")

    if not docker.image_exists(options.image, runner=runner):
        dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
        argv = ["docker", "build", "-t", options.image, "-f", str(dockerfile), str(install_root / "agent")]
        docker.require_success(runner(argv), argv)

    if docker.container_running(options.container_name, runner=runner):
        runner(["docker", "stop", options.container_name])
    if docker.container_exists(options.container_name, runner=runner):
        runner(["docker", "rm", options.container_name])

    runner(["docker", "volume", "create", options.volume_name])
    # The proxy needs the orchestrator URL the host CLI advertises. We resolve it
    # against a representative engagement directory when one is available so the
    # per-engagement .orchestrator.env override applies; otherwise we fall back
    # to the install-level default.
    representative_engagement = _representative_engagement(engagements_root)
    base_url = container_host_url(
        resolve_orchestrator_base_url(install_root, representative_engagement)
    )
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
        f"{engagements_root}:/engagements",
        "-v",
        f"{options.volume_name}:/root/.mitmproxy",
        "-e",
        f"ORCHESTRATOR_BASE_URL={base_url}",
        options.image,
        "--set",
        "engagements_root=/engagements",
        "--set",
        "block_global=false",
        # Akamai-fronted sites (LastPass, Salesforce Experience Cloud, and
        # other large CDNs) serve CSP / cache-control headers with trailing
        # whitespace that hyper-h2 strict mode rejects per RFC 7540
        # §8.1.2.2. Without disabling h2 the proxy 502s every admin-portal
        # request. Disabling h2 forces the upstream to HTTP/1.1, which all
        # Akamai edges still serve; performance loss is negligible inside
        # an engagement and the capture rate goes from ~30% to 100%.
        "--set",
        "http2=false",
    ]
    docker.run_with_host_gateway_fallback(argv, runner=runner)
    if verify_port and not _wait_for_port("127.0.0.1", options.port):
        raise SystemExit(f"mitmproxy container started but port {options.port} is not reachable on 127.0.0.1")


def stop_proxy(container_name: str = _CONTAINER_NAME, *, runner: docker.Runner = docker.run_command) -> None:
    if docker.container_exists(container_name, runner=runner):
        runner(["docker", "rm", "-f", container_name])


def request_proxy_reload(engagements_root: Path) -> None:
    """Touch the sentinel file the addon watches to force a registry refresh.

    The container bind-mounts ``engagements_root`` at ``/engagements``, so a
    write on the host side is immediately visible to the addon's polling
    thread.
    """
    engagements_root = engagements_root.expanduser().resolve()
    engagements_root.mkdir(parents=True, exist_ok=True)
    sentinel = engagements_root / _RELOAD_SENTINEL
    sentinel.touch()


def read_proxy_routes(engagements_root: Path) -> dict | None:
    """Return the addon's last-written routing snapshot, or None if absent."""
    import json

    cache = engagements_root.expanduser().resolve() / _ROUTES_CACHE
    if not cache.is_file():
        return None
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _representative_engagement(engagements_root: Path) -> Path:
    """Pick an arbitrary engagement directory to resolve the orchestrator URL.

    We only need the per-engagement ``.orchestrator.env`` override mechanism;
    the actual engagement does not matter because every captured flow re-reads
    the URL from the env var the addon receives at container start.
    """
    for path in sorted(engagements_root.iterdir()):
        if not path.is_dir():
            continue
        if path.name.startswith("."):
            continue
        if (path / "scope.json").exists():
            return path
    return engagements_root


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except OSError:
        return False


def _wait_for_port(host: str, port: int) -> bool:
    for attempt in range(_PORT_WAIT_ATTEMPTS):
        if _port_open(host, port):
            return True
        if attempt < _PORT_WAIT_ATTEMPTS - 1:
            time.sleep(_PORT_WAIT_DELAY_SECONDS)
    return False
