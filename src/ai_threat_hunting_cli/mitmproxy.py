from __future__ import annotations

import json
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


def build_image(
    install_root: Path,
    image: str = "security-research-proxy:latest",
    *,
    force: bool = False,
    runner: docker.Runner = docker.run_command,
) -> None:
    """Build the proxy image. ``--force`` rebuilds even if the tag exists."""
    install_root = install_root.expanduser().resolve()
    dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    if not dockerfile.is_file():
        raise SystemExit(f"mitmproxy Dockerfile missing: {dockerfile}")
    if not force and docker.image_exists(image, runner=runner):
        print(f"mitmproxy\timage current\t{image}")
        return
    print(f"mitmproxy\tbuilding\timage={image}")
    argv = [
        "docker",
        "build",
        *(["--no-cache"] if force else []),
        "-t",
        image,
        "-f",
        str(dockerfile),
        str(install_root / "agent"),
    ]
    docker.require_success(runner(argv), argv)
    print(f"mitmproxy\timage built\t{image}")


def start_proxy(
    options: MitmproxyOptions,
    *,
    runner: docker.Runner = docker.run_command,
    verify_port: bool = True,
    verify_running: bool = True,
    force_rebuild: bool = False,
) -> None:
    if options.mode != "docker":
        raise SystemExit("Only Docker mitmproxy mode is managed by the CLI. Use host mitmproxy directly for --host workflows.")
    install_root = options.install_root.expanduser().resolve()
    engagements_root = options.engagements_root.expanduser().resolve()
    if not engagements_root.is_dir():
        raise SystemExit(f"Engagements root does not exist: {engagements_root}")

    if force_rebuild or not docker.image_exists(options.image, runner=runner):
        build_image(install_root, options.image, force=force_rebuild, runner=runner)

    if docker.container_running(options.container_name, runner=runner):
        print(f"mitmproxy\tstopping\tcontainer={options.container_name}")
        runner(["docker", "stop", options.container_name])
    if docker.container_exists(options.container_name, runner=runner):
        runner(["docker", "rm", options.container_name])

    runner(["docker", "volume", "create", options.volume_name])
    # The proxy is one process for all engagements, so its backend URL must come
    # from process/install-level configuration. Per-engagement overrides are for
    # engagement-scoped helpers and would make one arbitrary engagement steer all
    # captured flow writes.
    base_url = container_host_url(
        resolve_orchestrator_base_url(install_root)
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
    print(f"mitmproxy\tstarting\tcontainer={options.container_name}\tport={options.port}")
    docker.run_with_host_gateway_fallback(argv, runner=runner)
    if verify_port and not _wait_for_port("127.0.0.1", options.port):
        # Distinguish "port never opened" from "port opened then container
        # died on addon error" so the operator goes to logs, not to a
        # fictional networking problem.
        if not docker.container_running(options.container_name, runner=runner):
            tail = _container_log_tail(options.container_name, runner=runner)
            raise SystemExit(
                f"mitmproxy container exited during startup. Last log lines:\n{tail}\n"
                f"Re-run `aith mitmproxy build --force` if the addon imports changed."
            )
        raise SystemExit(f"mitmproxy container started but port {options.port} is not reachable on 127.0.0.1")
    # The port can come up before the addon finishes its lifespan. If the
    # addon crashes a second later, the user sees "started" then nothing
    # works. Verify the container is still running.
    if verify_running and not docker.container_running(options.container_name, runner=runner):
        tail = _container_log_tail(options.container_name, runner=runner)
        raise SystemExit(
            f"mitmproxy container started but exited within seconds. Last log lines:\n{tail}"
        )
    print(
        f"mitmproxy\trunning\tcontainer={options.container_name}\tport={options.port}\t"
        f"engagements_root={engagements_root}"
    )


def stop_proxy(container_name: str = _CONTAINER_NAME, *, runner: docker.Runner = docker.run_command) -> None:
    if not docker.container_exists(container_name, runner=runner):
        print(f"mitmproxy\tnot running\t{container_name}")
        return
    print(f"mitmproxy\tstopping\tcontainer={container_name}")
    runner(["docker", "rm", "-f", container_name])
    print(f"mitmproxy\tstopped\tcontainer={container_name}")


def proxy_status_payload(
    install_root: Path,
    engagements_root: Path,
    *,
    port: int = 8080,
    container_name: str = _CONTAINER_NAME,
    image: str = "security-research-proxy:latest",
    volume_name: str = "mitmproxy-ca",
    runner: docker.Runner = docker.run_command,
) -> dict:
    """Structured status snapshot. Drives both human and --json output.

    Surfaces: container state + last exit code (so an exited container is
    not silently treated as "missing"); whether the proxy port is reachable
    on the host loopback (catches crashes after `docker run` returned);
    presence of the CA volume + the image; how many engagement routes the
    addon has loaded; the upstream orchestrator URL the addon will POST to;
    and the last log lines when the container is not running so the
    operator does not need a second command to learn why.
    """
    install_root = install_root.expanduser().resolve()
    engagements_root = engagements_root.expanduser().resolve()
    container = _docker_inspect_summary(container_name, runner=runner)
    running = container.get("running") is True
    status_port = _container_host_port(container) or port
    port_reachable = _port_open("127.0.0.1", status_port)
    routes_snapshot = read_proxy_routes(engagements_root)
    if running:
        state = "running" if port_reachable else "starting"
    elif container.get("exists"):
        state = "exited"
    else:
        state = "missing"
    log_tail = None
    if container.get("exists") and not running:
        log_tail = _container_log_tail(container_name, runner=runner)
    return {
        "state": state,
        "container": container_name,
        "container_id": container.get("id"),
        "exists": bool(container.get("exists")),
        "running": running,
        "exit_code": container.get("exit_code"),
        "started_at": container.get("started_at"),
        "finished_at": container.get("finished_at"),
        "image": image,
        "image_present": docker.image_exists(image, runner=runner),
        "port": status_port,
        "port_reachable": port_reachable,
        "cert_volume": volume_name,
        "cert_volume_present": docker.volume_exists(volume_name, runner=runner),
        "engagements_root": str(engagements_root),
        "upstream_url": container_host_url(resolve_orchestrator_base_url(install_root)),
        "routes_loaded": (len((routes_snapshot or {}).get("engagements") or [])
                          if routes_snapshot else 0),
        "routes_generated_at": (routes_snapshot or {}).get("generated_at") if routes_snapshot else None,
        "log_tail": log_tail,
    }


def _docker_inspect_summary(container_name: str, *, runner: docker.Runner) -> dict:
    """Single docker inspect call returns the fields proxy_status_payload needs."""
    fmt = "{{json .}}"
    result = runner(["docker", "inspect", "--format", fmt, container_name])
    if result.returncode != 0:
        return {"exists": False}
    line = (result.stdout or "").strip().splitlines()[0] if result.stdout else ""
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return {"exists": False}
    if not isinstance(doc, dict):
        return {"exists": False}
    state = doc.get("State") if isinstance(doc.get("State"), dict) else {}
    cid = str(doc.get("Id") or "")
    exit_code = state.get("ExitCode")
    return {
        "exists": True,
        "id": cid[:12],
        "running": state.get("Running") is True,
        "exit_code": exit_code if isinstance(exit_code, int) else None,
        "started_at": state.get("StartedAt") or None,
        "finished_at": state.get("FinishedAt") or None,
        "host_port": _published_host_port(doc),
    }


def _container_host_port(container: dict) -> int | None:
    value = container.get("host_port")
    return value if isinstance(value, int) and value > 0 else None


def _published_host_port(inspect_doc: dict) -> int | None:
    network = inspect_doc.get("NetworkSettings") if isinstance(inspect_doc.get("NetworkSettings"), dict) else {}
    ports = network.get("Ports") if isinstance(network.get("Ports"), dict) else {}
    bindings = ports.get("8080/tcp")
    if not isinstance(bindings, list):
        return None
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        raw_port = str(binding.get("HostPort") or "").strip()
        if raw_port.isdigit():
            port = int(raw_port)
            if port > 0:
                return port
    return None


def _container_log_tail(container_name: str, *, runner: docker.Runner, lines: int = 12) -> str:
    result = runner(["docker", "logs", "--tail", str(lines), container_name])
    out = (result.stdout or "") + (result.stderr or "")
    return out.strip() or "(no log output)"


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
