from __future__ import annotations

import json
import shutil
import socket
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from . import docker
from . import image_freshness
from .application import application_root_for_workspace
from .paths import container_host_url, resolve_orchestrator_base_url

_PORT_WAIT_ATTEMPTS = 30
_PORT_WAIT_DELAY_SECONDS = 0.2

_CONTAINER_NAME = "vigil-proxy"
_RELOAD_SENTINEL = ".mitmproxy-reload-requested"
_ROUTES_CACHE = ".mitmproxy-routes.json"


@dataclass(frozen=True, slots=True)
class MitmproxyOptions:
    install_root: Path
    engagements_root: Path
    mode: str = "docker"
    port: int = 8080
    image: str = "vigil-proxy:latest"
    container_name: str = _CONTAINER_NAME
    volume_name: str = "mitmproxy-ca"


def _scope_entries_source(application_root: Path) -> Path:
    """Read the matched release's parser, including an explicitly pinned release."""
    for tree in ("cli", "src"):
        source = application_root / tree / "vigil_cli" / "scope_entries.py"
        if source.is_file():
            return source
    raise SystemExit(f"canonical scope parser missing from application: {application_root}")


def _ignore_build_artifacts(_directory: str, names: list[str]) -> list[str]:
    return [name for name in names if image_freshness.is_excluded_input(name)]


@contextmanager
def _proxy_build_context(install_root: Path) -> Iterator[Path]:
    """Stage the proxy's exact image inputs without exposing install state.

    The install root contains engagements and environment files that are not
    image inputs. Docker receives only the addon, its assess package, the
    Dockerfile, and the canonical scope-entry parser owned by ``vigil_cli``.
    """
    agent_root = install_root / "agent"
    dockerfile = agent_root / "docker" / "mitmproxy" / "Dockerfile"
    assess_source = agent_root / "scripts" / "assess"
    addon_source = agent_root / "scripts" / "proxy_addon.py"
    required = (dockerfile, assess_source, addon_source)
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise SystemExit(f"mitmproxy image input missing: {', '.join(missing)}")

    with tempfile.TemporaryDirectory(prefix="vigil-proxy-build-") as temporary:
        context = Path(temporary)
        shutil.copy2(dockerfile, context / "Dockerfile")
        shutil.copytree(
            assess_source,
            context / "scripts" / "assess",
            ignore=_ignore_build_artifacts,
        )
        (context / "scripts").mkdir(exist_ok=True)
        shutil.copy2(addon_source, context / "scripts" / "proxy_addon.py")
        canonical_destination = context / "vigil_cli" / "scope_entries.py"
        canonical_destination.parent.mkdir()
        shutil.copy2(_scope_entries_source(install_root), canonical_destination)
        yield context


def build_image(
    install_root: Path,
    image: str = "vigil-proxy:latest",
    *,
    force: bool = False,
    runner: docker.Runner | None = None,
    build_runner: docker.Runner | None = None,
    daemon_runner: docker.Runner | None = None,
) -> None:
    """Build the proxy image. ``--force`` rebuilds even if the tag exists."""
    install_root = application_root_for_workspace(install_root)
    dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    if not dockerfile.is_file():
        raise SystemExit(f"mitmproxy Dockerfile missing: {dockerfile}")
    # Only report "current" when the image is provably built from exactly the
    # inputs on disk. A bare tag-exists check (the original behaviour) reported
    # "current" even after proxy_addon.py / the Dockerfile changed; the mtime
    # check that replaced it reported "outdated" forever, because `.pyc` files
    # written by ordinary assess runs were always newer than the image.
    # A metadata query and an image build need different runners. `run_command`
    # bounds every call with VIGIL_DOCKER_TIMEOUT (20s by default) because it
    # exists for fast `docker inspect`-shaped queries; a proxy build takes ~18s
    # and raced that bound. A timed-out build leaves the image unstamped, and an
    # unstamped image can never be proven current -- which resurrects the
    # rebuild-every-time loop this freshness work exists to remove. Builds
    # therefore stream (unbounded), exactly as `build_runtime` already does.
    # A caller that has already split the two passes `build_runner` as well, and
    # then neither role borrows the other's behaviour: `run_command_streaming`
    # returns empty stdout by design, so using it for the label query below
    # reports every image unstamped and rebuilds it on every run. A caller that
    # passes only `runner` keeps the single test seam — both roles use it.
    meta_runner = runner or docker.run_command
    image_build_runner = build_runner or runner or docker.run_command_streaming
    health_runner = daemon_runner or (
        docker.run_command
        if meta_runner is docker.run_command_streaming
        else meta_runner
    )
    docker.require_daemon("build the mitmproxy image", runner=health_runner)
    inputs = mitmproxy_image_inputs(install_root)
    if not force and not image_freshness.image_outdated(
        image, inputs, root=install_root, runner=meta_runner
    ):
        print(f"mitmproxy\timage current (up to date with source)\t{image}")
        return
    print(f"mitmproxy\tbuilding\timage={image}")
    with _proxy_build_context(install_root) as build_context:
        argv = [
            "docker",
            "build",
            *(["--no-cache"] if force else []),
            "-t",
            image,
            # Stamp the input digest so the NEXT freshness check has something to
            # compare against. An unstamped image can never be proven current, so
            # every later `vigil up` would rebuild it again.
            "--label",
            image_freshness.inputs_label_arg(inputs, root=install_root),
            "-f",
            str(build_context / "Dockerfile"),
            str(build_context),
        ]
        docker.require_success(image_build_runner(argv), argv)
    print(f"mitmproxy\timage built\t{image}")


def mitmproxy_image_inputs(install_root: Path) -> list[Path]:
    """Every source path copied into the proxy image (see the mitmproxy
    Dockerfile: it COPYs `scripts/assess` wholesale, `proxy_addon.py`, and the
    canonical scope-entry parser from the matched application CLI snapshot).

    The whole `assess` package is genuinely baked in, so the directory is the
    honest input. Build artifacts inside it (`__pycache__`, `.pyc`, tool caches)
    are excluded centrally by `image_freshness`, not here — the digest walk is
    the single place that knows what a source file is.
    """
    return [
        install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile",
        install_root / "agent" / "scripts" / "assess",
        install_root / "agent" / "scripts" / "proxy_addon.py",
        _scope_entries_source(install_root),
    ]


def start_proxy(
    options: MitmproxyOptions,
    *,
    runner: docker.Runner | None = None,
    build_runner: docker.Runner | None = None,
    verify_port: bool = True,
    verify_running: bool = True,
    force_rebuild: bool = False,
) -> None:
    if options.mode != "docker":
        raise SystemExit("Only Docker mitmproxy mode is managed by the CLI. Use host mitmproxy directly for --host workflows.")
    install_root = options.install_root.expanduser().resolve()
    application_root = application_root_for_workspace(install_root)
    engagements_root = options.engagements_root.expanduser().resolve()
    if not engagements_root.is_dir():
        raise SystemExit(f"Engagements root does not exist: {engagements_root}")

    # `runner` is the METADATA runner and must capture stdout: everything below
    # except the build reads a docker query's output — the image label, `docker
    # ps`, the log tail. Handing it a streaming runner (which returns empty
    # stdout by design) makes a current image look unstamped and rebuilds it,
    # and makes the post-start liveness check see no container and declare the
    # proxy it just started already dead. A caller with a separate unbounded
    # runner for the build passes `build_runner`; `runner` stays raw on the
    # build call so `build_image` can still pick the streaming default itself.
    exec_runner = runner or docker.run_command
    if force_rebuild or image_freshness.image_outdated(
        options.image, mitmproxy_image_inputs(application_root), root=application_root, runner=exec_runner
    ):
        build_image(
            install_root,
            options.image,
            force=force_rebuild,
            runner=runner,
            build_runner=build_runner,
        )

    if docker.container_running(options.container_name, runner=exec_runner):
        print(f"mitmproxy\tstopping\tcontainer={options.container_name}")
        exec_runner(["docker", "stop", options.container_name])
    if docker.container_exists(options.container_name, runner=exec_runner):
        exec_runner(["docker", "rm", options.container_name])

    exec_runner(["docker", "volume", "create", options.volume_name])
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
        # Some Akamai-fronted enterprise portals serve CSP / cache-control
        # headers with trailing
        # whitespace that hyper-h2 strict mode rejects per RFC 7540
        # §8.1.2.2. Without disabling h2 the proxy 502s every admin-portal
        # request. Disabling h2 forces the upstream to HTTP/1.1, which all
        # Akamai edges still serve; performance loss is negligible inside
        # an engagement and the capture rate goes from ~30% to 100%.
        "--set",
        "http2=false",
    ]
    print(f"mitmproxy\tstarting\tcontainer={options.container_name}\tport={options.port}")
    docker.run_with_host_gateway_fallback(argv, runner=exec_runner)
    if verify_port and not _wait_for_port("127.0.0.1", options.port):
        # Distinguish "port never opened" from "port opened then container
        # died on addon error" so the operator goes to logs, not to a
        # fictional networking problem.
        if not docker.container_running(options.container_name, runner=exec_runner):
            tail = _container_log_tail(options.container_name, runner=exec_runner)
            raise SystemExit(
                f"mitmproxy container exited during startup. Last log lines:\n{tail}\n"
                f"Re-run `vigil mitmproxy build --force` if the addon imports changed."
            )
        raise SystemExit(f"mitmproxy container started but port {options.port} is not reachable on 127.0.0.1")
    # The port can come up before the addon finishes its lifespan; if it
    # crashes a second later, the user sees "started" then nothing works.
    if verify_running and not docker.container_running(options.container_name, runner=exec_runner):
        tail = _container_log_tail(options.container_name, runner=exec_runner)
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
    image: str = "vigil-proxy:latest",
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
    state_value = doc.get("State")
    state = state_value if isinstance(state_value, dict) else {}
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
    network_value = inspect_doc.get("NetworkSettings")
    network = network_value if isinstance(network_value, dict) else {}
    ports_value = network.get("Ports")
    ports = ports_value if isinstance(ports_value, dict) else {}
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
