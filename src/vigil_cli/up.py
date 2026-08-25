from __future__ import annotations

import getpass
import select
import sys
from dataclasses import dataclass
from pathlib import Path

from . import config as config_module
from . import docker
from .image_freshness import image_outdated, proxy_image_drift
from .install import InstallOptions, install_from_source
from .mitmproxy import MitmproxyOptions, build_image as build_mitmproxy_image, mitmproxy_image_inputs, start_proxy
from .oob import OobOptions, oob_options as _oob_options, oob_status, start_oob
from .orchestrator import OrchestratorOptions, start_orchestrator
from .paths import default_runtime_container, resolve_source_root
from .runtime import RuntimeOptions, build_runtime, runtime_image_inputs, start_runtime, stop_runtime


@dataclass(frozen=True, slots=True)
class UpOptions:
    install_root: Path
    no_build: bool = False
    runtime_restart_timeout: int = 10
    yes_restart_runtime: bool = False
    no_restart_runtime: bool = False


def run_up(options: UpOptions, *, runner: docker.Runner = docker.run_command) -> None:
    install_root = options.install_root.expanduser().resolve()

    try:
        source_root = resolve_source_root(None, install_root=install_root)
        print("source sync\tupdating install root")
        install_from_source(
            InstallOptions(
                source_root=source_root,
                install_root=install_root,
                verify_docker_image=False,
            ),
            runner=runner,
        )
    except SystemExit:
        print("source sync\tskipped (no source checkout found)")

    runtime_was_running = docker.container_running(default_runtime_container(), runner=runner)

    runtime_built = False
    if options.no_build:
        print("runtime image\tbuild skipped")
    elif image_outdated(
        "vigil:latest", _runtime_image_inputs(install_root), root=install_root, runner=runner
    ):
        print("runtime image\tbuilding")
        build_runtime(install_root, runner=runner)
        runtime_built = True
    else:
        print("runtime image\tcurrent")

    _start_or_restart_runtime(install_root, runtime_was_running, runtime_built, options, runner=runner)

    if options.no_build:
        print("mitmproxy image\tbuild skipped")
    elif image_outdated(
        "vigil-proxy:latest",
        mitmproxy_image_inputs(install_root),
        root=install_root,
        runner=runner,
    ):
        print("mitmproxy image\tbuilding")
        _build_mitmproxy_image(install_root, runner=runner)
    else:
        print("mitmproxy image\tcurrent")

    start_orchestrator(OrchestratorOptions(install_root=install_root, allow_existing=True))
    _start_mitmproxy_if_needed(install_root, options, runner=runner)
    _start_oob_if_needed(install_root, runner=runner)


def _start_or_restart_runtime(
    install_root: Path,
    runtime_was_running: bool,
    runtime_built: bool,
    options: UpOptions,
    *,
    runner: docker.Runner,
) -> None:
    runtime_options = RuntimeOptions(install_root=install_root)
    if not runtime_was_running:
        print("runtime\tstarting")
        start_runtime(runtime_options, runner=runner)
        return

    drifted = _runtime_image_drift(runtime_options, runner=runner)
    if runtime_built or drifted:
        if _confirm_runtime_restart(options):
            print("runtime\trestarting")
            stop_runtime(runner=runner)
            start_runtime(RuntimeOptions(install_root=install_root, recreate=True), runner=runner)
            return
        print("runtime\trunning old image; restart skipped")
        print("Run `vigil runtime restart` when you are ready to pick up the new image.")
        return

    print("runtime\talready running")
    start_runtime(runtime_options, runner=runner, allow_existing=True)


def _confirm_runtime_restart(options: UpOptions) -> bool:
    if options.yes_restart_runtime:
        return True
    if options.no_restart_runtime:
        return False
    if not sys.stdin.isatty():
        print("runtime restart prompt skipped in non-interactive mode; defaulting to no")
        return False

    timeout = max(0, options.runtime_restart_timeout)
    print(
        "Runtime image changed. Restarting Kali runtime will terminate any in-flight `vigil assess kali ...` "
        "or `docker exec` sessions; OOB interactsh client domains may be lost unless their session files "
        "can resume with the server."
    )
    print(f"Restart Kali runtime now? [y/N] waiting {timeout}s: ", end="", flush=True)
    readable, _, _ = select.select([sys.stdin], [], [], timeout)
    if not readable:
        print()
        return False
    answer = sys.stdin.readline().strip().lower()
    return answer in {"y", "yes"}


def _start_mitmproxy_if_needed(install_root: Path, options: UpOptions, *, runner: docker.Runner) -> None:
    if docker.container_running("vigil-proxy", runner=runner):
        if proxy_image_drift(runner=runner):
            print("mitmproxy\trunning old image; restart to pick up rebuilt image")
            print("Run `vigil mitmproxy start` to recreate the container on the current image.")
        else:
            print("mitmproxy\talready running")
        return
    engagements_root = install_root / "agent" / "engagements"
    engagements_root.mkdir(parents=True, exist_ok=True)
    print("mitmproxy\tstarting (serves all active engagements)")
    start_proxy(
        MitmproxyOptions(install_root=install_root, engagements_root=engagements_root),
        runner=runner,
    )
    del options  # accepted for signature parity; the proxy no longer pins to an engagement


def _start_oob_if_needed(install_root: Path, *, runner: docker.Runner) -> None:
    options = _oob_options(install_root)
    status = oob_status(
        oob_domain=options.oob_domain,
        tenant_prefix=options.tenant_prefix,
        dns_remote_port=options.dns_remote_port,
        reverse_remote_port=options.reverse_remote_port,
        runner=runner,
        deep=False,
    )  # only needs server/frpc liveness
    if status.get("server") or status.get("frpc"):
        route_matches = status.get("route_matches")
        if route_matches is False or (
            route_matches is None and options.tenant_prefix != "legacy"
        ):
            raise SystemExit(
                "OOB sessions are already active for another tenant, or their tenant route cannot be verified. "
                "Run `vigil oob restart` intentionally before switching tenant routes."
            )
        print("oob\talready active; existing FRP/interactsh sessions left untouched")
        return

    if not options.frp_token:
        token = _prompt_frp_token()
        if token:
            config_module.set_config_value("oob.frp_token", token)
            options = OobOptions(
                install_root=install_root,
                frp_host=options.frp_host,
                frp_port=options.frp_port,
                frp_token=token,
                oob_domain=options.oob_domain,
                tenant_prefix=options.tenant_prefix,
                dns_remote_port=options.dns_remote_port,
                reverse_remote_port=options.reverse_remote_port,
                tenant_route=options.tenant_route,
            )
        else:
            print("oob\tskipped; missing FRP token")
            print("Configure it with: vigil config set oob.frp_token <token>")
            print("Then start OOB with: vigil oob start")
            return

    print("oob\tstarting")
    start_oob(options, runner=runner)


def _prompt_frp_token() -> str:
    if not sys.stdin.isatty():
        return ""
    return getpass.getpass("OOB FRP token: ").strip()


def _runtime_image_inputs(install_root: Path) -> list[Path]:
    return runtime_image_inputs(install_root)


def _runtime_image_drift(options: RuntimeOptions, *, runner: docker.Runner) -> bool:
    container_id = docker.container_image_id(options.container_name, runner=runner)
    configured_id = docker.image_id(options.image, runner=runner)
    return bool(container_id and configured_id and container_id != configured_id)


def _build_mitmproxy_image(install_root: Path, *, runner: docker.Runner = docker.run_command_streaming) -> None:
    """Delegate to the one proxy-image builder.

    `vigil up` used to assemble its own `docker build` argv here, which omitted
    the input-digest label. An unstamped image can never be proven current, so
    the very next `vigil up` rebuilt it again — forever.
    """
    build_mitmproxy_image(install_root, runner=runner)
