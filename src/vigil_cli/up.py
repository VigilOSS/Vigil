from __future__ import annotations

import getpass
import json
import os
import select
import subprocess
import sys
from contextlib import nullcontext, redirect_stdout
from dataclasses import asdict, dataclass
from functools import partial
from pathlib import Path

from . import config as config_module
from . import docker
from .application import resolve_application_root
from .workspace import initialize_workspace
from .image_freshness import image_outdated, proxy_image_drift
from .mitmproxy import MitmproxyOptions, build_image as build_mitmproxy_image, mitmproxy_image_inputs, start_proxy
from .oob import (
    OOB_CONFIGURATION_FIELDS,
    OOB_UNRESERVED_SLOT_HELP,
    OobOptions,
    oob_options as _oob_options,
    oob_status,
    requires_relay_slot_reservation,
    start_oob,
)
from .orchestrator import OrchestratorOptions, start_orchestrator
from .paths import default_runtime_container, engagements_root
from .runtime import RuntimeCapacityError, RuntimeOptions, runtime_image_inputs, start_runtime
from .runtime_images import ensure_runtime_image
from .service_locks import service_start_lock


@dataclass(frozen=True, slots=True)
class UpOptions:
    install_root: Path
    source_root: Path | None = None
    no_build: bool = False
    runtime_restart_timeout: int = 10
    yes_restart_runtime: bool = False
    no_restart_runtime: bool = False
    allow_oversubscribe: bool = False
    json_output: bool = False


def _progress(component: str, message: str) -> None:
    print(f"  {component:<14} {message}")


def run_up(
    options: UpOptions,
    *,
    runner: docker.Runner = docker.run_command,
    build_runner: docker.Runner = docker.run_command_streaming,
) -> None:
    """Bring the local stack up.

    Two runners, deliberately: ``runner`` bounds fast metadata queries so a
    wedged daemon errors instead of hanging, while ``build_runner`` streams
    without a timeout because a cold image build legitimately runs for minutes.
    Never pass ``runner`` to a build site — that bound kills the build at 20s
    and swallows its progress output.
    """
    install_root = Path(os.path.abspath(options.install_root.expanduser()))

    previous_application = os.environ.get("VIGIL_APPLICATION_DIR")
    state: dict[str, object] = {"status": "ready", "services": {}}
    try:
        with redirect_stdout(sys.stderr) if options.json_output else nullcontext():
            application_root = resolve_application_root(options.source_root, preserve_path=True)
            initialize_workspace(install_root, application_root=application_root)
            os.environ["VIGIL_APPLICATION_DIR"] = str(application_root)
            resources = config_module.runtime_resources()
            state["configured_resources"] = asdict(resources)
            print("Starting Vigil")
            _progress("Runtime limits", f"{resources.memory_gb} GiB RAM · {resources.cpus:g} CPU")
            if options.json_output and build_runner is docker.run_command_streaming:
                build_runner = partial(docker.run_command_streaming, stderr_output=True)
            _start_stack(install_root, application_root, options, runner=runner, build_runner=build_runner, state=state)
    except (SystemExit, OSError, subprocess.CalledProcessError) as exc:
        if not options.json_output:
            raise
        state["status"] = "error"
        state["error"] = {
            "code": "runtime_memory_limit" if isinstance(exc, RuntimeCapacityError) else "startup_failed",
            "message": str(exc),
            **({"resources": exc.details} if isinstance(exc, RuntimeCapacityError) else {}),
        }
        print(json.dumps(state, indent=2))
        raise SystemExit(1) from exc
    finally:
        if previous_application is None:
            os.environ.pop("VIGIL_APPLICATION_DIR", None)
        else:
            os.environ["VIGIL_APPLICATION_DIR"] = previous_application
    if options.json_output:
        print(json.dumps(state, indent=2))
    else:
        print("Vigil startup complete.")


def _start_stack(
    install_root: Path,
    application_root: Path,
    options: UpOptions,
    *,
    runner: docker.Runner,
    build_runner: docker.Runner,
    state: dict[str, object],
) -> None:
    services: dict[str, str] = {}
    state["services"] = services
    with (service_start_lock(f"runtime:{default_runtime_container()}"),
          service_start_lock("runtime-image:vigil:latest")):
        runtime_was_running = docker.container_running(default_runtime_container(), runner=runner)

        runtime_built = False
        if options.no_build:
            _progress("Runtime image", "build skipped")
        elif image_outdated(
            "vigil:latest", _runtime_image_inputs(application_root), root=application_root, runner=runner
        ):
            _progress("Runtime image", "preparing…")
            ensure_runtime_image(install_root, runner=runner, build_runner=build_runner)
            runtime_built = True
        else:
            _progress("Runtime image", "current")

        services["runtime"] = _start_or_restart_runtime(install_root, runtime_was_running, runtime_built, options, runner=runner)

    if options.no_build:
        _progress("Proxy image", "build skipped")
    elif image_outdated(
        "vigil-proxy:latest",
        mitmproxy_image_inputs(application_root),
        root=application_root,
        runner=runner,
    ):
        _progress("Proxy image", "building…")
        _build_mitmproxy_image(install_root, runner=build_runner)
    else:
        _progress("Proxy image", "current")

    start_orchestrator(OrchestratorOptions(install_root=install_root, allow_existing=True))
    services["orchestrator"] = "running"
    _progress("Orchestrator", "running")
    services["mitmproxy"] = _start_mitmproxy_if_needed(install_root, options, runner=runner, build_runner=build_runner)
    services["oob"] = _start_oob_if_needed(install_root, runner=runner)


def _start_or_restart_runtime(
    install_root: Path,
    runtime_was_running: bool,
    runtime_built: bool,
    options: UpOptions,
    *,
    runner: docker.Runner,
) -> str:
    runtime_options = RuntimeOptions(install_root=install_root, allow_oversubscribe=options.allow_oversubscribe)
    if not runtime_was_running:
        if options.no_build and not docker.image_exists(runtime_options.image, runner=runner):
            raise SystemExit(f"Runtime image {runtime_options.image} is missing; run `vigil runtime build` or retry `vigil up` without --no-build.")
        _progress("Runtime", "starting…")
        start_runtime(runtime_options, runner=runner, allow_existing=True, prepare_image=False)
        _progress("Runtime", "running")
        return "running"

    drifted = _runtime_image_drift(runtime_options, runner=runner)
    if runtime_built or drifted:
        if _confirm_runtime_restart(options):
            _progress("Runtime", "restarting…")
            start_runtime(RuntimeOptions(install_root=install_root, recreate=True, allow_oversubscribe=options.allow_oversubscribe), runner=runner, prepare_image=False)
            _progress("Runtime", "running")
            return "running"
        _progress("Runtime", "running; image update pending")
        print("Run `vigil runtime restart` when you are ready to pick up the new image.")
        return "running_old_image"

    _progress("Runtime", "already running")
    start_runtime(runtime_options, runner=runner, allow_existing=True)
    return "running"


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


def _start_mitmproxy_if_needed(
    install_root: Path,
    options: UpOptions,
    *,
    runner: docker.Runner,
    build_runner: docker.Runner,
) -> str:
    with service_start_lock("mitmproxy:vigil-proxy"):
        return _start_mitmproxy_locked(install_root, options, runner=runner, build_runner=build_runner)


def _start_mitmproxy_locked(
    install_root: Path,
    options: UpOptions,
    *,
    runner: docker.Runner,
    build_runner: docker.Runner,
) -> str:
    """Start capture once, preserving an existing shared capture process.

    Both runners go in, and they are not interchangeable. `start_proxy` reads
    the image label, `docker ps` and a log tail through its `runner`, so passing
    the streaming one there — which returns empty stdout by design — rebuilt a
    current image every time and made the post-start liveness check declare the
    proxy it had just started already dead.
    """
    if docker.container_running("vigil-proxy", runner=runner):
        mounted = docker.container_mounts("vigil-proxy", runner=runner).get("/engagements")
        expected = engagements_root(install_root).resolve()
        if not mounted or Path(mounted).resolve() != expected:
            raise SystemExit(
                f"Shared capture uses a different engagements directory ({mounted or 'unknown'}); "
                f"this working root needs {expected}. Existing capture was left running."
            )
        if proxy_image_drift(runner=runner):
            _progress("Proxy", "running; image update pending")
            print("Run `vigil mitmproxy start` to recreate the container on the current image.")
            return "running_old_image"
        else:
            _progress("Proxy", "already running")
        return "running"
    engagement_directory = engagements_root(install_root)
    engagement_directory.mkdir(parents=True, exist_ok=True)
    _progress("Proxy", "starting…")
    start_proxy(
        MitmproxyOptions(install_root=install_root, engagements_root=engagement_directory),
        runner=runner,
        build_runner=build_runner,
        build_if_needed=not options.no_build,
    )
    _progress("Proxy", "running")
    return "running"


def _start_oob_if_needed(install_root: Path, *, runner: docker.Runner) -> str:
    options = _oob_options(install_root)
    status = oob_status(
        oob_domain=options.oob_domain,
        slot_prefix=options.slot_prefix,
        dns_remote_port=options.dns_remote_port,
        reverse_remote_port=options.reverse_remote_port,
        runner=runner,
        deep=False,
    )  # only needs server/frpc liveness
    if status.get("server") or status.get("frpc"):
        route_matches = status.get("route_matches")
        if route_matches is False or (
            route_matches is None and options.slot_prefix != "legacy"
        ):
            raise SystemExit(
                "OOB sessions are already active for another relay slot, or their relay route cannot be verified. "
                "Run `vigil oob restart` intentionally before switching relay routes."
            )
        _progress("Callbacks", "already active")
        return "active"

    if not options.frp_host or not options.oob_domain:
        _progress("Callbacks", "skipped; not configured (optional)")
        _print_oob_configuration_help()
        return "skipped_unconfigured"

    # `start_oob` refuses this outright; `vigil up` skips it instead, the same
    # way it skips OOB for any other missing prerequisite — the rest of the
    # stack is already up and OOB is one optional service, so the command's exit
    # status should not claim the bring-up failed. Checked here rather than left
    # to the refusal so the token prompt below never asks for a credential this
    # run cannot use.
    if requires_relay_slot_reservation(install_root):
        _progress("Callbacks", "skipped; no relay slot reserved (optional)")
        print(OOB_UNRESERVED_SLOT_HELP)
        return "skipped_unreserved"

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
                slot_prefix=options.slot_prefix,
                dns_remote_port=options.dns_remote_port,
                reverse_remote_port=options.reverse_remote_port,
                relay_route=options.relay_route,
            )
        else:
            _progress("Callbacks", "skipped; missing FRP token (optional)")
            print("Configure it with: vigil config set oob.frp_token <token>")
            print("Then start OOB with: vigil oob start")
            return "skipped_missing_token"

    _progress("Callbacks", "starting…")
    start_oob(options, runner=runner)
    return "active"


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



def _print_oob_configuration_help() -> None:
    """Point at the callback command's canonical setup checklist."""
    keys = ", ".join(key for key, _ in OOB_CONFIGURATION_FIELDS)
    print(f"  Callback setup: set {keys} with vigil config set.")
    print("  Then: vigil install && vigil oob start")

def _build_mitmproxy_image(install_root: Path, *, runner: docker.Runner = docker.run_command_streaming) -> None:
    """Delegate to the one proxy-image builder.

    `vigil up` used to assemble its own `docker build` argv here, which omitted
    the input-digest label. An unstamped image can never be proven current, so
    the very next `vigil up` rebuilt it again — forever.

    One runner goes in and `build_image` uses it for its own freshness re-check
    as well as the build, which for a streaming runner means that re-check can
    only ever answer "outdated". That is safe HERE and only here: `run_up`
    already decided the image is stale, through the capturing runner, before
    calling this. Do not copy the single-runner call into a path without that
    outer check — `start_proxy` is where that went wrong, and the fix there was
    to pass `runner` and `build_runner` separately.
    """
    build_mitmproxy_image(install_root, runner=runner)
