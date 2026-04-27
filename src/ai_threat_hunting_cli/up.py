from __future__ import annotations

import getpass
import select
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import config as config_module
from . import docker
from .engagements import current_engagement_path, resolve_engagement_path
from .mitmproxy import MitmproxyOptions, start_proxy
from .oob import OobOptions, oob_status, start_oob
from .orchestrator import OrchestratorOptions, start_orchestrator
from .runtime import RuntimeOptions, build_runtime, start_runtime, stop_runtime


@dataclass(frozen=True, slots=True)
class UpOptions:
    install_root: Path
    engagement: str | None = None
    select: bool = False
    no_build: bool = False
    runtime_restart_timeout: int = 10
    yes_restart_runtime: bool = False
    no_restart_runtime: bool = False


def run_up(options: UpOptions, *, runner: docker.Runner = docker.run_command) -> None:
    install_root = options.install_root.expanduser().resolve()
    runtime_was_running = docker.container_running("security-research", runner=runner)

    runtime_built = False
    if options.no_build:
        print("runtime image\tbuild skipped")
    elif _image_outdated("security-research:latest", _runtime_image_inputs(install_root), runner=runner):
        print("runtime image\tbuilding")
        build_runtime(install_root, runner=runner)
        runtime_built = True
    else:
        print("runtime image\tcurrent")

    _start_or_restart_runtime(install_root, runtime_was_running, runtime_built, options, runner=runner)

    if options.no_build:
        print("mitmproxy image\tbuild skipped")
    elif _image_outdated("security-research-proxy:latest", _mitmproxy_image_inputs(install_root), runner=runner):
        print("mitmproxy image\tbuilding")
        _build_mitmproxy_image(install_root, runner=runner)
    else:
        print("mitmproxy image\tcurrent")

    start_orchestrator(OrchestratorOptions(install_root=install_root))
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
        print("Run `aith runtime restart` when you are ready to pick up the new image.")
        return

    print("runtime\talready running")
    start_runtime(runtime_options, runner=runner)


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
        "Runtime image changed. Restarting Kali runtime will terminate any in-flight `aith assess kali ...` "
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
    if docker.container_running("security-research-proxy", runner=runner):
        print("mitmproxy\talready running")
        return
    engagement = _resolve_optional_engagement(install_root, options)
    if engagement is None:
        print("mitmproxy\tskipped; run `aith mitmproxy start --select` or pass `aith up --engagement <key>`")
        return
    print(f"mitmproxy\tstarting for {engagement.name}")
    start_proxy(MitmproxyOptions(install_root=install_root, engagement_dir=engagement), runner=runner)


def _start_oob_if_needed(install_root: Path, *, runner: docker.Runner) -> None:
    status = oob_status(runner=runner)
    if status.get("server") or status.get("frpc"):
        print("oob\talready active; existing FRP/interactsh sessions left untouched")
        return

    options = _oob_options(install_root)
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
            )
        else:
            print("oob\tskipped; missing FRP token")
            print("Configure it with: aith config set oob.frp_token <token>")
            print("Then start OOB with: aith oob start")
            return

    print("oob\tstarting")
    start_oob(options, runner=runner)


def _prompt_frp_token() -> str:
    if not sys.stdin.isatty():
        return ""
    return getpass.getpass("OOB FRP token: ").strip()


def _oob_options(install_root: Path) -> OobOptions:
    from .oob import DEFAULT_FRP_HOST, DEFAULT_FRP_PORT, DEFAULT_OOB_DOMAIN
    import os

    token = os.environ.get("AI_THREAT_HUNTING_FRP_TOKEN") or config_module.get_config_value("oob.frp_token") or ""
    host = os.environ.get("AI_THREAT_HUNTING_FRP_HOST") or config_module.get_config_value("oob.frp_host", DEFAULT_FRP_HOST) or DEFAULT_FRP_HOST
    port = int(os.environ.get("AI_THREAT_HUNTING_FRP_PORT") or config_module.get_config_value("oob.frp_port", str(DEFAULT_FRP_PORT)) or DEFAULT_FRP_PORT)
    domain = os.environ.get("AI_THREAT_HUNTING_OOB_DOMAIN") or config_module.get_config_value("oob.domain", DEFAULT_OOB_DOMAIN) or DEFAULT_OOB_DOMAIN
    return OobOptions(install_root=install_root, frp_host=host, frp_port=port, frp_token=token, oob_domain=domain)


def _resolve_optional_engagement(install_root: Path, options: UpOptions) -> Path | None:
    if options.engagement:
        return resolve_engagement_path(install_root, options.engagement)
    if options.select:
        return resolve_engagement_path(install_root, select=True)
    return current_engagement_path()


def _runtime_image_inputs(install_root: Path) -> list[Path]:
    return [
        install_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        install_root / "docker" / "kali-mcp-runtime",
        install_root / "docker" / "callback_listener.py",
        install_root / "docker" / "start-callback.sh",
    ]


def _mitmproxy_image_inputs(install_root: Path) -> list[Path]:
    return [
        install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile",
        install_root / "agent" / "scripts" / "proxy_addon.py",
    ]


def _image_outdated(image: str, inputs: list[Path], *, runner: docker.Runner) -> bool:
    created = _image_created_at(image, runner=runner)
    if created is None:
        return True
    latest_input = _latest_mtime(inputs)
    return latest_input is not None and latest_input > created.timestamp()


def _image_created_at(image: str, *, runner: docker.Runner) -> datetime | None:
    result = runner(["docker", "image", "inspect", "-f", "{{.Created}}", image])
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if not value:
        return None
    try:
        return _parse_docker_timestamp(value).astimezone(timezone.utc)
    except ValueError:
        return None


def _parse_docker_timestamp(value: str) -> datetime:
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if "." in normalized:
        prefix, suffix = normalized.split(".", 1)
        tz_index = len(suffix)
        for marker in ("+", "-"):
            index = suffix.find(marker)
            if index != -1:
                tz_index = index
                break
        fraction = suffix[:tz_index]
        timezone_part = suffix[tz_index:]
        normalized = f"{prefix}.{fraction[:6].ljust(6, '0')}{timezone_part}"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _latest_mtime(paths: list[Path]) -> float | None:
    latest: float | None = None
    for path in paths:
        if path.is_file():
            latest = max(latest or 0, path.stat().st_mtime)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    latest = max(latest or 0, child.stat().st_mtime)
    return latest


def _runtime_image_drift(options: RuntimeOptions, *, runner: docker.Runner) -> bool:
    container_id = docker.container_image_id(options.container_name, runner=runner)
    configured_id = docker.image_id(options.image, runner=runner)
    return bool(container_id and configured_id and container_id != configured_id)


def _build_mitmproxy_image(install_root: Path, *, runner: docker.Runner) -> None:
    dockerfile = install_root / "agent" / "docker" / "mitmproxy" / "Dockerfile"
    argv = ["docker", "build", "-t", "security-research-proxy:latest", "-f", str(dockerfile), str(install_root / "agent")]
    docker.require_success(runner(argv), argv)
