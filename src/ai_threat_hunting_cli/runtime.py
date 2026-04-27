from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .config import RuntimeResources, runtime_resources
from .paths import container_host_url, resolve_orchestrator_base_url


HEAVY_TIER_HOST_GB_THRESHOLD = 32
HEAVY_TIER_TARGET_GB = 16


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
    resources = runtime_resources()
    _maybe_warn_tier_undersized(resources)
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
        "--cap-add=SYS_PTRACE",
        f"--memory={resources.memory_gb}g",
        f"--memory-swap={resources.memory_gb}g",
        "--memory-swappiness=0",
        f"--cpus={_format_cpus(resources.cpus)}",
        f"--pids-limit={resources.pids_limit}",
        f"--shm-size={resources.shm_size}",
        "--oom-score-adj=-500",
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


def runtime_resource_state(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> dict[str, object]:
    """Return configured runtime resources merged with live cgroup state from the container."""
    configured = runtime_resources()
    state: dict[str, object] = {
        "configured": {
            "memory_gb": configured.memory_gb,
            "cpus": configured.cpus,
            "pids_limit": configured.pids_limit,
            "shm_size": configured.shm_size,
        },
        "container": container_name,
        "running": docker.container_running(container_name, runner=runner),
    }
    if not state["running"]:
        state["live"] = None
        return state
    state["live"] = _read_live_cgroup_state(container_name, runner=runner)
    return state


def aith_runtime_resources(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command, json_output: bool = False) -> None:
    state = runtime_resource_state(container_name, runner=runner)
    if json_output:
        print(json.dumps(state, indent=2))
        return
    configured = state["configured"]  # type: ignore[index]
    print(f"container\t{state['container']}\trunning={state['running']}")
    print(
        f"configured\tmemory={configured['memory_gb']}g\tcpus={configured['cpus']}\t"  # type: ignore[index]
        f"pids_limit={configured['pids_limit']}\tshm_size={configured['shm_size']}"  # type: ignore[index]
    )
    live = state.get("live")
    if live is None:
        print("live\tcontainer not running")
        return
    memory_max = live.get("memory_max", "?") if isinstance(live, dict) else "?"
    cpu_max = live.get("cpu_max", "?") if isinstance(live, dict) else "?"
    pids_max = live.get("pids_max", "?") if isinstance(live, dict) else "?"
    print(f"live\tmemory.max={memory_max}\tcpu.max={cpu_max}\tpids.max={pids_max}")


def _read_live_cgroup_state(container_name: str, *, runner: docker.Runner) -> dict[str, str]:
    command = (
        "for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max /sys/fs/cgroup/pids.max; do "
        "printf '%s=' \"$f\"; cat \"$f\" 2>/dev/null || printf 'unavailable'; printf '\\n'; "
        "done"
    )
    result = runner(["docker", "exec", container_name, "sh", "-lc", command])
    if result.returncode != 0:
        return {"error": (result.stderr or result.stdout).strip() or "docker exec failed"}
    payload: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        if key.endswith("memory.max"):
            payload["memory_max"] = value.strip()
        elif key.endswith("cpu.max"):
            payload["cpu_max"] = value.strip()
        elif key.endswith("pids.max"):
            payload["pids_max"] = value.strip()
    return payload


def _validate_image_current(options: RuntimeOptions, *, runner: docker.Runner) -> None:
    container_id = docker.container_image_id(options.container_name, runner=runner)
    configured_id = docker.image_id(options.image, runner=runner)
    if container_id and configured_id and container_id != configured_id:
        raise SystemExit(
            "Runtime container image drift detected. Recreate with `aith runtime restart`."
        )


def _validate_tools(container_name: str, *, runner: docker.Runner) -> None:
    required_tools = ["dtach", "ping", "katana", "gau", "nuclei", "httpx", "trufflehog", "gf", "uro", "xmllint"]
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


def _format_cpus(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:g}"


def _maybe_warn_tier_undersized(resources: RuntimeResources) -> None:
    """Print a one-line tier-upgrade hint when host RAM is much larger than configured memory."""
    host_gb = _host_memory_gb()
    if host_gb is None:
        return
    if host_gb >= HEAVY_TIER_HOST_GB_THRESHOLD and resources.memory_gb < HEAVY_TIER_TARGET_GB:
        print(
            f"hint\thost has {host_gb} GB RAM but runtime is set to {resources.memory_gb} GB; "
            "consider AITH_RUNTIME_MEMORY_GB=16 (or 32) for better parallelism. "
            "See README Resource Sizing."
        )


def _host_memory_gb() -> int | None:
    """Best-effort read of host RAM in GB; return None on any platform without /proc/meminfo."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    return int(parts[1]) // (1024 * 1024)
    except (OSError, ValueError):
        return None
    return None
