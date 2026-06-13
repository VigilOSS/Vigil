from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import docker
from .config import RuntimeEgress, RuntimeResources, runtime_egress, runtime_resources
from .paths import container_host_url, default_runtime_container, read_env_file, resolve_orchestrator_base_url


HEAVY_TIER_HOST_GB_THRESHOLD = 32
HEAVY_TIER_TARGET_GB = 16

ULIMIT_NOFILE_RECOMMENDED = 65536
ULIMIT_NPROC_RECOMMENDED = 8192

# subfinder reads provider API keys ONLY from an on-disk provider-config.yaml
# (subfinder's native schema), NOT from arbitrary SUBFINDER_* env vars. We pass
# the keys into the container via `docker run --env-file .env` and then, at
# `vigil runtime start`, translate the non-empty SUBFINDER_* env vars into that
# on-disk file. Mirrors the asnmap/PDCP credential pattern but for subfinder.
#
# Each tuple is (subfinder source name, list of env vars that compose ONE key
# entry). Single-var sources emit a bare key string; multi-var sources emit the
# `:`-joined composite subfinder splits on (see subfinder createMultiPartKey).
# Only emitted when EVERY listed var is non-empty, so a half-configured Censys
# (id but no secret) does not write a malformed `id:` entry. Sources/value
# formats track the keys already wired in agent/.env.example.
_SUBFINDER_PROVIDER_KEY_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("chaos", ("SUBFINDER_CHAOS_API_KEY",)),
    ("github", ("SUBFINDER_GITHUB_TOKEN",)),
    ("securitytrails", ("SUBFINDER_SECURITYTRAILS_API_KEY",)),
    ("virustotal", ("SUBFINDER_VIRUSTOTAL_API_KEY",)),
    ("shodan", ("SUBFINDER_SHODAN_API_KEY",)),
    ("intelx", ("SUBFINDER_INTELX_API_KEY",)),
    ("urlscan", ("SUBFINDER_URLSCAN_API_KEY",)),
    ("censys", ("SUBFINDER_CENSYS_API_ID", "SUBFINDER_CENSYS_API_SECRET")),
    ("passivetotal", ("SUBFINDER_PASSIVETOTAL_USERNAME", "SUBFINDER_PASSIVETOTAL_API_KEY")),
)

# Written inside the container, under the runtime user's HOME. subfinder's lookup
# chain checks $HOME/.config/subfinder/provider-config.yaml.
_SUBFINDER_CONFIG_REL_PATH = ".config/subfinder/provider-config.yaml"


def _resolve_runtime_data_dir(install_root: Path) -> Path:
    """Resolve the runtime container's host-side ``/data`` mount dir.

    Precedence: ``VIGIL_RUNTIME_DATA_DIR`` (or legacy ``KALI_MCP_DATA_DIR``) from the
    process environment, then the same keys from the install-root ``.env`` — the file
    ``vigil runtime start`` hands to ``docker --env-file``, so a value set there is
    honoured host-side too rather than silently only inside the container — else
    ``<install>/.runtime-data``. A relative value resolves against ``install_root``.
    Deliberately distinct from the orchestrator DB dir's ``VIGIL_DATA_DIR``
    (``paths.resolve_orchestrator_data_dir``): separate directories with separate
    defaults, so one env var must not relocate both. ``start_runtime`` and
    ``runtime_mounts_ok`` must resolve this identically or a running container's mount
    check will spuriously fail after an upgrade.
    """
    dotenv = read_env_file(install_root / ".env")
    value = (
        os.environ.get("VIGIL_RUNTIME_DATA_DIR")
        or os.environ.get("KALI_MCP_DATA_DIR")
        or dotenv.get("VIGIL_RUNTIME_DATA_DIR")
        or dotenv.get("KALI_MCP_DATA_DIR")
    )
    if not value:
        return install_root / ".runtime-data"
    path = Path(value).expanduser()
    return path if path.is_absolute() else install_root / path


def _subfinder_provider_config_script() -> str:
    """Build the POSIX-sh snippet that writes subfinder's provider-config.yaml.

    The snippet runs INSIDE the container via `docker exec`. It reads the
    container's OWN environment (already populated from `--env-file .env`), so
    the API-key *values* are expanded in-container and never appear in the host
    process's argv or on the host filesystem — only env-var *names* travel in
    the exec command. This is the key-leak-safe insertion point: keys are never
    baked into the image and never logged host-side.

    Key-leak / multi-engagement note: the file is written under the runtime
    user's HOME inside the SHARED runtime container. If one container is reused
    across engagements with different scopes, the same provider keys are visible
    to every engagement that execs subfinder there — which is already true of the
    `--env-file` env vars themselves. Operators who must isolate keys per scope
    should run a dedicated runtime (distinct VIGIL_RUNTIME_CONTAINER) per
    engagement; the file is regenerated on every `vigil runtime start`, so
    swapping `.env` and restarting fully replaces it.
    """
    # Emit one heredoc-free, append-built YAML so we never depend on a YAML lib
    # being present in the container. `printf '%s\n'` is POSIX and quote-safe for
    # the values because subfinder keys are tokens without embedded newlines.
    lines = [
        'set -eu',
        'cfg="${HOME:-/root}/' + _SUBFINDER_CONFIG_REL_PATH + '"',
        'dir="$(dirname "$cfg")"',
        'mkdir -p "$dir"',
        'tmp="$cfg.tmp.$$"',
        ': > "$tmp"',
        'emitted=0',
    ]
    for source, env_vars in _SUBFINDER_PROVIDER_KEY_MAP:
        # Guard: every component var must be non-empty before we emit the entry.
        guard = " && ".join(f'[ -n "${{{var}:-}}" ]' for var in env_vars)
        value_expr = ":".join(f'${{{var}}}' for var in env_vars)
        lines.append(f'if {guard}; then')
        lines.append(f'  printf \'%s:\\n  - "%s"\\n\' "{source}" "{value_expr}" >> "$tmp"')
        lines.append('  emitted=$((emitted+1))')
        lines.append('fi')
    lines.extend([
        'mv "$tmp" "$cfg"',
        'chmod 600 "$cfg" 2>/dev/null || true',
        'printf "%s\\n" "$emitted"',
    ])
    return "\n".join(lines)


def generate_subfinder_provider_config(
    container_name: str, *, runner: docker.Runner = docker.run_command
) -> int | None:
    """Translate non-empty SUBFINDER_* env vars in the runtime into subfinder's
    on-disk provider-config.yaml.

    Returns the number of provider keys written, 0 when none were configured, or
    None when the probe could not run (container down / docker unreachable).
    Fail-open by design: subfinder is useful keyless, so a missing-keys or
    unreachable-probe outcome is a one-line stderr WARN, never a hard failure
    (locked posture: fail-open with a WARN when no keys are configured).
    """
    script = _subfinder_provider_config_script()
    result = runner(["docker", "exec", container_name, "sh", "-c", script])
    if result.returncode != 0:
        print(
            "[vigil] WARN: could not generate subfinder provider-config.yaml in the "
            f"runtime ({(result.stderr or result.stdout or '').strip() or 'docker exec failed'}). "
            "subfinder will run keyless (free sources only).",
            file=sys.stderr,
        )
        return None
    # The script's LAST stdout line is the count of emitted keys. Distinguish a
    # genuine "0 keys" (a clean integer the script printed) from inconclusive
    # output (empty/non-numeric stdout — e.g. the script did not actually run):
    # only a genuine count drives the keyless WARN, so an inconclusive probe stays
    # silent rather than spuriously claiming "no keys configured".
    stdout_lines = (result.stdout or "").strip().splitlines()
    try:
        emitted = int(stdout_lines[-1])
    except (ValueError, IndexError):
        return None
    if emitted == 0:
        print(
            "[vigil] WARN: no SUBFINDER_* provider keys configured; subfinder will run "
            "keyless (free sources only, ~60-70% coverage). For the free-key minimum set "
            "SUBFINDER_CHAOS_API_KEY + SUBFINDER_GITHUB_TOKEN in <install>/.env and re-run "
            "`vigil runtime start`. See agent/references/tools/recon/subfinder.md.",
            file=sys.stderr,
        )
    else:
        print(
            f"[vigil] subfinder provider-config.yaml generated with {emitted} keyed "
            "source(s).",
            file=sys.stderr,
        )
    return emitted


@dataclass(frozen=True, slots=True)
class RuntimeOptions:
    install_root: Path
    image: str = "vigil:latest"
    container_name: str = field(default_factory=default_runtime_container)
    recreate: bool = False
    allow_oversubscribe: bool = False


_RUNTIME_INPUTS_LABEL = "com.vigil.runtime-inputs-sha256"


def runtime_image_inputs(install_root: Path) -> list[Path]:
    """Files BAKED into the runtime image. A change to one of these (and ONLY
    these) requires ``vigil runtime build``; every other file under
    ``agent/scripts`` is host-side and is live after ``vigil install`` plus a
    service restart, so it must NOT flag a rebuild."""
    return [
        install_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        install_root / "docker" / "callback_listener.py",
        install_root / "docker" / "start-callback.sh",
    ]


def runtime_inputs_digest(install_root: Path) -> str:
    digest = hashlib.sha256()
    for path in runtime_image_inputs(install_root):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"<absent>")
        digest.update(b"\0")
    return digest.hexdigest()


def runtime_image_build_state(
    install_root: Path, *, image: str = "vigil:latest", runner: docker.Runner = docker.run_command
) -> str:
    """Content-based build state: ``missing`` | ``stale`` | ``current`` |
    ``unknown``. Compares the current baked-input digest to the digest stamped on
    the image at build time, so it is NOT fooled by ``vigil install`` rewriting
    file mtimes. An image built before digest stamping returns ``unknown``."""
    if not docker.image_exists(image, runner=runner):
        return "missing"
    result = runner([
        "docker", "image", "inspect", "-f",
        '{{ index .Config.Labels "' + _RUNTIME_INPUTS_LABEL + '" }}', image,
    ])
    baked = (result.stdout or "").strip() if result.returncode == 0 else ""
    if not baked or baked == "<no value>":
        return "unknown"
    return "current" if baked == runtime_inputs_digest(install_root) else "stale"


def build_runtime(install_root: Path, *, variant: str = "full", dev: bool = False, runner: docker.Runner = docker.run_command_streaming) -> None:
    if variant == "lightweight" and not dev:
        raise SystemExit("The lightweight runtime is development-only. Re-run with --dev to build it.")
    dockerfile = install_root / "agent" / "docker" / ("runtime-lightweight" if variant == "lightweight" else "runtime-full") / "Dockerfile"
    image = "vigil-lightweight:latest" if variant == "lightweight" else "vigil:latest"
    argv = ["docker", "build", "-t", image, "-f", str(dockerfile)]
    if variant == "full":
        argv += ["--label", f"{_RUNTIME_INPUTS_LABEL}={runtime_inputs_digest(install_root)}"]
    argv.append(str(install_root))
    docker.require_success(runner(argv), argv)


def _egress_run_args(egress: RuntimeEgress) -> list[str]:
    """Translate the opt-in egress config into extra `docker run` argv.

    Off by default: an unset ``RuntimeEgress`` returns ``[]`` so the no-egress
    path is byte-for-byte the previous behaviour. When a proxy is set we export
    BOTH lower- and upper-case forms (curl honours the lower-case names; Go tools
    — httpx/nuclei/katana/ffuf/subfinder — honour the upper-case ones) plus
    ALL_PROXY for SOCKS, and ALWAYS export NO_PROXY/no_proxy so backend traffic
    (host.docker.internal) bypasses the proxy. When a network is set we attach it
    with ``--network``; the host-gateway add-host stays in the base argv so the
    orchestrator loop remains reachable.
    """
    args: list[str] = []
    if egress.network:
        args.extend(["--network", egress.network])
    if egress.proxy:
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            args.extend(["-e", f"{name}={egress.proxy}"])
        for name in ("NO_PROXY", "no_proxy"):
            args.extend(["-e", f"{name}={egress.no_proxy}"])
    return args


def _surface_egress_choice(egress: RuntimeEgress) -> None:
    """Emit a one-line, auditable note of the active egress choice to stderr.

    Silent on the default (unset) path so the no-egress run is unchanged. When a
    proxy is active, also WARN that raw-socket tools cannot be proxied."""
    if not egress.enabled:
        return
    parts: list[str] = []
    if egress.proxy:
        parts.append(f"proxy={_redact_proxy(egress.proxy)}")
    if egress.network:
        parts.append(f"network={egress.network}")
    if egress.proxy:
        parts.append(f"no_proxy={egress.no_proxy}")
    print(
        "[vigil] runtime egress separation ACTIVE: " + " ".join(parts),
        file=sys.stderr,
    )
    if egress.proxy:
        print(
            "[vigil] WARN: HTTP(S)_PROXY/ALL_PROXY only covers tools that honour proxy env "
            "(curl/httpx/nuclei/ffuf/katana/subfinder). Raw-socket tools (nmap, naabu, masscan, "
            "ping) IGNORE proxy env and still egress the host IP — attach a network-level "
            "VPN sidecar via VIGIL_RUNTIME_EGRESS_NETWORK to capture those too. "
            "See agent/references/runtime-guides/runtime-egress-separation.md.",
            file=sys.stderr,
        )


def _redact_proxy(url: str) -> str:
    """Strip any user:pass@ credentials before logging a proxy URL."""
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            host = parts.hostname or ""
            if parts.port:
                host = f"{host}:{parts.port}"
            netloc = f"***@{host}" if host else "***"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except ValueError:
        return "<set>"
    return url


def start_runtime(
    options: RuntimeOptions,
    *,
    runner: docker.Runner = docker.run_command,
    validate_tools: bool = True,
    allow_existing: bool = False,
) -> None:
    install_root = options.install_root.expanduser().resolve()
    data_dir = _resolve_runtime_data_dir(install_root)
    engagements_dir = install_root / "agent" / "engagements"
    data_dir.mkdir(parents=True, exist_ok=True)
    engagements_dir.mkdir(parents=True, exist_ok=True)

    if not docker.image_exists(options.image, runner=runner):
        raise SystemExit(
            f"Missing runtime image: {options.image}. Run `vigil runtime build` first.\n"
            "The runtime is only needed for target-facing Kali tools. Backend state reads/writes "
            "use the orchestrator service; run `vigil orchestrator status` or "
            "`vigil orchestrator start` if that is what you need."
        )

    if docker.container_running(options.container_name, runner=runner) and not options.recreate:
        _validate_image_current(options, runner=runner)
        _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
        if validate_tools:
            _validate_tools(options.container_name, runner=runner)
        _check_runtime_ulimits(options.container_name, runner=runner)
        # Refresh subfinder's on-disk provider-config from the running container's
        # env vars so a `.env` key edit followed by `vigil up` takes effect without
        # a recreate. Fail-open (WARN only) — never blocks an already-running runtime.
        generate_subfinder_provider_config(options.container_name, runner=runner)
        if not allow_existing:
            raise SystemExit(_already_running_message(options.container_name, install_root))
        return

    env_file = install_root / ".env"
    base_url = container_host_url(resolve_orchestrator_base_url(install_root))
    resources = runtime_resources()
    # Resolve egress BEFORE any teardown so a malformed VIGIL_RUNTIME_EGRESS_PROXY
    # fails clearly without first `docker rm -f`-ing the running container.
    egress = runtime_egress()
    _preflight_shared_vm(resources, options, runner=runner)

    if docker.container_exists(options.container_name, runner=runner):
        runner(["docker", "rm", "-f", options.container_name])

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
    # Opt-in egress separation: no-op argv when both knobs are unset, so the
    # default no-egress path is byte-for-byte unchanged. Placed AFTER --env-file so
    # the first-class egress knobs win over any stale HTTP(S)_PROXY left in .env
    # (docker run uses the last -e for a given var). --network/-e both precede the
    # image, so appending here is safe. The host-gateway add-host above stays put
    # so the orchestrator/backend loop is always reachable even when a custom
    # egress network is attached.
    argv.extend(_egress_run_args(egress))
    argv.extend(["-e", f"ORCHESTRATOR_BASE_URL={base_url}", options.image])
    _surface_egress_choice(egress)
    docker.run_with_host_gateway_fallback(argv, runner=runner)
    _validate_image_current(options, runner=runner)
    _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
    if validate_tools:
        _validate_tools(options.container_name, runner=runner)
    _check_runtime_ulimits(options.container_name, runner=runner)
    # Translate the SUBFINDER_* keys (delivered via --env-file above) into
    # subfinder's on-disk provider-config.yaml inside the container. Fail-open.
    generate_subfinder_provider_config(options.container_name, runner=runner)


def stop_runtime(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> None:
    container_name = container_name or default_runtime_container()
    if docker.container_exists(container_name, runner=runner):
        runner(["docker", "rm", "-f", container_name])


def runtime_status(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> str:
    container_name = container_name or default_runtime_container()
    return "running" if docker.container_running(container_name, runner=runner) else "stopped"


def _already_running_message(container_name: str, install_root: Path) -> str:
    return (
        "Runtime container is already running.\n"
        f"  container: {container_name}\n"
        f"  install root: {install_root}\n"
        "Use `vigil runtime status` or `vigil runtime resources` to inspect it.\n"
        "Use `vigil runtime restart` to recreate it, or `vigil runtime stop` to stop it."
    )


def runtime_mounts_ok(install_root: Path, container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> bool:
    container_name = container_name or default_runtime_container()
    install_root = install_root.expanduser().resolve()
    data_dir = _resolve_runtime_data_dir(install_root)
    engagements_dir = install_root / "agent" / "engagements"
    try:
        _validate_mounts(container_name, data_dir, engagements_dir, runner=runner)
    except SystemExit:
        return False
    return True


def runtime_resource_state(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> dict[str, object]:
    """Return configured runtime resources merged with live cgroup state from the container."""
    container_name = container_name or default_runtime_container()
    configured = runtime_resources()
    egress = runtime_egress()
    state: dict[str, object] = {
        "configured": {
            "memory_gb": configured.memory_gb,
            "cpus": configured.cpus,
            "pids_limit": configured.pids_limit,
            "shm_size": configured.shm_size,
        },
        "egress": {
            "enabled": egress.enabled,
            "proxy": _redact_proxy(egress.proxy) if egress.proxy else None,
            "network": egress.network,
            "no_proxy": egress.no_proxy if egress.proxy else None,
        },
        "container": container_name,
        "running": docker.container_running(container_name, runner=runner),
    }
    if not state["running"]:
        state["live"] = None
        return state
    state["live"] = _read_live_cgroup_state(container_name, runner=runner)
    return state


def vigil_runtime_resources(container_name: str | None = None, *, runner: docker.Runner = docker.run_command, json_output: bool = False) -> None:
    container_name = container_name or default_runtime_container()
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
    egress = state.get("egress")
    if isinstance(egress, dict) and egress.get("enabled"):
        proxy = egress.get("proxy") or "-"
        network = egress.get("network") or "-"
        print(
            f"egress\tenabled=true\tproxy={proxy}\tnetwork={network}\t"
            f"no_proxy={egress.get('no_proxy') or '-'}"
        )
    else:
        print("egress\tenabled=false\t(shares host/browser egress IP)")
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
            "Runtime container image drift detected. Recreate with `vigil runtime restart`."
        )


def _check_runtime_ulimits(container_name: str, *, runner: docker.Runner) -> None:
    """Warn to stderr when dockerd defaults look low for the workload.

    `docker exec`-launched processes inherit from dockerd's daemon defaults, not
    from container PID 1's `--ulimit`, and `/etc/security/limits.conf` only
    applies under PAM. The fix is dockerd-side (daemon.json `default-ulimits`);
    this probe just surfaces the gap so operators don't chase phantom
    `too many open files` errors during a long Phase 3.
    """
    result = runner(["docker", "exec", container_name, "sh", "-lc", "ulimit -n; ulimit -u"])
    if result.returncode != 0:
        return
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return
    nofile = _parse_ulimit_value(lines[0])
    nproc = _parse_ulimit_value(lines[1])
    warnings: list[str] = []
    if nofile is not None and nofile < ULIMIT_NOFILE_RECOMMENDED:
        warnings.append(f"nofile={nofile} (recommend >={ULIMIT_NOFILE_RECOMMENDED})")
    if nproc is not None and nproc < ULIMIT_NPROC_RECOMMENDED:
        warnings.append(f"nproc={nproc} (recommend >={ULIMIT_NPROC_RECOMMENDED})")
    if warnings:
        print(
            "[vigil] WARN: dockerd default ulimits are low: "
            + ", ".join(warnings)
            + ". See README 'Container resource limits' for the daemon.json fix.",
            file=sys.stderr,
        )


def _parse_ulimit_value(raw: str) -> int | None:
    if raw == "unlimited":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _validate_tools(container_name: str, *, runner: docker.Runner) -> None:
    required_tools = ["dtach", "ping", "katana", "gau", "nuclei", "httpx", "trufflehog", "gf", "uro", "xmllint"]
    for tool in required_tools:
        result = runner(["docker", "exec", container_name, "sh", "-lc", f"command -v '{tool}' >/dev/null"])
        if result.returncode != 0:
            raise SystemExit(f"Runtime tool validation failed; missing {tool}")
    result = runner(["docker", "exec", container_name, "test", "-d", "/engagements"])
    if result.returncode != 0:
        raise SystemExit("Runtime /engagements mount missing. Recreate with `vigil runtime restart`.")


def _validate_mounts(container_name: str, data_dir: Path, engagements_dir: Path, *, runner: docker.Runner) -> None:
    mounts = docker.container_mounts(container_name, runner=runner)
    expected = {
        "/data": data_dir.expanduser().resolve(),
        "/engagements": engagements_dir.expanduser().resolve(),
    }
    for destination, expected_source in expected.items():
        actual_source = mounts.get(destination)
        if not actual_source:
            raise SystemExit(f"Runtime mount drift detected: missing {destination}. Recreate with `vigil runtime restart`.")
        if Path(actual_source).expanduser().resolve() != expected_source:
            raise SystemExit(
                f"Runtime mount drift detected for {destination}: {actual_source} != {expected_source}. "
                "Recreate with `vigil runtime restart`."
            )


def _format_cpus(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return f"{value:g}"


def _preflight_shared_vm(
    resources: RuntimeResources,
    options: RuntimeOptions,
    *,
    runner: docker.Runner,
) -> None:
    """Refuse/warn before starting when the requested tier oversubscribes the VM.

    The runtime competes for one shared Docker VM (on Docker Desktop the VM is a
    fixed allocation co-located with whatever else the user runs — including, in
    one engagement, production databases). Reading actual VM capacity from
    ``docker info`` lets us refuse a tier that would OOM-kill neighbors, instead
    of trusting VIGIL_RUNTIME_* blindly. Fails OPEN: when capacity is unreadable we
    fall back to the host-RAM undersizing hint and proceed (never hard-fail on an
    unreadable probe).
    """
    info = docker.docker_info(runner=runner)
    mem_total = info.get("MemTotal")
    ncpu = info.get("NCPU")
    if not isinstance(mem_total, (int, float)) or mem_total <= 0:
        _maybe_warn_tier_undersized(resources)
        return

    vm_mem_gb = mem_total / (1024 ** 3)
    frac = resources.memory_gb / vm_mem_gb if vm_mem_gb > 0 else 0.0
    cotenants = sorted(docker.container_names(runner=runner) - {options.container_name})

    if frac >= 0.85 and not options.allow_oversubscribe:
        detail = (
            f" and {len(cotenants)} other container(s) are running "
            f"({', '.join(cotenants[:5])}{'…' if len(cotenants) > 5 else ''})"
            if cotenants else ""
        )
        raise SystemExit(
            f"Refusing to start runtime: memory tier {resources.memory_gb} GB is "
            f"{frac:.0%} of the Docker VM's {vm_mem_gb:.1f} GB{detail}.\n"
            "  This oversubscribes a shared VM and can OOM-kill co-located containers.\n"
            "  Lower VIGIL_RUNTIME_MEMORY_GB / VIGIL_RUNTIME_CPUS, stop co-tenant containers,\n"
            "  use a dedicated Docker context/VM, or pass --allow-oversubscribe to override."
        )

    if frac >= 0.6 or cotenants:
        note = (
            f"warning: runtime tier {resources.memory_gb} GB is {frac:.0%} of the "
            f"{vm_mem_gb:.1f} GB Docker VM"
        )
        if cotenants:
            note += (
                f"; {len(cotenants)} co-tenant container(s) running "
                f"({', '.join(cotenants[:5])}{'…' if len(cotenants) > 5 else ''})"
            )
        note += ". Heavy recon may contend with neighbors — prefer a dedicated runtime."
        print(note)

    if isinstance(ncpu, (int, float)) and ncpu > 0 and resources.cpus >= ncpu:
        print(
            f"warning: runtime --cpus={_format_cpus(resources.cpus)} claims the VM's entire "
            f"CPU allocation (NCPU={int(ncpu)}); this can starve the Docker daemon and host."
        )

    # Also keep the host-RAM undersizing hint for dedicated boxes with headroom.
    _maybe_warn_tier_undersized(resources)


def _maybe_warn_tier_undersized(resources: RuntimeResources) -> None:
    """Print a one-line tier-upgrade hint when host RAM is much larger than configured memory."""
    host_gb = _host_memory_gb()
    if host_gb is None:
        return
    if host_gb >= HEAVY_TIER_HOST_GB_THRESHOLD and resources.memory_gb < HEAVY_TIER_TARGET_GB:
        print(
            f"hint\thost has {host_gb} GB RAM but runtime is set to {resources.memory_gb} GB; "
            "consider VIGIL_RUNTIME_MEMORY_GB=16 (or 32) for better parallelism. "
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
