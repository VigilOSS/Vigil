from __future__ import annotations

import json
import math
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import docker
from . import image_freshness
from .application import application_root_for_workspace
from .config import (
    RuntimeEgress,
    RuntimeResources,
    runtime_egress,
    runtime_resources,
)
from .paths import (
    container_host_url,
    default_runtime_container,
    engagements_root,
    read_env_file,
    resolve_orchestrator_base_url,
    resolve_runtime_state_dir,
)
from .scope_entries import classify_scope_entry
from .service_locks import service_start_lock


HEAVY_TIER_HOST_GB_THRESHOLD = 32
HEAVY_TIER_TARGET_GB = 16

ULIMIT_NOFILE_RECOMMENDED = 65536
ULIMIT_NPROC_RECOMMENDED = 8192


class RuntimeCapacityError(SystemExit):
    """A refused memory limit, with capacity facts for CLI consumers."""

    def __init__(self, message: str, *, requested_gib: int, docker_gib: float):
        super().__init__(message)
        self.details = {"requested_gib": requested_gib, "docker_gib": docker_gib}

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
        return resolve_runtime_state_dir(install_root)
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


def runtime_image_inputs(install_root: Path) -> list[Path]:
    """Files BAKED into the runtime image. A change to one of these (and ONLY
    these) requires ``vigil runtime build``; every other file under
    ``agent/scripts`` is host-side and is live after ``vigil install`` plus a
    service restart, so it must NOT flag a rebuild."""
    return [
        install_root / "agent" / "docker" / "runtime-full" / "Dockerfile",
        install_root / "agent" / "docker" / "runtime-full" / "install-external-tools.sh",
        install_root / "agent" / "docker" / "patches" / "arjun-batch-resilience.py",
        install_root / "docker" / "callback_listener.py",
        install_root / "docker" / "start-callback.sh",
    ]


@contextmanager
def _runtime_build_context(install_root: Path, *, variant: str) -> Iterator[Path]:
    """Stage only files referenced by the selected runtime Dockerfile."""
    dockerfile = (
        install_root
        / "agent"
        / "docker"
        / ("runtime-lightweight" if variant == "lightweight" else "runtime-full")
        / "Dockerfile"
    )
    inputs = (
        [dockerfile, install_root / "agent" / "docker" / "patches" / "arjun-batch-resilience.py"]
        if variant == "lightweight"
        else runtime_image_inputs(install_root)
    )
    missing = [str(path) for path in inputs if not path.is_file()]
    if missing:
        raise SystemExit(f"runtime image input missing: {', '.join(missing)}")

    with tempfile.TemporaryDirectory(prefix="vigil-runtime-build-") as temporary:
        context = Path(temporary)
        for source in inputs:
            destination = context / source.relative_to(install_root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        yield context


def runtime_inputs_digest(install_root: Path) -> str:
    """Content digest of the runtime image's baked inputs.

    Delegates to the shared image-input digest so the runtime and proxy images
    are judged fresh by exactly one mechanism.
    """
    return image_freshness.inputs_digest(
        runtime_image_inputs(install_root), root=install_root
    )


def runtime_image_build_state(
    install_root: Path, *, image: str = "vigil:latest", runner: docker.Runner = docker.run_command
) -> str:
    """Content-based build state: ``missing`` | ``stale`` | ``current`` |
    ``unknown``. Compares the current baked-input digest to the digest stamped on
    the image at build time, so it is NOT fooled by ``vigil install`` rewriting
    file mtimes. An image built before digest stamping returns ``unknown``."""
    return image_freshness.image_inputs_state(
        image, runtime_image_inputs(install_root), root=install_root, runner=runner
    )


# --------------------------------------------------------------------------- #
# Host-side recon tools (the `--runtime host` / `vigil assess recon` split).
#
# On macOS/Windows Docker Desktop the DNS-heavy + bulk-liveness stages must run
# on the HOST: every distinct destination IP is NAT-tracked by the userspace
# proxy (com.docker.backend), so a brute over a large resolver set or a bulk
# httpx liveness pass wedges the whole VM (engagement I-001). These binaries are
# therefore expected on the HOST PATH. Everything else (katana crawl, nuclei,
# ffuf, exploit/auth'd HTTP) stays in the isolated container and needs nothing
# host-side. This tuple is the single source of truth for the `vigil doctor`
# host-tool check and the host-tool install list in the README.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class HostTool:
    binary: str
    go_install: str | None  # `go install <spec>`, or None when not go-installable
    essential: bool = True
    note: str = ""


HOST_RECON_TOOLS: tuple[HostTool, ...] = (
    HostTool("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0"),
    HostTool("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3"),
    HostTool("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@v1.9.0"),
    HostTool("puredns", "github.com/d3mondev/puredns/v2@v2.1.1", note="brute engine; needs massdns"),
    HostTool(
        "massdns", None,
        note="not go-installable: `brew install massdns` (macOS) or build from "
             "github.com/blechschmidt/massdns (Linux)",
    ),
    HostTool("shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.1.0",
             essential=False, note="optional brute alternative"),
    HostTool("alterx", "github.com/projectdiscovery/alterx/cmd/alterx@v0.1.0",
             essential=False, note="optional permutation generator"),
)


def host_recon_tool_status() -> list[tuple[HostTool, bool]]:
    """(tool, present_on_host_PATH) for every host-side recon binary."""
    return [(t, shutil.which(t.binary) is not None) for t in HOST_RECON_TOOLS]


def missing_essential_host_tools() -> list[str]:
    return [t.binary for t, present in host_recon_tool_status() if t.essential and not present]


def build_runtime(
    install_root: Path,
    *,
    variant: str = "full",
    dev: bool = False,
    runner: docker.Runner = docker.run_command_streaming,
    daemon_runner: docker.Runner = docker.run_command,
) -> None:
    if variant == "lightweight" and not dev:
        raise SystemExit("The lightweight runtime is development-only. Re-run with --dev to build it.")
    image = "vigil-lightweight:latest" if variant == "lightweight" else "vigil:latest"
    with service_start_lock(f"runtime-image:{image}"):
        docker.require_daemon("build the runtime image", runner=daemon_runner)
        install_root = application_root_for_workspace(install_root)
        dockerfile = install_root / "agent" / "docker" / ("runtime-lightweight" if variant == "lightweight" else "runtime-full") / "Dockerfile"
        with _runtime_build_context(install_root, variant=variant) as build_context:
            staged_dockerfile = build_context / dockerfile.relative_to(install_root)
            argv = ["docker", "build", "-t", image, "-f", str(staged_dockerfile)]
            if variant == "full":
                argv += [
                    "--label",
                    image_freshness.inputs_label_arg(
                        runtime_image_inputs(install_root), root=install_root
                    ),
                ]
            argv.append(str(build_context))
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
        parts.append(f"proxy={egress.proxy}")
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


# A local replica host suffix. ``*.com.local`` / ``*.us.local`` names resolve to
# loopback in the host /etc/hosts, which inside the runtime container is the
# container itself — they reach the real host only through an ``extra_hosts``
# mapping to the host gateway (below).
_LOCAL_REPLICA_SUFFIX = ".local"


def local_replica_hosts(install_root: Path) -> list[str]:
    """Exact ``.local`` replica host names declared across all live engagements.

    A local replica resolves to loopback, which inside the runtime container is
    the container itself. Each such host is wired into the container's
    ``/etc/hosts`` via ``--add-host <host>:host-gateway`` so EVERY tool — not
    just curl — resolves it to the host machine. The runtime is shared across
    engagements (like the proxy), so the set is the union across all of them.
    Wildcard ``*.<domain>`` roots are excluded: ``extra_hosts`` / ``/etc/hosts``
    cannot express a wildcard, so only exact names are injected.
    """
    engagements_dir = engagements_root(install_root)
    if not engagements_dir.is_dir():
        return []
    hosts: set[str] = set()
    for scope_path in sorted(engagements_dir.glob("*/scope.json")):
        try:
            scope = json.loads(scope_path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(scope, dict) or str(scope.get("status") or "") == "archived":
            continue
        raw_hosts = scope.get("hosts")
        if not isinstance(raw_hosts, list):
            continue
        for raw in raw_hosts:
            classified = classify_scope_entry(str(raw))
            if not classified or classified["entry_kind"] not in ("bare_host", "url"):
                continue
            host = classified["host"]
            if host.endswith(_LOCAL_REPLICA_SUFFIX):
                hosts.add(host)
    return sorted(hosts)


def _extra_host_run_args(hosts: list[str]) -> list[str]:
    """``--add-host`` argv wiring each local replica host to the host gateway."""
    return [f"--add-host={host}:host-gateway" for host in hosts]


def _print_local_host_restart_notice(hosts: list[str]) -> None:
    listed = ", ".join(hosts)
    print(
        f"runtime\t{len(hosts)} local replica host(s) not reachable in the running "
        f"runtime: {listed}",
        file=sys.stderr,
    )
    print(
        "  Local .local hosts are wired into the runtime only at container "
        "creation. Run `vigil runtime restart` to pick them up — first ensure no "
        "other engagement is running against the shared runtime, as a restart "
        "terminates any in-flight `vigil assess kali` sessions.",
        file=sys.stderr,
    )


def warn_if_local_hosts_need_restart(
    install_root: Path,
    *,
    container_name: str | None = None,
    runner: docker.Runner = docker.run_command,
) -> list[str]:
    """Warn (and return the list) when scoped ``.local`` hosts are missing from
    the RUNNING runtime.

    ``extra_hosts`` are fixed at container creation, so a local host scoped after
    the runtime came up is not reachable until it is recreated. A stopped runtime
    picks the hosts up on its next start, and a host already injected is covered —
    both return an empty list without a notice.
    """
    name = container_name or default_runtime_container()
    if not docker.container_running(name, runner=runner):
        return []
    wanted = local_replica_hosts(install_root)
    if not wanted:
        return []
    injected = docker.container_extra_hosts(name, runner=runner)
    missing = [host for host in wanted if host not in injected]
    if missing:
        _print_local_host_restart_notice(missing)
    return missing


def start_runtime(
    options: RuntimeOptions,
    *,
    runner: docker.Runner = docker.run_command,
    validate_tools: bool = True,
    allow_existing: bool = False,
    prepare_image: bool = True,
) -> None:
    with (service_start_lock(f"runtime:{options.container_name}"),
          service_start_lock(f"runtime-image:{options.image}")):
        _start_runtime_locked(options, runner=runner, validate_tools=validate_tools,
                              allow_existing=allow_existing, prepare_image=prepare_image)


def _start_runtime_locked(
    options: RuntimeOptions,
    *,
    runner: docker.Runner,
    validate_tools: bool,
    allow_existing: bool,
    prepare_image: bool,
) -> None:
    install_root = options.install_root.expanduser().resolve()
    data_dir = _resolve_runtime_data_dir(install_root)
    engagements_dir = engagements_root(install_root)
    data_dir.mkdir(parents=True, exist_ok=True)
    engagements_dir.mkdir(parents=True, exist_ok=True)

    # Fail fast with an accurate message when the Docker daemon is unresponsive
    # or not running. Without this, the first metadata query below
    # (``image_exists``) returns empty against a wedged daemon — the bounded
    # ``run_command`` timeout keeps it from hanging (I-02) — and start_runtime
    # would raise the MISLEADING "Missing runtime image" instead of naming the
    # real problem. Distinguish a hung daemon (timed out) from an absent one.
    health = docker.daemon_status(runner=runner)
    if not health.responsive:
        headline = (
            "Docker is not responding (the daemon/VM appears wedged)"
            if health.timed_out
            else "Docker does not appear to be running"
        )
        detail = f"\n  {health.detail}" if health.detail else ""
        raise SystemExit(
            f"{headline} — cannot start the runtime.{detail}\n"
            "  Start or restart Docker (on macOS: launch Docker Desktop, or quit and reopen it "
            "if it is hung), then retry. Confirm with `docker info`.\n"
            "  Set VIGIL_DOCKER_TIMEOUT (seconds) if a slow-but-healthy daemon needs longer to respond."
        )

    runtime_is_running = docker.container_running(options.container_name, runner=runner)
    if allow_existing and not options.recreate and not runtime_is_running and docker.container_exists(options.container_name, runner=runner):
        existing_image = runner(["docker", "inspect", "-f", "{{.Config.Image}}", options.container_name])
        if existing_image.returncode or not existing_image.stdout.strip():
            raise SystemExit("Cannot establish the stopped runtime image; inspect it before starting explicitly.")
        if existing_image.stdout.strip() != options.image:
            raise SystemExit(
                f"Stopped runtime uses custom image {existing_image.stdout.strip()}; on-demand startup left it untouched. "
                "Start that image explicitly with `vigil runtime start --image <image>` before retrying."
            )
    if (not runtime_is_running or options.recreate) and prepare_image:
        from .runtime_images import ensure_runtime_image

        # A previous release may leave the default tag present but stale. Resolve
        # its content identity before creating a container, not just its presence.
        ensure_runtime_image(install_root, image=options.image, runner=runner)

    if runtime_is_running and not options.recreate:
        try:
            _validate_image_current(options, runner=runner)
        except SystemExit:
            if not allow_existing:
                raise
            print("runtime\trunning; image update pending. Existing jobs continue; restart explicitly when they finish.", file=sys.stderr)
        _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
        if validate_tools:
            _validate_tools(options.container_name, runner=runner)
        _check_runtime_ulimits(options.container_name, runner=runner)
        # Refresh subfinder's on-disk provider-config from the running container's
        # env vars so a `.env` key edit followed by `vigil up` takes effect without
        # a recreate. Fail-open (WARN only) — never blocks an already-running runtime.
        generate_subfinder_provider_config(options.container_name, runner=runner)
        # extra_hosts are fixed at creation, so a .local replica scoped since this
        # container came up is unreachable until a recreate — surface that rather
        # than let a tool silently fail to resolve it.
        warn_if_local_hosts_need_restart(
            install_root, container_name=options.container_name, runner=runner
        )
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
        remove_argv = ["docker", "rm", "-f", options.container_name]
        docker.require_success(runner(remove_argv), remove_argv)

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
    # Wire every in-scope .local replica host to the host gateway so ALL tools —
    # not just curl's --resolve path — resolve them to the host machine.
    local_hosts = local_replica_hosts(install_root)
    argv.extend(_extra_host_run_args(local_hosts))
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
    # Keep a container that fails validation available for logs and mount inspection.
    _validate_image_current(options, runner=runner)
    _validate_mounts(options.container_name, data_dir, engagements_dir, runner=runner)
    if validate_tools:
        _validate_tools(options.container_name, runner=runner)
    _check_runtime_ulimits(options.container_name, runner=runner)
    # Translate the SUBFINDER_* keys (delivered via --env-file above) into
    # subfinder's on-disk provider-config.yaml inside the container. Fail-open.
    generate_subfinder_provider_config(options.container_name, runner=runner)
    if local_hosts:
        print(
            f"runtime\twired {len(local_hosts)} local replica host(s) to the host gateway",
            file=sys.stderr,
        )


def stop_runtime(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> None:
    container_name = container_name or default_runtime_container()
    if docker.container_exists(container_name, runner=runner):
        remove_argv = ["docker", "rm", "-f", container_name]
        docker.require_success(runner(remove_argv), remove_argv)


def runtime_status(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> str:
    container_name = container_name or default_runtime_container()
    if docker.container_running(container_name, runner=runner):
        return "running"
    # Not listed as running. Distinguish a genuinely stopped container from an
    # unresponsive/absent Docker daemon so `vigil runtime status` (and the
    # `vigil status` snapshot) never reports a wedged VM as a benign "stopped"
    # (I-02). The daemon probe is bounded by run_command's timeout, so this
    # degrades instead of hanging.
    if not docker.daemon_available(runner=runner):
        return "docker-unavailable"
    return "stopped"


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
    engagements_dir = engagements_root(install_root)
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
            "proxy": egress.proxy or None,
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
            + ". See docs/operations.md 'File-descriptor and process limits' for the daemon.json fix.",
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
    value = float(value)
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
        print("Warning: Docker memory capacity is unavailable; resource safety check skipped.", file=sys.stderr)
        _maybe_warn_tier_undersized(resources)
        return

    vm_mem_gb = mem_total / (1024 ** 3)
    frac = resources.memory_gb / vm_mem_gb if vm_mem_gb > 0 else 0.0
    cotenants = sorted(docker.container_names(runner=runner) - {options.container_name})

    if frac >= 0.85 and not options.allow_oversubscribe:
        safe_gib = math.floor(vm_mem_gb * 0.75)
        retry_command = "vigil runtime start --recreate" if options.recreate else "vigil up"
        recovery = (
            f"  Retry: VIGIL_RUNTIME_MEMORY_GB={safe_gib} {retry_command}\n"
            if safe_gib >= 1 else ""
        )
        raise RuntimeCapacityError(
            f"Runtime blocked: {resources.memory_gb} GiB memory limit / "
            f"{vm_mem_gb:.1f} GiB Docker memory ({frac:.0%}; must be below 85%).\n"
            f"{recovery}"
            f"  Or increase Docker memory. Override: {retry_command} --allow-oversubscribe",
            requested_gib=resources.memory_gb, docker_gib=vm_mem_gb,
        )

    if frac >= 0.6:
        note = (
            f"Warning: runtime memory limit is {resources.memory_gb} GiB / "
            f"{vm_mem_gb:.1f} GiB Docker memory ({frac:.0%})."
        )
        if cotenants:
            note += (
                f" {len(cotenants)} other container(s) running "
                f"({', '.join(cotenants[:5])}{'…' if len(cotenants) > 5 else ''})"
            )
        note += " Reduce the limit or increase Docker memory for more headroom."
        print(note, file=sys.stderr)

    if isinstance(ncpu, (int, float)) and ncpu > 0 and resources.cpus >= ncpu:
        print(
            f"Warning: runtime CPU limit is {_format_cpus(resources.cpus)} / {int(ncpu)} Docker CPUs. "
            "Lower VIGIL_RUNTIME_CPUS to leave headroom for other services.",
            file=sys.stderr,
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
            "See docs/operations.md 'Resource sizing'.",
            file=sys.stderr,
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
