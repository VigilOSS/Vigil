from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import config as config_module
from . import docker
from .oob_relay import (
    OobRelayRoute,
    has_pre_routing_oob_state,
    legacy_relay_route,
    load_relay_route,
)
from .paths import default_runtime_container

DEFAULT_FRP_HOST = ""
DEFAULT_FRP_PORT = 7000
DEFAULT_OOB_DOMAIN = ""
# Server-side resources hardcoded in the OOB profile. Globally unique on frps:
# any other client holding these blocks our registration with port already used /
# router config conflict. Stays in sync with _render_runtime_files() below.
OOB_TCP_REMOTE_PORT = 8443
OOB_UDP_REMOTE_PORT = 53
OOB_ROOT = "/data/oob"
OOB_RELAY_ROUTE_FILE = f"{OOB_ROOT}/active-relay-routing.json"
# Marker name written by installs from before the relay-slot rename. `/data` is a
# host bind mount, so a runtime started then still has this file and nothing else;
# reading it is what keeps those live sessions claimable after an upgrade.
LEGACY_OOB_RELAY_ROUTE_FILE = f"{OOB_ROOT}/active-tenant-routing.json"
FRPC_READY_TIMEOUT_SECONDS = 15.0
MAX_OOB_POLL_RECORDS = 10_000
OOB_STATUS_RETRY_DELAY_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class OobOptions:
    install_root: Path
    frp_host: str = DEFAULT_FRP_HOST
    frp_port: int = DEFAULT_FRP_PORT
    frp_token: str = ""
    oob_domain: str = DEFAULT_OOB_DOMAIN
    slot_prefix: str = "legacy"
    dns_remote_port: int = OOB_UDP_REMOTE_PORT
    reverse_remote_port: int = OOB_TCP_REMOTE_PORT
    relay_route: OobRelayRoute | None = None
    container_name: str = field(default_factory=default_runtime_container)


def oob_options(install_root: Path) -> OobOptions:
    """Resolve OOB options without silently selecting third-party infrastructure."""
    token = os.environ.get("VIGIL_FRP_TOKEN") or config_module.get_config_value("oob.frp_token") or ""
    host = os.environ.get("VIGIL_FRP_HOST") or config_module.get_config_value("oob.frp_host", DEFAULT_FRP_HOST) or DEFAULT_FRP_HOST
    port = int(os.environ.get("VIGIL_FRP_PORT") or config_module.get_config_value("oob.frp_port", str(DEFAULT_FRP_PORT)) or DEFAULT_FRP_PORT)
    configured_domain = (
        os.environ.get("VIGIL_OOB_DOMAIN")
        or config_module.get_config_value("oob.domain", DEFAULT_OOB_DOMAIN)
        or DEFAULT_OOB_DOMAIN
    )
    route = load_relay_route(install_root)
    if route is None and configured_domain:
        route = legacy_relay_route(install_root, base_domain=configured_domain)
    elif route is not None:
        external_domain = os.environ.get("VIGIL_OOB_DOMAIN")
        external_value = external_domain.strip().rstrip(".").lower() if external_domain else ""
        if external_value and external_value not in {route.base_domain, route.oob_domain}:
            raise SystemExit(
                "VIGIL_OOB_DOMAIN cannot override persisted Vigil relay routing. "
                f"Expected relay slot domain {route.oob_domain!r} or its persisted base domain "
                f"{route.base_domain!r}, got {external_domain!r}."
            )
    return OobOptions(
        install_root=install_root,
        frp_host=host,
        frp_port=port,
        frp_token=token,
        oob_domain=route.oob_domain if route is not None else "",
        slot_prefix=route.slot_prefix if route is not None else "legacy",
        dns_remote_port=route.dns_remote_port if route is not None else OOB_UDP_REMOTE_PORT,
        reverse_remote_port=route.reverse_remote_port if route is not None else OOB_TCP_REMOTE_PORT,
        relay_route=route,
    )


OOB_CONFIGURATION_HELP = (
    "Configure it with: vigil config set oob.frp_host <host>\n"
    "                   vigil config set oob.domain <domain>\n"
    "                   vigil config set oob.frp_token <token>\n"
    "Then run `vigil install` — the relay slot (this install's subdomain and\n"
    "port block) is reserved during install, and only when a domain is already\n"
    "configured, so a domain set afterwards needs one more install to take\n"
    "effect."
)

OOB_UNRESERVED_SLOT_HELP = (
    "Run `vigil install` with `oob.domain` set to reserve this install its own\n"
    "relay slot, then start OOB."
)


def requires_relay_slot_reservation(install_root: Path) -> bool:
    """True when starting OOB here would fabricate its own legacy evidence.

    `vigil oob start` cannot run without rendering `frpc.toml`, an active-route
    marker and per-client files into `/data/oob` — and that state is precisely
    the discriminator `oob_relay.has_pre_routing_oob_state` reads as proof a
    root is already live on the shared 53/8443 route. So an install that starts
    OOB with no slot reserved comes out the other side looking like a legacy
    install, and the `vigil install` it was told to run then PINS the shared
    route instead of allocating. The remedy destroyed itself by being followed.

    The refusal is therefore scoped to roots with nothing at stake: no routing
    record AND no prior OOB state. A root already live on the shared route is
    the population that route exists for — it is warned, never refused, because
    moving its ports is what would break its correlation.
    """
    return load_relay_route(install_root) is None and not has_pre_routing_oob_state(
        install_root
    )


def start_oob(
    options: OobOptions,
    *,
    runner: docker.Runner = docker.run_command,
    frpc_ready_timeout: float = FRPC_READY_TIMEOUT_SECONDS,
) -> None:
    # Every key `start_oob` requires is named in ONE refusal. Checking host and
    # domain here and the token further down used to refuse the operator twice:
    # once for the pair, then again for the token they were never told about.
    if not options.frp_host or not options.oob_domain or not options.frp_token:
        raise SystemExit(
            "OOB infrastructure is not configured.\n" + OOB_CONFIGURATION_HELP
        )
    # A configured domain with no routing record resolves to the SHARED legacy
    # route (ports 53/8443) through `oob_options`, and every other install in
    # that state lands on the same ports and subdomain — callbacks then
    # correlate to the wrong engagement. Documenting the `vigil install` step is
    # not enough on its own: nothing stops an operator reaching this command
    # without it, and the degraded route is otherwise indistinguishable from a
    # reserved one at startup. Refuse BEFORE anything is rendered, for the
    # reason `requires_relay_slot_reservation` gives. A pinned legacy route (a
    # record that says so) is a deliberate state and is neither refused nor
    # warned about.
    if requires_relay_slot_reservation(options.install_root):
        raise SystemExit(
            "OOB start refused: no relay slot reserved for this install — it "
            "would use the SHARED legacy route "
            f"({options.oob_domain}, ports {options.dns_remote_port}/"
            f"{options.reverse_remote_port}), which every other install in this "
            "state also uses, so callbacks could not be told apart — and the "
            "state it left behind would pin this root to that route for good.\n"
            + OOB_UNRESERVED_SLOT_HELP
        )
    if load_relay_route(options.install_root) is None:
        print(
            "[vigil] warning: no relay slot reserved for this install — keeping "
            "the SHARED legacy route "
            f"({options.oob_domain}, ports {options.dns_remote_port}/"
            f"{options.reverse_remote_port}) this root's callbacks are already "
            "live on. Another install in the same state uses it too, and "
            "callbacks cannot be told apart. Run `vigil install` to pin this "
            "route on the record; a dedicated slot would move the ports those "
            "callbacks come back on.",
            file=sys.stderr,
        )
    _require_runtime(options.container_name, runner=runner)
    _require_runtime_tools(options.container_name, runner=runner)
    active = any(
        _tmux_has_session(options.container_name, session, runner=runner)
        for session in ("oob-server", "frpc")
    )
    runtime_route, route_issue = _runtime_relay_route(options.container_name, runner=runner)
    route_matches: bool | None = None
    if route_issue:
        route_matches = False
    elif runtime_route:
        route_matches = _route_matches_options(runtime_route, options)
    running_clients = list_running_oob_clients(options.container_name, runner=runner)
    for client_name in running_clients:
        client_metadata, client_issue = _read_oob_client_metadata(
            options.container_name, client_name, runner=runner
        )
        if client_issue or client_metadata is None:
            detail = client_issue or "client route metadata is missing"
            raise SystemExit(
                f"The running OOB client {client_name!r} route cannot be verified: {detail}. "
                f"Stop it explicitly with `vigil oob client stop {client_name}` before switching routes."
            )
        if not _client_metadata_matches_options(client_metadata, options):
            raise SystemExit(
                f"The running OOB client {client_name!r} belongs to another relay route. "
                f"Stop it explicitly with `vigil oob client stop {client_name}` before switching routes."
            )
    if active and (
        route_matches is False
        or (route_matches is None and options.slot_prefix != "legacy")
    ):
        detail = route_issue or "the active sessions do not match this install's persisted route"
        raise SystemExit(
            "OOB sessions are already active for another relay slot (or their relay route cannot be verified): "
            f"{detail}. Run `vigil oob restart` intentionally before switching relay routes."
        )
    _kill_stale_oob_processes(options.container_name, runner=runner)
    _render_runtime_files(options, runner=runner)
    _ensure_tmux_session(
        options.container_name,
        "oob-server",
        f"python3 {OOB_ROOT}/oob_server_watch.py 2>&1 | tee -a {OOB_ROOT}/watch.log",
        runner=runner,
    )
    _reset_frpc_log(options.container_name, runner=runner)
    frpc_cmd = (
        f"while true; do "
        f"frpc -c {OOB_ROOT}/frpc.toml 2>&1 | tee {OOB_ROOT}/frpc.log; "
        f"echo '[frpc] exited, restarting in 30s...' >> {OOB_ROOT}/frpc.log; "
        f"sleep 30; done"
    )
    _ensure_tmux_session(
        options.container_name,
        "frpc",
        frpc_cmd,
        runner=runner,
    )
    if frpc_ready_timeout > 0:
        _check_frpc_for_conflicts(options, runner=runner, timeout=frpc_ready_timeout)


def stop_oob(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> None:
    container_name = container_name or default_runtime_container()
    for session in ("frpc", "oob-server"):
        _run_exec(container_name, f"tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true", runner=runner, check=False)
    _kill_stale_oob_processes(container_name, runner=runner)


def oob_status(
    container_name: str | None = None,
    *,
    oob_domain: str | None = None,
    slot_prefix: str = "legacy",
    dns_remote_port: int = OOB_UDP_REMOTE_PORT,
    reverse_remote_port: int = OOB_TCP_REMOTE_PORT,
    runner: docker.Runner = docker.run_command,
    deep: bool = True,
) -> dict[str, object]:
    """Live OOB state plus an active HEALTH verdict.

    Liveness alone (tmux sessions exist) masks the failure mode that bit us: every
    interactsh-client can be "running" yet failing to register because the OOB
    domain does not resolve (broken Route53 delegation). So with ``deep=True``
    (the default, used by ``vigil oob status``) this also checks, for each RUNNING
    client, whether it actually registered an interactsh payload, and whether the
    OOB domain resolves and its two-label public HTTP route reaches this relay
    slot, then derives a ``health`` (``ok``/``degraded``/``down``) + human
    ``issues``.

    ``deep=False`` skips those per-client log reads and the DNS/HTTP probes for
    the lightweight aggregate callers (`vigil status`, `vigil up`): registration
    is reported as unknown (``None``) and health reflects only session liveness,
    so those hot paths keep their original cost. ``domain`` is always resolved to
    the default when not supplied so the verdict is never silently a false
    ``ok``.
    """
    container_name = container_name or default_runtime_container()
    domain = oob_domain or DEFAULT_OOB_DOMAIN
    if not docker.container_running(container_name, runner=runner):
        return {
            "state": "stopped", "health": "down", "server": False, "frpc": False,
            "clients": [], "running": [], "client_health": [], "domain": domain,
            "slot_prefix": slot_prefix,
            "port_range": [dns_remote_port, reverse_remote_port],
            "runtime_route": None,
            "route_matches": None,
            "domain_resolves": None,
            "edge_route_healthy": None,
            "probe_attempts": 0,
            "issues": ["Kali runtime container is not running — start it with `vigil runtime start`."],
        }
    server = _tmux_has_session(container_name, "oob-server", runner=runner)
    frpc = _tmux_has_session(container_name, "frpc", runner=runner)
    runtime_route, route_issue = _runtime_relay_route(container_name, runner=runner)
    route_matches = None
    if route_issue:
        route_matches = False
    elif runtime_route:
        route_matches = _route_matches_values(
            runtime_route,
            slot_prefix=slot_prefix,
            oob_domain=domain,
            dns_remote_port=dns_remote_port,
            reverse_remote_port=reverse_remote_port,
        )
    running = list_running_oob_clients(container_name, runner=runner)
    # Reuse the already-fetched running set instead of re-querying tmux inside list_oob_clients.
    clients = sorted(set(running) | _configured_oob_clients(container_name, runner=runner))
    if deep:
        client_health = [
            {"name": name, "registered": bool(client_payload_host(name, container_name, runner=runner, oob_domain=domain))}
            for name in running
        ]
        domain_resolves = _oob_domain_resolves(container_name, domain, runner=runner)
        edge_route_healthy = _oob_http_route_healthy(
            container_name, domain, runner=runner
        )
        probe_attempts = 1
        registration_failed = bool(running) and not any(
            item["registered"] for item in client_health
        )
        if registration_failed or not domain_resolves or not edge_route_healthy:
            probe_attempts = 2
            time.sleep(OOB_STATUS_RETRY_DELAY_SECONDS)
            if registration_failed:
                client_health = [
                    {
                        "name": name,
                        "registered": bool(
                            client_payload_host(
                                name,
                                container_name,
                                runner=runner,
                                oob_domain=domain,
                            )
                        ),
                    }
                    for name in running
                ]
            if not domain_resolves:
                domain_resolves = _oob_domain_resolves(
                    container_name,
                    domain,
                    runner=runner,
                )
            if not edge_route_healthy:
                edge_route_healthy = _oob_http_route_healthy(
                    container_name,
                    domain,
                    runner=runner,
                )
    else:
        client_health = [{"name": name, "registered": None} for name in running]
        domain_resolves = None
        edge_route_healthy = None
        probe_attempts = 0
    if server and frpc:
        state = "running"
    elif server or frpc or clients:
        state = "partial"
    else:
        state = "stopped"
    health, issues = _assess_oob_health(
        server=server, frpc=frpc, state=state, running=running,
        client_health=client_health, domain=domain, domain_resolves=domain_resolves,
        edge_route_healthy=edge_route_healthy,
    )
    active = server or frpc
    if active and route_matches is False:
        if route_issue:
            issues.append(route_issue)
        issues.append(
            "Active OOB sessions belong to another relay route; callbacks and FRP ports would be routed "
            "to the wrong install. Run `vigil oob restart` intentionally before switching relay slots."
        )
        if health == "ok":
            health = "degraded"
    elif active and route_matches is None and slot_prefix != "legacy":
        issues.append(
            "Active OOB sessions have no valid relay-routing marker, so this install cannot safely claim them. "
            "Run `vigil oob restart` to bind the sessions to the persisted relay route."
        )
        if health == "ok":
            health = "degraded"
    elif route_issue:
        issues.append(route_issue)
        if health == "ok":
            health = "degraded"
    return {
        "state": state,
        "health": health,
        "server": server,
        "frpc": frpc,
        "clients": clients,
        "running": running,
        "client_health": client_health,
        "domain": domain,
        "slot_prefix": slot_prefix,
        "port_range": [dns_remote_port, reverse_remote_port],
        "runtime_route": runtime_route,
        "route_matches": route_matches,
        "domain_resolves": domain_resolves,
        "edge_route_healthy": edge_route_healthy,
        "probe_attempts": probe_attempts,
        "issues": issues,
    }


def _assess_oob_health(
    *,
    server: bool,
    frpc: bool,
    state: str,
    running: list[str],
    client_health: list[dict[str, object]],
    domain: str | None,
    domain_resolves: bool | None,
    edge_route_healthy: bool | None = None,
) -> tuple[str, list[str]]:
    """Derive an OOB health verdict + human issues from gathered signals (PURE).

    ``degraded`` means the sessions are up but OOB cannot actually carry a
    callback (the masked-failure class); ``down`` means it is not running.
    """
    issues: list[str] = []
    if not server:
        issues.append("interactsh-server session (oob-server) is down — run `vigil oob start`.")
    if not frpc:
        issues.append("frpc tunnel session is down — run `vigil oob start`.")
    if domain and domain_resolves is False:
        issues.append(
            f"OOB domain '{domain}' does not resolve from the runtime after two probes — callbacks cannot land. "
            "Inspect the runtime container's Docker DNS resolver and the server-side CoreDNS/frps "
            "containers; verify public delegation only if those Docker services are healthy."
        )
    if domain and edge_route_healthy is False:
        issues.append(
            f"OOB HTTP edge route for '{domain}' did not return a direct slot response on two probes — "
            "callbacks may be redirecting or reaching another relay slot. Inspect the server-side Caddy "
            "and frps containers plus the persisted relay route."
        )
    # Only flag registration when it was actually checked (deep=True); a None
    # entry means "not probed" (deep=False) and must not read as unregistered.
    known = [c for c in client_health if c.get("registered") is not None]
    if running and known and not any(c.get("registered") for c in known):
        issues.append(
            f"{len(running)} OOB client(s) running but NONE registered an interactsh payload on two probes — "
            "clients cannot reach the server. Inspect `vigil oob client logs <name>`, the runtime Docker "
            "resolver, and the server-side CoreDNS/frps containers."
        )
    if state == "stopped":
        health = "down"
    elif issues:
        health = "degraded"
    else:
        health = "ok"
    return health, issues


def _oob_domain_resolves(container_name: str, domain: str, *, runner: docker.Runner) -> bool:
    """True if a wildcard subdomain of ``domain`` resolves from inside the runtime.

    Queries a two-label ``healthcheck.client-probe.<domain>`` name so it
    exercises the same wildcard depth as a real nonce/client callback and the
    delegation path real callbacks use (delegation → frp host → interactsh),
    not just an apex A record. Failure is the exact signal the broken-NS outage
    produced. Capped at one ~3s try so a dead delegation cannot hang status.
    """
    marker = f"healthcheck.client-probe.{domain}"
    result = _run_exec(
        container_name,
        f"dig +short +time=3 +tries=1 {shlex.quote(marker)} A 2>/dev/null",
        runner=runner,
        check=False,
    )
    return any(_looks_like_ip(line.strip()) for line in result.stdout.splitlines())


def _oob_http_route_healthy(
    container_name: str, domain: str, *, runner: docker.Runner
) -> bool:
    """Confirm the public HTTP edge reaches this relay slot, without accepting redirects."""
    marker = f"healthcheck.client-probe.{domain}"
    result = _run_exec(
        container_name,
        (
            "curl -sS -D - -o /dev/null --max-time 5 "
            f"{shlex.quote(f'http://{marker}/')}"
        ),
        runner=runner,
        check=False,
    )
    if result.returncode != 0:
        return False
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return False
    status_parts = lines[0].split()
    status = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0
    server = next(
        (
            line.split(":", 1)[1].strip().rstrip(".").lower()
            for line in lines[1:]
            if line.lower().startswith("server:")
        ),
        "",
    )
    return 200 <= status < 300 and server == domain.strip().rstrip(".").lower()


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def start_oob_client(
    options: OobOptions,
    name: str,
    *,
    engagement: str | None = None,
    agent: str | None = None,
    runner: docker.Runner = docker.run_command,
) -> None:
    _require_runtime(options.container_name, runner=runner)
    client_name = sanitize_name(name)
    session = f"oob-client-{client_name}"
    runtime_route, route_issue = _runtime_relay_route(
        options.container_name, runner=runner
    )
    if route_issue:
        raise SystemExit(
            "OOB client start refused because the active runtime route marker "
            f"cannot be verified: {route_issue}. Run `vigil oob restart` before starting clients."
        )
    if runtime_route is None:
        raise SystemExit(
            "OOB client start refused because the active runtime route marker is missing. "
            "Run `vigil oob start` before starting clients."
        )
    if not _route_matches_options(runtime_route, options):
        raise SystemExit(
            "OOB client start refused because the active runtime route does not match "
            "this install's persisted relay route. Stop clients for the old route explicitly, "
            "then run `vigil oob restart`."
        )
    metadata = {
        "name": client_name,
        "engagement": engagement,
        "agent": agent,
        "server": options.oob_domain,
        "slot_prefix": options.slot_prefix,
        "dns_remote_port": options.dns_remote_port,
        "reverse_remote_port": options.reverse_remote_port,
    }
    if _tmux_has_session(options.container_name, session, runner=runner):
        existing, client_issue = _read_oob_client_metadata(
            options.container_name, client_name, runner=runner
        )
        if client_issue or existing is None:
            detail = client_issue or "client metadata is missing"
            raise SystemExit(
                f"The running OOB client {client_name!r} metadata cannot be verified: {detail}. "
                f"Stop it explicitly with `vigil oob client stop {client_name}` before reusing this name."
            )
        if not _client_metadata_matches_options(existing, options):
            raise SystemExit(
                f"The running OOB client {client_name!r} belongs to another relay route. "
                f"Stop it explicitly with `vigil oob client stop {client_name}` before reusing this name."
            )
        ownership_keys = ("name", "engagement", "agent")
        if any(existing.get(key) != metadata[key] for key in ownership_keys):
            raise SystemExit(
                f"The running OOB client {client_name!r} metadata does not match the requested "
                "engagement or agent. Stop it explicitly before reusing this name."
            )
        if not _is_pre_wave2_client_metadata(existing) and any(
            existing.get(key) != value for key, value in metadata.items()
        ):
            raise SystemExit(
                f"The running OOB client {client_name!r} metadata does not match the requested "
                "route. Stop it explicitly before reusing this name."
            )
        return
    _run_exec(options.container_name, f"mkdir -p {OOB_ROOT}/clients", runner=runner)
    _write_runtime_file(options.container_name, f"{OOB_ROOT}/clients/{client_name}.json", json.dumps(metadata, indent=2) + "\n", runner=runner)
    log_path = f"{OOB_ROOT}/clients/{client_name}.log"
    session_file = f"{OOB_ROOT}/clients/{client_name}.session"
    inner = (
        f"interactsh-client -server {shlex.quote(options.oob_domain)} "
        f"-session-file {shlex.quote(session_file)} -v -poll-interval 5 "
        f"2>&1 | tee -a {shlex.quote(log_path)}"
    )
    command = f"while true; do {inner}; echo '[oob-client] exited, retrying in 10s...' | tee -a {shlex.quote(log_path)}; sleep 10; done"
    _ensure_tmux_session(options.container_name, session, command, runner=runner)


def stop_oob_client(name: str, container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> None:
    container_name = container_name or default_runtime_container()
    client_name = sanitize_name(name)
    _run_exec(container_name, f"tmux kill-session -t oob-client-{shlex.quote(client_name)} 2>/dev/null || true", runner=runner, check=False)


def list_running_oob_clients(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> list[str]:
    """Names of OOB clients with a LIVE tmux session (running, not merely configured).

    This is the set ``vigil oob mint`` binds a nonce to — only a running client
    polls interactsh, so only a running client's id can receive a callback.
    """
    container_name = container_name or default_runtime_container()
    result = _run_exec(container_name, "tmux list-sessions -F '#S' 2>/dev/null | sed -n 's/^oob-client-//p'", runner=runner, check=False)
    if result.returncode != 0:
        return []
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


def _configured_oob_clients(container_name: str, *, runner: docker.Runner) -> set[str]:
    """Names with a persisted ``<name>.json`` metadata file (configured, maybe dead)."""
    cfg_result = _run_exec(
        container_name,
        f"ls {OOB_ROOT}/clients/*.json 2>/dev/null | xargs -I{{}} basename {{}} .json",
        runner=runner, check=False,
    )
    if cfg_result.returncode != 0:
        return set()
    return {line.strip() for line in cfg_result.stdout.splitlines() if line.strip()}


def _read_oob_client_metadata(
    container_name: str,
    client_name: str,
    *,
    runner: docker.Runner,
) -> tuple[dict[str, object] | None, str | None]:
    result = _run_exec(
        container_name,
        f"cat {shlex.quote(f'{OOB_ROOT}/clients/{client_name}.json')} 2>/dev/null",
        runner=runner,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None, "client route metadata is missing"
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")
        if payload.get("name") != client_name:
            raise ValueError("client name does not match the live session")
        server = payload["server"]
        if not isinstance(server, str) or not server:
            raise ValueError("missing or malformed route fields")
        if "slot_prefix" not in payload and "tenant_prefix" in payload:
            # Pre-rename clients spell the route key `tenant_prefix`. Normalizing it
            # here keeps every comparison below — and in the callers — single-shape.
            payload["slot_prefix"] = payload.pop("tenant_prefix")
        route_fields = ("slot_prefix", "dns_remote_port", "reverse_remote_port")
        present_route_fields = [field in payload for field in route_fields]
        if any(present_route_fields) and not all(present_route_fields):
            raise ValueError("partially populated client route metadata")
        if not _is_pre_wave2_client_metadata(payload):
            slot_prefix = payload["slot_prefix"]
            dns_port = payload["dns_remote_port"]
            reverse_port = payload["reverse_remote_port"]
            if (
                not isinstance(slot_prefix, str)
                or not slot_prefix
                or isinstance(dns_port, bool)
                or not isinstance(dns_port, int)
                or isinstance(reverse_port, bool)
                or not isinstance(reverse_port, int)
            ):
                raise ValueError("missing or malformed route fields")
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        return None, f"client route metadata is invalid: {exc}"
    return payload, None


def _client_metadata_matches_options(
    metadata: dict[str, object], options: OobOptions
) -> bool:
    if _is_pre_wave2_client_metadata(metadata):
        return (
            options.slot_prefix == "legacy"
            and metadata.get("server")
            == options.oob_domain.strip().rstrip(".").lower()
            and options.dns_remote_port == OOB_UDP_REMOTE_PORT
            and options.reverse_remote_port == OOB_TCP_REMOTE_PORT
        )
    return (
        metadata.get("slot_prefix") == options.slot_prefix
        and metadata.get("server") == options.oob_domain.strip().rstrip(".").lower()
        and metadata.get("dns_remote_port") == options.dns_remote_port
        and metadata.get("reverse_remote_port") == options.reverse_remote_port
    )


def _is_pre_wave2_client_metadata(metadata: dict[str, object]) -> bool:
    route_fields = ("slot_prefix", "dns_remote_port", "reverse_remote_port")
    return not any(field in metadata for field in route_fields)


def list_oob_clients(container_name: str | None = None, *, runner: docker.Runner = docker.run_command) -> list[str]:
    container_name = container_name or default_runtime_container()
    live = set(list_running_oob_clients(container_name, runner=runner))
    return sorted(live | _configured_oob_clients(container_name, runner=runner))


@dataclass(frozen=True, slots=True)
class ChannelVerification:
    """Verdict of an end-to-end OOB channel proof.

    ``verified`` is True only when a freshly minted marker completed the whole
    round trip: public DNS -> public HTTP -> the callback landing in the running
    client's log. Anything less carries the failing step in ``reason``.
    """

    verified: bool
    reason: str = ""
    client: str = ""
    marker: str = ""
    payload_host: str = ""
    dns_address: str = ""
    http_status: int = 0
    cached: bool = False
    age_seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "reason": self.reason,
            "client": self.client,
            "marker": self.marker,
            "payload_host": self.payload_host,
            "dns_address": self.dns_address,
            "http_status": self.http_status,
            "cached": self.cached,
            "age_seconds": round(self.age_seconds, 1),
        }

    def describe_freshness(self) -> str:
        """How this verdict was obtained, for callers that print one line."""
        return f"cached({self.age_seconds:.0f}s ago)" if self.cached else "fresh"


def verify_oob_channel(
    options: OobOptions,
    *,
    client: str = "",
    runner: docker.Runner = docker.run_command,
    callback_timeout: float = 10.0,
) -> ChannelVerification:
    """Prove the public DNS and HTTP routes actually reach this relay slot's OOB server.

    Mints a throwaway marker, resolves it against public DNS, fetches it over
    public HTTP, and waits for the callback to appear in the client's log — the
    only sequence that distinguishes a live channel from a dead one.

    Returns a verdict rather than raising, because the caller decides what a
    failure means: ``vigil oob test`` turns it into an error, while
    ``vigil oob poll`` (through :func:`verify_oob_channel_cached`) uses it to
    qualify a zero-match result without blocking the agent. ``client`` pins the
    check to one registered client; empty picks the first running one.
    """
    if not docker.container_running(options.container_name, runner=runner):
        return ChannelVerification(
            verified=False,
            reason="Kali runtime is not running; start it with `vigil runtime start`",
            client=client,
        )

    candidates = (
        [sanitize_name(client)]
        if client
        else list_running_oob_clients(options.container_name, runner=runner)
    )
    selected_client = ""
    payload_host = ""
    for candidate in candidates:
        candidate_host = client_payload_host(
            candidate,
            options.container_name,
            runner=runner,
            oob_domain=options.oob_domain,
        )
        if candidate_host:
            selected_client = candidate
            payload_host = candidate_host
            break
    if not payload_host:
        detail = (
            f"client {client!r} is not running or has no payload host"
            if client
            else "no registered OOB client is running; start one with "
            "`vigil oob client start <name> --engagement <key> --agent <role>`"
        )
        return ChannelVerification(verified=False, reason=detail, client=selected_client or client)

    marker = mint_nonce(prefix=SELF_TEST_NONCE_PREFIX, length=8)
    host = f"{marker}.{payload_host}"

    def unverified(reason: str) -> ChannelVerification:
        return ChannelVerification(
            verified=False,
            reason=reason,
            client=selected_client,
            marker=marker,
            payload_host=payload_host,
        )

    dns_result = _run_exec(
        options.container_name,
        f"dig +short +time=5 +tries=1 {shlex.quote(host)} @8.8.8.8 A",
        runner=runner,
        check=False,
    )
    dns_address = next(
        (
            line.strip()
            for line in dns_result.stdout.splitlines()
            if _looks_like_ip(line.strip())
        ),
        "",
    )
    if dns_result.returncode != 0 or not dns_address:
        detail = (dns_result.stderr or dns_result.stdout).strip() or "no A record returned"
        return unverified(f"public DNS probe failed for {host}: {detail}")

    http_result = _run_exec(
        options.container_name,
        (
            "curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "
            f"{shlex.quote(f'http://{host}/')}"
        ),
        runner=runner,
        check=False,
    )
    status_text = http_result.stdout.strip()
    status = int(status_text) if status_text.isdigit() else 0
    if http_result.returncode != 0 or not 200 <= status < 300:
        detail = (http_result.stderr or status_text).strip() or "no HTTP status returned"
        return unverified(f"public HTTP probe failed for {host}: {detail}")

    client_log = shlex.quote(f"{OOB_ROOT}/clients/{sanitize_name(selected_client)}.log")
    deadline = time.monotonic() + callback_timeout
    while True:
        callback_result = _run_exec(
            options.container_name,
            f"grep -aiF -- {shlex.quote(marker)} {client_log}",
            runner=runner,
            check=False,
        )
        if marker.lower() in callback_result.stdout.lower():
            return ChannelVerification(
                verified=True,
                reason="marker completed DNS + HTTP + callback round trip",
                client=selected_client,
                marker=marker,
                payload_host=payload_host,
                dns_address=dns_address,
                http_status=status,
            )
        if time.monotonic() >= deadline:
            return unverified(
                f"callback was not observed by client {selected_client!r} "
                f"within {callback_timeout:g}s for {host}"
            )
        time.sleep(0.5)


# Where a channel verdict is remembered between CLI invocations. Every
# `vigil oob poll` is a fresh process, so an in-process cache would never hit;
# the file lives beside the relay routing record it is keyed against.
CHANNEL_VERIFICATION_CACHE_RELATIVE_PATH = Path(".runtime-data/oob/channel-verification.json")
# How long a verdict stays usable. A live channel is stable across a poll loop
# (it breaks on runtime/route events, not between two polls), so trusting it for
# minutes costs nothing real. A BROKEN channel expires much sooner: the operator
# is likely fixing it right now, and a stale "unverified" that outlives the
# repair is its own kind of lie.
VERIFIED_CHANNEL_TTL_SECONDS = 300.0
UNVERIFIED_CHANNEL_TTL_SECONDS = 60.0


def _channel_cache_path(options: OobOptions) -> Path:
    return options.install_root / CHANNEL_VERIFICATION_CACHE_RELATIVE_PATH


def _channel_cache_key(options: OobOptions, client: str) -> str:
    # One verdict per slot domain + client: a different client is a different
    # payload host and a different interactsh log, so it is a different channel.
    # The name is sanitized exactly as :func:`verify_oob_channel` pins it, so two
    # spellings of one client share the verdict they would both have produced.
    name = sanitize_name(client) if str(client or "").strip() else ""
    return f"{options.oob_domain}|{name}"


def _read_channel_cache(path: Path) -> dict[str, dict]:
    # Every read is defensive: this file is a local optimisation that a stray
    # edit or a half-written line could corrupt, and a poll must never die on it.
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return entries if isinstance(entries, dict) else {}


def _cached_channel_verdict(entry: object, *, now: float) -> ChannelVerification | None:
    """Rebuild a still-usable verdict from a cache entry, or None."""
    if not isinstance(entry, dict):
        return None
    verdict = entry.get("verification")
    stored_at = entry.get("stored_at")
    if not isinstance(verdict, dict) or not isinstance(stored_at, (int, float)):
        return None
    age = now - float(stored_at)
    verified = bool(verdict.get("verified"))
    raw_status = verdict.get("http_status")
    ttl = VERIFIED_CHANNEL_TTL_SECONDS if verified else UNVERIFIED_CHANNEL_TTL_SECONDS
    # A negative age means the clock moved backwards; re-prove rather than trust it.
    if age < 0 or age >= ttl:
        return None
    return ChannelVerification(
        verified=verified,
        reason=str(verdict.get("reason", "")),
        client=str(verdict.get("client", "")),
        marker=str(verdict.get("marker", "")),
        payload_host=str(verdict.get("payload_host", "")),
        dns_address=str(verdict.get("dns_address", "")),
        http_status=raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else 0,
        cached=True,
        age_seconds=age,
    )


def _store_channel_verdict(path: Path, key: str, result: ChannelVerification, *, now: float) -> None:
    entries = _read_channel_cache(path)
    entries[key] = {"stored_at": now, "verification": result.as_dict()}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"entries": entries}, indent=2, sort_keys=True), encoding="utf-8"
        )
    except OSError:
        # The cache is an optimisation, not state anyone depends on. A read-only
        # install root costs the round trip again; it must never fail the poll.
        pass


def verify_oob_channel_cached(
    options: OobOptions,
    *,
    client: str = "",
    runner: docker.Runner = docker.run_command,
    callback_timeout: float = 10.0,
    now: float | None = None,
) -> ChannelVerification:
    """Prove the OOB channel on a cadence instead of on every call.

    :func:`verify_oob_channel` costs a full DNS + HTTP + callback round trip —
    up to ``callback_timeout`` when the channel is broken. `vigil oob poll` runs
    it on the zero-match path, which is exactly what an agent loops on while it
    waits for a blind callback, so proving the same fact on every empty poll
    taxes the hot path hardest for no new information.

    The guarantee is unchanged: a zero match is still qualified by a real
    end-to-end proof. Only the cadence changes — a recent verdict is reused
    within its TTL and reported as reused (``cached`` / ``age_seconds``), never
    dressed up as a fresh round trip.
    """
    now = time.time() if now is None else now
    path = _channel_cache_path(options)
    key = _channel_cache_key(options, client)
    cached = _cached_channel_verdict(_read_channel_cache(path).get(key), now=now)
    if cached is not None:
        return cached
    result = verify_oob_channel(
        options, client=client, runner=runner, callback_timeout=callback_timeout
    )
    _store_channel_verdict(path, key, result, now=now)
    return result


def test_oob(options: OobOptions, *, runner: docker.Runner = docker.run_command) -> None:
    """Prove the public DNS and HTTP routes reach this relay slot's OOB server."""
    result = verify_oob_channel(options, runner=runner)
    if not result.verified:
        raise SystemExit(f"oob test: {result.reason}")
    print(
        f"oob test\tok\tdomain={options.oob_domain}\tmarker={result.marker}"
        f"\tdns={result.dns_address}\thttp={result.http_status}"
    )


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    if not cleaned:
        raise SystemExit("OOB client name cannot be empty")
    return cleaned[:80]


# ── OAST (out-of-band) nonce minting + correlation ───────────────────────
#
# A unique random subdomain label IS the correlation token. Minting returns
# the callback URLs; correlation parses the SAME interactsh-client log that
# `oob client logs` reads and extracts the nonce from each callback host.

# DNS labels are case-insensitive and interactsh lowercases the host before
# logging, so a lowercase token survives the round-trip unchanged. Length 16
# of [a-z0-9] is ~82 bits — collision-safe and well under the 63-char DNS
# label limit even with the engagement prefix.
_NONCE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_DEFAULT_NONCE_LENGTH = 16

# Matches the verbose text a ``-v`` interactsh-client line emits for a received
# interaction: ``Received <protocol> interaction (qtype) ... from <remote> at
# <observed>``. Used by ``_parse_verbose_interaction`` to extract the protocol,
# remote address, query type, and timestamp from the text that follows the
# ``[<host>]`` bracket.
#
# Callback host shape context: interactsh hosts look like
# ``<33-char-clientid><nonce>.oob.example.com`` when a tool (nuclei/dalfox)
# prepends its own id to the leftmost label, or
# ``<nonce>.<33-char-clientid>.oob.example.com`` when ``vigil oob mint``
# binds the nonce under a running client's registered payload host. Both shapes
# carry the client id so interactsh delivers the hit to that client's poll; the
# parser extracts the FULL leftmost label and the matcher checks whether any
# recorded nonce is a substring of it (handles both shapes). A bare
# ``<nonce>.oob.example.com`` is NOT minted anymore — it never reaches the
# per-client log ``poll`` reads (see :func:`callback_urls`).
_INTERACTSH_VERBOSE_RE = re.compile(
    r"Received\s+(?P<protocol>[A-Za-z0-9]+)\s+interaction"
    r"(?:\s*\((?P<qtype>[^)]*)\))?"
    r".*?\bfrom\s+(?P<remote>[0-9a-fA-F:.]+)"
    r"(?:\s+at\s+(?P<observed>.+?))?\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class OobInteraction:
    """One parsed interactsh callback line.

    ``full_host`` is the entire callback hostname as logged; ``label`` is its
    leftmost DNS label (where the nonce lives). ``nonce`` is filled in by
    :func:`match_interactions_to_nonces` once the recorded nonce set is known
    — the pure parser cannot know it from the line alone.
    """

    protocol: str
    full_host: str
    label: str
    remote_address: str
    query_type: str
    observed_at: str
    raw_line: str
    nonce: str = ""


# Prefix stamped on the throwaway markers :func:`verify_oob_channel` mints. Its
# callbacks land in the SAME client log the poller reads as evidence, so both
# sides must agree on one spelling: the verifier stamps it, the poller drops it.
SELF_TEST_NONCE_PREFIX = "vigil-test"


def _nonce_prefix_label(prefix: str) -> str:
    """The prefix as it survives into a DNS label: [a-z0-9] only, capped at 24.

    A DNS label cannot carry the punctuation a caller may write, so
    :func:`mint_nonce` strips it. Recognising a minted marker later means
    applying the SAME reduction — reading the raw prefix would look for
    ``vigil-test-`` in a label that says ``vigiltest-``, and the recogniser
    would silently never fire.
    """
    return re.sub(r"[^a-z0-9]+", "", str(prefix or "").lower())[:24]


def is_self_test_interaction(interaction: OobInteraction) -> bool:
    """True when this callback is Vigil's own channel-verification round trip.

    Every unmatched interaction is reported to the operator as a real, unclaimed
    callback. Vigil's own verification markers are neither — counting them would
    let a channel check manufacture the evidence it exists to qualify, and they
    accumulate in the log for the life of the client.
    """
    label = (interaction.label or "").strip().lower()
    marker_prefix = _nonce_prefix_label(SELF_TEST_NONCE_PREFIX)
    return bool(marker_prefix) and label.startswith(f"{marker_prefix}-")


def mint_nonce(
    *,
    prefix: str = "",
    length: int = _DEFAULT_NONCE_LENGTH,
    token_factory: Callable[[int], str] | None = None,
) -> str:
    """Generate a unique URL-safe nonce subdomain label.

    ``token_factory`` is injectable so tests can seed deterministic nonces;
    it receives the requested label length and must return a string of
    [a-z0-9] characters. The default draws from :mod:`secrets`.

    An optional ``prefix`` (e.g. a sanitized engagement key) is prepended with
    a ``-`` separator so callbacks are visually attributable in the raw log;
    it does not affect correlation (matching is on the random token).
    """
    if token_factory is None:
        token = "".join(secrets.choice(_NONCE_ALPHABET) for _ in range(length))
    else:
        token = token_factory(length)
        token = re.sub(r"[^a-z0-9]+", "", token.lower())
        if not token:
            raise ValueError("token_factory produced an empty nonce after sanitization")
    if prefix:
        clean_prefix = _nonce_prefix_label(prefix)
        if clean_prefix:
            return f"{clean_prefix}-{token}"
    return token


def callback_urls(nonce: str, base_host: str) -> dict[str, str]:
    """Build the callback URLs for a minted nonce bound under a client.

    ``base_host`` is a running interactsh-client's registered payload host
    (``<clientid>.<oob_domain>``), so the result is
    ``<nonce>.<clientid>.<oob_domain>``. Binding under the client id is what
    lets the callback reach that client's poll: interactsh keys delivery off the
    registered correlation id (read from the RIGHTMOST subdomain label), so a
    bare ``<nonce>.<oob_domain>`` is recorded only in the raw server log and
    never delivered to the per-client log ``vigil oob poll`` reads.

    ``http``/``https`` are full callback URLs; ``dns`` is the bare host (for
    payloads that only trigger a DNS lookup); ``host`` is the form they share.
    """
    host = f"{nonce}.{base_host}"
    return {
        "host": host,
        "http": f"http://{host}/",
        "https": f"https://{host}/",
        "dns": host,
    }


# Strips terminal colour codes interactsh-client emits so the registration line
# parses regardless of TTY styling.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_client_payload_host(log_text: str, oob_domain: str = DEFAULT_OOB_DOMAIN) -> str:
    """Extract a client's registered interactsh payload host from its log (PURE).

    interactsh-client prints its registered callback domain once per
    registration, right after the banner::

        [INF] Listing 1 payload for OOB Testing
        [INF] <33-char-id>.oob.example.com

    That ``<id>`` is the correlation handle interactsh keys delivery on, so a
    minted probe must be fired *under* it (``<nonce>.<id>.oob...``) to land in
    THIS client's poll. Returns the MOST RECENT such host (a restart re-registers
    and may rotate the id), or ``""`` if the client has not registered yet.

    Robust against: terminal colour codes; the ``[INF]``/``[VER]``/``[FTL]``
    level tags (their bracket has no dot); and real callback lines
    ``[<host>] Received ... interaction`` (their bracket holds an FQDN and the
    line carries trailing text, so the anchored host match rejects them). No
    network / filesystem — feed it the client-log tail.
    """
    domain = oob_domain.strip().rstrip(".").lower()
    if not domain:
        return ""
    host_re = re.compile(r"^(?P<host>[a-z0-9-]+\." + re.escape(domain) + r")$")
    found = ""
    for raw_line in log_text.splitlines():
        line = _ANSI_RE.sub("", raw_line).strip()
        bracket = re.match(r"^\[(?P<tag>[^\]]*)\]\s*(?P<rest>.*)$", line)
        if bracket and "." not in bracket.group("tag"):
            line = bracket.group("rest").strip()
        match = host_re.match(line.lower())
        if match:
            found = match.group("host")
    return found


def parse_interactsh_log(log_text: str) -> list[OobInteraction]:
    """Parse interactsh-client output into structured interactions (PURE).

    Handles two line shapes the client can emit:

    * ``-v`` verbose text, e.g.
      ``[abc123.oob.example.com] Received HTTP interaction from 1.2.3.4 at 2026-05-30 12:00:00``
      (the leading ``[host]`` bracket is interactsh's own prefix; the
      retry/marker lines this module writes — ``[oob-client] ...`` — are
      ignored because their bracket is not a callback host).
    * JSON lines (``interactsh-client -json``), one object per line with
      ``unique-id``/``full-id``/``protocol``/``remote-address`` fields.

    Returns one :class:`OobInteraction` per recognised callback, in log
    order. ``nonce`` is left blank; call :func:`match_interactions_to_nonces`
    to bind each to a recorded probe. No network, no filesystem — unit-test
    by feeding raw text.
    """
    interactions: list[OobInteraction] = []
    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parsed = _parse_json_interaction(line) or _parse_verbose_interaction(line)
        if parsed is not None:
            interactions.append(parsed)
    return interactions


def _split_host_label(host: str) -> tuple[str, str]:
    host = host.strip().rstrip(".").lower()
    label = host.split(".", 1)[0] if host else ""
    return host, label


def _parse_json_interaction(line: str) -> OobInteraction | None:
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    host = str(
        payload.get("full-id")
        or payload.get("full-domain")
        or payload.get("unique-id")
        or ""
    )
    if not host:
        return None
    full_host, label = _split_host_label(host)
    if not full_host:
        return None
    return OobInteraction(
        protocol=str(payload.get("protocol") or "").lower(),
        full_host=full_host,
        label=label,
        remote_address=str(payload.get("remote-address") or payload.get("remote-addr") or ""),
        query_type=str(payload.get("q-type") or payload.get("query-type") or ""),
        observed_at=str(payload.get("timestamp") or ""),
        raw_line=line,
    )


def _parse_verbose_interaction(line: str) -> OobInteraction | None:
    bracket = re.match(r"^\[(?P<host>[^\]]+)\]\s*(?P<rest>.*)$", line)
    if not bracket:
        return None
    host = bracket.group("host").strip()
    rest = bracket.group("rest").strip()
    # Ignore our own runtime markers — `[oob-client] exited, retrying...` —
    # whose bracket holds a tag, not a callback host. A real callback host
    # always contains a dot (it is an FQDN).
    if "." not in host:
        return None
    match = _INTERACTSH_VERBOSE_RE.search(rest)
    if not match:
        return None
    full_host, label = _split_host_label(host)
    if not full_host:
        return None
    return OobInteraction(
        protocol=match.group("protocol").lower(),
        full_host=full_host,
        label=label,
        remote_address=match.group("remote") or "",
        query_type=(match.group("qtype") or "").strip(),
        observed_at=(match.group("observed") or "").strip(),
        raw_line=line,
    )


def match_interactions_to_nonces(
    interactions: list[OobInteraction],
    nonces: list[str] | set[str],
) -> tuple[list[OobInteraction], list[OobInteraction]]:
    """Bind parsed interactions to recorded nonces (PURE).

    Returns ``(matched, unmatched)``. A nonce matches when it equals the
    callback's leftmost label OR appears as a substring of it (covering the
    ``<clientid><nonce>`` shape some tools produce). Longer nonces are tried
    first so a more specific token wins over a shorter accidental substring.
    Matched interactions are returned as copies with ``nonce`` populated.
    """
    ordered = sorted({str(n).strip().lower() for n in nonces if str(n).strip()}, key=lambda n: (-len(n), n))
    matched: list[OobInteraction] = []
    unmatched: list[OobInteraction] = []
    for interaction in interactions:
        hit = ""
        for nonce in ordered:
            if nonce in interaction.label:
                hit = nonce
                break
        if hit:
            matched.append(_with_nonce(interaction, hit))
        else:
            unmatched.append(interaction)
    return matched, unmatched


def interactions_for_domain(
    interactions: list[OobInteraction],
    oob_domain: str,
    *,
    client_payload_host: str = "",
) -> list[OobInteraction]:
    """Admit interactions emitted by one relay slot client's dedicated log.

    Interactsh's verbose client output uses either a complete callback FQDN or
    a compact ``<probe>.<correlation-id>`` bracket with the configured server
    domain omitted. The caller reads exactly one slot-bound client log, so a
    compact one- or two-label identifier carries no slot suffix, so it is
    admitted only when its rightmost label matches this client's current
    registered correlation ID. Complete hostnames must still match the
    persisted slot domain.
    """
    domain = oob_domain.strip().rstrip(".").lower()
    if not domain:
        return []
    suffix = f".{domain}"
    registered = client_payload_host.strip().rstrip(".").lower()
    correlation_id = registered[: -len(suffix)] if registered.endswith(suffix) else ""
    if not correlation_id or "." in correlation_id:
        correlation_id = ""

    def belongs_to_client(interaction: OobInteraction) -> bool:
        host = interaction.full_host.strip().rstrip(".").lower()
        if host.endswith(suffix):
            return True
        if not correlation_id or host.count(".") > 1:
            return False
        return host == correlation_id or host.endswith(f".{correlation_id}")

    return [interaction for interaction in interactions if belongs_to_client(interaction)]


def _with_nonce(interaction: OobInteraction, nonce: str) -> OobInteraction:
    return OobInteraction(
        protocol=interaction.protocol,
        full_host=interaction.full_host,
        label=interaction.label,
        remote_address=interaction.remote_address,
        query_type=interaction.query_type,
        observed_at=interaction.observed_at,
        raw_line=interaction.raw_line,
        nonce=nonce,
    )


def read_client_log(
    name: str,
    container_name: str | None = None,
    *,
    runner: docker.Runner = docker.run_command,
    lines: int = 2000,
) -> str:
    """Read recent parser-candidate interactions from the client log.

    Reads the SAME source ``vigil oob client logs`` reads
    (``/data/oob/clients/<name>.log``).

    A verbose interactsh callback expands to dozens of raw request/response
    lines. A physical-line tail therefore lets a DNS burst evict a nearby HTTP
    interaction and creates a false negative. Reverse-scan the file and retain
    only the newest bounded parser candidates: verbose ``Received ...
    interaction`` summaries and JSONL protocol records. The parser and slot
    admission remain authoritative; this grep is only a compact prefilter.

    Best-effort: a missing log yields ``""``.
    """
    container_name = container_name or default_runtime_container()
    client = sanitize_name(name)
    count = int(lines)
    if not 1 <= count <= MAX_OOB_POLL_RECORDS:
        raise ValueError(f"OOB poll records must be between 1 and {MAX_OOB_POLL_RECORDS}")
    log_path = f"{OOB_ROOT}/clients/{shlex.quote(client)}.log"
    candidate_pattern = (
        r'^\[[^]]+\][[:space:]]+Received[[:space:]]+'
        r'[[:alnum:]_-]+[[:space:]]+interaction|'
        r'^\{.*"protocol"[[:space:]]*:'
    )
    command = (
        f"tac {log_path} 2>/dev/null | "
        f"grep -aE -m {count} -- {shlex.quote(candidate_pattern)} | tac || true"
    )
    result = _run_exec(container_name, command, runner=runner, check=False)
    return result.stdout or ""


def read_client_registration_log(
    name: str,
    container_name: str | None = None,
    *,
    runner: docker.Runner = docker.run_command,
    oob_domain: str = DEFAULT_OOB_DOMAIN,
) -> str:
    """Return the client-log lines that mention the OOB domain (whole file).

    The interactsh registration banner (``[INF] <id>.<oob_domain>``) is printed
    exactly ONCE, at registration, right after the client starts — then a busy
    client appends thousands of interaction lines on top of it. The previous
    approach tailed a fixed window, so on any client fielding more than a few
    hundred callbacks the banner scrolled out of view and a perfectly-registered
    client reported as ``registered: False`` (the false-negative that made OOB
    look like it was "flapping"). Grepping the whole log for the domain keeps the
    banner findable regardless of log size while staying cheap — ``grep`` streams
    the file and emits only the handful of host-bearing lines, and
    :func:`parse_client_payload_host` still does the strict banner filtering.
    Best-effort: a missing log yields ``""``.
    """
    container_name = container_name or default_runtime_container()
    client = sanitize_name(name)
    log_path = f"{OOB_ROOT}/clients/{shlex.quote(client)}.log"
    domain = oob_domain.strip().rstrip(".")
    # -a keeps grep from bailing to "binary file matches" on the control bytes
    # interactsh -v emits; -F/-i match the domain literally, case-insensitively.
    command = f"grep -aiF -- {shlex.quote(domain)} {log_path} 2>/dev/null || true"
    result = _run_exec(container_name, command, runner=runner, check=False)
    return result.stdout or ""


def client_payload_host(
    name: str,
    container_name: str | None = None,
    *,
    runner: docker.Runner = docker.run_command,
    oob_domain: str = DEFAULT_OOB_DOMAIN,
) -> str:
    """Live interactsh payload host for client ``name`` (``<id>.<oob_domain>``), or "".

    Scans the client's WHOLE interaction log (via
    :func:`read_client_registration_log`) for the one-time registration banner
    and extracts it via :func:`parse_client_payload_host`. Empty means the client
    is not running or has not registered an interactsh id yet — in which case a
    minted nonce cannot be bound to it and could not be correlated by
    ``vigil oob poll``. Whole-log scan (not a tail) so a busy client with a large
    log is still detected as registered.
    """
    log_text = read_client_registration_log(name, container_name, runner=runner, oob_domain=oob_domain)
    return parse_client_payload_host(log_text, oob_domain)


def poll_client_payload_host(
    options: OobOptions,
    name: str,
    *,
    engagement: str,
    runner: docker.Runner = docker.run_command,
) -> str:
    """Return a poll client's registration only when its ownership is current."""
    client_name = sanitize_name(name)
    metadata, issue = _read_oob_client_metadata(
        options.container_name,
        client_name,
        runner=runner,
    )
    if issue or metadata is None:
        raise SystemExit(
            f"OOB poll refused for client {client_name!r}: "
            f"{issue or 'client metadata is missing'}."
        )
    if not _client_metadata_matches_options(metadata, options):
        raise SystemExit(
            f"OOB poll refused because client {client_name!r} belongs to another relay route."
        )
    if metadata.get("engagement") != engagement:
        raise SystemExit(
            f"OOB poll refused because client {client_name!r} belongs to engagement "
            f"{metadata.get('engagement')!r}, not {engagement!r}."
        )
    payload_host = client_payload_host(
        client_name,
        options.container_name,
        runner=runner,
        oob_domain=options.oob_domain,
    )
    if not payload_host:
        raise SystemExit(
            f"OOB poll refused because client {client_name!r} has no current registration."
        )
    return payload_host


# ── OOB client artifact cleanup (manual retention) ───────────────────────
#
# `vigil oob clean` reclaims space from long-finished engagements. It removes
# the per-client log/metadata/session files for clients that are (a) NOT
# currently running and (b) whose EVERY artifact is older than the cutoff.
# Nothing runs it on a schedule — the operator invokes it by hand.

OOB_CLIENTS_DIR = f"{OOB_ROOT}/clients"
_OOB_CLIENT_SUFFIXES = (".log", ".json", ".session")
_SECONDS_PER_DAY = 86400


def _oob_client_name_from_path(path: str) -> str:
    """Client name owning ``path``, or "" if it is not a per-client artifact.

    Only files DIRECTLY under ``OOB_CLIENTS_DIR`` with a known suffix map to a
    client; anything else (a nested path, an unknown extension, a path outside
    the clients dir) yields "" so the pruner can never select an unrelated file.
    """
    prefix = OOB_CLIENTS_DIR + "/"
    if not path.startswith(prefix):
        return ""
    base = path[len(prefix):]
    if "/" in base:
        return ""
    for suffix in _OOB_CLIENT_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix):
            return base[: -len(suffix)]
    return ""


def select_prunable_oob_clients(
    files: list[tuple[str, float]],
    running: set[str] | list[str],
    *,
    now: float,
    max_age_days: int,
) -> tuple[list[str], list[str]]:
    """Pick OOB clients safe to prune (PURE — no I/O).

    ``files`` is ``(path, mtime_epoch)`` for everything under the clients dir. A
    client is prunable iff it is NOT in ``running`` AND every one of its
    artifacts is older than ``max_age_days`` — so a client that received a
    callback within the window (recent ``.log`` mtime) or is live is kept even if
    its metadata file is old. Returns ``(client_names_sorted, paths_sorted)``.
    """
    cutoff = now - max_age_days * _SECONDS_PER_DAY
    running_set = {str(n) for n in running}
    by_client: dict[str, list[tuple[str, float]]] = {}
    for path, mtime in files:
        name = _oob_client_name_from_path(path)
        if name:
            by_client.setdefault(name, []).append((path, float(mtime)))
    prune_clients: list[str] = []
    prune_paths: list[str] = []
    for name, entries in by_client.items():
        if name in running_set:
            continue
        if entries and all(mtime < cutoff for _, mtime in entries):
            prune_clients.append(name)
            prune_paths.extend(path for path, _ in entries)
    return sorted(prune_clients), sorted(prune_paths)


def _gather_oob_client_files(container_name: str, *, runner: docker.Runner) -> tuple[float, list[tuple[str, float]]]:
    """Return ``(now_epoch, [(path, mtime_epoch), ...])`` for the clients dir.

    ``now`` is read from the container clock so the age comparison uses the same
    clock that stamped the mtimes. Best-effort: a missing dir yields ``(now, [])``.
    """
    command = (
        f'echo "NOW $(date +%s)"; '
        f"find {shlex.quote(OOB_CLIENTS_DIR)} -maxdepth 1 -type f -printf '%T@ %p\\n' 2>/dev/null || true"
    )
    result = _run_exec(container_name, command, runner=runner, check=False)
    now = 0.0
    files: list[tuple[str, float]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("NOW "):
            try:
                now = float(line[4:].strip())
            except ValueError:
                pass
            continue
        mtime_str, _, path = line.partition(" ")
        if path:
            try:
                files.append((path, float(mtime_str)))
            except ValueError:
                continue
    return now, files


def _remove_oob_files(container_name: str, paths: list[str], *, runner: docker.Runner) -> None:
    if not paths:
        return
    quoted = " ".join(shlex.quote(p) for p in paths)
    _run_exec(container_name, f"rm -f -- {quoted}", runner=runner, check=False)


def clean_oob_clients(
    container_name: str | None = None,
    *,
    max_age_days: int = 5,
    dry_run: bool = False,
    runner: docker.Runner = docker.run_command,
) -> dict[str, object]:
    """Remove per-client OOB artifacts for non-running clients older than N days.

    The command behind ``vigil oob clean``. Running clients are always kept
    (their files are in use), as is any client touched within the window. With
    ``dry_run`` it selects but does not delete. Returns a summary dict for the
    CLI to render.
    """
    container_name = container_name or default_runtime_container()
    if max_age_days < 1:
        raise SystemExit("oob clean: --days must be >= 1 (refusing to prune everything).")
    _require_runtime(container_name, runner=runner)
    now, files = _gather_oob_client_files(container_name, runner=runner)
    running = set(list_running_oob_clients(container_name, runner=runner))
    clients, paths = select_prunable_oob_clients(files, running, now=now, max_age_days=max_age_days)
    if paths and not dry_run:
        _remove_oob_files(container_name, paths, runner=runner)
    return {
        "removed": bool(paths) and not dry_run,
        "dry_run": dry_run,
        "max_age_days": max_age_days,
        "clients": clients,
        "files": paths,
        "kept_running": sorted(running),
    }


def _kill_stale_oob_processes(container_name: str, *, runner: docker.Runner) -> None:
    """Kill leftover interactsh-server and frpc processes before (re)starting."""
    for proc in ("interactsh-server", "frpc"):
        _run_exec(container_name, f"pkill -f {shlex.quote(proc)} 2>/dev/null || true", runner=runner, check=False)


def _reset_frpc_log(container_name: str, *, runner: docker.Runner) -> None:
    _run_exec(container_name, f"mkdir -p {OOB_ROOT} && : > {OOB_ROOT}/frpc.log", runner=runner)


def _require_runtime(container_name: str, *, runner: docker.Runner) -> None:
    if not docker.container_running(container_name, runner=runner):
        raise SystemExit("Kali runtime is not running. Start it with `vigil runtime start`.")


def _require_runtime_tools(container_name: str, *, runner: docker.Runner) -> None:
    for tool in (
        "tmux", "frpc", "interactsh-server", "interactsh-client", "dig",
        "curl", "grep", "tac", "python3",
    ):
        result = _run_exec(container_name, f"command -v {shlex.quote(tool)} >/dev/null", runner=runner, check=False)
        if result.returncode != 0:
            raise SystemExit(f"OOB runtime tool missing: {tool}")


_FRPC_CONFLICT_PATTERNS = (
    "port already used",
    "router config conflict",
    "proxy name [",
)
_FRPC_SUCCESS_PATTERNS = (
    "start proxy success",
    "new proxy [",
)
_FRPC_EXPECTED_PROXY_LABELS = frozenset(("dns", "http", "reverse"))
_FRPC_PROXY_LABEL_HINTS = {
    "dns": "*-oob-dns",
    "http": "*-oob",
    "reverse": "*-oob-rev",
}


def _check_frpc_for_conflicts(
    options: OobOptions,
    *,
    runner: docker.Runner,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Post-flight: confirm frpc registered our proxies, surface conflicts loudly.

    Relay routes own a persisted domain and two-port FRP block. If another
    client holds either resource when we register, frps rejects our registration
    and frpc retries silently every ~30s (`loginFailExit = false`). Polling
    `/data/oob/frpc.log` for the success/conflict lines lets us turn that
    silent loop into a clear SystemExit without needing any extra channel
    beyond the frp control connection we already have.
    """
    deadline = time.monotonic() + timeout
    last_log = ""
    while time.monotonic() < deadline:
        result = _run_exec(
            options.container_name,
            f"tail -n 200 {OOB_ROOT}/frpc.log 2>/dev/null || true",
            runner=runner,
            check=False,
        )
        last_log = result.stdout or ""
        conflicts = [
            line.strip()
            for line in last_log.splitlines()
            if any(pat in line for pat in _FRPC_CONFLICT_PATTERNS)
        ]
        if conflicts:
            _kill_oob_sessions(options.container_name, runner=runner)
            raise SystemExit(
                "OOB resources are already held by another frpc client. frps reported:\n"
                + "\n".join(f"  {line}" for line in conflicts[:10])
                + f"\n\nRelay route {options.slot_prefix!r} owns remotePort "
                + f"{options.dns_remote_port}/{options.reverse_remote_port} and customDomains {options.oob_domain!r}.\n"
                "Resolve the duplicate allocation in the shared OOB registry, stop the conflicting instance, then retry. To inspect:\n"
                f"  docker exec {options.container_name} tail -n 200 {OOB_ROOT}/frpc.log\n"
                "(See docs/oob-routing.md for the relay-slot allocation contract.)"
            )
        registered = _frpc_registered_proxy_labels(last_log)
        if registered >= _FRPC_EXPECTED_PROXY_LABELS:
            return
        sleep(1.0)
    missing = sorted(_FRPC_EXPECTED_PROXY_LABELS - _frpc_registered_proxy_labels(last_log))
    missing_hint = ", ".join(_FRPC_PROXY_LABEL_HINTS[label] for label in missing)
    target_hint = f" for {missing_hint}" if missing_hint else ""
    print(
        f"oob check\tfrpc did not confirm proxy registration{target_hint} within {int(timeout)}s; "
        f"if callbacks do not land, run `docker exec {options.container_name} tail -n 200 {OOB_ROOT}/frpc.log`"
    )


def _frpc_registered_proxy_labels(log_text: str) -> set[str]:
    labels: set[str] = set()
    for line in log_text.splitlines():
        if not any(pat in line for pat in _FRPC_SUCCESS_PATTERNS):
            continue
        for token in re.findall(r"\[([^\]]+)\]", line):
            if token.endswith("-oob-dns"):
                labels.add("dns")
            elif token.endswith("-oob-rev"):
                labels.add("reverse")
            elif token.endswith("-oob"):
                labels.add("http")
    return labels


def _kill_oob_sessions(container_name: str, *, runner: docker.Runner) -> None:
    for session in ("frpc", "oob-server"):
        _run_exec(
            container_name,
            f"tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true",
            runner=runner,
            check=False,
        )
    _kill_stale_oob_processes(container_name, runner=runner)


def _render_runtime_files(options: OobOptions, *, runner: docker.Runner) -> None:
    _run_exec(options.container_name, f"mkdir -p {OOB_ROOT}/clients", runner=runner)
    proxy_prefix = (
        "vigil-"
        + hashlib.sha256(options.slot_prefix.encode("utf-8")).hexdigest()[:16]
    )
    render = f"""python3 - <<'PY'
from pathlib import Path
import socket

root = Path({OOB_ROOT!r})
root.mkdir(parents=True, exist_ok=True)
container_ip = socket.gethostbyname(socket.gethostname())
Path({f"{OOB_ROOT}/frpc.toml"!r}).write_text(f'''serverAddr = {options.frp_host!r}
serverPort = {options.frp_port}
auth.token = {options.frp_token!r}
loginFailExit = false
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30

[[proxies]]
name = "{proxy_prefix}-oob-dns"
type = "udp"
localIP = "{{container_ip}}"
localPort = 53
remotePort = {options.dns_remote_port}

[[proxies]]
name = "{proxy_prefix}-oob"
type = "http"
localIP = "{{container_ip}}"
localPort = 80
customDomains = [{options.oob_domain!r}, "*.{options.oob_domain}"]

[[proxies]]
name = "{proxy_prefix}-oob-rev"
type = "tcp"
localIP = "{{container_ip}}"
localPort = 4444
remotePort = {options.reverse_remote_port}
''', encoding='utf-8')
PY"""
    _run_exec(options.container_name, render, runner=runner)
    runtime_route = {
        "version": 1,
        "slot_prefix": options.slot_prefix,
        "oob_domain": options.oob_domain,
        "dns_remote_port": options.dns_remote_port,
        "reverse_remote_port": options.reverse_remote_port,
    }
    _write_runtime_file(
        options.container_name,
        OOB_RELAY_ROUTE_FILE,
        json.dumps(runtime_route, indent=2, sort_keys=True) + "\n",
        runner=runner,
    )
    _write_runtime_file(options.container_name, f"{OOB_ROOT}/oob_server_watch.py", _server_watch_source(options), runner=runner)


def _route_slot_prefix(payload: dict[str, object]) -> object:
    """Read the marker's slot prefix under its current or pre-rename key."""
    if "slot_prefix" in payload:
        return payload["slot_prefix"]
    return payload["tenant_prefix"]


def _runtime_relay_route(
    container_name: str, *, runner: docker.Runner
) -> tuple[dict[str, object] | None, str | None]:
    result = _run_exec(
        container_name,
        f"cat {shlex.quote(OOB_RELAY_ROUTE_FILE)} 2>/dev/null "
        f"|| cat {shlex.quote(LEGACY_OOB_RELAY_ROUTE_FILE)} 2>/dev/null",
        runner=runner,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None, None
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")
        slot_prefix = _route_slot_prefix(payload)
        oob_domain = payload["oob_domain"]
        dns_port = payload["dns_remote_port"]
        reverse_port = payload["reverse_remote_port"]
        if (
            not isinstance(slot_prefix, str)
            or not slot_prefix
            or not isinstance(oob_domain, str)
            or not oob_domain
            or isinstance(dns_port, bool)
            or not isinstance(dns_port, int)
            or isinstance(reverse_port, bool)
            or not isinstance(reverse_port, int)
        ):
            raise ValueError("missing or malformed route fields")
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        return None, f"Active OOB relay-routing marker is invalid: {exc}"
    return {
        "slot_prefix": slot_prefix,
        "oob_domain": oob_domain.strip().rstrip(".").lower(),
        "dns_remote_port": dns_port,
        "reverse_remote_port": reverse_port,
    }, None


def _route_matches_values(
    runtime_route: dict[str, object],
    *,
    slot_prefix: str,
    oob_domain: str,
    dns_remote_port: int,
    reverse_remote_port: int,
) -> bool:
    return runtime_route == {
        "slot_prefix": slot_prefix,
        "oob_domain": oob_domain.strip().rstrip(".").lower(),
        "dns_remote_port": dns_remote_port,
        "reverse_remote_port": reverse_remote_port,
    }


def _route_matches_options(runtime_route: dict[str, object], options: OobOptions) -> bool:
    return _route_matches_values(
        runtime_route,
        slot_prefix=options.slot_prefix,
        oob_domain=options.oob_domain,
        dns_remote_port=options.dns_remote_port,
        reverse_remote_port=options.reverse_remote_port,
    )


def _server_watch_source(options: OobOptions) -> str:
    return f"""from __future__ import annotations

import subprocess
import time

DOMAIN = {options.oob_domain!r}
FRP_HOST = {options.frp_host!r}
CHECK_INTERVAL = 60
current_ip = ""
process = None

while True:
    lookup = subprocess.run(["dig", "+short", FRP_HOST, "A"], text=True, capture_output=True, check=False)
    new_ip = next((line.strip() for line in lookup.stdout.splitlines() if line.strip()), "")
    if not new_ip:
        print(f"[oob-watch] DNS lookup failed for {{FRP_HOST}}", flush=True)
        time.sleep(CHECK_INTERVAL)
        continue
    if new_ip != current_ip or process is None or process.poll() is not None:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        subprocess.run(["pkill", "-f", "interactsh-server"], check=False)
        current_ip = new_ip
        log = open("/data/oob/server.log", "ab", buffering=0)
        process = subprocess.Popen(
            ["interactsh-server", "-d", DOMAIN, "-listen-ip", "0.0.0.0", "-ip", current_ip, "-skip-acme", "-v", "-debug"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        print(f"[oob-watch] interactsh-server started pid={{process.pid}} ip={{current_ip}}", flush=True)
    time.sleep(CHECK_INTERVAL)
"""


def _write_runtime_file(container_name: str, path: str, contents: str, *, runner: docker.Runner) -> None:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_text({contents!r}, encoding='utf-8')\n"
        "PY"
    )
    _run_exec(container_name, script, runner=runner)


def _tmux_has_session(container_name: str, session: str, *, runner: docker.Runner) -> bool:
    return _run_exec(container_name, f"tmux has-session -t {shlex.quote(session)}", runner=runner, check=False).returncode == 0


def _ensure_tmux_session(container_name: str, session: str, command: str, *, runner: docker.Runner) -> None:
    quoted_session = shlex.quote(session)
    quoted_command = shlex.quote(command)
    shell = (
        f"tmux has-session -t {quoted_session} 2>/dev/null "
        f"|| tmux new-session -d -s {quoted_session} {quoted_command} "
        f"|| tmux has-session -t {quoted_session} 2>/dev/null"
    )
    _run_exec(container_name, shell, runner=runner)


def _run_exec(container_name: str, command: str, *, runner: docker.Runner, check: bool = True) -> docker.DockerResult:
    argv = ["docker", "exec", container_name, "sh", "-lc", command]
    result = runner(argv)
    if check:
        docker.require_success(result, argv)
    return result
